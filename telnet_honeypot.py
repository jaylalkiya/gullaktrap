"""
Telnet honeypot for GullakTrap.

Telnet is the highest-traffic target on the open internet -- Mirai and its
descendants sweep 23/2323 continuously with small hardcoded credential
lists -- so this sensor is usually the one that fills the database.

It speaks enough of RFC 854 to look real: it negotiates ECHO and
SUPPRESS-GO-AHEAD, strips IAC sequences from the input stream, and presents
a BusyBox-flavoured shell of the kind embedded devices actually run.
"""

import os
import socket
import time
from threading import Thread

from netutil import bind_listener

# Telnet protocol bytes (RFC 854)
IAC, DONT, DO, WONT, WILL, SB, SE = (255, 254, 253, 252, 251, 250, 240)
ECHO, SGA = 1, 3


class TelnetHoneypot:
    BANNER_SUGGESTIONS = [
        "\r\nDD-WRT v24-sp2 std (c) 2020 NewMedia-NET GmbH\r\n",
        "\r\nBusyBox v1.20.2 (2016-06-08) built-in shell (ash)\r\n",
        "\r\nOpenWrt 19.07.7, r11306-c4a6851c72\r\n",
        "\r\nHuawei Home Gateway\r\n",
        "\r\nWelcome to Embedded Linux Router\r\n",
        "\r\nZTE Corporation. All rights reserved.\r\n",
    ]

    # What the fake device pretends to be once someone gets in.
    HOSTNAME = 'router'

    def __init__(self, port=2323, log_callback=None, server_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.server_banner = server_banner or self.BANNER_SUGGESTIONS[0]
        self.files_dir = files_dir or 'telnet_files'
        self.server_socket = None
        self.running = False
        self.thread = None

        # Optional callbacks so main.py can record sessions/credentials
        # without this module importing storage directly.
        self.hooks = session_hooks or {}

        self.total_connections = 0
        self.auth_attempts = 0
        self._ensure_files_directory()

    def _ensure_files_directory(self):
        if not os.path.exists(self.files_dir):
            os.makedirs(self.files_dir)
            with open(os.path.join(self.files_dir, 'readme.txt'), 'w') as f:
                f.write('Embedded device configuration store.\n')

    def log_attack(self, event_type, details, **kw):
        if self.log_callback:
            self.log_callback('telnet', event_type, details, **kw)

    def _hook(self, name, *args, **kwargs):
        fn = self.hooks.get(name)
        if fn:
            try:
                return fn(*args, **kwargs)
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self):
        try:
            self.server_socket = bind_listener(self.port, backlog=5,
                                               protocol='telnet')
            self.running = True
            self.thread = Thread(target=self._run_server, daemon=True)
            self.thread.start()
            self.log_attack(
                'Server Started',
                "Telnet Honeypot on port %d | Banner: %r | Files: '%s'"
                % (self.port, self.server_banner.strip(), self.files_dir))
        except Exception as e:
            self.log_attack('Startup Error',
                            'Failed to start Telnet honeypot: %s' % e)
            raise

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.log_attack('Server Stopped',
                        'Telnet Honeypot on port %d stopped' % self.port)

    def _run_server(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client, address = self.server_socket.accept()
                except socket.timeout:
                    continue
                self.total_connections += 1
                Thread(target=self._handle_client, args=(client, address),
                       daemon=True).start()
            except OSError:
                if self.running:
                    continue
                break

    # ------------------------------------------------------------------
    # protocol helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _negotiate(sock):
        """Tell the client we will echo and suppress go-ahead."""
        sock.sendall(bytes([IAC, WILL, ECHO, IAC, WILL, SGA]))

    @staticmethod
    def _strip_iac(data):
        """Remove telnet command sequences, returning printable payload."""
        out = bytearray()
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == IAC:
                if i + 1 < len(data) and data[i + 1] == SB:
                    end = data.find(bytes([IAC, SE]), i)
                    i = (end + 2) if end != -1 else len(data)
                else:
                    i += 3          # IAC + verb + option
                continue
            out.append(byte)
            i += 1
        return bytes(out)

    def _readline(self, sock, pending, echo=True, mask=False, limit=200):
        """Read one CR/LF terminated line, handling IAC and backspace.

        `pending` is a bytearray of already-received, IAC-stripped bytes that
        outlives a single call. Bots and scanners routinely pipeline the whole
        session -- ``user\\r\\npass\\r\\ncmd\\r\\n`` -- into one packet; without a
        carry-over buffer every byte past the first newline would be dropped
        and the login/command stream would desync. Draining `pending` before
        touching the socket keeps every line.
        """
        buf = bytearray()
        while True:
            # Consume buffered bytes before blocking on another recv.
            while pending:
                byte = pending.pop(0)
                if byte in (13, 10):
                    if buf or byte == 13:
                        try:
                            sock.sendall(b'\r\n')
                        except OSError:
                            return None
                        return buf.decode('utf-8', errors='replace')
                    continue
                if byte in (8, 127):
                    if buf:
                        buf.pop()
                        if echo:
                            try:
                                sock.sendall(b'\b \b')
                            except OSError:
                                return None
                    continue
                if byte < 32 or len(buf) >= limit:
                    continue
                buf.append(byte)
                if echo:
                    try:
                        sock.sendall(b'*' if mask else bytes([byte]))
                    except OSError:
                        return None

            try:
                chunk = sock.recv(256)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            pending.extend(self._strip_iac(chunk))

    # ------------------------------------------------------------------
    # session
    # ------------------------------------------------------------------

    def _handle_client(self, sock, address):
        ip, src_port = address[0], address[1]
        session_key = '%s:%s' % (ip, src_port)
        started = time.time()
        sock.settimeout(120)

        session_id = self._hook('open_session', session_key, 'telnet', ip,
                                src_port)
        self.log_attack(
            'Connection Established',
            'New telnet connection #%d from %s' % (self.total_connections,
                                                   session_key),
            ip=ip, session_id=session_id)

        username = password = None
        commands = 0
        # One carry-over buffer for the whole session so pipelined lines
        # survive across the login prompts and the command loop.
        pending = bytearray()

        try:
            self._negotiate(sock)
            sock.sendall(self.server_banner.encode())

            # Mirai-family bots expect exactly this prompt pair.
            sock.sendall(b'%s login: ' % self.HOSTNAME.encode())
            username = self._readline(sock, pending)
            if username is None:
                return

            sock.sendall(b'Password: ')
            password = self._readline(sock, pending, mask=False, echo=False)
            if password is None:
                return

            self.auth_attempts += 1
            self.log_attack(
                'Credential Capture',
                "CREDENTIAL CAPTURED | %s | Username: '%s' | Password: '%s'"
                % (session_key, username, password),
                severity='crit', ip=ip, session_id=session_id, mitre='T1110')
            self._hook('credential', 'telnet', ip, username, password,
                       session_id)

            # Accept everything -- the point is to watch what they do next.
            sock.sendall(
                b'\r\n\r\nBusyBox v1.20.2 (2016-06-08) built-in shell (ash)\r\n'
                b'Enter \'help\' for a list of built-in commands.\r\n\r\n')
            self.log_attack('Login Success',
                            "%s | User '%s' accepted" % (session_key, username),
                            ip=ip, session_id=session_id)

            prompt = ('%s@%s:~# ' % (username or 'root', self.HOSTNAME)).encode()
            while self.running:
                sock.sendall(prompt)
                line = self._readline(sock, pending)
                if line is None:
                    break
                line = line.strip()
                if not line:
                    continue

                commands += 1
                self._hook('keystroke', session_id,
                           time.time() - started, line + '\n')
                self.log_attack(
                    'Shell Command',
                    "%s | COMMAND #%d | '%s'" % (session_key, commands, line),
                    severity='warn', ip=ip, session_id=session_id,
                    mitre='T1059')
                self._hook('command', 'telnet', ip, line, session_id)

                out = self._execute(line, ip, session_id)
                if out is None:
                    break
                if out:
                    sock.sendall(out.replace('\n', '\r\n').encode() + b'\r\n')

        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._hook('close_session', session_id, username, True, commands)
            self.log_attack(
                'Session Summary',
                'TELNET SESSION CLOSED | %s | Duration: %ds | User: %s |'
                ' Commands: %d' % (session_key, int(time.time() - started),
                                   username, commands),
                ip=ip, session_id=session_id)

    def _execute(self, command, ip, session_id):
        """BusyBox-flavoured responses. Returns None to close the session."""
        cmd = command.strip()
        low = cmd.lower()
        first = low.split()[0] if low.split() else ''

        if first in ('exit', 'quit', 'logout'):
            return None

        if first in ('ls', 'dir'):
            try:
                names = sorted(os.listdir(self.files_dir))
            except OSError:
                names = []
            return '  '.join(names) if names else ''

        if first == 'pwd':
            return '/'

        if first in ('whoami', 'id'):
            return ('uid=0(root) gid=0(root)' if first == 'id' else 'root')

        if first == 'uname':
            if '-a' in low:
                return ('Linux router 3.10.14 #1 SMP Mon Jan 20 12:00:00 UTC '
                        '2020 mips GNU/Linux')
            return 'Linux'

        if first == 'cat':
            target = cmd[4:].strip()
            base = os.path.realpath(self.files_dir)
            path = os.path.realpath(os.path.join(base, target))
            self.log_attack('File Access',
                            "%s | FILE READ ATTEMPT | '%s'" % (ip, target),
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1005')
            if path != base and not path.startswith(base + os.sep):
                self.log_attack('Path Traversal',
                                "%s | PATH TRAVERSAL | '%s'" % (ip, target),
                                severity='crit', ip=ip, session_id=session_id,
                                mitre='T1083')
                return 'cat: %s: No such file or directory' % target
            if os.path.isfile(path):
                try:
                    with open(path, 'r', errors='replace') as f:
                        return f.read()
                except OSError:
                    return 'cat: %s: Permission denied' % target
            return 'cat: %s: No such file or directory' % target

        # The payload-fetch verbs are the whole reason this sensor exists.
        if first in ('wget', 'curl', 'tftp', 'busybox'):
            url = ''
            for token in cmd.split()[1:]:
                if token.startswith(('http://', 'https://', 'ftp://')):
                    url = token
                    break
            if url:
                self.log_attack(
                    'Malware Download',
                    "%s | PAYLOAD FETCH | Command: '%s' | URL: '%s'"
                    % (ip, cmd, url),
                    severity='crit', ip=ip, session_id=session_id,
                    mitre='T1105')
                self._hook('payload', url, ip, session_id, first)
                return ('Connecting to %s... failed: Connection refused'
                        % url.split('/')[2] if '/' in url else 'failed')
            if first == 'busybox':
                return 'BusyBox v1.20.2 (2016-06-08) multi-call binary.'
            return '%s: missing URL' % first

        if first in ('rm', 'kill', 'killall'):
            self.log_attack('Delete Attempt',
                            "%s | DESTRUCTIVE COMMAND | '%s'" % (ip, cmd),
                            severity='crit', ip=ip, session_id=session_id,
                            mitre='T1070')
            return '%s: permission denied' % first

        if first in ('chmod', 'chown'):
            return ''

        # Persistence: dropping an SSH key or a cron entry to survive a reboot
        # or password change. Bots increasingly do this after the wget stage.
        if 'authorized_keys' in low:
            self.log_attack('SSH Key Persistence',
                            "%s | PERSISTENCE (ssh authorized_keys) | '%s'" % (ip, cmd),
                            severity='crit', ip=ip, session_id=session_id,
                            mitre='T1098')
            return ''

        if 'crontab' in low or '/etc/cron' in low:
            self.log_attack('Cron Persistence',
                            "%s | PERSISTENCE (scheduled task) | '%s'" % (ip, cmd),
                            severity='crit', ip=ip, session_id=session_id,
                            mitre='T1053')
            return ''

        if first == 'echo':
            return cmd[5:].strip().strip('"').strip("'")

        if first in ('help', '?'):
            return ('Built-in commands:\r\n  ls cat pwd echo uname whoami '
                    'wget id exit')

        if first in ('ps', 'top'):
            return ('  PID USER       VSZ STAT COMMAND\r\n'
                    '    1 root      1ether S    /sbin/init\r\n'
                    '  842 root      1240 S    /usr/sbin/telnetd')

        if first == 'cd':
            return ''

        self.log_attack('Unknown Command',
                        "%s | Unknown: '%s'" % (ip, cmd),
                        ip=ip, session_id=session_id)
        return '%s: applet not found' % first.split('/')[-1]


if __name__ == '__main__':
    def test_log(protocol, event_type, details, **kw):
        print('[%s] %s: %s' % (protocol.upper(), event_type, details))

    hp = TelnetHoneypot(port=2323, log_callback=test_log)
    hp.start()
    print('Telnet honeypot on 2323. Ctrl+C to stop.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hp.stop()
