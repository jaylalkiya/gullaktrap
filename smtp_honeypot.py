"""
SMTP honeypot for GullakTrap.

Mail servers on 25/465/587 draw two very common attacker behaviours:
credential brute force against AUTH LOGIN/PLAIN, and open-relay probing
(spammers testing whether they can bounce mail through you to a third
party). This low-interaction sensor speaks just enough ESMTP to make both
play out -- it advertises AUTH, decodes the base64 credentials attackers
submit, and flags any RCPT TO a domain that is not us as a relay attempt --
while never actually delivering a message.
"""

import base64
import socket
import time
from threading import Thread

from netutil import bind_listener


class SMTPHoneypot:

    BANNER_SUGGESTIONS = [
        'mail.example.com ESMTP Postfix (Ubuntu)',
        'mail.corp.local ESMTP Sendmail 8.15.2',
        'smtp.example.com ESMTP Exim 4.94',
        'EXCH01.corp.local Microsoft ESMTP MAIL Service',
    ]

    # We pretend to be responsible for this domain; RCPT TO anything else is
    # a relay attempt.
    LOCAL_DOMAIN = 'example.com'

    def __init__(self, port=25, log_callback=None, server_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.server_banner = server_banner or self.BANNER_SUGGESTIONS[0]
        self.files_dir = files_dir or 'smtp_files'
        self.server_socket = None
        self.running = False
        self.thread = None
        self.hooks = session_hooks or {}
        self.total_connections = 0

    # ------------------------------------------------------------------
    def log_attack(self, event_type, details, **kw):
        if self.log_callback:
            self.log_callback('smtp', event_type, details, **kw)

    def _hook(self, name, *args, **kwargs):
        fn = self.hooks.get(name)
        if fn:
            try:
                return fn(*args, **kwargs)
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------
    def start(self):
        try:
            self.server_socket = bind_listener(self.port, backlog=5,
                                               protocol='smtp')
            self.running = True
            self.thread = Thread(target=self._run_server, daemon=True)
            self.thread.start()
            self.log_attack('Server Started',
                            'SMTP Honeypot on port %d | Banner: %r'
                            % (self.port, self.server_banner))
        except Exception as e:
            self.log_attack('Startup Error',
                            'Failed to start SMTP honeypot: %s' % e)
            raise

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.log_attack('Server Stopped',
                        'SMTP Honeypot on port %d stopped' % self.port)

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
    def _readline(self, sock, pending, limit=1024):
        """One CRLF-terminated line, buffering leftover bytes across calls."""
        while True:
            nl = pending.find(b'\n')
            if nl != -1:
                line = pending[:nl]
                del pending[:nl + 1]
                return line.rstrip(b'\r').decode('utf-8', 'replace')
            if len(pending) > limit:
                line = bytes(pending[:limit]); pending.clear()
                return line.decode('utf-8', 'replace')
            try:
                chunk = sock.recv(1024)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            pending.extend(chunk)

    def _handle_client(self, sock, address):
        ip, src_port = address[0], address[1]
        session_key = '%s:%s' % (ip, src_port)
        started = time.time()
        sock.settimeout(60)
        pending = bytearray()
        helo = mailfrom = None
        rcpts = 0

        session_id = self._hook('open_session', session_key, 'smtp', ip,
                                src_port)
        self.log_attack('Connection Established',
                        'New SMTP connection #%d from %s'
                        % (self.total_connections, session_key),
                        ip=ip, session_id=session_id, mitre='T1595')

        try:
            sock.sendall(('220 %s\r\n' % self.server_banner).encode())
            while self.running:
                line = self._readline(sock, pending)
                if line is None:
                    break
                cmd = line.strip()
                if not cmd:
                    continue
                verb = cmd.split(' ')[0].upper()

                if verb == 'QUIT':
                    sock.sendall(b'221 2.0.0 Bye\r\n')
                    break

                elif verb in ('HELO', 'EHLO'):
                    helo = cmd[len(verb):].strip()
                    self.log_attack('Client Hello',
                                    "%s | %s %s" % (session_key, verb, helo),
                                    ip=ip, session_id=session_id, mitre='T1592')
                    if verb == 'EHLO':
                        host = self.server_banner.split(' ')[0]
                        sock.sendall(
                            ('250-%s\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n'
                             '250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 HELP\r\n'
                             % host).encode())
                    else:
                        sock.sendall(b'250 Hello\r\n')

                elif verb == 'AUTH':
                    self._handle_auth(sock, pending, cmd, session_key, ip,
                                      session_id)

                elif verb == 'MAIL':
                    mailfrom = self._addr(cmd)
                    self.log_attack('Mail From',
                                    "%s | MAIL FROM %s" % (session_key, mailfrom),
                                    ip=ip, session_id=session_id)
                    sock.sendall(b'250 2.1.0 Ok\r\n')

                elif verb == 'RCPT':
                    rcpts += 1
                    to = self._addr(cmd)
                    domain = to.split('@')[-1].lower().strip('>') if '@' in to else ''
                    if domain and self.LOCAL_DOMAIN not in domain:
                        self.log_attack(
                            'Open Relay Attempt',
                            "%s | relay to %s (from %s)" % (session_key, to, mailfrom),
                            severity='crit', ip=ip, session_id=session_id,
                            mitre='T1071.003')
                    else:
                        self.log_attack('Mail Recipient',
                                        "%s | RCPT TO %s" % (session_key, to),
                                        ip=ip, session_id=session_id)
                    sock.sendall(b'250 2.1.5 Ok\r\n')

                elif verb == 'DATA':
                    sock.sendall(b'354 End data with <CR><LF>.<CR><LF>\r\n')
                    body = self._read_data(sock, pending)
                    self.log_attack(
                        'Message Data',
                        "%s | %d bytes queued (spam/relay payload)"
                        % (session_key, len(body)),
                        severity='warn', ip=ip, session_id=session_id,
                        mitre='T1071.003')
                    sock.sendall(b'250 2.0.0 Ok: queued as 4A2F1C0\r\n')

                elif verb in ('VRFY', 'EXPN'):
                    self.log_attack(
                        'User Enumeration',
                        "%s | %s %s" % (session_key, verb, cmd[len(verb):].strip()),
                        severity='warn', ip=ip, session_id=session_id,
                        mitre='T1589')
                    sock.sendall(b'252 2.1.5 Cannot VRFY user\r\n')

                elif verb in ('RSET', 'NOOP'):
                    sock.sendall(b'250 2.0.0 Ok\r\n')

                elif verb == 'STARTTLS':
                    self.log_attack('STARTTLS Requested',
                                    "%s | STARTTLS" % session_key,
                                    ip=ip, session_id=session_id)
                    sock.sendall(b'454 4.7.0 TLS not available\r\n')

                else:
                    self.log_attack('Unknown Command',
                                    "%s | %s" % (session_key, cmd[:120]),
                                    ip=ip, session_id=session_id)
                    sock.sendall(b'502 5.5.2 Command not recognized\r\n')

        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._hook('close_session', session_id, helo, False, rcpts)
            self.log_attack('Session Summary',
                            'SMTP SESSION CLOSED | %s | Duration: %ds | HELO: %s'
                            ' | RCPTs: %d' % (session_key,
                                              int(time.time() - started),
                                              helo, rcpts),
                            ip=ip, session_id=session_id)

    # ------------------------------------------------------------------
    def _handle_auth(self, sock, pending, cmd, session_key, ip, session_id):
        parts = cmd.split(' ')
        mech = parts[1].upper() if len(parts) > 1 else ''
        user = passwd = ''

        if mech == 'LOGIN':
            # RFC 4954: server prompts (base64 'Username:'), client answers.
            if len(parts) > 2:
                user = self._b64(parts[2])
            else:
                sock.sendall(b'334 ' + base64.b64encode(b'Username:') + b'\r\n')
                user = self._b64(self._readline(sock, pending) or '')
            sock.sendall(b'334 ' + base64.b64encode(b'Password:') + b'\r\n')
            passwd = self._b64(self._readline(sock, pending) or '')

        elif mech == 'PLAIN':
            # authzid\0authcid\0passwd, base64-encoded, inline or next line.
            blob = parts[2] if len(parts) > 2 else (self._readline(sock, pending) or '')
            try:
                dec = base64.b64decode(blob + '===').decode('utf-8', 'replace')
                bits = dec.split('\x00')
                user, passwd = (bits[1], bits[2]) if len(bits) >= 3 else (dec, '')
            except Exception:
                user, passwd = blob, ''
        else:
            sock.sendall(b'504 5.5.4 Unrecognized authentication type\r\n')
            return

        self.log_attack(
            'Credential Capture',
            "CREDENTIAL CAPTURED | %s | AUTH %s | Username: '%s' | Password: '%s'"
            % (session_key, mech, user, passwd),
            severity='crit', ip=ip, session_id=session_id, mitre='T1110')
        self._hook('credential', 'smtp', ip, user, passwd, session_id)
        sock.sendall(b'535 5.7.8 Authentication credentials invalid\r\n')

    def _read_data(self, sock, pending, cap=65536):
        """Read a DATA body until the <CRLF>.<CRLF> terminator."""
        buf = bytearray()
        while len(buf) < cap:
            idx = pending.find(b'\r\n.\r\n')
            if idx != -1:
                buf.extend(pending[:idx]); del pending[:idx + 5]
                return bytes(buf)
            buf.extend(pending); pending.clear()
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            pending.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _addr(cmd):
        if ':' in cmd:
            return cmd.split(':', 1)[1].strip()
        return cmd.strip()

    @staticmethod
    def _b64(s):
        try:
            return base64.b64decode((s or '').strip() + '===').decode(
                'utf-8', 'replace')
        except Exception:
            return s or ''
