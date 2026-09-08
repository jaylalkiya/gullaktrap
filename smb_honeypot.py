"""
SMB honeypot for GullakTrap.

TCP/445 is one of the most attacked ports on the internet -- worms like
WannaCry and NotPetya spread over SMBv1 with the EternalBlue exploit, and
scanners constantly probe it. This is a low-interaction sensor: it frames
the NetBIOS/SMB messages an attacker sends, fingerprints the dialect
(flagging deprecated SMBv1), records share (Tree Connect) and logon
(Session Setup) attempts, and raises a critical alert on the Trans2/NT-Trans
traffic pattern EternalBlue uses -- without implementing the vulnerable
protocol itself.
"""

import socket
import time
from threading import Thread

from netutil import bind_listener

# SMB1 command codes (byte at offset 4 of the SMB header)
SMB1_CMDS = {
    0x72: 'Negotiate',
    0x73: 'Session Setup AndX',
    0x75: 'Tree Connect AndX',
    0x71: 'Tree Disconnect',
    0x25: 'Transaction',
    0x32: 'Transaction2',
    0xA0: 'NT Transact',
    0x2E: 'Read AndX',
    0x2F: 'Write AndX',
    0x04: 'Close',
    0x74: 'Logoff AndX',
}
# SMB2 command codes (2-byte LE at offset 12 of the SMB2 header)
SMB2_CMDS = {
    0x0000: 'Negotiate', 0x0001: 'Session Setup', 0x0002: 'Logoff',
    0x0003: 'Tree Connect', 0x0004: 'Tree Disconnect', 0x0005: 'Create',
    0x0006: 'Close', 0x0008: 'Read', 0x0009: 'Write',
}


class SMBHoneypot:

    BANNER_SUGGESTIONS = [
        'Windows Server 2008 R2 Standard 7601',
        'Windows 7 Professional 7601',
        'Samba 4.11.6-Ubuntu',
        'Windows Server 2012 R2',
    ]

    def __init__(self, port=445, log_callback=None, server_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.server_banner = server_banner or self.BANNER_SUGGESTIONS[0]
        self.files_dir = files_dir or 'smb_files'
        self.server_socket = None
        self.running = False
        self.thread = None
        self.hooks = session_hooks or {}
        self.total_connections = 0

    # ------------------------------------------------------------------
    def log_attack(self, event_type, details, **kw):
        if self.log_callback:
            self.log_callback('smb', event_type, details, **kw)

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
                                               protocol='smb')
            self.running = True
            self.thread = Thread(target=self._run_server, daemon=True)
            self.thread.start()
            self.log_attack('Server Started',
                            'SMB Honeypot on port %d | Pretending: %r'
                            % (self.port, self.server_banner))
        except Exception as e:
            self.log_attack('Startup Error',
                            'Failed to start SMB honeypot: %s' % e)
            raise

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.log_attack('Server Stopped',
                        'SMB Honeypot on port %d stopped' % self.port)

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
    def _read_msg(self, sock, pending):
        """Read one NetBIOS-framed SMB message (4-byte header + payload)."""
        while len(pending) < 4:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            pending.extend(chunk)
        length = int.from_bytes(pending[1:4], 'big')
        while len(pending) < 4 + length:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            pending.extend(chunk)
        msg = bytes(pending[4:4 + length])
        del pending[:4 + length]
        return msg

    def _handle_client(self, sock, address):
        ip, src_port = address[0], address[1]
        session_key = '%s:%s' % (ip, src_port)
        started = time.time()
        sock.settimeout(30)
        pending = bytearray()
        msgs = 0
        smbv1 = False

        session_id = self._hook('open_session', session_key, 'smb', ip,
                                src_port)
        self.log_attack('Connection Established',
                        'New SMB connection #%d from %s'
                        % (self.total_connections, session_key),
                        ip=ip, session_id=session_id, mitre='T1595')

        try:
            while self.running and msgs < 24:
                msg = self._read_msg(sock, pending)
                if msg is None:
                    break
                msgs += 1
                if len(msg) < 5:
                    continue

                if msg[:4] == b'\xffSMB':
                    smbv1 = True
                    self._inspect_smb1(msg, session_key, ip, session_id)
                elif msg[:4] == b'\xfeSMB':
                    self._inspect_smb2(msg, session_key, ip, session_id)
                else:
                    self.log_attack('Unknown Protocol',
                                    '%s | non-SMB payload on 445 (%d bytes)'
                                    % (session_key, len(msg)),
                                    ip=ip, session_id=session_id)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._hook('close_session', session_id, None, False, msgs)
            self.log_attack('Session Summary',
                            'SMB SESSION CLOSED | %s | Duration: %ds | Messages:'
                            ' %d | SMBv1: %s' % (session_key,
                                                 int(time.time() - started),
                                                 msgs, smbv1),
                            ip=ip, session_id=session_id)

    # ------------------------------------------------------------------
    def _inspect_smb1(self, msg, session_key, ip, session_id):
        cmd = msg[4]
        name = SMB1_CMDS.get(cmd, 'cmd 0x%02x' % cmd)

        self.log_attack('SMBv1 Detected',
                        "%s | SMBv1 %s (deprecated -- EternalBlue/WannaCry class)"
                        % (session_key, name),
                        severity='warn', ip=ip, session_id=session_id,
                        mitre='T1210')

        if cmd == 0x72:
            self.log_attack('SMB Negotiate',
                            "%s | SMBv1 dialect negotiation" % session_key,
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1190')
        elif cmd == 0x73:
            user = self._ntlm_user(msg)
            self.log_attack('Session Setup',
                            "%s | SMBv1 logon attempt%s"
                            % (session_key, (" (user '%s')" % user) if user else ''),
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1110')
            if user:
                self._hook('credential', 'smb', ip, user, '', session_id)
        elif cmd == 0x75:
            share = self._tree_share(msg)
            self.log_attack('Tree Connect',
                            "%s | connect to share %s"
                            % (session_key, share or '(unknown)'),
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1135')
        elif cmd in (0x32, 0xA0, 0x25):
            # Trans2 / NT-Trans is the traffic shape EternalBlue rides on.
            self.log_attack('EternalBlue Probe',
                            "%s | SMBv1 %s -- MS17-010 exploit pattern"
                            % (session_key, name),
                            severity='crit', ip=ip, session_id=session_id,
                            mitre='T1210')

    def _inspect_smb2(self, msg, session_key, ip, session_id):
        cmd = int.from_bytes(msg[12:14], 'little') if len(msg) >= 14 else -1
        name = SMB2_CMDS.get(cmd, 'cmd 0x%04x' % cmd)
        if cmd == 0x0000:
            self.log_attack('SMB Negotiate',
                            "%s | SMBv2/3 dialect negotiation" % session_key,
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1190')
        elif cmd == 0x0001:
            self.log_attack('Session Setup',
                            "%s | SMBv2 logon attempt" % session_key,
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1110')
        elif cmd == 0x0003:
            self.log_attack('Tree Connect',
                            "%s | SMBv2 share/tree connect" % session_key,
                            severity='warn', ip=ip, session_id=session_id,
                            mitre='T1135')
        else:
            self.log_attack('SMB Request',
                            "%s | SMBv2 %s" % (session_key, name),
                            ip=ip, session_id=session_id)

    # ------------------------------------------------------------------
    @staticmethod
    def _ntlm_user(msg):
        """Best-effort username lift from an NTLMSSP Type-3 blob."""
        i = msg.find(b'NTLMSSP\x00')
        if i == -1:
            return ''
        # Domain\User often survives as UTF-16LE ASCII text in the blob.
        tail = msg[i:]
        out = []
        j = 0
        while j < len(tail) - 1:
            c = tail[j]
            if 32 <= c <= 126 and tail[j + 1] == 0:
                out.append(chr(c)); j += 2
            else:
                if out:
                    out.append(' ')
                j += 1
        text = ''.join(out)
        for tok in text.split():
            if '\\' in tok or (tok.isalnum() and 2 < len(tok) < 24
                               and tok not in ('NTLMSSP',)):
                return tok
        return ''

    @staticmethod
    def _tree_share(msg):
        """Pull a \\\\host\\SHARE path out of a Tree Connect AndX."""
        for marker in (b'IPC$', b'ADMIN$', b'C$'):
            if marker in msg:
                return marker.decode()
        idx = msg.find(b'\\\\')
        if idx != -1:
            raw = msg[idx:idx + 80]
            ascii_txt = ''.join(chr(c) for c in raw if 32 <= c <= 126)
            return ascii_txt.split('\x00')[0][:48]
        return ''
