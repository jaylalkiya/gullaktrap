"""
SNMP honeypot for GullakTrap.

SNMP runs over UDP/161 and its "password" is the community string -- and the
whole internet is swept for agents that still answer to 'public' or 'private'.
This sensor parses the BER-encoded request just far enough to pull out the
community string (logged as a captured credential) and the PDU type, then
answers a GetRequest with a believable sysDescr so scanners like snmpwalk
see a live agent. A SetRequest -- an attempt to *write* device config -- is
flagged critical.
"""

import socket
import time
from threading import Thread

from netutil import apply_bind_policy, PortUnavailable, _explain

# BER / SNMP tags
SEQ = 0x30
INT = 0x02
OCTET = 0x04
GET_REQUEST = 0xA0
GET_NEXT = 0xA1
GET_RESPONSE = 0xA2
SET_REQUEST = 0xA3

PDU_NAMES = {
    GET_REQUEST: 'GetRequest',
    GET_NEXT: 'GetNextRequest',
    SET_REQUEST: 'SetRequest',
    0xA5: 'GetBulkRequest',
}


class SNMPHoneypot:

    BANNER_SUGGESTIONS = [
        'Linux gateway 5.4.0 #1 SMP x86_64',
        'Cisco IOS Software, C2960 Software',
        'HP ETHERNET MULTI-ENVIRONMENT',
        'RouterOS RB750',
    ]

    def __init__(self, port=161, log_callback=None, server_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.sys_descr = server_banner or self.BANNER_SUGGESTIONS[0]
        self.files_dir = files_dir or 'snmp_files'
        self.sock = None
        self.running = False
        self.thread = None
        self.hooks = session_hooks or {}
        self.total_connections = 0
        self._seen = set()

    # ------------------------------------------------------------------
    def log_attack(self, event_type, details, **kw):
        if self.log_callback:
            self.log_callback('snmp', event_type, details, **kw)

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
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            apply_bind_policy(sock)
            try:
                sock.bind(('0.0.0.0', int(self.port)))
            except OSError as exc:
                sock.close()
                raise PortUnavailable('SNMP sensor: '
                                      + _explain(int(self.port), exc))
            self.sock = sock
            self.running = True
            self.thread = Thread(target=self._run_server, daemon=True)
            self.thread.start()
            self.log_attack('Server Started',
                            'SNMP Honeypot on udp/%d | sysDescr: %r'
                            % (self.port, self.sys_descr))
        except Exception as e:
            self.log_attack('Startup Error',
                            'Failed to start SNMP honeypot: %s' % e)
            raise

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.log_attack('Server Stopped',
                        'SNMP Honeypot on udp/%d stopped' % self.port)

    def _run_server(self):
        while self.running:
            try:
                self.sock.settimeout(1.0)
                try:
                    data, addr = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
            except OSError:
                if self.running:
                    continue
                break
            self.total_connections += 1
            try:
                self._handle_packet(data, addr)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _handle_packet(self, data, addr):
        ip, src_port = addr[0], addr[1]
        session_key = '%s:%s' % (ip, src_port)
        parsed = self._parse(data)
        if not parsed:
            self.log_attack('Malformed Packet',
                            '%s | non-SNMP / unparsable udp payload (%d bytes)'
                            % (session_key, len(data)), ip=ip)
            return

        community, pdu_tag, req_id_tlv, first_oid = parsed
        pdu_name = PDU_NAMES.get(pdu_tag, 'PDU 0x%02x' % pdu_tag)

        if ip not in self._seen:
            self._seen.add(ip)
            self.log_attack('Connection Established',
                            'New SNMP source %s' % ip, ip=ip, mitre='T1595')

        # The community string is the credential.
        self.log_attack(
            'Community String',
            "%s | community '%s' | %s" % (session_key, community, pdu_name),
            severity='warn', ip=ip, mitre='T1110')
        self._hook('credential', 'snmp', ip, community, '', None)

        if pdu_tag == SET_REQUEST:
            self.log_attack(
                'SNMP Write',
                "%s | SetRequest with community '%s' (device tampering)"
                % (session_key, community),
                severity='crit', ip=ip, mitre='T1565')
        else:
            self.log_attack(
                'SNMP Query',
                "%s | %s (MIB dump / recon) community '%s'"
                % (session_key, pdu_name, community),
                severity='warn', ip=ip, mitre='T1602')

        # Answer GET/GETNEXT so the agent looks real.
        if pdu_tag in (GET_REQUEST, GET_NEXT) and req_id_tlv and first_oid:
            resp = self._build_response(community, req_id_tlv, first_oid)
            if resp:
                try:
                    self.sock.sendto(resp, addr)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # minimal BER
    # ------------------------------------------------------------------
    @staticmethod
    def _read_len(data, i):
        length = data[i]; i += 1
        if length & 0x80:
            n = length & 0x7f
            length = int.from_bytes(data[i:i + n], 'big'); i += n
        return length, i

    def _parse(self, data):
        """Return (community, pdu_tag, request_id_tlv_bytes, first_oid_tlv) or None."""
        try:
            i = 0
            if data[i] != SEQ:
                return None
            _, i = self._read_len(data, i + 1)
            # version INTEGER
            if data[i] != INT:
                return None
            vlen, i = self._read_len(data, i + 1); i += vlen
            # community OCTET STRING
            if data[i] != OCTET:
                return None
            clen, i = self._read_len(data, i + 1)
            community = data[i:i + clen].decode('utf-8', 'replace'); i += clen
            # PDU
            pdu_tag = data[i]
            _, i = self._read_len(data, i + 1)
            # request-id INTEGER (keep raw TLV to echo back verbatim)
            if data[i] != INT:
                return community, pdu_tag, None, None
            start = i
            rlen, j = self._read_len(data, i + 1)
            req_id_tlv = data[start:j + rlen]
            i = j + rlen
            # error-status INTEGER
            elen, i = self._read_len(data, i + 1); i += elen
            # error-index INTEGER
            xlen, i = self._read_len(data, i + 1); i += xlen
            # varbind list SEQUENCE
            if data[i] != SEQ:
                return community, pdu_tag, req_id_tlv, None
            _, i = self._read_len(data, i + 1)
            # first varbind SEQUENCE
            if data[i] != SEQ:
                return community, pdu_tag, req_id_tlv, None
            _, i = self._read_len(data, i + 1)
            # OID
            if data[i] != 0x06:
                return community, pdu_tag, req_id_tlv, None
            ostart = i
            olen, k = self._read_len(data, i + 1)
            first_oid = data[ostart:k + olen]
            return community, pdu_tag, req_id_tlv, first_oid
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _enc_len(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    def _tlv(self, tag, val):
        return bytes([tag]) + self._enc_len(len(val)) + val

    def _build_response(self, community, req_id_tlv, oid_tlv):
        try:
            value = self._tlv(OCTET, self.sys_descr.encode('utf-8', 'replace'))
            varbind = self._tlv(SEQ, oid_tlv + value)
            varbinds = self._tlv(SEQ, varbind)
            err_status = self._tlv(INT, b'\x00')
            err_index = self._tlv(INT, b'\x00')
            pdu = self._tlv(GET_RESPONSE,
                            req_id_tlv + err_status + err_index + varbinds)
            version = self._tlv(INT, b'\x00')          # SNMPv1
            comm = self._tlv(OCTET, community.encode('utf-8', 'replace'))
            return self._tlv(SEQ, version + comm + pdu)
        except Exception:
            return None
