"""
Payload capture for GullakTrap.

When an attacker runs `wget http://.../bot.sh` inside a fake shell, the URL
itself is the most valuable artefact of the whole session. It is always
recorded. Actually downloading the file is a separate, deliberate decision:

    set GULLAKTRAP_FETCH_PAYLOADS=1

Downloading is off by default for good reasons -- it fetches attacker
controlled URLs from your host, and it writes live malware to your disk.
When it is on, samples land in quarantine/ named by SHA-256 with a .bin
suffix so nothing is executable by accident, size is capped, and redirects
are not followed.
"""

import hashlib
import os
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request

import storage

QUARANTINE_DIR = 'quarantine'
MAX_BYTES = 8 * 1024 * 1024      # 8 MB ceiling per sample
TIMEOUT = 10
USER_AGENT = 'Wget/1.20.3 (linux-gnu)'   # look like the tool they invoked


def fetching_enabled():
    return os.environ.get('GULLAKTRAP_FETCH_PAYLOADS', '').strip().lower() \
        in ('1', 'true', 'yes', 'on')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects -- they are a cheap way to point us somewhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_url(url):
    """Reject anything that is not a plain remote http/ftp fetch."""
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if parts.scheme not in ('http', 'https', 'ftp'):
        return False
    if not parts.hostname:
        return False

    # Never let a captured URL make us scan our own network.
    try:
        import ipaddress
        infos = socket.getaddrinfo(parts.hostname, None)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or addr.is_reserved
                    or addr.is_link_local):
                return False
    except (socket.gaierror, ValueError, OSError):
        return False
    return True


def _download(url, payload_id):
    """Fetch to quarantine. Runs on its own thread; never raises outward."""
    try:
        if not _safe_url(url):
            _update(payload_id, status='blocked')
            return

        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})

        digest = hashlib.sha256()
        chunks = []
        total = 0
        with opener.open(req, timeout=TIMEOUT) as resp:
            while total < MAX_BYTES:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                chunks.append(chunk)

        sha = digest.hexdigest()
        # .bin, never the attacker's extension -- nothing should be runnable.
        name = '%s.bin' % sha
        path = os.path.join(QUARANTINE_DIR, name)
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                for chunk in chunks:
                    f.write(chunk)

        _update(payload_id, sha256=sha, size=total, stored_as=name,
                status='captured')
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        _update(payload_id, status='unreachable')
    except Exception:
        _update(payload_id, status='error')


def _update(payload_id, **fields):
    if not payload_id or not fields:
        return
    sets = ', '.join('%s=?' % k for k in fields)
    args = list(fields.values()) + [payload_id]
    try:
        conn = storage.db()
        conn.execute('UPDATE payloads SET %s WHERE id=?' % sets, args)
        conn.commit()
    except Exception:
        pass


def record(url, ip=None, session_id=None, method=None):
    """Log the payload URL, and fetch it only if that was enabled.

    Returns the payloads row id so callers can correlate.
    """
    status = 'pending' if fetching_enabled() else 'recorded'
    payload_id = storage.add_payload(url, ip=ip, session_id=session_id,
                                     method=method, status=status)
    if fetching_enabled():
        threading.Thread(target=_download, args=(url, payload_id),
                         name='payload-fetch', daemon=True).start()
    return payload_id
