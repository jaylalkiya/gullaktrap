"""
Attacker enrichment for GullakTrap: geolocation, network owner, threat tags.

Privacy note
------------
Enrichment sends attacker IP addresses to a third-party lookup service, so it
is OFF by default and must be switched on deliberately:

    set GULLAKTRAP_GEOIP=1        (Windows)
    export GULLAKTRAP_GEOIP=1     (Linux/macOS)

With it off, addresses are still classified locally -- private/loopback
ranges, and behavioural tags derived from data we captured ourselves -- so
the attacker views stay useful with no outbound traffic at all.
"""

import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request

import storage

# ip-api.com: no key required, ~45 requests/minute for free use.
GEO_ENDPOINT = ('http://ip-api.com/json/%s'
                '?fields=status,message,country,countryCode,city,lat,lon,'
                'as,org,proxy,hosting')
TOR_LIST = 'https://check.torproject.org/torbulkexitlist'

USER_AGENT = 'GullakTrap-Honeypot/2.0 (+research)'
TIMEOUT = 6

_worker = None
_stop = threading.Event()
_tor_exits = set()
_tor_fetched_at = 0


def enabled():
    """External lookups only happen when explicitly enabled."""
    return os.environ.get('GULLAKTRAP_GEOIP', '').strip().lower() in (
        '1', 'true', 'yes', 'on')


# ---------------------------------------------------------------------------
# local classification -- always available, never touches the network
# ---------------------------------------------------------------------------

def classify_local(ip):
    """Tags derivable without any external service."""
    tags = []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ['malformed']

    if addr.is_loopback:
        tags.append('loopback')
    elif addr.is_private:
        tags.append('private')
    elif addr.is_reserved or addr.is_multicast:
        tags.append('reserved')
    else:
        tags.append('public')
    return tags


def behavioural_tags(ip):
    """Tags inferred from what this address actually did to us.

    Cheap, honest signal that needs no third party: an address that hit
    several protocols is sweeping, one with many failed logins is brute
    forcing, one that tried to pull a payload is staging malware.
    """
    tags = []
    conn = storage.db()

    row = conn.execute('SELECT protocols, events FROM attackers WHERE ip=?',
                       (ip,)).fetchone()
    if row:
        protos = [p for p in (row['protocols'] or '').split(',') if p]
        if len(protos) >= 2:
            tags.append('multi-protocol')
        if (row['events'] or 0) >= 50:
            tags.append('high-volume')

    creds = conn.execute('SELECT COUNT(*) AS n FROM credentials WHERE ip=?',
                         (ip,)).fetchone()
    if creds and creds['n'] >= 10:
        tags.append('brute-force')

    pay = conn.execute('SELECT COUNT(*) AS n FROM payloads WHERE ip=?',
                       (ip,)).fetchone()
    if pay and pay['n']:
        tags.append('malware-staging')

    crit = conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE ip=? AND severity='crit'",
        (ip,)).fetchone()
    if crit and crit['n'] >= 5:
        tags.append('aggressive')

    return tags


# ---------------------------------------------------------------------------
# external lookups
# ---------------------------------------------------------------------------

def _fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode('utf-8', errors='replace')


def geolocate(ip):
    """Country/city/ASN for a public address, or {} on any failure."""
    if not enabled():
        return {}
    try:
        data = json.loads(_fetch(GEO_ENDPOINT % ip))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return {}

    if data.get('status') != 'success':
        return {}

    tags = []
    if data.get('proxy'):
        tags.append('proxy-vpn')
    if data.get('hosting'):
        tags.append('datacenter')

    return {
        'country': data.get('country'),
        'country_code': data.get('countryCode'),
        'city': data.get('city'),
        'lat': data.get('lat'),
        'lon': data.get('lon'),
        'asn': data.get('as'),
        'org': data.get('org'),
        'tags': tags,
    }


def refresh_tor_exits(max_age=6 * 3600):
    """Cache the Tor exit list; refreshed at most every six hours."""
    global _tor_exits, _tor_fetched_at
    if not enabled():
        return _tor_exits
    if _tor_exits and time.time() - _tor_fetched_at < max_age:
        return _tor_exits
    try:
        body = _fetch(TOR_LIST)
    except (urllib.error.URLError, OSError, TimeoutError):
        return _tor_exits
    _tor_exits = {line.strip() for line in body.splitlines() if line.strip()}
    _tor_fetched_at = time.time()
    return _tor_exits


def enrich(ip):
    """Full profile for one address. Safe to call with lookups disabled."""
    tags = classify_local(ip)
    result = {'tags': tags}

    if 'public' not in tags:
        result['country'] = 'Local network'
        result['tags'] = tags + behavioural_tags(ip)
        return result

    geo = geolocate(ip)
    result.update({k: v for k, v in geo.items() if k != 'tags'})
    tags = tags + geo.get('tags', []) + behavioural_tags(ip)

    if ip in refresh_tor_exits():
        tags.append('tor-exit')

    # dedupe but keep order, so the badge row reads consistently
    result['tags'] = list(dict.fromkeys(tags))
    return result


# ---------------------------------------------------------------------------
# background worker
# ---------------------------------------------------------------------------

def _loop(interval, log):
    while not _stop.is_set():
        try:
            for ip in storage.pending_enrichment(limit=10):
                if _stop.is_set():
                    break
                data = enrich(ip)
                storage.set_enrichment(ip, data)
                if log and data.get('tags'):
                    log('system', 'Attacker Enriched',
                        '%s -> %s%s' % (
                            ip,
                            data.get('country') or 'unknown',
                            ' [' + ', '.join(data['tags']) + ']'))
                # ip-api rate limits at roughly 45/min; stay well under it.
                if enabled():
                    _stop.wait(1.6)
        except Exception:
            # A background enricher must never take the console down.
            pass
        _stop.wait(interval)


def start_worker(interval=30, log=None):
    """Begin enriching addresses in the background (idempotent)."""
    global _worker
    if _worker and _worker.is_alive():
        return _worker
    _stop.clear()
    _worker = threading.Thread(target=_loop, args=(interval, log),
                               name='intel-worker', daemon=True)
    _worker.start()
    return _worker


def stop_worker():
    _stop.set()
