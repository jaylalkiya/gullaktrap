"""
Structured event storage for GullakTrap.

The original console kept events as formatted sentences in a list and a text
file, which made questions like "what are the ten most-tried passwords" a
log-parsing exercise. Everything is stored as columns here instead, so the
analytics views are ordinary queries.

Design notes
------------
* One SQLite file, WAL mode, so the honeypot threads can write while the
  dashboard reads without blocking each other.
* One connection per thread (sqlite3 objects are not shareable across
  threads), handed out through a thread-local.
* Writes are small and frequent, so each helper commits immediately rather
  than holding a transaction open across a captured session.
"""

import sqlite3
import threading
import time
from datetime import datetime, timedelta

_local = threading.local()
_db_path = None
_init_lock = threading.Lock()
_initialised = False


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key  TEXT    NOT NULL,           -- ip:port as seen by the sensor
    protocol     TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    src_port     INTEGER,
    started_at   REAL    NOT NULL,
    ended_at     REAL,
    duration     REAL,
    username     TEXT,
    authenticated INTEGER DEFAULT 0,
    command_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(session_key);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    ts         REAL NOT NULL,
    protocol   TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    ip         TEXT,
    details    TEXT,
    mitre      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    ts         REAL NOT NULL,
    protocol   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    username   TEXT,
    password   TEXT
);
CREATE INDEX IF NOT EXISTS idx_creds_pair ON credentials(username, password);
CREATE INDEX IF NOT EXISTS idx_creds_ip ON credentials(ip);

CREATE TABLE IF NOT EXISTS commands (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    ts         REAL NOT NULL,
    protocol   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    command    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cmds_session ON commands(session_id);

-- Keystroke stream for SSH session replay. `offset` is seconds since the
-- session opened, which is what makes playback reproduce original timing.
CREATE TABLE IF NOT EXISTS keystrokes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    offset     REAL    NOT NULL,
    stream     TEXT    NOT NULL,             -- 'in' (attacker) or 'out'
    data       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keys_session ON keystrokes(session_id, offset);

CREATE TABLE IF NOT EXISTS payloads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    ts         REAL NOT NULL,
    ip         TEXT,
    url        TEXT NOT NULL,
    method     TEXT,
    sha256     TEXT,
    size       INTEGER,
    stored_as  TEXT,
    status     TEXT
);
CREATE INDEX IF NOT EXISTS idx_payload_sha ON payloads(sha256);

-- One row per source address, kept up to date as events arrive so the
-- attacker views never have to aggregate the whole events table.
CREATE TABLE IF NOT EXISTS attackers (
    ip          TEXT PRIMARY KEY,
    first_seen  REAL,
    last_seen   REAL,
    events      INTEGER DEFAULT 0,
    sessions    INTEGER DEFAULT 0,
    protocols   TEXT,
    country     TEXT,
    country_code TEXT,
    city        TEXT,
    lat         REAL,
    lon         REAL,
    asn         TEXT,
    org         TEXT,
    threat_tags TEXT,
    enriched_at REAL
);
"""

# Columns added after the first release. SQLite has no "ADD COLUMN IF NOT
# EXISTS", so we diff PRAGMA table_info and add what an older database lacks.
_MIGRATIONS = {
    'attackers': {
        'lat': 'REAL',
        'lon': 'REAL',
    },
}


def _migrate(conn):
    for table, columns in _MIGRATIONS.items():
        have = {r['name'] for r in conn.execute(
            'PRAGMA table_info(%s)' % table).fetchall()}
        for name, decl in columns.items():
            if name not in have:
                conn.execute('ALTER TABLE %s ADD COLUMN %s %s'
                             % (table, name, decl))


# ---------------------------------------------------------------------------
# connection handling
# ---------------------------------------------------------------------------

def init(path):
    """Point storage at a database file and create the schema."""
    global _db_path, _initialised
    with _init_lock:
        _db_path = path
        conn = _connect()
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        _initialised = True
    return path


def _connect():
    conn = sqlite3.connect(_db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def db():
    """Thread-local connection. Sensors each run on their own thread."""
    if _db_path is None:
        raise RuntimeError('storage.init() has not been called')
    conn = getattr(_local, 'conn', None)
    if conn is None:
        conn = _local.conn = _connect()
    return conn


def close():
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        conn.close()
        _local.conn = None


# ---------------------------------------------------------------------------
# writes
# ---------------------------------------------------------------------------

def open_session(session_key, protocol, ip, src_port=None, started_at=None):
    started_at = started_at or time.time()
    conn = db()
    cur = conn.execute(
        'INSERT INTO sessions (session_key, protocol, ip, src_port, started_at)'
        ' VALUES (?,?,?,?,?)',
        (session_key, protocol, ip, src_port, started_at))
    conn.commit()
    _touch_attacker(ip, protocol, session=True)
    return cur.lastrowid


def close_session(session_id, username=None, authenticated=None,
                  command_count=None):
    if not session_id:
        return
    conn = db()
    row = conn.execute('SELECT started_at FROM sessions WHERE id=?',
                       (session_id,)).fetchone()
    now = time.time()
    duration = (now - row['started_at']) if row else None

    sets = ['ended_at=?', 'duration=?']
    args = [now, duration]
    if username is not None:
        sets.append('username=?'); args.append(username)
    if authenticated is not None:
        sets.append('authenticated=?'); args.append(1 if authenticated else 0)
    if command_count is not None:
        sets.append('command_count=?'); args.append(command_count)
    args.append(session_id)

    conn.execute('UPDATE sessions SET %s WHERE id=?' % ', '.join(sets), args)
    conn.commit()


def add_event(protocol, type_, details, severity='info', ip=None,
              session_id=None, mitre=None, ts=None):
    conn = db()
    cur = conn.execute(
        'INSERT INTO events (session_id, ts, protocol, type, severity, ip,'
        ' details, mitre) VALUES (?,?,?,?,?,?,?,?)',
        (session_id, ts or time.time(), protocol, type_, severity, ip,
         details, mitre))
    conn.commit()
    if ip:
        _touch_attacker(ip, protocol)
    return cur.lastrowid


def add_credential(protocol, ip, username, password, session_id=None):
    conn = db()
    conn.execute(
        'INSERT INTO credentials (session_id, ts, protocol, ip, username,'
        ' password) VALUES (?,?,?,?,?,?)',
        (session_id, time.time(), protocol, ip, username, password))
    conn.commit()


def add_command(protocol, ip, command, session_id=None):
    conn = db()
    conn.execute(
        'INSERT INTO commands (session_id, ts, protocol, ip, command)'
        ' VALUES (?,?,?,?,?)',
        (session_id, time.time(), protocol, ip, command))
    conn.commit()


def add_keystroke(session_id, offset, data, stream='in'):
    conn = db()
    conn.execute(
        'INSERT INTO keystrokes (session_id, offset, stream, data)'
        ' VALUES (?,?,?,?)', (session_id, offset, stream, data))
    conn.commit()


def add_payload(url, ip=None, session_id=None, method=None, sha256=None,
                size=None, stored_as=None, status='recorded'):
    conn = db()
    cur = conn.execute(
        'INSERT INTO payloads (session_id, ts, ip, url, method, sha256, size,'
        ' stored_as, status) VALUES (?,?,?,?,?,?,?,?,?)',
        (session_id, time.time(), ip, url, method, sha256, size, stored_as,
         status))
    conn.commit()
    return cur.lastrowid


def _touch_attacker(ip, protocol, session=False):
    """Keep the per-IP rollup current without rescanning the events table."""
    conn = db()
    now = time.time()
    row = conn.execute('SELECT protocols FROM attackers WHERE ip=?',
                       (ip,)).fetchone()
    if row is None:
        conn.execute(
            'INSERT INTO attackers (ip, first_seen, last_seen, events,'
            ' sessions, protocols) VALUES (?,?,?,?,?,?)',
            (ip, now, now, 1, 1 if session else 0, protocol))
    else:
        protos = set((row['protocols'] or '').split(',')) - {''}
        protos.add(protocol)
        conn.execute(
            'UPDATE attackers SET last_seen=?, events=events+1,'
            ' sessions=sessions+?, protocols=? WHERE ip=?',
            (now, 1 if session else 0, ','.join(sorted(protos)), ip))
    conn.commit()


def set_enrichment(ip, data):
    """Store GeoIP / threat-intel results for an address."""
    conn = db()
    conn.execute(
        'UPDATE attackers SET country=?, country_code=?, city=?, lat=?, lon=?,'
        ' asn=?, org=?, threat_tags=?, enriched_at=? WHERE ip=?',
        (data.get('country'), data.get('country_code'), data.get('city'),
         data.get('lat'), data.get('lon'),
         data.get('asn'), data.get('org'),
         ','.join(data.get('tags') or []), time.time(), ip))
    conn.commit()


def geo_points():
    """Enriched attackers that have coordinates, for the world attack map.

    Each point carries its event count and worst-seen severity so the map can
    size and colour the markers without a second query per address.
    """
    return _rows(
        "SELECT a.ip, a.lat, a.lon, a.city, a.country, a.country_code,"
        " a.events, a.protocols, a.threat_tags,"
        " (SELECT COUNT(*) FROM events e"
        "  WHERE e.ip=a.ip AND e.severity='crit') AS crit"
        " FROM attackers a"
        " WHERE a.lat IS NOT NULL AND a.lon IS NOT NULL"
        " ORDER BY a.events DESC LIMIT 500")


# ---------------------------------------------------------------------------
# analytics reads
# ---------------------------------------------------------------------------

def _rows(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]


def overview():
    conn = db()
    one = lambda sql, a=(): (conn.execute(sql, a).fetchone() or [0])[0]
    day_ago = time.time() - 86400
    return {
        'events': one('SELECT COUNT(*) FROM events'),
        'events_24h': one('SELECT COUNT(*) FROM events WHERE ts>?', (day_ago,)),
        'sessions': one('SELECT COUNT(*) FROM sessions'),
        'attackers': one('SELECT COUNT(*) FROM attackers'),
        'credentials': one('SELECT COUNT(*) FROM credentials'),
        'commands': one('SELECT COUNT(*) FROM commands'),
        'payloads': one('SELECT COUNT(*) FROM payloads'),
        'critical': one("SELECT COUNT(*) FROM events WHERE severity='crit'"),
    }


def top_attackers(limit=10):
    return _rows(
        'SELECT ip, events, sessions, protocols, first_seen, last_seen,'
        ' country, country_code, city, org, threat_tags'
        ' FROM attackers ORDER BY events DESC LIMIT ?', (limit,))


def top_credentials(limit=10):
    return _rows(
        'SELECT username, password, COUNT(*) AS hits,'
        ' COUNT(DISTINCT ip) AS sources'
        ' FROM credentials GROUP BY username, password'
        ' ORDER BY hits DESC LIMIT ?', (limit,))


def top_usernames(limit=10):
    return _rows(
        'SELECT username AS value, COUNT(*) AS hits FROM credentials'
        ' WHERE username IS NOT NULL AND username<>""'
        ' GROUP BY username ORDER BY hits DESC LIMIT ?', (limit,))


def top_passwords(limit=10):
    return _rows(
        'SELECT password AS value, COUNT(*) AS hits FROM credentials'
        ' WHERE password IS NOT NULL AND password<>""'
        ' GROUP BY password ORDER BY hits DESC LIMIT ?', (limit,))


def top_commands(limit=10):
    return _rows(
        'SELECT command AS value, COUNT(*) AS hits FROM commands'
        ' GROUP BY command ORDER BY hits DESC LIMIT ?', (limit,))


def protocol_breakdown():
    return _rows('SELECT protocol, COUNT(*) AS hits FROM events'
                 ' GROUP BY protocol ORDER BY hits DESC')


def severity_breakdown():
    return _rows('SELECT severity, COUNT(*) AS hits FROM events'
                 ' GROUP BY severity ORDER BY hits DESC')


def mitre_breakdown(limit=12):
    return _rows(
        'SELECT mitre, COUNT(*) AS hits FROM events'
        ' WHERE mitre IS NOT NULL AND mitre<>""'
        ' GROUP BY mitre ORDER BY hits DESC LIMIT ?', (limit,))


def timeline(hours=24):
    """Events per hour for the last `hours`, zero-filled so the chart is even."""
    since = time.time() - hours * 3600
    raw = {r['bucket']: r['hits'] for r in _rows(
        "SELECT strftime('%Y-%m-%d %H:00', ts, 'unixepoch', 'localtime')"
        " AS bucket, COUNT(*) AS hits FROM events WHERE ts>=?"
        " GROUP BY bucket", (since,))}

    out = []
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    for back in range(hours - 1, -1, -1):
        stamp = now - timedelta(hours=back)
        key = stamp.strftime('%Y-%m-%d %H:00')
        out.append({'hour': stamp.strftime('%H:00'), 'hits': raw.get(key, 0)})
    return out


def attacker(ip):
    row = db().execute('SELECT * FROM attackers WHERE ip=?', (ip,)).fetchone()
    if row is None:
        return None
    profile = dict(row)
    profile['recent_events'] = _rows(
        'SELECT ts, protocol, type, severity, details FROM events'
        ' WHERE ip=? ORDER BY ts DESC LIMIT 40', (ip,))
    profile['credentials'] = _rows(
        'SELECT username, password, protocol, ts FROM credentials'
        ' WHERE ip=? ORDER BY ts DESC LIMIT 30', (ip,))
    profile['commands'] = _rows(
        'SELECT command, ts FROM commands WHERE ip=? ORDER BY ts DESC LIMIT 30',
        (ip,))
    profile['sessions'] = _rows(
        'SELECT id, protocol, started_at, duration, username, authenticated,'
        ' command_count FROM sessions WHERE ip=? ORDER BY started_at DESC'
        ' LIMIT 20', (ip,))
    return profile


def sessions(limit=50, protocol=None, replayable_only=False):
    sql = ('SELECT s.id, s.protocol, s.ip, s.started_at, s.duration,'
           ' s.username, s.authenticated, s.command_count,'
           ' (SELECT COUNT(*) FROM keystrokes k WHERE k.session_id=s.id)'
           ' AS keystrokes FROM sessions s')
    where, args = [], []
    if protocol:
        where.append('s.protocol=?'); args.append(protocol)
    if replayable_only:
        where.append('(SELECT COUNT(*) FROM keystrokes k'
                     ' WHERE k.session_id=s.id) > 0')
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY s.started_at DESC LIMIT ?'
    args.append(limit)
    return _rows(sql, args)


def replay(session_id):
    meta = db().execute(
        'SELECT id, protocol, ip, started_at, duration, username,'
        ' command_count FROM sessions WHERE id=?', (session_id,)).fetchone()
    if meta is None:
        return None
    return {
        'session': dict(meta),
        'frames': _rows(
            'SELECT offset, stream, data FROM keystrokes WHERE session_id=?'
            ' ORDER BY offset ASC, id ASC', (session_id,)),
    }


def payloads(limit=50):
    return _rows(
        'SELECT id, ts, ip, url, method, sha256, size, stored_as, status'
        ' FROM payloads ORDER BY ts DESC LIMIT ?', (limit,))


def pending_enrichment(limit=25):
    """Addresses that have never been enriched, newest activity first."""
    return [r['ip'] for r in _rows(
        'SELECT ip FROM attackers WHERE enriched_at IS NULL'
        ' ORDER BY last_seen DESC LIMIT ?', (limit,))]


def export_rows(table, limit=5000):
    allowed = {'events', 'credentials', 'commands', 'sessions', 'attackers',
               'payloads'}
    if table not in allowed:
        raise ValueError('unknown table %r' % table)
    order = 'ts' if table in {'events', 'credentials', 'commands',
                              'payloads'} else 'rowid'
    return _rows('SELECT * FROM %s ORDER BY %s DESC LIMIT ?' % (table, order),
                 (limit,))
