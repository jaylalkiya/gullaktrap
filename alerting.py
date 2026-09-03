"""
Outbound alerting for GullakTrap.

A honeypot nobody watches catches nothing, so high-severity events can be
pushed to a webhook or a Telegram chat. Both are OFF unless configured --
alerting sends captured attack data to an external service, which should
always be a deliberate choice.

    GULLAKTRAP_WEBHOOK=https://hooks.example.com/...
    GULLAKTRAP_TG_TOKEN=123456:ABC...
    GULLAKTRAP_TG_CHAT=987654321
    GULLAKTRAP_ALERT_LEVEL=crit        (crit | warn -- default crit)

Delivery runs on its own queue thread: an alert must never slow down, or
block, the sensor that captured the event.
"""

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 8
USER_AGENT = 'GullakTrap-Honeypot/2.0'

_queue = queue.Queue(maxsize=500)
_worker = None
_stop = threading.Event()

# Per-event-type cooldown, so a brute-force run does not emit 400 alerts.
_last_sent = {}
COOLDOWN = 60.0

SEVERITY_RANK = {'info': 0, 'ok': 0, 'warn': 1, 'crit': 2}


def webhook_url():
    return os.environ.get('GULLAKTRAP_WEBHOOK', '').strip()


def telegram_config():
    return (os.environ.get('GULLAKTRAP_TG_TOKEN', '').strip(),
            os.environ.get('GULLAKTRAP_TG_CHAT', '').strip())


def min_level():
    return os.environ.get('GULLAKTRAP_ALERT_LEVEL', 'crit').strip().lower()


def configured():
    token, chat = telegram_config()
    return bool(webhook_url()) or bool(token and chat)


def status():
    token, chat = telegram_config()
    return {
        'enabled': configured(),
        'webhook': bool(webhook_url()),
        'telegram': bool(token and chat),
        'level': min_level(),
        'queued': _queue.qsize(),
    }


# ---------------------------------------------------------------------------
# transports
# ---------------------------------------------------------------------------

def _post_json(url, payload):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.status


def _send_webhook(alert):
    url = webhook_url()
    if not url:
        return
    _post_json(url, alert)


def _send_telegram(alert):
    token, chat = telegram_config()
    if not (token and chat):
        return
    text = (
        '*%s* on %s\n'
        '`%s`\n'
        'source: `%s`\n'
        '%s'
    ) % (alert['type'], alert['protocol'].upper(), alert['severity'],
         alert.get('ip') or 'unknown', alert['details'][:600])

    url = 'https://api.telegram.org/bot%s/sendMessage' % token
    data = urllib.parse.urlencode({
        'chat_id': chat, 'text': text, 'parse_mode': 'Markdown',
    }).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.status


# ---------------------------------------------------------------------------
# queue worker
# ---------------------------------------------------------------------------

def _loop():
    while not _stop.is_set():
        try:
            alert = _queue.get(timeout=1.0)
        except queue.Empty:
            continue
        for send in (_send_webhook, _send_telegram):
            try:
                send(alert)
            except (urllib.error.URLError, OSError, ValueError, TimeoutError):
                # Never retry forever and never surface to the sensor thread.
                pass
        _queue.task_done()


def start_worker():
    global _worker
    if _worker and _worker.is_alive():
        return _worker
    _stop.clear()
    _worker = threading.Thread(target=_loop, name='alert-worker', daemon=True)
    _worker.start()
    return _worker


def stop_worker():
    _stop.set()


def notify(protocol, type_, details, severity='info', ip=None, brand=''):
    """Queue an alert if it clears the configured threshold and cooldown."""
    if not configured():
        return False
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(min_level(), 2):
        return False

    key = (protocol, type_, ip)
    now = time.time()
    if now - _last_sent.get(key, 0) < COOLDOWN:
        return False
    _last_sent[key] = now

    alert = {
        'source': brand or 'GullakTrap',
        'protocol': protocol,
        'type': type_,
        'severity': severity,
        'ip': ip,
        'details': details,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    try:
        _queue.put_nowait(alert)
    except queue.Full:
        return False
    return True
