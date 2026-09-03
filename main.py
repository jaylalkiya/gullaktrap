"""
Freak-Pot Honeypot System with Authentication
A Joker-themed modular honeypot with HTTP, FTP, and SSH protocols
Enhanced with custom configuration and file upload support
"""

from flask import (Flask, render_template_string, jsonify, request,
                   session, redirect, url_for, Response)
from werkzeug.utils import secure_filename
from threading import Lock
from functools import wraps
import atexit
import csv
import io
import json
import re
from datetime import datetime
import os
import sys
import getpass

# Windows consoles and piped stdout (VS Code's runner, subprocess capture)
# default to cp1252, which cannot encode box drawing or status glyphs -- a
# single print would abort startup with UnicodeEncodeError. Force UTF-8 where
# the stream supports it and degrade to a replacement char rather than raising.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError, OSError):
        pass

# Import honeypot modules
from http_honeypot import HTTPHoneypot
from ftp_honeypot import FTPHoneypot
from ssh_honeypot import SSHHoneypot
from branding import BRAND, theme_css, console_banner
from telnet_honeypot import TelnetHoneypot
import storage
import intel
import alerting
import capture
from classify import classify, technique_name
from analytics_view import ANALYTICS_TEMPLATE
from report_view import REPORT_TEMPLATE

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# File upload configuration
UPLOAD_FOLDER = 'uploads'
FTP_FILES_FOLDER = 'ftp_files'
SSH_FILES_FOLDER = 'ssh_files'
TELNET_FILES_FOLDER = 'telnet_files'
ALLOWED_EXTENSIONS = {'html', 'htm', 'txt', 'pdf', 'doc', 'docx', 'zip', 'tar', 'gz', 'sql', 'conf', 'ini', 'log', 'key', 'pem', 'sh', 'py', 'js', 'json', 'xml', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['FTP_FILES_FOLDER'] = FTP_FILES_FOLDER
app.config['SSH_FILES_FOLDER'] = SSH_FILES_FOLDER
app.config['TELNET_FILES_FOLDER'] = TELNET_FILES_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max

# Create directories if they don't exist
for folder in [UPLOAD_FOLDER, FTP_FILES_FOLDER, SSH_FILES_FOLDER,
               TELNET_FILES_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Store honeypot instances
honeypots = {
    'http': None,
    'ftp': None,
    'ssh': None,
    'telnet': None
}

# Store logs
logs = []
MAX_LOGS = 1000

# Store credentials (will be set from CLI)
AUTH_USERNAME = None
AUTH_PASSWORD = None

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

LOG_FILE = '%s_logs.json' % BRAND['slug']
DB_FILE = '%s.db' % BRAND['slug']

_log_lock = Lock()
_log_seq = 0

# Matches a dotted-quad anywhere in a log sentence.
_IP_RE = re.compile(r"(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![0-9.])")


def _extract_ip(details):
    """Best-effort source address for sensors that only log a sentence."""
    match = _IP_RE.search(details or '')
    if not match:
        return None
    ip = match.group(1)
    # Startup lines say "Listening on 0.0.0.0:2121" -- that is our own bind
    # address, not a source, and it would show up as a phantom attacker.
    if ip in ('0.0.0.0', '255.255.255.255'):
        return None
    return ip


def _safe(fn, *args, **kwargs):
    """Storage failures must never break a live capture."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None


def log_event(protocol, event_type, details, severity=None, ip=None,
              session_id=None, mitre=None):
    """Central event sink: live feed, JSON file, database, alerting.

    Sensors call this from their own threads, so the sequence counter and
    the file append are both taken under the lock -- without it the JSON
    file interleaves partial lines under concurrent scans.

    Severity and the ATT&CK technique are derived here rather than in the
    browser, so the database, the alert threshold and the dashboard all
    agree on what counts as critical.
    """
    global _log_seq

    auto_sev, auto_mitre = classify(event_type)
    severity = severity or auto_sev
    mitre = mitre or auto_mitre
    if ip is None:
        ip = _extract_ip(details)

    with _log_lock:
        _log_seq += 1
        entry = {
            'id': _log_seq,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': protocol,
            'type': event_type,
            'details': details,
            'severity': severity,
            'ip': ip,
            'mitre': mitre,
            'technique': technique_name(mitre) if mitre else None,
        }
        logs.insert(0, entry)
        if len(logs) > MAX_LOGS:
            logs.pop()

        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except OSError:
            pass

    # Outside the lock: a slow disk or network must not stall a sensor.
    _safe(storage.add_event, protocol, event_type, details,
          severity=severity, ip=ip, session_id=session_id, mitre=mitre)
    _safe(alerting.notify, protocol, event_type, details,
          severity=severity, ip=ip, brand=BRAND['name'])


# Hooks handed to each sensor so they can record structured rows without
# importing storage themselves.
SESSION_HOOKS = {
    'open_session': lambda key, proto, ip, port=None: _safe(
        storage.open_session, key, proto, ip, port),
    'close_session': lambda sid, user=None, auth=None, count=None: _safe(
        storage.close_session, sid, user, auth, count),
    'credential': lambda proto, ip, user, pw, sid=None: _safe(
        storage.add_credential, proto, ip, user, pw, sid),
    'command': lambda proto, ip, cmd, sid=None: _safe(
        storage.add_command, proto, ip, cmd, sid),
    'keystroke': lambda sid, offset, data, stream='in': _safe(
        storage.add_keystroke, sid, offset, data, stream),
    'payload': lambda url, ip=None, sid=None, method=None: _safe(
        capture.record, url, ip, sid, method),
}

# Storage has to exist before any sensor can log into it, and both the
# enrichment and alert workers are idle until they have something to do.
storage.init(DB_FILE)
alerting.start_worker()
intel.start_worker(log=log_event)


@atexit.register
def _shutdown():
    """Stop the background workers and release the sensor ports on exit."""
    intel.stop_worker()
    alerting.stop_worker()
    for sensor in honeypots.values():
        if sensor is not None:
            try:
                sensor.stop()
            except Exception:
                pass
    storage.close()

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ brand.name }} | Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <style>{{ theme|safe }}</style>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        
        @keyframes grid-move {
            0% { background-position: 0 0; }
            100% { background-position: 50px 50px; }
        }
        
        @keyframes glow {
            0%, 100% { text-shadow: 0 0 5px var(--hot); }
            50% { text-shadow: 0 0 10px var(--hot), 0 0 15px var(--hot); }
        }
        
        @keyframes fade-in {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        
        body {
            background: var(--bg);
            font-family: 'Courier New', monospace;
            color: var(--hot);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(var(--hot-rgb), 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(var(--hot-rgb), 0.04) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            animation: grid-move 20s linear infinite;
            z-index: 1;
        }
        
        
        
        .login-container {
            position: relative;
            z-index: 10;
            background: var(--bg-2);
            border: 1px solid var(--hot);
            padding: 50px 40px;
            border-radius: 4px;
            max-width: 450px;
            width: 90%;
            box-shadow: 0 0 30px rgba(var(--hot-rgb), 0.20);
            animation: fade-in 0.8s ease-out;
        }
        
        .login-container::before,
        .login-container::after {
            content: '';
            position: absolute;
            width: 30px;
            height: 30px;
            border: 2px solid var(--hot);
        }
        
        .login-container::before {
            top: 15px;
            left: 15px;
            border-right: none;
            border-bottom: none;
        }
        
        .login-container::after {
            top: 15px;
            right: 15px;
            border-left: none;
            border-bottom: none;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .login-header h1 {
            font-size: 2.5em;
            color: var(--hot);
            letter-spacing: 8px;
            margin-bottom: 10px;
            animation: glow 3s ease-in-out infinite;
        }
        
        .login-header h1::before {
            content: '> ';
            opacity: 0.6;
        }
        
        .login-header h1::after {
            content: '_';
            animation: blink 1s step-end infinite;
            margin-left: 5px;
        }
        
        .login-header .subtitle {
            color: var(--hot-soft);
            font-size: 0.9em;
            font-style: italic;
            opacity: 0.8;
        }
        
        .joker-quote {
            transition: opacity .26s ease;
            text-align: center;
            color: var(--muted);
            font-size: 0.85em;
            margin-bottom: 30px;
            font-style: italic;
            padding: 10px;
            background: var(--bg);
            border-left: 3px solid var(--hot);
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            color: var(--muted);
            font-size: 0.9em;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        
        .form-group label::before {
            content: '>> ';
            color: var(--hot);
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            background: var(--bg);
            border: 1px solid var(--line-soft);
            color: var(--hot);
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--hot);
            box-shadow: 0 0 10px rgba(var(--hot-rgb), 0.20);
        }
        
        .btn-login {
            width: 100%;
            padding: 15px;
            background: transparent;
            border: 1px solid var(--hot);
            color: var(--hot);
            border-radius: 4px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            text-transform: uppercase;
            font-family: 'Courier New', monospace;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .btn-login::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(var(--hot-rgb), 0.20);
            transition: width 0.5s, height 0.5s, top 0.5s, left 0.5s;
            transform: translate(-50%, -50%);
        }
        
        .btn-login:hover::before {
            width: 500px;
            height: 500px;
        }
        
        .btn-login:hover {
            background: var(--hot);
            color: var(--bg);
            box-shadow: 0 0 20px rgba(var(--hot-rgb), 0.45);
        }
        
        .error-message {
            background: rgba(var(--alert-rgb), 0.10);
            border: 1px solid var(--alert);
            color: var(--alert);
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            text-align: center;
            animation: fade-in 0.3s ease-out;
        }
        
        .error-message::before {
            content: '⚠ ';
        }
        
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--hot);
            border-radius: 5px;
        }
    </style>
    <script src="{{ url_for('static', filename='fx.js') }}" defer></script>
</head>
<body>
    <canvas id="fx-matrix"></canvas>
    <div id="fx-scan"></div>
    <div id="fx-vignette"></div>
    
    <div class="login-container">
        <div class="login-header">
            <h1 class="wordmark" data-glitch="{{ brand.name }}">{{ brand.name }}</h1>
            <div class="brand-tag">{{ brand.tagline }} &middot; access control</div>
        </div>
        
        <div class="joker-quote">
            &gt; {{ brand.quotes[0] }}
        </div>
        
        {% if error %}
        <div class="error-message">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-login">Access System</button>
        </form>
    </div>
    
    <script>
document.addEventListener('DOMContentLoaded', function () {
            FX.matrix(document.getElementById('fx-matrix'));
        });
    </script>
</body>
</html>
"""

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ brand.name }} | {{ brand.subtitle }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <style>{{ theme|safe }}</style>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        
        @keyframes grid-move {
            0% { background-position: 0 0; }
            100% { background-position: 50px 50px; }
        }
        
        @keyframes glow {
            0%, 100% { text-shadow: 0 0 5px var(--hot); }
            50% { text-shadow: 0 0 10px var(--hot), 0 0 15px var(--hot); }
        }
        
        @keyframes typing {
            from { width: 0; }
            to { width: 100%; }
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        
        @keyframes slide-in {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes fade-in {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        body {
            background: var(--bg);
            font-family: 'Courier New', monospace;
            color: var(--hot);
            min-height: 100vh;
            padding: 20px 20px 60px 20px;
            line-height: 1.6;
            position: relative;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(var(--hot-rgb), 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(var(--hot-rgb), 0.04) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            animation: grid-move 20s linear infinite;
            z-index: 1;
        }
        
        
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            position: relative;
            z-index: 10;
        }
        
        .header {
            text-align: center;
            padding: 30px;
            background: var(--bg-2);
            border: 1px solid var(--hot);
            margin-bottom: 20px;
            border-radius: 4px;
            position: relative;
            box-shadow: 0 0 20px rgba(var(--hot-rgb), 0.10);
            animation: fade-in 0.8s ease-out;
        }
        
        .header::before,
        .header::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            border: 2px solid var(--hot);
        }
        
        .header::before {
            top: 10px;
            left: 10px;
            border-right: none;
            border-bottom: none;
        }
        
        .header::after {
            top: 10px;
            right: 10px;
            border-left: none;
            border-bottom: none;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: var(--hot);
            letter-spacing: 8px;
            margin-bottom: 10px;
            animation: glow 3s ease-in-out infinite;
            position: relative;
        }
        
        .header h1::before {
            content: '> ';
            opacity: 0.6;
        }
        
        .header h1::after {
            content: '_';
            animation: blink 1s step-end infinite;
            margin-left: 5px;
        }
        
        .header .tagline {
            color: var(--hot-soft);
            font-size: 1em;
            font-style: italic;
            opacity: 0.8;
        }
        
        .header .tagline::before,
        .header .tagline::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            border: 2px solid var(--hot);
        }
        
        .header .tagline::before {
            bottom: 10px;
            left: 10px;
            border-right: none;
            border-top: none;
        }
        
        .header .tagline::after {
            bottom: 10px;
            right: 10px;
            border-left: none;
            border-top: none;
        }
        
        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            padding: 8px 16px;
            background: transparent;
            border: 1px solid var(--alert);
            color: var(--alert);
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            font-family: 'Courier New', monospace;
            text-decoration: none;
            transition: all 0.3s;
            z-index: 100;
        }
        
        .logout-btn:hover {
            background: var(--alert);
            color: var(--bg);
            box-shadow: 0 0 15px rgba(var(--alert-rgb), 0.45);
        }
        
        .joker-quote {
            text-align: center;
            color: var(--muted);
            font-size: 0.95em;
            margin-bottom: 20px;
            font-style: italic;
            padding: 10px;
            background: var(--bg-2);
            border-left: 3px solid var(--hot);
            animation: slide-in 0.6s ease-out;
            position: relative;
            overflow: hidden;
        }
        
        .joker-quote::before {
            content: '';
            position: absolute;
            left: -100%;
            top: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(var(--hot-rgb), 0.10), transparent);
            animation: shimmer 3s infinite;
        }
        
        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-card {
            background: var(--bg-2);
            border: 1px solid var(--hot);
            padding: 20px;
            text-align: center;
            border-radius: 4px;
            position: relative;
            transition: all 0.3s ease;
            animation: fade-in 0.5s ease-out backwards;
        }
        
        .stat-card:nth-child(1) { animation-delay: 0.1s; }
        .stat-card:nth-child(2) { animation-delay: 0.2s; }
        .stat-card:nth-child(3) { animation-delay: 0.3s; }
        .stat-card:nth-child(4) { animation-delay: 0.4s; }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--hot), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(var(--hot-rgb), 0.20);
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-number {
            font-size: 2.5em;
            color: var(--hot);
            font-weight: bold;
            text-shadow: 0 0 10px rgba(var(--hot-rgb), 0.45);
        }
        
        .stat-label {
            color: var(--muted);
            font-size: 0.9em;
            margin-top: 8px;
            text-transform: uppercase;
        }
        
        .controls {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }
        
        .control-card {
            background: var(--bg-2);
            border: 1px solid var(--hot);
            padding: 25px;
            border-radius: 4px;
            position: relative;
            transition: all 0.3s ease;
            animation: slide-in 0.6s ease-out backwards;
            overflow: hidden;
        }
        
        .control-card:nth-child(1) { animation-delay: 0.2s; }
        .control-card:nth-child(2) { animation-delay: 0.3s; }
        .control-card:nth-child(3) { animation-delay: 0.4s; }
        
        .control-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 0;
            background: var(--hot);
            transition: height 0.3s ease;
            z-index: 1;
        }
        
        .control-card::after {
            content: '01001010';
            position: absolute;
            top: 10px;
            right: 10px;
            font-size: 0.7em;
            color: rgba(var(--hot-rgb), 0.10);
            letter-spacing: 2px;
            pointer-events: none;
        }
        
        .control-card:hover {
            border-color: var(--hot);
            box-shadow: 0 0 20px rgba(var(--hot-rgb), 0.15);
        }
        
        .control-card:hover::before {
            height: 100%;
        }
        
        .control-card:hover::after {
            color: rgba(var(--hot-rgb), 0.20);
        }
        
        .control-card h2 {
            color: var(--hot);
            font-size: 1.5em;
            margin-bottom: 15px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--line-soft);
            padding-bottom: 10px;
            position: relative;
        }
        
        .control-card h2::before {
            content: '>> ';
            color: var(--hot);
            opacity: 0.6;
        }
        
        .status {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            font-size: 1em;
            padding: 10px;
            background: var(--bg);
            border-radius: 4px;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
            position: relative;
        }
        
        .status-dot::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 100%;
            height: 100%;
            border-radius: 50%;
            animation: pulse-ring 2s ease-out infinite;
        }
        
        @keyframes pulse-ring {
            0% {
                width: 100%;
                height: 100%;
                opacity: 0.8;
            }
            100% {
                width: 200%;
                height: 200%;
                opacity: 0;
            }
        }
        
        .status-dot.active {
            background: var(--hot);
            box-shadow: 0 0 10px var(--hot);
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        
        .status-dot.active::before {
            box-shadow: 0 0 10px var(--hot);
        }
        
        .status-dot.inactive {
            background: var(--alert);
            box-shadow: 0 0 8px var(--alert);
        }
        
        .status-dot.inactive::before {
            box-shadow: 0 0 8px var(--alert);
        }
        
        .btn {
            padding: 10px 20px;
            border: 1px solid var(--hot);
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: bold;
            margin: 5px;
            transition: all 0.3s;
            text-transform: uppercase;
            background: transparent;
            font-family: 'Courier New', monospace;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(var(--hot-rgb), 0.20);
            transition: width 0.5s, height 0.5s, top 0.5s, left 0.5s;
            transform: translate(-50%, -50%);
        }
        
        .btn:hover::before {
            width: 300px;
            height: 300px;
        }
        
        .btn-start {
            color: var(--hot);
            border-color: var(--hot);
        }
        
        .btn-start:hover {
            background: var(--hot);
            color: var(--bg);
            box-shadow: 0 0 15px rgba(var(--hot-rgb), 0.45);
        }
        
        .btn-stop {
            color: var(--alert);
            border-color: var(--alert);
        }
        
        .btn-stop:hover {
            background: var(--alert);
            color: var(--bg);
            box-shadow: 0 0 15px rgba(var(--alert-rgb), 0.45);
        }
        
        .config {
            margin-top: 15px;
        }
        
        .config-label {
            color: var(--muted);
            font-size: 0.9em;
            margin-top: 12px;
            margin-bottom: 5px;
            display: block;
        }
        
        .config input, .config select, .config textarea {
            width: 100%;
            padding: 8px;
            margin: 5px 0;
            background: var(--bg);
            border: 1px solid var(--line-soft);
            color: var(--hot);
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .config input:focus, .config select:focus, .config textarea:focus {
            outline: none;
            border-color: var(--hot);
        }
        
        .config textarea {
            min-height: 60px;
            resize: vertical;
        }
        
        .config select option {
            background: var(--bg);
            color: var(--hot);
        }
        
        .banner-hint {
            color: var(--dim);
            font-size: 0.85em;
            margin-top: 5px;
        }
        
        .http-advanced, .ftp-advanced, .ssh-advanced {
            background: var(--bg);
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
            border: 1px solid var(--line-soft);
        }
        
        .file-list {
            max-height: 100px;
            overflow-y: auto;
            margin-top: 10px;
            padding: 8px;
            background: var(--bg);
            border-radius: 4px;
            border: 1px solid var(--line-soft);
        }
        
        .file-item {
            padding: 6px;
            margin: 4px 0;
            background: var(--bg-2);
            border-radius: 3px;
            font-size: 0.85em;
            border-left: 2px solid var(--hot);
        }
        
        .logs-section {
            background: var(--bg-2);
            border: 1px solid var(--hot);
            padding: 25px;
            border-radius: 4px;
            position: relative;
            animation: fade-in 0.8s ease-out 0.5s backwards;
        }
        
        .logs-section::before,
        .logs-section::after {
            content: '';
            position: absolute;
            width: 30px;
            height: 30px;
            border: 2px solid var(--hot);
        }
        
        .logs-section::before {
            top: 15px;
            left: 15px;
            border-right: none;
            border-bottom: none;
        }
        
        .logs-section::after {
            top: 15px;
            right: 15px;
            border-left: none;
            border-bottom: none;
        }
        
        .logs-section h2 {
            color: var(--hot);
            font-size: 1.5em;
            margin-bottom: 20px;
            text-align: center;
            text-transform: uppercase;
            border-bottom: 1px solid var(--line-soft);
            padding-bottom: 10px;
            animation: glow 3s ease-in-out infinite;
            position: relative;
        }
        
        .logs-section h2::before {
            content: '[';
            margin-right: 10px;
        }
        
        .logs-section h2::after {
            content: ']';
            margin-left: 10px;
        }
        
        .logs-section h2 .live-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: var(--alert);
            border-radius: 50%;
            margin-left: 15px;
            animation: live-blink 1s ease-in-out infinite;
            box-shadow: 0 0 10px var(--alert);
        }
        
        @keyframes live-blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .logs-container {
            max-height: 500px;
            overflow-y: auto;
            background: var(--bg);
            padding: 15px;
            border-radius: 4px;
            border: 1px solid var(--line-soft);
            position: relative;
        }
        
        .logs-container::before,
        .logs-container::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            border: 2px solid var(--hot);
            opacity: 0.3;
        }
        
        .logs-container::before {
            bottom: 15px;
            left: 15px;
            border-right: none;
            border-top: none;
        }
        
        .logs-container::after {
            bottom: 15px;
            right: 30px;
            border-left: none;
            border-top: none;
        }
        
        .log-entry {
            padding: 10px;
            margin: 8px 0;
            border-left: 3px solid;
            background: var(--bg-2);
            border-radius: 3px;
            font-size: 0.9em;
            animation: log-stream 0.5s ease-out;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }
        
        @keyframes log-stream {
            0% {
                max-height: 0;
                opacity: 0;
                transform: translateY(-10px);
                margin: 0;
                padding: 0 10px;
            }
            50% {
                opacity: 0.5;
            }
            100% {
                max-height: 100px;
                opacity: 1;
                transform: translateY(0);
                margin: 8px 0;
                padding: 10px;
            }
        }
        
        .log-entry::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 3px;
            background: currentColor;
            animation: log-flash 0.5s ease-out;
        }
        
        @keyframes log-flash {
            0%, 50% {
                box-shadow: 0 0 10px currentColor, 0 0 20px currentColor;
            }
            100% {
                box-shadow: none;
            }
        }
        
        .log-entry:hover {
            background: rgba(var(--hot-rgb), 0.05);
            transform: translateX(5px);
            box-shadow: -3px 0 0 var(--hot);
        }
        
        .log-entry.http { border-left-color: var(--hot); }
        .log-entry.ftp { border-left-color: var(--hot-soft); }
        .log-entry.ssh { border-left-color: var(--hot-soft); }
        
        .log-timestamp {
            color: var(--dim);
            font-weight: bold;
        }
        
        .log-protocol {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 0 5px;
            box-shadow: 0 0 5px currentColor;
            animation: protocol-pulse 0.5s ease-out;
        }
        
        @keyframes protocol-pulse {
            0% {
                transform: scale(1.3);
                box-shadow: 0 0 15px currentColor;
            }
            100% {
                transform: scale(1);
                box-shadow: 0 0 5px currentColor;
            }
        }
        
        .log-protocol.http { background: var(--line); color: var(--hot); }
        .log-protocol.ftp { background: var(--line); color: var(--hot-soft); }
        .log-protocol.ssh { background: var(--line); color: var(--hot-soft); }
        
        .log-entry.new-entry {
            animation: log-stream 0.5s ease-out, highlight-new 3s ease-out;
        }
        
        @keyframes highlight-new {
            0% {
                background: rgba(var(--hot-rgb), 0.20);
            }
            100% {
                background: var(--bg-2);
            }
        }
        
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--hot);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--hot-soft);
        }
        
        input[type="file"]::file-selector-button {
            background: transparent;
            color: var(--hot);
            border: 1px solid var(--hot);
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
            font-family: 'Courier New', monospace;
        }
        
        input[type="file"]::file-selector-button:hover {
            background: var(--hot);
            color: var(--bg);
        }
        
        .system-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: var(--bg-2);
            border-top: 1px solid var(--hot);
            padding: 8px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.85em;
            z-index: 1000;
            box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.5);
        }
        
        .system-bar-item {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--hot);
        }
        
        .system-bar-item .indicator {
            width: 6px;
            height: 6px;
            background: var(--hot);
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }
        
        .system-bar-time {
            color: var(--muted);
            font-family: 'Courier New', monospace;
        }
    </style>
    <script src="{{ url_for('static', filename='fx.js') }}" defer></script>
</head>
<body>
    <canvas id="fx-matrix"></canvas>
    <div id="fx-scan"></div>
    <div id="fx-vignette"></div>
    
    <div id="boot"></div>

    <div class="container">
        <div class="header">
            <a href="{{ url_for('analytics_page') }}" class="logout-btn"
               style="right:110px;border-color:var(--hot);color:var(--hot)">INTEL</a>
            <a href="{{ url_for('logout') }}" class="logout-btn">LOGOUT</a>
            <h1 class="wordmark" data-glitch="{{ brand.name }}">{{ brand.name }}</h1>
            <div class="brand-tag">{{ brand.tagline }} &middot; {{ brand.subtitle }} {{ brand.version }}</div>
        </div>
        
        <div class="joker-quote" id="quote">
            > Madness is like gravity... all it takes is a little push!
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-attacks">0</div>
                <canvas class="stat-spark" id="spark-total" data-color-var="--info"></canvas>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="http-attacks">0</div>
                <canvas class="stat-spark" id="spark-http" data-color-var="--http"></canvas>
                <div class="stat-label">HTTP Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="ftp-attacks">0</div>
                <canvas class="stat-spark" id="spark-ftp" data-color-var="--ftp"></canvas>
                <div class="stat-label">FTP Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="ssh-attacks">0</div>
                <canvas class="stat-spark" id="spark-ssh" data-color-var="--ssh"></canvas>
                <div class="stat-label">SSH Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="telnet-attacks">0</div>
                <canvas class="stat-spark" id="spark-telnet" data-color-var="--telnet"></canvas>
                <div class="stat-label">Telnet Attacks</div>
            </div>
        </div>
        
        <div class="controls">
            <div class="control-card">
                <h2>HTTP Honeypot</h2>
                <div class="status">
                    <div class="status-dot inactive" id="http-status"></div>
                    <span id="http-status-text">Inactive</span>
                </div>
                <button class="btn btn-start" onclick="startHoneypot('http')">Start</button>
                <button class="btn btn-stop" onclick="stopHoneypot('http')">Stop</button>
                
                <div class="config">
                    <label class="config-label">Port Number</label>
                    <input type="number" id="http-port" placeholder="Port" value="8080">
                    
                    <div class="http-advanced">
                        <label class="config-label">Server Banner</label>
                        <select id="http-banner">
                            <option value="Apache/2.4.41 (Ubuntu)">Apache/2.4.41 (Ubuntu)</option>
                            <option value="Apache/2.2.15 (CentOS)">Apache/2.2.15 (CentOS) - Old vulnerable</option>
                            <option value="Microsoft-IIS/7.5">Microsoft-IIS/7.5</option>
                            <option value="Microsoft-IIS/6.0">Microsoft-IIS/6.0 - Very vulnerable</option>
                            <option value="nginx/1.10.3">nginx/1.10.3</option>
                            <option value="Apache/2.0.52 (Red Hat)">Apache/2.0.52 (Red Hat) - Ancient</option>
                            <option value="custom">Custom Banner...</option>
                        </select>
                        <input type="text" id="http-banner-custom" placeholder="Enter custom banner..." style="display:none; margin-top:10px;">
                        <div class="banner-hint">> Older versions attract more attacks</div>
                        
                        <label class="config-label" style="margin-top: 15px;">Custom HTML File</label>
                        <input type="file" id="http-html-file" accept=".html,.htm" onchange="uploadHTMLFile(this)">
                        <select id="http-html-select" style="margin-top: 10px;">
                            <option value="">-- Default HTML --</option>
                        </select>
                        <div class="banner-hint">> Upload or select your custom HTML page</div>
                    </div>
                </div>
            </div>
            
            <div class="control-card">
                <h2>FTP Honeypot</h2>
                <div class="status">
                    <div class="status-dot inactive" id="ftp-status"></div>
                    <span id="ftp-status-text">Inactive</span>
                </div>
                <button class="btn btn-start" onclick="startHoneypot('ftp')">Start</button>
                <button class="btn btn-stop" onclick="stopHoneypot('ftp')">Stop</button>
                
                <div class="config">
                    <label class="config-label">Port Number</label>
                    <input type="number" id="ftp-port" placeholder="Port" value="2121">
                    
                    <div class="ftp-advanced">
                        <label class="config-label">FTP Server Banner</label>
                        <select id="ftp-banner">
                            <option value="220 Welcome to FreakPot FTP Server (vsFTPd 3.0.3)">vsFTPd 3.0.3</option>
                            <option value="220 ProFTPD 1.3.3c Server (Debian)">ProFTPD 1.3.3c - Old</option>
                            <option value="220 Microsoft FTP Service">Microsoft FTP</option>
                            <option value="220 (vsFTPD 2.3.4)">vsFTPD 2.3.4 - Backdoor!</option>
                            <option value="220 FileZilla Server 0.9.41 beta">FileZilla 0.9.41</option>
                            <option value="220 wu-ftpd 2.6.0">wu-ftpd 2.6.0 - Ancient</option>
                            <option value="custom">Custom Banner...</option>
                        </select>
                        <input type="text" id="ftp-banner-custom" placeholder="Enter custom FTP banner..." style="display:none; margin-top:10px;">
                        <div class="banner-hint">> vsFTPD 2.3.4 is famous for backdoor</div>
                        
                        <label class="config-label" style="margin-top: 15px;">Upload Fake Files</label>
                        <input type="file" id="ftp-file-upload" multiple onchange="uploadFTPFiles(this)">
                        <div class="banner-hint">> Upload files to show in FTP listings</div>
                        
                        <div class="file-list" id="ftp-files-list" style="margin-top: 10px;">
                            <div style="text-align: center; color: var(--dim); font-size: 0.85em;">No files uploaded yet</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="control-card">
                <h2>SSH Honeypot</h2>
                <div class="status">
                    <div class="status-dot inactive" id="ssh-status"></div>
                    <span id="ssh-status-text">Inactive</span>
                </div>
                <button class="btn btn-start" onclick="startHoneypot('ssh')">Start</button>
                <button class="btn btn-stop" onclick="stopHoneypot('ssh')">Stop</button>
                
                <div class="config">
                    <label class="config-label">Port Number</label>
                    <input type="number" id="ssh-port" placeholder="Port" value="2222">
                    
                    <div class="ssh-advanced">
                        <label class="config-label">SSH Server Banner</label>
                        <select id="ssh-banner">
                            <option value="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5">OpenSSH 8.2p1 Ubuntu</option>
                            <option value="SSH-2.0-OpenSSH_7.4">OpenSSH 7.4 - Older</option>
                            <option value="SSH-2.0-OpenSSH_5.3">OpenSSH 5.3 - Very old</option>
                            <option value="SSH-2.0-libssh-0.7.0">libssh 0.7.0 - Has CVEs</option>
                            <option value="SSH-2.0-dropbear_2014.63">Dropbear 2014</option>
                            <option value="SSH-2.0-Cisco-1.25">Cisco SSH</option>
                            <option value="SSH-2.0-ROSSSH">MikroTik RouterOS</option>
                            <option value="custom">Custom Banner...</option>
                        </select>
                        <input type="text" id="ssh-banner-custom" placeholder="Enter custom SSH banner..." style="display:none; margin-top:10px;">
                        <div class="banner-hint">> OpenSSH 5.3 has known vulnerabilities</div>
                        
                        <label class="config-label" style="margin-top: 15px;">Upload Fake Files</label>
                        <input type="file" id="ssh-file-upload" multiple onchange="uploadSSHFiles(this)">
                        <div class="banner-hint">> Upload files for SSH filesystem simulation</div>
                        
                        <div class="file-list" id="ssh-files-list" style="margin-top: 10px;">
                            <div style="text-align: center; color: var(--dim); font-size: 0.85em;">No files uploaded yet</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="control-card">
                <h2>Telnet Honeypot</h2>
                <div class="status">
                    <div class="status-dot inactive" id="telnet-status"></div>
                    <span id="telnet-status-text">Inactive</span>
                </div>
                <button class="btn btn-start" onclick="startHoneypot('telnet')">Start</button>
                <button class="btn btn-stop" onclick="stopHoneypot('telnet')">Stop</button>

                <div class="config">
                    <label class="config-label">Port Number</label>
                    <input type="number" id="telnet-port" placeholder="Port" value="2323">

                    <label class="config-label">Device Banner</label>
                    <select id="telnet-banner">
                        <option value="&#13;&#10;DD-WRT v24-sp2 std (c) 2020 NewMedia-NET GmbH&#13;&#10;">DD-WRT Router</option>
                        <option value="&#13;&#10;BusyBox v1.20.2 (2016-06-08) built-in shell (ash)&#13;&#10;">BusyBox 1.20.2</option>
                        <option value="&#13;&#10;OpenWrt 19.07.7, r11306-c4a6851c72&#13;&#10;">OpenWrt 19.07</option>
                        <option value="&#13;&#10;Huawei Home Gateway&#13;&#10;">Huawei Gateway</option>
                        <option value="&#13;&#10;ZTE Corporation. All rights reserved.&#13;&#10;">ZTE Device</option>
                        <option value="custom">Custom Banner...</option>
                    </select>
                    <input type="text" id="telnet-banner-custom" placeholder="Enter custom telnet banner..." style="display:none; margin-top:10px;">
                    <div class="banner-hint">&gt; Telnet draws the most IoT botnet traffic of any port</div>
                </div>
            </div>
        </div>

        <div class="control-card" style="margin-bottom:20px; border:1px solid var(--danger, #d43); box-shadow:0 0 18px rgba(210,60,50,.25);">
            <h2 style="display:flex; align-items:center; gap:8px;">
                <span>&#9876;</span> Red Team &mdash; Attack Simulator
            </h2>
            <p style="color: var(--dim, #9aa); font-size:13px; line-height:1.5; margin:6px 0 14px;">
                Fire simulated SSH / FTP / HTTP / Telnet attacks at your own
                <strong>running</strong> sensors to test capture, MITRE
                classification and alerting. Every event appears in the log
                below and in Analytics. Only sensors you have started are hit,
                always on 127.0.0.1.
            </p>
            <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:14px;">
                <label class="config-label" style="margin:0;">Attempts per brute-force sensor</label>
                <input type="number" id="attack-brute" value="4" min="1" max="50"
                       style="width:80px;">
            </div>
            <button class="btn btn-start" id="attack-btn" onclick="launchAttack()"
                    style="background: var(--danger, #d43);">&#9876; Launch Simulated Attack</button>
            <div id="attack-result" style="margin-top:12px; font-family:monospace; font-size:13px; min-height:18px;"></div>
        </div>

        <div class="logs-section">
            <h2>Attack Logs <span class="live-indicator"></span></h2>
            <div class="logs-container" id="logs">
                <div style="text-align: center; color: var(--dim);">Waiting for attacks...</div>
            </div>
        </div>
    </div>
    
    <div class="system-bar">
        <div class="system-bar-item">
            <span class="indicator"></span>
            <span>SYSTEM ONLINE</span>
        </div>
        <div class="system-bar-item">
            <span>{{ brand.name }} {{ brand.version }}</span>
        </div>
        <div class="system-bar-item">
            <span class="system-bar-time" id="system-time">00:00:00</span>
        </div>
    </div>
    
    <script>
// Quotes come from BRAND so rebranding changes them in one place.
        let currentQuote = 0;
        setInterval(function () {
            const el = document.getElementById('quote');
            if (!el || !BRAND.quotes.length) return;
            currentQuote = (currentQuote + 1) % BRAND.quotes.length;
            el.style.opacity = '0';
            setTimeout(function () {
                el.textContent = '> ' + BRAND.quotes[currentQuote];
                el.style.opacity = '1';
            }, 260);
        }, 10000);
        
        // Handle custom banner inputs
        document.getElementById('http-banner').addEventListener('change', function() {
            document.getElementById('http-banner-custom').style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        document.getElementById('ftp-banner').addEventListener('change', function() {
            document.getElementById('ftp-banner-custom').style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        document.getElementById('ssh-banner').addEventListener('change', function() {
            document.getElementById('ssh-banner-custom').style.display = this.value === 'custom' ? 'block' : 'none';
        });

        document.getElementById('telnet-banner').addEventListener('change', function() {
            document.getElementById('telnet-banner-custom').style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        // Upload HTML file
        async function uploadHTMLFile(input) {
            if (input.files && input.files[0]) {
                const formData = new FormData();
                formData.append('file', input.files[0]);
                
                try {
                    const response = await fetch('/upload_html', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        alert('HTML file uploaded successfully!');
                        loadHTMLFiles();
                    } else {
                        alert('Upload failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Upload error: ' + error);
                }
            }
        }
        
        // Upload FTP files
        async function uploadFTPFiles(input) {
            if (input.files && input.files.length > 0) {
                for (let file of input.files) {
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {
                        const response = await fetch('/upload_ftp_file', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        
                        if (data.status === 'success') {
                            console.log('FTP file uploaded:', data.filename);
                        }
                    } catch (error) {
                        console.error('Upload error:', error);
                    }
                }
                alert(`Uploaded ${input.files.length} file(s) successfully!`);
                loadFTPFiles();
            }
        }
        
        // Upload SSH files
        async function uploadSSHFiles(input) {
            if (input.files && input.files.length > 0) {
                for (let file of input.files) {
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {
                        const response = await fetch('/upload_ssh_file', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await response.json();
                        
                        if (data.status === 'success') {
                            console.log('SSH file uploaded:', data.filename);
                        }
                    } catch (error) {
                        console.error('Upload error:', error);
                    }
                }
                alert(`Uploaded ${input.files.length} file(s) successfully!`);
                loadSSHFiles();
            }
        }
        
        // Load available HTML files
        async function loadHTMLFiles() {
            try {
                const response = await fetch('/list_html_files');
                const data = await response.json();
                const select = document.getElementById('http-html-select');
                
                select.innerHTML = '<option value="">-- Default HTML --</option>';
                data.files.forEach(file => {
                    const option = document.createElement('option');
                    option.value = file;
                    option.textContent = file;
                    select.appendChild(option);
                });
            } catch (error) {
                console.error('Error loading HTML files:', error);
            }
        }
        
        // Load FTP files list
        async function loadFTPFiles() {
            try {
                const response = await fetch('/list_ftp_files');
                const data = await response.json();
                const container = document.getElementById('ftp-files-list');
                
                if (data.files.length === 0) {
                    container.innerHTML = '<div style="text-align: center; color: var(--dim); font-size: 0.85em;">No files uploaded yet</div>';
                } else {
                    container.innerHTML = data.files.map(file => `
                        <div class="file-item">
                            <span>${file}</span>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading FTP files:', error);
            }
        }
        
        // Load SSH files list
        async function loadSSHFiles() {
            try {
                const response = await fetch('/list_ssh_files');
                const data = await response.json();
                const container = document.getElementById('ssh-files-list');
                
                if (data.files.length === 0) {
                    container.innerHTML = '<div style="text-align: center; color: var(--dim); font-size: 0.85em;">No files uploaded yet</div>';
                } else {
                    container.innerHTML = data.files.map(file => `
                        <div class="file-item">
                            <span>${file}</span>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading SSH files:', error);
            }
        }
        
        async function launchAttack() {
            const btn = document.getElementById('attack-btn');
            const out = document.getElementById('attack-result');
            const brute = parseInt(document.getElementById('attack-brute').value) || 4;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = 'Attacking…';
            out.style.color = 'var(--dim, #9aa)';
            out.textContent = 'Launching red-team run…';
            try {
                const res = await fetch('/attack', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ brute })
                });
                const data = await res.json();
                out.style.color = res.ok ? 'var(--ok, #4ad66d)' : 'var(--danger, #d43)';
                out.textContent = (res.ok ? '✔ ' : '✖ ') + data.message;
            } catch (e) {
                out.style.color = 'var(--danger, #d43)';
                out.textContent = '✖ Request failed: ' + e;
            } finally {
                setTimeout(function () {
                    btn.disabled = false;
                    btn.innerHTML = original;
                }, 5000);
            }
        }

        async function startHoneypot(protocol) {
            const port = document.getElementById(`${protocol}-port`).value;
            const config = { protocol, port: parseInt(port) };
            
            if (protocol === 'http') {
                const bannerSelect = document.getElementById('http-banner');
                let banner = bannerSelect.value;
                if (banner === 'custom') {
                    banner = document.getElementById('http-banner-custom').value;
                    if (!banner) {
                        alert('Please enter a custom banner');
                        return;
                    }
                }
                
                const htmlFile = document.getElementById('http-html-select').value;
                config.banner = banner;
                if (htmlFile) {
                    config.html_file = 'uploads/' + htmlFile;
                }
            }
            
            if (protocol === 'ftp') {
                const bannerSelect = document.getElementById('ftp-banner');
                let banner = bannerSelect.value;
                if (banner === 'custom') {
                    banner = document.getElementById('ftp-banner-custom').value;
                    if (!banner) {
                        alert('Please enter a custom FTP banner');
                        return;
                    }
                }
                config.banner = banner;
            }
            
            if (protocol === 'ssh') {
                const bannerSelect = document.getElementById('ssh-banner');
                let banner = bannerSelect.value;
                if (banner === 'custom') {
                    banner = document.getElementById('ssh-banner-custom').value;
                    if (!banner) {
                        alert('Please enter a custom SSH banner');
                        return;
                    }
                }
                config.banner = banner;
            }
            
            if (protocol === 'telnet') {
                const bannerSelect = document.getElementById('telnet-banner');
                let banner = bannerSelect.value;
                if (banner === 'custom') {
                    banner = document.getElementById('telnet-banner-custom').value;
                    if (!banner) {
                        alert('Please enter a custom telnet banner');
                        return;
                    }
                }
                config.banner = banner;
            }
            
            const response = await fetch('/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            });
            const data = await response.json();
            alert(data.message);
            updateStatus();
        }
        
        async function stopHoneypot(protocol) {
            const response = await fetch('/stop', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({protocol})
            });
            const data = await response.json();
            alert(data.message);
            updateStatus();
        }
        
        async function updateStatus() {
            const response = await fetch('/status');
            const data = await response.json();
            
            for (const protocol in data.status) {
                const isActive = data.status[protocol];
                const statusDot = document.getElementById(`${protocol}-status`);
                const statusText = document.getElementById(`${protocol}-status-text`);
                
                if (isActive) {
                    statusDot.className = 'status-dot active';
                    statusText.textContent = 'Active';
                } else {
                    statusDot.className = 'status-dot inactive';
                    statusText.textContent = 'Inactive';
                }
            }
        }
        
        
/* ---------------- live log stream ---------------- */
        const BRAND = {{ brand|tojson }};
        let lastLogId = 0;
        let logsPaused = false;
        let pendingRows = [];
        const sparks = {};

        // Attackers control log details (usernames, paths, shell commands),
        // so everything rendered into the console must be escaped -- otherwise
        // a payload typed at the honeypot executes in the operator browser.
        function esc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function buildRow(log) {
            const sev = log.severity || FX.severity(log.type);
            const row = document.createElement('div');
            row.className = 'log-entry ' + esc(log.protocol) + ' sev-' + sev + ' fresh';
            row.innerHTML =
                '<span class="log-ts">[' + esc(log.timestamp) + ']</span>' +
                '<span class="log-proto ' + esc(log.protocol) + '">' +
                    esc(String(log.protocol).toUpperCase()) + '</span>' +
                '<span class="log-type">' + esc(log.type) + '</span>' +
                (log.mitre ? '<span class="log-proto" style="color:var(--info)"'
                    + ' title="' + esc(log.technique || '') + '">'
                    + esc(log.mitre) + '</span>' : '') +
                '<span class="log-detail">' + esc(log.details) + '</span>';
            setTimeout(function () { row.classList.remove('fresh'); }, 900);
            return row;
        }

        function flushPending() {
            const box = document.getElementById('logs');
            while (pendingRows.length) box.prepend(pendingRows.pop());
            trimLogs();
            updatePausedBadge();
        }

        function trimLogs() {
            const box = document.getElementById('logs');
            while (box.children.length > 300) box.lastElementChild.remove();
        }

        function updatePausedBadge() {
            const badge = document.getElementById('log-paused');
            if (!badge) return;
            if (logsPaused && pendingRows.length) {
                badge.textContent = pendingRows.length + ' new -- move away to resume';
                badge.style.opacity = '1';
            } else {
                badge.style.opacity = '0';
            }
        }

        function initSparks() {
            ['total', 'http', 'ftp', 'ssh', 'telnet'].forEach(function (k) {
                const c = document.getElementById('spark-' + k);
                if (!c) return;
                c.dataset.color = getComputedStyle(document.documentElement)
                    .getPropertyValue(c.dataset.colorVar).trim();
                sparks[k] = new FX.Spark(c, 60);
            });
        }

        async function updateLogs() {
            let data;
            try {
                const r = await fetch('/logs');
                data = await r.json();
            } catch (e) { return; }

            const box = document.getElementById('logs');
            if (lastLogId === 0 && data.logs.length) box.innerHTML = '';

            // /logs is newest-first; render oldest-first so prepend preserves order.
            const fresh = data.logs.filter(function (l) { return l.id > lastLogId; });
            fresh.reverse();

            fresh.forEach(function (log) {
                const row = buildRow(log);
                if (logsPaused) pendingRows.unshift(row);
                else box.prepend(row);
            });

            if (data.logs.length) {
                lastLogId = data.logs.reduce(function (m, l) {
                    return l.id > m ? l.id : m;
                }, lastLogId);
            }
            if (!logsPaused) trimLogs();
            updatePausedBadge();

            FX.countTo(document.getElementById('total-attacks'), data.stats.total);
            FX.countTo(document.getElementById('http-attacks'), data.stats.http);
            FX.countTo(document.getElementById('ftp-attacks'), data.stats.ftp);
            FX.countTo(document.getElementById('ssh-attacks'), data.stats.ssh);
            FX.countTo(document.getElementById('telnet-attacks'),
                       data.stats.telnet || 0);

            if (sparks.total) {
                sparks.total.push(data.stats.total);
                sparks.http.push(data.stats.http);
                sparks.ftp.push(data.stats.ftp);
                sparks.ssh.push(data.stats.ssh);
                if (sparks.telnet) sparks.telnet.push(data.stats.telnet || 0);
            }
        }

        setInterval(updateStatus, 2000);
        setInterval(updateLogs, 2000);
        
        // Update system time
        function updateSystemTime() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            document.getElementById('system-time').textContent = `${hours}:${minutes}:${seconds}`;
        }
        setInterval(updateSystemTime, 1000);
        updateSystemTime();
        
        // Initial updates
        updateStatus();
        updateLogs();
        loadHTMLFiles();
        loadFTPFiles();
        loadSSHFiles();
        
/* ---------------- ambience + boot ---------------- */
        document.addEventListener('DOMContentLoaded', function () {
            FX.matrix(document.getElementById('fx-matrix'));
            initSparks();

            // pause-on-hover badge for the log stream
            const box = document.getElementById('logs');
            if (box) {
                const badge = document.createElement('div');
                badge.id = 'log-paused';
                badge.style.cssText =
                    'position:sticky;top:0;z-index:5;opacity:0;transition:opacity .2s;' +
                    'background:var(--bg-3);color:var(--warn);border:1px solid var(--warn);' +
                    'border-radius:3px;padding:3px 9px;font-size:.72em;margin-bottom:6px;' +
                    'text-align:center;pointer-events:none';
                box.parentNode.insertBefore(badge, box);
                box.addEventListener('mouseenter', function () { logsPaused = true; });
                box.addEventListener('mouseleave', function () {
                    logsPaused = false;
                    flushPending();
                });
            }

            const boot = [
                { text: '> ' + BRAND.name.toLowerCase() + ' ' + BRAND.version + ' -- ' + BRAND.tagline, cls: 'ok', speed: 14 },
                { text: '  power-on self test ................ [ OK ]', cls: 'nb' },
                { text: '  loading deception modules ......... [ OK ]', cls: 'nb' },
                { text: '  http  sensor ...................... armed', cls: 'nb' },
                { text: '  ftp   sensor ...................... armed', cls: 'nb' },
                { text: '  ssh   sensor ...................... armed', cls: 'nb' },
                { text: '  telnet sensor ..................... armed', cls: 'nb' },
                { text: '  capture pipeline .................. [ OK ]', cls: 'nb' },
                { text: '> operator authenticated', cls: 'al', speed: 16 },
                { text: '> console ready. ' + BRAND.quotes[0], cls: 'ok', speed: 13 }
            ];
            FX.boot(document.getElementById('boot'), boot);
        });
    </script>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to dashboard
    if 'logged_in' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == AUTH_USERNAME and password == AUTH_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials. Access Denied!',
                                       brand=BRAND, theme=theme_css())
    
    return render_template_string(LOGIN_TEMPLATE, error=None,
                                  brand=BRAND, theme=theme_css())

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE, brand=BRAND, theme=theme_css(),
                               quotes=BRAND['quotes'])

@app.route('/upload_html', methods=['POST'])
@login_required
def upload_html():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'status': 'success', 'message': 'File uploaded successfully', 'filename': filename})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file type'})

@app.route('/upload_ftp_file', methods=['POST'])
@login_required
def upload_ftp_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['FTP_FILES_FOLDER'], filename))
        return jsonify({'status': 'success', 'message': 'FTP file uploaded successfully', 'filename': filename})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file type'})

@app.route('/upload_ssh_file', methods=['POST'])
@login_required
def upload_ssh_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['SSH_FILES_FOLDER'], filename))
        return jsonify({'status': 'success', 'message': 'SSH file uploaded successfully', 'filename': filename})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file type'})

@app.route('/list_html_files')
@login_required
def list_html_files():
    try:
        files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if allowed_file(f) and f.endswith(('.html', '.htm'))]
        return jsonify({'files': files})
    except OSError:
        return jsonify({'files': []})

@app.route('/list_ftp_files')
@login_required
def list_ftp_files():
    try:
        files = [f for f in os.listdir(app.config['FTP_FILES_FOLDER']) if allowed_file(f)]
        return jsonify({'files': files})
    except OSError:
        return jsonify({'files': []})

@app.route('/list_ssh_files')
@login_required
def list_ssh_files():
    try:
        files = [f for f in os.listdir(app.config['SSH_FILES_FOLDER']) if allowed_file(f)]
        return jsonify({'files': files})
    except OSError:
        return jsonify({'files': []})

@app.route('/start', methods=['POST'])
@login_required
def start_honeypot():
    data = request.json
    protocol = data.get('protocol')
    port = data.get('port')
    
    try:
        if protocol == 'http':
            banner = data.get('banner', 'Apache/2.4.41 (Ubuntu)')
            html_file = data.get('html_file')
            
            honeypots['http'] = HTTPHoneypot(
                port=port, 
                log_callback=log_event,
                html_file=html_file,
                server_banner=banner
            )
            honeypots['http'].start()
            
        elif protocol == 'ftp':
            banner = data.get('banner', FTPHoneypot.BANNER_SUGGESTIONS[0])
            
            honeypots['ftp'] = FTPHoneypot(
                port=port,
                log_callback=log_event,
                server_banner=banner,
                files_dir=app.config['FTP_FILES_FOLDER'],
                session_hooks=SESSION_HOOKS
            )
            honeypots['ftp'].start()
            
        elif protocol == 'ssh':
            banner = data.get('banner', SSHHoneypot.BANNER_SUGGESTIONS[0])
            
            honeypots['ssh'] = SSHHoneypot(
                port=port,
                log_callback=log_event,
                ssh_banner=banner,
                files_dir=app.config['SSH_FILES_FOLDER'],
                session_hooks=SESSION_HOOKS
            )
            honeypots['ssh'].start()

        elif protocol == 'telnet':
            banner = data.get('banner', TelnetHoneypot.BANNER_SUGGESTIONS[0])

            honeypots['telnet'] = TelnetHoneypot(
                port=port,
                log_callback=log_event,
                server_banner=banner,
                files_dir=app.config['TELNET_FILES_FOLDER'],
                session_hooks=SESSION_HOOKS
            )
            honeypots['telnet'].start()
        
        return jsonify({'status': 'success', 'message': f'{protocol.upper()} honeypot started on port {port}'})
    except Exception as e:
        # A sensor that failed to bind must not be left in the registry, or
        # /status reports it as present and the operator sees a live sensor
        # that is listening to nothing.
        honeypots[protocol] = None
        log_event(protocol, 'Startup Failed', str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 409

@app.route('/stop', methods=['POST'])
@login_required
def stop_honeypot():
    data = request.json
    protocol = data.get('protocol')
    
    try:
        if honeypots[protocol]:
            honeypots[protocol].stop()
            honeypots[protocol] = None
        return jsonify({'status': 'success', 'message': f'{protocol.upper()} honeypot stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/attack', methods=['POST'])
@login_required
def launch_attack():
    """Fire the built-in red-team simulator at the running sensors.

    The attacks hit 127.0.0.1 on each live sensor's own port, so every event
    flows back through log_event just like real traffic -- it lands in the
    live feed, the database and Analytics automatically. Runs on a background
    thread so the request returns immediately and the logs stream in.
    """
    import threading
    import attack_sim

    data = request.json or {}
    brute = max(1, int(data.get('brute', 4) or 4))
    requested = data.get('protocols') or None   # None => every running sensor

    funcs = {
        'http': attack_sim.attack_http,
        'ftp': attack_sim.attack_ftp,
        'ssh': attack_sim.attack_ssh,
        'telnet': attack_sim.attack_telnet,
    }
    targets = []
    for proto in ('http', 'ftp', 'ssh', 'telnet'):
        hp = honeypots.get(proto)
        if hp is not None and getattr(hp, 'running', False):
            if not requested or proto in requested:
                targets.append((proto, hp.port))

    if not targets:
        return jsonify({'status': 'error',
                        'message': 'No running sensors to attack. '
                                   'Start a honeypot first.'}), 409

    def _run():
        log_event('system', 'Attack Simulation Started',
                  'Red-team run against %s (brute=%d)'
                  % (', '.join(p for p, _ in targets), brute))
        stats = attack_sim.Stats()
        for proto, port in targets:
            try:
                funcs[proto]('127.0.0.1', port, stats, brute)
            except Exception as e:  # noqa: BLE001 -- one sensor must not stop the run
                log_event(proto, 'Simulation Error', str(e))
        log_event('system', 'Attack Simulation Complete',
                  '%d simulated attack events fired at %s'
                  % (stats.events, ', '.join(p for p, _ in targets)))

    threading.Thread(target=_run, name='attack-sim', daemon=True).start()
    names = ', '.join('%s:%d' % (p, port) for p, port in targets)
    return jsonify({'status': 'success',
                    'message': 'Attack simulation launched against %s' % names})


@app.route('/status')
@login_required
def get_status():
    status = {
        'http': honeypots['http'] is not None and honeypots['http'].running,
        'ftp': honeypots['ftp'] is not None and honeypots['ftp'].running,
        'ssh': honeypots['ssh'] is not None and honeypots['ssh'].running,
        'telnet': honeypots['telnet'] is not None and honeypots['telnet'].running
    }
    return jsonify({'status': status})

@app.route('/logs')
@login_required
def get_logs():
    stats = {
        'total': len(logs),
        'http': len([l for l in logs if l['protocol'] == 'http']),
        'ftp': len([l for l in logs if l['protocol'] == 'ftp']),
        'ssh': len([l for l in logs if l['protocol'] == 'ssh']),
        'telnet': len([l for l in logs if l['protocol'] == 'telnet'])
    }
    return jsonify({'logs': logs[:100], 'stats': stats})


# ---------------------------------------------------------------------------
# analytics API
# ---------------------------------------------------------------------------

@app.route('/analytics')
@login_required
def analytics_page():
    return render_template_string(ANALYTICS_TEMPLATE, brand=BRAND,
                                  theme=theme_css())


@app.route('/api/overview')
@login_required
def api_overview():
    return jsonify({
        'overview': storage.overview(),
        'protocols': storage.protocol_breakdown(),
        'severity': storage.severity_breakdown(),
        'timeline': storage.timeline(24),
        'mitre': [dict(r, name=technique_name(r['mitre']))
                  for r in storage.mitre_breakdown()],
        'alerting': alerting.status(),
        'geoip': intel.enabled(),
        'payload_fetch': capture.fetching_enabled(),
    })


@app.route('/api/attackers')
@login_required
def api_attackers():
    return jsonify({'attackers': storage.top_attackers(25)})


@app.route('/api/attacker/<ip>')
@login_required
def api_attacker(ip):
    profile = storage.attacker(ip)
    if profile is None:
        return jsonify({'error': 'unknown address'}), 404
    return jsonify(profile)


@app.route('/api/map')
@login_required
def api_map():
    """Geolocated attacker points for the world attack map."""
    return jsonify({'points': storage.geo_points(), 'geoip': intel.enabled()})


def _flag(country_code):
    """ISO-3166 alpha-2 -> regional-indicator flag emoji ('IN' -> 🇮🇳)."""
    if not country_code or len(country_code) != 2:
        return ''
    cc = country_code.upper()
    if not cc.isalpha():
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc)


@app.route('/report')
@login_required
def report_page():
    """A printable (Save-as-PDF) security summary of everything captured."""
    def _pct(rows, key='hits'):
        top = max([r[key] for r in rows] + [1])
        for r in rows:
            r['pct'] = round(100 * r[key] / top)
        return rows

    ov = storage.overview()
    protocols = _pct(storage.protocol_breakdown())
    severity = _pct(storage.severity_breakdown())
    timeline = _pct(storage.timeline(24))
    mitre = storage.mitre_breakdown()
    for m in mitre:
        m['name'] = technique_name(m['mitre'])

    attackers = storage.top_attackers(15)
    for a in attackers:
        a['flag'] = _flag(a.get('country_code'))
        a['where'] = ', '.join(x for x in (a.get('city'), a.get('country')) if x)
        a['tags'] = [t for t in (a.get('threat_tags') or '').split(',') if t]

    return render_template_string(
        REPORT_TEMPLATE, brand=BRAND, ov=ov, protocols=protocols,
        severity=severity, timeline=timeline, mitre=mitre, attackers=attackers,
        creds=storage.top_credentials(12), commands=storage.top_commands(12),
        payloads=storage.payloads(20),
        generated=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        operator=AUTH_USERNAME or 'operator', db_file=DB_FILE,
        geoip=intel.enabled())


@app.route('/api/credentials')
@login_required
def api_credentials():
    return jsonify({
        'pairs': storage.top_credentials(15),
        'usernames': storage.top_usernames(10),
        'passwords': storage.top_passwords(10),
        'commands': storage.top_commands(12),
    })


@app.route('/api/sessions')
@login_required
def api_sessions():
    replayable = request.args.get('replayable') == '1'
    return jsonify({'sessions': storage.sessions(60,
                                                 replayable_only=replayable)})


@app.route('/api/replay/<int:session_id>')
@login_required
def api_replay(session_id):
    data = storage.replay(session_id)
    if data is None:
        return jsonify({'error': 'unknown session'}), 404
    return jsonify(data)


@app.route('/api/payloads')
@login_required
def api_payloads():
    return jsonify({'payloads': storage.payloads(60),
                    'fetching': capture.fetching_enabled()})


@app.route('/api/export/<table>.csv')
@login_required
def api_export(table):
    """Download a table as CSV for offline analysis or a report."""
    try:
        rows = storage.export_rows(table)
    except ValueError:
        return jsonify({'error': 'unknown table'}), 404

    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition':
                 'attachment; filename=%s_%s.csv'
                 % (BRAND['slug'], table)})


if __name__ == '__main__':
    print()
    print(console_banner())
    print()
    
    # Credentials come from the environment when set, so the console can
    # start unattended (scripts, containers, CI). getpass reads the Windows
    # console directly and ignores redirected stdin, so without this the
    # app can only ever be launched by hand from a real terminal.
    AUTH_USERNAME = os.environ.get('HONEYPOT_USER')
    AUTH_PASSWORD = os.environ.get('HONEYPOT_PASS')

    if AUTH_USERNAME and AUTH_PASSWORD:
        print('Credentials read from HONEYPOT_USER / HONEYPOT_PASS.')
    else:
        print('Set up authentication credentials:')
        try:
            AUTH_USERNAME = input('Enter username: ').strip()
            AUTH_PASSWORD = getpass.getpass('Enter password: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\n[!] Aborted. Set HONEYPOT_USER and HONEYPOT_PASS to start unattended.')
            sys.exit(1)

    if not AUTH_USERNAME or not AUTH_PASSWORD:
        print('\n[!] Error: Username and password cannot be empty!')
        sys.exit(1)
    
    print()
    print("=" * 60)
    print(f"[+] Operator : {AUTH_USERNAME}")
    print("[+] Console  : http://localhost:5000")
    print("[+] Database : %s" % DB_FILE)
    print("[%s] GeoIP    : %s" % ('+' if intel.enabled() else ' ',
          'enabled' if intel.enabled() else 'off (set GULLAKTRAP_GEOIP=1)'))
    print("[%s] Alerting : %s" % ('+' if alerting.configured() else ' ',
          'configured' if alerting.configured() else 'off (set GULLAKTRAP_WEBHOOK)'))
    print("[%s] Payloads : %s" % ('+' if capture.fetching_enabled() else ' ',
          'downloading to quarantine/' if capture.fetching_enabled()
          else 'URL only (set GULLAKTRAP_FETCH_PAYLOADS=1 to download)'))
    print('  ' + BRAND['quotes'][0])
    print("=" * 60)
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=False)