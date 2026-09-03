"""
Event severity and MITRE ATT&CK mapping for GullakTrap.

Severity used to be inferred in the browser from the event title. Doing it
on the server instead means the database, the alerting thresholds and the
dashboard all agree on what "critical" means, and it lets each event carry
the ATT&CK technique it represents.
"""

# (substring, severity, ATT&CK technique)
RULES = [
    # --- critical: the attacker is doing something, not just knocking ---
    ('path traversal',       'crit', 'T1083'),
    ('malware download',     'crit', 'T1105'),
    ('payload fetch',        'crit', 'T1105'),
    ('credential capture',   'crit', 'T1110'),
    ('credential theft',     'crit', 'T1110'),
    ('sql injection',        'crit', 'T1190'),
    ('command injection',    'crit', 'T1059'),
    ('file inclusion',       'crit', 'T1190'),
    ('xss attempt',          'crit', 'T1059.007'),
    ('delete attempt',       'crit', 'T1070'),
    ('destructive command',  'crit', 'T1070'),
    ('file upload',          'crit', 'T1105'),

    # --- warning: reconnaissance and access attempts ---
    ('scanner detected',     'warn', 'T1595'),
    ('shell command',        'warn', 'T1059'),
    ('password attempt',     'warn', 'T1110'),
    ('password authentication', 'warn', 'T1110'),
    ('auth attempt',         'warn', 'T1110'),
    ('public key auth',      'warn', 'T1110'),
    ('login success',        'warn', 'T1078'),
    ('file access',          'warn', 'T1005'),
    ('file read',            'warn', 'T1005'),
    ('file download',        'warn', 'T1005'),
    ('permission change',    'warn', 'T1222'),
    ('directory change',     'warn', 'T1083'),
    ('list request',         'warn', 'T1083'),
    ('unknown command',      'warn', 'T1059'),
    ('post request',         'warn', 'T1595'),
    ('get request',          'warn', 'T1595'),
    ('username provided',    'warn', 'T1589'),

    # --- operational ---
    ('server started',       'ok',   None),
    ('server stopped',       'info', None),
    ('startup failed',       'warn', None),
    ('startup error',        'warn', None),
    ('session summary',      'info', None),
    ('connection established', 'info', 'T1595'),
]

TECHNIQUE_NAMES = {
    'T1005':     'Data from Local System',
    'T1059':     'Command and Scripting Interpreter',
    'T1059.007': 'JavaScript Injection',
    'T1070':     'Indicator Removal',
    'T1078':     'Valid Accounts',
    'T1083':     'File and Directory Discovery',
    'T1105':     'Ingress Tool Transfer',
    'T1110':     'Brute Force',
    'T1190':     'Exploit Public-Facing Application',
    'T1222':     'File and Directory Permissions Modification',
    'T1589':     'Gather Victim Identity Information',
    'T1595':     'Active Scanning',
}


def classify(event_type):
    """Return (severity, technique) for an event title."""
    text = (event_type or '').lower()
    for needle, severity, technique in RULES:
        if needle in text:
            return severity, technique
    return 'info', None


def technique_name(code):
    return TECHNIQUE_NAMES.get(code, code or '')
