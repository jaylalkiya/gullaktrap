"""
Branding, palette and UI effects for the honeypot console.

Everything that defines the project's identity lives here. To rebrand,
edit BRAND below -- the console banner, page titles, wordmark, footer and
log filename all derive from it. Nothing else needs to change.
"""

import os
import sys

# ---------------------------------------------------------------------------
# IDENTITY  --  edit this block to rebrand the whole application
# ---------------------------------------------------------------------------

BRAND = {
    'name':      'GullakTrap',                     # shown as the wordmark
    'slug':      'gullaktrap',                     # log/db filenames, cookies
    'tagline':   'deception grid',                 # under the wordmark
    'subtitle':  'Intrusion Capture System',       # browser title / header
    'version':   'v2.0',
    'quotes': [
        "A gullak only opens once it is full. So does this one.",
        "They came for the coins. They left the fingerprints.",
        "Every knock is recorded. Every key is kept.",
        "The lock was never real. The ledger always was.",
    ],
}

# ---------------------------------------------------------------------------
# PALETTE  --  "hacker mode": black terminal, neon green + cyan, glow accents
# ---------------------------------------------------------------------------

PALETTE = {
    'bg':        '#020604',   # page base, near-black
    'bg-2':      '#04120c',   # panel / card
    'bg-3':      '#071d13',   # raised / hover / inset
    'line':      '#0f5a38',   # neon-dim borders
    'line-soft': '#0a3623',
    'text':      '#b7ffd8',   # body copy, soft neon
    'muted':     '#54c78d',   # secondary copy
    'dim':       '#2f8a5c',   # tertiary / disabled
    'hot':       '#00ff9c',   # primary accent -- neon green
    'hot-soft':  '#00cc7d',
    'accent':    '#22d3ee',   # secondary accent -- neon cyan
    'alert':     '#ff2e63',   # critical
    'danger':    '#ff2e63',   # alias used by inline red-team styles
    'warn':      '#ffd21a',   # warning
    'info':      '#22d3ee',   # informational
    'ok':        '#00ff9c',   # success / online
    'http':      '#00ff9c',
    'ftp':       '#22d3ee',
    'ssh':       '#ffd21a',
    'telnet':    '#ff7a45',
    'smb':       '#b06cff',
    'smtp':      '#ff6ec7',
    'snmp':      '#2ee6c9',
    # rgb triplets so CSS can build rgba() without hardcoding the palette
    'hot-rgb':   '0, 255, 156',
    'accent-rgb':'34, 211, 238',
    'alert-rgb': '255, 46, 99',
    'ok-rgb':    '0, 255, 156',
    'bg-rgb':    '2, 6, 4',
}


def _console_supports(text):
    """True if the active stdout encoding can render `text`.

    Windows consoles fall back to cp1252 when output is piped, and box
    drawing characters raise UnicodeEncodeError there -- which would take
    the whole app down on startup. Check before printing, not after.
    """
    enc = getattr(sys.stdout, 'encoding', None) or 'ascii'
    try:
        text.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def console_banner():
    """Box-drawn startup banner. Adapts to any BRAND name length."""
    name = ' '.join(BRAND['name'].upper())
    sub = '%s  %s' % (BRAND['tagline'], BRAND['version'])
    width = max(len(name), len(sub), 38) + 6

    if _console_supports('╔═╗║╚╝'):
        tl, tr, bl, br, h, v = '╔', '╗', '╚', '╝', '═', '║'
    else:
        tl = tr = bl = br = '+'
        h, v = '=', '|'

    top = tl + h * width + tr
    bot = bl + h * width + br
    blank = v + ' ' * width + v
    row = lambda s: v + s.center(width) + v
    return '\n'.join([top, blank, row(name), row(sub), blank, bot])


_ANSI_READY = None


def enable_ansi():
    """Turn on ANSI colour for this terminal; True if colour is usable.

    Modern Windows consoles support ANSI once the virtual-terminal flag is
    set, but Python does not set it for us. When output is redirected (piped
    to a file, a CI log) we return False so no escape codes leak into it.
    """
    if not sys.stdout.isatty():
        return False
    if os.name != 'nt':
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        return True
    except Exception:
        return False


def cc(code, text):
    """Wrap `text` in an ANSI SGR colour, or return it plain if unsupported."""
    global _ANSI_READY
    if _ANSI_READY is None:
        _ANSI_READY = enable_ansi()
    if not _ANSI_READY:
        return text
    return '\033[%sm%s\033[0m' % (code, text)


def cli_glyphs():
    """Console symbols (on, off, arrow, rule), ASCII where unicode can't render."""
    if _console_supports('●○▸─'):
        return '●', '○', '▸', '─'   # ● ○ ▸ ─
    return '*', 'o', '>', '-'


def theme_css():
    """`:root` design tokens plus the shared component chrome."""
    root = ':root{\n' + '\n'.join(
        '  --%s: %s;' % (k, v) for k, v in PALETTE.items()
    )
    root += ('\n  --ui: "JetBrains Mono", "Cascadia Mono", "SFMono-Regular",'
             ' Consolas, "Liberation Mono", monospace;'
             '\n  --mono: "JetBrains Mono", "Cascadia Mono", "SFMono-Regular",'
             ' Consolas, "Liberation Mono", monospace;'
             '\n  --radius: 6px;'
             '\n  --radius-sm: 4px;'
             '\n  --glow: 0 0 8px rgba(var(--hot-rgb), .55);'
             '\n  --shadow: 0 0 0 1px rgba(var(--hot-rgb), .06), 0 14px 40px rgba(0,0,0,.6),'
             ' inset 0 0 30px rgba(var(--hot-rgb), .03);'
             '\n  --ring: 0 0 0 2px rgba(var(--hot-rgb), .35), 0 0 14px rgba(var(--hot-rgb), .35);'
             '\n}')
    return root + _CHROME_CSS


_CHROME_CSS = """
/* ==================================================================
   GullakTrap -- shared chrome :: HACKER MODE
   Black terminal, neon-green + cyan glow, monospace everything,
   scanlines + grid + matrix ambience (fx.js injects the canvas).
   ================================================================== */

/* ---------- reset / base ---------- */
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--mono);
  font-size:14px;
  line-height:1.55;
  letter-spacing:.02em;
  min-height:100vh;
  overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
  text-shadow:0 0 1px rgba(var(--hot-rgb),.15);
}
/* faint terminal grid + corner glows */
body::before{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    linear-gradient(rgba(var(--hot-rgb),.05) 1px, transparent 1px) 0 0/44px 44px,
    linear-gradient(90deg, rgba(var(--hot-rgb),.05) 1px, transparent 1px) 0 0/44px 44px,
    radial-gradient(60rem 42rem at 8% -8%, rgba(var(--hot-rgb),.12), transparent 60%),
    radial-gradient(52rem 40rem at 102% 0%, rgba(var(--accent-rgb),.10), transparent 55%);
}
/* CRT scanlines + soft vignette */
body::after{
  content:'';position:fixed;inset:0;z-index:2;pointer-events:none;
  background:
    repeating-linear-gradient(0deg, rgba(0,0,0,0) 0 2px, rgba(0,0,0,.16) 2px 3px),
    radial-gradient(ellipse at center, rgba(0,0,0,0) 58%, rgba(0,0,0,.55) 100%);
  mix-blend-mode:multiply;opacity:.7;
}
#fx-matrix{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.14}
.container,.login-wrap,.login-container{position:relative;z-index:3}

code,kbd,pre,.mono,.stat-number,.log-ts,.log-detail{font-family:var(--mono)}
a{color:var(--hot);text-decoration:none;transition:color .15s ease, text-shadow .15s ease}
a:hover{color:var(--hot);text-shadow:var(--glow)}
::selection{background:rgba(var(--hot-rgb),.28);color:#001a10}

::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{
  background:var(--line);border-radius:20px;
  border:3px solid transparent;background-clip:content-box;
}
::-webkit-scrollbar-thumb:hover{background:var(--hot);background-clip:content-box}

/* ---------- wordmark ---------- */
.wordmark{
  font-family:var(--mono);
  font-weight:800;
  letter-spacing:.08em;
  line-height:1.05;
  color:var(--hot);
  text-shadow:0 0 10px rgba(var(--hot-rgb),.65), 0 0 26px rgba(var(--hot-rgb),.30);
  display:inline-block;position:relative;
}
.wordmark::before{content:'./';color:var(--dim);margin-right:.12em;font-weight:400;text-shadow:none}
.wordmark::after{
  content:'_';color:var(--hot);margin-left:.06em;
  animation:fx-blink 1.05s step-end infinite;
}
.brand-tag{
  color:var(--muted);letter-spacing:.22em;text-transform:uppercase;
  font-size:.68rem;margin-top:.4rem;
}

/* ---------- pills / badges ---------- */
.pill{
  display:inline-flex;align-items:center;gap:.4em;
  padding:.3em .7em;border-radius:var(--radius-sm);
  font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
  border:1px solid var(--line);color:var(--muted);
  background:rgba(var(--hot-rgb),.04);
}

/* ---------- buttons (terminal style) ---------- */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:.5em;
  padding:.55em 1.05em;border-radius:var(--radius-sm);
  font-family:var(--mono);font-size:.82rem;font-weight:700;
  letter-spacing:.06em;text-transform:uppercase;cursor:pointer;
  border:1px solid var(--line);background:rgba(var(--hot-rgb),.03);color:var(--text);
  transition:all .15s ease;
}
.btn:hover{border-color:var(--hot);color:var(--hot);
  box-shadow:0 0 14px rgba(var(--hot-rgb),.28);text-shadow:var(--glow)}
.btn:active{transform:translateY(1px)}
.btn:focus-visible{outline:none;box-shadow:var(--ring)}
.btn-start{border-color:var(--hot);color:var(--hot);background:rgba(var(--hot-rgb),.08)}
.btn-start:hover{background:var(--hot);color:#00160d;box-shadow:0 0 18px rgba(var(--hot-rgb),.55);text-shadow:none}
.btn-stop{border-color:var(--line);color:var(--muted);background:transparent}
.btn-stop:hover{border-color:var(--alert);color:var(--alert);
  background:rgba(var(--alert-rgb),.08);box-shadow:0 0 14px rgba(var(--alert-rgb),.28)}

/* ---------- form controls ---------- */
input,select,textarea{font-family:var(--mono)}
input[type=text],input[type=password],input[type=number],select,textarea,
.config input,.config select,.config textarea{
  width:100%;padding:.58em .7em;
  background:#01100a;color:var(--text);caret-color:var(--hot);
  border:1px solid var(--line);border-radius:var(--radius-sm);
  font-size:.86rem;transition:border-color .15s ease, box-shadow .15s ease;
}
input::placeholder,textarea::placeholder{color:var(--dim)}
input:focus,select:focus,textarea:focus{
  outline:none;border-color:var(--hot);box-shadow:var(--ring);
}
select option{background:var(--bg-2);color:var(--text)}
input[type=file]::file-selector-button{
  background:rgba(var(--hot-rgb),.06);color:var(--hot);
  border:1px solid var(--line);border-radius:var(--radius-sm);
  padding:.5em .9em;margin-right:.75em;cursor:pointer;font-family:var(--mono);
  text-transform:uppercase;font-size:.74rem;letter-spacing:.05em;
  transition:all .15s ease;
}
input[type=file]::file-selector-button:hover{border-color:var(--hot);box-shadow:0 0 12px rgba(var(--hot-rgb),.3)}

/* ---------- panels ---------- */
.panel,.control-card,.logs-section,.stat-card,.login-container{
  background:linear-gradient(180deg, var(--bg-2), var(--bg));
  border:1px solid var(--line);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
  position:relative;
}
/* neon corner ticks on the main cards */
.control-card::before,.control-card::after,
.logs-section::before,.logs-section::after,
.login-container::before,.login-container::after{
  content:'';position:absolute;width:14px;height:14px;
  border:2px solid var(--hot);opacity:.55;pointer-events:none;
  box-shadow:0 0 8px rgba(var(--hot-rgb),.5);
}
.control-card::before,.logs-section::before,.login-container::before{
  top:9px;left:9px;border-right:0;border-bottom:0;
}
.control-card::after,.logs-section::after,.login-container::after{
  bottom:9px;right:9px;border-left:0;border-top:0;
}

/* ---------- entrances ---------- */
.rise{opacity:0;transform:translateY(12px);
  animation:fx-rise .5s cubic-bezier(.22,.8,.3,1) forwards}
.rise-1{animation-delay:.03s}.rise-2{animation-delay:.08s}
.rise-3{animation-delay:.13s}.rise-4{animation-delay:.18s}
.rise-5{animation-delay:.23s}.rise-6{animation-delay:.28s}

/* ---------- log stream ---------- */
.log-entry{
  border-left:3px solid var(--line);
  padding:.5em .75em;margin-bottom:.35em;
  background:rgba(var(--hot-rgb),.03);
  border-radius:0 var(--radius-sm) var(--radius-sm) 0;
  transition:background .16s ease,transform .16s ease,box-shadow .16s ease;
  word-break:break-word;font-size:.82rem;
}
.log-entry:hover{background:rgba(var(--hot-rgb),.07);transform:translateX(3px);
  box-shadow:-3px 0 10px rgba(var(--hot-rgb),.15)}
.log-entry.fresh{animation:fx-fresh .9s ease-out}
.log-entry.sev-crit{border-left-color:var(--alert);box-shadow:inset 2px 0 0 var(--alert)}
.log-entry.sev-warn{border-left-color:var(--warn)}
.log-entry.sev-info{border-left-color:var(--info)}
.log-entry.sev-ok{border-left-color:var(--ok)}
.log-ts{color:var(--dim);font-size:.78em;margin-right:.5em}
.log-proto,.log-protocol{
  display:inline-block;min-width:46px;text-align:center;
  padding:.1em .5em;margin-right:.5em;border-radius:var(--radius-sm);
  font-family:var(--mono);font-size:.66rem;font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;
  border:1px solid currentColor;background:rgba(0,0,0,.35);
  box-shadow:0 0 8px currentColor;
}
.log-proto.http,.log-protocol.http{color:var(--http)}
.log-proto.ftp,.log-protocol.ftp{color:var(--ftp)}
.log-proto.ssh,.log-protocol.ssh{color:var(--ssh)}
.log-proto.telnet,.log-protocol.telnet{color:var(--telnet)}
.log-proto.smb,.log-protocol.smb{color:var(--smb)}
.log-proto.smtp,.log-protocol.smtp{color:var(--smtp)}
.log-proto.snmp,.log-protocol.snmp{color:var(--snmp)}
.log-type{color:var(--hot);font-weight:700;margin-right:.4em}
.log-detail{color:var(--muted)}

/* ---------- stat cards ---------- */
.stat-card{overflow:hidden}
.stat-card::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg, transparent, var(--hot), transparent);
  opacity:.6;box-shadow:0 0 10px rgba(var(--hot-rgb),.6);
}
.stat-spark{display:block;width:100%;height:28px;margin-top:8px;opacity:.95}
.stat-number{font-variant-numeric:tabular-nums;font-family:var(--mono);
  color:var(--hot);text-shadow:0 0 12px rgba(var(--hot-rgb),.5)}

/* ---------- live dot ---------- */
.live-indicator{
  display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--ok);box-shadow:0 0 8px var(--ok), 0 0 0 0 rgba(var(--ok-rgb),.6);
  animation:fx-pulse 1.8s ease-out infinite;
}

/* ---------- keyframes ---------- */
@keyframes fx-blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes fx-rise{to{opacity:1;transform:translateY(0)}}
@keyframes fx-pulse{
  0%{box-shadow:0 0 8px var(--ok), 0 0 0 0 rgba(var(--ok-rgb),.5)}
  70%{box-shadow:0 0 8px var(--ok), 0 0 0 9px rgba(var(--ok-rgb),0)}
  100%{box-shadow:0 0 8px var(--ok), 0 0 0 0 rgba(var(--ok-rgb),0)}
}
@keyframes fx-fresh{
  0%{opacity:0;transform:translateX(-14px);background:rgba(var(--hot-rgb),.16)}
  22%{opacity:1;transform:translateX(0)}
  100%{background:rgba(var(--hot-rgb),.03)}
}

/* ---------- accessibility ---------- */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;
    animation-iteration-count:1!important;
    transition-duration:.001ms!important;
    scroll-behavior:auto!important;
  }
  #fx-matrix{display:none}
  body::after{opacity:.4}
}
"""

