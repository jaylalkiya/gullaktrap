"""
Branding, palette and UI effects for the honeypot console.

Everything that defines the project's identity lives here. To rebrand,
edit BRAND below -- the console banner, page titles, wordmark, footer and
log filename all derive from it. Nothing else needs to change.
"""

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
# PALETTE  --  layered terminal green, amber warn, red critical
# ---------------------------------------------------------------------------

PALETTE = {
    'bg':        '#05080a',   # page base, near-black
    'bg-2':      '#0c1410',   # panel
    'bg-3':      '#12201a',   # raised / hover
    'line':      '#1f3d2b',   # borders and rules
    'line-soft': '#14261c',
    'text':      '#8fd9a8',   # body copy
    'muted':     '#5f9c78',   # secondary copy
    'dim':       '#3f6b52',   # tertiary / disabled
    'hot':       '#2fe36b',   # primary accent -- terminal green
    'hot-soft':  '#23b355',
    'alert':     '#ff4d4d',   # critical
    'warn':      '#ffc107',   # warning
    'info':      '#46b0ff',   # informational
    'http':      '#2fe36b',
    'ftp':       '#46b0ff',
    'ssh':       '#ffc107',
    'telnet':    '#ff8a3d',
    # rgb triplets so CSS can build rgba() without hardcoding the palette
    'hot-rgb':   '47, 227, 107',
    'alert-rgb': '255, 77, 77',
    'bg-rgb':    '5, 8, 10',
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


def theme_css():
    """`:root` custom properties plus shared chrome, effects and motion."""
    root = ':root{\n' + '\n'.join(
        '  --%s: %s;' % (k, v) for k, v in PALETTE.items()
    ) + '\n  --mono: "JetBrains Mono", "Fira Code", "Cascadia Mono", Consolas,'
    root += ' "Courier New", monospace;\n}'
    return root + _CHROME_CSS


_CHROME_CSS = """
/* ---------- reset / base ---------- */
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--mono);
  min-height:100vh;
  overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
}
::selection{background:var(--hot);color:var(--bg)}

::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:var(--bg-2)}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--info)}

/* ---------- ambient layers ---------- */
#fx-matrix{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.16}
#fx-scan{
  position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.35;
  background:repeating-linear-gradient(
    180deg,rgba(0,0,0,0) 0 2px,rgba(0,0,0,.28) 2px 4px);
}
#fx-vignette{
  position:fixed;inset:0;z-index:1;pointer-events:none;
  background:radial-gradient(ellipse at center,
    rgba(0,0,0,0) 55%,rgba(0,0,0,.55) 100%);
}
.container,.login-wrap{position:relative;z-index:2}

/* ---------- wordmark ---------- */
.wordmark{
  font-size:clamp(2rem,7vw,3.6rem);
  font-weight:700;
  letter-spacing:.16em;
  color:var(--hot);
  text-shadow:0 0 18px rgba(var(--hot-rgb),.45),0 0 46px rgba(var(--hot-rgb),.16);
  position:relative;
  display:inline-block;
}
.wordmark::after{
  content:'_';
  color:var(--hot);
  animation:fx-blink 1.05s step-end infinite;
  margin-left:.1em;
}
.wordmark[data-glitch]::before{
  content:attr(data-glitch);
  position:absolute;left:0;top:0;width:100%;
  color:var(--alert);
  clip-path:inset(0 0 55% 0);
  opacity:0;
  animation:fx-glitch 6.5s infinite;
}
.brand-tag{
  color:var(--muted);letter-spacing:.34em;text-transform:uppercase;
  font-size:.72rem;margin-top:.5rem;
}

/* ---------- boot overlay ---------- */
#boot{
  position:fixed;inset:0;z-index:9999;background:var(--bg);
  padding:8vh 6vw;font-size:.86rem;line-height:1.85;
  color:var(--hot);overflow:hidden;
}
#boot .ok{color:var(--hot)}
#boot .nb{color:var(--muted)}
#boot .al{color:var(--alert)}
#boot.done{
  opacity:0;transform:scale(1.03);
  transition:opacity .5s ease,transform .5s ease;pointer-events:none;
}
#boot .cursor{
  display:inline-block;width:.55em;height:1em;background:var(--hot);
  vertical-align:-.14em;animation:fx-blink 1s step-end infinite;
}

/* ---------- entrances ---------- */
.rise{
  opacity:0;transform:translateY(14px);
  animation:fx-rise .5s cubic-bezier(.22,.8,.3,1) forwards;
}
.rise-1{animation-delay:.04s}.rise-2{animation-delay:.10s}
.rise-3{animation-delay:.16s}.rise-4{animation-delay:.22s}
.rise-5{animation-delay:.28s}.rise-6{animation-delay:.34s}

/* ---------- log stream ---------- */
.log-entry{
  border-left:3px solid var(--line);
  padding:7px 12px;margin-bottom:5px;
  background:var(--bg-2);
  border-radius:0 4px 4px 0;
  transition:background .18s ease,transform .18s ease;
  word-break:break-word;
}
.log-entry:hover{background:var(--bg-3);transform:translateX(3px)}
.log-entry.fresh{animation:fx-fresh .9s ease-out}
.log-entry.sev-crit{border-left-color:var(--alert)}
.log-entry.sev-warn{border-left-color:var(--warn)}
.log-entry.sev-info{border-left-color:var(--info)}
.log-entry.sev-ok{border-left-color:var(--hot)}
.log-ts{color:var(--dim);font-size:.78em;margin-right:.5em}
.log-proto{
  display:inline-block;min-width:44px;text-align:center;
  padding:1px 6px;margin-right:.55em;border-radius:3px;
  font-size:.7em;font-weight:700;letter-spacing:.09em;
  border:1px solid currentColor;
}
.log-proto.http{color:var(--http)}
.log-proto.ftp{color:var(--ftp)}
.log-proto.ssh{color:var(--ssh)}
.log-proto.telnet{color:var(--telnet)}
.log-type{color:var(--hot);margin-right:.4em}
.log-detail{color:var(--text);opacity:.82}

/* ---------- stat cards ---------- */
.stat-card{position:relative;overflow:hidden}
.stat-spark{display:block;width:100%;height:26px;margin-top:8px;opacity:.75}
.stat-number{font-variant-numeric:tabular-nums}

/* ---------- live dot ---------- */
.live-indicator{
  display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--hot);box-shadow:0 0 0 0 rgba(var(--hot-rgb),.6);
  animation:fx-pulse 1.9s ease-out infinite;
}

/* ---------- keyframes ---------- */
@keyframes fx-blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes fx-rise{to{opacity:1;transform:translateY(0)}}
@keyframes fx-pulse{
  0%{box-shadow:0 0 0 0 rgba(var(--hot-rgb),.55)}
  70%{box-shadow:0 0 0 11px rgba(var(--hot-rgb),0)}
  100%{box-shadow:0 0 0 0 rgba(var(--hot-rgb),0)}
}
@keyframes fx-fresh{
  0%{opacity:0;transform:translateX(-16px);background:var(--bg-3)}
  22%{opacity:1;transform:translateX(0)}
  100%{background:var(--bg-2)}
}
@keyframes fx-glitch{
  0%,92%,100%{opacity:0;transform:translate(0)}
  93%{opacity:.85;transform:translate(-2px,1px)}
  95%{opacity:.85;transform:translate(3px,-1px)}
  97%{opacity:.85;transform:translate(-1px,0)}
}

/* ---------- accessibility ---------- */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;
    animation-iteration-count:1!important;
    transition-duration:.001ms!important;
    scroll-behavior:auto!important;
  }
  #fx-matrix,#fx-scan{display:none}
}
"""
