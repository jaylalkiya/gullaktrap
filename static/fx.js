/*
 * fx.js -- UI motion for the honeypot console.
 *
 * Every effect is canvas- or transform-based so it stays on the GPU and
 * costs close to nothing, and every one of them no-ops when the visitor
 * has asked for reduced motion.
 */
(function (global) {
  'use strict';

  var REDUCED = global.matchMedia &&
    global.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function css(name) {
    return getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
  }

  /* ------------------------------------------------------------------
   * Matrix rain -- hacker-mode ambience. One canvas, trailing alpha
   * fill so columns leave a fading tail without storing history.
   * If no canvas is passed we create a fixed full-screen one, so the
   * effect turns on everywhere without touching the templates.
   * ---------------------------------------------------------------- */
  function matrix(canvas) {
    if (REDUCED) return;
    if (!canvas) {
      canvas = document.getElementById('fx-matrix');
      if (!canvas) {
        canvas = document.createElement('canvas');
        canvas.id = 'fx-matrix';
        document.body.appendChild(canvas);
      }
    }
    var ctx = canvas.getContext('2d');
    var GLYPHS = 'アイウエオカキクケコサシスセソタチツテト0123456789<>[]{}/\\|=+*#$%&@';
    var SIZE = 15;
    var cols, drops, hot, dim;

    function resize() {
      canvas.width = global.innerWidth;
      canvas.height = global.innerHeight;
      cols = Math.ceil(canvas.width / SIZE);
      drops = new Array(cols);
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -canvas.height;
      hot = css('--hot') || '#00ff9c';
      dim = css('--dim') || '#2f8a5c';
      ctx.font = SIZE + 'px monospace';
    }

    function frame() {
      ctx.fillStyle = 'rgba(' + (css('--bg-rgb') || '2, 6, 4') + ', 0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      for (var i = 0; i < cols; i++) {
        var ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
        var y = drops[i];
        ctx.fillStyle = Math.random() > 0.93 ? hot : dim;   // lead glyph burns bright
        ctx.fillText(ch, i * SIZE, y);
        drops[i] = (y > canvas.height && Math.random() > 0.975) ? 0 : y + SIZE;
      }
      requestAnimationFrame(frame);
    }

    resize();
    global.addEventListener('resize', resize);
    requestAnimationFrame(frame);
  }

  /* boot() -- retired fake boot log; kept as a no-op for old callers. */
  function boot(el, lines, done) {
    if (el) { try { el.remove(); } catch (e) {} }
    if (done) done();
  }

  /* Auto-start the rain on every page that loads fx.js. */
  if (document.readyState === 'loading') {
    global.addEventListener('DOMContentLoaded', function () { matrix(); });
  } else {
    matrix();
  }

  /* ------------------------------------------------------------------
   * Counter roll-up -- eases to the new value instead of snapping.
   * ---------------------------------------------------------------- */
  function countTo(el, value) {
    if (!el) return;
    var from = parseInt(el.dataset.v || '0', 10);
    value = value | 0;
    el.dataset.v = value;
    if (from === value) return;
    if (REDUCED) { el.textContent = value.toLocaleString(); return; }

    var start = performance.now();
    var span = Math.min(900, 220 + Math.abs(value - from) * 9);

    (function step(now) {
      var t = Math.max(0, Math.min(1, (now - start) / span));
      var eased = 1 - Math.pow(1 - t, 3);           // ease-out cubic
      el.textContent = Math.round(from + (value - from) * eased)
        .toLocaleString();
      if (t < 1) requestAnimationFrame(step);
    })(start);
  }

  /* ------------------------------------------------------------------
   * Sparkline -- a rolling window of recent activity per stat card.
   * ---------------------------------------------------------------- */
  function Spark(canvas, keep) {
    this.canvas = canvas;
    this.keep = keep || 60;
    this.data = [];
    this.last = null;
  }

  Spark.prototype.push = function (total) {
    // Store the delta per tick, so the graph shows rate, not cumulative.
    if (this.last !== null) {
      this.data.push(Math.max(0, total - this.last));
      if (this.data.length > this.keep) this.data.shift();
    }
    this.last = total;
    this.draw();
  };

  Spark.prototype.draw = function () {
    var c = this.canvas;
    if (!c) return;
    var w = c.clientWidth || 120;
    var h = c.clientHeight || 26;
    var dpr = global.devicePixelRatio || 1;
    if (c.width !== w * dpr || c.height !== h * dpr) {
      c.width = w * dpr;
      c.height = h * dpr;
    }
    var ctx = c.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    if (this.data.length < 2) {
      // Nothing to plot yet -- hold the baseline so the slot looks idle
      // rather than broken.
      ctx.strokeStyle = css('--line-soft') || '#0a3623';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, h - 1.5);
      ctx.lineTo(w, h - 1.5);
      ctx.stroke();
      return;
    }

    var max = Math.max.apply(null, this.data) || 1;
    var stepX = w / (this.data.length - 1);
    var color = c.dataset.color || css('--hot') || '#2fe36b';

    var pts = this.data.map(function (v, i) {
      return [i * stepX, h - 2 - (v / max) * (h - 4)];
    });

    ctx.beginPath();
    ctx.moveTo(pts[0][0], h);
    pts.forEach(function (p) { ctx.lineTo(p[0], p[1]); });
    ctx.lineTo(pts[pts.length - 1][0], h);
    ctx.closePath();
    var grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, hexA(color, 0.34));
    grad.addColorStop(1, hexA(color, 0));
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    pts.forEach(function (p, i) {
      if (i) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1]);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.4;
    ctx.lineJoin = 'round';
    ctx.stroke();
  };

  function hexA(hex, a) {
    hex = (hex || '').replace('#', '');
    if (hex.length === 3) {
      hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
    }
    if (hex.length !== 6) return 'rgba(47,227,107,' + a + ')';
    return 'rgba(' + parseInt(hex.slice(0, 2), 16) + ',' +
      parseInt(hex.slice(2, 4), 16) + ',' +
      parseInt(hex.slice(4, 6), 16) + ',' + a + ')';
  }

  /* ------------------------------------------------------------------
   * Severity classification -- drives the coloured left border.
   * ---------------------------------------------------------------- */
  var CRIT = ['path traversal', 'malware download', 'credential capture',
    'delete attempt', 'sql injection', 'command injection',
    'file inclusion', 'xss attempt', 'log4shell', 'shellshock',
    'ssrf attempt', 'xxe attempt', 'ssh key persistence',
    'cron persistence', 'history cleared', 'destructive command'];
  var WARN = ['scanner detected', 'password attempt', 'shell command',
    'file read', 'file access', 'login success', 'auth attempt',
    'password authentication', 'public key auth', 'permission change'];
  var OK = ['server started'];

  function severity(type) {
    var t = (type || '').toLowerCase();
    var has = function (list) {
      return list.some(function (k) { return t.indexOf(k) !== -1; });
    };
    if (has(CRIT)) return 'crit';
    if (has(WARN)) return 'warn';
    if (has(OK)) return 'ok';
    return 'info';
  }

  global.FX = {
    reduced: REDUCED,
    matrix: matrix,
    boot: boot,
    countTo: countTo,
    Spark: Spark,
    severity: severity
  };
})(window);
