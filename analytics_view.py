"""
The intelligence view for GullakTrap.

Kept out of main.py because that file already carries two large templates.
All colour comes from the palette in branding.py -- there are no hardcoded
hex values here.
"""

ANALYTICS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ brand.name }} | Intelligence</title>
<style>{{ theme|safe }}</style>
<style>
.container{max-width:1400px;margin:0 auto;padding:22px}
.header{text-align:center;padding:26px 12px 18px;position:relative}
.header .wordmark{font-size:2.2rem}
.nav{position:absolute;top:20px;left:20px;display:flex;gap:10px}
.nav a,.logout-btn{
  padding:7px 14px;border:1px solid var(--line);color:var(--muted);
  border-radius:4px;text-decoration:none;font-size:.78em;
  transition:all .2s;background:transparent;
}
.nav a:hover{border-color:var(--hot);color:var(--hot)}
.logout-btn{position:absolute;top:20px;right:20px}
.logout-btn:hover{border-color:var(--alert);color:var(--alert);
  background:rgba(var(--alert-rgb),.08)}

/* align-items:start so a short panel keeps its own height instead of
   stretching to match the tall one beside it. */
.grid{display:grid;gap:16px;margin-bottom:18px;align-items:start}
.g4{grid-template-columns:repeat(4,1fr)}
@media (max-width:1080px){.g4{grid-template-columns:repeat(3,1fr)}}
@media (max-width:760px){.g4{grid-template-columns:repeat(2,1fr)}}
@media (max-width:420px){.g4{grid-template-columns:1fr}}
.g2{grid-template-columns:repeat(auto-fit,minmax(400px,1fr))}

.card{
  background:var(--bg-2);border:1px solid var(--line);border-radius:var(--radius);
  padding:18px 20px;position:relative;overflow:hidden;box-shadow:var(--shadow);
}
.card h2{
  font-size:.82em;letter-spacing:.16em;text-transform:uppercase;
  color:var(--hot);margin-bottom:14px;font-weight:600;
}
.kpi{font-size:2.1em;color:var(--hot);font-variant-numeric:tabular-nums;
  line-height:1.1}
.kpi.crit{color:var(--alert)}
.klabel{color:var(--muted);font-size:.72em;letter-spacing:.14em;
  text-transform:uppercase;margin-top:4px}

table{width:100%;border-collapse:collapse;font-size:.82em}
th{
  text-align:left;color:var(--muted);font-weight:500;padding:6px 8px;
  border-bottom:1px solid var(--line);font-size:.88em;
  letter-spacing:.08em;text-transform:uppercase;
}
td{padding:6px 8px;border-bottom:1px solid var(--line-soft);
  word-break:break-word}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .15s}
tbody tr:hover{background:var(--bg-3)}
.num{text-align:right;font-variant-numeric:tabular-nums;color:var(--hot)}
.mono{color:var(--text)}
.ip{color:var(--hot);cursor:pointer;text-decoration:none;border-bottom:1px
  dotted var(--line)}
.ip:hover{color:var(--warn)}

.bar{height:5px;background:var(--line-soft);border-radius:3px;overflow:hidden;
  margin-top:4px}
.bar span{display:block;height:100%;background:var(--hot);border-radius:3px;
  transition:width .5s cubic-bezier(.22,.8,.3,1)}

.tag{
  display:inline-block;padding:1px 7px;margin:2px 3px 2px 0;font-size:.68em;
  border:1px solid currentColor;border-radius:10px;letter-spacing:.05em;
}
.t-crit{color:var(--alert)}.t-warn{color:var(--warn)}
.t-info{color:var(--info)}.t-ok{color:var(--hot)}
.t-muted{color:var(--muted)}

#chart{width:100%;height:150px;display:block}

.empty{color:var(--dim);text-align:center;padding:22px;font-size:.85em}

/* modal for attacker profile + session replay */
.modal{
  position:fixed;inset:0;z-index:500;background:rgba(0,0,0,.78);
  display:none;align-items:center;justify-content:center;padding:24px;
}
.modal.open{display:flex;animation:fx-rise .25s ease-out}
.modal-box{
  background:var(--bg-2);border:1px solid var(--line);border-radius:var(--radius);
  max-width:900px;width:100%;max-height:86vh;overflow:auto;padding:24px;
  box-shadow:var(--shadow);
}
.modal-box h3{color:var(--hot);margin-bottom:4px;font-size:1.1em}
.modal-close{
  float:right;border:1px solid var(--alert);color:var(--alert);
  background:transparent;border-radius:4px;padding:4px 11px;cursor:pointer;
  font-family:var(--mono);font-size:.8em;
}
.modal-close:hover{background:var(--alert);color:var(--bg)}

#replay{
  background:var(--bg);border:1px solid var(--line);border-radius:4px;
  padding:14px;min-height:230px;max-height:340px;overflow:auto;
  white-space:pre-wrap;font-size:.84em;color:var(--hot);margin-top:12px;
}
.replay-bar{display:flex;gap:10px;align-items:center;margin-top:10px}
.btn{
  background:transparent;border:1px solid var(--hot);color:var(--hot);
  padding:6px 15px;border-radius:4px;cursor:pointer;font-family:var(--mono);
  font-size:.8em;transition:all .2s;
}
.btn:hover{background:var(--hot);color:var(--bg)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.speed{color:var(--muted);font-size:.78em}

.flags{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.flag{
  font-size:.7em;padding:3px 9px;border-radius:3px;border:1px solid var(--line);
  color:var(--muted);
}
.flag.on{border-color:var(--hot);color:var(--hot)}
#map{height:440px;border-radius:12px;overflow:hidden;background:#0b0f14}
.leaflet-container{font-family:inherit;background:#0b0f14}
/* OSM ships light tiles; invert + tint them into the terminal palette. */
.leaflet-tile-pane{
  filter:invert(1) hue-rotate(180deg) brightness(.62) contrast(1.05)
         saturate(.45);
}
.leaflet-control-attribution{
  background:rgba(0,0,0,.55)!important;color:var(--dim)!important;
  font-size:.62rem!important;
}
.leaflet-control-attribution a{color:var(--muted)!important}
.leaflet-control-zoom a{
  background:var(--bg-2)!important;color:var(--hot)!important;
  border-color:var(--line)!important;
}
/* Shown instead of an empty 440px map when there is nothing to plot. */
.map-empty{
  border:1px dashed var(--line);border-radius:var(--radius);
  padding:22px;color:var(--muted);font-size:.84em;line-height:1.7;
}
.map-empty b{color:var(--text)}
.map-empty code{
  color:var(--hot);background:rgba(var(--hot-rgb),.08);
  padding:1px 6px;border-radius:3px;
}
.mono-flag{font-size:15px;margin-right:4px}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script src="{{ url_for('static', filename='fx.js') }}" defer></script>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="nav"><a href="{{ url_for('index') }}">&larr; CONSOLE</a>
      <a href="/report" target="_blank">&#128196; REPORT</a></div>
    <a href="{{ url_for('logout') }}" class="logout-btn">LOGOUT</a>
    <h1 class="wordmark" data-glitch="{{ brand.name }}">{{ brand.name }}</h1>
    <div class="brand-tag">intelligence &middot; {{ brand.version }}</div>
  </div>

  <div class="grid g4" id="kpis"></div>

  <div class="card rise rise-1">
    <h2>Attack origins &mdash; world map</h2>
    <div id="mapnote"></div>
    <div id="map"></div>
  </div>

  <div class="card rise rise-1">
    <h2>Activity &mdash; last 24 hours</h2>
    <canvas id="chart"></canvas>
  </div>

  <div class="grid g2">
    <div class="card rise rise-2">
      <h2>Top attackers</h2>
      <div id="attackers"><div class="empty">no data yet</div></div>
    </div>
    <div class="card rise rise-3">
      <h2>Most-tried credentials</h2>
      <div id="creds"><div class="empty">no data yet</div></div>
    </div>
  </div>

  <div class="grid g2">
    <div class="card rise rise-4">
      <h2>Top usernames</h2>
      <div id="usernames"><div class="empty">no data yet</div></div>
    </div>
    <div class="card rise rise-4">
      <h2>Top passwords</h2>
      <div id="passwords"><div class="empty">no data yet</div></div>
    </div>
  </div>

  <div class="grid g2">
    <div class="card rise rise-5">
      <h2>Commands executed</h2>
      <div id="commands"><div class="empty">no data yet</div></div>
    </div>
    <div class="card rise rise-5">
      <h2>ATT&amp;CK techniques observed</h2>
      <div id="mitre"><div class="empty">no data yet</div></div>
    </div>
  </div>

  <div class="grid g2">
    <div class="card rise rise-6">
      <h2>Sessions &mdash; click to replay</h2>
      <div id="sessions"><div class="empty">no data yet</div></div>
    </div>
    <div class="card rise rise-6">
      <h2>Captured payloads</h2>
      <div id="payloads"><div class="empty">no data yet</div></div>
      <div class="flags" id="flags"></div>
    </div>
  </div>

  <div class="card rise rise-6">
    <h2>Export</h2>
    <div style="display:flex;gap:9px;flex-wrap:wrap">
      <a class="btn" href="/api/export/events.csv">events.csv</a>
      <a class="btn" href="/api/export/credentials.csv">credentials.csv</a>
      <a class="btn" href="/api/export/commands.csv">commands.csv</a>
      <a class="btn" href="/api/export/sessions.csv">sessions.csv</a>
      <a class="btn" href="/api/export/attackers.csv">attackers.csv</a>
      <a class="btn" href="/api/export/payloads.csv">payloads.csv</a>
    </div>
  </div>
</div>

<div class="modal" id="modal">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal()">CLOSE</button>
    <div id="modal-body"></div>
  </div>
</div>

<script>
const BRAND = {{ brand|tojson }};

function esc(v){
  const d=document.createElement('div');
  d.textContent = (v===null||v===undefined) ? '' : String(v);
  return d.innerHTML;
}
function ts(sec){
  if(!sec) return '--';
  return new Date(sec*1000).toLocaleString();
}
function table(head, rows){
  if(!rows.length) return '<div class="empty">no data yet</div>';
  return '<table><thead><tr>' +
    head.map(h=>'<th>'+esc(h)+'</th>').join('') +
    '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
}
function bar(v,max){
  const pct = max ? Math.round(v/max*100) : 0;
  return '<div class="bar"><span style="width:'+pct+'%"></span></div>';
}

/* ---------------- overview ---------------- */
async function loadOverview(){
  const d = await (await fetch('/api/overview')).json();
  const o = d.overview;
  const kpi = [
    ['events','Total events',''],
    ['events_24h','Last 24h',''],
    ['attackers','Unique sources',''],
    ['sessions','Sessions',''],
    ['credentials','Credentials',''],
    ['commands','Commands',''],
    ['payloads','Payloads',''],
    ['critical','Critical','crit'],
  ];
  document.getElementById('kpis').innerHTML = kpi.map(function(k){
    return '<div class="card"><div class="kpi '+k[2]+'" data-v="'+
      (o[k[0]]||0)+'">'+(o[k[0]]||0).toLocaleString()+
      '</div><div class="klabel">'+k[1]+'</div></div>';
  }).join('');

  drawChart(d.timeline||[]);

  const maxM = Math.max.apply(null,(d.mitre||[]).map(m=>m.hits).concat([1]));
  document.getElementById('mitre').innerHTML = table(
    ['Technique','Name','Count'],
    (d.mitre||[]).map(m=>'<tr><td class="mono">'+esc(m.mitre)+
      '</td><td>'+esc(m.name)+bar(m.hits,maxM)+
      '</td><td class="num">'+m.hits+'</td></tr>'));

  const f = document.getElementById('flags');
  f.innerHTML =
    '<span class="flag '+(d.geoip?'on':'')+'">GeoIP '+(d.geoip?'on':'off')+'</span>'+
    '<span class="flag '+(d.payload_fetch?'on':'')+'">payload download '+
      (d.payload_fetch?'on':'off')+'</span>'+
    '<span class="flag '+(d.alerting.enabled?'on':'')+'">alerting '+
      (d.alerting.enabled?d.alerting.level:'off')+'</span>';
}

/* ---------------- timeline chart ---------------- */
function drawChart(points){
  const c = document.getElementById('chart');
  const dpr = window.devicePixelRatio||1;
  const w = c.clientWidth, h = 150;
  c.width = w*dpr; c.height = h*dpr;
  const x = c.getContext('2d');
  x.setTransform(dpr,0,0,dpr,0,0);
  x.clearRect(0,0,w,h);
  if(!points.length) return;

  const cs = getComputedStyle(document.documentElement);
  const hot = cs.getPropertyValue('--hot').trim();
  const line = cs.getPropertyValue('--line').trim();
  const dim = cs.getPropertyValue('--dim').trim();
  const max = Math.max.apply(null, points.map(p=>p.hits).concat([1]));
  const pad = 24, bw = (w-pad) / points.length;

  x.strokeStyle = line; x.lineWidth = 1;
  for(let g=0; g<=3; g++){
    const y = pad/2 + (h-pad-pad/2) * g/3;
    x.beginPath(); x.moveTo(pad,y); x.lineTo(w,y); x.stroke();
  }

  points.forEach(function(p,i){
    const bh = (p.hits/max) * (h-pad-10);
    const bx = pad + i*bw;
    x.fillStyle = hot;
    x.globalAlpha = p.hits ? 0.85 : 0.12;
    x.fillRect(bx+1, h-pad+6-bh, Math.max(1,bw-3), Math.max(1,bh));
  });
  x.globalAlpha = 1;

  x.fillStyle = dim; x.font = '9px monospace';
  points.forEach(function(p,i){
    if(i % 4) return;
    x.fillText(p.hour, pad + i*bw, h-6);
  });
  x.fillText(String(max), 0, pad/2+4);
  x.fillText('0', 0, h-pad+6);
}

/* ---------------- tables ---------------- */
function ccFlag(cc){
  if(!cc || cc.length!==2) return '';
  cc = cc.toUpperCase();
  if(!/^[A-Z]{2}$/.test(cc)) return '';
  return String.fromCodePoint.apply(null,
    [...cc].map(c=>0x1F1E6 + c.charCodeAt(0) - 65));
}

async function loadAttackers(){
  const d = await (await fetch('/api/attackers')).json();
  const max = Math.max.apply(null,(d.attackers||[]).map(a=>a.events).concat([1]));
  document.getElementById('attackers').innerHTML = table(
    ['Source','Where','Events','Protocols'],
    (d.attackers||[]).map(function(a){
      const tags = (a.threat_tags||'').split(',').filter(Boolean)
        .map(t=>'<span class="tag t-warn">'+esc(t)+'</span>').join('');
      const flag = ccFlag(a.country_code);
      const where = (flag?'<span class="mono-flag">'+flag+'</span>':'')+
        ([a.city,a.country].filter(Boolean).join(', ') ||
        '<span class="t-muted">not enriched</span>');
      return '<tr><td><a class="ip" onclick="showAttacker(\\''+esc(a.ip)+
        '\\')">'+esc(a.ip)+'</a>'+tags+'</td><td>'+where+
        '</td><td class="num">'+a.events+bar(a.events,max)+
        '</td><td class="mono">'+esc(a.protocols||'')+'</td></tr>';
    }));
}

/* ---------------- world attack map ---------------- */
let _map = null, _markers = null;
async function loadMap(){
  const d = await (await fetch('/api/map')).json();
  const pts = d.points || [];
  const note = document.getElementById('mapnote');
  const mapEl = document.getElementById('map');
  if(!_map){
    _map = L.map('map', {worldCopyJump:true, minZoom:1})
             .setView([25, 10], 2);
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',
      {maxZoom:19,
       attribution:'&copy; OpenStreetMap contributors'}).addTo(_map);
    _markers = L.layerGroup().addTo(_map);
  }
  _markers.clearLayers();
  if(!pts.length){
    note.className = 'map-empty';
    note.innerHTML = d.geoip
      ? '<b>No geolocated attackers yet.</b><br>Loopback and private ' +
        'source IPs — including your own simulator runs — are never ' +
        'plotted. Real remote attackers will appear here.'
      : '<b>Geolocation is off.</b><br>Restart with ' +
        '<code>GULLAKTRAP_GEOIP=1</code> to place attacker IPs on the map.';
    note.style.display = '';
    mapEl.style.display = 'none';
    return;
  }
  note.style.display = 'none';
  note.className = '';
  note.innerHTML = '';
  mapEl.style.display = '';
  _map.invalidateSize();
  const max = Math.max.apply(null, pts.map(p=>p.events).concat([1]));
  pts.forEach(function(p){
    if(p.lat==null || p.lon==null) return;
    const hot = (p.crit||0) > 0;
    const r = 5 + 13 * Math.sqrt((p.events||1)/max);
    const color = hot ? '#ff3860' : '#ffb020';
    const tags = (p.threat_tags||'').split(',').filter(Boolean)
      .map(t=>'<span class="tag t-warn">'+esc(t)+'</span>').join(' ');
    L.circleMarker([p.lat, p.lon], {
      radius:r, color:color, weight:1.5, fillColor:color, fillOpacity:.35
    }).bindPopup(
      '<div style="min-width:170px">'+
      '<div style="font-size:15px"><b>'+ccFlag(p.country_code)+' '+esc(p.ip)+'</b></div>'+
      '<div>'+esc([p.city,p.country].filter(Boolean).join(', ')||'unknown')+'</div>'+
      '<div style="color:#888">'+esc(p.protocols||'')+' &middot; '+
        (p.events||0)+' events'+(p.crit?', '+p.crit+' critical':'')+'</div>'+
      '<div style="margin-top:4px">'+tags+'</div></div>'
    ).addTo(_markers);
  });
}

async function loadCreds(){
  const d = await (await fetch('/api/credentials')).json();
  const mp = Math.max.apply(null,(d.pairs||[]).map(p=>p.hits).concat([1]));
  document.getElementById('creds').innerHTML = table(
    ['Username','Password','Tries','Sources'],
    (d.pairs||[]).map(p=>'<tr><td class="mono">'+esc(p.username)+
      '</td><td class="mono">'+esc(p.password)+
      '</td><td class="num">'+p.hits+bar(p.hits,mp)+
      '</td><td class="num">'+p.sources+'</td></tr>'));

  [['usernames',d.usernames],['passwords',d.passwords],
   ['commands',d.commands]].forEach(function(pair){
    const rows = pair[1]||[];
    const mx = Math.max.apply(null, rows.map(r=>r.hits).concat([1]));
    document.getElementById(pair[0]).innerHTML = table(
      ['Value','Count'],
      rows.map(r=>'<tr><td class="mono">'+esc(r.value)+bar(r.hits,mx)+
        '</td><td class="num">'+r.hits+'</td></tr>'));
  });
}

async function loadSessions(){
  const d = await (await fetch('/api/sessions')).json();
  document.getElementById('sessions').innerHTML = table(
    ['When','Proto','Source','User','Cmds','Replay'],
    (d.sessions||[]).map(function(s){
      const can = s.keystrokes > 0;
      return '<tr><td>'+ts(s.started_at)+'</td><td class="mono">'+
        esc(s.protocol)+'</td><td class="mono">'+esc(s.ip)+
        '</td><td class="mono">'+esc(s.username||'--')+
        '</td><td class="num">'+(s.command_count||0)+'</td><td>'+
        (can ? '<button class="btn" onclick="showReplay('+s.id+
               ')">&#9658; play</button>'
             : '<span class="t-muted">--</span>')+'</td></tr>';
    }));
}

async function loadPayloads(){
  const d = await (await fetch('/api/payloads')).json();
  document.getElementById('payloads').innerHTML = table(
    ['When','Source','URL','Status','SHA-256'],
    (d.payloads||[]).map(p=>'<tr><td>'+ts(p.ts)+'</td><td class="mono">'+
      esc(p.ip)+'</td><td class="mono">'+esc((p.url||'').slice(0,60))+
      '</td><td><span class="tag '+
      (p.status==='captured'?'t-crit':'t-muted')+'">'+esc(p.status)+
      '</span></td><td class="mono">'+
      esc((p.sha256||'').slice(0,16)||'--')+'</td></tr>'));
}

/* ---------------- attacker profile ---------------- */
async function showAttacker(ip){
  const d = await (await fetch('/api/attacker/'+encodeURIComponent(ip))).json();
  if(d.error){ return; }
  const tags = (d.threat_tags||'').split(',').filter(Boolean)
    .map(t=>'<span class="tag t-warn">'+esc(t)+'</span>').join('');

  document.getElementById('modal-body').innerHTML =
    '<h3>'+esc(d.ip)+'</h3><div class="klabel">'+
    esc([d.city,d.country].filter(Boolean).join(', ')||'location not enriched')+
    '</div>'+tags+
    '<div class="grid g2" style="margin-top:14px">'+
      '<div><h2>Detail</h2>'+table(['Field','Value'],[
        '<tr><td>Organisation</td><td class="mono">'+esc(d.org||'--')+'</td></tr>',
        '<tr><td>ASN</td><td class="mono">'+esc(d.asn||'--')+'</td></tr>',
        '<tr><td>First seen</td><td>'+ts(d.first_seen)+'</td></tr>',
        '<tr><td>Last seen</td><td>'+ts(d.last_seen)+'</td></tr>',
        '<tr><td>Events</td><td class="num">'+(d.events||0)+'</td></tr>',
        '<tr><td>Protocols</td><td class="mono">'+esc(d.protocols||'')+'</td></tr>',
      ])+'</div>'+
      '<div><h2>Credentials tried</h2>'+table(['User','Pass'],
        (d.credentials||[]).slice(0,12).map(c=>'<tr><td class="mono">'+
          esc(c.username)+'</td><td class="mono">'+esc(c.password)+
          '</td></tr>'))+'</div>'+
    '</div>'+
    '<h2 style="margin-top:16px">Recent activity</h2>'+
    table(['When','Proto','Event','Detail'],
      (d.recent_events||[]).slice(0,20).map(e=>'<tr><td>'+ts(e.ts)+
        '</td><td class="mono">'+esc(e.protocol)+'</td><td><span class="tag t-'+
        esc(e.severity)+'">'+esc(e.type)+'</span></td><td class="mono">'+
        esc((e.details||'').slice(0,90))+'</td></tr>'));

  openModal();
}

/* ---------------- session replay ---------------- */
let replayTimer = null;

async function showReplay(id){
  const d = await (await fetch('/api/replay/'+id)).json();
  if(d.error) return;
  const s = d.session;

  document.getElementById('modal-body').innerHTML =
    '<h3>Session #'+s.id+' &mdash; '+esc(s.ip)+'</h3>'+
    '<div class="klabel">'+esc(s.protocol)+' &middot; '+ts(s.started_at)+
    ' &middot; user '+esc(s.username||'--')+'</div>'+
    '<div id="replay"></div>'+
    '<div class="replay-bar">'+
      '<button class="btn" id="rp-play">&#9658; replay</button>'+
      '<button class="btn" id="rp-all">show all</button>'+
      '<span class="speed">'+d.frames.length+' keystrokes captured</span>'+
    '</div>';

  const out = document.getElementById('replay');
  const frames = d.frames;

  function play(){
    clearTimeout(replayTimer);
    out.textContent = '';
    let i = 0;
    (function step(){
      if(i >= frames.length) return;
      out.textContent += frames[i].data;
      out.scrollTop = out.scrollHeight;
      const gap = i+1 < frames.length
        ? Math.min(600,(frames[i+1].offset - frames[i].offset)*1000)
        : 0;
      i++;
      replayTimer = setTimeout(step, Math.max(12, gap));
    })();
  }

  document.getElementById('rp-play').onclick = play;
  document.getElementById('rp-all').onclick = function(){
    clearTimeout(replayTimer);
    out.textContent = frames.map(f=>f.data).join('');
  };

  openModal();
  play();
}

function openModal(){ document.getElementById('modal').classList.add('open'); }
function closeModal(){
  clearTimeout(replayTimer);
  document.getElementById('modal').classList.remove('open');
}
document.getElementById('modal').addEventListener('click', function(e){
  if(e.target === this) closeModal();
});
document.addEventListener('keydown', function(e){
  if(e.key === 'Escape') closeModal();
});

/* ---------------- boot ---------------- */
function refresh(){
  loadOverview(); loadAttackers(); loadCreds();
  loadSessions(); loadPayloads(); loadMap();
}
document.addEventListener('DOMContentLoaded', function(){
  refresh();
  setInterval(refresh, 10000);
  window.addEventListener('resize', function(){
    fetch('/api/overview').then(r=>r.json()).then(d=>drawChart(d.timeline||[]));
  });
});
</script>
</body>
</html>
"""
