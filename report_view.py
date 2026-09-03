"""
Printable security report for GullakTrap.

A single self-contained page that summarises everything the honeypot has seen
-- executive KPIs, protocol/severity/ATT&CK breakdowns, top attackers with
geolocation, the credentials and commands attackers tried, and captured
payloads. It carries a "Save as PDF" button that calls window.print(); the
print stylesheet hides the chrome and lays the page out for paper, so the
operator gets a clean PDF with no extra tooling or dependencies.

main.py builds the context from the same storage.* reads the live dashboard
uses, so the report can never drift from what Analytics shows.
"""

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ brand.name }} — Security Report</title>
<style>
  :root{
    --ink:#14181f; --muted:#5b6472; --line:#e2e6ec; --bg:#f4f6f9;
    --card:#ffffff; --brand:#7b2ff7; --crit:#d6335b; --warn:#e08a1e;
    --ok:#2fa860; --info:#2f7fe0;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
  .page{max-width:960px;margin:0 auto;padding:32px 28px 60px;}
  .toolbar{position:sticky;top:0;background:var(--bg);padding:12px 0;
           display:flex;gap:10px;justify-content:flex-end;z-index:5;}
  .btn{border:0;border-radius:8px;padding:10px 16px;font-weight:600;
       cursor:pointer;font-size:13px;text-decoration:none;color:#fff;
       background:var(--brand);}
  .btn.ghost{background:#e9ecf2;color:var(--ink);}
  header.rpt{display:flex;justify-content:space-between;align-items:flex-end;
             border-bottom:3px solid var(--brand);padding-bottom:16px;
             margin-bottom:24px;}
  header.rpt h1{margin:0;font-size:26px;letter-spacing:.5px;}
  header.rpt .sub{color:var(--muted);font-size:13px;margin-top:4px;}
  header.rpt .meta{text-align:right;color:var(--muted);font-size:12px;}
  h2.section{font-size:15px;text-transform:uppercase;letter-spacing:1px;
             color:var(--brand);margin:32px 0 12px;
             border-left:4px solid var(--brand);padding-left:10px;}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
  .kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;
       padding:14px 16px;}
  .kpi .n{font-size:26px;font-weight:700;}
  .kpi .l{font-size:11px;text-transform:uppercase;letter-spacing:.5px;
          color:var(--muted);margin-top:2px;}
  .kpi.crit .n{color:var(--crit);}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:22px;}
  table{width:100%;border-collapse:collapse;background:var(--card);
        border:1px solid var(--line);border-radius:10px;overflow:hidden;
        font-size:13px;}
  th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);}
  th{background:#eef1f6;font-size:11px;text-transform:uppercase;
     letter-spacing:.5px;color:var(--muted);}
  tr:last-child td{border-bottom:0;}
  td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;}
  .mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;}
  .tag{display:inline-block;background:#f0e6ff;color:var(--brand);
       border-radius:20px;padding:1px 8px;font-size:11px;margin:1px 2px;}
  .sev{display:inline-block;width:9px;height:9px;border-radius:50%;
       margin-right:6px;vertical-align:middle;}
  .sev.crit{background:var(--crit);} .sev.warn{background:var(--warn);}
  .sev.ok{background:var(--ok);} .sev.info{background:var(--info);}
  .barwrap{background:#eef1f6;border-radius:6px;height:10px;overflow:hidden;
           min-width:80px;}
  .barwrap i{display:block;height:100%;background:var(--brand);}
  .spark{display:flex;align-items:flex-end;gap:2px;height:56px;
         padding:10px;background:var(--card);border:1px solid var(--line);
         border-radius:10px;}
  .spark i{flex:1;background:var(--brand);border-radius:2px 2px 0 0;
           min-height:2px;opacity:.85;}
  .empty{color:var(--muted);padding:14px;background:var(--card);
         border:1px dashed var(--line);border-radius:10px;}
  footer.rpt{margin-top:40px;color:var(--muted);font-size:11px;
             border-top:1px solid var(--line);padding-top:12px;}
  @media print{
    :root{--bg:#fff;}
    .toolbar{display:none;}
    body{background:#fff;}
    .page{max-width:none;padding:0;}
    .kpi,table,.spark,.empty{break-inside:avoid;}
    h2.section{break-after:avoid;}
  }
</style>
</head>
<body>
<div class="page">
  <div class="toolbar">
    <a class="btn ghost" href="/">&larr; Console</a>
    <button class="btn" onclick="window.print()">&#128424; Save as PDF</button>
  </div>

  <header class="rpt">
    <div>
      <h1>{{ brand.name }} — Security Incident Report</h1>
      <div class="sub">Honeypot threat-intelligence summary</div>
    </div>
    <div class="meta">
      Generated: {{ generated }}<br>
      Operator: {{ operator }}<br>
      Window: all recorded activity
    </div>
  </header>

  <h2 class="section">Executive summary</h2>
  <div class="kpis">
    <div class="kpi"><div class="n">{{ ov.events }}</div><div class="l">Total events</div></div>
    <div class="kpi"><div class="n">{{ ov.events_24h }}</div><div class="l">Last 24 h</div></div>
    <div class="kpi crit"><div class="n">{{ ov.critical }}</div><div class="l">Critical</div></div>
    <div class="kpi"><div class="n">{{ ov.attackers }}</div><div class="l">Unique sources</div></div>
    <div class="kpi"><div class="n">{{ ov.sessions }}</div><div class="l">Sessions</div></div>
    <div class="kpi"><div class="n">{{ ov.credentials }}</div><div class="l">Creds captured</div></div>
    <div class="kpi"><div class="n">{{ ov.commands }}</div><div class="l">Commands run</div></div>
    <div class="kpi"><div class="n">{{ ov.payloads }}</div><div class="l">Payloads</div></div>
  </div>

  <h2 class="section">Activity — last 24 hours</h2>
  {% if timeline %}
  <div class="spark">
    {% for t in timeline %}<i style="height:{{ t.pct }}%" title="{{ t.hour }}: {{ t.hits }}"></i>{% endfor %}
  </div>
  {% else %}<div class="empty">No activity recorded.</div>{% endif %}

  <div class="cols">
    <div>
      <h2 class="section">By protocol</h2>
      {% if protocols %}<table><tr><th>Protocol</th><th class="num">Events</th><th>Share</th></tr>
      {% for p in protocols %}<tr><td class="mono">{{ p.protocol }}</td>
        <td class="num">{{ p.hits }}</td>
        <td><div class="barwrap"><i style="width:{{ p.pct }}%"></i></div></td></tr>{% endfor %}
      </table>{% else %}<div class="empty">No data.</div>{% endif %}
    </div>
    <div>
      <h2 class="section">By severity</h2>
      {% if severity %}<table><tr><th>Severity</th><th class="num">Events</th><th>Share</th></tr>
      {% for s in severity %}<tr><td><span class="sev {{ s.severity }}"></span>{{ s.severity }}</td>
        <td class="num">{{ s.hits }}</td>
        <td><div class="barwrap"><i style="width:{{ s.pct }}%"></i></div></td></tr>{% endfor %}
      </table>{% else %}<div class="empty">No data.</div>{% endif %}
    </div>
  </div>

  <h2 class="section">MITRE ATT&amp;CK techniques observed</h2>
  {% if mitre %}<table><tr><th>Technique</th><th>Name</th><th class="num">Events</th></tr>
  {% for m in mitre %}<tr><td class="mono">{{ m.mitre }}</td><td>{{ m.name }}</td>
    <td class="num">{{ m.hits }}</td></tr>{% endfor %}
  </table>{% else %}<div class="empty">No techniques mapped yet.</div>{% endif %}

  <h2 class="section">Top attackers</h2>
  {% if attackers %}<table>
    <tr><th>Source IP</th><th>Location</th><th>Network</th><th class="num">Events</th><th>Tags</th></tr>
    {% for a in attackers %}<tr>
      <td class="mono">{{ a.flag }} {{ a.ip }}</td>
      <td>{{ a.where or '—' }}</td>
      <td>{{ a.org or '—' }}</td>
      <td class="num">{{ a.events }}</td>
      <td>{% for t in a.tags %}<span class="tag">{{ t }}</span>{% endfor %}</td>
    </tr>{% endfor %}
  </table>{% else %}<div class="empty">No attackers recorded.</div>{% endif %}

  <div class="cols">
    <div>
      <h2 class="section">Most-tried credentials</h2>
      {% if creds %}<table><tr><th>Username</th><th>Password</th><th class="num">Hits</th></tr>
      {% for c in creds %}<tr><td class="mono">{{ c.username }}</td>
        <td class="mono">{{ c.password }}</td><td class="num">{{ c.hits }}</td></tr>{% endfor %}
      </table>{% else %}<div class="empty">No credentials captured.</div>{% endif %}
    </div>
    <div>
      <h2 class="section">Commands executed</h2>
      {% if commands %}<table><tr><th>Command</th><th class="num">Hits</th></tr>
      {% for c in commands %}<tr><td class="mono">{{ c.value }}</td>
        <td class="num">{{ c.hits }}</td></tr>{% endfor %}
      </table>{% else %}<div class="empty">No commands recorded.</div>{% endif %}
    </div>
  </div>

  <h2 class="section">Captured payloads</h2>
  {% if payloads %}<table><tr><th>Source</th><th>URL</th><th>Status</th></tr>
  {% for p in payloads %}<tr><td class="mono">{{ p.ip or '—' }}</td>
    <td class="mono">{{ p.url }}</td><td>{{ p.status }}</td></tr>{% endfor %}
  </table>{% else %}<div class="empty">No payload URLs captured.</div>{% endif %}

  <footer class="rpt">
    {{ brand.name }} {{ brand.version }} &middot; Generated {{ generated }} &middot;
    Data source: {{ db_file }} &middot; Geolocation:
    {{ 'enabled' if geoip else 'disabled (set GULLAKTRAP_GEOIP=1)' }}.
    Report reflects only traffic this honeypot captured.
  </footer>
</div>
</body>
</html>
"""
