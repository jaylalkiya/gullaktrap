# GullakTrap — Deception Grid (v2.0)

A modular, multi-protocol **honeypot** with a live web console, threat-intel
enrichment, MITRE ATT&CK classification, session replay, a world attack map,
a printable PDF report — and a built-in **red-team attack simulator** to test
it all end to end.

GullakTrap pretends to be a set of vulnerable services (SSH, FTP, HTTP, Telnet).
Its only job is to let attackers "break in" and record everything they do:
credentials tried, commands run, files touched, malware URLs fetched. Every
event is classified by severity and mapped to a MITRE ATT&CK technique, then
surfaced on a live dashboard.

---

## Features

- **Four fake sensors** — SSH (`2222`), FTP (`2121`), HTTP (`8080`), Telnet
  (`2323`) — each a convincing decoy that logs attacker behaviour.
- **Live console** (`:5000`) — start/stop sensors, live attack feed, custom
  banners and served content.
- **Attack classification** — every event tagged with a severity and a
  **MITRE ATT&CK** technique (`classify.py`).
- **Threat-intel enrichment** — geolocation, network owner, Tor/VPN/datacenter
  and behavioural tags per attacker IP (`intel.py`, opt-in).
- **World attack map** — Leaflet map plotting geolocated attackers, sized by
  volume and coloured by severity (Analytics page).
- **Session replay** — replays an attacker's SSH keystrokes with original
  timing.
- **Printable PDF report** — `/report`, one-click *Save as PDF*.
- **Red-team attack simulator** — `attack_sim.py` and a **⚔ Launch Simulated
  Attack** button that fire realistic attacks at your own running sensors so
  you can verify capture → classify → alert → dashboard without waiting for a
  real intruder.
- **Alerting** — optional Slack/Discord webhook or Telegram push on critical
  events (`alerting.py`).
- **Payload capture** — records malware URLs attackers try to pull; optional
  quarantined download.
- **CSV export** of every table for offline analysis.

---

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`:

```
pip install -r requirements.txt
```

(`flask` for the console, `paramiko` for the SSH sensor.)

---

## Quick start

**1. Start the console** (Terminal 1):

```bash
python main.py
```

It asks for an operator username/password (this protects the dashboard, it is
not an attacker credential). To skip the prompt:

```bash
# Windows PowerShell
$env:HONEYPOT_USER="admin"; $env:HONEYPOT_PASS="secret"; python main.py
# Linux/macOS
HONEYPOT_USER=admin HONEYPOT_PASS=secret python main.py
```

**2. Open** http://localhost:5000 and log in. Start the sensors you want.

**3. Test it with the attack simulator** (Terminal 2):

```bash
python attack_sim.py
```

or click **⚔ Launch Simulated Attack** on the console. Then watch the **Attack
Logs** and open **INTEL** (Analytics) for the map, charts, MITRE breakdown, and
the **📄 PDF report**.

> If port `8080` is already in use, change the HTTP sensor's port in the
> dashboard and pass `--http-port <port>` to the simulator.

---

## The attack simulator

`attack_sim.py` speaks each sensor's dialect and fires realistic attacks:
SSH/FTP/Telnet credential brute force + shell commands (`cat /etc/passwd`,
`wget` malware, `rm -rf`), and HTTP SQLi / XSS / path-traversal / scanner
user-agents / credential POSTs.

```bash
python attack_sim.py                    # all sensors, localhost, default ports
python attack_sim.py --only ssh,telnet  # subset
python attack_sim.py --brute 10         # 10 credential attempts per sensor
python attack_sim.py --skip ftp --delay 2
```

**Safety:** the target defaults to `127.0.0.1`. Aiming at any non-local host is
refused unless you pass `--yes-i-own-this`. Simulated malware URLs use the
non-routable RFC 5737 documentation range, so nothing real is ever fetched.
This tool is for testing honeypots **you operate** — nothing else.

---

## Configuration (environment variables)

| Variable | Purpose | Default |
|---|---|---|
| `HONEYPOT_USER` / `HONEYPOT_PASS` | Console login (skips the prompt) | — (prompts) |
| `GULLAKTRAP_GEOIP` | `1` enables IP geolocation + Tor/VPN lookups (needed for the map to show real attackers) | off |
| `GULLAKTRAP_WEBHOOK` | Slack/Discord webhook URL for alerts | off |
| `GULLAKTRAP_TG_TOKEN` / `GULLAKTRAP_TG_CHAT` | Telegram bot token + chat id for alerts | off |
| `GULLAKTRAP_ALERT_LEVEL` | Minimum severity to alert on (`crit` or `warn`) | `crit` |
| `GULLAKTRAP_FETCH_PAYLOADS` | `1` downloads captured malware URLs to `quarantine/` (off by default — it fetches attacker-controlled URLs) | off |

> **Geolocation & the map:** with `GULLAKTRAP_GEOIP=1`, real attacker IPs are
> placed on the world map. Local/private sources (e.g. your own tests from
> `127.0.0.1`, including the attack simulator) are never mapped — the map fills
> in only when real remote attackers hit an exposed sensor.

---

## Project layout

| File | Responsibility |
|---|---|
| `main.py` | Flask console, routes, event sink, dashboard template |
| `ssh_honeypot.py` `ftp_honeypot.py` `http_honeypot.py` `telnet_honeypot.py` | The four fake sensors |
| `attack_sim.py` | Red-team attack simulator |
| `classify.py` | Severity + MITRE ATT&CK mapping |
| `intel.py` | GeoIP / threat-intel enrichment |
| `capture.py` | Payload URL capture + optional quarantine download |
| `alerting.py` | Webhook / Telegram alerts |
| `storage.py` | SQLite persistence + analytics reads |
| `analytics_view.py` | Intelligence dashboard (charts, map, replay) |
| `report_view.py` | Printable PDF report template |
| `branding.py` | Name, theme, palette |
| `netutil.py` | Port helpers |

Data lands in `gullaktrap.db` (SQLite). Captured/served files live under
`uploads/`, `ftp_files/`, `ssh_files/`, `telnet_files/`, and `quarantine/`.

---

## Ethics & scope

GullakTrap is a **defensive** research tool. Run the sensors only on
infrastructure you control, and use the attack simulator only against your own
honeypot. Do not point any part of this at systems you do not own or are not
authorised to test.
