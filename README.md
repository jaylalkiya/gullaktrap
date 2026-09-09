<div align="center">

# GullakTrap

**A modular, multi-protocol honeypot with live threat intelligence, MITRE ATT&CK classification, and a built-in red-team simulator.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0%2B-black.svg)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-v2.0-brightgreen.svg)]()

*Deception Grid · Intrusion Capture System*

</div>

---

## Overview

GullakTrap presents seven deliberately vulnerable-looking network services to
the internet. Its only job is to let attackers "break in" and record everything
they do — credentials tried, commands run, files touched, malware URLs fetched.

Every captured event is scored for severity, mapped to a **MITRE ATT&CK**
technique, enriched with threat intelligence about the source IP, and pushed to
a live web console. A bundled red-team simulator exercises the entire pipeline
end to end, so you can validate detection and alerting without waiting for a
real intruder.

> **Why the name?** A *gullak* is a traditional Indian clay coin bank — it has
> no lid, and must be broken open to be emptied. Attackers come for what looks
> like an easy prize and leave their fingerprints on the way in.

### Table of contents

- [Sensors](#sensors)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Attack simulator](#attack-simulator)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Security & scope](#security--scope)
- [License](#license)

---

## Sensors

Each sensor is an independent, self-contained decoy that can be started and
stopped from the console at runtime.

| Protocol | Default port | Transport | What it captures |
|---|---|---|---|
| **HTTP** | `8080` | TCP | SQLi, XSS, path traversal, scanner user-agents, credential POSTs |
| **FTP** | `2121` | TCP | Credential brute force, directory listing, file upload/download |
| **SSH** | `2222` | TCP | Credential brute force, full interactive shell session + keystroke timing |
| **Telnet** | `2323` | TCP | Credential brute force, IoT-style shell commands |
| **SMB** | `445` | TCP | Session setup, share enumeration, worm/ransomware probing |
| **SMTP** | `25` | TCP | `AUTH LOGIN` credential capture, `VRFY` enumeration, open-relay probing |
| **SNMP** | `161` | UDP | Community-string brute force, OID walks, device fingerprinting |

> **Privileged ports:** SMB (`445`), SMTP (`25`), and SNMP (`161`) are below
> 1024 and require root/Administrator to bind. Without elevation, set a high
> port in the console instead — for example `1445`, `2525`, or `1161`.

---

## Capabilities

**Detection & analysis**
- **Attack classification** — every event is assigned a severity and mapped to
  a MITRE ATT&CK technique (`classify.py`).
- **Threat-intel enrichment** — geolocation, network owner, and Tor / VPN /
  datacenter plus behavioural tagging per source IP (`intel.py`, opt-in).
- **Session replay** — replays an attacker's SSH keystrokes with their original
  inter-keystroke timing.
- **Payload capture** — records malware URLs attackers attempt to pull, with
  optional quarantined download.

**Console & reporting**
- **Live web console** on `:5000` — start/stop sensors, real-time attack feed,
  editable banners and served content, per-sensor event counters.
- **World attack map** — Leaflet map plotting geolocated attackers, sized by
  volume and coloured by severity.
- **Printable report** — a print-optimised `/report` view for one-click *Save as
  PDF*.
- **CSV export** for every table, for offline analysis.

**Operations**
- **Alerting** — optional Slack/Discord webhook or Telegram push on critical
  events (`alerting.py`).
- **Red-team simulator** — `attack_sim.py`, also wired to a **⚔ Launch
  Simulated Attack** button in the console.

---

## Architecture

```
   attacker traffic
          |
          v
+---------------------------------------------------+
|  SENSORS                                           |
|  http · ftp · ssh · telnet · smb · smtp · snmp     |
+---------------------------------------------------+
          |  raw events
          v
+---------------------------------------------------+
|  EVENT PIPELINE  (main.py)                         |
|                                                    |
|  classify.py  ->  severity + MITRE ATT&CK          |
|  intel.py     ->  geo / ASN / Tor / VPN tagging    |
|  capture.py   ->  payload URL capture              |
+---------------------------------------------------+
          |                              |
          v                              v
+--------------------+        +----------------------+
|  storage.py        |        |  alerting.py         |
|  SQLite ledger     |        |  webhook / Telegram  |
+--------------------+        +----------------------+
          |
          v
+---------------------------------------------------+
|  PRESENTATION                                      |
|  console · analytics_view.py · report_view.py      |
+---------------------------------------------------+
```

---

## Installation

**Requirements:** Python 3.10 or newer.

```bash
git clone https://github.com/jaylalkiya/gullaktrap.git
cd gullaktrap
pip install -r requirements.txt
```

Dependencies are intentionally minimal — `flask` for the console and `paramiko`
for the SSH sensor.

---

## Quick start

**1. Launch the console**

```bash
python main.py
```

You will be prompted for an operator username and password. This protects the
dashboard; it is *not* an attacker-facing credential. To skip the prompt:

```bash
# Windows PowerShell
$env:HONEYPOT_USER="admin"; $env:HONEYPOT_PASS="secret"; python main.py

# Linux / macOS
HONEYPOT_USER=admin HONEYPOT_PASS=secret python main.py
```

**2. Open the console**

Navigate to <http://localhost:5000>, log in, and start the sensors you want.

**3. Verify the pipeline**

```bash
python attack_sim.py
```

Or click **⚔ Launch Simulated Attack** in the console. Then watch **Attack
Logs** populate, and open **INTEL** for the map, charts, MITRE breakdown, and
the PDF report.

> If a default port is already in use, change it in the console and pass the
> matching `--<sensor>-port` flag to the simulator.

---

## Attack simulator

`attack_sim.py` speaks each sensor's native protocol and fires realistic,
staged attacks: credential brute force and post-login shell activity
(`cat /etc/passwd`, `wget` of malware, `rm -rf`) against SSH/FTP/Telnet;
injection and traversal payloads against HTTP; and protocol-specific abuse
against SMB, SMTP, and SNMP.

```bash
python attack_sim.py                       # every sensor, localhost, default ports
python attack_sim.py --only ssh,telnet     # target a subset
python attack_sim.py --skip ftp --delay 2  # skip a sensor, pause between sensors
python attack_sim.py --brute 10            # 10 credential attempts per sensor
python attack_sim.py --scenario recon,brute
python attack_sim.py --smb-port 1445       # match a non-default console port
```

| Flag | Purpose | Default |
|---|---|---|
| `--host` | Target host | `127.0.0.1` |
| `--only` / `--skip` | Comma-separated sensor include / exclude list | all |
| `--scenario` | `recon`, `brute`, `exploit`, `malware`, `shell`, `persist` | `all` |
| `--brute` | Credential attempts per brute-forceable sensor | `5` |
| `--delay` | Seconds to pause between sensors | `0` |
| `--<sensor>-port` | Override a sensor's port | per-sensor default |
| `--yes-i-own-this` | Required to target a non-local host | off |

### Built-in safety

- The target defaults to `127.0.0.1`. Any non-loopback, non-RFC1918 host is
  **refused** unless you explicitly pass `--yes-i-own-this`.
- Simulated malware URLs use the non-routable **RFC 5737** documentation
  address range, so nothing real is ever fetched.

This tool is for exercising honeypots **you operate**. Nothing else.

---

## Configuration

All configuration is via environment variables — no secrets are stored in the
repository.

| Variable | Purpose | Default |
|---|---|---|
| `HONEYPOT_USER` / `HONEYPOT_PASS` | Console login (skips the interactive prompt) | prompts |
| `GULLAKTRAP_GEOIP` | `1` enables IP geolocation and Tor/VPN lookups | off |
| `GULLAKTRAP_WEBHOOK` | Slack/Discord webhook URL for alerts | off |
| `GULLAKTRAP_TG_TOKEN` / `GULLAKTRAP_TG_CHAT` | Telegram bot token and chat ID | off |
| `GULLAKTRAP_ALERT_LEVEL` | Minimum severity to alert on (`crit` or `warn`) | `crit` |
| `GULLAKTRAP_FETCH_PAYLOADS` | `1` downloads captured malware URLs to `quarantine/` | off |

> **On `GULLAKTRAP_FETCH_PAYLOADS`:** this fetches attacker-controlled URLs from
> your host. It is off by default and should only be enabled inside an isolated
> analysis environment.

> **On the world map:** with `GULLAKTRAP_GEOIP=1`, real attacker IPs are plotted.
> Loopback and private-range sources — including your own simulator runs — are
> never mapped, so the map fills in only when genuine remote traffic reaches an
> exposed sensor.

---

## Project layout

| Path | Responsibility |
|---|---|
| `main.py` | Flask console, routes, event sink, dashboard template |
| `ssh_honeypot.py` | SSH sensor (Paramiko, interactive shell emulation) |
| `ftp_honeypot.py` | FTP sensor |
| `http_honeypot.py` | HTTP sensor |
| `telnet_honeypot.py` | Telnet sensor |
| `smb_honeypot.py` | SMB sensor |
| `smtp_honeypot.py` | SMTP sensor |
| `snmp_honeypot.py` | SNMP sensor (UDP) |
| `attack_sim.py` | Red-team attack simulator |
| `classify.py` | Severity scoring and MITRE ATT&CK mapping |
| `intel.py` | GeoIP and threat-intel enrichment |
| `capture.py` | Payload URL capture and optional quarantine download |
| `alerting.py` | Webhook and Telegram alerting |
| `storage.py` | SQLite persistence and analytics queries |
| `analytics_view.py` | Intelligence dashboard — charts, map, session replay |
| `report_view.py` | Printable report template |
| `branding.py` | Name, palette, theme, and UI copy |
| `netutil.py` | Port and network helpers |
| `static/fx.js` | Console visual effects |

### Runtime artifacts

These are generated at runtime and excluded from version control:

```
gullaktrap.db          SQLite event ledger
gullaktrap_logs.json   JSON event log
ssh_host_key.rsa       generated SSH host key
uploads/               files attackers upload
ftp_files/ ssh_files/ telnet_files/    files served to attackers
quarantine/            downloaded payloads (opt-in)
```

---

## Security & scope

GullakTrap is a **defensive** security research tool.

- Deploy sensors only on infrastructure you own or are explicitly authorised to
  operate.
- Use the attack simulator only against your own honeypot.
- A honeypot is intentionally attractive to attackers. Run it isolated from
  production networks and treat everything it captures as hostile input.
- Never enable payload downloading outside a sandboxed analysis environment.

Do not point any part of this project at systems you do not own or are not
authorised to test.

---

## License

No license has been specified for this project yet. Until one is added, all
rights are reserved and the code is not licensed for redistribution or reuse.
