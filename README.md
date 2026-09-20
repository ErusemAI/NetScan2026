<div align="center">

```
  ███╗   ██╗███████╗████████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ██║     ███████║█████╗  ██║     █████╔╝
  ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
  ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
```

# NET//CHECK · v3.0

**⚡ Technopunk Network Scanner, Port Auditor & CVE Correlation Hub ⚡**

A multithreaded network reconnaissance engine that sweeps your LAN, fingerprints every live device, and renders a glowing cyber-telemetry HUD — complete with OS inference, MAC/vendor lookup, service banner grabbing, and curated vulnerability correlation.

[![Python 3.x](https://img.shields.io/badge/Python-3.x-4B8BBE?logo=python&logoColor=white)]
[![Node.js](https://img.shields.io/badge/Node.js-16+-339933?logo=nodedotjs&logoColor=white)]
[![MySQL](https://img.shields.io/badge/MySQL-5.7%20%7C%208.x-4479A1?logo=mysql&logoColor=white)]
[![License MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]
[![Status active](https://img.shields.io/badge/status-active-brightgreen)]

</div>

---

## ⚡ Features

- 📡 **Multithreaded ping sweep** — fast ICMP discovery across an entire subnet (50 threads by default).
- 🔌 **TCP port probing + banner grabbing** — 18 curated service ports with live application banners.
- 🧬 **MAC / OUI vendor lookup** — correlates ARP-table entries against a built-in OUI database for hardware-vendor identification.
- 🖥️ **OS inference engine** — heuristically fingerprints the likely operating system of each node.
- 🛡️ **CVE correlation hub** — matches open ports & services against a curated defensive knowledge base (EternalBlue and other advisories) with CVSS severity ratings.
- 🌐 **Technopunk HTML telemetry HUD** — auto-refreshing dashboard (`netcheck.html`) with live radar, device grid, and per-device deep-intel modals.
- 🔁 **Continuous watch mode** — `--watch` keeps the radar sweeping and the HUD updating in real time.
- 📦 **Zero-dependency core** — the scanner is pure Python 3 standard library; no `pip install` required.

## 🛰️ How It Works

```
   ┌────────────┐   ┌───────────────┐   ┌──────────────┐   ┌──────────────┐
   │ Ping Sweep │ → │ TCP Port Probe│ → │ Banner Grab  │ → │ OS + CVE     │
   │ (ICMP)     │   │ (18 services) │   │ (service ID) │   │ Inference    │
   └────────────┘   └───────────────┘   └──────────────┘   └──────────────┘
        ↓                    ↓                   ↓                  ↓
   MAC / OUI lookup  ←── ARP-table correlation ──→  CVE knowledge base
        └──────────────────────────────────────────────────┐
                                                           ↓
              Technopunk HTML reports + live scan_status.json telemetry
```

## 📊 Generated Reports

Every run renders a full set of self-contained, dark-themed technopunk artifacts:

| Artifact | Purpose |
| --- | --- |
| `netcheck.html` | **Main dashboard** — live radar HUD, device grid, auto-refreshing telemetry (polls every ~4 s). |
| `devices/index.html` | Navigable **device directory / overview**. |
| `devices/device_<ip>.html` | Standalone **deep-intel profile** per device: open ports, banners, MAC/vendor, OS guess, CVE hits. |
| `devices/scan_status.json` | Live **scan-status JSON** consumed by the HUD for real-time updates. |

> A full sample scan of a live `/24` network is bundled in [`devices/`](devices/) so you can open the dashboard straight from the repo.

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/ErusemAI/NetScan2026.git
cd NetScan2026

# 2. Scan your local network (auto-detects subnet)
python3 check_network.py

# 3. Or target a specific subnet / host
python3 check_network.py 192.168.42.0/24
python3 check_network.py 192.168.42.1

# 4. Watch mode — live radar, refresh every 5 s
python3 check_network.py 192.168.42.0/24 -W -i 5

# 5. Raw JSON telemetry (no HTML)
python3 check_network.py 192.168.42.0/24 --json
```

Open the generated `netcheck.html` in any browser to view the HUD. See [INSTALL.md](INSTALL.md) for full setup, output-path options, and platform notes.

## ⌨️ CLI Reference

| Flag | Default | Description |
| --- | --- | --- |
| `target` *(positional)* | auto-detect local network | Subnet CIDR (e.g. `192.168.42.0/24`) or a single IP to scan. |
| `-t`, `--threads` | `50` | Number of concurrent scanner threads. |
| `-w`, `--timeout` | `1.0` | Ping timeout in seconds. |
| `-W`, `--watch` | off | Continuous live-monitoring mode. |
| `-i`, `--interval` | `5` | Watch-mode refresh interval (seconds). |
| `--html-file` | `/var/www/html/netcheck.html` | Primary dashboard output path. |
| `-p`, `--primary-dir` | `/var/www/html/devices` | Primary directory for device pages + `scan_status.json`. |
| `-f`, `--fallback-dir` | local `devices/` | Local fallback report directory (used when the web root isn't writable). |
| `-I`, `--iface` | `eth0` | Network interface to probe. |
| `-R`, `--ip-range` | `192.168.1.0/24` | CIDR used for auto-detection. |
| `--json` | off | Emit raw telemetry as JSON instead of the HUD. |
| `--no-html` | off | Skip HTML report generation. |
| `--no-color` | off | Disable ANSI colors in terminal output. |
| `-h`, `--help` | — | Print help and exit. |

## 🖥️ Web Backend (Node / Express + MySQL)

An optional backend serves the static HUD over HTTP and persists scans, users, and permissions to MySQL on port **3000**.

```bash
npm install
cp backend/config/connection.example.json backend/config/connection.json   # then edit credentials
npm start        # → http://localhost:3000
```

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/scans` | GET / POST | List or create scan records. |
| `/admin/login` | POST | Create/authenticate an admin user (bcrypt-hashed). |
| `/api/users` | GET | List users and roles. |

## 📁 Project Layout

```
NetScan2026/
├── check_network.py            # Scanner engine + technopunk report generator (core)
├── netcheck.html               # Generated main dashboard (sample output)
├── devices/                    # Sample telemetry from a live /24 scan
│   ├── index.html              #   Device directory
│   ├── admin.html              #   Admin view
│   ├── device_<ip>.html        #   Per-device deep-intel pages
│   └── scan_status.json        #   Live HUD telemetry feed
├── backend/
│   ├── server.js               # Node / Express + MySQL API server
│   ├── db.sql                  # Reference schema (auto-created on start)
│   └── config/
│       └── connection.example.json  # DB config template (copy to connection.json)
├── package.json                # Backend dependencies & scripts
├── README.md
├── INSTALL.md
├── CHANGELOG.md
└── LICENSE                     # MIT
```

## 🛡️ CVE Severity Legend

| Severity | CVSS | Meaning |
| --- | --- | --- |
| 🔴 **CRITICAL** | 9.0 – 10.0 | Unauthenticated RCE / wormable — patch immediately. |
| 🟠 **HIGH** | 7.0 – 8.9 | Significant, likely-exploitable exposure. |
| 🟡 **MEDIUM** | 4.0 – 6.9 | Conditional or lower-impact risk. |
| 🟢 **LOW** | 0.1 – 3.9 | Minor / informational. |

## 🔌 Tech Stack

- **Python 3** (standard library only) — scanner engine & report generator.
- **Node.js + Express** — optional web backend.
- **MySQL** (`mysql2`) — scan / user / permission persistence.
- **bcryptjs** — password hashing for the admin API.

## 📄 License

Released under the [MIT License](LICENSE). © 2026 ErusemAI.

<div align="center">

*NET//CHECK v3.0 · Technopunk Cyber Intelligence Engine · Built 2026-09-20*

</div>
