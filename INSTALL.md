# 📦 Installation Guide — NET//CHECK v3.0 (NetScan2026)

This guide covers two independent parts of the project:

1. **The Python scanner** (`check_network.py`) — the core engine. No installation required.
2. **The optional web backend** (`backend/`) — Node / Express + MySQL, for serving the HUD over HTTP and persisting scans/users.

You can run either or both.

---

## 1. Prerequisites

| Component | Version | Needed for |
| --- | --- | --- |
| Python | 3.8+ | Scanner (standard library only — no `pip install`) |
| Node.js + npm | 16+ | Web backend (optional) |
| MySQL / MariaDB | 5.7 / 8.x or 10.x | Web backend persistence (optional) |

> **Platform note:** The scanner is built for **Linux** (it uses `ip`, `ping`, and the system ARP table). It also runs on **macOS** if you pass a target explicitly, and works on **Windows via WSL2**. See [Troubleshooting](#5-troubleshooting).

---

## 2. Get the Code

```bash
git clone https://github.com/ErusemAI/NetScan2026.git
cd NetScan2026
```

---

## 3. Part A — Run the Scanner (no install)

The scanner is pure Python 3 standard library, so you can run it directly:

### Basic runs

```bash
# Auto-detect and scan your local network
python3 check_network.py

# Scan a specific subnet
python3 check_network.py 192.168.42.0/24

# Deep-scan a single host
python3 check_network.py 192.168.42.1
```

### Useful variations

```bash
# Live radar — continuous monitoring, refresh every 5 seconds
python3 check_network.py 192.168.42.0/24 -W -i 5

# More aggressive concurrency + longer ping timeout
python3 check_network.py 192.168.42.0/24 -t 80 -w 2

# Raw JSON telemetry (skip the HTML HUD)
python3 check_network.py 192.168.42.0/24 --json

# Write reports to a local folder instead of /var/www/html (no root needed)
python3 check_network.py 192.168.42.0/24 \
    --html-file ./netcheck.html -p ./devices -f ./devices
```

### Where the reports go

On each run the scanner writes to **two destinations**:

- **Primary** — `--html-file` (default `/var/www/html/netcheck.html`) plus a sibling `devices/` directory. This is where you'd serve it from a web server.
- **Local fallback** — a local copy under your home directory, used automatically when the primary path isn't writable.

Override any of these with `--html-file`, `-p/--primary-dir`, and `-f/--fallback-dir`. After a run, open `netcheck.html` in a browser to view the HUD.

---

## 4. Part B — Web Backend + MySQL (optional)

### 1. Install dependencies

```bash
npm install
```

### 2. Configure the database connection

The backend reads its DB credentials from `backend/config/connection.json`. A template is provided:

```bash
cp backend/config/connection.example.json backend/config/connection.json
# then edit backend/config/connection.json with your MySQL host / user / password
```

Example `connection.json`:

```json
{
  "host": "localhost",
  "user": "root",
  "password": "your_password_here",
  "database": "netscan"
}
```

> The real `connection.json` is git-ignored so your credentials never get committed.

### 3. (Optional) Pre-create the schema

The server auto-creates the `netscan` database and its tables on first start, but you can also load the reference schema manually:

```bash
mysql -u root -p < backend/db.sql
```

Tables created: `users`, `scans`, `permissions`.

### 4. Start the server

```bash
npm start        # node backend/server.js
# → Net‑Scan backend running on :3000
```

The server serves the static HUD from the project root and exposes these endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/scans` | GET | List all scan records. |
| `/api/scans` | POST | Create a scan record (`{ "name": "..." }`). |
| `/admin/login` | POST | Create/authenticate an admin user (bcrypt-hashed). Body: `{ "username", "password" }`. |
| `/api/users` | GET | List users and roles. |

---

## 5. Troubleshooting

**`PermissionError` writing to `/var/www/html`**
The default primary path is a web root that usually needs elevated access. Either run with `sudo`, or point the output somewhere you own:

```bash
python3 check_network.py 192.168.42.0/24 --html-file ./netcheck.html -p ./devices -f ./devices
```

**Auto-detection fails (macOS / non-Linux)**
Subnet auto-detection uses the Linux `ip` command. On macOS or other systems, pass the target and range explicitly:

```bash
python3 check_network.py 192.168.42.0/24 -R 192.168.42.0/24 --iface en0
```

**Wrong interface name**
The default interface is `eth0`. If your NIC differs (e.g. `en0`, `wlan0`), set it:

```bash
python3 check_network.py -I en0
```

**No devices found on a /24**
Some hosts block ICMP. Lower the timeout and increase threads, or scan a single known host to confirm reachability:

```bash
python3 check_network.py 192.168.42.1 -w 2
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).
