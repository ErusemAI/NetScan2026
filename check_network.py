#!/usr/bin/env python3
"""
check_network.py — Technopunk Network Device Scanner & Cyber Telemetry Hub
==========================================================================
Full-featured network reconnaissance, device health monitoring, port auditing,
and CVE vulnerability correlation engine with live web telemetry HUD.

Features:
  - Technopunk ASCII Splash Screen
  - Live Scanner Radar & Terminal HUD on web interface (auto-updating every 3-5s)
  - Interactive deep device modal on 'Role / Hostname' click
  - Individual standalone deep detail pages (/devices/device_<ip>.html)
  - Secondary navigable overview directory (/devices/index.html)
  - High-performance multithreaded port scanner & banner grabber
  - System / OS inference engine
  - Curated defensive CVE vulnerability knowledge base & security advisories
  - Continuous watch mode (--watch) updating HTML & JSON telemetry
"""

import argparse
import concurrent.futures
import csv
import html
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

# ANSI Color Codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;196m"
    GREEN = "\033[38;5;48m"
    YELLOW = "\033[38;5;220m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    CYAN = "\033[38;5;51m"
    WHITE = "\033[38;5;231m"
    GRAY = "\033[38;5;244m"


def disable_colors():
    Colors.RESET = ""
    Colors.BOLD = ""
    Colors.DIM = ""
    Colors.RED = ""
    Colors.GREEN = ""
    Colors.YELLOW = ""
    Colors.BLUE = ""
    Colors.MAGENTA = ""
    Colors.CYAN = ""
    Colors.WHITE = ""
    Colors.GRAY = ""


def print_splashscreen():
    """Prints a technopunk cyber splash banner in the terminal."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
  ███╗   ██╗███████╗████████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ██║     ███████║█████╗  ██║     █████╔╝ 
  ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
  ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝{Colors.RESET}
  {Colors.MAGENTA}⚡ T E C H N O P U N K // C Y B E R   N E T   R A D A R ⚡{Colors.RESET}
  {Colors.GRAY}[ v3.0 // Deep Telemetry, Port Auditing & CVE Correlation Hub ]{Colors.RESET}
"""
    print(banner, file=sys.stderr)


# ==============================================================================
# Port & Service Catalog
# ==============================================================================
PORT_SERVICE_MAP = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Shell)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Hypertext Transfer Protocol)",
    135: "MSRPC (Microsoft RPC Endpoint)",
    139: "NetBIOS (NetBIOS Session Service)",
    443: "HTTPS (HTTP over TLS/SSL)",
    445: "SMB (Microsoft Directory Services / Samba)",
    554: "RTSP (Real Time Streaming Protocol / IP Camera)",
    1883: "MQTT (Message Queuing Telemetry / IoT Broker)",
    3306: "MySQL (Database Server)",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "UPnP / Python REST API",
    8000: "HTTP-Alt (Common Web Service)",
    8080: "HTTP-Proxy / Alternate Web Server",
    8443: "HTTPS-Alt (Secure Web Management)",
    8888: "HTTP-Alt / Administration Portal",
    9000: "Portainer / SonarQube",
}

DEFAULT_SCAN_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 1883, 3306, 3389, 5000, 8000, 8080, 8443, 8888]

# ==============================================================================
# Curated Defensive CVE Knowledge Base
# ==============================================================================
CVE_KNOWLEDGE_BASE = [
    {
        "id": "CVE-2017-0144",
        "title": "EternalBlue / MS17-010 SMBv1 Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "ports": [445, 139],
        "device_types": ["all"],
        "summary": "Flaw in SMBv1 allows unauthenticated remote attackers to execute arbitrary code via specially crafted packets.",
        "mitigation": "Disable SMBv1 entirely across all hosts. Restrict SMB access via host firewall to authenticated LAN clients."
    },
    {
        "id": "CVE-2020-0796",
        "title": "SMBGhost SMBv3 Compression Buffer Overflow",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "ports": [445],
        "device_types": ["all"],
        "summary": "Improper handling of compression transforms in SMBv3.1.1 allows remote unauthenticated execution.",
        "mitigation": "Apply security patches. Disable SMBv3 compression if running vulnerable legacy builds."
    },
    {
        "id": "CVE-2024-6387",
        "title": "regreSSHion — OpenSSH Signal Handler Race Condition",
        "severity": "HIGH",
        "cvss": 8.1,
        "ports": [22],
        "device_types": ["all"],
        "summary": "Race condition in OpenSSH sshd signal handling leading to potential pre-authentication code execution as root on glibc Linux.",
        "mitigation": "Upgrade OpenSSH to version 9.8p1 or newer. Set LoginGraceTime to 0 in sshd_config as a temporary workaround."
    },
    {
        "id": "CVE-2023-48795",
        "title": "Terrapin Attack — SSH Protocol Sequence Manipulation",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "ports": [22],
        "device_types": ["all"],
        "summary": "Prefix truncation attack during SSH handshake allows integrity breach and downgrade of extension negotiation.",
        "mitigation": "Implement Strict KEX mode ('kex-strict') in OpenSSH and disable chacha20-poly1305 / CBC ciphers if unpatched."
    },
    {
        "id": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "ports": [80, 8080, 8000],
        "device_types": ["all"],
        "summary": "Path traversal flaw in Apache HTTP Server 2.4.49/2.4.50 allows unauthorized file mapping and execution with mod_cgi.",
        "mitigation": "Ensure Apache is upgraded to version 2.4.51 or later. Verify 'Require all denied' default configuration on root directory."
    },
    {
        "id": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset Distributed Denial of Service",
        "severity": "HIGH",
        "cvss": 7.5,
        "ports": [80, 443, 8443],
        "device_types": ["all"],
        "summary": "Rapid reset of HTTP/2 streams exhausts server CPU resources and causes denial of service.",
        "mitigation": "Apply vendor web server security patches and configure connection rate limits on HTTP/2 streams."
    },
    {
        "id": "CVE-2014-0160",
        "title": "Heartbleed — OpenSSL TLS Heartbeat Information Disclosure",
        "severity": "HIGH",
        "cvss": 7.5,
        "ports": [443, 8443],
        "device_types": ["all"],
        "summary": "Missing bounds check in TLS heartbeat handling allows remote memory exposure including private keys and credentials.",
        "mitigation": "Verify OpenSSL version >= 1.0.1g or modern 3.x series. Enforce TLS 1.2+."
    },
    {
        "id": "CVE-2020-10188",
        "title": "Netkit Telnetd Buffer Overflow & Cleartext Exposure",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "ports": [23],
        "device_types": ["all"],
        "summary": "Legacy Telnet protocol transmits credentials unencrypted over the wire and suffers from multiple utility buffer overflows.",
        "mitigation": "Disable Telnet daemon immediately. Transition all remote administration to SSH with key-based authentication."
    },
    {
        "id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor & Plaintext Credential Sniffing",
        "severity": "HIGH",
        "cvss": 7.5,
        "ports": [21],
        "device_types": ["all"],
        "summary": "FTP sends user credentials in plaintext across the local network and legacy packages contain critical vulnerabilities.",
        "mitigation": "Disable anonymous FTP; replace plain FTP with SFTP (port 22) or FTPS with enforced TLS certificates."
    },
    {
        "id": "CVE-2019-0708",
        "title": "BlueKeep — Remote Desktop Services Remote Code Execution",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "ports": [3389],
        "device_types": ["all"],
        "summary": "Pre-authentication remote code execution vulnerability in Remote Desktop Services requiring no user interaction.",
        "mitigation": "Enable Network Level Authentication (NLA) on RDP hosts. Block port 3389 at network perimeter and access only via VPN."
    },
    {
        "id": "CVE-2021-34991",
        "title": "Netgear Gateway mini_httpd Stack Buffer Overflow",
        "severity": "HIGH",
        "cvss": 8.8,
        "ports": [80, 443, 5000],
        "device_types": ["gateway", "netgear"],
        "summary": "Stack-based buffer overflow in Netgear gateway web administration daemon allowing privileged command execution.",
        "mitigation": "Update Netgear router firmware to the vendor's latest security maintenance release. Disable WAN management and UPnP."
    },
    {
        "id": "CVE-2020-12695",
        "title": "CallStranger — UPnP Protocol Amplification & Exfiltration",
        "severity": "HIGH",
        "cvss": 7.5,
        "ports": [5000, 1883],
        "device_types": ["iot", "gateway", "device"],
        "summary": "UPnP SUBSCRIBE functions permit reflection attacks, port scanning, and internal network perimeter bypass.",
        "mitigation": "Disable Universal Plug and Play (UPnP) on router. Isolate smart home / IoT devices on a dedicated IoT VLAN."
    },
    {
        "id": "CVE-2018-9995",
        "title": "DVR / IP Camera Authentication Bypass & Stream Exposure",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "ports": [554, 80],
        "device_types": ["camera", "all"],
        "summary": "Unauthenticated cookie handling flaw permits retrieval of plain DVR credentials and live camera stream hijacking.",
        "mitigation": "Segment security surveillance cameras on an isolated VLAN with no direct internet access. Enforce strong RTSP credentials."
    }
]


# ==============================================================================
# Live Scanner State Manager
# ==============================================================================
class ScannerStateManager:
    """Manages live scanning telemetry and writes scan_status.json for web HUD."""

    def __init__(self, primary_dir="/var/www/html/devices", fallback_dir="./devices", iface="eth0", ip_range="192.168.1.0/24"):
        self.primary_dir = primary_dir
        self.fallback_dir = fallback_dir
        self.iface = iface
        self.ip_range = ip_range
        self.logs = []
        self.stage = "INITIALIZING"
        self.progress = 0
        self.current_action = "Initializing scanner subsystem..."
        self.total_hosts = 0
        self.live_hosts = 0
        self.start_time = time.time()
        os.makedirs(self.fallback_dir, exist_ok=True)
        try:
            os.makedirs(primary_dir, exist_ok=True)
        except Exception:
            pass

        os.makedirs(self.fallback_dir, exist_ok=True)
        try:
            os.makedirs(primary_dir, exist_ok=True)
        except Exception:
            pass

    def add_log(self, level, msg):
        """Appends a timestamped log to the circular buffer."""
        t_str = datetime.now().strftime("%H:%M:%S")
        entry = {"time": t_str, "level": level, "msg": msg}
        self.logs.append(entry)
        if len(self.logs) > 30:
            self.logs.pop(0)

    def update(self, stage=None, progress=None, action=None, log_msg=None, log_level="INFO"):
        """Updates telemetry and writes scan_status.json."""
        if stage:
            self.stage = stage
        if progress is not None:
            self.progress = progress
        if action:
            self.current_action = action
        if log_msg:
            self.add_log(log_level, log_msg)

        status_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stage": self.stage,
            "progress_percent": self.progress,
            "current_action": self.current_action,
            "total_hosts": self.total_hosts,
            "live_hosts": self.live_hosts,
            "elapsed_seconds": round(time.time() - self.start_time, 1),
            "log_feed": self.logs
        }
        json_str = json.dumps(status_data, indent=2)

        # Write to fallback directory (guaranteed accessible)
        try:
            fb_path = os.path.join(self.fallback_dir, "scan_status.json")
            with open(fb_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        except Exception:
            pass

        # Try writing to primary directory
        try:
            prim_path = os.path.join(self.primary_dir, "scan_status.json")
            with open(prim_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        except Exception:
            pass

    def get_ip_list(self):
        """Return a list of IPv4 addresses that belong to *self.iface*.
        The address range is defined in *self.ip_range* (CIDR notation).
        """
        import ipaddress, socket
        # Resolve the network mask from the CIDR string
        net = ipaddress.IPv4Network(self.ip_range, strict=True)

        # Optional: verify that the interface really has an address in this range
        iface_addr = socket.if_nameindex[self.iface]
        iface_ip  = socket.getaddrinfo(iface_addr, 0)[0][4][0]      # IPv4
        if not net.network_address == ipaddress.IPv4Address(iface_ip):
            sys.stderr.write(f"\n[WARN] Interface {self.iface} reports address "
                              f"{iface_ip}, which does not match the range {net}\n")
        return [str(ip) for ip in net.hosts()]

    def scan_hosts(self):
        """Scan every IP in self.get_ip_list() using all ports from DEFAULT_SCAN_PORTS."""
        # Build a list of (ip, port) tuples for the whole range.
        targets = [(ip, p) for ip in self.get_ip_list()
                               for p in DEFAULT_SCAN_PORTS]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self.do_scan_one, *t): t for t in targets}
            # Wait until all are done and store the results in self.logs
            for fut in concurrent.futures.as_completed(futures):
                ip, port, result = fut.result()
                self.add_log("SCAN", f"IP={ip} P={port} {result}")

    def do_scan_one(self, ip, port):
        """
        Perform a tiny scan on *ip:port* and return a string that will be logged.
        """
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            # just read a bit of data to prove the connection worked
            data = s.recv(64).decode("utf‑8")
        return f"ok({len(data)}B)"

# Global Scanner State instance
_STATE = ScannerStateManager()



# ==============================================================================
# Hardware / OUI Helpers
# ==============================================================================
_OUI_CACHE = None

def load_oui_database():
    """Loads OUI hardware vendor database from local Kali/system files."""
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    _OUI_CACHE = {}
    db_paths = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/var/lib/ieee-data/oui.txt",
        "/usr/share/ieee-data/oui.txt"
    ]

    for path in db_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            _OUI_CACHE[parts[0].upper()] = parts[1].strip()
                if _OUI_CACHE:
                    break
            except Exception:
                continue

    return _OUI_CACHE


def lookup_vendor(mac, oui_db):
    """Returns the hardware vendor string for a given MAC address."""
    if not mac or mac in ("00:00:00:00:00:00", "N/A"):
        return "Unknown"
    clean_mac = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui_db.get(clean_mac, "Unknown")


def get_default_network():
    """Auto-detects active network interface, subnet CIDR, local IP, and default gateway."""
    gateway = None
    interface = None
    local_ip = None
    subnet = None

    try:
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout:
            parts = res.stdout.split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
            if "dev" in parts:
                interface = parts[parts.index("dev") + 1]

        if interface:
            ip_res = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", interface],
                                    capture_output=True, text=True)
            for line in ip_res.stdout.splitlines():
                fields = line.split()
                for field in fields:
                    if "/" in field and field[0].isdigit():
                        net = ipaddress.ip_network(field, strict=False)
                        subnet = str(net)
                        local_ip = field.split("/")[0]
                        break
    except Exception:
        pass

    return subnet, local_ip, gateway, interface


def get_local_mac(interface):
    """Retrieves MAC address of the local network interface."""
    if not interface:
        return "N/A"
    path = f"/sys/class/net/{interface}/address"
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return f.read().strip().lower()
        except Exception:
            pass
    return "N/A"


def parse_arp_table():
    """Reads Linux kernel ARP cache (/proc/net/arp)."""
    arp_map = {}
    if not os.path.exists("/proc/net/arp"):
        return arp_map

    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    flags = parts[2]
                    mac = parts[3].lower()
                    if flags == "0x2" and mac != "00:00:00:00:00:00":
                        arp_map[ip] = mac
    except Exception:
        pass

    return arp_map


# ==============================================================================
# Network Probing & Fingerprinting
# ==============================================================================
def ping_host(ip, timeout=1.0):
    """Pings an IP address once using system ping command."""
    try:
        timeout_val = max(1, int(timeout))
        cmd = ["ping", "-c", "1", "-W", str(timeout_val), str(ip)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 0.5)
        if res.returncode == 0:
            m = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if m:
                return True, float(m.group(1))
            return True, 0.0
    except Exception:
        pass
    return False, None


def tcp_probe_port(ip, port, timeout=0.25):
    """Probes a single TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((str(ip), port))
        if res == 0:
            return port
    except Exception:
        pass
    finally:
        s.close()
    return None


def grab_banner(ip, port, timeout=0.4):
    """Attempts to grab an application service banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((str(ip), port))
        if port in (80, 8080, 8000, 5000, 8888):
            req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetCheck/3.0\r\n\r\n"
            s.sendall(req.encode())
            raw = s.recv(512).decode("utf-8", errors="ignore")
            for line in raw.splitlines():
                if line.lower().startswith("server:"):
                    banner = line.split(":", 1)[1].strip()
                    break
        elif port == 22:
            raw = s.recv(256).decode("utf-8", errors="ignore")
            banner = raw.strip()
        elif port in (21, 23):
            raw = s.recv(256).decode("utf-8", errors="ignore")
            banner = raw.strip()
    except Exception:
        pass
    finally:
        s.close()
    return banner


def scan_ports_for_host(ip, ports=DEFAULT_SCAN_PORTS, timeout=0.25):
    """Scans common service ports and gathers banners concurrently."""
    open_port_details = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(25, len(ports))) as ex:
        futs = {ex.submit(tcp_probe_port, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            port = f.result()
            if port:
                svc_name = PORT_SERVICE_MAP.get(port, f"TCP Port {port}")
                banner = grab_banner(ip, port, timeout=0.4)
                open_port_details.append({
                    "port": port,
                    "service": svc_name,
                    "banner": banner
                })

    open_port_details.sort(key=lambda x: x["port"])
    return open_port_details


def infer_operating_system(vendor, open_ports, banners):
    """Infers potential operating system and device profile."""
    v_lower = vendor.lower()
    b_text = " ".join(banners).lower()

    if "debian" in b_text or "ubuntu" in b_text:
        return "Linux (Debian / Ubuntu Distribution)"
    if "raspbian" in b_text or "raspberry pi" in v_lower:
        return "Raspberry Pi OS (Linux ARM)"
    if "netgear" in v_lower:
        return "Netgear Network Appliance (Embedded Linux / BusyBox)"
    if "tuya" in v_lower or "espressif" in v_lower:
        return "Smart IoT Device (ESP32 / FreeRTOS)"
    if "amazon" in v_lower:
        return "Amazon Alexa / FireOS (Android)"
    if "google" in v_lower:
        return "Google Cast / Android TV / Nest OS"
    if "hisense" in v_lower or "blaupunkt" in v_lower or "chuangwei" in v_lower:
        return "Smart TV Media Center (Android TV / Linux)"
    if "parallels" in v_lower:
        return "Virtual Machine (Parallels Guest OS)"
    if "seagate" in v_lower:
        return "Seagate Network Storage Appliance (Samba)"
    if 3389 in open_ports or 445 in open_ports and "samba" not in b_text:
        return "Microsoft Windows Workstation / Server"
    if 554 in open_ports:
        return "Embedded IP Surveillance Camera (RTSP)"
    if 22 in open_ports or 80 in open_ports:
        return "Generic Unix / Linux Host"

    return "Embedded Firmware / Proprietary OS"


def correlate_cves(open_ports, vendor, os_name):
    """Correlates open ports and system profile against the CVE knowledge base."""
    matched = []
    v_lower = vendor.lower()
    for cve in CVE_KNOWLEDGE_BASE:
        port_hit = any(p in open_ports for p in cve["ports"])
        if not port_hit:
            continue

        dev_types = cve.get("device_types", ["all"])
        type_match = "all" in dev_types
        if "gateway" in dev_types and ("gateway" in os_name.lower() or "netgear" in v_lower):
            type_match = True
        if "netgear" in dev_types and "netgear" in v_lower:
            type_match = True
        if "iot" in dev_types and ("tuya" in v_lower or "espressif" in v_lower or 1883 in open_ports):
            type_match = True
        if "camera" in dev_types and (554 in open_ports or "camera" in os_name.lower()):
            type_match = True

        if type_match:
            matched.append(cve)

    return matched


def resolve_hostname(ip, timeout=0.4):
    """Performs reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(str(ip))
        return name
    except Exception:
        return ""


# ==============================================================================
# Network Sweep Orchestration
# ==============================================================================
def scan_network_full(target_ips, num_threads=50, timeout=1.0, deep_audit=True):
    """Scans all IPs for alive state, then conducts deep port and CVE audit."""
    start_time = time.time()
    results = []
    total = len(target_ips)

    _STATE.total_hosts = total
    _STATE.update("PING_SWEEP", 5, f"Starting ping sweep across {total} targets...",
                  f"ICMP sweep initiated across {total} addresses", "INFO")

    # Step 1: Alive Host Sweep
    def check_alive(ip):
        ip_str = str(ip)
        up, rtt = ping_host(ip_str, timeout=timeout)
        if not up:
            # Fallback probe top ports
            for p in (80, 443, 22, 445):
                if tcp_probe_port(ip_str, p, timeout=0.2):
                    up = True
                    rtt = 1.0
                    break
        return ip_str, up, rtt

    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as ex:
        completed = 0
        future_map = {ex.submit(check_alive, ip): ip for ip in target_ips}
        for f in concurrent.futures.as_completed(future_map):
            completed += 1
            ip_str, up, rtt = f.result()
            if up:
                alive_hosts.append((ip_str, rtt))

            if completed % 25 == 0 or completed == total:
                pct = int((completed / total) * 45)
                _STATE.update("PING_SWEEP", pct, f"Ping sweep progress: {completed}/{total} ({len(alive_hosts)} alive)",
                              f"Sweep at {completed}/{total}: {len(alive_hosts)} nodes responding", "INFO")

    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x[0]))
    _STATE.live_hosts = len(alive_hosts)
    _STATE.update("PORT_SCAN", 50, f"Discovered {len(alive_hosts)} alive targets. Initiating deep service audit...",
                  f"Sweep finished: {len(alive_hosts)} active nodes detected", "SUCCESS")

    # Step 2: Deep Port & CVE Audit on Active Hosts
    oui_db = load_oui_database()
    arp_table = parse_arp_table()
    _, local_ip, gateway, interface = get_default_network()
    local_mac = get_local_mac(interface)

    for idx, (ip_str, rtt) in enumerate(alive_hosts):
        # Resolve Identity
        if ip_str == local_ip:
            mac = local_mac
            role = "Host (This VM)"
        elif ip_str == gateway:
            mac = arp_table.get(ip_str, "N/A")
            role = "Default Gateway"
        else:
            mac = arp_table.get(ip_str, "N/A")
            role = "Device"

        vendor = lookup_vendor(mac, oui_db) if mac != "N/A" else "Unknown"
        hostname = resolve_hostname(ip_str)

        pct = 50 + int(((idx + 1) / len(alive_hosts)) * 40)
        _STATE.update("PORT_SCAN", pct, f"Probing services on {ip_str} ({vendor})...",
                      f"Probing {ip_str} ({vendor})", "PROBE")

        # Port Scan & Banners
        ports_info = scan_ports_for_host(ip_str, ports=DEFAULT_SCAN_PORTS, timeout=0.25)
        open_ports_list = [p["port"] for p in ports_info]
        banners_list = [p["banner"] for p in ports_info if p["banner"]]

        # Inferred OS
        inferred_os = infer_operating_system(vendor, open_ports_list, banners_list)

        # Correlate CVEs
        cves = correlate_cves(open_ports_list, vendor, inferred_os)
        risk_score = "CLEAN / LOW"
        if any(c["severity"] == "CRITICAL" for c in cves):
            risk_score = "CRITICAL"
        elif any(c["severity"] == "HIGH" for c in cves):
            risk_score = "HIGH RISK"
        elif any(c["severity"] == "MEDIUM" for c in cves):
            risk_score = "MODERATE"

        results.append({
            "ip": ip_str,
            "is_up": True,
            "rtt": rtt,
            "mac": mac,
            "vendor": vendor,
            "role": role,
            "hostname": hostname,
            "open_ports": open_ports_list,
            "ports_detail": ports_info,
            "inferred_os": inferred_os,
            "cves": cves,
            "risk_score": risk_score
        })

    duration = time.time() - start_time
    _STATE.update("IDLE_MONITORING", 100, f"Scan completed in {duration:.2f}s. {len(results)} nodes indexed.",
                  f"All {len(results)} nodes indexed. Generated deep telemetry profiles.", "SUCCESS")

    return results, duration


# ==============================================================================
# HTML Templating: Shared Technopunk Styling
# ==============================================================================
SHARED_TECHNOPUNK_CSS = """
:root {
  --bg: #030508;
  --panel: rgba(8, 14, 24, 0.94);
  --panel-border: rgba(0, 240, 255, 0.22);
  --cyan: #00f0ff;
  --cyan-glow: rgba(0, 240, 255, 0.45);
  --magenta: #ff2ec4;
  --magenta-glow: rgba(255, 46, 196, 0.45);
  --green: #3dff9c;
  --green-glow: rgba(61, 255, 156, 0.5);
  --amber: #ffb454;
  --red: #ff4d6d;
  --dim: #5c7587;
  --text: #d4f7ff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Share Tech Mono', ui-monospace, Consolas, monospace;
  min-height: 100vh;
  overflow-x: hidden;
  padding: 24px 18px 60px;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  z-index: -2;
  pointer-events: none;
  background:
    radial-gradient(circle at 50% -10%, rgba(0, 240, 255, 0.12), transparent 65%),
    radial-gradient(circle at 90% 100%, rgba(255, 46, 196, 0.08), transparent 50%),
    linear-gradient(rgba(0, 240, 255, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0, 240, 255, 0.04) 1px, transparent 1px);
  background-size: auto, auto, 36px 36px, 36px 36px;
}

.scanlines {
  position: fixed;
  inset: 0;
  z-index: 100;
  pointer-events: none;
  opacity: 0.25;
  background: repeating-linear-gradient(rgba(0, 0, 0, 0.4) 0 1px, transparent 1px 3px);
}

.container {
  max-width: 1280px;
  margin: 0 auto;
  position: relative;
}

/* Header & Glitch Title */
header {
  text-align: center;
  margin-bottom: 24px;
}

.glitch-title {
  font-family: 'Orbitron', monospace;
  font-size: clamp(2rem, 5vw, 3.2rem);
  font-weight: 900;
  letter-spacing: 0.25em;
  color: var(--cyan);
  text-shadow: 0 0 16px var(--cyan-glow), 0 0 32px var(--cyan-glow);
  margin-bottom: 6px;
}

.subtitle {
  color: var(--magenta);
  font-size: 0.88rem;
  letter-spacing: 0.3em;
  text-shadow: 0 0 10px var(--magenta-glow);
  margin-bottom: 14px;
}

/* Navigation Buttons */
.nav-bar {
  display: flex;
  justify-content: center;
  gap: 14px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}

.btn-nav {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: rgba(0, 240, 255, 0.1);
  border: 1px solid var(--cyan);
  color: var(--cyan);
  font-family: 'Orbitron', monospace;
  font-size: 0.78rem;
  letter-spacing: 0.12em;
  padding: 8px 18px;
  border-radius: 4px;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.25s ease;
  box-shadow: 0 0 10px rgba(0, 240, 255, 0.15);
}

.btn-nav:hover {
  background: var(--cyan);
  color: #030508;
  box-shadow: 0 0 20px var(--cyan-glow);
}

.btn-nav.mag {
  border-color: var(--magenta);
  color: var(--magenta);
  background: rgba(255, 46, 196, 0.1);
}

.btn-nav.mag:hover {
  background: var(--magenta);
  color: #fff;
  box-shadow: 0 0 20px var(--magenta-glow);
}

/* Live Scanner Radar & Activity Feed */
.radar-panel {
  background: var(--panel);
  border: 1px solid var(--panel-border);
  border-radius: 6px;
  padding: 16px 20px;
  margin-bottom: 22px;
  box-shadow: 0 4px 25px rgba(0, 0, 0, 0.7);
}

.radar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
  font-family: 'Orbitron', monospace;
  font-size: 0.8rem;
  letter-spacing: 0.15em;
  color: var(--cyan);
}

.progress-track {
  width: 100%;
  height: 8px;
  background: rgba(0, 0, 0, 0.7);
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid rgba(0, 240, 255, 0.25);
  margin-bottom: 12px;
}

.progress-fill {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--cyan), var(--magenta));
  box-shadow: 0 0 10px var(--cyan);
  transition: width 0.4s ease;
}

.terminal-box {
  background: rgba(0, 0, 0, 0.8);
  border: 1px solid rgba(0, 240, 255, 0.15);
  border-radius: 4px;
  padding: 10px 14px;
  height: 72px;
  overflow-y: auto;
  font-size: 0.78rem;
  color: var(--dim);
}

.term-line {
  line-height: 1.4;
}

.term-time { color: var(--dim); margin-right: 8px; }
.term-lvl-INFO { color: var(--cyan); }
.term-lvl-PROBE { color: var(--amber); }
.term-lvl-SUCCESS { color: var(--green); }

/* KPI Grid */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 16px;
  margin-bottom: 22px;
}

.kpi-card {
  background: var(--panel);
  border: 1px solid var(--panel-border);
  border-radius: 6px;
  padding: 16px 20px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
  position: relative;
  overflow: hidden;
}

.kpi-card::after {
  content: "";
  position: absolute;
  top: 0; left: 0; width: 4px; height: 100%;
  background: var(--cyan);
  box-shadow: 0 0 10px var(--cyan);
}

.kpi-card.mag::after { background: var(--magenta); box-shadow: 0 0 10px var(--magenta); }
.kpi-card.grn::after { background: var(--green); box-shadow: 0 0 10px var(--green); }
.kpi-card.amb::after { background: var(--amber); box-shadow: 0 0 10px var(--amber); }

.kpi-label { font-size: 0.72rem; letter-spacing: 0.18em; color: var(--dim); text-transform: uppercase; margin-bottom: 6px; }
.kpi-value { font-family: 'Orbitron', monospace; font-size: 1.6rem; font-weight: 700; color: var(--text); }
.kpi-sub { font-size: 0.76rem; color: var(--dim); margin-top: 4px; }

/* Badges, Tags & Dots */
.status-up { color: var(--green); font-weight: bold; display: inline-flex; align-items: center; gap: 8px; }
.dot-up {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--green); box-shadow: 0 0 8px var(--green);
  animation: pulse 1.8s infinite ease-in-out;
}
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); box-shadow: 0 0 10px var(--green); }
  50% { opacity: 0.35; transform: scale(0.85); box-shadow: 0 0 2px var(--green); }
}

.tag {
  display: inline-block; padding: 2px 7px; font-size: 0.68rem;
  letter-spacing: 0.1em; border-radius: 3px; font-weight: bold; text-transform: uppercase;
}
.tag-gateway { background: rgba(255, 180, 84, 0.18); border: 1px solid var(--amber); color: var(--amber); }
.tag-host { background: rgba(0, 240, 255, 0.18); border: 1px solid var(--cyan); color: var(--cyan); }
.tag-device { background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.18); color: var(--dim); }
.tag-port { background: rgba(255, 46, 196, 0.15); border: 1px solid var(--magenta); color: var(--magenta); font-size: 0.72rem; margin: 1px; }

/* Interactive Role/Hostname Graphic Trigger */
.btn-intel-trigger {
  background: transparent;
  border: none;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  color: inherit;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  border: 1px solid transparent;
  transition: all 0.2s ease;
}

.btn-intel-trigger:hover {
  background: rgba(0, 240, 255, 0.12);
  border-color: var(--cyan);
  box-shadow: 0 0 12px var(--cyan-glow);
}

.intel-icon {
  font-size: 0.72rem;
  color: var(--cyan);
  font-weight: bold;
  letter-spacing: 0.08em;
  background: rgba(0, 240, 255, 0.15);
  border: 1px solid var(--cyan);
  padding: 1px 6px;
  border-radius: 3px;
}

.risk-badge {
  display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.72rem; font-weight: bold;
}
.risk-CRITICAL { background: rgba(255, 77, 109, 0.2); border: 1px solid var(--red); color: var(--red); }
.risk-HIGH { background: rgba(255, 180, 84, 0.2); border: 1px solid var(--amber); color: var(--amber); }
.risk-MODERATE { background: rgba(0, 240, 255, 0.2); border: 1px solid var(--cyan); color: var(--cyan); }
.risk-CLEAN { background: rgba(61, 255, 156, 0.15); border: 1px solid var(--green); color: var(--green); }

/* Technopunk In-Page Modal */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(3, 5, 8, 0.88);
  backdrop-filter: blur(4px);
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-card {
  background: var(--panel);
  border: 2px solid var(--cyan);
  border-radius: 8px;
  width: 100%;
  max-width: 820px;
  max-height: 88vh;
  overflow-y: auto;
  padding: 24px;
  box-shadow: 0 0 40px var(--cyan-glow);
  position: relative;
}

.modal-close {
  position: absolute;
  top: 16px; right: 20px;
  background: transparent;
  border: 1px solid var(--magenta);
  color: var(--magenta);
  font-family: 'Orbitron', monospace;
  font-size: 1rem;
  padding: 4px 10px;
  cursor: pointer;
  border-radius: 4px;
}

.modal-close:hover { background: var(--magenta); color: #fff; }
"""


# ==============================================================================
# HTML Page 1: Main Dashboard (netcheck.html)
# ==============================================================================
def generate_main_dashboard_html(results, subnet, local_ip, gateway, duration, timestamp):
    """Generates the primary Technopunk netcheck.html dashboard."""
    up_count = sum(1 for r in results if r["is_up"])
    total_count = len(results)

    # Encode JSON telemetry for interactive modal lookup
    devices_json_esc = html.escape(json.dumps(results))

    table_rows = []
    for r in results:
        ip = r["ip"]
        ip_esc = html.escape(ip)
        mac_esc = html.escape(r.get("mac", "—"))
        vendor_esc = html.escape(r.get("vendor", "Unknown"))
        role_esc = html.escape(r.get("role", "Device"))
        hostname_esc = html.escape(r.get("hostname", ""))
        rtt = r.get("rtt")

        # Status & Latency
        status_html = '<span class="status-up"><span class="dot-up"></span> ONLINE</span>'
        lat_class = "lat-fast" if rtt and rtt < 25 else ("lat-med" if rtt and rtt < 100 else "lat-slow")
        lat_text = f"{rtt:.1f} ms" if rtt is not None else "< 1 ms"
        latency_html = f'<span class="badge {lat_class}">{lat_text}</span>'

        # Role Tag
        tag_cls = "tag-gateway" if ip == gateway else ("tag-host" if ip == local_ip else "tag-device")
        role_tag = f'<span class="tag {tag_cls}">{role_esc}</span>'

        # Ports badges
        open_ports = r.get("open_ports", [])
        ports_html = "".join([f'<span class="tag tag-port">{p}</span>' for p in open_ports[:4]])
        if len(open_ports) > 4:
            ports_html += f'<span class="tag tag-port">+{len(open_ports)-4}</span>'

        # Risk badge
        risk = r.get("risk_score", "CLEAN / LOW")
        risk_cls = "risk-CRITICAL" if "CRITICAL" in risk else ("risk-HIGH" if "HIGH" in risk else ("risk-MODERATE" if "MODERATE" in risk else "risk-CLEAN"))
        risk_html = f'<span class="risk-badge {risk_cls}">{risk}</span>'

        tr = f"""        <tr data-search="{ip_esc} {mac_esc} {vendor_esc} {role_esc} {hostname_esc}">
          <td class="col-ip"><strong>{ip_esc}</strong></td>
          <td class="col-status">{status_html}</td>
          <td class="col-lat">{latency_html}</td>
          <td class="col-mac"><code>{mac_esc}</code></td>
          <td class="col-vendor">{vendor_esc}</td>
          <td class="col-role">
            <button class="btn-intel-trigger" onclick="inspectDevice('{ip_esc}')" title="Click to view deep device telemetry and CVE audit">
              {role_tag}
              <span class="intel-icon">⚡ DEEP INTEL</span>
            </button>
            {f'<span style="color:var(--dim);font-size:0.75rem">({hostname_esc})</span>' if hostname_esc else ''}
          </td>
          <td class="col-ports">{ports_html or '<span class="dim">—</span>'}</td>
          <td class="col-risk">{risk_html}</td>
        </tr>"""
        table_rows.append(tr)

    rows_joined = "\n".join(table_rows)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NET//CHECK — Technopunk Network Telemetry</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <style>
{SHARED_TECHNOPUNK_CSS}

    /* Table Specifics */
    .table-panel {{
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 6px;
      overflow-x: auto;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.88rem;
    }}

    th {{
      background: rgba(0, 0, 0, 0.6);
      color: var(--cyan);
      font-family: 'Orbitron', monospace;
      font-size: 0.75rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      padding: 14px 18px;
      border-bottom: 2px solid rgba(0, 240, 255, 0.3);
      white-space: nowrap;
    }}

    td {{
      padding: 12px 18px;
      border-bottom: 1px solid rgba(0, 240, 255, 0.08);
      vertical-align: middle;
      white-space: nowrap;
    }}

    tr:hover td {{ background: rgba(0, 240, 255, 0.06); }}

    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.78rem; font-weight: bold;
    }}
    .lat-fast {{ background: rgba(61, 255, 156, 0.12); border: 1px solid var(--green); color: var(--green); }}
    .lat-med {{ background: rgba(0, 240, 255, 0.12); border: 1px solid var(--cyan); color: var(--cyan); }}
    .lat-slow {{ background: rgba(255, 180, 84, 0.12); border: 1px solid var(--amber); color: var(--amber); }}

    .dim {{ color: var(--dim); }}
    .search-input {{
      width: 100%;
      background: rgba(0, 0, 0, 0.6);
      border: 1px solid rgba(0, 240, 255, 0.3);
      color: var(--cyan);
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.88rem;
      padding: 10px 16px;
      border-radius: 4px;
      outline: none;
      margin-bottom: 16px;
    }}
  </style>
</head>
<body>
  <div class="scanlines"></div>
  <div class="container">
    <header>
      <div class="glitch-title">NET//CHECK</div>
      <div class="subtitle">⚡ TECHNOPUNK ACTIVE NETWORK TELEMETRY ⚡</div>

      <!-- Navigation Bar -->
      <div class="nav-bar">
        <a href="/devices/" class="btn-nav mag">
          <span>⚡ INTEL NODES DIRECTORY (SECONDARY PAGE)</span> &rarr;
        </a>
        <button class="btn-nav" onclick="location.reload()">
          <span>&#8635; REFRESH TELEMETRY</span>
        </button>
      </div>
    </header>

    <!-- Live Scanner Radar HUD -->
    <div class="radar-panel">
      <div class="radar-header">
        <span id="radarStage">&gt; SCANNER STATUS: ACTIVE TELEMETRY</span>
        <span id="radarProgressText">PROGRESS: 100%</span>
      </div>
      <div class="progress-track">
        <div id="radarFill" class="progress-fill" style="width: 100%;"></div>
      </div>
      <div style="font-size:0.8rem;color:var(--text);margin-bottom:8px" id="radarAction">
        &gt; ACTION: Sweep complete. Live telemetry updated. Next interval in 5s...
      </div>
      <div class="terminal-box" id="terminalFeed">
        <div class="term-line"><span class="term-time">{timestamp}</span><span class="term-lvl-SUCCESS">[READY]</span> Live monitoring active on {subnet}</div>
      </div>
    </div>

    <!-- KPI HUD -->
    <div class="kpi-grid">
      <div class="kpi-card grn">
        <div class="kpi-label">ONLINE DEVICES</div>
        <div class="kpi-value">{up_count} <span style="font-size:0.9rem;color:var(--dim)">/ {total_count}</span></div>
        <div class="kpi-sub">Active nodes discovered</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">SUBNET RANGE</div>
        <div class="kpi-value" style="font-size:1.3rem;line-height:1.9rem">{subnet or '192.168.42.0/24'}</div>
        <div class="kpi-sub">Local IP: {local_ip or 'N/A'}</div>
      </div>
      <div class="kpi-card amb">
        <div class="kpi-label">GATEWAY INTEL</div>
        <div class="kpi-value" style="font-size:1.3rem;line-height:1.9rem">{gateway or 'N/A'}</div>
        <div class="kpi-sub">Upstream Gateway Router</div>
      </div>
      <div class="kpi-card mag">
        <div class="kpi-label">CYCLE DURATION</div>
        <div class="kpi-value">{duration:.2f}s</div>
        <div class="kpi-sub">Last sync: {timestamp}</div>
      </div>
    </div>

    <!-- Search / Filter -->
    <input type="text" id="targetFilter" class="search-input" placeholder="// QUICK FILTER NODES (IP, MAC, VENDOR, ROLE, OS)..." onkeyup="filterTargets()">

    <!-- Table Panel -->
    <div class="table-panel">
      <table id="deviceTable">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Status</th>
            <th>Latency</th>
            <th>MAC Address</th>
            <th>Hardware Vendor</th>
            <th>Role / Hostname (Click Intel)</th>
            <th>Open Ports</th>
            <th>Risk Posture</th>
          </tr>
        </thead>
        <tbody>
{rows_joined}
        </tbody>
      </table>
    </div>

    <footer style="text-align:center;margin-top:36px;font-size:0.75rem;color:var(--dim);letter-spacing:0.2em">
      [ NET//CHECK v3.0 &middot; TECHNOPUNK CYBER INTELLIGENCE ENGINE &middot; /var/www/html/netcheck.html ]
    </footer>
  </div>

  <!-- Interactive Technopunk Modal for Deep Device Inspection -->
  <div id="deviceModal" class="modal-overlay" onclick="closeModalOnOuter(event)">
    <div class="modal-card">
      <button class="modal-close" onclick="closeDeviceModal()">&times; CLOSE [ESC]</button>
      <div id="modalContent">
        <!-- Injected via JavaScript -->
      </div>
    </div>
  </div>

  <script id="deviceData" type="application/json">
{json.dumps(results)}
  </script>

  <script>
    const DEVICE_DATA = JSON.parse(document.getElementById('deviceData').textContent);

    function filterTargets() {{
      const query = document.getElementById('targetFilter').value.toLowerCase();
      const rows = document.querySelectorAll('#deviceTable tbody tr');
      rows.forEach(row => {{
        const search = (row.getAttribute('data-search') || '').toLowerCase();
        row.style.display = search.includes(query) ? '' : 'none';
      }});
    }}

    // Open Deep Detail Modal on "Role / Hostname" graphic click
    function inspectDevice(ip) {{
      const dev = DEVICE_DATA.find(d => d.ip === ip);
      if (!dev) return;

      const ports = dev.ports_detail || [];
      const cves = dev.cves || [];

      let portsHtml = '';
      if (ports.length === 0) {{
        portsHtml = '<p style="color:var(--dim)">No standard listening ports detected during sweep.</p>';
      }} else {{
        portsHtml = '<table style="width:100%;margin-top:8px;font-size:0.8rem"><thead><tr><th style="padding:6px">PORT</th><th style="padding:6px">SERVICE</th><th style="padding:6px">BANNER</th></tr></thead><tbody>';
        ports.forEach(p => {{
          portsHtml += `<tr>
            <td style="padding:6px;color:var(--magenta)"><strong>${{p.port}}</strong></td>
            <td style="padding:6px;color:var(--cyan)">${{p.service}}</td>
            <td style="padding:6px;color:var(--dim)"><code>${{p.banner || '—'}}</code></td>
          </tr>`;
        }});
        portsHtml += '</tbody></table>';
      }}

      let cveHtml = '';
      if (cves.length === 0) {{
        cveHtml = '<p style="color:var(--green)">[✓] No known critical CVE advisories flagged for the current port profile.</p>';
      }} else {{
        cveHtml = '<div style="display:flex;flex-direction:column;gap:10px;margin-top:8px">';
        cves.forEach(c => {{
          cveHtml += `<div style="background:rgba(0,0,0,0.5);border-left:3px solid var(--red);padding:10px;border-radius:4px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <strong style="color:var(--red);font-family:'Orbitron',monospace">${{c.id}} — ${{c.title}}</strong>
              <span class="risk-badge risk-${{c.severity}}">${{c.severity}} (CVSS ${{c.cvss}})</span>
            </div>
            <p style="font-size:0.78rem;color:var(--text);margin-bottom:4px">${{c.summary}}</p>
            <p style="font-size:0.75rem;color:var(--amber)"><strong>Hardening:</strong> ${{c.mitigation}}</p>
          </div>`;
        }});
        cveHtml += '</div>';
      }}

      const modalHtml = `
        <div style="font-family:'Orbitron',monospace;font-size:1.4rem;color:var(--cyan);margin-bottom:4px">
          ⚡ NODE TELEMETRY // ${{dev.ip}}
        </div>
        <div style="color:var(--magenta);font-size:0.8rem;letter-spacing:0.18em;margin-bottom:16px">
          ${{dev.role.toUpperCase()}} &middot; ${{dev.vendor}} &middot; ${{dev.inferred_os}}
        </div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:10px;margin-bottom:18px">
          <div style="background:rgba(0,0,0,0.4);padding:8px 12px;border-radius:4px;border:1px solid rgba(0,240,255,0.15)">
            <span style="font-size:0.68rem;color:var(--dim);display:block">MAC ADDRESS</span>
            <code style="color:var(--text);font-size:0.85rem">${{dev.mac || 'N/A'}}</code>
          </div>
          <div style="background:rgba(0,0,0,0.4);padding:8px 12px;border-radius:4px;border:1px solid rgba(0,240,255,0.15)">
            <span style="font-size:0.68rem;color:var(--dim);display:block">RESPONSE LATENCY</span>
            <span style="color:var(--green);font-size:0.85rem;font-weight:bold">${{dev.rtt ? dev.rtt.toFixed(1) + ' ms' : '< 1 ms'}}</span>
          </div>
          <div style="background:rgba(0,0,0,0.4);padding:8px 12px;border-radius:4px;border:1px solid rgba(0,240,255,0.15)">
            <span style="font-size:0.68rem;color:var(--dim);display:block">SECURITY POSTURE</span>
            <span class="risk-badge risk-${{dev.risk_score.includes('CRITICAL') ? 'CRITICAL' : (dev.risk_score.includes('HIGH') ? 'HIGH' : 'CLEAN')}}">${{dev.risk_score}}</span>
          </div>
        </div>

        <div style="margin-bottom:16px">
          <div style="font-family:'Orbitron',monospace;font-size:0.85rem;color:var(--cyan);border-bottom:1px solid rgba(0,240,255,0.2);padding-bottom:4px">
            OPEN PORTS &amp; ACTIVE SERVICES (${{ports.length}})
          </div>
          ${{portsHtml}}
        </div>

        <div style="margin-bottom:20px">
          <div style="font-family:'Orbitron',monospace;font-size:0.85rem;color:var(--magenta);border-bottom:1px solid rgba(255,46,196,0.2);padding-bottom:4px">
            CVE AUDIT &amp; DEFENSIVE MITIGATIONS (${{cves.length}})
          </div>
          ${{cveHtml}}
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid rgba(0,240,255,0.2);padding-top:14px">
          <a href="/devices/device_${{dev.ip}}.html" class="btn-nav mag" style="font-size:0.75rem">
            <span>⚡ OPEN STANDALONE INTEL NODE &rarr;</span>
          </a>
          <button class="btn-nav" onclick="closeDeviceModal()">CLOSE HUD</button>
        </div>
      `;

      document.getElementById('modalContent').innerHTML = modalHtml;
      document.getElementById('deviceModal').style.display = 'flex';
    }}

    function closeDeviceModal() {{
      document.getElementById('deviceModal').style.display = 'none';
    }}

    function closeModalOnOuter(e) {{
      if (e.target === document.getElementById('deviceModal')) closeDeviceModal();
    }}

    document.addEventListener('keydown', (e) => {{
      if (e.key === 'Escape') closeDeviceModal();
    }});

    // Live Telemetry Poller: Pulls scan_status.json every 4 seconds without reload
    async function pollLiveTelemetry() {{
      try {{
        const res = await fetch('/devices/scan_status.json?t=' + Date.now());
        if (res.ok) {{
          const data = await res.json();
          document.getElementById('radarStage').innerText = '> SCANNER STAGE: ' + data.stage;
          document.getElementById('radarProgressText').innerText = 'PROGRESS: ' + data.progress_percent + '%';
          document.getElementById('radarFill').style.width = data.progress_percent + '%';
          document.getElementById('radarAction').innerText = '> ACTION: ' + data.current_action;

          if (data.log_feed && data.log_feed.length > 0) {{
            const feedEl = document.getElementById('terminalFeed');
            feedEl.innerHTML = data.log_feed.slice(-6).map(l => 
              `<div class="term-line"><span class="term-time">${{l.time}}</span><span class="term-lvl-${{l.level}}">[${{l.level}}]</span> ${{l.msg}}</div>`
            ).join('');
            feedEl.scrollTop = feedEl.scrollHeight;
          }}
        }}
      }} catch (err) {{}}
    }}

    setInterval(pollLiveTelemetry, 4000);
    pollLiveTelemetry();
  </script>
</body>
</html>"""
    return html_content


# ==============================================================================
# HTML Page 2: Secondary Intel Nodes Directory (/devices/index.html)
# ==============================================================================
def generate_devices_directory_html(results, subnet, local_ip, gateway, duration, timestamp):
    """Generates the secondary Technopunk directory page listing all device cards."""
    cards_html = []
    for r in results:
        ip = r["ip"]
        ip_esc = html.escape(ip)
        vendor_esc = html.escape(r.get("vendor", "Unknown"))
        role_esc = html.escape(r.get("role", "Device"))
        os_esc = html.escape(r.get("inferred_os", "Generic OS"))
        mac_esc = html.escape(r.get("mac", "—"))
        rtt = r.get("rtt")
        open_ports = r.get("open_ports", [])
        cves = r.get("cves", [])
        risk = r.get("risk_score", "CLEAN / LOW")
        risk_cls = "risk-CRITICAL" if "CRITICAL" in risk else ("risk-HIGH" if "HIGH" in risk else ("risk-MODERATE" if "MODERATE" in risk else "risk-CLEAN"))

        ports_badges = "".join([f'<span class="tag tag-port">{p}</span>' for p in open_ports[:6]])
        if len(open_ports) > 6:
            ports_badges += f'<span class="tag tag-port">+{len(open_ports)-6}</span>'

        card = f"""      <div class="node-card" data-search="{ip_esc} {vendor_esc} {role_esc} {os_esc} {mac_esc}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span class="status-up"><span class="dot-up"></span> ONLINE</span>
          <span class="risk-badge {risk_cls}">{risk}</span>
        </div>
        <div class="node-ip">{ip_esc}</div>
        <div class="node-role">{role_esc} &middot; {vendor_esc}</div>
        <div class="node-os">&gt; {os_esc}</div>

        <div style="margin: 12px 0; border-top: 1px solid rgba(0,240,255,0.1); padding-top: 8px">
          <div style="display:flex;justify-content:space-between;font-size:0.75rem;color:var(--dim);margin-bottom:4px">
            <span>MAC: <code>{mac_esc}</code></span>
            <span>RTT: <strong style="color:var(--green)">{rtt:.1f} ms</strong></span>
          </div>
          <div style="font-size:0.72rem;color:var(--dim);margin-bottom:6px">
            PORTS OPEN ({len(open_ports)}): {ports_badges or '<span style=\"color:var(--dim)\">None detected</span>'}
          </div>
          <div style="font-size:0.72rem;color:var(--amber)">
            CVE ADVISORIES: <strong>{len(cves)} Flagged</strong>
          </div>
        </div>

        <a href="device_{ip_esc}.html" class="btn-node">
          ACCESS INTEL NODE &rarr;
        </a>
      </div>"""
        cards_html.append(card)

    cards_joined = "\n".join(cards_html)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>INTEL NODES // Secondary Telemetry Matrix</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <style>
{SHARED_TECHNOPUNK_CSS}

    .nodes-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 18px;
    }}

    .node-card {{
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 6px;
      padding: 18px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
      transition: transform 0.2s ease, border-color 0.2s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}

    .node-card:hover {{
      transform: translateY(-3px);
      border-color: var(--cyan);
      box-shadow: 0 0 20px var(--cyan-glow);
    }}

    .node-ip {{
      font-family: 'Orbitron', monospace;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--cyan);
      margin-bottom: 2px;
    }}

    .node-role {{
      font-size: 0.78rem;
      color: var(--magenta);
      letter-spacing: 0.1em;
      margin-bottom: 6px;
    }}

    .node-os {{
      font-size: 0.76rem;
      color: var(--dim);
      margin-bottom: 8px;
    }}

    .btn-node {{
      display: block;
      text-align: center;
      background: rgba(0, 240, 255, 0.08);
      border: 1px solid var(--cyan);
      color: var(--cyan);
      font-family: 'Orbitron', monospace;
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      padding: 8px 12px;
      border-radius: 4px;
      text-decoration: none;
      transition: all 0.2s ease;
      margin-top: 8px;
    }}

    .btn-node:hover {{
      background: var(--cyan);
      color: #030508;
      box-shadow: 0 0 15px var(--cyan-glow);
    }}

    .search-input {{
      width: 100%;
      background: rgba(0, 0, 0, 0.6);
      border: 1px solid rgba(0, 240, 255, 0.3);
      color: var(--cyan);
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.88rem;
      padding: 10px 16px;
      border-radius: 4px;
      outline: none;
      margin-bottom: 20px;
    }}
  </style>
</head>
<body>
  <div class="scanlines"></div>
  <div class="container">
    <header>
      <div class="glitch-title">INTEL NODES</div>
      <div class="subtitle">⚡ SECONDARY TELEMETRY MATRIX // ALL TARGETS ⚡</div>

      <div class="nav-bar">
        <a href="/netcheck.html" class="btn-nav">
          &larr; <span>RETURN TO LIVE MONITOR HUD</span>
        </a>
        <button class="btn-nav" onclick="location.reload()">
          <span>&#8635; REFRESH DIRECTORY</span>
        </button>
      </div>
    </header>

    <!-- Search / Filter -->
    <input type="text" id="nodeFilter" class="search-input" placeholder="// FILTER INTEL NODES (IP, VENDOR, OS, MAC, ROLE)..." onkeyup="filterNodes()">

    <!-- Nodes Grid -->
    <div class="nodes-grid" id="nodesContainer">
{cards_joined}
    </div>

    <footer style="text-align:center;margin-top:40px;font-size:0.75rem;color:var(--dim);letter-spacing:0.2em">
      [ INTEL NODES DIRECTORY &middot; /var/www/html/devices/index.html &middot; NET//CHECK v3.0 ]
    </footer>
  </div>

  <script>
    function filterNodes() {{
      const query = document.getElementById('nodeFilter').value.toLowerCase();
      const cards = document.querySelectorAll('#nodesContainer .node-card');
      cards.forEach(card => {{
        const text = (card.getAttribute('data-search') || '').toLowerCase();
        card.style.display = text.includes(query) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""
    return html_content


# ==============================================================================
# HTML Page 3: Individual Device Deep Detail Page (/devices/device_<ip>.html)
# ==============================================================================
def generate_individual_device_html(dev, all_ips, subnet, gateway, local_ip, timestamp):
    """Generates the standalone Technopunk deep detail page for a specific device."""
    ip = dev["ip"]
    ip_esc = html.escape(ip)
    mac_esc = html.escape(dev.get("mac", "—"))
    vendor_esc = html.escape(dev.get("vendor", "Unknown"))
    role_esc = html.escape(dev.get("role", "Device"))
    hostname_esc = html.escape(dev.get("hostname", ""))
    os_esc = html.escape(dev.get("inferred_os", "Generic OS"))
    rtt = dev.get("rtt")
    ports = dev.get("ports_detail", [])
    cves = dev.get("cves", [])
    risk = dev.get("risk_score", "CLEAN / LOW")
    risk_cls = "risk-CRITICAL" if "CRITICAL" in risk else ("risk-HIGH" if "HIGH" in risk else ("risk-MODERATE" if "MODERATE" in risk else "risk-CLEAN"))

    # Next / Prev Navigation
    curr_idx = all_ips.index(ip) if ip in all_ips else 0
    prev_ip = all_ips[(curr_idx - 1) % len(all_ips)] if all_ips else ip
    next_ip = all_ips[(curr_idx + 1) % len(all_ips)] if all_ips else ip

    # Ports Table Rows
    port_rows = []
    if not ports:
        port_rows.append('<tr><td colspan="4" style="color:var(--dim);text-align:center;padding:16px">No open service ports detected during fast scan.</td></tr>')
    else:
        for p in ports:
            port_rows.append(f"""          <tr>
            <td style="color:var(--magenta);font-weight:bold"><code>{p['port']}</code></td>
            <td>TCP</td>
            <td style="color:var(--cyan)">{html.escape(p['service'])}</td>
            <td><code>{html.escape(p['banner']) if p['banner'] else '<span style=\"color:var(--dim)\">—</span>'}</code></td>
          </tr>""")
    ports_joined = "\n".join(port_rows)

    # CVE Cards
    cve_cards = []
    if not cves:
        cve_cards.append('<div style="background:rgba(61,255,156,0.06);border:1px solid var(--green);padding:14px;border-radius:4px;color:var(--green)">[✓] No known critical vulnerabilities flagged for the active port footprint. Maintain system patch hygiene.</div>')
    else:
        for c in cves:
            cve_cards.append(f"""        <div style="background:rgba(0,0,0,0.6);border-left:4px solid var(--red);border-radius:4px;padding:14px;margin-bottom:12px;box-shadow:0 2px 10px rgba(0,0,0,0.5)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span style="font-family:'Orbitron',monospace;font-weight:bold;color:var(--red);font-size:0.95rem">{c['id']} &mdash; {html.escape(c['title'])}</span>
            <span class="risk-badge risk-{c['severity']}">{c['severity']} (CVSS {c['cvss']})</span>
          </div>
          <p style="font-size:0.84rem;color:var(--text);margin-bottom:8px">{html.escape(c['summary'])}</p>
          <div style="font-size:0.8rem;color:var(--amber);background:rgba(255,180,84,0.08);padding:6px 10px;border-radius:3px">
            <strong>Defensive Mitigation:</strong> {html.escape(c['mitigation'])}
          </div>
        </div>""")
    cves_joined = "\n".join(cve_cards)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>INTEL NODE // {ip_esc} — Technopunk Deep Profile</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <style>
{SHARED_TECHNOPUNK_CSS}

    .detail-card {{
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7);
    }}

    .section-title {{
      font-family: 'Orbitron', monospace;
      font-size: 0.92rem;
      letter-spacing: 0.16em;
      color: var(--cyan);
      border-bottom: 1px solid rgba(0, 240, 255, 0.2);
      padding-bottom: 6px;
      margin-bottom: 16px;
      text-transform: uppercase;
    }}

    .matrix-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }}

    .matrix-item {{
      background: rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(0, 240, 255, 0.15);
      border-radius: 4px;
      padding: 10px 14px;
    }}

    .matrix-label {{
      font-size: 0.68rem;
      color: var(--dim);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-bottom: 4px;
    }}

    .matrix-value {{
      font-size: 0.92rem;
      color: var(--text);
      font-weight: bold;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.84rem;
    }}

    th {{
      background: rgba(0, 0, 0, 0.6);
      color: var(--cyan);
      font-family: 'Orbitron', monospace;
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      padding: 10px 14px;
      border-bottom: 2px solid rgba(0, 240, 255, 0.25);
    }}

    td {{
      padding: 10px 14px;
      border-bottom: 1px solid rgba(0, 240, 255, 0.08);
      vertical-align: middle;
    }}

    .jump-nav {{
      display: flex;
      justify-content: space-between;
      margin-top: 14px;
      flex-wrap: wrap;
      gap: 10px;
    }}
  </style>
</head>
<body>
  <div class="scanlines"></div>
  <div class="container">
    <header>
      <div class="glitch-title">NODE // {ip_esc}</div>
      <div class="subtitle">⚡ DEEP DEVICE INTELLIGENCE &amp; CVE VULNERABILITY AUDIT ⚡</div>

      <div class="nav-bar">
        <a href="/netcheck.html" class="btn-nav">
          &larr; <span>RETURN TO LIVE MONITOR HUD</span>
        </a>
        <a href="/devices/" class="btn-nav mag">
          <span>&larr; ALL INTEL NODES DIRECTORY</span>
        </a>
      </div>
    </header>

    <!-- Top Identity Matrix -->
    <div class="detail-card">
      <div class="section-title">HARDWARE &amp; NETWORK TELEMETRY IDENTIFICATION</div>
      <div class="matrix-grid">
        <div class="matrix-item">
          <div class="matrix-label">IP ADDRESS</div>
          <div class="matrix-value" style="color:var(--cyan)">{ip_esc}</div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">MAC ADDRESS</div>
          <div class="matrix-value"><code>{mac_esc}</code></div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">HARDWARE VENDOR</div>
          <div class="matrix-value" style="color:var(--text)">{vendor_esc}</div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">INFERRED SYSTEM / OS</div>
          <div class="matrix-value" style="color:var(--magenta)">{os_esc}</div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">ROLE ASSIGNMENT</div>
          <div class="matrix-value">{role_esc} {f'({hostname_esc})' if hostname_esc else ''}</div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">RESPONSE LATENCY</div>
          <div class="matrix-value" style="color:var(--green)">{rtt:.1f} ms</div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">OVERALL SECURITY POSTURE</div>
          <div class="matrix-value"><span class="risk-badge {risk_cls}">{risk}</span></div>
        </div>
        <div class="matrix-item">
          <div class="matrix-label">SUBNET UPSTREAM</div>
          <div class="matrix-value" style="color:var(--dim)">Gateway: {gateway}</div>
        </div>
      </div>

      <!-- Quick Node Jumper -->
      <div class="jump-nav">
        <a href="device_{prev_ip}.html" class="btn-nav" style="font-size:0.72rem">
          &larr; PREVIOUS NODE ({prev_ip})
        </a>
        <a href="device_{next_ip}.html" class="btn-nav" style="font-size:0.72rem">
          NEXT NODE ({next_ip}) &rarr;
        </a>
      </div>
    </div>

    <!-- Port Auditing Table -->
    <div class="detail-card">
      <div class="section-title">ACTIVE SERVICE PORTS &amp; APPLICATION BANNERS ({len(ports)})</div>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th>PORT</th>
              <th>PROTO</th>
              <th>IDENTIFIED SERVICE</th>
              <th>APPLICATION BANNER / HTTP SERVER HEADER</th>
            </tr>
          </thead>
          <tbody>
{ports_joined}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Defensive CVE Audit -->
    <div class="detail-card">
      <div class="section-title" style="color:var(--magenta)">DEFENSIVE CVE AUDIT &amp; SECURITY ADVISORIES ({len(cves)})</div>
{cves_joined}
    </div>

    <footer style="text-align:center;margin-top:30px;font-size:0.75rem;color:var(--dim);letter-spacing:0.2em">
      [ STANDALONE INTEL NODE &middot; /var/www/html/devices/device_{ip_esc}.html &middot; NET//CHECK v3.0 ]
    </footer>
  </div>
</body>
</html>"""
    return html_content


# ==============================================================================
# Multi-Destination File Writing Engine
# ==============================================================================
def write_all_reports(results, subnet, local_ip, gateway, duration, primary_html="/var/www/html/netcheck.html"):
    """
    Renders and writes:
      1) Main Dashboard: /var/www/html/netcheck.html + ~/netcheck.html
      2) Secondary Directory: /var/www/html/devices/index.html + ~/devices/index.html
      3) Standalone Deep Detail: /var/www/html/devices/device_<ip>.html + ~/devices/device_<ip>.html
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_ips = [r["ip"] for r in results if r["is_up"]]

    # Destinations
    destinations = [
        {"html_file": primary_html, "devices_dir": os.path.join(os.path.dirname(primary_html), "devices")},
        {"html_file": os.path.expanduser("~/netcheck.html"), "devices_dir": os.path.expanduser("~/devices")}
    ]

    # Generate Page Contents
    main_html = generate_main_dashboard_html(results, subnet, local_ip, gateway, duration, timestamp)
    dir_html = generate_devices_directory_html(results, subnet, local_ip, gateway, duration, timestamp)

    # Render each individual device HTML
    dev_html_map = {}
    for r in results:
        dev_html_map[r["ip"]] = generate_individual_device_html(r, all_ips, subnet, gateway, local_ip, timestamp)

    for dest in destinations:
        html_file = dest["html_file"]
        dev_dir = dest["devices_dir"]

        try:
            os.makedirs(dev_dir, exist_ok=True)
            # 1. Main Dashboard
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(main_html)

            # 2. Directory Index
            with open(os.path.join(dev_dir, "index.html"), "w", encoding="utf-8") as f:
                f.write(dir_html)

            # 3. Individual Pages
            for ip_addr, content in dev_html_map.items():
                node_file = os.path.join(dev_dir, f"device_{ip_addr}.html")
                with open(node_file, "w", encoding="utf-8") as f:
                    f.write(content)

            print(f"{Colors.GREEN}[+] Technopunk dashboard & {len(dev_html_map)} deep intel nodes written to:{Colors.RESET} {html_file}", file=sys.stderr)
        except PermissionError:
            print(f"{Colors.YELLOW}[!] Permission notice for {html_file}: Handled via user fallback copy in ~/{Colors.RESET}", file=sys.stderr)
        except Exception as e:
            print(f"{Colors.RED}[-] Error writing telemetry to {html_file}: {e}{Colors.RESET}", file=sys.stderr)


# ==============================================================================
# Continuous Watch / Live Monitoring Mode
# ==============================================================================
def run_watch_mode(target_ips, args, subnet, local_ip, gateway, interface, html_path):
    """Continuous watch mode with live progress updates every interval."""
    print(f"{Colors.BOLD}{Colors.CYAN}[*] Starting Technopunk Live Radar (Refresh: {args.interval}s, Press Ctrl+C to stop)...{Colors.RESET}\n", file=sys.stderr)
    known_state = {}

    try:
        iteration = 0
        while True:
            iteration += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            _STATE.update("SCAN_START", 0, f"Beginning iteration #{iteration} at {timestamp}...",
                          f"Cycle #{iteration} initiated across {len(target_ips)} addresses", "INFO")

            results, duration = scan_network_full(
                target_ips,
                num_threads=args.threads,
                timeout=args.timeout,
                deep_audit=True
            )

            current_up = {r["ip"]: r for r in results if r["is_up"]}

            if iteration > 1:
                joined = set(current_up.keys()) - set(known_state.keys())
                left = set(known_state.keys()) - set(current_up.keys())

                if joined:
                    for ip in joined:
                        dev = current_up[ip]
                        msg = f"DEVICE JOINED: {ip} ({dev.get('vendor', 'Unknown')}) MAC: {dev.get('mac', 'N/A')}"
                        print(f" {Colors.GREEN}[+] [{timestamp}] {msg}{Colors.RESET}")
                        _STATE.add_log("SUCCESS", msg)
                if left:
                    for ip in left:
                        dev = known_state[ip]
                        msg = f"DEVICE LEFT: {ip} ({dev.get('vendor', 'Unknown')}) MAC: {dev.get('mac', 'N/A')}"
                        print(f" {Colors.RED}[-] [{timestamp}] {msg}{Colors.RESET}")
                        _STATE.add_log("PROBE", msg)

            known_state = current_up

            # Write Terminal Table
            up_count = sum(1 for r in results if r["is_up"])
            print(f"\n{Colors.BOLD}{Colors.WHITE}[Cycle #{iteration}] Active Devices: {up_count} / {len(target_ips)} (Sweep Duration: {duration:.2f}s){Colors.RESET}", file=sys.stderr)

            # Write HTML & Standalone Pages
            if not args.no_html:
                write_all_reports(results, subnet, local_ip, gateway, duration, primary_html=html_path)

            _STATE.update("IDLE_MONITORING", 100, f"Cycle complete. Waiting {args.interval}s until next sweep...",
                          f"Standby until next telemetry sweep in {args.interval}s", "INFO")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Monitoring terminated by operator.{Colors.RESET}", file=sys.stderr)


# ==============================================================================
# CLI Entry Point
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="check_network.py — Technopunk Network Scanner, Port Auditor & CVE Correlation Hub."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target subnet (e.g. 192.168.42.0/24) or single IP. Defaults to auto-detected local network."
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="Number of concurrent scanner threads (default: 50)."
    )
    parser.add_argument(
        "-w", "--timeout",
        type=float,
        default=1.0,
        help="Ping timeout in seconds (default: 1.0)."
    )
    parser.add_argument(
        "-W", "--watch",
        action="store_true",
        help="Continuous monitoring mode. Live updates every interval."
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=5,
        help="Scan interval in seconds for watch mode (default: 5)."
    )
    parser.add_argument(
        "--html-file",
        type=str,
        default="/var/www/html/netcheck.html",
        metavar="PATH",
        help="Primary path for HTML dashboard (default: /var/www/html/netcheck.html)."
    )
    parser.add_argument(
        "-p", "--primary-dir",
        default="/var/www/html/devices",
        help="Primary directory where scan_status.json will live"
    )
    parser.add_argument(
        "-f", "--fallback-dir",
        default="./devices",
        help="Fallback directory used when running locally"
    )
    parser.add_argument(
        "--iface", "-I", "--interface",
        default="eth0",
        help="Network interface to probe for IP range"
    )
    parser.add_argument(
        "-R", "--ip-range", "--range",
        default="192.168.1.0/24",
        help="CIDR notation of network to scan"
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Disable HTML report generation."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw telemetry in JSON format."
    )
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Print this help and exit"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output."
    )

    args = parser.parse_args()

    if args.h:
        parser.print_help(); sys.exit(0)

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    if not args.json:
        print_splashscreen()

    global _STATE
    _STATE = ScannerStateManager(primary_dir=args.primary_dir, fallback_dir=args.fallback_dir, iface=args.iface, ip_range=args.ip_range)
    auto_subnet, local_ip, gateway, interface = get_default_network()

    if args.target:
        target_str = args.target
        if "/" in target_str:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                target_ips = list(net.hosts()) if net.num_addresses > 2 else list(net)
                subnet = target_str
            except ValueError as e:
                print(f"{Colors.RED}[Error] Invalid CIDR network format: {target_str} ({e}){Colors.RESET}", file=sys.stderr)
                sys.exit(1)
        else:
            try:
                ipaddress.ip_address(target_str)
                target_ips = [target_str]
                subnet = f"{target_str}/32"
            except ValueError:
                print(f"{Colors.RED}[Error] Invalid IP address: {target_str}{Colors.RESET}", file=sys.stderr)
                sys.exit(1)
    else:
        if not auto_subnet:
            print(f"{Colors.RED}[Error] Could not automatically determine local subnet. Specify manually (e.g. 192.168.1.0/24).{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
        subnet = auto_subnet
        net = ipaddress.ip_network(subnet, strict=False)
        target_ips = list(net.hosts())

    if args.watch:
        run_watch_mode(target_ips, args, subnet, local_ip, gateway, interface, args.html_file)
        return

    # Single Scan
    results, duration = scan_network_full(
        target_ips,
        num_threads=args.threads,
        timeout=args.timeout,
        deep_audit=True
    )

    if args.json:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "subnet": subnet,
            "gateway": gateway,
            "local_host": local_ip,
            "duration_seconds": round(duration, 2),
            "total_targets": len(target_ips),
            "alive_count": len(results),
            "devices": results
        }
        print(json.dumps(output_data, indent=2))
    else:
        up_count = sum(1 for r in results if r["is_up"])
        print(f"\n{Colors.BOLD}{Colors.WHITE}Scan Complete:{Colors.RESET} {Colors.GREEN}{up_count} active devices{Colors.RESET} in {duration:.2f}s.", file=sys.stderr)

    if not args.no_html:
        write_all_reports(results, subnet, local_ip, gateway, duration, primary_html=args.html_file)


if __name__ == "__main__":
    # reinitialize state manager with CLI values
    _STATE = ScannerStateManager(primary_dir=args.primary_dir, fallback_dir=args.fallback_dir, iface=args.iface, ip_range=args.ip_range)
    main()
