# Changelog

All notable changes to **NetScan2026 / NET//CHECK** are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project follows the v3.0 engine line.

## [1.0.0] - 2026-09-20

### Added
- Initial public release of the **NET//CHECK v3.0** technopunk network scanner & telemetry hub.
- Multithreaded ICMP ping sweep for fast subnet-wide device discovery (50 threads by default).
- TCP port probing across 18 curated service ports with live application banner grabbing.
- MAC / OUI vendor lookup via built-in OUI database + system ARP-table correlation.
- OS inference engine for per-device operating-system fingerprinting.
- Curated defensive CVE knowledge base with CVSS severity ratings (EternalBlue and other advisories).
- Technopunk HTML telemetry reports: main dashboard (`netcheck.html`), device directory, standalone per-device deep-intel pages, and live `scan_status.json`.
- Continuous **watch mode** (`--watch`) for real-time radar monitoring.
- Optional Node / Express + MySQL backend with scans / users / permissions API on port 3000.

## [Unreleased]

### Planned
- Configurable service-port list via CLI / config file.
- Export of scan results to CSV / PDF.
- Docker image for one-command deployment of the web backend.
