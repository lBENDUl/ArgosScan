# 👁️ ArgosScan

> **The guardian with a thousand eyes.**  
> Open-source vulnerability scanner — port scanning, service detection, CVE matching, and SSL analysis from a single CLI.

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

---

## Features

| Feature | Description |
|---|---|
| 🔌 Port scanning | nmap wrapper with `fast / normal / thorough` presets |
| 🔍 Service identification | Banner grabbing for version enrichment |
| 🛡️ CVE matching | Real-time NVD API v2 queries with 12-hour local cache |
| 🔒 SSL/TLS analysis | Protocol version, cipher suite, and certificate checks |
| 📊 HTML report | Self-contained, styled report you can share or archive |
| 📄 JSON export | Machine-readable output for CI/CD pipelines |
| 🖥️ CLI output | Colour-coded terminal report |

---

## Requirements

- Python 3.9+
- nmap

```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap
```

---

## Installation

```bash
git clone https://github.com/lBENDUl/ArgosScan.git
cd argosScan
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Basic scan (CLI output)
python argosScan.py scan example.com

# Specific ports
python argosScan.py scan example.com -p 22,80,443

# HTML report
python argosScan.py scan example.com --format html -o report.html

# JSON export
python argosScan.py scan example.com --format json -o results.json

# Deep scan
python argosScan.py scan example.com -s thorough
```

---

## Commands

### `scan` — Full vulnerability scan

```
python argosScan.py scan TARGET [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `-p, --ports` | `1-10000` | Port range or comma-separated list |
| `-s, --speed` | `normal` | `fast` / `normal` / `thorough` |
| `--format` | `cli` | `cli` / `html` / `json` |
| `-o, --output` | auto | Output file path |
| `--nvd-key` | — | NVD API key (or `NVD_API_KEY` env var) |
| `--no-ssl` | — | Skip SSL/TLS analysis |
| `--log-file` | — | Write debug log to file |

### `ssl` — SSL/TLS only

```bash
python argosScan.py ssl example.com
python argosScan.py ssl example.com -p 8443
```

### `ports` — Quick port scan

```bash
python argosScan.py ports example.com
python argosScan.py ports example.com -p 1-1024 -s fast
```

### `clear-cache` — Wipe NVD cache

```bash
python argosScan.py clear-cache
```

---

## Scan Speed Presets

| Preset | nmap flags | Best for |
|---|---|---|
| `fast` | `-T4 --top-ports 100 -sV` | Quick triage of top-100 ports |
| `normal` | `-T3 -sV` | Balanced speed + accuracy (default) |
| `thorough` | `-T2 -sV --version-intensity 9` | Deep analysis, slower |

---

## NVD API Key

Without a key ArgosScan uses the public NVD endpoint (limited to ~5 requests/s). For frequent scans, get a free key at https://nvd.nist.gov/developers/request-an-api-key and set it via:

```bash
# Environment variable (recommended)
export NVD_API_KEY=your-key-here

# Or per invocation
python argosScan.py scan example.com --nvd-key your-key-here
```

---

## Project Structure

```
argosScan/
├── argosScan.py          ← CLI entrypoint
├── modules/
│   ├── port_scanner.py   ← nmap wrapper
│   ├── service_identifier.py  ← banner grabbing
│   ├── cve_matcher.py    ← NVD API client
│   └── ssl_analyzer.py   ← TLS checks
├── reporters/
│   ├── cli_reporter.py   ← ANSI terminal output
│   ├── html_reporter.py  ← self-contained HTML report
│   └── json_reporter.py  ← JSON export
├── utils/
│   ├── logger.py         ← logging setup
│   ├── validator.py      ← target validation
│   └── cache.py          ← TTL file cache
├── tests/
│   └── test_argosScan.py
├── requirements.txt
└── README.md
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## ⚠️ Legal Notice

Only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal in your jurisdiction.

---

## Roadmap (Open Source)

- [ ] Concurrent CVE lookups
- [ ] UDP port scanning
- [ ] Service fingerprint database (offline fallback)
- [ ] SARIF output format
- [ ] GitHub Actions integration example

---

## License

MIT © [lBENDUl](https://github.com/lBENDUl)
