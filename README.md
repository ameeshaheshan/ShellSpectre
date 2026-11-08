<div align="center">
<a href="https://github.com/ameeshaheshan/ShellSpectre/"><img src="https://raw.githubusercontent.com/ameeshaheshan/ShellSpectre/main/src/banner.png)" alt="ShellSpectre" onerror="this.style.display='none'"></a><br>

# ⚡ ShellSpectre v2.6

**Advanced CVE-2026-109618 & CVE-2026-109619 Detection & Security Research Framework**<br>
**High-Fidelity Scanning 🔍 · SAPI Profiling 🛡️ · Pre-Auth Multipart Assessment 💥**<br><br>

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey?style=for-the-badge)](https://github.com/ameeshaheshan)
[![CLI](https://img.shields.io/badge/CLI-Modern_Engine-purple?style=for-the-badge)](shellspectre.py)

  <br>
  
## 🎯 Overview
**ShellSpectre ⚡** is a specialized security framework designed for security researchers, sysadmins, and penetration testers to audit, detect, and analyze vulnerabilities associated with **CVE-2026-109618** and **CVE-2026-109619** (PHP core multipart parser memory corruption and state persistence flaws).

Built with cross-platform terminal compatibility (Windows, Linux, macOS), automatic local virtual environment management, dynamic baseline differential calibration to eliminate false positives, and multi-format reporting (JSON, CSV, Markdown).

[Features](#-features) • [Technical Architecture](#-technical-architecture) • [Installation](#-installation) • [Usage](#-usage) • [Options](#-options) • [Reporting](#-reporting) • [Remediation](#-remediation) • [Credits](#-credits--acknowledgements) • [Disclaimer](#-disclaimer)

</div>

---

## ⚡ Features

| Icon | Feature                          | Description                                                                                                           |
| :--: | :------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
|  🛡️  | **Dynamic Baseline Calibration** | `--calibrate` establishes normal response profiles before running probes to prevent false positives.                  |
|  🔍  | **SAPI Pre-Flight Profiling**    | `--preflight` fingerprints web server architecture (`Apache mod_php`, `PHP-FPM`, `LiteSpeed LSPHP`) and PHP versions. |
|  📦  | **Smart Virtual Environment**    | Automatic `.venv` bootstrapping and self-installation from `requirements.txt` on startup.                             |
|  🖥️  | **Cross-Platform UI**            | Native terminal screen clearing and 24-bit ANSI color formatting for Windows, Linux, and macOS.                       |
|  ⏱️  | **Rate Limiting & Concurrency**  | Configurable thread pooling (`-t`) and request pacing (`--delay`) to protect fragile environments.                    |
|  📊  | **Multi-Format Export**          | Export findings directly to **JSON**, **CSV**, or **Markdown** tables.                                                |

---

## 🔬 Technical Architecture

### The Vulnerability Mechanism

**ShellSpectre** audits two related PHP core memory management flaws disclosed in late 2026:

1. **CVE-2026-109618 (Multipart OOM Corruption):**
   When parsing heavily amplified or nested multipart parameter keys (`a[][a][a]...`), PHP's Zend Engine allocates nested hash tables for request parameter storage. When these allocations exceed PHP's `memory_limit`, the engine executes an abrupt out-of-memory (OOM) bailout using `longjmp()`. This bypasses normal garbage collection routines, leaving internal hash tables in a half-initialized state.

2. **CVE-2026-109619 (Stale Global State Persistence):**
   In architectures using persistent worker models—most notably **Apache `mod_php` with the Prefork MPM**—worker processes sequentially handle multiple HTTP requests without process recycling. When an OOM occurs mid-request while `session.upload_progress` tracking structures are allocated, dangling pointers in global state persist into subsequent requests, leading to memory corruption.

### Low-Level HTTP Protocol & Streaming Engine

Standard high-level HTTP client libraries (such as `requests` or `urllib3`) buffer entire responses and struggle with half-closed sockets, chunked upload streams, and server worker aborts. **ShellSpectre** implements a custom non-blocking HTTP/1.1 transport using **`h11`** on top of `asyncio.Protocol`:

```python
class DuplexHTTPProtocol(asyncio.Protocol):
    """Custom full-duplex streaming transport with backpressure flow control."""
    def __init__(self):
        self.transport = None
        self.incoming = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False

    def data_received(self, data: bytes):
        if not data: return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        # Apply backpressure when read buffer exceeds high-water limit (256 KB)
        if self.buffered_bytes >= 256 * 1024 and not self.reading_paused:
            self.transport.pause_reading()
            self.reading_paused = True
```

### Crash Signature & SAPI Verdict Matrix

The detection engine parses server response signatures to differentiate between standard application errors, reverse proxy worker disconnects, and Zend Engine memory corruption:

```python
def evaluate_crash_signal(control: HTTPResult, probe: HTTPResult, sapi: str) -> tuple:
    # 1. In-band fatal error: memory limit reached inside core multipart parser (pre-RINIT)
    if b"Allowed memory size of" in probe.body and b"Unknown" in probe.body:
        return ("PHP-FPM/mod_php", "In-band fatal error: memory exhausted in Unknown during multipart parsing")

    # 2. Worker death: Control request returned valid HTML (200), but probe returned empty 500
    if probe.status_code == 500 and control.body and not probe.body:
        return ("PHP-FPM/mod_php", "HTTP 500 with empty body vs populated baseline (worker restarted)")

    # 3. Gateway aborts: Frontend reverse proxy lost backend socket
    if probe.status_code in (502, 503, 504):
        return ("PHP-FPM", f"HTTP {probe.status_code} from reverse proxy gateway (backend worker terminated)")

    return (None, None)
```

### Probe Construction Mechanics

The detection engine uses a 42-byte control request followed by up to three structured multipart probes:

```python
# Probe generation snippet (from scanner core)
def build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    # Nested array key depth (62 levels) forces deep HashTable allocations
    name = b"a[]" + (b"[a]" * 62)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]
```

### Probe Progression Profile

| Probe Stage | Payload Size | Multipart Parts | Detection Target                                         |
| :---------: | :----------: | :-------------: | :------------------------------------------------------- |
| **Control** |   42 Bytes   |        1        | Establishes status baseline (`200 OK` vs. custom errors) |
| **Probe 1** |    1 MiB     |      4,000      | Low-memory configurations (`memory_limit <= 32M`)        |
| **Probe 2** |    8 MiB     |      1,020      | Standard configurations (`memory_limit = 128M`)          |
| **Probe 3** |    20 MiB    |      1,020      | High-memory configurations (`memory_limit >= 256M`)      |

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/ameeshaheshan/ShellSpectre.git

# Navigate to directory
cd ShellSpectre

# Run directly (virtual environment and dependencies are automatically bootstrapped)
python shellspectre.py -u https://target.local
```

### Docker Setup

```bash
# Build container image
docker build -t shellspectre .

# Run single scan in container
docker run --rm shellspectre -u https://example.com/index.php
```

---

## 💡 Progressive Usage Guide

ShellSpectre provides a flexible CLI interface designed to scale from quick health-checks to full enterprise security assessments.

```bash
python shellspectre.py [OPTIONS] [-u URL | -l LIST]
```

---

### 🟢 Level 1: Basic Scans (Quick Single-Target Audits)

#### 1.1 Simple Availability & Vulnerability Check

```bash
python shellspectre.py -u https://example.com/index.php
```

📌 **Explanation:**

- Tests `/index.php` on `https://example.com`.
- Sends a 42-byte control probe to verify normal response codes.
- Streams structured multipart probes (1 MiB, 8 MiB, 20 MiB) until a verdict is settled.

#### 1.2 Inspect HTTP Reasons and Verdict Evidence (Verbose Mode)

```bash
python shellspectre.py -u https://example.com/index.php -v
```

📌 **Explanation:**

- `-v` (`--verbose`) displays underlying decision reasons, detected SAPI hints, advertised PHP release versions, and raw HTTP response headers.

#### 1.3 Ignore Self-Signed / Invalid TLS Certificates

```bash
python shellspectre.py -u https://dev-server.lan:8443/ -k
```

📌 **Explanation:**

- `-k` (`--insecure`) disables SSL/TLS certificate verification, ideal for auditing internal lab environments, staging servers, and self-signed intranets.

---

### 🟡 Level 2: Intermediate Scans (Batch & Targeted Audits)

#### 2.1 Multi-Threaded Batch Scanning

```bash
python shellspectre.py -l targets.txt -t 20 -o results.json
```

📌 **Explanation:**

- `-l targets.txt` loads targets from a text file, automatically pruning duplicates.
- `-t 20` spawns 20 parallel threads to process targets concurrently.
- `-o results.json` saves all vulnerable hosts and evidence directly into a structured JSON file.

#### 2.2 Dynamic Baseline Calibration (Zero False Positives)

```bash
python shellspectre.py -l targets.txt --calibrate -o clean_results.json
```

📌 **Explanation:**

- `--calibrate` sends a non-intrusive baseline probe before testing.
- If a target natively returns `500 Internal Server Error` or drops requests under baseline conditions, it will **not** be falsely reported as vulnerable.

#### 2.3 Custom Parameter & Endpoint Auditing

```bash
python shellspectre.py -u https://example.com --path /app.php --path /api/v1/upload.php
```

📌 **Explanation:**

- `--path` allows supplying custom PHP endpoints where the application handles incoming multipart forms. Repeatable for multiple entry points.

---

### 🔴 Level 3: Advanced Scans (Hardened Enterprise Audits)

#### 3.1 Pre-Flight SAPI Profiling & Rate Limiting

```bash
python shellspectre.py -l production_hosts.txt --preflight --delay 0.5 -t 5
```

📌 **Explanation:**

- `--preflight` interrogates web server headers and cookies before launching heavy probes, fingerprinting whether the backend is `mod_php`, `PHP-FPM`, or `LiteSpeed`.
- `--delay 0.5` introduces a 500ms delay between requests to protect sensitive production endpoints from CPU exhaustion.

#### 3.2 Custom Headers & Authentication Wrappers

```bash
python shellspectre.py -u https://secure.corp.local/admin.php \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -H "Cookie: PHPSESSID=s3cur3s3ss10n; auth=true" \
  -H "X-Forwarded-For: 127.0.0.1" \
  --follow-redirects
```

📌 **Explanation:**

- `-H` attaches arbitrary HTTP headers (can be specified multiple times).
- `--follow-redirects` automatically tracks up to 10 HTTP redirects (e.g., 301/302 from HTTP to HTTPS or SSO gateways).

#### 3.3 SAPI Rule Enforcement

```bash
python shellspectre.py -u https://cluster.internal.net --sapi fpm --timeout 90
```

📌 **Explanation:**

- `--sapi fpm` restricts verdict rules strictly to PHP-FPM failure modes (502/503 worker exits), ignoring `mod_php` heuristics.
- `--timeout 90` increases connection and response read deadlines to 90 seconds for high-latency connections.

#### 3.4 Multi-Format Exporting (Markdown / CSV / JSON)

```bash
# Export as an executive Markdown audit table
python shellspectre.py -l hosts.txt --calibrate --format markdown -o report.md

# Export as an Excel-friendly CSV spreadsheet
python shellspectre.py -l hosts.txt --calibrate --format csv -o audit.csv
```

📌 **Explanation:**

- `--format markdown` outputs GitHub-ready tables.
- `--format csv` formats findings for ingest into spreadsheet tools and ticketing systems.

---

### 🚀 Level 4: Full Hardened Production Pipeline (Master Command)

```bash
python shellspectre.py \
  -l enterprise_assets.txt \
  -t 15 \
  --timeout 45 \
  --calibrate \
  --preflight \
  --delay 0.25 \
  --follow-redirects \
  -H "User-Agent: EnterpriseSecScanner/2.6" \
  --format markdown \
  -o executive_audit_report.md
```

## 🔧 Options

```text
options:
  -h, --help            Show this help message and exit
  --disclaimer          Print authorized-use-only notice and exit
  --mode {scan,exploit,auto}
                        Operation mode (default: scan)
  -u, --url URL         Single target URL
  -l, --list LIST       File containing target URLs (one per line)
  -t, --threads THREADS Concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 60)
  -o, --output OUTPUT   Output report file
  --all-results         Save all results, not only vulnerable
  -k, --insecure        Disable TLS certificate verification
  --follow-redirects    Follow HTTP redirects (up to 10 hops)
  -H, --header HEADER   Custom header 'Key: Value' (repeatable)
  -v, --verbose         Verbose output (show response details)
  -q, --quiet           Only print positive detections
  --no-color            Disable ANSI color output
  --sapi {auto,mod_php,fpm}
                        SAPI verdict rules (default: auto)
  --path PATH           Custom path to test (repeatable)
  --path-file PATH_FILE File of paths to test (one per line)
  --calibrate           Perform dynamic baseline calibration
  --preflight           Perform deep SAPI and web server pre-flight profiling
  --format {json,csv,markdown}
                        Output format (default: json)
  --delay DELAY         Delay in seconds between requests (default: 0.0)
```

---

## 📊 Reporting

### Markdown Summary Report (`--format markdown`)

```markdown
# ShellSpectre Scan Report

- **Scan Time:** 2026-11-08T14:00:00Z
- **Total Scanned:** 2 | **Vulnerable:** 1 | **Not Vulnerable:** 1

| Host                                      | Verdict        | SAPI    | PHP Version | Status | Reason                                          |
| ----------------------------------------- | -------------- | ------- | ----------- | ------ | ----------------------------------------------- |
| `https://vulnerable-host.local/index.php` | **VULNERABLE** | mod_php | PHP/8.3.35  | 500    | Probe 2 crashed worker handler (OOM in Unknown) |
| `https://patched-host.local/index.php`    | FIXED          | mod_php | PHP/8.3.36  | 200    | Patched release reported                        |
```

### JSON Format (`--format json`)

```json
{
  "scan_time": "2026-11-08T14:00:00Z",
  "format": "json",
  "total_results": 1,
  "results": [
    {
      "host": "https://vulnerable-host.local/index.php",
      "verdict": "VULNERABLE",
      "vulnerable": true,
      "sapi": "mod_php",
      "powered_by": "PHP/8.3.35",
      "status_code": 500,
      "reason": "Probe 2 (8 MiB, 1020 parts) crashed the request handler: in-band PHP fatal error",
      "timestamp": "2026-11-08T14:00:02Z"
    }
  ]
}
```

---

## 🛡️ Remediation

To remediate CVE-2026-109618 and CVE-2026-109619:

1. **Upgrade Core PHP Packages:**
   Update to official patched releases or vendor backports:
   - **PHP 8.2:** Upgrade to `8.2.35` or later
   - **PHP 8.3:** Upgrade to `8.3.36` or later
   - **PHP 8.4:** Upgrade to `8.4.27` or later
   - **PHP 8.5:** Upgrade to `8.5.12` or later

2. **Disable Session Upload Tracking (if unused):**

   ```ini
   ; In php.ini
   session.upload_progress.enabled = Off
   ```

3. **WAF & Request Body Restraints:**
   Enforce body-size and nesting constraints in your reverse proxy (e.g. Nginx or Cloudflare):
   ```nginx
   # Nginx configuration
   client_max_body_size 10M;
   ```

---

## 🤝 Credits & Acknowledgements

- **Original Research:** Discovered and analyzed by the security research teams investigating core PHP multipart memory handling (CVE-2026-109618 / CVE-2026-109619).
- **Inspiration:** Architectural design and CLI concepts inspired by [devploit/php2shell](https://github.com/devploit/php2shell).
- **Scanner Core Logic:** Based on detection methodologies researched by the Assetnote Security Research Team.

---

## ⚠️ Disclaimer

> **For Authorized Security Research and Defensive Auditing Only.**
>
> This tool is designed strictly for researchers, administrators, and security professionals to identify and remediate vulnerabilities in systems they own or have explicit written permission to test. Unauthorized scanning or testing of third-party systems without permission is illegal. The developers assume no liability for misuse of this software.

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ameeshaheshan/ShellSpectre&type=Date)](https://star-history.com/#ameeshaheshan/ShellSpectre&Date)

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/ameeshaheshan">Ameesha Heshan</a></sub>
</div>
