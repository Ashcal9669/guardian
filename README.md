# Guardian — macOS + iOS Full System Security Scanner

Guardian is an open-source security scanner for Apple Silicon Macs and connected iPhones. It performs deep, automated analysis of the local system for malware, persistence mechanisms, suspicious processes, network anomalies, and more — without requiring an Apple ID, iCloud, or any paid service.

## Prerequisites

- macOS 12 Monterey or later (Apple Silicon / M-series recommended)
- Python 3.9+
- [Homebrew](https://brew.sh/)
- `libimobiledevice` (for iPhone scanning)

## Installation

```bash
# Install libimobiledevice for iOS device support
brew install libimobiledevice

# Install required Python packages
pip3 install yara-python psutil
```

Clone or download Guardian, then run directly — no build step required.

## Usage

```bash
# Full scan (macOS + iOS if iPhone connected)
sudo python3 guardian.py

# Quick scan — skip slow filesystem traversal
sudo python3 guardian.py --quick

# macOS only — no iPhone scanning
sudo python3 guardian.py --no-ios

# Save report to a custom directory
sudo python3 guardian.py --output /tmp/security-reports

# Run specific modules only
sudo python3 guardian.py --modules mac.integrity,mac.processes,mac.network

# Run without sudo (reduced coverage — some checks require root)
python3 guardian.py --quick --no-ios
```

## What It Scans

**macOS (always):**
- System Integrity Protection (SIP) status and configuration
- User accounts — hidden users, sudo group members, unexpected admins
- Running processes — known malware names, suspicious launch locations, DYLD injection, invalid code signatures, unexpected listening ports
- Network connections — active connections, DNS configuration, firewall status, ARP cache anomalies
- Persistence mechanisms — LaunchAgents, LaunchDaemons, login items, cron jobs, shell profile modifications
- Filesystem (full scan, skip with `--quick`) — world-writable setuid binaries, hidden files in key locations, recently modified system files
- Browsers — suspicious extensions, unexpected profiles, credential database tampering

**YARA (if `yara-python` installed):**
- Rule-based scanning of `/Applications`, `~/Library`, `/tmp`, `/var/tmp`
- Matches against the bundled `ioc/yara_rules.yar` ruleset

**IOC cross-reference:**
- All network findings are checked against `ioc/known_bad.json` (malicious IPs, domains, process names)
- Matches are escalated to `critical` severity

**iPhone (plug in via USB):**
- Requires USB connection — trust the computer when prompted on the iPhone
- Device info and iOS version
- Installed app inventory
- Syslog snapshot analysis for suspicious activity

## Permissions Note

Guardian works without `sudo` but with reduced coverage:
- Process inspection and code signing checks are limited
- Some filesystem locations require root access
- LaunchDaemon inspection (system-level) requires root

Run with `sudo` for full coverage:

```bash
sudo python3 guardian.py
```

## iPhone Scanning

1. Connect your iPhone via USB
2. Unlock the iPhone and tap **Trust** when prompted
3. Run Guardian — it will auto-detect the connected device

No Apple ID, iCloud credentials, or developer certificate required. Guardian uses `libimobiledevice`, an open-source reimplementation of Apple's communication protocol.

## Output

Guardian generates an HTML report and saves it to `~/Desktop` by default (override with `--output`). The report is automatically opened in your default browser after the scan completes.

Exit codes:
- `0` — no findings above medium severity
- `1` — high severity findings present
- `2` — critical severity findings present
