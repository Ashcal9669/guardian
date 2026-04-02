"""
macOS Process Scanner
Scans running processes for malware indicators, suspicious locations,
invalid code signatures, and known malicious process names.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Any

# ---------------------------------------------------------------------------
# Known macOS malware / spyware process names (case-insensitive exact match)
# ---------------------------------------------------------------------------
KNOWN_MALWARE_NAMES: set[str] = {
    "mshelper",          # MSHelper cryptominer
    "pplauncher",        # Proton RAT launcher
    "subrosa",           # SubRosa spyware
    "pirrit",            # Pirrit adware
    "genieo",            # Genieo adware
    "vsearch",           # VSearch adware
    "crossrider",        # Crossrider adware
    "mackeeper",         # MacKeeper PUP
    "dummyplayer",       # DummyPlayer spyware
    "amos",              # Atomic macOS Stealer
    "atomicstealer",     # Atomic Stealer variant
    "realstealer",       # RealStealer info stealer
    "xloader",           # XLoader malware
    "pureland",          # Pureland spyware
    "cresent_core",      # Crescentcore malware
    "mughthesec",        # MughTheSec adware
    "bundlore",          # Bundlore adware
    "shlayer",           # Shlayer dropper
    "adload",            # AdLoad adware
    "tarmac",            # Tarmac dropper
    "osx.dok",           # OSX.Dok malware
    "calisto",           # Calisto backdoor
    "fruitfly",          # FruitFly surveillance
    "backdoor.mac",      # Generic backdoor
    "keydnap",           # KeyDnap backdoor
    "crisis",            # OSX.Crisis RAT
    "imuler",            # OSX.Imuler RAT
    "flashback",         # Flashback trojan
    "wirenet",           # Wirenet password stealer
    "eleanor",           # Eleanor backdoor
    "coinminer",         # generic coinminer
}

# Directories that are suspicious for process execution
SUSPICIOUS_DIRS: list[str] = [
    "/tmp/",
    "/var/tmp/",
    "/var/folders/",
    os.path.expanduser("~/Downloads/"),
    os.path.expanduser("~/.Trash/"),
    "/private/tmp/",
    "/private/var/tmp/",
    "/private/var/folders/",
]

# Ports that are normal on macOS (safe list — anything else on LISTEN is flagged)
SAFE_LISTENING_PORTS: set[int] = {
    22,    # SSH (when enabled)
    80,    # HTTP
    88,    # Kerberos
    443,   # HTTPS
    548,   # AFP
    631,   # CUPS printing
    3283,  # Apple Remote Desktop
    5900,  # VNC / Screen Sharing
    8080,  # HTTP alt
    8443,  # HTTPS alt
    49152, # mDNSResponder ephemeral
}

# Regex that flags base64-looking or random-string process names (≥12 hex/alnum chars, no vowel runs)
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{12,}={0,2}$')
_RANDOM_RE = re.compile(r'^[a-f0-9]{8,}$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", -1
    except Exception as exc:
        return "", str(exc), -1


def _make_finding(
    fid: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: dict,
    remediation: str,
) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "source": "mac.processes",
    }


def _parse_ps_aux(output: str) -> list[dict]:
    """Parse `ps aux` output into list of process dicts."""
    procs = []
    lines = output.strip().splitlines()
    if not lines:
        return procs
    for line in lines[1:]:  # skip header
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            procs.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu": parts[2],
                "mem": parts[3],
                "vsz": parts[4],
                "rss": parts[5],
                "tt": parts[6],
                "stat": parts[7],
                "started": parts[8],
                "time": parts[9],
                "command": parts[10],
            })
        except IndexError:
            continue
    return procs


def _codesign_check(path: str) -> tuple[bool, str]:
    """
    Returns (is_valid, detail_message).
    is_valid=True means the binary has a valid Apple or trusted signature.
    """
    if not path or not os.path.exists(path):
        return False, "binary path not found"
    stdout, stderr, rc = _run(["codesign", "-v", "--deep", path], timeout=10)
    if rc == 0:
        # Also check if it's Apple-signed
        out2, _, _ = _run(["codesign", "-dv", path], timeout=10)
        combined = out2 + stderr  # codesign -dv writes to stderr
        return True, combined
    return False, stderr.strip()


def _get_exe_from_command(command: str) -> str:
    """Extract the executable path from a ps command string."""
    # Strip leading whitespace / env vars / shell flags
    cmd = command.strip()
    # If starts with a known shell, get the script path
    for shell in ("/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python", "/usr/bin/perl"):
        if cmd.startswith(shell):
            return shell
    # Return first token that looks like a path
    first = cmd.split()[0] if cmd.split() else ""
    return first


def _looks_random(name: str) -> bool:
    """Heuristic: does this process name look like a random/generated string?"""
    base = os.path.basename(name)
    if _B64_RE.match(base):
        return True
    if _RANDOM_RE.match(base):
        return True
    # Long name with no vowels = suspicious
    alpha = re.sub(r'[^a-z]', '', base.lower())
    if len(alpha) >= 10 and not re.search(r'[aeiou]', alpha):
        return True
    return False


def _parse_lsof_listening(output: str) -> list[dict]:
    """Parse lsof -i -n -P output, return rows where TYPE==LISTEN."""
    results = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        if "LISTEN" not in line and "listen" not in line.lower():
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        name_field = parts[-1]  # e.g. *:8080 or 192.168.1.1:443
        port = None
        if ":" in name_field:
            try:
                port = int(name_field.rsplit(":", 1)[-1])
            except ValueError:
                pass
        results.append({
            "command": parts[0],
            "pid": parts[1],
            "user": parts[2],
            "name": name_field,
            "port": port,
        })
    return results


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_suspicious_locations(procs: list[dict], findings: list, counter: list):
    for proc in procs:
        cmd = proc["command"]
        exe = _get_exe_from_command(cmd)
        for sus_dir in SUSPICIOUS_DIRS:
            if exe.startswith(sus_dir) or cmd.startswith(sus_dir):
                counter[0] += 1
                fid = f"proc_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="high",
                    category="malware",
                    title=f"Process running from suspicious directory",
                    description=(
                        f"Process PID {proc['pid']} ({proc['user']}) is executing "
                        f"from a temporary or user-writable directory: {sus_dir}"
                    ),
                    evidence={
                        "pid": proc["pid"],
                        "user": proc["user"],
                        "command": cmd,
                        "suspicious_dir": sus_dir,
                    },
                    remediation=(
                        "Investigate the process immediately. Terminate with `kill -9 <pid>` "
                        "if malicious. Legitimate software should not run from /tmp or ~/Downloads."
                    ),
                ))
                break  # only flag once per process


def _scan_known_malware(procs: list[dict], findings: list, counter: list):
    for proc in procs:
        basename_lower = os.path.basename(proc["command"].split()[0]).lower() if proc["command"].split() else ""
        if basename_lower not in KNOWN_MALWARE_NAMES:
            continue
        counter[0] += 1
        fid = f"proc_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="critical",
            category="malware",
            title=f"Known malware process detected: {basename_lower}",
            description=(
                f"Process PID {proc['pid']} matches the exact process name of known macOS malware "
                f"'{basename_lower}'. Immediate investigation required."
            ),
            evidence={
                "pid": proc["pid"],
                "user": proc["user"],
                "command": proc["command"],
                "matched_name": basename_lower,
            },
            remediation=(
                f"Terminate the process: `kill -9 {proc['pid']}`. Run a full malware scan "
                "with Malwarebytes or ClamAV. Consider re-imaging the system."
            ),
        ))


def _scan_random_names(procs: list[dict], findings: list, counter: list):
    for proc in procs:
        exe = _get_exe_from_command(proc["command"])
        basename = os.path.basename(exe)
        if _looks_random(basename):
            counter[0] += 1
            fid = f"proc_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="malware",
                title=f"Process with suspicious random-looking name: {basename}",
                description=(
                    f"Process PID {proc['pid']} has a name that resembles a randomly generated "
                    f"or base64-encoded string, a common evasion technique."
                ),
                evidence={
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "command": proc["command"],
                    "basename": basename,
                },
                remediation=(
                    "Investigate the process and its parent. Use `lsof -p <pid>` to see open "
                    "files. Terminate if malicious."
                ),
            ))


def _scan_code_signatures(procs: list[dict], findings: list, counter: list):
    checked: set[str] = set()
    for proc in procs:
        exe = _get_exe_from_command(proc["command"])
        if not exe or exe in checked:
            continue
        if not os.path.isabs(exe):
            continue
        # Skip kernel/system processes
        if exe in ("/sbin/launchd", "/usr/libexec/xpcproxy"):
            continue
        checked.add(exe)
        is_valid, detail = _codesign_check(exe)
        if not is_valid and os.path.exists(exe):
            counter[0] += 1
            fid = f"proc_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="high",
                category="integrity",
                title=f"Process with no/invalid code signature: {os.path.basename(exe)}",
                description=(
                    f"The executable '{exe}' (PID {proc['pid']}) has no valid code signature "
                    "or its signature is invalid. This may indicate tampering or malware."
                ),
                evidence={
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "exe": exe,
                    "codesign_error": detail,
                },
                remediation=(
                    "Verify the binary is legitimate. If unknown, remove it and check "
                    "for persistence mechanisms. Re-install affected applications from "
                    "official sources."
                ),
            ))


def _scan_listening_ports(findings: list, counter: list) -> int:
    """Flag processes listening on unexpected ports."""
    stdout, stderr, rc = _run(["lsof", "-i", "-n", "-P", "-sTCP:LISTEN"], timeout=15)
    if rc != 0 and not stdout:
        return 0
    listeners = _parse_lsof_listening(stdout)
    for listener in listeners:
        port = listener.get("port")
        if port is None:
            continue
        if port not in SAFE_LISTENING_PORTS and port < 49152:
            counter[0] += 1
            fid = f"proc_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="network",
                title=f"Process listening on unexpected port {port}",
                description=(
                    f"Process '{listener['command']}' (PID {listener['pid']}, "
                    f"user {listener['user']}) is listening on port {port}, "
                    "which is not in the expected safe list for macOS."
                ),
                evidence={
                    "command": listener["command"],
                    "pid": listener["pid"],
                    "user": listener["user"],
                    "address": listener["name"],
                    "port": port,
                },
                remediation=(
                    f"Investigate why '{listener['command']}' is listening on port {port}. "
                    "Use `lsof -p <pid>` for more details. Disable if not intentional."
                ),
            ))
    return len(listeners)


def _scan_injection_indicators(procs: list[dict], findings: list, counter: list):
    """
    Check for signs of process injection by looking for processes with
    DYLD_INSERT_LIBRARIES or unusual mach port references via lsof.
    """
    stdout, stderr, rc = _run(["ps", "auxeww"], timeout=15)
    if rc != 0 or not stdout:
        return
    injection_re = re.compile(r'DYLD_INSERT_LIBRARIES=(\S+)')
    for line in stdout.splitlines()[1:]:
        m = injection_re.search(line)
        if m:
            parts = line.split(None, 10)
            pid = parts[1] if len(parts) > 1 else "?"
            dylib = m.group(1)
            counter[0] += 1
            fid = f"proc_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="critical",
                category="malware",
                title=f"DYLD_INSERT_LIBRARIES injection detected (PID {pid})",
                description=(
                    f"Process PID {pid} is running with DYLD_INSERT_LIBRARIES={dylib}. "
                    "This technique is used to inject malicious dylibs into legitimate processes."
                ),
                evidence={
                    "pid": pid,
                    "dylib_path": dylib,
                    "full_cmdline": line[:300],
                },
                remediation=(
                    "Immediately terminate the process. Investigate the dylib at the indicated "
                    "path. Check LaunchAgent/Daemon plists for the injection vector."
                ),
            ))


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan() -> dict:
    start = time.time()
    findings: list[dict] = []
    counter = [0]  # mutable counter shared across helpers
    metadata: dict[str, Any] = {}

    try:
        # 1. Gather process list
        stdout, stderr, rc = _run(["ps", "aux"], timeout=15)
        if rc != 0 and not stdout:
            return {
                "module": "mac.processes",
                "status": "error",
                "findings": [],
                "metadata": {},
                "error": f"Failed to run ps aux: {stderr}",
            }

        procs = _parse_ps_aux(stdout)
        metadata["process_count"] = len(procs)

        # 2. Run each sub-scanner
        _scan_suspicious_locations(procs, findings, counter)
        _scan_known_malware(procs, findings, counter)
        _scan_random_names(procs, findings, counter)
        _scan_injection_indicators(procs, findings, counter)

        # Code signature scanning can be slow — limit to first 60 unique exes
        unique_exes_procs = []
        seen_exes: set[str] = set()
        for p in procs:
            exe = _get_exe_from_command(p["command"])
            if exe and exe not in seen_exes and os.path.isabs(exe):
                seen_exes.add(exe)
                unique_exes_procs.append(p)
                if len(unique_exes_procs) >= 60:
                    break
        _scan_code_signatures(unique_exes_procs, findings, counter)

        # Listening ports (uses lsof internally)
        listener_count = _scan_listening_ports(findings, counter)
        metadata["listening_ports_checked"] = listener_count

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.processes",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.processes",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.processes",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
