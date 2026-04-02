"""
macOS Filesystem Scanner
Scans for SUID/SGID binaries, world-writable system files, suspicious dotfiles,
recently modified system binaries, temp directory threats, browser extensions,
keylogger indicators, cryptocurrency miners, and dylib injection.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Baseline SUID/SGID binaries that are normal on macOS
SUID_BASELINE: set[str] = {
    "/bin/ps",
    "/usr/bin/at",
    "/usr/bin/atq",
    "/usr/bin/atrm",
    "/usr/bin/batch",
    "/usr/bin/crontab",
    "/usr/bin/login",
    "/usr/bin/newgrp",
    "/usr/bin/passwd",
    "/usr/bin/rcp",
    "/usr/bin/rlogin",
    "/usr/bin/rsh",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/lib/pt_chown",
    "/usr/libexec/security_authtrampoline",
    "/usr/sbin/traceroute",
    "/usr/sbin/traceroute6",
    "/usr/sbin/postdrop",
    "/usr/sbin/postqueue",
    "/sbin/mount_nfs",
    "/sbin/ping",
    "/sbin/ping6",
    "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent",
}

# Known malicious/miner binary names
MINER_NAMES: set[str] = {
    "xmrig",
    "minergate",
    "cpuminer",
    "minerd",
    "cgminer",
    "bfgminer",
    "ethminer",
    "nheqminer",
    "ccminer",
    "sgminer",
    "multiminer",
    "nicehash",
    "claymore",
    "phoenixminer",
    "lolminer",
    "nbminer",
    "gminer",
    "teamredminer",
    "xmr-stak",
    "cryptonight",
}

KEYLOGGER_PATTERNS: list[str] = [
    "keylog",
    "keystroke",
    "keypress",
    "key_capture",
    "keycap",
    "klog",
    "type_capture",
    "screen_capture",
    "screengrab",
    "screenshot_tool",
]

# System binary directories to check for recent modifications
SYSTEM_BIN_DIRS: list[str] = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/libexec",
]

# Browser extension directories
HOME = os.path.expanduser("~")
BROWSER_EXT_DIRS: dict[str, str] = {
    "Chrome":   f"{HOME}/Library/Application Support/Google/Chrome/Default/Extensions",
    "Chromium": f"{HOME}/Library/Application Support/Chromium/Default/Extensions",
    "Brave":    f"{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
    "Edge":     f"{HOME}/Library/Application Support/Microsoft Edge/Default/Extensions",
    "Arc":      f"{HOME}/Library/Application Support/Arc/User Data/Default/Extensions",
    "Firefox":  f"{HOME}/Library/Application Support/Firefox/Profiles",
    "Safari":   f"{HOME}/Library/Safari/Extensions",
}

# Days threshold for "recently modified"
RECENT_DAYS = 7

# Max depth for os.walk in system dirs
MAX_SYSTEM_DEPTH = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 20) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
        "source": "mac.filesystem",
    }


def _walk_limited(root: str, max_depth: int):
    """os.walk with a max depth limit."""
    root = root.rstrip(os.sep)
    root_depth = root.count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames.clear()
        yield dirpath, dirnames, filenames


def _file_age_days(path: str) -> float:
    """Return file age in days based on mtime."""
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) / 86400
    except OSError:
        return float("inf")


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_suid_sgid(findings: list, counter: list) -> int:
    """Find SUID/SGID binaries not in the baseline."""
    stdout, stderr, rc = _run(
        ["find", "/usr", "/bin", "/sbin", "-perm", "+6000", "-type", "f"],
        timeout=30,
    )
    count = 0
    for path in stdout.splitlines():
        path = path.strip()
        if not path:
            continue
        count += 1
        if path in SUID_BASELINE:
            continue
        counter[0] += 1
        fid = f"fs_{counter[0]:03d}"
        try:
            stat = os.stat(path)
            mode = oct(stat.st_mode)
        except OSError:
            mode = "unknown"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="integrity",
            title=f"Non-baseline SUID/SGID binary: {path}",
            description=(
                f"Binary '{path}' has SUID or SGID bit set and is not in the "
                "known-good baseline. This can allow privilege escalation."
            ),
            evidence={"path": path, "mode": mode},
            remediation=(
                f"Investigate '{path}'. If not needed, remove the SUID bit: "
                f"`sudo chmod u-s '{path}'`. Remove the binary if malicious."
            ),
        ))
    return count


def _scan_world_writable_system(findings: list, counter: list) -> int:
    """Find world-writable files in system directories."""
    stdout, _, rc = _run(
        ["find", "/usr", "/bin", "/sbin", "/etc", "-perm", "-o+w", "-not", "-type", "l"],
        timeout=30,
    )
    count = 0
    for path in stdout.splitlines():
        path = path.strip()
        if not path:
            continue
        count += 1
        counter[0] += 1
        fid = f"fs_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="integrity",
            title=f"World-writable file in system directory: {path}",
            description=(
                f"'{path}' is world-writable and located in a system directory. "
                "This allows any user to modify critical system files."
            ),
            evidence={"path": path},
            remediation=(
                f"Fix permissions: `sudo chmod o-w '{path}'`. "
                "Investigate how permissions were changed."
            ),
        ))
    return count


def _scan_hidden_dotfiles(findings: list, counter: list) -> int:
    """Flag unusual hidden files in the home directory."""
    home = os.path.expanduser("~")
    known_dotfiles: set[str] = {
        ".zshrc", ".zprofile", ".zshenv", ".bash_profile", ".bashrc", ".profile",
        ".bash_history", ".zsh_history", ".ssh", ".gnupg", ".config",
        ".local", ".vim", ".vimrc", ".emacs", ".gitconfig", ".gitignore_global",
        ".npmrc", ".cargo", ".rustup", ".pyenv", ".rbenv", ".nvm",
        ".DS_Store", ".CFUserTextEncoding", ".Trash", ".lesshst",
        ".wget-hsts", ".docker", ".kube", ".aws", ".azure",
        ".Xauthority", ".ICEauthority",
    }

    count = 0
    try:
        entries = os.listdir(home)
    except PermissionError:
        return 0

    for entry in entries:
        if not entry.startswith("."):
            continue
        if entry in known_dotfiles:
            continue
        full_path = os.path.join(home, entry)
        count += 1
        # Flag executable hidden files specially
        is_executable = os.access(full_path, os.X_OK) and os.path.isfile(full_path)
        severity = "high" if is_executable else "low"
        counter[0] += 1
        fid = f"fs_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity=severity,
            category="malware",
            title=f"Unusual hidden file in home directory: {entry}",
            description=(
                f"Hidden file/directory '{full_path}' is not in the known dotfile baseline. "
                + ("It is executable, which is particularly suspicious." if is_executable else "")
            ),
            evidence={
                "path": full_path,
                "is_executable": is_executable,
                "is_directory": os.path.isdir(full_path),
            },
            remediation=(
                f"Investigate '{full_path}'. If unknown, remove it. "
                "Check if it was placed there by malware."
            ),
        ))
    return count


def _scan_recently_modified_system_bins(findings: list, counter: list) -> int:
    """Flag system binaries modified in the last RECENT_DAYS days."""
    count = 0
    cutoff = time.time() - (RECENT_DAYS * 86400)

    for d in SYSTEM_BIN_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    mtime = os.path.getmtime(fpath)
                except OSError:
                    continue
                if mtime > cutoff:
                    count += 1
                    import datetime
                    mtime_str = datetime.datetime.fromtimestamp(mtime).isoformat()
                    counter[0] += 1
                    fid = f"fs_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="medium",
                        category="integrity",
                        title=f"System binary recently modified: {fpath}",
                        description=(
                            f"'{fpath}' was modified {mtime_str}, within the last "
                            f"{RECENT_DAYS} days. Unexpected modifications to system "
                            "binaries may indicate compromise."
                        ),
                        evidence={"path": fpath, "mtime": mtime_str},
                        remediation=(
                            "Verify the binary with `codesign -v " + fpath + "`. "
                            "Compare against a known-good system or re-install macOS "
                            "if tampering is suspected."
                        ),
                    ))
        except PermissionError:
            continue
    return count


def _scan_tmp_directories(findings: list, counter: list) -> int:
    """Scan /tmp and /var/tmp for suspicious files."""
    tmp_dirs = ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"]
    count = 0
    for tmp_dir in tmp_dirs:
        if not os.path.isdir(tmp_dir):
            continue
        try:
            for fname in os.listdir(tmp_dir):
                fpath = os.path.join(tmp_dir, fname)
                count += 1
                if not os.path.isfile(fpath):
                    continue
                is_exec = os.access(fpath, os.X_OK)
                is_script = fname.endswith((".sh", ".py", ".rb", ".pl", ".php"))
                if is_exec or is_script:
                    counter[0] += 1
                    fid = f"fs_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="high",
                        category="malware",
                        title=f"Executable/script in temp directory: {fname}",
                        description=(
                            f"File '{fpath}' in a temporary directory is executable "
                            "or a script. Malware often stages payloads in /tmp."
                        ),
                        evidence={
                            "path": fpath,
                            "is_executable": is_exec,
                            "is_script": is_script,
                            "size_bytes": os.path.getsize(fpath),
                        },
                        remediation=(
                            f"Inspect '{fpath}' with `file '{fpath}'` and `strings '{fpath}'`. "
                            "Remove if malicious. Do NOT execute."
                        ),
                    ))
        except PermissionError:
            continue
    return count


def _scan_browser_extensions(findings: list, counter: list) -> int:
    """List browser extensions and flag by directory size/count."""
    total_ext = 0
    for browser, ext_dir in BROWSER_EXT_DIRS.items():
        if not os.path.isdir(ext_dir):
            continue
        try:
            if browser == "Firefox":
                # Firefox stores extensions in xpi files under profiles
                for profile in os.listdir(ext_dir):
                    profile_path = os.path.join(ext_dir, profile)
                    if not os.path.isdir(profile_path):
                        continue
                    extensions_dir = os.path.join(profile_path, "extensions")
                    if not os.path.isdir(extensions_dir):
                        continue
                    for ext in os.listdir(extensions_dir):
                        total_ext += 1
                        counter[0] += 1
                        fid = f"fs_{counter[0]:03d}"
                        findings.append(_make_finding(
                            fid=fid,
                            severity="info",
                            category="surveillance",
                            title=f"Firefox extension: {ext}",
                            description=(
                                f"Firefox extension '{ext}' found in profile '{profile}'. "
                                "Browser extensions can access browsing data and credentials."
                            ),
                            evidence={
                                "browser": browser,
                                "extension_id": ext,
                                "profile": profile,
                                "path": os.path.join(extensions_dir, ext),
                            },
                            remediation=(
                                "Review extensions at about:addons in Firefox. "
                                "Remove any you do not recognise."
                            ),
                        ))
            elif browser == "Safari":
                for ext in os.listdir(ext_dir):
                    if ext.endswith(".appex") or ext.endswith(".safariextz"):
                        total_ext += 1
                        counter[0] += 1
                        fid = f"fs_{counter[0]:03d}"
                        findings.append(_make_finding(
                            fid=fid,
                            severity="info",
                            category="surveillance",
                            title=f"Safari extension: {ext}",
                            description=(
                                f"Safari extension '{ext}' is installed. "
                                "Review if expected."
                            ),
                            evidence={
                                "browser": browser,
                                "extension": ext,
                                "path": os.path.join(ext_dir, ext),
                            },
                            remediation=(
                                "Review Safari extensions in Safari > Settings > Extensions."
                            ),
                        ))
            else:
                # Chromium-based: each subdirectory is an extension ID
                ext_ids = os.listdir(ext_dir)
                for ext_id in ext_ids:
                    ext_path = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue
                    total_ext += 1
                    # Try to read the extension manifest for name
                    ext_name = ext_id
                    versions = [v for v in os.listdir(ext_path) if os.path.isdir(os.path.join(ext_path, v))]
                    manifest_path = None
                    for v in versions:
                        mp = os.path.join(ext_path, v, "manifest.json")
                        if os.path.isfile(mp):
                            manifest_path = mp
                            break
                    permissions: list[str] = []
                    if manifest_path:
                        try:
                            import json
                            with open(manifest_path, "r", errors="replace") as mf:
                                manifest = json.load(mf)
                            ext_name = manifest.get("name", ext_id)
                            permissions = manifest.get("permissions", [])
                            host_perms = manifest.get("host_permissions", [])
                            permissions += host_perms
                        except Exception:
                            pass

                    # Flag dangerous permissions
                    dangerous_perms = [
                        p for p in permissions
                        if any(d in str(p) for d in [
                            "<all_urls>", "http://*/*", "https://*/*",
                            "tabs", "history", "cookies", "passwords",
                            "webRequest", "nativeMessaging", "debugger",
                            "proxy", "management", "downloads",
                        ])
                    ]

                    severity = "medium" if dangerous_perms else "info"
                    counter[0] += 1
                    fid = f"fs_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity=severity,
                        category="surveillance",
                        title=f"{browser} extension: {ext_name}",
                        description=(
                            f"{browser} extension '{ext_name}' (ID: {ext_id}) is installed."
                            + (f" Dangerous permissions: {dangerous_perms}" if dangerous_perms else "")
                        ),
                        evidence={
                            "browser": browser,
                            "extension_id": ext_id,
                            "extension_name": ext_name,
                            "path": ext_path,
                            "dangerous_permissions": dangerous_perms,
                            "all_permissions": permissions[:20],
                        },
                        remediation=(
                            f"Review {browser} extensions at chrome://extensions. "
                            "Remove extensions with excessive permissions if not needed."
                        ),
                    ))
        except PermissionError:
            continue
    return total_ext


def _scan_keylogger_indicators(findings: list, counter: list) -> int:
    """Search for files with keylogger-related names."""
    search_dirs = [
        os.path.expanduser("~"),
        "/Library",
        "/tmp",
        "/var/tmp",
        "/Applications",
    ]
    count = 0
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        try:
            for dirpath, dirnames, filenames in _walk_limited(search_dir, max_depth=4):
                # Skip system dirs
                dirnames[:] = [d for d in dirnames if not d.startswith(".") or dirpath == search_dir]
                for fname in filenames:
                    fname_lower = fname.lower()
                    for pattern in KEYLOGGER_PATTERNS:
                        if pattern in fname_lower:
                            fpath = os.path.join(dirpath, fname)
                            count += 1
                            counter[0] += 1
                            fid = f"fs_{counter[0]:03d}"
                            findings.append(_make_finding(
                                fid=fid,
                                severity="critical",
                                category="surveillance",
                                title=f"Potential keylogger file: {fname}",
                                description=(
                                    f"File '{fpath}' has a name suggesting keylogging "
                                    f"functionality (matched pattern: '{pattern}')."
                                ),
                                evidence={
                                    "path": fpath,
                                    "matched_pattern": pattern,
                                    "is_executable": os.access(fpath, os.X_OK),
                                },
                                remediation=(
                                    f"Investigate '{fpath}'. If malicious, remove it and "
                                    "check for LaunchAgent/Daemon persistence entries."
                                ),
                            ))
                            break  # one finding per file
        except PermissionError:
            continue
    return count


def _scan_crypto_miners(findings: list, counter: list) -> int:
    """Look for known cryptocurrency miner binaries."""
    search_dirs = [
        "/usr/local/bin",
        "/usr/bin",
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/bin"),
        "/tmp",
        "/var/tmp",
        "/Applications",
        os.path.expanduser("~/Library"),
    ]
    count = 0
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                if any(m in fname.lower() for m in MINER_NAMES):
                    fpath = os.path.join(d, fname)
                    count += 1
                    counter[0] += 1
                    fid = f"fs_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="critical",
                        category="malware",
                        title=f"Cryptocurrency miner binary found: {fname}",
                        description=(
                            f"File '{fpath}' matches the name of a known cryptocurrency "
                            "miner. This software hijacks CPU resources."
                        ),
                        evidence={
                            "path": fpath,
                            "filename": fname,
                            "is_executable": os.access(fpath, os.X_OK),
                        },
                        remediation=(
                            f"Remove the binary: `rm '{fpath}'`. Check for LaunchAgent "
                            "persistence. Review running processes for the miner."
                        ),
                    ))
        except PermissionError:
            continue
    return count


def _scan_dylib_injection(findings: list, counter: list) -> int:
    """Flag non-Apple .dylib files in ~/Library."""
    lib_dirs = [
        os.path.expanduser("~/Library"),
        "/Library",
    ]
    count = 0
    for lib_dir in lib_dirs:
        if not os.path.isdir(lib_dir):
            continue
        try:
            for dirpath, dirnames, filenames in _walk_limited(lib_dir, max_depth=3):
                for fname in filenames:
                    if not fname.endswith(".dylib"):
                        continue
                    fpath = os.path.join(dirpath, fname)
                    count += 1
                    # Check code signature
                    _, _, rc = _run(["codesign", "-v", fpath], timeout=6)
                    is_signed = (rc == 0)
                    out, err, _ = _run(["codesign", "-dv", fpath], timeout=6)
                    combined = (out + err).lower()
                    is_apple = "apple" in combined

                    if not is_apple:
                        counter[0] += 1
                        fid = f"fs_{counter[0]:03d}"
                        findings.append(_make_finding(
                            fid=fid,
                            severity="medium" if is_signed else "high",
                            category="malware",
                            title=f"Non-Apple dylib in Library: {fname}",
                            description=(
                                f"Dynamic library '{fpath}' is not Apple-signed. "
                                "Malicious dylibs can be injected into processes to steal "
                                "data or escalate privileges."
                            ),
                            evidence={
                                "path": fpath,
                                "is_signed": is_signed,
                                "is_apple_signed": is_apple,
                            },
                            remediation=(
                                f"Verify '{fpath}' belongs to a trusted application. "
                                "Use `otool -L <binary>` to find what loads it. "
                                "Remove if unknown."
                            ),
                        ))
        except PermissionError:
            continue
    return count


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan() -> dict:
    start = time.time()
    findings: list[dict] = []
    counter = [0]
    metadata: dict[str, Any] = {}

    try:
        suid_count = _scan_suid_sgid(findings, counter)
        metadata["suid_sgid_found"] = suid_count

        ww_count = _scan_world_writable_system(findings, counter)
        metadata["world_writable_found"] = ww_count

        dot_count = _scan_hidden_dotfiles(findings, counter)
        metadata["unusual_dotfiles_found"] = dot_count

        recent_count = _scan_recently_modified_system_bins(findings, counter)
        metadata["recently_modified_system_bins"] = recent_count

        tmp_count = _scan_tmp_directories(findings, counter)
        metadata["tmp_files_checked"] = tmp_count

        ext_count = _scan_browser_extensions(findings, counter)
        metadata["browser_extensions_found"] = ext_count

        kl_count = _scan_keylogger_indicators(findings, counter)
        metadata["keylogger_indicators_found"] = kl_count

        miner_count = _scan_crypto_miners(findings, counter)
        metadata["miner_binaries_found"] = miner_count

        dylib_count = _scan_dylib_injection(findings, counter)
        metadata["non_apple_dylibs_found"] = dylib_count

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.filesystem",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.filesystem",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.filesystem",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }


def _walk_limited(root: str, max_depth: int):
    """os.walk with a depth limit."""
    root = root.rstrip(os.sep)
    root_depth = root.count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames.clear()
        yield dirpath, dirnames, filenames
