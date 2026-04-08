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
from pathlib import Path
from typing import Any

from ..remediation import build_remediation


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
    # "keycap" removed — too broad, matches keyboard asset/doc filenames
    # "type_capture" removed — matches dev/media tooling artifacts
    # "screen_capture" removed — matches many legitimate tools; use "screenshot_tool" only
    "screengrab",
    "screenshot_tool",
]

# Apple system files whose names contain pattern substrings but are benign
KEYLOGGER_PATTERN_ALLOWLIST: frozenset[str] = frozenset({
    "feedbacklog",           # Apple Intelligence feedback DB
    "com.apple.feedbacklogd",
    "screenshotui",          # macOS Screenshot.app helper
    "com.apple.screencapture",
})

KNOWN_BENIGN_DOTFILE_PREFIXES: tuple[str, ...] = (
    ".git",
    ".vscode",
    ".idea",
    ".cache",
    ".gradle",
    ".m2",
    ".terraform",
    ".venv",
    ".virtualenv",
    ".ipynb",
    ".jupyter",
    ".conda",
    ".python",
    ".ansible",
    ".sdkman",
    ".swiftpm",
    ".codex",
    ".claude",
    ".oh-my-zsh",
    ".zcompdump",
    ".npm",
    ".yarn",
    ".pnpm",
)

SUSPICIOUS_DOTFILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"keylog|steal|rat|backdoor|launchagent|payload|implant", re.IGNORECASE),
    re.compile(r"^[.][A-Za-z0-9_-]{18,}$"),
)

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
            remediation=build_remediation(
                "A non-baseline SUID or SGID binary can let a normal user execute code with elevated privileges. That is a classic privilege-escalation foothold if the binary is malicious or misconfigured.",
                [
                    (
                        "Inspect the binary’s permissions, ownership, and signature.",
                        [
                            f"ls -l '{path}'",
                            f"codesign -dv --verbose=4 '{path}'",
                        ],
                    ),
                    (
                        "Remove the SUID and SGID bits if the binary does not need them.",
                        [
                            f"sudo chmod u-s '{path}'",
                            f"sudo chmod g-s '{path}'",
                        ],
                    ),
                    (
                        "If the file is malicious or orphaned, delete it after preserving any evidence you need.",
                        f"sudo rm -f '{path}'",
                    ),
                ],
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
            remediation=build_remediation(
                "World-writable files in system directories allow any local user or process to modify code or configuration that other users trust. That can lead directly to persistence or privilege escalation.",
                [
                    (
                        "Inspect the file metadata before changing it.",
                        f"ls -l '{path}'",
                    ),
                    (
                        "Remove world-write permission from the file.",
                        f"sudo chmod o-w '{path}'",
                    ),
                    (
                        "Verify the corrected permissions and trace package ownership if needed.",
                        [
                            f"ls -l '{path}'",
                            f"pkgutil --file-info '{path}'",
                        ],
                    ),
                ],
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
        if entry.startswith(KNOWN_BENIGN_DOTFILE_PREFIXES):
            continue
        full_path = os.path.join(home, entry)
        path_obj = Path(full_path)
        is_executable = os.access(full_path, os.X_OK) and os.path.isfile(full_path)
        is_symlink = path_obj.is_symlink()
        looks_suspicious = any(pattern.search(entry) for pattern in SUSPICIOUS_DOTFILE_PATTERNS)
        if not (is_executable or is_symlink or looks_suspicious):
            continue
        count += 1
        severity = "high" if is_executable else ("medium" if looks_suspicious else "low")
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
                "is_symlink": is_symlink,
                "matched_suspicious_pattern": looks_suspicious,
            },
            remediation=build_remediation(
                "Unexpected executable or suspicious hidden files in a home directory can be user-level persistence, droppers, or stolen-data staging artifacts. Hidden names are often used to avoid casual discovery.",
                [
                    (
                        "Inspect the hidden item without executing it.",
                        [
                            f"ls -la '{full_path}'",
                            f"file '{full_path}'",
                        ],
                    ),
                    (
                        "Search for references to the item in login, shell, or launchd persistence locations.",
                        f"grep -Rni '{entry}' ~/.zsh* ~/.bash* ~/.profile ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null",
                    ),
                    (
                        "Delete the item if it is not legitimate.",
                        f"rm -rf '{full_path}'",
                    ),
                ],
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
                        remediation=build_remediation(
                            "System binaries should not change unexpectedly. A recent modification can indicate a software update, but it can also mean local tampering with trusted executables.",
                            [
                                (
                                    "Inspect the binary metadata and signature.",
                                    [
                                        f"ls -lT '{fpath}'",
                                        f"codesign -v '{fpath}'",
                                    ],
                                ),
                                (
                                    "Check whether the file belongs to an Apple package and compare hashes if you have a known-good reference.",
                                    [
                                        f"pkgutil --file-info '{fpath}'",
                                        f"shasum -a 256 '{fpath}'",
                                    ],
                                ),
                                (
                                    "If tampering is suspected, replace the affected software via Software Update or a trusted reinstall path.",
                                    "sudo softwareupdate --install --all",
                                ),
                            ],
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
                        remediation=build_remediation(
                            "Executables and scripts in temporary directories are a common malware pattern because `/tmp` and related paths are easy to write to and are often ignored by users.",
                            [
                                (
                                    "Inspect the file without running it.",
                                    [
                                        f"file '{fpath}'",
                                        f"strings '{fpath}' | head -50",
                                    ],
                                ),
                                (
                                    "Check whether any running process is using the file.",
                                    f"lsof '{fpath}'",
                                ),
                                (
                                    "Delete the file if it is not legitimate.",
                                    f"rm -f '{fpath}'",
                                ),
                            ],
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
                            remediation=build_remediation(
                                "Browser extensions can read browsing data, inject content, and access credentials depending on granted permissions. Unknown extensions should always be reviewed.",
                                [
                                    (
                                        "List the Firefox extension on disk so you can match it in the browser UI.",
                                        f"ls -l '{os.path.join(extensions_dir, ext)}'",
                                    ),
                                    (
                                        "Inspect Firefox’s extension registry for the installed item.",
                                        f"find '{extensions_dir}' -maxdepth 1 -name '{ext}' -print",
                                    ),
                                    (
                                        "Remove the extension file if you confirm it is unwanted, then reopen Firefox and verify it is gone from about:addons.",
                                        f"rm -rf '{os.path.join(extensions_dir, ext)}'",
                                    ),
                                ],
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
                            remediation=build_remediation(
                                "Safari extensions can access web content and browser state. Any extension package you do not recognize should be matched back to an expected Safari add-on or removed.",
                                [
                                    (
                                        "Inspect the extension package on disk.",
                                        f"ls -l '{os.path.join(ext_dir, ext)}'",
                                    ),
                                    (
                                        "Open Safari and compare the package to what is enabled in Extensions settings.",
                                        "open -a Safari",
                                    ),
                                    (
                                        "Delete the package if you confirm it is not needed.",
                                        f"rm -rf '{os.path.join(ext_dir, ext)}'",
                                    ),
                                ],
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
                        remediation=build_remediation(
                            f"{browser} extensions with broad permissions can read page content, intercept requests, or access stored session data. That may be normal for password managers or blockers, but it should be intentional.",
                            [
                                (
                                    "Inspect the extension manifest and permission set on disk.",
                                    f"find '{ext_path}' -name manifest.json -maxdepth 2 -print -exec sed -n '1,200p' {{}} \\;",
                                ),
                                (
                                    f"Review the extension in {browser}’s extension manager and compare the ID.",
                                    "open 'chrome://extensions'",
                                ),
                                (
                                    "Remove the extension directory if you confirm it is unwanted.",
                                    f"rm -rf '{ext_path}'",
                                ),
                            ],
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
                    if fname_lower in KEYLOGGER_PATTERN_ALLOWLIST:
                        continue
                    for pattern in KEYLOGGER_PATTERNS:
                        if pattern in fname_lower:
                            fpath = os.path.join(dirpath, fname)
                            is_executable = os.access(fpath, os.X_OK)
                            severity = "critical" if is_executable else "high"
                            count += 1
                            counter[0] += 1
                            fid = f"fs_{counter[0]:03d}"
                            findings.append(_make_finding(
                                fid=fid,
                                severity=severity,
                                category="surveillance",
                                title=f"Potential keylogger file: {fname}",
                                description=(
                                    f"File '{fpath}' has a name suggesting keylogging "
                                    f"functionality (matched pattern: '{pattern}')."
                                ),
                                evidence={
                                    "path": fpath,
                                    "matched_pattern": pattern,
                                    "is_executable": is_executable,
                                },
                                remediation=build_remediation(
                                    "A filename associated with keylogging or covert capture deserves immediate review because surveillance tools often hide in plain sight under descriptive names.",
                                    [
                                        (
                                            "Inspect the file and confirm whether it is executable.",
                                            [
                                                f"ls -l '{fpath}'",
                                                f"file '{fpath}'",
                                            ],
                                        ),
                                        (
                                            "Search for persistence that launches the file.",
                                            f"grep -Rni '{fname}' ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons ~/.zsh* ~/.bash* ~/.profile 2>/dev/null",
                                        ),
                                        (
                                            "Delete the file if it is malicious.",
                                            f"rm -f '{fpath}'",
                                        ),
                                    ],
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
                        remediation=build_remediation(
                            "Cryptocurrency miners consume CPU or GPU resources for someone else’s benefit. If installed without consent, they indicate abuse of the system and may come with additional persistence or malware components.",
                            [
                                (
                                    "Inspect the suspected miner binary and look for running copies.",
                                    [
                                        f"ls -l '{fpath}'",
                                        f"ps aux | grep -i '{fname}'",
                                    ],
                                ),
                                (
                                    "Kill any running miner processes.",
                                    f"pkill -f '{fname}'",
                                ),
                                (
                                    "Delete the binary and then check launchd persistence for relaunch entries.",
                                    [
                                        f"rm -f '{fpath}'",
                                        "find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name '*.plist' -print 2>/dev/null",
                                    ],
                                ),
                            ],
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
                            remediation=build_remediation(
                                "Unexpected non-Apple dynamic libraries can be used for injection or runtime hooking. Even when they belong to legitimate software, you should confirm what loads them and whether they are expected.",
                                [
                                    (
                                        "Inspect the library metadata and code signature.",
                                        [
                                            f"ls -l '{fpath}'",
                                            f"codesign -dv --verbose=4 '{fpath}'",
                                        ],
                                    ),
                                    (
                                        "Search for executables or plists that reference the library.",
                                        [
                                            f"grep -Rni '{fname}' ~/Library /Library /Applications 2>/dev/null",
                                            f"otool -L '{fpath}'",
                                        ],
                                    ),
                                    (
                                        "Delete the library if it is untrusted and then re-check related processes or launch items.",
                                        f"rm -f '{fpath}'",
                                    ),
                                ],
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
