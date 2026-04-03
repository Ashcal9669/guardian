"""
macOS Persistence Scanner
Checks all common persistence mechanisms: LaunchAgents, LaunchDaemons,
Login Items, crontabs, shell startup files, SSH keys, kernel extensions,
login hooks, startup items, and dock items.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from ..remediation import build_remediation


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LAUNCHAGENT_DIRS: list[str] = [
    os.path.expanduser("~/Library/LaunchAgents"),
    "/Library/LaunchAgents",
    "/System/Library/LaunchAgents",
]

LAUNCHDAEMON_DIRS: list[str] = [
    "/Library/LaunchDaemons",
    "/System/Library/LaunchDaemons",
]

SHELL_STARTUP_FILES: list[str] = [
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.zprofile"),
    os.path.expanduser("~/.zshenv"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.bash_login"),
    os.path.expanduser("~/.config/fish/config.fish"),
]

KEXT_DIRS: list[str] = [
    "/Library/Extensions",
    "/System/Library/Extensions",
]

PERIODIC_DIRS: list[str] = [
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
]

# Suspicious executable path indicators
SUSPICIOUS_PATH_FRAGMENTS: list[str] = [
    "/tmp/",
    "/var/tmp/",
    "/var/folders/",
    "/private/tmp/",
    "/private/var/tmp/",
    os.path.expanduser("~/Downloads/"),
    os.path.expanduser("~/.Trash/"),
    "/Library/Caches/",
    os.path.expanduser("~/Library/Caches/"),
]

# Apple bundle ID prefixes — used to skip known-Apple plists
APPLE_BUNDLE_PREFIXES: tuple[str, ...] = (
    "com.apple.",
    "com.Apple.",
)

SUSPICIOUS_LABEL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"update|helper|agent|daemon|installer|login|launch", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9._-]{18,}$"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
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
        "source": "mac.persistence",
    }


def _load_plist(path: str) -> dict | None:
    """Try to load a plist file, return None on failure."""
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        pass
    # Try XML fallback
    try:
        with open(path, "rb") as f:
            return plistlib.load(f, fmt=plistlib.FMT_XML)
    except Exception:
        return None


def _codesign_valid(path: str) -> bool:
    if not path or not os.path.exists(path):
        return False
    _, _, rc = _run(["codesign", "-v", "--deep", path], timeout=8)
    return rc == 0


def _is_suspicious_path(path: str) -> bool:
    for frag in SUSPICIOUS_PATH_FRAGMENTS:
        if path.startswith(frag):
            return True
    return False


def _extract_executables_from_plist(pdata: dict) -> list[str]:
    """Extract all executable paths referenced in a LaunchAgent/Daemon plist."""
    exes: list[str] = []
    # ProgramArguments: list of strings, first is executable
    prog_args = pdata.get("ProgramArguments", [])
    if isinstance(prog_args, list) and prog_args:
        exes.append(str(prog_args[0]))
    # Program: direct path
    prog = pdata.get("Program", "")
    if prog:
        exes.append(str(prog))
    return [e for e in exes if e]


def _is_apple_plist(plist_path: str, pdata: dict) -> bool:
    label = pdata.get("Label", "")
    if isinstance(label, str) and label.startswith(APPLE_BUNDLE_PREFIXES):
        return True
    # Also check if file lives in /System/Library
    if plist_path.startswith("/System/Library"):
        return True
    return False


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_launch_items(dirs: list[str], item_type: str, findings: list, counter: list) -> int:
    """Scan LaunchAgent or LaunchDaemon directories."""
    total = 0
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except PermissionError:
            continue
        for fname in entries:
            if not fname.endswith(".plist"):
                continue
            full_path = os.path.join(d, fname)
            total += 1
            pdata = _load_plist(full_path)
            if pdata is None:
                continue
            if _is_apple_plist(full_path, pdata):
                continue  # skip known Apple items

            exes = _extract_executables_from_plist(pdata)
            if not exes:
                exes = [""]
            for exe in exes:
                severity = "medium"
                reasons = []
                label = str(pdata.get("Label", fname))

                # Check for suspicious paths
                if _is_suspicious_path(exe):
                    severity = "critical"
                    reasons.append(f"executable in suspicious directory: {exe}")

                if not exe or not os.path.isabs(exe):
                    reasons.append("missing or non-absolute executable path in plist")

                # Check code signature
                if os.path.exists(exe) and not _codesign_valid(exe):
                    if severity not in ("critical",):
                        severity = "high"
                    reasons.append(f"invalid/missing code signature on: {exe}")

                if any(pattern.search(label) for pattern in SUSPICIOUS_LABEL_PATTERNS):
                    reasons.append(f"suspicious label: {label}")

                if pdata.get("RunAtLoad") and pdata.get("KeepAlive"):
                    reasons.append("launches at load and requests keepalive")

                if not reasons:
                    continue

                counter[0] += 1
                fid = f"persist_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity=severity,
                    category="persistence",
                    title=f"{item_type} entry: {label}",
                    description=(
                        f"A {item_type} plist '{full_path}' references '{exe}'. "
                        + " ".join(reasons)
                    ),
                    evidence={
                        "plist_path": full_path,
                        "label": str(label),
                        "executables": exes,
                        "reasons": reasons,
                        "run_at_load": pdata.get("RunAtLoad", False),
                        "keep_alive": pdata.get("KeepAlive", False),
                    },
                    remediation=build_remediation(
                        f"This {item_type} runs automatically through launchd and was flagged because its label, executable path, signature state, or keepalive behavior looks unusual. Persistence items in user-writable paths are a common malware foothold.",
                        [
                            (
                                "Inspect the plist contents to see what it launches.",
                                f"plutil -p '{full_path}'",
                            ),
                            (
                                "Review the referenced executable and verify its signature and path.",
                                [
                                    f"ls -l '{exe}'" if exe else f"ls -l '{full_path}'",
                                    f"codesign -dv --verbose=4 '{exe}'" if exe else f"plutil -p '{full_path}'",
                                ],
                            ),
                            (
                                "Unload the item if you determine it is not legitimate.",
                                f"launchctl unload '{full_path}'",
                            ),
                            (
                                "Remove the plist and then inspect nearby staging locations for related files.",
                                [
                                    f"rm '{full_path}'",
                                    "find /tmp /private/tmp ~/Library ~/Library/LaunchAgents /Library/LaunchDaemons -maxdepth 3 -type f | head -200",
                                ],
                            ),
                        ],
                    ),
                ))
    return total


def _scan_crontabs(findings: list, counter: list):
    """Scan crontabs for the current user and root."""
    users_to_check = ["root"]
    # Add current user
    import getpass
    try:
        users_to_check.append(getpass.getuser())
    except Exception:
        pass

    for user in set(users_to_check):
        if user == "root":
            stdout, _, rc = _run(["sudo", "-n", "crontab", "-u", "root", "-l"], timeout=10)
        else:
            stdout, _, rc = _run(["crontab", "-l"], timeout=10)

        if rc != 0 or not stdout.strip():
            continue

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Parse cron line: min hr dom mon dow command
            parts = stripped.split(None, 5)
            if len(parts) < 6:
                continue
            cmd = parts[5]
            counter[0] += 1
            fid = f"persist_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="persistence",
                title=f"Crontab entry for user '{user}'",
                description=(
                    f"Crontab entry found for user '{user}': {stripped[:200]}"
                ),
                evidence={
                    "user": user,
                    "cron_entry": stripped,
                    "command": cmd,
                },
                remediation=build_remediation(
                    "Cron jobs execute on a schedule without user interaction. Unexpected cron entries are a classic persistence mechanism because they quietly re-run code at fixed intervals.",
                    [
                        (
                            f"List the current cron table for '{user}' and confirm the suspicious command.",
                            f"sudo crontab -u {user} -l" if user == "root" else "crontab -l",
                        ),
                        (
                            "Inspect the referenced command or script before removing it.",
                            f"printf '%s\n' \"{cmd}\"",
                        ),
                        (
                            "Edit the crontab and delete the malicious or unwanted entry.",
                            f"sudo crontab -u {user} -e" if user == "root" else "crontab -e",
                        ),
                    ],
                ),
            ))


def _scan_periodic_scripts(findings: list, counter: list):
    """Scan /etc/periodic/ directories for unexpected scripts."""
    for d in PERIODIC_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            scripts = os.listdir(d)
        except PermissionError:
            continue
        for script in scripts:
            full = os.path.join(d, script)
            # Flag scripts not owned by root or with unexpected content
            try:
                stat = os.stat(full)
                owner_uid = stat.st_uid
            except OSError:
                continue
            if owner_uid != 0:
                counter[0] += 1
                fid = f"persist_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="high",
                    category="persistence",
                    title=f"Periodic script not owned by root: {script}",
                    description=(
                        f"Script '{full}' is in a periodic execution directory but "
                        f"is owned by UID {owner_uid} instead of root."
                    ),
                    evidence={"path": full, "owner_uid": owner_uid},
                    remediation=build_remediation(
                        "Scripts inside `/etc/periodic` run automatically as part of the system’s scheduled maintenance. Anything there that is not owned by root can be abused to execute code with elevated trust.",
                        [
                            (
                                "Inspect the directory and confirm the file ownership.",
                                f"ls -la '{d}'",
                            ),
                            (
                                "Review the script contents to decide whether it belongs there.",
                                f"sed -n '1,160p' '{full}'",
                            ),
                            (
                                "If the script is legitimate, restore root ownership; otherwise remove it.",
                                [
                                    f"sudo chown root:wheel '{full}'",
                                    f"sudo rm -f '{full}'",
                                ],
                            ),
                        ],
                    ),
                ))


def _scan_shell_startup_files(findings: list, counter: list):
    """Scan shell startup files for suspicious commands."""
    suspicious_patterns = [
        re.compile(r'curl\s+.*(sh|bash|zsh|python)\b', re.IGNORECASE),
        re.compile(r'wget\s+.*(sh|bash|zsh|python)\b', re.IGNORECASE),
        re.compile(r'eval\s*\(.*base64', re.IGNORECASE),
        re.compile(r'python.*-c.*exec', re.IGNORECASE),
        re.compile(r'/tmp/\S+\.sh', re.IGNORECASE),
        re.compile(r'DYLD_INSERT_LIBRARIES', re.IGNORECASE),
        re.compile(r'nc\s+-[a-z]*e\s', re.IGNORECASE),   # netcat reverse shell
        re.compile(r'bash\s+-i\s+>&\s*/dev/tcp', re.IGNORECASE),
    ]

    for fpath in SHELL_STARTUP_FILES:
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="replace") as f:
                lines = f.readlines()
        except PermissionError:
            continue

        for lineno, line in enumerate(lines, 1):
            for pattern in suspicious_patterns:
                if pattern.search(line):
                    counter[0] += 1
                    fid = f"persist_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="high",
                        category="persistence",
                        title=f"Suspicious command in shell startup: {os.path.basename(fpath)}",
                        description=(
                            f"Suspicious pattern found on line {lineno} of '{fpath}': "
                            f"{line.strip()[:200]}"
                        ),
                        evidence={
                            "file": fpath,
                            "line_number": lineno,
                            "line": line.strip()[:300],
                            "pattern": pattern.pattern,
                        },
                        remediation=build_remediation(
                            "Shell startup files run whenever a shell session starts. Attackers often place one-line downloaders, reverse shells, or environment-variable injections here to relaunch malware on login or terminal open.",
                            [
                                (
                                    "Inspect the suspicious line in context before editing.",
                                    f"nl -ba '{fpath}' | sed -n '{max(1, lineno - 3)},{lineno + 3}p'",
                                ),
                                (
                                    "Edit the startup file and remove the malicious command.",
                                    f"${{EDITOR:-vi}} '{fpath}'",
                                ),
                                (
                                    "Search the rest of your shell startup files for similar persistence commands.",
                                    "grep -RniE 'curl .*sh|wget .*sh|DYLD_INSERT_LIBRARIES|base64|/tmp/.*\\.sh|bash -i >& /dev/tcp' ~/.zsh* ~/.bash* ~/.profile ~/.config/fish/config.fish 2>/dev/null",
                                ),
                            ],
                        ),
                    ))
                    break  # one finding per line


def _scan_ssh_authorized_keys(findings: list, counter: list):
    """Scan SSH authorized_keys files for all users."""
    users_dir = "/Users"
    try:
        users = os.listdir(users_dir)
    except PermissionError:
        return

    for user in users:
        if user.startswith("."):
            continue
        auth_keys_path = os.path.join(users_dir, user, ".ssh", "authorized_keys")
        if not os.path.isfile(auth_keys_path):
            continue
        try:
            with open(auth_keys_path, "r", errors="replace") as f:
                content = f.read()
        except PermissionError:
            continue

        keys = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        if keys:
            counter[0] += 1
            fid = f"persist_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="persistence",
                title=f"SSH authorized_keys present for user '{user}'",
                description=(
                    f"User '{user}' has {len(keys)} SSH authorized key(s). "
                    "These allow passwordless remote access and should be reviewed."
                ),
                evidence={
                    "user": user,
                    "path": auth_keys_path,
                    "key_count": len(keys),
                    "keys_preview": [k[:80] for k in keys[:5]],
                },
                remediation=build_remediation(
                    "Any key in `authorized_keys` grants passwordless SSH access to that account. Unknown keys can provide silent backdoor access even after the user changes their password.",
                    [
                        (
                            "Inspect the current keys and identify any unknown entries.",
                            f"nl -ba '{auth_keys_path}'",
                        ),
                        (
                            "Edit the file and delete keys you do not trust.",
                            f"${{EDITOR:-vi}} '{auth_keys_path}'",
                        ),
                        (
                            "If remote access is not needed at all, disable SSH on the Mac.",
                            "sudo systemsetup -setremotelogin off",
                        ),
                    ],
                ),
            ))


def _scan_kexts(findings: list, counter: list):
    """Scan kernel extensions for non-Apple entries."""
    for d in KEXT_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except PermissionError:
            continue
        for entry in entries:
            if not entry.endswith(".kext"):
                continue
            full = os.path.join(d, entry)
            # Check code signature
            is_valid, detail = (False, "")
            _, _, rc = _run(["codesign", "-v", full], timeout=8)
            is_valid = (rc == 0)
            # Check if Apple-signed
            out, err, _ = _run(["codesign", "-dv", full], timeout=8)
            combined = (out + err).lower()
            is_apple = "apple" in combined or "com.apple" in combined

            if not is_apple:
                counter[0] += 1
                fid = f"persist_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="high" if not is_valid else "medium",
                    category="persistence",
                    title=f"Non-Apple kernel extension: {entry}",
                    description=(
                        f"Kernel extension '{full}' is not Apple-signed. "
                        "Third-party kexts run at kernel level and represent a significant "
                        "security risk if malicious."
                    ),
                    evidence={
                        "path": full,
                        "codesign_valid": is_valid,
                        "is_apple_signed": is_apple,
                        "codesign_detail": combined[:500],
                    },
                    remediation=build_remediation(
                        "Kernel extensions run with very high privilege. A non-Apple kext may be expected for legacy hardware or security software, but an unknown one can directly affect kernel behavior and persistence.",
                        [
                            (
                                "List the loaded third-party kernel extensions.",
                                "kmutil showloaded --list-only" if os.uname().machine == "arm64" else "kextstat | grep -v com.apple",
                            ),
                            (
                                "Inspect the extension bundle and its signature details.",
                                [
                                    f"ls -l '{full}'",
                                    f"codesign -dv --verbose=4 '{full}'",
                                ],
                            ),
                            (
                                "If the kext is not legitimate, unload and remove the owning software package.",
                                f"sudo kmutil unload -p '{full}'" if os.uname().machine == "arm64" else f"sudo kextunload '{full}'",
                            ),
                        ],
                    ),
                ))


def _scan_login_hooks(findings: list, counter: list):
    """Check com.apple.loginwindow for login/logout hooks."""
    plist_path = "/Library/Preferences/com.apple.loginwindow.plist"
    pdata = _load_plist(plist_path)
    if not pdata:
        return

    for hook_key in ["LoginHook", "LogoutHook"]:
        hook_val = pdata.get(hook_key, "")
        if hook_val:
            counter[0] += 1
            fid = f"persist_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="high",
                category="persistence",
                title=f"Login hook configured: {hook_key}",
                description=(
                    f"A {hook_key} is configured at '{hook_val}'. Login hooks run as root "
                    "on every login and are a common malware persistence mechanism."
                ),
                evidence={
                    "hook_type": hook_key,
                    "hook_path": hook_val,
                    "plist": plist_path,
                },
                remediation=build_remediation(
                    "Login and logout hooks execute scripts as part of the loginwindow flow. They are deprecated, uncommon on normal Macs, and frequently abused for persistence because they run automatically.",
                    [
                        (
                            "Inspect the configured hook and review the referenced script.",
                            [
                                f"defaults read /Library/Preferences/com.apple.loginwindow {hook_key}",
                                f"ls -l '{hook_val}'",
                            ],
                        ),
                        (
                            "Remove the hook from the loginwindow preferences.",
                            f"sudo defaults delete /Library/Preferences/com.apple.loginwindow {hook_key}",
                        ),
                        (
                            "If the script is malicious, delete it after preserving any evidence you need.",
                            f"sudo rm -f '{hook_val}'",
                        ),
                    ],
                ),
            ))


def _scan_startup_items(findings: list, counter: list):
    """Check /Library/StartupItems (legacy but still used by malware)."""
    startup_dir = "/Library/StartupItems"
    if not os.path.isdir(startup_dir):
        return
    try:
        items = os.listdir(startup_dir)
    except PermissionError:
        return

    for item in items:
        full = os.path.join(startup_dir, item)
        counter[0] += 1
        fid = f"persist_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="persistence",
            title=f"Legacy StartupItem found: {item}",
            description=(
                f"A legacy startup item exists at '{full}'. These are deprecated but still "
                "executed and are commonly used by malware for persistence."
            ),
            evidence={"path": full},
            remediation=build_remediation(
                "Legacy StartupItems are deprecated but still get attention because malware can abuse them for persistence on older or modified systems. A StartupItem should almost always be reviewed closely.",
                [
                    (
                        "Inspect the StartupItem contents and any scripts it runs.",
                        [
                            f"find '{full}' -maxdepth 2 -print",
                            f"sed -n '1,160p' '{full}'/* 2>/dev/null",
                        ],
                    ),
                    (
                        "If the item is not legitimate, remove it.",
                        f"sudo rm -rf '{full}'",
                    ),
                    (
                        "Search for related launchd persistence after cleanup.",
                        "find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name '*.plist' -print 2>/dev/null",
                    ),
                ],
            ),
        ))


def _scan_login_items(findings: list, counter: list):
    """List Login Items via osascript."""
    script = (
        'tell application "System Events" to get the name of every login item'
    )
    cmd = ["osascript", "-e", script]
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        uid_out, _, uid_rc = _run(["id", "-u", sudo_user], timeout=5)
        if uid_rc == 0 and uid_out.strip().isdigit():
            cmd = ["launchctl", "asuser", uid_out.strip(), "osascript", "-e", script]

    stdout, stderr, rc = _run(cmd, timeout=15)
    if rc != 0 or not stdout.strip():
        return

    items = [i.strip() for i in stdout.strip().split(",") if i.strip()]
    for item in items:
        counter[0] += 1
        fid = f"persist_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="info",
            category="persistence",
            title=f"Login Item: {item}",
            description=(
                f"'{item}' is configured as a Login Item and will launch at user login. "
                "Review to ensure it is expected."
            ),
            evidence={"item_name": item},
            remediation=build_remediation(
                "Login Items start automatically when the user signs in. Many are benign, but anything unexpected should be traced back to the installed application because it provides persistent execution at login.",
                [
                    (
                        "List the current login items again so you can compare before and after cleanup.",
                        "osascript -e 'tell application \"System Events\" to get the name of every login item'",
                    ),
                    (
                        f"Remove the unexpected login item named '{item}'.",
                        f"osascript -e 'tell application \"System Events\" to delete login item \"{item}\"'",
                    ),
                    (
                        "Re-list login items to confirm it is gone.",
                        "osascript -e 'tell application \"System Events\" to get the name of every login item'",
                    ),
                ],
            ),
        ))


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan() -> dict:
    start = time.time()
    findings: list[dict] = []
    counter = [0]
    metadata: dict[str, Any] = {}

    try:
        # LaunchAgents
        la_count = _scan_launch_items(LAUNCHAGENT_DIRS, "LaunchAgent", findings, counter)
        metadata["launch_agents_scanned"] = la_count

        # LaunchDaemons
        ld_count = _scan_launch_items(LAUNCHDAEMON_DIRS, "LaunchDaemon", findings, counter)
        metadata["launch_daemons_scanned"] = ld_count

        # Login Items
        _scan_login_items(findings, counter)

        # Crontabs
        _scan_crontabs(findings, counter)

        # Periodic scripts
        _scan_periodic_scripts(findings, counter)

        # Shell startup files
        _scan_shell_startup_files(findings, counter)

        # SSH authorized_keys
        _scan_ssh_authorized_keys(findings, counter)

        # Login hooks
        _scan_login_hooks(findings, counter)

        # Startup items (legacy)
        _scan_startup_items(findings, counter)

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.persistence",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.persistence",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.persistence",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
