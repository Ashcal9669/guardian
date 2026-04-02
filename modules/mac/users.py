"""
macOS User Account Scanner
Scans local user accounts for security issues: UID-0 accounts, empty passwords,
sudo access, SSH keys, login history, remote access, and screen sharing.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import time
from typing import Any


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
        "source": "mac.users",
    }


def _load_plist(path: str) -> dict | None:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def _get_user_uid(username: str) -> int | None:
    stdout, _, rc = _run(["id", "-u", username], timeout=5)
    try:
        return int(stdout.strip())
    except ValueError:
        return None


def _get_user_home(username: str) -> str:
    stdout, _, _ = _run(
        ["dscl", ".", "-read", f"/Users/{username}", "NFSHomeDirectory"],
        timeout=5,
    )
    for line in stdout.splitlines():
        if "NFSHomeDirectory:" in line:
            return line.split(":", 1)[-1].strip()
    return f"/Users/{username}"


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_local_users(findings: list, counter: list) -> list[str]:
    """List all local user accounts using dscl."""
    stdout, _, rc = _run(["dscl", ".", "list", "/Users"], timeout=10)
    if rc != 0:
        return []

    users = []
    for line in stdout.splitlines():
        username = line.strip()
        if not username or username.startswith("_"):
            continue  # skip service accounts
        users.append(username)
    return users


def _scan_uid_zero_accounts(users: list[str], findings: list, counter: list):
    """Flag any account with UID 0 that isn't 'root'."""
    for user in users:
        uid = _get_user_uid(user)
        if uid == 0 and user != "root":
            counter[0] += 1
            fid = f"user_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="critical",
                category="persistence",
                title=f"Non-root account with UID 0: {user}",
                description=(
                    f"User account '{user}' has UID 0, giving it root-level privileges. "
                    "This is a common backdoor technique."
                ),
                evidence={"username": user, "uid": uid},
                remediation=(
                    f"Investigate account '{user}'. If not intentional, remove it: "
                    f"`sudo dscl . -delete /Users/{user}`. "
                    "Ensure no other accounts have UID 0."
                ),
            ))


def _scan_empty_passwords(users: list[str], findings: list, counter: list):
    """Check for accounts with empty or blank passwords via dscl."""
    for user in users:
        # Check if user has AuthenticationAuthority set to ;ShadowHash; (normal)
        # or ;DisabledUser; or empty
        stdout, _, rc = _run(
            ["dscl", ".", "-read", f"/Users/{user}", "AuthenticationAuthority"],
            timeout=5,
        )
        if rc != 0:
            continue
        auth_val = stdout.strip()
        # If AuthenticationAuthority is absent or contains no-password marker
        if ";nopassword;" in auth_val.lower() or "blank" in auth_val.lower():
            counter[0] += 1
            fid = f"user_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="critical",
                category="persistence",
                title=f"Account with no password: {user}",
                description=(
                    f"User account '{user}' appears to have no password set. "
                    "This allows login without credentials."
                ),
                evidence={"username": user, "auth_authority": auth_val[:200]},
                remediation=(
                    f"Set a password for '{user}': `sudo passwd {user}`. "
                    "Disable the account if not needed: "
                    f"`sudo dscl . -create /Users/{user} UserShell /usr/bin/false`."
                ),
            ))


def _scan_sudo_access(findings: list, counter: list):
    """Check /etc/sudoers and /etc/sudoers.d/ for non-standard sudo grants."""
    sudoers_files = ["/etc/sudoers"]
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for f in os.listdir(sudoers_d):
                sudoers_files.append(os.path.join(sudoers_d, f))
        except PermissionError:
            pass

    for fpath in sudoers_files:
        try:
            with open(fpath, "r", errors="replace") as f:
                content = f.read()
        except PermissionError:
            continue
        except FileNotFoundError:
            continue

        for lineno, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Flag NOPASSWD entries and ALL=(ALL) grants
            if "NOPASSWD" in stripped:
                counter[0] += 1
                fid = f"user_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="high",
                    category="persistence",
                    title=f"NOPASSWD sudo grant in {os.path.basename(fpath)}",
                    description=(
                        f"Line {lineno} of '{fpath}' grants passwordless sudo access: "
                        f"{stripped[:200]}"
                    ),
                    evidence={
                        "file": fpath,
                        "line_number": lineno,
                        "line": stripped[:300],
                    },
                    remediation=(
                        f"Review '{fpath}'. Remove NOPASSWD unless absolutely required. "
                        "Use `sudo visudo` to edit safely."
                    ),
                ))
            # Flag broad ALL grants to non-admin groups
            elif re.match(r'^\w+\s+ALL\s*=\s*\(ALL\)', stripped):
                counter[0] += 1
                fid = f"user_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="medium",
                    category="persistence",
                    title=f"Broad sudo grant in {os.path.basename(fpath)}",
                    description=(
                        f"Line {lineno} of '{fpath}' grants broad sudo access: "
                        f"{stripped[:200]}"
                    ),
                    evidence={
                        "file": fpath,
                        "line_number": lineno,
                        "line": stripped[:300],
                    },
                    remediation=(
                        "Review whether this sudo grant is intentional and necessary. "
                        "Restrict to specific commands if possible."
                    ),
                ))


def _scan_ssh_keys(users: list[str], findings: list, counter: list):
    """List SSH authorized_keys for all local users."""
    for user in users:
        home = _get_user_home(user)
        auth_keys = os.path.join(home, ".ssh", "authorized_keys")
        if not os.path.isfile(auth_keys):
            continue
        try:
            with open(auth_keys, "r", errors="replace") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except PermissionError:
            continue

        if not lines:
            continue

        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="persistence",
            title=f"SSH authorized_keys for user '{user}' ({len(lines)} key(s))",
            description=(
                f"User '{user}' has {len(lines)} SSH authorized key(s). "
                "These grant passwordless remote access to this account."
            ),
            evidence={
                "username": user,
                "path": auth_keys,
                "key_count": len(lines),
                "key_previews": [k[:80] for k in lines[:5]],
            },
            remediation=(
                f"Review '{auth_keys}'. Remove unknown keys. "
                "Disable SSH if not needed: `sudo systemsetup -setremotelogin off`."
            ),
        ))


def _scan_login_history(findings: list, counter: list):
    """Parse `last` output for unusual login patterns."""
    stdout, _, rc = _run(["last", "-100"], timeout=10)
    if rc != 0 or not stdout:
        return

    # Look for logins from unusual TTYs or at unusual hours
    # Also flag logins for root
    root_logins: list[str] = []
    unusual_source_logins: list[str] = []
    last_ips: set[str] = set()

    for line in stdout.splitlines():
        if not line.strip() or line.startswith("wtmp"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        user = parts[0]
        tty = parts[1] if len(parts) > 1 else ""
        source = parts[2] if len(parts) > 2 else ""

        if user == "root":
            root_logins.append(line.strip())

        # Flag logins from external IPs (not localhost or internal)
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', source):
            import ipaddress
            try:
                addr = ipaddress.ip_address(source)
                if not addr.is_private and not addr.is_loopback:
                    unusual_source_logins.append(line.strip())
                    last_ips.add(source)
            except ValueError:
                pass

    if root_logins:
        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="persistence",
            title=f"Root account login history detected ({len(root_logins)} entry/entries)",
            description=(
                f"The root account has been used to log in {len(root_logins)} time(s). "
                "Direct root logins bypass audit trails and are a security risk."
            ),
            evidence={"root_login_lines": root_logins[:10]},
            remediation=(
                "Disable root login: `sudo dsenableroot -d`. "
                "Use sudo for administrative tasks instead."
            ),
        ))

    if unusual_source_logins:
        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="network",
            title=f"Remote logins from external IPs detected ({len(last_ips)} unique IP(s))",
            description=(
                f"Login history shows {len(unusual_source_logins)} login(s) from external "
                f"IP addresses: {', '.join(list(last_ips)[:5])}."
            ),
            evidence={
                "login_lines": unusual_source_logins[:10],
                "source_ips": list(last_ips),
            },
            remediation=(
                "Verify these logins were authorised. If not, change all passwords, "
                "rotate SSH keys, and disable remote login if not needed."
            ),
        ))


def _scan_hidden_admin_accounts(users: list[str], findings: list, counter: list):
    """Check for hidden admin accounts (IsHidden flag or UID < 500 that aren't service accounts)."""
    for user in users:
        stdout, _, rc = _run(
            ["dscl", ".", "-read", f"/Users/{user}", "IsHidden"],
            timeout=5,
        )
        if rc == 0 and "1" in stdout:
            uid = _get_user_uid(user)
            # Hidden accounts with admin UIDs (≥ 500) are suspicious
            if uid and uid >= 500:
                counter[0] += 1
                fid = f"user_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="high",
                    category="persistence",
                    title=f"Hidden user account with normal UID: {user}",
                    description=(
                        f"User '{user}' (UID {uid}) has IsHidden=1 set, making it invisible "
                        "in the login screen. Hidden accounts are used by malware for "
                        "persistent backdoor access."
                    ),
                    evidence={"username": user, "uid": uid, "dscl_output": stdout.strip()},
                    remediation=(
                        f"Investigate account '{user}'. Remove if not intentional: "
                        f"`sudo dscl . -delete /Users/{user}`."
                    ),
                ))


def _scan_screen_sharing(findings: list, counter: list):
    """Check if Screen Sharing (VNC) is enabled."""
    ss_plist = "/Library/Preferences/com.apple.screensharing.plist"
    pdata = _load_plist(ss_plist)
    enabled = False
    if pdata:
        enabled = pdata.get("enabled", False) or pdata.get("ShadowHashData", False)
        # Another check: launchd service
    if not enabled:
        # Check via launchctl
        stdout, _, rc = _run(
            ["sudo", "-n", "launchctl", "list", "com.apple.screensharing"],
            timeout=8,
        )
        if rc == 0 and stdout.strip():
            enabled = True

    if enabled:
        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="surveillance",
            title="Screen Sharing (VNC) is enabled",
            description=(
                "Screen Sharing is enabled, allowing remote visual access to this Mac's desktop. "
                "If not intentionally configured, this is a significant surveillance risk."
            ),
            evidence={"plist": ss_plist, "enabled": enabled},
            remediation=(
                "Disable Screen Sharing in System Settings > General > Sharing > Screen Sharing. "
                "Or: `sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist`."
            ),
        ))


def _scan_remote_management(findings: list, counter: list):
    """Check if Apple Remote Desktop (ARD) is enabled."""
    stdout, _, rc = _run(
        ["sudo", "-n", "launchctl", "list", "com.apple.RemoteDesktop.agent"],
        timeout=8,
    )
    if rc == 0 and stdout.strip():
        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="surveillance",
            title="Apple Remote Desktop (ARD) management agent is active",
            description=(
                "The Apple Remote Desktop agent is running. ARD allows full remote control "
                "and management of this Mac. Verify this is intentional."
            ),
            evidence={"launchctl_output": stdout.strip()},
            remediation=(
                "Disable ARD in System Settings > General > Sharing > Remote Management. "
                "Or: `sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/"
                "Contents/Resources/kickstart -deactivate -stop`."
            ),
        ))


def _scan_remote_login_status(findings: list, counter: list):
    """Check if SSH Remote Login is enabled."""
    stdout, stderr, rc = _run(["systemsetup", "-getremotelogin"], timeout=10)
    output = (stdout + stderr).strip()
    if "on" in output.lower():
        counter[0] += 1
        fid = f"user_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="network",
            title="SSH Remote Login is enabled",
            description=(
                "SSH remote login (sshd) is enabled on this Mac. "
                "If not intentionally configured, this increases the attack surface."
            ),
            evidence={"systemsetup_output": output},
            remediation=(
                "Disable if not needed: `sudo systemsetup -setremotelogin off`. "
                "If SSH must remain enabled, restrict in /etc/ssh/sshd_config: "
                "AllowUsers, PasswordAuthentication no, etc."
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
        users = _scan_local_users(findings, counter)
        metadata["local_users_found"] = len(users)
        metadata["local_users"] = users[:20]

        _scan_uid_zero_accounts(users, findings, counter)
        _scan_empty_passwords(users, findings, counter)
        _scan_sudo_access(findings, counter)
        _scan_ssh_keys(users, findings, counter)
        _scan_login_history(findings, counter)
        _scan_hidden_admin_accounts(users, findings, counter)
        _scan_screen_sharing(findings, counter)
        _scan_remote_management(findings, counter)
        _scan_remote_login_status(findings, counter)

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.users",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.users",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.users",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
