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

from ..remediation import build_remediation


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
                remediation=build_remediation(
                    "Any non-root account with UID 0 has full root privilege. Attackers create hidden UID-0 users as durable backdoors because they blend in with standard account mechanisms while retaining unrestricted access.",
                    [
                        (
                            f"Inspect the account record and confirm it really has UID 0.",
                            [
                                f"id {user}",
                                f"dscl . -read /Users/{user}",
                            ],
                        ),
                        (
                            "If the account is not intentional, delete it.",
                            f"sudo dscl . -delete /Users/{user}",
                        ),
                        (
                            "Verify that only the true root account still has UID 0.",
                            "dscl . -list /Users UniqueID | awk '$2 == 0 {print}'",
                        ),
                    ],
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
                remediation=build_remediation(
                    "An account without a password can permit trivial local or remote access depending on other services and policies. That should be corrected immediately unless the account is intentionally disabled.",
                    [
                        (
                            "Inspect the account’s authentication settings.",
                            f"dscl . -read /Users/{user} AuthenticationAuthority",
                        ),
                        (
                            "Set a password if the account should remain active.",
                            f"sudo passwd {user}",
                        ),
                        (
                            "If the account is not needed, disable interactive shell access.",
                            f"sudo dscl . -create /Users/{user} UserShell /usr/bin/false",
                        ),
                    ],
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
                    remediation=build_remediation(
                        "A `NOPASSWD` sudo rule allows privileged commands without interactive approval. That is convenient for automation, but it also removes a safety barrier that would normally slow down misuse.",
                        [
                            (
                                "Inspect the matching sudoers line in context.",
                                f"nl -ba '{fpath}' | sed -n '{max(1, lineno - 3)},{lineno + 3}p'",
                            ),
                            (
                                "Edit the file safely with `visudo` and remove or narrow the rule.",
                                f"sudo visudo -f '{fpath}'",
                            ),
                            (
                                "Validate the sudoers syntax after the change.",
                                f"sudo visudo -c -f '{fpath}'",
                            ),
                        ],
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
                    remediation=build_remediation(
                        "Broad sudo grants can give a regular user nearly unrestricted privilege escalation. Even when intentional, they should be reviewed to ensure the scope is still justified.",
                        [
                            (
                                "Inspect the sudoers rule in context.",
                                f"nl -ba '{fpath}' | sed -n '{max(1, lineno - 3)},{lineno + 3}p'",
                            ),
                            (
                                "Edit the file safely and restrict the grant to specific commands or groups if possible.",
                                f"sudo visudo -f '{fpath}'",
                            ),
                            (
                                "Validate the sudoers file after editing.",
                                f"sudo visudo -c -f '{fpath}'",
                            ),
                        ],
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
            remediation=build_remediation(
                "Entries in `authorized_keys` grant passwordless SSH access to the account. Unknown keys are a common persistence method because they survive password changes.",
                [
                    (
                        "Inspect the current authorized keys.",
                        f"nl -ba '{auth_keys}'",
                    ),
                    (
                        "Edit the file and remove any key you do not trust.",
                        f"sudo ${EDITOR:-vi} '{auth_keys}'",
                    ),
                    (
                        "Disable SSH entirely if remote access is not required.",
                        "sudo systemsetup -setremotelogin off",
                    ),
                ],
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
            remediation=build_remediation(
                "Direct root logins reduce accountability and create a very high-value remote target. On a managed Mac, you normally want administrators to use `sudo` from named user accounts instead.",
                [
                    (
                        "Confirm whether the root account is enabled.",
                        "dsenableroot -q",
                    ),
                    (
                        "Disable direct root logins if they are not explicitly required.",
                        "sudo dsenableroot -d",
                    ),
                    (
                        "Re-check recent login history after cleanup.",
                        "last -20",
                    ),
                ],
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
            remediation=build_remediation(
                "External login sources show that someone reached the Mac from outside the local network. If those sessions were not authorized, credentials and SSH trust material may already be compromised.",
                [
                    (
                        "Review the suspicious login history entries and source IPs.",
                        "last -100",
                    ),
                    (
                        "Rotate passwords and remove or replace SSH authorized keys for affected accounts.",
                        "find /Users -path '*/.ssh/authorized_keys' -print -exec nl -ba {} \\;",
                    ),
                    (
                        "Disable SSH if it should not remain exposed.",
                        "sudo systemsetup -setremotelogin off",
                    ),
                ],
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
                    remediation=build_remediation(
                        "A hidden account with a normal user UID can provide stealthy local persistence because it is absent from the login UI but still functions as a regular account behind the scenes.",
                        [
                            (
                                "Inspect the account attributes and confirm it is hidden.",
                                [
                                    f"dscl . -read /Users/{user}",
                                    f"id {user}",
                                ],
                            ),
                            (
                                "Delete the account if it is not intentional.",
                                f"sudo dscl . -delete /Users/{user}",
                            ),
                            (
                                "Verify there are no remaining hidden regular-user accounts.",
                                "for u in $(dscl . list /Users); do dscl . -read /Users/$u IsHidden 2>/dev/null; done",
                            ),
                        ],
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
            remediation=build_remediation(
                "Screen Sharing exposes a remote desktop service. If it was enabled without the owner’s intent, it can provide full visual and interactive access to the Mac.",
                [
                    (
                        "Check whether the Screen Sharing launchd service is active.",
                        "sudo launchctl list | grep screensharing",
                    ),
                    (
                        "Disable the service if remote desktop access is not required.",
                        "sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist",
                    ),
                    (
                        "Verify that the service is no longer loaded.",
                        "sudo launchctl list | grep screensharing",
                    ),
                ],
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
            remediation=build_remediation(
                "Apple Remote Desktop provides stronger remote control and management than simple SSH. If it is active unexpectedly, someone may have the ability to observe or control the Mac remotely.",
                [
                    (
                        "Confirm that the ARD agent is loaded.",
                        "sudo launchctl list | grep RemoteDesktop",
                    ),
                    (
                        "Deactivate and stop Apple Remote Desktop if it is not needed.",
                        "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
                    ),
                    (
                        "Verify that the ARD agent is no longer active.",
                        "sudo launchctl list | grep RemoteDesktop",
                    ),
                ],
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
            remediation=build_remediation(
                "SSH Remote Login opens a network administration path into the Mac. That may be legitimate, but if it is enabled without a clear need it increases exposure to brute force, credential theft, and lateral movement.",
                [
                    (
                        "Confirm the current SSH state.",
                        "systemsetup -getremotelogin",
                    ),
                    (
                        "Disable SSH if this Mac should not accept remote logins.",
                        "sudo systemsetup -setremotelogin off",
                    ),
                    (
                        "If SSH must stay enabled, review the effective sshd restrictions.",
                        "sudo sshd -T | egrep 'allowusers|permitrootlogin|passwordauthentication'",
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
