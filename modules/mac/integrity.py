"""
macOS System Integrity Scanner
Checks SIP, Gatekeeper, FileVault, Firewall, Secure Boot, kernel extensions,
XProtect/MRT status, and Rosetta usage on Apple Silicon.
"""

from __future__ import annotations

import os
import platform
import plistlib
import re
import sqlite3
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
        "source": "mac.integrity",
    }


def _is_apple_silicon() -> bool:
    """Return True if running on Apple Silicon (M-series)."""
    stdout, _, _ = _run(["sysctl", "-n", "hw.optional.arm64"], timeout=5)
    return stdout.strip() == "1"


def _load_plist(path: str) -> dict | None:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _check_sip(findings: list, counter: list) -> dict:
    """Check System Integrity Protection status."""
    stdout, stderr, rc = _run(["csrutil", "status"], timeout=10)
    output = (stdout + stderr).strip()
    is_enabled = "enabled" in output.lower()
    is_disabled = "disabled" in output.lower()

    result = {"raw": output, "enabled": is_enabled}

    if is_disabled or (not is_enabled and not is_disabled):
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="critical",
            category="integrity",
            title="System Integrity Protection (SIP) is disabled",
            description=(
                "SIP is disabled, removing macOS protections against modifying system files, "
                "loading unsigned kernel extensions, and other critical security controls."
            ),
            evidence={"csrutil_output": output},
            remediation=build_remediation(
                "System Integrity Protection is Apple’s guardrail for core system files and runtime protections. If it is off, malware or an attacker with admin access can tamper with parts of macOS that should normally be locked down.",
                [
                    (
                        "Confirm the current SIP state so you have a record before changing it.",
                        "csrutil status",
                    ),
                    (
                        "Restart into macOS Recovery and re-enable SIP from Recovery Terminal.",
                        "csrutil enable",
                    ),
                    (
                        "Restart normally and verify that SIP is enabled again.",
                        "csrutil status",
                    ),
                ],
            ),
        ))
    return result


def _check_gatekeeper(findings: list, counter: list) -> dict:
    """Check Gatekeeper status."""
    stdout, stderr, rc = _run(["spctl", "--status"], timeout=10)
    output = (stdout + stderr).strip()
    is_enabled = "assessments enabled" in output.lower()

    result = {"raw": output, "enabled": is_enabled}

    if not is_enabled:
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="integrity",
            title="Gatekeeper is disabled",
            description=(
                "Gatekeeper is disabled, allowing unsigned or unnotarized applications "
                "to run without warning. This significantly increases malware risk."
            ),
            evidence={"spctl_output": output},
            remediation=build_remediation(
                "Gatekeeper checks whether apps are signed and notarized before they run. When it is disabled, unsigned or tampered apps can launch with much less friction, which materially increases malware risk.",
                [
                    (
                        "Check the current Gatekeeper status.",
                        "spctl --status",
                    ),
                    (
                        "Re-enable Gatekeeper so app assessments are enforced again.",
                        "sudo spctl --master-enable",
                    ),
                    (
                        "Verify that assessments are now enabled.",
                        "spctl --status",
                    ),
                ],
            ),
        ))
    return result


def _check_filevault(findings: list, counter: list) -> dict:
    """Check FileVault encryption status."""
    stdout, stderr, rc = _run(["fdesetup", "status"], timeout=10)
    output = (stdout + stderr).strip()
    is_on = "on" in output.lower() and "off" not in output.lower()

    result = {"raw": output, "enabled": is_on}

    if not is_on:
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="integrity",
            title="FileVault disk encryption is not enabled",
            description=(
                "FileVault is not enabled. Without disk encryption, data on this Mac can be "
                "accessed if the physical disk is removed or the machine is stolen."
            ),
            evidence={"fdesetup_output": output},
            remediation=build_remediation(
                "FileVault encrypts the startup disk. Without it, anyone who gets physical access to the Mac or removes the drive can read the data offline.",
                [
                    (
                        "Verify the current encryption state before making changes.",
                        "fdesetup status",
                    ),
                    (
                        "Turn on FileVault from Terminal if you are ready to start encryption.",
                        "sudo fdesetup enable",
                    ),
                    (
                        "Store the recovery key securely and confirm encryption has started.",
                        "fdesetup status",
                    ),
                ],
            ),
        ))
    return result


def _check_firewall(findings: list, counter: list) -> dict:
    """Check macOS application firewall status."""
    stdout, stderr, rc = _run(
        ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
        timeout=10,
    )
    output = (stdout + stderr).strip()
    try:
        state = int(output)
    except ValueError:
        state = -1

    # 0 = off, 1 = on, 2 = block all incoming
    result = {"raw": output, "state": state, "enabled": state >= 1}

    if state == 0:
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="network",
            title="macOS Application Firewall is disabled",
            description=(
                "The macOS application-level firewall (ALF) is disabled. "
                "This allows all incoming connections without filtering."
            ),
            evidence={"alf_state": state, "raw_output": output},
            remediation=build_remediation(
                "The macOS Application Firewall limits unsolicited inbound connections. If it is disabled, services that bind to the network are more exposed than they should be.",
                [
                    (
                        "Check the current firewall state.",
                        "defaults read /Library/Preferences/com.apple.alf globalstate",
                    ),
                    (
                        "Enable the firewall.",
                        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                    ),
                    (
                        "Confirm the preference was updated.",
                        "defaults read /Library/Preferences/com.apple.alf globalstate",
                    ),
                ],
            ),
        ))
    return result


def _check_secure_boot(findings: list, counter: list) -> dict | None:
    """Check Secure Boot status (Apple Silicon only)."""
    if not _is_apple_silicon():
        return None

    stdout, stderr, rc = _run(["bputil", "-d"], timeout=15)
    output = (stdout + stderr).strip()

    result = {"raw": output}

    # Look for indicators of reduced security
    if "reduced security" in output.lower() or "permissive security" in output.lower():
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="high",
            category="integrity",
            title="Secure Boot is in reduced/permissive security mode",
            description=(
                "Apple Silicon Secure Boot is not in Full Security mode. "
                "Reduced or Permissive Security allows unsigned kernel extensions "
                "and reduces boot security guarantees."
            ),
            evidence={"bputil_output": output[:2000]},
            remediation=build_remediation(
                "Reduced or permissive Secure Boot weakens the chain of trust at startup. That makes it easier for low-level software to load before macOS applies its normal protections.",
                [
                    (
                        "Record the current boot policy so you know what changed.",
                        "bputil -d",
                    ),
                    (
                        "Restart into Recovery and switch the Mac back to Full Security in Startup Security Utility.",
                        "bputil -d",
                    ),
                    (
                        "After rebooting, verify the security mode again.",
                        "bputil -d",
                    ),
                ],
            ),
        ))
    return result


def _check_system_version(findings: list, counter: list) -> dict:
    """Get system version and check if it's recent."""
    stdout, _, rc = _run(["sw_vers"], timeout=10)
    result = {"raw": stdout.strip()}

    # Parse version
    version_match = re.search(r'ProductVersion:\s+(\S+)', stdout)
    version = version_match.group(1) if version_match else "unknown"
    result["version"] = version

    # Check major version — macOS 13 (Ventura) is the minimum security-supported version
    try:
        major = int(version.split(".")[0])
        if major < 13:
            counter[0] += 1
            fid = f"integ_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="high",
                category="integrity",
                title=f"Unsupported macOS version: {version}",
                description=(
                    f"macOS {version} is no longer receiving security updates from Apple. "
                    "Running an unsupported OS exposes the system to unpatched vulnerabilities."
                ),
                evidence={"sw_vers_output": stdout.strip(), "version": version},
                remediation=build_remediation(
                    f"macOS {version} is outside Apple’s actively supported security window. Unsupported releases stop receiving patches, so known vulnerabilities remain exposed.",
                    [
                        (
                            "Record the current macOS version and build.",
                            "sw_vers",
                        ),
                        (
                            "List available software updates.",
                            "softwareupdate -l",
                        ),
                        (
                            "Install all recommended macOS updates.",
                            "sudo softwareupdate --install --all",
                        ),
                    ],
                ),
            ))
    except (ValueError, IndexError):
        pass

    return result


def _check_unsigned_kexts(findings: list, counter: list) -> int:
    """Check for loaded kernel extensions that are not Apple-signed."""
    if _is_apple_silicon():
        stdout, _, rc = _run(["kmutil", "showloaded", "--list-only"], timeout=20)
    else:
        stdout, _, rc = _run(["kextstat"], timeout=15)
    if rc != 0 or not stdout:
        return 0

    count = 0
    for line in stdout.splitlines():
        if not line.strip() or line.lower().startswith(("index", "no variant", "bundle identifier")):
            continue
        if "com.apple" in line.lower():
            continue
        bundle_match = re.search(r"(com\.[A-Za-z0-9._-]+)", line)
        bundle_id = bundle_match.group(1) if bundle_match else line.split()[-1].strip("()")
        count += 1
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="integrity",
            title=f"Third-party kernel extension loaded: {bundle_id}",
            description=(
                f"Kernel extension '{bundle_id}' is loaded and is not an Apple extension. "
                "Third-party kexts run at kernel level and represent elevated risk."
            ),
            evidence={"kextstat_line": line.strip(), "bundle_id": bundle_id},
            remediation=build_remediation(
                "Third-party kernel extensions run in kernel space, so a buggy or malicious one can cause full-system compromise. Review any loaded kext that is not Apple-provided.",
                [
                    (
                        "List the currently loaded third-party kernel extensions.",
                        "kmutil showloaded --list-only" if _is_apple_silicon() else "kextstat | grep -v com.apple",
                    ),
                    (
                        f"Inspect the suspicious bundle identifier and identify the parent software package for '{bundle_id}'.",
                        f"kmutil showloaded --list-only | grep '{bundle_id}'" if _is_apple_silicon() else f"kextstat | grep '{bundle_id}'",
                    ),
                    (
                        "If the kext is not legitimate, unload it and remove the owning software.",
                        f"sudo kextunload -b '{bundle_id}'",
                    ),
                ],
            ),
        ))
    return count


def _check_rosetta_intel_processes(findings: list, counter: list) -> bool:
    """Record whether Rosetta is installed on Apple Silicon without flagging it as suspicious."""
    if not _is_apple_silicon():
        return False

    stdout, _, rc = _run(["pkgutil", "--pkg-info", "com.apple.pkg.RosettaUpdateAuto"], timeout=10)
    if rc != 0:
        return False
    return True


def _check_system_extensions(findings: list, counter: list) -> int:
    """List active non-Apple system extensions."""
    stdout, _, rc = _run(["systemextensionsctl", "list"], timeout=20)
    if rc != 0 or not stdout:
        return 0

    count = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("*") or "com.apple." in stripped:
            continue
        if "[" not in stripped and "active" not in stripped.lower():
            continue
        count += 1
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="info",
            category="integrity",
            title="Non-Apple system extension present",
            description=(
                "A third-party system extension is installed or active. This is often legitimate "
                "for security, VPN, or hardware software, but it runs with elevated system privileges."
            ),
            evidence={"systemextensionsctl_line": stripped},
            remediation=build_remediation(
                "System extensions can legitimately belong to VPN, security, or hardware software, but they also run with elevated privileges. Anything you do not recognize should be traced back to its installed application.",
                [
                    (
                        "List the active system extensions.",
                        "systemextensionsctl list",
                    ),
                    (
                        "Identify the owning app or vendor for the unexpected extension entry.",
                        "systemextensionsctl list",
                    ),
                    (
                        "Remove the parent app if the extension is not expected, then verify the extension disappears.",
                        "systemextensionsctl list",
                    ),
                ],
            ),
        ))
    return count


def _check_tcc_database(findings: list, counter: list) -> int:
    """Inspect TCC privacy databases for suspicious high-risk grants."""
    sensitive_services = {
        "kTCCServiceAccessibility",
        "kTCCServiceListenEvent",
        "kTCCServiceScreenCapture",
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceCamera",
        "kTCCServiceMicrophone",
    }
    db_paths = [
        os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db"),
        "/Library/Application Support/com.apple.TCC/TCC.db",
    ]

    findings_count = 0
    for db_path in db_paths:
        if not os.path.exists(db_path):
            continue
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(access)").fetchall()
            }
            auth_expr = "auth_value" if "auth_value" in columns else ("allowed" if "allowed" in columns else "0")
            rows = conn.execute(
                f"""
                SELECT service, client, client_type, {auth_expr} AS auth_value
                FROM access
                """
            ).fetchall()
            conn.close()
        except Exception:
            continue

        grouped: dict[str, set[str]] = {}
        for row in rows:
            service = str(row["service"])
            client = str(row["client"])
            auth_value = int(row["auth_value"] or 0)
            if service not in sensitive_services or auth_value <= 0:
                continue
            if client.startswith("com.apple.") or client.startswith("/System/"):
                continue
            grouped.setdefault(client, set()).add(service)

        for client, services in grouped.items():
            if len(services) < 2 and not client.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")):
                continue
            findings_count += 1
            counter[0] += 1
            fid = f"integ_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium" if len(services) >= 3 else "low",
                category="privacy",
                title="Sensitive TCC permissions granted to non-Apple client",
                description=(
                    f"Client '{client}' has been granted sensitive privacy permissions recorded in TCC.db. "
                    "This may be legitimate, but broad privacy access should be reviewed."
                ),
                evidence={
                    "client": client,
                    "services": sorted(services),
                    "database": db_path,
                },
                remediation=build_remediation(
                    "TCC records access to sensitive privacy domains such as camera, microphone, screen capture, and full disk access. A non-Apple client with broad TCC grants may be legitimate, but it deserves review because those permissions materially expand what the app can collect.",
                    [
                        (
                            f"Inspect the TCC grants recorded for '{client}'.",
                            f"sqlite3 '{db_path}' \"SELECT service,client,auth_value FROM access WHERE client='{client}';\"",
                        ),
                        (
                            "Review the app in System Settings > Privacy & Security and remove any permission that is not required.",
                            f"open 'x-apple.systempreferences:com.apple.preference.security?Privacy_{sorted(services)[0] if services else 'AllFiles'}'",
                        ),
                        (
                            "If the app should not have these grants, remove the app and re-check the database.",
                            f"sqlite3 '{db_path}' \"SELECT service,client,auth_value FROM access WHERE client='{client}';\"",
                        ),
                    ],
                ),
            ))
    return findings_count


def _check_xprotect(findings: list, counter: list) -> dict:
    """Check XProtect and MRT (Malware Removal Tool) update dates."""
    xprotect_meta = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    mrt_path = "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"

    result = {}

    for label, plist_path in [("XProtect", xprotect_meta), ("MRT", mrt_path)]:
        pdata = _load_plist(plist_path)
        if pdata:
            version = pdata.get("CFBundleShortVersionString", pdata.get("CFBundleVersion", "unknown"))
            result[f"{label}_version"] = version
        else:
            result[f"{label}_version"] = "not found"
            counter[0] += 1
            fid = f"integ_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="integrity",
                title=f"{label} not found at expected path",
                description=(
                    f"{label} was not found at '{plist_path}'. This may indicate "
                    "it has been removed or the system has been tampered with."
                ),
                evidence={"expected_path": plist_path},
                remediation=build_remediation(
                    f"{label} is a built-in Apple security component. If it is missing from its expected path, the Mac may be damaged, partially updated, or tampered with.",
                    [
                        (
                            "Verify the component path and whether the plist is actually missing.",
                            f"ls -l '{plist_path}'",
                        ),
                        (
                            "Install all available Apple security updates.",
                            "sudo softwareupdate --install --all",
                        ),
                        (
                            "Re-check the component after updates complete.",
                            f"ls -l '{plist_path}'",
                        ),
                    ],
                ),
            ))

    return result


def _check_remote_login(findings: list, counter: list):
    """Check if remote login (SSH) is enabled."""
    stdout, stderr, rc = _run(["systemsetup", "-getremotelogin"], timeout=10)
    output = (stdout + stderr).strip()
    if "on" in output.lower():
        counter[0] += 1
        fid = f"integ_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="network",
            title="Remote Login (SSH) is enabled",
            description=(
                "SSH remote login is enabled on this Mac. If not intentionally configured, "
                "this allows remote access and increases attack surface."
            ),
            evidence={"systemsetup_output": output},
            remediation=build_remediation(
                "Remote Login enables the built-in SSH server. That is often intentional for administration, but if it is enabled unexpectedly it creates an exposed remote entry point.",
                [
                    (
                        "Confirm the current SSH service state.",
                        "systemsetup -getremotelogin",
                    ),
                    (
                        "Disable SSH if this Mac should not accept remote logins.",
                        "sudo systemsetup -setremotelogin off",
                    ),
                    (
                        "If SSH must stay enabled, review the active sshd configuration.",
                        "sudo sshd -T | egrep 'allowusers|passwordauthentication|permitrootlogin'",
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
        sip = _check_sip(findings, counter)
        metadata["sip_enabled"] = sip.get("enabled")

        gk = _check_gatekeeper(findings, counter)
        metadata["gatekeeper_enabled"] = gk.get("enabled")

        fv = _check_filevault(findings, counter)
        metadata["filevault_enabled"] = fv.get("enabled")

        fw = _check_firewall(findings, counter)
        metadata["firewall_state"] = fw.get("state")

        sb = _check_secure_boot(findings, counter)
        if sb:
            metadata["secure_boot_output"] = sb.get("raw", "")[:200]

        ver = _check_system_version(findings, counter)
        metadata["macos_version"] = ver.get("version")

        kext_count = _check_unsigned_kexts(findings, counter)
        metadata["third_party_kexts_loaded"] = kext_count

        metadata["rosetta_installed"] = _check_rosetta_intel_processes(findings, counter)

        metadata["system_extensions_found"] = _check_system_extensions(findings, counter)

        metadata["tcc_sensitive_clients_found"] = _check_tcc_database(findings, counter)

        xp = _check_xprotect(findings, counter)
        metadata.update(xp)

        _check_remote_login(findings, counter)

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.integrity",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.integrity",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.integrity",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
