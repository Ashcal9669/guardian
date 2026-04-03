"""
macOS Browser Scanner
Scans installed browsers for surveillance indicators: malicious extensions,
proxy hijacking, rogue certificate authorities, and managed policy abuse.
"""

from __future__ import annotations

import ipaddress
import json
import os
import plistlib
import re
import subprocess
import time
from typing import Any

from ..remediation import build_remediation


# ---------------------------------------------------------------------------
# Known malicious extension IDs (Chromium-based)
# Source: various threat intelligence reports
# ---------------------------------------------------------------------------
MALICIOUS_EXTENSION_IDS: set[str] = {
    "hkligngkgcpcolhcnkgccglchdafcnao",  # WebNavigator Bing hijacker
    "mbopgmdnpcbohhpnfglgohlbhfongabi",  # Search Marquis hijacker
    "neajdppkdcdipfabeoofebfddakdcjhd",  # CacheFlow hidden surveillance
    "flliilndjeohchalpbbcdekjklbdgfkk",  # DataSpii spyware (Hover Zoom+)
    "jldhpllghnbhlbpcmnajkpdmadaclbnc",  # The Great Suspender (malicious reupload)
    "aapocclcgogkmnckokdopfmhonfmgoek",  # Google Slides (fake)
    "aohghmighlieiainnegkcijnfilokake",  # Google Docs (fake)
    "nmmhkkegccagdldgiimedpiccmgmieda",  # Google Wallet (fake)
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm",  # Chrome Media Router (spoofed)
    "bfbmjmiodbnnpllbbbfblcplfjjepjdn",  # Particle — fake extension
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin (fake)
    "bmnlcjabgnpnenekpadlanbbkooimhnj",  # Honey (adware variant)
    "noondiphcjgcjpbofaoclgjdgicbjjfo",  # Suspicious ad injector
    "ecbpbkjidipkajdhkjnfbjkmmfakcebd",  # Screen recorder spyware
    "hifnmfgfdfhklginbanjabnbnebkbckf",  # Keylogger extension
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs Offline (fake)
    "klbibkeccnjlkjkiokjodocebajanakg",  # The Great Suspender (original malicious)
    "mgijmajocgfcbeboacabfgobmjgjcoja",  # Credit Karma (adware)
    "oiigbmnaadbkfbmpbfijlflahbdbdgdf",  # Safe Browsing fake
    "bjjcnpbleajbljdgjiojbkjmkbolbhjb",  # SessionBox (data harvesting variant)
}

# Permissions that are dangerous for browser extensions
DANGEROUS_PERMISSIONS: set[str] = {
    "<all_urls>",
    "http://*/*",
    "https://*/*",
    "tabs",
    "history",
    "cookies",
    "passwords",
    "webRequest",
    "webRequestBlocking",
    "nativeMessaging",
    "debugger",
    "proxy",
    "management",
    "downloads",
    "bookmarks",
    "topSites",
    "browsingData",
    "clipboardRead",
    "clipboardWrite",
    "contentSettings",
    "privacy",
    "enterprise.platformKeys",
}

SUSPICIOUS_PROXY_HOST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"charles|burp|mitm|intercept|zscaler|netskope|websense", re.IGNORECASE),
    re.compile(r"^localhost$", re.IGNORECASE),
)

HOME = os.path.expanduser("~")

BROWSER_PROFILES: dict[str, dict] = {
    "Chrome": {
        "type": "chromium",
        "base": f"{HOME}/Library/Application Support/Google/Chrome",
        "profiles": ["Default", "Profile 1", "Profile 2", "Profile 3"],
    },
    "Chromium": {
        "type": "chromium",
        "base": f"{HOME}/Library/Application Support/Chromium",
        "profiles": ["Default"],
    },
    "Brave": {
        "type": "chromium",
        "base": f"{HOME}/Library/Application Support/BraveSoftware/Brave-Browser",
        "profiles": ["Default", "Profile 1"],
    },
    "Edge": {
        "type": "chromium",
        "base": f"{HOME}/Library/Application Support/Microsoft Edge",
        "profiles": ["Default", "Profile 1"],
    },
    "Arc": {
        "type": "chromium",
        "base": f"{HOME}/Library/Application Support/Arc/User Data",
        "profiles": ["Default"],
    },
    "Firefox": {
        "type": "firefox",
        "base": f"{HOME}/Library/Application Support/Firefox/Profiles",
        "profiles": [],  # dynamically discovered
    },
    "Safari": {
        "type": "safari",
        "base": f"{HOME}/Library/Safari",
        "profiles": [],
    },
}


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
        "source": "mac.browsers",
    }


def _load_json(path: str) -> dict | list | None:
    try:
        with open(path, "r", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _load_plist(path: str) -> dict | None:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def _get_dangerous_perms(permissions: list) -> list[str]:
    """Return only dangerous permissions from a list."""
    result = []
    for p in permissions:
        p_str = str(p)
        if p_str in DANGEROUS_PERMISSIONS:
            result.append(p_str)
        elif any(d in p_str for d in ["http://", "https://", "ftp://", "*://"]):
            result.append(p_str)
    return result


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_chromium_extensions(
    browser: str, profile_dir: str, findings: list, counter: list
) -> int:
    """Scan a single Chromium profile's extension directory."""
    ext_dir = os.path.join(profile_dir, "Extensions")
    if not os.path.isdir(ext_dir):
        return 0

    count = 0
    try:
        ext_ids = os.listdir(ext_dir)
    except PermissionError:
        return 0

    for ext_id in ext_ids:
        ext_path = os.path.join(ext_dir, ext_id)
        if not os.path.isdir(ext_path):
            continue
        count += 1

        # Find the latest version directory
        versions = sorted(
            [v for v in os.listdir(ext_path) if os.path.isdir(os.path.join(ext_path, v))],
            reverse=True,
        )
        manifest = None
        manifest_path = None
        for v in versions:
            mp = os.path.join(ext_path, v, "manifest.json")
            if os.path.isfile(mp):
                manifest_path = mp
                manifest = _load_json(mp)
                break

        ext_name = ext_id
        permissions: list = []
        host_permissions: list = []
        ext_version = "unknown"
        background_scripts: list = []

        if manifest and isinstance(manifest, dict):
            ext_name = manifest.get("name", ext_id)
            permissions = manifest.get("permissions", [])
            host_permissions = manifest.get("host_permissions", [])
            ext_version = manifest.get("version", "unknown")
            bg = manifest.get("background", {})
            if isinstance(bg, dict):
                background_scripts = bg.get("scripts", []) or ([bg.get("service_worker")] if bg.get("service_worker") else [])

        all_perms = [str(p) for p in (permissions + host_permissions)]
        dangerous = _get_dangerous_perms(all_perms)

        # Determine severity
        is_known_malicious = ext_id in MALICIOUS_EXTENSION_IDS
        severity = "critical" if is_known_malicious else ("high" if len(dangerous) >= 3 else ("medium" if dangerous else "info"))

        counter[0] += 1
        fid = f"browser_{counter[0]:03d}"
        desc = f"{browser} extension '{ext_name}' (ID: {ext_id}, v{ext_version})"
        if is_known_malicious:
            desc += " IS IN THE KNOWN MALICIOUS EXTENSION LIST."
        if dangerous:
            desc += f" Dangerous permissions: {dangerous[:5]}."

        findings.append(_make_finding(
            fid=fid,
            severity=severity,
            category="spyware" if is_known_malicious else "surveillance",
            title=f"{browser} extension: {ext_name}" + (" [KNOWN MALICIOUS]" if is_known_malicious else ""),
            description=desc,
            evidence={
                "browser": browser,
                "extension_id": ext_id,
                "extension_name": ext_name,
                "version": ext_version,
                "path": ext_path,
                "dangerous_permissions": dangerous,
                "all_permissions": all_perms[:20],
                "background_scripts": background_scripts[:5],
                "known_malicious": is_known_malicious,
            },
            remediation=build_remediation(
                "Browser extensions can read and modify browsing data, intercept traffic, and access saved credentials. Known-malicious extensions should be removed immediately, and unfamiliar high-permission extensions should be treated as risky until verified."
                if is_known_malicious else
                "This extension has elevated or privacy-sensitive permissions. Even legitimate extensions deserve review because broad browser access can expose credentials, sessions, and browsing activity.",
                [
                    (
                        "Open the browser's extension management page and locate the exact extension by name or ID.",
                        ["open 'chrome://extensions'"],
                    ),
                    (
                        "Inspect the extension files and manifest to confirm what it can access.",
                        [f"find '{ext_path}' -maxdepth 2 -name manifest.json -print -exec cat {{}} \\;"],
                    ),
                    (
                        "Remove the extension if it is malicious, unfamiliar, or has unnecessary permissions.",
                        ["open 'chrome://extensions'"],
                    ),
                    (
                        "Restart the browser and confirm the extension is no longer installed.",
                        ["open 'chrome://extensions'"],
                    ),
                ],
            ),
        ))

    return count


def _scan_chromium_preferences(
    browser: str, profile_dir: str, findings: list, counter: list
):
    """Check Chromium Preferences for proxy settings and managed policies."""
    prefs_path = os.path.join(profile_dir, "Preferences")
    prefs = _load_json(prefs_path)
    if not isinstance(prefs, dict):
        return

    # Check proxy settings
    proxy = prefs.get("proxy", {})
    if isinstance(proxy, dict) and proxy.get("mode") not in (None, "system", "direct", "auto_detect"):
        proxy_host = str(proxy.get("server") or proxy.get("pac_url") or "")
        suspicious = any(pattern.search(proxy_host) for pattern in SUSPICIOUS_PROXY_HOST_PATTERNS)
        suspicious = suspicious or proxy.get("mode") not in ("fixed_servers", "pac_script")
        if not suspicious:
            return
        counter[0] += 1
        fid = f"browser_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="network",
            title=f"{browser}: suspicious proxy configuration in Preferences",
            description=(
                f"{browser} has a non-standard proxy mode configured: '{proxy.get('mode')}'. "
                "This may route traffic through an interception or debugging proxy."
            ),
            evidence={
                "browser": browser,
                "profile": profile_dir,
                "proxy_settings": proxy,
            },
            remediation=build_remediation(
                "A browser-specific proxy can silently redirect traffic through an interception or monitoring service. If you did not configure it deliberately, it may indicate adware, debugging residue, or browser hijacking.",
                [
                    (
                        "Inspect the relevant Preferences file and confirm the proxy mode and server values.",
                        [f"plutil -p '{prefs_path}' | grep -A8 'proxy'"],
                    ),
                    (
                        "Back up the Preferences file before making changes.",
                        [f"cp '{prefs_path}' '{prefs_path}.bak'"],
                    ),
                    (
                        "Close the browser and remove the suspicious proxy configuration by resetting the Preferences file or editing the proxy keys.",
                        [f"rm '{prefs_path}'"],
                    ),
                    (
                        "Restart the browser and confirm the proxy settings are back to normal.",
                        [f"open -a '{browser}'"],
                    ),
                ],
            ),
        ))

    # Check for managed/forced policies
    managed_path = os.path.join(profile_dir, "Managed Preferences")
    policies_path = os.path.join("/Library/Managed Preferences", browser)
    for pol_path in [managed_path, policies_path]:
        if os.path.isdir(pol_path):
            counter[0] += 1
            fid = f"browser_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="info",
                category="surveillance",
                title=f"{browser}: managed enterprise policies detected",
                description=(
                    f"Managed policy directory found at '{pol_path}'. "
                    "Enterprise policies can force install extensions, disable security features, "
                    "or redirect traffic. This is common on managed Macs and should be reviewed in context."
                ),
                evidence={"browser": browser, "policy_path": pol_path},
                remediation=build_remediation(
                    "Managed browser policies can force-install extensions, disable security features, or redirect traffic. On a personal Mac, unexpected policy files can indicate unwanted management or tampering.",
                    [
                        (
                            "Review the active browser policies in the browser UI.",
                            ["open 'chrome://policy'"],
                        ),
                        (
                            "Inspect the managed policy directory on disk.",
                            [f"find '{pol_path}' -maxdepth 2 -type f -print -exec cat {{}} \\;"],
                        ),
                        (
                            "If the policies are not expected, remove the unwanted policy files and restart the browser.",
                            [f"rm -rf '{pol_path}'"],
                        ),
                    ],
                ),
            ))
            break


def _scan_firefox_extensions(
    profile_path: str, profile_name: str, findings: list, counter: list
) -> int:
    """Scan a Firefox profile for extensions."""
    addons_json_path = os.path.join(profile_path, "addons.json")
    ext_dir = os.path.join(profile_path, "extensions")
    count = 0

    # Try addons.json first (JSON database)
    addons_data = _load_json(addons_json_path)
    if isinstance(addons_data, dict):
        addons = addons_data.get("addons", [])
        for addon in addons:
            if not isinstance(addon, dict):
                continue
            count += 1
            addon_id = addon.get("id", "unknown")
            addon_name = addon.get("defaultLocale", {}).get("name", addon_id)
            permissions = addon.get("userPermissions", {}).get("permissions", [])
            origins = addon.get("userPermissions", {}).get("origins", [])
            all_perms = [str(p) for p in permissions + origins]
            dangerous = _get_dangerous_perms(all_perms)
            is_system = addon.get("isSystem", False)
            if is_system:
                continue

            severity = "medium" if len(dangerous) >= 2 else ("low" if dangerous else "info")
            counter[0] += 1
            fid = f"browser_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity=severity,
                category="surveillance",
                title=f"Firefox extension: {addon_name}",
                description=(
                    f"Firefox profile '{profile_name}' has extension '{addon_name}' (ID: {addon_id}). "
                    + (f"Dangerous permissions: {dangerous[:5]}." if dangerous else "")
                ),
                evidence={
                    "browser": "Firefox",
                    "profile": profile_name,
                    "addon_id": addon_id,
                    "addon_name": addon_name,
                    "dangerous_permissions": dangerous,
                    "active": addon.get("active", True),
                    "source_uri": addon.get("sourceURI", ""),
                },
                remediation=build_remediation(
                    "Firefox add-ons can read page content, intercept traffic, and access browsing history. Extensions with broad origins or permissions should be kept only if you recognize and need them.",
                    [
                        (
                            "Open Firefox's add-on manager and find the flagged add-on.",
                            ["open 'about:addons'"],
                        ),
                        (
                            "Review the add-on's stored metadata on disk.",
                            [f"cat '{addons_json_path}' | sed -n '1,200p'"],
                        ),
                        (
                            "Disable or remove the add-on if it is unfamiliar or over-privileged.",
                            ["open 'about:addons'"],
                        ),
                    ],
                ),
            ))
        return count

    # Fallback: scan the extensions directory
    if not os.path.isdir(ext_dir):
        return count
    try:
        for ext_entry in os.listdir(ext_dir):
            count += 1
            counter[0] += 1
            fid = f"browser_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="info",
                category="surveillance",
                title=f"Firefox extension file: {ext_entry}",
                description=(
                    f"Firefox extension file '{ext_entry}' found in profile '{profile_name}'."
                ),
                evidence={
                    "browser": "Firefox",
                    "profile": profile_name,
                    "path": os.path.join(ext_dir, ext_entry),
                },
                remediation=build_remediation(
                    "This Firefox extension file was found on disk and should be matched to an add-on you intentionally installed. Unrecognized extension packages can continue affecting browser behavior until removed.",
                    [
                        (
                            "Open Firefox's add-on manager and identify the matching extension entry.",
                            ["open 'about:addons'"],
                        ),
                        (
                            "Inspect the extension file on disk.",
                            [f"ls -la '{os.path.join(ext_dir, ext_entry)}'"],
                        ),
                        (
                            "Remove the extension from Firefox if you do not recognize it.",
                            ["open 'about:addons'"],
                        ),
                    ],
                ),
            ))
    except PermissionError:
        pass
    return count


def _scan_certificate_authorities(findings: list, counter: list):
    """Check for custom trust overrides rather than flagging legitimate CAs."""
    suspicious_domains: list[dict[str, str]] = []
    for domain in ("user", "admin"):
        stdout, _, rc = _run(["security", "dump-trust-settings", "-d", domain], timeout=20)
        if rc != 0 or not stdout:
            continue
        if "No Trust Settings were found" in stdout:
            continue
        current_cert = ""
        for line in stdout.splitlines():
            stripped = line.strip()
            cert_match = re.match(r'Cert\s+\d+:\s+(.+)', stripped)
            if cert_match:
                current_cert = cert_match.group(1)
                continue
            lowered = stripped.lower()
            if "policy oid" in lowered or "result:" in lowered:
                suspicious_domains.append({
                    "domain": domain,
                    "certificate": current_cert or "unknown",
                    "setting": stripped,
                })

    if suspicious_domains:
        counter[0] += 1
        fid = f"browser_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="medium",
            category="network",
            title=f"Custom certificate trust overrides detected ({len(suspicious_domains)} entries)",
            description=(
                "Custom user or admin trust settings are configured. These can be legitimate, "
                "but they are also a common way to force trust for interception certificates."
            ),
            evidence={
                "trust_overrides": suspicious_domains[:20],
            },
            remediation=build_remediation(
                "Custom certificate trust overrides can be used to force the Mac to trust interception certificates, enabling TLS inspection or man-in-the-middle monitoring. Some are legitimate, but each override should be attributable to software you expect.",
                [
                    (
                        "Dump the current user and admin trust settings for review.",
                        [
                            "security dump-trust-settings -d user",
                            "security dump-trust-settings -d admin",
                        ],
                    ),
                    (
                        "Inspect matching certificates in the keychains.",
                        ["security find-certificate -a -p ~/Library/Keychains/login.keychain-db | head -20"],
                    ),
                    (
                        "Remove unexpected trust overrides or the associated certificate.",
                        ["open '/Applications/Utilities/Keychain Access.app'"],
                    ),
                ],
            ),
        ))


def _scan_safari_extensions(findings: list, counter: list) -> int:
    """Scan Safari extensions."""
    safari_ext_dir = f"{HOME}/Library/Safari/Extensions"
    safari_plist = f"{HOME}/Library/Safari/Extensions/Extensions.plist"
    count = 0

    pdata = _load_plist(safari_plist)
    if pdata and isinstance(pdata, dict):
        installed_extensions = pdata.get("Installed Extensions", [])
        if isinstance(installed_extensions, list):
            for ext in installed_extensions:
                if not isinstance(ext, dict):
                    continue
                count += 1
                ext_name = ext.get("Archive File Name", ext.get("Bundle Identifier", "unknown"))
                is_enabled = ext.get("Enabled", True)
                bundle_id = ext.get("Bundle Identifier", "")
                counter[0] += 1
                fid = f"browser_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="info",
                    category="surveillance",
                    title=f"Safari extension: {ext_name}",
                    description=(
                        f"Safari extension '{ext_name}' (bundle: {bundle_id}) is "
                        f"{'enabled' if is_enabled else 'disabled'}."
                    ),
                    evidence={
                        "browser": "Safari",
                        "extension_name": ext_name,
                        "bundle_id": bundle_id,
                        "enabled": is_enabled,
                    },
                    remediation=build_remediation(
                        "Safari extensions can access web content, page scripts, and browser data. Any extension you do not recognize should be removed, especially if it remains enabled.",
                        [
                            (
                                "Open Safari's extension settings and locate the extension.",
                                ["open -a Safari"],
                            ),
                            (
                                "Inspect the on-disk extension metadata if needed.",
                                [f"plutil -p '{safari_plist}'"],
                            ),
                            (
                                "Disable or remove the extension if it is not expected.",
                                ["open -a Safari"],
                            ),
                        ],
                    ),
                ))

    # Fallback: scan .appex files in the extensions directory
    if not os.path.isdir(safari_ext_dir):
        return count
    try:
        for entry in os.listdir(safari_ext_dir):
            if entry.endswith(".appex") or entry.endswith(".safariextz"):
                count += 1
                counter[0] += 1
                fid = f"browser_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="info",
                    category="surveillance",
                    title=f"Safari extension file: {entry}",
                    description=f"Safari extension package '{entry}' found.",
                    evidence={
                        "browser": "Safari",
                        "path": os.path.join(safari_ext_dir, entry),
                    },
                    remediation=build_remediation(
                        "A Safari extension package was found on disk. Even if Safari is not currently using it, it should be traceable to software you intentionally installed.",
                        [
                            (
                                "Inspect the extension package on disk.",
                                [f"ls -la '{os.path.join(safari_ext_dir, entry)}'"],
                            ),
                            (
                                "Open Safari and review installed extensions.",
                                ["open -a Safari"],
                            ),
                            (
                                "Remove the package if it is not recognized and no longer needed.",
                                [f"rm -rf '{os.path.join(safari_ext_dir, entry)}'"],
                            ),
                        ],
                    ),
                ))
    except PermissionError:
        pass

    return count


def _scan_browser_proxy_settings(findings: list, counter: list):
    """Check system-level proxy settings that affect all browsers."""
    # Check system proxy via scutil
    stdout, _, rc = _run(["scutil", "--proxy"], timeout=10)
    if rc != 0 or not stdout:
        return

    proxy_info: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            proxy_info[key.strip()] = val.strip()

    # Flag if HTTP/HTTPS proxy is set to a non-local address
    for proxy_type in ["HTTPProxy", "HTTPSProxy", "SOCKSProxy"]:
        enable_key = proxy_type.replace("Proxy", "Enable")
        if proxy_type in proxy_info and proxy_info.get(enable_key) == "1":
            proxy_host = proxy_info[proxy_type]
            port_key = proxy_type.replace("Proxy", "Port")
            proxy_port = proxy_info.get(port_key, "?")
            try:
                addr = ipaddress.ip_address(proxy_host)
                if not addr.is_private and not addr.is_loopback:
                    counter[0] += 1
                    fid = f"browser_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="low",
                        category="network",
                        title=f"System {proxy_type} set to external host: {proxy_host}:{proxy_port}",
                        description=(
                            f"System-wide {proxy_type} is configured to route all traffic "
                            f"through {proxy_host}:{proxy_port}, an external address. "
                            "This is often legitimate on corporate or filtered networks, but it should be verified."
                        ),
                        evidence={
                            "proxy_type": proxy_type,
                            "proxy_host": proxy_host,
                            "proxy_port": proxy_port,
                            "full_proxy_config": proxy_info,
                        },
                        remediation=build_remediation(
                            "A system proxy affects all browser traffic and can route browsing through an external server. That is normal on some managed networks, but it should always be explicitly expected.",
                            [
                                (
                                    "Inspect the current system proxy settings.",
                                    ["scutil --proxy"],
                                ),
                                (
                                    "Identify which network service is active so you can update the correct interface.",
                                    ["networksetup -listallnetworkservices"],
                                ),
                                (
                                    "Disable the unexpected proxy on the affected service.",
                                    ["networksetup -setwebproxystate 'Wi-Fi' off", "networksetup -setsecurewebproxystate 'Wi-Fi' off"],
                                ),
                            ],
                        ),
                    ))
            except ValueError:
                if any(pattern.search(proxy_host) for pattern in SUSPICIOUS_PROXY_HOST_PATTERNS):
                    counter[0] += 1
                    fid = f"browser_{counter[0]:03d}"
                    findings.append(_make_finding(
                        fid=fid,
                        severity="medium",
                        category="network",
                        title=f"System {proxy_type} configured with interception-style host",
                        description=(
                            f"System-wide {proxy_type} is set to {proxy_host}:{proxy_port}. "
                            "This hostname resembles a debugging or interception proxy."
                        ),
                        evidence={
                            "proxy_type": proxy_type,
                            "proxy_host": proxy_host,
                            "proxy_port": proxy_port,
                        },
                        remediation=build_remediation(
                            "Interception-style proxy hostnames are often used by debugging tools, traffic filters, or monitoring products. If you did not install or configure one, browser traffic may be being redirected unexpectedly.",
                            [
                                (
                                    "Review the current proxy configuration.",
                                    ["scutil --proxy"],
                                ),
                                (
                                    "Turn off the unexpected proxy for the active network service.",
                                    ["networksetup -setwebproxystate 'Wi-Fi' off", "networksetup -setsecurewebproxystate 'Wi-Fi' off"],
                                ),
                                (
                                    "Re-check the proxy settings to confirm they are gone.",
                                    ["scutil --proxy"],
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
    total_extensions = 0

    try:
        # Scan each browser
        for browser_name, config in BROWSER_PROFILES.items():
            btype = config["type"]
            base = config["base"]

            if not os.path.isdir(base):
                continue

            if btype == "chromium":
                profiles = config.get("profiles", ["Default"])
                for profile_name in profiles:
                    profile_dir = os.path.join(base, profile_name)
                    if not os.path.isdir(profile_dir):
                        continue
                    ext_count = _scan_chromium_extensions(
                        browser_name, profile_dir, findings, counter
                    )
                    total_extensions += ext_count
                    _scan_chromium_preferences(
                        browser_name, profile_dir, findings, counter
                    )

            elif btype == "firefox":
                # Discover Firefox profiles dynamically
                try:
                    profiles_dir = base
                    if os.path.isdir(profiles_dir):
                        for entry in os.listdir(profiles_dir):
                            profile_dir = os.path.join(profiles_dir, entry)
                            if os.path.isdir(profile_dir):
                                ext_count = _scan_firefox_extensions(
                                    profile_dir, entry, findings, counter
                                )
                                total_extensions += ext_count
                except PermissionError:
                    pass

            elif btype == "safari":
                ext_count = _scan_safari_extensions(findings, counter)
                total_extensions += ext_count

        # Check for rogue certificate authorities
        _scan_certificate_authorities(findings, counter)

        # Check system-level proxy settings
        _scan_browser_proxy_settings(findings, counter)

        metadata["total_extensions_found"] = total_extensions
        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.browsers",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.browsers",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.browsers",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
