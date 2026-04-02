"""
scanner.py — Main iOS scanning logic for Guardian.

Uses connector.py + Python stdlib only. No Apple ID required.
Returns a ScanResult dict conforming to the Guardian data contract.
"""

import re
import uuid
from datetime import datetime
from typing import Any

from .connector import (
    check_libimobiledevice_installed,
    get_device_info,
    get_installed_apps,
    get_syslog_snapshot,
    is_device_connected,
)

# ---------------------------------------------------------------------------
# Constants / IOC lists
# ---------------------------------------------------------------------------

MODULE_NAME = "ios_scanner"

# Known iOS stalkerware / spyware bundle IDs
STALKERWARE_BUNDLE_IDS: set = {
    "com.retina-x.ispy",
    "com.mobistealth.mobistealth",
    "com.flexispy.flexispy",
    "com.highster.phone-spy",
    "com.spyic.spyic",
    "com.cocospy.cocospy",
    "com.mspy.mspy",
    "com.ikeymonitor.ikeymonitor",
    "com.hoverwatch.hoverwatch",
    "com.eyezy.eyezy",
    "com.spyzie.spyzie",
    "com.minspy.minspy",
    "com.uste.tracker",
    "com.spapp.spapp",
    "com.imazing.profile-editor",  # can be misused
    "com.neatspy.neatspy",
    "com.famisafe.famisafe",
    "com.bark.app",                 # legitimate parental, but flag for review
    "com.qustodio.qustodio",        # parental control — flag for awareness
    "com.mspy.lite",
    "com.itracker.itracker",
    "com.xnspy.xnspy",
    "com.spyera.spyera",
    "com.trackview.trackview",
    "com.phonesheriff.phonesheriff",
    "com.familytime.familytime",
    "com.cerberus-app.cerberus",
    "com.gps-phone-tracker.tracker",
    "com.snoopza.snoopza",
}

# Jailbreak strings to search for in syslog
JAILBREAK_STRINGS: list = [
    "Cydia",
    "substrate",
    "cycript",
    "unc0ver",
    "checkra1n",
    "palera1n",
    "dopamine",
    "Sileo",
    "Zebra",
    "TweakCompatible",
    "jailbreak",
    "rootless",
    "KFD",          # kernel function table diffing used by modern jailbreaks
    "ElleKit",
    "libellekit",
]

# Syslog patterns indicating privacy-sensitive access
SYSLOG_PRIVACY_PATTERNS: list = [
    (r"CLLocationManager", "location", "Unexpected location access detected"),
    (r"kCLAuthorizationStatus", "location", "Location authorization status change"),
    (r"AVCaptureSession", "camera", "Camera capture session detected"),
    (r"AVAudioSession.*record", "microphone", "Audio recording session detected"),
    (r"AVAudioRecorder", "microphone", "Audio recorder instantiated"),
    (r"RPScreenRecorder", "screen", "Screen recording session detected"),
    (r"CoreMotion.*CMMotionManager", "motion", "Motion sensor access detected"),
    (r"AddressBook|CNContactStore", "contacts", "Contacts access detected"),
    (r"LAContext.*evaluatePolicy", "biometric", "Biometric authentication attempt"),
    (r"SecItemCopyMatching|SecKeychainFind", "keychain", "Keychain read access detected"),
    (r"SecItemAdd|SecKeychainAddGenericPassword", "keychain", "Keychain write access detected"),
]

# Syslog patterns indicating malicious/exploit activity
SYSLOG_EXPLOIT_PATTERNS: list = [
    (r"checkra1n|palera1n|unc0ver|dopamine", "jailbreak_tool", "Known jailbreak tool string in syslog"),
    (r"frida|FridaGadget", "dynamic_instrumentation", "Frida dynamic instrumentation framework detected"),
    (r"cycript", "scripting_bridge", "Cycript scripting bridge detected"),
    (r"MobileSubstrate|CydiaSubstrate|libsubstrate", "substrate", "Cydia Substrate hook detected"),
    (r"Exception Type:.*EXC_BAD_ACCESS.*KERN_INVALID_ADDRESS", "crash_exploit", "Potential memory corruption crash"),
    (r"kernel\[0\].*panic", "kernel_panic", "Kernel panic detected"),
    (r"amfid.*DENY", "code_signing", "Code signing denial — possible unauthorized binary"),
    (r"taskgated.*deny", "code_signing", "Taskgated denied binary execution"),
    (r"sandbox.*deny.*network-outbound", "sandbox_violation", "App sandbox network violation"),
]

# Known suspicious domain patterns in syslog
SUSPICIOUS_DOMAIN_PATTERNS: list = [
    r"\.tk\b", r"\.xyz\b", r"\.top\b", r"\.pw\b", r"\.cc\b",
    r"dyndns\.", r"no-ip\.", r"ngrok\.io",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # raw IP in network log
]

# iOS versions with known unpatched critical CVEs
# Devices running below these versions should be flagged
MINIMUM_SAFE_IOS_VERSIONS: dict = {
    # (major, minor) -> minimum safe patch
    # For iOS 16 branch: 16.7.10 is the last update for older devices
    16: (16, 7, 10),
    # For iOS 17 branch: 17.6 and later are considered patched
    17: (17, 6, 0),
    # iOS 18 branch: 18.1 considered baseline
    18: (18, 1, 0),
}

# Versions below iOS 15 are considered entirely end-of-life
EOL_IOS_MAJOR_VERSION = 15

# Current latest iOS major version (used for "significantly outdated" check)
CURRENT_IOS_MAJOR = 17


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _make_finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: dict,
    remediation: str,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "source": MODULE_NAME,
    }


def _parse_ios_version(version_str: str) -> tuple:
    """Parse a version string like '16.7.1' into a comparable tuple of ints."""
    try:
        parts = [int(x) for x in version_str.strip().split(".")]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _is_sideloaded_indicator(bundle_id: str) -> bool:
    """
    Heuristically detect sideloaded apps by bundle ID patterns that don't
    match Apple's typical reverse-DNS naming, or that use known enterprise
    provisioning prefixes.
    """
    if not bundle_id:
        return False
    # Enterprise sideloaded apps often come from .enterprise or .internal TLDs
    suspicious_suffixes = [".enterprise", ".internal", ".dev", ".local"]
    for suffix in suspicious_suffixes:
        if bundle_id.endswith(suffix):
            return True
    # Numeric-only segments often indicate auto-generated / unofficial bundles
    parts = bundle_id.split(".")
    if len(parts) >= 2:
        # All-numeric TLD or second-level domain is unusual
        if parts[0].isdigit() or parts[1].isdigit():
            return True
    return False


def _levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance for typosquat detection."""
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (ca != cb)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# Well-known legitimate Apple app bundle IDs to check for typosquatting
LEGITIMATE_APP_BUNDLES: list = [
    ("com.apple.mobilesafari", "Safari"),
    ("com.apple.mobilemail", "Mail"),
    ("com.apple.mobilecal", "Calendar"),
    ("com.apple.camera", "Camera"),
    ("com.apple.Health", "Health"),
    ("com.apple.facetime", "FaceTime"),
    ("com.apple.mobilephone", "Phone"),
    ("com.apple.MobileSMS", "Messages"),
    ("com.apple.maps", "Maps"),
    ("com.apple.AppStore", "App Store"),
    ("com.google.chrome.ios", "Google Chrome"),
    ("com.facebook.Facebook", "Facebook"),
    ("com.burbn.instagram", "Instagram"),
    ("com.atebits.Tweetie2", "Twitter/X"),
    ("com.whatsapp.WhatsApp", "WhatsApp"),
    ("com.spotify.client", "Spotify"),
    ("com.netflix.Netflix", "Netflix"),
    ("com.google.Gmail", "Gmail"),
    ("com.microsoft.Office.Outlook", "Outlook"),
    ("com.zoom.us.zoom-video-meetings", "Zoom"),
]


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_device_info(device_info: dict) -> list:
    """Collect device metadata as an info-level finding."""
    findings = []
    if device_info:
        findings.append(
            _make_finding(
                severity="info",
                category="device_metadata",
                title="iOS Device Information Collected",
                description="Basic device metadata was collected for the security report.",
                evidence={
                    "DeviceName": device_info.get("DeviceName", "Unknown"),
                    "ProductType": device_info.get("ProductType", "Unknown"),
                    "ProductVersion": device_info.get("ProductVersion", "Unknown"),
                    "SerialNumber": device_info.get("SerialNumber", "Unknown"),
                    "UniqueDeviceID": device_info.get("UniqueDeviceID", "Unknown"),
                    "BuildVersion": device_info.get("BuildVersion", "Unknown"),
                    "CPUArchitecture": device_info.get("CPUArchitecture", "Unknown"),
                },
                remediation="No action required. This is informational.",
            )
        )
    return findings


def _check_ios_version(device_info: dict) -> list:
    """Flag outdated iOS versions with known unpatched CVEs."""
    findings = []
    version_str = device_info.get("ProductVersion", "")
    if not version_str:
        return findings

    version_tuple = _parse_ios_version(version_str)
    major = version_tuple[0]

    # End-of-life check
    if major < EOL_IOS_MAJOR_VERSION:
        findings.append(
            _make_finding(
                severity="critical",
                category="ios_version",
                title=f"End-of-Life iOS Version Detected: {version_str}",
                description=(
                    f"The device is running iOS {version_str}, which is end-of-life and "
                    f"no longer receives security updates from Apple. Multiple critical "
                    f"unpatched CVEs exist for this version, including kernel exploits "
                    f"and WebKit RCE vulnerabilities."
                ),
                evidence={
                    "installed_version": version_str,
                    "major_version": major,
                    "status": "end_of_life",
                },
                remediation=(
                    "Upgrade to the latest supported iOS version immediately. "
                    "Go to Settings > General > Software Update. "
                    "If your device cannot run a supported iOS version, consider replacing it."
                ),
            )
        )
        return findings

    # Significantly outdated check (more than 2 major versions behind iOS 17)
    if major < (CURRENT_IOS_MAJOR - 2):
        findings.append(
            _make_finding(
                severity="high",
                category="ios_version",
                title=f"Significantly Outdated iOS Version: {version_str}",
                description=(
                    f"The device is running iOS {version_str}, which is more than 2 major "
                    f"versions behind the current iOS {CURRENT_IOS_MAJOR}. This version "
                    f"likely contains unpatched vulnerabilities that are actively exploited."
                ),
                evidence={
                    "installed_version": version_str,
                    "current_major": CURRENT_IOS_MAJOR,
                    "versions_behind": CURRENT_IOS_MAJOR - major,
                },
                remediation=(
                    "Update iOS as soon as possible via Settings > General > Software Update. "
                    "Running outdated iOS increases risk of exploitation by known CVEs."
                ),
            )
        )

    # Check against known minimum safe patch versions per major branch
    if major in MINIMUM_SAFE_IOS_VERSIONS:
        min_safe = MINIMUM_SAFE_IOS_VERSIONS[major]
        if version_tuple < min_safe:
            min_str = ".".join(str(x) for x in min_safe if x or True)
            # Build clean version string
            min_display = f"{min_safe[0]}.{min_safe[1]}" + (
                f".{min_safe[2]}" if min_safe[2] else ""
            )
            findings.append(
                _make_finding(
                    severity="high",
                    category="ios_version",
                    title=f"iOS {version_str} Has Known Unpatched CVEs",
                    description=(
                        f"The device is running iOS {version_str}. The minimum safe version "
                        f"for the iOS {major}.x branch is {min_display}. "
                        f"Known critical CVEs include WebKit RCE, kernel privilege escalation, "
                        f"and Bluetooth vulnerabilities patched in subsequent releases."
                    ),
                    evidence={
                        "installed_version": version_str,
                        "minimum_safe_version": min_display,
                        "major_branch": major,
                    },
                    remediation=(
                        f"Update to iOS {min_display} or later via "
                        "Settings > General > Software Update."
                    ),
                )
            )

    return findings


def _check_jailbreak(device_info: dict, syslog_lines: list) -> list:
    """Detect jailbreak indicators from device info and syslog."""
    findings = []
    jb_indicators: list = []

    # Check syslog for known jailbreak strings
    jb_syslog_hits: dict = {}
    for line in syslog_lines:
        for jb_str in JAILBREAK_STRINGS:
            if jb_str.lower() in line.lower():
                jb_syslog_hits.setdefault(jb_str, []).append(line[:200])

    if jb_syslog_hits:
        all_matches = {k: v[:3] for k, v in jb_syslog_hits.items()}  # cap evidence
        findings.append(
            _make_finding(
                severity="critical",
                category="jailbreak",
                title="Jailbreak Strings Detected in Device Syslog",
                description=(
                    "The device syslog contains strings associated with known iOS jailbreak "
                    "tools and frameworks. This strongly suggests the device has been "
                    "jailbroken, which disables Apple's security model and exposes the device "
                    "to malware, spyware, and unauthorized access."
                ),
                evidence={"matched_strings": all_matches},
                remediation=(
                    "Restore the device to factory settings and reinstall a clean version of iOS. "
                    "Go to Settings > General > Transfer or Reset iPhone > Erase All Content and Settings. "
                    "Use iTunes/Finder to perform a full restore if the device is unresponsive."
                ),
            )
        )

    # Check iOS version for known jailbreak-prone versions
    version_str = device_info.get("ProductVersion", "")
    if version_str:
        version_tuple = _parse_ios_version(version_str)
        major = version_tuple[0]
        # checkra1n supports A8–A11 chips up to iOS 14.x
        # Versions below 15 are highly susceptible to public jailbreaks
        if major <= 14:
            findings.append(
                _make_finding(
                    severity="high",
                    category="jailbreak",
                    title=f"iOS {version_str} Is Susceptible to Public Jailbreaks",
                    description=(
                        f"iOS {version_str} has multiple publicly available jailbreaks "
                        f"(checkra1n, unc0ver, Taurine). Even without confirmed jailbreak "
                        f"evidence, the device may have been compromised via one of these tools."
                    ),
                    evidence={
                        "ios_version": version_str,
                        "known_jailbreaks": ["checkra1n", "unc0ver", "Taurine", "Odyssey"],
                    },
                    remediation=(
                        "Update to the latest iOS version to eliminate available jailbreak vectors. "
                        "Settings > General > Software Update."
                    ),
                )
            )

    return findings


def _check_installed_apps(apps: list) -> list:
    """
    Analyze installed apps for:
    - Known stalkerware bundle IDs
    - Sideloaded app indicators
    - Typosquatting of legitimate apps
    """
    findings = []

    # Stalkerware check
    stalkerware_found = []
    for app in apps:
        bid = app.get("BundleID", "").lower()
        if bid in STALKERWARE_BUNDLE_IDS:
            stalkerware_found.append(app)

    if stalkerware_found:
        findings.append(
            _make_finding(
                severity="critical",
                category="stalkerware",
                title=f"Known Stalkerware/Spyware App(s) Detected ({len(stalkerware_found)} found)",
                description=(
                    "One or more apps with bundle IDs matching known stalkerware or spyware "
                    "products were found on this device. These apps are designed to covertly "
                    "monitor calls, messages, location, and other sensitive data without the "
                    "device owner's knowledge."
                ),
                evidence={
                    "apps": [
                        {
                            "BundleID": a.get("BundleID"),
                            "DisplayName": a.get("CFBundleDisplayName"),
                            "Version": a.get("CFBundleVersion"),
                        }
                        for a in stalkerware_found
                    ]
                },
                remediation=(
                    "Immediately delete the identified app(s). "
                    "Go to Settings > General > iPhone Storage and uninstall the app. "
                    "Also go to Settings > General > VPN & Device Management and remove any "
                    "unknown configuration profiles. "
                    "Consider performing a factory reset for full remediation."
                ),
            )
        )

    # Sideloaded app detection
    sideloaded_found = []
    for app in apps:
        bid = app.get("BundleID", "")
        if _is_sideloaded_indicator(bid):
            sideloaded_found.append(app)

    if sideloaded_found:
        findings.append(
            _make_finding(
                severity="medium",
                category="sideloaded_app",
                title=f"Potentially Sideloaded App(s) Detected ({len(sideloaded_found)} found)",
                description=(
                    "Apps with bundle ID patterns suggesting enterprise sideloading or "
                    "unofficial distribution were found. Sideloaded apps bypass App Store "
                    "review and may contain malicious code."
                ),
                evidence={
                    "apps": [
                        {
                            "BundleID": a.get("BundleID"),
                            "DisplayName": a.get("CFBundleDisplayName"),
                        }
                        for a in sideloaded_found[:10]  # cap evidence at 10
                    ]
                },
                remediation=(
                    "Review each listed app and uninstall any you do not recognize or trust. "
                    "Check Settings > General > VPN & Device Management for enterprise "
                    "provisioning profiles and remove any that are unknown."
                ),
            )
        )

    # Typosquatting detection
    typosquat_found = []
    for app in apps:
        bid = app.get("BundleID", "")
        display = app.get("CFBundleDisplayName", "")
        for legit_bid, legit_name in LEGITIMATE_APP_BUNDLES:
            if bid == legit_bid:
                continue  # it IS the legitimate app
            # Check bundle ID similarity
            bid_distance = _levenshtein(bid, legit_bid)
            name_distance = _levenshtein(display.lower(), legit_name.lower())
            if bid_distance <= 3 or (display and name_distance <= 2):
                typosquat_found.append(
                    {
                        "suspicious_bundle": bid,
                        "suspicious_name": display,
                        "similar_to_bundle": legit_bid,
                        "similar_to_name": legit_name,
                        "bundle_edit_distance": bid_distance,
                        "name_edit_distance": name_distance,
                    }
                )

    if typosquat_found:
        findings.append(
            _make_finding(
                severity="high",
                category="typosquatting",
                title=f"Potential App Typosquatting Detected ({len(typosquat_found)} suspicious apps)",
                description=(
                    "Apps were found with bundle IDs or display names very similar to "
                    "well-known legitimate apps. This is a common technique used by "
                    "malicious apps to impersonate trusted software."
                ),
                evidence={"suspicious_apps": typosquat_found[:10]},
                remediation=(
                    "Review each flagged app carefully. If you did not intentionally install "
                    "it, delete it immediately via Settings > General > iPhone Storage. "
                    "Only install apps directly from the official App Store."
                ),
            )
        )

    return findings


def _check_mdm_profiles(device_info: dict, syslog_lines: list) -> list:
    """
    Detect MDM (Mobile Device Management) profile indicators.
    MDM profiles can grant remote control, surveillance, and data access.
    """
    findings = []
    mdm_indicators: list = []

    # Check syslog for MDM activity
    mdm_patterns = [
        "MDMClient",
        "com.apple.managedconfiguration",
        "MCInstallation",
        "ManagedPreferences",
        "MobileDeviceManagement",
        "MDMProfileInstall",
        "ConfigurationProfile",
    ]
    for line in syslog_lines:
        for pattern in mdm_patterns:
            if pattern.lower() in line.lower():
                mdm_indicators.append({"pattern": pattern, "log_excerpt": line[:200]})
                break

    if mdm_indicators:
        findings.append(
            _make_finding(
                severity="high",
                category="mdm_profile",
                title="MDM Profile Activity Detected in Syslog",
                description=(
                    "Mobile Device Management (MDM) activity was observed in the device syslog. "
                    "MDM profiles allow remote parties to monitor device activity, install apps, "
                    "read emails, track location, and access encrypted communications. "
                    "Unless this device is enrolled in a known corporate MDM, this is suspicious."
                ),
                evidence={"mdm_log_hits": mdm_indicators[:5]},
                remediation=(
                    "Go to Settings > General > VPN & Device Management to review all installed "
                    "configuration profiles and MDM enrollments. "
                    "Remove any profiles you do not recognize or that were not installed by your "
                    "organization's IT department. "
                    "If uncertain, perform a factory reset: Settings > General > Transfer or Reset iPhone."
                ),
            )
        )

    # Check device info for supervised mode (common with MDM)
    if device_info.get("IsSupervised", "").lower() == "true":
        findings.append(
            _make_finding(
                severity="high",
                category="mdm_profile",
                title="Device Is in Supervised Mode",
                description=(
                    "The device reports as 'Supervised', which means an MDM solution has "
                    "been granted elevated control over the device. Supervised mode allows "
                    "complete remote management including silent app installation, network "
                    "traffic interception, and data access."
                ),
                evidence={"IsSupervised": "true"},
                remediation=(
                    "If this device is not a corporate-managed device, supervised mode is a "
                    "major red flag. Remove MDM profiles via Settings > General > VPN & Device "
                    "Management, or perform a full factory restore via iTunes/Finder to remove "
                    "the supervision lock."
                ),
            )
        )

    return findings


def _check_syslog(syslog_lines: list) -> list:
    """
    Scan captured syslog for privacy access, exploit, and network anomalies.
    """
    findings = []

    if not syslog_lines:
        findings.append(
            _make_finding(
                severity="info",
                category="syslog",
                title="No Syslog Data Captured",
                description="Syslog capture returned no lines. The device may be locked or disconnected.",
                evidence={},
                remediation="Ensure the device is unlocked and trusted for this computer, then re-scan.",
            )
        )
        return findings

    # Privacy-sensitive access
    privacy_hits: dict = {}
    for line in syslog_lines:
        for pattern, access_type, description in SYSLOG_PRIVACY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                privacy_hits.setdefault(access_type, []).append(line[:200])

    for access_type, hit_lines in privacy_hits.items():
        severity = "medium"
        if access_type in ("microphone", "camera", "keychain"):
            severity = "high"
        findings.append(
            _make_finding(
                severity=severity,
                category="privacy_access",
                title=f"Unexpected {access_type.title()} Access Detected in Syslog",
                description=(
                    f"The device syslog contains evidence of {access_type} access. "
                    f"While some access may be legitimate, unexpected background access "
                    f"can indicate surveillance software or malicious apps."
                ),
                evidence={"access_type": access_type, "log_samples": hit_lines[:3]},
                remediation=(
                    f"Review which apps have {access_type} permission in "
                    f"Settings > Privacy & Security > {access_type.title()}. "
                    f"Revoke access for any apps you don't recognize or trust."
                ),
            )
        )

    # Exploit / malicious activity patterns
    exploit_hits: list = []
    for line in syslog_lines:
        for pattern, exploit_type, description in SYSLOG_EXPLOIT_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                exploit_hits.append(
                    {
                        "type": exploit_type,
                        "description": description,
                        "log_excerpt": line[:200],
                    }
                )

    if exploit_hits:
        findings.append(
            _make_finding(
                severity="critical",
                category="exploit_activity",
                title=f"Suspicious Exploit Activity in Syslog ({len(exploit_hits)} events)",
                description=(
                    "The device syslog contains strings associated with known exploit frameworks, "
                    "jailbreak tools, or dynamic instrumentation. This may indicate active "
                    "compromise, spyware, or forensic tools running on the device."
                ),
                evidence={"events": exploit_hits[:5]},
                remediation=(
                    "Immediately backup important data and perform a factory reset. "
                    "Settings > General > Transfer or Reset iPhone > Erase All Content and Settings. "
                    "Use iTunes/Finder for a full DFU restore to ensure clean OS installation."
                ),
            )
        )

    # Suspicious network activity
    suspicious_network: list = []
    network_line_pattern = re.compile(
        r"(https?://|tcp|udp|connect|socket|nw_connection)", re.IGNORECASE
    )
    for line in syslog_lines:
        if network_line_pattern.search(line):
            for domain_pat in SUSPICIOUS_DOMAIN_PATTERNS:
                if re.search(domain_pat, line, re.IGNORECASE):
                    suspicious_network.append(line[:200])
                    break

    if suspicious_network:
        findings.append(
            _make_finding(
                severity="high",
                category="network_anomaly",
                title=f"Suspicious Network Activity in Syslog ({len(suspicious_network)} events)",
                description=(
                    "Network connections to suspicious domains or IP patterns were found in "
                    "the device syslog. This may indicate data exfiltration, C2 communication, "
                    "or ad/tracking SDKs with unusual behavior."
                ),
                evidence={"network_events": suspicious_network[:5]},
                remediation=(
                    "Review network-enabled apps in Settings > Privacy & Security > Local Network "
                    "and consider using a VPN or DNS filter (e.g., NextDNS) to block suspicious "
                    "domains. If exfiltration is suspected, perform a factory reset."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Main scan() entry point
# ---------------------------------------------------------------------------

def scan() -> dict:
    """
    Run the iOS security scan and return a ScanResult dict.

    Checks performed:
      1. Device connection (skip if not connected)
      2. Device info collection
      3. iOS version / CVE check
      4. Jailbreak detection
      5. Installed apps analysis (stalkerware, sideloaded, typosquatting)
      6. MDM profile detection
      7. Syslog analysis
    """
    start_time = datetime.utcnow()

    # --- Pre-flight: check tooling ---
    if not check_libimobiledevice_installed():
        return {
            "module": MODULE_NAME,
            "status": "error",
            "findings": [],
            "metadata": {"scan_time": datetime.utcnow().isoformat() + "Z"},
            "error": (
                "libimobiledevice is not installed. "
                "Install via Homebrew: brew install libimobiledevice ideviceinstaller"
            ),
        }

    # --- Check 1: Device connection ---
    if not is_device_connected():
        return {
            "module": MODULE_NAME,
            "status": "skipped",
            "findings": [],
            "metadata": {
                "reason": "No iPhone connected via USB",
                "scan_time": datetime.utcnow().isoformat() + "Z",
            },
            "error": None,
        }

    all_findings: list = []
    metadata: dict = {}
    scan_error: Any = None

    try:
        # --- Check 2: Device info ---
        device_info = get_device_info()
        metadata["device_info"] = {
            "DeviceName": device_info.get("DeviceName", "Unknown"),
            "ProductType": device_info.get("ProductType", "Unknown"),
            "ProductVersion": device_info.get("ProductVersion", "Unknown"),
        }
        all_findings.extend(_check_device_info(device_info))

        # --- Check 3: iOS version CVE check ---
        all_findings.extend(_check_ios_version(device_info))

        # --- Check 4: Installed apps ---
        apps = get_installed_apps()
        metadata["installed_app_count"] = len(apps)
        all_findings.extend(_check_installed_apps(apps))

        # --- Check 5: Syslog capture + analysis ---
        syslog_lines = get_syslog_snapshot(duration_seconds=10)
        metadata["syslog_lines_captured"] = len(syslog_lines)

        # Jailbreak: uses both device_info and syslog
        all_findings.extend(_check_jailbreak(device_info, syslog_lines))

        # MDM profile detection
        all_findings.extend(_check_mdm_profiles(device_info, syslog_lines))

        # Full syslog analysis
        all_findings.extend(_check_syslog(syslog_lines))

    except Exception as exc:  # noqa: BLE001
        scan_error = str(exc)

    end_time = datetime.utcnow()
    metadata["scan_duration_seconds"] = (end_time - start_time).total_seconds()
    metadata["scan_time"] = end_time.isoformat() + "Z"
    metadata["findings_count"] = len(all_findings)

    return {
        "module": MODULE_NAME,
        "status": "error" if scan_error else "success",
        "findings": all_findings,
        "metadata": metadata,
        "error": scan_error,
    }
