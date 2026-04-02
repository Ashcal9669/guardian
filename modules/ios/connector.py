"""
connector.py — libimobiledevice wrapper for iOS device communication.

Uses libimobiledevice CLI tools installed via Homebrew:
  ideviceinfo, idevicesyslog, ideviceinstaller, idevicebackup2, idevicediagnostics
No Apple ID required.
"""

import shutil
import subprocess
import threading
import time
from typing import Optional

REQUIRED_TOOLS = ("ideviceinfo", "ideviceinstaller")


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def check_libimobiledevice_installed() -> bool:
    """Return True if the required libimobiledevice binaries are present on PATH."""
    return all(shutil.which(tool) is not None for tool in REQUIRED_TOOLS)


# ---------------------------------------------------------------------------
# Device connection
# ---------------------------------------------------------------------------

def is_device_connected() -> bool:
    """
    Run `ideviceinfo` and return True if a device responds successfully.
    A non-zero return code means no device is reachable.
    """
    try:
        result = subprocess.run(
            ["ideviceinfo"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Device info
# ---------------------------------------------------------------------------

def get_device_info() -> dict:
    """
    Parse `ideviceinfo` output into a structured dict.

    Returns a dict with keys such as:
        DeviceName, ProductType, ProductVersion, SerialNumber,
        UniqueDeviceID, BuildVersion, CPUArchitecture, HardwareModel,
        ModelNumber, RegionInfo, SoftwareBundleVersion, WiFiAddress,
        BluetoothAddress, PhoneNumber, TimeZone
    """
    try:
        result = subprocess.run(
            ["ideviceinfo"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return {}

        info: dict = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                info[key.strip()] = value.strip()
        return info

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}


# ---------------------------------------------------------------------------
# Installed apps
# ---------------------------------------------------------------------------

def get_installed_apps() -> list:
    """
    Run `ideviceinstaller -l` and parse the app list.

    Each entry is a dict with:
        BundleID, CFBundleDisplayName, CFBundleVersion
    """
    try:
        result = subprocess.run(
            ["ideviceinstaller", "-l"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []

        apps = []
        for line in result.stdout.splitlines():
            # Format: "com.example.app, 1.0.0, ExampleApp"
            # or:     "com.example.app - ExampleApp 1.0.0"
            line = line.strip()
            if not line or line.startswith("Total:") or line.startswith("CFBundleIdentifier"):
                continue

            app: dict = {
                "BundleID": "",
                "CFBundleDisplayName": "",
                "CFBundleVersion": "",
            }

            # ideviceinstaller typically outputs CSV-like lines:
            # com.bundle.id, CFBundleVersion, CFBundleDisplayName
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3:
                app["BundleID"] = parts[0]
                app["CFBundleVersion"] = parts[1]
                app["CFBundleDisplayName"] = parts[2].strip('"').strip("'")
            elif len(parts) == 2:
                app["BundleID"] = parts[0]
                app["CFBundleDisplayName"] = parts[1].strip('"').strip("'")
            elif len(parts) == 1 and parts[0]:
                app["BundleID"] = parts[0]

            if app["BundleID"]:
                apps.append(app)

        return apps

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


# ---------------------------------------------------------------------------
# Syslog capture
# ---------------------------------------------------------------------------

def get_syslog_snapshot(duration_seconds: int = 10) -> list:
    """
    Capture syslog for *duration_seconds* using `idevicesyslog` with a timeout.
    Returns a list of log line strings.
    """
    lines: list = []
    process: Optional[subprocess.Popen] = None

    def _reader(proc: subprocess.Popen) -> None:
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                lines.append(line.rstrip("\n"))
        except Exception:
            pass

    try:
        process = subprocess.Popen(
            ["idevicesyslog"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        reader_thread = threading.Thread(target=_reader, args=(process,), daemon=True)
        reader_thread.start()
        time.sleep(duration_seconds)
    except FileNotFoundError:
        return []
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

    return lines
