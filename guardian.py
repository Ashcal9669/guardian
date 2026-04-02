#!/usr/bin/env python3
"""
guardian.py — macOS + iOS Full System Security Scanner
Main CLI entry point.

Usage:
    python guardian.py [options]
      --output DIR     Output directory for HTML report (default: ~/Desktop)
      --no-ios         Skip iPhone scanning
      --quick          Skip slow filesystem scans
      --modules LIST   Comma-separated list of modules to run
      --help
"""

import argparse
import importlib
import json
import os
import platform
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RED    = "\033[91m"
BOLD   = "\033[1m"


def _c(colour: str, text: str) -> str:
    """Wrap *text* in an ANSI colour code if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{colour}{text}{RESET}"
    return text


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
 ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
 ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
 ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
  macOS + iOS Full System Security Scanner | M-Series | v1.0
"""


def print_banner() -> None:
    print(_c(CYAN, BANNER))


# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

def _check_python_version() -> None:
    if sys.version_info < (3, 9):
        print(_c(RED, f"[✗] Python 3.9+ required. Running: {sys.version}"))
        sys.exit(1)


def _check_macos() -> None:
    if sys.platform != "darwin":
        print(_c(RED, f"[✗] Guardian is macOS-only. Detected platform: {sys.platform}"))
        sys.exit(1)


def _check_apple_silicon() -> None:
    """Warn if not running on Apple Silicon (M-series)."""
    processor = platform.processor()
    if processor and "arm" in processor.lower():
        return
    # Fallback via sysctl
    try:
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        brand = result.stdout.strip().lower()
        if "apple" in brand:
            return
    except Exception:
        pass
    print(_c(YELLOW, "[!] Warning: Guardian is optimised for Apple Silicon (M-series). "
                      "Some checks may behave differently on Intel Macs."))


def _check_third_party_packages() -> dict:
    """
    Check for yara-python and psutil.
    Returns dict: {'yara': bool, 'psutil': bool}
    """
    availability = {"yara": False, "psutil": False}
    missing = []

    try:
        import yara  # noqa: F401
        availability["yara"] = True
    except ImportError:
        missing.append("yara-python")

    try:
        import psutil  # noqa: F401
        availability["psutil"] = True
    except ImportError:
        missing.append("psutil")

    if missing:
        print(_c(YELLOW, f"[!] Optional packages not installed: {', '.join(missing)}"))
        print(_c(YELLOW,  "    Some scan capabilities will be reduced."))
        print(_c(YELLOW,  "    To install:"))
        print(_c(YELLOW,  "      pip3 install " + " ".join(missing)))

    return availability


def _check_libimobiledevice() -> bool:
    """Check if ideviceinfo is on PATH."""
    import shutil
    if shutil.which("ideviceinfo") is not None:
        return True
    print(_c(YELLOW, "[!] libimobiledevice not found — iOS scanning will be skipped."))
    print(_c(YELLOW, "    Install with: brew install libimobiledevice"))
    return False


def _check_sudo() -> None:
    """Warn if not running as root."""
    if os.geteuid() != 0:
        print(_c(YELLOW, "[!] Not running as root. Some checks may have reduced coverage."))
        print(_c(YELLOW, "    Re-run with: sudo python3 guardian.py"))


def run_prerequisite_checks() -> dict:
    """Run all prerequisite checks. Returns context dict."""
    _check_python_version()
    _check_macos()
    _check_apple_silicon()
    pkg = _check_third_party_packages()
    libimd = _check_libimobiledevice()
    _check_sudo()
    print()
    return {
        "yara_available": pkg["yara"],
        "psutil_available": pkg["psutil"],
        "libimobiledevice_available": libimd,
    }


# ---------------------------------------------------------------------------
# IOC loading
# ---------------------------------------------------------------------------

def load_ioc_database() -> dict:
    """Load ioc/known_bad.json. Returns empty structure on failure."""
    ioc_path = Path(__file__).parent / "ioc" / "known_bad.json"
    default: dict = {
        "malicious_ips": [],
        "malicious_domains": [],
        "malicious_process_names": [],
    }
    if not ioc_path.exists():
        return default
    try:
        with open(ioc_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Normalise to sets for O(1) lookup (stored as lists in file)
        return {
            "malicious_ips": set(data.get("malicious_ips", [])),
            "malicious_domains": set(data.get("malicious_domains", [])),
            "malicious_process_names": set(
                n.lower() for n in data.get("malicious_process_names", [])
            ),
        }
    except Exception as exc:
        print(_c(YELLOW, f"[!] Could not load IOC database: {exc}"))
        return default


# ---------------------------------------------------------------------------
# IOC cross-reference
# ---------------------------------------------------------------------------

def _crossref_findings(findings: list, ioc_db: dict) -> list:
    """
    Upgrade severity to 'critical' for any finding whose evidence matches
    known-bad IPs, domains, or process names.
    """
    malicious_ips = ioc_db.get("malicious_ips", set())
    malicious_domains = ioc_db.get("malicious_domains", set())
    malicious_procs = ioc_db.get("malicious_process_names", set())

    for finding in findings:
        ev = finding.get("evidence", {})

        # Network: check remote_ip / remote_addr / domain fields
        for ip_key in ("remote_ip", "ip", "address", "remote_addr"):
            val = ev.get(ip_key, "")
            if val and val in malicious_ips:
                finding["severity"] = "critical"
                finding.setdefault("ioc_match", []).append(f"malicious_ip:{val}")
                break

        for domain_key in ("domain", "remote_host", "hostname", "host"):
            val = ev.get(domain_key, "")
            if val and val in malicious_domains:
                finding["severity"] = "critical"
                finding.setdefault("ioc_match", []).append(f"malicious_domain:{val}")
                break

        # Process: check command / process_name fields
        for proc_key in ("command", "process_name", "name"):
            val = ev.get(proc_key, "")
            if val:
                val_lower = os.path.basename(val.split()[0]).lower() if val.split() else ""
                for mp in malicious_procs:
                    if mp in val_lower:
                        finding["severity"] = "critical"
                        finding.setdefault("ioc_match", []).append(f"malicious_process:{mp}")
                        break

    return findings


def crossref_all_results(results: dict, ioc_db: dict) -> None:
    """Apply IOC cross-referencing to all module results in-place."""
    for module_name, result in results.items():
        if isinstance(result, dict) and "findings" in result:
            result["findings"] = _crossref_findings(result["findings"], ioc_db)


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------

def run_yara_scan(yara_available: bool) -> list:
    """
    If yara-python is available, load the rule file and scan key directories.
    Returns a list of finding dicts (source='yara').
    """
    if not yara_available:
        return []

    rules_path = Path(__file__).parent / "ioc" / "yara_rules.yar"
    if not rules_path.exists():
        print(_c(YELLOW, f"[!] YARA rules file not found: {rules_path}"))
        return []

    try:
        import yara  # type: ignore

        rules = yara.compile(filepath=str(rules_path))
    except Exception as exc:
        print(_c(RED, f"[✗] Failed to compile YARA rules: {exc}"))
        return []

    scan_dirs = [
        "/Applications",
        os.path.expanduser("~/Library"),
        "/tmp",
        "/var/tmp",
    ]

    findings: list = []
    fid_counter = 0

    for directory in scan_dirs:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory, followlinks=False):
            # Don't recurse into deeply nested subdirs of ~/Library to keep it fast
            depth = root[len(directory):].count(os.sep)
            if depth > 4:
                dirs.clear()
                continue
            for fname in files:
                fpath = os.path.join(root, fname)
                if not os.path.isfile(fpath):
                    continue
                # Skip very large files (> 50 MB)
                try:
                    if os.path.getsize(fpath) > 50 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                try:
                    matches = rules.match(fpath, timeout=10)
                    for match in matches:
                        fid_counter += 1
                        findings.append({
                            "id": f"yara_{fid_counter:03d}",
                            "severity": "high",
                            "category": "malware",
                            "title": f"YARA rule match: {match.rule}",
                            "description": (
                                f"File '{fpath}' matched YARA rule '{match.rule}' "
                                f"(namespace: {match.namespace})."
                            ),
                            "evidence": {
                                "file": fpath,
                                "rule": match.rule,
                                "namespace": match.namespace,
                                "tags": list(match.tags),
                                "strings": [
                                    {"offset": s.offset, "identifier": s.identifier}
                                    for s in match.strings[:10]
                                ],
                            },
                            "remediation": (
                                f"Investigate '{fpath}'. If confirmed malicious, quarantine "
                                "and delete. Check for related persistence mechanisms."
                            ),
                            "source": "yara",
                        })
                except yara.TimeoutError:
                    pass
                except yara.Error:
                    pass
                except Exception:
                    pass

    return findings


# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

def _load_module(module_path: str):
    """
    Dynamically import a module under the guardian package tree.
    module_path is e.g. 'mac.integrity'.
    """
    full_path = f"modules.{module_path}"
    # Ensure guardian package root is on sys.path
    guardian_root = str(Path(__file__).parent)
    if guardian_root not in sys.path:
        sys.path.insert(0, guardian_root)
    return importlib.import_module(full_path)


def _run_module(module_path: str) -> dict:
    """Import and call scan() on a module. Returns a result dict."""
    try:
        mod = _load_module(module_path)
        if not hasattr(mod, "scan"):
            return {
                "module": module_path,
                "status": "error",
                "findings": [],
                "metadata": {},
                "error": f"Module '{module_path}' has no scan() function.",
            }
        return mod.scan()
    except ModuleNotFoundError as exc:
        return {
            "module": module_path,
            "status": "error",
            "findings": [],
            "metadata": {},
            "error": f"Module not found: {exc}",
        }
    except Exception as exc:
        return {
            "module": module_path,
            "status": "error",
            "findings": [],
            "metadata": {},
            "error": str(exc),
        }


def _print_module_start(name: str) -> None:
    print(_c(YELLOW, f"  [→] Scanning: {name}..."), flush=True)


def _print_module_done(name: str, n_findings: int, duration: float) -> None:
    print(_c(GREEN, f"  [✓] {name}: {n_findings} findings ({duration:.1f}s)"))


def _print_module_skipped(name: str, reason: str) -> None:
    print(_c(YELLOW, f"  [!] {name}: skipped - {reason}"))


def _print_module_error(name: str, message: str) -> None:
    print(_c(RED, f"  [✗] {name}: error - {message}"))


# ---------------------------------------------------------------------------
# macOS version
# ---------------------------------------------------------------------------

def _get_macos_version() -> str:
    try:
        result = subprocess.run(
            ["sw_vers"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return platform.mac_ver()[0] or "unknown"


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOURS = {
    "critical": RED + BOLD,
    "high":     RED,
    "medium":   YELLOW,
    "low":      CYAN,
    "info":     RESET,
}


def _count_severities(all_results: dict) -> dict:
    counts: dict = {s: 0 for s in SEVERITY_ORDER}
    for result in all_results.values():
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings", []):
            sev = finding.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
    return counts


def print_summary(all_results: dict) -> None:
    counts = _count_severities(all_results)
    total = sum(counts.values())

    print()
    print(_c(BOLD, "=" * 56))
    print(_c(BOLD, "  SCAN SUMMARY"))
    print(_c(BOLD, "=" * 56))
    print(f"  {'Severity':<12}  {'Count':>6}")
    print(f"  {'-'*12}  {'-'*6}")
    for sev in SEVERITY_ORDER:
        colour = SEVERITY_COLOURS.get(sev, RESET)
        count = counts[sev]
        label = sev.upper()
        if sys.stdout.isatty():
            print(f"  {colour}{label:<12}{RESET}  {count:>6}")
        else:
            print(f"  {label:<12}  {count:>6}")
    print(f"  {'-'*12}  {'-'*6}")
    print(f"  {'TOTAL':<12}  {total:>6}")
    print(_c(BOLD, "=" * 56))
    print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="guardian",
        description="macOS + iOS Full System Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python guardian.py\n"
            "  python guardian.py --quick --no-ios\n"
            "  python guardian.py --output /tmp/reports\n"
            "  python guardian.py --modules mac.integrity,mac.processes\n"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        default=os.path.expanduser("~/Desktop"),
        help="Output directory for HTML report (default: ~/Desktop)",
    )
    parser.add_argument(
        "--no-ios",
        action="store_true",
        default=False,
        help="Skip iPhone scanning",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        default=False,
        help="Skip slow filesystem scans",
    )
    parser.add_argument(
        "--modules",
        metavar="LIST",
        default=None,
        help="Comma-separated list of modules to run (e.g. mac.integrity,mac.processes)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

# All modules in canonical run order
ALL_MODULES_ORDERED = [
    "mac.integrity",
    "mac.users",
    "mac.processes",
    "mac.network",
    "mac.persistence",
    "mac.filesystem",
    "mac.browsers",
    "ios.scanner",
]

# Modules that can run concurrently (after integrity/persistence)
PARALLEL_MODULES = {"mac.processes", "mac.network", "mac.users", "mac.browsers"}

# Modules that must run sequentially first
SEQUENTIAL_FIRST = ["mac.integrity", "mac.persistence"]


def main(argv=None) -> int:
    args = parse_args(argv)

    print_banner()

    # Prerequisite checks
    ctx = run_prerequisite_checks()

    # Determine which modules to run
    if args.modules:
        requested = [m.strip() for m in args.modules.split(",") if m.strip()]
        # Validate requested modules
        unknown = [m for m in requested if m not in ALL_MODULES_ORDERED]
        if unknown:
            print(_c(RED, f"[✗] Unknown modules: {', '.join(unknown)}"))
            print(f"    Valid modules: {', '.join(ALL_MODULES_ORDERED)}")
            return 1
        modules_to_run = requested
    else:
        modules_to_run = list(ALL_MODULES_ORDERED)

    # Apply flags
    skip_reasons: dict = {}
    if args.quick and "mac.filesystem" in modules_to_run:
        modules_to_run.remove("mac.filesystem")
        skip_reasons["mac.filesystem"] = "skipped via --quick flag"

    if args.no_ios and "ios.scanner" in modules_to_run:
        modules_to_run.remove("ios.scanner")
        skip_reasons["ios.scanner"] = "skipped via --no-ios flag"

    # Check if iOS device is actually connected
    if "ios.scanner" in modules_to_run:
        if not ctx["libimobiledevice_available"]:
            modules_to_run.remove("ios.scanner")
            skip_reasons["ios.scanner"] = "libimobiledevice not installed"
        else:
            try:
                guardian_root = str(Path(__file__).parent)
                if guardian_root not in sys.path:
                    sys.path.insert(0, guardian_root)
                from modules.ios.connector import is_device_connected
                if not is_device_connected():
                    modules_to_run.remove("ios.scanner")
                    skip_reasons["ios.scanner"] = "no iOS device connected"
            except Exception as exc:
                modules_to_run.remove("ios.scanner")
                skip_reasons["ios.scanner"] = f"connector error: {exc}"

    # Load IOC database
    ioc_db = load_ioc_database()

    # Collect all results
    all_results: dict = {}
    scan_start = time.time()

    # Print any pre-determined skips
    for module_name in ALL_MODULES_ORDERED:
        if module_name in skip_reasons:
            _print_module_skipped(module_name, skip_reasons[module_name])

    try:
        # --- Phase 1: Sequential first modules ---
        seq_first = [m for m in SEQUENTIAL_FIRST if m in modules_to_run]
        for module_name in seq_first:
            _print_module_start(module_name)
            t0 = time.time()
            result = _run_module(module_name)
            elapsed = time.time() - t0
            all_results[module_name] = result
            status = result.get("status", "error")
            n = len(result.get("findings", []))
            if status == "error":
                _print_module_error(module_name, result.get("error", "unknown error"))
            elif status == "skipped":
                reason = result.get("metadata", {}).get("reason", "module reported skip")
                _print_module_skipped(module_name, reason)
            else:
                _print_module_done(module_name, n, elapsed)

        # --- Phase 2: Parallel independent modules ---
        parallel = [m for m in modules_to_run if m in PARALLEL_MODULES]
        if parallel:
            with ThreadPoolExecutor(max_workers=min(len(parallel), 4)) as executor:
                future_to_module = {
                    executor.submit(_run_module, m): m for m in parallel
                }
                # Print starts before submitting (best-effort ordering)
                for m in parallel:
                    _print_module_start(m)

                for future in as_completed(future_to_module):
                    module_name = future_to_module[future]
                    t_done = time.time()
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "module": module_name,
                            "status": "error",
                            "findings": [],
                            "metadata": {},
                            "error": str(exc),
                        }
                    all_results[module_name] = result
                    elapsed = t_done - scan_start
                    status = result.get("status", "error")
                    n = len(result.get("findings", []))
                    if status == "error":
                        _print_module_error(module_name, result.get("error", "unknown error"))
                    elif status == "skipped":
                        reason = result.get("metadata", {}).get("reason", "module reported skip")
                        _print_module_skipped(module_name, reason)
                    else:
                        _print_module_done(module_name, n, elapsed)

        # --- Phase 3: Sequential remaining modules ---
        sequential_remaining = [
            m for m in modules_to_run
            if m not in SEQUENTIAL_FIRST and m not in PARALLEL_MODULES
        ]
        for module_name in sequential_remaining:
            _print_module_start(module_name)
            t0 = time.time()
            result = _run_module(module_name)
            elapsed = time.time() - t0
            all_results[module_name] = result
            status = result.get("status", "error")
            n = len(result.get("findings", []))
            if status == "error":
                _print_module_error(module_name, result.get("error", "unknown error"))
            elif status == "skipped":
                reason = result.get("metadata", {}).get("reason", "module reported skip")
                _print_module_skipped(module_name, reason)
            else:
                _print_module_done(module_name, n, elapsed)

    except KeyboardInterrupt:
        print()
        print(_c(YELLOW, "\n[!] Scan interrupted by user. Generating partial report..."))

    # --- YARA scan (after filesystem, if available) ---
    if ctx["yara_available"] and "mac.filesystem" in modules_to_run:
        print(_c(YELLOW, "  [→] Running YARA scan on key directories..."), flush=True)
        t0 = time.time()
        yara_findings = run_yara_scan(yara_available=True)
        elapsed = time.time() - t0
        # Merge into filesystem results if present, else create standalone entry
        if "mac.filesystem" in all_results:
            all_results["mac.filesystem"].setdefault("findings", []).extend(yara_findings)
        else:
            all_results["yara"] = {
                "module": "yara",
                "status": "success",
                "findings": yara_findings,
                "metadata": {"duration_s": round(elapsed, 2)},
                "error": None,
            }
        print(_c(GREEN, f"  [✓] YARA scan: {len(yara_findings)} matches ({elapsed:.1f}s)"))

    # --- IOC cross-referencing ---
    crossref_all_results(all_results, ioc_db)

    # --- Collect device info for report ---
    device_info: dict = {}
    if "ios.scanner" in all_results:
        try:
            from modules.ios.connector import get_device_info
            device_info = get_device_info()
        except Exception:
            pass

    macos_version = _get_macos_version()

    # --- Report generation ---
    report_path: str = ""
    try:
        guardian_root = str(Path(__file__).parent)
        if guardian_root not in sys.path:
            sys.path.insert(0, guardian_root)
        from report.generator import generate_report  # type: ignore

        output_dir = Path(args.output).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = generate_report(
            results=all_results,
            output_dir=str(output_dir),
            macos_version=macos_version,
            device_info=device_info,
        )
        print(_c(GREEN, f"\n[✓] Report saved: {report_path}"))

        # Auto-open in browser
        try:
            subprocess.run(["open", report_path], check=False)
        except Exception:
            pass

    except ModuleNotFoundError:
        print(_c(YELLOW, "\n[!] report.generator module not found — skipping HTML report."))
    except Exception as exc:
        print(_c(RED, f"\n[✗] Report generation failed: {exc}"))

    # --- Summary table ---
    print_summary(all_results)

    total_elapsed = time.time() - scan_start
    print(_c(CYAN, f"  Scan completed in {total_elapsed:.1f}s\n"))

    # Return non-zero exit code if any critical findings found
    counts = _count_severities(all_results)
    if counts.get("critical", 0) > 0:
        return 2
    if counts.get("high", 0) > 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(_c(YELLOW, "\n[!] Aborted."))
        sys.exit(130)
