"""
guardian/report/generator.py

Generates a self-contained HTML security report from Guardian scan results.
Uses only Python stdlib — no external dependencies.

Public API
----------
generate_report(scan_results, output_path, device_info=None) -> str
    Build the HTML file and return the path to it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from .template import HTML_TEMPLATE


# ── Severity ordering (worst → best) ──────────────────────────────────────────
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_SEV_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8c00",
    "medium":   "#ffd700",
    "low":      "#4fc3f7",
    "info":     "#9e9e9e",
}

_RISK_CLASS = {
    "critical": "risk-critical",
    "high":     "risk-high",
    "medium":   "risk-medium",
    "low":      "risk-low",
    "clean":    "risk-clean",
}


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_report(
    scan_results: list | dict,
    output_path: str,
    device_info: Optional[dict] = None,
) -> str:
    """
    Generate a self-contained HTML report from Guardian scan results.

    Parameters
    ----------
    scan_results : list[ScanResult]
        List of scan result dicts as defined by the Guardian data contract.
    output_path : str
        Destination path for the HTML file (including filename).
        Parent directories are created automatically if they do not exist.
    device_info : dict, optional
        Optional iOS device information dict.  Recognised keys:
            "name"  – device name / model
            "udid"  – device UDID
            "ios_version" – iOS version string

    Returns
    -------
    str
        Absolute path to the generated HTML file.
    """
    if isinstance(scan_results, dict):
        scan_results = list(scan_results.values())
    scan_results = scan_results or []

    # Collect all findings across every module
    all_findings: list[dict] = []
    for result in scan_results:
        findings = result.get("findings") or []
        all_findings.extend(findings)

    # Build each template section
    scan_date      = _build_scan_date()
    macos_version  = _build_macos_version(scan_results)
    device_html    = _build_device_info(device_info)
    summary_html   = _build_summary_stats(all_findings)
    module_html    = _build_module_status(scan_results)
    findings_json  = _build_findings_json(all_findings)

    html = HTML_TEMPLATE
    html = html.replace("{{SCAN_DATE}}",      scan_date)
    html = html.replace("{{MACOS_VERSION}}",  macos_version)
    html = html.replace("{{DEVICE_INFO}}",    device_html)
    html = html.replace("{{SUMMARY_STATS}}",  summary_html)
    html = html.replace("{{MODULE_STATUS}}",  module_html)
    html = html.replace("{{FINDINGS_JSON}}",  findings_json)

    # Write output
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path


# ── Section builders ───────────────────────────────────────────────────────────

def _build_scan_date() -> str:
    """Return a human-readable scan timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _build_macos_version(scan_results: list) -> str:
    """
    Extract macOS version from module metadata if present, else try platform.
    Falls back to 'Unknown'.
    """
    # Check every result's metadata for a version hint
    for result in scan_results:
        meta = result.get("metadata") or {}
        for key in ("macos_version", "os_version", "version"):
            val = meta.get(key)
            if val:
                return str(val)

    # Try the live system as a last resort (works when running on the host)
    try:
        import platform
        ver = platform.mac_ver()[0]
        if ver:
            return ver
    except Exception:
        pass

    return "Unknown"


def _build_device_info(device_info: Optional[dict]) -> str:
    """
    Return an HTML snippet for the iPhone line in the header meta block.
    Returns an empty string when no device is connected.
    """
    if not device_info:
        return ""

    name    = device_info.get("name") or "iPhone"
    ios_ver = device_info.get("ios_version") or ""
    udid    = device_info.get("udid") or ""

    label = name
    if ios_ver:
        label += f" (iOS {ios_ver})"

    parts = [f"iPhone connected: <strong>{_esc(label)}</strong>"]
    if udid:
        short_udid = udid[:8] + "…" if len(udid) > 8 else udid
        parts.append(
            f'<span style="font-size:0.75em;color:var(--text-muted)">'
            f"UDID: {_esc(short_udid)}</span>"
        )
    return "<div>" + " &nbsp; ".join(parts) + "</div>"


def _build_summary_stats(findings: list) -> str:
    """
    Return the HTML for the severity count tiles and the overall risk badge.
    """
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # Determine worst severity
    risk = "clean"
    for sev in _SEV_ORDER:
        if counts[sev] > 0:
            risk = sev
            break

    # Build tiles
    tiles_html = ""
    # "All" tile
    tiles_html += (
        f'<div class="severity-tile" data-sev="all" style="--tile-color:var(--text-secondary)">'
        f'  <div class="tile-count">{total}</div>'
        f'  <div class="tile-label">Total</div>'
        f"</div>"
    )
    for sev in _SEV_ORDER:
        color = _SEV_COLORS[sev]
        label = sev.capitalize()
        tiles_html += (
            f'<div class="severity-tile" data-sev="{sev}" style="--tile-color:{color}">'
            f'  <div class="tile-count">{counts[sev]}</div>'
            f'  <div class="tile-label">{label}</div>'
            f"</div>"
        )

    # Risk badge label
    if risk == "clean":
        risk_label = "Clean"
        risk_icon  = _icon_check()
    else:
        risk_label = risk.capitalize()
        risk_icon  = _icon_alert()

    risk_class = _RISK_CLASS.get(risk, "risk-clean")

    html = (
        f'<div class="summary-grid">{tiles_html}</div>'
        f'<div class="risk-banner">'
        f'  <span class="risk-label">Overall risk level:</span>'
        f'  <span class="risk-badge {risk_class}">{risk_icon} {_esc(risk_label)}</span>'
        f"</div>"
    )
    return html


def _build_module_status(scan_results: list) -> str:
    """Return the HTML pills for the module status bar."""
    if not scan_results:
        return '<span style="color:var(--text-muted);font-size:0.8125rem">No modules ran.</span>'

    pills = []
    for result in scan_results:
        module = result.get("module") or "unknown"
        status = (result.get("status") or "skipped").lower()

        css_class = {
            "success": "module-pill-success",
            "error":   "module-pill-error",
            "skipped": "module-pill-skipped",
        }.get(status, "module-pill-skipped")

        count = len(result.get("findings") or [])
        count_str = f" ({count})" if status == "success" else ""

        pills.append(
            f'<span class="module-pill {css_class}">'
            f'  <span class="pill-dot"></span>'
            f"  {_esc(module)}{_esc(count_str)}"
            f"</span>"
        )
    return "\n".join(pills)


def _build_findings_json(findings: list) -> str:
    """
    Serialise findings to a JSON array safe for inline <script> injection.
    The string is already wrapped in the closing `</script>` boundary, so we
    only need to escape the forward-slash in `</` sequences to avoid breaking
    the HTML parser.
    """
    raw = json.dumps(findings, ensure_ascii=False, default=str)
    return (
        raw
        .replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


# ── Tiny utilities ─────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    """Minimal HTML-escape for text nodes / attribute values."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _icon_check() -> str:
    return (
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="2.5" aria-hidden="true">'
        '<polyline points="20 6 9 17 4 12"/></svg>'
    )


def _icon_alert() -> str:
    return (
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="2.5" aria-hidden="true">'
        '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 '
        '1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
        '<line x1="12" y1="9" x2="12" y2="13"/>'
        '<line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    )
