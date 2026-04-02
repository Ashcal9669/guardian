"""
macOS Network Scanner
Scans network connections, listening ports, DNS configuration,
/etc/hosts integrity, and suspicious interfaces.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import time
from typing import Any


# ---------------------------------------------------------------------------
# Suspicious IP ranges: Tor exits, common C2 blocks, malicious ASNs
# These are representative ranges — extend as needed.
# ---------------------------------------------------------------------------
SUSPICIOUS_IP_RANGES: list[str] = [
    # Known Tor exit relay ranges (sample)
    "185.220.100.0/22",
    "185.220.101.0/24",
    "199.87.154.0/24",
    "162.247.72.0/22",
    "204.85.191.0/24",
    # Bulletproof hosting / known malicious ASNs
    "5.188.0.0/16",     # Selectel (abused)
    "91.108.4.0/22",    # Telegram (not malicious, but notable C2 disguise)
    "77.73.134.0/24",   # Cybercrime hosting
    "193.142.146.0/24", # Known C2 range
    "45.142.212.0/24",  # Abuse-reported
    "94.140.114.0/24",  # AdGuard DNS (flagged for policy review)
    "31.13.64.0/19",    # Meta (C2 lookalike)
    "198.54.117.0/24",  # Abuse-reported hosting
    "185.153.196.0/22", # Cybercrime range
    "89.248.160.0/19",  # Shodan scanning / abused range
    "216.239.32.0/19",  # Googlebot used for C2 disguise
    "104.21.0.0/16",    # Cloudflare (used by C2 infra)
]

_SUSPICIOUS_NETWORKS: list[ipaddress.IPv4Network] = []
for _cidr in SUSPICIOUS_IP_RANGES:
    try:
        _SUSPICIOUS_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        pass

# Ports considered normal on macOS — anything else LISTENING is flagged
SAFE_LISTEN_PORTS: set[int] = {
    22, 53, 80, 88, 111, 443, 445, 548, 631, 3283,
    5900, 8080, 8443, 24800,
}

# Clean macOS /etc/hosts baseline (minimal)
CLEAN_HOSTS_ENTRIES: set[str] = {
    "127.0.0.1\tlocalhost",
    "255.255.255.255\tbroadcasthost",
    "::1\t\t\t\tlocalhost",
    "::1             localhost",
    "127.0.0.1       localhost",
    "255.255.255.255 broadcasthost",
    "fe80::1%lo0\tlocalhost",
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
        "source": "mac.network",
    }


def _is_suspicious_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
        for net in _SUSPICIOUS_NETWORKS:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


def _parse_lsof_connections(output: str) -> list[dict]:
    """Parse lsof -i -n -P output into connection dicts."""
    conns = []
    for line in output.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        name_field = parts[-1]
        state = parts[-2] if len(parts) > 9 else ""
        # name_field looks like: 192.168.1.1:54321->1.2.3.4:443
        conns.append({
            "command": parts[0],
            "pid": parts[1],
            "user": parts[2],
            "type": parts[7] if len(parts) > 7 else "",
            "name": name_field,
            "state": state,
        })
    return conns


def _extract_remote_ip(name_field: str) -> str | None:
    """Extract remote IP from lsof name like host:port->remote:port."""
    if "->" in name_field:
        remote = name_field.split("->")[1]
        ip_part = remote.rsplit(":", 1)[0]
        return ip_part
    return None


def _extract_local_port(name_field: str) -> int | None:
    """Extract local port from lsof name."""
    try:
        local = name_field.split("->")[0] if "->" in name_field else name_field
        port_str = local.rsplit(":", 1)[-1]
        return int(port_str)
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Sub-scanners
# ---------------------------------------------------------------------------

def _scan_active_connections(findings: list, counter: list) -> tuple[list[dict], int]:
    stdout, stderr, rc = _run(["lsof", "-i", "-n", "-P"], timeout=20)
    if rc != 0 and not stdout:
        return [], 0
    conns = _parse_lsof_connections(stdout)

    flagged: list[dict] = []
    for conn in conns:
        remote_ip = _extract_remote_ip(conn["name"])
        if remote_ip and _is_suspicious_ip(remote_ip):
            counter[0] += 1
            fid = f"net_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="critical",
                category="botnet",
                title=f"Connection to suspicious IP: {remote_ip}",
                description=(
                    f"Process '{conn['command']}' (PID {conn['pid']}, user {conn['user']}) "
                    f"has an active connection to {remote_ip}, which falls within a known "
                    "malicious or Tor exit node IP range."
                ),
                evidence={
                    "command": conn["command"],
                    "pid": conn["pid"],
                    "user": conn["user"],
                    "connection": conn["name"],
                    "remote_ip": remote_ip,
                },
                remediation=(
                    f"Immediately terminate process {conn['pid']} with `kill -9 {conn['pid']}`. "
                    "Investigate the binary for malware. Block the IP at the firewall level."
                ),
            ))
            flagged.append(conn)

    return conns, len(conns)


def _scan_listening_ports(findings: list, counter: list) -> int:
    stdout, stderr, rc = _run(["lsof", "-i", "-n", "-P", "-sTCP:LISTEN"], timeout=15)
    if rc != 0 and not stdout:
        return 0

    count = 0
    for line in stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name_field = parts[-1]
        port: int | None = None
        try:
            port = int(name_field.rsplit(":", 1)[-1])
        except ValueError:
            continue

        count += 1
        if port not in SAFE_LISTEN_PORTS and port < 49152:
            counter[0] += 1
            fid = f"net_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="medium",
                category="network",
                title=f"Unusual listening port: {port}",
                description=(
                    f"Process '{parts[0]}' (PID {parts[1]}, user {parts[2]}) is listening "
                    f"on TCP port {port}, which is not in the expected macOS safe list."
                ),
                evidence={
                    "command": parts[0],
                    "pid": parts[1],
                    "user": parts[2],
                    "address": name_field,
                    "port": port,
                },
                remediation=(
                    f"Run `lsof -p {parts[1]}` to inspect open files. Disable the service "
                    "if it is not intentionally configured."
                ),
            ))
    return count


def _scan_dns_config(findings: list, counter: list):
    """Check DNS configuration for signs of poisoning or unexpected resolvers."""
    stdout, stderr, rc = _run(["scutil", "--dns"], timeout=10)
    if rc != 0 or not stdout:
        return

    # Look for non-standard DNS servers (not RFC1918, not well-known public DNS)
    known_public_dns = {
        "8.8.8.8", "8.8.4.4",         # Google
        "1.1.1.1", "1.0.0.1",         # Cloudflare
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "4.2.2.1", "4.2.2.2",
    }
    resolver_ips: list[str] = []
    for line in stdout.splitlines():
        m = re.search(r'nameserver\s*\[\d+\]\s*:\s*(\S+)', line)
        if m:
            resolver_ips.append(m.group(1))

    for ip in resolver_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                continue  # Local router or DHCP — normal
        except ValueError:
            continue
        if ip not in known_public_dns:
            counter[0] += 1
            fid = f"net_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="high",
                category="network",
                title=f"Unknown DNS resolver configured: {ip}",
                description=(
                    f"DNS resolver {ip} is not a well-known public DNS provider or private "
                    "address. This could indicate DNS hijacking or a malicious configuration."
                ),
                evidence={"resolver_ip": ip, "full_dns_config": stdout[:2000]},
                remediation=(
                    "Verify DNS settings in System Settings > Network > DNS. "
                    "Reset to a known-good DNS provider (e.g. 1.1.1.1 or 8.8.8.8)."
                ),
            ))


def _scan_etc_hosts(findings: list, counter: list):
    """Detect /etc/hosts modifications beyond the macOS baseline."""
    hosts_path = "/etc/hosts"
    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()
    except PermissionError:
        return
    except FileNotFoundError:
        return

    suspicious_entries = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Normalise whitespace for comparison
        normalised = re.sub(r'\s+', ' ', stripped)
        # Flag redirections of popular domains to non-loopback addresses
        parts = normalised.split()
        if len(parts) >= 2:
            ip = parts[0]
            hostnames = parts[1:]
            # Flag if well-known domains are redirected
            for h in hostnames:
                if any(d in h for d in [
                    "apple.com", "google.com", "microsoft.com", "icloud.com",
                    "ocsp.apple.com", "crl.apple.com", "updates.cdn-apple.com",
                ]):
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not addr.is_loopback:
                            suspicious_entries.append(stripped)
                    except ValueError:
                        pass

    if suspicious_entries:
        counter[0] += 1
        fid = f"net_{counter[0]:03d}"
        findings.append(_make_finding(
            fid=fid,
            severity="critical",
            category="network",
            title="/etc/hosts contains suspicious domain redirections",
            description=(
                "The /etc/hosts file has been modified to redirect known Apple or system "
                "domains to non-loopback IP addresses. This can be used to intercept "
                "software updates or bypass security checks."
            ),
            evidence={"suspicious_entries": suspicious_entries, "hosts_path": hosts_path},
            remediation=(
                "Review /etc/hosts with `cat /etc/hosts`. Remove any unauthorized entries. "
                "Restore the default macOS /etc/hosts if needed."
            ),
        ))


def _scan_network_interfaces(findings: list, counter: list):
    """Flag unexpected VPN tunnels, packet capture interfaces, or extra loopbacks."""
    stdout, stderr, rc = _run(["ifconfig", "-a"], timeout=10)
    if rc != 0 or not stdout:
        return

    interfaces: list[str] = []
    current = None
    iface_details: dict[str, str] = {}
    for line in stdout.splitlines():
        if re.match(r'^\w', line):
            current = line.split(":")[0]
            interfaces.append(current)
            iface_details[current] = line
        elif current:
            iface_details[current] = iface_details.get(current, "") + " " + line.strip()

    # Flag suspicious interface types
    suspicious_iface_prefixes = ["pktap", "ipsec", "tun", "tap", "utun", "gif", "stf"]
    for iface in interfaces:
        for prefix in suspicious_iface_prefixes:
            if iface.startswith(prefix):
                # utun0/1/2 are normal for VPN — flag if more than 3 utun exist
                if iface.startswith("utun"):
                    idx_str = iface[4:]
                    try:
                        if int(idx_str) < 3:
                            break
                    except ValueError:
                        pass
                counter[0] += 1
                fid = f"net_{counter[0]:03d}"
                findings.append(_make_finding(
                    fid=fid,
                    severity="medium",
                    category="network",
                    title=f"Suspicious network interface detected: {iface}",
                    description=(
                        f"Network interface '{iface}' (type prefix '{prefix}') detected. "
                        "This may indicate an active VPN tunnel, packet capture session, "
                        "or a network-level surveillance tool."
                    ),
                    evidence={"interface": iface, "details": iface_details.get(iface, "")[:500]},
                    remediation=(
                        "Verify the interface with `ifconfig " + iface + "`. "
                        "If you do not recognise it, check for VPN software or "
                        "packet capture tools running as root."
                    ),
                ))
                break  # only flag once per interface


def _scan_packet_capture(findings: list, counter: list):
    """Check if any processes have a BPF/packet-capture socket open."""
    stdout, stderr, rc = _run(
        ["lsof", "-n", "-c", "tcpdump", "-c", "wireshark", "-c", "scapy", "/dev/bpf0"],
        timeout=10,
    )
    # Also check any /dev/bpf* usage
    stdout2, _, _ = _run(["lsof", "/dev/bpf0", "/dev/bpf1", "/dev/bpf2"], timeout=10)
    combined = (stdout or "") + (stdout2 or "")
    if combined.strip():
        lines = [l for l in combined.splitlines() if l and not l.startswith("COMMAND")]
        if lines:
            counter[0] += 1
            fid = f"net_{counter[0]:03d}"
            findings.append(_make_finding(
                fid=fid,
                severity="high",
                category="surveillance",
                title="Packet capture interface (BPF) is currently open",
                description=(
                    "One or more processes have opened a BPF (Berkeley Packet Filter) device, "
                    "indicating active packet capture. This could be a legitimate network tool "
                    "or a surveillance/eavesdropping application."
                ),
                evidence={"lsof_output": combined[:2000]},
                remediation=(
                    "Identify the processes using BPF with `lsof /dev/bpf*`. "
                    "Terminate any unrecognised packet capture processes."
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
        # Active connections + suspicious IP check
        conns, conn_count = _scan_active_connections(findings, counter)
        metadata["connections_checked"] = conn_count

        # Listening ports
        listen_count = _scan_listening_ports(findings, counter)
        metadata["listening_ports_checked"] = listen_count

        # DNS configuration
        _scan_dns_config(findings, counter)

        # /etc/hosts integrity
        _scan_etc_hosts(findings, counter)

        # Network interfaces / VPN tunnels
        _scan_network_interfaces(findings, counter)

        # Packet capture
        _scan_packet_capture(findings, counter)

        metadata["findings_count"] = len(findings)
        metadata["duration_s"] = round(time.time() - start, 2)

        return {
            "module": "mac.network",
            "status": "success",
            "findings": findings,
            "metadata": metadata,
            "error": None,
        }

    except PermissionError as exc:
        return {
            "module": "mac.network",
            "status": "skipped",
            "findings": findings,
            "metadata": {"reason": "insufficient permissions", "detail": str(exc)},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "module": "mac.network",
            "status": "error",
            "findings": findings,
            "metadata": metadata,
            "error": str(exc),
        }
