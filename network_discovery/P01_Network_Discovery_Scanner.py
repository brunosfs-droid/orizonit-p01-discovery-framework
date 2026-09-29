#!/usr/bin/env python3
"""Orizon IT P01 Network Discovery Scanner v0.4.1 (MVP).

Active, non-credentialed network discovery intended for authorized infrastructure
assessment. The scanner supports multiple IPv4 CIDRs/ranges, exclusions,
guardrails for large scopes, basic host discovery, TCP service fingerprinting,
SSDP enrichment, ARP/neighbor correlation, JSON output and SHA-256 integrity.

This version DOES NOT attempt authentication and DOES NOT exploit services.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCANNER_NAME = "P01-Network-Discovery-Scanner"
SCANNER_VERSION = "0.4.1"
SCHEMA_VERSION = "0.4"

DEFAULT_SAFE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    515, 548, 631, 993, 995, 1883, 3389, 5900, 5985, 5986,
    8000, 8080, 8443, 8883, 9100,
]

STANDARD_EXTRA_PORTS = [
    88, 389, 636, 1433, 1521, 2049, 2375, 2376, 3306, 5432,
    6379, 8291, 9200, 27017,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 515: "printer-lpd", 548: "afp", 631: "ipp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1883: "mqtt", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8291: "mikrotik-winbox", 8443: "https-alt", 8883: "mqtt-tls",
    9100: "printer-raw", 9200: "elasticsearch", 27017: "mongodb",
}

BANNER_PORTS = {21, 22, 23, 25, 110, 143}
HTTP_PORTS = {80, 8000, 8080}
HTTPS_PORTS = {443, 8443}
REACHABILITY_PORTS = [22, 80, 443, 445, 3389, 8080]


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_label(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return value.strip("-")[:80] or "run"


def load_expression_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    expressions: List[str] = []
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        expressions.append(line)
    return expressions


def expand_ipv4_expression(expr: str) -> List[ipaddress.IPv4Address]:
    """Expand IPv4 CIDR, single IP, full range or shorthand last-octet range."""
    expr = expr.strip()
    if not expr:
        return []

    if "/" in expr:
        net = ipaddress.ip_network(expr, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 not supported in v0.4a: {expr}")
        return list(net.hosts()) if net.num_addresses > 2 else list(net)

    # Full range: 192.168.1.10-192.168.1.50
    if "-" in expr:
        left, right = [x.strip() for x in expr.split("-", 1)]
        start = ipaddress.ip_address(left)
        if "." not in right:
            parts = left.split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid shorthand range: {expr}")
            right = ".".join(parts[:3] + [right])
        end = ipaddress.ip_address(right)
        if start.version != 4 or end.version != 4:
            raise ValueError(f"IPv6 not supported in v0.4a: {expr}")
        if int(end) < int(start):
            raise ValueError(f"Range end is before start: {expr}")
        return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]

    ip = ipaddress.ip_address(expr)
    if ip.version != 4:
        raise ValueError(f"IPv6 not supported in v0.4a: {expr}")
    return [ip]


def resolve_scope(targets: Sequence[str], excludes: Sequence[str]) -> Tuple[List[str], List[str]]:
    target_ips: Set[ipaddress.IPv4Address] = set()
    exclude_ips: Set[ipaddress.IPv4Address] = set()
    for expr in targets:
        target_ips.update(expand_ipv4_expression(expr))
    for expr in excludes:
        exclude_ips.update(expand_ipv4_expression(expr))
    effective = sorted((target_ips - exclude_ips), key=int)
    return [str(x) for x in effective], [str(x) for x in sorted(exclude_ips, key=int)]


def parse_ports(value: Optional[str], profile: str) -> List[int]:
    if value:
        ports: Set[int] = set()
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid TCP port: {port}")
            ports.add(port)
        return sorted(ports)
    ports = set(DEFAULT_SAFE_PORTS)
    if profile == "standard":
        ports.update(STANDARD_EXTRA_PORTS)
    return sorted(ports)


def ping_host(ip: str, timeout: float) -> bool:
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(max(100, int(timeout * 1000))), ip]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(max(100, int(timeout * 1000))), ip]
        else:
            # Linux iputils: -W is timeout in seconds.
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout + 0.999))), ip]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=max(2.0, timeout + 1.5))
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_tcp_ports(ip: str, ports: Sequence[int], timeout: float) -> List[int]:
    open_ports: List[int] = []
    for port in ports:
        if tcp_connect(ip, port, timeout):
            open_ports.append(port)
    return open_ports


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def read_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(768)
            except socket.timeout:
                data = b""
            if not data:
                # Some plaintext services answer after newline.
                try:
                    sock.sendall(b"\r\n")
                    data = sock.recv(768)
                except OSError:
                    return None
            text = data.decode("utf-8", errors="replace").strip()
            return text[:700] or None
    except OSError:
        return None


def http_probe(ip: str, port: int, tls: bool, timeout: float) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    conn: Any = None
    try:
        if tls:
            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        conn.request("HEAD", "/", headers={"Host": ip, "User-Agent": "OrizonIT-P01-Discovery/0.4"})
        resp = conn.getresponse()
        result["http_status"] = resp.status
        result["http_reason"] = resp.reason
        if resp.getheader("Server"):
            result["server_header"] = resp.getheader("Server")
        if resp.getheader("Location"):
            result["location"] = resp.getheader("Location")
        if tls and getattr(conn, "sock", None):
            try:
                result["tls_version"] = conn.sock.version()
                cipher = conn.sock.cipher()
                if cipher:
                    result["tls_cipher"] = cipher[0]
                cert_bin = conn.sock.getpeercert(binary_form=True)
                if cert_bin:
                    result["certificate_sha256"] = hashlib.sha256(cert_bin).hexdigest()
            except (ssl.SSLError, OSError, AttributeError):
                pass
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        result["probe_error"] = str(exc)[:250]
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
    return result


def parse_neighbor_table() -> Dict[str, str]:
    """Best-effort local L2 IP -> MAC mapping. Does not cross routers."""
    mappings: Dict[str, str] = {}
    system = platform.system().lower()
    commands: List[List[str]] = []
    if system == "windows":
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh", "show"], ["arp", "-an"]]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue
        text = proc.stdout or ""
        if cmd[:2] == ["ip", "neigh"]:
            for line in text.splitlines():
                m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+.*\blladdr\s+([0-9a-fA-F:.-]{11,20})", line)
                if m:
                    mappings[m.group(1)] = normalize_mac(m.group(2))
        else:
            for line in text.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", line)
                if m:
                    mappings[m.group(1)] = normalize_mac(m.group(2))
        if mappings:
            break
    return mappings


def normalize_mac(mac: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(compact) != 12:
        return mac.upper()
    return ":".join(compact[i:i+2] for i in range(0, 12, 2))


def mac_address_type(mac: Optional[str]) -> Optional[str]:
    """Classify MAC administration bit; does not infer vendor."""
    if not mac:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(compact) != 12:
        return "Unknown"
    first = int(compact[:2], 16)
    if first & 0x01:
        return "Multicast"
    if first & 0x02:
        return "Locally Administered"
    return "Universally Administered"


def build_mac_correlations(assets: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Surface same-MAC/multi-IP observations without auto-deduplicating assets."""
    mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
    for asset in assets:
        mac = asset.get("mac")
        ip = asset.get("ip")
        if mac and ip:
            mac_to_ips[str(mac)].add(str(ip))
    correlations: List[Dict[str, Any]] = []
    for mac, ips in sorted(mac_to_ips.items()):
        if len(ips) > 1:
            correlations.append({
                "type": "same_mac_multiple_ips",
                "mac": mac,
                "ips": sorted(ips, key=lambda x: int(ipaddress.ip_address(x))),
                "confidence": "High",
                "automatic_deduplication": False,
                "interpretation": "May represent multi-addressing, DHCP/ARP transition, proxying, bridging, or stale neighbor state. Confirm before merging assets.",
            })
    return correlations


def ssdp_discover(timeout: float = 1.6, source_ips: Optional[Sequence[str]] = None) -> Dict[str, List[Dict[str, str]]]:
    """Return SSDP responses keyed by source IPv4 address.

    On multi-homed hosts, attempt one M-SEARCH per in-scope local IPv4 so the
    multicast query is emitted from the relevant interface when possible.
    """
    responses: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    message = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST:239.255.255.250:1900\r\n'
        'MAN:"ssdp:discover"\r\n'
        'MX:1\r\n'
        'ST:ssdp:all\r\n'
        '\r\n'
    ).encode("ascii")

    candidates: List[Optional[str]] = []
    for value in source_ips or []:
        try:
            if ipaddress.ip_address(value).version == 4:
                candidates.append(value)
        except ValueError:
            continue
    if not candidates:
        candidates = [None]

    for source_ip in candidates:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.settimeout(0.2)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            if source_ip:
                sock.bind((source_ip, 0))
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip))
                except OSError:
                    pass
            sock.sendto(message, ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                headers: Dict[str, str] = {}
                text = data.decode("utf-8", errors="replace")
                lines = text.split("\r\n")
                if lines:
                    headers["status_line"] = lines[0][:200]
                for line in lines[1:]:
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    if key in {"server", "location", "st", "usn", "cache-control"}:
                        headers[key] = value.strip()[:500]
                if source_ip:
                    headers["scanner_source_interface"] = source_ip
                if headers and headers not in responses[addr[0]]:
                    responses[addr[0]].append(headers)
        except OSError:
            pass
        finally:
            sock.close()
    return dict(responses)

def get_local_context() -> Dict[str, Any]:
    hostname = socket.gethostname()
    ips: Set[str] = set()
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # UDP connect does not send traffic; it asks the OS which source address would be used.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    gateways: List[str] = []
    system = platform.system().lower()
    try:
        if system == "windows":
            proc = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, timeout=4)
            for line in proc.stdout.splitlines():
                m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    gateways.append(m.group(1))
        else:
            proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=4)
            for line in proc.stdout.splitlines():
                m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    gateways.append(m.group(1))
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass
    return {
        "hostname": hostname,
        "platform": platform.platform(),
        "local_ipv4": sorted(ips),
        "default_gateways": sorted(set(gateways)),
    }


def classify_asset(ip: str, hostname: Optional[str], open_ports: Set[int], port_details: List[Dict[str, Any]], ssdp: List[Dict[str, str]], local_context: Dict[str, Any]) -> Tuple[str, Optional[str], str, List[str]]:
    evidence: List[str] = []
    os_guess: Optional[str] = None
    device = "Unknown"
    confidence = "Low"

    if ip in set(local_context.get("default_gateways") or []):
        device = "Router/Gateway"
        confidence = "High"
        evidence.append("IP matches local default gateway")

    if {9100, 515, 631} & open_ports:
        device = "Printer"
        confidence = "High"
        evidence.append("Printer service port detected")

    if 445 in open_ports and ({135, 3389, 5985, 5986} & open_ports):
        os_guess = "Windows"
        if device == "Unknown":
            device = "Windows Host"
        confidence = "High" if 135 in open_ports else "Medium"
        evidence.append("Windows-associated service combination detected")

    ssh_banner = " ".join(str(x.get("banner") or "") for x in port_details if x.get("port") == 22)
    if 22 in open_ports and "OpenSSH" in ssh_banner and os_guess is None:
        os_guess = "Linux/Unix-like"
        if device == "Unknown":
            device = "Linux/Unix Host"
        confidence = "Medium"
        evidence.append("OpenSSH banner detected")

    ssdp_text = " ".join(" ".join(x.values()) for x in ssdp).lower()
    if ssdp_text:
        if any(k in ssdp_text for k in ["mediarenderer", "smarttv", "smart-tv", "roku", "dlna", "tv"]):
            device = "Media/TV/IoT"
            confidence = "Medium"
            evidence.append("SSDP media/TV signature detected")
        elif device == "Unknown":
            device = "UPnP/IoT Device"
            confidence = "Medium"
            evidence.append("SSDP response detected")

    if device == "Unknown" and ({80, 443, 8080, 8443} & open_ports) and ({22, 23} & open_ports):
        device = "Network/Embedded Candidate"
        confidence = "Low"
        evidence.append("Management web + SSH/Telnet combination detected")

    if hostname:
        hn = hostname.lower()
        if device == "Unknown" and any(k in hn for k in ["router", "gateway", "gw-", "switch", "sw-", "ap-", "accesspoint"]):
            device = "Network Device Candidate"
            confidence = "Low"
            evidence.append("Hostname suggests network device")

    return device, os_guess, confidence, evidence


def enrich_open_ports(ip: str, ports: Sequence[int], timeout: float) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for port in sorted(ports):
        item: Dict[str, Any] = {"port": port, "protocol": "tcp", "service": SERVICE_NAMES.get(port, "unknown")}
        if port in BANNER_PORTS:
            banner = read_banner(ip, port, timeout)
            if banner:
                item["banner"] = banner
        elif port in HTTP_PORTS:
            item.update(http_probe(ip, port, tls=False, timeout=max(timeout, 0.6)))
        elif port in HTTPS_PORTS:
            item.update(http_probe(ip, port, tls=True, timeout=max(timeout, 0.8)))
        details.append(item)
    return details


def in_scope(ip: str, scope_ips: Set[str]) -> bool:
    return ip in scope_ips


def discover_host(ip: str, ports: Sequence[int], timeout: float, ping_result: bool, arp_mac: Optional[str], ssdp: List[Dict[str, str]], local_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    methods: List[str] = []
    if ping_result:
        methods.append("icmp_echo")
    if arp_mac:
        methods.append("arp_neighbor")
    if ssdp:
        methods.append("ssdp")

    initial_open: List[int] = []
    if not methods:
        initial_open = scan_tcp_ports(ip, REACHABILITY_PORTS, timeout)
        if initial_open:
            methods.append("tcp_connect")

    if not methods:
        return None

    open_ports = set(initial_open)
    open_ports.update(scan_tcp_ports(ip, [p for p in ports if p not in open_ports], timeout))

    local_ips = set(local_context.get("local_ipv4") or [])
    if ip in local_ips:
        hostname = str(local_context.get("hostname") or "") or reverse_dns(ip)
        hostname_source = "local_execution_host"
        hostname_confidence = "High"
    else:
        hostname = reverse_dns(ip)
        hostname_source = "reverse_dns" if hostname else None
        hostname_confidence = "Medium" if hostname else None

    port_details = enrich_open_ports(ip, sorted(open_ports), timeout)
    device, os_guess, confidence, evidence = classify_asset(ip, hostname, open_ports, port_details, ssdp, local_context)

    return {
        "ip": ip,
        "hostname": hostname,
        "hostname_source": hostname_source,
        "hostname_confidence": hostname_confidence,
        "mac": arp_mac,
        "mac_address_type": mac_address_type(arp_mac),
        "discovery_methods": methods,
        "open_ports": port_details,
        "ssdp": ssdp,
        "device_type_guess": device,
        "os_guess": os_guess,
        "confidence": confidence,
        "classification_evidence": evidence,
        "credentialed": False,
    }

def write_output(output_dir: Path, run_label: str, payload: Dict[str, Any]) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"P01-Network-Discovery_{timestamp}_{safe_label(run_label)}.json"
    out = output_dir / filename
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    sha = out.with_suffix(out.suffix + ".sha256")
    sha.write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    try:
        if os.name != "nt":
            os.chmod(out, 0o600)
            os.chmod(sha, 0o600)
    except OSError:
        pass
    return out, sha


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Orizon IT P01 Network Discovery Scanner v0.4.1")
    parser.add_argument("--target", action="append", default=[], help="IPv4 CIDR, IP or range. Repeatable.")
    parser.add_argument("--target-file", help="Text file with one target expression per line.")
    parser.add_argument("--exclude", action="append", default=[], help="IPv4 CIDR, IP or range to exclude. Repeatable.")
    parser.add_argument("--exclude-file", help="Text file with exclusions.")
    parser.add_argument("--profile", choices=["safe", "standard"], default="safe")
    parser.add_argument("--ports", help="Override TCP ports as comma-separated list.")
    parser.add_argument("--timeout", type=float, default=0.35, help="Per TCP connection timeout in seconds.")
    parser.add_argument("--workers", type=int, default=64, help="Concurrent host workers (1-256).")
    parser.add_argument("--max-hosts", type=int, default=2048, help="Guardrail: maximum effective IPs without --allow-large-scope.")
    parser.add_argument("--allow-large-scope", action="store_true", help="Explicitly allow a scope larger than --max-hosts.")
    parser.add_argument("--disable-ssdp", action="store_true", help="Disable SSDP M-SEARCH enrichment.")
    parser.add_argument("--output-dir", default="./output")
    parser.add_argument("--run-label", default="network-discovery")
    parser.add_argument("--ack-authorized-scan", action="store_true", help="Required acknowledgement that the operator is authorized to scan the target scope.")
    args = parser.parse_args(argv)

    if not args.ack_authorized_scan:
        parser.error("--ack-authorized-scan is required. Scan only networks for which you have explicit authorization.")
    targets = list(args.target) + load_expression_file(args.target_file)
    excludes = list(args.exclude) + load_expression_file(args.exclude_file)
    if not targets:
        parser.error("Provide at least one --target or --target-file.")
    if not (1 <= args.workers <= 256):
        parser.error("--workers must be between 1 and 256.")
    if args.timeout <= 0 or args.timeout > 10:
        parser.error("--timeout must be > 0 and <= 10 seconds.")

    try:
        scope_ips, resolved_excludes = resolve_scope(targets, excludes)
        ports = parse_ports(args.ports, args.profile)
    except ValueError as exc:
        parser.error(str(exc))

    if not scope_ips:
        parser.error("Effective scope is empty after exclusions.")
    if len(scope_ips) > args.max_hosts and not args.allow_large_scope:
        parser.error(
            f"Effective scope contains {len(scope_ips)} IPs, exceeding guardrail {args.max_hosts}. "
            "Split the scope into smaller ranges or use --allow-large-scope after reviewing impact."
        )

    started = time.monotonic()
    warnings: List[Dict[str, str]] = []
    limitations: List[Dict[str, str]] = [
        {"section": "network_discovery", "message": "v0.4a is IPv4-only and does not attempt credentials."},
        {"section": "asset_identity", "message": "MAC/ARP visibility is generally limited to local L2 segments; routed devices may not expose MAC addresses."},
        {"section": "fingerprinting", "message": "OS/device classification is heuristic unless later confirmed by credentialed enrichment."},
    ]
    errors: List[Dict[str, str]] = []
    local_context = get_local_context()
    scope_set = set(scope_ips)
    local_ips_in_scope = sorted(ip for ip in (local_context.get("local_ipv4") or []) if ip in scope_set)
    gateways_in_scope = sorted(ip for ip in (local_context.get("default_gateways") or []) if ip in scope_set)
    scope_relationship = {
        "local_ipv4_in_scope": local_ips_in_scope,
        "default_gateways_in_scope": gateways_in_scope,
        "has_local_overlap": bool(local_ips_in_scope),
        "has_gateway_overlap": bool(gateways_in_scope),
    }
    if not local_ips_in_scope and not gateways_in_scope:
        warnings.append({
            "section": "scope_sanity",
            "message": "Selected scope contains no local IPv4 address or default gateway. Routed discovery may be intentional, but ARP/MAC and multicast enrichment can be limited.",
        })

    ssdp_map: Dict[str, List[Dict[str, str]]] = {}
    if not args.disable_ssdp:
        ssdp_map = {
            ip: rows
            for ip, rows in ssdp_discover(source_ips=local_ips_in_scope).items()
            if in_scope(ip, scope_set)
        }

    # Phase 1: ICMP attempts primarily for liveness and ARP cache stimulation.
    ping_results: Dict[str, bool] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {pool.submit(ping_host, ip, args.timeout): ip for ip in scope_ips}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                ping_results[ip] = bool(future.result())
            except Exception as exc:  # defensive, should be rare
                ping_results[ip] = False
                errors.append({"section": "icmp", "target": ip, "message": str(exc)[:300]})

    neighbors = parse_neighbor_table()

    assets: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {
            pool.submit(
                discover_host,
                ip,
                ports,
                args.timeout,
                ping_results.get(ip, False),
                neighbors.get(ip),
                ssdp_map.get(ip, []),
                local_context,
            ): ip
            for ip in scope_ips
        }
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                asset = future.result()
                if asset:
                    assets.append(asset)
            except Exception as exc:
                errors.append({"section": "host_discovery", "target": ip, "message": str(exc)[:300]})

    assets.sort(key=lambda x: int(ipaddress.ip_address(x["ip"])))
    identity_correlations = build_mac_correlations(assets)
    correlation_by_mac = {c["mac"]: c for c in identity_correlations}
    for asset in assets:
        corr = correlation_by_mac.get(asset.get("mac"))
        if corr:
            asset["identity_hints"] = {
                "same_mac_seen_on_ips": corr["ips"],
                "possible_same_asset": True,
                "automatic_deduplication": False,
            }
    if identity_correlations:
        warnings.append({
            "section": "asset_identity",
            "message": f"{len(identity_correlations)} MAC address(es) were observed on multiple IPs. Review identity_correlations before counting logical assets.",
        })

    by_type = Counter(a["device_type_guess"] for a in assets)
    by_confidence = Counter(a["confidence"] for a in assets)
    if len(scope_ips) > 1024:
        warnings.append({"section": "scope", "message": f"Large scope scanned: {len(scope_ips)} IPs. Smaller segments improve duration and troubleshooting."})

    payload: Dict[str, Any] = {
        "metadata": {
            "scanner_name": SCANNER_NAME,
            "scanner_version": SCANNER_VERSION,
            "schema_version": SCHEMA_VERSION,
            "scanned_at_utc": utc_now_iso(),
            "run_label": args.run_label,
            "execution_host": socket.gethostname(),
            "execution_user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "python_version": platform.python_version(),
            "read_only_mode": True,
            "network_active_probing": True,
            "credential_attempts": False,
            "authorization_acknowledged": True,
            "duration_seconds": round(time.monotonic() - started, 2),
            "error_count": len(errors),
            "limitation_count": len(limitations),
            "warning_count": len(warnings),
        },
        "scope": {
            "targets": targets,
            "excludes": excludes,
            "resolved_excluded_ips": resolved_excludes,
            "effective_ip_count": len(scope_ips),
            "profile": args.profile,
            "tcp_ports": ports,
            "workers": args.workers,
            "timeout_seconds": args.timeout,
            "ssdp_enabled": not args.disable_ssdp,
            "scope_relationship": scope_relationship,
        },
        "local_context": local_context,
        "summary": {
            "hosts_discovered": len(assets),
            "by_device_type": dict(sorted(by_type.items())),
            "by_confidence": dict(sorted(by_confidence.items())),
            "ssdp_hosts": sum(1 for a in assets if a.get("ssdp")),
            "credentialed_hosts": 0,
            "unique_macs_observed": len({a.get("mac") for a in assets if a.get("mac")}),
            "multi_ip_mac_correlations": len(identity_correlations),
        },
        "assets": assets,
        "identity_correlations": identity_correlations,
        "errors": errors,
        "limitations": limitations,
        "warnings": warnings,
    }

    out, sha = write_output(Path(args.output_dir), args.run_label, payload)
    print("Network discovery finalizado.")
    print(f"Hosts descobertos: {len(assets)}")
    print(f"JSON: {out}")
    print(f"SHA256: {sha}")
    print(f"Erros: {len(errors)} | Limitações: {len(limitations)} | Avisos: {len(warnings)}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
