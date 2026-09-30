#!/usr/bin/env python3
"""Orizon IT P01 SSH Credentialed Enrichment v0.4b.2.

Authorized, read-only SSH enrichment for one target at a time.

Security properties:
- credential profile selection is scope/protocol aware;
- secrets are resolved only at execution time from the Credential Manager;
- secrets are never written to JSON/log/stdout;
- local SSH agent/key discovery is disabled for password profiles;
- bounded profile candidates reduce credential spraying/lockout risk;
- only a fixed allowlist of read-only commands is executed;
- host-key policy is explicit (TOFU or strict);
- discovered networks are emitted as candidates only; this component never
  recursively scans or pivots through the target.

This component intentionally performs no configuration changes.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

ENRICHER_NAME = "P01-SSH-Credentialed-Enrichment"
ENRICHER_VERSION = "0.4b.2"
SCHEMA_VERSION = "0.4b"

ROOT = Path(__file__).resolve().parents[1]
CRED_DIR = ROOT / "credential_manager"

def _credential_api():
    """Load the sibling Credential Manager only when credential operations are needed."""
    if str(CRED_DIR) not in sys.path:
        sys.path.insert(0, str(CRED_DIR))
    try:
        import P01_Credential_Manager as cred  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "P01_Credential_Manager.py was not found in the repository credential_manager directory."
        ) from exc
    return cred

try:
    import paramiko  # type: ignore
except ImportError:  # pragma: no cover - exercised by CLI preflight
    paramiko = None


MAX_OUTPUT_CHARS = 65536

SAFE_COMMAND_FAMILIES: Dict[str, List[str]] = {
    "hostname": [
        "hostname",
        "uname -n",
    ],
    "kernel": [
        "uname -a",
        "cat /proc/version",
    ],
    "os_release": [
        "cat /etc/os-release",
        "cat /etc/openwrt_release",
    ],
    "platform": [
        "ubus call system board",
    ],
    "interfaces": [
        "ip -j address",
        "ip addr show",
        "ifconfig -a",
    ],
    "routes": [
        "ip -j route",
        "ip route show",
        "route -n",
    ],
    "ip_forwarding": [
        "cat /proc/sys/net/ipv4/ip_forward",
    ],
}

def _normalized_allowed_commands() -> set[str]:
    return {" ".join(command.split()) for commands in SAFE_COMMAND_FAMILIES.values() for command in commands}



def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_label(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return value.strip("-")[:80] or "run"


def _truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> Tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit], True


def command_is_read_only(command: str) -> bool:
    # Strong allowlist: no arbitrary remote command may be executed.
    normalized = " ".join(command.split())
    return normalized in _normalized_allowed_commands()


def validate_command_catalog() -> None:
    bad: List[str] = []
    for family, commands in SAFE_COMMAND_FAMILIES.items():
        for command in commands:
            if not command_is_read_only(command):
                bad.append(f"{family}: {command}")
    if bad:
        raise RuntimeError("Non-read-only command detected in allowlist: " + "; ".join(bad))


def _decode_stream(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _run_command(client: Any, command: str, timeout: float) -> Dict[str, Any]:
    if not command_is_read_only(command):
        raise RuntimeError(f"Command is not allowed by read-only policy: {command}")

    started = time.monotonic()
    result: Dict[str, Any] = {
        "command": command,
        "read_only_allowlisted": True,
    }
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=False)
        try:
            stdin.close()
        except Exception:
            pass

        out = _decode_stream(stdout.read())
        err = _decode_stream(stderr.read())

        exit_status: Optional[int] = None
        try:
            exit_status = int(stdout.channel.recv_exit_status())
        except Exception:
            pass

        out, out_truncated = _truncate(out.strip())
        err, err_truncated = _truncate(err.strip())

        result.update({
            "success": exit_status == 0 if exit_status is not None else bool(out),
            "exit_status": exit_status,
            "stdout": out,
            "stderr": err,
            "stdout_truncated": out_truncated,
            "stderr_truncated": err_truncated,
        })
    except Exception as exc:
        result.update({
            "success": False,
            "error_type": type(exc).__name__,
            "error": _safe_exception_message(exc),
        })

    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def run_first_success(client: Any, family: str, timeout: float) -> Dict[str, Any]:
    attempts: List[Dict[str, Any]] = []
    for command in SAFE_COMMAND_FAMILIES[family]:
        result = _run_command(client, command, timeout)
        attempts.append(result)
        if result.get("success") and (result.get("stdout") or family == "ip_forwarding"):
            return {
                "family": family,
                "selected_command": command,
                "success": True,
                "result": result,
                "attempts": attempts,
            }
    return {
        "family": family,
        "selected_command": None,
        "success": False,
        "result": attempts[-1] if attempts else None,
        "attempts": attempts,
    }


def _safe_exception_message(exc: Exception) -> str:
    """Return a bounded message while avoiding accidental credential disclosure."""
    text = str(exc or "").strip()
    # Paramiko/socket exceptions should not contain supplied passwords, but keep
    # the output bounded and remove obvious URI userinfo just in case.
    text = re.sub(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*\S+", r"\1=<redacted>", text)
    text = re.sub(r"(?i)://[^/@:\s]+:[^/@\s]+@", "://<redacted>@", text)
    return text[:400] or type(exc).__name__


def sha256_fingerprint(key: Any) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def prepare_ssh_client(known_hosts: Path, host_key_policy: str) -> Any:
    if paramiko is None:
        raise RuntimeError(
            "Paramiko is required for SSH enrichment. Install with: "
            "python -m pip install -r credentialed_enrichment/requirements-ssh.txt"
        )

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if known_hosts.exists():
        try:
            client.load_host_keys(str(known_hosts))
        except Exception as exc:
            raise RuntimeError(f"Unable to load known-hosts file: {_safe_exception_message(exc)}") from exc

    if host_key_policy == "strict":
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif host_key_policy == "tofu":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        raise ValueError(f"Unsupported host-key policy: {host_key_policy}")
    return client


def _save_tofu_host_key(client: Any, known_hosts: Path, policy: str) -> None:
    if policy != "tofu":
        return
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    client.save_host_keys(str(known_hosts))
    try:
        if os.name != "nt":
            os.chmod(known_hosts, 0o600)
    except OSError:
        pass


def parse_ip_json_interfaces(text: str) -> List[Dict[str, Any]]:
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(rows, list):
        return []

    result: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        iface = {
            "ifname": row.get("ifname"),
            "flags": row.get("flags", []),
            "mtu": row.get("mtu"),
            "operstate": row.get("operstate"),
            "mac": row.get("address"),
            "ipv4": [],
        }
        for addr in row.get("addr_info", []) or []:
            if not isinstance(addr, dict) or addr.get("family") != "inet":
                continue
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if local is None or prefix is None:
                continue
            iface["ipv4"].append({
                "address": str(local),
                "prefix_length": int(prefix),
                "scope": addr.get("scope"),
            })
        result.append(iface)
    return result


def parse_ifconfig_interfaces(text: str) -> List[Dict[str, Any]]:
    """Best-effort parser for BusyBox/net-tools ifconfig output."""
    result: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split(":", 1)[0].split()[0]
            current = {"ifname": name, "ipv4": []}
            result.append(current)
        if current is None:
            continue

        mac_match = re.search(r"(?:ether|HWaddr)\s+([0-9A-Fa-f:.-]{11,20})", line)
        if mac_match:
            current["mac"] = mac_match.group(1).upper()

        cidr_match = re.search(r"\binet(?: addr:|\s+)(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if cidr_match:
            current["ipv4"].append({
                "address": cidr_match.group(1),
                "prefix_length": int(cidr_match.group(2)),
                "scope": None,
            })
            continue

        inet_match = re.search(r"\binet(?: addr:|\s+)(\d+\.\d+\.\d+\.\d+)", line)
        mask_match = re.search(r"(?:Mask:|netmask\s+)(0x[0-9A-Fa-f]+|\d+\.\d+\.\d+\.\d+)", line)
        if inet_match:
            prefix = 32
            if mask_match:
                try:
                    raw_mask = mask_match.group(1)
                    if raw_mask.startswith("0x"):
                        mask_int = int(raw_mask, 16)
                        mask = ipaddress.IPv4Address(mask_int)
                    else:
                        mask = ipaddress.IPv4Address(raw_mask)
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                except Exception:
                    prefix = 32
            current["ipv4"].append({
                "address": inet_match.group(1),
                "prefix_length": prefix,
                "scope": None,
            })
    return result


def parse_ip_addr_text(text: str) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        head = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if head:
            current = {"ifname": head.group(1), "ipv4": []}
            result.append(current)
            continue
        if current is None:
            continue
        mac_match = re.search(r"\blink/ether\s+([0-9A-Fa-f:.-]{11,20})", line)
        if mac_match:
            current["mac"] = mac_match.group(1).upper()
        inet_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if inet_match:
            current["ipv4"].append({
                "address": inet_match.group(1),
                "prefix_length": int(inet_match.group(2)),
                "scope": None,
            })
    return result


def parse_interfaces(command: Optional[str], text: str) -> List[Dict[str, Any]]:
    if not command:
        return []
    if command == "ip -j address":
        parsed = parse_ip_json_interfaces(text)
        if parsed:
            return parsed
    if command == "ip addr show":
        parsed = parse_ip_addr_text(text)
        if parsed:
            return parsed
    return parse_ifconfig_interfaces(text)


def parse_ip_json_routes(text: str) -> List[Dict[str, Any]]:
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    result: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        result.append({
            "destination": row.get("dst", "default"),
            "gateway": row.get("gateway"),
            "device": row.get("dev"),
            "protocol": row.get("protocol"),
            "scope": row.get("scope"),
            "source": row.get("prefsrc"),
        })
    return result


def parse_ip_route_text(text: str) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        destination = parts[0]
        gateway = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else None
        device = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        source = parts[parts.index("src") + 1] if "src" in parts and parts.index("src") + 1 < len(parts) else None
        result.append({
            "destination": destination,
            "gateway": gateway,
            "device": device,
            "source": source,
        })
    return result


def parse_route_n(text: str) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 8 or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", cols[0]):
            continue
        dest, gateway, mask = cols[0], cols[1], cols[2]
        iface = cols[-1]
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            network = str(ipaddress.ip_network(f"{dest}/{prefix}", strict=False))
        except Exception:
            network = dest
        result.append({
            "destination": "default" if dest == "0.0.0.0" and mask == "0.0.0.0" else network,
            "gateway": None if gateway == "0.0.0.0" else gateway,
            "device": iface,
            "source": None,
        })
    return result


def parse_routes(command: Optional[str], text: str) -> List[Dict[str, Any]]:
    if not command:
        return []
    if command == "ip -j route":
        parsed = parse_ip_json_routes(text)
        if parsed:
            return parsed
    if command == "ip route show":
        parsed = parse_ip_route_text(text)
        if parsed:
            return parsed
    return parse_route_n(text)


def _network_metadata(network: ipaddress.IPv4Network) -> Dict[str, Any]:
    return {
        "network": str(network),
        "is_private": network.is_private,
        "is_link_local": network.is_link_local,
        "is_loopback": network.is_loopback,
        "is_multicast": network.is_multicast,
        "authorization_status": "unassessed",
        "auto_scan": False,
    }


def build_candidate_networks(
    interfaces: Sequence[Mapping[str, Any]],
    routes: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Build candidate networks; never authorizes or scans them."""
    candidates: Dict[str, Dict[str, Any]] = {}

    for iface in interfaces:
        ifname = iface.get("ifname")
        for addr in iface.get("ipv4", []) or []:
            try:
                address = ipaddress.ip_address(str(addr.get("address")))
                prefix = int(addr.get("prefix_length"))
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except Exception:
                continue
            if network.is_loopback or network.is_link_local or network.is_multicast:
                continue
            item = candidates.setdefault(str(network), {
                **_network_metadata(network),
                "sources": [],
            })
            item["sources"].append({
                "evidence": "interface_address",
                "interface": ifname,
                "address": str(address),
                "prefix_length": prefix,
            })

    for route in routes:
        destination = str(route.get("destination") or "")
        if not destination or destination == "default":
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version != 4 or network.is_loopback or network.is_link_local or network.is_multicast:
            continue
        item = candidates.setdefault(str(network), {
            **_network_metadata(network),
            "sources": [],
        })
        item["sources"].append({
            "evidence": "route_table",
            "interface": route.get("device"),
            "gateway": route.get("gateway"),
            "source": route.get("source"),
        })

    output = list(candidates.values())
    output.sort(key=lambda x: (int(ipaddress.ip_network(x["network"]).network_address), ipaddress.ip_network(x["network"]).prefixlen))
    return output


def _extract_simple_identity(families: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    identity: Dict[str, Any] = {}
    hostname = families.get("hostname", {})
    if hostname.get("success") and hostname.get("result"):
        identity["hostname"] = (hostname["result"].get("stdout") or "").splitlines()[0][:255] or None

    kernel = families.get("kernel", {})
    if kernel.get("success") and kernel.get("result"):
        identity["kernel"] = kernel["result"].get("stdout")

    os_rel = families.get("os_release", {})
    if os_rel.get("success") and os_rel.get("result"):
        identity["os_release_raw"] = os_rel["result"].get("stdout")

    platform_info = families.get("platform", {})
    if platform_info.get("success") and platform_info.get("result"):
        raw = platform_info["result"].get("stdout") or ""
        try:
            identity["platform"] = json.loads(raw)
        except json.JSONDecodeError:
            identity["platform_raw"] = raw

    return identity


def collect_read_only(client: Any, command_timeout: float) -> Dict[str, Any]:
    validate_command_catalog()
    families: Dict[str, Dict[str, Any]] = {}
    for family in SAFE_COMMAND_FAMILIES:
        families[family] = run_first_success(client, family, command_timeout)

    interfaces_family = families["interfaces"]
    interface_text = ""
    interface_command = interfaces_family.get("selected_command")
    if interfaces_family.get("success") and interfaces_family.get("result"):
        interface_text = interfaces_family["result"].get("stdout") or ""
    interfaces = parse_interfaces(interface_command, interface_text)

    routes_family = families["routes"]
    route_text = ""
    route_command = routes_family.get("selected_command")
    if routes_family.get("success") and routes_family.get("result"):
        route_text = routes_family["result"].get("stdout") or ""
    routes = parse_routes(route_command, route_text)

    forwarding_value: Optional[bool] = None
    forward = families["ip_forwarding"]
    if forward.get("success") and forward.get("result"):
        raw = str(forward["result"].get("stdout") or "").strip()
        if raw in {"0", "1"}:
            forwarding_value = raw == "1"

    candidates = build_candidate_networks(interfaces, routes)

    # Keep command evidence but only from a fixed allowlist.
    command_evidence: List[Dict[str, Any]] = []
    for family, record in families.items():
        selected = record.get("result")
        if selected:
            command_evidence.append({
                "family": family,
                "command": selected.get("command"),
                "success": selected.get("success"),
                "exit_status": selected.get("exit_status"),
                "stdout": selected.get("stdout"),
                "stderr": selected.get("stderr"),
                "stdout_truncated": selected.get("stdout_truncated", False),
                "stderr_truncated": selected.get("stderr_truncated", False),
                "duration_ms": selected.get("duration_ms"),
            })

    return {
        "identity": _extract_simple_identity(families),
        "network": {
            "interfaces": interfaces,
            "routes": routes,
            "ipv4_forwarding": forwarding_value,
            "candidate_networks": candidates,
            "candidate_network_count": len(candidates),
        },
        "command_evidence": command_evidence,
    }


def connect_with_profile(
    target: str,
    port: int,
    profile_match: Any,
    known_hosts: Path,
    host_key_policy: str,
    connect_timeout: float,
    command_timeout: float,
    collect_commands: bool,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    if paramiko is None:
        raise RuntimeError(
            "Paramiko is required for SSH enrichment. Install with: "
            "python -m pip install -r credentialed_enrichment/requirements-ssh.txt"
        )

    profile = profile_match.profile
    profile_id = str(profile.get("id"))
    username = str(profile.get("username") or "").strip()
    secret_refs = profile.get("secret_refs") or {}
    password_ref = secret_refs.get("password")

    attempt: Dict[str, Any] = {
        "profile_id": profile_id,
        "protocol": "ssh",
        "username": username or None,
        "matched_scope": profile_match.matched_scope,
        "scope_prefix_length": profile_match.prefix_length,
        "host_key_policy": host_key_policy,
        "success": False,
    }

    if str(profile.get("auth_type") or "").lower() != "password":
        attempt["result"] = "unsupported_auth_type"
        attempt["error_type"] = "UnsupportedAuthType"
        return attempt, None
    if not username:
        attempt["result"] = "profile_missing_username"
        attempt["error_type"] = "CredentialConfigError"
        return attempt, None
    if not password_ref:
        attempt["result"] = "profile_missing_password_ref"
        attempt["error_type"] = "CredentialConfigError"
        return attempt, None

    try:
        password = _credential_api().resolve_secret(str(password_ref), prompt_label=f"SSH secret for {profile_id}: ")
    except Exception as exc:
        attempt["result"] = "secret_resolution_failed"
        attempt["error_type"] = type(exc).__name__
        attempt["error"] = _safe_exception_message(exc)
        return attempt, None

    client = prepare_ssh_client(known_hosts, host_key_policy)
    started = time.monotonic()
    try:
        client.connect(
            hostname=target,
            port=port,
            username=username,
            password=password,
            timeout=connect_timeout,
            banner_timeout=connect_timeout,
            auth_timeout=connect_timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        _save_tofu_host_key(client, known_hosts, host_key_policy)

        transport = client.get_transport()
        remote_version = getattr(transport, "remote_version", None) if transport else None
        server_key = transport.get_remote_server_key() if transport else None

        attempt.update({
            "success": True,
            "result": "authenticated",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "remote_ssh_version": remote_version,
            "server_host_key": {
                "algorithm": server_key.get_name() if server_key else None,
                "fingerprint_sha256": sha256_fingerprint(server_key) if server_key else None,
            },
        })

        enrichment = collect_read_only(client, command_timeout) if collect_commands else {
            "identity": {},
            "network": {
                "interfaces": [],
                "routes": [],
                "ipv4_forwarding": None,
                "candidate_networks": [],
                "candidate_network_count": 0,
            },
            "command_evidence": [],
        }
        return attempt, enrichment
    except Exception as exc:
        attempt.update({
            "success": False,
            "result": "authentication_or_connection_failed",
            "error_type": type(exc).__name__,
            "error": _safe_exception_message(exc),
            "duration_ms": int((time.monotonic() - started) * 1000),
        })
        return attempt, None
    finally:
        # Ensure the secret doesn't remain in a long-lived variable after use.
        password = None
        try:
            client.close()
        except Exception:
            pass


def write_output(output_dir: Path, run_label: str, payload: Dict[str, Any]) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"P01-SSH-Enrichment_{timestamp}_{safe_label(run_label)}.json"
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
    parser = argparse.ArgumentParser(description="Orizon IT P01 SSH Credentialed Enrichment v0.4b.2")
    parser.add_argument("--profiles", required=True, help="Credential profile JSON.")
    parser.add_argument("--target", required=True, help="Authorized IPv4 target.")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--max-candidates", type=int, default=2, help="Maximum matching credential profiles to try (1-3).")
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--command-timeout", type=float, default=8.0)
    parser.add_argument("--host-key-policy", choices=["tofu", "strict"], default="tofu")
    parser.add_argument("--known-hosts", default=str(Path.home() / ".orizonit" / "p01" / "known_hosts"))
    parser.add_argument("--auth-only", action="store_true", help="Authenticate only; do not execute read-only enrichment commands.")
    parser.add_argument("--output-dir", default="./output")
    parser.add_argument("--run-label", default="ssh-enrichment")
    parser.add_argument("--ack-authorized-access", action="store_true", help="Required: operator confirms authorization to authenticate to the target.")
    args = parser.parse_args(argv)

    if not args.ack_authorized_access:
        parser.error("--ack-authorized-access is required.")
    try:
        target = ipaddress.ip_address(args.target)
    except ValueError:
        parser.error("--target must be a valid IPv4 address.")
    if target.version != 4:
        parser.error("Only IPv4 targets are supported in v0.4b.2.")
    if not (1 <= args.port <= 65535):
        parser.error("--port must be 1..65535.")
    if not (1 <= args.max_candidates <= 3):
        parser.error("--max-candidates must be 1..3.")
    if not (0.5 <= args.connect_timeout <= 30):
        parser.error("--connect-timeout must be between 0.5 and 30 seconds.")
    if not (0.5 <= args.command_timeout <= 30):
        parser.error("--command-timeout must be between 0.5 and 30 seconds.")

    validate_command_catalog()

    errors: List[Dict[str, Any]] = []
    limitations: List[Dict[str, Any]] = [
        {
            "section": "credentialed_enrichment",
            "message": "v0.4b.2 implements SSH password authentication only; SNMP and WinRM/WMI are later increments.",
        },
        {
            "section": "dynamic_scope",
            "message": "Networks learned from interfaces/routes are candidate evidence only and are never automatically scanned by this component.",
        },
    ]
    warnings: List[Dict[str, Any]] = []

    try:
        cred = _credential_api()
        doc = cred.load_profiles(Path(args.profiles))
        matches = cred.match_profiles(doc, str(target), "ssh", max_candidates=args.max_candidates)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Credential profile error: {_safe_exception_message(exc)}", file=sys.stderr)
        return 2

    if not matches:
        warnings.append({
            "section": "credentials",
            "message": "No enabled SSH credential profile matched the target scope.",
        })

    attempts: List[Dict[str, Any]] = []
    enrichment: Optional[Dict[str, Any]] = None
    selected_profile_id: Optional[str] = None

    for match in matches:
        # Exactly one authentication attempt per matched profile. We do not
        # repeat the same secret even if max_attempts_per_target > 1.
        attempt, collected = connect_with_profile(
            target=str(target),
            port=args.port,
            profile_match=match,
            known_hosts=Path(args.known_hosts).expanduser(),
            host_key_policy=args.host_key_policy,
            connect_timeout=args.connect_timeout,
            command_timeout=args.command_timeout,
            collect_commands=not args.auth_only,
        )
        attempts.append(attempt)
        if attempt.get("success"):
            enrichment = collected
            selected_profile_id = attempt.get("profile_id")
            break

    auth_success = selected_profile_id is not None
    if matches and not auth_success:
        warnings.append({
            "section": "authentication",
            "message": f"Authentication did not succeed after {len(attempts)} bounded profile attempt(s). No further profiles were tried.",
        })

    candidate_network_count = 0
    if enrichment:
        candidate_network_count = int(enrichment.get("network", {}).get("candidate_network_count", 0))

    payload: Dict[str, Any] = {
        "metadata": {
            "enricher_name": ENRICHER_NAME,
            "enricher_version": ENRICHER_VERSION,
            "schema_version": SCHEMA_VERSION,
            "collected_at_utc": utc_now_iso(),
            "run_label": args.run_label,
            "execution_host": socket.gethostname(),
            "execution_user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "read_only_mode": True,
            "credentialed": True,
            "authorization_acknowledged": True,
            "secret_values_persisted_to_output": False,
            "error_count": len(errors),
            "limitation_count": len(limitations),
            "warning_count": len(warnings),
        },
        "target": {
            "ip": str(target),
            "port": args.port,
            "protocol": "ssh",
        },
        "credential_policy": {
            "matching_profiles": len(matches),
            "max_candidates": args.max_candidates,
            "attempts_made": len(attempts),
            "selected_profile_id": selected_profile_id,
            "stopped_after_success": auth_success,
            "same_profile_retries": 0,
        },
        "authentication": {
            "success": auth_success,
            "attempts": attempts,
        },
        "enrichment": enrichment,
        "summary": {
            "authentication_success": auth_success,
            "candidate_networks_discovered": candidate_network_count,
        },
        "errors": errors,
        "limitations": limitations,
        "warnings": warnings,
    }

    out, sha = write_output(Path(args.output_dir), args.run_label, payload)
    print("SSH credentialed enrichment finalizado.")
    print(f"Target: {target}:{args.port}")
    print(f"Autenticação: {'SUCESSO' if auth_success else 'FALHA'}")
    print(f"Tentativas: {len(attempts)}")
    print(f"Candidate networks: {candidate_network_count}")
    print(f"JSON: {out}")
    print(f"SHA256: {sha}")
    print(f"Erros: {len(errors)} | Limitações: {len(limitations)} | Avisos: {len(warnings)}")
    return 0 if auth_success else 3


if __name__ == "__main__":
    raise SystemExit(main())
