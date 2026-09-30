#!/usr/bin/env python3
'''Orizon IT P01 Windows WinRM Credentialed Enrichment v0.4b.4.'''

from __future__ import annotations

import argparse
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
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ADAPTER_NAME = "P01-WinRM-Credentialed-Enrichment"
ADAPTER_VERSION = "0.4b.4"
SCHEMA_VERSION = "0.4b"

ROOT = Path(__file__).resolve().parents[1]
CRED_DIR = ROOT / "credential_manager"
if str(CRED_DIR) not in sys.path:
    sys.path.insert(0, str(CRED_DIR))

from P01_Credential_Manager import CredentialConfigError, load_profiles, match_profiles, resolve_secret

try:
    import winrm
except ImportError:
    winrm = None

MUTATING_POWERSHELL_RE = re.compile(
    r"(?im)\b(?:Set|New|Remove|Add|Start|Stop|Restart|Repair|Enable|Disable|Install|Uninstall|Rename|Clear|Reset|Update)-[A-Za-z0-9_-]+"
)

POWERSHELL_AUTH_PROBE = r'''
$ErrorActionPreference = 'Stop'
"P01_WINRM_AUTH_PROBE"
'''.strip()

POWERSHELL_COLLECTION = r'''
$ErrorActionPreference = 'SilentlyContinue'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue

$interfaces = @()
Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    $cfg = $_
    $addresses = @()
    @($cfg.IPv4Address) | ForEach-Object {
        if ($_ -and $_.IPAddress) {
            $addresses += [pscustomobject]@{
                address = [string]$_.IPAddress
                prefix_length = [int]$_.PrefixLength
            }
        }
    }
    $gateways = @()
    @($cfg.IPv4DefaultGateway) | ForEach-Object {
        if ($_ -and $_.NextHop) { $gateways += [string]$_.NextHop }
    }
    $interfaces += [pscustomobject]@{
        interface_alias = [string]$cfg.InterfaceAlias
        interface_index = [int]$cfg.InterfaceIndex
        ipv4 = $addresses
        ipv4_gateways = $gateways
    }
}

$routes = @()
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $routes += [pscustomobject]@{
        destination_prefix = [string]$_.DestinationPrefix
        next_hop = [string]$_.NextHop
        interface_index = [int]$_.InterfaceIndex
        route_metric = [int]$_.RouteMetric
        protocol = [string]$_.Protocol
        state = [string]$_.State
    }
}

$dns = @()
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $dns += [pscustomobject]@{
        interface_alias = [string]$_.InterfaceAlias
        interface_index = [int]$_.InterfaceIndex
        server_addresses = @($_.ServerAddresses | ForEach-Object { [string]$_ })
    }
}

$firewall = @()
Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
    $firewall += [pscustomobject]@{
        name = [string]$_.Name
        enabled = [bool]$_.Enabled
        default_inbound_action = [string]$_.DefaultInboundAction
        default_outbound_action = [string]$_.DefaultOutboundAction
    }
}

$hotfixes = @()
Get-HotFix -ErrorAction SilentlyContinue |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 20 |
    ForEach-Object {
        $hotfixes += [pscustomobject]@{
            hotfix_id = [string]$_.HotFixID
            description = [string]$_.Description
            installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null }
        }
    }

$secureChannel = $null
$secureChannelChecked = $false
if ($cs.PartOfDomain -and [int]$cs.DomainRole -lt 4) {
    $secureChannelChecked = $true
    try {
        $secureChannel = [bool](Test-ComputerSecureChannel -ErrorAction Stop)
    } catch {
        $secureChannel = $null
    }
}

$localAdmins = @()
if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
    try {
        Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
            $localAdmins += [pscustomobject]@{
                name = [string]$_.Name
                object_class = [string]$_.ObjectClass
                principal_source = [string]$_.PrincipalSource
            }
        }
    } catch {}
}

$roles = @()
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Get-WindowsFeature -ErrorAction SilentlyContinue |
        Where-Object { $_.Installed } |
        ForEach-Object {
            $roles += [pscustomobject]@{
                name = [string]$_.Name
                display_name = [string]$_.DisplayName
            }
        }
}

$result = [ordered]@{
    identity = [ordered]@{
        computer_name = [string]$env:COMPUTERNAME
        fqdn = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $null }
        manufacturer = [string]$cs.Manufacturer
        model = [string]$cs.Model
        serial_number = [string]$bios.SerialNumber
        domain = [string]$cs.Domain
        part_of_domain = [bool]$cs.PartOfDomain
        domain_role = [int]$cs.DomainRole
        current_user = [string]$env:USERNAME
    }
    operating_system = [ordered]@{
        caption = [string]$os.Caption
        version = [string]$os.Version
        build_number = [string]$os.BuildNumber
        architecture = [string]$os.OSArchitecture
        last_boot_up_time = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { $null }
        install_date = if ($os.InstallDate) { $os.InstallDate.ToString('o') } else { $null }
    }
    hardware = [ordered]@{
        logical_processors = [int]$cs.NumberOfLogicalProcessors
        total_physical_memory_bytes = [UInt64]$cs.TotalPhysicalMemory
        cpu_name = if ($cpu) { [string]$cpu.Name } else { $null }
    }
    network = [ordered]@{
        interfaces = $interfaces
        routes = $routes
        dns = $dns
    }
    security = [ordered]@{
        firewall_profiles = $firewall
        secure_channel_checked = $secureChannelChecked
        secure_channel_healthy = $secureChannel
        local_administrators = $localAdmins
    }
    patching = [ordered]@{
        recent_hotfixes = $hotfixes
    }
    services = [ordered]@{
        winrm = if ($winrmService) {
            [pscustomobject]@{
                status = [string]$winrmService.Status
                start_type = [string]$winrmService.StartType
            }
        } else { $null }
    }
    roles = $roles
}

$result | ConvertTo-Json -Depth 10 -Compress
'''.strip()

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def safe_label(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return value.strip("-")[:80] or "run"

def safe_error(exc: Exception) -> str:
    text = str(exc or "").strip()
    text = re.sub(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*\S+", r"\1=<redacted>", text)
    text = re.sub(r"(?i)://[^/@:\s]+:[^/@\s]+@", "://<redacted>@", text)
    return text[:500] or type(exc).__name__

def powershell_is_read_only(script: str) -> bool:
    return MUTATING_POWERSHELL_RE.search(script) is None

def validate_scripts() -> None:
    for name, script in {"auth_probe": POWERSHELL_AUTH_PROBE, "collection": POWERSHELL_COLLECTION}.items():
        if not powershell_is_read_only(script):
            raise RuntimeError(f"Mutating PowerShell verb detected in {name} script.")

def decode_stream(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def run_ps(session: Any, script: str) -> Dict[str, Any]:
    validate_scripts()
    started = time.monotonic()
    try:
        response = session.run_ps(script)
        return {
            "success": int(response.status_code) == 0,
            "status_code": int(response.status_code),
            "stdout": decode_stream(response.std_out).strip(),
            "stderr": decode_stream(response.std_err).strip(),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except Exception as exc:
        return {
            "success": False,
            "status_code": None,
            "stdout": "",
            "stderr": "",
            "error_type": type(exc).__name__,
            "error": safe_error(exc),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

def parse_collection_json(stdout: str) -> Dict[str, Any]:
    if not stdout:
        raise ValueError("WinRM collection returned empty stdout.")
    obj = json.loads(stdout)
    if not isinstance(obj, dict):
        raise ValueError("WinRM collection JSON root must be an object.")
    return obj

def build_candidate_networks(collection: Mapping[str, Any]) -> List[Dict[str, Any]]:
    candidates: Dict[str, Dict[str, Any]] = {}
    network = collection.get("network") or {}
    for iface in network.get("interfaces", []) or []:
        if not isinstance(iface, Mapping):
            continue
        alias = iface.get("interface_alias")
        for addr in iface.get("ipv4", []) or []:
            if not isinstance(addr, Mapping):
                continue
            try:
                ip = ipaddress.ip_address(str(addr.get("address")))
                prefix = int(addr.get("prefix_length"))
                net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            except Exception:
                continue
            if net.version != 4 or net.is_loopback or net.is_link_local or net.is_multicast:
                continue
            item = candidates.setdefault(str(net), {
                "network": str(net), "is_private": net.is_private,
                "authorization_status": "unassessed", "auto_scan": False, "sources": []
            })
            item["sources"].append({
                "evidence": "interface_address", "interface": alias,
                "address": str(ip), "prefix_length": prefix
            })
    for route in network.get("routes", []) or []:
        if not isinstance(route, Mapping):
            continue
        prefix = str(route.get("destination_prefix") or "")
        if not prefix or prefix == "0.0.0.0/0":
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.is_loopback or net.is_link_local or net.is_multicast:
            continue
        item = candidates.setdefault(str(net), {
            "network": str(net), "is_private": net.is_private,
            "authorization_status": "unassessed", "auto_scan": False, "sources": []
        })
        item["sources"].append({
            "evidence": "route_table", "interface_index": route.get("interface_index"),
            "next_hop": route.get("next_hop")
        })
    result = list(candidates.values())
    result.sort(key=lambda x: (int(ipaddress.ip_network(x["network"]).network_address), ipaddress.ip_network(x["network"]).prefixlen))
    return result

def build_context(scheme: str, device_type: str, os_family: str, hostname: Optional[str], vendor: Optional[str], realm: Optional[str], confidence: str) -> Dict[str, Any]:
    return {
        "device_type": device_type,
        "os_family": os_family,
        "hostname": hostname,
        "vendor": vendor,
        "realm": realm,
        "confidence": confidence,
        "services": ["winrm-https" if scheme == "https" else "winrm-http"],
    }

def create_session(target: str, port: int, scheme: str, username: str, password: str, transport: str, server_cert_validation: str) -> Any:
    if winrm is None:
        raise RuntimeError("pywinrm is required. Install from credentialed_enrichment/requirements-winrm.txt")
    kwargs: Dict[str, Any] = {"auth": (username, password), "transport": transport}
    if scheme == "https":
        kwargs["server_cert_validation"] = server_cert_validation
    return winrm.Session(f"{scheme}://{target}:{port}/wsman", **kwargs)

def attempt_profile(profile_match: Any, target: str, port: int, scheme: str, transport: str, server_cert_validation: str, auth_only: bool) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    profile = profile_match.profile
    profile_id = str(profile.get("id") or "")
    username = str(profile.get("username") or "").strip()
    password_ref = (profile.get("secret_refs") or {}).get("password")
    attempt: Dict[str, Any] = {
        "profile_id": profile_id, "protocol": "winrm", "username": username or None,
        "matched_scope": profile_match.matched_scope,
        "scope_prefix_length": profile_match.prefix_length,
        "selector_score": profile_match.selector_score,
        "matched_selectors": list(profile_match.matched_selectors),
        "transport": transport, "scheme": scheme, "success": False,
    }
    if str(profile.get("auth_type") or "").lower() != "password":
        attempt["result"] = "unsupported_auth_type"
        return attempt, None
    if not username or not password_ref:
        attempt["result"] = "profile_incomplete"
        return attempt, None
    try:
        password = resolve_secret(str(password_ref), prompt_label=f"WinRM secret for {profile_id}: ")
    except Exception as exc:
        attempt.update({"result": "secret_resolution_failed", "error_type": type(exc).__name__, "error": safe_error(exc)})
        return attempt, None
    try:
        session = create_session(target, port, scheme, username, password, transport, server_cert_validation)
        probe = run_ps(session, POWERSHELL_AUTH_PROBE)
        if not probe.get("success") or probe.get("stdout") != "P01_WINRM_AUTH_PROBE":
            attempt.update({
                "result": "authentication_or_remote_execution_failed",
                "probe_status_code": probe.get("status_code"),
                "error": probe.get("error") or probe.get("stderr") or "WinRM auth probe failed",
                "error_type": probe.get("error_type"),
            })
            return attempt, None
        attempt.update({"success": True, "result": "authenticated", "probe_status_code": probe.get("status_code")})
        if auth_only:
            return attempt, {
                "collection_status": "auth_only",
                "identity": {},
                "network": {"interfaces": [], "routes": [], "dns": [], "candidate_networks": [], "candidate_network_count": 0},
            }
        collected = run_ps(session, POWERSHELL_COLLECTION)
        if not collected.get("success"):
            return attempt, {
                "collection_status": "authenticated_collection_failed",
                "collection_error": {
                    "status_code": collected.get("status_code"),
                    "stderr": collected.get("stderr"),
                    "error_type": collected.get("error_type"),
                    "error": collected.get("error"),
                },
                "identity": {},
                "network": {"interfaces": [], "routes": [], "dns": [], "candidate_networks": [], "candidate_network_count": 0},
            }
        payload = parse_collection_json(collected.get("stdout") or "")
        candidates = build_candidate_networks(payload)
        payload.setdefault("network", {})["candidate_networks"] = candidates
        payload["network"]["candidate_network_count"] = len(candidates)
        payload["collection_status"] = "collected"
        payload["collection_evidence"] = {
            "status_code": collected.get("status_code"),
            "duration_ms": collected.get("duration_ms"),
            "powershell_read_only_allowlist": True,
        }
        return attempt, payload
    except Exception as exc:
        attempt.update({"result": "authentication_or_connection_failed", "error_type": type(exc).__name__, "error": safe_error(exc)})
        return attempt, None
    finally:
        password = None

def write_output(output_dir: Path, run_label: str, payload: Mapping[str, Any]) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = output_dir / f"P01-WinRM-Enrichment_{timestamp}_{safe_label(run_label)}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    sha = out.with_suffix(out.suffix + ".sha256")
    sha.write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    return out, sha

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="P01 WinRM Credentialed Enrichment v0.4b.4")
    p.add_argument("--profiles", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--scheme", choices=["http", "https"], default="http")
    p.add_argument("--port", type=int)
    p.add_argument("--transport", choices=["ntlm"], default="ntlm")
    p.add_argument("--server-cert-validation", choices=["validate", "ignore"], default="validate")
    p.add_argument("--realm")
    p.add_argument("--hostname")
    p.add_argument("--vendor")
    p.add_argument("--device-type", default="Windows Host")
    p.add_argument("--os-family", default="Windows")
    p.add_argument("--confidence", default="High")
    p.add_argument("--max-candidates", type=int, default=1)
    p.add_argument("--auth-only", action="store_true")
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--run-label", default="winrm-enrichment")
    p.add_argument("--ack-authorized-access", action="store_true")
    args = p.parse_args(argv)
    if not args.ack_authorized_access:
        p.error("--ack-authorized-access is required.")
    target = ipaddress.ip_address(args.target)
    if target.version != 4:
        p.error("Only IPv4 is supported.")
    port = args.port if args.port is not None else (5986 if args.scheme == "https" else 5985)
    validate_scripts()
    try:
        doc = load_profiles(Path(args.profiles))
        context = build_context(args.scheme, args.device_type, args.os_family, args.hostname, args.vendor, args.realm, args.confidence)
        matches = match_profiles(doc, str(target), "winrm", args.max_candidates, context=context)
    except (CredentialConfigError, OSError, ValueError) as exc:
        print(f"Credential profile error: {safe_error(exc)}", file=sys.stderr)
        return 2

    errors: List[Dict[str, Any]] = []
    limitations = [
        {"section": "transport", "message": "v0.4b.4 validates password authentication using NTLM transport first; Kerberos/certificate/CredSSP are later increments."},
        {"section": "dynamic_scope", "message": "Candidate networks are evidence only and are never automatically scanned by this adapter."},
    ]
    warnings: List[Dict[str, Any]] = []
    if not matches:
        warnings.append({"section": "credentials", "message": "No eligible WinRM credential profile matched the target context."})

    attempts, enrichment, selected = [], None, None
    for match in matches:
        attempt, collected = attempt_profile(match, str(target), port, args.scheme, args.transport, args.server_cert_validation, args.auth_only)
        attempts.append(attempt)
        if attempt.get("success"):
            selected, enrichment = str(attempt.get("profile_id")), collected
            break
    auth_success = selected is not None
    if matches and not auth_success:
        warnings.append({"section": "authentication", "message": f"WinRM authentication did not succeed after {len(attempts)} bounded profile attempt(s)."})

    collection_status = enrichment.get("collection_status") if enrichment else None
    candidate_count = int((enrichment.get("network") or {}).get("candidate_network_count", 0)) if enrichment else 0
    payload = {
        "metadata": {
            "adapter_name": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION,
            "schema_version": SCHEMA_VERSION, "collected_at_utc": utc_now_iso(),
            "run_label": args.run_label, "execution_host": socket.gethostname(),
            "execution_user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "read_only_mode": True, "credentialed": True,
            "authorization_acknowledged": True, "secret_values_persisted_to_output": False,
            "error_count": len(errors), "limitation_count": len(limitations), "warning_count": len(warnings),
        },
        "target": {"ip": str(target), "port": port, "protocol": "winrm", "scheme": args.scheme, "transport": args.transport},
        "context": context,
        "credential_policy": {
            "matching_profiles": len(matches), "max_candidates": args.max_candidates,
            "attempts_made": len(attempts), "selected_profile_id": selected,
            "stopped_after_success": auth_success, "same_profile_retries": 0,
        },
        "authentication": {"success": auth_success, "attempts": attempts},
        "enrichment": enrichment,
        "summary": {"authentication_success": auth_success, "collection_status": collection_status, "candidate_networks_discovered": candidate_count},
        "errors": errors, "limitations": limitations, "warnings": warnings,
    }
    out, sha = write_output(Path(args.output_dir), args.run_label, payload)
    print("WinRM credentialed enrichment finalizado.")
    print(f"Target: {args.scheme}://{target}:{port}/wsman")
    print(f"Autenticação: {'SUCESSO' if auth_success else 'FALHA'}")
    print(f"Tentativas: {len(attempts)}")
    print(f"Collection status: {collection_status}")
    print(f"Candidate networks: {candidate_count}")
    print(f"JSON: {out}")
    print(f"SHA256: {sha}")
    return 0 if auth_success else 3

if __name__ == "__main__":
    raise SystemExit(main())
