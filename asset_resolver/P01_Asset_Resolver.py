#!/usr/bin/env python3
"""Orizon IT P01 Asset Resolver v0.4c.0.

Offline-only evidence correlation:
- consumes Network Discovery plus credentialed target/full enrichment JSON;
- preserves source and field-level provenance;
- never merges on IP alone;
- prefers deterministic, corroborated identity signals;
- records conflicts instead of silently overwriting;
- never resolves secrets, authenticates, scans, pivots, or expands scope.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

NAME = "P01-Asset-Resolver"
VERSION = "0.4c.0"
SCHEMA_VERSION = "0.4c"

STRENGTH_RANK = {
    "declared": 10,
    "weak": 20,
    "medium": 50,
    "observed": 65,
    "strong": 80,
    "credentialed_confirmed": 95,
}

SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(password|passwd|pwd|secret|token|community|passphrase|private_key)(_|$)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PREFIXES = ("wincred://", "prompt://", "env://")

GENERIC_SERIALS = {
    "",
    "0",
    "none",
    "unknown",
    "default string",
    "to be filled by o.e.m.",
    "system serial number",
}


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "asset-resolver")).strip("-")
    return cleaned or "asset-resolver"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: JSON root must be an object")
    return value


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def verify_sidecar(path: Path) -> Optional[bool]:
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if not sidecar.exists():
        return None
    expected = sidecar.read_text(encoding="utf-8-sig").strip().split()[0].lower()
    return expected == digest_file(path).lower()


def norm_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def norm_hostname(value: Any) -> Optional[str]:
    text = norm_text(value)
    if not text:
        return None
    return text.rstrip(".").lower()


def short_hostname(value: Any) -> Optional[str]:
    host = norm_hostname(value)
    if not host:
        return None
    return host.split(".", 1)[0]


def norm_mac(value: Any) -> Optional[str]:
    text = norm_text(value)
    if not text:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(compact) != 12:
        return text.lower()
    return ":".join(compact[i:i+2] for i in range(0, 12, 2)).lower()


def valid_serial(value: Any) -> Optional[str]:
    text = norm_text(value)
    if not text:
        return None
    if text.lower() in GENERIC_SERIALS:
        return None
    return text.strip()


def valid_ip(value: Any) -> Optional[str]:
    text = norm_text(value)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def field_claim(field: str, value: Any, source_id: str, strength: str, evidence: str) -> Dict[str, Any]:
    return {
        "field": field,
        "value": value,
        "source_id": source_id,
        "strength": strength,
        "evidence": evidence,
    }


def source_descriptor(path: Path, doc: Mapping[str, Any], source_kind: str) -> Dict[str, Any]:
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    return {
        "source_id": f"src-{digest_file(path)[:16]}",
        "source_kind": source_kind,
        "file_name": path.name,
        "sha256": digest_file(path),
        "sha256_verified": verify_sidecar(path),
        "run_label": metadata.get("run_label"),
        "collected_at_utc": metadata.get("collected_at_utc") or metadata.get("generated_at_utc"),
    }


def source_kind(doc: Mapping[str, Any]) -> str:
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    if metadata.get("scanner_name") == "P01-Network-Discovery-Scanner":
        return "network_discovery"
    if metadata.get("executor_name") == "P01-Credentialed-Discovery-Executor" and "action" in doc:
        return "credentialed_target"
    if metadata.get("adapter_name") == "P01-WinRM-Credentialed-Enrichment":
        return "winrm_enrichment"
    if metadata.get("enricher_name") == "P01-SSH-Credentialed-Enrichment":
        return "ssh_enrichment"
    raise ValueError("Unsupported P01 evidence document")


def _service_list(open_ports: Any) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for item in open_ports or []:
        if not isinstance(item, Mapping):
            continue
        port = item.get("port")
        protocol = str(item.get("protocol") or "tcp").lower()
        service = norm_text(item.get("service"))
        if isinstance(port, int):
            output.append({"port": port, "protocol": protocol, "service": service})
    return output


def network_observations(path: Path, doc: Mapping[str, Any]) -> List[Dict[str, Any]]:
    src = source_descriptor(path, doc, "network_discovery")
    observations: List[Dict[str, Any]] = []
    for idx, asset in enumerate(doc.get("assets", []) or []):
        if not isinstance(asset, Mapping):
            continue
        ip = valid_ip(asset.get("ip"))
        if not ip:
            continue
        hostname = norm_hostname(asset.get("hostname"))
        fqdn = hostname if hostname and "." in hostname else None
        short = short_hostname(hostname)
        mac = norm_mac(asset.get("mac"))
        obs_id = f"obs-{src['sha256'][:12]}-{idx:04d}"
        claims: List[Dict[str, Any]] = []
        if hostname:
            claims.append(field_claim("hostname", short or hostname, src["source_id"], "medium", "network_discovery_hostname"))
        if fqdn:
            claims.append(field_claim("fqdn", fqdn, src["source_id"], "medium", "reverse_dns_or_local_hostname"))
        if asset.get("device_type_guess"):
            claims.append(field_claim("device_class", asset.get("device_type_guess"), src["source_id"], "medium", "network_fingerprint"))
        if asset.get("os_guess"):
            claims.append(field_claim("os_family", asset.get("os_guess"), src["source_id"], "medium", "network_fingerprint"))
        observations.append({
            "observation_id": obs_id,
            "source": src,
            "kind": "network_discovery",
            "target_ip": ip,
            "hostnames": sorted({x for x in (hostname, short) if x}),
            "fqdn": fqdn,
            "short_hostname": short,
            "macs": [mac] if mac else [],
            "strong_ids": [],
            "claims": claims,
            "addresses": [ip],
            "services": _service_list(asset.get("open_ports")),
            "interfaces": [],
            "raw_confidence": asset.get("confidence"),
        })
    return observations


def _unwrap_credentialed(doc: Mapping[str, Any]) -> Tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], str]:
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    if metadata.get("executor_name") == "P01-Credentialed-Discovery-Executor":
        action = doc.get("action") if isinstance(doc.get("action"), Mapping) else {}
        enrichment = doc.get("enrichment") if isinstance(doc.get("enrichment"), Mapping) else {}
        authentication = doc.get("authentication") if isinstance(doc.get("authentication"), Mapping) else {}
        return action, enrichment, authentication, "credentialed_target"
    target = doc.get("target") if isinstance(doc.get("target"), Mapping) else {}
    context = doc.get("context") if isinstance(doc.get("context"), Mapping) else {}
    action = {
        "target_ip": target.get("ip"),
        "hostname": context.get("hostname"),
        "device_type": context.get("device_type"),
        "os_family": context.get("os_family"),
        "realm": context.get("realm"),
        "protocol": target.get("protocol"),
    }
    enrichment = doc.get("enrichment") if isinstance(doc.get("enrichment"), Mapping) else {}
    authentication = doc.get("authentication") if isinstance(doc.get("authentication"), Mapping) else {}
    return action, enrichment, authentication, source_kind(doc)


def _interface_addresses(enrichment: Mapping[str, Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
    network = enrichment.get("network") if isinstance(enrichment.get("network"), Mapping) else {}
    addresses: List[str] = []
    interfaces_out: List[Dict[str, Any]] = []
    for iface in network.get("interfaces", []) or []:
        if not isinstance(iface, Mapping):
            continue
        name = iface.get("interface_alias") or iface.get("name") or iface.get("interface")
        iface_addresses: List[str] = []
        ipv4 = iface.get("ipv4")
        if isinstance(ipv4, list):
            for item in ipv4:
                if isinstance(item, Mapping):
                    ip = valid_ip(item.get("address"))
                else:
                    ip = valid_ip(item)
                if ip:
                    addresses.append(ip)
                    iface_addresses.append(ip)
        elif isinstance(ipv4, Mapping):
            ip = valid_ip(ipv4.get("address"))
            if ip:
                addresses.append(ip)
                iface_addresses.append(ip)
        interfaces_out.append({
            "name": name,
            "ipv4": sorted(set(iface_addresses)),
        })
    return sorted(set(addresses)), interfaces_out


def credentialed_observation(path: Path, doc: Mapping[str, Any]) -> Dict[str, Any]:
    kind = source_kind(doc)
    src = source_descriptor(path, doc, kind)
    action, enrichment, authentication, unwrapped_kind = _unwrap_credentialed(doc)
    ip = valid_ip(action.get("target_ip") or action.get("ip"))
    if not ip:
        raise ValueError(f"{path}: credentialed evidence does not contain a valid target IP")

    identity = enrichment.get("identity") if isinstance(enrichment.get("identity"), Mapping) else {}
    operating_system = enrichment.get("operating_system") if isinstance(enrichment.get("operating_system"), Mapping) else {}

    hostname_values = [
        norm_hostname(action.get("hostname")),
        norm_hostname(identity.get("computer_name")),
        norm_hostname(identity.get("hostname")),
        norm_hostname(identity.get("fqdn")),
    ]
    hostnames = sorted({x for x in hostname_values if x})
    fqdn = norm_hostname(identity.get("fqdn"))
    if not fqdn:
        fqdn = next((x for x in hostnames if "." in x), None)
    short = short_hostname(identity.get("computer_name") or identity.get("hostname") or fqdn or action.get("hostname"))

    strong_ids: List[Dict[str, Any]] = []
    serial = valid_serial(identity.get("serial_number"))
    if serial:
        strong_ids.append({"type": "serial_number", "value": serial.lower()})

    server_key = authentication.get("server_host_key")
    if isinstance(server_key, Mapping):
        fp = norm_text(server_key.get("fingerprint_sha256"))
        if fp:
            strong_ids.append({"type": "ssh_host_key_sha256", "value": fp.lower()})

    addresses, interfaces = _interface_addresses(enrichment)
    addresses = sorted(set(addresses + [ip]))

    claims: List[Dict[str, Any]] = []
    if short:
        claims.append(field_claim("hostname", short, src["source_id"], "credentialed_confirmed", "credentialed_identity"))
    if fqdn:
        claims.append(field_claim("fqdn", fqdn, src["source_id"], "credentialed_confirmed", "credentialed_identity"))

    device_type = action.get("device_type")
    if device_type:
        claims.append(field_claim("device_class", device_type, src["source_id"], "observed", "planned_target_context"))

    os_family = action.get("os_family")
    if os_family:
        claims.append(field_claim("os_family", os_family, src["source_id"], "observed", "planned_target_context"))

    caption = norm_text(operating_system.get("caption"))
    if caption:
        claims.append(field_claim("operating_system", caption, src["source_id"], "credentialed_confirmed", "credentialed_os_collection"))

    domain = norm_hostname(identity.get("domain"))
    part_of_domain = identity.get("part_of_domain")
    if part_of_domain is True and domain:
        claims.append(field_claim("realm_dns_domain", domain, src["source_id"], "credentialed_confirmed", "credentialed_domain_membership"))
        realm_name = norm_text(action.get("realm"))
        if realm_name:
            claims.append(field_claim("realm_name", realm_name, src["source_id"], "credentialed_confirmed", "credentialed_domain_membership"))
        claims.append(field_claim("realm_evidence_state", "credentialed_confirmed", src["source_id"], "credentialed_confirmed", "credentialed_domain_membership"))
    elif action.get("realm"):
        claims.append(field_claim("realm_name", action.get("realm"), src["source_id"], "observed", "planned_target_context"))

    role = identity.get("domain_role")
    if isinstance(role, int):
        if role >= 4:
            claims.append(field_claim("device_class", "Domain Controller", src["source_id"], "credentialed_confirmed", "win32_computersystem_domain_role"))
        elif role == 3:
            claims.append(field_claim("device_class", "Windows Server", src["source_id"], "credentialed_confirmed", "win32_computersystem_domain_role"))
        elif role in (0, 1, 2):
            claims.append(field_claim("device_class", "Windows Workstation", src["source_id"], "credentialed_confirmed", "win32_computersystem_domain_role"))

    services: List[Dict[str, Any]] = []
    protocol = str(action.get("protocol") or "").lower()
    if protocol == "winrm":
        services.append({"port": action.get("port") or 5985, "protocol": "tcp", "service": "winrm"})
    elif protocol == "ssh":
        services.append({"port": action.get("port") or 22, "protocol": "tcp", "service": "ssh"})

    return {
        "observation_id": f"obs-{src['sha256'][:16]}",
        "source": src,
        "kind": unwrapped_kind,
        "target_ip": ip,
        "hostnames": hostnames,
        "fqdn": fqdn,
        "short_hostname": short,
        "macs": [],
        "strong_ids": strong_ids,
        "claims": claims,
        "addresses": addresses,
        "services": services,
        "interfaces": interfaces,
        "raw_confidence": "High" if authentication.get("success") else "Medium",
    }


def manifest_claims_for_observation(obs: Mapping[str, Any], manifest: Mapping[str, Any], source_id: str) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    ip = valid_ip(obs.get("target_ip"))
    fqdn = norm_hostname(obs.get("fqdn"))
    hostnames = [norm_hostname(x) for x in obs.get("hostnames", []) or []]
    candidates = [x for x in [fqdn] + hostnames if x]
    if not ip:
        return claims
    addr = ipaddress.ip_address(ip)

    for domain in manifest.get("domains", []) or []:
        if not isinstance(domain, Mapping):
            continue
        scopes = domain.get("scopes", []) or []
        applies = False
        for scope in scopes:
            try:
                if addr in ipaddress.ip_network(str(scope), strict=False):
                    applies = True
                    break
            except ValueError:
                continue
        if not applies:
            continue

        dns_domain = norm_hostname(domain.get("dns_domain"))
        realm = norm_text(domain.get("netbios_name"))
        if dns_domain:
            claims.append(field_claim("declared_realm_dns_domain", dns_domain, source_id, "declared", "assessment_manifest"))
        if realm:
            claims.append(field_claim("declared_realm_name", realm, source_id, "declared", "assessment_manifest"))

        if dns_domain and any(h == dns_domain or h.endswith("." + dns_domain) for h in candidates):
            claims.append(field_claim("realm_dns_domain", dns_domain, source_id, "observed", "hostname_suffix_matches_declared_domain"))
            if realm:
                claims.append(field_claim("realm_name", realm, source_id, "observed", "hostname_suffix_matches_declared_domain"))
            claims.append(field_claim("realm_evidence_state", "observed", source_id, "observed", "hostname_suffix_matches_declared_domain"))
    return claims


def identity_match_score(obs: Mapping[str, Any], cluster: Mapping[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    obs_strong = {(x.get("type"), str(x.get("value")).lower()) for x in obs.get("strong_ids", []) or [] if x.get("type") and x.get("value")}
    cluster_strong = {(x.get("type"), str(x.get("value")).lower()) for x in cluster.get("strong_ids", []) or [] if x.get("type") and x.get("value")}
    if obs_strong & cluster_strong:
        score += 100
        reasons.append("strong_identifier")

    obs_fqdn = norm_hostname(obs.get("fqdn"))
    cluster_fqdns = {norm_hostname(x) for x in cluster.get("fqdns", []) or [] if norm_hostname(x)}
    if obs_fqdn and obs_fqdn in cluster_fqdns:
        score += 60
        reasons.append("fqdn")

    obs_short = norm_hostname(obs.get("short_hostname"))
    cluster_shorts = {norm_hostname(x) for x in cluster.get("short_hostnames", []) or [] if norm_hostname(x)}
    if obs_short and obs_short in cluster_shorts:
        score += 35
        reasons.append("hostname")

    obs_macs = {norm_mac(x) for x in obs.get("macs", []) or [] if norm_mac(x)}
    cluster_macs = {norm_mac(x) for x in cluster.get("macs", []) or [] if norm_mac(x)}
    if obs_macs & cluster_macs:
        score += 45
        reasons.append("mac")

    obs_ips = {valid_ip(x) for x in obs.get("addresses", []) or [] if valid_ip(x)}
    cluster_ips = {valid_ip(x) for x in cluster.get("addresses", []) or [] if valid_ip(x)}
    if obs_ips & cluster_ips:
        score += 20
        reasons.append("ip")

    return score, reasons


def corroborated_match(reasons: Sequence[str]) -> bool:
    reason_set = set(reasons)
    if "strong_identifier" in reason_set:
        return True
    namespace = bool(reason_set.intersection({"fqdn", "hostname"}))
    network = bool(reason_set.intersection({"mac", "ip"}))
    return namespace and network


def seed_anchor(obs: Mapping[str, Any]) -> str:
    if obs.get("fqdn"):
        return "fqdn:" + str(obs["fqdn"]).lower()
    if obs.get("short_hostname"):
        return "hostname:" + str(obs["short_hostname"]).lower()
    macs = obs.get("macs") or []
    if macs:
        return "mac:" + str(macs[0]).lower()
    return "ip:" + str(obs.get("target_ip"))


def new_cluster(obs: Mapping[str, Any]) -> Dict[str, Any]:
    anchor = seed_anchor(obs)
    asset_id = "ast-" + hashlib.sha256(anchor.encode("utf-8")).hexdigest()[:16]
    cluster = {
        "asset_id": asset_id,
        "seed_anchor": anchor,
        "observation_ids": [],
        "sources": [],
        "strong_ids": [],
        "fqdns": [],
        "short_hostnames": [],
        "macs": [],
        "addresses": [],
        "services": [],
        "interfaces": [],
        "claims": [],
        "correlations": [],
    }
    merge_observation(cluster, obs, score=None, reasons=["seed"])
    return cluster


def _append_unique_dict(items: List[Dict[str, Any]], value: Dict[str, Any], keys: Sequence[str]) -> None:
    identity = tuple(value.get(k) for k in keys)
    if not any(tuple(x.get(k) for k in keys) == identity for x in items):
        items.append(value)


def merge_observation(cluster: Dict[str, Any], obs: Mapping[str, Any], score: Optional[int], reasons: Sequence[str]) -> None:
    cluster["observation_ids"].append(obs["observation_id"])
    src = dict(obs["source"])
    _append_unique_dict(cluster["sources"], src, ("source_id",))
    for item in obs.get("strong_ids", []) or []:
        _append_unique_dict(cluster["strong_ids"], dict(item), ("type", "value"))
    if obs.get("fqdn") and obs["fqdn"] not in cluster["fqdns"]:
        cluster["fqdns"].append(obs["fqdn"])
    if obs.get("short_hostname") and obs["short_hostname"] not in cluster["short_hostnames"]:
        cluster["short_hostnames"].append(obs["short_hostname"])
    for mac in obs.get("macs", []) or []:
        if mac not in cluster["macs"]:
            cluster["macs"].append(mac)
    for ip in obs.get("addresses", []) or []:
        if ip not in cluster["addresses"]:
            cluster["addresses"].append(ip)
    for service in obs.get("services", []) or []:
        if isinstance(service, Mapping):
            _append_unique_dict(cluster["services"], dict(service), ("port", "protocol", "service"))
    for iface in obs.get("interfaces", []) or []:
        if isinstance(iface, Mapping):
            cluster["interfaces"].append(dict(iface))
    cluster["claims"].extend(dict(x) for x in obs.get("claims", []) or [])
    cluster["correlations"].append({
        "observation_id": obs["observation_id"],
        "score": score,
        "matched_evidence": list(reasons),
    })


def claim_values_conflict(field: str, values: Sequence[Any]) -> bool:
    normalized = {str(v).strip().lower() for v in values if v is not None}
    if len(normalized) <= 1:
        return False

    # Evidence-state values are monotonic refinements, not contradictory facts.
    if field == "realm_evidence_state":
        return False

    # Device-class refinement is compatible with a broader family label.
    if field == "device_class":
        windows_family = {"windows host", "windows server", "windows workstation", "domain controller"}
        if normalized.issubset(windows_family):
            return False
        linux_family = {"linux/unix host", "linux host", "linux server"}
        if normalized.issubset(linux_family):
            return False

    return True


def choose_claims(claims: Sequence[Mapping[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    by_field: Dict[str, List[Dict[str, Any]]] = {}
    for claim in claims:
        field = str(claim.get("field") or "")
        if not field:
            continue
        by_field.setdefault(field, []).append(dict(claim))

    resolved: Dict[str, Any] = {}
    provenance: Dict[str, List[Dict[str, Any]]] = {}
    conflicts: List[Dict[str, Any]] = []

    for field, items in sorted(by_field.items()):
        ordered = sorted(
            items,
            key=lambda x: (
                -STRENGTH_RANK.get(str(x.get("strength") or "weak"), 0),
                str(x.get("value") or "").lower(),
                str(x.get("source_id") or ""),
            ),
        )
        resolved[field] = ordered[0].get("value")
        provenance[field] = ordered

        meaningful = [
            x for x in ordered
            if STRENGTH_RANK.get(str(x.get("strength") or "weak"), 0) >= STRENGTH_RANK["medium"]
            and x.get("value") is not None
        ]
        distinct = {}
        for x in meaningful:
            distinct.setdefault(json.dumps(x.get("value"), sort_keys=True, ensure_ascii=False), []).append(x)
        if len(distinct) > 1 and claim_values_conflict(field, [group[0].get("value") for group in distinct.values()]):
            conflicts.append({
                "field": field,
                "values": [group[0].get("value") for group in distinct.values()],
                "claims": meaningful,
                "resolution": "highest_strength_then_deterministic_tiebreak",
            })

    return resolved, provenance, conflicts


def final_asset(cluster: Mapping[str, Any]) -> Dict[str, Any]:
    resolved, provenance, conflicts = choose_claims(cluster.get("claims", []))
    realm_state = resolved.get("realm_evidence_state")
    confidence = "High" if cluster.get("strong_ids") else ("High" if len(cluster.get("sources", [])) >= 2 else "Medium")
    return {
        "asset_id": cluster["asset_id"],
        "identity": {
            "canonical_hostname": resolved.get("hostname"),
            "fqdn": resolved.get("fqdn"),
            "realm_name": resolved.get("realm_name"),
            "realm_dns_domain": resolved.get("realm_dns_domain"),
            "realm_evidence_state": realm_state,
            "device_class": resolved.get("device_class"),
            "os_family": resolved.get("os_family"),
            "operating_system": resolved.get("operating_system"),
        },
        "identifiers": sorted(cluster.get("strong_ids", []), key=lambda x: (str(x.get("type")), str(x.get("value")))),
        "addresses": sorted(set(cluster.get("addresses", [])), key=lambda x: tuple(int(p) for p in x.split("."))),
        "mac_addresses": sorted(set(cluster.get("macs", []))),
        "services": sorted(cluster.get("services", []), key=lambda x: (x.get("protocol") or "", x.get("port") or 0, x.get("service") or "")),
        "network_interfaces": cluster.get("interfaces", []),
        "sources": sorted(cluster.get("sources", []), key=lambda x: (x.get("source_kind") or "", x.get("file_name") or "")),
        "field_provenance": provenance,
        "conflicts": conflicts,
        "correlations": cluster.get("correlations", []),
        "confidence": confidence,
    }


def resolve(
    network_path: Path,
    evidence_paths: Sequence[Path],
    manifest_path: Optional[Path] = None,
    require_evidence_sidecars: bool = False,
) -> Dict[str, Any]:
    network_doc = load_json(network_path)
    if source_kind(network_doc) != "network_discovery":
        raise ValueError("--network must be a P01 Network Discovery JSON")

    checked: List[Tuple[Path, Optional[bool]]] = [(network_path, verify_sidecar(network_path))]
    for p in evidence_paths:
        checked.append((p, verify_sidecar(p)))
    if require_evidence_sidecars:
        missing_or_bad = [str(p) for p, state in checked if state is not True]
        if missing_or_bad:
            raise ValueError("Missing or invalid SHA256 sidecar(s): " + ", ".join(missing_or_bad))

    observations = network_observations(network_path, network_doc)
    network_count = len(observations)

    enrichment_observations: List[Dict[str, Any]] = []
    for path in sorted(set(Path(p) for p in evidence_paths), key=lambda x: x.name.lower()):
        doc = load_json(path)
        enrichment_observations.append(credentialed_observation(path, doc))

    clusters = [new_cluster(obs) for obs in observations]

    unresolved: List[Dict[str, Any]] = []
    ambiguous: List[Dict[str, Any]] = []

    for obs in sorted(enrichment_observations, key=lambda x: (x.get("target_ip") or "", x.get("kind") or "", x.get("observation_id") or "")):
        candidates: List[Tuple[int, str, List[str], Dict[str, Any]]] = []
        for cluster in clusters:
            score, reasons = identity_match_score(obs, cluster)
            if corroborated_match(reasons):
                candidates.append((score, cluster["asset_id"], reasons, cluster))
        candidates.sort(key=lambda x: (-x[0], x[1]))

        if not candidates:
            cluster = new_cluster(obs)
            clusters.append(cluster)
            unresolved.append({
                "observation_id": obs["observation_id"],
                "new_asset_id": cluster["asset_id"],
                "reason": "no_corroborated_match",
            })
            continue

        top = candidates[0]
        competing = [x for x in candidates[1:] if x[0] == top[0]]
        if competing:
            cluster = new_cluster(obs)
            clusters.append(cluster)
            ambiguous.append({
                "observation_id": obs["observation_id"],
                "new_asset_id": cluster["asset_id"],
                "reason": "ambiguous_equal_score",
                "candidates": [{"asset_id": x[1], "score": x[0], "evidence": x[2]} for x in [top] + competing],
            })
            continue

        merge_observation(top[3], obs, top[0], top[2])

    manifest_source = None
    if manifest_path:
        manifest = load_json(manifest_path)
        manifest_source = {
            "source_id": f"src-{digest_file(manifest_path)[:16]}",
            "source_kind": "assessment_manifest",
            "file_name": manifest_path.name,
            "sha256": digest_file(manifest_path),
            "sha256_verified": verify_sidecar(manifest_path),
            "assessment_id": manifest.get("assessment_id"),
        }
        for cluster in clusters:
            pseudo_obs = {
                "target_ip": cluster["addresses"][0] if cluster["addresses"] else None,
                "fqdn": cluster["fqdns"][0] if cluster["fqdns"] else None,
                "hostnames": cluster["fqdns"] + cluster["short_hostnames"],
            }
            claims = manifest_claims_for_observation(pseudo_obs, manifest, manifest_source["source_id"])
            if claims:
                cluster["claims"].extend(claims)
                _append_unique_dict(cluster["sources"], dict(manifest_source), ("source_id",))

    assets = [final_asset(c) for c in clusters]
    assets.sort(key=lambda x: x["asset_id"])

    output = {
        "metadata": {
            "resolver_name": NAME,
            "resolver_version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "generated_at_utc": utc_now_iso(),
            "execution_host": socket.gethostname(),
            "offline_only": True,
            "read_only_mode": True,
            "secret_resolution": False,
            "authentication_attempts": False,
            "network_access_performed": False,
        },
        "inputs": {
            "network_discovery": source_descriptor(network_path, network_doc, "network_discovery"),
            "credentialed_evidence_count": len(evidence_paths),
            "assessment_manifest": manifest_source,
        },
        "summary": {
            "network_assets_seen": network_count,
            "credentialed_observations_seen": len(enrichment_observations),
            "logical_assets_resolved": len(assets),
            "correlated_observations": sum(max(0, len(a["correlations"]) - 1) for a in assets),
            "unresolved_observations": len(unresolved),
            "ambiguous_correlations": len(ambiguous),
            "assets_with_conflicts": sum(bool(a["conflicts"]) for a in assets),
            "assets_with_strong_identifiers": sum(bool(a["identifiers"]) for a in assets),
        },
        "assets": assets,
        "unresolved_observations": unresolved,
        "ambiguous_correlations": ambiguous,
        "limitations": [
            "v0.4c.0 does not use IP address alone as an automatic merge key",
            "v0.4c.0 asset IDs are deterministic from the seed observation identity anchor but are not yet backed by a persistent asset registry",
            "observed realm evidence is namespace/context correlation, not proof of AD membership",
            "no network access, authentication, scope expansion, or secret resolution is performed",
        ],
    }
    assert_no_secret_material(output)
    return output


def assert_no_secret_material(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            safe_security_metadata = str(key) in {"secret_resolution", "secret_values_persisted_to_output"}
            if SENSITIVE_KEY_RE.search(str(key)) and not safe_security_metadata:
                raise ValueError(f"Sensitive key leaked into resolver output: {path}.{key}")
            assert_no_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            assert_no_secret_material(child, f"{path}[{idx}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if any(prefix in lowered for prefix in SENSITIVE_VALUE_PREFIXES):
            raise ValueError(f"Secret provider reference leaked into resolver output at {path}")


def evidence_paths(explicit: Sequence[str], directories: Sequence[str], run_label: Optional[str]) -> List[Path]:
    paths = [Path(x) for x in explicit]
    for raw_dir in directories:
        directory = Path(raw_dir)
        if not directory.exists():
            raise ValueError(f"Evidence directory not found: {directory}")
        for path in directory.glob("P01-Credentialed-Target_*.json"):
            if run_label and run_label not in path.name:
                continue
            paths.append(path)
    unique = sorted({p.resolve() for p in paths}, key=lambda x: x.name.lower())
    if not unique:
        raise ValueError("No credentialed evidence JSON files selected")
    return unique


def write_output(output_dir: Path, run_label: str, payload: Mapping[str, Any]) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = output_dir / f"P01-Asset-Resolver_{timestamp}_{safe_label(run_label)}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sha = out.with_suffix(out.suffix + ".sha256")
    digest = digest_file(out)
    sha.write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    try:
        if os.name != "nt":
            os.chmod(out, 0o600)
            os.chmod(sha, 0o600)
    except OSError:
        pass
    return out, sha


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"{NAME} v{VERSION}")
    p.add_argument("--network", required=True, help="P01 Network Discovery JSON")
    p.add_argument("--evidence", action="append", default=[], help="Credentialed target/enrichment JSON; repeatable")
    p.add_argument("--evidence-dir", action="append", default=[], help="Directory containing P01-Credentialed-Target_*.json")
    p.add_argument("--evidence-run-label", help="When --evidence-dir is used, include only filenames containing this run label")
    p.add_argument("--manifest", help="Optional v0.4b.6 Assessment Manifest JSON")
    p.add_argument("--require-evidence-sidecars", action="store_true", help="Require valid .sha256 sidecars for Network Discovery and all credentialed evidence")
    p.add_argument("--run-label", default="asset-resolver")
    p.add_argument("--output-dir", default="./output")
    args = p.parse_args(argv)

    try:
        selected = evidence_paths(args.evidence, args.evidence_dir, args.evidence_run_label)
        payload = resolve(
            Path(args.network),
            selected,
            manifest_path=Path(args.manifest) if args.manifest else None,
            require_evidence_sidecars=args.require_evidence_sidecars,
        )
    except Exception as exc:
        p.error(str(exc))

    out, sha = write_output(Path(args.output_dir), args.run_label, payload)
    print("Asset Resolver finalizado.")
    print(f"Network assets: {payload['summary']['network_assets_seen']}")
    print(f"Credentialed observations: {payload['summary']['credentialed_observations_seen']}")
    print(f"Logical assets: {payload['summary']['logical_assets_resolved']}")
    print(f"Unresolved: {payload['summary']['unresolved_observations']}")
    print(f"Ambiguous: {payload['summary']['ambiguous_correlations']}")
    print(f"Conflicts: {payload['summary']['assets_with_conflicts']}")
    print(f"JSON: {out}")
    print(f"SHA256: {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
