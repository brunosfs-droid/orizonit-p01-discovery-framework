#!/usr/bin/env python3
"""Orizon IT P01 Assessment Context & Credential Intake v0.4b.6.

Creates and validates non-secret assessment context and writes credential
profile metadata without ever storing secret values in the manifest/profile
files. Runtime discovery remains deterministic and non-interactive.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

VERSION = "0.4b.6"
MANIFEST_SCHEMA_VERSION = "0.4b.6"

REALM_KINDS = {
    "ad_domain",
    "local_host",
    "linux_local",
    "vcenter_sso",
    "network_aaa",
    "device_local",
    "other",
}
TARGET_CLASSES = {
    "windows",
    "windows_server",
    "windows_workstation",
    "domain_controller",
    "linux",
    "vcenter",
    "esxi",
    "network_device",
    "switch",
    "router",
    "firewall",
    "storage",
    "appliance",
    "other",
}
PRIVILEGE_CLASSES = {
    "read_only",
    "inventory",
    "operator",
    "local_admin",
    "domain_admin",
    "platform_admin",
    "network_admin",
}
PURPOSES = {
    "discovery",
    "inventory",
    "configuration_audit",
    "patch_assessment",
    "topology",
}
HIGH_PRIVILEGE = {"domain_admin", "platform_admin", "network_admin"}
REALM_EVIDENCE_STATES = {"declared", "observed", "credentialed_confirmed"}
SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "community", "passphrase", "private_key"}

ROOT = Path(__file__).resolve().parents[1]
CRED_DIR = ROOT / "credential_manager"
if str(CRED_DIR) not in sys.path:
    sys.path.insert(0, str(CRED_DIR))

from P01_Credential_Manager import validate_profile_document  # noqa: E402


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _parse_ipv4_network(value: str) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(str(value), strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 assessment scopes are supported in v0.4b.6")
    return network


def _detect_secret_fields(value: Any, path: str = "$") -> List[str]:
    findings: List[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if str(key).lower() in SENSITIVE_KEYS and child not in (None, "", False):
                findings.append(f"{child_path} is not allowed in an Assessment Manifest")
            findings.extend(_detect_secret_fields(child, child_path))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            findings.extend(_detect_secret_fields(child, f"{path}[{idx}]"))
    return findings


def validate_manifest(doc: Mapping[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    if doc.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be '{MANIFEST_SCHEMA_VERSION}', got {doc.get('schema_version')!r}"
        )

    assessment_id = str(doc.get("assessment_id") or "").strip()
    if not assessment_id:
        errors.append("assessment_id is required")

    errors.extend(_detect_secret_fields(doc))

    authorized = doc.get("authorized_scopes")
    if not isinstance(authorized, list) or not authorized:
        errors.append("authorized_scopes must be a non-empty array")
        authorized = []
    authorized_nets: List[ipaddress.IPv4Network] = []
    for raw in authorized:
        try:
            net = _parse_ipv4_network(str(raw))
            authorized_nets.append(net)
            if net.prefixlen == 0:
                errors.append("authorized_scopes may not contain 0.0.0.0/0")
            elif net.prefixlen < 16:
                warnings.append(f"broad authorized scope declared: {net}")
        except Exception as exc:
            errors.append(f"invalid authorized scope {raw!r}: {exc}")

    excludes = doc.get("exclude_scopes", [])
    if not isinstance(excludes, list):
        errors.append("exclude_scopes must be an array")
        excludes = []
    for raw in excludes:
        try:
            _parse_ipv4_network(str(raw))
        except Exception as exc:
            errors.append(f"invalid exclude scope {raw!r}: {exc}")

    domains = doc.get("domains", [])
    if not isinstance(domains, list):
        errors.append("domains must be an array")
        domains = []
    seen_dns = set()
    for idx, item in enumerate(domains):
        base = f"domains[{idx}]"
        if not isinstance(item, Mapping):
            errors.append(f"{base} must be an object")
            continue
        dns = str(item.get("dns_domain") or "").strip().lower().rstrip(".")
        netbios = str(item.get("netbios_name") or "").strip()
        state = str(item.get("evidence_state") or "declared").strip().lower()
        scopes = item.get("scopes", [])
        if not dns:
            errors.append(f"{base}.dns_domain is required")
        elif dns in seen_dns:
            errors.append(f"duplicate dns_domain: {dns}")
        else:
            seen_dns.add(dns)
        if not netbios:
            errors.append(f"{base}.netbios_name is required")
        if state != "declared":
            errors.append(f"{base}.evidence_state must be 'declared' in a pre-flight manifest")
        if not isinstance(scopes, list) or not scopes:
            errors.append(f"{base}.scopes must be a non-empty array")
            scopes = []
        for raw in scopes:
            try:
                net = _parse_ipv4_network(str(raw))
                if authorized_nets and not any(net.subnet_of(a) or net == a for a in authorized_nets):
                    warnings.append(f"{base} scope {net} is outside declared authorized_scopes")
            except Exception as exc:
                errors.append(f"{base}.scopes contains invalid network {raw!r}: {exc}")

    allowed = doc.get("allowed_protocols", [])
    if not isinstance(allowed, list) or not all(isinstance(x, str) and x.strip() for x in allowed):
        errors.append("allowed_protocols must be an array of strings")

    policy = doc.get("safety_policy", {})
    if not isinstance(policy, Mapping):
        errors.append("safety_policy must be an object")
    else:
        concurrency = policy.get("default_concurrency", 1)
        max_actions = policy.get("max_actions", 25)
        if not isinstance(concurrency, int) or concurrency < 1 or concurrency > 10:
            errors.append("safety_policy.default_concurrency must be integer 1..10")
        if not isinstance(max_actions, int) or max_actions < 1 or max_actions > 1000:
            errors.append("safety_policy.max_actions must be integer 1..1000")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "assessment_id": assessment_id or None,
        "domain_count": len(domains),
    }


def load_manifest(path: Path) -> Dict[str, Any]:
    doc = _load_json(path)
    result = validate_manifest(doc)
    if not result["valid"]:
        raise ValueError("; ".join(result["errors"]))
    return doc


def manifest_context_for_asset(asset: Mapping[str, Any], manifest: Mapping[str, Any]) -> Dict[str, Any]:
    """Build non-secret context hints from observed asset evidence + declared manifest.

    Declared domains are never promoted to an effective realm by declaration alone.
    An observed hostname suffix may confirm that a declared realm is applicable.
    """
    ip_raw = str(asset.get("ip") or "")
    hostname = str(asset.get("hostname") or "").strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(ip_raw)
    except ValueError:
        ip = None

    device_type = str(asset.get("device_type_guess") or "").strip().lower()
    target_classes: List[str] = []
    if "windows" in device_type:
        target_classes.append("windows")
    elif "linux" in device_type or "unix" in device_type:
        target_classes.append("linux")
    elif "router" in device_type or "gateway" in device_type:
        target_classes.extend(["network_device", "router"])
    elif "network" in device_type or "embedded" in device_type:
        target_classes.append("network_device")

    declared_candidates: List[Dict[str, Any]] = []
    observed: Optional[Dict[str, Any]] = None
    for domain in manifest.get("domains", []) or []:
        if not isinstance(domain, Mapping):
            continue
        applies = False
        if ip is not None:
            for raw_scope in domain.get("scopes", []) or []:
                try:
                    if ip in _parse_ipv4_network(str(raw_scope)):
                        applies = True
                        break
                except Exception:
                    continue
        if not applies:
            continue
        candidate = {
            "realm": domain.get("netbios_name"),
            "dns_domain": domain.get("dns_domain"),
            "realm_kind": "ad_domain",
            "evidence_state": "declared",
        }
        declared_candidates.append(candidate)
        dns = str(domain.get("dns_domain") or "").strip().lower().rstrip(".")
        if hostname and dns and (hostname == dns or hostname.endswith("." + dns)):
            observed = {
                "realm": domain.get("netbios_name"),
                "dns_domain": domain.get("dns_domain"),
                "realm_kind": "ad_domain",
                "evidence_state": "observed",
                "source": "hostname_suffix_matches_declared_domain",
            }

    result = {
        "assessment_id": manifest.get("assessment_id"),
        "target_classes": sorted(set(target_classes)),
        "declared_realm_candidates": declared_candidates,
        "realm": None,
        "realm_kind": None,
        "realm_evidence_state": None,
        "realm_source": None,
    }
    if observed:
        result.update({
            "realm": observed["realm"],
            "realm_kind": observed["realm_kind"],
            "realm_evidence_state": observed["evidence_state"],
            "realm_source": observed["source"],
        })
    return result


def _prompt(label: str, default: Optional[str] = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value or not required:
            return value
        print("Value is required.")


def _prompt_list(label: str, default: Optional[Sequence[str]] = None) -> List[str]:
    default_text = ",".join(default or [])
    value = _prompt(label + " (comma-separated)", default_text or None, required=True)
    return [x.strip() for x in value.split(",") if x.strip()]


def build_manifest(
    assessment_id: str,
    environment_label: str,
    authorized_scopes: Sequence[str],
    exclude_scopes: Sequence[str],
    domains: Sequence[Mapping[str, Any]],
    allowed_protocols: Sequence[str],
) -> Dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "environment_label": environment_label,
        "authorized_scopes": list(authorized_scopes),
        "exclude_scopes": list(exclude_scopes),
        "domains": [dict(x) for x in domains],
        "allowed_protocols": sorted(set(str(x).lower() for x in allowed_protocols)),
        "discovery_nodes": [],
        "safety_policy": {
            "default_concurrency": 1,
            "max_actions": 25,
            "require_authorized_ack": True,
            "auto_expand_scope": False,
        },
    }


def _target_class_defaults(target_classes: Sequence[str]) -> Dict[str, List[str]]:
    classes = set(target_classes)
    device_types: List[str] = []
    os_families: List[str] = []
    if classes.intersection({"windows", "windows_server", "windows_workstation", "domain_controller"}):
        device_types.append("Windows Host")
        os_families.append("Windows")
    if "linux" in classes:
        device_types.append("Linux/Unix Host")
        os_families.append("Linux/Unix-like")
    if "router" in classes:
        device_types.extend(["Router/Gateway", "Network/Embedded Candidate"])
    if classes.intersection({"switch", "firewall", "network_device"}):
        device_types.append("Network/Embedded Candidate")
    return {
        "device_types": sorted(set(device_types)),
        "os_families": sorted(set(os_families)),
    }


def build_credential_profile(
    profile_id: str,
    protocol: str,
    scopes: Sequence[str],
    username: Optional[str],
    secret_ref: str,
    realm_kind: str,
    realm_name: Optional[str],
    target_classes: Sequence[str],
    privilege_class: str,
    purposes: Sequence[str],
    service: str,
    hostname_patterns: Sequence[str],
    realm_evidence_min: str,
    high_privilege_acknowledged: bool,
) -> Dict[str, Any]:
    defaults = _target_class_defaults(target_classes)
    selectors: Dict[str, Any] = {
        "services": [service],
        "min_confidence": "High" if protocol == "winrm" else "Medium",
        "allow_unknown": False,
    }
    if defaults["device_types"]:
        selectors["device_types"] = defaults["device_types"]
    if defaults["os_families"]:
        selectors["os_families"] = defaults["os_families"]
    if hostname_patterns:
        selectors["hostname_patterns"] = list(hostname_patterns)
    if realm_name:
        selectors["realms"] = [realm_name]

    high = privilege_class in HIGH_PRIVILEGE
    return {
        "id": profile_id,
        "enabled": True,
        "protocol": protocol,
        "auth_type": "password",
        "scopes": list(scopes),
        "priority": 10,
        "username": username or None,
        "secret_refs": {"password": secret_ref},
        "max_attempts_per_target": 1,
        "tags": ["assessment-intake"] + list(target_classes),
        "selectors": selectors,
        "failure_budget_per_job": 1 if high else 2,
        "realm_kind": realm_kind,
        "realm_name": realm_name,
        "target_classes": list(target_classes),
        "privilege_class": privilege_class,
        "purposes": list(purposes),
        "realm_evidence_min": realm_evidence_min,
        "high_privilege_acknowledged": bool(high_privilege_acknowledged),
    }


def _domain_arg(value: str) -> Dict[str, Any]:
    parts = [x.strip() for x in value.split(",")]
    if len(parts) < 3:
        raise argparse.ArgumentTypeError("--domain format: DNS,NETBIOS,SCOPE[;SCOPE...][,FOREST]")
    dns, netbios, scopes_raw = parts[:3]
    forest = parts[3] if len(parts) > 3 and parts[3] else dns
    scopes = [x.strip() for x in scopes_raw.split(";") if x.strip()]
    return {
        "dns_domain": dns,
        "netbios_name": netbios,
        "forest": forest,
        "scopes": scopes,
        "evidence_state": "declared",
    }


def cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"P01 Assessment Context & Credential Intake v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create a non-secret Assessment Manifest")
    init.add_argument("--output", required=True)
    init.add_argument("--assessment-id")
    init.add_argument("--environment-label")
    init.add_argument("--authorized-scope", action="append")
    init.add_argument("--exclude-scope", action="append", default=[])
    init.add_argument("--domain", action="append", type=_domain_arg, default=[])
    init.add_argument("--allowed-protocol", action="append")
    init.add_argument("--non-interactive", action="store_true")

    val = sub.add_parser("validate", help="Validate an Assessment Manifest")
    val.add_argument("--manifest", required=True)

    add = sub.add_parser("credential-add", help="Append a non-secret credential profile")
    add.add_argument("--manifest", required=True)
    add.add_argument("--profiles", required=True)
    add.add_argument("--id")
    add.add_argument("--protocol")
    add.add_argument("--scope", action="append")
    add.add_argument("--username")
    add.add_argument("--secret-ref")
    add.add_argument("--realm-kind")
    add.add_argument("--realm-name")
    add.add_argument("--target-class", action="append")
    add.add_argument("--privilege-class")
    add.add_argument("--purpose", action="append")
    add.add_argument("--service")
    add.add_argument("--hostname-pattern", action="append", default=[])
    add.add_argument("--realm-evidence-min")
    add.add_argument("--ack-high-privilege", action="store_true")
    add.add_argument("--non-interactive", action="store_true")

    args = p.parse_args(argv)

    if args.command == "validate":
        result = validate_manifest(_load_json(Path(args.manifest)))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["valid"] else 2

    if args.command == "init":
        if args.non_interactive:
            if not args.assessment_id or not args.authorized_scope:
                p.error("--non-interactive init requires --assessment-id and --authorized-scope")
            assessment_id = args.assessment_id
            environment_label = args.environment_label or args.assessment_id
            authorized = args.authorized_scope
            protocols = args.allowed_protocol or ["ssh", "winrm"]
            domains = args.domain
        else:
            assessment_id = args.assessment_id or _prompt("Assessment ID")
            environment_label = args.environment_label or _prompt("Environment label", assessment_id)
            authorized = args.authorized_scope or _prompt_list("Authorized IPv4 scopes")
            protocols = args.allowed_protocol or _prompt_list("Allowed protocols", ["ssh", "winrm"])
            domains = list(args.domain)
            if not domains:
                while True:
                    dns = _prompt("AD DNS domain (blank to finish)", required=False)
                    if not dns:
                        break
                    netbios = _prompt("NetBIOS realm")
                    scopes = _prompt_list("Domain scopes", authorized)
                    forest = _prompt("Forest DNS name", dns)
                    domains.append({
                        "dns_domain": dns,
                        "netbios_name": netbios,
                        "forest": forest,
                        "scopes": scopes,
                        "evidence_state": "declared",
                    })
        doc = build_manifest(
            assessment_id,
            environment_label,
            authorized,
            args.exclude_scope,
            domains,
            protocols,
        )
        result = validate_manifest(doc)
        if not result["valid"]:
            print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)
            return 2
        _write_json(Path(args.output), doc)
        print(f"Assessment Manifest written: {args.output}")
        return 0

    if args.command == "credential-add":
        manifest = load_manifest(Path(args.manifest))
        profiles_path = Path(args.profiles)
        profiles = _load_json(profiles_path) if profiles_path.exists() else {"schema_version": "0.4b", "profiles": []}

        if args.non_interactive:
            required = [args.id, args.protocol, args.scope, args.secret_ref, args.realm_kind, args.target_class, args.privilege_class, args.purpose, args.service]
            if any(x in (None, [], "") for x in required):
                p.error("--non-interactive credential-add is missing required profile metadata")
            profile_id = args.id
            protocol = args.protocol
            scopes = args.scope
            username = args.username
            secret_ref = args.secret_ref
            realm_kind = args.realm_kind
            realm_name = args.realm_name
            target_classes = args.target_class
            privilege = args.privilege_class
            purposes = args.purpose
            service = args.service
            evidence_min = args.realm_evidence_min or ("observed" if realm_kind == "ad_domain" else "declared")
        else:
            profile_id = args.id or _prompt("Profile ID")
            protocol = (args.protocol or _prompt("Protocol", "winrm")).lower()
            scopes = args.scope or _prompt_list("Authorized credential scopes", manifest.get("authorized_scopes", []))
            username = args.username or _prompt("Username", required=False)
            secret_ref = args.secret_ref or _prompt("Secret reference (e.g. wincred://ORIZONIT/P01/name)")
            realm_kind = args.realm_kind or _prompt("Realm kind", "ad_domain")
            realm_name = args.realm_name
            if realm_name is None and realm_kind == "ad_domain":
                realm_name = _prompt("Realm/NetBIOS name")
            target_classes = args.target_class or _prompt_list("Target classes", ["windows"])
            privilege = args.privilege_class or _prompt("Privilege class", "inventory")
            purposes = args.purpose or _prompt_list("Purposes", ["discovery", "inventory"])
            service = args.service or _prompt("Detected service selector", "winrm-http" if protocol == "winrm" else protocol)
            evidence_min = args.realm_evidence_min or _prompt("Minimum realm evidence", "observed" if realm_kind == "ad_domain" else "declared")

        if realm_kind not in REALM_KINDS:
            print(f"Unsupported realm_kind: {realm_kind}", file=sys.stderr)
            return 2
        if any(x not in TARGET_CLASSES for x in target_classes):
            print("Unsupported target_class", file=sys.stderr)
            return 2
        if privilege not in PRIVILEGE_CLASSES:
            print(f"Unsupported privilege_class: {privilege}", file=sys.stderr)
            return 2
        if any(x not in PURPOSES for x in purposes):
            print("Unsupported purpose", file=sys.stderr)
            return 2
        if evidence_min not in REALM_EVIDENCE_STATES:
            print(f"Unsupported realm evidence state: {evidence_min}", file=sys.stderr)
            return 2
        if privilege in HIGH_PRIVILEGE and not args.ack_high_privilege:
            print("High-privilege profile requires --ack-high-privilege", file=sys.stderr)
            return 2

        profile = build_credential_profile(
            profile_id,
            protocol,
            scopes,
            username,
            secret_ref,
            realm_kind,
            realm_name,
            target_classes,
            privilege,
            purposes,
            service,
            args.hostname_pattern,
            evidence_min,
            args.ack_high_privilege,
        )
        profiles.setdefault("profiles", [])
        if any(str(x.get("id")) == profile_id for x in profiles["profiles"] if isinstance(x, Mapping)):
            print(f"Profile already exists: {profile_id}", file=sys.stderr)
            return 2
        profiles["profiles"].append(profile)
        validation = validate_profile_document(profiles)
        if not validation["valid"]:
            print(json.dumps(validation, indent=2, ensure_ascii=False), file=sys.stderr)
            return 2
        _write_json(profiles_path, profiles)
        print(f"Credential profile added: {profile_id}")
        print("Secret value was not requested or written.")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
