"""Pure planning/binding helpers for the explicit SNMP v0.4b.8 extension."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "credentialed_enrichment"))
from P01_SNMP_Enricher import prepare, InputError  # noqa: E402
from P01_Credential_Manager import _safe_profile_view, validate_profile_document  # noqa: E402

VERSION = "0.4b.8"
CONTEXT_FIELDS = ("device_type", "os_family", "hostname", "vendor", "realm",
                  "realm_kind", "realm_evidence_state", "confidence", "target_classes")
ENDPOINT_FIELDS = {"target_ip", "port", "profile_id", "transport", "source", "timeout_seconds", "deadline_seconds"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def binding(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def ipv4(value):
    if not isinstance(value, str):
        raise ValueError("invalid_snmp_request")
    address = ipaddress.ip_address(value)
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ValueError("invalid_snmp_request")
    return str(address)


def load_requests(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("invalid_snmp_request")
            result[key] = value
        return result
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("invalid_snmp_request")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid_snmp_request")))


def authorization(request, manifest=None):
    target = ipaddress.ip_address(request["target_ip"])
    if manifest is None:
        return {"source": "operator_declared_endpoint", "authorized_scopes": [str(target) + "/32"],
                "exclude_scopes": [], "allowed_protocols": ["snmp"]}
    policy = {"source": "assessment_manifest", "authorized_scopes": manifest.get("authorized_scopes"),
              "exclude_scopes": manifest.get("exclude_scopes", []), "allowed_protocols": manifest.get("allowed_protocols")}
    check_authorization(policy, str(target))
    return policy


def check_authorization(policy, target):
    if not isinstance(policy, dict) or set(policy) != {"source", "authorized_scopes", "exclude_scopes", "allowed_protocols"}:
        raise ValueError("invalid_snmp_authorization")
    if policy["source"] not in {"operator_declared_endpoint", "assessment_manifest"}:
        raise ValueError("invalid_snmp_authorization")
    if (not isinstance(policy["allowed_protocols"], list) or
        any(not isinstance(value, str) for value in policy["allowed_protocols"]) or
        "snmp" not in policy["allowed_protocols"]):
        raise ValueError("snmp_not_authorized")
    networks = []
    for key in ("authorized_scopes", "exclude_scopes"):
        values = policy[key]
        if (not isinstance(values, list) or any(not isinstance(value, str) for value in values) or
            key == "authorized_scopes" and not values):
            raise ValueError("invalid_snmp_authorization")
        parsed = [ipaddress.ip_network(value, strict=False) for value in values]
        if any(network.version != 4 or key == "authorized_scopes" and network.prefixlen == 0 for network in parsed):
            raise ValueError("invalid_snmp_authorization")
        networks.append(parsed)
    address = ipaddress.ip_address(ipv4(target))
    if not any(address in net for net in networks[0]) or any(address in net for net in networks[1]):
        raise ValueError("snmp_not_authorized")
    if policy["source"] == "operator_declared_endpoint" and policy != authorization({"target_ip": target}):
        raise ValueError("invalid_snmp_authorization")


def requests_by_ip(document, discovery, manifest=None):
    if not isinstance(document, dict) or set(document) != {"schema_version", "endpoints"} or document["schema_version"] != VERSION:
        raise ValueError("invalid_snmp_request")
    endpoints = document["endpoints"]
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 25:
        raise ValueError("invalid_snmp_request")
    seed_counts = {}
    for asset in discovery.get("assets", []):
        if isinstance(asset, dict) and isinstance(asset.get("ip"), str):
            seed_counts[asset["ip"]] = seed_counts.get(asset["ip"], 0) + 1
    result = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or set(endpoint) != {"target_ip", "port", "profile_id"}:
            raise ValueError("invalid_snmp_request")
        ip = ipv4(endpoint["target_ip"])
        if ip in result or seed_counts.get(ip) != 1:
            raise ValueError("ambiguous_or_unknown_snmp_seed")
        if type(endpoint["port"]) is not int or not 1 <= endpoint["port"] <= 65535:
            raise ValueError("invalid_snmp_request")
        if not isinstance(endpoint["profile_id"], str) or not endpoint["profile_id"].strip():
            raise ValueError("invalid_snmp_request")
        result[ip] = {**endpoint, "authorization": authorization(endpoint, manifest)}
    return result


def context_from_asset(asset):
    context = {key: asset.get(key) for key in CONTEXT_FIELDS}
    context["target_classes"] = asset.get("target_classes", [])
    context["services"] = ["snmp"]
    return context


def safe_profile(profile):
    return {**_safe_profile_view(profile), "snmp_security": profile.get("snmp_security")}


def plan_endpoint(request, profiles, context, conflicts=False):
    endpoint = {key: request[key] for key in ("target_ip", "port", "profile_id")}
    endpoint.update(transport="udp", source="operator_declared", timeout_seconds=2.0, deadline_seconds=20.0)
    result = {"protocol": "snmp", "snmp_extension_version": VERSION,
              "endpoint": endpoint, "authorization": request["authorization"],
              "context": context, "context_sha256": binding(context),
              "endpoint_sha256": binding({"endpoint": endpoint, "authorization": request["authorization"]}),
              "eligible_profile_count": 0, "eligible_profiles": [],
              "action": "no_eligible_profile", "skip_reason": "snmp_profile_or_context_ineligible"}
    if conflicts:
        result["skip_reason"] = "snmp_context_conflict"
        return result
    try:
        profile, match, _ = prepare(profiles, request["target_ip"], request["profile_id"], context,
                                    request["port"], 2.0, 20.0)
    except InputError:
        return result
    result.update(action="adapter_candidate", skip_reason=None, eligible_profile_count=1,
                  eligible_profiles=[{"profile": safe_profile(profile), "profile_sha256": binding(profile),
                                      "matched_scope": match.matched_scope, "scope_prefix_length": match.prefix_length,
                                      "selector_score": match.selector_score, "matched_selectors": list(match.matched_selectors)}])
    return result


def validate_planned_endpoint(asset, plan, profile):
    """Rebind to the live profile and asset context before any secret access."""
    if plan.get("snmp_extension_version") != VERSION or asset.get("context_conflicts"):
        raise ValueError("snmp_plan_missing_or_conflicting")
    endpoint = plan.get("endpoint")
    if not isinstance(endpoint, dict) or set(endpoint) != ENDPOINT_FIELDS:
        raise ValueError("snmp_endpoint_drift")
    if (endpoint["target_ip"] != asset.get("ip") or endpoint["profile_id"] != profile.get("id") or
        endpoint["transport"] != "udp" or endpoint["source"] != "operator_declared" or
        endpoint["timeout_seconds"] != 2.0 or endpoint["deadline_seconds"] != 20.0):
        raise ValueError("snmp_endpoint_drift")
    context = context_from_asset(asset)
    if plan.get("context") != context or plan.get("context_sha256") != binding(context):
        raise ValueError("snmp_context_drift")
    policy = plan.get("authorization")
    check_authorization(policy, endpoint["target_ip"])
    if plan.get("endpoint_sha256") != binding({"endpoint": endpoint, "authorization": policy}):
        raise ValueError("snmp_endpoint_drift")
    eligible = plan.get("eligible_profiles")
    if not isinstance(eligible, list) or len(eligible) != 1 or plan.get("eligible_profile_count") != 1:
        raise ValueError("snmp_plan_missing_or_conflicting")
    snapshot = eligible[0]
    if snapshot.get("profile_sha256") != binding(profile) or snapshot.get("profile") != safe_profile(profile):
        raise ValueError("snmp_profile_drift")
    _, match, _ = prepare({"schema_version": "0.4b", "profiles": [profile]}, endpoint["target_ip"],
                          profile["id"], context, endpoint["port"], 2.0, 20.0)
    expected = {"matched_scope": match.matched_scope, "scope_prefix_length": match.prefix_length,
                "selector_score": match.selector_score, "matched_selectors": list(match.matched_selectors)}
    if any(snapshot.get(key) != value for key, value in expected.items()):
        raise ValueError("snmp_profile_drift")
    return context


def reserve_output(directory):
    Path(directory).mkdir(mode=0o700)


def write_private(path, payload):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = (json.dumps(payload, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")
    digest = hashlib.sha256(data).hexdigest()
    sidecar = path.with_suffix(path.suffix + ".sha256")
    for destination, content in ((path, data), (sidecar, f"{digest}  {path.name}\n".encode("utf-8"))):
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
    return path, sidecar, digest
