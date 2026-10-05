"""Pure SNMP evidence reader. No adapter, credential provider or network imports."""
from __future__ import annotations

import ipaddress
import datetime as dt
import math
import re
from typing import Any, Mapping, Optional

VERSION = "0.4b.9"
ADAPTER_NAME = "P01-SNMP-Credentialed-Enrichment"
ADAPTER_VERSION = "0.4b.7"
FIELDS = (
    ("sys_object_id", "1.3.6.1.2.1.1.2.0", "oid"),
    ("sys_description", "1.3.6.1.2.1.1.1.0", "text"),
    ("sys_uptime_ticks", "1.3.6.1.2.1.1.3.0", "ticks"),
    ("sys_name", "1.3.6.1.2.1.1.5.0", "text"),
    ("sys_location", "1.3.6.1.2.1.1.6.0", "text"),
    ("sys_services", "1.3.6.1.2.1.1.7.0", "services"),
    ("interface_count", "1.3.6.1.2.1.2.1.0", "count"),
    ("ipv4_forwarding", "1.3.6.1.2.1.4.1.0", "forwarding"),
)
STATUSES = {"collected", "not_attempted", "not_available", "timeout", "deadline_exceeded",
            "access_denied", "remote_error", "security_error", "protocol_error", "invalid_response",
            "invalid_value", "oversized_value", "sensitive_value_omitted", "dependency_unavailable"}
FAILURES = {None, "configuration", "transport_or_silent_denial", "authentication_or_security",
            "remote_access_denied", "remote_or_invalid_response"}


def is_snmp(document: Mapping[str, Any]) -> bool:
    metadata = document.get("metadata")
    action, enrichment = document.get("action"), document.get("enrichment")
    return (isinstance(metadata, Mapping) and metadata.get("enricher_name") == ADAPTER_NAME or
            isinstance(action, Mapping) and action.get("protocol") == "snmp" or
            isinstance(enrichment, Mapping) and
            (enrichment.get("protocol") == "snmp" or enrichment.get("adapter_name") == ADAPTER_NAME))


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("invalid_snmp_evidence_contract")


def _object(value: Any, required: set, extra: set = frozenset()) -> Mapping:
    _require(isinstance(value, Mapping))
    _require(required <= set(value) <= required | extra)
    return value


def _integer(value: Any, low: int, high: int) -> None:
    _require(type(value) is int and low <= value <= high)


def _scalar(kind: str, value: Any) -> None:
    if kind == "text":
        _require(isinstance(value, str))
        _require(len(value.encode("utf-8")) <= 1024 and not re.search(
            r"(?:wincred|prompt|env)://|-----BEGIN[^\n]*PRIVATE KEY-----", value, re.IGNORECASE))
    elif kind == "oid":
        _require(isinstance(value, str) and bool(re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,10}){1,127}", value)))
        parts = [int(x) for x in value.split(".")]
        _require(all(0 <= x <= 4294967295 for x in parts) and parts[0] <= 2 and
                 (parts[0] == 2 or parts[1] <= 39))
    else:
        low, high = {"ticks": (0, 4294967295), "services": (0, 127),
                     "count": (0, 2147483647), "forwarding": (1, 2)}[kind]
        _integer(value, low, high)


def usable_name(value: Any) -> Optional[str]:
    """sysName is an operator-controlled label; only DNS-shaped names corroborate."""
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or name in {"unknown", "none", "localhost"}:
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
           for part in name.split(".")):
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        return name


def _parse(document: Mapping[str, Any]) -> dict:
    metadata = document.get("metadata")
    _require(isinstance(metadata, Mapping))
    timestamp = metadata.get("generated_at_utc")
    _require(isinstance(timestamp, str))
    _require(dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).utcoffset() is not None)
    _require(metadata.get("read_only_mode") is True and
             metadata.get("secret_values_persisted_to_output") is False)
    standalone = metadata.get("enricher_name") == ADAPTER_NAME
    auth = document.get("authentication")
    if standalone:
        _object(document, {"metadata", "target", "credential_policy", "authentication",
                           "collection", "summary", "limits", "warnings"})
        _object(metadata, {"enricher_name", "enricher_version", "schema_version", "generated_at_utc",
                           "execution_mode", "read_only_mode", "secret_values_persisted_to_output"})
        _require(metadata.get("enricher_version") == ADAPTER_VERSION and
                 metadata.get("schema_version") == ADAPTER_VERSION)
        _require(metadata.get("execution_mode") in {"dry_run", "execute"})
        target = _object(document.get("target"), {"ip", "port", "transport"})
        ip, port = target["ip"], target["port"]
        _require(target["transport"] == "udp")
        policy = _object(document.get("credential_policy"), {"profile_id", "auth_type", "matched_scope",
                                                            "attempt_limit", "same_profile_retries", "context_source"})
        _require(isinstance(policy["profile_id"], str) and bool(policy["profile_id"].strip()) and
                 isinstance(policy["matched_scope"], str) and
                 policy["auth_type"] in {"snmpv2c", "snmpv3"} and
                 type(policy["attempt_limit"]) is int and policy["attempt_limit"] == 1 and
                 type(policy["same_profile_retries"]) is int and policy["same_profile_retries"] == 0 and
                 policy["context_source"] == "operator_supplied")
        collection = _object(document.get("collection"), {"status", "fields"})
        status, fields = collection["status"], collection["fields"]
        summary, limits, warnings = document.get("summary"), document.get("limits"), document.get("warnings")
    else:
        _require(metadata.get("executor_name") == "P01-Credentialed-Discovery-Executor" and
                 metadata.get("executor_version") == "0.4b.8" and
                 metadata.get("snmp_extension_version") == "0.4b.8" and
                 metadata.get("snmp_execution_enabled") is True)
        action = document.get("action")
        _require(isinstance(action, Mapping) and action.get("protocol") == "snmp")
        ip, port = action.get("target_ip"), action.get("port")
        enrichment = document.get("enrichment")
        if enrichment is None:
            auth = _object(auth, {"profile_id", "protocol", "success", "result", "failure_category",
                                  "counts_against_credential_budget"})
            _require(auth["success"] is False and auth["result"] == "executor_dispatch_exception" and
                     auth["failure_category"] == "remote_execution_or_unknown" and
                     auth["counts_against_credential_budget"] is False and auth["protocol"] == "snmp")
            status, fields, summary, limits, warnings = "not_attempted", [], {
                "get_operations_attempted": 0, "collected_fields": 0}, None, []
        else:
            enrichment = _object(enrichment, {"protocol", "adapter_name", "adapter_version", "schema_version",
                                              "collection_status", "fields", "summary", "limits", "warnings"})
            _require(enrichment["protocol"] == "snmp" and enrichment["adapter_name"] == ADAPTER_NAME and
                     enrichment["adapter_version"] == ADAPTER_VERSION and
                     enrichment["schema_version"] == ADAPTER_VERSION)
            status, fields = enrichment["collection_status"], enrichment["fields"]
            summary, limits, warnings = enrichment["summary"], enrichment["limits"], enrichment["warnings"]

    address = ipaddress.ip_address(ip)
    _require(isinstance(ip, str) and address.version == 4 and not
             (address.is_unspecified or address.is_multicast or address.is_reserved))
    _integer(port, 1, 65535)
    _require(isinstance(fields, list) and isinstance(warnings, list) and
             warnings in ([], ["snmpv2c_unencrypted_transport"]))
    summary = _object(summary, {"get_operations_attempted", "collected_fields"})
    if limits is None:
        return {"target_ip": str(address), "port": port, "mode": "unknown", "status": status,
                "authentication_success": False, "authentication_result": auth["result"],
                "failure_category": auth["failure_category"], "inventory_eligible": False,
                "fields": [], "summary": dict(summary), "limits": None, "warnings": warnings}

    limits = _object(limits, {"max_get_operations", "operation_timeout_seconds", "deadline_seconds", "max_text_bytes"})
    _require(type(limits["max_get_operations"]) is int and limits["max_get_operations"] in {1, 8} and
             type(limits["max_text_bytes"]) is int and limits["max_text_bytes"] == 1024)
    for key, high in (("operation_timeout_seconds", 5), ("deadline_seconds", 45)):
        value = limits[key]
        _require(type(value) in (int, float) and math.isfinite(value) and 0.1 <= value <= high)
    maximum = limits["max_get_operations"]
    auth = _object(auth, {"success", "result", "failure_category", "counts_against_credential_budget"},
                   {"profile_id", "protocol"} if not standalone else set())
    _require(type(auth["success"]) is bool and auth["counts_against_credential_budget"] is False and
             auth["result"] in {"not_attempted", "secret_unavailable", "read_access_confirmed", "probe_failed"} and
             auth["failure_category"] in FAILURES)
    _require(auth["success"] == (auth["result"] == "read_access_confirmed"))
    _require(not auth["success"] or auth["failure_category"] is None)
    _integer(summary["get_operations_attempted"], 0, maximum)
    _integer(summary["collected_fields"], 0, maximum)
    _require(len(fields) in {0, maximum})
    rows = []
    for row, (name, oid, kind) in zip(fields, FIELDS[:maximum]):
        row = _object(row, {"field", "oid", "status"}, {"value"})
        _require(row["field"] == name and row["oid"] == oid and row["status"] in STATUSES)
        _require(("value" in row) == (row["status"] == "collected"))
        if row["status"] == "collected":
            _scalar(kind, row["value"])
        rows.append(dict(row))
    collected = sum(row["status"] == "collected" for row in rows)
    _require(collected == summary["collected_fields"] <= summary["get_operations_attempted"])
    _require(summary["get_operations_attempted"] <= sum(row["status"] != "not_attempted" for row in rows))
    probe = bool(rows and rows[0]["status"] in {"collected", "sensitive_value_omitted"})
    _require(auth["success"] == probe)
    if status == "not_attempted":
        _require(not rows and not auth["success"] and summary["get_operations_attempted"] == 0 and
                 auth["result"] in {"not_attempted", "secret_unavailable"})
    elif status == "not_collected":
        _require(len(rows) == maximum and not probe and auth["result"] == "probe_failed")
    elif status == "access_probe_only":
        _require(maximum == 1 and len(rows) == 1 and probe)
    elif status in {"collected", "collected_with_field_failures"}:
        _require(maximum == 8 and len(rows) == 8 and probe and
                 ((collected == 8) == (status == "collected")))
    else:
        _require(False)
    dry = standalone and metadata["execution_mode"] == "dry_run"
    if dry:
        _require(status == "not_attempted" and auth["result"] == "not_attempted")
    elif status == "not_attempted":
        _require(auth["result"] == "secret_unavailable")
    return {"target_ip": str(address), "port": port, "mode": "dry_run" if dry else
            "auth_only" if maximum == 1 else "full", "status": status,
            "authentication_success": auth["success"], "authentication_result": auth["result"],
            "failure_category": auth["failure_category"],
            "inventory_eligible": not dry and maximum == 8 and probe,
            "fields": rows, "summary": dict(summary), "limits": dict(limits), "warnings": list(warnings)}


def parse(document: Mapping[str, Any]) -> dict:
    """Fail closed with a fixed error; caller retains original bytes and source SHA."""
    try:
        _require(is_snmp(document))
        return _parse(document)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, UnicodeError):
        raise ValueError("invalid_snmp_evidence_contract") from None
