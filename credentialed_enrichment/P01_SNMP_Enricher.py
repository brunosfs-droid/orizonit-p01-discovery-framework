#!/usr/bin/env python3
"""Bounded, opt-in, single-target SNMP GET enrichment. No Cancã login."""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "credential_manager"))
from P01_Credential_Manager import (  # noqa: E402
    match_profiles, resolve_secret, validate_profile_document,
)

NAME = "P01-SNMP-Credentialed-Enrichment"
VERSION = "0.4b.7"
SECURITY = {"level": "authPriv", "auth_protocol": "sha256", "privacy_protocol": "aes128"}
# name, numeric OID, ASN.1 kind; sysObjectID is the only access probe.
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
MAX_TEXT_BYTES = 1024


class InputError(ValueError):
    pass


def prepare(profiles, target, profile_id, context, port, timeout, deadline):
    """All eligibility gates precede importing SNMP or accessing a provider."""
    try:
        ip = ipaddress.ip_address(target)
        if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise InputError()
        if type(port) is not int or not 1 <= port <= 65535:
            raise InputError()
        for value, minimum, maximum in ((timeout, 0.1, 5), (deadline, 0.1, 45)):
            if isinstance(value, bool) or not math.isfinite(value) or not minimum <= value <= maximum:
                raise InputError()
        if not validate_profile_document(profiles)["valid"]:
            raise InputError()
        selected = [p for p in profiles["profiles"] if p.get("id") == profile_id]
        if len(selected) != 1:
            raise InputError()
        profile = selected[0]
        # Absent context remains Unknown; it never implies service detection.
        context = {} if context is None else context
        if not isinstance(context, dict):
            raise InputError()
        matches = match_profiles({"profiles": selected}, str(ip), "snmp", 1, context)
        if len(matches) != 1:
            raise InputError()
        refs = profile["secret_refs"]
        if profile.get("auth_type") == "snmpv2c":
            if set(refs) != {"community"} or profile.get("snmp_security") is not None:
                raise InputError()
        elif profile.get("auth_type") == "snmpv3":
            if set(refs) != {"auth_key", "priv_key"} or profile.get("snmp_security") != SECURITY:
                raise InputError()
            username = profile.get("username")
            if not isinstance(username, str) or not 1 <= len(username.encode("utf-8")) <= 32:
                raise InputError()
        else:
            raise InputError()
        return profile, matches[0], str(ip)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise InputError("invalid_or_ineligible_input") from None


def observation(field, status, value=None):
    result = {"field": field[0], "oid": field[1], "status": status}
    if status == "collected":
        result["value"] = value
    return result


def decode_response(field, response, secrets):
    """Validate exact OID and ASN.1 type; never serialize a raw response/error."""
    from pysnmp.proto import errind, rfc1902, rfc1905
    indication, status, index, bindings = response
    if indication:
        if isinstance(indication, errind.RequestTimedOut):
            return observation(field, "timeout")
        if isinstance(indication, (errind.UnknownUserName, errind.WrongDigest,
                                   errind.AuthenticationFailure, errind.DecryptionError)):
            return observation(field, "security_error")
        return observation(field, "protocol_error")
    if status:
        return observation(field, "access_denied" if int(status) in {6, 16} else "remote_error")
    if int(index) != 0 or len(bindings) != 1 or str(bindings[0][0]) != field[1]:
        return observation(field, "invalid_response")
    value = bindings[0][1]
    if isinstance(value, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)):
        return observation(field, "not_available")
    kind = field[2]
    tag = getattr(value, "tagSet", None)
    if kind == "text" and tag == rfc1902.OctetString.tagSet:
        raw = value.asOctets()
        if len(raw) > MAX_TEXT_BYTES:
            return observation(field, "oversized_value")
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            return observation(field, "invalid_value")
        for secret in sorted(secrets.values(), key=len, reverse=True):
            decoded = decoded.replace(secret, "<redacted>")
    elif kind == "oid" and tag == rfc1902.ObjectIdentifier.tagSet:
        if not 2 <= len(value) <= 128:
            return observation(field, "invalid_value")
        decoded = str(value)
    elif kind == "ticks" and tag == rfc1902.TimeTicks.tagSet:
        decoded = int(value)
    elif kind in {"services", "count", "forwarding"} and tag == rfc1902.Integer32.tagSet:
        decoded = int(value)
        if (kind == "services" and not 0 <= decoded <= 127 or
            kind == "count" and not 0 <= decoded <= 2147483647 or
            kind == "forwarding" and decoded not in {1, 2}):
            return observation(field, "invalid_value")
    else:
        return observation(field, "invalid_value")
    # Non-text values that equal/contain a resolved secret also stay out of evidence.
    if kind != "text" and any(secret in str(decoded) for secret in secrets.values()):
        return observation(field, "sensitive_value_omitted")
    return observation(field, "collected", decoded)


class SNMPClient:
    """One ephemeral engine, no MIB downloads, fixed GETs and zero retries."""
    async def open(self, profile, secrets, target, port, timeout):
        from pysnmp.hlapi.v3arch import asyncio as snmp
        self.api = snmp
        self.engine = snmp.SnmpEngine(maxMessageSize=8192)
        if profile["auth_type"] == "snmpv2c":
            self.auth = snmp.CommunityData(secrets["community"].encode("utf-8"), mpModel=1)
        else:
            self.auth = snmp.UsmUserData(
                profile["username"].encode("utf-8"), secrets["auth_key"].encode("utf-8"),
                secrets["priv_key"].encode("utf-8"),
                authProtocol=snmp.USM_AUTH_HMAC192_SHA256,
                privProtocol=snmp.USM_PRIV_CFB128_AES,
            )
        self.transport = await snmp.UdpTransportTarget.create((target, port), timeout=timeout, retries=0)

    async def get(self, field):
        return await self.api.get_cmd(
            self.engine, self.auth, self.transport, self.api.ContextData(),
            self.api.ObjectType(self.api.ObjectIdentity(field[1])), lookupMib=False,
        )

    def close(self):
        if hasattr(self, "engine"):
            self.engine.close_dispatcher()


async def exchange(profile, secrets, target, port, timeout, deadline, auth_only,
                   client_factory=SNMPClient):
    fields = FIELDS[:1] if auth_only else FIELDS
    rows = [observation(field, "not_attempted") for field in fields]
    attempted = 0
    client = None
    end = time.monotonic() + deadline
    try:
        client = client_factory()
        await asyncio.wait_for(client.open(profile, secrets, target, port, timeout),
                               timeout=max(0.001, end - time.monotonic()))
        for position, field in enumerate(fields):
            remaining = end - time.monotonic()
            if remaining <= 0:
                rows[position:] = [observation(f, "deadline_exceeded") for f in fields[position:]]
                break
            attempted += 1
            try:
                response = await asyncio.wait_for(client.get(field), min(remaining, timeout + 0.5))
                rows[position] = decode_response(field, response, secrets)
            except asyncio.TimeoutError:
                rows[position] = observation(field, "timeout")
            except Exception:
                rows[position] = observation(field, "protocol_error")
            if position == 0 and rows[0]["status"] not in {"collected", "sensitive_value_omitted"}:
                break
            if rows[position]["status"] in {"timeout", "security_error", "protocol_error"}:
                # A failed channel is not retried for every remaining scalar.
                break
    except asyncio.TimeoutError:
        rows[0] = observation(fields[0], "deadline_exceeded")
    except ImportError:
        rows[0] = observation(fields[0], "dependency_unavailable")
    except Exception:
        rows[0] = observation(fields[0], "protocol_error")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                rows[0] = observation(fields[0], "protocol_error")
    return rows, attempted


def collect(profiles, target, profile_id, context=None, *, execute=False,
            authorized=False, auth_only=False, port=161, timeout=2.0, deadline=20.0,
            provider=None, client_factory=SNMPClient):
    profile, match, target = prepare(profiles, target, profile_id, context, port, timeout, deadline)
    if execute and not authorized or auth_only and not execute:
        raise InputError("execution_not_authorized")
    payload = {
        "metadata": {"enricher_name": NAME, "enricher_version": VERSION,
                     "schema_version": VERSION, "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                     "execution_mode": "execute" if execute else "dry_run",
                     "read_only_mode": True, "secret_values_persisted_to_output": False},
        "target": {"ip": target, "port": port, "transport": "udp"},
        "credential_policy": {"profile_id": profile_id, "auth_type": profile["auth_type"],
                              "matched_scope": match.matched_scope, "attempt_limit": 1,
                              "same_profile_retries": 0, "context_source": "operator_supplied"},
        "authentication": {"success": False, "result": "not_attempted",
                           "failure_category": None, "counts_against_credential_budget": False},
        "collection": {"status": "not_attempted", "fields": []},
        "summary": {"get_operations_attempted": 0, "collected_fields": 0},
        "limits": {"max_get_operations": 1 if auth_only else len(FIELDS),
                   "operation_timeout_seconds": timeout, "deadline_seconds": deadline,
                   "max_text_bytes": MAX_TEXT_BYTES},
        "warnings": ["snmpv2c_unencrypted_transport"] if profile["auth_type"] == "snmpv2c" else [],
    }
    if not execute:
        return payload
    secrets = {}
    try:
        for name, ref in profile["secret_refs"].items():
            secret = (provider or resolve_secret)(ref)
            minimum = 1 if name == "community" else 8
            if not isinstance(secret, str) or not minimum <= len(secret.encode("utf-8")) <= 255:
                raise InputError()
            secrets[name] = secret
    except Exception:
        payload["authentication"].update(result="secret_unavailable", failure_category="configuration")
        return payload
    try:
        rows, attempted = asyncio.run(exchange(profile, secrets, target, port, timeout, deadline,
                                               auth_only, client_factory))
    finally:
        secrets.clear()
    probe = rows[0]["status"]
    access = probe in {"collected", "sensitive_value_omitted"}
    category = {"timeout": "transport_or_silent_denial", "deadline_exceeded": "transport_or_silent_denial",
                "security_error": "authentication_or_security", "access_denied": "remote_access_denied",
                "dependency_unavailable": "configuration"}.get(probe, "remote_or_invalid_response")
    payload["authentication"].update(success=access, result="read_access_confirmed" if access else "probe_failed",
                                      failure_category=None if access else category)
    count = sum(row["status"] == "collected" for row in rows)
    status = ("access_probe_only" if auth_only else "collected" if count == len(rows)
              else "collected_with_field_failures") if access else "not_collected"
    payload["collection"] = {"status": status, "fields": rows}
    payload["summary"] = {"get_operations_attempted": attempted, "collected_fields": count}
    return payload


def write_result(directory, payload):
    """Caller reserves a new private directory; no existing output is replaced."""
    directory = Path(directory)
    data = (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    digest = hashlib.sha256(data).hexdigest()
    for name, content in (("snmp.json", data), ("snmp.json.sha256", f"{digest}  snmp.json\n".encode("ascii"))):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
    return digest


class FixedParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"error":"invalid_arguments"}\n')


def cli(argv=None):
    parser = FixedParser(description=f"{NAME} {VERSION}", allow_abbrev=False)
    for name in ("profiles", "profile-id", "target", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--context", help="Local JSON context for profile selectors; no secret values")
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--deadline", type=float, default=20.0)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--ack-authorized-access", action="store_true")
    args = parser.parse_args(argv)
    try:
        profiles = json.loads(Path(args.profiles).read_text(encoding="utf-8-sig"))
        context = json.loads(Path(args.context).read_text(encoding="utf-8-sig")) if args.context else None
        prepare(profiles, args.target, args.profile_id, context, args.port, args.timeout, args.deadline)
        if args.execute and not args.ack_authorized_access or args.auth_only and not args.execute:
            raise InputError()
        # Output is reserved before a provider or network is used.
        directory = Path(args.output_dir)
        directory.mkdir(mode=0o700)
        payload = collect(profiles, args.target, args.profile_id, context,
                          execute=args.execute, authorized=args.ack_authorized_access,
                          auth_only=args.auth_only, port=args.port, timeout=args.timeout, deadline=args.deadline)
        digest = write_result(directory, payload)
        print(json.dumps({"status": payload["collection"]["status"], "sha256": digest}))
        return 0 if not args.execute or payload["authentication"]["success"] else 3
    except Exception:
        print('{"error":"invalid_input_or_output"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
