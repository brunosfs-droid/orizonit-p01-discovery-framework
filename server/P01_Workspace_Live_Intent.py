#!/usr/bin/env python3
"""R02: offline live-scan intent preview; NEVER executes a scanner.

Only trusted server-side configuration defines network scope. An operator can
name an approved scope and mode but cannot supply targets, credentials or
commands. The result is a non-authorizing, unpersisted preview only.
"""
import hashlib
import ipaddress
import json
import re
from types import MappingProxyType

import P01_Workspace_Coordinator as runtime

pg, ws = runtime.pg, runtime.ws
VERSION = "0.6.41"
SCOPE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MODES = frozenset(("auth_only", "full_enrichment"))
PRIVATE = tuple(ipaddress.IPv4Network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
))
MAX_SCOPES = 128
MAX_NETWORKS = 16
MAX_HOSTS = 256


def _scope_id(value):
    pg.require(type(value) is str and SCOPE_ID.fullmatch(value) is not None,
               "workspace_input_invalid")
    return value


def _network(value):
    pg.require(type(value) is str and "/" in value and len(value) <= 18,
               "workspace_input_invalid")
    try:
        net = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError):
        raise pg.PersistenceError("workspace_input_invalid") from None
    pg.require(type(net) is ipaddress.IPv4Network and
               value == net.with_prefixlen and
               any(net.subnet_of(parent) for parent in PRIVATE),
               "workspace_input_invalid")
    pg.require(net.prefixlen >= 24, "workspace_input_invalid")
    return net


def _hosts(net):
    return 1 if net.prefixlen == 32 else 2 if net.prefixlen == 31 else net.num_addresses - 2


class ApprovedScopes:
    """Frozen private configuration: workspace -> scope -> static approved scan bounds."""
    def __init__(self, scopes):
        pg.require(type(scopes) is dict and len(scopes) <= MAX_SCOPES,
                   "workspace_input_invalid")
        normalized = {}
        for workspace_id, choices in scopes.items():
            ws.identifier(workspace_id)
            pg.require(type(choices) is dict and 1 <= len(choices) <= MAX_SCOPES,
                       "workspace_input_invalid")
            parsed = {}
            for scope_id, spec in choices.items():
                _scope_id(scope_id)
                pg.require(type(spec) is dict and set(spec) == {"networks", "modes"} and
                           type(spec["networks"]) is list and 1 <= len(spec["networks"]) <= MAX_NETWORKS and
                           type(spec["modes"]) is list and 1 <= len(spec["modes"]) <= 2 and
                           len(set(str(x) for x in spec["modes"])) == len(spec["modes"]) and
                           all(type(x) is str and x in MODES for x in spec["modes"]) and
                           "auth_only" in spec["modes"], "workspace_input_invalid")
                networks = [_network(n) for n in spec["networks"]]
                pg.require(len(set(networks)) == len(networks) and
                           all(not a.overlaps(b) for i, a in enumerate(networks)
                               for b in networks[i + 1:]), "workspace_input_invalid")
                host_count = sum(_hosts(net) for net in networks)
                pg.require(host_count <= MAX_HOSTS, "workspace_input_invalid")
                parsed[scope_id] = MappingProxyType({
                    "networks": tuple(str(n) for n in networks),
                    "modes": frozenset(spec["modes"]),
                    "hosts": host_count
                })
            normalized[workspace_id] = MappingProxyType(parsed)
        self._scopes = MappingProxyType(normalized)

    def _lookup(self, workspace_id, scope_id):
        ws.identifier(workspace_id); _scope_id(scope_id)
        scope = self._scopes.get(workspace_id, {}).get(scope_id)
        pg.require(scope is not None, "workspace_access_denied")
        return scope


def preview(operation, approved, scope_id, mode, *, ack_authorized_access=False):
    """Create a generation-specific preview, not an approval or runnable job."""
    pg.require(type(operation) is runtime.Operation and
               isinstance(approved, ApprovedScopes) and
               type(mode) is str and mode in MODES and
               type(ack_authorized_access) is bool and ack_authorized_access,
               "workspace_input_invalid")
    _scope_id(scope_id)
    operation.check()
    scope = approved._lookup(operation.token.workspace_id, scope_id)
    pg.require(mode in scope["modes"], "workspace_access_denied")
    # Include lease identity in digest, but never disclose it or the CIDRs.
    payload = {
        "workspace_id": operation.token.workspace_id,
        "generation": operation.token.generation,
        "lease_id": operation.token.lease_id,
        "scope_id": scope_id,
        "mode": mode,
        "networks": scope["networks"],
        "ack_authorized_access": True,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    operation.check()
    return {
        "status": "preview_only",
        "version": VERSION,
        "scope_digest_sha256": digest,
        "workspace_id": operation.token.workspace_id,
        "generation": operation.token.generation,
        "scope_id": scope_id,
        "requested_mode": mode,
        "network_count": len(scope["networks"]),
        "maximum_target_hosts": scope["hosts"],
        "execution_authorized": False,
        "network_activity_performed": False,
        "authentication_performed": False,
        "pending_gates": [
            "explicit_execution_policy",
            "credential_isolation",
            "scanner_cancellation_homologation",
            "EVE_NG_operator_acceptance",
        ],
    }
