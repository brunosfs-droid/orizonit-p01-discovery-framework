#!/usr/bin/env python3
"""Startup-scoped, deny-by-default mTLS node assessment grants v0.6.10."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

MAX_POLICY_BYTES = 64 * 1024
MAX_NODES = 128
MAX_GRANTS_PER_NODE = 128
PERMISSIONS = frozenset({"bundle:ingest", "bundle:read"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class AuthorizationError(ValueError):
    """Fixed client-facing authorization error; never includes policy contents."""

    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid identifier")
    return value


class NodePolicy:
    """An immutable grant snapshot, constructed only from validated bytes."""

    __slots__ = ("_grants", "_sha256")

    def __init__(self, raw: bytes):
        try:
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_BYTES:
                raise ValueError("invalid size")
            doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
            if not isinstance(doc, dict) or set(doc) != {"policy_version", "nodes"}:
                raise ValueError("invalid root")
            if doc["policy_version"] != "1":
                raise ValueError("invalid version")
            nodes = doc["nodes"]
            if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
                raise ValueError("invalid nodes")
            grants = {}
            for node in nodes:
                if not isinstance(node, dict) or set(node) != {"node_id", "grants"}:
                    raise ValueError("invalid node")
                key = _identifier(node["node_id"]).lower()
                if key in grants:
                    raise ValueError("duplicate node")
                entries = node["grants"]
                if not isinstance(entries, list) or len(entries) > MAX_GRANTS_PER_NODE:
                    raise ValueError("invalid grants")
                scopes = {}
                for entry in entries:
                    if not isinstance(entry, dict) or set(entry) != {"assessment_id", "permissions"}:
                        raise ValueError("invalid grant")
                    assessment = _identifier(entry["assessment_id"])
                    if assessment in scopes:
                        raise ValueError("duplicate assessment")
                    allowed = entry["permissions"]
                    if not isinstance(allowed, list) or not all(isinstance(p, str) for p in allowed):
                        raise ValueError("invalid permissions")
                    if len(allowed) != len(set(allowed)) or not set(allowed) <= PERMISSIONS:
                        raise ValueError("invalid permissions")
                    scopes[assessment] = frozenset(allowed)
                grants[key] = MappingProxyType(scopes)
            object.__setattr__(self, "_grants", MappingProxyType(grants))
            object.__setattr__(self, "_sha256", hashlib.sha256(raw).hexdigest())
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError("invalid node authorization policy") from None

    def __setattr__(self, name, value):
        raise AttributeError("node authorization policy is immutable")

    def __delattr__(self, name):
        raise AttributeError("node authorization policy is immutable")

    @property
    def sha256(self) -> str:
        return self._sha256

    def require_node(self, authenticated_node_id: str | None) -> Mapping:
        if not authenticated_node_id:
            raise AuthorizationError("node authorization required", 401)
        if not isinstance(authenticated_node_id, str):
            raise AuthorizationError("node is not authorized")
        grants = self._grants.get(authenticated_node_id.lower())
        if grants is None:
            raise AuthorizationError("node is not authorized")
        return grants

    def require(self, authenticated_node_id: str | None, assessment_id: str, permission: str) -> None:
        grants = self.require_node(authenticated_node_id)
        if (not isinstance(assessment_id, str) or not isinstance(permission, str)
                or permission not in PERMISSIONS
                or permission not in grants.get(assessment_id, frozenset())):
            raise AuthorizationError("operation is not authorized")


def load_node_policy(path: Path) -> NodePolicy:
    """Read one bounded regular file; no network, secrets or store mutations."""
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES:
            raise ValueError("invalid file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_POLICY_BYTES + 1)
        return NodePolicy(raw)
    except (OSError, ValueError, TypeError):
        raise ValueError("invalid node authorization policy") from None
    finally:
        if fd is not None:
            os.close(fd)
