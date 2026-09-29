#!/usr/bin/env python3
"""Orizon IT P01 Credential Manager v0.4b.1.

Secure foundation for credential profile selection and secret resolution.

Design goals:
- no plaintext secrets in profile files;
- scope/protocol aware profile selection;
- bounded candidate selection to reduce lockout/spraying risk;
- secret references only (env://, prompt://, wincred://);
- Windows Credential Manager generic credentials for saved local secrets;
- CLI never prints secret values.

This component does not authenticate to target devices by itself. Protocol adapters
(SNMP/SSH/WinRM) consume this library in later v0.4b increments.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import ipaddress
import json
import os
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

MANAGER_NAME = "P01-Credential-Manager"
MANAGER_VERSION = "0.4b.1"
PROFILE_SCHEMA_VERSION = "0.4b"

SUPPORTED_SECRET_SCHEMES = {"env", "prompt", "wincred"}
SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(password|passwd|pwd|secret|token|community|passphrase|private_key)(_|$)",
    re.IGNORECASE,
)


class CredentialConfigError(ValueError):
    """Raised when a credential profile document violates the contract."""


class SecretProviderError(RuntimeError):
    """Raised when a secret reference cannot be resolved."""


@dataclass(frozen=True)
class ProfileMatch:
    profile: Dict[str, Any]
    matched_scope: str
    prefix_length: int


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise CredentialConfigError("Credential profile root must be a JSON object.")
    return doc


def _parse_secret_ref(value: str) -> Tuple[str, str]:
    if not isinstance(value, str) or "://" not in value:
        raise CredentialConfigError("Secret references must use scheme://value syntax.")
    scheme, locator = value.split("://", 1)
    scheme = scheme.strip().lower()
    locator = locator.strip()
    if scheme not in SUPPORTED_SECRET_SCHEMES:
        raise CredentialConfigError(
            f"Unsupported secret reference scheme '{scheme}'. Supported: {sorted(SUPPORTED_SECRET_SCHEMES)}"
        )
    if not locator:
        raise CredentialConfigError("Secret reference locator cannot be empty.")
    return scheme, locator


def _detect_plaintext_secret_keys(obj: Any, path: str = "$") -> List[str]:
    """Detect likely plaintext secret fields outside the dedicated secret_refs map."""
    findings: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}"
            if key == "secret_refs":
                if not isinstance(value, dict):
                    findings.append(f"{child} must be an object of secret references")
                    continue
                for secret_name, secret_ref in value.items():
                    try:
                        _parse_secret_ref(secret_ref)
                    except CredentialConfigError as exc:
                        findings.append(f"{child}.{secret_name}: {exc}")
                continue
            if SENSITIVE_KEY_RE.search(str(key)) and value not in (None, "", False):
                findings.append(f"{child} looks like a plaintext secret field")
            findings.extend(_detect_plaintext_secret_keys(value, child))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            findings.extend(_detect_plaintext_secret_keys(value, f"{path}[{idx}]"))
    return findings


def _parse_network(scope: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(scope, strict=False)
    except ValueError as exc:
        raise CredentialConfigError(f"Invalid IPv4 scope '{scope}': {exc}") from exc
    if network.version != 4:
        raise CredentialConfigError(f"Only IPv4 credential scopes are supported in v0.4b.1: {scope}")
    return network


def validate_profile_document(doc: Mapping[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    if doc.get("schema_version") != PROFILE_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be '{PROFILE_SCHEMA_VERSION}', got {doc.get('schema_version')!r}"
        )

    profiles = doc.get("profiles")
    if not isinstance(profiles, list):
        errors.append("profiles must be an array")
        profiles = []

    plaintext_findings = _detect_plaintext_secret_keys(doc)
    errors.extend(plaintext_findings)

    seen_ids = set()
    for index, profile in enumerate(profiles):
        base = f"profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{base} must be an object")
            continue
        profile_id = str(profile.get("id") or "").strip()
        if not profile_id:
            errors.append(f"{base}.id is required")
        elif profile_id in seen_ids:
            errors.append(f"Duplicate profile id: {profile_id}")
        else:
            seen_ids.add(profile_id)

        protocol = str(profile.get("protocol") or "").strip().lower()
        if not protocol:
            errors.append(f"{base}.protocol is required")

        scopes = profile.get("scopes")
        if not isinstance(scopes, list) or not scopes:
            errors.append(f"{base}.scopes must be a non-empty array")
            scopes = []
        for scope in scopes:
            try:
                net = _parse_network(str(scope))
                if net.prefixlen == 0:
                    errors.append(f"{base}.scopes may not contain 0.0.0.0/0")
                elif net.prefixlen < 16:
                    warnings.append(
                        f"{base} uses broad credential scope {net}; narrower scopes reduce accidental authentication attempts"
                    )
            except CredentialConfigError as exc:
                errors.append(str(exc))

        priority = profile.get("priority", 100)
        if not isinstance(priority, int) or priority < 0 or priority > 10000:
            errors.append(f"{base}.priority must be integer 0..10000")

        max_attempts = profile.get("max_attempts_per_target", 1)
        if not isinstance(max_attempts, int) or max_attempts < 1 or max_attempts > 3:
            errors.append(f"{base}.max_attempts_per_target must be integer 1..3")

        secret_refs = profile.get("secret_refs", {})
        if not isinstance(secret_refs, dict) or not secret_refs:
            errors.append(f"{base}.secret_refs must contain at least one secret reference")
        else:
            for name, ref in secret_refs.items():
                if not str(name).strip():
                    errors.append(f"{base}.secret_refs contains an empty key")
                try:
                    _parse_secret_ref(ref)
                except CredentialConfigError as exc:
                    errors.append(f"{base}.secret_refs.{name}: {exc}")

    return {"valid": not errors, "errors": errors, "warnings": warnings, "profile_count": len(profiles)}


def load_profiles(path: Path) -> Dict[str, Any]:
    doc = _load_json(path)
    result = validate_profile_document(doc)
    if not result["valid"]:
        raise CredentialConfigError("; ".join(result["errors"]))
    return doc


def _best_scope_for_target(scopes: Iterable[str], target: ipaddress.IPv4Address) -> Optional[ipaddress.IPv4Network]:
    matches: List[ipaddress.IPv4Network] = []
    for raw in scopes:
        net = _parse_network(str(raw))
        if target in net:
            matches.append(net)
    if not matches:
        return None
    matches.sort(key=lambda n: n.prefixlen, reverse=True)
    return matches[0]


def match_profiles(
    doc: Mapping[str, Any],
    target_ip: str,
    protocol: str,
    max_candidates: int = 2,
) -> List[ProfileMatch]:
    if max_candidates < 1 or max_candidates > 5:
        raise ValueError("max_candidates must be between 1 and 5")
    target = ipaddress.ip_address(target_ip)
    if target.version != 4:
        raise ValueError("Only IPv4 targets are supported in v0.4b.1")
    protocol = protocol.strip().lower()

    matches: List[ProfileMatch] = []
    for profile in doc.get("profiles", []):
        if not isinstance(profile, dict) or not profile.get("enabled", True):
            continue
        if str(profile.get("protocol") or "").strip().lower() != protocol:
            continue
        best = _best_scope_for_target(profile.get("scopes", []), target)
        if not best:
            continue
        matches.append(ProfileMatch(profile=dict(profile), matched_scope=str(best), prefix_length=best.prefixlen))

    matches.sort(
        key=lambda m: (
            int(m.profile.get("priority", 100)),
            -m.prefix_length,
            str(m.profile.get("id", "")),
        )
    )
    return matches[:max_candidates]


# ---- Windows Credential Manager provider ---------------------------------

if platform.system().lower() == "windows":
    from ctypes import wintypes

    LPBYTE = ctypes.POINTER(wintypes.BYTE)

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", LPBYTE),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    PCREDENTIALW = ctypes.POINTER(CREDENTIALW)
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2


def _require_windows() -> None:
    if platform.system().lower() != "windows":
        raise SecretProviderError("wincred:// is available only on Windows in v0.4b.1")


def wincred_store(target: str, username: str, secret: str) -> None:
    _require_windows()
    advapi = ctypes.WinDLL("Advapi32.dll")
    advapi.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIALW), wintypes.DWORD]
    advapi.CredWriteW.restype = wintypes.BOOL

    blob = secret.encode("utf-16-le")
    blob_buffer = ctypes.create_string_buffer(blob)
    cred = CREDENTIALW()
    cred.Flags = 0
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.Comment = "Orizon IT P01 credential profile secret"
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(blob_buffer, LPBYTE)
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = username
    if not advapi.CredWriteW(ctypes.byref(cred), 0):
        raise ctypes.WinError()


def wincred_read(target: str) -> Tuple[Optional[str], str]:
    _require_windows()
    advapi = ctypes.WinDLL("Advapi32.dll")
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIALW)]
    advapi.CredReadW.restype = wintypes.BOOL
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    advapi.CredFree.restype = None

    pcred = PCREDENTIALW()
    if not advapi.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)):
        raise ctypes.WinError()
    try:
        cred = pcred.contents
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        try:
            secret = blob.decode("utf-16-le")
        except UnicodeDecodeError:
            secret = blob.decode("utf-8", errors="strict")
        return cred.UserName, secret
    finally:
        advapi.CredFree(pcred)


def wincred_delete(target: str) -> None:
    _require_windows()
    advapi = ctypes.WinDLL("Advapi32.dll")
    advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi.CredDeleteW.restype = wintypes.BOOL
    if not advapi.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        raise ctypes.WinError()


def resolve_secret(ref: str, prompt_label: Optional[str] = None) -> str:
    scheme, locator = _parse_secret_ref(ref)
    if scheme == "env":
        value = os.environ.get(locator)
        if value is None:
            raise SecretProviderError(f"Environment variable '{locator}' is not set")
        return value
    if scheme == "prompt":
        return getpass.getpass(prompt_label or f"Secret for {locator}: ")
    if scheme == "wincred":
        _, secret = wincred_read(locator)
        return secret
    raise SecretProviderError(f"Unsupported secret provider scheme: {scheme}")


def secret_ref_status(ref: str) -> Dict[str, Any]:
    scheme, locator = _parse_secret_ref(ref)
    if scheme == "env":
        return {"scheme": scheme, "locator": locator, "available": locator in os.environ}
    if scheme == "prompt":
        return {"scheme": scheme, "locator": locator, "available": True, "interactive": True}
    if scheme == "wincred":
        try:
            username, _ = wincred_read(locator)
            return {"scheme": scheme, "locator": locator, "available": True, "username": username}
        except Exception as exc:  # provider availability only; no secret disclosure
            return {"scheme": scheme, "locator": locator, "available": False, "error": type(exc).__name__}
    return {"scheme": scheme, "locator": locator, "available": False}


def _safe_profile_view(profile: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": profile.get("id"),
        "enabled": profile.get("enabled", True),
        "protocol": profile.get("protocol"),
        "auth_type": profile.get("auth_type"),
        "scopes": profile.get("scopes", []),
        "priority": profile.get("priority", 100),
        "username": profile.get("username"),
        "secret_ref_names": sorted((profile.get("secret_refs") or {}).keys()),
        "tags": profile.get("tags", []),
        "max_attempts_per_target": profile.get("max_attempts_per_target", 1),
    }


def cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Orizon IT P01 Credential Manager v0.4b.1")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="Validate credential profile file; never resolves secrets")
    p_validate.add_argument("--profiles", required=True)

    p_match = sub.add_parser("match", help="Show ordered eligible profile metadata for target/protocol")
    p_match.add_argument("--profiles", required=True)
    p_match.add_argument("--target", required=True)
    p_match.add_argument("--protocol", required=True)
    p_match.add_argument("--max-candidates", type=int, default=2)

    p_check = sub.add_parser("check", help="Check referenced secret availability without printing secret values")
    p_check.add_argument("--profiles", required=True)
    p_check.add_argument("--profile-id", required=True)

    p_store = sub.add_parser("store-wincred", help="Store a generic secret in Windows Credential Manager")
    p_store.add_argument("--target", required=True, help="Credential target, e.g. ORIZONIT/P01/home-router-ssh")
    p_store.add_argument("--username", required=True)

    p_delete = sub.add_parser("delete-wincred", help="Delete a generic secret from Windows Credential Manager")
    p_delete.add_argument("--target", required=True)

    args = parser.parse_args(argv)

    if args.command == "validate":
        doc = _load_json(Path(args.profiles))
        result = validate_profile_document(doc)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["valid"] else 2

    if args.command == "match":
        doc = load_profiles(Path(args.profiles))
        matches = match_profiles(doc, args.target, args.protocol, args.max_candidates)
        output = [
            {
                "profile": _safe_profile_view(m.profile),
                "matched_scope": m.matched_scope,
                "scope_prefix_length": m.prefix_length,
            }
            for m in matches
        ]
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0

    if args.command == "check":
        doc = load_profiles(Path(args.profiles))
        profiles = [p for p in doc.get("profiles", []) if p.get("id") == args.profile_id]
        if not profiles:
            print(f"Profile not found: {args.profile_id}", file=sys.stderr)
            return 2
        profile = profiles[0]
        statuses = {
            name: secret_ref_status(ref)
            for name, ref in (profile.get("secret_refs") or {}).items()
        }
        print(json.dumps({"profile_id": args.profile_id, "secrets": statuses}, indent=2, ensure_ascii=False))
        return 0 if all(v.get("available") for v in statuses.values()) else 3

    if args.command == "store-wincred":
        secret = getpass.getpass("Secret (input hidden): ")
        confirm = getpass.getpass("Confirm secret: ")
        if secret != confirm:
            print("Secrets do not match.", file=sys.stderr)
            return 2
        if not secret:
            print("Empty secret is not allowed.", file=sys.stderr)
            return 2
        wincred_store(args.target, args.username, secret)
        print(f"Stored Windows Credential Manager target: {args.target}")
        return 0

    if args.command == "delete-wincred":
        wincred_delete(args.target)
        print(f"Deleted Windows Credential Manager target: {args.target}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
