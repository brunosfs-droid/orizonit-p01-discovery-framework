#!/usr/bin/env python3
"""
Orizon IT - Produto 01 / Infrastructure Assessment
Linux Discovery Collector v0.3

Read-only collector. It does not install packages, change configuration,
restart services, or transmit data over the network.

Outputs JSON + SHA256. Output classification: CONFIDENTIAL - CLIENT DATA.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import grp
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

COLLECTOR_NAME = "P01-Linux-Discovery-Collector"
COLLECTOR_VERSION = "0.3.0"
SCHEMA_VERSION = "0.3"
ERRORS: list[dict[str, Any]] = []
LIMITATIONS: list[dict[str, Any]] = []
WARNINGS: list[dict[str, Any]] = []

PERMISSION_MARKERS = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "not authorized",
    "access denied",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_error(section: str, message: str, exception_type: str | None = None) -> None:
    ERRORS.append({"section": section, "message": message, "exception_type": exception_type})


def record_limitation(section: str, message: str, exception_type: str | None = None) -> None:
    LIMITATIONS.append({"section": section, "message": message, "exception_type": exception_type})


def record_warning(section: str, message: str) -> None:
    WARNINGS.append({"section": section, "message": message, "exception_type": None})


def safe_read_text(
    path: str,
    section: str,
    max_bytes: int = 1024 * 1024,
    failure_class: str = "error",
) -> str | None:
    try:
        p = Path(path)
        if not p.exists():
            return None
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except PermissionError as exc:
        record_limitation(section, str(exc), type(exc).__name__)
        return None
    except Exception as exc:  # noqa: BLE001
        if failure_class == "limitation":
            record_limitation(section, str(exc), type(exc).__name__)
        else:
            record_error(section, str(exc), type(exc).__name__)
        return None


def run_command(
    section: str,
    command: list[str],
    timeout: int = 15,
    env: dict[str, str] | None = None,
    nonzero_policy: str = "error",  # error | warning | state
) -> dict[str, Any]:
    executable = command[0]
    if shutil.which(executable) is None:
        return {
            "available": False,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": f"Command not found: {executable}",
        }

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        result = {
            "available": True,
            "command": command,
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
        if proc.returncode != 0:
            combined = f"{stdout}\n{stderr}".lower()
            message = f"Command returned {proc.returncode}: {' '.join(command)}"
            if any(marker in combined for marker in PERMISSION_MARKERS):
                record_limitation(section, f"{message}. {stderr or stdout}".strip())
            elif nonzero_policy == "warning":
                record_warning(section, f"{message}. {stderr or stdout}".strip())
            elif nonzero_policy == "error":
                record_error(section, message)
            # nonzero_policy == 'state': return code is treated as observed state.
        return result
    except subprocess.TimeoutExpired:
        record_error(section, f"Timeout after {timeout}s: {' '.join(command)}", "TimeoutExpired")
        return {
            "available": True,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": f"Timeout after {timeout}s",
        }
    except Exception as exc:  # noqa: BLE001
        record_error(section, str(exc), type(exc).__name__)
        return {
            "available": True,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }


def parse_os_release() -> dict[str, str]:
    content = safe_read_text("/etc/os-release", "system.os_release")
    if not content:
        return {}
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def parse_meminfo() -> dict[str, int | str]:
    content = safe_read_text("/proc/meminfo", "system.meminfo")
    if not content:
        return {}
    wanted = {"MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree"}
    result: dict[str, int | str] = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key not in wanted:
            continue
        parts = value.strip().split()
        result[key] = int(parts[0]) if parts and parts[0].isdigit() else value.strip()
    return result


def get_uptime_seconds() -> float | None:
    content = safe_read_text("/proc/uptime", "system.uptime")
    if not content:
        return None
    try:
        return float(content.split()[0])
    except (ValueError, IndexError) as exc:
        record_error("system.uptime", str(exc), type(exc).__name__)
        return None


def parse_resolver() -> dict[str, list[str]]:
    content = safe_read_text("/etc/resolv.conf", "network.resolver")
    result = {"nameservers": [], "search": [], "options": []}
    if not content:
        return result
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "nameserver" and len(parts) >= 2:
            result["nameservers"].append(parts[1])
        elif parts[0] in {"search", "domain"} and len(parts) >= 2:
            result["search"].extend(parts[1:])
        elif parts[0] == "options" and len(parts) >= 2:
            result["options"].extend(parts[1:])
    return result


def json_command(section: str, command: list[str]) -> Any:
    result = run_command(section, command)
    if result.get("returncode") == 0 and result.get("stdout"):
        try:
            return json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            record_error(section, f"Invalid JSON from command: {exc}", "JSONDecodeError")
    return result


def collect_sshd_settings() -> dict[str, Any]:
    selected_keys = {
        "port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
        "usepam", "allowusers", "allowgroups", "denyusers", "denygroups",
        "x11forwarding", "maxauthtries", "clientaliveinterval", "clientalivecountmax",
    }
    result: dict[str, Any] = {"effective": {}, "source": None, "visibility": "unknown"}
    cmd = run_command("security.sshd", ["sshd", "-T"], timeout=10, nonzero_policy="state")
    if cmd.get("returncode") == 0 and cmd.get("stdout"):
        effective: dict[str, str] = {}
        for line in cmd["stdout"].splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in selected_keys:
                effective[parts[0].lower()] = parts[1]
        result.update({"effective": effective, "source": "sshd -T", "visibility": "effective"})
        return result

    config = safe_read_text("/etc/ssh/sshd_config", "security.sshd_config", failure_class="limitation")
    if config:
        parsed: dict[str, str] = {}
        for raw in config.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in selected_keys:
                parsed[parts[0].lower()] = parts[1]
        result.update({
            "effective": parsed,
            "source": "/etc/ssh/sshd_config (static parse; includes/Match blocks may change effective values)",
            "visibility": "partial",
        })
        record_warning("security.sshd", "Could not obtain effective sshd -T output; static configuration was parsed instead.")
    else:
        result["visibility"] = "unavailable"
        if os.geteuid() != 0:
            record_limitation("security.sshd", "Effective SSH configuration could not be collected with the current privileges.")
    return result


def local_user_summary(include_users: bool) -> dict[str, Any]:
    try:
        entries = list(pwd.getpwall())
        summary: dict[str, Any] = {
            "total": len(entries),
            "uid_0_accounts": [u.pw_name for u in entries if u.pw_uid == 0],
            "interactive_shell_accounts_count": sum(
                1 for u in entries
                if u.pw_shell and u.pw_shell not in {
                    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"
                }
            ),
        }
        if include_users:
            summary["accounts"] = [
                {"name": u.pw_name, "uid": u.pw_uid, "gid": u.pw_gid, "home": u.pw_dir, "shell": u.pw_shell}
                for u in entries
            ]
        return summary
    except Exception as exc:  # noqa: BLE001
        record_error("identity.local_users", str(exc), type(exc).__name__)
        return {}


def group_summary() -> dict[str, Any]:
    try:
        entries = list(grp.getgrall())
        return {"total": len(entries), "groups": [g.gr_name for g in entries]}
    except Exception as exc:  # noqa: BLE001
        record_error("identity.groups", str(exc), type(exc).__name__)
        return {}


def package_inventory(include_packages: bool) -> dict[str, Any]:
    inventory: dict[str, Any] = {"manager": None, "count": None, "packages": None}
    if shutil.which("dpkg-query"):
        cmd = run_command("software.packages", ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
        if cmd.get("returncode") == 0:
            lines = [line for line in cmd["stdout"].splitlines() if line.strip()]
            inventory.update({"manager": "dpkg", "count": len(lines)})
            if include_packages:
                inventory["packages"] = lines
            return inventory
    if shutil.which("rpm"):
        cmd = run_command("software.packages", ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=30)
        if cmd.get("returncode") == 0:
            lines = [line for line in cmd["stdout"].splitlines() if line.strip()]
            inventory.update({"manager": "rpm", "count": len(lines)})
            if include_packages:
                inventory["packages"] = lines
            return inventory
    return inventory


def firewall_status() -> dict[str, Any]:
    result: dict[str, Any] = {}
    if shutil.which("ufw"):
        result["ufw"] = run_command("security.firewall.ufw", ["ufw", "status"], nonzero_policy="state")
    if shutil.which("firewall-cmd"):
        result["firewalld_state"] = run_command(
            "security.firewall.firewalld", ["firewall-cmd", "--state"], nonzero_policy="state"
        )
        result["firewalld_zones"] = run_command(
            "security.firewall.firewalld_zones", ["firewall-cmd", "--get-active-zones"], nonzero_policy="state"
        )
    if shutil.which("nft"):
        result["nft_tables"] = run_command("security.firewall.nft", ["nft", "list", "tables"], nonzero_policy="state")
    if not result:
        result["available"] = False
    return result


def collect_identity_integration() -> dict[str, Any]:
    result: dict[str, Any] = {}
    if shutil.which("realm"):
        result["realmd"] = run_command("identity.realmd", ["realm", "list"], nonzero_policy="state")
    if shutil.which("sssctl"):
        result["sssd_domains"] = run_command("identity.sssd", ["sssctl", "domain-list"], nonzero_policy="state")
    if shutil.which("wbinfo"):
        result["winbind_ping_dc"] = run_command("identity.winbind", ["wbinfo", "--ping-dc"], nonzero_policy="state")
    if not result:
        result["available"] = False
    return result



def parse_simple_assignments(content: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not content:
        return result
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip().lower()] = value.strip().strip('"').strip("'")
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].strip().lower()] = parts[1].strip().strip('"').strip("'")
    return result


def collect_password_policy() -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    merged: dict[str, str] = {}

    candidates = [Path("/etc/security/pwquality.conf")]
    pwq_dir = Path("/etc/security/pwquality.conf.d")
    if pwq_dir.is_dir():
        candidates.extend(sorted(pwq_dir.glob("*.conf")))

    for path in candidates:
        content = safe_read_text(str(path), f"security.password_policy.pwquality.{path.name}", failure_class="limitation")
        if content is None:
            continue
        parsed = parse_simple_assignments(content)
        sources.append({"path": str(path), "settings": parsed})
        merged.update(parsed)

    pam_paths = [
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    pam: list[dict[str, Any]] = []
    modules = {"pam_pwquality": False, "pam_faillock": False, "pam_pwhistory": False, "pam_unix_obscure": False}
    for path in pam_paths:
        content = safe_read_text(path, f"security.password_policy.pam.{Path(path).name}", failure_class="limitation")
        if content is None:
            continue
        lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        relevant = [
            ln for ln in lines
            if any(m in ln for m in ("pam_pwquality.so", "pam_faillock.so", "pam_pwhistory.so", "pam_unix.so"))
        ]
        low = "\n".join(relevant).lower()
        if "pam_pwquality.so" in low:
            modules["pam_pwquality"] = True
        if "pam_faillock.so" in low:
            modules["pam_faillock"] = True
        if "pam_pwhistory.so" in low:
            modules["pam_pwhistory"] = True
        if any("pam_unix.so" in ln.lower() and re.search(r"\bobscure\b", ln.lower()) for ln in relevant):
            modules["pam_unix_obscure"] = True
        pam.append({"path": path, "relevant_lines": relevant})

    login_defs_content = safe_read_text("/etc/login.defs", "security.password_policy.login_defs", failure_class="limitation")
    login_defs_all = parse_simple_assignments(login_defs_content)
    login_defs = {
        k: login_defs_all.get(k)
        for k in ("pass_max_days", "pass_min_days", "pass_min_len", "pass_warn_age", "encrypt_method")
        if k in login_defs_all
    }

    faillock_content = safe_read_text("/etc/security/faillock.conf", "security.password_policy.faillock", failure_class="limitation")
    faillock = parse_simple_assignments(faillock_content)

    authselect = None
    if shutil.which("authselect"):
        authselect = run_command("security.password_policy.authselect", ["authselect", "current"], nonzero_policy="state")

    return {
        "pwquality": {
            "sources": sources,
            "effective_candidate": merged,
            "note": "Values are collected from pwquality configuration files. PAM command-line options can override these values and are retained separately.",
        },
        "pam": {"modules": modules, "files": pam},
        "login_defs": login_defs,
        "faillock": faillock,
        "authselect": authselect,
    }


def _parse_testparm(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("Loaded services file") or line.startswith("Server role"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current and "=" in line:
            key, value = line.split("=", 1)
            sections[current][key.strip().lower()] = value.strip()
    return sections


def collect_samba_shares() -> dict[str, Any]:
    if not shutil.which("testparm"):
        return {"available": False, "reason": "testparm not found", "items": []}

    cmd = run_command("shares.samba.testparm", ["testparm", "-s"], timeout=20, nonzero_policy="state")
    if cmd.get("returncode") != 0:
        return {"available": True, "command": cmd, "items": []}

    sections = _parse_testparm(str(cmd.get("stdout", "")))
    items: list[dict[str, Any]] = []
    for name, cfg in sections.items():
        if name.lower() == "global":
            continue
        path = cfg.get("path")
        read_only_raw = cfg.get("read only", "yes").lower()
        writeable_raw = cfg.get("writeable", cfg.get("writable", "no")).lower()
        guest_ok = cfg.get("guest ok", "no").lower() in {"yes", "true", "1"}
        writable = read_only_raw in {"no", "false", "0"} or writeable_raw in {"yes", "true", "1"}
        stat_info: dict[str, Any] | None = None
        getfacl = None
        if path and Path(path).exists():
            try:
                st = Path(path).stat()
                stat_info = {
                    "mode_octal": oct(st.st_mode & 0o7777),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "world_writable": bool(st.st_mode & 0o002),
                    "group_writable": bool(st.st_mode & 0o020),
                }
            except PermissionError as exc:
                record_limitation(f"shares.samba.stat.{name}", str(exc), type(exc).__name__)
            except Exception as exc:  # noqa: BLE001
                record_warning(f"shares.samba.stat.{name}", str(exc))
            if shutil.which("getfacl"):
                getfacl = run_command(f"shares.samba.getfacl.{name}", ["getfacl", "-cp", path], timeout=10, nonzero_policy="state")

        force_user = cfg.get("force user", "")
        guest_write_configured = guest_ok and writable
        strong_write_confirmation = guest_write_configured and bool(
            (stat_info and stat_info.get("world_writable")) or force_user
        )
        items.append({
            "name": name,
            "path": path,
            "read_only": read_only_raw,
            "writeable": writeable_raw,
            "guest_ok": guest_ok,
            "write_list": cfg.get("write list", ""),
            "valid_users": cfg.get("valid users", ""),
            "force_user": force_user,
            "filesystem": stat_info,
            "getfacl": getfacl,
            "guest_write_configured": guest_write_configured,
            "strong_write_confirmation": strong_write_confirmation,
        })
    return {"available": True, "command": cmd, "items": items}


def _ftp_listener_details(ss_stdout: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in ss_stdout.splitlines():
        if not re.search(r"(?:^|\s)(?:\[[^\]]+\]|\S+):21(?:\s|$)", line):
            continue
        tokens = line.split()
        local = None
        for token in tokens:
            if re.search(r":21$", token):
                local = token
                break
        if not local:
            continue
        host = local.rsplit(":", 1)[0].strip("[]")
        process_match = re.search(r'users:\(\(\"([^\"]+)\"', line)
        process_name = process_match.group(1) if process_match else None
        exposed = host not in {"127.0.0.1", "::1", "localhost"}
        items.append({"local_endpoint": local, "process_name": process_name, "network_exposed": exposed, "raw": line})
    return items


def collect_ftp_posture(listening: dict[str, Any]) -> dict[str, Any]:
    stdout = str(listening.get("stdout", "")) if isinstance(listening, dict) else ""
    listeners = _ftp_listener_details(stdout)
    exposed = any(x.get("network_exposed") for x in listeners)
    processes = {str(x.get("process_name") or "").lower() for x in listeners}

    product = None
    encryption = "not_detected" if not listeners else "unknown"
    plaintext_allowed: bool | None = None
    evidence: dict[str, Any] = {}

    if "vsftpd" in processes or shutil.which("vsftpd"):
        product = "vsftpd"
        cfg = None
        cfg_path = None
        for path in ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"):
            cfg = safe_read_text(path, "security.ftp.vsftpd", failure_class="limitation")
            if cfg is not None:
                cfg_path = path
                break
        parsed = parse_simple_assignments(cfg)
        if parsed:
            ssl_enable = parsed.get("ssl_enable", "no").lower() in {"yes", "true", "1"}
            force_login = parsed.get("force_local_logins_ssl", "no").lower() in {"yes", "true", "1"}
            force_data = parsed.get("force_local_data_ssl", "no").lower() in {"yes", "true", "1"}
            if not ssl_enable:
                encryption, plaintext_allowed = "disabled", True
            elif force_login and force_data:
                encryption, plaintext_allowed = "required", False
            else:
                encryption, plaintext_allowed = "optional", True
            evidence = {"config": cfg_path, "ssl_enable": ssl_enable, "force_local_logins_ssl": force_login, "force_local_data_ssl": force_data}

    elif "proftpd" in processes or shutil.which("proftpd"):
        product = "proftpd"
        merged = ""
        paths = []
        for path in ("/etc/proftpd/proftpd.conf", "/etc/proftpd/tls.conf"):
            content = safe_read_text(path, f"security.ftp.proftpd.{Path(path).name}", failure_class="limitation")
            if content is not None:
                merged += "\n" + content
                paths.append(path)
        if merged:
            tls_engine = bool(re.search(r"(?im)^\s*TLSEngine\s+on\b", merged))
            tls_required = bool(re.search(r"(?im)^\s*TLSRequired\s+on\b", merged))
            if tls_engine and tls_required:
                encryption, plaintext_allowed = "required", False
            elif tls_engine:
                encryption, plaintext_allowed = "optional", True
            else:
                encryption, plaintext_allowed = "disabled", True
            evidence = {"config": paths, "tls_engine": tls_engine, "tls_required": tls_required}

    elif "pure-ftpd" in processes or shutil.which("pure-ftpd"):
        product = "pure-ftpd"
        tls = safe_read_text("/etc/pure-ftpd/conf/TLS", "security.ftp.pureftpd", failure_class="limitation")
        if tls is not None:
            value = tls.strip()
            if value == "2":
                encryption, plaintext_allowed = "required", False
            elif value == "1":
                encryption, plaintext_allowed = "optional", True
            elif value == "0":
                encryption, plaintext_allowed = "disabled", True
            evidence = {"config": "/etc/pure-ftpd/conf/TLS", "value": value}

    return {
        "listener_detected": bool(listeners),
        "network_exposed": exposed,
        "listeners": listeners,
        "product": product,
        "encryption_status": encryption,
        "plaintext_allowed": plaintext_allowed,
        "evidence": evidence,
    }


def sanitize_label(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned[:64] or None


def main() -> int:
    parser = argparse.ArgumentParser(description="Orizon IT P01 Linux Discovery Collector v0.3")
    parser.add_argument("--output-dir", default="./output", help="Directory for JSON and SHA256 output")
    parser.add_argument("--run-label", default=None, help="Optional lab/customer execution label, e.g. L01-ubuntu-user")
    parser.add_argument("--include-local-users", action="store_true", help="Include detailed local user list")
    parser.add_argument("--include-packages", action="store_true", help="Include full installed package list")
    args = parser.parse_args()

    started_monotonic = time.monotonic()
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    run_label = sanitize_label(args.run_label)

    metadata = {
        "collector_name": COLLECTOR_NAME,
        "collector_version": COLLECTOR_VERSION,
        "schema_version": SCHEMA_VERSION,
        "collected_at_utc": utc_now(),
        "hostname": hostname,
        "fqdn": fqdn,
        "execution_user": pwd.getpwuid(os.geteuid()).pw_name,
        "euid": os.geteuid(),
        "is_root": os.geteuid() == 0,
        "privilege_profile": "root" if os.geteuid() == 0 else "standard-user",
        "run_label": run_label,
        "python_version": platform.python_version(),
        "read_only_mode": True,
    }

    system = {
        "os_release": parse_os_release(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "uptime_seconds": get_uptime_seconds(),
        "cpu_count": os.cpu_count(),
        "memory_kb": parse_meminfo(),
        "lscpu": run_command("system.lscpu", ["lscpu"]),
        "virtualization": run_command("system.virtualization", ["systemd-detect-virt"], nonzero_policy="state"),
        "dmi": {
            "product_name": safe_read_text("/sys/class/dmi/id/product_name", "system.dmi.product_name"),
            "sys_vendor": safe_read_text("/sys/class/dmi/id/sys_vendor", "system.dmi.sys_vendor"),
            "product_version": safe_read_text("/sys/class/dmi/id/product_version", "system.dmi.product_version"),
        },
    }

    storage = {
        "lsblk": json_command("storage.lsblk", ["lsblk", "-J", "-b", "-o", "NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,UUID,MODEL,SERIAL,ROTA"]),
        "df": run_command("storage.df", ["df", "-PT"]),
        "mounts": run_command("storage.mounts", ["findmnt", "-J"]),
    }

    listening = run_command("network.listening_ports", ["ss", "-lntupH"], nonzero_policy="state")
    network = {
        "addresses": json_command("network.addresses", ["ip", "-j", "address"]),
        "routes": json_command("network.routes", ["ip", "-j", "route"]),
        "links": json_command("network.links", ["ip", "-j", "link"]),
        "resolver": parse_resolver(),
        "resolvectl_dns": run_command("network.resolvectl_dns", ["resolvectl", "dns"], nonzero_policy="state"),
        "resolvectl_domain": run_command("network.resolvectl_domain", ["resolvectl", "domain"], nonzero_policy="state"),
        "hostnamectl": run_command("network.hostnamectl", ["hostnamectl"], nonzero_policy="state"),
        "listening_ports": listening,
        "listening_process_visibility": "full_expected" if os.geteuid() == 0 else "limited_without_root",
    }
    if os.geteuid() != 0:
        record_limitation(
            "network.listening_ports",
            "Port/process mapping can be incomplete for a standard user; socket endpoints are still collected where permitted.",
        )

    services = {
        "running": run_command("services.running", ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"], timeout=20, nonzero_policy="state"),
        "failed": run_command("services.failed", ["systemctl", "list-units", "--type=service", "--state=failed", "--no-pager", "--no-legend"], timeout=20, nonzero_policy="state"),
        "enabled": run_command("services.enabled", ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager", "--no-legend"], timeout=20, nonzero_policy="state"),
    }

    security = {
        "firewall": firewall_status(),
        "selinux": run_command("security.selinux", ["getenforce"], nonzero_policy="state"),
        "apparmor": run_command("security.apparmor", ["aa-status", "--enabled"], nonzero_policy="state"),
        "sshd": collect_sshd_settings(),
        "ftp": collect_ftp_posture(listening),
        "password_policy": collect_password_policy(),
        "sysctl_security": {
            "ip_forward": safe_read_text("/proc/sys/net/ipv4/ip_forward", "security.sysctl.ip_forward"),
            "rp_filter_all": safe_read_text("/proc/sys/net/ipv4/conf/all/rp_filter", "security.sysctl.rp_filter"),
            "aslr": safe_read_text("/proc/sys/kernel/randomize_va_space", "security.sysctl.aslr"),
        },
    }

    identity = {
        "local_users": local_user_summary(args.include_local_users),
        "local_groups": group_summary(),
        "integration": collect_identity_integration(),
        "nsswitch": safe_read_text("/etc/nsswitch.conf", "identity.nsswitch"),
    }

    time_sync = {
        "timedatectl": run_command("time.timedatectl", ["timedatectl", "show", "--property=Timezone", "--property=NTPSynchronized", "--property=NTP", "--property=LocalRTC"], nonzero_policy="state"),
        "chrony": run_command("time.chrony", ["chronyc", "tracking"], nonzero_policy="state"),
    }

    software = {"packages": package_inventory(args.include_packages)}
    shares = {"samba": collect_samba_shares()}

    result = {
        "metadata": metadata,
        "data": {
            "system": system,
            "storage": storage,
            "network": network,
            "services": services,
            "security": security,
            "identity": identity,
            "time_sync": time_sync,
            "software": software,
            "shares": shares,
        },
        "errors": ERRORS,
        "limitations": LIMITATIONS,
        "warnings": WARNINGS,
    }

    metadata["duration_seconds"] = round(time.monotonic() - started_monotonic, 2)
    metadata["error_count"] = len(ERRORS)
    metadata["limitation_count"] = len(LIMITATIONS)
    metadata["warning_count"] = len(WARNINGS)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label_part = f"_{run_label}" if run_label else ""
    output_path = output_dir / f"{COLLECTOR_NAME}_{hostname}_{timestamp}{label_part}.json"

    output_bytes = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    output_path.write_bytes(output_bytes)
    os.chmod(output_path, 0o600)

    digest = hashlib.sha256(output_bytes).hexdigest()
    hash_path = Path(str(output_path) + ".sha256")
    hash_path.write_text(f"{digest}  {output_path.name}\n", encoding="ascii")
    os.chmod(hash_path, 0o600)

    print("Collector finalizado.")
    print(f"JSON:        {output_path}")
    print(f"SHA256:      {hash_path}")
    print(f"Erros:       {len(ERRORS)}")
    print(f"Limitacoes:  {len(LIMITATIONS)}")
    print(f"Avisos:      {len(WARNINGS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
