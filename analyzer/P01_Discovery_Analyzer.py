#!/usr/bin/env python3
# Orizon IT - P01 Discovery Analyzer v0.2
# Read-only: consumes collector JSON files and produces deterministic findings.

from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ANALYZER_NAME = "P01-Discovery-Analyzer"
ANALYZER_VERSION = "0.2.0"
OUTPUT_SCHEMA_VERSION = "0.2"
SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    return data


def get_nested(obj: Dict[str, Any], *path: str, default=None):
    cur: Any = obj
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def collector_kind(doc: Dict[str, Any]) -> str:
    name = str(get_nested(doc, "metadata", "collector_name", default="")).lower()
    if "windows" in name:
        return "windows"
    if "linux" in name:
        return "linux"
    return "unknown"


def asset_name(doc: Dict[str, Any]) -> str:
    m = doc.get("metadata", {}) if isinstance(doc.get("metadata"), dict) else {}
    return str(m.get("hostname") or m.get("computer_name") or "unknown")


def privilege_score(doc: Dict[str, Any]) -> int:
    p = str(get_nested(doc, "metadata", "privilege_profile", default="")).lower()
    scores = {"root": 30, "local-admin": 30, "administrator": 30, "standard-user": 10}
    score = scores.get(p, 0)
    score -= int(get_nested(doc, "metadata", "error_count", default=0) or 0) * 10
    score -= int(get_nested(doc, "metadata", "limitation_count", default=0) or 0)
    return score


def collected_ts(doc: Dict[str, Any]) -> str:
    return str(get_nested(doc, "metadata", "collected_at_utc", default=""))


def choose_canonical(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        groups[(r["asset"].lower(), r["kind"])].append(r)
    chosen = []
    for _, items in groups.items():
        items.sort(key=lambda x: (privilege_score(x["doc"]), collected_ts(x["doc"])), reverse=True)
        chosen.append(items[0])
    return chosen


def finding(rule: Dict[str, Any], rec: Dict[str, Any], evidence: Dict[str, Any], rationale: str, confidence: str = "High", asset_override: Optional[str] = None, asset_type: str = "Host") -> Dict[str, Any]:
    target_asset = asset_override or rec["asset"]
    return {
        "finding_id": f"{rule['id']}::{target_asset}",
        "rule_id": rule["id"],
        "title": rule["title"],
        "category": rule["category"],
        "severity": rule["severity"],
        "asset": target_asset,
        "asset_type": asset_type,
        "collector_host": rec["asset"],
        "collector_kind": rec["kind"],
        "collector_version": get_nested(rec["doc"], "metadata", "collector_version", default=None),
        "source_file": rec["path"].name,
        "source_sha256": rec["sha256"],
        "run_label": get_nested(rec["doc"], "metadata", "run_label", default=None),
        "privilege_profile": get_nested(rec["doc"], "metadata", "privilege_profile", default=None),
        "confidence": confidence,
        "evidence": evidence,
        "rationale": rationale,
        "recommendation": rule["recommendation"],
        "status": "Open"
    }


def parse_ms_date(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    m = re.search(r"/Date\((\d+)\)/", value.replace("\\/", "/"))
    if not m:
        return None
    return datetime.fromtimestamp(int(m.group(1)) / 1000.0, tz=timezone.utc)


def h_windows_firewall_disabled(rule, rec):
    profiles = get_nested(rec["doc"], "data", "security", "firewall_profiles", default=[])
    if isinstance(profiles, dict): profiles = [profiles]
    disabled = [p.get("Name") for p in profiles if isinstance(p, dict) and str(p.get("Enabled")).lower() in {"0","false"}]
    if disabled:
        return finding(rule, rec, {"disabled_profiles": disabled}, "Um ou mais perfis do Windows Defender Firewall foram coletados como desabilitados.")


def h_defender_signature_stale(rule, rec):
    d = get_nested(rec["doc"], "data", "security", "defender", default={})
    if not isinstance(d, dict) or not d.get("AntivirusEnabled"):
        return None
    dt = parse_ms_date(d.get("AntivirusSignatureLastUpdated"))
    if not dt:
        return None
    age = (datetime.now(timezone.utc) - dt).days
    threshold = int(rule.get("threshold_days", 7))
    if age > threshold:
        return finding(rule, rec, {"last_updated": d.get("AntivirusSignatureLastUpdated"), "age_days": age, "threshold_days": threshold}, "A data de atualização das assinaturas excede o threshold definido no ruleset.")


def h_ad_min_password_length(rule, rec):
    pp = get_nested(rec["doc"], "data", "active_directory", "password_policy", default={})
    if not isinstance(pp, dict): return None
    actual = pp.get("MinPasswordLength")
    threshold = int(rule.get("threshold", 14))
    if isinstance(actual, (int, float)) and actual < threshold:
        domain = str(get_nested(rec["doc"], "data", "active_directory", "domain", "DNSRoot", default=rec["asset"]))
        return finding(rule, rec, {"min_password_length": actual, "baseline_minimum": threshold}, "A política coletada possui comprimento mínimo inferior ao baseline configurado no ruleset.", asset_override=domain, asset_type="Domain")


def h_ad_password_never_expires(rule, rec):
    summary = get_nested(rec["doc"], "data", "active_directory", "object_summary", default={})
    if not isinstance(summary, dict): return None
    count = int(summary.get("users_password_never_expires") or 0)
    if count > 0:
        domain = str(get_nested(rec["doc"], "data", "active_directory", "domain", "DNSRoot", default=rec["asset"]))
        return finding(rule, rec, {"accounts_count": count}, "Foram identificadas contas marcadas para não expirar senha. O contexto de cada conta deve ser revisado antes de qualquer remediação.", asset_override=domain, asset_type="Domain")


def h_ad_lockout_disabled(rule, rec):
    pp = get_nested(rec["doc"], "data", "active_directory", "password_policy", default={})
    if isinstance(pp, dict) and pp.get("LockoutThreshold") == 0:
        domain = str(get_nested(rec["doc"], "data", "active_directory", "domain", "DNSRoot", default=rec["asset"]))
        return finding(rule, rec, {"lockout_threshold": 0}, "LockoutThreshold igual a zero indica que a política de bloqueio de conta não está habilitada na política coletada.", asset_override=domain, asset_type="Domain")


def h_linux_firewall_inactive(rule, rec):
    fw = get_nested(rec["doc"], "data", "security", "firewall", default={})
    if not isinstance(fw, dict): return None
    evidence = {}
    ufw = fw.get("ufw")
    if isinstance(ufw, dict) and "inactive" in str(ufw.get("stdout", "")).lower():
        evidence["ufw"] = ufw.get("stdout")
    firewalld = fw.get("firewalld_state")
    if isinstance(firewalld, dict) and "not running" in (str(firewalld.get("stdout", "")) + " " + str(firewalld.get("stderr", ""))).lower():
        evidence["firewalld"] = firewalld.get("stderr") or firewalld.get("stdout")
    if evidence:
        return finding(rule, rec, evidence, "O mecanismo de firewall local detectado está inativo. A aplicabilidade deve ser confirmada com o desenho de rede e segurança do cliente.")


def h_linux_ssh_root_login(rule, rec):
    eff = get_nested(rec["doc"], "data", "security", "sshd", "effective", default={})
    if isinstance(eff, dict) and str(eff.get("permitrootlogin", "")).lower() == "yes":
        return finding(rule, rec, {"permitrootlogin": "yes"}, "A configuração efetiva do sshd permite login direto de root.")


def h_linux_ssh_password_auth(rule, rec):
    eff = get_nested(rec["doc"], "data", "security", "sshd", "effective", default={})
    if isinstance(eff, dict) and str(eff.get("passwordauthentication", "")).lower() == "yes":
        return finding(rule, rec, {"passwordauthentication": "yes"}, "A configuração efetiva do sshd permite autenticação por senha.")


def h_linux_ntp_not_synchronized(rule, rec):
    td = get_nested(rec["doc"], "data", "time_sync", "timedatectl", default={})
    if not isinstance(td, dict): return None
    stdout = str(td.get("stdout", ""))
    if "NTPSynchronized=no" in stdout:
        vals = {}
        for line in stdout.splitlines():
            if "=" in line:
                k,v = line.split("=",1); vals[k]=v
        return finding(rule, rec, vals, "O sistema reporta NTPSynchronized=no no momento da coleta.")


def h_linux_failed_services(rule, rec):
    f = get_nested(rec["doc"], "data", "services", "failed", default={})
    if not isinstance(f, dict): return None
    stdout = str(f.get("stdout", "")).strip()
    if stdout:
        lines = [x.strip() for x in stdout.splitlines() if x.strip()]
        return finding(rule, rec, {"failed_services": lines, "count": len(lines)}, "Foram coletadas unidades systemd em estado failed.")


def _domain_asset(rec: Dict[str, Any]) -> str:
    return str(get_nested(rec["doc"], "data", "active_directory", "domain", "DNSRoot", default=rec["asset"]))


def h_ad_stale_computers(rule, rec):
    inactive = get_nested(rec["doc"], "data", "active_directory", "inactive_accounts", default={})
    if not isinstance(inactive, dict):
        return None
    computers = inactive.get("computers", {})
    if not isinstance(computers, dict):
        return None
    count = int(computers.get("enabled_stale_count") or 0)
    if count <= 0:
        return None
    threshold = int(inactive.get("threshold_days") or rule.get("threshold_days", 90))
    return finding(
        rule, rec,
        {"enabled_stale_count": count, "threshold_days": threshold, "details_included": bool(inactive.get("details_included"))},
        "Foram identificadas contas de computador habilitadas sem atividade de logon no período definido para o assessment. LastLogonDate é adequado para análise de inatividade, mas não representa auditoria exata de autenticação.",
        asset_override=_domain_asset(rec), asset_type="Domain"
    )


def h_ad_stale_users(rule, rec):
    inactive = get_nested(rec["doc"], "data", "active_directory", "inactive_accounts", default={})
    if not isinstance(inactive, dict):
        return None
    users = inactive.get("users", {})
    if not isinstance(users, dict):
        return None
    count = int(users.get("enabled_stale_count") or 0)
    if count <= 0:
        return None
    threshold = int(inactive.get("threshold_days") or rule.get("threshold_days", 90))
    return finding(
        rule, rec,
        {"enabled_stale_count": count, "threshold_days": threshold, "details_included": bool(inactive.get("details_included"))},
        "Foram identificadas contas de usuário habilitadas sem atividade de logon no período definido. Contas de serviço e exceções devem ser revisadas antes de qualquer ação.",
        asset_override=_domain_asset(rec), asset_type="Domain"
    )


def h_windows_secure_channel_broken(rule, rec):
    sc = get_nested(rec["doc"], "data", "security", "domain_secure_channel", default={})
    if not isinstance(sc, dict):
        return None
    if str(sc.get("status", "")).lower() == "broken" or sc.get("healthy") is False:
        return finding(
            rule, rec,
            {"domain": sc.get("domain"), "status": sc.get("status"), "method": sc.get("method")},
            "O host está associado a um domínio, porém a verificação local do secure channel indicou falha de confiança com o domínio."
        )


def _windows_share_lists(rec: Dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    smb = get_nested(rec["doc"], "data", "shares", "smb", default={})
    if not isinstance(smb, dict):
        return [], []
    confirmed: list[dict[str, Any]] = []
    potential: list[dict[str, Any]] = []
    for sh in smb.get("items", []) or []:
        if not isinstance(sh, dict) or sh.get("special"):
            continue
        if sh.get("confirmed_broad_write"):
            confirmed.append({"name": sh.get("name"), "path": sh.get("path")})
        elif sh.get("broad_write_share") and not sh.get("ntfs_permissions_available", True):
            potential.append({"name": sh.get("name"), "path": sh.get("path"), "reason": "share_acl_broad_ntfs_unverified"})
    return confirmed, potential


def _linux_share_lists(rec: Dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    samba = get_nested(rec["doc"], "data", "shares", "samba", default={})
    if not isinstance(samba, dict):
        return [], []
    confirmed: list[dict[str, Any]] = []
    potential: list[dict[str, Any]] = []
    for sh in samba.get("items", []) or []:
        if not isinstance(sh, dict):
            continue
        base = {"name": sh.get("name"), "path": sh.get("path"), "guest_ok": sh.get("guest_ok"), "force_user": sh.get("force_user")}
        if sh.get("strong_write_confirmation"):
            confirmed.append(base)
        elif sh.get("guest_write_configured"):
            potential.append({**base, "reason": "guest_write_configured_filesystem_effective_access_not_fully_confirmed"})
    return confirmed, potential


def h_share_broad_write_confirmed(rule, rec):
    confirmed, _ = _windows_share_lists(rec) if rec["kind"] == "windows" else _linux_share_lists(rec)
    if confirmed:
        return finding(
            rule, rec,
            {"shares": confirmed, "count": len(confirmed)},
            "Foram identificados compartilhamentos em que a coleta conseguiu confirmar configuração de escrita para principal amplo/guest em conjunto com evidência local compatível.",
            confidence="High"
        )


def h_share_broad_write_potential(rule, rec):
    _, potential = _windows_share_lists(rec) if rec["kind"] == "windows" else _linux_share_lists(rec)
    if potential:
        return finding(
            rule, rec,
            {"shares": potential, "count": len(potential)},
            "A camada de compartilhamento permite escrita ampla/guest, porém a coleta não conseguiu confirmar completamente o acesso efetivo no filesystem. Requer validação antes da remediação.",
            confidence="Medium"
        )


def h_ftp_plaintext_exposed(rule, rec):
    ftp = get_nested(rec["doc"], "data", "security", "ftp", default={})
    if not isinstance(ftp, dict) or not ftp.get("network_exposed"):
        return None
    enc = str(ftp.get("encryption_status", "unknown")).lower()
    plaintext = ftp.get("plaintext_allowed") is True or enc in {"disabled", "optional", "plaintext_allowed"}
    if plaintext:
        return finding(
            rule, rec,
            {"product": ftp.get("product"), "encryption_status": ftp.get("encryption_status"), "listeners": ftp.get("listeners", []), "evidence": ftp.get("evidence") or ftp.get("iis_ftp_sites")},
            "Foi detectado serviço FTP acessível por interface de rede com possibilidade de sessão sem criptografia, conforme configuração local coletada."
        )


def h_ftp_encryption_unknown(rule, rec):
    ftp = get_nested(rec["doc"], "data", "security", "ftp", default={})
    if not isinstance(ftp, dict) or not ftp.get("network_exposed"):
        return None
    if str(ftp.get("encryption_status", "")).lower() == "unknown":
        return finding(
            rule, rec,
            {"product": ftp.get("product"), "listeners": ftp.get("listeners", [])},
            "Foi detectado listener FTP acessível pela rede, mas a coleta local não conseguiu comprovar se TLS é obrigatório. A exposição deve ser validada.",
            confidence="Medium"
        )


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def h_linux_password_minlen(rule, rec):
    if rec["kind"] != "linux":
        return None
    policy = get_nested(rec["doc"], "data", "security", "password_policy", default={})
    if not isinstance(policy, dict):
        return None
    eff = get_nested(policy, "pwquality", "effective_candidate", default={})
    if not isinstance(eff, dict):
        return None
    actual = _to_int(eff.get("minlen"))
    source = "pwquality.conf"
    if actual is None:
        pam_files = get_nested(policy, "pam", "files", default=[])
        for pf in pam_files if isinstance(pam_files, list) else []:
            if not isinstance(pf, dict):
                continue
            for line in pf.get("relevant_lines", []) or []:
                m = re.search(r"\bminlen=(\d+)\b", str(line), re.I)
                if m:
                    actual = int(m.group(1)); source = "pam_option"; break
            if actual is not None:
                break
    threshold = int(rule.get("threshold", 14))
    if actual is not None and actual < threshold:
        return finding(
            rule, rec,
            {"minlen": actual, "baseline_minimum": threshold, "source": source, "pwquality_settings": eff},
            "A configuração local coletada para libpwquality define comprimento mínimo inferior ao baseline do ruleset. PAM pode conter opções adicionais e deve ser considerado na validação final."
        )


def h_linux_password_complexity_missing(rule, rec):
    if rec["kind"] != "linux":
        return None
    policy = get_nested(rec["doc"], "data", "security", "password_policy", default={})
    if not isinstance(policy, dict) or "pam" not in policy:
        return None
    modules = get_nested(policy, "pam", "modules", default={})
    if not isinstance(modules, dict):
        return None
    if not bool(modules.get("pam_pwquality")) and not bool(modules.get("pam_unix_obscure")):
        integration = get_nested(rec["doc"], "data", "identity", "integration", default={})
        return finding(
            rule, rec,
            {"pam_pwquality_present": False, "pam_unix_obscure_present": False, "identity_integration": integration},
            "O collector não identificou pam_pwquality na pilha PAM local examinada. Em hosts integrados a AD/LDAP/IPA, a política efetiva pode ser definida externamente e deve ser correlacionada antes da remediação.",
            confidence="Medium"
        )



HANDLERS = {
    "windows_firewall_disabled": h_windows_firewall_disabled,
    "defender_signature_stale": h_defender_signature_stale,
    "ad_min_password_length": h_ad_min_password_length,
    "ad_password_never_expires": h_ad_password_never_expires,
    "ad_lockout_disabled": h_ad_lockout_disabled,
    "linux_firewall_inactive": h_linux_firewall_inactive,
    "linux_ssh_root_login": h_linux_ssh_root_login,
    "linux_ssh_password_auth": h_linux_ssh_password_auth,
    "linux_ntp_not_synchronized": h_linux_ntp_not_synchronized,
    "linux_failed_services": h_linux_failed_services,
    "ad_stale_computers": h_ad_stale_computers,
    "ad_stale_users": h_ad_stale_users,
    "windows_secure_channel_broken": h_windows_secure_channel_broken,
    "share_broad_write_confirmed": h_share_broad_write_confirmed,
    "share_broad_write_potential": h_share_broad_write_potential,
    "ftp_plaintext_exposed": h_ftp_plaintext_exposed,
    "ftp_encryption_unknown": h_ftp_encryption_unknown,
    "linux_password_minlen": h_linux_password_minlen,
    "linux_password_complexity_missing": h_linux_password_complexity_missing,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Orizon IT P01 Discovery Analyzer v0.2")
    ap.add_argument("--input-dir", required=True, help="Diretório contendo JSONs produzidos pelos collectors")
    ap.add_argument("--output-dir", required=True, help="Diretório para o relatório JSON do Analyzer")
    ap.add_argument("--rules-file", required=True, help="Arquivo P01_Rules_v0.2.json")
    ap.add_argument("--run-label", default="analyzer-run", help="Rótulo da execução")
    ap.add_argument("--recursive", action="store_true", help="Busca JSONs recursivamente")
    args = ap.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    rules_path = Path(args.rules_file)
    if not input_dir.is_dir():
        print(f"Input directory not found: {input_dir}", file=sys.stderr); return 2
    ruleset = load_json(rules_path)
    pattern = "**/*.json" if args.recursive else "*.json"
    records = []
    ingestion_errors = []
    for p in sorted(input_dir.glob(pattern)):
        if p.resolve() == rules_path.resolve():
            continue
        try:
            doc = load_json(p)
            kind = collector_kind(doc)
            if kind == "unknown":
                continue
            records.append({"path":p, "doc":doc, "kind":kind, "asset":asset_name(doc), "sha256":sha256_file(p)})
        except Exception as e:
            ingestion_errors.append({"file":p.name, "error":str(e), "type":type(e).__name__})

    canonical = choose_canonical(records)
    findings = []
    rule_errors = []
    for rec in canonical:
        for rule in ruleset.get("rules", []):
            if not rule.get("enabled", True):
                continue
            h = HANDLERS.get(rule.get("handler"))
            if not h:
                rule_errors.append({"rule_id":rule.get("id"), "error":"handler_not_found"}); continue
            try:
                result = h(rule, rec)
                if result:
                    findings.append(result)
            except Exception as e:
                rule_errors.append({"rule_id":rule.get("id"), "asset":rec["asset"], "error":str(e), "type":type(e).__name__})

    findings.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"],0), x["rule_id"], x["asset"].lower()))
    sev = Counter(f["severity"] for f in findings)
    coverage = []
    for r in records:
        coverage.append({
            "asset":r["asset"], "collector_kind":r["kind"], "source_file":r["path"].name,
            "sha256":r["sha256"], "run_label":get_nested(r["doc"],"metadata","run_label",default=None),
            "privilege_profile":get_nested(r["doc"],"metadata","privilege_profile",default=None),
            "error_count":int(get_nested(r["doc"],"metadata","error_count",default=0) or 0),
            "limitation_count":int(get_nested(r["doc"],"metadata","limitation_count",default=0) or 0),
            "warning_count":int(get_nested(r["doc"],"metadata","warning_count",default=0) or 0),
            "selected_for_analysis": any(c["path"].resolve()==r["path"].resolve() for c in canonical)
        })

    report = {
        "metadata":{
            "analyzer_name":ANALYZER_NAME,
            "analyzer_version":ANALYZER_VERSION,
            "output_schema_version":OUTPUT_SCHEMA_VERSION,
            "ruleset_name":ruleset.get("ruleset_name"),
            "ruleset_version":ruleset.get("ruleset_version"),
            "analyzed_at_utc":utc_now(),
            "run_label":args.run_label,
            "read_only_mode":True,
            "input_files":len(records),
            "canonical_assets":len(canonical),
            "finding_count":len(findings),
            "ingestion_error_count":len(ingestion_errors),
            "rule_error_count":len(rule_errors)
        },
        "summary":{
            "by_severity":{k:sev.get(k,0) for k in ["Critical","High","Medium","Low","Informational"]},
            "assets_analyzed":sorted({r["asset"] for r in canonical}),
            "finding_scopes":sorted({f["asset"] for f in findings}),
            "rules_enabled":sum(1 for x in ruleset.get("rules",[]) if x.get("enabled",True))
        },
        "coverage":coverage,
        "findings":findings,
        "ingestion_errors":ingestion_errors,
        "rule_errors":rule_errors
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+","-",args.run_label).strip("-") or "run"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = output_dir / f"P01-Discovery-Analyzer_{stamp}_{safe}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    digest = sha256_file(out)
    (Path(str(out)+".sha256")).write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    print(f"Analyzer finalizado.\nJSON: {out}\nSHA256: {digest}\nFindings: {len(findings)}\nErrors: ingestion={len(ingestion_errors)} rules={len(rule_errors)}")
    return 0 if not ingestion_errors and not rule_errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
