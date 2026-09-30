#!/usr/bin/env python3
"""P01 Multi-target Credentialed Executor v0.4b.5.

Dry-run by default. Execute mode requires an authorized-access acknowledgement
and SHA256 verification of the reviewed Credential Plan.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, importlib.util, ipaddress, json, re, socket, sys
from pathlib import Path
from typing import Any, Mapping

NAME="P01-Credentialed-Discovery-Executor"; VERSION="0.4b.5"; SCHEMA="0.4b"
ROOT=Path(__file__).resolve().parents[1]; CRED=ROOT/"credential_manager"
if str(CRED) not in sys.path: sys.path.insert(0,str(CRED))
from P01_Credential_Manager import ProfileMatch, _safe_profile_view, load_profiles

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def label(v):
    v=re.sub(r"[^A-Za-z0-9._-]+","-",str(v).strip()); return v.strip("-")[:80] or "job"
def load(path):
    with Path(path).open(encoding="utf-8-sig") as f: v=json.load(f)
    if not isinstance(v,dict): raise ValueError("JSON root must be an object")
    return v
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def verify(path,sidecar):
    got=digest(path); words=Path(sidecar).read_text(encoding="utf-8-sig").split()
    if not words or not re.fullmatch(r"[0-9a-fA-F]{64}",words[0]): raise ValueError("invalid SHA256 sidecar")
    if got.lower()!=words[0].lower(): raise ValueError("Credential Plan SHA256 mismatch")
    return got
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def index(doc): return {str(p["id"]):dict(p) for p in doc.get("profiles",[]) if isinstance(p,dict) and p.get("id")}
def cred_id(profile):
    refs=profile.get("secret_refs") or {}
    material="|".join(f"{k}={refs[k]}" for k in sorted(refs)) if refs else f"profile:{profile.get('id','')}"
    return "cred-"+hashlib.sha256(material.encode()).hexdigest()[:16]
def winrm_scheme(safe_profile):
    services={str(x).lower() for x in (safe_profile.get("selectors") or {}).get("services",[])}
    if services=={"winrm-http"}: return "http"
    if services=={"winrm-https"}: return "https"
    return None
def build_actions(plan,profiles,max_actions=25):
    live=index(profiles); out=[]
    for asset in plan.get("assets",[]):
        if not isinstance(asset,Mapping) or asset.get("credentialed_action_status")!="adapter_candidate": continue
        ip=str(asset.get("ip") or "")
        try: ipaddress.ip_address(ip)
        except ValueError: continue
        for pp in asset.get("protocol_plans",[]) or []:
            proto=str(pp.get("protocol") or "").lower()
            eligible=pp.get("eligible_profiles",[]) or []
            if proto not in {"ssh","winrm"} or pp.get("action")!="adapter_candidate" or not eligible: continue
            pm=eligible[0]; snap=pm.get("profile") or {}; pid=str(snap.get("id") or "")
            a={"target_ip":ip,"hostname":asset.get("hostname"),"device_type":asset.get("device_type"),
               "os_family":asset.get("os_family"),"confidence":asset.get("confidence"),"realm":asset.get("realm"),
               "protocol":proto,"profile_id":pid or None,"matched_scope":pm.get("matched_scope"),
               "scope_prefix_length":pm.get("scope_prefix_length"),"selector_score":pm.get("selector_score"),
               "matched_selectors":pm.get("matched_selectors",[]),"execution_eligibility":"pending","skip_reason":None}
            if pid not in live:
                a.update(execution_eligibility="blocked",skip_reason="planned_profile_missing_from_live_profiles"); out.append(a); continue
            prof=live[pid]
            if canon(_safe_profile_view(prof))!=canon(snap):
                a.update(execution_eligibility="blocked",skip_reason="profile_drift_since_plan_generation"); out.append(a); continue
            a.update(execution_eligibility="ready",credential_identity_id=cred_id(prof),
                     failure_budget_per_job=int(prof.get("failure_budget_per_job",2)))
            if proto=="ssh": a.update(port=22,protocol_variant="ssh")
            else:
                scheme=winrm_scheme(snap)
                if not scheme: a.update(execution_eligibility="blocked",skip_reason="ambiguous_or_missing_winrm_service_selector")
                else: a.update(scheme=scheme,port=5986 if scheme=="https" else 5985,protocol_variant=f"winrm-{scheme}")
            out.append(a)
    out.sort(key=lambda a:(int(ipaddress.ip_address(a["target_ip"])),a["protocol"],str(a.get("profile_id"))))
    if len(out)>max_actions: raise ValueError(f"{len(out)} actions exceed max_actions={max_actions}")
    return out
def circuits(actions):
    s={}
    for a in actions:
        cid=a.get("credential_identity_id")
        if not cid: continue
        b=int(a.get("failure_budget_per_job",2))
        if cid not in s: s[cid]={"failure_budget_per_job":b,"authentication_failures":0,"transport_failures":0,"remote_or_unknown_failures":0,"successes":0,"circuit_open":False}
        else: s[cid]["failure_budget_per_job"]=min(s[cid]["failure_budget_per_job"],b)
    return s
def classify_ssh(attempt):
    if attempt.get("success"): return {"failure_category":None,"counts_against_credential_budget":False}
    e=(str(attempt.get("error_type") or "")+" "+str(attempt.get("error") or "")).lower()
    if any(x in e for x in ("authenticationexception","authentication failed","permission denied","auth failed")):
        return {"failure_category":"authentication","counts_against_credential_budget":True}
    if any(x in e for x in ("timeout","timed out","novalidconnectionserror","connection refused","no route to host","unable to connect")):
        return {"failure_category":"transport","counts_against_credential_budget":False}
    return {"failure_category":"remote_execution_or_unknown","counts_against_credential_budget":False}
def update_circuit(state,cid,attempt):
    x=state[cid]
    if attempt.get("success"): x["successes"]+=1; return
    cat=attempt.get("failure_category") or "remote_execution_or_unknown"
    if cat=="authentication": x["authentication_failures"]+=1
    elif cat=="transport": x["transport_failures"]+=1
    else: x["remote_or_unknown_failures"]+=1
    if x["authentication_failures"]>=x["failure_budget_per_job"]: x["circuit_open"]=True
def mod(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    if not spec or not spec.loader: raise RuntimeError(f"cannot load {path}")
    m=importlib.util.module_from_spec(spec); sys.modules[name]=m; spec.loader.exec_module(m); return m
def dispatch(a,profile,auth_only,known_hosts,hostkey):
    pm=ProfileMatch(dict(profile),str(a.get("matched_scope") or ""),int(a.get("scope_prefix_length") or 0),
                    int(a.get("selector_score") or 0),tuple(a.get("matched_selectors") or []))
    if a["protocol"]=="ssh":
        m=mod("p01_exec_ssh",ROOT/"credentialed_enrichment"/"P01_SSH_Enricher.py")
        attempt,enrich=m.connect_with_profile(str(a["target_ip"]),22,pm,known_hosts,hostkey,5.0,8.0,not auth_only)
        attempt.update(classify_ssh(attempt)); return attempt,enrich
    m=mod("p01_exec_winrm",ROOT/"credentialed_enrichment"/"P01_WinRM_Enricher.py")
    return m.attempt_profile(pm,str(a["target_ip"]),int(a["port"]),str(a["scheme"]),"ntlm","validate",auth_only)
def safe_action(a):
    fields={"target_ip","hostname","device_type","os_family","confidence","realm","protocol","protocol_variant","port","profile_id",
            "matched_scope","scope_prefix_length","selector_score","matched_selectors","execution_eligibility","skip_reason",
            "credential_identity_id","failure_budget_per_job"}
    return {k:a[k] for k in fields if k in a}
def write(path,payload):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(payload,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); h=digest(path)
    sha=path.with_suffix(path.suffix+".sha256"); sha.write_text(f"{h}  {path.name}\n",encoding="utf-8"); return path,sha,h
def run_job(plan,profiles,plan_hash,outdir,run_label,execute=False,auth_only=False,max_actions=25,known_hosts=None,hostkey="strict"):
    acts=build_actions(plan,profiles,max_actions); live=index(profiles); state=circuits(acts); results=[]
    for seq,a in enumerate(acts,1):
        r={"sequence":seq,"action":safe_action(a)}
        if a.get("execution_eligibility")!="ready": r.update(execution_status="skipped",skip_reason=a.get("skip_reason")); results.append(r); continue
        cid=a["credential_identity_id"]
        if state[cid]["circuit_open"]: r.update(execution_status="skipped",skip_reason="credential_circuit_open"); results.append(r); continue
        if not execute: r["execution_status"]="dry_run_ready"; results.append(r); continue
        try: attempt,enrich=dispatch(a,live[a["profile_id"]],auth_only,known_hosts,hostkey)
        except Exception as exc:
            attempt={"profile_id":a["profile_id"],"protocol":a["protocol"],"success":False,"result":"executor_dispatch_exception",
                     "error_type":type(exc).__name__,"error":str(exc)[:300],"failure_category":"remote_execution_or_unknown",
                     "counts_against_credential_budget":False}; enrich=None
        if a["protocol"]=="ssh" and "failure_category" not in attempt: attempt.update(classify_ssh(attempt))
        update_circuit(state,cid,attempt)
        target={"metadata":{"executor_name":NAME,"executor_version":VERSION,"generated_at_utc":now(),"run_label":run_label,
                            "execution_host":socket.gethostname(),"read_only_mode":True,"secret_values_persisted_to_output":False,
                            "plan_sha256":plan_hash},"action":safe_action(a),"authentication":attempt,"enrichment":enrich,
                "circuit_after_attempt":dict(state[cid])}
        fn=f"P01-Credentialed-Target_{label(a['target_ip'])}_{a['protocol']}_{label(run_label)}.json"
        tp,ts,th=write(Path(outdir)/"targets"/fn,target)
        r.update(execution_status="completed",authentication_success=bool(attempt.get("success")),
                 failure_category=attempt.get("failure_category"),counts_against_credential_budget=bool(attempt.get("counts_against_credential_budget",False)),
                 collection_status=enrich.get("collection_status") if isinstance(enrich,Mapping) else None,
                 target_result_file=str(tp),target_result_sha256_file=str(ts),target_result_sha256=th); results.append(r)
    summary={"actions_total":len(acts),"actions_ready":sum(a.get("execution_eligibility")=="ready" for a in acts),
             "actions_blocked_preflight":sum(a.get("execution_eligibility")!="ready" for a in acts),
             "dry_run_ready":sum(r.get("execution_status")=="dry_run_ready" for r in results),
             "completed":sum(r.get("execution_status")=="completed" for r in results),
             "skipped":sum(r.get("execution_status")=="skipped" for r in results),
             "authentication_successes":sum(r.get("authentication_success") is True for r in results),
             "authentication_failures":sum(r.get("execution_status")=="completed" and r.get("authentication_success") is False for r in results),
             "open_credential_circuits":sum(x["circuit_open"] for x in state.values())}
    return {"metadata":{"executor_name":NAME,"executor_version":VERSION,"schema_version":SCHEMA,"generated_at_utc":now(),"run_label":run_label,
                        "execution_host":socket.gethostname(),"execution_mode":"execute" if execute else "dry_run","auth_only":bool(auth_only),
                        "read_only_mode":True,"secret_resolution":bool(execute),"authentication_attempts":bool(execute),
                        "plan_sha256":plan_hash,"concurrency":1},
            "source_plan":{"planner_name":plan.get("metadata",{}).get("planner_name"),"planner_version":plan.get("metadata",{}).get("planner_version"),
                           "source_run_label":plan.get("source",{}).get("run_label")},
            "summary":summary,"actions":results,"credential_circuits":state,
            "limitations":["first planned profile candidate only","sequential execution only","no pivoting","no dynamic-scope expansion"]}
def cli(argv=None):
    p=argparse.ArgumentParser(description=f"{NAME} {VERSION}")
    p.add_argument("--plan",required=True);p.add_argument("--plan-sha256");p.add_argument("--profiles",required=True);p.add_argument("--output-dir",default="./output")
    p.add_argument("--run-label",default="credentialed-executor");p.add_argument("--max-actions",type=int,default=25);p.add_argument("--execute",action="store_true")
    p.add_argument("--auth-only",action="store_true");p.add_argument("--ack-authorized-access",action="store_true");p.add_argument("--concurrency",type=int,default=1)
    p.add_argument("--ssh-host-key-policy",choices=["strict","tofu"],default="strict");p.add_argument("--ssh-known-hosts",default=str(Path.home()/".orizonit"/"p01"/"known_hosts"))
    a=p.parse_args(argv)
    if a.concurrency!=1:p.error("v0.4b.5 supports only --concurrency 1")
    if a.execute and not a.ack_authorized_access:p.error("--execute requires --ack-authorized-access")
    if a.execute and not a.plan_sha256:p.error("--execute requires --plan-sha256")
    if a.auth_only and not a.execute:p.error("--auth-only requires --execute")
    plan=load(a.plan); profiles=load_profiles(Path(a.profiles)); ph=verify(a.plan,a.plan_sha256) if a.plan_sha256 else digest(a.plan)
    payload=run_job(plan,profiles,ph,Path(a.output_dir),a.run_label,a.execute,a.auth_only,a.max_actions,Path(a.ssh_known_hosts).expanduser(),a.ssh_host_key_policy)
    ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"); out=Path(a.output_dir)/f"P01-Credentialed-Job_{ts}_{label(a.run_label)}.json";out,sha,_=write(out,payload)
    print("Credentialed executor finalizado.");print(f"Mode: {payload['metadata']['execution_mode']}");print(f"Actions: {payload['summary']['actions_total']}")
    print(f"Ready: {payload['summary']['actions_ready']}");print(f"Completed: {payload['summary']['completed']}");print(f"Skipped: {payload['summary']['skipped']}")
    print(f"Open circuits: {payload['summary']['open_credential_circuits']}");print(f"JSON: {out}");print(f"SHA256: {sha}");return 0
if __name__=="__main__": raise SystemExit(cli())
