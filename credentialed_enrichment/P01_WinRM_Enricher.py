#!/usr/bin/env python3
'''Orizon IT P01 WinRM Credentialed Enrichment v0.4b.4.3.

Read-only Windows enrichment over WinRM with modular PowerShell collection.
'''

from __future__ import annotations
import argparse, datetime as dt, hashlib, ipaddress, json, os, re, socket, sys, time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ADAPTER_NAME="P01-WinRM-Credentialed-Enrichment"
ADAPTER_VERSION="0.4b.4.3"
SCHEMA_VERSION="0.4b"
ROOT=Path(__file__).resolve().parents[1]
CRED_DIR=ROOT/"credential_manager"
if str(CRED_DIR) not in sys.path: sys.path.insert(0,str(CRED_DIR))
from P01_Credential_Manager import CredentialConfigError, load_profiles, match_profiles, resolve_secret

try:
    import winrm
except ImportError:
    winrm=None

MUTATING_POWERSHELL_RE=re.compile(r"(?im)\b(?:Set|New|Remove|Add|Start|Stop|Restart|Repair|Enable|Disable|Install|Uninstall|Rename|Clear|Reset|Update)-[A-Za-z0-9_-]+")

POWERSHELL_AUTH_PROBE=r'''
$ErrorActionPreference='Stop'
"P01_WINRM_AUTH_PROBE"
'''.strip()

POWERSHELL_SECTIONS={
"identity":r'''
$ErrorActionPreference='SilentlyContinue'
$cs=Get-CimInstance Win32_ComputerSystem;$bios=Get-CimInstance Win32_BIOS
$fqdn=$null;try{$fqdn=[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName}catch{}
[pscustomobject]@{computer_name=[string]$env:COMPUTERNAME;fqdn=[string]$fqdn;manufacturer=[string]$cs.Manufacturer;model=[string]$cs.Model;serial_number=[string]$bios.SerialNumber;domain=[string]$cs.Domain;part_of_domain=[bool]$cs.PartOfDomain;domain_role=[int]$cs.DomainRole;current_user=[string]$env:USERNAME}|ConvertTo-Json -Compress
'''.strip(),
"operating_system":r'''
$ErrorActionPreference='SilentlyContinue'
$os=Get-CimInstance Win32_OperatingSystem
$lastBoot=$null;if($os.LastBootUpTime){$lastBoot=$os.LastBootUpTime.ToString('o')}
$installDate=$null;if($os.InstallDate){$installDate=$os.InstallDate.ToString('o')}
[pscustomobject]@{caption=[string]$os.Caption;version=[string]$os.Version;build_number=[string]$os.BuildNumber;architecture=[string]$os.OSArchitecture;last_boot_up_time=$lastBoot;install_date=$installDate}|ConvertTo-Json -Compress
'''.strip(),
"hardware":r'''
$ErrorActionPreference='SilentlyContinue'
$cs=Get-CimInstance Win32_ComputerSystem;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
$cpuName=$null;if($cpu){$cpuName=[string]$cpu.Name}
[pscustomobject]@{logical_processors=[int]$cs.NumberOfLogicalProcessors;total_physical_memory_bytes=[UInt64]$cs.TotalPhysicalMemory;cpu_name=$cpuName}|ConvertTo-Json -Compress
'''.strip(),
"interfaces":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
Get-NetIPConfiguration|ForEach-Object{$c=$_;$a=@();@($c.IPv4Address)|ForEach-Object{if($_.IPAddress){$a+=[pscustomobject]@{address=[string]$_.IPAddress;prefix_length=[int]$_.PrefixLength}}};$g=@();@($c.IPv4DefaultGateway)|ForEach-Object{if($_.NextHop){$g+=[string]$_.NextHop}};$r+=[pscustomobject]@{interface_alias=[string]$c.InterfaceAlias;interface_index=[int]$c.InterfaceIndex;ipv4=$a;ipv4_gateways=$g}}
ConvertTo-Json -InputObject @($r) -Depth 5 -Compress
'''.strip(),
"routes":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
Get-NetRoute -AddressFamily IPv4|ForEach-Object{$r+=[pscustomobject]@{destination_prefix=[string]$_.DestinationPrefix;next_hop=[string]$_.NextHop;interface_index=[int]$_.InterfaceIndex;route_metric=[int]$_.RouteMetric;protocol=[string]$_.Protocol;state=[string]$_.State}}
ConvertTo-Json -InputObject @($r) -Depth 4 -Compress
'''.strip(),
"dns":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
Get-DnsClientServerAddress -AddressFamily IPv4|ForEach-Object{$r+=[pscustomobject]@{interface_alias=[string]$_.InterfaceAlias;interface_index=[int]$_.InterfaceIndex;server_addresses=@($_.ServerAddresses|ForEach-Object{[string]$_})}}
ConvertTo-Json -InputObject @($r) -Depth 4 -Compress
'''.strip(),
"firewall":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
Get-NetFirewallProfile|ForEach-Object{$r+=[pscustomobject]@{name=[string]$_.Name;enabled=[bool]$_.Enabled;default_inbound_action=[string]$_.DefaultInboundAction;default_outbound_action=[string]$_.DefaultOutboundAction}}
ConvertTo-Json -InputObject @($r) -Depth 3 -Compress
'''.strip(),
"secure_channel":r'''
$ErrorActionPreference='SilentlyContinue';$cs=Get-CimInstance Win32_ComputerSystem;$checked=$false;$healthy=$null
if($cs.PartOfDomain -and [int]$cs.DomainRole -lt 4){$checked=$true;try{$healthy=[bool](Test-ComputerSecureChannel -ErrorAction Stop)}catch{$healthy=$null}}
[pscustomobject]@{checked=$checked;healthy=$healthy}|ConvertTo-Json -Compress
'''.strip(),
"local_administrators":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
if(Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){try{$g=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop;Get-LocalGroupMember -Group $g.Name -ErrorAction Stop|ForEach-Object{$r+=[pscustomobject]@{name=[string]$_.Name;object_class=[string]$_.ObjectClass;principal_source=[string]$_.PrincipalSource}}}catch{}}
ConvertTo-Json -InputObject @($r) -Depth 3 -Compress
'''.strip(),
"hotfixes":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 20|ForEach-Object{$installed=$null;if($_.InstalledOn){$installed=$_.InstalledOn.ToString('o')};$r+=[pscustomobject]@{hotfix_id=[string]$_.HotFixID;description=[string]$_.Description;installed_on=$installed}}
ConvertTo-Json -InputObject @($r) -Depth 3 -Compress
'''.strip(),
"winrm_service":r'''
$ErrorActionPreference='SilentlyContinue';$s=Get-Service -Name WinRM -ErrorAction SilentlyContinue
if($s){[pscustomobject]@{status=[string]$s.Status;start_type=[string]$s.StartType}|ConvertTo-Json -Compress}else{'null'}
'''.strip(),
"roles":r'''
$ErrorActionPreference='SilentlyContinue';$r=@()
if(Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue){Get-WindowsFeature|Where-Object{$_.Installed}|ForEach-Object{$r+=[pscustomobject]@{name=[string]$_.Name;display_name=[string]$_.DisplayName}}}
ConvertTo-Json -InputObject @($r) -Depth 3 -Compress
'''.strip(),
}

def utc_now_iso(): return dt.datetime.now(dt.timezone.utc).isoformat()
def safe_label(v):
    v=re.sub(r"[^A-Za-z0-9._-]+","-",v.strip()); return v.strip("-")[:80] or "run"
def safe_error(exc):
    text=str(exc or "").strip()
    text=re.sub(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*\S+",r"\1=<redacted>",text)
    text=re.sub(r"(?i)://[^/@:\s]+:[^/@\s]+@","://<redacted>@",text)
    return text[:500] or type(exc).__name__
def powershell_is_read_only(script): return MUTATING_POWERSHELL_RE.search(script) is None
def classify_attempt_failure(error_type, error_message, status_code=None):
    """Classify a failed WinRM attempt for safe credential-budget handling."""
    et=(error_type or "").lower()
    msg=(error_message or "").lower()
    transport_tokens=("timeout","connecttimeout","readtimeout","connectionerror","newconnectionerror","maxretryerror")
    transport_msg=("timed out","connection refused","max retries exceeded","no route to host","name or service not known","temporary failure in name resolution")
    auth_msg=("unauthorized","invalid credential","invalidcredentials","access is denied","401","0x8009030c","logon failure")
    if any(t in et for t in transport_tokens) or any(t in msg for t in transport_msg):
        return {"failure_category":"transport","counts_against_credential_budget":False}
    if status_code==401 or any(t in msg for t in auth_msg):
        return {"failure_category":"authentication","counts_against_credential_budget":True}
    return {"failure_category":"remote_execution_or_unknown","counts_against_credential_budget":False}

def validate_scripts():
    for name,script in {"auth_probe":POWERSHELL_AUTH_PROBE,**POWERSHELL_SECTIONS}.items():
        if not powershell_is_read_only(script): raise RuntimeError(f"Mutating PowerShell verb detected in {name}")
def decode_stream(v):
    if v is None:return ""
    if isinstance(v,bytes):return v.decode("utf-8",errors="replace")
    return str(v)
def run_ps(session,script):
    started=time.monotonic()
    try:
        r=session.run_ps(script)
        return {"success":int(r.status_code)==0,"status_code":int(r.status_code),"stdout":decode_stream(r.std_out).strip(),"stderr":decode_stream(r.std_err).strip(),"duration_ms":int((time.monotonic()-started)*1000)}
    except Exception as exc:
        return {"success":False,"status_code":None,"stdout":"","stderr":"","error_type":type(exc).__name__,"error":safe_error(exc),"duration_ms":int((time.monotonic()-started)*1000)}
def parse_json_output(text,section):
    if text=="":raise ValueError(f"{section} returned empty stdout")
    return json.loads(text)
def collect_sections(session):
    validate_scripts(); values={}; evidence=[]
    for section,script in POWERSHELL_SECTIONS.items():
        result=run_ps(session,script)
        ev={"section":section,"success":False,"status_code":result.get("status_code"),"duration_ms":result.get("duration_ms")}
        if result.get("success"):
            try: values[section]=parse_json_output(result.get("stdout") or "",section);ev["success"]=True
            except Exception as exc: ev.update({"error_type":type(exc).__name__,"error":safe_error(exc),"stderr":result.get("stderr")})
        else: ev.update({"error_type":result.get("error_type"),"error":result.get("error"),"stderr":result.get("stderr")})
        evidence.append(ev)
    return values,evidence
def assemble_collection(values,evidence):
    sec=values.get("secure_channel") or {}
    payload={
      "identity":values.get("identity") or {},
      "operating_system":values.get("operating_system") or {},
      "hardware":values.get("hardware") or {},
      "network":{"interfaces":values.get("interfaces") or [],"routes":values.get("routes") or [],"dns":values.get("dns") or []},
      "security":{"firewall_profiles":values.get("firewall") or [],"secure_channel_checked":sec.get("checked") if isinstance(sec,Mapping) else None,"secure_channel_healthy":sec.get("healthy") if isinstance(sec,Mapping) else None,"local_administrators":values.get("local_administrators") or []},
      "patching":{"recent_hotfixes":values.get("hotfixes") or []},
      "services":{"winrm":values.get("winrm_service")},
      "roles":values.get("roles") or [],
      "collection_sections":list(evidence)}
    failed=[e for e in evidence if not e.get("success")]
    payload["collection_status"]="collected" if not failed else "collected_with_section_failures"
    payload["failed_section_count"]=len(failed)
    return payload
def build_candidate_networks(collection):
    candidates={};network=collection.get("network") or {}
    for iface in network.get("interfaces",[]) or []:
        if not isinstance(iface,Mapping):continue
        for addr in iface.get("ipv4",[]) or []:
            try:
                ip=ipaddress.ip_address(str(addr.get("address")));prefix=int(addr.get("prefix_length"));net=ipaddress.ip_network(f"{ip}/{prefix}",strict=False)
            except Exception:continue
            if net.version!=4 or net.is_loopback or net.is_link_local or net.is_multicast:continue
            item=candidates.setdefault(str(net),{"network":str(net),"is_private":net.is_private,"authorization_status":"unassessed","auto_scan":False,"sources":[]})
            item["sources"].append({"evidence":"interface_address","interface":iface.get("interface_alias"),"address":str(ip),"prefix_length":prefix})
    for route in network.get("routes",[]) or []:
        prefix=str(route.get("destination_prefix") or "")
        if not prefix or prefix=="0.0.0.0/0":continue
        try:net=ipaddress.ip_network(prefix,strict=False)
        except ValueError:continue
        if net.version!=4 or net.prefixlen==32 or net.is_loopback or net.is_link_local or net.is_multicast:continue
        item=candidates.setdefault(str(net),{"network":str(net),"is_private":net.is_private,"authorization_status":"unassessed","auto_scan":False,"sources":[]})
        item["sources"].append({"evidence":"route_table","interface_index":route.get("interface_index"),"next_hop":route.get("next_hop")})
    result=list(candidates.values());result.sort(key=lambda x:(int(ipaddress.ip_network(x["network"]).network_address),ipaddress.ip_network(x["network"]).prefixlen));return result
def build_context(scheme,device_type,os_family,hostname,vendor,realm,confidence):
    return {"device_type":device_type,"os_family":os_family,"hostname":hostname,"vendor":vendor,"realm":realm,"confidence":confidence,"services":["winrm-https" if scheme=="https" else "winrm-http"]}
def create_session(target,port,scheme,username,password,transport,server_cert_validation):
    if winrm is None:raise RuntimeError("pywinrm is required")
    kwargs={"auth":(username,password),"transport":transport}
    if scheme=="https":kwargs["server_cert_validation"]=server_cert_validation
    return winrm.Session(f"{scheme}://{target}:{port}/wsman",**kwargs)
def attempt_profile(profile_match,target,port,scheme,transport,server_cert_validation,auth_only):
    profile=profile_match.profile;profile_id=str(profile.get("id") or "");username=str(profile.get("username") or "").strip();password_ref=(profile.get("secret_refs") or {}).get("password")
    attempt={"profile_id":profile_id,"protocol":"winrm","username":username or None,"matched_scope":profile_match.matched_scope,"scope_prefix_length":profile_match.prefix_length,"selector_score":profile_match.selector_score,"matched_selectors":list(profile_match.matched_selectors),"transport":transport,"scheme":scheme,"success":False,"failure_category":None,"counts_against_credential_budget":False}
    if str(profile.get("auth_type") or "").lower()!="password":attempt["result"]="unsupported_auth_type";return attempt,None
    if not username or not password_ref:attempt["result"]="profile_incomplete";return attempt,None
    try:password=resolve_secret(str(password_ref),prompt_label=f"WinRM secret for {profile_id}: ")
    except Exception as exc:attempt.update({"result":"secret_resolution_failed","error_type":type(exc).__name__,"error":safe_error(exc)});return attempt,None
    try:
        session=create_session(target,port,scheme,username,password,transport,server_cert_validation)
        probe=run_ps(session,POWERSHELL_AUTH_PROBE)
        if not probe.get("success") or probe.get("stdout")!="P01_WINRM_AUTH_PROBE":
            failure_error=probe.get("error") or probe.get("stderr") or "WinRM auth probe failed"
            failure=classify_attempt_failure(probe.get("error_type"),failure_error,probe.get("status_code"))
            attempt.update({"result":"authentication_or_remote_execution_failed","probe_status_code":probe.get("status_code"),"error":failure_error,"error_type":probe.get("error_type"),**failure});return attempt,None
        attempt.update({"success":True,"result":"authenticated","probe_status_code":probe.get("status_code"),"failure_category":None,"counts_against_credential_budget":False})
        if auth_only:return attempt,{"collection_status":"auth_only","identity":{},"network":{"interfaces":[],"routes":[],"dns":[],"candidate_networks":[],"candidate_network_count":0}}
        values,evidence=collect_sections(session);payload=assemble_collection(values,evidence);candidates=build_candidate_networks(payload);payload["network"]["candidate_networks"]=candidates;payload["network"]["candidate_network_count"]=len(candidates);return attempt,payload
    except Exception as exc:
        err=safe_error(exc);failure=classify_attempt_failure(type(exc).__name__,err,None)
        attempt.update({"result":"authentication_or_connection_failed","error_type":type(exc).__name__,"error":err,**failure});return attempt,None
    finally:password=None
def write_output(output_dir,run_label,payload):
    output_dir.mkdir(parents=True,exist_ok=True);ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ");out=output_dir/f"P01-WinRM-Enrichment_{ts}_{safe_label(run_label)}.json";out.write_text(json.dumps(payload,indent=2,ensure_ascii=False)+"\n",encoding="utf-8");digest=hashlib.sha256(out.read_bytes()).hexdigest();sha=out.with_suffix(out.suffix+".sha256");sha.write_text(f"{digest}  {out.name}\n",encoding="utf-8");return out,sha
def main(argv=None):
    p=argparse.ArgumentParser(description="P01 WinRM Credentialed Enrichment v0.4b.4.2")
    p.add_argument("--profiles",required=True);p.add_argument("--target",required=True);p.add_argument("--scheme",choices=["http","https"],default="http");p.add_argument("--port",type=int);p.add_argument("--transport",choices=["ntlm"],default="ntlm");p.add_argument("--server-cert-validation",choices=["validate","ignore"],default="validate");p.add_argument("--realm");p.add_argument("--hostname");p.add_argument("--vendor");p.add_argument("--device-type",default="Windows Host");p.add_argument("--os-family",default="Windows");p.add_argument("--confidence",default="High");p.add_argument("--max-candidates",type=int,default=1);p.add_argument("--auth-only",action="store_true");p.add_argument("--output-dir",default="./output");p.add_argument("--run-label",default="winrm-enrichment");p.add_argument("--ack-authorized-access",action="store_true");args=p.parse_args(argv)
    if not args.ack_authorized_access:p.error("--ack-authorized-access is required.")
    target=ipaddress.ip_address(args.target);port=args.port if args.port is not None else (5986 if args.scheme=="https" else 5985);validate_scripts()
    try:
        doc=load_profiles(Path(args.profiles));context=build_context(args.scheme,args.device_type,args.os_family,args.hostname,args.vendor,args.realm,args.confidence);matches=match_profiles(doc,str(target),"winrm",args.max_candidates,context=context)
    except (CredentialConfigError,OSError,ValueError) as exc:print(f"Credential profile error: {safe_error(exc)}",file=sys.stderr);return 2
    errors=[];limitations=[{"section":"transport","message":"v0.4b.4.2 validates password authentication using NTLM transport first; Kerberos/certificate/CredSSP are later increments."},{"section":"dynamic_scope","message":"Candidate networks are evidence only and are never automatically scanned by this adapter."}];warnings=[]
    if not matches:warnings.append({"section":"credentials","message":"No eligible WinRM credential profile matched the target context."})
    attempts=[];enrichment=None;selected=None
    for match in matches:
        attempt,collected=attempt_profile(match,str(target),port,args.scheme,args.transport,args.server_cert_validation,args.auth_only);attempts.append(attempt)
        if attempt.get("success"):selected=str(attempt.get("profile_id"));enrichment=collected;break
    auth_success=selected is not None
    if matches and not auth_success:warnings.append({"section":"authentication","message":f"WinRM authentication did not succeed after {len(attempts)} bounded profile attempt(s)."})
    if enrichment and int(enrichment.get("failed_section_count",0))>0:warnings.append({"section":"collection","message":f"{enrichment['failed_section_count']} WinRM collection section(s) failed; successful sections were preserved."})
    status=enrichment.get("collection_status") if enrichment else None;candidate_count=int((enrichment.get("network") or {}).get("candidate_network_count",0)) if enrichment else 0
    payload={"metadata":{"adapter_name":ADAPTER_NAME,"adapter_version":ADAPTER_VERSION,"schema_version":SCHEMA_VERSION,"collected_at_utc":utc_now_iso(),"run_label":args.run_label,"execution_host":socket.gethostname(),"execution_user":os.environ.get("USERNAME") or os.environ.get("USER") or "unknown","read_only_mode":True,"credentialed":True,"authorization_acknowledged":True,"secret_values_persisted_to_output":False,"error_count":len(errors),"limitation_count":len(limitations),"warning_count":len(warnings)},"target":{"ip":str(target),"port":port,"protocol":"winrm","scheme":args.scheme,"transport":args.transport},"context":context,"credential_policy":{"matching_profiles":len(matches),"max_candidates":args.max_candidates,"attempts_made":len(attempts),"selected_profile_id":selected,"stopped_after_success":auth_success,"same_profile_retries":0},"authentication":{"success":auth_success,"attempts":attempts},"enrichment":enrichment,"summary":{"authentication_success":auth_success,"collection_status":status,"candidate_networks_discovered":candidate_count},"errors":errors,"limitations":limitations,"warnings":warnings}
    out,sha=write_output(Path(args.output_dir),args.run_label,payload);print("WinRM credentialed enrichment finalizado.");print(f"Target: {args.scheme}://{target}:{port}/wsman");print(f"Autenticação: {'SUCESSO' if auth_success else 'FALHA'}");print(f"Tentativas: {len(attempts)}");print(f"Collection status: {status}");print(f"Candidate networks: {candidate_count}");print(f"JSON: {out}");print(f"SHA256: {sha}");print(f"Erros: {len(errors)} | Limitações: {len(limitations)} | Avisos: {len(warnings)}");return 0 if auth_success else 3
if __name__=="__main__":raise SystemExit(main())
