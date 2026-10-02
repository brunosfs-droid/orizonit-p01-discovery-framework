# Cancã — LAB Windows Service v0.5f.1 / P01LAB R1

Date: 01/10/2026. Status: LAB VALIDATED for the manual lifecycle described below. Foundation v0.5f.0 validated on Windows R1.
Host v0.5f.1 / agent wrapper v0.5f.0 / runtime v0.5e.6.

First gate: real Windows Server 2022 SCM lifecycle, isolated all-denied workspace,
canonical journals, stop/restart, abrupt idle-host exit and preserved review intent.
Do not use the completed P01LAB-AGENT-R1 or the existing tamper/interruption runs.

Run in the Administrator Windows PowerShell window on P01-MGMT01. The helper
installs `CancaP01Agent` under LocalService with its service SID, manual start and
no recovery actions. It refuses if a service with that name already exists.
It creates an independent fixture under the selected LAB directory; references
to manifest/profiles and transport are absent. There is no discovery/AUTH/POST.

It grants the service SID read/execute on repository/interpreter and the fixture,
modify on runtime output/state/log directories and lock file. Config/policy stay
read-only to this SID. It changes no other service or completed run. SID ACL entries
on deployment/interpreter remain after removing the test service; review/remove
those explicit entries if discarding this host deployment. Do not grant Everyone
or broad LocalService write access to policy/PKI. Administration is necessary for
SCM installation/removal and SID ACLs.

```powershell
Set-Location "C:\GitHub\orizonit-p01-discovery-framework"
. .\.venv\Scripts\Activate.ps1
git pull origin main
python -m pip install -r agent/requirements-windows-service.txt
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar a dependência do serviço." }
python tests/windows_service_scm_smoke.py `
    --lab-root "C:\Canca\service-lab" --node-id "P01-MGMT01"
"Exit LAB: $LASTEXITCODE"
```

Expected: WINDOWS SCM SMOKE PASS / exit 0; starts=4, exactly one invocation per
start; two policy_denied and two review_required; idle_repeat=false;
automatic_recovery_enabled=false; source_state_unchanged=true;
intent_preserved=true; lock_reacquired=true; service_removed=true;
journal_audit PASS and evidence_retained=true.

Sequence: install; first policy-denied start; refuse removal while running; stop;
second policy-denied start; stop; controlled pre-dispatch exit creates a running
intent; third start returns review_required; terminate only this test-owned idle
service process; verify stopped/no automatic restart and released lock; fourth
manual start returns review_required; stop; audit and remove service.

The abrupt SCM-host exit is tested while idle; pre-dispatch interruption is a
separate child proof. Neither claims cancellation/recovery inside AUTH/FULL or
after POST. An interval descriptor in the fixture remains metadata, with no
automatically repeated invocation in the observed idle window.

The helper prints fixture_directory and saves `windows-service-proof.json` +
SHA256 there. Canonical journals/sidecars, policy backup and the running intent
remain in `runs\P01CI\P01LAB-AGENT-NEG-SERVICE`. Preserve this fixture for review;
do not remove the intent to run another stage. A fresh helper execution creates
another independent fixture. No service remains installed after a successful run.

On failure preserve the output and fixture; do not widen policy grants. If SCM
reports STOP_PENDING, wait for the invocation and query it; avoid killing any
process outside the helper's own registered PID. The helper attempts stop/remove
in finally. If cleanup fails, use the printed/retained fixture's `service.json`
with the same interpreter/deployment:

```powershell
$ServiceConfig = "<fixture_directory>\service.json"
python agent/P01_Windows_Service.py query --config $ServiceConfig
python agent/P01_Windows_Service.py stop --config $ServiceConfig
# After query shows stopped:
python agent/P01_Windows_Service.py remove --config $ServiceConfig
```

Send a capture of the PASS summary, the actual service account/start/recovery
state while installed if available, and fixed failure output if not passing.
Do not share environment values, credential profiles or PKI. Acceptance is for
service lifecycle and review gating only; service-principal live access and
scheduling/soak require later gates.

## R1 acceptance

P01-MGMT01 capture `image(20261002-002654).png` confirms WINDOWS SCM SMOKE PASS,
4 starts, 2 denials/2 reviews, unchanged state, preserved intent, released lock,
removed service and 7/7 hash/content-valid journals.
[Evidence and limits](validation/WINDOWS_SERVICE_P01LAB_R1_v0.5f.1.md).
Final shell exit and fixture metadata are cropped; do not infer captured values.
Next operator gate: [Linux/systemd R1](LAB_LINUX_SERVICE_v0.5f.2_R1.md).
