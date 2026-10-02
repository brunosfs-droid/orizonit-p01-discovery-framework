# Cancã Windows Service v0.5f.1

Current host code is v0.5f.3 CANDIDATE: [explicit scheduler](SCHEDULER.md).
The guide below describes the legacy manual configuration, still accepted by the
new host. Scheduling remains disabled with that schema. Historical LAB acceptance
belongs to the earlier component/commit; v0.5f.3 R1 is pending. Remove installed old
hosts with their original deployment/config before upgrading the pinned command.

Status: CANDIDATE. Host component v0.5f.1; policy wrapper/journals v0.5f.0;
canonical runtime v0.5e.6. Windows foundation R1 acceptance is complete.

Install dependency in the interpreter used by the service:

```powershell
python -m pip install -r agent/requirements-windows-service.txt
```

Config has exactly three fields, no transport, credentials or provider locators:

```json
{
  "schema_version": "0.5f.1",
  "workspace": "C:\\Canca\\runs\\ASSESSMENT\\RUN",
  "policy": "C:\\Canca\\runs\\ASSESSMENT\\RUN\\config\\agent-policy.json"
}
```

Use absolute local paths. Policy must reside inside the workspace. Protect config,
policy and deployment against edits by unauthorized principals. Grant the service
SID read/execute on deployment, Python/venv and config; modify on workspace
state/logs/evidence/output directories and the retained lock file. Keep the policy
directory read-only to the service. Provision manifest/profile/known_hosts access
separately before future live stages. No password/key is accepted by this host.

Service name is `CancaP01Agent`, account `NT AUTHORITY\LocalService`, service SID
`NT SERVICE\CancaP01Agent`. Installation uses manual/demand start and explicitly
empty SCM recovery actions. Install requires all policy grants denied and a valid
workspace. It does not start the service, widen ACLs or change the workspace.
Existing services are never overwritten. Management operations verify the exact
installed interpreter/script/config command and expected account/start/recovery/SID.
Code/interpreter/config moves require stop/remove with the original deployment
before reinstalling; an unrelated service with the same name is preserved.

```powershell
$ServiceConfig = "C:\ProgramData\Canca\windows-service.json"
python agent/P01_Windows_Service.py doctor --config $ServiceConfig
python agent/P01_Windows_Service.py install --config $ServiceConfig
# Grant the service SID the required ACLs after installation, before start.
python agent/P01_Windows_Service.py start --config $ServiceConfig
python agent/P01_Windows_Service.py query --config $ServiceConfig
python agent/P01_Windows_Service.py stop --config $ServiceConfig
# Wait until query reports stopped before removal.
python agent/P01_Windows_Service.py remove --config $ServiceConfig
```

The SCM launches the pinned interpreter directly with `host --config`, using
pywin32's native dispatcher. Each manual start invokes canonical `agent.run_once`
once, then remains idle until stop. No schedule/timer/retry is installed;
`policy.schedule` remains metadata. Policy is reread under the agent's existing
decision flow. A stop before invocation prevents it; stop during an invocation
requests STOP_PENDING and waits for that invocation, reporting progress. This does
not cancel a live SSH/WinRM/POST operation in flight. Killing the host preserves
running intent and the existing review gate; kernel ownership releases the lock.
An operator must review an interrupted live stage before any portable recovery.

No invocation transport parameters are supplied by the service. Upload remains
a manual invocation-only mTLS operation. Do not expect grants alone to provision
credentials: LocalService has a different credential/session context from the
interactive operator. First service LAB uses all grants denied and isolated
fixtures; service-principal live AUTH/FULL/upload qualification is not claimed.

Invocation evidence remains `logs/agent/*.json` + SHA256, without service fields
or a changed journal schema. Fixed host start/result/stop messages go to Windows
Application Event Log. Raw exceptions, paths, results and transports are excluded
from invocation messages. `running` SCM means the host is alive; it can be idle
after policy denial, operator review or a fixed failure. Inspect agent status,
journals and Event Log to see the invocation result. Remove preserves evidence.

Exit codes: 0 management request/check accepted, 2 configuration/platform/dependency/
SCM failure. A start/stop return is a request; query SCM to verify the resulting
state. Stop/remove and installation require an elevated administrator.

Native LAB helper installs only a new test-owned service, exercises four starts,
two stops/restarts, abrupt termination of the idle host, lock reacquisition and
review gating, then removes the service while retaining fixtures:
[LAB R1](../docs/LAB_WINDOWS_SERVICE_v0.5f.1_R1.md).
