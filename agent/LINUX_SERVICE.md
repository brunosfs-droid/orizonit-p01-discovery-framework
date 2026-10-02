# Linux/systemd host v0.5f.2

Optional manual host for agent v0.5f.0 / runtime v0.5e.6. Python 3.10+ on a
Linux host whose PID 1 is systemd. No additional Python dependency.
Name: `canca-p01-agent.service`; dedicated unprivileged user/group `canca-agent`.
No timer, enablement, retry, inbound API or stored transport/credentials.

Commands: `doctor`, `query`, `install`, `start`, `stop`, `remove`, `host`.
Default config `/etc/canca/linux-service.json` has exactly:

```json
{"schema_version":"0.5f.2","workspace":"/var/lib/canca/runs/ASSESSMENT/RUN","policy":"/var/lib/canca/runs/ASSESSMENT/RUN/config/agent-policy.json"}
```

Absolute local paths only; policy must resolve inside workspace. Duplicate/extra
keys, control characters and systemd variable/specifier expansion are rejected.
Policy remains schema v0.5f and identity-bound. No secret provisioning is implied.
Install requires all stage grants denied and an initialized valid workspace.

Provision the non-login user/group explicitly; installer validates nonzero UID/GID,
matching primary group and absence of supplementary groups. It creates no users
and changes no workspace ACLs/ownership. Code/core/config/policy/workspace parent
must be root-owned without group/other write, including ancestors. Account needs
read/traverse on deployment, interpreter, config and policy. Make output/state/log
directories and retained `.canca-workspace.lock` writable only to that UID.
Keep the workspace parent and config directory root-owned/non-writable so the
service cannot replace config/policy. Store deployment and workspace outside
`/root`, `/home`, `/tmp`; e.g. `/opt/canca` and `/var/lib/canca`.

Install pins the current absolute interpreter, script and config in a root-owned
unit at `/etc/systemd/system/canca-p01-agent.service`. Unit has `Restart=no`, no
`[Install]` targets, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`,
`ProtectSystem=strict`, `UMask=0077`. Only runtime output/state/log directories
and lock are allowlisted for writes. This is defense in depth together with DAC;
it is not a claim of complete isolation for privileged operators or live stages.

Each start calls canonical `run_once` at most once, then stays idle until SIGTERM
or SIGINT. Result written to journal stdout includes only fixed status/stage/error
codes. Full audit evidence remains the canonical JSON/SHA256 journals. Policy deny
or review does not make the idle host inactive: inspect agent journals separately.
Stop is cooperative and waits for an in-flight invocation. KillMode=mixed sends
the initial stop signal only to the main host, so it can wait for its call. `TimeoutStopSec=infinity`
prevents systemd timeout escalation; a hung stage can therefore leave stop pending
until operator review. There is no promise of cancellation inside AUTH/FULL/POST.
Abrupt kill preserves running intent; next manual start requires review, no replay.

Management verifies exact unit bytes/fragment, absence of drop-ins, static
enablement state, user/group and `Restart=no` before acting. It refuses foreign,
overridden or enabled units. Root is required for install/start/stop/remove.
Install uses exclusive file creation and never overwrites an existing unit.
Start/stop submit non-blocking systemd requests; query actual state before the
next command. Remove requires inactive/failed state and MainPID=0, reloads manager
and preserves workspace, journals, deployment and the dedicated account.

```bash
/usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py doctor --config /etc/canca/linux-service.json
sudo /usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py install --config /etc/canca/linux-service.json
sudo /usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py start --config /etc/canca/linux-service.json
/usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py query --config /etc/canca/linux-service.json
sudo /usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py stop --config /etc/canca/linux-service.json
# Wait until inactive/failed with MainPID 0, then:
sudo /usr/bin/python3 /opt/canca/agent/P01_Linux_Service.py remove --config /etc/canca/linux-service.json
```

Do not `systemctl enable`, attach a timer, override recovery or delete running
intent to bypass review. Host supplies no mTLS transport; pending upload remains
manual invocation-only. Linux unattended policy still rejects prompt/wincred and
requires explicit env provisioning for any separately authorized live credential
stage. R1 qualifies only an isolated offline lifecycle fixture.

Validation: ten Linux contracts, a real subprocess SIGTERM check, full regression,
and native systemd CI on Ubuntu/Python 3.10 and 3.12. Rocky LAB is a separate gate:
[R1 operator guide](../docs/LAB_LINUX_SERVICE_v0.5f.2_R1.md).
