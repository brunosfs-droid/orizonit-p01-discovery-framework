# ADR 0009 — Linux/systemd host

Date: 2026-10-01 (-03). Status: Accepted; v0.5f.2 Rocky Linux P01LAB R1 manual lifecycle LAB VALIDATED. Refs Issue #83; follows ADR 0007/0008.

Use a fixed root-installed systemd unit with a dedicated non-login, non-root
`canca-agent` user/group. Pin interpreter/script/config; require root-owned code
and policy ancestors, valid workspace and all grants denied for installation.
No password, provider reference, mTLS parameter, timer or enablement is persisted.
The host component version changes to 0.5f.2; canonical policy wrapper/journals
remain 0.5f.0/schema 0.5f and runtime stays 0.5e.6. Windows host remains unchanged.

Reuse canonical run_once, shared flock, intent and hash-binding gates. At most
one call per start; then idle until SIGTERM/SIGINT. Stop uses KillMode=mixed (initial SIGTERM to main host only), waits
cooperatively with no forced timeout escalation. Crash/restart cannot bypass review_required. No
automatic retry/scheduler/recovery; scheduling/recovery/soak stays v0.5f.3.

Use Restart=no, static unit (no Install targets), NoNewPrivileges, PrivateTmp,
ProtectHome and ProtectSystem=strict. Restrict write allowlist to output/state/log
directories and retained lock. DAC keeps workspace root/config/policy read-only
to the service. Installer does not create users or set ACLs. Lifecycle helper
provisions only its offline fixture and retains the account for evidence ownership.

Reject same-name existing unit, drop-ins, enabled unit, different fragment, account,
recovery or byte contents. Controls require exact owned registration. Start/stop
are non-blocking requests; removal requires inactive/failed and no PID. Preserve
all evidence and account/deployment on removal; reset failed state only for this
removed unit. No manipulation of ingestion/API service or its data.

Validate contracts locally and real native systemd on Ubuntu CI (Python 3.10/3.12).
R1 on P01-LNX-RKY01 separately passed: 4 starts, 2 denials, 2 reviews, idle windows,
refused running removal, stop/restart, independent pre-dispatch intent, idle-host
SIGKILL, no automatic restart, lock reacquisition, 7-journal audit and removal.
CI and Rocky R1 are separate evidence sets. R1 reported Rocky 10.2/Python
3.12.13/systemd 257 and SELinux Enforcing at preflight. Native PASS/exit 0,
retained fixture, systemd journal and seven-file-pair listing were captured; raw
journals were not uploaded. [R1 evidence](validation/LINUX_SERVICE_P01LAB_R1_v0.5f.2.md). No live credentialed stages,
mid-stage cancellation/POST reconciliation or long-duration soak are qualified.

Primary references consulted (systemd source documentation, v252):

- [service stop timeout, Restart and command handling](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml)
- [filesystem namespace, ProtectSystem and ReadWritePaths](https://github.com/systemd/systemd/blob/v252/man/systemd.exec.xml)
- [unit syntax and quoting](https://github.com/systemd/systemd/blob/v252/man/systemd.syntax.xml)

- [SIGTERM/SIGKILL scope for KillMode=mixed](https://github.com/systemd/systemd/blob/v252/man/systemd.kill.xml)
