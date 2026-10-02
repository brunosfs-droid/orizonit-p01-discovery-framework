# Cancã v0.5f.2 — Linux/systemd host

Date: 2026-10-01 (-03). Status: LAB VALIDATED for Rocky Linux P01LAB R1 manual lifecycle.
Prerequisite: v0.5f.0 Windows foundation and v0.5f.1 Windows SCM lifecycle accepted.
Refs Issue #83; [ADR 0009](ADR_0009_Linux_Service_v0.5f.2.md).

Manual static systemd unit, dedicated non-root account, pinned root-owned
deployment/config, no recovery/timer. One canonical agent invocation per start,
then idle. Cooperative SIGTERM/SIGINT stop; preserved intent prevents replay.
No persisted transport/credentials. Exact registration/drop-in/enablement checks
before controls; removal preserves journals/workspace/account. Python 3.10+;
agent v0.5f.0 and runtime v0.5e.6 stay unchanged.

Local validation: 187 tests (177 baseline + 10 Linux contracts), including a real
host subprocess stopped with SIGTERM. PR #91 native systemd CI passed on Ubuntu/Python 3.10 and 3.12;
Windows SCM 3.12/3.13 also passed. Real native smoke
uses a separate all-denied fixture and verifies 4 starts, 2 denials/2 reviews,
idle windows, stop/restart, refusal to remove running host, pre-dispatch intent,
idle-host SIGKILL, no automatic restart, reacquired lock, 7 journals and removal.

[Rocky LAB R1](LAB_LINUX_SERVICE_v0.5f.2_R1.md) passed on P01-LNX-RKY01:
Rocky 10.2, Python 3.12.13, systemd 257, SELinux Enforcing shown in preflight.
Native PASS/exit 0, 4 starts, 2 denials/2 reviews, preserved state/intent, released
lock, removed unit, 7/7 journals hash/content-valid and retained fixture.
Systemd journal and file listing corroborate the reported result; raw proof and
journal bytes were not uploaded. [Acceptance](validation/LINUX_SERVICE_P01LAB_R1_v0.5f.2.md).
Fixture: /var/lib/canca/service-lab/P01-SYSTEMD-R1-ff8b130868c1.
The absent unit after PASS is expected removal. Literal cleanup placeholder errors
were corrected by the operator and the guide now prompts for the actual path.
This isolated offline core fixture is not a full live discovery-node deployment.
No live service-account AUTH/FULL/upload, mid-stage cancellation, automatic
scheduling/recovery or soak acceptance. Next: planned v0.5f.3 scheduling/restart/recovery hardening and soak.
