# Cancã v0.5f.2 — Linux/systemd host

Date: 2026-10-01 (-03). Status: CANDIDATE; Rocky Linux P01LAB R1 pending.
Prerequisite: v0.5f.0 Windows foundation and v0.5f.1 Windows SCM lifecycle accepted.
Refs Issue #83; [ADR 0009](ADR_0009_Linux_Service_v0.5f.2.md).

Manual static systemd unit, dedicated non-root account, pinned root-owned
deployment/config, no recovery/timer. One canonical agent invocation per start,
then idle. Cooperative SIGTERM/SIGINT stop; preserved intent prevents replay.
No persisted transport/credentials. Exact registration/drop-in/enablement checks
before controls; removal preserves journals/workspace/account. Python 3.10+;
agent v0.5f.0 and runtime v0.5e.6 stay unchanged.

Local validation: 187 tests (177 baseline + 10 Linux contracts), including a real
host subprocess stopped with SIGTERM. Native systemd CI is required before merge
on Ubuntu/Python 3.10 and 3.12; Windows SCM 3.12/3.13 remains in CI. Real native smoke
uses a separate all-denied fixture and verifies 4 starts, 2 denials/2 reviews,
idle windows, stop/restart, refusal to remove running host, pre-dispatch intent,
idle-host SIGKILL, no automatic restart, reacquired lock, 7 journals and removal.

[Rocky LAB R1](LAB_LINUX_SERVICE_v0.5f.2_R1.md) is the next operator gate; Ubuntu
CI does not qualify the actual Rocky version or SELinux context. Native helper
retains fixture and JSON/SHA256 proof with --lab-root. It stages only the offline
core; does not provision a live discovery node or modify the ingestion server.
No live service-account AUTH/FULL/upload, mid-stage cancellation, automatic
scheduling/recovery or soak acceptance. Next: v0.5f.3 after Linux lifecycle LAB.
