# ADR 0008 — Windows Service host

Status: Accepted; v0.5f.1 Windows P01LAB R1 manual lifecycle LAB VALIDATED.
Date: 2026-10-01. Refs Issue #83; follows ADR 0007 and Windows v0.5f.0 acceptance.

Use pywin32 312's native SCM dispatcher to launch a pinned Python interpreter,
without a second discovery engine or modifications to foundation journal schema.
The optional host version is v0.5f.1; policy wrapper v0.5f.0 and runtime v0.5e.6
retain their versions. Service registration has a fixed name, LocalService account
and enabled service SID. Manual start only; empty recovery actions and no timers.
Install requires all grants denied, strict local config and valid bound workspace.
No password or credential provisioning is part of installation.

Each SCM start performs at most one canonical run_once and waits idle for stop.
Stop before invocation prevents execution. A stop during an invocation waits for
its completion and reports STOP_PENDING progress; it does not assert cancellation
of network/credential/POST work. Abrupt termination preserves canonical intent and
requires review on restart. Automatic scheduling, recovery policy and soak remain
v0.5f.3; v0.5f.1 qualifies manual lifecycle/restart refusal rather than auto retry.

Config contains only version/workspace/policy paths. Policy remains strict,
default-deny and identity-bound. No transport is persisted or supplied by the host;
pending upload still needs the manual mTLS invocation. LocalService's credential
context is separate from the operator; initial native LAB does not authorize or
qualify service-principal live AUTH/FULL/upload. These need explicit provisioning
and additional evidence before unattended use.

Management verifies exact installed command/account/start/recovery/SID before
start/stop/remove. It rejects a same-name unrelated registration. Removal requires
stopped state and preserves workspace/journals. The LAB helper creates an isolated
workspace, grants the service SID only the required paths, exercises lifecycle and
intent preservation, removes its service, and retains evidence when --lab-root is
set. Production installer does not modify ACLs automatically.

Validation: portable unit contracts on Windows/Linux plus real elevated Windows
SCM CI using all-denied fixtures. P01-MGMT01 lifecycle acceptance is recorded in
[Windows Service R1 evidence](validation/WINDOWS_SERVICE_P01LAB_R1_v0.5f.1.md):
4 starts, 2 denials/2 reviews, preserved state/intent, no idle retry/recovery,
lock reacquired, service removed and 7/7 audited journals. Raw journals were not
uploaded; capture bottom is cropped. Live credentials/cancellation remain unqualified.

Primary implementation references:

- [pywin32 ServiceFramework](https://github.com/mhammond/pywin32/blob/b312/win32/Lib/win32serviceutil.py)
- [pywin32 SCM bindings](https://github.com/mhammond/pywin32/blob/b312/win32/src/win32service.i)
- [Microsoft LocalService account](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
