# Cancã v0.5f.1 — Windows Service host

Date: 2026-10-01. Status: CANDIDATE; Windows Server 2022 P01LAB pending.
Prerequisite: v0.5f.0 Windows P01LAB R1 LAB VALIDATED, 27 captures reviewed;
Linux covered by CI only. Refs Issue #83; [ADR 0008](ADR_0008_Windows_Service_v0.5f.1.md).

Host component v0.5f.1 reuses the v0.5f.0 policy wrapper and v0.5e.6 runtime.
Strict version/workspace/policy config, local paths, no credentials or transport.
SCM name CancaP01Agent, LocalService account/service SID, manual start, no automatic
recovery/scheduling. Installation requires all grants denied; exact registration
ownership checked before controls. One invocation per start then idle. Stop waits
cooperatively for an in-flight invocation. Removal requires stopped state and
preserves evidence. Canonical running intent/review gate survives host restart.

Automated validation: seven new worker/config contracts; full local regression
suite 177 tests passed. Windows/Ubuntu agent CI runs contracts. Windows CI also
installs pywin32 312 and exercises real elevated SCM installation, four manual
starts, idle exclusion, stop/remove refusal while running, controlled pre-dispatch
intent, abrupt idle-host termination, no recovery actions, lock reacquisition,
review_required after restart, journal audit and removal with state preserved.
Confirm native CI success before merging; CI evidence is separate from P01LAB.

Pending real gates: [Windows Service LAB R1](LAB_WINDOWS_SERVICE_v0.5f.1_R1.md).
No claim of service-principal live AUTH/FULL/upload, stop cancellation mid-stage,
automatic scheduling/recovery or soak. Host supplies no mTLS transport; pending
upload remains manual invocation-only. Service account does not inherit the
interactive operator's env/wincred secrets. Use service query for actual SCM
installation state; foundation doctor does not query SCM.

Next: service lifecycle LAB -> v0.5f.2 Linux/systemd -> v0.5f.3 scheduling/recovery/soak.
