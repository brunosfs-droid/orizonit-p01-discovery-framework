# Cancã v0.5f.1 — Windows Service host

Date: 2026-10-01. Status: LAB VALIDATED for Windows Server 2022 P01LAB R1 manual lifecycle.
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
PR #90 CI passed, including real SCM on Python 3.12 and 3.13. CI evidence is separate from P01LAB.

Real P01-MGMT01 capture 20261002-002654 confirms WINDOWS SCM SMOKE PASS:
4 starts, 2 policy_denied/2 review_required, no idle repeat/recovery, state and
intent preserved, lock reacquired, service removed and 7/7 journal hashes/content
valid. [Acceptance record](validation/WINDOWS_SERVICE_P01LAB_R1_v0.5f.1.md).
The capture is cropped before fixture metadata/exit; raw journals were not uploaded.
No claim of service-principal live AUTH/FULL/upload, stop cancellation mid-stage,
automatic scheduling/recovery or soak. Host supplies no mTLS transport; pending
upload remains manual invocation-only. Service account does not inherit the
interactive operator's env/wincred secrets. Use service query for actual SCM
installation state; foundation doctor does not query SCM.

Next: v0.5f.2 Linux/systemd candidate and Rocky lifecycle LAB -> v0.5f.3 scheduling/recovery/soak.
