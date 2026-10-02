# Cancã — Linux/systemd v0.5f.2 / P01LAB R1 acceptance

Status: LAB VALIDATED for manual service lifecycle and preserved review gate.
Operator date: 2026-10-01 (-03); attached filenames use 2026-10-02.
Node: P01-LNX-RKY01 (192.168.100.50). Refs Issue #83; ADR 0009.
Tested source: main `e83930b2c2f850b008232e4c28b2d0dad7d4c56a` (PR #91).

Seven attached captures reviewed. The Windows capture shows main fast-forward
to PR #91, git archive of tracked agent/runtime/tests/docs and completed SCP.
Linux archive listing shows the expected host/helper and documentation. This is
an operator/code correlation, not a separately supplied deployment hash inventory.

Environment shown: Rocky Linux 10.2 (Red Quartz), Python 3.12.13 at
/usr/bin/python3, systemd 257, PID 1 systemd; getenforce reports Enforcing in the
preflight capture. Python version guard passed. No package installation was
needed in this observed environment. The R1 fixture does not qualify every
SELinux policy/label or a different Rocky installation.

The actual command uses --lab-root /var/lib/canca/service-lab and node
P01-LNX-RKY01. Full visible result and captured shell exit:

| Field | Observed value |
| --- | --- |
| status / service_version | LINUX SYSTEMD SMOKE PASS / 0.5f.2 |
| shell Exit LAB | 0 |
| starts / one_invocation_per_start | 4 / true |
| policy_denied_starts / review_required_starts | 2 / 2 |
| idle_repeat / automatic_recovery_enabled | false / false |
| source_state_unchanged / intent_preserved | true / true |
| lock_reacquired / service_removed | true / true |
| journal_audit | JOURNAL AUDIT PASS; 7 journals |
| sha256_valid / contract_fields_valid | true / true |
| evidence_retained | true |
| fixture_directory | /var/lib/canca/service-lab/P01-SYSTEMD-R1-ff8b130868c1 |

The independent journalctl capture corroborates the four host starts:
PIDs 3602 and 3624 returned policy_denied/discovery; PID 3645 returned
review_required, then exited with status=9/KILL; PID 3665 returned
review_required after the next manual start, then stopped normally. Journal
timestamps are shown as Oct 1 23:03:31–23:03:38; retain the displayed host time
without asserting synchronized cross-host durations. No automatic replay is
shown. The helper creates intent with a separate pre-dispatch child process;
the systemd-host SIGKILL occurs while idle.

After PASS, systemctl status reports the unit could not be found: expected,
because service_removed=true and the helper uninstalled its test-owned unit.
Historical journalctl records and the retained fixture remain accessible.
Fixture listing separately shows service.json, staged deployment, proof JSON +
SHA256, workspace state/config sidecars and seven journal JSON/sidecar pairs.
Raw proof/journal bytes were not uploaded; hash/content validity is the native
helper's reported audit, corroborated by the listing rather than a second byte
verification performed here.

The later errors do not invalidate PASS. The copied line containing literal
<identificador> caused a Bash syntax error and left Fixture unset; subsequent
commands therefore tried /deployment/... and failed to find the script. The
operator then assigned the exact printed fixture path and successfully listed
the preserved files. The guide now prompts for the printed path and separates
post-PASS inspection from cleanup needed only if a test fails with a unit left
installed. No reinstall/stop/remove is needed after this successful run.

| Capture filename | Evidence |
| --- | --- |
| image(20261002-020152).png | OS/Python/systemd/PID 1/SELinux and version guard |
| image(20261002-020202).png | Windows git pull, tracked archive, completed SCP |
| image(20261002-020222).png | SSH destination, received archive and file listing |
| image(20261002-020353).png | Native PASS, complete fixture metadata, captured exit 0 |
| image(20261002-020555).png | PASS, absent removed unit, independent systemd journal |
| image(20261002-021107).png | Placeholder failure, corrected path, proof/journal listing |
| image(20261002-021119).png | Corroborating journal, placeholder error and corrected path |

Original captures and per-image SHA256 are retained in the separate Linux R1
archive. Windows v0.5f.0/v0.5f.1 evidence archives are unchanged. Multiple views
of the same fixture are not counted as independent smoke runs.

Acceptance limits: all-denied offline lifecycle fixture and manual review gate;
no live service-account discovery/AUTH/FULL/upload, mid-stage cancellation/POST
reconciliation, automatic scheduling/recovery or long-duration soak. No new
ingestion-server/POST observation is claimed from these seven images. Preserve
the running intent; do not delete it to authorize replay. Next gate: planned
v0.5f.3 scheduling/restart/recovery hardening and bounded soak.
