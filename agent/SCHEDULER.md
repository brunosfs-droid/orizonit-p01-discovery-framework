# Explicit bounded scheduler v0.5f.3

CANDIDATE. Both service hosts now use v0.5f.3; agent/runtime remain v0.5f.0/v0.5e.6.
Manual start and empty OS recovery remain mandatory. No timer, autostart or transport
provisioning is installed. Historical Windows v0.5f.1 and Linux v0.5f.2 LAB acceptances
cover their manual lifecycle, not this new scheduler.

Install with all grants denied and scheduling disabled. After installation and OS
permissions, an operator can enable the following config while the service is stopped:

```json
{
  "schema_version": "0.5f.3",
  "workspace": "/var/lib/canca/runs/ASSESSMENT/RUN",
  "policy": "/var/lib/canca/runs/ASSESSMENT/RUN/config/agent-policy.json",
  "scheduler": {"enabled": false, "max_invocations": 2}
}
```

Windows uses absolute local Windows paths with JSON escaping. Config accepts only
these keys. `enabled` is a bool; `max_invocations` is an integer from 1 through 10000.
Omitting scheduler defaults to disabled. Three-key legacy configs (`0.5f.1` Windows,
`0.5f.2` Linux) remain manual-only. The policy must separately contain a validated
`schedule: {"kind":"interval","interval_seconds":60}`; interval is 60..86400 seconds.
A schedule descriptor alone does not enable scheduling or grant any stage.

One manual service start creates one session. The first tick is immediate; subsequent
ticks wait the full policy interval **after completion**, using a monotonic Event wait.
Each tick reloads config/policy, validates identity/integrity and invokes canonical
`run_once` under the shared reentrant workspace lock. No overlap, catch-up, missed-tick
replay or automatic retry. `advanced` and `policy_denied` consume the bounded attempt
budget; denial performs no stage dispatch. `already_complete` ends the cycle.
`review_required`, an error, changed workspace/policy path or changed attempt budget
halts it. Stop interrupts an idle wait; an invocation already running completes
cooperatively. Stop does not cancel SSH/WinRM/POST in flight. Disabling scheduling
ends the cycle on its next check; it does not trigger a manual invocation.

At completion/stop/halt the host stays idle until the operator stops it. A new manual
start can create another bounded session only after the previous one ended safely.
The OS never restarts the host automatically. Linux still uses a dedicated account,
root-owned pinned deployment/config, static unit, strict sandbox and retained lock;
Windows still uses LocalService and the dedicated service SID.

`logs/scheduler/<session UUID>.json` and SHA256 sidecar record the initial intent
before a tick, attempt count, config digest, identity, sanitized result and final
reason. Canonical `logs/agent` records remain schema v0.5f. A running scheduler
intent or halted scheduler session blocks subsequent service invocation, including
manual mode after disabling scheduling. Hash/field/identity failures also fail closed.
Raw errors, transport options, credentials and provider locators are never persisted.
SHA256 proves integrity relative to protected files, not authenticity against a
principal able to rewrite both JSON and its digest.

Recovery requires operator review: preserve and audit both journal families, verify
runtime checkpoints/artifacts and external side effects, reconcile using the explicit
portable workflow where appropriate, document the outcome, and archive **all reviewed
blocking scheduler records with their sidecars** outside `logs/scheduler`. Reconcile
canonical running intents as well. No recovery/clear/force command is supplied; never
clear an intent simply to restart. A fresh isolated LAB fixture can test again without
altering retained review evidence.

No service transport is supplied. An upload grant without invocation-only mTLS
parameters halts with `transport_required`; live service AUTH/FULL/upload remain
unqualified. Bounded sessions do not rotate journals: monitor disk usage and preserve
review records. Automated retention is deferred until its own reviewed contract.

Validation: scheduler unit contracts include 200 accelerated denied ticks, policy
reread, stop/revocation, redaction, interrupted intent and manual-mode bypass gates.
`tests/scheduled_agent_soak.py` is the native SCM/systemd R1: two real ticks 60 seconds
apart, policy reread, bounded idle, termination during the next session's wait, and
restart blocked before canonical invocation. Default R1 is a short soak. `--ticks 10`
extends the initial cycle to at least nine minutes; neither establishes multi-day
reliability. Full CI also retains the manual SCM/systemd lifecycle smoke.

[LAB guide](../docs/LAB_SCHEDULER_v0.5f.3_R1.md) ·
[status](../docs/STATUS_SCHEDULER_v0.5f.3.md) ·
[ADR 0010](../docs/ADR_0010_Scheduler_v0.5f.3.md)
