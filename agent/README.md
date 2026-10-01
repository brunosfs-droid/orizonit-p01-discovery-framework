# Cancã Optional Agent v0.5f.0

Optional policy wrapper around `runtime/P01_Discovery_Node.py` v0.5e.6.
One `run-once` advances at most one stage. No OS service or scheduler is installed.

```powershell
python agent/P01_Agent.py validate-policy --policy agent/agent-policy.example.json
python agent/P01_Agent.py doctor --workspace <existing-workspace> --policy <policy.json>
python agent/P01_Agent.py status --workspace <existing-workspace> --policy <policy.json>
python agent/P01_Agent.py run-once --workspace <existing-workspace> --policy <policy.json>
```

Initialize the workspace with the portable runtime first. Copy the example policy
and set its exact assessment/run/node identity. Missing grants are false; explicit
grants are independent for `discovery`, `planning`, `dry_run`, `auth_only`, `full`,
`resolver`, `export`, `upload`. Discovery additionally requires IPv4 targets, still
constrained by the runtime's Assessment Manifest. Fixed safe scan profile, SSDP
disabled, max_hosts <= 2048 and max_actions <= 250. No force/retry flags are exposed.
SSH uses strict host keys. Unattended credentials require the existing `env://`
or `wincred://` provider and an identity which can resolve them; a prompt provider
in any configured profile blocks AUTH/FULL conservatively.

Upload is granted separately and requires `--server-url`, `--ca-cert`,
`--client-cert`, `--client-key` on that invocation. No paths or transport options
are written to agent policy/journal. Certificate/private-key provisioning is
external. A completed run needs only workspace + valid matching policy and
returns `already_complete`; no completed stage or upload is replayed.

`schedule: {"kind":"interval","interval_seconds":300}` is optional metadata
only. It never starts a loop or registers a task/service in v0.5f.0.

Policy denies, failures and interrupted checkpoints remain visible and fail
closed. After a failure, review the preserved evidence and recover through the
explicit portable workflow. A policy digest is a change record, not a signature.
Protect policy, referenced manifest/profiles, known_hosts and workspace with OS
permissions. Use a local filesystem for workspace locking; network filesystem
lock guarantees have not been qualified.

The shared `.canca-workspace.lock` blocks concurrent agent and portable mutations.
It is intentionally retained; kernel ownership is released when the process
exits. Do not delete or replace it while another process can use the workspace.
Journal JSON/SHA256 lives in `logs/agent/<invocation_id>.json`; a `running` entry
survives interrupted dispatch. An unfinished `running` journal also blocks unattended progression until operator
review, including a POST interrupted before its runtime checkpoint. Preserve the
journal; verify runtime artifacts and server receipt/idempotency status, recover
with the explicit portable workflow, then archive the reviewed intent outside
`logs/agent`. Never simply delete intent and retry a live stage. State checkpoints
remain the runtime's source of truth. Journal retention/rotation is pending v0.5f.3, so monitor disk usage.

Exit codes: 0 successful check/advance/complete, 2 invalid input/integrity/runtime
failure or workspace busy, 3 policy stop or operator review required. A `doctor`
may be ready while its next live stage is denied; readiness is not authorization.

Real LAB procedure: [LAB_OPTIONAL_AGENT_v0.5f.0_R1.md](../docs/LAB_OPTIONAL_AGENT_v0.5f.0_R1.md).
Architecture decision: [ADR 0007](../docs/ADR_0007_Optional_Agent_v0.5f.md).

Next increments: v0.5f.1 Windows Service; v0.5f.2 Linux/systemd; v0.5f.3 scheduling,
restart/recovery and soak. LAB acceptance of this foundation precedes installation.
