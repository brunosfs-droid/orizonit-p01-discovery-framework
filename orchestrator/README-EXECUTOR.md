# P01 Multi-target Credentialed Executor — v0.4b.5

The executor is the runtime bridge between a reviewed Credential Plan and the existing SSH/WinRM adapters.

## Safety model

Default mode is **dry-run**.

Dry-run:
- loads the Credential Plan;
- validates live profiles against the safe profile snapshots embedded in the plan;
- computes hashed credential identity IDs;
- builds deterministic execution order;
- resolves no secret;
- performs no authentication.

Execution requires:
- `--execute`;
- `--ack-authorized-access`;
- the plan sidecar via `--plan-sha256`.

## Runtime rules

- only `adapter_candidate` entries are considered;
- `not_planned` assets are never authenticated;
- profile drift blocks execution until the Planner is rerun;
- only the first planned profile candidate is executed in v0.4b.5;
- concurrency is fixed at 1;
- SSH host key policy defaults to `strict`;
- no pivoting;
- no Dynamic Scope Expansion.

## Shared-credential circuit breaker

Profiles that point to the same secret reference share a hashed `credential_identity_id`.

Only authentication failures consume `failure_budget_per_job`.

Transport failures and remote-execution/unknown failures are recorded but do not poison credential health.

When the budget is reached, later actions using the same credential identity are skipped with `credential_circuit_open`.

The raw secret reference is never written to the job output.

## Dry-run

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Executor.py `
  --plan C:\P01\output\P01-Credential-Plan_<timestamp>_P01LAB-MULTI-R1.json `
  --profiles .\credential_manager\credentials.p01lab.local.json `
  --run-label P01LAB-MULTI-DRY-R1 `
  --output-dir C:\P01\output
```

## AUTH-only execution

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Executor.py `
  --plan C:\P01\output\P01-Credential-Plan_<timestamp>_P01LAB-MULTI-R1.json `
  --plan-sha256 C:\P01\output\P01-Credential-Plan_<timestamp>_P01LAB-MULTI-R1.json.sha256 `
  --profiles .\credential_manager\credentials.p01lab.local.json `
  --execute `
  --auth-only `
  --ack-authorized-access `
  --run-label P01LAB-MULTI-AUTH-R1 `
  --output-dir C:\P01\output
```

Full execution uses the same command without `--auth-only`.
