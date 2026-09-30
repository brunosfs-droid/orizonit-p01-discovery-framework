# P01 LAB — Multi-target Executor v0.4b.5
## Stage 1: Dry-run only

Do not run `--execute` in the first round.

### 1. Normalize shared domain identity

If P01-DC01 and P01-W11-01 intentionally use the same domain discovery account, both profiles should point to the same secret reference, for example:

```text
wincred://ORIZONIT/P01/p01lab-domain-winrm
```

If they intentionally use different accounts, keep separate secret references.

### 2. Remove placeholders

Ensure there are no placeholder usernames such as `SEU_USUARIO`, `CHANGEME` or `REPLACE_ME`.

Run:

```powershell
python .\credential_manager\P01_Credential_Manager.py validate `
  --profiles .\credential_manager\credentials.p01lab.local.json
```

### 3. Regenerate the Credential Plan

Any profile change after plan generation is intentionally detected as `profile_drift_since_plan_generation`.

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Planner.py `
  --discovery C:\P01\output\P01-Network-Discovery_20260930T110940Z_P01LAB-NODE-W11-WINRM-R2.json `
  --profiles .\credential_manager\credentials.p01lab.local.json `
  --realm-map C:\P01\realm-map-w11.json `
  --max-candidates 2 `
  --run-label P01LAB-MULTI-R1 `
  --output-dir C:\P01\output
```

### 4. Execute dry-run

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Executor.py `
  --plan C:\P01\output\P01-Credential-Plan_<timestamp>_P01LAB-MULTI-R1.json `
  --profiles .\credential_manager\credentials.p01lab.local.json `
  --run-label P01LAB-MULTI-DRY-R1 `
  --output-dir C:\P01\output
```

Expected:
- execution mode `dry_run`;
- 5 actions ready;
- 0 secret resolution;
- 0 authentication attempts;
- 0 completed runtime actions;
- deterministic order;
- no profile drift;
- DC01 and W11 share the same `credential_identity_id` only if their profiles point at the same secret reference.

### 5. Evidence

Send:
- regenerated Planner JSON + SHA256;
- Executor dry-run JSON + SHA256.

Do not run multi-target AUTH until the dry-run is reviewed.
