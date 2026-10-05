# Orchestrator

The orchestrator is the central execution/planning layer of the P01 Discovery Framework.

## SNMP extension v0.4b.8

Explicit UDP endpoints from existing discovery seeds can be planned with
`--snmp-requests`. Executor v0.4b.8 requires `--enable-snmp` in addition to its
execute acknowledgement and reviewed plan SHA256. Profile/context/authorization
bindings precede secrets; unconfirmed reads suspend shared SNMP credentials.
Default portable behavior stays unchanged and needs no Cancã login.
See the [contract and CLI guide](../docs/SNMP_PLANNED_EXECUTION_v0.4b.8.md).
Resolver/bundle/managed SNMP integration remains pending; no manual LAB action.

## v0.4b.3 — Credentialed Discovery Planner

The first implemented orchestration component is:

`P01_Credentialed_Discovery_Planner.py`

It consumes:

- Network Discovery JSON;
- Credential Profile metadata;
- optional realm map.

It produces a **non-secret execution plan**. It never resolves secret values and never authenticates by itself.

The planner maps discovered services to available protocol adapters and asks the Context-aware Credential Resolver which profiles are eligible for each asset.

### Example

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Planner.py `
  --discovery C:\P01\output\P01-Network-Discovery_<timestamp>_P01LAB-NODE-R1.json `
  --profiles .\credential_manager\credentials.p01lab.local.json `
  --max-candidates 2 `
  --run-label P01LAB-CREDPLAN-R1 `
  --output-dir C:\P01\output
```

Optional realm context:

```json
{
  "192.168.100.10": "P01LAB",
  "192.168.100.20": "P01LAB"
}
```

Then pass it with:

```powershell
--realm-map .\orchestrator\realm-map.local.json
```

Local realm maps belong in `.gitignore` and should not contain secrets.

## Responsibilities

- consume discovered asset context;
- map detected services to protocol adapters;
- select eligible credential profiles through protocol + scope + selectors;
- preserve profile priority and scope specificity;
- expose why a profile matched;
- produce an auditable, non-secret execution plan;
- later invoke protocol adapters with circuit-breaker/failure-budget controls;
- later consolidate execution status for Analyzer/Asset Resolver.

## Non-responsibilities

The orchestrator must not:

- store plaintext credentials;
- guess credentials for Unknown assets;
- use discovered devices as silent pivots;
- contain platform-specific discovery logic that belongs in collectors/adapters;
- auto-expand candidate networks outside explicit authorization.

## Planned evolution

- v0.4b.3: context-aware planner;
- next: controlled execution orchestration with shared-credential failure budgets;
- WinRM/WMI and SNMP adapters;
- v0.4c: Asset Resolver integration;
- v0.4d: authorized Dynamic Scope Expansion.

Credentials must never be stored in inventory or planner output.
