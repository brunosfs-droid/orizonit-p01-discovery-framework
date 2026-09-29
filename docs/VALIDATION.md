# Validation Plan

## Objective

Prove that collectors:

- execute successfully on supported platforms;
- do not make unintended configuration changes;
- generate parseable JSON;
- generate the expected SHA-256 artifact;
- report privilege/module limitations honestly;
- maintain stable field semantics between compatible versions.

## Windows test matrix

| Scenario | Expected result |
|---|---|
| Standalone Windows, standard user | Collection completes with limitations |
| Standalone Windows, local admin | Full local collection expected |
| Domain member, standard user | Local collection + domain context where available |
| Domain member, local admin | Expanded local visibility |
| Domain Controller with AD module | AD collection succeeds |
| Host without AD module | AD error/limitation recorded; local collection continues |
| `-SkipAD` | AD collection intentionally skipped |
| `-SkipGPO` | GPO collection intentionally skipped |

## Output validation

### JSON

```powershell
Get-Content .\output.json -Raw | ConvertFrom-Json | Out-Null
```

### SHA-256

```powershell
Get-FileHash .\output.json -Algorithm SHA256
Get-Content .\output.json.sha256
```

The computed hash must match the hash file.

## Read-only validation

Before and after a test run, compare relevant configuration state. The collector
must not:

- install packages;
- create users;
- modify firewall rules;
- change services;
- change registry configuration;
- change domain objects;
- alter GPO;
- create persistence.

## Evidence

For each validated release record:

- collector version;
- OS/version;
- PowerShell/Python version;
- privilege profile;
- command used;
- result;
- known limitations;
- representative sanitized output.
