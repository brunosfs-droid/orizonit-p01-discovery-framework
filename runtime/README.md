# Cancã Portable Discovery Node — v0.5e.1

The portable runtime is the first unified operator workflow for the Cancã Discovery Node.

It is intentionally **portable-first**: no Windows service or systemd installation is required.

## Scope of v0.5e.1

Implemented:

- `doctor` — validate runtime prerequisites without scanning or authentication;
- `init` — create an isolated assessment/run workspace;
- `run` — execute the managed Network Discovery stage;
- `status` — show deterministic checkpoints, artifacts and next action;
- `export` — wrap the validated v0.5a Evidence Bundle using existing evidence;
- `upload` — wrap the validated v0.5d HTTPS/mTLS uploader;
- Assessment Manifest authorization enforcement before active discovery;
- manifest excludes automatically honored by runtime discovery;
- SHA256-protected runtime state/config;
- resume guards that prevent silent re-scan/re-export/re-upload of completed steps.

Still external in v0.5e.1:

- Credential Planner orchestration;
- Credentialed Executor orchestration;
- Asset Resolver orchestration.

## Workspace

```text
canca-runs/
└── ACME-2026-001/
    └── RUN-001/
        ├── config/
        │   ├── runtime.json
        │   └── runtime.json.sha256
        ├── evidence/
        ├── resolved/
        ├── bundle/
        ├── receipts/
        ├── logs/
        └── state/
            ├── run-state.json
            └── run-state.json.sha256
```

The runtime state records only non-secret operational metadata, paths/hashes and step results.

It does **not** persist plaintext passwords, Secret Provider locators (`wincred://`, `prompt://`, `env://`), private-key material, or server-initiated remote execution instructions.

## State machine

```text
initialized               completed
network_discovery         pending -> running -> completed / failed
credential_plan           external_required
credentialed_execution    external_required
asset_resolver            external_required
evidence_bundle           pending -> completed / failed
upload                    pending -> completed / failed
```

A completed upload is not repeated unless the operator explicitly passes `--force-resend`.

A completed bundle is not rebuilt unless the operator explicitly passes `--force-rebuild`.

## Doctor

```powershell
python .\runtime\P01_Discovery_Node.py doctor `
  --workspace-root C:\Canca\runs
```

Connected-mode prerequisite check:

```powershell
python .\runtime\P01_Discovery_Node.py doctor `
  --workspace-root C:\Canca\runs `
  --server-url https://P01-LNX-RKY01.p01.lab.test:8443 `
  --ca-cert C:\P01\pki-v05d-r1\ca.crt `
  --client-cert C:\P01\pki-v05d-r1\p01-mgmt01.crt `
  --client-key C:\P01\pki-v05d-r1\p01-mgmt01.key
```

Doctor performs no network activity in v0.5e.1.

## Init

```powershell
python .\runtime\P01_Discovery_Node.py init `
  --workspace-root C:\Canca\runs `
  --assessment-id P01LAB-CTX-R1 `
  --run-id P01LAB-RUNTIME-R1 `
  --node-id P01-MGMT01 `
  --manifest C:\P01\assessment-p01lab-v046.json `
  --profiles C:\P01\credentials.p01lab.v046.lab.json
```

The profiles file is referenced by path only. Its contents are not copied into runtime state.

## Managed Network Discovery

v0.5e.1 manages the first active stage directly:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R2 `
  --target 192.168.100.0/24 `
  --profile safe `
  --ack-authorized-scan
```

The runtime refuses to scan without explicit acknowledgement and rejects effective IPs outside the Assessment Manifest `authorized_scopes`. Manifest `exclude_scopes` are always applied.

A completed discovery is not repeated unless the operator explicitly passes `--force-rescan`. Force-rescan is rejected once downstream completed steps would become stale.

## Status

```powershell
python .\runtime\P01_Discovery_Node.py status `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R1
```

## Export existing evidence

v0.5e.1 uses already collected evidence while the orchestration stages are still external:

```powershell
python .\runtime\P01_Discovery_Node.py export `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R1 `
  --network C:\P01\output\P01-Network-Discovery_20260930T110940Z_P01LAB-NODE-W11-WINRM-R2.json `
  --evidence-dir C:\P01\output\targets `
  --evidence-run-label P01LAB-MULTI-FULL-R1 `
  --asset-resolver C:\P01\output\P01-Asset-Resolver_20261001T015830Z_P01LAB-ASSET-RESOLVER-R2.json
```

Source evidence sidecars are required by default.

## Upload

```powershell
python .\runtime\P01_Discovery_Node.py upload `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R1 `
  --server-url https://P01-LNX-RKY01.p01.lab.test:8443 `
  --ca-cert C:\P01\pki-v05d-r1\ca.crt `
  --client-cert C:\P01\pki-v05d-r1\p01-mgmt01.crt `
  --client-key C:\P01\pki-v05d-r1\p01-mgmt01.key `
  --max-retries 0
```

The private-key path is used for the current invocation only and is not written into runtime state.

## Resume policy

The runtime never silently repeats a completed bundle build or completed upload.

Credential Planner, Credentialed Executor and Asset Resolver will gain the same checkpoint discipline in the next incremental runtime releases.
