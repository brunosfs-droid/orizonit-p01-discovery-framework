# Cancã Portable Discovery Node — v0.5e.7

The portable runtime is the first unified operator workflow for the Cancã Discovery Node.

It is intentionally **portable-first**: no Windows service or systemd installation is required.

SNMP is explicit opt-in in v0.5e.7: [requests, preview, AUTH, FULL and offline replay](../docs/SNMP_EVIDENCE_PORTABLE_v0.4b.9.md).
The portable collector requires no Cancã login. Target credentials remain in the existing provider; Web login and node mTLS stay separate.

## Scope of v0.5e.7

Implemented:

- `doctor` — validate runtime prerequisites without scanning or authentication;
- `init` — create an isolated assessment/run workspace;
- `run` — advance the managed workflow: Network Discovery first, then Credential Planner;
- `status` — show deterministic checkpoints, artifacts and next action;
- `export` — wrap the validated v0.5a Evidence Bundle using existing evidence;
- `upload` — wrap the validated v0.5d HTTPS/mTLS uploader;
- Assessment Manifest authorization enforcement before active discovery;
- manifest excludes automatically honored by runtime discovery;
- SHA256-protected runtime state/config;
- managed Credential Planner using the workspace Network Discovery artifact plus Assessment Manifest/Credential Profiles;
- managed Multi-target Credentialed Executor **dry-run/preflight** using the workspace Credential Plan;
- gated live **AUTH-only** execution with explicit authorization acknowledgement;
- gated live **FULL enrichment** after successful AUTH validation;
- managed offline **Asset Resolver** consuming only the workspace Network Discovery + recorded FULL target evidence;
- workspace-driven **Evidence Bundle export** derived from validated runtime state with no manual evidence paths required;
- connected mTLS upload end-to-end from that bundle;
- zero-input `upload --workspace ...` resume after completion, with no second network call;
- resume guards that prevent silent re-scan/re-plan/re-preview/re-auth/re-full/re-resolve/re-export/re-upload of completed steps.

Live connected upload in v0.5e.6 still requires explicit transport inputs because server URL and mTLS material are security-sensitive invocation context. The client private-key path remains invocation-only and is never persisted.

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
credential_plan           pending -> running -> completed / failed
credentialed_execution    pending -> running -> preview_completed -> auth_validated -> full_completed / failed
asset_resolver            pending -> running -> completed / failed
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

Doctor performs no network activity in v0.5e.6.

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

v0.5e.2 keeps managed Network Discovery as the first active stage:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R2 `
  --target 192.168.100.0/24 `
  --profile safe `
  --ack-authorized-scan
```

The runtime refuses to scan without explicit acknowledgement and rejects effective IPs outside the Assessment Manifest `authorized_scopes`. Manifest `exclude_scopes` are always applied.

A completed discovery is not repeated unless the operator explicitly passes `--force-rescan`. Force-rescan is rejected once downstream completed steps would become stale.

## Managed Credential Planner

After Network Discovery is completed, run the same operational command again **without `--target`** so the runtime advances to the next managed stage:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R2 `
  --max-candidates 2
```

The runtime reuses the Network Discovery artifact recorded in state and the Assessment Manifest / Credential Profiles references captured at `init`. Planning performs **no network activity, no secret resolution and no authentication**.

The generated Credential Plan JSON + SHA256 are stored under `evidence\credential_plan`. A repeated `run` returns `already_complete`; `--force-replan` is refused if completed downstream stages would become stale.

Existing v0.5e.1 workspaces with `credential_plan: external_required` can be continued in place; the stage is adopted safely when invoked.

## Managed Credentialed Executor dry-run

After a Credential Plan is completed, run the same command again:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3 `
  --max-actions 25
```

v0.5e.3 invokes the existing Multi-target Executor in **dry-run only**. It revalidates the plan artifact/hash and live Credential Profiles, then writes a Credentialed Job JSON + SHA256 under `evidence\credentialed_execution`.

The runtime records `credentialed_execution: preview_completed`, not live completion. No secret is resolved and no authentication is attempted in this increment. Repeating the same command returns `already_complete`.

## Managed Credentialed Executor AUTH-only

After a validated dry-run preview, live authentication requires all three explicit flags:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3 `
  --execute `
  --auth-only `
  --ack-authorized-access `
  --max-actions 25
```

v0.5e.3.1 revalidates the Credential Plan, dry-run preview and Credential Profiles before resolving any secret. The existing sequential executor and shared-credential circuit breaker remain in force.

This increment performs authentication only; FULL enrichment is refused. Successful AUTH evidence is stored under `evidence\credentialed_execution`, and the runtime advances to `credentialed_execution: auth_validated`.

A repeated AUTH-only command returns `already_complete` and performs no additional network activity, secret resolution or authentication. If an AUTH run fails or is partial, retry is refused unless the operator explicitly adds `--force-auth-retry` together with the authorization acknowledgement.

## Managed Credentialed Executor FULL enrichment

After `credentialed_execution: auth_validated`, FULL collection is a separate explicit live gate:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3 `
  --execute `
  --full-enrichment `
  --ack-authorized-access `
  --max-actions 25
```

The runtime revalidates the Credential Plan, dry-run preview, AUTH-only job and live Credential Profiles before executing the existing read-only enrichers. The executor remains sequential (`concurrency=1`) and preserves credential failure budgets/circuit breakers.

Successful FULL evidence is stored under `evidence\credentialed_execution` as an aggregate job plus per-target JSON/SHA256 pairs. The runtime records `credentialed_execution: full_completed`.

A repeated FULL command returns `already_complete` and performs no second network/authentication pass. Partial or failed FULL execution preserves its evidence but requires explicit `--force-full-retry` together with `--ack-authorized-access`.

## Managed Asset Resolver

After `credentialed_execution: full_completed`, the next plain `run` advances the offline resolver:

```powershell
python .\runtime\P01_Discovery_Node.py run `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3
```

The runtime selects the Network Discovery artifact from state and **only** the per-target evidence referenced by the validated EXEC-FULL aggregate job. AUTH-only target evidence is not mixed into resolution. Network, FULL job and every target sidecar are revalidated before correlation.

Asset Resolver v0.4c.1 runs offline/read-only and writes JSON + SHA256 under `resolved`. It performs no network access, secret resolution or authentication. A repeated `run` returns `already_complete`; `--force-reresolve` is refused once downstream bundle/upload steps are complete.

## Workspace-driven Evidence Bundle export

After `asset_resolver: completed`, the normal export no longer requires artifact paths:

```powershell
python .\runtime\P01_Discovery_Node.py export `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3
```

The runtime derives Network Discovery, the EXEC-FULL aggregate job, exactly the collected target evidence referenced by that job, the completed Asset Resolver artifact, and the Assessment Manifest from workspace state. Every workspace evidence input is hash/sidecar validated before packaging.

AUTH-only target files and unrelated JSONs in the evidence directory are never selected by workspace-driven export.

Explicit-path export remains available for backward compatibility.

## Connected upload and zero-input resume

A first live upload still requires explicit transport material:

```powershell
python .\runtime\P01_Discovery_Node.py upload `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3 `
  --server-url https://P01-LNX-RKY01.p01.lab.test:8443 `
  --ca-cert C:\P01\pki\ca.crt `
  --client-cert C:\P01\pki\p01-mgmt01.crt `
  --client-key C:\P01\pki\p01-mgmt01.key
```

After the upload checkpoint is completed, the safe-resume check needs only the workspace:

```powershell
python .\runtime\P01_Discovery_Node.py upload `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R3
```

The second command returns `already_complete` before any network/TLS setup. A forced resend still requires the complete transport parameter set.

## Status

```powershell
python .\runtime\P01_Discovery_Node.py status `
  --workspace C:\Canca\runs\P01LAB-CTX-R1\P01LAB-RUNTIME-R1
```

## Export existing evidence

Legacy explicit-path export can still package previously collected evidence:

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

Asset Resolver and workspace-driven Evidence Bundle export now follow the same checkpoint/resume discipline. Connected upload preserves no-silent-repeat behavior.


## Shared workspace locking

Portable init/discovery/planning/credentialed execution/resolver/export/upload now
share a nonblocking OS lock with the optional [agent](../agent/README.md). A busy
workspace is rejected; completed-checkpoint behavior and the v0.5e schema remain
unchanged. The retained `.canca-workspace.lock` file is not evidence of a live
process and must not be deleted while that workspace can be in use.
