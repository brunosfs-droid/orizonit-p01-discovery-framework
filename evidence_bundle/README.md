# P01 Evidence Bundle — v0.5a.1

The v0.5a format/roles remain unchanged. Creation and validation now check recognized SNMP evidence contracts while retaining exact raw bytes and hashes. [SNMP bundle/replay contract](../docs/SNMP_EVIDENCE_PORTABLE_v0.4b.9.md).

The Evidence Bundle is the portable transport contract between a P01 Discovery Node and the future P01 Server/Ingestion Plane.

The same `.p01bundle` is used for connected upload and offline/manual transfer.

## Current scope

v0.5a creates and validates bundles containing:

- Network Discovery JSON;
- credentialed target evidence;
- optional Assessment Manifest;
- optional Asset Resolver result.

## Bundle layout

    bundle-manifest.json
    integrity/sha256-manifest.json
    context/<assessment-manifest>.json
    evidence/network/<network-discovery>.json
    evidence/credentialed/<target>.json
    evidence/resolved/<asset-resolver>.json

## Security

- no password/token/private-key values;
- no Secret Provider references such as `wincred://`, `prompt://` or `env://`;
- SHA256 inventory for every payload;
- optional verification of original evidence sidecars before bundle creation;
- outer `.p01bundle.sha256` sidecar;
- duplicate ZIP entry protection;
- path traversal protection;
- symlink rejection;
- uncompressed-size and file-count limits.

Important: SHA256 inventory provides consistency/integrity checking but not publisher authenticity. Digital signatures are intentionally deferred to the signed-bundle stage.

## Create

PowerShell example:

    python .\evidence_bundle\P01_Evidence_Bundle.py create `
      --assessment-id P01LAB-CTX-R1 `
      --run-id P01LAB-BUNDLE-R1 `
      --node-id P01-MGMT01 `
      --network C:\P01\output\P01-Network-Discovery_<timestamp>_P01LAB-NODE-W11-WINRM-R2.json `
      --manifest C:\P01\assessment-p01lab-v046.json `
      --asset-resolver C:\P01\output\P01-Asset-Resolver_<timestamp>_P01LAB-ASSET-RESOLVER-R2.json `
      --evidence-dir C:\P01\output\targets `
      --evidence-run-label P01LAB-MULTI-FULL-R1 `
      --require-evidence-sidecars `
      --output C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle

## Validate

    python .\evidence_bundle\P01_Evidence_Bundle.py validate `
      --bundle C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle

Expected validation includes `valid=true`, bundle identity, artifact counts and outer SHA256 verification.

## Architectural rule

Connected and offline paths must converge immediately after transport:

    Discovery Node
         |
         +-- HTTPS upload ------+
         |                      |
         +-- .p01bundle file ---+--> same ingestion pipeline
                                |
                                +--> validation
                                +--> raw evidence store
                                +--> Asset Resolver
                                +--> Analyzer
                                +--> Reporting
