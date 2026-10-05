# P01 Asset Resolver — v0.4c.1

The Asset Resolver is an **offline-only** correlation engine that consolidates independent P01 evidence into canonical logical assets while preserving provenance.

It does not scan, authenticate, resolve secrets, pivot, or expand scope.

## Inputs

Current v0.4c.1 inputs:

- Network Discovery JSON;
- Credentialed Target JSON from the v0.4b.5 Multi-target Executor;
- raw WinRM/SSH enrichment JSON is also accepted;
- validated SNMP standalone v0.4b.7 and executor target v0.4b.8 evidence; AUTH-only/dry/failed probes remain diagnostics;
- optional v0.4b.6 Assessment Manifest.

SNMP fields retain observed OID/source-SHA claims and field coverage. `sysObjectID` identifies a product/model and is never a strong identifier. Remote usable `sysName` requires independent corroboration and does not promote AD realm through a manifest suffix. Plan hints do not become collected identity. [SNMP evidence contract](../docs/SNMP_EVIDENCE_PORTABLE_v0.4b.9.md).

## Core safety rule

The resolver **never auto-merges on IP address alone**.

Automatic merge requires either:

- an exact strong identifier match; or
- corroborated namespace identity (`fqdn` or hostname) **plus** network identity (`IP` or MAC).

Network Discovery observations are seeded independently. Two discovery assets are therefore not silently collapsed merely because they share a MAC.

## Strong identifiers

v0.4c.0 currently recognizes:

- meaningful Windows serial number;
- SSH server host-key SHA256 fingerprint.

Future sources may add stable system UUID, SMBIOS UUID, service tag, vCenter VM UUID and vendor identifiers.

## Field provenance

Canonical fields are resolved from claims. Every claim preserves value, source ID, evidence strength and evidence reason.

Conflicting medium-or-strong values are retained in `conflicts` rather than silently overwritten.

## Realm provenance

Assessment Manifest correlations can add declared realm claims and observed realm claims when hostname/FQDN matches a declared domain.

Credentialed Windows domain-membership evidence can promote realm state to `credentialed_confirmed`.

`observed` must not be interpreted as confirmed AD membership.

## Run against executor FULL evidence

Example PowerShell:

    python .\asset_resolver\P01_Asset_Resolver.py `
      --network C:\P01\output\P01-Network-Discovery_<timestamp>_P01LAB-NODE-W11-WINRM-R2.json `
      --evidence-dir C:\P01\output\targets `
      --evidence-run-label P01LAB-MULTI-FULL-R1 `
      --manifest C:\P01\assessment-p01lab-v046.json `
      --require-evidence-sidecars `
      --run-label P01LAB-ASSET-RESOLVER-R1 `
      --output-dir C:\P01\output

Expected first P01LAB acceptance:

- 5 Network Discovery assets;
- 5 credentialed observations;
- exactly 5 logical assets;
- 0 unresolved observations;
- 0 ambiguous correlations;
- no secret material in output;
- JSON + SHA256 output.

## Limitations

v0.4c.0 uses deterministic asset IDs derived from the seed observation identity anchor. A persistent asset registry is intentionally deferred.

The first version correlates existing evidence only. It does not yet persist lifecycle state across assessment runs.
