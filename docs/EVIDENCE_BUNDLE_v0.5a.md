# P01 v0.5a — Evidence Bundle Format

## Goal

Create one evidence transport contract that works identically for online and offline assessment workflows.

## Invariants

1. Transport does not change evidence semantics.
2. Raw evidence remains immutable after ingestion.
3. Secrets never enter the bundle.
4. Every payload file is hash-addressable.
5. Bundle validation happens before Asset Resolver/Analyzer execution.
6. A repeated import of the same bundle_id must become idempotent in the server stage.

## Identity

`bundle_id` is deterministic from:

- assessment_id;
- run_id;
- node_id;
- ordered artifact role/path/hash/size inventory.

The bundle file itself may have a different binary SHA256 if creation metadata or ZIP encoding differs, while the logical bundle_id stays stable for the same evidence set.

## Integrity model

v0.5a uses:

- source sidecar verification before package creation when requested;
- artifact SHA256 in `bundle-manifest.json`;
- full payload plus manifest inventory in `integrity/sha256-manifest.json`;
- outer `.p01bundle.sha256` sidecar.

Authenticity is not yet provided by bare SHA256. The signed-bundle stage will add a trusted digital signature.

## Trust boundary

The future server must treat a received bundle as untrusted until:

- ZIP safety validation;
- manifest/schema validation;
- SHA256 inventory validation;
- secret-material guard;
- signature validation when the signed format is enabled;
- tenant/assessment binding validation.

## Portable-first

The Discovery Node should not require a permanent installation for one-shot assessments.

Optional installed-service mode can reuse the same bundle producer later for scheduled/continuous assessments.
