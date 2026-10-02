# P01 Offline Import — v0.5b.0

The Offline Import stage materializes a validated `.p01bundle` into a local/server evidence store and can re-run the Asset Resolver using only the imported evidence.

## Guarantees

- validates the bundle before materialization;
- no `extractall` is used;
- preserves the original bundle under `raw/`;
- import is idempotent by `bundle_id` + bundle SHA256;
- second import of the same bytes returns `already_imported`;
- server-side processing performs no network access, authentication or secret resolution;
- import receipt JSON + SHA256 records what happened;
- optional semantic comparison checks the server Asset Resolver result against the embedded edge Asset Resolver result.

## Example

    python .\ingestion\P01_Offline_Import.py import `
      --bundle C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle `
      --store-dir C:\P01\server `
      --require-outer-sidecar `
      --process `
      --process-run-label P01LAB-SERVER-REPROCESS-R1

## Store layout

    C:\P01\server\
      assessments\<assessment_id>\imports\<bundle_id>\
        raw\
        payload\
        processed\asset_resolver\
        receipt\import-receipt.json
        receipt\import-receipt.json.sha256

## Semantic equivalence

The importer intentionally ignores execution-specific metadata such as processing host and generated timestamp when comparing edge and server Asset Resolver outputs.

It requires equivalent logical asset semantics:
- logical asset counts;
- unresolved/ambiguous state;
- canonical identity;
- identifiers;
- addresses;
- services;
- conflicts;
- confidence.

## Security

The importer treats every bundle as untrusted until bundle validation succeeds. Payload files are data only and are never executed.


## API metadata index v0.6.1 (CANDIDATE)

A API oferece `--metadata-index postgres` (default `off`) após o mesmo import
canônico. HTTP 201/200 confirma o filesystem; `metadata_index` informa separadamente
indexação, pendência ou revisão. [Contrato e reconciliação](../docs/INGESTION_INDEX_v0.6.1.md).
