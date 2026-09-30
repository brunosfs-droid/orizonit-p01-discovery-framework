# P01 Central Ingestion API — v0.5c.0

The Central Ingestion API receives the same `.p01bundle` used by offline/manual import and delegates processing to the exact same v0.5b `import_bundle()` pipeline.

## Architectural invariant

`online upload` and `offline manual import` differ only in transport.

After the server receives the bundle, both paths use the same validation, evidence store, Asset Resolver replay and semantic checks.

## v0.5c safety boundary

v0.5c is **localhost-only**.

It intentionally does not provide:
- Internet exposure;
- TLS termination;
- node enrollment;
- remote customer authentication;
- server-to-node control;
- arbitrary command execution.

Those belong to v0.5d.

## Start server

    python .\ingestion\P01_Ingestion_API.py serve `
      --store-dir C:\P01\api-server-r1 `
      --bind 127.0.0.1 `
      --port 8088 `
      --process `
      --process-run-label P01LAB-API-SERVER-REPROCESS-R1

Health:

    Invoke-RestMethod http://127.0.0.1:8088/healthz

## Upload

The request body is the raw `.p01bundle`.

Required:
- `Content-Type: application/octet-stream`
- `Content-Length`
- `X-P01-Bundle-SHA256`

Recommended:
- `Idempotency-Key: <bundle_id>`

PowerShell:

    $bundle = 'C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle'
    $sha = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()
    Invoke-RestMethod `
      -Uri http://127.0.0.1:8088/api/v1/bundles `
      -Method Post `
      -ContentType 'application/octet-stream' `
      -Headers @{
        'X-P01-Bundle-SHA256' = $sha
        'Idempotency-Key' = 'bnd-de6f9f2af21fc179ae1f'
      } `
      -InFile $bundle

Expected first response:

    status = imported
    semantic_match = true

Expected second identical upload:

    status = already_imported
    semantic_match = true

## Status

    Invoke-RestMethod http://127.0.0.1:8088/api/v1/bundles/bnd-de6f9f2af21fc179ae1f

## Security

- upload is streamed to staging;
- maximum upload size is enforced before processing;
- supplied SHA256 is verified before bundle validation;
- caller filenames and paths are ignored;
- Idempotency-Key must match the validated logical bundle ID when supplied;
- the common v0.5b importer performs final bundle validation/materialization;
- server-side processing never contacts customer assets;
- no secrets are resolved;
- no arbitrary payload is executed;
- non-loopback bind is rejected by design in v0.5c.

## Next

v0.5d will add production connected-mode controls: TLS, authenticated Discovery Node enrollment, tenant/assessment authorization, retry/audit semantics and controlled remote bind.
