# P01 Central Ingestion API — v0.5d.0

The Central Ingestion API receives the same `.p01bundle` used by offline/manual import and delegates processing to the exact same v0.5b `import_bundle()` pipeline.

## Architectural invariant

`online upload` and `offline manual import` differ only in transport.

After the server receives the bundle, both paths use the same validation, evidence store, Asset Resolver replay and semantic checks.

## Transport modes

### localhost

Preserves the v0.5c development mode and remains loopback-only.

### mtls

Allows remote binding only when all trust material is configured:
- server certificate;
- server private key;
- trusted client CA.

mTLS mode requires a client certificate before HTTP ingestion. `X-P01-Node-ID` must match the authenticated client certificate identity, and the validated bundle `node_id` must match that same node identity.

No server-to-node command execution is introduced.

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


## v0.5c.1 connection hygiene

Requests rejected before the upload body is consumed (for example missing/malformed SHA256 or oversized Content-Length) return `Connection: close` and terminate the HTTP/1.1 connection. This prevents unread request bytes from being interpreted as a follow-on HTTP request.

## mTLS server example

    python .\ingestion\P01_Ingestion_API.py serve `
      --store-dir C:\P01\mtls-server-r1 `
      --bind 127.0.0.1 `
      --port 8443 `
      --transport-mode mtls `
      --tls-cert C:\P01\pki\server.crt `
      --tls-key C:\P01\pki\server.key `
      --client-ca C:\P01\pki\ca.crt `
      --process

Remote/non-loopback use is permitted only in `mtls` mode.

## Node identity

The first DNS Subject Alternative Name of the client certificate is used as the node identity. Common Name is a compatibility fallback only when no DNS SAN exists.

The server also verifies that the bundle manifest `node_id` matches the authenticated node.

## v0.6.10 — explicit assessment grants

For mTLS deployments requiring assessment isolation, add `--node-policy` with a
validated node/assessment grant file. `bundle:ingest` and `bundle:read` are
independent; absent grants deny access before import/index or receipt output.
The certificate/header/bundle identity and ownership checks remain mandatory.
Policy changes require a controlled restart. Without this opt-in flag, health
reports `authorization_mode: transport_only`; legacy transport is not assessment
authorization. [Configuration and limits](../docs/NODE_AUTHORIZATION_v0.6.10.md).
