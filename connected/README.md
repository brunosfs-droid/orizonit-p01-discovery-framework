# P01 Connected Discovery Node Upload — v0.5d.0

v0.5d adds authenticated remote transport for the same `.p01bundle` validated in v0.5a/v0.5b/v0.5c.

Connected mode changes transport only. Bundle validation, idempotency, import, Asset Resolver and later reporting remain unchanged.

## Security model

- HTTPS only;
- TLS 1.2 minimum;
- mutual TLS required for remote mode;
- server certificate validated by the Discovery Node;
- client certificate validated by the server;
- `X-P01-Node-ID` must match the authenticated client certificate identity;
- bundle manifest `node_id` must match the authenticated node identity;
- no server-initiated execution on the Discovery Node;
- no credentials or private keys are embedded in the bundle;
- HTTP/application/TLS validation failures are never retried automatically;
- bounded retries apply only to transport failures.

## Client certificate identity

The server uses the first DNS Subject Alternative Name from the client certificate as the node identity. If no DNS SAN exists, Common Name is used as a compatibility fallback.

LAB certificates should therefore use:

`subjectAltName = DNS:P01-MGMT01`

## Uploader

    python .\connected\P01_Discovery_Node_Uploader.py `
      --server-url https://localhost:8443 `
      --bundle C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle `
      --node-id P01-MGMT01 `
      --ca-cert C:\P01\pki\ca.crt `
      --client-cert C:\P01\pki\p01-mgmt01.crt `
      --client-key C:\P01\pki\p01-mgmt01.key `
      --output-dir C:\P01\connected-output

## Server mTLS mode

    python .\ingestion\P01_Ingestion_API.py serve `
      --store-dir C:\P01\mtls-server-r1 `
      --bind 127.0.0.1 `
      --port 8443 `
      --transport-mode mtls `
      --tls-cert C:\P01\pki\server.crt `
      --tls-key C:\P01\pki\server.key `
      --client-ca C:\P01\pki\ca.crt `
      --process

Do not commit or upload CA private keys, server private keys or client private keys.
