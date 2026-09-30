# P01LAB — Connected Discovery Node Upload v0.5d.0 — mTLS R1

Goal: validate authenticated connected transport using the already validated P01LAB `.p01bundle`. This R1 runs client and server on the same host/loopback only to validate TLS and identity semantics before separating hosts.

Do not commit or upload any `.key` file.

## 1. Update

    git switch main
    git pull origin main

After the v0.5d PR is merged, confirm:

    python .\ingestion\P01_Ingestion_API.py --help
    python .\connected\P01_Discovery_Node_Uploader.py --help

Expected: `v0.5d.0`.

## 2. Locate OpenSSL

PowerShell:

    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    if (-not $openssl) {
      $openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
    }
    if (-not (Test-Path $openssl)) { throw 'OpenSSL not found' }
    & $openssl version

## 3. Create LAB PKI

    $pki = 'C:\P01\pki-v05d-r1'
    Remove-Item $pki -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $pki -Force | Out-Null

Create the LAB CA:

    & $openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes `
      -keyout "$pki\ca.key" `
      -out "$pki\ca.crt" `
      -subj '/CN=P01LAB-Root-CA'

Create server request and extensions:

    & $openssl req -newkey rsa:3072 -nodes `
      -keyout "$pki\server.key" `
      -out "$pki\server.csr" `
      -subj '/CN=localhost'

    @'
    subjectAltName=DNS:localhost,IP:127.0.0.1
    extendedKeyUsage=serverAuth
    keyUsage=digitalSignature,keyEncipherment
    '@ | Set-Content "$pki\server.ext" -Encoding ascii

    & $openssl x509 -req `
      -in "$pki\server.csr" `
      -CA "$pki\ca.crt" `
      -CAkey "$pki\ca.key" `
      -CAcreateserial `
      -out "$pki\server.crt" `
      -days 30 -sha256 `
      -extfile "$pki\server.ext"

Create Discovery Node client certificate:

    & $openssl req -newkey rsa:3072 -nodes `
      -keyout "$pki\p01-mgmt01.key" `
      -out "$pki\p01-mgmt01.csr" `
      -subj '/CN=P01-MGMT01'

    @'
    subjectAltName=DNS:P01-MGMT01
    extendedKeyUsage=clientAuth
    keyUsage=digitalSignature,keyEncipherment
    '@ | Set-Content "$pki\p01-mgmt01.ext" -Encoding ascii

    & $openssl x509 -req `
      -in "$pki\p01-mgmt01.csr" `
      -CA "$pki\ca.crt" `
      -CAkey "$pki\ca.key" `
      -CAserial "$pki\ca.srl" `
      -out "$pki\p01-mgmt01.crt" `
      -days 30 -sha256 `
      -extfile "$pki\p01-mgmt01.ext"

Verify:

    & $openssl verify -CAfile "$pki\ca.crt" "$pki\server.crt"
    & $openssl verify -CAfile "$pki\ca.crt" "$pki\p01-mgmt01.crt"

Both must return `OK`.

## 4. Start mTLS server

PowerShell A:

    Remove-Item C:\P01\mtls-server-r1 -Recurse -Force -ErrorAction SilentlyContinue

    python .\ingestion\P01_Ingestion_API.py serve `
      --store-dir C:\P01\mtls-server-r1 `
      --bind 127.0.0.1 `
      --port 8443 `
      --transport-mode mtls `
      --tls-cert C:\P01\pki-v05d-r1\server.crt `
      --tls-key C:\P01\pki-v05d-r1\server.key `
      --client-ca C:\P01\pki-v05d-r1\ca.crt `
      --process `
      --process-run-label P01LAB-MTLS-SERVER-R1

Expected:

    P01-Central-Ingestion-API v0.5d.0
    Listening: https://127.0.0.1:8443
    Transport mode: mtls
    Bind policy: mtls_authenticated

## 5. Valid connected upload

PowerShell B:

    New-Item -ItemType Directory C:\P01\connected-output -Force | Out-Null

    python .\connected\P01_Discovery_Node_Uploader.py `
      --server-url https://localhost:8443 `
      --bundle C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle `
      --node-id P01-MGMT01 `
      --ca-cert C:\P01\pki-v05d-r1\ca.crt `
      --client-cert C:\P01\pki-v05d-r1\p01-mgmt01.crt `
      --client-key C:\P01\pki-v05d-r1\p01-mgmt01.key `
      --max-retries 0 `
      --output-dir C:\P01\connected-output

Expected:

    Upload status: success
    HTTP status: 201
    Server status: imported
    Semantic match: True
    Authenticated node: P01-MGMT01

Run the same command again. Expected `HTTP status: 200` and `Server status: already_imported`.

## 6. Missing client certificate gate

Use Python stdlib without a client certificate:

    python -c "import ssl,urllib.request; c=ssl.create_default_context(cafile=r'C:\P01\pki-v05d-r1\ca.crt'); print(urllib.request.urlopen('https://localhost:8443/healthz',context=c,timeout=5).read())"

Expected: TLS handshake failure / certificate required. No HTTP 200.

## 7. Certificate/header node mismatch gate

Prepare values:

    $bundle = 'C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle'
    $sha = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()

Use the valid client certificate but claim another Node ID:

    curl.exe -i `
      --cacert C:\P01\pki-v05d-r1\ca.crt `
      --cert C:\P01\pki-v05d-r1\p01-mgmt01.crt `
      --key C:\P01\pki-v05d-r1\p01-mgmt01.key `
      -H "Content-Type: application/vnd.orizon.p01bundle" `
      -H "X-P01-Bundle-SHA256: $sha" `
      -H "X-P01-Node-ID: OTHER-NODE" `
      --data-binary "@$bundle" `
      https://localhost:8443/api/v1/bundles

Expected: HTTP 403 and a node identity mismatch message.

## 8. Evidence

Send:

- screenshot of OpenSSL verify OK;
- screenshot of server startup;
- first uploader result;
- repeated uploader result;
- missing-client-cert TLS failure;
- certificate/header mismatch HTTP 403;
- `P01-Upload-Receipt_bnd-de6f9f2af21fc179ae1f.json` and `.sha256`.

Never send `ca.key`, `server.key` or `p01-mgmt01.key`.
