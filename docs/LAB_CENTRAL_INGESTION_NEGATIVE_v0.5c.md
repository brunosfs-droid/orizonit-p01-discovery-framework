# P01LAB — Central Ingestion API v0.5c.0 Negative Gates

Goal: close the v0.5c transport-safety gates on localhost before any v0.5d remote/TLS work.

Keep the API bound to 127.0.0.1. Do not open firewall rules.

## Server

Start with an intentionally small upload limit so the size gate can be tested without creating large files:

```powershell
python .\ingestion\P01_Ingestion_API.py serve `
  --store-dir C:\P01\api-server-neg-r1 `
  --bind 127.0.0.1 `
  --port 8088 `
  --max-upload-mib 1 `
  --process
```

Use the existing bundle:

```powershell
$bundle = 'C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle'
$sha = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()
```

## Gate 1 — missing SHA256 header

```powershell
try {
  Invoke-WebRequest `
    -Uri http://127.0.0.1:8088/api/v1/bundles `
    -Method Post `
    -ContentType 'application/octet-stream' `
    -InFile $bundle
} catch {
  $_.Exception.Response.StatusCode.value__
  $_.ErrorDetails.Message
}
```

Expected: HTTP 400. The error must state that `X-P01-Bundle-SHA256` is required/invalid.

## Gate 2 — wrong SHA256 header

```powershell
$wrongSha = '0' * 64
try {
  Invoke-WebRequest `
    -Uri http://127.0.0.1:8088/api/v1/bundles `
    -Method Post `
    -ContentType 'application/octet-stream' `
    -Headers @{ 'X-P01-Bundle-SHA256' = $wrongSha } `
    -InFile $bundle
} catch {
  $_.Exception.Response.StatusCode.value__
  $_.ErrorDetails.Message
}
```

Expected: HTTP 422, uploaded bundle SHA256 mismatch.

## Gate 3 — tampered bundle

Create a copy and alter one byte:

```powershell
$tampered = 'C:\P01\bundles\P01LAB-BUNDLE-R1-TAMPERED.p01bundle'
Copy-Item $bundle $tampered -Force

$bytes = [System.IO.File]::ReadAllBytes($tampered)
$bytes[$bytes.Length - 32] = $bytes[$bytes.Length - 32] -bxor 1
[System.IO.File]::WriteAllBytes($tampered, $bytes)

$tamperedSha = (Get-FileHash $tampered -Algorithm SHA256).Hash.ToLower()
```

Upload with the correct SHA256 of the tampered bytes:

```powershell
try {
  Invoke-WebRequest `
    -Uri http://127.0.0.1:8088/api/v1/bundles `
    -Method Post `
    -ContentType 'application/octet-stream' `
    -Headers @{ 'X-P01-Bundle-SHA256' = $tamperedSha } `
    -InFile $tampered
} catch {
  $_.Exception.Response.StatusCode.value__
  $_.ErrorDetails.Message
}
```

Expected: HTTP 422 and bundle validation failure. No import directory may be committed for the tampered bundle.

## Gate 4 — upload-size limit

The server is running with `--max-upload-mib 1` and the real bundle is larger than 1 MiB only if its actual size exceeds that limit. Check first:

```powershell
(Get-Item $bundle).Length
```

If the bundle is already > 1 MiB, upload it normally and expect HTTP 413.

If it is smaller, create a harmless 2 MiB dummy file and attempt upload:

```powershell
$big = 'C:\P01\bundles\oversize.bin'
$data = New-Object byte[] (2MB)
[System.IO.File]::WriteAllBytes($big, $data)
$bigSha = (Get-FileHash $big -Algorithm SHA256).Hash.ToLower()

try {
  Invoke-WebRequest `
    -Uri http://127.0.0.1:8088/api/v1/bundles `
    -Method Post `
    -ContentType 'application/octet-stream' `
    -Headers @{ 'X-P01-Bundle-SHA256' = $bigSha } `
    -InFile $big
} catch {
  $_.Exception.Response.StatusCode.value__
  $_.ErrorDetails.Message
}
```

Expected: HTTP 413 before bundle validation/import.

## Acceptance

v0.5c.0 can be marked LAB VALIDATED when:

- missing SHA256 -> 400;
- wrong SHA256 -> 422;
- tampered bundle -> 422;
- oversized request -> 413;
- no invalid request creates a committed import;
- API remains localhost-only;
- existing positive path remains imported/already_imported with semantic_match=true.
