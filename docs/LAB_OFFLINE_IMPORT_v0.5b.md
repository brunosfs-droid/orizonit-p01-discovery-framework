# Orizon IT — P01 LAB
## Offline Import v0.5b.0 — P01LAB R1

Goal: import the already validated `P01LAB-BUNDLE-R1.p01bundle` into a clean server-side store and reprocess the Asset Resolver from bundle evidence only.

### 1. Update

    git switch main
    git pull origin main

### 2. Confirm version

    python .\ingestion\P01_Offline_Import.py --help

Expected: `P01-Offline-Import v0.5b.0`.

### 3. Create server store

    New-Item -ItemType Directory -Path C:\P01\server -Force

### 4. First import + server reprocessing

    python .\ingestion\P01_Offline_Import.py import `
      --bundle C:\P01\bundles\P01LAB-BUNDLE-R1.p01bundle `
      --store-dir C:\P01\server `
      --require-outer-sidecar `
      --process `
      --process-run-label P01LAB-SERVER-REPROCESS-R1

Expected:

    Status: imported
    Semantic match: true

### 5. Inspect receipt

    Get-Content C:\P01\server\assessments\P01LAB-CTX-R1\imports\bnd-de6f9f2af21fc179ae1f\receipt\import-receipt.json

Expected key facts:
- outer_sha256_verified = true
- artifact_count = 8
- credentialed_evidence_count = 5
- processing.asset_resolver_executed = true
- processing.semantic_match = true
- security.secret_resolution = false
- security.authentication_attempts = false
- security.network_access_performed = false

### 6. Second import — idempotency

Run the exact same import command again.

Expected:

    Status: already_imported
    Semantic match: true

No second import directory should be created.

### 7. Evidence to send

Send:

- `import-receipt.json`
- `import-receipt.json.sha256`
- server-side Asset Resolver JSON + SHA256 from `processed\asset_resolver`

Do not edit the imported payload or receipt manually.
