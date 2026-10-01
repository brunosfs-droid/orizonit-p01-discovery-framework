param(
    [string]$CompletedWorkspace = "C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1"
)

# Run from the repository root with its Python virtual environment active.
# Creates an independent run with all grants denied; no live stage is run.
$ErrorActionPreference = "Stop"
$SourceState = Get-Content -Raw (Join-Path $CompletedWorkspace "state/run-state.json") | ConvertFrom-Json
$RunsRoot = Split-Path (Split-Path $CompletedWorkspace -Parent) -Parent
$NegativeRun = "P01LAB-AGENT-NEG-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$InitArguments = @(
    "runtime/P01_Discovery_Node.py", "init", "--workspace-root", $RunsRoot,
    "--assessment-id", $SourceState.assessment_id, "--run-id", $NegativeRun,
    "--node-id", $SourceState.node_id
)
if ($SourceState.source_refs.assessment_manifest) {
    $InitArguments += @("--manifest", $SourceState.source_refs.assessment_manifest)
}
if ($SourceState.source_refs.credential_profiles) {
    $InitArguments += @("--profiles", $SourceState.source_refs.credential_profiles)
}
$InitRaw = & python @InitArguments
if ($LASTEXITCODE -ne 0) { throw "Negative run initialization failed; no tamper performed." }
$InitRaw | ForEach-Object { Write-Host $_ }
# Portable init emits human-readable output, not JSON.
$NegativeWorkspace = Join-Path (Join-Path $RunsRoot $SourceState.assessment_id) $NegativeRun
if (-not (Test-Path -LiteralPath (Join-Path $NegativeWorkspace "state/run-state.json"))) {
    throw "Initialized workspace state was not found."
}
$NegativePolicy = Join-Path $NegativeWorkspace "config/agent-policy.json"
@{
    schema_version = "0.5f"
    identity = @{
        assessment_id = $SourceState.assessment_id
        run_id = $NegativeRun
        node_id = $SourceState.node_id
    }
    grants = @{
        discovery = $false; planning = $false; dry_run = $false
        auth_only = $false; full = $false; resolver = $false
        export = $false; upload = $false
    }
} | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $NegativePolicy

$BaselineRaw = & python agent/P01_Agent.py status --workspace $NegativeWorkspace --policy $NegativePolicy
$BaselineExit = $LASTEXITCODE
$Baseline = ($BaselineRaw -join "`n") | ConvertFrom-Json
if ($BaselineExit -ne 3 -or $Baseline.status -ne "policy_denied") {
    throw "Baseline must be policy_denied; no tamper performed."
}

$StatePath = Join-Path $NegativeWorkspace "state/run-state.json"
$StateBefore = (Get-FileHash -Algorithm SHA256 $StatePath).Hash
$ConfigPath = Join-Path $NegativeWorkspace "config/runtime.json"
$ConfigBefore = (Get-FileHash -Algorithm SHA256 $ConfigPath).Hash
$Original = [System.IO.File]::ReadAllBytes($ConfigPath)
$BackupPath = Join-Path $NegativeWorkspace "logs/runtime-original.bin"
[System.IO.File]::WriteAllBytes($BackupPath, $Original)

try {
    # Append whitespace without changing the original sidecar.
    [System.IO.File]::WriteAllBytes($ConfigPath, [byte[]]($Original + [byte]32))
    $DoctorRaw = & python agent/P01_Agent.py doctor --workspace $NegativeWorkspace --policy $NegativePolicy
    $DoctorExit = $LASTEXITCODE
    $Doctor = ($DoctorRaw -join "`n") | ConvertFrom-Json
    $RunRaw = & python agent/P01_Agent.py run-once --workspace $NegativeWorkspace --policy $NegativePolicy
    $RunExit = $LASTEXITCODE
    $Run = ($RunRaw -join "`n") | ConvertFrom-Json
    Write-Host ("tamper_doctor: {0}; exit={1}" -f $Doctor.error_code, $DoctorExit)
    Write-Host ("tamper_run_once: {0}; exit={1}" -f $Run.error_code, $RunExit)
    if ($DoctorExit -ne 2 -or $Doctor.error_code -ne "workspace_integrity_failed" -or
        $RunExit -ne 2 -or $Run.error_code -ne "workspace_integrity_failed") {
        throw "Tamper gate did not fail closed as expected."
    }
}
finally {
    # Restore exact bytes, including encoding. Do not recompute or replace sidecars.
    [System.IO.File]::WriteAllBytes($ConfigPath, $Original)
}

$ConfigRestored = (Get-FileHash -Algorithm SHA256 $ConfigPath).Hash -eq $ConfigBefore
$StateUnchanged = (Get-FileHash -Algorithm SHA256 $StatePath).Hash -eq $StateBefore
$AfterRaw = & python agent/P01_Agent.py status --workspace $NegativeWorkspace --policy $NegativePolicy
$AfterExit = $LASTEXITCODE
$After = ($AfterRaw -join "`n") | ConvertFrom-Json
Write-Host "ConfigRestored: $ConfigRestored"
Write-Host "StateUnchanged: $StateUnchanged"
Write-Host ("Restored status: {0}; exit={1}" -f $After.status, $AfterExit)
Write-Host "NegativeWorkspace: $NegativeWorkspace"
if (-not $ConfigRestored -or -not $StateUnchanged -or $AfterExit -ne 3 -or $After.status -ne "policy_denied") {
    throw "Restoration verification failed; preserve the negative workspace and backup."
}

Write-Host "CONFIG TAMPER PASS. Preserve this isolated run and its journals."
