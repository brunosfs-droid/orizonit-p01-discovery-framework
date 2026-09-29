# Installation

## Windows collector

### Requirements

- Windows PowerShell 5.1 or newer compatible PowerShell runtime
- Local access to the target host
- Administrative privileges for full local visibility
- ActiveDirectory module for AD collection
- GroupPolicy module for GPO collection

### Suggested directory layout

```text
C:\P01\
├── Scripts\
└── Output\
```

### Run

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File C:\P01\Scripts\P01_Windows_AD_Discovery_Collector.ps1

C:\P01\Scripts\P01_Windows_AD_Discovery_Collector.ps1 `
  -OutputDirectory C:\P01\Output `
  -RunLabel LAB-P01
```

### Optional switches

- `-SkipAD`
- `-SkipGPO`
- `-IncludeLocalUsers`
- `-IncludeInstalledSoftware`

## Linux collector

The Linux collector is still under validation. Installation and execution
requirements will be documented when the implementation reaches the repository.
