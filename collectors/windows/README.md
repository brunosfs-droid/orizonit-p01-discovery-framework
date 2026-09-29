# Windows / Active Directory Collector

Canonical collector:

`P01_Windows_AD_Discovery_Collector.ps1`

## Current compatibility target

- Windows PowerShell 5.1+
- Windows 10/11
- Windows Server versions supporting the used CIM/Net* cmdlets
- Active Directory and GroupPolicy modules when those sections are requested

## Principles

- read-only;
- no network exfiltration;
- JSON output;
- SHA-256 integrity file;
- errors, limitations and warnings remain visible in output.

## Example

```powershell
.\P01_Windows_AD_Discovery_Collector.ps1 `
  -OutputDirectory C:\P01\Output `
  -RunLabel LAB-P01
```
