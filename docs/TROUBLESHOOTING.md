# Troubleshooting

## Windows: script is not digitally signed

For laboratory execution, prefer a process-scoped override:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\P01_Windows_AD_Discovery_Collector.ps1
```

Do not weaken the machine execution policy permanently just to run the collector.

## Windows PowerShell 5.1: `Argument types do not match`

Older collector revisions used array subexpressions against
`System.Collections.Generic.List[object]`. Current code should explicitly use
`.ToArray()` where required for Windows PowerShell 5.1 compatibility.

## Active Directory module missing

Install the appropriate RSAT/AD DS tools. The collector should record the
failure and preserve the rest of the local inventory.

## GroupPolicy module missing

Install GPMC/RSAT Group Policy Management Tools or run with `-SkipGPO`.

## SSH port test from PowerShell

```powershell
Test-NetConnection 192.168.100.50 -Port 22
```

Expected:

```text
TcpTestSucceeded : True
```

## Linux SSH: no hostkeys available

Generate missing SSH host keys:

```bash
sudo ssh-keygen -A
sudo sshd -t
sudo systemctl reset-failed ssh
sudo systemctl enable --now ssh
```

On Rocky Linux the service is usually `sshd`:

```bash
sudo systemctl enable --now sshd
```
