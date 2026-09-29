<#
.SYNOPSIS
  Orizon IT - Produto 01 / Infrastructure Assessment
  Windows + Active Directory Discovery Collector v0.2.1

.DESCRIPTION
  Coletor read-only para inventário técnico de host Windows e, opcionalmente,
  Active Directory e GPO. Não altera configurações e não envia dados para rede.

  Saída: JSON + arquivo SHA256 no diretório informado.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\P01_Windows_AD_Discovery_Collector.ps1 `
    -OutputDirectory C:\P01\output -RunLabel W01-domain-user

.NOTES
  Versão: 0.2.1
  Schema: 0.2
  Classificação recomendada da saída: CONFIDENCIAL - DADOS DO CLIENTE

  Para laboratório, prefira -ExecutionPolicy Bypass somente no processo iniciado.
  Não é necessário reduzir permanentemente a política de execução do host.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\output",
    [string]$RunLabel,
    [switch]$SkipAD,
    [switch]$SkipGPO,
    [switch]$IncludeLocalUsers,
    [switch]$IncludeInstalledSoftware
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$CollectorName = 'P01-Windows-AD-Discovery-Collector'
$CollectorVersion = '0.2.1'
$SchemaVersion = '0.2'
$StartTime = Get-Date
$script:CollectorErrors = New-Object System.Collections.Generic.List[object]
$script:CollectorLimitations = New-Object System.Collections.Generic.List[object]
$script:CollectorWarnings = New-Object System.Collections.Generic.List[object]

function Add-CollectorError {
    param(
        [string]$Section,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $script:CollectorErrors.Add([pscustomobject]@{
        section = $Section
        message = $ErrorRecord.Exception.Message
        exception_type = $ErrorRecord.Exception.GetType().FullName
    }) | Out-Null
}

function Add-CollectorLimitation {
    param(
        [string]$Section,
        [string]$Message,
        [string]$ExceptionType = $null
    )
    $script:CollectorLimitations.Add([pscustomobject]@{
        section = $Section
        message = $Message
        exception_type = $ExceptionType
    }) | Out-Null
}

function Add-CollectorWarning {
    param(
        [string]$Section,
        [string]$Message
    )
    $script:CollectorWarnings.Add([pscustomobject]@{
        section = $Section
        message = $Message
        exception_type = $null
    }) | Out-Null
}

function Invoke-CollectorSection {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )
    try {
        return & $ScriptBlock
    }
    catch {
        Add-CollectorError -Section $Name -ErrorRecord $_
        return $null
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-SafePropertyValue {
    param(
        [Parameter(Mandatory=$false)]$Object,
        [Parameter(Mandatory=$true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-SafeLabel {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $clean = ($Value.Trim() -replace '[^A-Za-z0-9._-]+','-').Trim('-','.','_')
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    if ($clean.Length -gt 64) { return $clean.Substring(0,64) }
    return $clean
}

function Get-InstalledSoftwareFromRegistry {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    return $items | Sort-Object DisplayName, DisplayVersion -Unique
}

$IsAdministrator = Test-IsAdministrator
$SafeRunLabel = ConvertTo-SafeLabel -Value $RunLabel

$executionPolicyList = Invoke-CollectorSection 'runtime.execution_policy' {
    Get-ExecutionPolicy -List | ForEach-Object {
        [pscustomobject]@{
            scope = $_.Scope.ToString()
            execution_policy = $_.ExecutionPolicy.ToString()
        }
    }
}

$metadata = [ordered]@{
    collector_name = $CollectorName
    collector_version = $CollectorVersion
    schema_version = $SchemaVersion
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    computer_name = $env:COMPUTERNAME
    execution_user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    is_administrator = $IsAdministrator
    privilege_profile = $(if ($IsAdministrator) { 'local-admin' } else { 'standard-user' })
    run_label = $SafeRunLabel
    powershell_version = $PSVersionTable.PSVersion.ToString()
    powershell_language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
    execution_policy = (Get-ExecutionPolicy).ToString()
    execution_policy_scopes = $executionPolicyList
    read_only_mode = $true
}

if (-not $IsAdministrator) {
    Add-CollectorLimitation -Section 'host.local_inventory' -Message (
        'A conta atual não é administradora local. O inventário do host permanece read-only, ' +
        'mas alguns objetos locais, especialmente tarefas agendadas e detalhes protegidos, podem ter visibilidade parcial.'
    )
}

$system = [ordered]@{}
$system.computer_system = Invoke-CollectorSection 'system.computer_system' {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, Domain, PartOfDomain, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors
}
$system.operating_system = Invoke-CollectorSection 'system.operating_system' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, WindowsDirectory
}
$system.bios = Invoke-CollectorSection 'system.bios' {
    Get-CimInstance Win32_BIOS |
        Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber
}
$system.processors = Invoke-CollectorSection 'system.processors' {
    Get-CimInstance Win32_Processor |
        Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
}
$system.volumes = Invoke-CollectorSection 'system.volumes' {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
}
$system.hotfixes = Invoke-CollectorSection 'system.hotfixes' {
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Select-Object HotFixID, Description, InstalledBy, InstalledOn
}

$network = [ordered]@{}
$network.adapters = Invoke-CollectorSection 'network.adapters' {
    Get-NetAdapter |
        Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, ifIndex
}
$network.ip_configuration = Invoke-CollectorSection 'network.ip_configuration' {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($cfg in @(Get-NetIPConfiguration)) {
        if ($null -eq $cfg) { continue }

        $ipv4Objects = @(Get-SafePropertyValue -Object $cfg -Name 'IPv4Address')
        $ipv6Objects = @(Get-SafePropertyValue -Object $cfg -Name 'IPv6Address')
        $gatewayObjects = @(Get-SafePropertyValue -Object $cfg -Name 'IPv4DefaultGateway')
        $dnsObject = Get-SafePropertyValue -Object $cfg -Name 'DNSServer'
        $dnsValues = @()
        if ($null -ne $dnsObject) {
            $dnsValues = @(Get-SafePropertyValue -Object $dnsObject -Name 'ServerAddresses')
        }

        $items.Add([pscustomobject]@{
            interface_alias = Get-SafePropertyValue -Object $cfg -Name 'InterfaceAlias'
            interface_index = Get-SafePropertyValue -Object $cfg -Name 'InterfaceIndex'
            ipv4_addresses = @($ipv4Objects | Where-Object { $null -ne $_ } | ForEach-Object {
                [pscustomobject]@{
                    address = Get-SafePropertyValue -Object $_ -Name 'IPAddress'
                    prefix_length = Get-SafePropertyValue -Object $_ -Name 'PrefixLength'
                }
            })
            ipv6_addresses = @($ipv6Objects | Where-Object { $null -ne $_ } | ForEach-Object {
                [pscustomobject]@{
                    address = Get-SafePropertyValue -Object $_ -Name 'IPAddress'
                    prefix_length = Get-SafePropertyValue -Object $_ -Name 'PrefixLength'
                }
            })
            ipv4_gateway = @($gatewayObjects | Where-Object { $null -ne $_ } | ForEach-Object {
                $nextHop = Get-SafePropertyValue -Object $_ -Name 'NextHop'
                if ($null -ne $nextHop) { $nextHop }
            })
            dns_servers = @($dnsValues | Where-Object { $null -ne $_ })
        }) | Out-Null
    }
    return $items.ToArray()
}
$network.ipv4_routes = Invoke-CollectorSection 'network.routes' {
    Get-NetRoute -AddressFamily IPv4 |
        Where-Object { $_.State -eq 'Alive' } |
        Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, ifIndex |
        Sort-Object DestinationPrefix, RouteMetric
}
$network.dns_client = Invoke-CollectorSection 'network.dns_client' {
    Get-DnsClient |
        Select-Object InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseSuffixWhenRegistering
}

$security = [ordered]@{}
$security.firewall_profiles = Invoke-CollectorSection 'security.firewall' {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName
}
$security.defender = Invoke-CollectorSection 'security.defender' {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus |
            Select-Object AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                IoavProtectionEnabled, NISEnabled, AMServiceEnabled, AntivirusSignatureLastUpdated,
                QuickScanAge, FullScanAge
    }
    else {
        [pscustomobject]@{ available = $false }
    }
}
$security.rdp = Invoke-CollectorSection 'security.rdp' {
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
    [pscustomobject]@{ enabled = ($rdp.fDenyTSConnections -eq 0) }
}
$security.local_administrators = Invoke-CollectorSection 'security.local_administrators' {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -SID 'S-1-5-32-544' |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    else {
        [pscustomobject]@{ available = $false }
    }
}

$services = [ordered]@{}
$services.windows_services = Invoke-CollectorSection 'services.windows_services' {
    $svc = @(Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName |
        Sort-Object Name)
    [pscustomobject]@{
        count = $svc.Count
        items = $svc
        note = 'Per-user service instances can change between interactive sessions.'
    }
}
$services.scheduled_tasks = Invoke-CollectorSection 'services.scheduled_tasks' {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = @(Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Sort-Object TaskPath, TaskName)
        [pscustomobject]@{
            count = $tasks.Count
            visibility = $(if ($IsAdministrator) { 'full_expected' } else { 'permission-dependent' })
            items = $tasks
        }
    }
    else {
        [pscustomobject]@{ available = $false; count = 0; visibility = 'unavailable'; items = @() }
    }
}
$services.server_roles = Invoke-CollectorSection 'services.server_roles' {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed |
            Select-Object Name, DisplayName, FeatureType
    }
    else {
        [pscustomobject]@{ available = $false; note = 'Get-WindowsFeature indisponivel neste sistema.' }
    }
}

$optional = [ordered]@{}
if ($IncludeLocalUsers) {
    $optional.local_users = Invoke-CollectorSection 'optional.local_users' {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            Get-LocalUser |
                Select-Object Name, Enabled, LastLogon, PasswordExpires, UserMayChangePassword, PasswordRequired
        }
        else {
            [pscustomobject]@{ available = $false }
        }
    }
}
if ($IncludeInstalledSoftware) {
    $optional.installed_software = Invoke-CollectorSection 'optional.installed_software' {
        Get-InstalledSoftwareFromRegistry
    }
}

$activeDirectory = [ordered]@{
    requested = (-not $SkipAD)
    collected = $false
}

if (-not $SkipAD) {
    $adModuleAvailable = Invoke-CollectorSection 'ad.module' {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'Modulo ActiveDirectory nao encontrado. Instale RSAT/AD DS Tools no host de coleta.'
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    }

    if ($adModuleAvailable) {
        $activeDirectory.collected = $true
        $activeDirectory.forest = Invoke-CollectorSection 'ad.forest' {
            Get-ADForest | Select-Object Name, RootDomain, ForestMode, SchemaMaster, DomainNamingMaster, GlobalCatalogs, Domains, Sites
        }
        $activeDirectory.domain = Invoke-CollectorSection 'ad.domain' {
            Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator, RIDMaster, InfrastructureMaster, DistinguishedName
        }
        $activeDirectory.domain_controllers = Invoke-CollectorSection 'ad.domain_controllers' {
            Get-ADDomainController -Filter * |
                Select-Object HostName, IPv4Address, Site, IsGlobalCatalog, IsReadOnly, OperatingSystem, OperatingSystemVersion
        }
        $activeDirectory.organizational_units = Invoke-CollectorSection 'ad.organizational_units' {
            Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
                Select-Object Name, DistinguishedName, ProtectedFromAccidentalDeletion
        }
        $activeDirectory.groups = Invoke-CollectorSection 'ad.groups' {
            Get-ADGroup -Filter * -Properties Members |
                Select-Object Name, DistinguishedName, GroupCategory, GroupScope,
                    @{Name='MemberCount';Expression={ @($_.Members).Count }}
        }
        $activeDirectory.password_policy = Invoke-CollectorSection 'ad.password_policy' {
            Get-ADDefaultDomainPasswordPolicy |
                Select-Object ComplexityEnabled, LockoutDuration, LockoutObservationWindow, LockoutThreshold,
                    MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount, ReversibleEncryptionEnabled
        }
        $activeDirectory.trusts = Invoke-CollectorSection 'ad.trusts' {
            Get-ADTrust -Filter * |
                Select-Object Name, Source, Target, Direction, TrustType, ForestTransitive, IntraForest, SIDFilteringForestAware
        }
        $activeDirectory.sites = Invoke-CollectorSection 'ad.sites' {
            if (Get-Command Get-ADReplicationSite -ErrorAction SilentlyContinue) {
                Get-ADReplicationSite -Filter * | Select-Object Name, DistinguishedName
            }
        }
        $activeDirectory.subnets = Invoke-CollectorSection 'ad.subnets' {
            if (Get-Command Get-ADReplicationSubnet -ErrorAction SilentlyContinue) {
                Get-ADReplicationSubnet -Filter * -Properties Site | Select-Object Name, Site, DistinguishedName
            }
        }
        $activeDirectory.object_summary = Invoke-CollectorSection 'ad.object_summary' {
            $staleCutoff = (Get-Date).AddDays(-90)
            $users = Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires
            $computers = Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem
            [pscustomobject]@{
                users_total = @($users).Count
                users_enabled = @($users | Where-Object Enabled).Count
                users_disabled = @($users | Where-Object { -not $_.Enabled }).Count
                users_password_never_expires = @($users | Where-Object PasswordNeverExpires).Count
                computers_total = @($computers).Count
                computers_enabled = @($computers | Where-Object Enabled).Count
                computers_disabled = @($computers | Where-Object { -not $_.Enabled }).Count
                computers_stale_90_days = @($computers | Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $staleCutoff }).Count
                server_os_count = @($computers | Where-Object { $_.OperatingSystem -like '*Server*' }).Count
            }
        }

        if (-not $SkipGPO) {
            $activeDirectory.gpo = Invoke-CollectorSection 'ad.gpo' {
                if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
                    throw 'Modulo GroupPolicy nao encontrado. Instale GPMC/RSAT Group Policy Management Tools.'
                }
                Import-Module GroupPolicy -ErrorAction Stop
                Get-GPO -All |
                    Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime, Owner
            }
        }
        else {
            $activeDirectory.gpo = [pscustomobject]@{ skipped = $true }
        }
    }
}

# Compatibilidade com Windows PowerShell 5.1:
# Converter Generic List explicitamente para array evita
# System.ArgumentException: Argument types do not match.
$collectorErrorsArray = $script:CollectorErrors.ToArray()
$collectorLimitationsArray = $script:CollectorLimitations.ToArray()
$collectorWarningsArray = $script:CollectorWarnings.ToArray()

$result = [ordered]@{
    metadata = $metadata
    data = [ordered]@{
        system = $system
        network = $network
        security = $security
        services = $services
        optional = $optional
        active_directory = $activeDirectory
    }
    errors = $collectorErrorsArray
    limitations = $collectorLimitationsArray
    warnings = $collectorWarningsArray
}

$EndTime = Get-Date
$result.metadata.duration_seconds = [Math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
$result.metadata.error_count = $collectorErrorsArray.Count
$result.metadata.limitation_count = $collectorLimitationsArray.Count
$result.metadata.warning_count = $collectorWarningsArray.Count

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$timestampFile = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$labelPart = $(if ($SafeRunLabel) { "_$SafeRunLabel" } else { '' })
$outputFile = Join-Path $OutputDirectory ("{0}_{1}_{2}{3}.json" -f $CollectorName, $env:COMPUTERNAME, $timestampFile, $labelPart)

$jsonText = ($result | ConvertTo-Json -Depth 15) + [Environment]::NewLine
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputFile, $jsonText, $utf8NoBom)

$hash = Get-FileHash -Path $outputFile -Algorithm SHA256
$hashFile = "$outputFile.sha256"
[System.IO.File]::WriteAllText(
    $hashFile,
    ("{0}  {1}{2}" -f $hash.Hash.ToLowerInvariant(), (Split-Path $outputFile -Leaf), [Environment]::NewLine),
    [System.Text.Encoding]::ASCII
)

Write-Host "Collector finalizado."
Write-Host "JSON:        $outputFile"
Write-Host "SHA256:      $hashFile"
Write-Host "Erros:       $($result.metadata.error_count)"
Write-Host "Limitacoes:  $($result.metadata.limitation_count)"
Write-Host "Avisos:      $($result.metadata.warning_count)"
