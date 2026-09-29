<#
.SYNOPSIS
  Orizon IT - Produto 01 / Infrastructure Assessment
  Windows + Active Directory Discovery Collector v0.3

.DESCRIPTION
  Coletor read-only para inventário técnico de host Windows e, opcionalmente,
  Active Directory e GPO. A v0.3 adiciona inatividade AD, secure channel, SMB e postura FTP. Não altera configurações e não envia dados para rede.

  Saída: JSON + arquivo SHA256 no diretório informado.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\P01_Windows_AD_Discovery_Collector_v0.3.ps1 `
    -OutputDirectory C:\P01\output -RunLabel W01-domain-user

.NOTES
  Versão: 0.3.0
  Schema: 0.3
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
    [switch]$IncludeInstalledSoftware,
    [switch]$IncludeIdentityDetails,
    [int]$InactiveThresholdDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$CollectorName = 'P01-Windows-AD-Discovery-Collector'
$CollectorVersion = '0.3.0'
$SchemaVersion = '0.3'
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


function ConvertTo-IsoDateOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('o') }
    catch { return $null }
}

function Get-DaysSince {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [int][Math]::Floor(((Get-Date) - [datetime]$Value).TotalDays) }
    catch { return $null }
}

function Resolve-PrincipalSidSafe {
    param([string]$AccountName)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $null }
    try {
        $nt = New-Object System.Security.Principal.NTAccount($AccountName)
        return $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch { return $null }
}

function Test-IsBroadPrincipal {
    param([string]$AccountName, [string]$Sid)
    $broadSids = @('S-1-1-0','S-1-5-7','S-1-5-32-546') # Everyone, Anonymous Logon, BUILTIN\Guests
    if ($Sid -and ($broadSids -contains $Sid)) { return $true }
    $name = ([string]$AccountName).ToLowerInvariant()
    return ($name -match '(^|\\)(everyone|todos|anonymous logon|logon an[oô]nimo|guests|convidados)$')
}

function Test-IsWidePrincipal {
    param([string]$AccountName, [string]$Sid)
    if (Test-IsBroadPrincipal -AccountName $AccountName -Sid $Sid) { return $true }
    if ($Sid -eq 'S-1-5-11') { return $true } # Authenticated Users
    $name = ([string]$AccountName).ToLowerInvariant()
    return ($name -match '(^|\\)(authenticated users|usu[aá]rios autenticados|domain users|usu[aá]rios do dom[ií]nio)$')
}

function Test-IsShareWriteRight {
    param($AccessRight)
    $v = ([string]$AccessRight).ToLowerInvariant()
    return ($v -eq 'full' -or $v -eq 'change')
}

function Test-IsNtfsWriteRight {
    param($FileSystemRights)
    $v = ([string]$FileSystemRights)
    return ($v -match 'FullControl|Modify|Write|CreateFiles|AppendData|WriteData|WriteAttributes|WriteExtendedAttributes')
}

function Get-SmbShareAssessment {
    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ available = $false; reason = 'Get-SmbShare unavailable'; items = @() }
    }

    foreach ($share in @(Get-SmbShare -ErrorAction Stop | Sort-Object Name)) {
        $shareAccess = @()
        $ntfsAccess = @()
        $shareAccessAvailable = $true
        $ntfsAccessAvailable = $true

        try {
            $shareAccess = @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | ForEach-Object {
                $sid = Resolve-PrincipalSidSafe -AccountName ([string]$_.AccountName)
                [pscustomobject]@{
                    account = [string]$_.AccountName
                    sid = $sid
                    access_control_type = [string]$_.AccessControlType
                    access_right = [string]$_.AccessRight
                    broad_principal = (Test-IsBroadPrincipal -AccountName ([string]$_.AccountName) -Sid $sid)
                    wide_principal = (Test-IsWidePrincipal -AccountName ([string]$_.AccountName) -Sid $sid)
                    write_capable = (([string]$_.AccessControlType -eq 'Allow') -and (Test-IsShareWriteRight -AccessRight $_.AccessRight))
                }
            })
        }
        catch {
            $shareAccessAvailable = $false
            Add-CollectorLimitation -Section ("shares.smb.share_acl.{0}" -f $share.Name) -Message $_.Exception.Message -ExceptionType $_.Exception.GetType().FullName
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$share.Path) -and (Test-Path -LiteralPath $share.Path)) {
            try {
                $acl = Get-Acl -LiteralPath $share.Path -ErrorAction Stop
                $ntfsAccess = @($acl.Access | ForEach-Object {
                    $account = [string]$_.IdentityReference.Value
                    $sid = Resolve-PrincipalSidSafe -AccountName $account
                    [pscustomobject]@{
                        account = $account
                        sid = $sid
                        access_control_type = [string]$_.AccessControlType
                        rights = [string]$_.FileSystemRights
                        inherited = [bool]$_.IsInherited
                        broad_principal = (Test-IsBroadPrincipal -AccountName $account -Sid $sid)
                        wide_principal = (Test-IsWidePrincipal -AccountName $account -Sid $sid)
                        write_capable = (([string]$_.AccessControlType -eq 'Allow') -and (Test-IsNtfsWriteRight -FileSystemRights $_.FileSystemRights))
                    }
                })
            }
            catch {
                $ntfsAccessAvailable = $false
                Add-CollectorLimitation -Section ("shares.smb.ntfs_acl.{0}" -f $share.Name) -Message $_.Exception.Message -ExceptionType $_.Exception.GetType().FullName
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$share.Path)) {
            $ntfsAccessAvailable = $false
        }

        $shareBroadWrite = @($shareAccess | Where-Object { $_.broad_principal -and $_.write_capable })
        $ntfsBroadWrite = @($ntfsAccess | Where-Object { $_.broad_principal -and $_.write_capable })
        $confirmed = $false
        foreach ($sa in $shareBroadWrite) {
            foreach ($na in $ntfsBroadWrite) {
                if ($sa.sid -and $na.sid -and ($sa.sid -eq $na.sid)) { $confirmed = $true }
                elseif (([string]$sa.account).ToLowerInvariant() -eq ([string]$na.account).ToLowerInvariant()) { $confirmed = $true }
            }
        }

        $results.Add([pscustomobject]@{
            name = [string]$share.Name
            path = [string]$share.Path
            description = [string]$share.Description
            special = [bool]$share.Special
            temporary = [bool]$share.Temporary
            share_permissions_available = $shareAccessAvailable
            ntfs_permissions_available = $ntfsAccessAvailable
            share_access = $shareAccess
            ntfs_access = $ntfsAccess
            broad_write_share = $shareBroadWrite
            broad_write_ntfs = $ntfsBroadWrite
            confirmed_broad_write = $confirmed
        }) | Out-Null
    }

    return [pscustomobject]@{ available = $true; items = $results.ToArray() }
}

function Get-WindowsFtpPosture {
    $listenerItems = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $listenerItems = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq 21 } | ForEach-Object {
                $procName = $null
                try { $procName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { }
                $addr = [string]$_.LocalAddress
                [pscustomobject]@{
                    local_address = $addr
                    local_port = [int]$_.LocalPort
                    owning_process_id = [int]$_.OwningProcess
                    process_name = $procName
                    network_exposed = ($addr -notin @('127.0.0.1','::1'))
                }
            })
        }
        catch {
            Add-CollectorLimitation -Section 'security.ftp.listeners' -Message $_.Exception.Message -ExceptionType $_.Exception.GetType().FullName
        }
    }

    $ftpServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'ftp' -or $_.DisplayName -match 'ftp'
    } | Select-Object Name, DisplayName, State, StartMode, PathName)

    $iisSites = New-Object System.Collections.Generic.List[object]
    $iisConfig = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $iisConfig) {
        try {
            [xml]$xml = Get-Content -LiteralPath $iisConfig -Raw -ErrorAction Stop
            $sitesNode = $xml.configuration.'system.applicationHost'.sites
            if ($null -ne $sitesNode) {
                foreach ($site in @($sitesNode.site)) {
                    $ftpBindings = @($site.bindings.binding | Where-Object { [string]$_.protocol -eq 'ftp' })
                    if ($ftpBindings.Count -eq 0) { continue }
                    $ssl = $site.ftpServer.security.ssl
                    $control = if ($null -ne $ssl) { [string]$ssl.controlChannelPolicy } else { '' }
                    $data = if ($null -ne $ssl) { [string]$ssl.dataChannelPolicy } else { '' }
                    $required = ($control -eq 'SslRequire' -and $data -eq 'SslRequire')
                    $plaintextAllowed = -not $required
                    $iisSites.Add([pscustomobject]@{
                        name = [string]$site.name
                        id = [string]$site.id
                        bindings = @($ftpBindings | ForEach-Object { [string]$_.bindingInformation })
                        control_channel_policy = $control
                        data_channel_policy = $data
                        tls_required = $required
                        plaintext_allowed = $plaintextAllowed
                    }) | Out-Null
                }
            }
        }
        catch {
            Add-CollectorWarning -Section 'security.ftp.iis' -Message ("IIS FTP config could not be parsed: {0}" -f $_.Exception.Message)
        }
    }

    $exposed = @($listenerItems | Where-Object { $_.network_exposed }).Count -gt 0
    $plaintextAllowed = @($iisSites.ToArray() | Where-Object { $_.plaintext_allowed }).Count -gt 0
    $allRequired = ($iisSites.Count -gt 0 -and @($iisSites.ToArray() | Where-Object { -not $_.tls_required }).Count -eq 0)
    $encryptionStatus = 'not_detected'
    if ($exposed -and $plaintextAllowed) { $encryptionStatus = 'plaintext_allowed' }
    elseif ($exposed -and $allRequired) { $encryptionStatus = 'tls_required' }
    elseif ($exposed) { $encryptionStatus = 'unknown' }

    return [pscustomobject]@{
        listener_detected = ($listenerItems.Count -gt 0)
        network_exposed = $exposed
        listeners = $listenerItems
        services = $ftpServices
        iis_ftp_sites = $iisSites.ToArray()
        encryption_status = $encryptionStatus
        plaintext_allowed = $plaintextAllowed
    }
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
    inactive_threshold_days = [Math]::Abs($InactiveThresholdDays)
    identity_details_included = [bool]$IncludeIdentityDetails
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
        Select-Object Manufacturer, Model, Domain, PartOfDomain, DomainRole, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors
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

$security.domain_secure_channel = Invoke-CollectorSection 'security.domain_secure_channel' {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not [bool]$cs.PartOfDomain) {
        [pscustomobject]@{ domain_joined = $false; domain = [string]$cs.Domain; status = 'not_domain_joined'; healthy = $null; method = $null }
    }
    elseif ([int]$cs.DomainRole -in @(4,5)) {
        [pscustomobject]@{ domain_joined = $true; domain = [string]$cs.Domain; status = 'not_applicable_domain_controller'; healthy = $null; method = 'Win32_ComputerSystem.DomainRole' }
    }
    elseif (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
        try {
            $healthy = [bool](Test-ComputerSecureChannel -ErrorAction Stop)
            [pscustomobject]@{ domain_joined = $true; domain = [string]$cs.Domain; status = $(if ($healthy) { 'healthy' } else { 'broken' }); healthy = $healthy; method = 'Test-ComputerSecureChannel' }
        }
        catch {
            Add-CollectorLimitation -Section 'security.domain_secure_channel' -Message $_.Exception.Message -ExceptionType $_.Exception.GetType().FullName
            [pscustomobject]@{ domain_joined = $true; domain = [string]$cs.Domain; status = 'unknown'; healthy = $null; method = 'Test-ComputerSecureChannel' }
        }
    }
    else {
        [pscustomobject]@{ domain_joined = $true; domain = [string]$cs.Domain; status = 'unknown'; healthy = $null; method = $null }
    }
}
$security.ftp = Invoke-CollectorSection 'security.ftp' { Get-WindowsFtpPosture }


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


$shares = [ordered]@{}
$shares.smb = Invoke-CollectorSection 'shares.smb' { Get-SmbShareAssessment }

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
            $staleCutoff = (Get-Date).AddDays(-1 * [Math]::Abs($InactiveThresholdDays))
            $users = @(Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, LastLogonDate, whenCreated, ServicePrincipalName)
            $computers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, whenCreated, OperatingSystem, OperatingSystemVersion, PasswordLastSet)

            $staleUsersEnabled = @($users | Where-Object {
                $_.Enabled -and ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $staleCutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $staleCutoff)))
            })
            $staleUsersAll = @($users | Where-Object {
                ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $staleCutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $staleCutoff)))
            })
            $staleComputersEnabled = @($computers | Where-Object {
                $_.Enabled -and ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $staleCutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $staleCutoff)))
            })
            $staleComputersAll = @($computers | Where-Object {
                ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $staleCutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $staleCutoff)))
            })

            [pscustomobject]@{
                users_total = $users.Count
                users_enabled = @($users | Where-Object Enabled).Count
                users_disabled = @($users | Where-Object { -not $_.Enabled }).Count
                users_password_never_expires = @($users | Where-Object PasswordNeverExpires).Count
                users_stale_threshold_days = [Math]::Abs($InactiveThresholdDays)
                users_stale_enabled = $staleUsersEnabled.Count
                users_stale_all = $staleUsersAll.Count
                computers_total = $computers.Count
                computers_enabled = @($computers | Where-Object Enabled).Count
                computers_disabled = @($computers | Where-Object { -not $_.Enabled }).Count
                computers_stale_90_days = $staleComputersAll.Count
                computers_stale_threshold_days = [Math]::Abs($InactiveThresholdDays)
                computers_stale_enabled = $staleComputersEnabled.Count
                computers_stale_all = $staleComputersAll.Count
                server_os_count = @($computers | Where-Object { $_.OperatingSystem -like '*Server*' }).Count
            }
        }
        $activeDirectory.inactive_accounts = Invoke-CollectorSection 'ad.inactive_accounts' {
            $thresholdDays = [Math]::Abs($InactiveThresholdDays)
            $cutoff = (Get-Date).AddDays(-1 * $thresholdDays)
            $users = @(Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, LastLogonDate, whenCreated, ServicePrincipalName)
            $computers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, whenCreated, OperatingSystem, OperatingSystemVersion, PasswordLastSet)

            $staleUsers = @($users | Where-Object {
                $_.Enabled -and ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $cutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $cutoff)))
            })
            $staleComputers = @($computers | Where-Object {
                $_.Enabled -and ((($_.LastLogonDate) -and ($_.LastLogonDate -lt $cutoff)) -or ((-not $_.LastLogonDate) -and $_.whenCreated -and ($_.whenCreated -lt $cutoff)))
            })

            $userItems = @()
            $computerItems = @()
            if ($IncludeIdentityDetails) {
                $userItems = @($staleUsers | ForEach-Object {
                    $reference = if ($_.LastLogonDate) { $_.LastLogonDate } else { $_.whenCreated }
                    [pscustomobject]@{
                        sam_account_name = [string]$_.SamAccountName
                        enabled = [bool]$_.Enabled
                        last_logon_utc = ConvertTo-IsoDateOrNull $_.LastLogonDate
                        created_utc = ConvertTo-IsoDateOrNull $_.whenCreated
                        inactivity_days = Get-DaysSince $reference
                        inactivity_basis = $(if ($_.LastLogonDate) { 'LastLogonDate' } else { 'whenCreated_no_logon' })
                        password_never_expires = [bool]$_.PasswordNeverExpires
                        service_account_candidate = (@($_.ServicePrincipalName).Count -gt 0)
                        distinguished_name = [string]$_.DistinguishedName
                    }
                })
                $computerItems = @($staleComputers | ForEach-Object {
                    $reference = if ($_.LastLogonDate) { $_.LastLogonDate } else { $_.whenCreated }
                    [pscustomobject]@{
                        name = [string]$_.Name
                        enabled = [bool]$_.Enabled
                        last_logon_utc = ConvertTo-IsoDateOrNull $_.LastLogonDate
                        created_utc = ConvertTo-IsoDateOrNull $_.whenCreated
                        password_last_set_utc = ConvertTo-IsoDateOrNull $_.PasswordLastSet
                        inactivity_days = Get-DaysSince $reference
                        inactivity_basis = $(if ($_.LastLogonDate) { 'LastLogonDate' } else { 'whenCreated_no_logon' })
                        operating_system = [string]$_.OperatingSystem
                        operating_system_version = [string]$_.OperatingSystemVersion
                        distinguished_name = [string]$_.DistinguishedName
                    }
                })
            }

            [pscustomobject]@{
                threshold_days = $thresholdDays
                details_included = [bool]$IncludeIdentityDetails
                users = [pscustomobject]@{ enabled_stale_count = $staleUsers.Count; items = $userItems }
                computers = [pscustomobject]@{ enabled_stale_count = $staleComputers.Count; items = $computerItems }
                note = 'LastLogonDate is derived from replicated lastLogonTimestamp and is appropriate for inactivity assessment, not exact authentication auditing.'
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
        shares = $shares
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
