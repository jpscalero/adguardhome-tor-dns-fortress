<#
.SYNOPSIS
    Aplica el hardening adicional que permite la edicion de Windows detectada.

.DESCRIPTION
    La fortaleza DNS es la misma en Home, Pro, Education y Enterprise. Este
    script solo anade modulos nativos segun el perfil:

      Home       -> no aplica modulos adicionales (solo nucleo).
      Pro        -> registro de firewall, registro DNS Client y auditoria de
                    Defender (ASR / Network Protection / Controlled Folder Access).
      Education  -> lo anterior + comprobaciones de AppLocker, App Control y
                    Credential Guard.
      Enterprise -> lo anterior + informe consolidado de empresa.

    Nada de AppLocker, App Control/WDAC, Credential Guard, BitLocker, Hyper-V ni
    Application Guard se activa o bloquea automaticamente. Esos modulos son de
    solo lectura: comprueban el estado y lo dejan en el informe.

    Los cambios de firewall, registro DNS y Defender se guardan en
    edition-hardening.state.json para poder revertirlos con -Undo.

.PARAMETER TargetDir
    Carpeta de AdGuard Home. Por defecto FORTRESS_DIR o C:\AdGuardHome.

.PARAMETER Edition
    Auto (detectar), Home, Pro, Education o Enterprise. Forzar una edicion no
    inventa capacidades que el sistema no tenga: los modulos no disponibles se
    omiten.

.PARAMETER DryRun
    Muestra el perfil y los modulos que se aplicarian, sin cambiar nada.

.PARAMETER Undo
    Revierte los cambios guardados en edition-hardening.state.json.

.PARAMETER Force
    Permite continuar si el archivo de estado esta corrupto. No sobrescribe un
    estado valido.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -DryRun

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [ValidateSet('Auto', 'Home', 'Pro', 'Education', 'Enterprise')]
    [string]$Edition = 'Auto',
    [switch]$DryRun,
    [switch]$Undo,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host ('  -> ' + $Message) -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host ('  -> AVISO: ' + $Message) -ForegroundColor Yellow
}

function Write-Skip {
    param([string]$Message)
    Write-Host ('  -> OMITIDO: ' + $Message) -ForegroundColor DarkGray
}

function Write-JsonNoBom {
    param(
        [string]$Path,
        [object]$Object
    )
    $json = $Object | ConvertTo-Json -Depth 12
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $json, $utf8)
}

function Read-HardeningState {
    param([string]$Path)
    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

function New-HardeningState {
    return [pscustomobject]@{
        Version   = 1
        CreatedAt = (Get-Date).ToString('o')
        Applied   = @()
        Firewall  = $null
        DnsClient = $null
        Defender  = $null
    }
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-FirewallLogging {
    param([string]$StatePath, $State)

    $profiles = @(Get-NetFirewallProfile -Profile Domain, Private, Public -ErrorAction Stop)
    if ($profiles.Count -eq 0) { throw 'No se pudieron leer los perfiles del firewall.' }

    $capture = @{}
    foreach ($p in $profiles) {
        $capture[[string]$p.Name] = [pscustomobject]@{
            LogBlocked          = [bool]$p.LogBlocked
            LogMaxSizeKilobytes = [int]$p.LogMaxSizeKilobytes
            LogFileName         = [string]$p.LogFileName
        }
    }

    $State.Firewall = [pscustomobject]$capture
    $State.Applied = @($State.Applied) + 'FirewallLogging'
    Write-JsonNoBom -Path $StatePath -Object $State

    Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked 'True' -LogMaxSizeKilobytes 16384 -ErrorAction Stop
}

function Restore-FirewallLogging {
    param($State)

    if (-not $State.Firewall) { return }
    foreach ($property in $State.Firewall.PSObject.Properties) {
        $saved = $property.Value
        $logBlocked = if ([bool]$saved.LogBlocked) { 'True' } else { 'False' }
        Set-NetFirewallProfile -Profile $property.Name -LogBlocked $logBlocked -LogMaxSizeKilobytes ([int]$saved.LogMaxSizeKilobytes) -ErrorAction Stop
    }
}

function Invoke-DnsClientLog {
    param([string]$StatePath, $State)

    $logName = 'Microsoft-Windows-DNS-Client/Operational'
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not $log) { throw ('No existe el canal {0}.' -f $logName) }

    $State.DnsClient = [pscustomobject]@{
        Enabled = [bool]$log.IsEnabled
    }
    $State.Applied = @($State.Applied) + 'DnsClientLog'
    Write-JsonNoBom -Path $StatePath -Object $State

    if (-not $log.IsEnabled) {
        & wevtutil.exe sl $logName /e:true | Out-Null
        if ($LASTEXITCODE -ne 0) { throw ('wevtutil no pudo activar {0}.' -f $logName) }
    }
}

function Restore-DnsClientLog {
    param($State)

    if (-not $State.DnsClient) { return }
    if (-not [bool]$State.DnsClient.Enabled) {
        & wevtutil.exe sl 'Microsoft-Windows-DNS-Client/Operational' /e:false | Out-Null
    }
}

function Get-AsrRuleIds {
    return @(
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
        '3B576869-A4EC-4529-8536-B80A7769E899',
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
        'D3E037E1-3EB8-44C8-A917-57927947596D',
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',
        'D1E49AAC-8F56-4280-B9BA-993A6D77406C',
        'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'
    )
}

function Invoke-DefenderAudit {
    param([string]$StatePath, $State)

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw 'El modulo Defender no esta disponible.'
    }
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $status -or -not $status.AntivirusEnabled) {
        throw 'Microsoft Defender Antivirus no esta activo; no se tocan ASR/NP/CFA.'
    }

    $prefs = Get-MpPreference -ErrorAction Stop
    $existingIds = @($prefs.AttackSurfaceReductionRules_Ids)
    $existing = @{}
    foreach ($id in $existingIds) {
        if ($id) { $existing[[string]$id] = $true }
    }

    $toAdd = @()
    foreach ($id in (Get-AsrRuleIds)) {
        if (-not $existing.ContainsKey($id)) { $toAdd += $id }
    }

    $State.Defender = [pscustomobject]@{
        NetworkProtection      = [int]$prefs.EnableNetworkProtection
        ControlledFolderAccess = [int]$prefs.EnableControlledFolderAccess
        AsrIds                 = $existingIds
        AsrActions             = @($prefs.AttackSurfaceReductionRules_Actions)
        AddedAsr               = $toAdd
    }
    $State.Applied = @($State.Applied) + 'DefenderAudit'
    Write-JsonNoBom -Path $StatePath -Object $State

    if ([int]$prefs.EnableNetworkProtection -eq 0) {
        Set-MpPreference -EnableNetworkProtection 2 -ErrorAction Stop
    }
    if ([int]$prefs.EnableControlledFolderAccess -eq 0) {
        Set-MpPreference -EnableControlledFolderAccess 2 -ErrorAction Stop
    }
    foreach ($id in $toAdd) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction Stop
    }
}

function Restore-DefenderAudit {
    param($State)

    if (-not $State.Defender) { return }
    $saved = $State.Defender

    # Restaura el valor exacto: 0=off, 1=bloqueo, 2=auditoria.
    Set-MpPreference -EnableNetworkProtection ([int]$saved.NetworkProtection) -ErrorAction SilentlyContinue
    Set-MpPreference -EnableControlledFolderAccess ([int]$saved.ControlledFolderAccess) -ErrorAction SilentlyContinue
    foreach ($id in @($saved.AddedAsr)) {
        if (-not $id) { continue }
        try {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction Stop
        } catch {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue
        }
    }
}

function Get-AppControlReadiness {
    $path = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
    $policies = @(Get-ChildItem -Path $path -Filter '*.cip' -ErrorAction SilentlyContinue)
    return [pscustomobject]@{
        Path          = $path
        PolicyCount   = $policies.Count
        PolicyNames   = @($policies | ForEach-Object { $_.Name })
    }
}

function Get-AppLockerReadiness {
    $cmd = Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue
    $service = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    $result = [pscustomobject]@{
        CmdletAvailable = ($null -ne $cmd)
        ServiceStatus   = if ($service) { [string]$service.Status } else { 'ausente' }
        HasPolicy       = $false
        Error           = ''
    }
    if ($cmd) {
        try {
            $xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $result.HasPolicy = [bool]($xml -match '<RuleCollection')
        } catch {
            $result.Error = $_.Exception.Message
        }
    }
    return $result
}

function Get-CredentialGuardReadiness {
    $result = [pscustomobject]@{
        VbsStatus  = 'desconocido'
        Configured = @()
        Running    = @()
        Error      = ''
    }
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        if ($dg) {
            $result.VbsStatus = [string]$dg.VirtualizationBasedSecurityStatus
            $result.Configured = @($dg.SecurityServicesConfigured)
            $result.Running = @($dg.SecurityServicesRunning)
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

function Get-BitLockerReadiness {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Available = $false; ProtectionStatus = 'no disponible'; VolumeStatus = ''; EncryptionPercentage = 0 }
    }
    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        return [pscustomobject]@{
            Available           = $true
            ProtectionStatus    = [string]$volume.ProtectionStatus
            VolumeStatus        = [string]$volume.VolumeStatus
            EncryptionPercentage = [int]$volume.EncryptionPercentage
        }
    } catch {
        return [pscustomobject]@{ Available = $true; ProtectionStatus = 'error'; VolumeStatus = $_.Exception.Message; EncryptionPercentage = 0 }
    }
}

function Get-VirtualizationReadiness {
    $hyperV = 'no encontrado'
    $sandbox = 'no encontrado'
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction SilentlyContinue
        if ($feature) { $hyperV = [string]$feature.State }
    } catch { }
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction SilentlyContinue
        if ($feature) { $sandbox = [string]$feature.State }
    } catch { }
    return [pscustomobject]@{ HyperV = $hyperV; Sandbox = $sandbox }
}

function Get-AppGuardReadiness {
    $state = 'no encontrado'
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-ApplicationGuard' -ErrorAction SilentlyContinue
        if ($feature) { $state = [string]$feature.State }
    } catch { }
    return [pscustomobject]@{ Feature = 'Windows-Defender-ApplicationGuard'; State = $state }
}

function Get-AuditPolicyReadiness {
    $lines = @()
    $ok = $false
    try {
        $lines = @(& auditpol.exe /get /category:* /r 2>$null | Select-Object -First 12)
        $ok = ($LASTEXITCODE -eq 0)
    } catch { }
    return [pscustomobject]@{ Available = $ok; Sample = $lines }
}

function Write-HardeningReport {
    param(
        [string]$Path,
        $WindowsProfile,
        [array]$Applied,
        [array]$Skipped,
        [object]$Readiness,
        [array]$Warnings,
        [bool]$Undo = $false
    )

    $report = [pscustomobject]@{
        Version      = 1
        Timestamp    = (Get-Date).ToString('o')
        Undo         = $Undo
        Profile      = $WindowsProfile.Summary
        EditionId    = $WindowsProfile.EditionId
        EditionName  = $WindowsProfile.EditionName
        Tier         = $WindowsProfile.Tier
        TierName     = $WindowsProfile.TierName
        Applied      = $Applied
        Skipped      = $Skipped
        Readiness    = $Readiness
        Warnings     = $Warnings
    }
    Write-JsonNoBom -Path $Path -Object $report
}

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------

$editionScript = Join-Path $PSScriptRoot 'windows-edition.ps1'
if (-not (Test-Path $editionScript)) {
    throw ('Falta {0}. Descomprime el repositorio completo.' -f $editionScript)
}
. $editionScript

$profile = Get-WindowsFortressProfile -Edition $Edition
Show-WindowsFortressProfile -WindowsProfile $profile

if (-not $profile.SupportedOS) {
    Write-Warn 'Esta edicion de Windows no esta soportada oficialmente. Se aplicara solo lo que sea seguro.'
}

$isAdmin = Test-Admin
if ((-not $DryRun) -and (-not $isAdmin)) {
    Write-Host '[ERROR] Ejecuta este script como Administrador.' -ForegroundColor Red
    exit 1
}

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}
if (-not (Test-Path $TargetDir)) {
    throw ('No existe {0}. Instala primero la fortaleza.' -f $TargetDir)
}

$statePath = Join-Path $TargetDir 'edition-hardening.state.json'
$reportPath = Join-Path $TargetDir 'edition-hardening.report.json'

if ($DryRun) {
    Write-Step 'Modulos que se aplicarian (DRY-RUN):'
    foreach ($module in $profile.Modules) {
        if ($module.Enabled) {
            Write-Host ('  [SI] {0}: {1}' -f $module.Id, $module.Description)
        } else {
            Write-Host ('  [NO] {0}: {1}' -f $module.Id, $module.Reason) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host 'DRY-RUN completado. No se ha cambiado nada.' -ForegroundColor Green
    exit 0
}

if ($Undo) {
    if (-not (Test-Path $statePath)) {
        Write-Step 'No hay cambios de hardening de edicion que revertir.'
        exit 0
    }
    try {
        $state = Read-HardeningState -Path $statePath
    } catch {
        Write-Host ('[ERROR] No se pudo leer {0}: {1}' -f $statePath, $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    $warnings = @()
    $failed = $false
    Write-Step 'Revirtiendo registros de firewall...'
    try { Restore-FirewallLogging -State $state; Write-Ok 'Firewall restaurado.' }
    catch { $warnings += ('Firewall: ' + $_.Exception.Message); $failed = $true; Write-Warn $_.Exception.Message }

    Write-Step 'Revirtiendo registro DNS Client...'
    try { Restore-DnsClientLog -State $state; Write-Ok 'Registro DNS restaurado.' }
    catch { $warnings += ('DNS Client: ' + $_.Exception.Message); $failed = $true; Write-Warn $_.Exception.Message }

    Write-Step 'Revirtiendo auditoria de Defender...'
    try { Restore-DefenderAudit -State $state; Write-Ok 'Defender restaurado.' }
    catch { $warnings += ('Defender: ' + $_.Exception.Message); $failed = $true; Write-Warn $_.Exception.Message }

    Write-HardeningReport -Path $reportPath -WindowsProfile $profile -Applied @() -Skipped @() -Readiness ([pscustomobject]@{}) -Warnings $warnings -Undo $true

    if ($failed) {
        Write-Warn 'Algunos cambios no se pudieron revertir. Se conserva el archivo de estado para reintentar.'
        exit 1
    }
    Remove-Item -Path $statePath -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host 'Hardening de edicion revertido.' -ForegroundColor Green
    exit 0
}

$state = $null
if (Test-Path $statePath) {
    try {
        $state = Read-HardeningState -Path $statePath
    } catch {
        if (-not $Force) {
            Write-Host ('[ERROR] El estado {0} esta corrupto. Usa -Force para ignorarlo o borralo a mano.' -f $statePath) -ForegroundColor Red
            exit 1
        }
        Write-Warn 'Estado corrupto ignorado por -Force.'
        $state = $null
    }
}
if (-not $state) { $state = New-HardeningState }

$applied = @()
$skipped = @()
$warnings = @()
$readiness = [ordered]@{}

Write-Step 'Aplicando modulos del perfil...'
foreach ($module in $profile.Modules) {
    if (-not $module.Enabled) {
        $skipped += [pscustomobject]@{ Id = $module.Id; Reason = $module.Reason }
        Write-Skip ('{0}: {1}' -f $module.Id, $module.Reason)
        continue
    }

    switch ($module.Id) {
        'Core' {
            $applied += [pscustomobject]@{ Id = $module.Id; Status = 'nucleo' }
            Write-Ok 'Core: sin cambios adicionales.'
        }
        'FirewallLogging' {
            if (@($state.Applied) -contains 'FirewallLogging') {
                Write-Ok 'FirewallLogging: ya aplicado.'
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'ya aplicado' }
            } else {
                try {
                    Invoke-FirewallLogging -StatePath $statePath -State $state
                    $applied += [pscustomobject]@{ Id = $module.Id; Status = 'aplicado' }
                    Write-Ok 'FirewallLogging: registro de firewall activado.'
                } catch {
                    $warnings += ('FirewallLogging: ' + $_.Exception.Message)
                    Write-Warn $_.Exception.Message
                }
            }
        }
        'DnsClientLog' {
            if (@($state.Applied) -contains 'DnsClientLog') {
                Write-Ok 'DnsClientLog: ya aplicado.'
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'ya aplicado' }
            } else {
                try {
                    Invoke-DnsClientLog -StatePath $statePath -State $state
                    $applied += [pscustomobject]@{ Id = $module.Id; Status = 'aplicado' }
                    Write-Ok 'DnsClientLog: canal operativo activado.'
                } catch {
                    $warnings += ('DnsClientLog: ' + $_.Exception.Message)
                    Write-Warn $_.Exception.Message
                }
            }
        }
        'DefenderAudit' {
            if (@($state.Applied) -contains 'DefenderAudit') {
                Write-Ok 'DefenderAudit: ya aplicado.'
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'ya aplicado' }
            } else {
                try {
                    Invoke-DefenderAudit -StatePath $statePath -State $state
                    $applied += [pscustomobject]@{ Id = $module.Id; Status = 'aplicado' }
                    Write-Ok 'DefenderAudit: ASR/NP/CFA en auditoria.'
                } catch {
                    $warnings += ('DefenderAudit: ' + $_.Exception.Message)
                    Write-Warn $_.Exception.Message
                }
            }
        }
        'AppControlReadiness' {
            try {
                $readiness.AppControl = Get-AppControlReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('AppControlReadiness: {0} politica(s) .cip.' -f $readiness.AppControl.PolicyCount)
            } catch {
                $warnings += ('AppControlReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'AppLockerReadiness' {
            try {
                $readiness.AppLocker = Get-AppLockerReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('AppLockerReadiness: servicio={0}, politica={1}' -f $readiness.AppLocker.ServiceStatus, $readiness.AppLocker.HasPolicy)
            } catch {
                $warnings += ('AppLockerReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'CredentialGuardReadiness' {
            try {
                $readiness.CredentialGuard = Get-CredentialGuardReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('CredentialGuardReadiness: VBS={0}, running={1}' -f $readiness.CredentialGuard.VbsStatus, (@($readiness.CredentialGuard.Running) -join ','))
            } catch {
                $warnings += ('CredentialGuardReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'BitLockerReadiness' {
            try {
                $readiness.BitLocker = Get-BitLockerReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('BitLockerReadiness: {0}' -f $readiness.BitLocker.ProtectionStatus)
            } catch {
                $warnings += ('BitLockerReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'VirtualizationReadiness' {
            try {
                $readiness.Virtualization = Get-VirtualizationReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('VirtualizationReadiness: Hyper-V={0}, Sandbox={1}' -f $readiness.Virtualization.HyperV, $readiness.Virtualization.Sandbox)
            } catch {
                $warnings += ('VirtualizationReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'AppGuardReadiness' {
            try {
                $readiness.AppGuard = Get-AppGuardReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'solo lectura' }
                Write-Ok ('AppGuardReadiness: {0}' -f $readiness.AppGuard.State)
            } catch {
                $warnings += ('AppGuardReadiness: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        'EnterpriseReport' {
            try {
                $readiness.AuditPolicy = Get-AuditPolicyReadiness
                $applied += [pscustomobject]@{ Id = $module.Id; Status = 'informe' }
                Write-Ok 'EnterpriseReport: informe consolidado preparado.'
            } catch {
                $warnings += ('EnterpriseReport: ' + $_.Exception.Message)
                Write-Warn $_.Exception.Message
            }
        }
        default {
            Write-Skip ('{0}: modulo sin implementacion.' -f $module.Id)
        }
    }
}

Write-HardeningReport -Path $reportPath -WindowsProfile $profile -Applied $applied -Skipped $skipped -Readiness $readiness -Warnings $warnings

Write-Host ''
Write-Host ('Hardening de edicion completado. Informe: {0}' -f $reportPath) -ForegroundColor Green
if ($warnings.Count -gt 0) {
    Write-Host ('  {0} aviso(s). Revisa el informe.' -f $warnings.Count) -ForegroundColor Yellow
}
exit 0
