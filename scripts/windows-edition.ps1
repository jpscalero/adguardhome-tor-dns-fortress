<#
.SYNOPSIS
    Detecta la edicion de Windows y calcula que modulos de la fortaleza puede
    usar: Home, Pro, Education o Enterprise.

.DESCRIPTION
    La fortaleza DNS (AdGuard Home + Tor + firewall + watchdog + failsafe) es
    identica en todas las ediciones. Lo que cambia es el hardening nativo de
    Windows que se puede anadir encima:

      Home       -> solo nucleo (perfil basico).
      Pro        -> nucleo + registros de firewall/DNS + auditoria de Defender.
      Education  -> lo de Pro + comprobaciones de AppLocker/App Control/Credential Guard.
      Enterprise -> lo de Education + informe consolidado de empresa.

    Este script no cambia nada: solo detecta y devuelve un objeto con el perfil.
    Se puede dot-source desde otros scripts:

        . .\scripts\windows-edition.ps1
        $perfil = Get-WindowsFortressProfile

    Tambien se puede ejecutar directamente para ver el perfil detectado.

.NOTES
    Los modulos AppLocker, App Control/WDAC y Credential Guard son de solo
    lectura: se comprueba su estado, pero no se activan ni se bloquean
    aplicaciones automaticamente. Eso evita dejar el equipo sin poder abrir
    programas por una politica mal aplicada.
#>

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

function Get-FortressTierName {
    param([int]$Tier)
    switch ($Tier) {
        1 { return 'Basico' }
        2 { return 'Avanzado' }
        3 { return 'Educacion' }
        4 { return 'Empresa' }
        default { return 'Desconocido' }
    }
}

function Get-FortressTierId {
    param([string]$Name)
    switch ($Name) {
        'Home' { return 1 }
        'Pro' { return 2 }
        'Education' { return 3 }
        'Enterprise' { return 4 }
        default { return 0 }
    }
}

function New-FortressModuleEntry {
    param(
        [string]$Id,
        [string]$Name,
        [int]$MinTier,
        [bool]$Available,
        [string]$Description
    )

    $detectedTier = [int]$script:FortressDetectedTier
    $editionSupportsTier = ($detectedTier -ge $MinTier)

    $reason = ''
    if ((-not $Available) -or (-not $editionSupportsTier)) {
        $reason = 'No disponible en esta edicion de Windows'
    } elseif ($script:FortressEffectiveTier -lt $MinTier) {
        $reason = ('Requiere perfil {0} o superior' -f (Get-FortressTierName -Tier $MinTier))
    }

    return [pscustomobject]@{
        Id          = $Id
        Name        = $Name
        MinTier     = $MinTier
        Available   = [bool]$Available
        Enabled     = ([bool]$Available -and $editionSupportsTier -and ($script:FortressEffectiveTier -ge $MinTier))
        Description = $Description
        Reason      = $reason
    }
}

function Get-WindowsFortressProfile {
    [CmdletBinding()]
    param(
        [ValidateSet('Auto', 'Home', 'Pro', 'Education', 'Enterprise')]
        [string]$Edition = 'Auto'
    )

    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    $editionId = if ($props -and $props.EditionID) { [string]$props.EditionID } else { '' }
    $productName = if ($props -and $props.ProductName) { [string]$props.ProductName } else { '' }
    $displayVersion = if ($props -and $props.DisplayVersion) { [string]$props.DisplayVersion } else { '' }

    $build = 0
    if ($props -and $props.CurrentBuildNumber) {
        [void][int]::TryParse([string]$props.CurrentBuildNumber, [ref]$build)
    }
    if ($build -le 0) {
        $build = [Environment]::OSVersion.Version.Build
    }

    $ubr = 0
    if ($props -and $props.UBR) {
        [void][int]::TryParse([string]$props.UBR, [ref]$ubr)
    }

    $id = $editionId.ToLowerInvariant()
    $isServer = $false
    $isUnknown = $false
    $isLtsc = $false
    $isHome = $false
    $isPro = $false
    $isProWorkstation = $false
    $isProEducation = $false
    $isEducation = $false
    $isEnterprise = $false

    if ($id -in @('core', 'coren', 'corecountryspecific', 'coresinglelanguage', 'home', 'homebasic', 'homepremium', 'starter', 'cloud', 'cloudn')) {
        $isHome = $true
    } elseif ($id -in @('education', 'educationn')) {
        $isEducation = $true
    } elseif ($id -in @('enterprise', 'enterprisen', 'enterprises', 'enterprisesn', 'iotenterprise', 'iotenterprises')) {
        $isEnterprise = $true
    } elseif ($id -like 'server*') {
        $isEnterprise = $true
        $isServer = $true
    } elseif ($id -in @('professional', 'professionaln', 'professionalworkstation', 'professionalworkstationn', 'professionaleducation', 'professionaleducationn', 'pro', 'proeducation', 'proforworkstations', 'ultimate')) {
        $isPro = $true
    } else {
        # Ante una edicion desconocida se usa el perfil mas restrictivo.
        $isHome = $true
        $isUnknown = $true
    }

    if ($isPro -and ($id -like '*workstation*')) { $isProWorkstation = $true }
    if ($isPro -and ($id -like '*education*')) { $isProEducation = $true }
    if (($id -in @('enterprises', 'enterprisesn', 'iotenterprises')) -or ($productName -match 'LTSC|IoT Enterprise')) {
        $isLtsc = $true
    }

    $detectedTier = if ($isEnterprise) { 4 } elseif ($isEducation) { 3 } elseif ($isPro) { 2 } else { 1 }
    $requestedTier = $detectedTier
    $forced = ($Edition -ne 'Auto')
    if ($forced) {
        $requestedTier = Get-FortressTierId -Name $Edition
        if ($requestedTier -le 0) { $requestedTier = 1 }
    }

    # La edicion real manda: forzar un perfil nunca supera el tier detectado, de
    # modo que Home no ejecuta modulos de Pro y Pro no ejecuta los de
    # Education/Enterprise. Forzar un perfil inferior si recorta de verdad.
    $effectiveTier = [Math]::Min($requestedTier, $detectedTier)
    $forcedCapped = ($requestedTier -gt $detectedTier)

    $editionName = if ($isServer) { 'Server' }
        elseif ($isEnterprise -and $id -like '*iot*') { 'IoT Enterprise' }
        elseif ($isEnterprise -and $isLtsc) { 'Enterprise LTSC' }
        elseif ($isEnterprise) { 'Enterprise' }
        elseif ($isEducation) { 'Education' }
        elseif ($isProWorkstation) { 'Pro for Workstations' }
        elseif ($isProEducation) { 'Pro Education' }
        elseif ($isPro) { 'Pro' }
        elseif ($isUnknown) { 'Desconocida' }
        else { 'Home' }

    if ($forced) {
        $editionName = ('{0} (forzado)' -f $Edition)
        if ($forcedCapped) {
            $editionName = ('{0} (forzado, limitado a {1})' -f $Edition, (Get-FortressTierName -Tier $effectiveTier))
        }
    }

    $windowsName = if ($build -ge 22000) { 'Windows 11' } elseif ($build -ge 10240) { 'Windows 10' } else { 'Windows' }
    $supportedOS = ((-not $isServer) -and (-not $isUnknown) -and ($build -ge 10240))
    $is64Bit = [Environment]::Is64BitOperatingSystem

    # Las capacidades se calculan con la edicion REAL, no con el perfil forzado.
    $supports = [ordered]@{
        Gpedit                 = ($detectedTier -ge 2)
        AuditPolicy            = ($detectedTier -ge 2)
        DefenderAsr            = ($detectedTier -ge 2)
        NetworkProtection      = ($detectedTier -ge 2)
        ControlledFolderAccess = $true
        AppControl             = ($detectedTier -ge 2)
        AppLocker              = ($detectedTier -ge 3)
        CredentialGuard        = ($detectedTier -ge 3)
        BitLocker              = ($detectedTier -ge 2)
        HyperV                 = ($detectedTier -ge 2)
        Sandbox                = ($detectedTier -ge 2)
        AppGuard               = ($detectedTier -ge 3)
    }

    if ($isServer) {
        $supports.Sandbox = $false
        $supports.AppGuard = $false
        $supports.Gpedit = $true
    }
    if ($isHome) {
        $supports.Gpedit = $false
        $supports.AuditPolicy = $false
        $supports.DefenderAsr = $false
        $supports.NetworkProtection = $false
        $supports.AppControl = $false
        $supports.AppLocker = $false
        $supports.CredentialGuard = $false
        $supports.BitLocker = $false
        $supports.HyperV = $false
        $supports.Sandbox = $false
        $supports.AppGuard = $false
    }

    $script:FortressEffectiveTier = $effectiveTier
    $script:FortressDetectedTier = $detectedTier
    $modules = @(
        New-FortressModuleEntry 'Core' 'Nucleo DNS/Tor/firewall/failsafe/watchdog' 1 $true 'AdGuard Home, Tor SOCKS5, DoH, DNSPort .onion, firewall anti-fuga, failsafe, watchdog, DoH del navegador y ACL del .env.'
        New-FortressModuleEntry 'FirewallLogging' 'Registro de firewall' 2 ($detectedTier -ge 2) 'Activa el registro de paquetes bloqueados en los perfiles Domain/Private/Public.'
        New-FortressModuleEntry 'DnsClientLog' 'Registro operativo DNS Client' 2 ($detectedTier -ge 2) 'Activa el canal Microsoft-Windows-DNS-Client/Operational para diagnostico.'
        New-FortressModuleEntry 'DefenderAudit' 'Defender ASR/NP/CFA en auditoria' 2 ([bool]$supports.DefenderAsr) 'Activa reglas ASR, Network Protection y Controlled Folder Access en modo auditoria, sin bloquear.'
        New-FortressModuleEntry 'AppControlReadiness' 'App Control/WDAC (solo lectura)' 2 ([bool]$supports.AppControl) 'Comprueba si hay politicas App Control/WDAC activas; no las modifica.'
        New-FortressModuleEntry 'BitLockerReadiness' 'BitLocker (solo lectura)' 2 ([bool]$supports.BitLocker) 'Comprueba el estado de BitLocker; no activa cifrado ni genera claves.'
        New-FortressModuleEntry 'VirtualizationReadiness' 'Hyper-V/Sandbox (solo lectura)' 2 ([bool]$supports.HyperV) 'Comprueba si Hyper-V y Windows Sandbox estan disponibles; no los instala.'
        New-FortressModuleEntry 'AppLockerReadiness' 'AppLocker (solo lectura)' 3 ([bool]$supports.AppLocker) 'Comprueba el servicio y las politicas AppLocker; no bloquea aplicaciones.'
        New-FortressModuleEntry 'CredentialGuardReadiness' 'Credential Guard (solo lectura)' 3 ([bool]$supports.CredentialGuard) 'Comprueba VBS/Credential Guard; no cambia la configuracion de arranque.'
        New-FortressModuleEntry 'AppGuardReadiness' 'Defender Application Guard (solo lectura)' 3 ([bool]$supports.AppGuard) 'Comprueba si la caracteristica Application Guard esta instalada; no la activa.'
        New-FortressModuleEntry 'EnterpriseReport' 'Informe Enterprise' 4 ($detectedTier -ge 4) 'Genera edition-hardening.report.json con el estado de todos los modulos y lecturas.'
    )
    $script:FortressEffectiveTier = 0
    $script:FortressDetectedTier = 0

    $enabled = @($modules | Where-Object { $_.Enabled })
    $disabled = @($modules | Where-Object { -not $_.Enabled })

    $buildLabel = if ($ubr -gt 0) { ('{0}.{1}' -f $build, $ubr) } else { [string]$build }
    $versionLabel = if ($displayVersion) { $displayVersion } else { 'sin version' }
    $summary = ('{0} {1} {2} (build {3}) | {4} | Tier {5} - {6}' -f $windowsName, $editionName, $versionLabel, $buildLabel, $editionId, $effectiveTier, (Get-FortressTierName -Tier $effectiveTier))

    $capabilitySummary = ('AppLocker={0}; App Control={1}; Credential Guard={2}; BitLocker={3}; Hyper-V={4}; Sandbox={5}' -f
        $(if ($supports.AppLocker) { 'SI' } else { 'NO' }),
        $(if ($supports.AppControl) { 'SI' } else { 'NO' }),
        $(if ($supports.CredentialGuard) { 'SI' } else { 'NO' }),
        $(if ($supports.BitLocker) { 'SI' } else { 'NO' }),
        $(if ($supports.HyperV) { 'SI' } else { 'NO' }),
        $(if ($supports.Sandbox) { 'SI' } else { 'NO' }))

    return [pscustomobject]@{
        EditionId          = $editionId
        ProductName        = $productName
        EditionName        = $editionName
        DisplayVersion     = $displayVersion
        WindowsName        = $windowsName
        Build              = $build
        UBR                = $ubr
        IsWindows11        = ($build -ge 22000)
        Is64Bit            = $is64Bit
        IsHome             = $isHome
        IsPro              = $isPro
        IsProWorkstation   = $isProWorkstation
        IsProEducation     = $isProEducation
        IsEducation        = $isEducation
        IsEnterprise       = $isEnterprise
        IsServer           = $isServer
        IsLtsc             = $isLtsc
        IsUnknown          = $isUnknown
        SupportedOS        = $supportedOS
        DetectedTier       = $detectedTier
        RequestedTier      = $requestedTier
        Tier               = $effectiveTier
        TierName           = (Get-FortressTierName -Tier $effectiveTier)
        Forced             = $forced
        ForcedCapped       = $forcedCapped
        Supports           = [pscustomobject]$supports
        Modules            = $modules
        EnabledModules     = @($enabled | ForEach-Object { $_.Id })
        DisabledModules    = @($disabled | ForEach-Object { $_.Id })
        Summary            = $summary
        CapabilitySummary  = $capabilitySummary
    }
}

function Show-WindowsFortressProfile {
    param(
        [Parameter(Mandatory = $true)]
        $WindowsProfile
    )

    Write-Host ''
    Write-Host '--- PERFIL DE WINDOWS ---' -ForegroundColor Cyan
    Write-Host ('  {0}' -f $WindowsProfile.Summary)
    if ($WindowsProfile.PSObject.Properties['ForcedCapped'] -and $WindowsProfile.ForcedCapped) {
        Write-Host ('  AVISO: el perfil solicitado no existe en esta edicion; se aplica como maximo {0}.' -f $WindowsProfile.TierName) -ForegroundColor Yellow
    }
    Write-Host ('  Capacidades: {0}' -f $WindowsProfile.CapabilitySummary)
    Write-Host ('  Modulos activos: {0}' -f (($WindowsProfile.EnabledModules -join ', ')))
    if ($WindowsProfile.DisabledModules.Count -gt 0) {
        Write-Host ('  Modulos omitidos: {0}' -f (($WindowsProfile.DisabledModules -join ', '))) -ForegroundColor DarkGray
        Write-Host '  Los modulos omitidos no se aplican; el nucleo DNS/Tor sigue funcionando.' -ForegroundColor DarkGray
    }
    Write-Host ''
}

if ($MyInvocation.InvocationName -ne '.') {
    Show-WindowsFortressProfile -WindowsProfile (Get-WindowsFortressProfile)
}
