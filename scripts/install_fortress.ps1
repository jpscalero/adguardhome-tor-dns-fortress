<#
.SYNOPSIS
    1-Click Automated Setup for AdGuard Home + Tor DNS Privacy Fortress on Windows 11 / 10.
.DESCRIPTION
    Configures port 53 exclusivity, applies the Windows 11 SharedAccess neutralizer,
    configures Tor SOCKS5 proxying, deploys hardened AdGuard Home YAML,
    and installs the self-healing background watchdog.
#>

param(
    [string]$TargetDir = "C:\AdGuardHome",
    [switch]$SkipTorInstall = $false,
    [switch]$Force = $false
)

# Ensure script is running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Este script requiere privilegios de Administrador. Por favor, ejecútalo como Administrador."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   🚀 INSTALADOR AUTOMATIZADO - DNS PRIVACY FORTRESS     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Neutralize Windows 11 Port 53 Hijack (SharedAccess / ICS)
Write-Host "[1/6] Aplicando solución nativa para el puerto 53 en Windows 11..." -ForegroundColor Yellow
try {
    $paramPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters'
    if (-not (Test-Path $paramPath)) {
        New-Item -Path $paramPath -Force | Out-Null
    }
    Set-ItemProperty -Path $paramPath -Name 'IcsDnsEnabled' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $paramPath -Name 'EnableDNS' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $paramPath -Name 'EnableDNSMcast' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $paramPath -Name 'DnsDoneNotification' -Value 1 -Type DWord -Force
    
    # Neutralize RPC triggers, failure recovery and disable service start
    & sc.exe triggerinfo SharedAccess delete 2>&1 | Out-Null
    & sc.exe failure SharedAccess reset= 0 actions= "" 2>&1 | Out-Null
    & sc.exe config SharedAccess start= disabled 2>&1 | Out-Null
    Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue

    # Stop any running SharedAccess svchost instances holding port 53
    $endpoints = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
    foreach ($ep in $endpoints) {
        $p = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -eq "svchost") {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  -> Puerto 53 liberado y desencadenadores neutralizados con éxito." -ForegroundColor Green
} catch {
    Write-Warning "  -> Error aplicando configuración de SharedAccess: $($_.Exception.Message)"
}

# 2. Directory & Configuration Setup
Write-Host "[2/6] Configurando estructura de directorios en $TargetDir..." -ForegroundColor Yellow
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$templateConfig = Join-Path $repoRoot "config\AdGuardHome.template.yaml"
$targetConfig = Join-Path $TargetDir "AdGuardHome.yaml"

if (-not (Test-Path $targetConfig) -or $Force) {
    if (Test-Path $templateConfig) {
        Copy-Item -Path $templateConfig -Destination $targetConfig -Force
        Write-Host "  -> Plantilla de configuración copiada a $targetConfig" -ForegroundColor Green
    }
} else {
    Write-Host "  -> Archivo de configuración existente detectado en $targetConfig. Manteniendo configuración existente." -ForegroundColor Cyan
}

# 2.5. Tor Configuration Deployment
Write-Host "[2.5/6] Verificando y desplegando configuración de Tor..." -ForegroundColor Yellow
$torPaths = @("C:\Tor\torrc", "C:\Program Files\Tor\torrc")
$torTemplate = Join-Path $repoRoot "config\torrc.template"
if (Test-Path $torTemplate) {
    foreach ($tp in $torPaths) {
        $tDir = Split-Path $tp
        if (Test-Path $tDir) {
            if ((-not (Test-Path $tp)) -or $Force) {
                Copy-Item -Path $torTemplate -Destination $tp -Force
                Write-Host "  -> Configuración de Tor desplegada en $tp" -ForegroundColor Green
            }
        }
    }
}

# 3. Copy scripts, launchers and diagnostic suite to AdGuardHome directory
Write-Host "[3/6] Desplegando scripts de Centinela AI, Decoy, Watchdog y Lanzadores..." -ForegroundColor Yellow
$scriptsToCopy = @("watchdog.ps1", "ai_dns_guard.js", "decoy_dns.js", "test_fortress.ps1")
foreach ($s in $scriptsToCopy) {
    $src = Join-Path $repoRoot "scripts\$s"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $TargetDir $s) -Force
    }
}

# Deploy silent VBS launchers with aliases
$launchersDir = Join-Path $repoRoot "launchers"
if (Test-Path $launchersDir) {
    Get-ChildItem -Path $launchersDir -Filter "*.vbs" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination (Join-Path $TargetDir $_.Name) -Force
    }
    # Ensure standard aliases for watchdog compatibility
    $aliasMap = @{
        "start_ai_guard.vbs" = "ocultar_guardia.vbs"
        "start_decoy.vbs"    = "ocultar_decoy.vbs"
    }
    foreach ($srcName in $aliasMap.Keys) {
        $srcPath = Join-Path $TargetDir $srcName
        $dstPath = Join-Path $TargetDir $aliasMap[$srcName]
        if ((Test-Path $srcPath) -and (-not (Test-Path $dstPath))) {
            Copy-Item -Path $srcPath -Destination $dstPath -Force
        }
    }
}

# 4. Set Windows DNS Client to 127.0.0.1
Write-Host "[4/6] Configurando adaptadores de red de Windows hacia 127.0.0.1..." -ForegroundColor Yellow
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' -and $_.InterfaceDescription -notlike '*Hyper-V*' }
foreach ($adapter in $adapters) {
    try {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @("127.0.0.1") -ErrorAction SilentlyContinue
        Write-Host "  -> Adaptador '$($adapter.Name)' configurado con 127.0.0.1" -ForegroundColor Green
    } catch {}
}
Clear-DnsClientCache
Write-Host "  -> Caché DNS de Windows purgada." -ForegroundColor Green

# 4.5. Anti-Bypass Windows Firewall Rules (Prevent Direct Outbound Plaintext DNS Leaks)
Write-Host "[4.5/6] Configurando reglas de firewall anti-fugas (bloqueo de bypass UDP/TCP 53 saliente)..." -ForegroundColor Yellow
$fwRules = @(
    @{ Name = "AdGuard_Block_Outbound_DNS_UDP"; Display = "AdGuard - Block Outbound Plaintext DNS UDP"; Protocol = "UDP"; Port = 53 },
    @{ Name = "AdGuard_Block_Outbound_DNS_TCP"; Display = "AdGuard - Block Outbound Plaintext DNS TCP"; Protocol = "TCP"; Port = 53 }
)
foreach ($r in $fwRules) {
    if (-not (Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $r.Name -DisplayName $r.Display -Direction Outbound -Action Block -Protocol $r.Protocol -RemotePort $r.Port -Enabled True | Out-Null
        Write-Host "  -> Regla de bloqueo saliente '$($r.Display)' configurada." -ForegroundColor Green
    }
}

# 5. Register Watchdog Scheduled Task
Write-Host "[5/6] Registrando tarea programada de autorrecuperación (Watchdog)..." -ForegroundColor Yellow
$taskName = "AdGuardHome_Fortress_Watchdog"
$watchdogScript = Join-Path $TargetDir "watchdog.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$watchdogScript`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "NT AUTHORITY\SYSTEM" -Force | Out-Null
Write-Host "  -> Tarea programada '$taskName' registrada y activa." -ForegroundColor Green

# 6. Final verification
Write-Host "[6/6] Ejecutando comprobación de salud del sistema..." -ForegroundColor Yellow
$diagScript = Join-Path $repoRoot "scripts\test_fortress.ps1"
if (Test-Path $diagScript) {
    & $diagScript
}

Write-Host ""
Write-Host "🎉 INSTALACIÓN COMPLETADA. Tu sistema ahora navega con privacidad total a través de la fortaleza DNS." -ForegroundColor Green
