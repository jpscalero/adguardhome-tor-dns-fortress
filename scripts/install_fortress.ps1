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
    [switch]$Force = $false,
    [switch]$DryRun = $false,
    [switch]$SkipEnvAcl = $false,
    [switch]$SkipBrowserDoh = $false,
    [switch]$SkipDiagnostics = $false,
    [ValidateSet('Auto', 'Home', 'Pro', 'Education', 'Enterprise')]
    [string]$EditionProfile = 'Auto',
    [switch]$SkipEditionHardening = $false
)

# Ensure script is running as Administrator
$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Este script requiere privilegios de Administrador. Por favor, ejecútalo como Administrador."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   🚀 INSTALADOR AUTOMATIZADO - DNS PRIVACY FORTRESS     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Perfil de edicion: Home, Pro, Education o Enterprise.
$fortressProfile = $null
$editionScript = Join-Path $PSScriptRoot 'windows-edition.ps1'
if (Test-Path $editionScript) {
    . $editionScript
    $fortressProfile = Get-WindowsFortressProfile -Edition $EditionProfile
    Show-WindowsFortressProfile -WindowsProfile $fortressProfile
} else {
    Write-Warning "No se encontro windows-edition.ps1; se instalara solo el nucleo."
}

# -DryRun: muestra el plan completo y sale sin tocar nada.
if ($DryRun) {
    Write-Host "MODO DRY-RUN: no se aplicara ningun cambio." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Plan de instalacion en ${TargetDir}:"
    Write-Host "  1. Neutralizar SharedAccess (IcsDnsEnabled=0, triggers, arranque deshabilitado)"
    Write-Host "  2. Copiar config/AdGuardHome.template.yaml si no existe"
    Write-Host "  3. Desplegar config/torrc.template en las rutas de Tor detectadas"
    Write-Host "  4. Copiar watchdog, failsafe, centinela, decoy, suite y lanzadores"
    Write-Host "  5. Apuntar los adaptadores activos a 127.0.0.1"
    Write-Host "  6. Crear reglas de firewall: 53/UDP, 53/TCP, 853/TCP, 5353/UDP"
    Write-Host "  7. Registrar tareas: watchdog (boot) y failsafe (cada 2 min)"
    Write-Host "  8. Restringir la ACL de config\.env"
    Write-Host "  9. Desactivar el DoH propio de Chrome/Edge/Firefox"
    Write-Host " 10. Aplicar el hardening adicional de la edicion Windows"
    Write-Host " 11. Ejecutar scripts/test_fortress.ps1"
    if ($fortressProfile) {
        Write-Host ""
        Write-Host ("  Perfil detectado: {0}" -f $fortressProfile.Summary) -ForegroundColor Cyan
        Write-Host ("  Modulos de edicion: {0}" -f ($fortressProfile.EnabledModules -join ', ')) -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "Vuelve a ejecutarlo sin -DryRun para aplicar." -ForegroundColor Green
    exit 0
}
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
$scriptsToCopy = @(
    "watchdog.ps1",
    "failsafe-dns.ps1",
    "harden-env-acl.ps1",
    "harden-browser-doh.ps1",
    "windows-edition.ps1",
    "apply-edition-hardening.ps1",
    "ai_dns_guard.js",
    "decoy_dns.js",
    "test_fortress.ps1"
)
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
    # Lanzadores .cmd (resuelven rutas y el node portable). Los VBS delegan en ellos.
    Get-ChildItem -Path $launchersDir -Filter "*.cmd" -ErrorAction SilentlyContinue | ForEach-Object {
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
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' -and $_.InterfaceDescription -notlike '*Hyper-V*' -and $_.InterfaceDescription -notlike '*Loopback*' }
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
    @{ Name = "AdGuard_Block_Outbound_DNS_TCP"; Display = "AdGuard - Block Outbound Plaintext DNS TCP"; Protocol = "TCP"; Port = 53 },
    @{ Name = "AdGuard_Block_Outbound_DOT_853"; Display = "AdGuard - Block Outbound DNS-over-TLS 853"; Protocol = "TCP"; Port = 853 },
    @{ Name = "AdGuard_Block_Outbound_MDNS"; Display = "AdGuard - Block Outbound mDNS 5353"; Protocol = "UDP"; Port = 5353 }
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

# 5.5. Register Failsafe Scheduled Task (cada 2 minutos)
Write-Host "[5.5/6] Registrando failsafe de red (cada 2 minutos)..." -ForegroundColor Yellow
$failsafeScript = Join-Path $TargetDir "failsafe-dns.ps1"
if (Test-Path $failsafeScript) {
    $failsafeTaskName = "AdGuardHome_Fortress_Failsafe"
    $fsAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$failsafeScript`""
    $fsTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
    $fsSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $failsafeTaskName -Action $fsAction -Trigger $fsTrigger -Settings $fsSettings -User "NT AUTHORITY\SYSTEM" -Force | Out-Null
    Write-Host "  -> Tarea programada '$failsafeTaskName' registrada (cada 2 min)." -ForegroundColor Green
} else {
    Write-Host "  -> AVISO: no se encontro failsafe-dns.ps1; failsafe no registrado." -ForegroundColor Yellow
}

# 5.6. Hardening de secretos y DoH del navegador
Write-Host "[5.6/6] Restringiendo permisos de config\.env y DoH del navegador..." -ForegroundColor Yellow
$envFilePath = Join-Path $TargetDir "config\.env"
if ((-not $SkipEnvAcl) -and (Test-Path $envFilePath)) {
    $aclScript = Join-Path $TargetDir "harden-env-acl.ps1"
    if (Test-Path $aclScript) {
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $aclScript -EnvFile $envFilePath
        Write-Host "  -> ACL del .env restringida (SYSTEM + Administradores + propietario)." -ForegroundColor Green
    }
} elseif (-not $SkipEnvAcl) {
    Write-Host "  -> AVISO: no existe config\.env todavia; crea tus credenciales y ejecuta scripts\harden-env-acl.ps1" -ForegroundColor Yellow
}

if (-not $SkipBrowserDoh) {
    $browserScript = Join-Path $TargetDir "harden-browser-doh.ps1"
    if (Test-Path $browserScript) {
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $browserScript
        Write-Host "  -> DoH propio de los navegadores desactivado (Chrome/Edge/Firefox)." -ForegroundColor Green
    }
}

# 5.7. Hardening adicional segun la edicion de Windows
if (-not $SkipEditionHardening) {
    $editionHardening = Join-Path $TargetDir "apply-edition-hardening.ps1"
    if (($fortressProfile) -and (Test-Path $editionHardening)) {
        Write-Host ("[5.7/6] Aplicando hardening de la edicion {0}..." -f $fortressProfile.EditionName) -ForegroundColor Yellow
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $editionHardening -TargetDir $TargetDir -Edition $EditionProfile
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "  -> El hardening de edicion devolvio un aviso; el nucleo DNS/Tor sigue instalado."
        }
    } else {
        Write-Host "  -> AVISO: no se encontro apply-edition-hardening.ps1; se omite el hardening adicional." -ForegroundColor Yellow
    }
}

# 6. Final verification
if ($SkipDiagnostics) {
    Write-Host "[6/6] Diagnóstico omitido (-SkipDiagnostics). Se ejecutará al final, con los servicios ya arrancados." -ForegroundColor Cyan
} else {
    Write-Host "[6/6] Ejecutando comprobación de salud del sistema..." -ForegroundColor Yellow
    $diagScript = Join-Path $repoRoot "scripts\test_fortress.ps1"
    if (Test-Path $diagScript) {
        & $diagScript
    }
}

Write-Host ""
if ($SkipDiagnostics) {
    Write-Host "Configuración aplicada. El instalador fácil continúa con los servicios y la comprobación final." -ForegroundColor Green
} else {
    Write-Host "🎉 INSTALACIÓN COMPLETADA. Tu sistema ahora navega con privacidad total a través de la fortaleza DNS." -ForegroundColor Green
}
if ($fortressProfile) {
    Write-Host ("Perfil Windows aplicado: {0}" -f $fortressProfile.Summary) -ForegroundColor Cyan
}
