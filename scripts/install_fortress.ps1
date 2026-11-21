<#
.SYNOPSIS
    1-Click Automated Setup for AdGuard Home + Tor DNS Privacy Fortress on Windows 11 / 10.
.DESCRIPTION
    Installs the AdGuard Home configuration and watchdog without stopping shared
    Windows processes. DNS client settings are changed only after Tor and AdGuard
    Home are listening on their required loopback ports.
#>

param(
    [string]$TargetDir = "C:\AdGuardHome",
    [string]$TorConfigPath = "",
    [string]$AdminPasswordHash = "",
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

function Test-TcpPortOpen {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

# 1. Inspect port 53 without changing SharedAccess or terminating any process.
Write-Host "[1/6] Comprobando conflictos del puerto 53 sin detener servicios..." -ForegroundColor Yellow
$port53Endpoints = @(
    Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
    Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue
)
$port53Conflicts = @()
foreach ($endpoint in $port53Endpoints) {
    $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -ne "AdGuardHome") {
        $port53Conflicts += "PID $($process.Id) ($($process.ProcessName)) at $($endpoint.LocalAddress)"
    }
}
if ($port53Conflicts.Count -gt 0) {
    $details = $port53Conflicts -join "; "
    Write-Error "El puerto 53 está ocupado por otro proceso: $details. No se ha detenido ningún servicio."
    exit 1
}
Write-Host "  -> No se detectaron propietarios ajenos a AdGuard Home." -ForegroundColor Green

# 2. Directory & Configuration Setup
Write-Host "[2/6] Configurando estructura de directorios en $TargetDir..." -ForegroundColor Yellow
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$templateConfig = Join-Path $repoRoot "config\AdGuardHome.template.yaml"
$targetConfig = Join-Path $TargetDir "AdGuardHome.yaml"
$configChanged = $false
$torConfigChanged = $false

if (-not (Test-Path $templateConfig -PathType Leaf)) {
    Write-Error "No se encontró la plantilla de configuración: $templateConfig"
    exit 1
}

$targetConfigExists = Test-Path $targetConfig -PathType Leaf
$applyTemplate = (-not $targetConfigExists) -or $Force
$configSource = if ($applyTemplate) {
    [System.IO.File]::ReadAllText($templateConfig)
} else {
    [System.IO.File]::ReadAllText($targetConfig)
}
$adminHashPlaceholder = "__ADMIN_BCRYPT_PASSWORD_HASH__"
$writeConfig = $applyTemplate
if ($configSource.Contains($adminHashPlaceholder)) {
    if ([string]::IsNullOrWhiteSpace($AdminPasswordHash)) {
        $AdminPasswordHash = Read-Host "Pega el hash bcrypt de admin generado con htpasswd -B -n -b (no introduzcas la contraseña en texto claro)"
    }
    if ($AdminPasswordHash -notmatch '^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$') {
        Write-Error "Se requiere un hash bcrypt válido para el panel. Consulta la sección Reset Web Password de la documentación oficial de AdGuard Home."
        exit 1
    }
    $configSource = $configSource.Replace($adminHashPlaceholder, $AdminPasswordHash)
    $writeConfig = $true
}

if ($configSource.Contains($adminHashPlaceholder)) {
    Write-Error "La configuración todavía contiene el marcador de contraseña. No se instalará un panel sin autenticación funcional."
    exit 1
}

if ($writeConfig) {
    if ($targetConfigExists) {
        $backupPath = "$targetConfig.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -LiteralPath $targetConfig -Destination $backupPath
        Write-Host "  -> Respaldo de configuración existente: $backupPath" -ForegroundColor Cyan
    }
    [System.IO.File]::WriteAllText($targetConfig, $configSource, [System.Text.UTF8Encoding]::new($false))
    $configChanged = $true
    Write-Host "  -> Configuración escrita en $targetConfig con hash de administrador válido." -ForegroundColor Green
} else {
    Write-Host "  -> Archivo de configuración existente detectado en $targetConfig. Manteniendo configuración existente." -ForegroundColor Cyan
}

# 2.5. Optional Tor configuration deployment to an explicit path.
Write-Host "[2.5/6] Configuración Tor..." -ForegroundColor Yellow
$torTemplate = Join-Path $repoRoot "config\torrc.template"
if ($TorConfigPath) {
    $resolvedTorConfig = [System.IO.Path]::GetFullPath($TorConfigPath)
    if (-not (Test-Path (Split-Path -Parent $resolvedTorConfig))) {
        Write-Error "No existe el directorio de configuración de Tor: $(Split-Path -Parent $resolvedTorConfig)"
        exit 1
    }
    if ((Test-Path $resolvedTorConfig) -and -not $Force) {
        Write-Host "  -> Se conserva el torrc existente; usa -Force para guardar un respaldo y reemplazarlo." -ForegroundColor Cyan
    } else {
        if (Test-Path $resolvedTorConfig) {
            $torBackup = "$resolvedTorConfig.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item -Path $resolvedTorConfig -Destination $torBackup
            Write-Host "  -> Respaldo de torrc existente: $torBackup" -ForegroundColor Cyan
        }
        Copy-Item -Path $torTemplate -Destination $resolvedTorConfig -Force
        $torConfigChanged = $true
        Write-Host "  -> Plantilla de Tor copiada a $resolvedTorConfig. Reinicia Tor antes de continuar." -ForegroundColor Green
    }
} else {
    Write-Host "  -> No se modifica ningún torrc. Usa -TorConfigPath con la ruta exacta del servicio Tor." -ForegroundColor Yellow
}

if ($torConfigChanged) {
    Write-Warning "Reinicia el servicio Tor y vuelve a ejecutar el instalador. No se han cambiado los adaptadores DNS de Windows."
    exit 1
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

# 4. Verify Tor and AdGuard before changing Windows DNS.
Write-Host "[4/6] Verificando AdGuard Home y Tor antes de cambiar DNS de Windows..." -ForegroundColor Yellow
$torDnsListener = Get-NetUDPEndpoint -LocalPort 5350 -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq "127.0.0.1" }
if (-not (Test-TcpPortOpen -Address "127.0.0.1" -Port 9050) -or -not $torDnsListener) {
    Write-Error "Tor no está listo: se requieren SOCKS 127.0.0.1:9050 y DNSPort UDP 127.0.0.1:5350. No se cambiarán los adaptadores de red."
    exit 1
}

$aghExe = Join-Path $TargetDir "AdGuardHome.exe"
if (-not (Test-Path $aghExe)) {
    Write-Error "No se encontró $aghExe. No se cambiarán los adaptadores de red."
    exit 1
}
$aghService = Get-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
if (-not $aghService) {
    & $aghExe -s install
    if ($LASTEXITCODE -ne 0) {
        Write-Error "AdGuard Home no pudo instalar su servicio (código $LASTEXITCODE). No se cambiarán los adaptadores de red."
        exit 1
    }
}
$aghService = Get-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
if (-not $aghService) {
    Write-Error "No se encontró el servicio AdGuardHome después de instalarlo. No se cambiarán los adaptadores de red."
    exit 1
}
if ($aghService.Status -eq "Running" -and $configChanged) {
    Restart-Service -Name "AdGuardHome" -Force
} elseif ($aghService.Status -ne "Running") {
    Start-Service -Name "AdGuardHome"
}
Start-Sleep -Seconds 2
$aghDnsListeners = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @("127.0.0.1", "::1") }
$aghDnsReady = $false
foreach ($endpoint in $aghDnsListeners) {
    $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq "AdGuardHome") { $aghDnsReady = $true }
}
if (-not $aghDnsReady) {
    Write-Error "AdGuard Home no escucha en 127.0.0.1:53 o ::1:53. No se cambiarán los adaptadores de red."
    exit 1
}

# Configure Windows DNS only after both local services pass the preflight.
Write-Host "  -> Tor y AdGuard Home están disponibles." -ForegroundColor Green
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
    if ($LASTEXITCODE -ne 0) {
        Write-Error "La suite de verificación detectó fallos. Revisa la salida anterior."
        exit 1
    }
}

Write-Host ""
Write-Host "🎉 INSTALACIÓN COMPLETADA. Tu sistema ahora navega con privacidad total a través de la fortaleza DNS." -ForegroundColor Green
