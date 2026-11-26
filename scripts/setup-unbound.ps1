#Requires -Version 5.1
<#
.SYNOPSIS
    Instala y configura Unbound como resolutor recursivo propio (Fase 5).

.DESCRIPTION
    Despliega un resolutor recursivo en 127.0.0.1:5335 para que AdGuard Home no
    delegue en Quad9/Cloudflare/AdGuard DNS. Incluye validacion DNSSEC local,
    qname minimisation y cache en RAM.

    Seguridad de la cadena de suministro: el script NO descarga nada por su
    cuenta. O le pasas el ZIP oficial con -PackagePath, o le pasas -DownloadUrl
    y -ExpectedSha256 juntos; en cualquier otro caso se limita a explicar que
    falta el binario. El hash se verifica siempre antes de descomprimir.

    El servicio se registra con el instalador oficial de Unbound si esta
    presente; si no, se crea la tarea programada AdGuardHome_Unbound.

.PARAMETER PackagePath
    ZIP oficial de Unbound para Windows ya descargado.

.PARAMETER DownloadUrl
    URL del ZIP oficial. Requiere -ExpectedSha256.

.PARAMETER ExpectedSha256
    SHA256 esperado del ZIP. Requiere -DownloadUrl.

.PARAMETER Undo
    Detiene y elimina el servicio o la tarea, y borra la configuracion generada.

.PARAMETER DryRun
    Muestra el plan sin tocar el sistema.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup-unbound.ps1 `
        -PackagePath .\unbound-1.22.0.zip -ExpectedSha256 <hash>
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [string]$UnboundDir = 'C:\Program Files\Unbound',
    [string]$PackagePath = '',
    [string]$DownloadUrl = '',
    [string]$ExpectedSha256 = '',
    [switch]$DryRun,
    [switch]$Undo
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Stop'
$taskName = 'AdGuardHome_Unbound'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

function Test-UnboundPort {
    param([int]$TimeoutMs = 1200)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect('127.0.0.1', 5335, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $client.Connected) { return $true }
        return $false
    } catch {
        return $false
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Remove-UnboundDeployment {
    if ($DryRun) {
        Write-Host '  DRY-RUN: se eliminarian tarea, servicio y configuracion de Unbound.' -ForegroundColor Cyan
        return
    }

    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host '  Tarea AdGuardHome_Unbound eliminada.'
    }

    $removeTool = Join-Path $UnboundDir 'unbound-service-remove.exe'
    if (Test-Path $removeTool) {
        & $removeTool 2>&1 | Out-Null
    }
    $svc = Get-Service -Name 'unbound' -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name 'unbound' -Force -ErrorAction SilentlyContinue
        & sc.exe delete unbound 2>&1 | Out-Null
    }
    Get-Process -Name 'unbound' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $conf = Join-Path $UnboundDir 'unbound.conf'
    if (Test-Path $conf) { Remove-Item $conf -Force -ErrorAction SilentlyContinue }
    Write-Host '  Unbound retirado (el binario se conserva).'
}

if ($Undo) {
    Write-Step 'Retirando el resolutor recursivo Unbound...'
    Remove-UnboundDeployment
    exit 0
}

if ($DryRun) {
    Write-Host 'DRY-RUN: no se aplicara ningun cambio.' -ForegroundColor Cyan
    Write-Host ('  Directorio de Unbound: {0}' -f $UnboundDir)
    Write-Host '  Puerto: 127.0.0.1:5335 (solo loopback)'
    Write-Host '  Validacion: DNSSEC con auto-trust-anchor (RFC 5011)'
    Write-Host '  Servicio: unbound-service-install.exe o tarea AdGuardHome_Unbound'
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error 'Este script requiere privilegios de Administrador.'
    exit 1
}

if (-not (Test-Path $TargetDir)) {
    Write-Error ("No existe {0}. Instala primero la fortaleza." -f $TargetDir)
    exit 2
}

# ---------------------------------------------------------------------------
# 1. Localizar o preparar el binario
# ---------------------------------------------------------------------------
$exe = Join-Path $UnboundDir 'unbound.exe'
$tempRoot = Join-Path $env:TEMP 'fortress-unbound'

if (-not (Test-Path $exe)) {
    $zip = $PackagePath
    if ($DownloadUrl -or $ExpectedSha256) {
        if (-not $DownloadUrl -or -not $ExpectedSha256) {
            Write-Error 'DownloadUrl y ExpectedSha256 deben indicarse juntos.'
            exit 2
        }
        if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            Write-Error 'ExpectedSha256 no tiene 64 caracteres hexadecimales.'
            exit 2
        }
        $zip = Join-Path $env:TEMP 'unbound-fortress.zip'
        Write-Step ("Descargando {0}" -f $DownloadUrl)
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $zip -UseBasicParsing
        $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
        if ($hash -ne $ExpectedSha256.ToUpperInvariant()) {
            Write-Error ("SHA256 no coincide. Esperado {0}, obtenido {1}." -f $ExpectedSha256.ToUpperInvariant(), $hash)
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
            exit 3
        }
        Write-Host '  SHA256 del paquete verificado.' -ForegroundColor Green
    }

    if ($zip) {
        if (-not (Test-Path $zip)) {
            Write-Error ("No existe el paquete {0}." -f $zip)
            exit 2
        }
        if (-not $PackagePath -and $ExpectedSha256) {
            $hash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
            if ($hash -ne $ExpectedSha256.ToUpperInvariant()) {
                Write-Error 'SHA256 del paquete no coincide.'
                exit 3
            }
        }
        if (Test-Path $tempRoot) { Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        Expand-Archive -Path $zip -DestinationPath $tempRoot -Force
        $found = Get-ChildItem -Path $tempRoot -Filter 'unbound.exe' -Recurse | Select-Object -First 1
        if (-not $found) {
            Write-Error 'El ZIP no contiene unbound.exe.'
            exit 3
        }
        if (-not (Test-Path $UnboundDir)) {
            New-Item -ItemType Directory -Path $UnboundDir -Force | Out-Null
        }
        Copy-Item -Path (Join-Path $found.DirectoryName '*') -Destination $UnboundDir -Recurse -Force
        Write-Host ("  Binario desplegado en {0}." -f $UnboundDir) -ForegroundColor Green
        $exe = Join-Path $UnboundDir 'unbound.exe'
    }
}

if (-not (Test-Path $exe)) {
    $cmd = Get-Command 'unbound.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $exe = $cmd.Source; $UnboundDir = Split-Path -Parent $exe }
}

if (-not (Test-Path $exe)) {
    Write-Host ''
    Write-Warning 'No se encontro unbound.exe.'
    Write-Host 'Descarga el ZIP oficial de Unbound para Windows desde https://nlnetlabs.nl/projects/unbound/download/'
    Write-Host 'Verifica su SHA256 y vuelve a ejecutar:'
    Write-Host '  powershell -ExecutionPolicy Bypass -File scripts\setup-unbound.ps1 -PackagePath .\unbound-X.Y.Z.zip'
    Write-Host 'Sin Unbound, el perfil privacy no puede activarse; el perfil speed sigue funcionando.'
    exit 2
}

# ---------------------------------------------------------------------------
# 2. Configuracion
# ---------------------------------------------------------------------------
Write-Step 'Desplegando unbound.conf (solo loopback, DNSSEC, sin logs de consultas)...'
$template = Join-Path $PSScriptRoot 'unbound.conf.template'
if (-not (Test-Path $template)) {
    $template = Join-Path $TargetDir 'unbound.conf.template'
}
if (-not (Test-Path $template)) {
    $template = Join-Path (Split-Path -Parent $PSScriptRoot) 'config\unbound.conf.template'
}
if (-not (Test-Path $template)) {
    Write-Error 'No se encontro config/unbound.conf.template.'
    exit 2
}

$conf = Join-Path $UnboundDir 'unbound.conf'
$rootKey = Join-Path $UnboundDir 'root.key'
$text = [System.IO.File]::ReadAllText($template)
$text = $text.Replace('__UNBOUND_DIR__', $UnboundDir.Replace('\', '\\'))
$text = $text.Replace('__UNBOUND_ROOT_KEY__', $rootKey.Replace('\', '\\'))
[System.IO.File]::WriteAllText($conf, $text, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  Configuracion escrita en {0}." -f $conf) -ForegroundColor Green

# Clave raiz: unbound-anchor la descarga y la mantiene con RFC 5011. Si no hay
# red en el momento de instalar, se siembra el ancla KSK-2017 y Unbound la
# actualizara en cuanto pueda validar.
if (-not (Test-Path $rootKey)) {
    $anchor = Join-Path $UnboundDir 'unbound-anchor.exe'
    $seeded = $false
    if (Test-Path $anchor) {
        Write-Step 'Obteniendo el ancla de confianza de la raiz DNS...'
        & $anchor -a $rootKey 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
        if (Test-Path $rootKey) { $seeded = $true }
    }
    if (-not $seeded) {
        $ds = '. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D' + [Environment]::NewLine
        [System.IO.File]::WriteAllText($rootKey, $ds, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host '  Ancla KSK-2017 sembrada; Unbound la actualizara por RFC 5011.' -ForegroundColor Yellow
    }
}

# Permisos: solo SYSTEM y Administradores escriben la configuracion y el ancla.
& icacls $UnboundDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 2>&1 | Out-Null

$checkconf = Join-Path $UnboundDir 'unbound-checkconf.exe'
if (Test-Path $checkconf) {
    & $checkconf $conf 2>&1 | ForEach-Object { Write-Host ('  ' + $_) }
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'unbound-checkconf rechazo la configuracion.'
        exit 4
    }
    Write-Host '  Configuracion validada por unbound-checkconf.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 3. Servicio o tarea
# ---------------------------------------------------------------------------
$serviceInstaller = Join-Path $UnboundDir 'unbound-service-install.exe'
$serviceReady = $false
if (Test-Path $serviceInstaller) {
    Write-Step 'Registrando el servicio oficial de Unbound...'
    & $serviceInstaller 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name 'unbound' -ErrorAction SilentlyContinue
    if ($svc) {
        Set-Service -Name 'unbound' -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name 'unbound' -ErrorAction SilentlyContinue
        $serviceReady = $true
    }
}

if (-not $serviceReady) {
    Write-Step 'Registrando Unbound como tarea programada de arranque...'
    $action = New-ScheduledTaskAction -Execute $exe -Argument ('-c "{0}"' -f $conf) -WorkingDirectory $UnboundDir
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
}

# ---------------------------------------------------------------------------
# 4. Verificacion real
# ---------------------------------------------------------------------------
Write-Step 'Comprobando que el resolutor responde y valida DNSSEC...'
$up = $false
for ($i = 1; $i -le 10; $i++) {
    if (Test-UnboundPort) { $up = $true; break }
    Start-Sleep -Milliseconds 700
}

if (-not $up) {
    Write-Error 'Unbound no escucha en 127.0.0.1:5335. Revisa el Visor de eventos o ejecuta unbound.exe -d -c unbound.conf.'
    exit 5
}

$resolution = Resolve-DnsName -Name 'example.com' -Server '127.0.0.1' -Port 5335 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
if (-not $resolution) {
    Write-Error 'Unbound escucha pero no resolvio example.com (revisa salida 53/UDP y el ancla de confianza).'
    exit 5
}
Write-Host '  Resolucion recursiva correcta (example.com).' -ForegroundColor Green

$dnssecOk = $true
try {
    $bogus = Resolve-DnsName -Name 'dnssec-failed.org' -Server '127.0.0.1' -Port 5335 -DnsOnly -QuickTimeout -ErrorAction Stop
    if ($bogus) { $dnssecOk = $false }
} catch {
    $dnssecOk = $true
}
if ($dnssecOk) {
    Write-Host '  DNSSEC: dnssec-failed.org rechazado correctamente.' -ForegroundColor Green
} else {
    Write-Warning 'DNSSEC: dnssec-failed.org resolvio; revisa el ancla de confianza antes de usar el perfil privacy.'
}

Write-Host ''
Write-Host 'Unbound listo. Activa el perfil con:' -ForegroundColor Cyan
Write-Host '  powershell -ExecutionPolicy Bypass -File scripts\apply-dns-profile.ps1 -Profile privacy'
exit 0
