#Requires -Version 5.1
<#
.SYNOPSIS
    Aplica un perfil coherente de upstreams DNS (privacy / speed / censorship).

.DESCRIPTION
    Reescribe el bloque marcado con FORTRESS-UPSTREAM en AdGuardHome.yaml:

      privacy      Resolutor recursivo propio (Unbound en 127.0.0.1:5335).
                   Ningun tercero ve el patron de consultas. Requiere Unbound.
      speed        DoH en paralelo por IP fija a traves del proxy Tor.
                   Es el perfil historico de la fortaleza.
      censorship   DoH sobre Tor con timeouts amplios para redes hostiles.
                   Pensado para combinarse con bridges de Tor.

    Antes de aplicar valida que el destino responda (Unbound en privacy) y, si
    existe AdGuardHome.exe, pasa --check-config. Si algo falla, restaura el
    respaldo y no deja la configuracion a medias.

.PARAMETER Profile
    privacy, speed o censorship.

.PARAMETER Restart
    Reinicia AdGuard Home despues de aplicar el perfil.

.PARAMETER DryRun
    Muestra el bloque resultante sin escribir nada.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\apply-dns-profile.ps1 -Profile privacy -Restart
#>

[CmdletBinding()]
param(
    [ValidateSet('privacy', 'speed', 'censorship')]
    [string]$Profile = 'speed',
    [string]$TargetDir = '',
    [switch]$Restart,
    [switch]$DryRun
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Stop'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

$configPath = Join-Path $TargetDir 'AdGuardHome.yaml'
$envPath = Join-Path $TargetDir 'config\.env'

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

function Test-TcpPort {
    param([int]$Port, [int]$TimeoutMs = 1200)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        return [bool]($ok -and $client.Connected)
    } catch {
        return $false
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Set-DnsProfileEnv {
    param([string]$Value)
    if (-not (Test-Path (Split-Path -Parent $envPath))) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $envPath) -Force | Out-Null
    }
    if (Test-Path $envPath) {
        $envText = Get-Content -Path $envPath -Raw
        if ($envText -match '(?m)^\s*DNS_PROFILE\s*=') {
            $envText = [regex]::Replace($envText, '(?m)^\s*DNS_PROFILE\s*=.*$', ('DNS_PROFILE=' + $Value))
        } else {
            $envText = $envText.TrimEnd() + [Environment]::NewLine + ('DNS_PROFILE=' + $Value) + [Environment]::NewLine
        }
        [System.IO.File]::WriteAllText($envPath, $envText, (New-Object System.Text.UTF8Encoding($false)))
    } else {
        [System.IO.File]::WriteAllText($envPath, ('DNS_PROFILE=' + $Value) + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
    }
}

if (-not (Test-Path $configPath)) {
    Write-Error ("No existe {0}. Ejecuta primero el instalador." -f $configPath)
    exit 2
}

$privacyBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil privacy: resolutor recursivo propio. Ningun tercero ve las consultas.
  # Unbound escucha solo en loopback y valida DNSSEC desde la raiz.
  upstream_dns:
    - 127.0.0.1:5335
    # .onion se resuelve dentro de Tor, sin resolutor convencional.
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5335
  fallback_dns: []
  upstream_mode: parallel
  fastest_timeout: 3s
  # <<< FORTRESS-UPSTREAM <<<
'@

$speedBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil speed: DoH en paralelo por IP fija a traves del proxy Tor.
  upstream_dns:
    - https://9.9.9.9/dns-query
    - https://149.112.112.112/dns-query
    - https://1.1.1.1/dns-query
    - https://1.0.0.1/dns-query
    - https://94.140.14.14/dns-query
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.2
    - 149.112.112.112
    - 1.0.0.1
  fallback_dns:
    - 9.9.9.9
    - 1.1.1.2
    - 149.112.112.112
  upstream_mode: parallel
  fastest_timeout: 1s
  # <<< FORTRESS-UPSTREAM <<<
'@

$censorshipBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil censorship: DoH sobre Tor con timeouts amplios. Combinalo con
  # UseBridges/obfs4 en torrc cuando la red bloquee Tor directo.
  upstream_dns:
    - https://9.9.9.9/dns-query
    - https://149.112.112.112/dns-query
    - https://1.1.1.1/dns-query
    - https://94.140.14.14/dns-query
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
    - 149.112.112.112
  fallback_dns:
    - 9.9.9.9
    - 1.1.1.1
  upstream_mode: parallel
  fastest_timeout: 3s
  # <<< FORTRESS-UPSTREAM <<<
'@

$block = $speedBlock
$timeout = '5s'
if ($Profile -eq 'privacy') {
    $block = $privacyBlock
    $timeout = '8s'
    if (-not (Test-TcpPort -Port 5335)) {
        Write-Error 'El perfil privacy necesita Unbound en 127.0.0.1:5335. Ejecuta scripts\setup-unbound.ps1.'
        exit 3
    }
} elseif ($Profile -eq 'censorship') {
    $block = $censorshipBlock
    $timeout = '10s'
}

# .NET lee UTF-8 sin BOM de forma fiable; Get-Content -Raw en PowerShell 5.1
# interpretaria el YAML como ANSI y corromperia los emojis de los comentarios.
$original = [System.IO.File]::ReadAllText($configPath)
if ($original -notmatch '(?s)# >>> FORTRESS-UPSTREAM >>>.*?# <<< FORTRESS-UPSTREAM <<<') {
    Write-Error 'AdGuardHome.yaml no contiene los marcadores FORTRESS-UPSTREAM. Reinstala la plantilla o anade el perfil con install_fortress.ps1 -Force.'
    exit 2
}

# El bloque no contiene '$', asi que se usa como reemplazo literal.
$updated = [regex]::Replace(
    $original,
    '(?s)# >>> FORTRESS-UPSTREAM >>>.*?# <<< FORTRESS-UPSTREAM <<<',
    $block
)
$updated = [regex]::Replace($updated, '(?m)^(\s*upstream_timeout:\s*).*$', ('${1}' + $timeout))

if ($DryRun) {
    Write-Host ('DRY-RUN: perfil {0} (upstream_timeout {1}). Bloque resultante:' -f $Profile, $timeout) -ForegroundColor Cyan
    Write-Host $block
    exit 0
}

$backup = $configPath + '.bak-profile-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -Path $configPath -Destination $backup -Force
Write-Step ("Respaldo creado en {0}" -f $backup)

try {
    [System.IO.File]::WriteAllText($configPath, $updated, (New-Object System.Text.UTF8Encoding($false)))

    $aghExe = Join-Path $TargetDir 'AdGuardHome.exe'
    if (Test-Path $aghExe) {
        & $aghExe -c $configPath --check-config 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
        if ($LASTEXITCODE -ne 0) {
            throw 'AdGuardHome --check-config rechazo la configuracion.'
        }
    }

    Set-DnsProfileEnv -Value $Profile
    Write-Host ("  Perfil DNS aplicado: {0}" -f $Profile) -ForegroundColor Green

    if ($Restart) {
        $svc = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Step 'Reiniciando AdGuard Home...'
            Restart-Service -Name 'AdGuardHome' -Force
            Start-Sleep -Seconds 3
        }
    }
} catch {
    Write-Warning ("Fallo al aplicar el perfil: {0}. Restaurando respaldo." -f $_.Exception.Message)
    Copy-Item -Path $backup -Destination $configPath -Force
    exit 4
}

Write-Host ''
Write-Host ('Perfil activo: {0}. Comprueba con scripts\test_fortress.ps1.' -f $Profile) -ForegroundColor Cyan
exit 0
