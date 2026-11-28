#Requires -Version 5.1
<#
.SYNOPSIS
    Aplica un perfil coherente de upstreams DNS (tor / speed / censorship / privacy).

.DESCRIPTION
    Reescribe el bloque marcado con FORTRESS-UPSTREAM en AdGuardHome.yaml:

      tor          DNS-over-HTTPS a Quad9 a traves del puente local
                   127.0.0.1:5336, que sale unicamente por Tor (9050).
      speed        Igual que tor, con timeouts ajustados.
      censorship   Igual que tor, con timeouts amplios para redes hostiles.
      privacy      Resolutor recursivo propio (Unbound en 127.0.0.1:5335).
                   Ningun tercero ve el patron de consultas. Requiere Unbound.

    En los perfiles tor/speed/censorship AdGuard Home nunca abre una conexion
    directa a Internet: habla con el puente en loopback y el puente es el unico
    que usa 127.0.0.1:9050. El puente reenvia el bit DO y las respuestas DNSSEC
    sin modificarlas; Quad9 valida la cadena.

    Si el YAML no tiene los marcadores (instalaciones anteriores), migra el
    bloque DNS completo sin tocar el resto de la configuracion. Antes de
    escribir valida con AdGuardHome.exe --check-config y, si -Restart, detiene
    el servicio para que no sobrescriba el archivo al cerrarse.

.PARAMETER Profile
    tor (por defecto), speed, censorship o privacy.

.PARAMETER Restart
    Detiene AdGuard Home antes de escribir y lo vuelve a iniciar despues.

.PARAMETER DryRun
    Muestra el bloque resultante sin escribir nada.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\apply-dns-profile.ps1 -Profile tor -Restart
#>

[CmdletBinding()]
param(
    [ValidateSet('tor', 'speed', 'censorship', 'privacy')]
    [string]$Profile = 'tor',
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
$bridgePort = 5336
$unboundPort = 5335

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

# Migra instalaciones antiguas: quita las claves DNS gestionadas y coloca el
# bloque marcado al final de la seccion dns:, conservando el resto del YAML.
function Add-FortressUpstreamBlock {
    param([string]$Text, [string]$Block)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]]($Text -split "`r?`n"))

    $dnsIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^dns:\s*$') { $dnsIndex = $i; break }
    }
    if ($dnsIndex -lt 0) { throw 'No se encontro la seccion dns: en AdGuardHome.yaml.' }

    $dnsEnd = $lines.Count
    for ($i = $dnsIndex + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\S') { $dnsEnd = $i; break }
    }

    $targets = 'upstream_dns|upstream_dns_file|bootstrap_dns|fallback_dns|upstream_mode|fastest_timeout|upstream_timeout'
    $output = [System.Collections.Generic.List[string]]::new()
    $blockLines = [string[]](($Block.TrimEnd()) -split "`r?`n")
    $blockHasTimeout = [bool]($Block -match '(?m)^\s*upstream_timeout:')

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($i -eq $dnsEnd) {
            foreach ($line in $blockLines) { $output.Add($line) }
            if (-not $blockHasTimeout) { $output.Add('  upstream_timeout: 5s') }
        }

        if ($i -gt $dnsIndex -and $i -lt $dnsEnd -and $lines[$i] -match ('^  (' + $targets + '):')) {
            $i++
            while ($i -lt $dnsEnd -and ($lines[$i] -match '^\s{4,}' -or $lines[$i] -match '^\s*$')) { $i++ }
            $i--
            continue
        }

        $output.Add($lines[$i])
    }

    if ($dnsEnd -eq $lines.Count) {
        foreach ($line in $blockLines) { $output.Add($line) }
        if (-not $blockHasTimeout) { $output.Add('  upstream_timeout: 5s') }
    }

    return ($output -join "`r`n")
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

$torBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil tor: AdGuard solo habla con el puente DoH local en 5336.
  # El puente sale por SOCKS5 127.0.0.1:9050; no hay upstream directo.
  upstream_dns:
    - 127.0.0.1:5336
    # .onion se resuelve dentro de Tor, sin resolutor convencional.
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5336
  fallback_dns: []
  upstream_mode: parallel
  fastest_timeout: 2s
  # <<< FORTRESS-UPSTREAM <<<
'@

$speedBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil speed: puente DoH local sobre Tor, timeouts ajustados.
  upstream_dns:
    - 127.0.0.1:5336
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5336
  fallback_dns: []
  upstream_mode: parallel
  fastest_timeout: 1s
  # <<< FORTRESS-UPSTREAM <<<
'@

$censorshipBlock = @'
  # >>> FORTRESS-UPSTREAM >>>
  # Perfil censorship: puente DoH sobre Tor con timeouts amplios.
  # Combinalo con UseBridges/obfs4 en torrc cuando la red bloquee Tor directo.
  upstream_dns:
    - 127.0.0.1:5336
    - '[/onion/]127.0.0.1:5350'
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:5336
  fallback_dns: []
  upstream_mode: parallel
  fastest_timeout: 3s
  # <<< FORTRESS-UPSTREAM <<<
'@

$block = $torBlock
$timeout = '8s'
if ($Profile -eq 'privacy') {
    $block = $privacyBlock
    $timeout = '8s'
    if (-not (Test-TcpPort -Port $unboundPort)) {
        Write-Error ('El perfil privacy necesita Unbound en 127.0.0.1:{0}. Ejecuta scripts\setup-unbound.ps1.' -f $unboundPort)
        exit 3
    }
} elseif ($Profile -eq 'censorship') {
    $block = $censorshipBlock
    $timeout = '10s'
    if (-not (Test-TcpPort -Port $bridgePort)) {
        Write-Error ('El perfil censorship necesita el puente DoH en 127.0.0.1:{0}. Inicia la tarea AdGuardHome_Fortress_DoHBridge.' -f $bridgePort)
        exit 3
    }
} else {
    if ($Profile -eq 'speed') { $block = $speedBlock; $timeout = '8s' }
    if (-not (Test-TcpPort -Port $bridgePort)) {
        Write-Error ('El perfil {0} necesita el puente DoH en 127.0.0.1:{1}. Inicia la tarea AdGuardHome_Fortress_DoHBridge.' -f $Profile, $bridgePort)
        exit 3
    }
}

# .NET lee UTF-8 sin BOM de forma fiable; Get-Content -Raw en PowerShell 5.1
# interpretaria el YAML como ANSI y corromperia los emojis de los comentarios.
$original = [System.IO.File]::ReadAllText($configPath)
if ($original -notmatch '(?s)# >>> FORTRESS-UPSTREAM >>>.*?# <<< FORTRESS-UPSTREAM <<<') {
    Write-Step 'YAML sin marcadores FORTRESS-UPSTREAM: migrando el bloque DNS...'
    try {
        $original = Add-FortressUpstreamBlock -Text $original -Block $block
    } catch {
        Write-Error ('No se pudo migrar el bloque DNS: {0}' -f $_.Exception.Message)
        exit 2
    }
    if ($original -notmatch '(?s)# >>> FORTRESS-UPSTREAM >>>.*?# <<< FORTRESS-UPSTREAM <<<') {
        Write-Error 'La migracion no genero los marcadores FORTRESS-UPSTREAM.'
        exit 2
    }
}

# El bloque no contiene '$', asi que se usa como reemplazo literal.
$updated = [regex]::Replace(
    $original,
    '(?s)# >>> FORTRESS-UPSTREAM >>>.*?# <<< FORTRESS-UPSTREAM <<<',
    $block.TrimEnd()
)
if ($updated -match '(?m)^(\s*upstream_timeout:\s*).*$') {
    $updated = [regex]::Replace($updated, '(?m)^(\s*upstream_timeout:\s*).*$', ('${1}' + $timeout))
} else {
    $updated = $updated.TrimEnd() + [Environment]::NewLine + ('  upstream_timeout: ' + $timeout) + [Environment]::NewLine
}

if ($DryRun) {
    Write-Host ('DRY-RUN: perfil {0} (upstream_timeout {1}). Bloque resultante:' -f $Profile, $timeout) -ForegroundColor Cyan
    Write-Host $block
    exit 0
}

$backup = $configPath + '.bak-profile-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -Path $configPath -Destination $backup -Force
Write-Step ("Respaldo creado en {0}" -f $backup)

$svc = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
$wasRunning = [bool]($svc -and $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
$stoppedForWrite = $false

try {
    if ($Restart -and $wasRunning) {
        Write-Step 'Deteniendo AdGuard Home para escribir la configuracion...'
        Stop-Service -Name 'AdGuardHome' -Force
        for ($i = 0; $i -lt 20; $i++) {
            $svc = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) { break }
            Start-Sleep -Milliseconds 500
        }
        $stoppedForWrite = $true
    } elseif ($wasRunning) {
        Write-Warning 'AdGuard Home esta en ejecucion: puede sobrescribir el YAML al cerrarse. Usa -Restart.'
    }

    [System.IO.File]::WriteAllText($configPath, $updated, (New-Object System.Text.UTF8Encoding($false)))

    $aghExe = Join-Path $TargetDir 'AdGuardHome.exe'
    if (Test-Path $aghExe) {
        # PowerShell 5.1 convierte el stderr nativo en ErrorRecord cuando
        # ErrorActionPreference=Stop. Se captura con Continue y se decide por
        # el codigo de salida real, no por el texto de los logs.
        $previousEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $checkOutput = & $aghExe -c $configPath --check-config 2>&1
        $checkExit = $LASTEXITCODE
        $ErrorActionPreference = $previousEap
        $checkOutput | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
        if ($checkExit -ne 0) {
            throw 'AdGuardHome --check-config rechazo la configuracion.'
        }
    }

    Set-DnsProfileEnv -Value $Profile
    Write-Host ("  Perfil DNS aplicado: {0}" -f $Profile) -ForegroundColor Green

    if ($Restart -and $wasRunning) {
        Write-Step 'Reiniciando AdGuard Home...'
        Start-Service -Name 'AdGuardHome'
        Start-Sleep -Seconds 3
    }
} catch {
    Write-Warning ("Fallo al aplicar el perfil: {0}. Restaurando respaldo." -f $_.Exception.Message)
    Copy-Item -Path $backup -Destination $configPath -Force
    if ($stoppedForWrite -and $wasRunning) {
        Start-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
    }
    exit 4
}

Write-Host ''
Write-Host ('Perfil activo: {0}. Comprueba con scripts\test_fortress.ps1.' -f $Profile) -ForegroundColor Cyan
exit 0
