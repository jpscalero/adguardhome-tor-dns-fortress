# ==============================================================================
# Fortress Doctor - diagnostico y reparacion de la fortaleza DNS
# ==============================================================================
# Uso:
#   powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1
#   powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1 -Fix
#   powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1 -History
#   powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1 -Json
#
# Guarda:
#   data\fortress-events.jsonl      historial de incidentes (una linea JSON)
#   data\fortress-diagnosis.json    ultimo diagnostico estructurado
#   diagnostico-AAAAmmdd-HHmmss.md  informe legible
#
# No cambia el upstream ni el YAML. Las reparaciones son: arrancar servicios,
# reiniciar el puente, reiniciar AdGuard, arrancar el decoy si el pipeline esta
# sano y crear reglas de firewall que falten. Todo queda registrado.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$AdGuardDir = '',
    [switch]$Fix,
    [switch]$History,
    [switch]$Json,
    [switch]$SkipTorExit
)

$ErrorActionPreference = 'Continue'
$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }
$healthHelper = Join-Path $PSScriptRoot 'fortress-health.ps1'
if (-not (Test-Path $healthHelper)) {
    Write-Host 'Falta fortress-health.ps1; no se puede diagnosticar.' -ForegroundColor Red
    exit 1
}
. $healthHelper

if (-not $AdGuardDir) {
    $AdGuardDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}
$dataDir = Join-Path $AdGuardDir 'data'
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
$eventsPath = Join-Path $dataDir 'fortress-events.jsonl'
$statePath = Join-Path $dataDir 'fortress-state.json'
$bridgeStatusPath = Join-Path $dataDir 'doh-bridge-status.json'
$decoyStatusPath = Join-Path $dataDir 'decoy-status.json'
$watchdogLog = Join-Path $AdGuardDir 'watchdog.log'
$bridgeLog = Join-Path $AdGuardDir 'doh-bridge.log'
$decoyLog = Join-Path $AdGuardDir 'logs\decoy.log'
$aiLog = Join-Path $AdGuardDir 'logs\ai_guard.log'
$failsafeLog = Join-Path $AdGuardDir 'failsafe.log'

$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

function Get-TailText {
    param([string]$Path, [int]$Lines = 160)
    try {
        if (-not (Test-Path $Path)) { return '' }
        return (Get-Content -Path $Path -Tail $Lines -ErrorAction SilentlyContinue) -join "`n"
    } catch { return '' }
}

function Get-RecentDecoyRestarts {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return 0 }
        $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-15)
        $count = 0
        foreach ($line in (Get-Content -Path $Path -Tail 500 -ErrorAction SilentlyContinue)) {
            if ($line -notmatch 'Generador Decoy DNS no esta en ejecucion') { continue }
            if ($line -match '^\[([^\]]+)\]') {
                try {
                    $ts = [DateTime]::Parse($Matches[1]).ToUniversalTime()
                    if ($ts -ge $cutoff) { $count++ }
                } catch { }
            }
        }
        return $count
    } catch { return 0 }
}

function Get-DnsAdapters {
    try {
        return @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.ServerAddresses -contains '127.0.0.1'
        })
    } catch { return @() }
}

if ($History) {
    if (-not (Test-Path $eventsPath)) {
        Write-Host 'Todavia no hay incidentes registrados.' -ForegroundColor Yellow
        exit 0
    }
    $items = Get-Content -Path $eventsPath -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $_ }
    $items | Select-Object ts, level, code, message | Format-Table -AutoSize
    exit 0
}

$script:Findings = New-Object System.Collections.ArrayList

function Add-Finding {
    param(
        [string]$Code,
        [ValidateSet('CRITICAL', 'WARN', 'INFO')][string]$Severity,
        [string]$Title,
        [string]$Cause,
        [string]$FixText
    )
    if (($script:Findings | Where-Object { $_.Code -eq $Code }).Count -gt 0) { return }
    [void]$script:Findings.Add([pscustomobject]@{
        Code = $Code
        Severity = $Severity
        Title = $Title
        Cause = $Cause
        Fix = $FixText
    })
}

# ---------------------------------------------------------------------------
# Recoleccion
# ---------------------------------------------------------------------------
$bridge = Get-FortressBridgeStatus -AdGuardDir $AdGuardDir
$decoy = Get-FortressDecoyStatus -AdGuardDir $AdGuardDir
$state = Get-FortressJsonFile -Path $statePath
$watchdogText = Get-TailText -Path $watchdogLog -Lines 220
$bridgeText = Get-TailText -Path $bridgeLog -Lines 120
$decoyText = Get-TailText -Path $decoyLog -Lines 80
$aiText = Get-TailText -Path $aiLog -Lines 80
$failsafeText = Get-TailText -Path $failsafeLog -Lines 60
$decoyRestarts = Get-RecentDecoyRestarts -Path $watchdogLog
$dnsAdapters = Get-DnsAdapters
$wpad = $null
try {
    $wpad = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -ErrorAction SilentlyContinue).AutoDetect
} catch { }

$torService = Get-FortressServiceStatus -Name 'tor'
$aghService = Get-FortressServiceStatus -Name 'AdGuardHome'
$torPort = Test-FortressTcpPort -Port 9050 -TimeoutMs 1500
$bridgePort = Test-FortressTcpPort -Port 5336 -TimeoutMs 1500
$torExit = $null
$bridgeDns = $null
$aghDns = $null

if ($torPort -and -not $SkipTorExit) {
    $torExit = Test-FortressTorExit -TimeoutMs 15000
}
if ($bridgePort) {
    $bridgeDns = Test-FortressDnsQuery -Name 'example.com' -Port 5336 -TimeoutMs 8000
}
if ($aghService -eq 'Running') {
    $aghDns = Test-FortressDnsQuery -Name 'example.com' -Port 53 -TimeoutMs 12000
}

$direct443 = $null
try { $direct443 = Get-NetFirewallRule -Name 'AdGuard_Block_AdGuard_Direct_HTTPS_TCP' -ErrorAction SilentlyContinue } catch { }

# ---------------------------------------------------------------------------
# Diagnostico (base de conocimiento)
# ---------------------------------------------------------------------------
if ($aghService -ne 'Running') {
    Add-Finding -Code 'AGH_STOPPED' -Severity 'CRITICAL' -Title 'AdGuard Home esta detenido' `
        -Cause 'El servicio no esta en ejecucion; el puerto 53 no responde y todo el DNS falla.' `
        -Fix 'Arrancar el servicio AdGuardHome y comprobar que el puente 5336 esta sano.'
}
if (-not $torPort) {
    Add-Finding -Code 'TOR_DOWN' -Severity 'CRITICAL' -Title 'Tor SOCKS5 9050 no escucha' `
        -Cause 'El servicio Tor esta parado o el puerto no se abrio; el puente no puede salir.' `
        -Fix 'Arrancar o reiniciar el servicio tor; comprobar el log de Tor.'
} elseif ($torExit -and -not $torExit.Success) {
    Add-Finding -Code 'TOR_EXIT_FAIL' -Severity 'CRITICAL' -Title 'Tor no completa una salida' `
        -Cause "SOCKS5 acepta la conexion pero no logra CONNECT/HTTP: $($torExit.Error)" `
        -Fix 'Reiniciar Tor y, si hay password de control, enviar SIGNAL NEWNYM; revisar red/reloj.'
}
if (-not $bridgePort) {
    Add-Finding -Code 'BRIDGE_DOWN' -Severity 'CRITICAL' -Title 'Puente DoH/Tor 5336 no escucha' `
        -Cause 'El proceso del puente no arranco o murio; AdGuard no tiene upstream DNS.' `
        -Fix 'Reiniciar la tarea AdGuardHome_Fortress_DoHBridge y revisar doh-bridge.log.'
} elseif ($bridgeDns -and -not $bridgeDns.Success) {
    Add-Finding -Code 'BRIDGE_DNS_FAIL' -Severity 'CRITICAL' -Title 'El puente 5336 no resuelve' `
        -Cause "El puerto abre pero la consulta falla: $($bridgeDns.Error)" `
        -Fix 'Revisar doh-bridge.log; comprobar Tor 9050 y que el puente nuevo use HTTP/2.'
}
if ($bridgeText -match 'HTTP 505') {
    Add-Finding -Code 'BRIDGE_HTTP1_505' -Severity 'CRITICAL' -Title 'Quad9 devuelve HTTP 505' `
        -Cause 'El puente esta usando HTTP/1.1; Quad9 retiro ese protocolo el 15/12/2025.' `
        -Fix 'Desplegar doh-tor-bridge.js con HTTP/2 (ALPN h2) y reiniciar la tarea del puente.'
}
if ($aghService -eq 'Running' -and $bridgeDns -and $bridgeDns.Success -and $aghDns -and -not $aghDns.Success) {
    Add-Finding -Code 'AGH_DNS_FAIL' -Severity 'CRITICAL' -Title 'AdGuard no resuelve aunque el puente si' `
        -Cause "El puente responde, pero 127.0.0.1:53 falla: $($aghDns.Error)" `
        -Fix 'Reiniciar AdGuard; si persiste, revisar upstream_dns en AdGuardHome.yaml (debe ser 127.0.0.1:5336).'
}
if ($aghService -ne 'Running' -and $bridgeDns -and $bridgeDns.Success) {
    Add-Finding -Code 'AGH_STOPPED_BRIDGE_OK' -Severity 'CRITICAL' -Title 'El puente funciona pero AdGuard esta parado' `
        -Cause 'Solo falta arrancar AdGuard; el camino Tor/DoH ya esta sano.' `
        -Fix 'Start-Service AdGuardHome.'
}
if ($decoyRestarts -ge 3 -or ($decoy -and $decoy.state -eq 'fatal')) {
    Add-Finding -Code 'DECOY_LOOP' -Severity 'WARN' -Title 'Bucle de relanzamiento del decoy' `
        -Cause "Se detectaron $decoyRestarts relanzamientos en 15 min. La version vieja termina cuando no hay DNS." `
        -Fix 'Desplegar decoy_dns.js v3 (persistente y con circuit breaker); el watchdog ya no lo relanza si el DNS no esta sano.'
}
if ($aghService -eq 'Running' -and $bridgeDns -and $bridgeDns.Success -and $aghDns -and $aghDns.Success -and -not (Get-FortressProcessList -Pattern '*decoy_dns.js*').Count) {
    Add-Finding -Code 'DECOY_STOPPED' -Severity 'WARN' -Title 'Decoy detenido con la red sana' `
        -Cause 'El generador de senuelos no esta corriendo; no afecta al DNS, pero se pierde el ruido de privacidad.' `
        -Fix 'Arrancar decoy_dns.js (o esperar al watchdog, que ya lo hara si el pipeline esta sano).'
}
if ($aiText -match 'ECONNREFUSED 127\.0\.0\.1:3000') {
    Add-Finding -Code 'AI_AGH_DOWN' -Severity 'WARN' -Title 'Centinela AI no puede hablar con AdGuard' `
        -Cause 'AdGuard esta detenido o su API web 127.0.0.1:3000 no responde; el centinela reintenta en bucle.' `
        -Fix 'Arrancar AdGuard; el centinela nuevo limita el log a un aviso cada 5 minutos.'
}
if ($aiText -match 'Gemini HTTP') {
    Add-Finding -Code 'AI_GEMINI_HTTP' -Severity 'WARN' -Title 'Gemini rechaza la peticion' `
        -Cause 'Clave, modelo o cuota invalida. El centinela cae a la heuristica local.' `
        -Fix 'Revisar GEMINI_API_KEY y GEMINI_MODEL en config\.env; el modelo por defecto es gemini-2.5-flash-lite.'
}
if ($dnsAdapters.Count -eq 0) {
    Add-Finding -Code 'DNS_ADAPTER' -Severity 'WARN' -Title 'Ningun adaptador apunta a 127.0.0.1' `
        -Cause 'DHCP u otro programa cambio el DNS; el sistema puede saltarse AdGuard.' `
        -Fix 'Ejecutar failsafe-dns.ps1 o volver a poner DNS 127.0.0.1 en el adaptador activo.'
}
if ($wpad -ne $null -and [int]$wpad -ne 0) {
    Add-Finding -Code 'WPAD_ON' -Severity 'WARN' -Title 'WPAD/AutoDetect activo' `
        -Cause 'Puede intentar descubrir un proxy por red y generar consultas/errores.' `
        -Fix 'Poner AutoDetect=0 en HKCU Internet Settings.'
}
if (-not $direct443) {
    Add-Finding -Code 'DIRECT_443_RULE' -Severity 'WARN' -Title 'Falta bloquear HTTPS directo de AdGuard' `
        -Cause 'AdGuard puede abrir 443 directo para filtros/actualizaciones, fuera de Tor.' `
        -Fix 'Crear la regla de salida AdGuard_Block_AdGuard_Direct_HTTPS_TCP/UDP.'
}
if ($bridgeText -match 'Certificado TLS no valido|alpn|ALPN') {
    Add-Finding -Code 'BRIDGE_TLS' -Severity 'CRITICAL' -Title 'Problema TLS/ALPN en el puente' `
        -Cause 'El SNI no coincide con el certificado o el upstream no negocia HTTP/2.' `
        -Fix 'Usar dns.quad9.net para Quad9 o cloudflare-dns.com para Cloudflare; no usar una IP como SNI.'
}
if ($bridgeText -match 'Timeout SOCKS5|ECONNREFUSED') {
    Add-Finding -Code 'BRIDGE_TOR' -Severity 'CRITICAL' -Title 'El puente no alcanza Tor' `
        -Cause 'Tor no acepta SOCKS5 en 127.0.0.1:9050.' `
        -Fix 'Arrancar/reiniciar tor y comprobar que 9050 escucha.'
}
if ($script:Findings.Count -eq 0) {
    Add-Finding -Code 'ALL_OK' -Severity 'INFO' -Title 'Pipeline sano' `
        -Cause 'Servicio, Tor, puente, AdGuard y DNS responden.' `
        -Fix 'No hay accion necesaria.'
}

# ---------------------------------------------------------------------------
# Reparacion segura
# ---------------------------------------------------------------------------
$fixes = New-Object System.Collections.ArrayList
function Add-FixResult {
    param([string]$Code, [bool]$Ok, [string]$Detail)
    [void]$fixes.Add([pscustomobject]@{ Code = $Code; Ok = $Ok; Detail = $Detail })
    Add-FortressEvent -Code $Code -Level $(if ($Ok) { 'HEAL' } else { 'ERROR' }) -Message $Detail -AdGuardDir $AdGuardDir
}

if ($Fix) {
    if (-not $isAdmin) {
        Write-Host 'AVISO: -Fix requiere PowerShell como Administrador para servicios, firewall y tareas.' -ForegroundColor Yellow
    }

    if ($aghService -ne 'Running') {
        try {
            Start-Service -Name 'AdGuardHome' -ErrorAction Stop
            Add-FixResult -Code 'FIX_AGH_START' -Ok $true -Detail 'AdGuardHome iniciado.'
            Start-Sleep -Seconds 3
        } catch {
            Add-FixResult -Code 'FIX_AGH_START' -Ok $false -Detail $_.Exception.Message
        }
    }

    if (-not $torPort) {
        try {
            Start-Service -Name 'tor' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            if (-not (Test-FortressTcpPort -Port 9050 -TimeoutMs 2000)) {
                Restart-Service -Name 'tor' -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            $ok = Test-FortressTcpPort -Port 9050 -TimeoutMs 2000
            Add-FixResult -Code 'FIX_TOR' -Ok $ok -Detail $(if ($ok) { 'Tor 9050 recuperado.' } else { 'Tor sigue sin abrir 9050.' })
        } catch {
            Add-FixResult -Code 'FIX_TOR' -Ok $false -Detail $_.Exception.Message
        }
    }

    $needBridgeFix = (-not $bridgePort) -or ($bridgeDns -and -not $bridgeDns.Success)
    if ($needBridgeFix) {
        try {
            $procs = Get-FortressProcessList -Pattern '*doh-tor-bridge.js*'
            foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
            Stop-ScheduledTask -TaskName 'AdGuardHome_Fortress_DoHBridge' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            Start-ScheduledTask -TaskName 'AdGuardHome_Fortress_DoHBridge' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            $probe = Test-FortressDnsQuery -Name 'example.com' -Port 5336 -TimeoutMs 10000
            Add-FixResult -Code 'FIX_BRIDGE' -Ok ([bool]$probe.Success) -Detail $(if ($probe.Success) { 'Puente 5336 recuperado.' } else { "Puente sigue fallando: $($probe.Error)" })
        } catch {
            Add-FixResult -Code 'FIX_BRIDGE' -Ok $false -Detail $_.Exception.Message
        }
    }

    if ($aghService -eq 'Running' -and $bridgeDns -and $bridgeDns.Success -and $aghDns -and -not $aghDns.Success) {
        try {
            Restart-Service -Name 'AdGuardHome' -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 4
            $probe = Test-FortressDnsQuery -Name 'example.com' -Port 53 -TimeoutMs 12000
            Add-FixResult -Code 'FIX_AGH_RESTART' -Ok ([bool]$probe.Success) -Detail $(if ($probe.Success) { 'AdGuard resuelve de nuevo.' } else { "AdGuard sigue fallando: $($probe.Error)" })
        } catch {
            Add-FixResult -Code 'FIX_AGH_RESTART' -Ok $false -Detail $_.Exception.Message
        }
    }

    if (-not (Get-FortressProcessList -Pattern '*decoy_dns.js*').Count) {
        try {
            $node = Join-Path $AdGuardDir 'node\node.exe'
            $script = Join-Path $AdGuardDir 'decoy_dns.js'
            if ((Test-Path $node) -and (Test-Path $script) -and (Test-FortressDnsQuery -Name 'example.com' -Port 53 -TimeoutMs 8000).Success) {
                Start-Process -FilePath $node -ArgumentList ('"' + $script + '"') -WorkingDirectory $AdGuardDir -WindowStyle Hidden
                Add-FixResult -Code 'FIX_DECOY' -Ok $true -Detail 'Decoy iniciado.'
            } else {
                Add-FixResult -Code 'FIX_DECOY' -Ok $false -Detail 'No se inicia: falta node/script o el DNS no esta sano.'
            }
        } catch {
            Add-FixResult -Code 'FIX_DECOY' -Ok $false -Detail $_.Exception.Message
        }
    }

    if (-not $direct443) {
        try {
            New-NetFirewallRule -Name 'AdGuard_Block_AdGuard_Direct_HTTPS_TCP' -DisplayName 'AdGuard - Block direct HTTPS 443' -Direction Outbound -Action Block -Program (Join-Path $AdGuardDir 'AdGuardHome.exe') -Protocol TCP -RemotePort 443 -Enabled True -ErrorAction Stop | Out-Null
            New-NetFirewallRule -Name 'AdGuard_Block_AdGuard_Direct_HTTPS_UDP' -DisplayName 'AdGuard - Block direct HTTPS 443 UDP' -Direction Outbound -Action Block -Program (Join-Path $AdGuardDir 'AdGuardHome.exe') -Protocol UDP -RemotePort 443 -Enabled True -ErrorAction SilentlyContinue | Out-Null
            Add-FixResult -Code 'FIX_DIRECT_443' -Ok $true -Detail 'Reglas de bloqueo directo 443 creadas.'
        } catch {
            Add-FixResult -Code 'FIX_DIRECT_443' -Ok $false -Detail $_.Exception.Message
        }
    }

    if ($dnsAdapters.Count -eq 0) {
        try {
            $failsafe = Join-Path $AdGuardDir 'failsafe-dns.ps1'
            if (Test-Path $failsafe) {
                & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $failsafe -Trace | Out-Null
                Add-FixResult -Code 'FIX_DNS_ADAPTER' -Ok $true -Detail 'Failsafe ejecutado para restaurar DNS.'
            }
        } catch {
            Add-FixResult -Code 'FIX_DNS_ADAPTER' -Ok $false -Detail $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------
$severityOrder = @{ CRITICAL = 0; WARN = 1; INFO = 2 }
$ordered = @($script:Findings | Sort-Object @{ Expression = { $severityOrder[$_.Severity] } })
$overall = if ($ordered | Where-Object { $_.Severity -eq 'CRITICAL' }) { 'CRITICO' } elseif ($ordered | Where-Object { $_.Severity -eq 'WARN' }) { 'DEGRADADO' } else { 'SANO' }
$timestamp = Get-Date
$reportPath = Join-Path $AdGuardDir ('diagnostico-' + $timestamp.ToString('yyyyMMdd-HHmmss') + '.md')
$snapshot = [ordered]@{
    generatedAt = $timestamp.ToUniversalTime().ToString('o')
    overall = $overall
    admin = $isAdmin
    fix = [bool]$Fix
    checks = [ordered]@{
        torService = $torService
        torPort = $torPort
        torExit = $torExit
        bridgePort = $bridgePort
        bridgeDns = $bridgeDns
        adguardService = $aghService
        adguardDns = $aghDns
        decoyRestarts15m = $decoyRestarts
        dnsAdapters = @($dnsAdapters | ForEach-Object { $_.InterfaceAlias })
        wpadAutoDetect = $wpad
        direct443Rule = [bool]$direct443
    }
    findings = @($ordered)
    fixes = @($fixes)
}
$snapshotJson = $snapshot | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText((Join-Path $dataDir 'fortress-diagnosis.json'), $snapshotJson, (New-Object System.Text.UTF8Encoding($false)))
Add-FortressEvent -Code ('DIAG_' + $overall) -Level $(if ($overall -eq 'SANO') { 'INFO' } else { 'WARN' }) -Message ('Diagnostico: ' + (($ordered | ForEach-Object { $_.Code }) -join ', ')) -Data @{ overall = $overall; findings = @($ordered | ForEach-Object { $_.Code }) } -AdGuardDir $AdGuardDir

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Diagnostico de la fortaleza DNS')
$lines.Add('')
$lines.Add('- Fecha: ' + $timestamp.ToString('yyyy-MM-dd HH:mm:ss'))
$lines.Add('- Equipo: ' + $env:COMPUTERNAME)
$lines.Add('- Administrador: ' + $isAdmin)
$lines.Add('- Resultado: **' + $overall + '**')
$lines.Add('')
$lines.Add('## Comprobaciones')
$lines.Add('')
$lines.Add('| Prueba | Resultado |')
$lines.Add('|---|---|')
$lines.Add('| Servicio Tor | ' + $torService + ' |')
$lines.Add('| Puerto SOCKS5 9050 | ' + $torPort + ' |')
$lines.Add('| Salida Tor | ' + $(if ($torExit) { if ($torExit.Success) { 'OK (' + $torExit.ElapsedMs + ' ms)' } else { 'FALLO: ' + $torExit.Error } } else { 'omitida' }) + ' |')
$lines.Add('| Puerto puente 5336 | ' + $bridgePort + ' |')
$lines.Add('| DNS puente 5336 | ' + $(if ($bridgeDns) { if ($bridgeDns.Success) { 'OK (' + $bridgeDns.ElapsedMs + ' ms)' } else { 'FALLO: ' + $bridgeDns.Error } } else { 'no probado' }) + ' |')
$lines.Add('| Servicio AdGuard | ' + $aghService + ' |')
$lines.Add('| DNS AdGuard 53 | ' + $(if ($aghDns) { if ($aghDns.Success) { 'OK (' + $aghDns.ElapsedMs + ' ms)' } else { 'FALLO: ' + $aghDns.Error } } else { 'no probado' }) + ' |')
$lines.Add('| Relanzamientos decoy 15m | ' + $decoyRestarts + ' |')
$lines.Add('| Adaptadores con DNS 127.0.0.1 | ' + $dnsAdapters.Count + ' |')
$lines.Add('| WPAD AutoDetect | ' + $wpad + ' |')
$lines.Add('| Regla directo 443 | ' + [bool]$direct443 + ' |')
$lines.Add('')
$lines.Add('## Hallazgos y solucion')
$lines.Add('')
foreach ($f in $ordered) {
    $lines.Add('### [' + $f.Severity + '] ' + $f.Title)
    $lines.Add('')
    $lines.Add('- Codigo: `' + $f.Code + '`')
    $lines.Add('- Causa: ' + $f.Cause)
    $lines.Add('- Solucion: ' + $f.Fix)
    $lines.Add('')
}
if ($fixes.Count -gt 0) {
    $lines.Add('## Reparaciones ejecutadas')
    $lines.Add('')
    foreach ($x in $fixes) {
        $lines.Add('- `' + $x.Code + '`: ' + $(if ($x.Ok) { 'OK' } else { 'FALLO' }) + ' - ' + $x.Detail)
    }
    $lines.Add('')
}
$lines.Add('## Historial')
$lines.Add('')
$lines.Add('Los incidentes se guardan en `data\fortress-events.jsonl`.')
$lines.Add('')
$lines.Add('Para reparar: `powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1 -Fix`')
$lines.Add('Para ver historial: `powershell -ExecutionPolicy Bypass -File fortress-doctor.ps1 -History`')
$reportText = ($lines -join "`r`n")
[System.IO.File]::WriteAllText($reportPath, $reportText, (New-Object System.Text.UTF8Encoding($false)))

if ($Json) {
    Write-Output $snapshotJson
    exit $(if ($overall -eq 'SANO') { 0 } else { 2 })
}

Write-Host ''
Write-Host ('=== FORTALEZA DNS: ' + $overall + ' ===') -ForegroundColor $(if ($overall -eq 'SANO') { 'Green' } elseif ($overall -eq 'DEGRADADO') { 'Yellow' } else { 'Red' })
Write-Host ''
Write-Host 'Comprobaciones:' -ForegroundColor Cyan
Write-Host ('  Tor servicio/puerto/salida : {0} / {1} / {2}' -f $torService, $torPort, $(if ($torExit) { if ($torExit.Success) { 'OK' } else { $torExit.Error } } else { 'omitida' }))
Write-Host ('  Puente 5336 puerto/DNS    : {0} / {1}' -f $bridgePort, $(if ($bridgeDns) { if ($bridgeDns.Success) { 'OK' } else { $bridgeDns.Error } } else { 'no probado' }))
Write-Host ('  AdGuard servicio/DNS      : {0} / {1}' -f $aghService, $(if ($aghDns) { if ($aghDns.Success) { 'OK' } else { $aghDns.Error } } else { 'no probado' }))
Write-Host ('  Decoy relanzamientos 15m  : {0}' -f $decoyRestarts)
Write-Host ('  Adaptadores DNS local     : {0}' -f $dnsAdapters.Count)
Write-Host ''
Write-Host 'Hallazgos:' -ForegroundColor Cyan
foreach ($f in $ordered) {
    $color = if ($f.Severity -eq 'CRITICAL') { 'Red' } elseif ($f.Severity -eq 'WARN') { 'Yellow' } else { 'Green' }
    Write-Host ('  [{0}] {1}' -f $f.Severity, $f.Title) -ForegroundColor $color
    Write-Host ('        Causa: ' + $f.Cause)
    Write-Host ('        Arreglo: ' + $f.Fix)
}
if ($fixes.Count -gt 0) {
    Write-Host ''
    Write-Host 'Reparaciones:' -ForegroundColor Cyan
    foreach ($x in $fixes) {
        Write-Host ('  {0}: {1} - {2}' -f $x.Code, $(if ($x.Ok) { 'OK' } else { 'FALLO' }), $x.Detail) -ForegroundColor $(if ($x.Ok) { 'Green' } else { 'Red' })
    }
}
Write-Host ''
Write-Host ('Informe: ' + $reportPath) -ForegroundColor Gray
Write-Host ('Base de incidentes: ' + $eventsPath) -ForegroundColor Gray
if (-not $Fix -and $overall -ne 'SANO') {
    Write-Host ''
    Write-Host 'Para intentar reparar: ejecuta de nuevo con -Fix como Administrador.' -ForegroundColor Yellow
}
exit $(if ($overall -eq 'SANO') { 0 } else { 2 })
