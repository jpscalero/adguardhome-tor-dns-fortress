<#
.SYNOPSIS
    Failsafe de red de la fortaleza DNS: evita quedarse sin Internet si AdGuard Home cae.

.DESCRIPTION
    Se ejecuta cada 2 minutos desde el Programador de tareas (SYSTEM) y mantiene
    coherentes tres cosas: resolucion local, DNS del sistema y reglas anti-fuga.

      - AdGuard responde y las reglas estan apagadas -> restaura MODO FORTALEZA
        (DNS 127.0.0.1 + reglas de bloqueo activas).
      - AdGuard NO responde -> MODO EMERGENCIA: apaga las reglas anti-fuga y pone
        DNS publico para no dejar el equipo sin resolucion.

    Si AdGuard responde, restaura 127.0.0.1 en los adaptadores fisicos activos
    aunque DHCP haya puesto un DNS publico: las reglas anti-fuga bloquean ese
    DNS externo y dejarlo seria quedarse sin resolucion. En emergencia solo
    cambia adaptadores que ya apuntaban a la fortaleza.

    Tapon de seguridad: la sonda es TCP al puerto 53 (no Resolve-DnsName, que da
    falsos negativos cuando solo falla un upstream y no el servidor local).

.PARAMETER DryRun
    Calcula y muestra lo que haria, sin cambiar nada.

.PARAMETER Restore
    Devuelve los adaptadores a DNS automatico (DHCP) y desactiva las reglas.

.PARAMETER Trace
    Escribe una linea de traza en cada ejecucion, incluso cuando no hace nada.
    Sin este modificador el log solo crece cuando el failsafe interviene.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\failsafe-dns.ps1 -Trace

.NOTES
    Codigo ASCII puro a proposito: Windows PowerShell 5.1 falla al parsear
    segun que caracteres no ASCII en scripts sin BOM.
#>

[CmdletBinding()]
param(
    [string]$AdGuardDir = '',
    [string]$LogFile = '',
    [string[]]$InterfaceAlias = @(),
    [string[]]$FallbackServers = @('1.1.1.1', '1.0.0.1'),
    [int]$ProbeAttempts = 3,
    [int]$ProbeDelaySeconds = 2,
    [switch]$Trace,
    [switch]$DryRun,
    [switch]$Restore
)

$ErrorActionPreference = 'SilentlyContinue'

if (-not $AdGuardDir) {
    $AdGuardDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}
if (-not $LogFile) {
    $LogFile = Join-Path $AdGuardDir 'failsafe.log'
}

$FortressRules = @(
    'AdGuard_Block_Outbound_DNS_UDP',
    'AdGuard_Block_Outbound_DNS_TCP',
    'AdGuard_Block_Outbound_DOT_853',
    'AdGuard_Block_Outbound_MDNS'
)

function Write-FailsafeLog {
    param([string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Output $line
    try {
        $dir = Split-Path -Parent $LogFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
        # Rotacion: 512 KB
        $item = Get-Item $LogFile
        if ($item.Length -gt 512KB) {
            $old = $LogFile + '.old'
            if (Test-Path $old) { Remove-Item $old -Force }
            Move-Item $LogFile $old -Force
        }
    } catch { }
}

function Test-AdGuard53 {
    for ($i = 1; $i -le $ProbeAttempts; $i++) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect('127.0.0.1', 53, $null, $null)
            $ok = $async.AsyncWaitHandle.WaitOne(1500, $false)
            if ($ok -and $client.Connected) { $client.Close(); return $true }
        } catch {
        } finally {
            if ($client) { try { $client.Close() } catch { } }
        }
        if ($i -lt $ProbeAttempts) { Start-Sleep -Seconds $ProbeDelaySeconds }
    }
    return $false
}

function Get-FortressRulesState {
    $states = @()
    foreach ($name in $FortressRules) {
        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        if ($rule) { $states += [bool]($rule.Enabled -eq 'True') }
    }
    if ($states.Count -eq 0) { return 'absent' }
    if ($states -contains $false) { return 'partial' }
    return 'on'
}

function Set-FortressRules {
    param([bool]$Enabled)
    foreach ($name in $FortressRules) {
        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        if (-not $rule) { continue }
        if ($DryRun) {
            Write-FailsafeLog ("DRY-RUN: regla {0} -> {1}" -f $name, $(if ($Enabled) { 'ON' } else { 'OFF' }))
            continue
        }
        if ($Enabled) { Enable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
        else { Disable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
    }
}

function Get-TargetAdapters {
    if ($InterfaceAlias.Count -gt 0) { return $InterfaceAlias }
    $names = @()
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.InterfaceDescription -notlike '*Virtual*' -and
            $_.InterfaceDescription -notlike '*Hyper-V*' -and
            $_.InterfaceDescription -notlike '*Loopback*'
        } |
        ForEach-Object { $names += $_.Name }
    return $names
}

function Get-CurrentDns {
    param([string]$Alias)
    $cfg = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $cfg) { return @() }
    return @($cfg.ServerAddresses)
}

function Set-SystemDns {
    param([string[]]$Servers, [switch]$ForceFortress)
    foreach ($alias in Get-TargetAdapters) {
        $current = Get-CurrentDns $alias
        $isFortressDns = ($current.Count -eq 1 -and $current[0] -eq '127.0.0.1')

        if ($Servers -contains '127.0.0.1') {
            if ($isFortressDns) { continue }
            if ($current.Count -gt 0) {
                if ($ForceFortress) {
                    Write-FailsafeLog ("{0}: DNS {1} ajeno; AdGuard responde, adoptando 127.0.0.1" -f $alias, ($current -join ','))
                } else {
                    if ($Trace) { Write-FailsafeLog ("{0}: DNS {1} no es de la fortaleza; no se toca" -f $alias, ($current -join ',')) }
                    continue
                }
            }
        } else {
            # Emergencia: solo si estaba apuntando a la fortaleza.
            if (-not $isFortressDns) {
                if ($Trace) { Write-FailsafeLog ("{0}: DNS {1} ajeno a la fortaleza; no se toca" -f $alias, ($current -join ',')) }
                continue
            }
        }

        if ($DryRun) {
            Write-FailsafeLog ("DRY-RUN: {0} DNS -> {1}" -f $alias, ($Servers -join ','))
            continue
        }
        Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $Servers -ErrorAction SilentlyContinue
        if ($Trace) { Write-FailsafeLog ("{0}: DNS -> {1}" -f $alias, ($Servers -join ',')) }
    }
}

function Reset-SystemDns {
    foreach ($alias in Get-TargetAdapters) {
        $current = Get-CurrentDns $alias
        if (-not ($current.Count -gt 0 -and $current[0] -eq '127.0.0.1')) { continue }
        if ($DryRun) { Write-FailsafeLog ("DRY-RUN: {0} DNS -> automatico" -f $alias); continue }
        Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction SilentlyContinue
        Write-FailsafeLog ("{0}: DNS devuelto a automatico" -f $alias)
    }
}

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------

if ($Restore) {
    Write-FailsafeLog 'MODO DESINSTALACION: devolviendo adaptadores a DNS automatico'
    Reset-SystemDns
    Set-FortressRules $false
    Clear-DnsClientCache
    Write-FailsafeLog 'Desinstalacion completada'
    exit 0
}

$adguardUp = Test-AdGuard53
$rulesState = Get-FortressRulesState
$service = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue

if ($Trace) {
    Write-FailsafeLog ("traza: adguard_53={0} reglas={1} servicio={2}" -f $adguardUp, $rulesState, $(if ($service) { $service.Status } else { 'ausente' }))
}

if ($adguardUp) {
    if ($rulesState -ne 'on') {
        Write-FailsafeLog ("MODO FORTALEZA: AdGuard responde en 53 y las reglas estan {0}. Restaurando." -f $rulesState)
        Set-FortressRules $true
        Write-FailsafeLog 'MODO FORTALEZA restaurado (reglas anti-fuga)'
    }
    Set-SystemDns -Servers @('127.0.0.1') -ForceFortress
    if (-not $DryRun) { Clear-DnsClientCache }
    exit 0
}

# AdGuard no responde: intentar levantarlo antes de rendirse
if ($service -and $service.Status -ne 'Running') {
    Write-FailsafeLog ("AdGuard no responde en 53 pero el servicio esta {0}. Intentando iniciarlo." -f $service.Status)
    if (-not $DryRun) {
        try { Start-Service -Name 'AdGuardHome' -ErrorAction Stop } catch { }
        Start-Sleep -Seconds 5
        if (Test-AdGuard53) {
            Write-FailsafeLog 'AdGuard arranco correctamente; no hace falta el modo emergencia'
            Set-FortressRules $true
            Set-SystemDns -Servers @('127.0.0.1') -ForceFortress
            exit 0
        }
    }
}

Write-FailsafeLog 'MODO EMERGENCIA: AdGuard no responde; DNS publico y reglas anti-fuga desactivadas'
Set-FortressRules $false
Set-SystemDns $FallbackServers
if (-not $DryRun) { Clear-DnsClientCache }
Write-FailsafeLog ("MODO EMERGENCIA activo (DNS {0})" -f ($FallbackServers -join ','))
exit 0
