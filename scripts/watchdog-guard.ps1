#Requires -Version 5.1
<#
.SYNOPSIS
    Guardian del watchdog: lo resucita y repara lo que el malware desactiva.

.DESCRIPTION
    Se ejecuta cada 10 minutos como SYSTEM (tarea AdGuardHome_Fortress_Guard):

      - Si el heartbeat tiene mas de 5 minutos, relanza el watchdog.
      - Si la tarea del watchdog desaparecio, la vuelve a registrar.
      - Arranca AdGuardHome, tor y unbound si estan detenidos.
      - Reactiva las reglas anti-fuga si alguien las apago.
      - Verifica los hashes de los scripts; si cambiaron, restaura la copia base
        y reinicia AdGuard Home.

    Todo queda en guard.log. No envia nada a la red.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\watchdog-guard.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [int]$MaxHeartbeatAgeSeconds = 300
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'SilentlyContinue'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

$logFile = Join-Path $TargetDir 'guard.log'
$heartbeat = Join-Path $TargetDir 'watchdog.heartbeat'
$watchdogTask = 'AdGuardHome_Fortress_Watchdog'
$guardTask = 'AdGuardHome_Fortress_Guard'
$watchdog = Join-Path $TargetDir 'watchdog.ps1'
$integrity = Join-Path $TargetDir 'integrity-check.ps1'
$actions = @()

function Write-GuardLog {
    param([string]$Level, [string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        Add-Content -Path $logFile -Value $line -Encoding UTF8
        $item = Get-Item $logFile
        if ($item.Length -gt 512KB) {
            $old = $logFile + '.old'
            if (Test-Path $old) { Remove-Item $old -Force }
            Move-Item $logFile $old -Force
        }
    } catch { }
}

function Register-WatchdogTask {
    if (-not (Test-Path $watchdog)) { return }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "{0}"' -f $watchdog)
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $watchdogTask -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    $script:actions += 'watchdog_task_recreated'
}

function Ensure-Service {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $Name -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $script:actions += ('service_' + $Name + '_restarted')
    }
}

# 1. Heartbeat y tarea del watchdog.
$task = Get-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
if (-not $task) {
    Register-WatchdogTask
} else {
    $age = 999999
    if (Test-Path $heartbeat) { $age = ((Get-Date) - (Get-Item $heartbeat).LastWriteTime).TotalSeconds }
    if ($age -gt $MaxHeartbeatAgeSeconds) {
        Start-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
        $script:actions += 'watchdog_restarted'
    }
}

# 2. Servicios del nucleo.
foreach ($svc in @('AdGuardHome', 'tor', 'unbound')) {
    Ensure-Service -Name $svc
}

# 3. Reglas anti-fuga.
$rules = @(
    'AdGuard_Block_Outbound_DNS_UDP',
    'AdGuard_Block_Outbound_DNS_TCP',
    'AdGuard_Block_Outbound_DOT_853',
    'AdGuard_Block_Outbound_MDNS'
)
foreach ($name in $rules) {
    $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ((-not $rule) -or ($rule.Enabled -ne 'True')) {
        if ($rule) { Enable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
        elseif ($name -eq 'AdGuard_Block_Outbound_DNS_UDP') {
            New-NetFirewallRule -Name $name -DisplayName 'AdGuard - Block Outbound Plaintext DNS UDP' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -Enabled True | Out-Null
        } elseif ($name -eq 'AdGuard_Block_Outbound_DNS_TCP') {
            New-NetFirewallRule -Name $name -DisplayName 'AdGuard - Block Outbound Plaintext DNS TCP' -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -Enabled True | Out-Null
        } elseif ($name -eq 'AdGuard_Block_Outbound_DOT_853') {
            New-NetFirewallRule -Name $name -DisplayName 'AdGuard - Block Outbound DNS-over-TLS 853' -Direction Outbound -Action Block -Protocol TCP -RemotePort 853 -Enabled True | Out-Null
        } elseif ($name -eq 'AdGuard_Block_Outbound_MDNS') {
            New-NetFirewallRule -Name $name -DisplayName 'AdGuard - Block Outbound mDNS 5353' -Direction Outbound -Action Block -Protocol UDP -RemotePort 5353 -Enabled True | Out-Null
        }
        $script:actions += ('rule_' + $name + '_restored')
    }
}

# 4. Integridad del codigo.
if (Test-Path $integrity) {
    & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $integrity -Verify -TargetDir $TargetDir | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-GuardLog 'CRITICAL' 'Integridad de scripts alterada; restaurando copia base.'
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $integrity -Restore -TargetDir $TargetDir | Out-Null
        Restart-Service -Name 'AdGuardHome' -Force -ErrorAction SilentlyContinue
        $script:actions += 'integrity_restored'
    }
}

# 5. Guardian presente (si alguien lo borra, se recrea en la siguiente vuelta
#    del watchdog; aqui solo se deja constancia).
if (-not (Get-ScheduledTask -TaskName $guardTask -ErrorAction SilentlyContinue)) {
    $script:actions += 'guard_task_missing'
}

if ($actions.Count -gt 0) {
    Write-GuardLog 'HEAL' ('Acciones: ' + ($actions -join ', '))
} elseif (Test-Path $logFile) {
    Write-GuardLog 'INFO' 'Sin intervenciones.'
}

exit 0
