#Requires -Version 5.1
<#
.SYNOPSIS
    Capa anti-manipulacion para malware con privilegios de administrador.

.DESCRIPTION
    Un administrador comprometido puede hacer cualquier cosa; este script no
    promete lo imposible. Lo que hace es subir el coste y cerrar las vias
    triviales que usa el malware oportunista:

      1. ACL: solo SYSTEM y Administradores pueden escribir scripts, lanzadores,
         configuracion, datos y logs. Los usuarios normales solo leen.
      2. Servicios: recuperacion automatica (restart) para AdGuardHome, tor,
         GoodbyeDPI y unbound; arranque automatico y failureflag.
      3. Watchdog: tarea con repeticion cada 5 minutos e instancias ignoradas,
         de modo que si la matan vuelve sola.
      4. Guardian: tarea AdGuardHome_Fortress_Guard cada 10 minutos que
         comprueba heartbeat, servicios, reglas y hashes de los scripts.
      5. Firewall: bloqueo entrante de panel (3000), SOCKS (9050), control Tor
         (9051), DNSPort (5350) y Unbound (5335). Loopback sigue permitido.
      6. Integridad: manifiesto SHA256 y copia base de los scripts criticos.

    Todo es reversible con -Undo (restaura ACL, elimina el guardian y las reglas
    nuevas; el watchdog y el failsafe los gestiona el desinstalador).

.PARAMETER Undo
    Revierte los cambios de este script.

.PARAMETER DryRun
    Muestra el plan sin aplicar nada.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\protect-fortress.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [switch]$Undo,
    [switch]$DryRun
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Continue'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

$configDir = Join-Path $TargetDir 'config'
$backupFile = Join-Path $configDir 'fortress-acl-backup'
$stateFile = Join-Path $configDir 'fortress-protected.json'
$guardTask = 'AdGuardHome_Fortress_Guard'
$watchdogTask = 'AdGuardHome_Fortress_Watchdog'
$inboundRules = @(
    'AdGuard_Block_Inbound_Panel_3000',
    'AdGuard_Block_Inbound_SOCKS_9050',
    'AdGuard_Block_Inbound_TorControl_9051',
    'AdGuard_Block_Inbound_DNSPort_5350',
    'AdGuard_Block_Inbound_Unbound_5335'
)

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

function Set-RestrictedAcl {
    param(
        [string]$Path,
        [switch]$UsersRead
    )
    if (-not (Test-Path $Path)) { return }
    if ($DryRun) {
        Write-Host ("  DRY-RUN: ACL restringida en {0}" -f $Path) -ForegroundColor Cyan
        return
    }
    if ($UsersRead) {
        & icacls $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 2>&1 | Out-Null
    } else {
        & icacls $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
    }
}

function Set-ServiceRecovery {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($DryRun) {
        Write-Host ("  DRY-RUN: {0} -> start=auto + restart 5s/15s/60s" -f $Name) -ForegroundColor Cyan
        return
    }
    & sc.exe config $Name start= auto 2>&1 | Out-Null
    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/15000/restart/60000 2>&1 | Out-Null
    & sc.exe failureflag $Name 1 2>&1 | Out-Null
    Write-Host ("  {0}: recuperacion automatica configurada." -f $Name) -ForegroundColor Green
}

function Register-FortressTask {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [int]$EveryMinutes
    )
    if (-not (Test-Path $ScriptPath)) { return }
    if ($DryRun) {
        Write-Host ("  DRY-RUN: tarea {0} cada {1} min -> {2}" -f $Name, $EveryMinutes, $ScriptPath) -ForegroundColor Cyan
        return
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "{0}"' -f $ScriptPath)
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host ("  Tarea {0} registrada (cada {1} min)." -f $Name, $EveryMinutes) -ForegroundColor Green
}

function Remove-InboundRules {
    foreach ($name in $inboundRules) {
        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        if (-not $rule) { continue }
        if ($DryRun) {
            Write-Host ("  DRY-RUN: eliminar regla {0}" -f $name) -ForegroundColor Cyan
            continue
        }
        Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path $TargetDir)) {
    Write-Error ("No existe {0}. Instala primero la fortaleza." -f $TargetDir)
    exit 2
}

if ($Undo) {
    Write-Step 'Revirtiendo la capa de proteccion...'
    Remove-InboundRules

    $task = Get-ScheduledTask -TaskName $guardTask -ErrorAction SilentlyContinue
    if ($task) {
        if (-not $DryRun) {
            Stop-ScheduledTask -TaskName $guardTask -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $guardTask -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host '  Guardian eliminado.'
    }

    if ((Test-Path $backupFile) -and -not $DryRun) {
        & icacls $TargetDir /restore $backupFile 2>&1 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
        Write-Host '  ACL original restaurada.' -ForegroundColor Green
    }

    if ((Test-Path $stateFile) -and -not $DryRun) {
        Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'Proteccion revertida.' -ForegroundColor Green
    exit 0
}

Write-Step 'Aplicando ACL restrictivas (SYSTEM/Administradores escriben, Usuarios leen)...'
if (-not $DryRun) {
    if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
    if (-not (Test-Path $backupFile)) {
        & icacls $TargetDir /save $backupFile /t /c 2>&1 | Out-Null
    }
}

Set-RestrictedAcl -Path $TargetDir -UsersRead
foreach ($dir in @('scripts', 'launchers', 'node')) {
    Set-RestrictedAcl -Path (Join-Path $TargetDir $dir) -UsersRead
}
foreach ($dir in @('config', 'data', 'logs')) {
    Set-RestrictedAcl -Path (Join-Path $TargetDir $dir)
}

$protectedFiles = @(Get-ChildItem -Path $TargetDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.ps1', '.cmd', '.vbs', '.js') })
foreach ($file in $protectedFiles) {
    if ($DryRun) { continue }
    & icacls $file.FullName /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' 2>&1 | Out-Null
}
Write-Host '  ACL aplicadas.' -ForegroundColor Green

Write-Step 'Configurando recuperacion automatica de servicios...'
foreach ($svc in @('AdGuardHome', 'tor', 'GoodbyeDPI', 'unbound')) {
    Set-ServiceRecovery -Name $svc
}

Write-Step 'Reforzando watchdog y registrando guardian...'
Register-FortressTask -Name $watchdogTask -ScriptPath (Join-Path $TargetDir 'watchdog.ps1') -EveryMinutes 5
Register-FortressTask -Name $guardTask -ScriptPath (Join-Path $TargetDir 'watchdog-guard.ps1') -EveryMinutes 10

Write-Step 'Creando reglas de firewall entrantes (loopback exento)...'
if (-not $DryRun) {
    $rules = @(
        @{ Name = 'AdGuard_Block_Inbound_Panel_3000'; Display = 'AdGuard - Block inbound panel 3000'; Protocol = 'TCP'; Port = 3000 },
        @{ Name = 'AdGuard_Block_Inbound_SOCKS_9050'; Display = 'AdGuard - Block inbound Tor SOCKS 9050'; Protocol = 'TCP'; Port = 9050 },
        @{ Name = 'AdGuard_Block_Inbound_TorControl_9051'; Display = 'AdGuard - Block inbound Tor control 9051'; Protocol = 'TCP'; Port = 9051 },
        @{ Name = 'AdGuard_Block_Inbound_DNSPort_5350'; Display = 'AdGuard - Block inbound Tor DNSPort 5350'; Protocol = 'TCP'; Port = 5350 },
        @{ Name = 'AdGuard_Block_Inbound_Unbound_5335'; Display = 'AdGuard - Block inbound Unbound 5335'; Protocol = 'TCP'; Port = 5335 }
    )
    foreach ($r in $rules) {
        if (-not (Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $r.Name -DisplayName $r.Display -Direction Inbound -Action Block -Protocol $r.Protocol -LocalPort $r.Port -Enabled True | Out-Null
        }
    }
    New-NetFirewallRule -Name 'AdGuard_Block_Inbound_Unbound_5335_UDP' -DisplayName 'AdGuard - Block inbound Unbound 5335 UDP' -Direction Inbound -Action Block -Protocol UDP -LocalPort 5335 -Enabled True -ErrorAction SilentlyContinue | Out-Null
}
Write-Host '  Reglas entrantes listas.' -ForegroundColor Green

Write-Step 'Generando manifiesto de integridad y copia base...'
$integrity = Join-Path $TargetDir 'integrity-check.ps1'
if (Test-Path $integrity) {
    if ($DryRun) {
        Write-Host '  DRY-RUN: integrity-check.ps1 -Create' -ForegroundColor Cyan
    } else {
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $integrity -Create -TargetDir $TargetDir
    }
}

if (-not $DryRun) {
    $state = [ordered]@{
        protected_at = (Get-Date).ToUniversalTime().ToString('o')
        version = '2.0.2'
        watchdog_task = $watchdogTask
        guard_task = $guardTask
        services = @('AdGuardHome', 'tor', 'GoodbyeDPI', 'unbound')
        inbound_rules = $inboundRules + @('AdGuard_Block_Inbound_Unbound_5335_UDP')
    }
    $state | ConvertTo-Json -Depth 4 | Set-Content -Path $stateFile -Encoding UTF8
}

Write-Host ''
Write-Host 'Proteccion aplicada. Un administrador comprometido sigue teniendo la ultima palabra,' -ForegroundColor Cyan
Write-Host 'pero ya no puede desactivar el watchdog, las reglas o los servicios sin dejar rastro.' -ForegroundColor Cyan
Write-Host 'Revisa guard.log y watchdog.log para ver las reparaciones automaticas.' -ForegroundColor Cyan
exit 0
