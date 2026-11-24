<#
.SYNOPSIS
    Desinstala la fortaleza y devuelve el equipo a su estado DNS original.

.DESCRIPTION
    Orden de las operaciones (de menos a mas invasivo):

      1. Detiene y elimina las tareas programadas (watchdog y failsafe).
      2. Detiene los procesos node del centinela y del senuelo.
      3. Desactiva las reglas de firewall creadas por el instalador.
      4. Devuelve los adaptadores a DNS automatico (DHCP) y purga la cache.
      5. Revierte las politicas de DoH de los navegadores.
      6. Restaura la ACL original de config\.env (si existe respaldo).

    No borra datos salvo que se indique -RemoveData. No desinstala AdGuard Home,
    Tor ni GoodbyeDPI: solo deshace lo que hizo este repositorio.

.PARAMETER RemoveData
    Borra tambien logs, cache y respaldos de configuracion.

.PARAMETER RestorationSharedAccess
    Vuelve a habilitar el servicio SharedAccess. ADVERTENCIA: puede recuperar el
    secuestro del puerto 53 y dejar AdGuard Home sin poder arrancar. Solo para
    quien vaya a usar el punto de acceso movil de Windows.

.PARAMETER DryRun
    Muestra el plan sin ejecutarlo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\uninstall_fortress.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [switch]$RemoveData,
    [switch]$RestorationSharedAccess,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

function Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

Step ("Desinstalando fortaleza de {0}" -f $TargetDir)
if ($DryRun) {
    Write-Host 'DRY-RUN: no se aplicara ningun cambio.' -ForegroundColor Cyan
}

# 1. Tareas programadas
foreach ($task in @('AdGuardHome_Fortress_Watchdog', 'AdGuardHome_Fortress_Failsafe')) {
    $existing = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if (-not $existing) { continue }
    Step ("Eliminando tarea programada {0}" -f $task)
    if (-not $DryRun) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# 2. Procesos node de la fortaleza
foreach ($pattern in @('ai_dns_guard.js', 'decoy_dns.js')) {
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like ("*" + $pattern + "*") })
    foreach ($p in $procs) {
        Step ("Deteniendo {0} (PID {1})" -f $pattern, $p.ProcessId)
        if (-not $DryRun) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}

# 3. Reglas de firewall
$rules = @(
    'AdGuard_Block_Outbound_DNS_UDP',
    'AdGuard_Block_Outbound_DNS_TCP',
    'AdGuard_Block_Outbound_DOT_853',
    'AdGuard_Block_Outbound_MDNS'
)
foreach ($name in $rules) {
    if (-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)) { continue }
    Step ("Eliminando regla {0}" -f $name)
    if (-not $DryRun) { Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
}

# 4. DNS del sistema
$failsafe = Join-Path $TargetDir 'failsafe-dns.ps1'
if (Test-Path $failsafe) {
    Step 'Devolviendo adaptadores a DNS automatico (via failsafe -Restore)'
    if (-not $DryRun) { & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $failsafe -Restore }
} else {
    foreach ($adapter in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        $cfg = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if (-not ($cfg.ServerAddresses -contains '127.0.0.1')) { continue }
        Step ("Restaurando DNS de {0}" -f $adapter.Name)
        if (-not $DryRun) { Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses -ErrorAction SilentlyContinue }
    }
}

# 5. Politicas de navegador
$browser = Join-Path $TargetDir 'harden-browser-doh.ps1'
if (Test-Path $browser) {
    Step 'Revirtiendo politicas de DoH de los navegadores'
    if (-not $DryRun) { & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $browser -Undo }
}

# 6. ACL del .env
$acl = Join-Path $TargetDir 'harden-env-acl.ps1'
if (Test-Path $acl) {
    Step 'Restaurando ACL original de config\.env'
    if (-not $DryRun) { & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $acl -Restore }
}

# 7. SharedAccess opcional
if ($RestorationSharedAccess) {
    Step 'Rehabilitando SharedAccess (puede romper el puerto 53 de AdGuard)'
    if (-not $DryRun) {
        & sc.exe config SharedAccess start= demand | Out-Null
        Write-Host '  Servicio en modo manual. Reinicia si necesitas el punto de acceso movil.' -ForegroundColor Yellow
    }
}

# 8. Datos
if ($RemoveData) {
    foreach ($rel in @('logs', 'data', 'config\.env-acl-backup')) {
        $path = Join-Path $TargetDir $rel
        if (Test-Path $path) {
            Step ("Borrando {0}" -f $path)
            if (-not $DryRun) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Write-Host ''
Write-Host 'Desinstalacion completada.' -ForegroundColor Green
Write-Host 'AdGuard Home, Tor y GoodbyeDPI siguen instalados: este script solo deshace los cambios del repositorio.'
Write-Host 'Se conservan configuracion, logs y respaldos salvo que uses -RemoveData.'
