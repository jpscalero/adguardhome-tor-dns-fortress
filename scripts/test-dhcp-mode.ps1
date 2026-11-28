# ==============================================================================
# Prueba controlada del modo DHCP (2026-11-28)
# - Pausa failsafe/guard/watchdog para que no reimpongan 127.0.0.1.
# - Desactiva SOLO las reglas de DNS 53 (UDP/TCP) durante la prueba.
# - Deja Ethernet en DHCP y comprueba router, sistema y web.
# - Restaura SIEMPRE las reglas, el DNS 127.0.0.1 y las tareas.
# ==============================================================================
$ErrorActionPreference = 'Continue'
$dir = 'C:\AdGuardHome'
$log = Join-Path $dir 'data\dhcp-mode-20261128.txt'
$iface = 14
$router = '192.168.0.1'
$tasks = @('AdGuardHome_DNS_Failsafe', 'AdGuardHome_Fortress_Guard', 'AdGuardHome_Fortress_Watchdog')
$rules = @('AdGuard_Block_Outbound_DNS_UDP', 'AdGuard_Block_Outbound_DNS_TCP')
$origRules = @{}
$result = $false

function L {
    param([string]$m)
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $m
    Write-Host $line
    try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch { }
}
Set-Content -Path $log -Value ('Prueba DHCP ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8

L 'Inicio. Guardando estado de reglas.'
foreach ($r in $rules) {
    $rule = Get-NetFirewallRule -Name $r -ErrorAction SilentlyContinue
    if ($rule) {
        $origRules[$r] = [string]$rule.Enabled
        L ("Regla {0}: {1}" -f $r, $rule.Enabled)
    } else { L ("Regla ausente: " + $r) }
}

try {
    L 'Pausando tareas que reimponen DNS/reglas.'
    foreach ($t in $tasks) {
        try {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null
            L ('Pausada: ' + $t)
        } catch { L ('No se pudo pausar ' + $t + ': ' + $_.Exception.Message) }
    }
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'failsafe-dns\.ps1|watchdog\.ps1|watchdog-guard\.ps1' } |
        ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; L ('Proceso detenido: ' + $_.ProcessId) } catch { } }

    L 'Desactivando reglas DNS 53.'
    foreach ($r in $rules) {
        try { Disable-NetFirewallRule -Name $r -ErrorAction Stop; L ('Desactivada: ' + $r) } catch { L ('ERROR al desactivar ' + $r + ': ' + $_.Exception.Message) }
    }

    L 'Poniendo Ethernet en DHCP.'
    Set-DnsClientServerAddress -InterfaceIndex $iface -ResetServerAddresses -ErrorAction Stop
    Clear-DnsClientCache
    Start-Sleep -Seconds 3
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $iface -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
    L ('DNS tras DHCP: ' + (($dns | Where-Object { $_ }) -join ','))

    L 'Sonda TCP 53 al router.'
    $tcp = Test-NetConnection -ComputerName $router -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
    L ('TCP 53 router: ' + $tcp)

    L ('Resolucion al router ' + $router + '.')
    try {
        $rr = Resolve-DnsName -Name 'example.com' -Server $router -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
        L ('Router A: ' + $rr.IPAddress)
    } catch { L ('Router ERROR: ' + $_.Exception.Message) }

    L 'Resolucion del sistema (DHCP).'
    try {
        $rs = Resolve-DnsName -Name 'example.com' -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
        L ('Sistema A: ' + $rs.IPAddress)
        $result = $true
    } catch { L ('Sistema ERROR: ' + $_.Exception.Message) }

    L 'Prueba HTTPS (sin depender de la sonda DNS).'
    try {
        $web = Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
        L ('HTTPS status: ' + $web.StatusCode)
        if ($web.StatusCode -eq 200) { $result = $true }
    } catch { L ('HTTPS ERROR: ' + $_.Exception.Message) }
}
catch {
    L ('ERROR en la prueba: ' + $_.Exception.Message)
}
finally {
    L 'Restaurando entorno de fortaleza.'
    foreach ($r in $rules) {
        try {
            if ($origRules.ContainsKey($r) -and $origRules[$r] -eq 'True') {
                Enable-NetFirewallRule -Name $r -ErrorAction Stop
                L ('Reactivada: ' + $r)
            }
        } catch { L ('ERROR al reactivar ' + $r + ': ' + $_.Exception.Message) }
    }

    try {
        Set-DnsClientServerAddress -InterfaceIndex $iface -ServerAddresses '127.0.0.1' -ErrorAction Stop
        Clear-DnsClientCache
        L 'DNS restaurado a 127.0.0.1.'
    } catch { L ('ERROR al restaurar DNS: ' + $_.Exception.Message) }

    foreach ($t in $tasks) {
        try {
            Enable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null
            L ('Rehabilitada: ' + $t)
        } catch { L ('ERROR al rehabilitar ' + $t + ': ' + $_.Exception.Message) }
    }
    foreach ($t in @('AdGuardHome_DNS_Failsafe', 'AdGuardHome_Fortress_Watchdog', 'AdGuardHome_Fortress_Guard')) {
        try { Start-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue; L ('Arrancada: ' + $t) } catch { L ('ERROR al arrancar ' + $t + ': ' + $_.Exception.Message) }
    }
    Start-Sleep -Seconds 8
    $after = @(Get-DnsClientServerAddress -InterfaceIndex $iface -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
    L ('DNS final: ' + (($after | Where-Object { $_ }) -join ','))
    try {
        $final = Resolve-DnsName -Name 'example.com' -Server '127.0.0.1' -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
        L ('AdGuard final A: ' + $final.IPAddress)
    } catch { L ('AdGuard final ERROR: ' + $_.Exception.Message) }
    $hb = Join-Path $dir 'watchdog.heartbeat'
    if (Test-Path $hb) { L ('Heartbeat edad: ' + [int]((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds + 's') }
    L ('Resultado DHCP funcional: ' + $result)
    L 'Fin.'
}
if ($result) { exit 0 } else { exit 1 }
