# ==============================================================================
# Reparacion final: ACL con SIDs, firewall 443, DNS adaptadores y watchdog
# El DNS del sistema solo se toca con -SetSystemDns (activacion final).
# ==============================================================================
param([switch]$SetSystemDns)

$ErrorActionPreference = 'Continue'
$dir = 'C:\AdGuardHome'
$log = Join-Path $env:TEMP 'fortress-final-repair.log'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function L {
    param([string]$m)
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $m
    Write-Host $line
    try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch { }
}

function Grant-Acl {
    param([string]$Path, [switch]$Directory, [switch]$UsersRead)
    if (-not (Test-Path $Path)) { L ('ACL omitida (no existe): ' + $Path); return }
    try {
        if ($Directory) {
            if ($UsersRead) {
                & icacls.exe $Path /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /C 2>&1 | Out-Null
            } else {
                & icacls.exe $Path /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C 2>&1 | Out-Null
            }
        } else {
            if ($UsersRead) {
                & icacls.exe $Path /grant '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' /C 2>&1 | Out-Null
            } else {
                & icacls.exe $Path /grant '*S-1-5-18:F' '*S-1-5-32-544:F' /C 2>&1 | Out-Null
            }
        }
        L ('ACL OK: ' + $Path)
    } catch {
        L ('ACL ERROR ' + $Path + ': ' + $_.Exception.Message)
    }
}

L 'Inicio reparacion final.'
L ('Usuario: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)

# 1) ACL con SIDs (no depende del idioma de Windows).
Grant-Acl -Path $dir -Directory -UsersRead
foreach ($sub in @('data', 'logs', 'node', 'scripts', 'launchers')) {
    Grant-Acl -Path (Join-Path $dir $sub) -Directory -UsersRead
}
Grant-Acl -Path (Join-Path $dir 'config') -Directory
foreach ($f in @('AdGuardHome.yaml', 'AdGuardHome.exe', 'AdGuardHome.log', 'watchdog.log',
                 'doh-bridge.log', 'failsafe.log', 'watchdog.ps1', 'fortress-health.ps1',
                 'fortress-doctor.ps1', 'doh-tor-bridge.js', 'decoy_dns.js', 'dns-probe.js',
                 'ai_dns_guard.js', 'set-adguard-upstreams.js', 'failsafe-dns.ps1',
                 'fortress.manifest.json', 'edition-hardening.report.json',
                 'network-hardening.state.json', 'watchdog.heartbeat')) {
    Grant-Acl -Path (Join-Path $dir $f) -UsersRead
}
Grant-Acl -Path (Join-Path $dir 'config\.env')

# 2) Firewall: bloquear 443 directo de AdGuard (TCP y UDP).
try {
    $exe = Join-Path $dir 'AdGuardHome.exe'
    foreach ($spec in @(
        @{ Name = 'AdGuard_Block_AdGuard_Direct_HTTPS_TCP'; Proto = 'TCP'; Display = 'AdGuard - Block direct HTTPS 443 TCP' },
        @{ Name = 'AdGuard_Block_AdGuard_Direct_HTTPS_UDP'; Proto = 'UDP'; Display = 'AdGuard - Block direct HTTPS 443 UDP' }
    )) {
        if (-not (Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $spec.Name -DisplayName $spec.Display -Direction Outbound -Action Block -Program $exe -Protocol $spec.Proto -RemotePort 443 -Enabled True -Profile Any | Out-Null
            L ('Firewall creado: ' + $spec.Name)
        } else {
            L ('Firewall ya existe: ' + $spec.Name)
        }
    }
} catch { L ('Firewall ERROR: ' + $_.Exception.Message) }

# 2b) Firewall: cerrar el panel 3000 y SOCKS 9050 al exterior.
foreach ($spec in @(
    @{ Name = 'AdGuard_Block_Inbound_Panel_3000'; Display = 'AdGuard - Block inbound panel 3000'; Port = 3000 },
    @{ Name = 'AdGuard_Block_Inbound_SOCKS_9050'; Display = 'AdGuard - Block inbound SOCKS 9050'; Port = 9050 }
)) {
    try {
        if (-not (Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $spec.Name -DisplayName $spec.Display -Direction Inbound -Action Block -Protocol TCP -LocalPort $spec.Port -Enabled True -Profile Any | Out-Null
            L ('Firewall inbound creado: ' + $spec.Name)
        } else { L ('Firewall inbound ya existe: ' + $spec.Name) }
    } catch { L ('Firewall inbound ERROR ' + $spec.Name + ': ' + $_.Exception.Message) }
}

# 3) DNS 127.0.0.1 en todos los adaptadores IPv4 (solo activacion final).
if (-not $SetSystemDns) {
    L 'DNS del sistema sin cambios (usar -SetSystemDns para apuntarlo a 127.0.0.1).'
} else {
    try {
        $adapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })
        foreach ($a in $adapters) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
                L ('DNS 127.0.0.1: ' + $a.InterfaceAlias + ' (idx ' + $a.InterfaceIndex + ')')
            } catch { L ('DNS ERROR ' + $a.InterfaceAlias + ': ' + $_.Exception.Message) }
        }
    } catch { L ('DNS lista ERROR: ' + $_.Exception.Message) }
}

# 4) WPAD/AutoDetect del usuario actual.
try {
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -Value 0 -Type DWord -Force
    L 'WPAD AutoDetect=0.'
} catch { L ('WPAD ERROR: ' + $_.Exception.Message) }

# 4b) Hardening de red local (idempotente; requiere reinicio para NetBIOS/SMBv1).
$networkScript = Join-Path $dir 'harden-network-protocols.ps1'
if (Test-Path $networkScript) {
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $networkScript -TargetDir $dir 2>&1 | ForEach-Object { L ('NET: ' + $_) }
        L ('Hardening exit: ' + $LASTEXITCODE)
        Grant-Acl -Path (Join-Path $dir 'network-hardening.state.json') -UsersRead
    } catch { L ('Hardening red ERROR: ' + $_.Exception.Message) }
} else { L 'No existe harden-network-protocols.ps1' }

# 5) Parar watchdog/guardian, registrar tareas S4U, reiniciar AdGuard y arrancar limpio.
try {
    Stop-ScheduledTask -TaskName 'AdGuardHome_Fortress_Watchdog' -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName 'AdGuardHome_Fortress_Guard' -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'powershell.exe' -and $_.CommandLine -like '*-File*watchdog.ps1*' } |
        ForEach-Object {
            try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; L ('watchdog detenido: ' + $_.ProcessId) } catch { L ('watchdog no detenido ' + $_.ProcessId + ': ' + $_.Exception.Message) }
        }
} catch { L ('watchdog stop ERROR: ' + $_.Exception.Message) }

# 5b) Registrar watchdog y guardian con la cuenta actual (S4U), no SYSTEM.
try {
    $taskUser = "$env:USERDOMAIN\$env:USERNAME"
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
    $wdAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "{0}"' -f (Join-Path $dir 'watchdog.ps1'))
    $wdTriggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $wdPrincipal = New-ScheduledTaskPrincipal -UserId $taskUser -LogonType S4U -RunLevel Highest
    Register-ScheduledTask -TaskName 'AdGuardHome_Fortress_Watchdog' -Action $wdAction -Trigger $wdTriggers -Settings $taskSettings -Principal $wdPrincipal -Force | Out-Null
    L ('Watchdog S4U registrado: ' + $taskUser)

    if (Test-Path (Join-Path $dir 'watchdog-guard.ps1')) {
        $gAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "{0}"' -f (Join-Path $dir 'watchdog-guard.ps1'))
        $gTriggers = @(
            (New-ScheduledTaskTrigger -AtStartup),
            (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650))
        )
        Register-ScheduledTask -TaskName 'AdGuardHome_Fortress_Guard' -Action $gAction -Trigger $gTriggers -Settings $taskSettings -Principal $wdPrincipal -Force | Out-Null
        L 'Guardian S4U registrado.'
    }
} catch { L ('Tareas S4U ERROR: ' + $_.Exception.Message) }

try {
    Restart-Service -Name 'AdGuardHome' -Force -ErrorAction Stop
    Start-Sleep -Seconds 5
    L ('AdGuardHome: ' + (Get-Service AdGuardHome).Status)
} catch { L ('AdGuardHome restart ERROR: ' + $_.Exception.Message) }

try {
    Start-ScheduledTask -TaskName 'AdGuardHome_Fortress_Watchdog' -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AdGuardHome_Fortress_Guard' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 6
    L 'Watchdog y guardian arrancados.'
} catch { L ('watchdog start ERROR: ' + $_.Exception.Message) }

# 6) Pruebas finales dentro de la elevacion.
$node = Join-Path $dir 'node\node.exe'
$probe = Join-Path $dir 'dns-probe.js'
if ((Test-Path $node) -and (Test-Path $probe)) {
    # AdGuard puede tardar en calentar tras el reinicio; esperar su DNS real.
    $dnsReady = $false
    for ($i = 0; $i -lt 10; $i++) {
        $readyOut = & $node $probe --name example.com --server 127.0.0.1 --port 53 --timeout 8000 2>&1
        if (($readyOut | Out-String) -match '"ok"\s*:\s*true') { $dnsReady = $true; break }
        Start-Sleep -Seconds 2
    }
    L ('AdGuard DNS listo tras reparacion: ' + $dnsReady)
    if (-not $dnsReady) {
        L 'ERROR: AdGuard no resolvio example.com tras la reparacion; no se declara exito.'
        exit 1
    }
    foreach ($q in @(
        @{ Name = 'example.com'; Port = 53; Extra = @() },
        @{ Name = 'dnssec-failed.org'; Port = 53; Extra = @('--dnssec') },
        @{ Name = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'; Port = 53; Extra = @('--timeout', '20000') }
    )) {
        try {
            $nodeArgs = @($probe, '--name', $q.Name, '--server', '127.0.0.1', '--port', "$($q.Port)") + $q.Extra
            if ($nodeArgs -notcontains '--timeout') { $nodeArgs += @('--timeout', '12000') }
            $out = & $node @nodeArgs 2>&1
            L ('DNS ' + $q.Name + ': ' + (($out | Out-String).Trim()))
        } catch { L ('DNS ' + $q.Name + ' ERROR: ' + $_.Exception.Message) }
    }
}

# 7) Estado de ACL y watchdog.
try {
    $acl = Get-Acl (Join-Path $dir 'watchdog.log')
    L ('ACL watchdog.log: ' + (($acl.Access | ForEach-Object { $_.IdentityReference.ToString() + '=' + $_.FileSystemRights }) -join '; '))
    $tail = Get-Content (Join-Path $dir 'watchdog.log') -Tail 4 -ErrorAction SilentlyContinue
    L ('watchdog.log: ' + (($tail | Out-String).Trim()))
    $ti = Get-ScheduledTaskInfo -TaskName 'AdGuardHome_Fortress_Watchdog' -ErrorAction SilentlyContinue
    L ('watchdog LastRunTime=' + $ti.LastRunTime + ' LastTaskResult=' + $ti.LastTaskResult)
} catch { L ('estado final ERROR: ' + $_.Exception.Message) }

# 8) Regenerar manifiesto al final (incluye los scripts reparados).
try {
    $integrity = Join-Path $dir 'integrity-check.ps1'
    if (Test-Path $integrity) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $integrity -Create -TargetDir $dir 2>&1 | ForEach-Object { L ('MANIFEST: ' + $_) }
        Grant-Acl -Path (Join-Path $dir 'fortress.manifest.json') -UsersRead
    }
} catch { L ('Manifest ERROR: ' + $_.Exception.Message) }

L 'Fin reparacion final.'
exit 0
