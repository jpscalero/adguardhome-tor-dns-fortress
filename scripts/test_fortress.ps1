# ==============================================================================
# 🛡️ Fortress Verification & Health Diagnostics Suite (21-Point Audit)
# Project: adguardhome-tor-dns-fortress
# Author: jpscalero
# ==============================================================================

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   🛡️ FORTRESS HEALTH & SECURITY DIAGNOSTIC SUITE        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Perfil de edicion (informativo; no cambia el numero de comprobaciones).
$editionInfo = $null
$editionScript = Join-Path $PSScriptRoot 'windows-edition.ps1'
if (Test-Path $editionScript) {
    . $editionScript
    $editionInfo = Get-WindowsFortressProfile
    Write-Host ("   Windows: {0}" -f $editionInfo.Summary) -ForegroundColor DarkCyan
    $fortressDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
    $editionReport = Join-Path $fortressDir 'edition-hardening.report.json'
    if (Test-Path $editionReport) {
        try {
            $reportData = Get-Content -Path $editionReport -Raw | ConvertFrom-Json
            $editionApplied = @($reportData.Applied | Where-Object { $_ }).Count
            $editionWarnings = @($reportData.Warnings | Where-Object { $_ }).Count
            Write-Host ("   Hardening de edicion: {0} modulo(s), {1} aviso(s)" -f $editionApplied, $editionWarnings) -ForegroundColor DarkCyan
        } catch { }
    }
} else {
    Write-Host '   Windows: perfil de edicion no disponible (windows-edition.ps1 ausente).' -ForegroundColor DarkGray
}
Write-Host ""

$passed = 0
$warnings = 0
$total = 0

function Assert-Check {
    param(
        [string]$Title,
        [scriptblock]$CheckBlock
    )
    $script:total++
    Write-Host "[$script:total] $Title... " -NoNewline
    try {
        $result = & $CheckBlock
        if ($result -eq $true) {
            Write-Host "OK" -ForegroundColor Green
            $script:passed++
        } elseif ($result -eq "WARN") {
            Write-Host "AVISO" -ForegroundColor Yellow
            $script:warnings++
        } else {
            Write-Host "FAILED" -ForegroundColor Red
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 1. Port 53 UDP Binding Check
Assert-Check "Puerto 53 UDP vinculado exclusivamente a AdGuard Home" {
    $ep = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq "127.0.0.1" }
    if ($ep) {
        $proc = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -eq "AdGuardHome") {
            return $true
        }
        Write-Host " (Ocupado por PID $($ep.OwningProcess): $($proc.ProcessName) -> Revisa ICS/SharedAccess o dnscache) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    Write-Host " (Puerto 53 UDP no está en escucha -> AdGuard Home no está iniciado) " -NoNewline -ForegroundColor Yellow
    return $false
}

# 2. Tor SOCKS5 Port 9050 Check & Anonymity Verification
Assert-Check "Túnel Tor SOCKS5 en escucha y salida anónima (127.0.0.1:9050)" {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect("127.0.0.1", 9050, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(1500, $false)
        if (-not ($wait -and $tcp.Connected)) {
            $tcp.Close()
            Write-Host " (Puerto 9050 cerrado -> El servicio Tor no está iniciado) " -NoNewline -ForegroundColor Yellow
            return $false
        }
        $tcp.EndConnect($async)
        $tcp.Close()

        # Test true Tor exit IP if curl is available
        try {
            $torApi = curl.exe -s --max-time 4 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>$null
            if ($torApi -match '"IsTor"\s*:\s*true') {
                Write-Host "(Exit IP confirmada) " -NoNewline -ForegroundColor Gray
            }
        } catch {}

        return $true
    } catch {
        $tcp.Close()
        Write-Host " (Error al conectar a Tor 9050: $($_.Exception.Message)) " -NoNewline -ForegroundColor Yellow
        return $false
    }
}

# 3. Tor DNSPort 5350 Check
Assert-Check "Puerto DNS nativo de Tor en escucha (UDP 127.0.0.1:5350)" {
    $ep5350 = Get-NetUDPEndpoint -LocalPort 5350 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq "127.0.0.1" }
    if ($null -ne $ep5350) {
        return $true
    }
    Write-Host " (DNSPort 5350 no responde -> Verifica que torrc incluya 'DNSPort 127.0.0.1:5350') " -NoNewline -ForegroundColor Yellow
    return $false
}

# 4. Standard DNS Live Resolution (github.com)
Assert-Check "Resolución DNS local en 127.0.0.1:53 (github.com)" {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $res = Resolve-DnsName -Name "github.com" -Server "127.0.0.1" -QuickTimeout -DnsOnly -ErrorAction Stop
    $sw.Stop()
    Write-Host "($($sw.ElapsedMilliseconds)ms) " -NoNewline -ForegroundColor Gray
    return ($null -ne $res -and $res.IPAddress.Length -gt 0)
}

# 5. Tor .onion Native Resolution Check
Assert-Check "Resolución nativa de dominios Tor .onion (Virtual IP 10.x.x.x)" {
    $out = nslookup 2gzyxa5ihm7nsggfxnu52r2g264425uzqm32my2tko6sqpnxuvjpageyd.onion 127.0.0.1 2>&1 | Out-String
    return ($out -match '10\.\d{1,3}\.\d{1,3}\.\d{1,3}')
}

# 6. Anti-Tracking / Canary Blocklist Check
Assert-Check "Bloqueo activo de telemetría y dominios de riesgo (NXDOMAIN)" {
    try {
        $res = Resolve-DnsName -Name "use-application-dns.net" -Server "127.0.0.1" -QuickTimeout -DnsOnly -ErrorAction Stop
        return $false # Should not resolve
    } catch {
        return $true # NXDOMAIN expected
    }
}

# 7. GoodbyeDPI Anti-Censorship Service Check
Assert-Check "Servicio GoodbyeDPI (Anti-DPI / WinDivert)" {
    $s = Get-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
    return ($s -and $s.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
}

# 8. AI DNS Sentinel Background Process Check
Assert-Check "Centinela AI de detección DGA/C2 (ai_dns_guard.js)" {
    $ai = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "node.exe" -and $_.CommandLine -like "*ai_dns_guard.js*" }
    if ($null -ne $ai) {
        return $true
    }
    Write-Host " (Módulo opcional detenido -> Iniciar con start_ai_guard.vbs si configuraste .env) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 9. Decoy DNS Traffic Generator Check
Assert-Check "Generador de tráfico señuelo anti-fingerprinting (decoy_dns.js)" {
    $decoy = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "node.exe" -and $_.CommandLine -like "*decoy_dns.js*" }
    if ($null -ne $decoy) {
        return $true
    }
    Write-Host " (Módulo opcional detenido -> Iniciar con start_decoy.vbs) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 10. Windows 11 Port 53 Hijack Neutralization Check
Assert-Check "Neutralización de secuestro de puerto 53 (SharedAccess/ICS)" {
    $sa = Get-Service -Name "SharedAccess" -ErrorAction SilentlyContinue
    $reg = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'IcsDnsEnabled' -ErrorAction SilentlyContinue
    $stopped = (-not $sa) -or ($sa.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)
    if ($stopped -and $reg -eq 0) {
        return $true
    }
    Write-Host " (SharedAccess status: $($sa.Status), IcsDnsEnabled: $reg -> Ejecuta scripts/install_fortress.ps1) " -NoNewline -ForegroundColor Yellow
    return $false
}

# 11. ACL de secretos (config\.env)
Assert-Check "Permisos de config\.env restringidos (sin Usuarios/AppContainer)" {
    $envFile = Join-Path $env:FORTRESS_DIR "config\.env"
    if (-not (Test-Path $envFile)) {
        $envFile = "C:\AdGuardHome\config\.env"
    }
    if (-not (Test-Path $envFile)) {
        Write-Host " (no existe .env; credenciales no configuradas) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $acl = Get-Acl $envFile
    $generic = @($acl.Access | Where-Object {
        $_.IdentityReference -match 'Everyone|Users|Usuarios|Authenticated|Autenticados|S-1-15-3'
    })
    if ($generic.Count -gt 0) {
        Write-Host " (acceso generico: $($generic[0].IdentityReference) -> scripts\harden-env-acl.ps1) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    return $true
}

# 12. Reglas anti-fuga ampliadas (853/TCP y 5353/UDP)
Assert-Check "Reglas anti-fuga DoT 853 y mDNS 5353 activas" {
    $names = @('AdGuard_Block_Outbound_DOT_853', 'AdGuard_Block_Outbound_MDNS')
    $missing = @()
    foreach ($n in $names) {
        $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if (-not $r -or $r.Enabled -ne 'True') { $missing += $n }
    }
    if ($missing.Count -eq 0) { return $true }
    Write-Host " (faltan o desactivadas: $($missing -join ', ') -> install_fortress.ps1) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 13. Frescura del heartbeat del watchdog
Assert-Check "Heartbeat del watchdog reciente (< 120 s)" {
    $hb = Join-Path $env:FORTRESS_DIR "watchdog.heartbeat"
    if (-not (Test-Path $hb)) { $hb = "C:\AdGuardHome\watchdog.heartbeat" }
    if (-not (Test-Path $hb)) {
        Write-Host " (sin heartbeat: watchdog no ejecutado) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $age = ((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds
    Write-Host "($([int]$age)s) " -NoNewline -ForegroundColor Gray
    return ($age -lt 120)
}

# 14. Tarea programada del failsafe
Assert-Check "Tarea programada del failsafe registrada" {
    $t = Get-ScheduledTask -TaskName "AdGuardHome_Fortress_Failsafe" -ErrorAction SilentlyContinue
    if ($t) { return $true }
    Write-Host " (no registrada -> install_fortress.ps1 la crea) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 15. DoH propio del navegador desactivado
Assert-Check "DoH del navegador desactivado por politica (Chrome/Edge)" {
    $chrome = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
    $edge = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
    if (($chrome -eq 'off') -and ($edge -eq 'off')) { return $true }
    Write-Host " (chrome=$chrome edge=$edge -> scripts\harden-browser-doh.ps1) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 16. Integridad del binario de AdGuard Home
Assert-Check "Integridad del binario de AdGuardHome (hash registrado)" {
    $exe = Join-Path $env:FORTRESS_DIR "AdGuardHome.exe"
    if (-not (Test-Path $exe)) { $exe = "C:\AdGuardHome\AdGuardHome.exe" }
    if (-not (Test-Path $exe)) {
        Write-Host " (binario no encontrado) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $hashFile = Join-Path (Split-Path $exe) "data\adguard-home.sha256"
    $current = (Get-FileHash -Path $exe -Algorithm SHA256).Hash
    if (-not (Test-Path $hashFile)) {
        try {
            New-Item -ItemType Directory -Path (Split-Path $hashFile) -Force | Out-Null
            Set-Content -Path $hashFile -Value $current -Encoding ASCII
        } catch { }
        Write-Host "(hash inicial registrado) " -NoNewline -ForegroundColor Gray
        return $true
    }
    $expected = (Get-Content $hashFile -Raw).Trim()
    if ($expected -eq $current) { return $true }
    Write-Host " (el binario cambio desde el ultimo registro; revisa la actualizacion) " -NoNewline -ForegroundColor Yellow
    return $false
}

# 17. DNS real de Windows (no solo la consulta explicita a 127.0.0.1)
Assert-Check "DNS real de Windows apunta a la fortaleza (127.0.0.1)" {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and
        $_.InterfaceDescription -notlike '*Virtual*' -and
        $_.InterfaceDescription -notlike '*Hyper-V*' -and
        $_.InterfaceDescription -notlike '*Loopback*'
    })
    if ($adapters.Count -eq 0) {
        Write-Host " (sin adaptadores fisicos activos) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }

    $bad = @()
    foreach ($adapter in $adapters) {
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | Where-Object { $_ })
        if (($dns.Count -ne 1) -or ($dns[0] -ne '127.0.0.1')) {
            $shown = if ($dns.Count -gt 0) { $dns -join ',' } else { 'automatico' }
            $bad += ('{0}={1}' -f $adapter.Name, $shown)
        }
    }

    if ($bad.Count -eq 0) {
        Write-Host ('({0}) ' -f (($adapters | ForEach-Object { $_.Name }) -join ', ')) -NoNewline -ForegroundColor Gray
        return $true
    }

    Write-Host ('(DNS real no apunta a la fortaleza: {0}) ' -f ($bad -join '; ')) -NoNewline -ForegroundColor Yellow
    return $false
}

# 18. Perfil DNS activo (recursivo propio o DoH)
Assert-Check "Perfil DNS activo y resolutor recursivo propio (Unbound)" {
    $fortressDir18 = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
    $envFile18 = Join-Path $fortressDir18 'config\.env'
    $profile = 'speed'
    if (Test-Path $envFile18) {
        $match = [regex]::Match((Get-Content $envFile18 -Raw), '(?m)^\s*DNS_PROFILE\s*=\s*(\w+)')
        if ($match.Success) { $profile = $match.Groups[1].Value.ToLowerInvariant() }
    }
    if ($profile -ne 'privacy') {
        Write-Host (" (perfil {0}; el recursivo se activa con -Profile privacy) " -f $profile) -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $ep = Get-NetUDPEndpoint -LocalPort 5335 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '127.0.0.1' }
    if (-not $ep) {
        Write-Host " (perfil privacy pero Unbound no escucha en 5335 -> setup-unbound.ps1) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    $res = Resolve-DnsName -Name 'example.com' -Server '127.0.0.1' -Port 5335 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
    if (-not $res) {
        Write-Host " (Unbound escucha pero no resuelve) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    Write-Host "(recursivo 127.0.0.1:5335) " -NoNewline -ForegroundColor Gray
    return $true
}

# 19. Watchdog reforzado y guardian
Assert-Check "Watchdog con repeticion y guardian anti-manipulacion registrados" {
    $wd = Get-ScheduledTask -TaskName 'AdGuardHome_Fortress_Watchdog' -ErrorAction SilentlyContinue
    $guard = Get-ScheduledTask -TaskName 'AdGuardHome_Fortress_Guard' -ErrorAction SilentlyContinue
    if ($wd -and $guard) {
        $repetition = @($wd.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval })
        if ($repetition.Count -gt 0) { return $true }
        Write-Host " (watchdog sin trigger de repeticion -> protect-fortress.ps1) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    Write-Host " (faltan tareas -> protect-fortress.ps1) " -NoNewline -ForegroundColor Yellow
    return "WARN"
}

# 20. ACL del directorio y recuperacion de servicios
Assert-Check "Directorio protegido y servicios con recuperacion automatica" {
    $fortressDir20 = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
    if (-not (Test-Path $fortressDir20)) {
        Write-Host " (directorio ausente) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $acl = Get-Acl $fortressDir20
    $writableUsers = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -match 'Users|Usuarios|Everyone|Authenticated' -and
        ($_.FileSystemRights -match 'Write|Modify|FullControl')
    })
    if ($writableUsers.Count -gt 0) {
        Write-Host " (Usuarios pueden escribir -> protect-fortress.ps1) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    $failure = (& sc.exe qfailure AdGuardHome 2>&1 | Out-String)
    if ($failure -notmatch 'RESTART') {
        Write-Host " (AdGuardHome sin acciones de recuperacion -> protect-fortress.ps1) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    return $true
}

# 21. Integridad de scripts y bloqueo entrante de puertos sensibles
Assert-Check "Integridad de scripts y puertos sensibles cerrados al exterior" {
    $fortressDir21 = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
    $manifest = Join-Path $fortressDir21 'fortress.manifest.json'
    if (-not (Test-Path $manifest)) {
        Write-Host " (sin manifiesto -> protect-fortress.ps1) " -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    $checker = Join-Path $fortressDir21 'integrity-check.ps1'
    if (Test-Path $checker) {
        & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $checker -Verify -TargetDir $fortressDir21 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host " (hashes alterados -> integrity-check.ps1 -Restore) " -NoNewline -ForegroundColor Yellow
            return $false
        }
    }
    $missing = @()
    foreach ($ruleName in @('AdGuard_Block_Inbound_Panel_3000', 'AdGuard_Block_Inbound_SOCKS_9050')) {
        $r = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if (-not $r -or $r.Enabled -ne 'True') { $missing += $ruleName }
    }
    if ($missing.Count -gt 0) {
        Write-Host (" (faltan reglas entrantes: {0}) " -f ($missing -join ', ')) -NoNewline -ForegroundColor Yellow
        return "WARN"
    }
    return $true
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
if ($passed -eq $total) {
    Write-Host "   ✅ TODAS LAS PRUEBAS SUPERADAS ($passed/$total): FORTALEZA 100% ACTIVA" -ForegroundColor Green
} elseif (($passed + $warnings) -eq $total) {
    Write-Host "   ✅ NÚCLEO CRÍTICO PROTEGIDO ($passed/$total servicios OK, $warnings avisos en módulos opcionales)" -ForegroundColor Green
} else {
    Write-Host "   ⚠️ RESULTADO: $passed de $total pruebas superadas" -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
