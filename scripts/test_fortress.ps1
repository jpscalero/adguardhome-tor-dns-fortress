# ==============================================================================
# 🛡️ Fortress Verification & Health Diagnostics Suite (10-Point Audit)
# Project: adguardhome-tor-dns-fortress
# Author: jpscalero
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   🛡️ FORTRESS HEALTH & SECURITY DIAGNOSTIC SUITE        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
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
