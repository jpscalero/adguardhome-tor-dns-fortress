# ==============================================================================
# Fortress Verification & Health Diagnostics Suite
# Project: adguardhome-tor-dns-fortress
# Author: jpscalero
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   🛡️ FORTRESS HEALTH & SECURITY DIAGNOSTIC SUITE        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$passed = 0
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
        } else {
            Write-Host "FAILED" -ForegroundColor Red
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 1. Port 53 Check
Assert-Check "Puerto 53 UDP vinculado exclusivamente a AdGuard Home" {
    $ep = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq "127.0.0.1" }
    if ($ep) {
        $proc = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
        return ($proc -and $proc.ProcessName -eq "AdGuardHome")
    }
    return $false
}

# 2. Tor SOCKS5 Port 9050 Check
Assert-Check "Túnel Tor SOCKS5 en escucha (127.0.0.1:9050)" {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect("127.0.0.1", 9050, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(1500, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($async)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        $tcp.Close()
        return $false
    }
}

# 3. DNS Live Resolution (github.com)
Assert-Check "Resolución DNS local en 127.0.0.1:53 (github.com)" {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $res = Resolve-DnsName -Name "github.com" -Server "127.0.0.1" -QuickTimeout -DnsOnly -ErrorAction Stop
    $sw.Stop()
    Write-Host "($($sw.ElapsedMilliseconds)ms) " -NoNewline -ForegroundColor Gray
    return ($null -ne $res -and $res.IPAddress.Length -gt 0)
}

# 4. Anti-Tracking / Blocklist Check
Assert-Check "Bloqueo activo de telemetría y dominios de riesgo (NXDOMAIN)" {
    try {
        $res = Resolve-DnsName -Name "use-application-dns.net" -Server "127.0.0.1" -QuickTimeout -DnsOnly -ErrorAction Stop
        return $false # Should not resolve
    } catch {
        return $true # NXDOMAIN expected
    }
}

# 5. GoodbyeDPI Service Check
Assert-Check "Servicio GoodbyeDPI (Anti-DPI / WinDivert)" {
    $s = Get-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
    return ($s -and $s.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
}

# 6. Windows DNS Adapter Configuration
Assert-Check "Adaptadores principales configurados con DNS 127.0.0.1" {
    $addrs = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains "127.0.0.1" }
    return ($addrs.Count -gt 0)
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
if ($passed -eq $total) {
    Write-Host "   ✅ TODAS LAS PRUEBAS SUPERADAS ($passed/$total): FORTALEZA ACTIVA" -ForegroundColor Green
} else {
    Write-Host "   ⚠️ RESULTADO: $passed de $total pruebas superadas" -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
