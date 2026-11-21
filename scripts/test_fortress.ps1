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
$failed = 0
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
            $script:failed++
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
    }
}

# 1. Port 53 UDP/TCP Binding Check
Assert-Check "Puerto 53 UDP/TCP vinculado exclusivamente a AdGuard Home" {
    $udp = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
    $tcp = @(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue)
    $listeners = @($udp + $tcp)
    if ($listeners.Count -eq 0) {
        Write-Host " (No hay listener local en el puerto 53) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    $invalid = @()
    foreach ($endpoint in $listeners) {
        $proc = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc -or $proc.ProcessName -ne "AdGuardHome" -or $endpoint.LocalAddress -notin @("127.0.0.1", "::1")) {
            $invalid += "PID $($endpoint.OwningProcess) at $($endpoint.LocalAddress)"
        }
    }
    if ($invalid.Count -gt 0) {
        Write-Host " (Listener ajeno o expuesto: $($invalid -join ', ')) " -NoNewline -ForegroundColor Yellow
        return $false
    }
    return (($udp.Count -gt 0) -and ($tcp.Count -gt 0))
}

# 2. Verify a real Tor exit response, not merely that the SOCKS port accepts TCP.
Assert-Check "Salida Tor confirmada por check.torproject.org" {
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        throw "No se encontró curl.exe; no se puede verificar la IP de salida Tor."
    }
    $torApiText = & curl.exe --fail --silent --show-error --max-time 15 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>$null
    $curlExitCode = $LASTEXITCODE
    if ($curlExitCode -ne 0) {
        throw "La petición Tor falló con código curl $curlExitCode."
    }
    $torApi = ($torApiText -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $parsedExitIp = $null
    $validExitIp = [System.Net.IPAddress]::TryParse([string]$torApi.IP, [ref]$parsedExitIp)
    if ($torApi.IsTor -ne $true -or -not $validExitIp) {
        throw "IsTor no es true o la API no devolvió una IP de salida válida."
    }
    Write-Host "(IsTor=true, IP $parsedExitIp) " -NoNewline -ForegroundColor Gray
    return $true
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

# 10. Administration panel remains bound to loopback only
Assert-Check "Panel de administración accesible solo por loopback" {
    $listeners = @(Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) { return "WARN" }
    $exposed = @($listeners | Where-Object { $_.LocalAddress -notin @("127.0.0.1", "::1") })
    return ($exposed.Count -eq 0)
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
if ($passed -eq $total) {
    Write-Host "   ✅ TODAS LAS PRUEBAS SUPERADAS ($passed/$total): FORTALEZA 100% ACTIVA" -ForegroundColor Green
} elseif ($failed -eq 0) {
    Write-Host "   ✅ NÚCLEO CRÍTICO PROTEGIDO ($passed/$total servicios OK, $warnings avisos)" -ForegroundColor Green
} else {
    Write-Host "   ❌ RESULTADO: $passed superadas, $failed fallidas, $warnings avisos" -ForegroundColor Red
}
Write-Host "==========================================================" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 }
exit 0
