# ==============================================================================
# AdGuard Home + Tor + Centinela AI Self-Healing Watchdog
# Project: adguardhome-tor-dns-fortress
# Author: jpscalero
# ==============================================================================

param(
    [string]$AdGuardDir = "C:\AdGuardHome",
    [int]$CheckIntervalSeconds = 15
)

$logFile = Join-Path $AdGuardDir "watchdog.log"
$maxLogBytes = 2 * 1024 * 1024 # 2MB

function Write-WatchdogLog {
    param(
        [Parameter(Mandatory=$true)][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    $ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] [$Level] $Message"
    Write-Output $line
    try {
        if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt $maxLogBytes)) {
            $oldLog = Join-Path $AdGuardDir "watchdog.old.log"
            if (Test-Path $oldLog) { Remove-Item $oldLog -Force }
            Rename-Item -Path $logFile -NewName "watchdog.old.log" -Force
        }
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    } catch {}
}

function Test-PortOpen {
    param(
        [string]$IP = "127.0.0.1",
        [int]$Port = 9050,
        [int]$TimeoutMs = 1500
    )
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($IP, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($success -and $tcp.Connected) {
            $tcp.EndConnect($async)
            $tcp.Close()
            return $true
        }
        if ($null -ne $tcp) { $tcp.Close() }
        return $false
    } catch {
        if ($null -ne $tcp) { $tcp.Close() }
        return $false
    }
}

Write-WatchdogLog "INFO" "Watchdog de Autorreparación iniciado. Monitoreando Tor, AdGuard Home, GoodbyeDPI y Puerto 53..."

$torFailCount = 0
$aghFailCount = 0

while ($true) {
    # --------------------------------------------------------------------------
    # 1. TOR SERVICE & SOCKS5 PROXY HEALTH
    # --------------------------------------------------------------------------
    try {
        $torSvc = Get-Service -Name "tor" -ErrorAction SilentlyContinue
        if ($torSvc -and ($torSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "Tor Service no está en ejecución. Iniciando..."
            Start-Service -Name "tor" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        $torPortOpen = Test-PortOpen -IP "127.0.0.1" -Port 9050 -TimeoutMs 2000
        if (-not $torPortOpen) {
            $torFailCount++
            Write-WatchdogLog "WARN" "Tor puerto SOCKS5 9050 no responde (Fallo $torFailCount/2)."
            if ($torFailCount -ge 2) {
                Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Reiniciando Tor Service por falta de respuesta en puerto 9050..."
                Restart-Service -Name "tor" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
                $torFailCount = 0
            }
        } else {
            $torFailCount = 0
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando Tor: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 2. GOODBYEDPI SERVICE HEALTH (Anti-DPI Evasion)
    # --------------------------------------------------------------------------
    try {
        $gdpi = Get-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
        if ($gdpi -and ($gdpi.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "GoodbyeDPI no está en ejecución. Iniciando servicio..."
            Start-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
        }
    } catch {}

    # --------------------------------------------------------------------------
    # 3. WINDOWS PORT 53 CONFLICT ARBITRATION (SharedAccess Neutralizer)
    # --------------------------------------------------------------------------
    try {
        $endpoints = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
        foreach ($ep in $endpoints) {
            if ($ep.OwningProcess) {
                $p = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
                if ($p -and ($p.ProcessName -eq "svchost")) {
                    Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Conflicto detectado: svchost (SharedAccess) ocupando puerto 53. Neutralizando..."
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'IcsDnsEnabled' -Value 0 -Type DWord -ErrorAction SilentlyContinue
                    Stop-Process -Id $ep.OwningProcess -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {}

    # --------------------------------------------------------------------------
    # 4. ADGUARD HOME SERVICE & DNS RESOLUTION HEALTH
    # --------------------------------------------------------------------------
    try {
        $aghSvc = Get-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
        if ($aghSvc -and ($aghSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "AdGuard Home Service detenido. Reiniciando..."
            Start-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        # Live DNS probe to loopback resolver
        $dnsOk = $false
        try {
            $res = Resolve-DnsName -Name "github.com" -Server "127.0.0.1" -QuickTimeout -DnsOnly -ErrorAction Stop
            if ($res -and $res.IPAddress) { $dnsOk = $true }
        } catch {
            $dnsOk = $false
        }

        if (-not $dnsOk) {
            $aghFailCount++
            Write-WatchdogLog "WARN" "AdGuard Home 127.0.0.1:53 no resolvió consulta de prueba (Fallo $aghFailCount/2)."
            if ($aghFailCount -ge 2) {
                Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Reiniciando AdGuardHome..."
                Restart-Service -Name "AdGuardHome" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 4
                $aghFailCount = 0
            }
        } else {
            $aghFailCount = 0
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando AdGuard Home: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $CheckIntervalSeconds
}
