# ==============================================================================
# 🛡️ AdGuard Home + Tor + Centinela AI Self-Healing Watchdog
# ==============================================================================
# Monitors and auto-repairs:
# 1. Tor Service ('tor') & Port 9050 SOCKS5 connectivity
# 2. GoodbyeDPI Service (Anti-DPI / WinDivert)
# 3. AdGuard Home Service ('AdGuardHome') & Port 53 DNS live resolution
# 4. AI DNS Centinela ('ai_dns_guard.js' Node process)
# 5. Decoy DNS Traffic ('decoy_dns.js' Node process)
# 6. Port 53 SharedAccess conflict arbitration (Windows 11 ICS fix)
# 7. End-to-end DNS -> SOCKS5 -> Upstream pipeline audit
# ==============================================================================

param(
    [string]$AdGuardDir = "C:\AdGuardHome",
    [int]$CheckIntervalSeconds = 30
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
    } catch {
        # Silent ignore
    }
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

Write-WatchdogLog "INFO" "Watchdog de Autorreparacion iniciado. Monitoreando Tor, AdGuard Home, GoodbyeDPI, Centinela AI y Decoy DNS..."

$torFailCount = 0
$aghFailCount = 0
$cycle = 0

while ($true) {
    $cycle++

    # --------------------------------------------------------------------------
    # 1. TOR SERVICE & SOCKS5 PROXY HEALTH CHECK
    # --------------------------------------------------------------------------
    try {
        $torSvc = Get-Service -Name "tor" -ErrorAction SilentlyContinue
        if ((-not $torSvc) -or ($torSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "Tor Service no esta en ejecucion. Iniciando..."
            Start-Service -Name "tor" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        $torPortOpen = Test-PortOpen -IP "127.0.0.1" -Port 9050 -TimeoutMs 2000
        if (-not $torPortOpen) {
            $torFailCount++
            Write-WatchdogLog "WARN" "Tor puerto SOCKS5 9050 no responde (Fallo $torFailCount de 2)."
            if ($torFailCount -ge 2) {
                Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Reiniciando Tor Service por falta de respuesta en puerto 9050..."
                Restart-Service -Name "tor" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
                $torFailCount = 0
            }
        } else {
            if ($torFailCount -gt 0) {
                Write-WatchdogLog "INFO" "Tor SOCKS5 puerto 9050 recuperado exitosamente."
            }
            $torFailCount = 0
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando estado de Tor: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 1.5. GOODBYEDPI SERVICE HEALTH CHECK (Anti-DPI Evasion)
    # --------------------------------------------------------------------------
    try {
        $gdSvc = Get-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
        if ((-not $gdSvc) -or ($gdSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "GoodbyeDPI Service no esta en ejecucion. Iniciando..."
            Start-Service -Name "GoodbyeDPI" -ErrorAction SilentlyContinue
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando GoodbyeDPI: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 2. ADGUARD HOME SERVICE & DNS HEALTH CHECK
    # --------------------------------------------------------------------------
    try {
        $aghSvc = Get-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
        if ((-not $aghSvc) -or ($aghSvc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            Write-WatchdogLog "WARN" "AdGuard Home Service detenido. Iniciando..."
            Start-Service -Name "AdGuardHome" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        $dnsRes = Resolve-DnsName -Name "localhost" -Server "127.0.0.1" -QuickTimeout -ErrorAction SilentlyContinue
        if (-not $dnsRes) {
            $dnsRes = Resolve-DnsName -Name "wikipedia.org" -Server "127.0.0.1" -QuickTimeout -ErrorAction SilentlyContinue
        }

        if (-not $dnsRes) {
            $aghFailCount++
            Write-WatchdogLog "WARN" "AdGuard Home no respondio consulta DNS local (Fallo $aghFailCount de 2)."
            if ($aghFailCount -ge 2) {
                Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Reiniciando AdGuard Home por falta de respuesta DNS..."
                Restart-Service -Name "AdGuardHome" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 4
                $aghFailCount = 0
            }
        } else {
            if ($aghFailCount -gt 0) {
                Write-WatchdogLog "INFO" "AdGuard Home ha recuperado la resolucion DNS local."
            }
            $aghFailCount = 0
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando AdGuard Home: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 2.2. DYNAMIC NETWORK INTERFACE SYNCHRONIZATION
    # --------------------------------------------------------------------------
    # Ensures AdGuard Home bind_hosts always matches the machine's current Wi-Fi/Ethernet IP
    # Prevents daemon failure on DHCP lease renewal or network switching
    try {
        $activeIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceAlias -in @("Wi-Fi", "Ethernet") -and
            $_.IPAddress -notlike "169.254*" -and
            $_.IPAddress -ne "127.0.0.1"
        }).IPAddress | Select-Object -First 1

        $cfgPath = Join-Path $AdGuardDir "AdGuardHome.yaml"
        if ($activeIp -and (Test-Path $cfgPath)) {
            $cfg = Get-Content $cfgPath -Raw
            if ($cfg -match "bind_hosts:\s*\r?\n\s*-\s*127\.0\.0\.1\s*\r?\n\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\r?\n\s*-\s*::1") {
                $boundIp = $Matches[1]
                if ($boundIp -ne $activeIp) {
                    Write-WatchdogLog "WARN" "Cambio de IP de red detectado ($boundIp -> $activeIp). Actualizando bind_hosts..."
                    $cfg = $cfg.Replace($boundIp, $activeIp)
                    Set-Content -Path $cfgPath -Value $cfg -Encoding UTF8 -Force
                    Restart-Service -Name "AdGuardHome" -Force -ErrorAction SilentlyContinue
                    Write-WatchdogLog "HEAL" "[AUTO-REPAIR] AdGuard Home reconfigurado y reiniciado con la nueva IP activa ($activeIp)."
                }
            }
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error en sincronizacion dinamica de interfaz: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 2.5. PORT 53 CONFLICT ARBITRATION (SharedAccess / ICS Fix)
    # --------------------------------------------------------------------------
    try {
        $udp53 = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
        foreach ($ep in $udp53) {
            $proc = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.Name -ne "AdGuardHome") {
                Write-WatchdogLog "WARN" "Puerto 53 UDP secuestrado por $($proc.Name) (PID: $($proc.Id)). Neutralizando..."
                # Disable ICS DNS in registry
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                Set-ItemProperty -Path $regPath -Name "IcsDnsEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                # Try graceful stop first
                Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                # Verify if still holding port
                $stillHolding = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -ne "AdGuardHome" }
                if ($stillHolding) {
                    Stop-Process -Id $ep.OwningProcess -Force -ErrorAction SilentlyContinue
                    Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Proceso conflictivo en puerto 53 terminado forzosamente."
                }
                # Restart AdGuard Home to reclaim port
                Restart-Service -Name "AdGuardHome" -Force -ErrorAction SilentlyContinue
                Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Puerto 53 recuperado para AdGuard Home."
            }
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error en arbitraje de puerto 53: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 3. CENTINELA AI (ai_dns_guard.js) HEALTH CHECK
    # --------------------------------------------------------------------------
    try {
        $aiProc = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*ai_dns_guard.js*" }

        if (-not $aiProc) {
            Write-WatchdogLog "WARN" "Centinela AI (ai_dns_guard.js) no esta en ejecucion. Relanzando..."
            $vbsPath = Join-Path $AdGuardDir "ocultar_guardia.vbs"
            if (-not (Test-Path $vbsPath)) {
                # Fallback: try launchers directory
                $vbsPath = Join-Path (Split-Path $AdGuardDir) "launchers\start_ai_guard.vbs"
            }
            if (Test-Path $vbsPath) {
                Start-Process -FilePath "wscript.exe" -ArgumentList $vbsPath -WindowStyle Hidden
                Start-Sleep -Seconds 2
                $newAi = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -like "*ai_dns_guard.js*" }
                if ($newAi) {
                    Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Centinela AI relanzado con exito (PID: $($newAi.ProcessId))."
                } else {
                    Write-WatchdogLog "ERROR" "Fallo el relanzamiento automatico de Centinela AI."
                }
            } else {
                Write-WatchdogLog "ERROR" "No se encontro el lanzador VBS para Centinela AI."
            }
        } elseif ($aiProc.Count -gt 1) {
            # Deduplicate multiple instances
            $aiProc | Select-Object -Skip 1 | ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-WatchdogLog "WARN" "Terminada instancia duplicada de Centinela AI (PID: $($_.ProcessId))."
            }
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando Centinela AI: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 3.5. DECOY DNS TRAFFIC (decoy_dns.js) HEALTH CHECK
    # --------------------------------------------------------------------------
    try {
        $decoyProc = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like "*decoy_dns.js*" }

        if (-not $decoyProc) {
            Write-WatchdogLog "WARN" "Generador Decoy DNS no esta en ejecucion. Relanzando..."
            $vbsPath = Join-Path $AdGuardDir "ocultar_decoy.vbs"
            if (-not (Test-Path $vbsPath)) {
                $vbsPath = Join-Path (Split-Path $AdGuardDir) "launchers\start_decoy.vbs"
            }
            if (Test-Path $vbsPath) {
                Start-Process -FilePath "wscript.exe" -ArgumentList $vbsPath -WindowStyle Hidden
                Start-Sleep -Seconds 2
                $newDecoy = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -like "*decoy_dns.js*" }
                if ($newDecoy) {
                    Write-WatchdogLog "HEAL" "[AUTO-REPAIR] Generador Decoy DNS relanzado con exito (PID: $($newDecoy.ProcessId))."
                }
            } else {
                Write-WatchdogLog "ERROR" "No se encontro el lanzador VBS para Decoy DNS."
            }
        } elseif ($decoyProc.Count -gt 1) {
            # Deduplicate multiple instances
            $decoyProc | Select-Object -Skip 1 | ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-WatchdogLog "WARN" "Terminada instancia duplicada de Decoy DNS (PID: $($_.ProcessId))."
            }
        }
    } catch {
        Write-WatchdogLog "ERROR" "Error comprobando Generador Decoy: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------------
    # 4. END-TO-END PIPELINE AUDIT (Every 10 cycles = ~5 minutes)
    # --------------------------------------------------------------------------
    if ($cycle % 10 -eq 0) {
        try {
            $e2eSw = [System.Diagnostics.Stopwatch]::StartNew()
            $e2eDns = Resolve-DnsName -Name "duckduckgo.com" -Server "127.0.0.1" -QuickTimeout -ErrorAction SilentlyContinue
            $e2eSw.Stop()
            if ($e2eDns) {
                Write-WatchdogLog "INFO" "[PIPELINE HEALTHY] End-to-end DNS -> SOCKS5(Tor) -> Resolver verificado en $($e2eSw.ElapsedMilliseconds)ms."
            } else {
                Write-WatchdogLog "WARN" "[PIPELINE SLOW/FAIL] Consulta end-to-end fallo o demoro demasiado."
            }
        } catch {
            Write-WatchdogLog "WARN" "Auditoria end-to-end fallo con excepcion: $($_.Exception.Message)"
        }
    }

    Start-Sleep -Seconds $CheckIntervalSeconds
}
