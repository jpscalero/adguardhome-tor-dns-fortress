# ==============================================================================
# Fortress Health - funciones compartidas por watchdog y doctor
# ==============================================================================
# Codigo ASCII puro: Windows PowerShell 5.1 sin BOM puede fallar con acentos.
# No depende de nslookup ni de Resolve-DnsName (ninguno acepta -Port en Windows).
# ==============================================================================

$script:FortressDirDefault = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }

function Get-FortressDir {
    param([string]$AdGuardDir = $script:FortressDirDefault)
    return $AdGuardDir
}

function Test-FortressTcpPort {
    param(
        [string]$Server = '127.0.0.1',
        [int]$Port = 53,
        [int]$TimeoutMs = 1500
    )
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($Server, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return [bool]$client.Connected
    } catch {
        return $false
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Read-FortressExact {
    param(
        [System.IO.Stream]$Stream,
        [int]$Count,
        [int]$TimeoutMs = 5000
    )
    $Stream.ReadTimeout = $TimeoutMs
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) { throw 'Conexion cerrada antes de completar la lectura.' }
        $offset += $read
    }
    return ,$buffer
}

function Test-FortressDnsQuery {
    param(
        [string]$Name = 'example.com',
        [string]$Server = '127.0.0.1',
        [int]$Port = 53,
        [int]$TimeoutMs = 12000,
        [switch]$Tcp
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $transport = if ($Tcp) { 'tcp' } else { 'udp' }
    try {
        $id = Get-Random -Minimum 1 -Maximum 65535
        $q = New-Object System.Collections.Generic.List[byte]
        $q.Add([byte](($id -shr 8) -band 0xff))
        $q.Add([byte]($id -band 0xff))
        $q.Add(0x01); $q.Add(0x00)  # flags: RD
        $q.Add(0x00); $q.Add(0x01)  # QDCOUNT
        $q.Add(0x00); $q.Add(0x00)  # ANCOUNT
        $q.Add(0x00); $q.Add(0x00)  # NSCOUNT
        $q.Add(0x00); $q.Add(0x00)  # ARCOUNT
        foreach ($label in $Name.TrimEnd('.').Split('.')) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            if ($bytes.Length -lt 1 -or $bytes.Length -gt 63) { throw 'Etiqueta DNS invalida.' }
            $q.Add([byte]$bytes.Length)
            foreach ($b in $bytes) { $q.Add($b) }
        }
        $q.Add(0x00)
        $q.Add(0x00); $q.Add(0x01)  # QTYPE A
        $q.Add(0x00); $q.Add(0x01)  # QCLASS IN
        $query = $q.ToArray()

        if ($Tcp) {
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $async = $client.BeginConnect($Server, $Port, $null, $null)
                if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw 'Timeout TCP.' }
                $client.EndConnect($async)
                $stream = $client.GetStream()
                $stream.ReadTimeout = $TimeoutMs
                $stream.WriteTimeout = $TimeoutMs
                $queryLength = [int]$query.Length
                $lengthBytes = New-Object byte[] 2
                $lengthBytes[0] = [byte](($queryLength -shr 8) -band 0xff)
                $lengthBytes[1] = [byte]($queryLength -band 0xff)
                $stream.Write($lengthBytes, 0, 2)
                $stream.Write($query, 0, $query.Length)
                $stream.Flush()
                $prefix = Read-FortressExact -Stream $stream -Count 2 -TimeoutMs $TimeoutMs
                $responseLength = ([int]$prefix[0] * 256) + [int]$prefix[1]
                if ($responseLength -lt 12 -or $responseLength -gt 65535) { throw 'Longitud DNS TCP invalida.' }
                $response = Read-FortressExact -Stream $stream -Count $responseLength -TimeoutMs $TimeoutMs
            } finally {
                if ($client) { try { $client.Close() } catch { } }
            }
        } else {
            $udp = New-Object System.Net.Sockets.UdpClient
            try {
                $udp.Client.ReceiveTimeout = $TimeoutMs
                $udp.Connect($Server, $Port)
                [void]$udp.Send($query, $query.Length)
                $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $response = $udp.Receive([ref]$remote)
            } finally {
                if ($udp) { try { $udp.Close() } catch { } }
            }
        }

        if (-not $response -or $response.Length -lt 12) { throw 'Respuesta DNS demasiado corta.' }
        $b0 = [int]$response[0]; $b1 = [int]$response[1]
        $b2 = [int]$response[2]; $b3 = [int]$response[3]
        $b6 = [int]$response[6]; $b7 = [int]$response[7]
        $responseId = ($b0 * 256) + $b1
        if ($responseId -ne $id) { throw 'ID DNS no coincide.' }
        $flags = ($b2 * 256) + $b3
        $rcode = $flags -band 15
        $answers = ($b6 * 256) + $b7
        $sw.Stop()
        $errorText = if ($rcode -eq 0) { $null } else { 'DNS RCODE ' + $rcode }
        return [pscustomobject]@{
            Success = ($rcode -eq 0 -and $answers -gt 0)
            Name = $Name
            Server = $Server
            Port = $Port
            Transport = $transport
            RCode = $rcode
            Answers = $answers
            Bytes = $response.Length
            ElapsedMs = $sw.ElapsedMilliseconds
            Error = $errorText
        }
    } catch {
        $sw.Stop()
        return [pscustomobject]@{
            Success = $false
            Name = $Name
            Server = $Server
            Port = $Port
            Transport = $transport
            RCode = $null
            Answers = 0
            Bytes = 0
            ElapsedMs = $sw.ElapsedMilliseconds
            Error = $_.Exception.Message
        }
    }
}

function Test-FortressTorExit {
    param(
        [string]$SocksHost = '127.0.0.1',
        [int]$SocksPort = 9050,
        [string]$TargetHost = 'example.com',
        [int]$TargetPort = 80,
        [int]$TimeoutMs = 20000
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = $null
    $stream = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($SocksHost, $SocksPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw 'Timeout conectando a SOCKS5.' }
        $client.EndConnect($async)
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()
        $greeting = [byte[]](0x05, 0x01, 0x00)
        $stream.Write($greeting, 0, $greeting.Length)
        $reply = Read-FortressExact -Stream $stream -Count 2 -TimeoutMs $TimeoutMs
        if ($reply[0] -ne 0x05 -or $reply[1] -ne 0x00) { throw 'SOCKS5 rechazo el metodo sin autenticacion.' }

        $hostBytes = [System.Text.Encoding]::ASCII.GetBytes($TargetHost)
        if ($hostBytes.Length -gt 255) { throw 'Destino SOCKS5 demasiado largo.' }
        $request = New-Object System.Collections.Generic.List[byte]
        $request.Add(0x05); $request.Add(0x01); $request.Add(0x00); $request.Add(0x03)
        $request.Add([byte]$hostBytes.Length)
        foreach ($b in $hostBytes) { $request.Add($b) }
        $request.Add([byte](($TargetPort -shr 8) -band 0xff))
        $request.Add([byte]($TargetPort -band 0xff))
        $requestBytes = $request.ToArray()
        $stream.Write($requestBytes, 0, $requestBytes.Length)
        $head = Read-FortressExact -Stream $stream -Count 4 -TimeoutMs $TimeoutMs
        if ($head[0] -ne 0x05) { throw 'Respuesta SOCKS5 invalida.' }
        if ($head[1] -ne 0x00) { throw ('SOCKS5 CONNECT rechazado (codigo ' + $head[1] + ').') }
        $atyp = $head[3]
        if ($atyp -eq 0x01) {
            [void](Read-FortressExact -Stream $stream -Count 4 -TimeoutMs $TimeoutMs)
        } elseif ($atyp -eq 0x04) {
            [void](Read-FortressExact -Stream $stream -Count 16 -TimeoutMs $TimeoutMs)
        } elseif ($atyp -eq 0x03) {
            $len = Read-FortressExact -Stream $stream -Count 1 -TimeoutMs $TimeoutMs
            [void](Read-FortressExact -Stream $stream -Count ([int]$len[0]) -TimeoutMs $TimeoutMs)
        } else {
            throw 'SOCKS5 ATYP desconocido.'
        }
        [void](Read-FortressExact -Stream $stream -Count 2 -TimeoutMs $TimeoutMs)

        if ($TargetPort -eq 80) {
            $http = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n")
            $stream.Write($http, 0, $http.Length)
            $stream.Flush()
            $buffer = New-Object byte[] 256
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { throw 'Sin respuesta HTTP a traves de Tor.' }
            $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
            if ($text -notmatch '^HTTP/') { throw 'Respuesta HTTP invalida a traves de Tor.' }
        }
        $sw.Stop()
        return [pscustomobject]@{
            Success = $true
            Target = "$TargetHost`:$TargetPort"
            ElapsedMs = $sw.ElapsedMilliseconds
            Error = $null
        }
    } catch {
        $sw.Stop()
        return [pscustomobject]@{
            Success = $false
            Target = "$TargetHost`:$TargetPort"
            ElapsedMs = $sw.ElapsedMilliseconds
            Error = $_.Exception.Message
        }
    } finally {
        if ($stream) { try { $stream.Dispose() } catch { } }
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Get-FortressJsonFile {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return $null }
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        if (-not $raw) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Write-FortressState {
    param(
        [hashtable]$State,
        [string]$AdGuardDir = $script:FortressDirDefault
    )
    try {
        $dataDir = Join-Path $AdGuardDir 'data'
        if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
        $path = Join-Path $dataDir 'fortress-state.json'
        $State['updatedAt'] = [DateTime]::UtcNow.ToString('o')
        $json = $State | ConvertTo-Json -Depth 10
        $tmp = $path + '.tmp'
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -Path $tmp -Destination $path -Force
    } catch {
        # El estado no debe tumbar el watchdog.
    }
}

function Add-FortressEvent {
    param(
        [string]$Code,
        [string]$Level = 'INFO',
        [string]$Message = '',
        [hashtable]$Data = @{},
        [string]$AdGuardDir = $script:FortressDirDefault
    )
    try {
        $dataDir = Join-Path $AdGuardDir 'data'
        if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
        $path = Join-Path $dataDir 'fortress-events.jsonl'
        if ((Test-Path $path) -and ((Get-Item $path).Length -gt 2MB)) {
            $old = $path + '.old'
            if (Test-Path $old) { Remove-Item $old -Force }
            Move-Item $path $old -Force
        }
        $event = [ordered]@{
            ts = [DateTime]::UtcNow.ToString('o')
            level = $Level
            code = $Code
            message = $Message
            data = $Data
        }
        $line = $event | ConvertTo-Json -Compress -Depth 8
        Add-Content -Path $path -Value $line -Encoding UTF8
    } catch {
        # El historial no debe tumbar el watchdog.
    }
}

function Get-FortressServiceStatus {
    param([string]$Name = 'AdGuardHome')
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        return [string]$svc.Status
    } catch {
        return 'ausente'
    }
}

function Get-FortressDecoyStatus {
    param([string]$AdGuardDir = $script:FortressDirDefault)
    return Get-FortressJsonFile -Path (Join-Path $AdGuardDir 'data\decoy-status.json')
}

function Get-FortressBridgeStatus {
    param([string]$AdGuardDir = $script:FortressDirDefault)
    return Get-FortressJsonFile -Path (Join-Path $AdGuardDir 'data\doh-bridge-status.json')
}

function Get-FortressProcessList {
    param([string]$Pattern)
    try {
        return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -eq 'node.exe' -and $_.CommandLine -and ($_.CommandLine -like $Pattern)
        })
    } catch {
        return @()
    }
}

function Get-FortressPipeline {
    param(
        [string]$AdGuardDir = $script:FortressDirDefault,
        [switch]$SkipTorExit
    )
    $torPort = Test-FortressTcpPort -Port 9050 -TimeoutMs 1500
    $torExit = $null
    if ($torPort -and -not $SkipTorExit) {
        $torExit = Test-FortressTorExit -TimeoutMs 12000
    }
    $bridgePort = Test-FortressTcpPort -Port 5336 -TimeoutMs 1500
    $bridgeDns = $null
    if ($bridgePort) {
        $bridgeDns = Test-FortressDnsQuery -Name 'example.com' -Port 5336 -TimeoutMs 8000
    }
    $aghService = Get-FortressServiceStatus -Name 'AdGuardHome'
    $aghDns = $null
    if ($aghService -eq 'Running') {
        $aghDns = Test-FortressDnsQuery -Name 'example.com' -Port 53 -TimeoutMs 8000
    }
    $healthy = [bool](
        $torPort -and
        ($SkipTorExit -or ($torExit -and $torExit.Success)) -and
        $bridgePort -and
        ($bridgeDns -and $bridgeDns.Success) -and
        ($aghService -eq 'Running') -and
        ($aghDns -and $aghDns.Success)
    )
    return [pscustomobject]@{
        Healthy = $healthy
        TorPort = $torPort
        TorExit = $torExit
        BridgePort = $bridgePort
        BridgeDns = $bridgeDns
        AdGuardService = $aghService
        AdGuardDns = $aghDns
        CheckedAt = [DateTime]::UtcNow.ToString('o')
    }
}
