<#
.SYNOPSIS
    Instala y arranca los servicios de AdGuard Home, Tor y GoodbyeDPI.

.DESCRIPTION
    El instalador de la fortaleza configura los ficheros y las reglas, pero no
    registra los servicios de terceros. Este script los instala si faltan y los
    deja en ejecucion, para que la instalacion se pueda hacer con un solo clic.

    GoodbyeDPI es opcional: si no esta descomprimido o su instalador falla, se
    avisa y se continua. El DNS y Tor siguen funcionando.

.PARAMETER TargetDir
    Carpeta de AdGuard Home. Por defecto FORTRESS_DIR o C:\AdGuardHome.

.PARAMETER TorDir
    Carpeta del Tor Expert Bundle. Por defecto C:\Tor.

.PARAMETER GoodbyeDir
    Carpeta de GoodbyeDPI. Por defecto C:\GoodbyeDPI.

.PARAMETER SkipGoodbyeDPI
    No intenta instalar GoodbyeDPI.

.PARAMETER DryRun
    Muestra lo que haria sin instalar ni arrancar nada.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\instalar-servicios.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [string]$TorDir = 'C:\Tor',
    [string]$GoodbyeDir = 'C:\GoodbyeDPI',
    [switch]$SkipGoodbyeDPI,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host ('  -> ' + $Message) -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host ('  -> AVISO: ' + $Message) -ForegroundColor Yellow
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ((-not $DryRun) -and (-not $isAdmin)) {
    Write-Host '[ERROR] Ejecuta este script como Administrador.' -ForegroundColor Red
    exit 1
}

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

Write-Host ''
Write-Host '==========================================================' -ForegroundColor Cyan
Write-Host '   SERVICIOS DE LA FORTALEZA DNS' -ForegroundColor Cyan
Write-Host '==========================================================' -ForegroundColor Cyan
Write-Host ''

# --- Tor (primero, para que AdGuard pueda descargar sus listas) -------------
Write-Step 'Tor...'
$torExe = Join-Path $TorDir 'tor.exe'
if (-not (Test-Path $torExe)) {
    throw ("No existe {0}. Descomprime el Tor Expert Bundle en {1}." -f $torExe, $TorDir)
}
$torService = Get-Service -Name 'tor' -ErrorAction SilentlyContinue
if (-not $torService) {
    if ($DryRun) {
        Write-Step 'DRY-RUN: tor.exe --service install'
    } else {
        Push-Location $TorDir
        try {
            & $torExe --service install
        } finally {
            Pop-Location
        }
        Start-Sleep -Seconds 2
        $torService = Get-Service -Name 'tor' -ErrorAction SilentlyContinue
        if (-not $torService) {
            throw 'No se pudo instalar el servicio tor.'
        }
    }
}
if ($DryRun) {
    Write-Step 'DRY-RUN: Start-Service tor'
} elseif ($torService.Status -eq 'Running') {
    Write-Ok 'Tor ya estaba en ejecucion.'
} else {
    Start-Service -Name 'tor' -ErrorAction Stop
    Write-Ok 'Tor en ejecucion.'
}

# --- AdGuard Home -----------------------------------------------------------
Write-Step 'AdGuard Home...'
$aghExe = Join-Path $TargetDir 'AdGuardHome.exe'
if (-not (Test-Path $aghExe)) {
    throw ("No existe {0}. Descomprime AdGuard Home en esa carpeta." -f $aghExe)
}
$aghService = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
if (-not $aghService) {
    if ($DryRun) {
        Write-Step 'DRY-RUN: AdGuardHome.exe -s install'
    } else {
        Push-Location $TargetDir
        try {
            & $aghExe -s install
        } finally {
            Pop-Location
        }
        Start-Sleep -Seconds 2
        $aghService = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
        if (-not $aghService) {
            throw 'No se pudo instalar el servicio AdGuardHome.'
        }
    }
}
if ($DryRun) {
    Write-Step 'DRY-RUN: Start-Service AdGuardHome'
} else {
    if ($aghService.Status -eq 'Running') {
        Write-Ok 'AdGuard Home ya estaba en ejecucion.'
    } else {
        Start-Service -Name 'AdGuardHome' -ErrorAction Stop
        Write-Ok 'AdGuard Home en ejecucion.'
    }

    Write-Step 'Esperando a que AdGuard Home escuche en 127.0.0.1:53...'
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect('127.0.0.1', 53, $null, $null)
            $connected = $async.AsyncWaitHandle.WaitOne(1000, $false)
            if ($connected -and $client.Connected) {
                $client.EndConnect($async)
                $ready = $true
                break
            }
        } catch {
        } finally {
            $client.Close()
        }
        Start-Sleep -Seconds 2
    }
    if ($ready) {
        Write-Ok 'AdGuard Home responde en 127.0.0.1:53.'
    } else {
        Write-Warn 'AdGuard Home aun no responde; la comprobacion final lo indicara.'
    }
}

# --- GoodbyeDPI (opcional) --------------------------------------------------
if ($SkipGoodbyeDPI) {
    Write-Step 'GoodbyeDPI omitido (-SkipGoodbyeDPI).'
} elseif (-not (Test-Path $GoodbyeDir)) {
    Write-Warn ("No existe {0}; se omite GoodbyeDPI. El DNS funciona igual, pero sin evasion DPI." -f $GoodbyeDir)
} else {
    Write-Step 'GoodbyeDPI...'
    $gdService = Get-Service -Name 'GoodbyeDPI' -ErrorAction SilentlyContinue
    if (-not $gdService) {
        $gdInstaller = Get-ChildItem -Path $GoodbyeDir -Filter 'service_install*.cmd' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $gdInstaller) {
            Write-Warn 'No se encontro service_install*.cmd en la carpeta de GoodbyeDPI; se omite.'
        } elseif ($DryRun) {
            Write-Step ('DRY-RUN: ejecutar {0}' -f $gdInstaller.FullName)
        } else {
            Push-Location $GoodbyeDir
            try {
                & cmd.exe /c ('"' + $gdInstaller.FullName + '"')
            } finally {
                Pop-Location
            }
            Start-Sleep -Seconds 2
            $gdService = Get-Service -Name 'GoodbyeDPI' -ErrorAction SilentlyContinue
        }
    }
    if ($DryRun) {
        Write-Step 'DRY-RUN: Start-Service GoodbyeDPI'
    } elseif ($gdService.Status -eq 'Running') {
        Write-Ok 'GoodbyeDPI ya estaba en ejecucion.'
    } elseif ($gdService) {
        try {
            Start-Service -Name 'GoodbyeDPI' -ErrorAction Stop
            Write-Ok 'GoodbyeDPI en ejecucion.'
        } catch {
            Write-Warn ('GoodbyeDPI no arranco: {0}' -f $_.Exception.Message)
        }
    } else {
        Write-Warn 'GoodbyeDPI no quedo instalado; se omite.'
    }
}

Write-Host ''
Write-Host 'Servicios preparados.' -ForegroundColor Green
Write-Host ''
