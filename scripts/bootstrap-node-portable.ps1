<#
.SYNOPSIS
    Instala Node.js en modo portable dentro de la carpeta de la fortaleza.

.DESCRIPTION
    El instalador MSI de Node falla en algunos equipos con error 1603 (acceso
    denegado al registro / otra instalacion en curso). Este script descarga el
    ZIP oficial, comprueba su SHA256 contra SHASUMS256.txt del mismo servidor y
    lo descomprime en <TargetDir>\node, sin tocar el registro ni el sistema.

    Despues anade <TargetDir>\node a la variable PATH de usuario para que los
    lanzadores encuentren node.exe, y para cuando el centinela o el watchdog lo
    invoquen por nombre.

.PARAMETER Version
    Version concreta (por ejemplo v22.14.0). Si se omite, usa la ultima LTS.

.PARAMETER TargetDir
    Carpeta de la fortaleza. Por defecto FORTRESS_DIR o C:\AdGuardHome.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\bootstrap-node-portable.ps1
#>

[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$TargetDir = ''
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Stop'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

# PowerShell 5.1 necesita TLS 1.2 explicito para nodejs.org
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

function Write-Step {
    param([string]$Message)
    Write-Output ('[*] ' + $Message)
}

function Resolve-NodeVersion {
    if ($Version) { return $Version }
    Write-Step 'Consultando la ultima version LTS en nodejs.org/dist/index.json ...'
    $index = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -UseBasicParsing
    $lts = $index | Where-Object { $_.lts -ne $false } | Select-Object -First 1
    if (-not $lts) { throw 'No se pudo determinar la version LTS de Node.' }
    return [string]$lts.version
}

$resolved = Resolve-NodeVersion
Write-Step ("Version objetivo: {0}" -f $resolved)

$arch = if ([Environment]::Is64BitOperatingSystem) { 'win-x64' } else { 'win-x86' }
$fileName = 'node-{0}-{1}.zip' -f $resolved, $arch
$baseUrl = 'https://nodejs.org/dist/{0}' -f $resolved
$zipUrl = '{0}/{1}' -f $baseUrl, $fileName
$sumsUrl = '{0}/SHASUMS256.txt' -f $baseUrl

$nodeDir = Join-Path $TargetDir 'node'
$nodeExe = Join-Path $nodeDir 'node.exe'

if (Test-Path $nodeExe) {
    $current = (& $nodeExe --version) 2>$null
    if ($current) { Write-Step ("Node ya presente en {0} ({1}). Nada que hacer." -f $nodeDir, $current); }
    else { Write-Step 'node.exe presente pero no ejecutable; se reinstalara.' }
    if ($current) {
        $pathUser = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $pathUser) { $pathUser = '' }
        if ($pathUser -notlike ('*' + $nodeDir + '*')) {
            $newPath = if ($pathUser) { $nodeDir + ';' + $pathUser } else { $nodeDir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Step 'Anadido al PATH de usuario.'
        }
        exit 0
    }
}

$tmp = Join-Path $env:TEMP ('node-portable-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $zipPath = Join-Path $tmp $fileName
    Write-Step ("Descargando {0}" -f $zipUrl)
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

    Write-Step 'Descargando SHASUMS256.txt y verificando integridad...'
    $sums = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing).Content
    $expected = $null
    foreach ($line in ($sums -split "`r?`n")) {
        $line = $line.Trim()
        if ($line -match ('^([0-9a-fA-F]{64})\s+' + [Regex]::Escape($fileName) + '$')) {
            $expected = $Matches[1].ToLowerInvariant()
            break
        }
    }
    if (-not $expected) { throw ("No se encontro el hash de {0} en SHASUMS256.txt" -f $fileName) }

    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw ("SHA256 no coincide. Esperado {0}, obtenido {1}. Descarga abortada." -f $expected, $actual)
    }
    Write-Step 'SHA256 correcto.'

    Write-Step 'Descomprimiendo...'
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $extracted = Join-Path $tmp ('node-{0}-{1}' -f $resolved, $arch)
    if (-not (Test-Path $extracted)) {
        $extracted = (Get-ChildItem -Path $tmp -Directory | Where-Object { $_.Name -like 'node-*' } | Select-Object -First 1).FullName
    }
    if (-not $extracted) { throw 'No se encontro la carpeta descomprimida de Node.' }

    if (Test-Path $nodeDir) { Remove-Item $nodeDir -Recurse -Force }
    Move-Item -Path $extracted -Destination $nodeDir

    $installed = (& (Join-Path $nodeDir 'node.exe') --version) 2>$null
    Write-Step ("Instalado Node {0} en {1}" -f $installed, $nodeDir)

    $pathUser = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $pathUser) { $pathUser = '' }
    if ($pathUser -notlike ('*' + $nodeDir + '*')) {
        $newPath = if ($pathUser) { $nodeDir + ';' + $pathUser } else { $nodeDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Step 'Anadido al PATH de usuario (abre una consola nueva para verlo).'
    }
}
finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
