#Requires -Version 5.1
<#
.SYNOPSIS
    Manifiesto SHA256 de los ficheros criticos de la fortaleza.

.DESCRIPTION
    -Create  calcula el manifiesto y guarda una copia base en config\baseline.
    -Verify  compara el estado actual con el manifiesto (codigo 1 si difiere).
    -Restore devuelve los scripts desde la copia base y vuelve a verificar.

    No incluye configuracion viva (.env, AdGuardHome.yaml), logs ni datos: esos
    cambian por diseno. Solo codigo ejecutable y el binario de AdGuard Home.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\integrity-check.ps1 -Create
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [string]$ManifestPath = '',
    [string]$BackupDir = '',
    [switch]$Create,
    [switch]$Verify,
    [switch]$Restore
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Stop'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}
if (-not $ManifestPath) { $ManifestPath = Join-Path $TargetDir 'fortress.manifest.json' }
if (-not $BackupDir) { $BackupDir = Join-Path $TargetDir 'config\baseline' }

function Get-CriticalFiles {
    $patterns = @('*.ps1', '*.cmd', '*.vbs', '*.js')
    $files = @()
    foreach ($pattern in $patterns) {
        $files += @(Get-ChildItem -Path $TargetDir -Filter $pattern -File -ErrorAction SilentlyContinue)
    }
    $exe = Join-Path $TargetDir 'AdGuardHome.exe'
    if (Test-Path $exe) { $files += Get-Item $exe }
    return $files | Sort-Object FullName -Unique
}

function New-Manifest {
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $entries = @()
    foreach ($file in Get-CriticalFiles) {
        $relative = $file.FullName.Substring($TargetDir.Length).TrimStart('\')
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $entries += [ordered]@{ path = $relative; sha256 = $hash }
        $destination = Join-Path $BackupDir $relative
        $parent = Split-Path -Parent $destination
        if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -Path $file.FullName -Destination $destination -Force
    }
    $manifest = [ordered]@{
        created_at = (Get-Date).ToUniversalTime().ToString('o')
        version = '2.0.4'
        files = $entries
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestPath -Encoding UTF8
    Write-Host ("Manifiesto creado: {0} ficheros -> {1}" -f $entries.Count, $ManifestPath) -ForegroundColor Green
    Write-Host ("Copia base: {0}" -f $BackupDir) -ForegroundColor DarkGray
}

function Test-Manifest {
    if (-not (Test-Path $ManifestPath)) {
        Write-Host 'No hay manifiesto de integridad.' -ForegroundColor Yellow
        return 2
    }
    $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
    $bad = @()
    foreach ($entry in $manifest.files) {
        $path = Join-Path $TargetDir $entry.path
        if (-not (Test-Path $path)) {
            $bad += ('FALTA   ' + $entry.path)
            continue
        }
        $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        if ($hash -ne $entry.sha256) {
            $bad += ('CAMBIO  ' + $entry.path)
        }
    }
    if ($bad.Count -gt 0) {
        Write-Host 'Integridad comprometida:' -ForegroundColor Red
        $bad | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }
        return 1
    }
    Write-Host ("Integridad correcta: {0} ficheros sin cambios." -f @($manifest.files).Count) -ForegroundColor Green
    return 0
}

function Restore-Manifest {
    if (-not (Test-Path $ManifestPath)) {
        Write-Host 'No hay manifiesto para restaurar.' -ForegroundColor Red
        return 2
    }
    $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
    $restored = 0
    foreach ($entry in $manifest.files) {
        $source = Join-Path $BackupDir $entry.path
        $destination = Join-Path $TargetDir $entry.path
        if (-not (Test-Path $source)) { continue }
        Copy-Item -Path $source -Destination $destination -Force
        $restored++
    }
    Write-Host ("Restaurados {0} ficheros desde la copia base." -f $restored) -ForegroundColor Yellow
    return (Test-Manifest)
}

if ($Create) { New-Manifest; exit 0 }
if ($Restore) { exit (Restore-Manifest) }
exit (Test-Manifest)
