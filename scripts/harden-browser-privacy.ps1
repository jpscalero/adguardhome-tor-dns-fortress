#Requires -Version 5.1
<#
.SYNOPSIS
    Reduce lo que el sitio web de destino puede saber del navegador.

.DESCRIPTION
    La fortaleza protege la capa DNS; el sitio final sigue viendo sesion,
    cookies, fingerprint, zona horaria e idioma (docs/LIMITS.md). Este script
    aplica lo unico que si se puede hacer desde el equipo:

      - Firefox: privacy.resistFingerprinting (fingerprint uniforme, zona horaria
        UTC, idioma en-US), aislamiento de cookies por sitio, borrado al cerrar,
        WebRTC desactivado y DoH propio desactivado.
      - Chrome/Edge: bloqueo de cookies de terceros, WebRTC sin UDP directo,
        DoH desactivado (si no lo hizo ya harden-browser-doh.ps1) y limpieza de
        datos al cerrar.

    No cierra la sesion iniciada: si entras en tu correo, el correo sabe quien
    eres. La mitigacion real es no iniciar sesion en el perfil privado y usar un
    perfil separado para cuentas.

.PARAMETER Undo
    Revierte user.js y los valores de politica anadidos.

.PARAMETER DryRun
    Muestra los cambios sin aplicarlos.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\harden-browser-privacy.ps1
#>

[CmdletBinding()]
param(
    [switch]$Undo,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

$firefoxPrefs = @{
    'privacy.resistFingerprinting' = 'true'
    'privacy.resistFingerprinting.letterboxing' = 'true'
    'privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts' = 'true'
    'privacy.spoof_english' = '2'
    'privacy.firstparty.isolate' = 'true'
    'network.cookie.cookieBehavior' = '5'
    'privacy.clearOnShutdown.cookies' = 'true'
    'privacy.clearOnShutdown.history' = 'true'
    'privacy.clearOnShutdown.sessions' = 'true'
    'privacy.clearOnShutdown.cache' = 'true'
    'privacy.clearOnShutdown.offlineApps' = 'true'
    'privacy.sanitize.sanitizeOnShutdown' = 'true'
    'media.peerconnection.enabled' = 'false'
    'network.trr.mode' = '0'
    'network.trr.confirmation_telemetry_enabled' = 'false'
    'privacy.globalprivacycontrol.enabled' = 'true'
    'browser.region.network.url' = '""'
    'browser.region.update.enabled' = 'false'
    'geo.enabled' = 'false'
    'webgl.disabled' = 'true'
}

function Get-FirefoxProfiles {
    $root = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
    if (-not (Test-Path $root)) { return @() }
    return @(Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue)
}

$firefoxTouched = @()
foreach ($profile in Get-FirefoxProfiles) {
    $userJs = Join-Path $profile.FullName 'user.js'
    $backup = Join-Path $profile.FullName 'user.js.fortress-bak'
    if ($Undo) {
        if (Test-Path $backup) {
            if (-not $DryRun) { Move-Item -Path $backup -Destination $userJs -Force }
            Write-Host ("  Firefox {0}: user.js restaurado." -f $profile.Name) -ForegroundColor Green
        } elseif (Test-Path $userJs) {
            if (-not $DryRun) { Remove-Item $userJs -Force }
            Write-Host ("  Firefox {0}: user.js eliminado." -f $profile.Name) -ForegroundColor Green
        }
        continue
    }

    if ($DryRun) {
        Write-Host ("  DRY-RUN: escribir {0}" -f $userJs) -ForegroundColor Cyan
        continue
    }
    if ((Test-Path $userJs) -and -not (Test-Path $backup)) {
        Copy-Item -Path $userJs -Destination $backup -Force
    }
    $lines = @(
        '// Fortaleza DNS - perfil de privacidad (generado por harden-browser-privacy.ps1)',
        '// ResistFingerprinting uniforma fingerprint, zona horaria (UTC) e idioma.'
    )
    foreach ($key in ($firefoxPrefs.Keys | Sort-Object)) {
        $lines += ('user_pref("{0}", {1});' -f $key, $firefoxPrefs[$key])
    }
    [System.IO.File]::WriteAllText($userJs, (($lines -join [Environment]::NewLine) + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
    $firefoxTouched += $profile.Name
    Write-Host ("  Firefox {0}: user.js aplicado." -f $profile.Name) -ForegroundColor Green
}

$policyValues = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'BlockThirdPartyCookies'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'WebRtcIPHandlingPolicy'; Value = 'disable_non_proxied_udp' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'DnsOverHttpsMode'; Value = 'off' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'BlockThirdPartyCookies'; Value = 1 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'WebRtcIPHandlingPolicy'; Value = 'disable_non_proxied_udp' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DnsOverHttpsMode'; Value = 'off' }
)

if ($DryRun) {
    foreach ($p in $policyValues) {
        $state = if ($Undo) { 'eliminar' } else { ('=' + $p.Value) }
        Write-Host ("  DRY-RUN: {0}\{1} {2}" -f $p.Path, $p.Name, $state) -ForegroundColor Cyan
    }
    exit 0
}

foreach ($p in $policyValues) {
    if ($Undo) {
        Remove-ItemProperty -Path $p.Path -Name $p.Name -ErrorAction SilentlyContinue
    } else {
        if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
        New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType ($(if ($p.Value -is [int]) { 'DWord' } else { 'String' })) -Force | Out-Null
    }
}

if ($Undo) {
    Write-Host 'Politicas de navegador revertidas.' -ForegroundColor Green
} else {
    Write-Host 'Politicas de Chrome/Edge aplicadas.' -ForegroundColor Green
}

Write-Host ''
Write-Host 'Recuerda: esto uniforma el fingerprint y la zona horaria, pero no oculta una sesion iniciada.' -ForegroundColor Cyan
Write-Host 'Usa un perfil sin cuentas para navegar y otro distinto para tu correo.' -ForegroundColor Cyan
exit 0
