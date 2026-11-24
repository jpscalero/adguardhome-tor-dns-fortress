<#
.SYNOPSIS
    Evita que los navegadores se salten AdGuard Home con su propio DoH.

.DESCRIPTION
    Chrome, Edge y Firefox pueden activar DNS over HTTPS propio. Si lo hacen,
    resuelven por su cuenta y el filtrado, el centinela y el .onion dejan de
    aplicarse: es una fuga silenciosa de la fortaleza.

    Este script escribe politicas de empresa (solo lectura para el usuario):
      - Chrome:  HKLM\SOFTWARE\Policies\Google\Chrome\DnsOverHttpsMode = "off"
      - Edge:    HKLM\SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode = "off"
      - Firefox: <instalacion>\distribution\policies.json con DNSOverHTTPS off

    Requiere administrador. Es reversible con -Undo.

.PARAMETER Undo
    Elimina las claves de politica y el policies.json creado por este script.

.PARAMETER DryRun
    Muestra las acciones sin aplicarlas.
#>

[CmdletBinding()]
param(
    [switch]$Undo,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

$policies = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome'; Name = 'DnsOverHttpsMode'; Value = 'off'; Label = 'Chrome' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DnsOverHttpsMode'; Value = 'off'; Label = 'Edge' }
)

foreach ($p in $policies) {
    if ($Undo) {
        if (Test-Path $p.Path) {
            if ($DryRun) { Write-Output ("DRY-RUN: quitar {0} de {1}" -f $p.Name, $p.Path); continue }
            Remove-ItemProperty -Path $p.Path -Name $p.Name -Force -ErrorAction SilentlyContinue
            Write-Output ("{0}: politica DoH eliminada" -f $p.Label)
        }
        continue
    }

    if ($DryRun) {
        Write-Output ("DRY-RUN: {0} -> {1}\{2} = {3}" -f $p.Label, $p.Path, $p.Name, $p.Value)
        continue
    }

    if (-not (Test-Path $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
    New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType String -Force | Out-Null
    Write-Output ("{0}: DnsOverHttpsMode=off aplicado" -f $p.Label)
}

# Firefox: policies.json en la carpeta de distribucion
$ffRoots = @(
    (Join-Path $env:ProgramFiles 'Mozilla Firefox'),
    (Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox')
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($root in $ffRoots) {
    $dist = Join-Path $root 'distribution'
    $policyFile = Join-Path $dist 'policies.json'

    if ($Undo) {
        if (Test-Path $policyFile) {
            if ($DryRun) { Write-Output ("DRY-RUN: borrar {0}" -f $policyFile); continue }
            Remove-Item $policyFile -Force -ErrorAction SilentlyContinue
            Write-Output ("Firefox: eliminado {0}" -f $policyFile)
        }
        continue
    }

    if ($DryRun) {
        Write-Output ("DRY-RUN: escribir {0} con DNSOverHTTPS desactivado" -f $policyFile)
        continue
    }

    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }

    $existing = $null
    if (Test-Path $policyFile) {
        try { $existing = Get-Content -Path $policyFile -Raw | ConvertFrom-Json } catch { $existing = $null }
    }
    if (-not $existing) { $existing = [pscustomobject]@{} }

    $merged = [ordered]@{}
    if ($existing.psobject.Properties) {
        foreach ($prop in $existing.psobject.Properties) { $merged[$prop.Name] = $prop.Value }
    }
    $merged['DNSOverHTTPS'] = [ordered]@{ 'Enabled' = $false }

    ($merged | ConvertTo-Json -Depth 8) | Set-Content -Path $policyFile -Encoding UTF8
    Write-Output ("Firefox: DNSOverHTTPS desactivado en {0}" -f $policyFile)
}

Write-Output ''
Write-Output 'Comprobacion manual recomendada:'
Write-Output '  - Chrome/Edge: chrome://policy  debe listar DnsOverHttpsMode = off'
Write-Output '  - Firefox: about:policies debe mostrar DNSOverHTTPS deshabilitado'
