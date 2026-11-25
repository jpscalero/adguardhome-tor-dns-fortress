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
    Elimina las claves de politica y revierte el policies.json de Firefox:
    restaura la copia .fortress-bak si existe o quita solo DNSOverHTTPS.

.PARAMETER DryRun
    Muestra las acciones sin aplicarlas.
#>

[CmdletBinding()]
param(
    [switch]$Undo,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

function Write-JsonNoBom {
    param(
        [string]$Path,
        [object]$Object
    )
    $json = $Object | ConvertTo-Json -Depth 8
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $json, $utf8)
}

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
$ffBases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)
if ($env:LOCALAPPDATA) { $ffBases += (Join-Path $env:LOCALAPPDATA 'Programs') }
$ffRoots = @()
foreach ($base in ($ffBases | Where-Object { $_ } | Select-Object -Unique)) {
    foreach ($name in @('Mozilla Firefox', 'Mozilla Firefox ESR')) {
        $candidate = Join-Path $base $name
        if (Test-Path $candidate) { $ffRoots += $candidate }
    }
}

foreach ($root in $ffRoots) {
    $dist = Join-Path $root 'distribution'
    $policyFile = Join-Path $dist 'policies.json'
    $backupFile = Join-Path $dist 'policies.json.fortress-bak'

    if ($Undo) {
        if (-not (Test-Path $policyFile)) { continue }
        if ($DryRun) {
            if (Test-Path $backupFile) { Write-Output ("DRY-RUN: restaurar {0} desde {1}" -f $policyFile, $backupFile) }
            else { Write-Output ("DRY-RUN: quitar DNSOverHTTPS de {0}" -f $policyFile) }
            continue
        }
        if (Test-Path $backupFile) {
            Copy-Item -Path $backupFile -Destination $policyFile -Force
            Write-Output ("Firefox: restaurado {0} desde la copia de seguridad" -f $policyFile)
            continue
        }
        try {
            $current = Get-Content -Path $policyFile -Raw | ConvertFrom-Json
            if ($current -and ($current.PSObject.Properties.Name -contains 'DNSOverHTTPS')) {
                $current.PSObject.Properties.Remove('DNSOverHTTPS')
                if (@($current.PSObject.Properties).Count -eq 0) {
                    Remove-Item $policyFile -Force
                    Write-Output ("Firefox: eliminado {0} (solo contenia DNSOverHTTPS)" -f $policyFile)
                } else {
                    Write-JsonNoBom -Path $policyFile -Object $current
                    Write-Output ("Firefox: DNSOverHTTPS eliminado de {0}" -f $policyFile)
                }
            }
        } catch {
            Write-Output ("AVISO: no se pudo revertir {0}; revisalo a mano." -f $policyFile)
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
        $raw = Get-Content -Path $policyFile -Raw
        if ($raw -and $raw.Trim().Length -gt 0) {
            try {
                $existing = $raw | ConvertFrom-Json
            } catch {
                Write-Output ("AVISO: {0} no es JSON valido; no se modifica. Corrigelo o borralo y vuelve a ejecutar." -f $policyFile)
                continue
            }
            if ($null -eq $existing -or $existing -is [System.Array] -or $existing -is [string] -or $existing -is [ValueType]) {
                Write-Output ("AVISO: {0} no contiene un objeto de politicas; no se modifica." -f $policyFile)
                continue
            }
            if (-not (Test-Path $backupFile)) {
                Copy-Item -Path $policyFile -Destination $backupFile -Force
                Write-Output ("Firefox: copia de seguridad en {0}" -f $backupFile)
            }
        }
    }
    if (-not $existing) { $existing = [pscustomobject]@{} }

    $merged = [ordered]@{}
    if ($existing.psobject.Properties) {
        foreach ($prop in $existing.psobject.Properties) { $merged[$prop.Name] = $prop.Value }
    }
    $merged['DNSOverHTTPS'] = [ordered]@{ 'Enabled' = $false }

    Write-JsonNoBom -Path $policyFile -Object $merged
    Write-Output ("Firefox: DNSOverHTTPS desactivado en {0}" -f $policyFile)
}

Write-Output ''
Write-Output 'Comprobacion manual recomendada:'
Write-Output '  - Chrome/Edge: chrome://policy  debe listar DnsOverHttpsMode = off'
Write-Output '  - Firefox: about:policies debe mostrar DNSOverHTTPS deshabilitado'
