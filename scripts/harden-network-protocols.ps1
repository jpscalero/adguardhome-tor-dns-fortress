#Requires -Version 5.1
<#
.SYNOPSIS
    Endurece los protocolos de descubrimiento y comparticion de Windows.

.DESCRIPTION
    Desactiva las vias clasicas de ataque en redes locales:

      LLMNR     respuestas multicast falsificadas (Responder / NBT-NS poisoning)
      NetBIOS   resolucion por difusion y sesiones NBT sobre TCP/IP
      WPAD      secuestro de la autodeteccion de proxy
      SMBv1     protocolo obsoleto usado por EternalBlue / WannaCry

    Guarda el estado original en network-hardening.state.json dentro de
    TargetDir y es reversible con -Undo. Requiere Administrador para aplicar o
    revertir; -DryRun solo muestra el estado y el plan, sin tocar nada.

    NetBIOS y SMBv1 pueden necesitar reinicio para que el cambio sea completo.
    Desactivar SMBv1 rompe equipos muy antiguos (Windows XP/2003 y algunos NAS);
    por eso todo es reversible.

.PARAMETER TargetDir
    Carpeta de la fortaleza (por defecto C:\AdGuardHome o FORTRESS_DIR).

.PARAMETER Undo
    Restaura los valores originales guardados por una ejecucion anterior.

.PARAMETER DryRun
    Muestra el estado actual y lo que se cambiaria, sin modificar el sistema.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\harden-network-protocols.ps1 -DryRun

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\harden-network-protocols.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\harden-network-protocols.ps1 -Undo
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [switch]$Undo,
    [switch]$DryRun
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Stop'

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}

$statePath = Join-Path $TargetDir 'network-hardening.state.json'
$llmnrKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$wpadUserKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$wpadMachineKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
$smbClientKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'

function Write-Step {
    param([string]$Message)
    Write-Host ('[*] ' + $Message) -ForegroundColor Yellow
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegDword {
    param([string]$Path, [string]$Name)
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $key) { return [pscustomobject]@{ Exists = $false; Value = $null } }
    if (-not ($key.GetValueNames() -contains $Name)) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }
    return [pscustomobject]@{ Exists = $true; Value = [int]$key.GetValue($Name) }
}

function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Restore-RegDword {
    param([string]$Path, [string]$Name, $Saved)
    if ($null -eq $Saved) { return }
    if ($Saved.Exists) {
        Set-RegDword -Path $Path -Name $Name -Value ([int]$Saved.Value)
    } else {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

function Get-NetbiosAdapters {
    return @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue |
        Where-Object { $_.SettingID })
}

function Set-NetbiosOption {
    param($Adapter, [int]$Option)
    $result = $null
    try {
        $result = Invoke-CimMethod -InputObject $Adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = $Option } -ErrorAction Stop
    } catch { }
    if ($null -ne $result -and $result.ReturnValue -eq 0) {
        return $true
    }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_' + $Adapter.SettingID
    if (Test-Path -LiteralPath $key) {
        Set-RegDword -Path $key -Name 'NetbiosOptions' -Value $Option
        return $true
    }
    return $false
}

function Get-Smb1ServerStatus {
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        return [pscustomobject]@{ Available = $true; Enabled = [bool]$cfg.EnableSMB1Protocol }
    } catch {
        return [pscustomobject]@{ Available = $false; Enabled = $null }
    }
}

# ---------------------------------------------------------------------------
# DryRun: estado actual y plan, sin privilegios ni cambios.
# ---------------------------------------------------------------------------
if ($DryRun) {
    Write-Host 'DRY-RUN: no se modificara nada.' -ForegroundColor Cyan
    Write-Host ''

    $llmnr = Get-RegDword -Path $llmnrKey -Name 'EnableMulticast'
    $llmnrText = if ($llmnr.Exists -and $llmnr.Value -eq 0) { 'deshabilitado' } else { 'habilitado o sin politica' }

    $wpadUser = Get-RegDword -Path $wpadUserKey -Name 'AutoDetect'
    $wpadMachine = Get-RegDword -Path $wpadMachineKey -Name 'DisableWpad'
    $wpadOk = (($wpadUser.Exists -and $wpadUser.Value -eq 0) -and ($wpadMachine.Exists -and $wpadMachine.Value -eq 1))
    $wpadText = if ($wpadOk) { 'deshabilitado' } else { 'habilitado o parcial' }

    $nics = Get-NetbiosAdapters
    $nbPending = @($nics | Where-Object {
        $null -eq $_.TcpipNetbiosOptions -or [int]$_.TcpipNetbiosOptions -ne 2
    })
    $nbText = if ($nbPending.Count -eq 0) { 'deshabilitado en todos los adaptadores' } else { ('pendiente en {0} de {1} adaptador(es)' -f $nbPending.Count, $nics.Count) }

    $smbServer = Get-Smb1ServerStatus
    $smbServerText = if (-not $smbServer.Available) { 'no disponible' } elseif ($smbServer.Enabled) { 'habilitado' } else { 'deshabilitado' }

    $smbClient = Get-RegDword -Path $smbClientKey -Name 'Start'
    if (-not $smbClient.Exists) {
        $smbClientText = 'no instalado'
    } elseif ([int]$smbClient.Value -eq 4) {
        $smbClientText = 'deshabilitado (Start=4)'
    } else {
        $smbClientText = ('habilitado (Start={0})' -f $smbClient.Value)
    }

    Write-Host 'Estado actual:' -ForegroundColor Cyan
    Write-Host ('  LLMNR ............ {0}' -f $llmnrText)
    Write-Host ('  WPAD ............. {0}' -f $wpadText)
    Write-Host ('  NetBIOS .......... {0}' -f $nbText)
    Write-Host ('  SMBv1 servidor ... {0}' -f $smbServerText)
    Write-Host ('  SMBv1 cliente .... {0}' -f $smbClientText)
    Write-Host ''
    Write-Host 'Cambios que aplicaria:' -ForegroundColor Cyan
    Write-Host '  - EnableMulticast=0 en la politica DNSClient (LLMNR).'
    Write-Host '  - AutoDetect=0 y DisableWpad=1 (WPAD).'
    Write-Host '  - NetbiosOptions=2 en cada adaptador con IP activa.'
    Write-Host '  - EnableSMB1Protocol=false (servidor) y mrxsmb10 Start=4 (cliente).'
    Write-Host ''
    Write-Host 'Estado original se guardaria en network-hardening.state.json para -Undo.' -ForegroundColor DarkGray
    exit 0
}

if (-not (Test-IsAdmin)) {
    Write-Error 'Este script requiere privilegios de Administrador. Ejecutalo en una consola elevada.'
    exit 1
}

# ---------------------------------------------------------------------------
# Undo: restaurar el estado guardado.
# ---------------------------------------------------------------------------
if ($Undo) {
    if (-not (Test-Path -LiteralPath $statePath)) {
        Write-Warning ('No existe {0}; no hay nada que revertir.' -f $statePath)
        exit 0
    }

    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    } catch {
        Write-Error ('No se pudo leer {0}: {1}' -f $statePath, $_.Exception.Message)
        exit 3
    }

    $errors = 0
    Write-Step 'Restaurando LLMNR y WPAD...'
    try {
        Restore-RegDword -Path $llmnrKey -Name 'EnableMulticast' -Saved $state.Llmnr
        Restore-RegDword -Path $wpadUserKey -Name 'AutoDetect' -Saved $state.WpadUser
        Restore-RegDword -Path $wpadMachineKey -Name 'DisableWpad' -Saved $state.WpadMachine
    } catch {
        $errors++
        Write-Warning ('  No se pudo restaurar LLMNR/WPAD: {0}' -f $_.Exception.Message)
    }

    Write-Step 'Restaurando NetBIOS sobre TCP/IP...'
    foreach ($entry in @($state.Netbios)) {
        $nic = Get-NetbiosAdapters | Where-Object { $_.SettingID -eq $entry.SettingID } | Select-Object -First 1
        if (-not $nic) { continue }
        try {
            if (-not (Set-NetbiosOption -Adapter $nic -Option ([int]$entry.Options))) {
                throw 'no se encontro la clave NetBT del adaptador'
            }
        } catch {
            $errors++
            Write-Warning ('  {0}: {1}' -f $entry.Description, $_.Exception.Message)
        }
    }

    Write-Step 'Restaurando SMBv1...'
    if ($state.Smb1Server.Available) {
        try {
            Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$state.Smb1Server.Value) -Force -ErrorAction Stop
        } catch {
            $errors++
            Write-Warning ('  Servidor SMBv1: {0}' -f $_.Exception.Message)
        }
    }
    if ($state.Smb1Client.Exists) {
        try {
            Restore-RegDword -Path $smbClientKey -Name 'Start' -Saved $state.Smb1Client
        } catch {
            $errors++
            Write-Warning ('  Cliente SMBv1: {0}' -f $_.Exception.Message)
        }
    }

    if ($errors -eq 0) {
        Remove-Item -LiteralPath $statePath -Force
        Write-Host ''
        Write-Host 'Endurecimiento revertido. Reinicia para que NetBIOS y SMBv1 vuelvan a su estado anterior.' -ForegroundColor Green
        exit 0
    }

    Write-Host ''
    Write-Warning ('Quedaron {0} error(es). El estado se conserva en {1} para reintentar.' -f $errors, $statePath)
    exit 4
}

# ---------------------------------------------------------------------------
# Apply: capturar estado original (una sola vez) y aplicar.
# ---------------------------------------------------------------------------
$existingState = $null
if (Test-Path -LiteralPath $statePath) {
    try {
        $existingState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        Write-Step ('Estado original ya guardado en {0}; se conserva para -Undo.' -f $statePath)
    } catch {
        Write-Warning ('No se pudo leer {0}; se sobrescribira con el estado actual.' -f $statePath)
    }
}

if (-not (Test-Path -LiteralPath $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$nics = Get-NetbiosAdapters

if ($existingState) {
    $knownIds = @($existingState.Netbios | ForEach-Object { $_.SettingID })
    $merged = @($existingState.Netbios)
    $added = $false
    foreach ($nic in $nics) {
        if ($knownIds -notcontains [string]$nic.SettingID) {
            $originalOption = 0
            if ($null -ne $nic.TcpipNetbiosOptions) { $originalOption = [int]$nic.TcpipNetbiosOptions }
            $merged += [pscustomobject]@{
                SettingID   = [string]$nic.SettingID
                Description = [string]$nic.Description
                Options     = $originalOption
            }
            $added = $true
        }
    }
    if ($added) {
        $existingState.Netbios = $merged
        $json = $existingState | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($statePath, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Step 'Estado original ampliado con los adaptadores nuevos.'
    }
}

if (-not $existingState) {
    $netbiosState = @()
    foreach ($nic in $nics) {
        $nbOptions = 0
        if ($null -ne $nic.TcpipNetbiosOptions) { $nbOptions = [int]$nic.TcpipNetbiosOptions }
        $netbiosState += [pscustomobject]@{
            SettingID   = [string]$nic.SettingID
            Description = [string]$nic.Description
            Options     = $nbOptions
        }
    }

    $smbServer = Get-Smb1ServerStatus
    $smbClient = Get-RegDword -Path $smbClientKey -Name 'Start'

    $state = [pscustomobject]@{
        Version    = 1
        CreatedAt  = (Get-Date).ToString('o')
        Llmnr      = Get-RegDword -Path $llmnrKey -Name 'EnableMulticast'
        WpadUser   = Get-RegDword -Path $wpadUserKey -Name 'AutoDetect'
        WpadMachine = Get-RegDword -Path $wpadMachineKey -Name 'DisableWpad'
        Netbios    = $netbiosState
        Smb1Server = [pscustomobject]@{ Available = $smbServer.Available; Value = $smbServer.Enabled }
        Smb1Client = [pscustomobject]@{ Exists = $smbClient.Exists; Value = $smbClient.Value }
    }

    $json = $state | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($statePath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Step ('Estado original guardado en {0}' -f $statePath)
}

$failed = 0

Write-Step 'Desactivando LLMNR (EnableMulticast=0)...'
try {
    Set-RegDword -Path $llmnrKey -Name 'EnableMulticast' -Value 0
    Write-Host '  LLMNR deshabilitado.' -ForegroundColor Green
} catch {
    $failed++
    Write-Warning ('  LLMNR: {0}' -f $_.Exception.Message)
}

Write-Step 'Desactivando WPAD...'
try {
    Set-RegDword -Path $wpadUserKey -Name 'AutoDetect' -Value 0
    Set-RegDword -Path $wpadMachineKey -Name 'DisableWpad' -Value 1
    Write-Host '  WPAD deshabilitado (usuario actual y WinHTTP).' -ForegroundColor Green
} catch {
    $failed++
    Write-Warning ('  WPAD: {0}' -f $_.Exception.Message)
}

Write-Step 'Desactivando NetBIOS sobre TCP/IP...'
$nbChanged = 0
foreach ($nic in $nics) {
    if ($null -ne $nic.TcpipNetbiosOptions -and [int]$nic.TcpipNetbiosOptions -eq 2) { continue }
    try {
        if (Set-NetbiosOption -Adapter $nic -Option 2) {
            $nbChanged++
        } else {
            $failed++
            Write-Warning ('  {0}: no se pudo escribir NetbiosOptions.' -f $nic.Description)
        }
    } catch {
        $failed++
        Write-Warning ('  {0}: {1}' -f $nic.Description, $_.Exception.Message)
    }
}
Write-Host ('  NetBIOS deshabilitado en {0} adaptador(es).' -f $nbChanged) -ForegroundColor Green

Write-Step 'Desactivando SMBv1...'
$smbServer = Get-Smb1ServerStatus
if ($smbServer.Available) {
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Write-Host '  Servidor SMBv1 deshabilitado.' -ForegroundColor Green
    } catch {
        $failed++
        Write-Warning ('  Servidor SMBv1: {0}' -f $_.Exception.Message)
    }
} else {
    Write-Host '  Servidor SMBv1: cmdlet no disponible; se omite.' -ForegroundColor DarkGray
}

$smbClient = Get-RegDword -Path $smbClientKey -Name 'Start'
if ($smbClient.Exists) {
    try {
        Set-RegDword -Path $smbClientKey -Name 'Start' -Value 4
        Write-Host '  Cliente SMBv1 deshabilitado (Start=4).' -ForegroundColor Green
    } catch {
        $failed++
        Write-Warning ('  Cliente SMBv1: {0}' -f $_.Exception.Message)
    }
} else {
    Write-Host '  Cliente SMBv1 no instalado; no hay nada que desactivar.' -ForegroundColor DarkGray
}

Write-Host ''
if ($failed -eq 0) {
    Write-Host 'Endurecimiento aplicado. Reinicia para que NetBIOS y SMBv1 queden completamente desactivados.' -ForegroundColor Green
    Write-Host ('Revierte con: powershell -ExecutionPolicy Bypass -File {0} -Undo' -f $PSCommandPath) -ForegroundColor DarkGray
    exit 0
}

Write-Warning ('Se aplicaron los cambios posibles, pero {0} operacion(es) fallaron. Revisa los avisos.' -f $failed)
exit 4
