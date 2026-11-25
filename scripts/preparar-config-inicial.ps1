<#
.SYNOPSIS
    Prepara el usuario del panel y config\.env para una instalacion nueva.

.DESCRIPTION
    AdGuard Home genera el hash bcrypt del administrador durante su asistente
    web inicial. Este script toma ese usuario del AdGuardHome.yaml existente,
    lo inyecta en la plantilla endurecida del repositorio y crea config\.env
    con las credenciales que usa el centinela.

    Es idempotente: si la configuracion ya esta endurecida y el .env ya existe,
    no cambia nada.

.PARAMETER TargetDir
    Carpeta de la fortaleza. Por defecto FORTRESS_DIR o C:\AdGuardHome.

.PARAMETER RepoRoot
    Raiz del repositorio descomprimido. Por defecto la carpeta padre de scripts.

.PARAMETER AiMode
    Modo del centinela para el .env: off, local, aggregate o full.
    Por defecto off (no sale ningun dato del equipo).

.PARAMETER AdminPassword
    Contrasena del panel. Si se omite, se pide de forma interactiva.
    Solo se usa para escribir ADGUARD_PASSWORD en config\.env.

.PARAMETER Force
    Sobrescribe config\.env si ya existe.

.PARAMETER SkipAcl
    No ejecuta harden-env-acl.ps1. Util para pruebas en una carpeta temporal.

.PARAMETER SkipServiceStop
    No detiene el servicio ni el proceso AdGuardHome. Solo para pruebas en una
    carpeta temporal; en una instalacion real debe omitirse.

.PARAMETER DryRun
    Muestra lo que haria sin escribir ni detener servicios.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\preparar-config-inicial.ps1
#>

[CmdletBinding()]
param(
    [string]$TargetDir = '',
    [string]$RepoRoot = '',
    [ValidateSet('off', 'local', 'aggregate', 'full')]
    [string]$AiMode = 'off',
    [string]$AdminPassword = '',
    [switch]$Force,
    [switch]$SkipAcl,
    [switch]$SkipServiceStop,
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

function Read-PasswordPlain {
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ((-not $DryRun) -and (-not $isAdmin)) {
    Write-Host '[ERROR] Ejecuta este script como Administrador.' -ForegroundColor Red
    exit 1
}

if (-not $TargetDir) {
    $TargetDir = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
}
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

$targetConfig = Join-Path $TargetDir 'AdGuardHome.yaml'
$templatePath = Join-Path $RepoRoot 'config\AdGuardHome.template.yaml'
$envExample = Join-Path $RepoRoot 'config\.env.example'
$envFile = Join-Path $TargetDir 'config\.env'

Write-Host ''
Write-Host '==========================================================' -ForegroundColor Cyan
Write-Host '   PREPARACION INICIAL - FORTALEZA DNS' -ForegroundColor Cyan
Write-Host '==========================================================' -ForegroundColor Cyan
Write-Host ''

foreach ($required in @($templatePath, $envExample)) {
    if (-not (Test-Path $required)) {
        throw ("Falta {0}. Descomprime el repositorio completo antes de ejecutar este script." -f $required)
    }
}
if (-not (Test-Path $targetConfig)) {
    throw ("No existe {0}. Primero abre AdGuard Home y completa su asistente web." -f $targetConfig)
}

function Get-UsersBlock {
    param(
        [string[]]$Lines,
        [string]$Path
    )
    $start = -1
    for ($i = 0; $i -lt $Lines.Length; $i++) {
        if ($Lines[$i] -match '^users:\s*\[\]\s*$') {
            throw ("{0} tiene 'users: []': el panel no tiene contrasena. Abre AdGuard Home, crea un administrador y vuelve a intentarlo." -f $Path)
        }
        if ($Lines[$i] -match '^users:\s*$') {
            $start = $i
            break
        }
    }
    if ($start -lt 0) {
        throw ("No se encontro la seccion 'users:' en {0}." -f $Path)
    }
    $end = $Lines.Length
    for ($j = $start + 1; $j -lt $Lines.Length; $j++) {
        if ($Lines[$j] -match '^\S') {
            $end = $j
            break
        }
    }
    $block = New-Object System.Collections.Generic.List[string]
    for ($k = $start; $k -lt $end; $k++) {
        $block.Add($Lines[$k])
    }
    while (($block.Count -gt 1) -and [string]::IsNullOrWhiteSpace($block[$block.Count - 1])) {
        $block.RemoveAt($block.Count - 1)
    }
    return ,$block.ToArray()
}

Write-Step 'Leyendo el usuario creado por AdGuard Home...'
$targetLines = [IO.File]::ReadAllLines($targetConfig)
$usersBlock = Get-UsersBlock -Lines $targetLines -Path $targetConfig

$passwordLine = $usersBlock | Where-Object { $_ -match '^\s*password:\s*\S' } | Select-Object -First 1
if (-not $passwordLine) {
    throw 'No se encontro la contrasena del panel en AdGuardHome.yaml.'
}
$adminHash = ($passwordLine -replace '^\s*password:\s*', '').Trim().Trim("'").Trim('"')
if ($adminHash -notmatch '^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$') {
    throw 'La contrasena del panel no es un hash bcrypt valido. Completa el asistente de AdGuard Home.'
}

$nameLine = $usersBlock | Where-Object { $_ -match '^\s*-\s*name:\s*\S' } | Select-Object -First 1
if (-not $nameLine) {
    throw 'No se encontro el nombre del administrador en AdGuardHome.yaml.'
}
$adminUser = ($nameLine -replace '^\s*-\s*name:\s*', '').Trim().Trim("'").Trim('"')
if (-not $adminUser) {
    $adminUser = 'admin'
}
Write-Ok ("Usuario del panel: {0}" -f $adminUser)

$targetRaw = [IO.File]::ReadAllText($targetConfig)
if ($targetRaw -match '__ADMIN_BCRYPT_PASSWORD_HASH__') {
    throw 'La configuracion actual tiene el marcador de ejemplo. Completa el asistente de AdGuard Home antes de ejecutar el instalador.'
}

$templateRaw = [IO.File]::ReadAllText($templatePath)
$targetLooksHardened = $targetRaw -match '(?m)^http_proxy:.*socks5://'
$needsMerge = ($templateRaw -match '__ADMIN_BCRYPT_PASSWORD_HASH__') -and (-not $targetLooksHardened)
if ($targetLooksHardened) {
    Write-Step 'La configuracion existente ya esta endurecida; se conserva tal cual.'
}

if ($needsMerge) {
    Write-Step 'Copiando el usuario a la configuracion endurecida...'
    $templateLines = [IO.File]::ReadAllLines($templatePath)
    $templateStart = -1
    for ($i = 0; $i -lt $templateLines.Length; $i++) {
        if ($templateLines[$i] -match '^users:\s*$') {
            $templateStart = $i
            break
        }
    }
    if ($templateStart -lt 0) {
        throw 'La plantilla no contiene una seccion users: valida.'
    }
    $templateEnd = $templateLines.Length
    for ($j = $templateStart + 1; $j -lt $templateLines.Length; $j++) {
        if ($templateLines[$j] -match '^\S') {
            $templateEnd = $j
            break
        }
    }

    $prefix = @()
    if ($templateStart -gt 0) {
        $prefix = $templateLines[0..($templateStart - 1)]
    }
    $suffix = @()
    if ($templateEnd -lt $templateLines.Length) {
        $suffix = $templateLines[$templateEnd..($templateLines.Length - 1)]
    }
    $mergedLines = @($prefix) + @($usersBlock) + @($suffix)
    $mergedText = ($mergedLines -join "`r`n") + "`r`n"

    $backupPath = ('{0}.bak-{1}' -f $targetConfig, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if ($DryRun) {
        Write-Step ('DRY-RUN: se guardaria una copia en {0}' -f $backupPath)
        Write-Step ('DRY-RUN: se escribiria la configuracion endurecida en {0}' -f $targetConfig)
    } else {
        if (-not $SkipServiceStop) {
            $aghService = Get-Service -Name 'AdGuardHome' -ErrorAction SilentlyContinue
            if ($aghService -and $aghService.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Step 'Deteniendo el servicio AdGuard Home para cambiar la configuracion...'
                Stop-Service -Name 'AdGuardHome' -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            Get-Process -Name 'AdGuardHome' -ErrorAction SilentlyContinue | ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 1
        }
        Copy-Item -Path $targetConfig -Destination $backupPath -Force
        Write-Ok ('Copia de seguridad: {0}' -f $backupPath)
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($targetConfig, $mergedText, $utf8)
        Write-Ok ('Configuracion endurecida escrita en {0}' -f $targetConfig)
    }
} else {
    Write-Step 'La configuracion ya esta endurecida; no hace falta volver a copiar el usuario.'
}

Write-Step 'Preparando config\.env...'
if ((Test-Path $envFile) -and (-not $Force)) {
    Write-Ok ('.env ya existe en {0}; se conserva.' -f $envFile)
} else {
    if (-not $AdminPassword) {
        if ($DryRun) {
            $AdminPassword = 'DRY-RUN'
        } else {
            $first = Read-PasswordPlain ("Escribe la contrasena del panel para '{0}'" -f $adminUser)
            $second = Read-PasswordPlain 'Repite la contrasena'
            if ($first -cne $second) {
                throw 'Las contrasenas no coinciden. Vuelve a ejecutar INSTALAR.cmd.'
            }
            if (-not $first) {
                throw 'La contrasena no puede estar vacia.'
            }
            $AdminPassword = $first
        }
    }

    $envLines = [IO.File]::ReadAllLines($envExample)
    $newEnvLines = foreach ($line in $envLines) {
        switch -Regex ($line) {
            '^ADGUARD_USERNAME=' { 'ADGUARD_USERNAME=' + $adminUser; break }
            '^ADGUARD_PASSWORD=' { 'ADGUARD_PASSWORD=' + $AdminPassword; break }
            '^AI_MODE='          { 'AI_MODE=' + $AiMode; break }
            default              { $line }
        }
    }

    if ($DryRun) {
        Write-Step ('DRY-RUN: se crearia {0} con AI_MODE={1}' -f $envFile, $AiMode)
    } else {
        $envDir = Split-Path -Parent $envFile
        if (-not (Test-Path $envDir)) {
            New-Item -ItemType Directory -Path $envDir -Force | Out-Null
        }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($envFile, (($newEnvLines -join "`r`n") + "`r`n"), $utf8)
        Write-Ok ('Credenciales guardadas en {0}' -f $envFile)
        if ($AiMode -in @('aggregate', 'full')) {
            Write-Warn 'AI_MODE necesita GEMINI_API_KEY. Si no la tienes, deja AI_MODE=off en config\.env.'
        }
    }
}

if ((-not $DryRun) -and (-not $SkipAcl) -and (Test-Path $envFile)) {
    $aclScript = Join-Path $RepoRoot 'scripts\harden-env-acl.ps1'
    if (Test-Path $aclScript) {
        Write-Step 'Restringiendo permisos de config\.env...'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $aclScript -EnvFile $envFile
        if ($LASTEXITCODE -ne 0) {
            Write-Warn 'No se pudieron restringir los permisos. Ejecuta scripts\harden-env-acl.ps1 como Administrador.'
        }
    }
}

Write-Host ''
Write-Host 'Preparacion inicial completada.' -ForegroundColor Green
Write-Host ('  Usuario del panel: {0}' -f $adminUser)
Write-Host ('  Configuracion:     {0}' -f $targetConfig)
Write-Host ('  Credenciales:      {0}' -f $envFile)
Write-Host ''
