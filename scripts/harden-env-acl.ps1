<#
.SYNOPSIS
    Restringe los permisos de config\.env (contrasena del panel y clave de API).

.DESCRIPTION
    El fichero .env guarda ADGUARD_PASSWORD y GEMINI_API_KEY. Por defecto hereda
    la ACL de la carpeta, que suele incluir SIDs de contenedor de aplicaciones
    (S-1-15-3-...): cualquier app empaquetada podia leer la clave.

    Este script:
      1. Guarda la ACL actual en config\.env-acl-backup (rollback con -Restore).
      2. Quita la herencia.
      3. Concede solo FullControl a SYSTEM y Administradores, y Modify al usuario
         propietario (que es quien ejecuta el centinela en primer plano).
      4. Verifica el resultado y avisa si queda algun acceso generico.

    No toca el contenido del fichero.

.PARAMETER Restore
    Devuelve la ACL guardada en el respaldo.

.PARAMETER DryRun
    Muestra lo que haria sin cambiar permisos.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\harden-env-acl.ps1
#>

[CmdletBinding()]
param(
    [string]$EnvFile = '',
    [string]$BackupDir = '',
    [switch]$Restore,
    [switch]$DryRun
)

$consoleHelper = Join-Path $PSScriptRoot 'console-utf8.ps1'
if (Test-Path $consoleHelper) { . $consoleHelper }

$ErrorActionPreference = 'Continue'

$fortress = if ($env:FORTRESS_DIR) { $env:FORTRESS_DIR } else { 'C:\AdGuardHome' }
if (-not $EnvFile) { $EnvFile = Join-Path $fortress 'config\.env' }
if (-not $BackupDir) { $BackupDir = Join-Path $fortress 'config' }
$backup = Join-Path $BackupDir '.env-acl-backup'

function Show-Acl {
    param([string]$Path)
    Write-Output '  ACL actual:'
    (& icacls $Path) | ForEach-Object { Write-Output ('    ' + $_) }
}

if (-not (Test-Path $EnvFile)) {
    Write-Output ("No existe {0}. Nada que hacer." -f $EnvFile)
    exit 0
}

if ($Restore) {
    if (-not (Test-Path $backup)) {
        Write-Output ("No hay respaldo de ACL en {0}." -f $backup)
        exit 1
    }
    Write-Output ("Restaurando ACL desde {0} ..." -f $backup)
    if ($DryRun) { Write-Output '  DRY-RUN: icacls /restore'; exit 0 }
    (& icacls (Split-Path -Parent $EnvFile) /restore $backup) 2>&1 | ForEach-Object { Write-Output ('  ' + $_) }
    Show-Acl $EnvFile
    exit 0
}

Write-Output ("Fichero: {0}" -f $EnvFile)
Show-Acl $EnvFile

Write-Output 'Guardando respaldo de la ACL...'
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
(& icacls (Split-Path -Parent $EnvFile) /save $backup /t /c) 2>&1 | ForEach-Object { Write-Output ('  ' + $_) }

if ($DryRun) {
    Write-Output ''
    Write-Output 'DRY-RUN: se aplicarian estos cambios:'
    Write-Output '  icacls <env> /inheritance:r'
    Write-Output '  icacls <env> /grant *S-1-5-18:(F)          # SYSTEM'
    Write-Output '  icacls <env> /grant *S-1-5-32-544:(F)      # Administradores'
    Write-Output '  icacls <env> /grant <usuario-propietario>:(M)'
    exit 0
}

Write-Output 'Quitando herencia (elimina Usuarios / Authenticated Users / AppContainer)...'
(& icacls $EnvFile /inheritance:r) 2>&1 | ForEach-Object { Write-Output ('  ' + $_) }

Write-Output 'Concediendo acceso minimo necesario...'
(& icacls $EnvFile /grant '*S-1-5-18:(F)') 2>&1 | ForEach-Object { Write-Output ('  SYSTEM: ' + $_) }
(& icacls $EnvFile /grant '*S-1-5-32-544:(F)') 2>&1 | ForEach-Object { Write-Output ('  Administradores: ' + $_) }

$owner = (Get-Acl $EnvFile).Owner
(& icacls $EnvFile /grant ($owner + ':(M)')) 2>&1 | ForEach-Object { Write-Output ('  ' + $owner + ': ' + $_) }

Write-Output ''
Show-Acl $EnvFile

Write-Output ''
Write-Output 'Verificacion:'
$acl = Get-Acl $EnvFile
$acl.Access | ForEach-Object {
    Write-Output ('  {0,-45} {1} ({2})' -f $_.IdentityReference, $_.FileSystemRights, $_.AccessControlType)
}

$generic = $acl.Access | Where-Object {
    $_.IdentityReference -match 'Everyone|Users|Usuarios|Authenticated|Autenticados|S-1-15-3'
}
if ($generic) {
    Write-Output ''
    Write-Output 'AVISO: quedan entradas genericas:'
    $generic | ForEach-Object { Write-Output ('  ' + $_.IdentityReference) }
    exit 1
}

Write-Output ''
Write-Output 'OK: el .env solo es accesible por SYSTEM, Administradores y el propietario.'
exit 0
