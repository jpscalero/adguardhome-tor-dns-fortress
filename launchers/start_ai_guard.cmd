@echo off
rem ============================================================================
rem Lanzador del Centinela AI.
rem Resuelve rutas absolutas y el node portable, para que funcione igual cuando
rem lo arranca el usuario, el watchdog o el Programador de tareas como SYSTEM
rem (SYSTEM no tiene "node" en el PATH).
rem ============================================================================
setlocal

set "FORTRESS_DIR=%~dp0.."
if not exist "%FORTRESS_DIR%\scripts\ai_dns_guard.js" set "FORTRESS_DIR=%~dp0"
if not exist "%FORTRESS_DIR%\ai_dns_guard.js" set "FORTRESS_DIR=C:\AdGuardHome"

set "AGH_HOST=127.0.0.1"
if "%AGH_PORT%"=="" set "AGH_PORT=3000"

set "NODE_EXE=%FORTRESS_DIR%\node\node.exe"
if not exist "%NODE_EXE%" set "NODE_EXE=node"

set "GUARD_JS=%FORTRESS_DIR%\ai_dns_guard.js"
if not exist "%GUARD_JS%" set "GUARD_JS=%FORTRESS_DIR%\scripts\ai_dns_guard.js"

if not exist "%GUARD_JS%" (
  echo [ERROR] No se encontro ai_dns_guard.js en %FORTRESS_DIR%
  exit /b 2
)

"%NODE_EXE%" "%GUARD_JS%" %*
exit /b %ERRORLEVEL%
