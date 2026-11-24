@echo off
rem ============================================================================
rem Lanzador del generador de trafico senuelo.
rem Igual que start_ai_guard.cmd: rutas absolutas y node portable.
rem ============================================================================
setlocal

set "FORTRESS_DIR=%~dp0.."
if not exist "%FORTRESS_DIR%\scripts\decoy_dns.js" set "FORTRESS_DIR=%~dp0"
if not exist "%FORTRESS_DIR%\decoy_dns.js" set "FORTRESS_DIR=C:\AdGuardHome"

set "NODE_EXE=%FORTRESS_DIR%\node\node.exe"
if not exist "%NODE_EXE%" set "NODE_EXE=node"

set "DECOY_JS=%FORTRESS_DIR%\decoy_dns.js"
if not exist "%DECOY_JS%" set "DECOY_JS=%FORTRESS_DIR%\scripts\decoy_dns.js"

if not exist "%DECOY_JS%" (
  echo [ERROR] No se encontro decoy_dns.js en %FORTRESS_DIR%
  exit /b 2
)

"%NODE_EXE%" "%DECOY_JS%" %*
exit /b %ERRORLEVEL%
