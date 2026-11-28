@echo off
rem ============================================================================
rem Lanzador del puente DNS-over-HTTPS sobre Tor.
rem AdGuard Home habla con 127.0.0.1:5336; el puente sale por 127.0.0.1:9050.
rem ============================================================================
setlocal

set "FORTRESS_DIR=%~dp0.."
if not exist "%FORTRESS_DIR%\scripts\doh-tor-bridge.js" set "FORTRESS_DIR=%~dp0"
if not exist "%FORTRESS_DIR%\doh-tor-bridge.js" set "FORTRESS_DIR=C:\AdGuardHome"

set "NODE_EXE=%FORTRESS_DIR%\node\node.exe"
if not exist "%NODE_EXE%" set "NODE_EXE=node"

set "BRIDGE_JS=%FORTRESS_DIR%\doh-tor-bridge.js"
if not exist "%BRIDGE_JS%" set "BRIDGE_JS=%FORTRESS_DIR%\scripts\doh-tor-bridge.js"

if not exist "%BRIDGE_JS%" (
  echo [ERROR] No se encontro doh-tor-bridge.js en %FORTRESS_DIR%
  exit /b 2
)

"%NODE_EXE%" "%BRIDGE_JS%" %*
exit /b %ERRORLEVEL%
