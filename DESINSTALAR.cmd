@echo off
setlocal EnableExtensions
title Fortaleza DNS - Desinstalar
cd /d "%~dp0"

fltmc filters >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ============================================================
echo    DESINSTALAR LA FORTALEZA DNS
echo ============================================================
echo.
echo Esto deshace los cambios de este repositorio:
echo   - tareas programadas
echo   - reglas de firewall
echo   - DNS de los adaptadores
echo   - politicas de DoH de los navegadores
echo.
echo NO desinstala AdGuard Home, Tor ni GoodbyeDPI.
echo Tus datos y logs se conservan salvo que uses -RemoveData.
echo.
pause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\uninstall_fortress.ps1" %*
echo.
pause
