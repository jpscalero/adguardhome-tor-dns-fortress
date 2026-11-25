@echo off
setlocal EnableExtensions
title Fortaleza DNS - Comprobar
cd /d "%~dp0"

fltmc filters >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ============================================================
echo    COMPROBACION DE LA FORTALEZA DNS
echo ============================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\test_fortress.ps1"
echo.
pause
