@echo off
setlocal EnableExtensions
title Fortaleza DNS - Instalacion facil
cd /d "%~dp0"

fltmc filters >nul 2>&1
if errorlevel 1 (
  echo.
  echo Se necesitan permisos de administrador.
  echo Acepta el aviso de Windows que va a aparecer.
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PS=powershell.exe -NoProfile -ExecutionPolicy Bypass"
set "TARGET=C:\AdGuardHome"

echo ============================================================
echo    FORTALEZA DNS - INSTALACION FACIL
echo ============================================================
echo.
echo Esta ventana hara todo el trabajo. No la cierres.
echo.

if not exist "%TARGET%\AdGuardHome.yaml" (
  echo [FALTA UN PASO] Todavia no existe %TARGET%\AdGuardHome.yaml
  echo.
  echo 1. Abre C:\AdGuardHome\AdGuardHome.exe con "Ejecutar como administrador".
  echo 2. En el navegador abre http://127.0.0.1:3000 y crea tu usuario.
  echo 3. Cierra la ventana negra de AdGuard Home.
  echo 4. Vuelve a hacer doble clic en INSTALAR.cmd.
  echo.
  pause
  exit /b 1
)

if not exist "%TARGET%\AdGuardHome.exe" (
  echo [FALTA UN PASO] No existe %TARGET%\AdGuardHome.exe
  echo Descomprime AdGuard Home en C:\AdGuardHome.
  echo.
  pause
  exit /b 1
)

if not exist "C:\Tor\tor.exe" (
  echo [FALTA UN PASO] No existe C:\Tor\tor.exe
  echo Descomprime el Tor Expert Bundle en C:\Tor, como explica la guia.
  echo.
  pause
  exit /b 1
)

echo [1/5] Preparando el usuario y la contrasena del panel...
%PS% -File "%~dp0scripts\preparar-config-inicial.ps1" -TargetDir "%TARGET%" -AiMode off
if errorlevel 1 goto :error

echo.
echo [2/5] Instalando Node portable (solo si falta)...
if not exist "%TARGET%\node\node.exe" (
  %PS% -File "%~dp0scripts\bootstrap-node-portable.ps1" -TargetDir "%TARGET%"
  if errorlevel 1 echo [AVISO] Node no se instalo. El centinela AI quedara en aviso; el DNS funciona igual.
) else (
  echo   Node ya esta instalado.
)

echo.
echo [3/5] Aplicando la configuracion de la fortaleza...
%PS% -File "%~dp0scripts\install_fortress.ps1" -TargetDir "%TARGET%" -SkipEnvAcl -SkipDiagnostics
if errorlevel 1 goto :error

echo.
echo [4/5] Instalando y arrancando los servicios...
%PS% -File "%~dp0scripts\instalar-servicios.ps1" -TargetDir "%TARGET%" -TorDir "C:\Tor" -GoodbyeDir "C:\GoodbyeDPI"
if errorlevel 1 goto :error

echo.
echo [5/5] Comprobacion final. La primera vez puede tardar un poco...
%PS% -File "%~dp0scripts\failsafe-dns.ps1"
schtasks /run /tn "AdGuardHome_Fortress_Watchdog" >nul 2>&1
timeout /t 12 /nobreak >nul
%PS% -File "%~dp0scripts\test_fortress.ps1"

echo.
echo ============================================================
echo    INSTALACION TERMINADA
echo ============================================================
echo.
echo Panel:  http://127.0.0.1:3000
echo Ayuda:  docs\INSTALACION-FACIL.md
echo.
echo Si algo salio en rojo, espera 2 minutos y ejecuta COMPROBAR.cmd.
echo.
start "" "http://127.0.0.1:3000"
pause
exit /b 0

:error
echo.
echo [ERROR] La instalacion se detuvo. Revisa el mensaje de arriba.
echo Consejo: vuelve a ejecutar INSTALAR.cmd; es seguro repetirlo.
echo.
pause
exit /b 1
