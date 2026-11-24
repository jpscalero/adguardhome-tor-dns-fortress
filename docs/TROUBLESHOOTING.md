# Resolución de problemas

## Sin Internet después de instalar

1. Comprueba que AdGuard responde:

   ```powershell
   Test-NetConnection -ComputerName 127.0.0.1 -Port 53
   ```

2. Ejecuta el failsafe con traza:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\failsafe-dns.ps1 -Trace
   Get-Content C:\AdGuardHome\failsafe.log -Tail 10
   ```

3. Si el log dice `MODO EMERGENCIA`, el DNS ya está en `1.1.1.1` y las reglas
   anti-fuga están apagadas: recuperaste la red. Revisa por qué AdGuard no
   arranca (`AdGuardHome.log`).

## «Puerto 53 en uso» o AdGuard no arranca

`SharedAccess` (ICS) secuestra el puerto. El instalador lo neutraliza; si algo lo
reactiva (una actualización, el punto de acceso móvil), vuelve a ejecutar:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1
```

Aviso: con `SharedAccess` desactivado, el **punto de acceso móvil de Windows no
funciona**. El tethering USB sí.

## El DNS funciona pero los dominios `.onion` no

```powershell
Get-NetUDPEndpoint -LocalPort 5350
```

Si no hay endpoint, el `torrc` no tiene `DNSPort`. Copia `config/torrc.template` y
reinicia Tor.

## Tor conecta pero la latencia es altísima

Es esperable: cada consulta fría cruza tres saltos. Verifica que la caché de
AdGuard esté activa y que `MaxCircuitDirtiness` no sea demasiado bajo (1800 s es
el valor recomendado). Si el ISP estrangula Tor, activa bridges en el `torrc`.

## El centinela no arranca o se reinicia en bucle

El watchdog ya no lo relanza si faltan credenciales. Comprueba:

```powershell
Get-Content C:\AdGuardHome\logs\ai_guard.log -Tail 20
```

Causas típicas:

| Síntoma en el log | Causa | Solución |
|---|---|---|
| `falta ADGUARD_PASSWORD` | `.env` ausente o vacío | Crear `config/.env` desde `.env.example` |
| `AI_MODE=aggregate sin GEMINI_API_KEY` | Falta la clave | Poner la clave o `AI_MODE=off` |
| `Sin lanzador` en `watchdog.log` | No se copiaron los `.cmd` | Ejecutar el instalador de nuevo |

## Muchos procesos `wscript.exe` acumulados

Era el bug de la versión 1.0.0: el watchdog lanzaba un lanzador nuevo cada 30 s sin
comprobar si ya había uno en vuelo. La versión 2.0.0 lo evita con detección de
lanzadores en curso y enfriamiento de 5 minutos. Para limpiar los que queden:

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'wscript.exe' -and $_.CommandLine -like '*ocultar_*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

## Chrome o Edge ignoran el filtrado

Tienen su propio DoH. Aplica la política y comprueba en `chrome://policy`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\harden-browser-doh.ps1
```

## La suite dice FAILED en el check del decoy

Si el decoy lo lanzó SYSTEM, su línea de comandos no es legible sin elevación. Es
un **aviso**, no un fallo real: ejecuta la suite como administrador.

## Quiero deshacerlo todo

```powershell
powershell -ExecutionPolicy Bypass -File scripts\uninstall_fortress.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File scripts\uninstall_fortress.ps1
```

Conserva configuración, logs y respaldos salvo que añadas `-RemoveData`.
