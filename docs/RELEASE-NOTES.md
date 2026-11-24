# Fortaleza DNS 2.0.0

Consolidación de todo lo aprendido instalando y operando la fortaleza en un
equipo real. **No se elimina nada de 1.0.0**: se añaden correcciones y
endurecimiento.

## Lo más importante

- **Failsafe de red**: si AdGuard Home cae, el equipo no se queda sin Internet.
  Restaura el modo fortaleza cuando vuelve y pasa a modo emergencia cuando no.
- **`config/.env` protegido**: se elimina la herencia que permitía a aplicaciones
  empaquetadas leer la contraseña del panel y la clave de Gemini.
- **Watchdog sin bucles**: se acabaron los cientos de `wscript.exe` acumulados.
- **`AI_MODE`**: el centinela ya no manda dominios a Google por defecto; envía un
  hash con sal (`aggregate`) o nada (`off`/`local`).
- **CI real**: sintaxis, analizador, tests, invariantes de configuración, escaneo
  de secretos y lint de documentación.

## Instalación

```powershell
# Desde una PowerShell de administrador
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1
powershell -ExecutionPolicy Bypass -File scripts\test_fortress.ps1
```

## Actualización desde 1.0.0

1. Copia `config/.env` (no lo pierdas).
2. Ejecuta el instalador: conserva `AdGuardHome.yaml` existente salvo `-Force`.
3. Añade `AI_MODE` a tu `.env` (por defecto `aggregate`).
4. Ejecuta `scripts\harden-env-acl.ps1`.

## Verificación

El ZIP incluye `SHA256SUMS`. Comprueba con:

```powershell
Get-FileHash .\fortress-2.0.0.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
```
