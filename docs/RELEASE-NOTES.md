# Fortaleza DNS — notas de la versión

> Este fichero alimenta el cuerpo de la release (`body_path` en
> `.github/workflows/release.yml`). Se mantiene **sin número de versión**: el tag
> ya lo indica, y así una release nueva nunca hereda el número de la anterior.

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
- **Perfil Docker/Linux** en `docker/`, con AdGuard escuchando en `0.0.0.0`
  dentro del contenedor y publicado solo en `127.0.0.1` del host.

## Instalación

```powershell
# Desde una PowerShell de administrador
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1
powershell -ExecutionPolicy Bypass -File scripts\test_fortress.ps1
```

Perfil Linux:

```bash
cd docker && docker compose up -d --build
```

## Actualización desde 1.0.0

1. Copia `config/.env` (no lo pierdas).
2. Ejecuta el instalador: conserva `AdGuardHome.yaml` existente salvo `-Force`.
3. Añade `AI_MODE` a tu `.env` (por defecto `aggregate`).
4. Ejecuta `scripts\harden-env-acl.ps1`.

## Verificación del paquete

El ZIP se genera con `git archive`, así que contiene **exactamente** los ficheros
versionados (incluidos `docker/`, `.github/` y `tests/`). Comprueba su integridad:

```powershell
Get-FileHash .\fortress-<version>.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
```

## Historial de empaquetado

- **2.0.1** — el ZIP de la 2.0.0 salía incompleto (50 de 62 ficheros) porque el
  workflow copiaba carpetas con una lista manual. Ahora usa `git archive`.
- **2.0.0** — primera release con failsafe, `AI_MODE` y perfil Docker.
