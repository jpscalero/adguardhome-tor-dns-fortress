# Prompt para Antigravity — Remediación integral del repositorio

Copia y pega el bloque de abajo tal cual en Antigravity (ábrelo en la carpeta raíz del repositorio `adguardhome-tor-dns-fortress`). El prompt es autosuficiente: incluye contexto, tareas priorizadas, criterios de aceptación y plan de verificación.

---

## ROL

Actúa como **ingeniero DevOps y especialista en seguridad DNS senior**, con dominio de AdGuard Home, Tor, PowerShell 5.1/7, Node.js 18+ y GitHub Actions. Tu misión es remediación integral del repositorio según la auditoría en `AUDITORIA.md` (raíz del proyecto). Trabaja con criterio de producción: cada cambio debe ser verificable, reversible y documentado.

## CONTEXTO

- Repositorio: `https://github.com/jpscalero/adguardhome-tor-dns-fortress` — fortaleza DNS local para Windows 11/10: AdGuard Home + Tor SOCKS5 + GoodbyeDPI + centinela IA (Node.js) + generador de tráfico señuelo + watchdog autorreparable.
- La auditoría completa está en `AUDITORIA.md`. Léelo entero antes de tocar nada: contiene la evidencia exacta de cada problema con líneas y pruebas de ejecución.
- Público objetivo: usuarios técnicos de Windows que ejecutan el instalador con doble propósito privacidad + anti-censura. Todo el texto de usuario va en español; el código y comentarios técnicos en inglés.

## OBJETIVOS POR PRIORIDAD

### BLOQUE 1 — Correctivos críticos (bloqueantes)

**T1. Reparar codificación de todos los `.ps1` (C1 de auditoría)**
- Convierte `scripts/install_fortress.ps1`, `scripts/watchdog.ps1` y `scripts/test_fortress.ps1` a UTF-8 **con BOM**.
- Verifica con el parser de PowerShell 5.1 que cada fichero parsea sin errores:
  ```powershell
  $t=$null; $e=$null
  [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$t, [ref]$e)
  ```
- Criterio de aceptación: cero errores de parseo en PS 5.1 y PS 7, con contenido intacto (solo cambia la codificación, no el texto).

**T2. Tor de verdad en el flujo DNS (C2)**
- En `config/AdGuardHome.template.yaml`, sustituye los upstreams DoH directos por el formato con proxy explícito de AdGuard Home (soportado desde v0.107.20):
  ```yaml
  upstream_dns:
    - '[https://dns.digitale-gesellschaft.ch/dns-query] socks5://127.0.0.1:9050'
    - '[https://doh.applied-privacy.net/query] socks5://127.0.0.1:9050'
    - '[https://base.dns.mullvad.net/dns-query] socks5://127.0.0.1:9050'
    - '[https://doh.dns.sb/dns-query] socks5://127.0.0.1:9050'
    - '[https://dns.quad9.net/dns-query] socks5://127.0.0.1:9050'
    - '[/onion/]127.0.0.1:5350'
  ```
- Mantén `http_proxy` (actualizaciones de filtros por Tor) y añade un comentario explicando la diferencia entre `http_proxy` (actualizaciones) y el proxy por-upstream (tráfico DNS).
- El bootstrap (`bootstrap_dns`) debe quedar con IPs literales (9.9.9.9, 149.112.112.112) porque el proxy SOCKS no puede resolver hostnames de bootstrap: elimina las entradas `https://` de bootstrap si las hay, o déjalas solo si AdGuard las soporta documentadamente.
- Criterio de aceptación: ningún upstream DoH sin proxy; YAML válido; comentario documental presente.

**T3. Eliminar la mutación de `ServiceDll` (C3)**
- En `scripts/install_fortress.ps1`, borra la línea que escribe `ServiceDll = ipnathlp.dll.disabled` y cualquier referencia.
- En `docs/WINDOWS_PORT_53_FIX.md`, elimina la sección "Neutralización del Driver en Segundo Plano" y añade una sección "Reversibilidad": cómo restaurar `ServiceDll` a `%SystemRoot%\System32\ipnathlp.dll` y por qué la mutación ya no se recomienda.
- Criterio de aceptación: el instalador ya no toca `ServiceDll`; la doc documenta reversión.

**T4. Watchdog seguro: lista blanca en arbitraje de puerto 53 (C4)**
- En `scripts/watchdog.ps1` (sección 2.5), antes de `Stop-Process`, comprueba el binario del proceso dueño del puerto:
  - Permitidos sin matar: `dnsched`, `svchost` (servicio `dnscache`), `wslhost`, `wslrelay`, procesos con `AdGuardHome` en el nombre.
  - Solo fuerza parada si el binario reside en `System32\ipnathlp.dll` (secuestrador conocido ICS) o si el servicio `SharedAccess` está en ejecución y el PID pertenece a su svchost.
  - En cualquier otro caso: log con PID, nombre y ruta del binario, y `continue` sin matar.
- Criterio de aceptación: ningún `Stop-Process` incondicional; decisión documentada en el log.

### BLOQUE 2 — Fiabilidad

**T5. Cliente HTTP robusto en el centinela (C5)**
- En `scripts/ai_dns_guard.js`, refactoriza `aghRequest` y `askGemini`:
  - Listener `res.on('aborted', ...)` que destruye el request.
  - `req.on('error')` y `req.on('timeout')` ya existen; asegúrate de que en todos los caminos se hace `req.destroy()` y no quedan sockets colgados.
  - Usa `http.Agent({ keepAlive: false, maxSockets: 4 })` y ciérralo en `process.on('SIGINT'/'SIGTERM')`.
- Criterio de aceptación: `node --check` OK; sin fugas de sockets evidentes; graceful shutdown.

**T6. Tor listo para rotación de circuitos (C7)**
- En `config/torrc.template`:
  - `MaxCircuitDirtiness 1800` (antes 180).
  - Añade `ControlPort 127.0.0.1:9051` con comentario de cómo generar `HashedControlPassword` (`tor --hash-password`).
  - Añade comentario por directiva explicando el "por qué" de cada valor no-default.
- En `scripts/watchdog.ps1`, añade función opcional `Invoke-TorNewNym` (SIGNAL NEWNYM por ControlPort autenticado) que solo se ejecuta si `TOR_CONTROL_PASSWORD` está definido en el entorno. Sin la variable, se salta silenciosamente.
- Criterio de aceptación: torrc con comentarios; rotación opcional funcional y documentada.

**T7. Watchdog a prueba de muertes silenciosas (M4)**
- Envuelve el cuerpo del `while` en `try/catch` que registra el error y continúa.
- Añade heartbeat: cada ciclo escribe `watchdog.heartbeat` con timestamp; si el watchdog arranca y detecta un heartbeat con más de 10 minutos de antigüedad, escribe aviso de "ciclo perdido".
- Criterio de aceptación: una excepción no mata el bucle; heartbeat funcional.

**T8. Decoy con verificación inicial y variación (M6 + M7)**
- En `scripts/decoy_dns.js`:
  - Al arrancar, comprueba que `127.0.0.1` resuelve (consulta `wikipedia.org`); si falla, reintenta con backoff exponencial (5s→10s→20s, máx 5 intentos) y luego entra en modo degradado (solo log, sin consultas) hasta que el watchdog lo relance.
  - Mezcla el pool académico con dominios populares variados: añade un segundo array `POPULAR_DOMAINS` (20-30 dominios de noticias, streaming, compras, deportes) y elige 70% del pool académico / 30% del popular, rotando semilla por hora.
- Criterio de aceptación: sin flood de errores si AGH está caído; pool diversificado.

### BLOQUE 3 — CI y repositorio

**T9. CI real y completa (M1 + M2)**
- Haz commit del workflow `.github/workflows/main.yml` existente (ahora solo está en el working tree; en `origin/main` está vacío) y amplíalo:
  - Job `bom-check`: falla si algún `scripts/*.ps1` carece de BOM (lee los 3 primeros bytes y comprueba `EF BB BF`).
  - Job `secrets-history`: paso con `gitleaks/gitleaks-action@v2` escaneando todo el historial.
  - Job `validate-code`: mantén `node --check` + parser PowerShell (añade también PS 7 vía `shell: pwsh`).
  - Job `config-integrity`: mantén validación YAML de plantillas.
- Criterio de aceptación: workflow en remoto, badge del README verde tras el push.

**T10. Metadatos de paquete (M11)**
- `package.json`: añade `"engines": { "node": ">=18" }`, script `"postinstall"` que imprima aviso de ejecutar el instalador como admin (no ejecutarlo automáticamente), y `"repository"`/`"bugs"`/`"homepage"` apuntando al repo.

**T11. Submodule wiki (M13 + M14)**
- Decisión: registra `wiki/` como submodule oficial:
  ```
  git submodule add https://github.com/jpscalero/adguardhome-tor-dns-fortress.wiki.git wiki
  ```
- Si rompe algo, alternativa aceptada: borra la copia local y documenta en `README` que el wiki vive solo en GitHub.

**T12. Documentación sin duplicación (M15 + M16 + M17)**
- Crea `CHANGELOG.md` (formato Keep a Changelog) con entradas por cada corrección de este remediado.
- En `README.md`, añade sección "⚠️ Riesgos conocidos": WinDivert/GoodbyeDPI puede disparar anticheats y EDRs corporativos; Tor ralentiza la resolución DNS (~200-800ms primera consulta); los TLDs bloqueados (`.zip`, `.mov`) pueden romper sitios legítimos muy raros.
- El diagrama Mermaid canónico queda en `docs/ARCHITECTURE.md`; el README enlaza a él en lugar de duplicarlo.

### BLOQUE 4 — Herramientas

**T13. Parametrizar tools/ (M8 + M10)**
- `tools/*.js`: sustituye `C:\AdGuardHome` hardcodeado por `process.env.FORTRESS_DIR || 'C:\\AdGuardHome'`.
- `launchers/*.vbs`: calcula la ruta del script relativa a la ubicación del propio `.vbs` (usa `WScript.ScriptFullName` + `FileSystemObject`), sin hardcodear `C:\AdGuardHome`.
- `build_master_fortress.js`: hazlo idempotente — si el fichero origen no existe, error claro; si existe, genera salida verificando que el YAML resultante parsea (usa `js-yaml` en devDependency o validación básica de indentación).
- Criterio de aceptación: ningún path hardcodeado fuera de los defaults; herramientas ejecutables desde cualquier directorio.

## RESTRICCIONES

1. **No rompas lo que funciona**: `watchdog.ps1` y `test_fortress.ps1` deben seguir parseando y ejecutando idéntico en PS 7 salvo las correcciones pedidas.
2. **No toques las listas de filtros ni `user_rules`** del template: son decisiones de producto del autor.
3. **No introduzcas dependencias npm en runtime** (el proyecto es stdlib-only a propósito). `devDependencies` permitidas solo para herramientas de build.
4. **Commits atómicos** por bloque, formato Conventional Commits en español neutro (`fix(installer): ...`, `feat(tor): ...`, `docs(audit): ...`).
5. Cada fichero modificado debe mantener estilo de comentarios y estructura existente.

## PLAN DE VERIFICACIÓN (ejecútalo al final y pega la salida en tu respuesta)

```powershell
# 1. Sintaxis PS 5.1 y PS 7
Get-ChildItem scripts/*.ps1 | ForEach-Object {
  $t=$null; $e=$null
  [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$t, [ref]$e)
  "$($_.Name): $($e.Count) errores"
}
# 2. Sintaxis JS
Get-ChildItem scripts/*.js, tools/*.js | ForEach-Object { node --check $_.FullName }
# 3. YAML válido
python3 -c "import yaml; yaml.safe_load(open('config/AdGuardHome.template.yaml'))"
# 4. BOM presente
Get-ChildItem scripts/*.ps1 | ForEach-Object {
  $b = [System.IO.File]::ReadAllBytes($_.FullName)[0..2]
  "$($_.Name): BOM=$([System.Text.Encoding]::UTF8.GetString($b) -eq [char]0xFEFF)"
}
# 5. Gitleaks local (si está instalado)
gitleaks detect --source . -v --redact
# 6. Suite del proyecto en máquina con la fortaleza desplegada
powershell -File scripts/test_fortress.ps1
```

## ENTREGABLES

1. Todos los ficheros corregidos según T1-T13.
2. `CHANGELOG.md` nuevo con cada cambio.
3. `AUDITORIA.md` actualizado: marca cada hallazgo como `[CORREGIDO]` con el commit que lo resuelve.
4. Salida completa del plan de verificación.
5. Resumen ejecutivo final: qué se corrigió, qué queda pendiente y por qué.

Empieza leyendo `AUDITORIA.md` completo, después los ficheros afectados, y ejecuta los bloques en orden (1 → 4). Si algo requiere decisión de producto (no técnica), detente y pregunta en lugar de asumir.
