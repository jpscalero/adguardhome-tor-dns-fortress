# Roadmap por versiones: 2.0.x → 3.0.0

> **Provisional.** Las versiones y su orden pueden cambiar; lo que no cambia son
> los criterios de salida: una versión se publica cuando su checklist está
> completo y verificado, no cuando llega una fecha.

Este documento planifica el trabajo **desde la última versión publicada** hasta
la 3.0.0. El `ROADMAP.md` describe las líneas de trabajo abiertas; este fichero
las ordena por versión y les pone criterios de aceptación.

## Punto de partida: 2.0.1

Ya en `main` y publicado:

- Windows: AdGuard Home + Tor (DoH por SOCKS5) + DNSSEC + GoodbyeDPI, con
  watchdog autorreparable, failsafe de red, centinela AI (`AI_MODE`) y señuelo.
- Correcciones de producción: ACL de `config/.env`, lanzadores `.cmd`/`.vbs`,
  Node portable verificado, watchdog sin bucles.
- Profesionalización: CI real (5 jobs), release con `git archive` + `SHA256SUMS`,
  plantillas de issues/PR, `NOTICE`, 12 tests unitarios, validador de config.
- Perfil Docker/Linux del núcleo DNS+Tor.

Deuda conocida al cerrar la 2.0.1:

| Tema | Detalle |
|---|---|
| Release v2.0.0 | Publicada con ZIP incompleto (50/62). Superseded por 2.0.1; pendiente de borrar. |
| Cuerpo de releases | Las dos primeras heredaron el título "2.0.0"; el fichero ya es neutro. |
| `workflow_dispatch` | El release manual usa `GITHUB_REF_NAME` = rama: generaría `fortress-main.zip`. |
| Dependabot | 4 PRs de acciones abiertos, CI en verde, sin fusionar. |

## Política de versiones

| Cambio | Versión |
|---|---|
| Corrección sin cambio de comportamiento ni de configuración | **patch** (2.0.x) |
| Funcionalidad nueva compatible (script, check, perfil opcional) | **minor** (2.x.0) |
| Cambia el formato de configuración, el contrato de los scripts o el modelo de instalación | **major** (3.0.0) |

Reglas adicionales: nada se elimina sin ruta de migración documentada; toda
funcionalidad nueva entra con su check en `scripts/test_fortress.ps1` o su test
en `tests/`.

## Resumen

| Versión | Objetivo | Criterio de salida |
|---|---|---|
| **2.0.2** | Cerrar la deuda operativa de la release | Release manual fiable, v2.0.0 retirada, notas correctas |
| **2.1.0** | Endurecimiento de red y Tor | Perfil recursivo, bridges asistidos, alertas externas |
| **2.2.0** | Observabilidad sin telemetría | Panel local y métricas, todo en loopback |
| **2.3.0** | Cobertura de pruebas real | Pester + integración en VM + instalador idempotente |
| **3.0.0** | Paridad Linux y contrato estable | Config unificada, systemd, releases firmadas y SBOM |

---

## 2.0.2 — Deuda de la release (patch)

- [x] `workflow_dispatch` con input `version` obligatorio: valida que el tag
      existe, hace `checkout` de ese tag y **rechaza** empaquetar una rama.
- [x] Cuerpo de release generado desde `docs/RELEASE-NOTES.md` + encabezado
      `# Fortaleza DNS <tag>` calculado en el workflow (no escrito a mano).
- [x] Borrar la release `v2.0.0`: **pendiente manual** con
      `gh release delete v2.0.0` (requiere permisos del repositorio).
- [ ] Fusionar o cerrar los PRs de Dependabot tras revisar el changelog de cada
      acción (requiere acceso a GitHub).
- [x] Job de CI que verifique que el ZIP de release contiene **todos** los
      ficheros versionados (`git archive` vs `unzip -Z1`).

**Hecho cuando:** un release lanzado a mano sobre `v2.0.1` produce el mismo ZIP
y el mismo checksum que el automático, y solo existe una release publicada.

## 2.1.0 — Endurecimiento de red y Tor (minor)

- [x] **Perfil recursivo con `unbound`**: resolver desde la raíz sin delegar en
      Quad9/Cloudflare. Conmutador `-Profile privacy|speed|censorship` en el
      instalador; `privacy` activa `unbound` local, `speed` mantiene DoH paralelo.
      **Adelantado a 2.0.2.**
- [x] **Endurecimiento de protocolos locales**: LLMNR, NetBIOS sobre TCP/IP,
      WPAD y SMBv1 desactivados con estado reversible y `-Undo`.
      **Adelantado a 2.0.3.**
- [ ] **Bridges asistidos**: script que detecte bloqueo de Tor (timeout de
      bootstrap) y ofrezca obfs4/snowflake con `--verify-config` antes de aplicar.
- [ ] **Rotación de upstream verificada**: antes de cambiar de resolutor, probar
      respuesta y DNSSEC; si falla, mantener el anterior.
- [ ] **Alertas externas**: notificación por `ntfy`/Telegram cuando el pipeline
      cae, Tor rota circuito o el failsafe entra en modo emergencia (opt-in, con
      URL de webhook en `.env` y sin datos de consultas).
- [ ] Reglas anti-fuga para el perfil Linux (`nftables`) equivalentes a las de
      Windows, con `-DryRun`.

**Hecho cuando:** con `PROFILE=privacy` no hay ningún resolutor de terceros en la
ruta, y una caída simulada de Tor produce una alerta en menos de 5 minutos.

## 2.2.0 — Observabilidad sin telemetría (minor)

- [ ] **Panel local estático** (`dashboard/index.html`) servido en loopback:
      latencia, hits, estado de Tor, última alerta del centinela. Sin peticiones
      externas, sin CDN, sin fuentes remotas.
- [ ] **Exportador de métricas** en formato Prometheus escrito por el watchdog
      (`data/metrics.prom`), consumible solo desde `127.0.0.1`.
- [ ] Rotación y retención configurables de `watchdog.log`, `failsafe.log`,
      `ai_guard.log` y respaldos de configuración (hoy: `.bak` acumulados).
- [ ] Comando `scripts/fortress-status.ps1` que resuma todo en una tabla para
      pegar en un issue.

**Hecho cuando:** el panel funciona con la red desconectada y no genera ninguna
conexión saliente (verificable en `Get-NetTCPConnection`).

## 2.3.0 — Cobertura de pruebas real (minor)

- [ ] **Pester** para los scripts PowerShell: failsafe (las tres ramas), ACL del
      `.env`, `-DryRun` del instalador y del desinstalador.
- [ ] **Instalador idempotente**: ejecutarlo dos veces no duplica tareas, reglas
      ni lanzadores (test automático sobre una VM limpia).
- [ ] **Integración en VM**: imagen de Windows en CI que instala la fortaleza,
      ejecuta la suite de 23 comprobaciones y publica el resultado.
- [ ] Tests del perfil Docker con `docker compose config` en CI (sin levantar
      contenedores) y validación de `AdGuardHome.yaml` con el binario real.

**Hecho cuando:** la suite de integración corre en cada PR y el instalador pasa
la prueba de doble ejecución.

## 3.0.0 — Paridad Linux y contrato estable (major)

### Configuración unificada

- [ ] Sustituir las tres plantillas (`AdGuardHome.template.yaml`,
      `torrc.template`, `docker/AdGuardHome.yaml`) por un único
      `fortress.yaml` + generador (`tools/render_config.js`) que produzca la
      configuración de cada plataforma.
- [ ] **Migrador** `tools/migrate_to_v3.ps1` que lea la configuración actual y
      genere el `fortress.yaml` equivalente, con copia de seguridad previa.
- [ ] Versionado del esquema (`schema_version` propio) y validación en CI.

### Paridad de sistema operativo

- [ ] Linux nativo sin Docker: unidades `systemd` para watchdog y failsafe,
      reglas `nftables` y comprobaciones equivalentes a la suite de Windows.
- [ ] Raspberry Pi / OpenWrt como resolutor de red completa (DHCP, VLAN de
      invitados, DNS por dispositivo).
- [ ] Documentar explícitamente qué funciones son solo de Windows y por qué.

### Cadena de suministro

- [ ] Releases **firmadas** (cosign/sigstore) además de `SHA256SUMS`.
- [ ] **SBOM** (CycloneDX) generado en el workflow y adjunto a la release.
- [ ] Verificación de integridad de binarios (`AdGuardHome.exe`, `tor.exe`) con
      hash publicado por el fabricante, no solo con el hash local.
- [ ] Script que compruebe versiones nuevas de AdGuard Home y Tor y abra un
      issue automáticamente.

### Contrato

- [ ] Interfaces estables y documentadas para los scripts (parámetros, códigos
      de salida, ficheros que escriben).
- [ ] Política de deprecación: aviso durante una minor completa antes de retirar
      cualquier opción; los `.vbs` quedan como envoltorios compatibles.
- [ ] `docs/UPGRADE-3.0.md` con la ruta desde 2.x.

**Hecho cuando:** una instalación limpia en Windows y otra en Linux producen el
mismo comportamiento verificable, las releases están firmadas y existe una guía
de actualización probada desde 2.0.x.

---

## Fuera de alcance de la 3.0.0 (y por qué)

| Idea | Motivo |
|---|---|
| Interfaz gráfica de escritorio (GUI) | Duplica el panel de AdGuard sin aportar seguridad; mantenimiento alto. |
| Bloquear QUIC/UDP 443 | Rompe YouTube y buena parte de la web moderna. |
| Doble VPN sobre Tor | Añade latencia sin mejorar el anonimato real. |
| App móvil | El objetivo es la red doméstica; el cliente no aporta privacidad. |
| Modelo de IA propio entrenado | Coste y sesgo sin mejora medible frente a heurísticas + hash. |

## Cómo se actualiza este documento

1. Cada release mueve su bloque a `CHANGELOG.md` y se marca aquí como hecho.
2. Si una tarea cambia de versión, se anota el motivo en el commit.
3. Las fechas no se prometen: se ordena por dependencias y por impacto.
