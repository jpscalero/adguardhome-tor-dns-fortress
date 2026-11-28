# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/), y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.4] - 2026-11-28

Verificación integral de la fortaleza en Windows 11 y corrección de los fallos
que impedían el 23/23.

### Añadido

- **Verificación documentada (`docs/VERIFICACION-2026-11-28.md`)**: línea base
  20/23, causas raíz, cambios, evidencia final 23/23 y límites conocidos.
- **Sonda DNS robusta en la suite**: los tests 4, 5, 6 y 18 usan
  `Test-FortressDnsQuery` con timeout, puerto y RCODE explícitos, en lugar de
  `Resolve-DnsName -QuickTimeout`/`nslookup -port`.
- **Reparación consolidada (`repair-system.ps1`)**: ACL, reglas inbound
  3000/9050, tareas S4U, hardening, espera activa del DNS y manifiesto.
- **Diagnóstico DHCP (`test-dhcp-mode.ps1`)**: mide DHCP con las reglas
  temporalmente desactivadas y restaura siempre `127.0.0.1`.
- **Tests endurecidos**: test 1/3 rechazan bindings fuera de loopback; test 2
  exige confirmar `IsTor`; test 14 exige un failsafe activo; test 16 avisa si
  falta el hash; test 19 avisa si watchdog/guardián están deshabilitados; test
  21 avisa si falta `integrity-check.ps1`. La suite devuelve exit 1 con
  cualquier FAILED/WARN; `repair-system.ps1` devuelve exit 1 si el DNS no queda
  listo.

### Cambiado

- **Watchdog y guardián** se registran con el usuario actual en S4U/Highest, no
  como SYSTEM, porque el `permcheck` de AdGuard elimina SYSTEM del ACL.
- **`repair-system.ps1`** solo cambia el DNS del sistema con `-SetSystemDns`;
  antes lo fijaba en `127.0.0.1` en cada ejecución.
- **Instalador** copia `fortress-health.ps1`, `fortress-doctor.ps1`,
  `dns-probe.js` y `set-adguard-upstreams.js`, y registra el watchdog con la
  cuenta actual.
- **Test 17** devuelve WARN si el DNS está en automático: es la activación
  final pendiente, no un fallo de la fortaleza.

### Corregido

- **Heartbeat viejo (test 13)**: ACL de `watchdog.heartbeat` y tarea del
  watchdog activa; heartbeat fresco en 10-22 s.
- **Acceso denegado a `fortress.manifest.json` y
  `edition-hardening.report.json` (test 21)**: ACL de lectura para Usuarios y
  manifiesto regenerado (38 ficheros).
- **NetBIOS pendiente (test 22)**: `network-hardening.state.json` con escritura
  para Administradores; `harden-network-protocols.ps1` exit 0. Requiere
  reinicio para efectividad total.

### Notas

- El DNS automático (DHCP) no resuelve mientras estén activas las reglas
  `AdGuard_Block_Outbound_DNS_UDP/TCP` (Program=Any, RemotePort=53); el estado
  funcional es `127.0.0.1` y `AdGuardHome_DNS_Failsafe` lo mantiene. No se debe
  desactivar sin un plan alternativo.
- La prueba DHCP controlada confirmó que el router `192.168.0.1` rechaza las
  consultas DNS incluso con el firewall abierto; el usuario aprobó el estado
  final `127.0.0.1`.
- **Versión del paquete**: `2.0.4`.
- Suite final: **23/23**. Publicado en la rama `main` de
  `github.com/jpscalero/adguardhome-tor-dns-fortress` con el commit de la
  versión 2.0.4. No se creó tag ni release automáticamente.

## [2.0.3] - 2026-11-26

Parche de seguridad: cierra el descubrimiento de nombres y SMBv1, las vias
clasicas de envenenamiento y relevo de credenciales en redes locales.

### Añadido

- **Endurecimiento de protocolos locales
  (`scripts/harden-network-protocols.ps1`)**: desactiva LLMNR
  (`EnableMulticast=0`), NetBIOS sobre TCP/IP en todos los adaptadores
  (`NetbiosOptions=2`), WPAD (`AutoDetect=0` y `DisableWpad=1`) y SMBv1
  (servidor y cliente `mrxsmb10`). Guarda el estado original en
  `network-hardening.state.json` y se revierte con `-Undo`; `-DryRun` muestra
  el estado sin tocar nada.
- **Instalación para principiantes (`docs/INSTALACION-FACIL.md`)**: guía paso a
  paso para quien nunca ha usado GitHub, PowerShell ni Tor, con enlaces de
  descarga, avisos de SmartScreen y solución de problemas básicos.
- **Instalador de doble clic (`INSTALAR.cmd`)**: se eleva solo, prepara el
  usuario creado en el asistente de AdGuard Home, genera `config\.env`,
  descarga Node portable si falta, aplica la configuración y arranca los
  servicios. Incluye `COMPROBAR.cmd` y `DESINSTALAR.cmd` para el día a día.
- **Comprobación 22 de la suite**: verifica LLMNR, WPAD, NetBIOS y SMBv1.
- **Puente DoH-over-Tor (`scripts/doh-tor-bridge.js`)**: escucha DNS en
  `127.0.0.1:5336` (UDP/TCP) y lo envía a Quad9 por DoH a través de
  `127.0.0.1:9050`, validando el certificado TLS y reenviando el bit DO.
  AdGuard Home ya no abre conexiones DNS directas a Internet.
- **Comprobación 23 de la suite**: verifica el puente, sus listeners y que
  AdGuard no tenga conexiones establecidas directas a 53/443/853.

### Cambiado

- **Instalador**: nuevo modificador `-SkipNetworkHardening`; el endurecimiento
  de red se aplica después de la privacidad del navegador. El perfil DNS por
  defecto pasa a `tor` y registra la tarea `AdGuardHome_Fortress_DoHBridge`
  con repetición cada 5 minutos. `-SkipUnbound` ya solo omite Unbound, no el
  perfil DNS.
- **Desinstalador**: revierte el endurecimiento de red y borra su estado con
  `-RemoveData`.
- **Suite de pruebas**: pasa de 21 a 23 comprobaciones (22 red local, 23
  puente DoH/Tor y fugas directas).
- **Versión del paquete**: `2.0.3`.

### Corregido

- **Fuga DNS por `http_proxy`**: AdGuard Home solo aplica `http_proxy` a su
  cliente HTTP. `dnsproxy` no admite `socks5://` en upstreams, así que los
  DoH salían directos a Quad9/Cloudflare. Ahora los perfiles `tor`, `speed` y
  `censorship` apuntan al puente local `127.0.0.1:5336`; el puente es el único
  que habla con `127.0.0.1:9050`. Sin fallback directo: si el puente cae, el
  DNS falla cerrado. DNSSEC se sigue validando en Quad9 y `.onion` en 5350.
- **Bug `Resolve-DnsName -Port`**: PowerShell 5.1 no tiene ese parámetro. Las
  comprobaciones de Unbound (`setup-unbound.ps1`) y de la suite ahora usan
  `nslookup -port=...`, que además distingue la respuesta real del servidor.

### Notas de migración

- La primera ejecución sobre un `AdGuardHome.yaml` anterior migra el bloque
  DNS: conserva filtros, usuarios y resto de claves, crea respaldo y valida con
  `--check-config`. Si el puente no escucha en 5336, el perfil no se aplica.
- NetBIOS y SMBv1 pueden requerir reinicio para que el cambio sea completo.
  Desactivar SMBv1 rompe equipos muy antiguos (Windows XP/2003 y algunos NAS):
  usa `harden-network-protocols.ps1 -Undo` para volver atrás.

## [2.0.2] - 2026-11-25

Cierre de la deuda operativa de la 2.0.1 y salto de la Fase 5: la fortaleza ya
no depende de un resolutor de terceros y resiste mejor la manipulacion local.

### Añadido

- **Resolutor recursivo propio (`config/unbound.conf.template`,
  `scripts/setup-unbound.ps1`)**: Unbound escucha solo en `127.0.0.1:5335`,
  resuelve desde la raiz, valida DNSSEC con ancla de confianza RFC 5011 y no
  escribe log de consultas. El instalador verifica el SHA256 del ZIP oficial y
  registra servicio o tarea; `-Undo` lo retira.
- **Perfiles DNS (`scripts/apply-dns-profile.ps1`)**: `privacy` (recursivo
  propio), `speed` (DoH en paralelo sobre Tor) y `censorship` (DoH con timeouts
  amplios para redes hostiles). Reescribe solo el bloque `FORTRESS-UPSTREAM`,
  crea respaldo, valida con `--check-config` y revierte si falla. Nuevo
  `DNS_PROFILE` en `config/.env`.
- **Capa anti-manipulacion (`scripts/protect-fortress.ps1`)**: ACL de solo
  lectura para Usuarios en scripts/lanzadores y acceso exclusivo de
  SYSTEM/Administradores a `config`, `data` y `logs`; recuperacion automatica de
  AdGuardHome, tor, GoodbyeDPI y unbound; watchdog con repeticion cada 5 minutos;
  reglas de firewall entrantes para 3000, 9050, 9051, 5350 y 5335.
- **Guardian del watchdog (`scripts/watchdog-guard.ps1`)**: cada 10 minutos
  comprueba heartbeat, recrea la tarea del watchdog si desaparece, arranca
  servicios, reactiva reglas anti-fuga y restaura scripts alterados.
- **Integridad SHA256 (`scripts/integrity-check.ps1`)**: manifiesto y copia base
  de scripts y binario; `-Create`, `-Verify` y `-Restore`. La suite falla si un
  hash cambio.
- **Privacidad del navegador (`scripts/harden-browser-privacy.ps1`)**: Firefox
  con `privacy.resistFingerprinting` (zona horaria UTC, idioma en-US),
  aislamiento de cookies y WebRTC desactivado; Chrome/Edge sin cookies de
  terceros, sin WebRTC directo y con DoH apagado. Reversible con `-Undo`.
- **Suite de 21 comprobaciones**: perfil recursivo, tareas reforzadas, ACL y
  recuperacion de servicios, integridad y reglas entrantes.
- **CI de paquete**: job que compara `git archive` con `git ls-files` para que
  nunca vuelva a publicarse un ZIP incompleto.

### Cambiado

- **Release (`release.yml`)**: `workflow_dispatch` exige un tag `vX.Y.Z`
  existente, hace checkout exacto, rechaza ramas, calcula el titulo
  `# Fortaleza DNS <tag>` y verifica el contenido del ZIP antes de publicar.
- **Instalador**: nuevos modificadores `-Profile`, `-SkipUnbound`,
  `-SkipProtection` y `-SkipBrowserPrivacy`; el watchdog se registra con
  repeticion y el guardian se anade al despliegue.
- **Desinstalador**: revierte proteccion, privacidad del navegador y Unbound, y
  elimina las reglas entrantes nuevas.
- **Version del paquete**: `2.0.2`.

### Corregido

- **Deuda de la release 2.0.1**: el release manual ya no puede empaquetar la
  rama `main` ni heredar el titulo de la version anterior; el cuerpo se genera
  desde `docs/RELEASE-NOTES.md` con el tag real.

### Notas de migracion

- Nada se elimina. El perfil por defecto sigue siendo `speed`; para pasar a
  recursivo: `scripts\setup-unbound.ps1 -PackagePath <zip>` y despues
  `scripts\apply-dns-profile.ps1 -Profile privacy -Restart`.
- La release `v2.0.0` debe borrarse a mano en GitHub (`gh release delete v2.0.0`);
  requiere permisos del repositorio y no se automatiza desde el workflow.


- **Preparación de credenciales (`scripts/preparar-config-inicial.ps1`)**: toma
  el hash bcrypt que crea el asistente de AdGuard Home y lo inyecta en la
  plantilla endurecida, sin pedir al usuario que edite YAML ni genere hashes.
- **Servicios automáticos (`scripts/instalar-servicios.ps1`)**: registra y
  arranca AdGuard Home, Tor y, si está disponible, GoodbyeDPI. Si GoodbyeDPI
  falta, avisa y continúa.
- **Perfiles por edición de Windows (`scripts/windows-edition.ps1`)**: detecta
  Home, Pro, Pro for Workstations, Pro Education, Education, Enterprise, LTSC,
  IoT y Server; asigna un tier y decide qué módulos de hardening se aplican.
- **Hardening por edición (`scripts/apply-edition-hardening.ps1`)**: aplica
  registro de firewall, registro DNS Client y auditoría de Defender (ASR/NP/CFA)
  en Pro o superior; comprueba AppLocker, App Control, Credential Guard,
  BitLocker, Hyper-V/Sandbox y Application Guard sin activarlos; genera
  `edition-hardening.report.json` y guarda el estado reversible en
  `edition-hardening.state.json`. Admite `-DryRun`, `-Undo` y `-Edition`.
- **Documentación de ediciones (`docs/EDICIONES-WINDOWS.md`)**: matriz completa
  por edición, explicación de Ethernet y casos especiales (IPv6-only, portales
  cautivos, VPN, adaptadores virtuales).

### Cambiado

- **`install_fortress.ps1`**: nuevos modificadores `-EditionProfile` y
  `-SkipEditionHardening`; el instalador muestra el perfil detectado, copia los
  scripts de edición y aplica el hardening correspondiente después del DoH de
  los navegadores.
- **`install_fortress.ps1`**: nuevo modificador `-SkipDiagnostics` para que el
  instalador fácil ejecute la comprobación final después de arrancar los
  servicios, en lugar de antes.
- **Suite de diagnóstico (`scripts/test_fortress.ps1`)**: muestra el perfil de
  Windows y el resumen del hardening de edición sin alterar las comprobaciones
  existentes; añade la comprobación 17, que verifica que el DNS IPv4 real de
  Windows apunta a `127.0.0.1` en los adaptadores físicos activos.
- **Desinstalador (`scripts/uninstall_fortress.ps1`)**: revierte el hardening de
  edición con `apply-edition-hardening.ps1 -Undo` antes de eliminar datos.

### Corregido

- **Fuga de módulos al forzar un perfil de edición**: `-Edition Enterprise` en
  un equipo Pro activaba el informe Enterprise, y en Home podía activar el
  registro de firewall, el registro DNS Client y ese mismo informe, porque esos
  módulos declaraban `Available = $true` y solo miraban el tier solicitado.
  Ahora la edición real recorta siempre el perfil pedido (`Tier` nunca supera
  `DetectedTier`) y cada módulo comprueba además el tier detectado, así que un
  equipo Home no ejecuta nada de Pro, Pro nada de Education y ninguno de los
  dos el informe Enterprise. El perfil forzado por encima de la edición se
  muestra como `(forzado, limitado a …)` con un aviso visible.
- **Acentos y símbolos corruptos en la consola**: Windows PowerShell 5.1
  escribía con la página de códigos OEM y la suite mostraba `T?nel`,
  `Resoluci?n` y `???` en el encabezado. El nuevo helper
  `scripts/console-utf8.ps1` fija la salida UTF-8 del proceso y se carga desde
  todos los scripts, así que `COMPROBAR.cmd` y las ejecuciones directas ya
  muestran acentos y el escudo correctamente, sin tocar la configuración del
  sistema.
- **Comprobación de administrador en los `.cmd`**: se usa `fltmc filters` en
  lugar de `net session`, que no es fiable en Windows Home.
- **BOM UTF-8 en los scripts PowerShell**: se añadió la cabecera a los cinco
  scripts que no la tenían y el CI ahora la verifica en cada ejecución.
- **DoH de Firefox (`harden-browser-doh.ps1`)**: el `policies.json` se escribe
  sin BOM, se conserva una copia `.fortress-bak` antes de modificarlo y `-Undo`
  restaura esa copia o elimina solo `DNSOverHTTPS`, sin borrar otras políticas.
- **Servicios (`instalar-servicios.ps1`)**: AdGuard Home se instala desde su
  propia carpeta y el script ya no falla si Tor, AdGuard o GoodbyeDPI estaban
  arrancados; se puede repetir con seguridad.
- **Documentación**: la salida de ejemplo del README refleja las 16
  comprobaciones reales, la descripción de resolutores coincide con la
  plantilla y el aviso del decoy se documenta como `AVISO`, no como `FAILED`.

## [2.0.1] - 2026-11-24

### Corregido

- **Paquete de la release incompleto**: el workflow copiaba carpetas con una
  lista manual y el ZIP de la 2.0.0 salia sin `docker/` ni `.github/`
  (50 entradas de 62). Ahora se usa `git archive`, que empaqueta exactamente los
  ficheros versionados y no puede olvidarse de nada.

## [2.0.0] - 2026-11-24

Consolidación de las correcciones probadas en producción y de las mejoras de
privacidad pendientes. Nada se elimina: todo lo de 1.0.0 sigue funcionando.

### Añadido

- **Failsafe de red (`scripts/failsafe-dns.ps1`)**: comprobación cada dos minutos
  con sonda TCP al puerto 53. Restaura `127.0.0.1` y las reglas anti-fuga si
  AdGuard responde, y pasa a modo emergencia (DNS público y reglas off) si no.
  Nunca pisa un DNS ajeno a la fortaleza y soporta `-DryRun`, `-Trace` y `-Restore`.
- **Endurecimiento de secretos (`scripts/harden-env-acl.ps1`)**: quita la herencia
  de `config/.env`, deja solo SYSTEM, Administradores y el propietario, y guarda
  la ACL original para revertir con `-Restore`.
- **Node portable verificado (`scripts/bootstrap-node-portable.ps1`)**: descarga
  el ZIP oficial, comprueba SHA256 contra `SHASUMS256.txt` y lo deja en
  `<fortress>\node` sin tocar el registro (evita el error 1603 del MSI).
- **Lanzadores robustos**: `launchers/start_ai_guard.cmd`, `start_decoy.cmd`,
  `ocultar_guardia.vbs` y `ocultar_decoy.vbs` resuelven rutas y `node.exe`
  portable, también cuando el watchdog los ejecuta como SYSTEM.
- **DoH del navegador desactivado (`scripts/harden-browser-doh.ps1`)**: políticas
  de Chrome, Edge y Firefox para que no se salten AdGuard Home, con `-Undo`.
- **`AI_MODE` en el centinela**: `off`, `local` (Ollama), `aggregate` (hash con
  sal, por defecto) y `full`. En `aggregate` el dominio nunca sale del equipo.
- **Reglas anti-fuga ampliadas**: bloqueo saliente de 853/TCP (DoT) y 5353/UDP
  (mDNS), además de 53/UDP y 53/TCP.
- **Suite de 16 comprobaciones**: ACL del `.env`, reglas 853/mDNS, frescura del
  heartbeat, tarea del failsafe, políticas de DoH e integridad del binario.
- **Desinstalador (`scripts/uninstall_fortress.ps1`)**: deshace tareas, reglas,
  DNS, políticas y ACL, con `-DryRun` y `-RemoveData` opcional.
- **Tests unitarios sin red (`tests/*.test.js`)**: entropía, apex, beaconing,
  redacción y heurística local con `node --test`.
- **CI real**: workflow de PowerShell (sintaxis + PSScriptAnalyzer), Node
  (sintaxis + tests), invariantes de configuración, gitleaks, actionlint y
  markdownlint. Release automática por tag con `SHA256SUMS`.
- **Plantillas**: issues de bug y de mejora, plantilla de PR, `CODEOWNERS`,
  `dependabot.yml`, `NOTICE` de terceros y `docs/LIMITS.md`.
- **Perfil Docker/Linux** en `docker/` (AdGuard Home + Tor) y `docs/LINUX.md`.

### Cambiado

- **Watchdog sin bucles de relanzamiento**: comprueba credenciales y `AI_MODE`
  antes de arrancar el centinela, detecta lanzadores en vuelo y aplica un
  enfriamiento de 5 minutos. Elimina la fuga de procesos `wscript` observada en
  producción (188 procesos).
- **`install_fortress.ps1`**: `-DryRun`, `-SkipEnvAcl`, `-SkipBrowserDoh`, copia
  de los scripts nuevos, registro de la tarea del failsafe y ACL del `.env` al
  final de la instalación.
- **`torrc.template`**: `IsolateSOCKSAuth` en el `SocksPort` y `ClientUseIPv6 0`
  para evitar timeouts silenciosos de circuito.
- **Suite**: de 10 a 16 comprobaciones y cabecera actualizada.

### Corregido

- **Fuga de lectura de secretos**: la ACL heredada de `config/.env` incluía un
  SID de contenedor de aplicaciones (`S-1-15-3-...`) y permitía leer la clave de
  Gemini y la contraseña del panel a aplicaciones empaquetadas.
- **Centinela sin credenciales**: ya no se relanza en bucle infinito; avisa una
  vez y espera cinco minutos.
- **`AI_MODE=aggregate` sin clave**: cae a la heurística local en lugar de
  fallar.

## [1.0.0] - 2026-09-30

### Añadido
- **Túnel Tor SOCKS5 por Upstream (`AdGuardHome.template.yaml`)**: Enrutamiento estricto de todas las peticiones DNS upstream hacia el proxy SOCKS5 local de Tor (`[https://...] socks5://127.0.0.1:9050`), garantizando que los resolutores DoH nunca observen la dirección IP de origen real.
- **Suite de Diagnóstico Ampliada a 10 Pruebas (`scripts/test_fortress.ps1`)**: Verificación automatizada de puerto 53 UDP, proxy SOCKS5 Tor (9050), DNS nativo de Tor (5350), resolución local, mapeo de IPs virtuales `.onion`, bloqueo de telemetría/DGA, driver GoodbyeDPI, centinela IA, generador decoy y estado de SharedAccess.
- **Heartbeat y Resiliencia en Watchdog (`scripts/watchdog.ps1`)**: Bucle central protegido contra excepciones no controladas con archivo `watchdog.heartbeat` para auditar ciclos perdidos y soporte de rotación de circuitos Tor (`SIGNAL NEWNYM` en puerto 9051 vía `TOR_CONTROL_PASSWORD`).
- **Verificación Inicial y Pool Mixto en Señuelos (`scripts/decoy_dns.js`)**: Comprobación inicial de conectividad contra `127.0.0.1` con retroceso exponencial (backoff) y diversificación de tráfico con un pool mixto (70% académico / 30% tráfico web popular) para mitigar el fingerprinting.
- **Políticas del Repositorio**: Adición de `SECURITY.md` con procedimiento de divulgación responsable y `CONTRIBUTING.md` con estándares de codificación UTF-8 con BOM y TypeScript/JavaScript stdlib.
- **Documentación de Reversibilidad**: Nueva sección en `docs/WINDOWS_PORT_53_FIX.md` que detalla los pasos para restaurar la configuración original de Windows y el servicio `SharedAccess`.

### Cambiado
- **Parametrización Portable (`tools/*.js` y `launchers/*.vbs`)**: Sustitución de rutas hardcodeadas `C:\AdGuardHome` por `process.env.FORTRESS_DIR || 'C:\\AdGuardHome'` y resolución dinámica de rutas mediante `FileSystemObject` en todos los lanzadores silenciosos VBScript.
- **Optimización de Tor (`config/torrc.template`)**: Ajuste de `MaxCircuitDirtiness 1800` (30 minutos para evitar churn excesivo de circuitos), habilitación de `ControlPort 127.0.0.1:9051`, instrucciones de cifrado `HashedControlPassword`, configuración de bridges anti-censura (`UseBridges`) y documentación de todas las directivas.
- **Metadatos de Paquete (`package.json`)**: Definición de `"engines": { "node": ">=18" }`, scripts de comprobación, aviso informativo en `postinstall`, enlaces a repositorio, bugs y homepage.
- **Arbitraje Seguro de Puerto 53 (`scripts/watchdog.ps1`)**: Lista blanca de procesos autorizados (`dnscache`, `svchost`, `wslhost`, `wslrelay`, `AdGuardHome`) para evitar terminaciones accidentales de servicios esenciales del sistema operativo.
- **Cliente HTTP Robusto (`scripts/ai_dns_guard.js`)**: Agentes HTTP/HTTPS dedicados (`keepAlive: false`, `maxSockets: 4`), destrucción forzosa de sockets ante abortos de conexión o timeouts, y captura de señales `SIGINT`/`SIGTERM` para apagado ordenado.

### Corregido
- **Codificación UTF-8 con BOM en Scripts PowerShell**: Conversión de `install_fortress.ps1`, `watchdog.ps1` y `test_fortress.ps1` al formato UTF-8 con BOM (`0xEF, 0xBB, 0xBF`), resolviendo el error sintáctico bloqueante en Windows PowerShell 5.1.
- **Eliminación de la Mutación Destructiva de `ServiceDll`**: Eliminada la modificación de `ServiceDll = ipnathlp.dll.disabled` en el instalador, adoptando la solución limpia basada en `IcsDnsEnabled=0` y eliminación de triggers sin degradar componentes del sistema.
- **Procesamiento de `.env`**: Mejora en el parser de expresiones regulares de variables de entorno para omitir comentarios y limpiar comillas en valores.
