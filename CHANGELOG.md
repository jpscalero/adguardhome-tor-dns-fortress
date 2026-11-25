# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/), y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Añadido

- **Instalación para principiantes (`docs/INSTALACION-FACIL.md`)**: guía paso a
  paso para quien nunca ha usado GitHub, PowerShell ni Tor, con enlaces de
  descarga, avisos de SmartScreen y solución de problemas básicos.
- **Instalador de doble clic (`INSTALAR.cmd`)**: se eleva solo, prepara el
  usuario creado en el asistente de AdGuard Home, genera `config\.env`,
  descarga Node portable si falta, aplica la configuración y arranca los
  servicios. Incluye `COMPROBAR.cmd` y `DESINSTALAR.cmd` para el día a día.
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
