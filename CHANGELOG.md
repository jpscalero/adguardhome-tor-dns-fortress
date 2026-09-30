# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/), y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
