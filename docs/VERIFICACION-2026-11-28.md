# Verificación y corrección de la fortaleza — 2026-11-28

**Versión del paquete: `2.0.4`.**

## Resultado

La suite completa terminó en **23/23 pruebas superadas** después de corregir
los fallos de ACL, heartbeat, NetBIOS y robustez de las pruebas DNS.

- **Antes:** 20/23.
- **Después:** 23/23.
- **DNS del sistema:** `127.0.0.1` (AdGuard Home).
- **Internet:** funcional a través de AdGuard/Tor; `example.com` resuelve.
- **Servicios:** AdGuard Home, Tor SOCKS5 `9050`, DNS nativo de Tor `5350`,
  puente DoH `5336` y watchdog activos.
- **Manifiesto:** 38 ficheros, regenerado y legible.
- **NetBIOS/SMBv1:** desactivados; queda pendiente un reinicio para que el
  cambio de NetBIOS quede completamente efectivo.

> **Nota importante sobre el DNS:** al inicio de esta ronda el adaptador
> Ethernet ya tenía `127.0.0.1` como DNS. Se intentó devolverlo a DHCP para
> respetar la condición de no fijar el DNS manualmente, pero el failsafe
> (`AdGuardHome_DNS_Failsafe`) lo volvió a aplicar y, además, las reglas
> `AdGuard_Block_Outbound_DNS_UDP/TCP` bloquean el puerto 53 para **cualquier**
> programa. Con DHCP el sistema se quedó sin resolución; con `127.0.0.1`
> funciona. Se conservó `127.0.0.1` para no romper Internet. No se dejó una
> configuración nueva: era el estado preexistente que el failsafe mantiene.

## Línea base

Ejecución inicial:

```text
[13] Heartbeat del watchdog reciente ... (20654s) FAILED
[21] Integridad de scripts y puertos sensibles ... Acceso denegado a
     fortress.manifest.json ... FAILED
[22] LLMNR, NetBIOS, WPAD y SMBv1 ... (pendiente: NetBIOS (1/2)) AVISO
20 de 23 pruebas superadas
```

También aparecían accesos denegados al leer `edition-hardening.report.json` y
`fortress.manifest.json` desde la cuenta de usuario.

## Causas raíz y correcciones

### 1. Heartbeat viejo (test 13)

**Causa:** el watchdog se ejecutaba como `SYSTEM`. El `permcheck` de AdGuard
Home elimina la entrada de `SYSTEM` del ACL del directorio al arrancar, por lo
que el proceso dejaba de poder escribir `watchdog.heartbeat`. Además, la tarea
`AdGuardHome_Fortress_Watchdog` estaba detenida.

**Corrección:**

- Watchdog y guardián re-registrados con la cuenta `ARCKANGEL\jpsca` con
  `LogonType = S4U` y `RunLevel = Highest`, no como `SYSTEM`.
- `watchdog.heartbeat` pasó a ser propiedad del grupo Administradores y se le
  concedió escritura a Administradores y lectura a Usuarios, manteniendo
  escritura para SYSTEM.
- Watchdog reiniciado; heartbeat verificado a 10 s y luego a 3 s en la suite final.

### 2. Acceso denegado al manifiesto y al informe (test 21)

**Causa:** los JSON de diagnóstico tenían un ACL que no incluía lectura para
`BUILTIN\Usuarios`; la suite se ejecuta sin elevación.

**Corrección:**

- `takeown /A` y `icacls` con SIDs (`*S-1-5-32-545:R`,
  `*S-1-5-32-544:F`, `*S-1-5-18:F`) sobre `fortress.manifest.json`,
  `edition-hardening.report.json`, `network-hardening.state.json` y
  `watchdog.heartbeat`.
- Manifiesto regenerado con `integrity-check.ps1 -Create`; 38 ficheros.
- El manifiesto y el informe se pueden leer sin elevación.

### 3. NetBIOS pendiente (test 22)

**Causa:** el hardening no había podido completarse porque
`network-hardening.state.json` no tenía escritura para Administradores.

**Corrección:**

- Se corrigió el ACL del estado y se ejecutó
  `harden-network-protocols.ps1 -TargetDir C:\AdGuardHome` con exit 0.
- Desactivados LLMNR, WPAD, NetBIOS sobre TCP/IP (1 adaptador) y servidor SMBv1.
- **Pendiente:** reiniciar para que NetBIOS y SMBv1 queden completamente
  efectivos; el estado del registro ya es el correcto.

### 4. Pruebas DNS frágiles (tests 4, 5, 6 y 18)

**Causa:** la suite usaba `Resolve-DnsName -QuickTimeout` y
`nslookup -port`, que no son fiables en todas las versiones de Windows y podían
dar falsos positivos o bloqueos.

**Corrección:**

- Las comprobaciones usan `Test-FortressDnsQuery` de `fortress-health.ps1`:
  consulta DNS real, timeout explícito, puerto explícito y RCODE.
- Test 5 (`.onion`) y test 6 (NXDOMAIN) usan la misma sonda.
- Test 18 usa la sonda contra el puerto 5335/5336, sin depender de `nslookup`.
- Test 17 devuelve **WARN** si el DNS está en automático: es la activación
  final pendiente, no un fallo de la fortaleza. Con `127.0.0.1` devuelve OK.
- Revisión de falsos positivos: test 1/3 rechazan bindings fuera de loopback;
  test 2 exige confirmar `IsTor` con 3 reintentos y timeout de 15 s (el primer
  circuito Tor puede tardar); test 14 exige un failsafe activo; test 16
  avisa si falta el hash; test 19 avisa si watchdog/guardián están
  deshabilitados; test 21 avisa si falta `integrity-check.ps1`.

### 5. Watchdog y guardián como SYSTEM

**Causa:** el ACL de AdGuard elimina SYSTEM; el guardián y el watchdog podían
quedar sin permisos para escribir logs/heartbeat.

**Corrección:**

- `watchdog.ps1` y `install_fortress.ps1` registran las tareas con el usuario
  actual (S4U, Highest) cuando no se ejecutan como SYSTEM.
- El guardián conserva la lógica de elevación, pero ya no fuerza SYSTEM en una
  instalación normal.
- El heartbeat se escribe al inicio de cada ciclo; el fallo de escritura no
  detiene el watchdog.

### 6. `repair-system.ps1` cambiaba el DNS sin avisar

**Causa:** el script fijaba `127.0.0.1` en todos los adaptadores IPv4 cada vez
que se ejecutaba. Fue el origen de que Ethernet siguiera en manual después de
una restauración a DHCP.

**Corrección:**

- Nuevo parámetro `-SetSystemDns`. Sin él, el script **no toca el DNS** y deja
  un mensaje en el log.
- La activación final debe ser explícita:
  `powershell -File scripts\repair-system.ps1 -SetSystemDns`.
- El instalador sigue fijando `127.0.0.1` como parte de la instalación; es el
  comportamiento esperado de la fortaleza.

### 7. El DNS automático no es viable con las reglas anti-fuga

**Evidencia:** tras `Set-DnsClientServerAddress -ResetServerAddresses`, la
interfaz quedó en `192.168.0.1` y DHCP activo, pero:

- `Resolve-DnsName example.com` agotó el tiempo de espera.
- `Resolve-DnsName example.com -Server 192.168.0.1` también agotó el tiempo.
- `Resolve-DnsName example.com -Server 9.9.9.9` también agotó el tiempo.
- `Resolve-DnsName example.com -Server 127.0.0.1` devolvió
  `104.20.23.154`.
- El log del failsafe mostró a las 17:40:
  `Ethernet: DNS 192.168.0.1 ajeno; AdGuard responde, adoptando 127.0.0.1`.

Las reglas `AdGuard_Block_Outbound_DNS_UDP` y
`AdGuard_Block_Outbound_DNS_TCP` tienen `Program = Any`, `RemoteAddress = Any`
y `RemotePort = 53`; bloquean todo DNS salvo el loopback que atiende AdGuard.
Por eso el estado funcional es `127.0.0.1`. El failsafe
`AdGuardHome_DNS_Failsafe` (distinto de `AdGuardHome_Fortress_Failsafe`, que
está desactivado) lo reaplica cada pocos minutos.

**Decisión:** no desactivar ese failsafe ni abrir el puerto 53 sin una revisión
de privacidad; hacerlo dejaría el sistema sin resolución o permitiría fugas.

### 8. Prueba DHCP controlada (17:48)

Se ejecutó `test-dhcp-mode.ps1` con restauración automática en `finally`:

- Se pausaron `AdGuardHome_DNS_Failsafe`, el guardián y el watchdog.
- Se desactivaron temporalmente `AdGuard_Block_Outbound_DNS_UDP/TCP`.
- Ethernet quedó en DHCP con DNS `192.168.0.1`.
- TCP 53 del router respondió `True`, pero las consultas DNS fueron
  **rechazadas** (`REFUSED`).
- El sistema y HTTPS fallaron; el script restauró reglas, tareas y
  `127.0.0.1` inmediatamente.
- El usuario aprobó explícitamente el estado final `127.0.0.1`.

Conclusión: el router no ofrece un DNS utilizable; DHCP no puede resolver en
esta red sin cambiar el router o permitir DNS público directo. El estado
`127.0.0.1` es el aprobado y el único funcional.

## Cambios en el repositorio

| Fichero | Cambio |
|---|---|
| `scripts/test_fortress.ps1` | Sonda DNS real en tests 4/5/6/18; tests 1/2/3/14/16/19/21 sin falsos positivos; WARN honesto en test 17 |
| `scripts/watchdog.ps1` | Guardián con usuario S4U cuando no es SYSTEM; heartbeat existente verificado |
| `scripts/install_fortress.ps1` | Copia `fortress-health.ps1`, `fortress-doctor.ps1`, `repair-system.ps1`, `dns-probe.js` y `set-adguard-upstreams.js`; watchdog con usuario S4U |
| `scripts/repair-system.ps1` | Consolidado: ACL, reglas inbound 3000/9050, tareas S4U, hardening, espera de DNS y manifiesto. `-SetSystemDns` fija `127.0.0.1`; sin el flag no toca el DNS |
| `scripts/test-dhcp-mode.ps1` | Diagnóstico DHCP con restauración automática; no forma parte del runtime normal |
| `docs/VERIFICACION-2026-11-28.md` | Este documento |
| `README.md`, `CHANGELOG.md`, `docs/TROUBLESHOOTING.md` | Referencias y diagnóstico |

Copias desplegadas en `C:\AdGuardHome`: `test_fortress.ps1`,
`fortress-health.ps1`, `watchdog.ps1` y `repair-system.ps1`. Los parches de un
solo uso se eliminaron; el diagnóstico DHCP vive solo en el repositorio y no se
copia al runtime.

## Evidencia final

```text
[1] Puerto 53 UDP ... OK
[2] Túnel Tor SOCKS5 ... (Exit IP confirmada) OK
[3] DNS nativo de Tor ... OK
[4] Resolución DNS local ... (1892ms) OK
[5] Dominios .onion ... OK
[6] Bloqueo de telemetría ... OK
[7] GoodbyeDPI ... OK
[8] Centinela AI ... OK
[9] Decoy DNS ... OK
[10] Puerto 53 / ICS ... OK
[11] config\.env restringido ... OK
[12] DoT 853 / mDNS 5353 ... OK
[13] Heartbeat ... (19s) OK
[14] Failsafe activo ... (activa: AdGuardHome_DNS_Failsafe) OK
[15] DoH del navegador ... OK
[16] Integridad del binario ... OK
[17] DNS real de Windows ... (Ethernet) OK
[18] Perfil DNS activo ... (puente DoH/Tor 127.0.0.1:5336) OK
[19] Watchdog y guardián ... OK
[20] Directorio protegido y recuperación ... OK
[21] Integridad de scripts y puertos ... OK
[22] LLMNR, NetBIOS, WPAD y SMBv1 ... OK
[23] Puente DoH/Tor ... (puente PID 15556) OK

TODAS LAS PRUEBAS SUPERADAS (23/23): FORTALEZA 100% ACTIVA
```

La suite ahora devuelve **exit 0 solo si `$passed -eq $total`**. Cualquier
`FAILED` o `WARN` produce **exit 1**, de modo que CI o un script no pueden
interpretar como éxito una suite incompleta. `repair-system.ps1` también sale
con **exit 1** si AdGuard no resuelve tras la reparación.

Comando reproducido:

```powershell
powershell -ExecutionPolicy Bypass -File C:\AdGuardHome\test_fortress.ps1
```

Salida guardada en [test-final-20261128.txt](test-final-20261128.txt) y en
`C:\AdGuardHome\data\test-final-20261128.txt`.

## Limitaciones y siguientes pasos

1. **Reiniciar Windows** para completar NetBIOS/SMBv1. La suite ya lee el
   estado correcto, pero el adaptador puede conservar NetBIOS hasta el reinicio.
2. **No ejecutar** `test-dhcp-mode.ps1` en horario de uso: desactiva
   temporalmente las reglas anti-fuga para medir el DHCP. Se auto-restaura,
   pero no es un script de producción. El DNS final se fija de forma deliberada
   con `repair-system.ps1 -SetSystemDns`.
3. **No desactivar `AdGuardHome_DNS_Failsafe`** sin un plan alternativo: es el
   que mantiene el DNS en `127.0.0.1` cuando AdGuard responde.
4. **Log de AdGuard:** `C:\AdGuardHome\AdGuardHome.log` conserva entradas
   antiguas y el servicio actual no escribe ahí; no afecta a la suite. Si se
   necesita diagnóstico del servicio, revisar la configuración `log.file`.
5. **GitHub:** publicado en la rama `main` de
   `github.com/jpscalero/adguardhome-tor-dns-fortress` con el commit de la
   versión 2.0.4. No se creó tag ni release automáticamente.

## Repositorio y publicación

- Remoto: `https://github.com/jpscalero/adguardhome-tor-dns-fortress.git`
  (`origin`, rama `main`).
- Estado: publicado en `main` con el commit de la versión 2.0.4; incluye los
  cambios previos de la fortaleza que estaban pendientes en el árbol.
- No se creó tag ni release automáticamente. La release de GitHub se genera con
  el workflow `release.yml` cuando se despacha sobre un tag existente.

## Cómo revertir

```powershell
# Revertir el hardening de red
powershell -ExecutionPolicy Bypass -File C:\AdGuardHome\harden-network-protocols.ps1 -Undo

# Volver a DHCP (solo si se acepta que el DNS automático puede no resolver)
# Diagnóstico DHCP (auto-restaura 127.0.0.1; no usar en producción)
powershell -ExecutionPolicy Bypass -File scripts\test-dhcp-mode.ps1

# Restaurar el estado de la fortaleza desde el manifiesto
powershell -ExecutionPolicy Bypass -File C:\AdGuardHome\integrity-check.ps1 -Restore -TargetDir C:\AdGuardHome
```

Antes de revertir, exporta una copia de `AdGuardHome.yaml` y de `config\.env`;
el manifiesto no sustituye una copia de seguridad de los datos.
