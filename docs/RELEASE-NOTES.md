# Fortaleza DNS — notas de la versión

> Este fichero alimenta el cuerpo de la release (`body_path` en
> `.github/workflows/release.yml`). Se mantiene **sin número de versión**: el
> workflow calcula `# Fortaleza DNS <tag>` y lo antepone, así que una release
> nueva nunca hereda el número de la anterior.

Base 2.0.3 (resolutor recursivo, perfiles DNS, puente DoH/Tor y protocolos
locales endurecidos) más el parche de verificación 2.0.4. **No se elimina nada
de 2.0.x**: el perfil por defecto pasa a `tor` y la migración del YAML es
automática (con respaldo).

## Parche 2.0.4 — verificación y cierre

La suite completa volvió a **23/23** en Windows 11. Se corrigieron el heartbeat
y ACL del watchdog, el acceso al manifiesto, el NetBIOS pendiente y los tests
que podían dar falsos positivos. Toda la evidencia está en
[`docs/VERIFICACION-2026-11-28.md`](VERIFICACION-2026-11-28.md).

- **DNS final:** `127.0.0.1`. Se probó DHCP con las reglas anti-fuga abiertas y
  el router `192.168.0.1` rechazó las consultas; el failsafe mantiene `127.0.0.1`
  para no romper Internet.
- **Scripts:** los parches de un solo uso se consolidaron en
  `repair-system.ps1`; `test-dhcp-mode.ps1` queda como diagnóstico con
  restauración automática.
- **Tests:** la suite devuelve exit 1 con cualquier fallo o aviso; se
  endurecieron los checks de binds externos, salida Tor, failsafe activo,
  hash y manifiesto.

## Lo más importante

- **Resolutor recursivo propio (Unbound)**: perfil `privacy` que resuelve desde
  la raíz con DNSSEC local, sin Quad9 ni Cloudflare. Ningún tercero ve el patrón
  de consultas. Requiere descargar el ZIP oficial de Unbound y verificar su
  SHA256; el instalador no descarga binarios a ciegas.
- **Puente DoH/Tor**: AdGuard Home habla con `127.0.0.1:5336`; el puente
  (`doh-tor-bridge.js`) sale por `127.0.0.1:9050` hacia Quad9 DoH. Corrige la
  fuga que producía `http_proxy`, que no cubre el DNS de dnsproxy. Sin
  fallback directo; si el puente cae, el DNS falla cerrado.
- **Perfiles DNS conmutables**: `tor` (por defecto), `speed`, `censorship` y
  `privacy`. El bloque `FORTRESS-UPSTREAM` se reescribe con respaldo,
  validación `--check-config` y rollback automático. Los YAML antiguos sin
  marcadores se migran conservando filtros, usuarios y resto de claves.
- **Capa anti-manipulación**: ACL de solo lectura, recuperación automática de
  servicios, watchdog con repetición cada 5 minutos, guardián cada 10 minutos,
  reglas entrantes para panel/SOCKS/control/DNSPort/Unbound y manifiesto SHA256
  con restauración de scripts.
- **Privacidad del navegador**: Firefox con fingerprint uniforme (zona horaria
  UTC, idioma en-US), cookies aisladas y WebRTC desactivado; Chrome/Edge sin
  cookies de terceros ni WebRTC directo. Reversible.
- **Protocolos locales endurecidos**: LLMNR, NetBIOS sobre TCP/IP, WPAD y
  SMBv1 (servidor y cliente) desactivados, con estado reversible y `-Undo`.
  Cierra el envenenamiento de nombres y el relevo NTLM en la LAN.
- **Release 2.0.2 fiable**: `workflow_dispatch` exige tag existente, hace
  checkout exacto, rechaza ramas, calcula el título y verifica que el ZIP
  contiene todos los ficheros versionados. Un job de CI repite esa comparación
  en cada push.
- **Suite de 23 comprobaciones**: incluye el puente y la ausencia de
  conexiones DNS directas de AdGuard.

## Instalación

```powershell
# Desde una PowerShell de administrador
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1
powershell -ExecutionPolicy Bypass -File scripts\test_fortress.ps1
```

Perfil recursivo (opcional, recomendado si tu prioridad es privacidad):

```powershell
# 1. Descarga el ZIP oficial de Unbound para Windows y calcula su hash
Get-FileHash .\unbound-X.Y.Z.zip -Algorithm SHA256

# 2. Despliega el resolutor (solo loopback, DNSSEC)
powershell -ExecutionPolicy Bypass -File scripts\setup-unbound.ps1 `
    -PackagePath .\unbound-X.Y.Z.zip

# 3. Activa el perfil y reinicia AdGuard
powershell -ExecutionPolicy Bypass -File scripts\apply-dns-profile.ps1 `
    -Profile privacy -Restart
```

Para volver al perfil DoH por Tor: `apply-dns-profile.ps1 -Profile tor -Restart`.

## Actualización desde 2.0.1 / 2.0.2 / 2.0.3

1. Copia `config/.env` (no lo pierdas).
2. Ejecuta el instalador; conserva `AdGuardHome.yaml` existente salvo `-Force`.
3. Añade `DNS_PROFILE=tor` a tu `.env` (o deja que lo escriba el perfil). El
   instalador migra el bloque DNS y registra el puente automáticamente.
4. Ejecuta `scripts\protect-fortress.ps1` para aplicar ACL, guardián y
   manifiesto de integridad.
5. Reinicia y comprueba con la suite de 23 puntos.
6. Si actualizas desde 2.0.2 o 2.0.3, ejecuta
   `scripts\harden-network-protocols.ps1` y `scripts\repair-system.ps1`
   (el instalador ya copia y aplica el hardening).
7. Reinicia para completar NetBIOS/SMBv1; vuelve a ejecutar la suite y exige
   exit 0 con 23/23.

## Verificación del paquete

El ZIP se genera con `git archive` y el workflow lo compara con
`git ls-tree -r --name-only <tag>`: si falta o sobra un fichero, la release
falla. Comprueba su integridad:

```powershell
Get-FileHash .\fortress-<version>.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
```

## Historial de empaquetado

- **2.0.4** — verificación integral 23/23, ACL/heartbeat, manifiesto, NetBIOS y
  tests estrictos; reparación consolidada. DNS final `127.0.0.1` aprobado tras
  comprobar que el router rechaza DHCP-DNS.
- **2.0.3** — parche de seguridad de protocolos locales (LLMNR, NetBIOS, WPAD
  y SMBv1) y puente DoH/Tor para cerrar la fuga DNS de dnsproxy, con
  comprobaciones 22 y 23 de la suite.
- **2.0.2** — release manual validada por tag, cuerpo calculado, ZIP comparado
  con el árbol versionado y deuda de la 2.0.1 cerrada (salvo borrar `v2.0.0`,
  que exige permisos del repositorio).
- **2.0.1** — el ZIP de la 2.0.0 salía incompleto (50 de 62 ficheros) porque el
  workflow copiaba carpetas con una lista manual. Ahora usa `git archive`.
- **2.0.0** — primera release con failsafe, `AI_MODE` y perfil Docker.
