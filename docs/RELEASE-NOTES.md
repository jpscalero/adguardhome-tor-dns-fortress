# Fortaleza DNS — notas de la versión

> Este fichero alimenta el cuerpo de la release (`body_path` en
> `.github/workflows/release.yml`). Se mantiene **sin número de versión**: el
> workflow calcula `# Fortaleza DNS <tag>` y lo antepone, así que una release
> nueva nunca hereda el número de la anterior.

Base 2.0.2 (resolutor recursivo, perfiles DNS y capa anti-manipulación) más el
parche de seguridad de protocolos locales. **No se elimina nada de 2.0.x**: el
perfil por defecto sigue siendo `speed` y la migración es opcional.

## Lo más importante

- **Resolutor recursivo propio (Unbound)**: perfil `privacy` que resuelve desde
  la raíz con DNSSEC local, sin Quad9 ni Cloudflare. Ningún tercero ve el patrón
  de consultas. Requiere descargar el ZIP oficial de Unbound y verificar su
  SHA256; el instalador no descarga binarios a ciegas.
- **Perfiles DNS conmutables**: `privacy`, `speed` y `censorship`. El bloque
  `FORTRESS-UPSTREAM` se reescribe con respaldo, validación `--check-config` y
  rollback automático.
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
- **Suite de 22 comprobaciones**.

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

Para volver al perfil DoH: `apply-dns-profile.ps1 -Profile speed -Restart`.

## Actualización desde 2.0.1 / 2.0.2

1. Copia `config/.env` (no lo pierdas).
2. Ejecuta el instalador; conserva `AdGuardHome.yaml` existente salvo `-Force`.
3. Añade `DNS_PROFILE=speed` a tu `.env` (o deja que lo escriba el perfil).
4. Ejecuta `scripts\protect-fortress.ps1` para aplicar ACL, guardián y
   manifiesto de integridad.
5. Reinicia y comprueba con la suite de 22 puntos.
6. Si actualizas desde 2.0.2, ejecuta `scripts\harden-network-protocols.ps1`
   (el instalador ya lo hace).

## Verificación del paquete

El ZIP se genera con `git archive` y el workflow lo compara con
`git ls-tree -r --name-only <tag>`: si falta o sobra un fichero, la release
falla. Comprueba su integridad:

```powershell
Get-FileHash .\fortress-<version>.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
```

## Historial de empaquetado

- **2.0.3** — parche de seguridad de protocolos locales (LLMNR, NetBIOS, WPAD
  y SMBv1) con reversión y comprobación 22 de la suite.
- **2.0.2** — release manual validada por tag, cuerpo calculado, ZIP comparado
  con el árbol versionado y deuda de la 2.0.1 cerrada (salvo borrar `v2.0.0`,
  que exige permisos del repositorio).
- **2.0.1** — el ZIP de la 2.0.0 salía incompleto (50 de 62 ficheros) porque el
  workflow copiaba carpetas con una lista manual. Ahora usa `git archive`.
- **2.0.0** — primera release con failsafe, `AI_MODE` y perfil Docker.
