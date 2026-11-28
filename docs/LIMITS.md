# Qué NO protege esta fortaleza

Documento de honestidad técnica. Si algo de aquí te sorprende, el README te ha
vendido más de lo que el software puede dar. Cada límite incluye la mitigación
disponible hoy en el repositorio.

## 1. El destino final sigue viéndote

Tor oculta tu IP al resolutor y a los nodos intermedios, pero **el sitio web al
que te conectas te identifica igual**: sesión iniciada, cookies, fingerprint del
navegador, zona horaria, idioma. Si entras en tu correo con Tor, el correo sabe
quién eres.

- Mitigación: `scripts/harden-browser-privacy.ps1` activa
  `privacy.resistFingerprinting` en Firefox (fingerprint uniforme, zona horaria
  UTC e idioma en-US), aísla cookies y desactiva WebRTC; Chrome/Edge bloquean
  cookies de terceros. Aun así, **una sesión iniciada te identifica**: usa un
  perfil sin cuentas para navegar y otro distinto para el correo.

## 2. El resolutor DoH ve tus consultas

El perfil por defecto `tor` envía el DNS a **Quad9** por DoH a través del
puente local y de Tor. Quad9 no ve tu IP real, pero sí el dominio consultado y
puede correlacionar patrones entre sesiones. El puente no resuelve nombres
fuera de Tor ni usa fallback directo: si cae, el DNS falla cerrado.

- Mitigación: perfil `privacy` con **Unbound recursivo propio**
  (`scripts/setup-unbound.ps1` + `scripts/apply-dns-profile.ps1`), que resuelve
  desde la raíz con DNSSEC local y no delega en nadie. También `.onion` por
  `DNSPort` (sin terceros).
- Coste del perfil recursivo: más latencia en caché fría y dependencia de que
  el puerto 53 saliente funcione. El perfil `tor` sigue disponible.

## 3. El centinela AI envía dominios a Google (modo `full`)

`ai_dns_guard.js` consulta la API de Gemini para confirmar si un dominio es
malicioso. En modo `full` **el dominio sospechoso sale del equipo**. Es el
compromiso más grande del diseño y por eso existe `AI_MODE`:

| Modo | Qué se envía | Cuándo usarlo |
|---|---|---|
| `off` | Nada | Máxima privacidad; solo heurísticas locales |
| `aggregate` (por defecto) | Hash con sal del apex, entropía y estadísticas de beacon | Uso diario |
| `local` | Nada; decide un modelo local en `127.0.0.1:11434` (Ollama) | Quien tenga GPU/RAM |
| `full` | Dominio completo | Depuración o máxima detección |

- Consecuencia práctica: en `aggregate` el modelo no puede ver el dominio, así
  que la tasa de acierto baja. Se compensa con reglas locales.

## 4. DNSSEC depende del upstream

`enable_dnssec: true` hace que AdGuard Home marque como fallidas las respuestas
sin validación válida, pero **la validación la hace el resolutor de arriba**. En
el perfil `tor` valida Quad9; el puente solo reenvía el bit DO y las respuestas
sin tocarlas. Si el upstream no valida (o valida mal), tú no lo notas.
Comprobación incluida: `dnssec-failed.org` debe ser rechazado.

## 5. Fugas que la fortaleza no controla

- **DoH propio del navegador**: Chrome, Edge y Firefox pueden activar su propio
  DoH y saltarse AdGuard. Mitigación en `scripts/harden-browser-doh.ps1`.
- **Aplicaciones con DNS embebido**: algunos clientes (juegos, VPN comerciales,
  cierto software de seguridad) resuelven por su cuenta. Las reglas de firewall
  bloquean 53/UDP, 53/TCP, 853 y mDNS, pero no el DoH por 443.
- **IPv6**: con `aaaa_disabled: true` se evitan filtraciones por AAAA, a costa de
  romper servicios IPv6-only. Documentado en `docs/TROUBLESHOOTING.md`.

## 6. Latencia y anonimato se pelean

Cada consulta fría cruza tres saltos de Tor antes de llegar al DoH. Medido en
equipo real: 200-500 ms en frío, 2-3 ms en caché, `google 204` en 0,2-0,5 s. Si
alguien promete "DNS instantáneo y anónimo", está mintiendo en una de las dos.

## 7. No hay protección ante un host comprometido

Si hay malware con privilegios de administrador, **puede** desactivar el
watchdog, las reglas de firewall y el servicio: un administrador tiene la última
palabra. Esta fortaleza protege la **capa DNS**, no sustituye un EDR.

- Mitigación implementada (`scripts/protect-fortress.ps1`, `watchdog-guard.ps1`,
  `integrity-check.ps1`): ACL de solo lectura, recuperación automática de
  servicios, watchdog con repetición cada 5 minutos, guardián cada 10 minutos,
  reglas entrantes y manifiesto SHA256 con restauración. Sube el coste y cierra
  las vías triviales; no detiene a un atacante con control total del kernel.
- `scripts/harden-network-protocols.ps1` desactiva LLMNR, NetBIOS sobre TCP/IP,
  WPAD y SMBv1: cierra el envenenamiento de nombres y el relevo NTLM en la LAN.
  No inspecciona el tráfico de la red ni protege si el router está comprometido.
- Lo que sí aporta el núcleo: el centinela detecta DGA y beaconing, y el failsafe
  evita que una caída te deje sin red.

## 8. Efectos secundarios conocidos

- `SharedAccess` desactivado (necesario para liberar el puerto 53) **rompe el
  punto de acceso móvil de Windows**. El tethering USB sigue funcionando.
- Portales cautivos (hoteles, aeropuertos) pueden no cargar hasta desactivar la
  fortaleza: usa `scripts/uninstall_fortress.ps1 -RestoreDns`.
- Con `safe_search` activo, las búsquedas salen filtradas por diseño.

## 9. Ámbito legal

Este software evita censura y protege la privacidad DNS. El uso que se haga de
él es responsabilidad de quien lo instala, y en algunos países la elusión de
controles de red está regulada. No se ofrece ninguna garantía: ver `LICENSE`.
