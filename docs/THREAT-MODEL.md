# Modelo de amenazas

## Activos a proteger

| Activo | Dónde vive | Impacto si se filtra |
|---|---|---|
| Contraseña del panel de AdGuard | `config/.env` | Control total del DNS de la red |
| Clave de la API de Gemini | `config/.env` | Gasto y consultas en tu nombre |
| Sal de los hashes de dominio | `data/ai_salt.txt` | Reversión por diccionario de los hashes enviados |
| Historial de consultas | `data/`, `logs/` | Perfil de navegación completo |
| IP pública | Fuera del equipo | Correlación de identidad |

## Adversarios

| Adversario | Capacidad | Qué hace la fortaleza |
|---|---|---|
| ISP con DPI | Ve metadatos, puede bloquear por SNI/DNS | DoH sobre Tor + GoodbyeDPI |
| Resolutor de terceros | Ve consultas si se usa en claro | Perfil `privacy`: Unbound recursivo propio; perfil `speed`: DoH cifrado por SOCKS5 |
| Malware local sin privilegios | Lee ficheros del usuario, lanza procesos | ACL del `.env`, reglas de firewall, centinela |
| Malware local con administrador | Todo | ACL, recuperación de servicios, watchdog con repetición, guardián, integridad SHA256 y firewall entrante. **No es invencible**: ver `LIMITS.md` |
| Sitio web visitado | Ve sesión, cookies, fingerprint | Fingerprint uniforme (RFP), cookies aisladas y WebRTC off; una sesión iniciada sigue identificando |
| App empaquetada del sistema | Lee ficheros con ACL heredada | Se elimina el SID `S-1-15-3-...` del `.env` |
| Observador de red del edificio | Patrones de tráfico | Padding de Tor; latencia no ocultable |

## Superficie de ataque del propio proyecto

1. **Tareas programadas con SYSTEM**: ejecutan PowerShell desde una ruta fija. Si
   un usuario sin privilegios puede escribir en `C:\AdGuardHome`, puede escalar.
   Mitigación: instalar en una ruta con ACL de administradores.
2. **Lanzadores `.vbs`/`.cmd`**: resuelven rutas relativas; un `.cmd` plantado
   junto al lanzador se ejecutaría. Mitigación: prioridad a rutas absolutas y
   verificación de existencia antes de ejecutar.
3. **API local de AdGuard Home**: escucha en `127.0.0.1` con Basic Auth. Cualquier
   proceso local que lea el `.env` controla el DNS. Mitigación: ACL restringida.
4. **Centinela**: es el único componente que habla con Internet fuera de Tor.
   Mitigación: `AI_MODE=aggregate` por defecto, `off` para cero salidas y `local`
   para Ollama.
5. **`icacls /restore`**: si el respaldo de ACL se manipula, se puede ampliar el
   acceso. Mitigación: el respaldo vive en `C:\AdGuardHome\config` con la misma
   protección de carpeta.

## Supuestos

- El equipo no está comprometido con privilegios de administrador.
- El usuario instala desde una cuenta administradora y no comparte esa cuenta.
- Los binarios de AdGuard Home y Tor provienen de sus fuentes oficiales.
- El reloj del sistema es correcto (DNSSEC y TLS dependen de ello).

## Fuera de alcance

- Anonimato frente al sitio visitado.
- Protección frente a un adversario global que correlaciona tráfico en los
  extremos de la red Tor (ataque de extremo a extremo).
- Censura que bloquee simultáneamente Tor, DoH y GoodbyeDPI: en ese escenario hay
  que usar bridges (`config/torrc.template`).
