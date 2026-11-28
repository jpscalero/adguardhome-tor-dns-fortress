# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.0.x   | Critical fixes only |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The AdGuard Home DNS Fortress project takes the security of its privacy and anti-censorship pipeline very seriously.

If you discover a security vulnerability, DNS leak, bypass mechanism, or credential exposure issue:
1. **DO NOT** open a public issue on GitHub.
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/jpscalero/adguardhome-tor-dns-fortress/security/advisories/new) or by contacting the repository maintainer.
3. Provide detailed steps to reproduce the issue, including PowerShell/Node.js version, Windows build, and relevant log excerpts (with credentials and IPs redacted).

### Security Architecture Principles
- **No Unencrypted DNS Leaks**: All outbound upstream traffic must be tunneled through Tor SOCKS5 or encrypted protocols (DoH, DoT, DoQ).
- **Non-Destructive Windows Integration**: We do not disable core Windows services or mutate protected system DLL mappings.
- **Zero Secrets in Repository**: No credentials, private keys, or personal tokens are committed to source control.

## Alcance

Se consideran vulnerabilidades de este proyecto:

- ejecución de código no deseada a través de los scripts o lanzadores;
- exposición de credenciales (`ADGUARD_PASSWORD`, `GEMINI_API_KEY`, sal de hash);
- fugas de DNS que la documentación afirme evitar;
- elevación de privilegios desde las tareas programadas o los servicios;
- denegación de servicio local provocada por el watchdog o el failsafe.

**Fuera de alcance**: vulnerabilidades de AdGuard Home, Tor o GoodbyeDPI (repórtalas
a sus proyectos), y decisiones de configuración documentadas en `docs/LIMITS.md`.

## Versiones soportadas

| Versión | Soporte |
|---|---|
| 2.x | Sí |
| 1.0.x | Solo correcciones críticas |

## Compromisos

- Acuse de recibo en 72 horas.
- No se abre un issue público hasta que exista corrección o mitigación.
- Se acredita al informante salvo que pida lo contrario.
- Este proyecto se mantiene sin ánimo de lucro y sin garantías (ver `LICENSE`).
