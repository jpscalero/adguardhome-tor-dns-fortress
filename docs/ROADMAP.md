# Roadmap

Lo hecho está en el `CHANGELOG.md`. Aquí solo lo que **falta**, por orden de
impacto real y con su motivo.

## Fase 5 — Independencia de terceros

- [ ] **Perfil recursivo con `unbound`**: resolver desde la raíz sin delegar en
      Quad9/Cloudflare. Es la única forma de que ningún tercero vea el patrón de
      consultas, a cambio de latencia y de perder la cobertura de DoH.
- [ ] **Selector de perfil** (`privacy` / `speed` / `censorship`) que aplique una
      combinación coherente de upstreams, timeouts y listas.
- [ ] **Rotación programada de upstreams** con verificación de que el nuevo
      responde antes de cambiar.

## Fase 6 — Observabilidad sin telemetría

- [ ] Panel local estático (HTML + JSON) con latencia, hits, estado de Tor y
      últimas alertas del centinela.
- [ ] Exportador de métricas para Prometheus (solo local, sin salida).
- [ ] Alertas por `ntfy`/Telegram cuando el pipeline cae o Tor rota circuito.

## Fase 7 — Cobertura de tests

- [ ] Tests de los scripts PowerShell con Pester (failsafe, ACL, instalador
      `-DryRun`).
- [ ] Pruebas de integración en máquina virtual de Windows con red simulada.
- [ ] Verificación de que `install_fortress.ps1` es idempotente (ejecutarlo dos
      veces no debe duplicar tareas ni reglas).

## Fase 8 — Alcance

- [ ] Paridad Linux real: unidades `systemd` para watchdog y failsafe, sin Docker.
- [ ] Soporte de Raspberry Pi / OpenWrt como resolutor de red completa.
- [ ] Guía de router: DHCP, VLAN de invitados y DNS por dispositivo.

## Ideas descartadas (y por qué)

- **Bloquear QUIC/UDP 443**: rompe YouTube y buena parte de la web moderna.
- **Doble VPN sobre Tor**: añade latencia sin mejorar el anonimato real.
- **Ofuscar el tráfico del centinela**: no aporta si el modo `aggregate` ya evita
  enviar el dominio.
