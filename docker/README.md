# Perfil Docker (Linux)

Núcleo de la fortaleza en Linux: **AdGuard Home + Tor**, con el panel y el DNS
escuchando solo en loopback.

## Arranque

```bash
cd docker
cp ../config/AdGuardHome.template.yaml ./AdGuardHome.yaml
# edita ./AdGuardHome.yaml si quieres cambiar upstreams o listas
docker compose up -d
```

Panel: <http://127.0.0.1:3000>

## Qué cubre y qué no

| Componente | Windows | Docker/Linux |
|---|---|---|
| AdGuard Home + DoH sobre Tor | Sí | Sí |
| DNSSEC | Sí | Sí |
| `.onion` vía DNSPort | Sí | Sí |
| Watchdog autorreparable | Sí | No (usar `restart: unless-stopped`) |
| Failsafe de red | Sí | No (usar systemd-resolved o un healthcheck) |
| Centinela AI / señuelo | Sí | No implementado |
| GoodbyeDPI | Sí | No aplica (herramienta de Windows) |

El perfil Docker **no** aplica el endurecimiento de Windows (puerto 53, ICS,
firewall, ACL). Si buscas paridad, usa la instalación de Windows documentada en
el README principal.

## Notas

- El fichero `torrc` de esta carpeta escucha en `0.0.0.0` **dentro** de la red
  del contenedor; el mapeo de puertos lo limita a `127.0.0.1` del host.
- `AdGuardHome.yaml` se monta en solo lectura: los cambios se hacen en el fichero
  y se reinicia el contenedor.
- En producción, coloca el panel detrás de un proxy con TLS o mantenlo en
  loopback y accede por túnel SSH.
