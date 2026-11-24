# Perfil Docker (Linux)

Núcleo de la fortaleza en Linux: **AdGuard Home + Tor**, con el DNS y el panel
accesibles **solo desde `127.0.0.1` del host**.

## Arranque

```bash
cd docker
docker compose up -d --build
```

- Panel: <http://127.0.0.1:3000>.

> **Antes del primer arranque, crea el administrador.** Con `users: []` AdGuard
> Home **desactiva la autenticación** (es lo que responde `--check-config`), así
> que el panel queda sin login. Solo escucha en `127.0.0.1`, pero ciérralo:
>
> ```bash
> htpasswd -bnBC 10 "" "tu_contrasena" | tr -d ':
'
> # pega el hash en docker/AdGuardHome.yaml -> users: - name: admin / password: '...'
> ```
>
> El repositorio no incluye credenciales por defecto a propósito.
- DNS: `127.0.0.1:53` (UDP y TCP).

## Por qué `0.0.0.0` dentro y `127.0.0.1` fuera

Son dos capas distintas y confundirlas es el error clásico:

| Capa | Qué hace | Valor |
|---|---|---|
| Dentro del contenedor | AdGuard escucha en todas sus interfaces para que el puerto publicado llegue | `http.address: 0.0.0.0:3000`, `bind_hosts: [0.0.0.0]` |
| En el host | Docker publica el puerto solo en loopback | `127.0.0.1:3000:3000`, `127.0.0.1:53:53/udp` |

Si dentro escuchara en `127.0.0.1`, el tráfico reenviado por Docker entraría por
la interfaz del contenedor (`eth0`) y nadie respondería: el panel y el DNS
quedarían mudos. Y si el mapeo del host fuera `0.0.0.0:53`, estarías sirviendo
DNS a toda la red sin querer.

Por eso este perfil usa `docker/AdGuardHome.yaml` (con `0.0.0.0` + `tor:9050`) y
**no** `config/AdGuardHome.template.yaml`, que es el de Windows y escucha en
loopback.

## Diferencias con la instalación de Windows

| Componente | Windows | Docker/Linux |
|---|---|---|
| AdGuard Home + DoH sobre Tor | Sí | Sí |
| DNSSEC | Sí | Sí |
| `.onion` vía DNSPort | `127.0.0.1:5350` | `tor:5350` |
| Watchdog autorreparable | Sí | No (`restart: unless-stopped`) |
| Failsafe de red | Sí | No (healthchecks + `restart`) |
| Centinela AI / señuelo | Sí | No implementado |
| GoodbyeDPI | Sí | No aplica |

## Notas

- El proxy se configura con `http_proxy: socks5://tor:9050`; el nombre `tor` lo
  resuelve la red interna de Docker. `127.0.0.1:9050` **no** funcionaría aquí:
  dentro de este contenedor sería el propio AdGuard.
- `AdGuardHome.yaml` se monta con escritura porque AdGuard guarda cambios de
  configuración al vuelo (filtros, reglas). Está versionado en el repo, así que
  puedes revisar el diff con `git diff docker/AdGuardHome.yaml`.
- `tor-data` conserva los guards entre reinicios; si quieres rotarlos:
  `docker compose down -v` (borra también la caché de AdGuard).
- Comprobaciones:

  ```bash
  docker compose ps
  docker compose logs tor --tail 20
  docker compose exec adguardhome wget -q -O- http://127.0.0.1:3000/ | head -3
  dig @127.0.0.1 github.com +short
  ```
