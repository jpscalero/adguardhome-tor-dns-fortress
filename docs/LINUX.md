# Perfil Linux

El repositorio nace para Windows porque los problemas que resuelve (puerto 53
secuestrado por ICS, DoH del navegador por políticas, tareas SYSTEM) son de
Windows. En Linux el núcleo DNS+Tor funciona igual, con menos piezas.

## Opción rápida: Docker

Ver [`docker/README.md`](../docker/README.md). Levanta AdGuard Home + Tor con el
panel y el DNS solo en loopback.

## Opción nativa

```bash
# 1. AdGuard Home (instalador oficial)
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v

# 2. Tor
sudo apt install tor

# 3. Configuración endurecida
sudo cp config/torrc.template /etc/tor/torrc
sudo systemctl restart tor

# 4. AdGuard Home apuntando al SOCKS5 de Tor
sudo cp config/AdGuardHome.template.yaml /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl restart AdGuardHome
```

## Qué cambia respecto a Windows

| Tema | Windows | Linux |
|---|---|---|
| Reserva del puerto 53 | `SharedAccess`/ICS | `systemd-resolved` (`DNSStubListener=no`) |
| DNS del sistema | `Set-DnsClientServerAddress` | `/etc/resolv.conf` o NetworkManager |
| Reglas anti-fuga | `New-NetFirewallRule` | `nftables`/`iptables` |
| Servicios | Programador de tareas | `systemd` (`Restart=always`) |
| Watchdog/failsafe | PowerShell | No portados todavía (ver `ROADMAP.md`) |
| GoodbyeDPI | Sí | No aplica |

Ejemplo mínimo de `nftables` para forzar todo el DNS por AdGuard:

```
table inet fortress {
  chain output {
    type filter hook output priority 0; policy accept;
    udp dport 53 ip daddr != 127.0.0.1 drop
    tcp dport 53 ip daddr != 127.0.0.1 drop
    tcp dport 853 drop
  }
}
```

## Aviso

El perfil Linux **no** está probado con la misma profundidad que el de Windows.
Si lo usas en producción, abre un issue con lo que falle.
