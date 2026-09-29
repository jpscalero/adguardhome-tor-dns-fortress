# 🏛️ Arquitectura de Seguridad y Privacidad Multicapa

## Diagrama de Flujo de Datos

```mermaid
flowchart TD
    subgraph Host ["💻 Host Local (Windows 11)"]
        Browser["🌐 Navegador (Brave / Chrome / Firefox)"]
        Decoy["🎲 Decoy DNS Noise (decoy_dns.js)"]
        Apps["📦 Aplicaciones del Sistema"]
        
        Browser -->|Petición DNS UDP 0ms| AGH["🛡️ AdGuard Home (127.0.0.1:53)"]
        Decoy -->|Tráfico Señuelo Jitter| AGH
        Apps -->|Petición DNS UDP 0ms| AGH

        subgraph LocalDefense ["🧠 Módulos de Defensa Local"]
            Centinela["🤖 Centinela AI (ai_dns_guard.js)<br/>• Análisis de Entropía DGA<br/>• Detección de Beacons C2"]
            Watchdog["🐕 Self-Healing Watchdog (watchdog.ps1)<br/>• Supervisión de Servicios<br/>• Arbitraje Puerto 53"]
            Cache["⚡ RAM Optimistic Cache (32MB / 100k+ dominios)"]
        end

        AGH <--> Centinela
        AGH <--> Cache
        Watchdog -.->|Supervisa y Repara| AGH
        Watchdog -.->|Supervisa y Repara| TorProxy
        Watchdog -.->|Supervisa y Repara| GDPI
    end

    subgraph EvasionLayer ["🛡️ Capa Anti-Inspección (GoodbyeDPI)"]
        GDPI["⚡ WinDivert Driver<br/>• TCP Segmentation<br/>• Fake Host Header<br/>• SNI Obfuscation"]
    end

    subgraph AnonymityLayer ["🧅 Capa de Anonimización (Tor)"]
        TorProxy["🧅 Tor Service (127.0.0.1:9050 SOCKS5)"]
        OnionDNS["🧅 Tor DNS Resolver (127.0.0.1:5350)"]
    end

    subgraph Internet ["🌍 Red Neutral Externa (DNS-over-HTTPS)"]
        Resolvers["🔒 Resolutores DoH en Jurisdicciones Neutrales<br/>• Digitale Gesellschaft (Suiza 🇨🇭)<br/>• Applied Privacy (Austria 🇦🇹)<br/>• Mullvad Zero-Logs (Suecia 🇸🇪)<br/>• DNS.SB (Alemania 🇩🇪)<br/>• Quad9 Foundation (Suiza 🇨🇭)"]
        OnionNet["🧅 Red Tor (.onion Hidden Services)"]
    end

    AGH -->|Cifrado SOCKS5 / DNS| TorProxy
    AGH -->|Consultas .onion| OnionDNS
    TorProxy --> GDPI
    GDPI -->|Túnel 3 Saltos Cifrados| Resolvers
    OnionDNS --> OnionNet
```

---

## Principios Fundamentales del Diseño

### 1. Resistencia a Fugas (Zero-Leak Policy)
* **EDNS Client Subnet (ECS) Desactivado**: Ni tu IP pública ni la subred de tu ISP se transmiten en las cabeceras DNS a los servidores destino.
* **Bloqueo AAAA Forzado**: En entornos donde el proveedor o la VPN no tiene túnel IPv6 completo, las peticiones IPv6 se cancelan de inmediato para evitar bypass de consultas DNS no enrutadas.
* **Refuse ANY**: Se deniegan automáticamente consultas de tipo `ANY` para prevenir amplificación DNS y reconocimiento de infraestructura.

### 2. Anonimización por Multi-Salto
* Ningún resolvedor DNS upstream conoce la IP real del usuario. Todos los paquetes DoH son transmitidos a través del circuito Tor (3 saltos: Entry Guard -> Middle Relay -> Exit Relay).
* Las consultas a servidores suizos y austriacos se ejecutan en modo **Paralelo Competitivo** (`parallel`), aceptando la respuesta criptográficamente verificada más rápida (DNSSEC).

### 3. Evasión de Inspección Profunda (Anti-DPI)
* **GoodbyeDPI** opera a nivel de paquete en el kernel de Windows a través de `WinDivert`. Fragmenta el handshake inicial TLS e inyecta paquetes SNI desfasados para neutralizar cualquier firewall estatal, corporativo o de ISP que intente registrar las consultas o bloquear sitios web.

### 4. Inteligencia Artificial Centinela y Tráfico Señuelo
* **`ai_dns_guard.js`**: Inspecciona continuamente el log de consultas en memoria. Calcula la entropía de Shannon para detectar dominios DGA (típicos de malware) y analiza la desviación estándar de los intervalos temporales para neutralizar beacons periódicos de troyanos C2.
* **`decoy_dns.js`**: Emite periódicamente consultas a dominios académicos, culturales y de código abierto con jitter aleatorio para frustrar el análisis de perfiles de navegación y correlación temporal de tráfico.
