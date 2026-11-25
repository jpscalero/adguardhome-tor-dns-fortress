# Compatibilidad por edición de Windows y por Ethernet

Este documento explica qué módulos de la fortaleza se activan en **Windows Home,
Pro, Education y Enterprise**, qué se omite en cada una y si todo funciona cuando
el equipo se conecta por **cable Ethernet** en lugar de Wi-Fi.

> **Resumen:** el núcleo DNS/Tor/firewall/failsafe/watchdog es idéntico en todas
> las ediciones. Lo que cambia es el hardening nativo de Windows que se puede
> añadir encima. Home se queda en el perfil básico; Pro, Education y Enterprise
> añaden módulos de auditoría y comprobaciones, nunca bloqueos automáticos de
> aplicaciones.

---

## 1. Cómo se detecta la edición

El instalador lee la edición real del registro de Windows y calcula un perfil:

```powershell
# Ver el perfil sin cambiar nada
powershell -ExecutionPolicy Bypass -File scripts\windows-edition.ps1
```

La detección usa:

- `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EditionID`
- `ProductName`, `DisplayVersion`, `CurrentBuildNumber` y `UBR`
- `[Environment]::Is64BitOperatingSystem`

Ediciones reconocidas:

| Edición de Windows | EditionID habitual | Perfil | Tier |
|---|---|---|---|
| Home / Core / Single Language | `Core`, `CoreN`, `CoreSingleLanguage`, `CoreCountrySpecific` | Home | 1 |
| Pro | `Professional`, `ProfessionalN` | Pro | 2 |
| Pro for Workstations | `ProfessionalWorkstation` | Pro | 2 |
| Pro Education | `ProfessionalEducation` | Pro | 2 |
| Education | `Education`, `EducationN` | Education | 3 |
| Enterprise | `Enterprise`, `EnterpriseN` | Enterprise | 4 |
| Enterprise LTSC | `EnterpriseS`, `EnterpriseSN` | Enterprise | 4 |
| IoT Enterprise | `IoTEnterprise`, `IoTEnterpriseS` | Enterprise | 4 |
| Windows Server | `ServerStandard`, `ServerDatacenter`, etc. | Enterprise | 4 (no soportado oficialmente) |
| Edición desconocida | — | Home (mínimo) | 1 |

`Windows 10` y `Windows 11` se distinguen por el build (`22000` o superior es
Windows 11). La versión (`22H2`, `23H2`, `24H2`, `26H2`...) se muestra, pero no
cambia el perfil: lo que manda es la edición y las capacidades reales del sistema.

### Forzar un perfil

Se puede pedir un perfil concreto para probar o para una instalación controlada:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_fortress.ps1 -EditionProfile Home
powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -Edition Enterprise
```

Forzar **no inventa capacidades**: si un Windows Home se fuerza a Enterprise, los
módulos que Home no soporta se siguen omitiendo. El perfil forzado solo decide
qué módulos disponibles se intentan.

Además, un perfil solicitado **nunca supera la edición real**: el `Tier` efectivo
se recorta al tier detectado y el perfil aparece como `Enterprise (forzado,
limitado a Avanzado)`. Así cada equipo bloquea los perfiles que no le
corresponden, incluso si se le pasa el modificador a mano:

| Edición real | Perfiles que puede ejecutar | Perfiles que se recortan |
|---|---|---|
| Home | Home (Básico) | Pro, Education y Enterprise |
| Pro | Home y Pro (hasta Avanzado) | Education y Enterprise |
| Education | Home, Pro y Education (hasta Educación) | Enterprise |
| Enterprise | Todos (hasta Empresa) | — |

Para comprobarlo sin cambiar nada:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -Edition Enterprise -DryRun
```

En un equipo Home, Pro o Education la salida mostrará `EnterpriseReport: No
disponible en esta edicion de Windows` y `Tier` recortado en la cabecera del
perfil.

---

## 2. Matriz de módulos

Leyenda: ✅ se aplica o se comprueba; — se omite.

| Módulo | Home | Pro | Education | Enterprise | Qué hace |
|---|:---:|:---:|:---:|:---:|---|
| **Núcleo DNS/Tor** | ✅ | ✅ | ✅ | ✅ | AdGuard Home, Tor SOCKS5, DoH, DNSPort `.onion`, filtros, caché, firewall anti-fuga, failsafe, watchdog, DoH del navegador y ACL del `.env`. |
| **Registro de firewall** | — | ✅ | ✅ | ✅ | Activa el registro de paquetes bloqueados en los perfiles Domain/Private/Public. |
| **Registro DNS Client** | — | ✅ | ✅ | ✅ | Activa el canal `Microsoft-Windows-DNS-Client/Operational` para diagnóstico. |
| **Defender en auditoría** | — | ✅ | ✅ | ✅ | ASR, Network Protection y Controlled Folder Access en modo **auditoría**, sin bloquear aplicaciones. |
| **App Control/WDAC** | — | ✅ | ✅ | ✅ | Comprueba políticas `.cip` activas; no las modifica. |
| **BitLocker** | — | ✅ | ✅ | ✅ | Comprueba el estado del cifrado; no activa BitLocker ni genera claves. |
| **Hyper-V / Sandbox** | — | ✅ | ✅ | ✅ | Comprueba si las características están disponibles; no las instala. |
| **AppLocker** | — | — | ✅ | ✅ | Comprueba servicio y políticas; no bloquea aplicaciones. |
| **Credential Guard** | — | — | ✅ | ✅ | Comprueba VBS/Credential Guard; no cambia el arranque. |
| **Application Guard** | — | — | ✅ | ✅ | Comprueba si la característica está instalada; no la activa. |
| **Informe Enterprise** | — | — | — | ✅ | Genera `edition-hardening.report.json` con todos los estados y la auditoría. |

### Por qué Home no lleva los módulos de Pro

No es una limitación artificial: Windows Home no incluye el editor de directivas
locales (`gpedit.msc`), AppLocker, Credential Guard, BitLocker completo, Hyper-V
ni Windows Sandbox. Tampoco admite las reglas ASR de Defender con la misma
cobertura que Pro/Enterprise. El núcleo de la fortaleza no depende de nada de
eso, así que Home funciona perfectamente con el perfil básico.

### Por qué Pro no lleva AppLocker ni Credential Guard

Microsoft reserva AppLocker y Credential Guard para **Education y Enterprise**.
Pro sí tiene App Control/WDAC, BitLocker, Hyper-V, Sandbox y las reglas ASR/NP/CFA
en auditoría; por eso su perfil es "Avanzado", no "Empresa".

Controlled Folder Access existe también en Home, pero el módulo de auditoría se
activa a partir de Pro para no cambiar el perfil básico de Home. No se activa en
modo bloqueo en ninguna edición.

### Qué se aplica realmente

- **Registro de firewall**: cambia `LogBlocked` y el tamaño máximo de log. Se
  guarda el valor anterior para `-Undo`.
- **Registro DNS Client**: activa un canal de eventos. Se guarda si estaba
  activo para `-Undo`.
- **Defender en auditoría**: si Defender está activo, añade reglas ASR en
  `AuditMode`, activa Network Protection en modo auditoría (`2`) y Controlled
  Folder Access en modo auditoría (`2`). **No** pone nada en bloqueo.
- **AppLocker, App Control/WDAC, Credential Guard, BitLocker, Hyper-V, Sandbox y
  Application Guard**: solo lectura. Se informa de su estado y no se cambia.
- **Informe Enterprise**: JSON con el perfil, módulos aplicados, módulos
  omitidos, lecturas y avisos.

---

## 3. Qué cambia en cada edición

### Windows Home — perfil Básico

- Núcleo completo: DNS local, Tor, DoH, `.onion`, filtros, firewall, failsafe,
  watchdog, DoH del navegador y ACL de credenciales.
- Sin módulos de auditoría de Windows.
- Es el perfil recomendado para equipos domésticos: menos superficie de cambio y
  las mismas garantías DNS.

### Windows Pro — perfil Avanzado

- Todo lo de Home.
- Registro de firewall y del cliente DNS para diagnosticar bloqueos.
- Auditoría de Defender (ASR/NP/CFA) sin bloquear.
- Comprobaciones de App Control/WDAC, BitLocker y Hyper-V/Sandbox.

### Windows Education — perfil Educación

- Todo lo de Pro.
- Comprobaciones de AppLocker, Credential Guard y Application Guard.
- Útil en equipos educativos donde ya existan políticas de aplicación.

### Windows Enterprise — perfil Empresa

- Todo lo de Education.
- Informe consolidado `edition-hardening.report.json`.
- Muestra el estado de la auditoría avanzada y de todas las capacidades.
- No activa AppLocker/WDAC/Credential Guard automáticamente: en una empresa esas
  políticas deben desplegarse con Intune/GPO y probarse antes.

### Ediciones especiales

- **Pro for Workstations**: mismas capacidades que Pro para la fortaleza.
- **Pro Education**: se trata como Pro; AppLocker/Credential Guard no están
  garantizados.
- **Enterprise LTSC / IoT Enterprise**: perfil Enterprise; algunas características
  opcionales (Application Guard, Store) pueden no estar instaladas. El informe lo
  refleja como `no encontrado`.
- **Windows Server**: se detecta como Enterprise, pero el proyecto está pensado
  para Windows 10/11 de escritorio. No se garantiza GoodbyeDPI ni los módulos de
  escritorio.

---

## 4. Cómo se aplica y se revierte

El instalador llama automáticamente a:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -Edition Auto
```

Para ver qué haría sin cambiar nada:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -DryRun
```

Si prefieres instalar solo el núcleo y no tocar el hardening nativo, usa
`install_fortress.ps1 -SkipEditionHardening`. El instalador fácil no lo hace por
defecto: en Home no hay módulos adicionales y en Pro/Enterprise se aplican en
modo auditoría.

Para revertir los cambios de firewall, DNS Client y Defender:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\apply-edition-hardening.ps1 -Undo
```

El estado original se guarda en:

```text
C:\AdGuardHome\edition-hardening.state.json
```

El informe legible por máquina se guarda en:

```text
C:\AdGuardHome\edition-hardening.report.json
```

`DESINSTALAR.cmd` ejecuta también el `-Undo` automáticamente. Si algún cambio no
se puede revertir, conserva el archivo de estado para reintentarlo y avisa.

---

## 5. ¿Funciona todo por Ethernet?

**Sí.** El núcleo de la fortaleza funciona igual por cable Ethernet que por
Wi-Fi. No hay ninguna función que dependa del adaptador inalámbrico:

| Componente | Dependencia de Ethernet |
|---|---|
| AdGuard Home | Escucha en `127.0.0.1:53` y `::1:53`; no depende de la interfaz física. |
| Tor SOCKS5 | Escucha en `127.0.0.1:9050`; el tráfico sale por la conexión activa, sea Ethernet o Wi-Fi. |
| Tor DNSPort | Escucha en `127.0.0.1:5350`; resuelve `.onion` sin depender de la interfaz. |
| Firewall anti-fuga | Bloquea puertos 53/UDP, 53/TCP, 853/TCP y 5353/UDP salientes; se aplica a todas las interfaces. |
| Failsafe | Configura los adaptadores físicos activos, incluido Ethernet. |
| Watchdog | Incluye `Ethernet` en la sincronización de IP local si se habilita el servicio LAN. |
| GoodbyeDPI | Funciona a nivel de WinDivert; no distingue Ethernet de Wi-Fi. |
| DoH del navegador | Es una directiva del navegador; no depende de la red. |

### Cómo configura el instalador Ethernet

1. Enumera los adaptadores con `Get-NetAdapter` cuyo estado es `Up`.
2. Excluye los que parecen virtuales/Hyper-V.
3. Pone `127.0.0.1` como DNS IPv4 en cada adaptador físico activo.
4. Purga la caché DNS.
5. El failsafe revisa cada dos minutos y vuelve a poner `127.0.0.1` si el DHCP o
   una VPN lo cambiaron.

Comprobación manual:

```powershell
Get-NetAdapter | Format-Table Name, Status, InterfaceDescription
Get-DnsClientServerAddress -AddressFamily IPv4 |
  Where-Object { $_.ServerAddresses } |
  Format-Table InterfaceAlias, ServerAddresses
Resolve-DnsName github.com -Server 127.0.0.1
Test-NetConnection 127.0.0.1 -Port 9050
```

Si el adaptador Ethernet aparece con `127.0.0.1`, el DNS está pasando por la
fortaleza.

### Casos especiales que sí debes conocer

1. **Solo hay un adaptador virtual activo** (Hyper-V, VPN, Docker, WSL): el
   instalador excluye los virtuales. Si no hay un adaptador físico `Up`, no se
   configura DNS automáticamente. Conecta el cable o configura el DNS a mano.
2. **Ethernet con portal cautivo o 802.1X**: el DNS puede quedar a `127.0.0.1`
   antes de autenticarte. Si el portal no carga, desconecta y vuelve a conectar;
   el failsafe restaurará la configuración. También puedes ejecutar
   `COMPROBAR.cmd` para ver el estado.
3. **IPv6**: el instalador configura DNS IPv4 (`127.0.0.1`). AdGuard escucha en
   `::1`, pero Windows no recibe `::1` como DNS IPv6 automáticamente. En una red
   **IPv6-only** hay que añadirlo a mano:
   ```powershell
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -AddressFamily IPv6 -ServerAddresses "::1"
   ```
   En redes dual-stack normales, IPv4 funciona y las reglas de firewall bloquean
   DNS IPv6 directo para que no haya fuga.
4. **Router que reparte su propio DNS**: el instalador cambia el DNS **de este
   PC**, no el del router. Otros dispositivos de la LAN seguirán usando el DNS
   del router. Para proteger toda la LAN, el router debe apuntar a AdGuard Home;
   eso queda fuera de este repositorio.
5. **Varias tarjetas a la vez** (Ethernet + Wi-Fi): se configura el DNS en todas
   las físicas activas. No hay conflicto: todas apuntan al mismo AdGuard local.
6. **VPN de terceros**: el failsafe actúa sobre adaptadores físicos; los
   adaptadores virtuales de la VPN quedan fuera. Si la VPN cambia el DNS del
   adaptador físico y AdGuard responde, el failsafe lo devuelve a `127.0.0.1`
   porque las reglas anti-fuga bloquean el DNS externo. Si quieres que la VPN use
   AdGuard, configura también el DNS de la VPN a `127.0.0.1`.

---

## 6. Preguntas rápidas

**¿Home pierde funciones de privacidad?** No. Pierde módulos de hardening nativo
de Windows que Home no tiene (AppLocker, Credential Guard, BitLocker, Hyper-V,
etc.), pero conserva todo el núcleo DNS/Tor/firewall/failsafe/watchdog.

**¿Enterprise es más seguro para la fortaleza?** Añade auditoría y visibilidad,
no más anonimato DNS. El anonimato depende de Tor y de la configuración de
AdGuard, que es la misma en todas las ediciones.

**¿AppLocker se activa en Enterprise?** No automáticamente. Solo se comprueba su
estado. Activar AppLocker sin una política probada puede impedir abrir programas.

**¿Puedo usar Ethernet y Wi-Fi a la vez?** Sí. Ambos adaptadores físicos activos
apuntan a `127.0.0.1`; el tráfico DNS local siempre llega a AdGuard.

**¿El watchdog cambia la IP de `bind_hosts` si cambio de red?** Solo si añadiste
una IP LAN a `bind_hosts` en `AdGuardHome.yaml`. Por defecto la plantilla escucha
solo en loopback y no necesita sincronización de IP.
