# Instalación fácil (para principiantes)

Esta guía es para alguien que **nunca ha usado GitHub, PowerShell ni Tor**.
No hace falta saber programar: solo descargar, descomprimir y hacer doble clic.

> Descarga siempre los archivos desde este repositorio oficial o desde las
> páginas oficiales de AdGuard, Tor y GoodbyeDPI que se indican abajo. No uses
> copias de terceros.

> Si ya sabes administrar Windows, usa la sección técnica del
> [README](../README.md). Esta guía hace lo mismo, pero explicando cada clic.

> **Windows Home, Pro, Education o Enterprise:** no tienes que elegir nada. El
> instalador detecta tu edición y aplica el perfil correspondiente. Home se queda
> en lo básico y Enterprise añade más comprobaciones, pero el núcleo DNS/Tor es
> el mismo. Funciona igual por **Wi-Fi o cable Ethernet**. Detalles en
> [EDICIONES-WINDOWS.md](EDICIONES-WINDOWS.md).

---

## Qué vas a instalar

| Programa | Para qué sirve | ¿Obligatorio? |
|---|---|---|
| **AdGuard Home** | Filtra la publicidad, el malware y la telemetría de todo el equipo. Es el centro de la fortaleza. | Sí |
| **Tor** | Hace que las consultas DNS salgan por tres servidores cifrados, así tu operadora no ve qué dominios pides. | Sí |
| **GoodbyeDPI** | Ayuda a que tu operadora no bloquee páginas por inspección de tráfico (DPI). | Recomendado |
| **Node.js portable** | Alimenta el centinela que detecta dominios sospechosos y el generador de tráfico señuelo. | Recomendado |

**Importante:** esta fortaleza protege las **consultas DNS** (el “libro de
direcciones” de Internet), no toda tu navegación. Tu tráfico normal de webs y
vídeos no pasa por Tor. Lo que sí consigues es que tu operadora no vea qué
dominios resuelves y que la publicidad y el malware se bloqueen antes de
conectarse.

---

## Antes de empezar

Necesitas:

- Un PC con **Windows 10 u 11 de 64 bits**.
- Una cuenta de Windows con permisos de **administrador**.
- **Conexión a Internet** (para descargar los programas).
- Entre **20 y 40 minutos**.
- La contraseña de tu usuario de Windows, por si Windows la pide al elevar
  permisos.

No lo instales en un equipo de trabajo controlado por tu empresa: las políticas
corporativas pueden bloquear el cambio de DNS. Tampoco es compatible con el
**punto de acceso móvil** de Windows (el instalador desactiva `SharedAccess`,
que es el servicio que lo gestiona). El tethering por USB sí funciona.

---

## Resumen en 6 pasos

1. Descargar este repositorio y descomprimirlo en `C:\fortaleza`.
2. Instalar AdGuard Home y crear tu usuario en su asistente.
3. Descomprimir Tor en `C:\Tor`.
4. Descomprimir GoodbyeDPI en `C:\GoodbyeDPI` (recomendado).
5. Doble clic en `INSTALAR.cmd` y esperar.
6. Comprobar que todo está en verde con `COMPROBAR.cmd`.

---

## Paso 1 — Descargar el repositorio (sin instalar git)

1. Abre esta dirección en tu navegador:
   <https://github.com/jpscalero/adguardhome-tor-dns-fortress>
2. Pulsa el botón verde **`Code`** y elige **`Download ZIP`**.
3. Abre tu carpeta **Descargas**. Verás un archivo llamado
   `adguardhome-tor-dns-fortress-main.zip`.
4. Haz clic derecho sobre él y elige **Extraer todo…**. En Windows 11 puede
   estar dentro de **Mostrar más opciones**.
5. En la ventana que aparece, borra la ruta que pone y escribe exactamente:

   ```text
   C:\fortaleza
   ```

6. Pulsa **Extraer**.
7. Abre `C:\fortaleza` y comprueba que dentro están `INSTALAR.cmd`,
   `COMPROBAR.cmd` y la carpeta `scripts`.

> Si dentro de `C:\fortaleza` ves otra carpeta llamada
> `adguardhome-tor-dns-fortress-main`, entra en ella y mueve **todo su
> contenido** un nivel arriba, para que `C:\fortaleza\INSTALAR.cmd` exista.
> El instalador necesita esa ruta exacta.

No necesitas cuenta de GitHub ni instalar nada más para este paso.

---

## Paso 2 — Instalar AdGuard Home y crear tu usuario

AdGuard Home es el programa que filtra el DNS. Lo instalamos primero porque su
asistente crea la contraseña del panel; el instalador de la fortaleza la
reutiliza.

1. Abre <https://github.com/AdguardTeam/AdGuardHome/releases/latest>.
2. En la sección **Assets**, descarga el archivo
   **`AdGuardHome_windows_amd64.zip`** (es el de 64 bits).
3. Abre la carpeta Descargas, haz clic derecho en el ZIP y elige
   **Extraer todo…**.
4. Escribe como destino:

   ```text
   C:\AdGuardHome
   ```

5. Pulsa **Extraer**. Comprueba que existe
   `C:\AdGuardHome\AdGuardHome.exe`.
6. Haz **clic derecho** en `AdGuardHome.exe` y elige
   **Ejecutar como administrador**.
7. Si aparece el aviso azul **“Windows protegió tu PC”**, pulsa
   **Más información → Ejecutar de todas formas**. Es normal en programas
   descargados de GitHub sin firma comercial.
8. Se abrirá una ventana negra y, a los pocos segundos, tu navegador en
   `http://127.0.0.1:3000`. Si no se abre solo, escribe esa dirección en el
   navegador.
9. Completa el asistente:
   - Crea un **usuario** (por ejemplo `admin`).
   - Crea una **contraseña** y **apúntala**. La necesitarás dos veces más.
   - Deja las opciones que vienen por defecto.
   - Si te pregunta por el puerto DNS y dice que el 53 está ocupado, elige
     **5353** y continúa. El instalador lo corrige después.
10. Al terminar, verás el panel de AdGuard Home. **Cierra la ventana negra**
    (la del programa, no la del navegador) con `Ctrl+C` o con la `X`. Si
    pregunta si quieres terminar el trabajo por lotes, di que sí.
11. Comprueba que se ha creado el archivo
    `C:\AdGuardHome\AdGuardHome.yaml`. Si no existe, repite el asistente.

> **No instales todavía AdGuard Home como servicio.** De eso se encarga
> `INSTALAR.cmd` al final, cuando la configuración ya está preparada.

---

## Paso 3 — Descomprimir Tor en `C:\Tor`

1. Abre <https://www.torproject.org/download/tor/>.
2. En la sección **Expert Bundle**, descarga la versión para **Windows**. No
   descargues el Tor Browser: para esta guía necesitas el *Expert Bundle*, que
   incluye `tor.exe`.
3. Descomprime el ZIP.
4. Crea la carpeta `C:\Tor` y mueve ahí el contenido, de forma que exista
   exactamente:

   ```text
   C:\Tor\tor.exe
   ```

   Si el ZIP crea una subcarpeta con un nombre largo, entra en ella y mueve
   **todo** a `C:\Tor`.

No hace falta ejecutar `tor.exe` a mano: el instalador lo registra como
servicio y lo arranca.

---

## Paso 4 — GoodbyeDPI (recomendado, no obligatorio)

GoodbyeDPI evita que algunos operadores bloqueen páginas por DPI. Si tu conexión
funciona bien y no sufres censura, puedes saltarte este paso; el DNS y Tor
funcionarán igual, pero la comprobación final mostrará un `FAILED` en el punto 7.
Es esperado y no afecta a la privacidad del DNS.

1. Abre <https://github.com/ValdikSS/GoodbyeDPI/releases/latest>.
2. Descarga el archivo `.zip` de la release (no el código fuente).
3. Descomprime el contenido en:

   ```text
   C:\GoodbyeDPI
   ```

4. Comprueba que dentro están `goodbyedpi.exe` y algún archivo llamado
   `service_install....cmd`.
5. Algunos antivirus marcan GoodbyeDPI o su driver `WinDivert` como sospechoso.
   Es un falso positivo conocido por el tipo de técnica que usa. Si tu antivirus
   lo bloquea, puedes omitir este paso.
6. Si juegas a juegos con anticheat (Valorant/Vanguard, Easy Anti-Cheat,
   BattlEye), GoodbyeDPI puede interferir. En ese caso omítelo: el DNS y Tor
   siguen protegiéndote.

---

## Paso 5 — Ejecutar el instalador

1. Abre `C:\fortaleza`.
2. Haz **doble clic** en **`INSTALAR.cmd`**.
3. Si Windows muestra **“Windows protegió tu PC”**, pulsa
   **Más información → Ejecutar de todas formas**. Después aparecerá el aviso
   de **Control de cuentas de usuario**: pulsa **Sí**. Si no aparece el aviso,
   haz clic derecho en `INSTALAR.cmd` y elige **Ejecutar como administrador**.
4. Se abrirá una ventana azul. Verás algo parecido a:

   ```text
   [1/5] Preparando el usuario y la contrasena del panel...
   [*] Leyendo el usuario creado por AdGuard Home...
   Escribe la contrasena del panel para 'admin':
   ```

5. Escribe **la misma contraseña que creaste en el asistente de AdGuard
   Home** y pulsa `Enter`. La pedirá dos veces para evitar erratas. Mientras
   escribes no se verá nada en pantalla: es normal, así se protegen las
   contraseñas. Si ya existía `config\.env`, no la volverá a pedir.
6. El instalador hará el resto solo:
   - copia tu usuario a la configuración blindada;
   - crea `config\.env` con tus credenciales;
   - descarga Node portable si falta;
   - neutraliza el secuestro del puerto 53;
   - configura el DNS del equipo a `127.0.0.1`;
   - crea las reglas de firewall anti-fuga;
   - registra el watchdog y el failsafe;
   - instala y arranca los servicios de AdGuard Home y Tor;
   - ejecuta la comprobación final.

7. Al terminar, se abrirá el panel de AdGuard Home en el navegador. Entra con
   el usuario y la contraseña que creaste.

La primera vez puede tardar varios minutos porque AdGuard descarga las listas
de bloqueo a través de Tor. Es normal que la comprobación final tarde o que
algún punto salga en amarillo/rojo: espera dos minutos y ejecuta
`COMPROBAR.cmd`.

### Qué significa cada resultado

- **`OK` en verde**: ese punto funciona.
- **`AVISO` en amarillo**: un módulo opcional no está activo (por ejemplo, el
  centinela si no instalaste Node). El DNS sigue protegido.
- **`FAILED` en rojo**: ese punto no funciona. Mira la sección
  [Si algo falla](#si-algo-falla).

---

## Paso 6 — Comprobar cuando quieras

1. Abre `C:\fortaleza`.
2. Haz doble clic en **`COMPROBAR.cmd`**.
3. Acepta el aviso de administrador.
4. Al final verás un resumen:

   ```text
   ✅ TODAS LAS PRUEBAS SUPERADAS (17/17): FORTALEZA 100% ACTIVA
   ```

   o

   ```text
   ✅ NÚCLEO CRÍTICO PROTEGIDO (15/17 servicios OK, 2 avisos...)
   ```

La segunda frase no es un error: significa que el DNS y Tor funcionan y que
solo falta un módulo opcional.

### Comprobaciones manuales rápidas

Abre el panel en <http://127.0.0.1:3000>. En **Filtros** deben aparecer las
listas activas. En **Configuración → DNS** el modo debe ser `parallel` y los
upstreams deben empezar por `https://`.

Si quieres ver el bloqueo en acción, abre una consola y ejecuta:

```powershell
nslookup doubleclick.net 127.0.0.1
```

La respuesta debe ser `0.0.0.0` o un error de dominio inexistente. Si devuelve
una IP pública, las listas aún no han cargado o AdGuard no está usando la
configuración correcta.

---

## Si algo falla

### “Windows protegió tu PC” o “Windows ha bloqueado esta aplicación”

Pulsa **Más información → Ejecutar de todas formas**. Ocurre porque los
archivos se descargan de GitHub y no llevan una firma comercial de pago.

### “No se puede cargar el archivo … porque la ejecución de scripts está deshabilitada”

No ejecutes los `.ps1` haciendo doble clic. Usa siempre `INSTALAR.cmd`,
`COMPROBAR.cmd` o `DESINSTALAR.cmd`: ellos se encargan de la política de
ejecución sin cambiar la configuración del sistema.

### El instalador dice que falta `C:\AdGuardHome\AdGuardHome.yaml`

Todavía no has completado el asistente de AdGuard Home. Vuelve al
[Paso 2](#paso-2--instalar-adguard-home-y-crear-tu-usuario), crea el usuario y
cierra la ventana negra. Después repite `INSTALAR.cmd`.

### “El puerto 53 está ocupado” o AdGuard no arranca

`SharedAccess` (ICS) de Windows reserva el puerto 53. `INSTALAR.cmd` lo
desactiva, pero si algo lo reactiva (una actualización, el punto de acceso
móvil), vuelve a ejecutar `INSTALAR.cmd`. Es seguro repetirlo.

### Me he quedado sin Internet después de instalar

1. Espera 30 segundos: los servicios pueden estar arrancando.
2. Ejecuta `COMPROBAR.cmd` y mira si AdGuard Home y Tor están en verde.
3. Si sigue sin funcionar, abre `C:\fortaleza` y ejecuta esta orden en una
   consola de PowerShell **como administrador**:

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\fortaleza\scripts\failsafe-dns.ps1 -Restore
   ```

   Eso devuelve el DNS a automático y desactiva las reglas anti-fuga. Es la
   red de seguridad: no borra nada.

### El panel no abre en `http://127.0.0.1:3000`

Abre una consola de PowerShell **como administrador** y comprueba el servicio:

```powershell
Get-Service AdGuardHome
Start-Service AdGuardHome
```

Si no existe el servicio, vuelve a ejecutar `INSTALAR.cmd`.

### El centinela sale en AVISO y el panel funciona

Lo más probable es que la contraseña guardada en `config\.env` no coincida con
la del panel. Abre `C:\AdGuardHome\config\.env` con el **Bloc de notas**,
corrige la línea `ADGUARD_PASSWORD=` y guarda. Después reinicia el equipo para
que el watchdog arranque el centinela con la contraseña correcta.

### GoodbyeDPI no se instala o el antivirus lo bloquea

Es opcional. Puedes omitirlo: el DNS y Tor seguirán funcionando. Si la
comprobación marca el punto 7 en rojo, es esperado.

### El punto de acceso móvil de Windows ya no funciona

Es una consecuencia conocida de desactivar `SharedAccess`. El tethering por USB
sí funciona. Si necesitas el punto de acceso móvil, ejecuta
`DESINSTALAR.cmd` y vuelve a habilitar el servicio con:

```powershell
Set-Service SharedAccess -StartupType Manual
Start-Service SharedAccess
```

### Quiero volver atrás

1. Abre `C:\fortaleza`.
2. Doble clic en **`DESINSTALAR.cmd`**.
3. Acepta el aviso de administrador y confirma.

Deshace las tareas, las reglas de firewall, el DNS y las políticas de los
navegadores. **No desinstala** AdGuard Home, Tor ni GoodbyeDPI, y conserva tus
datos y registros. Si quieres borrarlos también, ejecuta desde PowerShell **como administrador**:

```powershell
powershell -ExecutionPolicy Bypass -File C:\fortaleza\scripts\uninstall_fortress.ps1 -RemoveData
```

---

## Preguntas frecuentes

### ¿Esto hace que toda mi navegación pase por Tor?

No. Tor se usa para las consultas DNS y para que AdGuard descargue sus listas
de bloqueo. Tu navegador sigue conectándose directamente a las webs. Para
navegar por Tor necesitas el Tor Browser, que es otro programa.

### ¿Por qué la primera página tarda un poco más?

Cada consulta que no está en caché cruza tres saltos de Tor (entre 200 y 800
ms). Después, la caché de AdGuard responde en 0 ms para los dominios
frecuentes.

### ¿Puedo usar el móvil o la Smart TV con esta protección?

Sí, pero esta guía configura solo el equipo donde se instala. Para toda la red
hay que abrir el DNS en la IP local y cambiar el DHCP del router; es un paso
avanzado y queda fuera de esta guía.

### ¿Qué es `config\.env` y por qué no debo compartirlo?

Es el archivo donde se guardan la contraseña del panel y, si la configuras, la
clave de Gemini. Cualquiera que lo lea puede controlar tu DNS. El instalador le
quita los permisos genéricos, pero no lo subas a GitHub ni lo pegues en un chat.

### ¿Qué modo de IA se instala?

En una instalación nueva, el instalador fácil usa `AI_MODE=off`: el centinela
solo aplica reglas locales y **no envía ningún dominio a Internet**. Si ya
tenías un `config\.env`, se conserva tu modo. Si quieres análisis con IA, edita
`C:\AdGuardHome\config\.env` y elige `aggregate` (solo sale un hash con sal) o
`full` (sale el dominio completo, solo para depurar). Después reinicia el equipo:
el watchdog arranca el centinela solo al arrancar Windows.

### ¿Puedo actualizar el repositorio sin perder la configuración?

Sí. Descarga el ZIP nuevo, descomprímelo en otra carpeta y copia solo los
archivos del repositorio que quieras actualizar (`scripts`, `launchers`,
`docs`). No copies encima de `C:\AdGuardHome\AdGuardHome.yaml` ni de
`C:\AdGuardHome\config\.env`: ahí están tus datos y credenciales. Después
ejecuta `INSTALAR.cmd` otra vez; conserva lo que ya existe.

---

## Archivos que crea el instalador

| Ruta | Qué es |
|---|---|
| `C:\AdGuardHome\AdGuardHome.yaml` | Configuración blindada de AdGuard Home. |
| `C:\AdGuardHome\config\.env` | Credenciales del panel y modo del centinela. |
| `C:\AdGuardHome\AdGuardHome.yaml.bak-...` | Copia de seguridad de tu configuración anterior. |
| `C:\AdGuardHome\watchdog.heartbeat` | Señal de vida del watchdog. |
| `C:\AdGuardHome\failsafe.log` | Registro de la red de seguridad DNS. |
| `C:\AdGuardHome\logs\` | Registros del centinela y del señuelo. |

No borres `config\.env` ni `AdGuardHome.yaml` si quieres conservar la
instalación.
