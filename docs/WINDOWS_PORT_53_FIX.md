# 🛠️ Solución Definitiva al Conflicto del Puerto 53 en Windows 11 / 10

## El Problema
Al instalar un servidor DNS local como **AdGuard Home**, **Pi-hole** o **Unbound** en Windows 11 o Windows 10, es muy frecuente que el servidor no pueda escuchar en `0.0.0.0:53` o `127.0.0.1:53` UDP, o que las peticiones se descarten en silencio produciendo errores en el navegador del tipo:
```text
DNS_PROBE_POSSIBLE
DNS_PROBE_FINISHED_BAD_CONFIG
```

### ¿Por qué ocurre?
1. **El servicio `SharedAccess` (Conexión compartida a Internet / ICS)**:
   * Windows 11 incluye un proxy DNS integrado dentro de la biblioteca `ipnathlp.dll` (Internet Protocol NAT Helper).
   * Este servicio se apropia de `0.0.0.0:53 UDP` con la bandera `SO_EXCLUSIVEADDRUSE`.
2. **Reinicio persistente por Hyper-V / WSL / HNS**:
   * Incluso si deshabilitas el servicio con `sc config SharedAccess start= disabled`, el **Servicio de Red de Host (`hns`)** o el conmutador por defecto de Hyper-V (`vEthernet Default Switch`) tienen desencadenadores de eventos RPC que reactivan automáticamente `SharedAccess` cambiándolo de nuevo a `DEMAND_START`.
3. **El conflicto de sockets en Windows**:
   * Cuando `svchost.exe` tiene reservado `0.0.0.0:53`, ninguna otra aplicación puede vincularse a `127.0.0.1:53` en IPv4.
   * AdGuard Home se ve forzado a escuchar únicamente en `[::]:53` (IPv6), dejando a todas las aplicaciones y navegadores IPv4 sin resolución DNS o atrapadas en el proxy arcaico de ICS.

---

## La Solución Técnica Aplicada (No Destructiva)

### 1. Desactivación nativa del Proxy DNS en `ipnathlp.dll`
Mediante los parámetros del registro de Windows que gobiernan el listener DNS de ICS, se desactiva el subcomponente DNS sin alterar los binarios ni drivers del sistema:
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'IcsDnsEnabled' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'EnableDNS' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'EnableDNSMcast' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'DnsDoneNotification' -Value 1 -Type DWord
```

### 2. Eliminación de Desencadenadores RPC
Para evitar que eventos de red o Hyper-V reactiven el servicio:
```cmd
sc.exe triggerinfo SharedAccess delete
sc.exe failure SharedAccess reset= 0 actions= ""
sc.exe config SharedAccess start= disabled
```

### 3. Asignación Explícita en AdGuard Home (`AdGuardHome.yaml`)
En lugar de `0.0.0.0`, se configuran las interfaces explícitas:
```yaml
dns:
  bind_hosts:
    - 127.0.0.1
    - '::1'
  port: 53
```

### 4. Verificación
Comprobar que el puerto 53 pertenece en exclusiva a `AdGuardHome.exe`:
```powershell
Get-NetUDPEndpoint -LocalPort 53 | Select-Object LocalAddress, LocalPort, OwningProcess, @{N='Process'; E={(Get-Process -Id $_.OwningProcess).ProcessName}}
```
Resultado esperado:
```text
LocalAddress LocalPort OwningProcess Process
------------ --------- ------------- -------
127.0.0.1           53          3628 AdGuardHome
::1                 53          3628 AdGuardHome
```

---

## 🔄 Reversibilidad y Restauración del Sistema

Si en algún momento necesitas revertir estos cambios para utilizar la función nativa de Windows de "Zona con cobertura inalámbrica móvil" o compartir internet con otros adaptadores:

### Restaurar Parámetros de SharedAccess:
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'IcsDnsEnabled' -Value 1 -Type DWord
sc.exe config SharedAccess start= demand
```

### Restauración de `ServiceDll` (si fue modificado en versiones anteriores):
En versiones tempranas de esta guía se mencionaba cambiar `ServiceDll` por `ipnathlp.dll.disabled`. **Esta práctica ha sido desaconsejada y eliminada del instalador oficial**, ya que es innecesaria una vez configurado `IcsDnsEnabled=0`. Si tu sistema fue afectado previamente, puedes restaurar el valor original ejecutando en PowerShell como Administrador:
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -Name 'ServiceDll' -Value '%SystemRoot%\System32\ipnathlp.dll' -Type ExpandString
```
