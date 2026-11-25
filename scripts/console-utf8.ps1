<#
.SYNOPSIS
    Fuerza la salida UTF-8 de la consola de la fortaleza.

.DESCRIPTION
    Windows PowerShell 5.1 escribe con la pagina de codigos OEM (850/437) cuando
    la consola no esta en UTF-8: "Tunel" se ve "T?nel" y el escudo sale "???".
    Este helper cambia solo la codificacion de salida del proceso actual; no
    toca la configuracion del sistema, del usuario ni del repositorio.

    Se carga con dot-sourcing desde los scripts interactivos:

        . (Join-Path $PSScriptRoot 'console-utf8.ps1')
#>

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {
    # Consola antigua sin soporte UTF-8: se conserva la codificacion por defecto.
}
