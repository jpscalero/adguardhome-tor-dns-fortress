' ============================================================================
' Lanza el Centinela AI en segundo plano delegando en start_ai_guard.cmd.
' Motivo: el lanzador anterior invocaba "node.exe" sin ruta y fallaba cuando lo
' ejecutaba el watchdog como SYSTEM (node no esta en su PATH). El .cmd resuelve
' el node portable de la fortaleza.
' ============================================================================
Option Explicit

Dim fso, sh, base, cmdPath, candidate

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

base = fso.GetParentFolderName(WScript.ScriptFullName)
cmdPath = ""

candidate = fso.BuildPath(base, "start_ai_guard.cmd")
If fso.FileExists(candidate) Then
    cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = fso.BuildPath(fso.BuildPath(base, ".."), "start_ai_guard.cmd")
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = fso.BuildPath(base, "launchers\start_ai_guard.cmd")
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = "C:\AdGuardHome\start_ai_guard.cmd"
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    WScript.Quit 2
End If

' 0 = ventana oculta, False = no esperar a que termine
sh.Run """" & cmdPath & """", 0, False
