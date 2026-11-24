' ============================================================================
' Lanza el generador de trafico senuelo en segundo plano delegando en
' start_decoy.cmd (rutas absolutas + node portable).
' ============================================================================
Option Explicit

Dim fso, sh, base, cmdPath, candidate

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

base = fso.GetParentFolderName(WScript.ScriptFullName)
cmdPath = ""

candidate = fso.BuildPath(base, "start_decoy.cmd")
If fso.FileExists(candidate) Then
    cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = fso.BuildPath(fso.BuildPath(base, ".."), "start_decoy.cmd")
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = fso.BuildPath(base, "launchers\start_decoy.cmd")
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    candidate = "C:\AdGuardHome\start_decoy.cmd"
    If fso.FileExists(candidate) Then cmdPath = candidate
End If

If cmdPath = "" Then
    WScript.Quit 2
End If

sh.Run """" & cmdPath & """", 0, False
