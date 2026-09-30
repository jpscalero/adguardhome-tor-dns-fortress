Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
baseDir = fso.GetParentFolderName(scriptDir)

target = fso.BuildPath(scriptDir, "watchdog.ps1")
If Not fso.FileExists(target) Then
    target = fso.BuildPath(fso.BuildPath(baseDir, "scripts"), "watchdog.ps1")
End If
If Not fso.FileExists(target) Then
    target = "C:\AdGuardHome\watchdog.ps1"
End If

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File """ & target & """", 0, False
