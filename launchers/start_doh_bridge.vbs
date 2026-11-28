Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
baseDir = fso.GetParentFolderName(scriptDir)

target = fso.BuildPath(scriptDir, "doh-tor-bridge.js")
If Not fso.FileExists(target) Then
    target = fso.BuildPath(fso.BuildPath(baseDir, "scripts"), "doh-tor-bridge.js")
End If
If Not fso.FileExists(target) Then
    target = "C:\AdGuardHome\doh-tor-bridge.js"
End If

nodeExe = fso.BuildPath(fso.BuildPath(baseDir, "node"), "node.exe")
If Not fso.FileExists(nodeExe) Then
    nodeExe = "node.exe"
End If

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """" & nodeExe & """ """ & target & """", 0, False
