Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
baseDir = fso.GetParentFolderName(scriptDir)

target = fso.BuildPath(scriptDir, "decoy_dns.js")
If Not fso.FileExists(target) Then
    target = fso.BuildPath(fso.BuildPath(baseDir, "scripts"), "decoy_dns.js")
End If
If Not fso.FileExists(target) Then
    target = "C:\AdGuardHome\decoy_dns.js"
End If

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "node.exe """ & target & """", 0, False
