Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "node.exe ""C:\AdGuardHome\decoy_dns.js""", 0, False
