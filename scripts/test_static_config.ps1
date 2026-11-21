$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\AdGuardHome.template.yaml"
$installerPath = Join-Path $PSScriptRoot "install_fortress.ps1"
$watchdogPath = Join-Path $PSScriptRoot "watchdog.ps1"
$healthTestPath = Join-Path $PSScriptRoot "test_fortress.ps1"

function Assert-Contains {
    param([string]$Name, [string]$Text, [string]$Pattern)
    if ($Text -notmatch $Pattern) { throw "[FAIL] $Name" }
    Write-Host "[PASS] $Name"
}

function Assert-NotContains {
    param([string]$Name, [string]$Text, [string]$Pattern)
    if ($Text -match $Pattern) { throw "[FAIL] $Name" }
    Write-Host "[PASS] $Name"
}

$config = Get-Content $configPath -Raw
$installer = Get-Content $installerPath -Raw
$watchdog = Get-Content $watchdogPath -Raw
$healthTest = Get-Content $healthTestPath -Raw

Assert-Contains "Admin panel binds to loopback" $config '(?m)^\s*address:\s*127\.0\.0\.1:3000\s*$'
Assert-Contains "Remote TLS endpoints are disabled until a certificate is configured" $config '(?ms)^tls:\s*\n\s*enabled:\s*false\s*\n.*?port_https:\s*0\s*\n\s*port_dns_over_tls:\s*0\s*\n\s*port_dns_over_quic:\s*0'
Assert-Contains "DNS upstream is Tor DNSPort only" $config '(?ms)^\s*upstream_dns:\s*\n\s*-\s*127\.0\.0\.1:5350\s*\n'
Assert-Contains "Bootstrap DNS is empty" $config '(?m)^\s*bootstrap_dns:\s*\[\]\s*$'
Assert-Contains "Fallback DNS is empty" $config '(?m)^\s*fallback_dns:\s*\[\]\s*$'
Assert-NotContains "No public DNS or fake SOCKS upstream syntax" $config '(?m)^\s*-\s*(?:\[https?://|(?:9\.9\.9\.9|1\.1\.1\.1|1\.1\.1\.2|149\.112\.112\.112))|\] socks5://'

Assert-NotContains "Installer does not terminate processes or alter SharedAccess" $installer '(?i)Stop-Process|Stop-Service\s+SharedAccess|Set-ItemProperty.*SharedAccess|sc\.exe\s+(?:config|failure|triggerinfo)\s+SharedAccess'
Assert-NotContains "Watchdog does not stop SharedAccess or kill svchost" $watchdog '(?i)Stop-Service\s+SharedAccess|Set-ItemProperty.*SharedAccess|Stop-Process.*svchost|ProcessName\s+-eq\s+"svchost"'
Assert-NotContains "Watchdog does not bind DNS to a changing LAN address" $watchdog 'Get-NetIPAddress|bind_hosts.*activeIp|DYNAMIC NETWORK INTERFACE'
Assert-Contains "Tor test calls the official exit-check endpoint" $healthTest 'check\.torproject\.org/api/ip'
Assert-Contains "Tor test requires IsTor=true" $healthTest 'IsTor\s+-ne\s+\$true'
Assert-Contains "Tor test validates the returned exit IP" $healthTest 'IPAddress\]::TryParse'
Assert-Contains "Health failures set a failing process exit code" $healthTest '(?s)if \(\$failed -gt 0\)\s*\{\s*exit 1\s*\}'
Assert-Contains "Installer requires a valid bcrypt admin hash" $installer 'AdminPasswordHash -notmatch.*\$2\[aby\]'
Assert-Contains "Installer substitutes the template's admin hash marker" $installer '\.Replace\(\$adminHashPlaceholder,\s*\$AdminPasswordHash\)'
Assert-Contains "Installer rejects an unreplaced admin hash marker" $installer '(?s)Contains\(\$adminHashPlaceholder\).*Write-Error'

$parseErrors = @()
Get-ChildItem -Path $repoRoot -Filter "*.ps1" -Recurse | ForEach-Object {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    foreach ($errorItem in $errors) { $parseErrors += "$($_.FullName): $($errorItem.Message)" }
}
if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }
Write-Host "[PASS] All PowerShell files parse successfully"
