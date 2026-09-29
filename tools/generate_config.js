const fs = require('fs');
const path = require('path');

const originalFile = 'C:\\AdGuardHome\\AdGuardHome.yaml';
const original = fs.readFileSync(originalFile, 'utf8');
const lines = original.split(/\r?\n/);

// Lines 1-21: http, users, auth, etc.
const head = lines.slice(0, 21).join('\n');

const newDns = `dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: true
  ratelimit: 0
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - https://dns.mullvad.net/dns-query
    - tls://dns.mullvad.net
    - tls://dns.quad9.net
    - https://dns.quad9.net/dns-query
    - quic://dns.adguard-dns.com
    - https://freedns.controld.com/p2
    - tls://p2.freedns.controld.com
    - https://security.cloudflare-dns.com/dns-query
    - tls://security.cloudflare-dns.com
    - sdns://AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
    - 149.112.112.112
    - 1.0.0.1
  fallback_dns:
    - 9.9.9.9
    - 1.1.1.2
    - 149.112.112.112
  upstream_mode: load_balance
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
    - version.server
    - authors.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_enabled: true
  cache_size: 33554432
  cache_ttl_min: 300
  cache_ttl_max: 86400
  cache_optimistic: true
  cache_optimistic_answer_ttl: 60s
  cache_optimistic_max_age: 24h
  bogus_nxdomain: []
  aaaa_disabled: true
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 5s
  private_networks:
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 169.254.0.0/16
    - 100.64.0.0/10
    - fd00::/8
    - fe80::/10
    - ::1/128
  use_private_ptr_resolvers: true
  local_ptr_upstreams:
    - 192.168.0.1
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: true
  serve_plain_dns: true
  hostsfile_enabled: true
  pending_requests:
    enabled: true`;

// tls, querylog, statistics are lines 96 to 123 (index 95 to 123 in 0-indexed)
const middle = lines.slice(95, 123).join('\n');

const newFilters = `filters:
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.plus.txt
    name: HaGeZi Pro++ (Ultimate Protection)
    id: 1788277954
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt
    name: HaGeZi Encrypted DNS/VPN/TOR/Proxy Bypass
    id: 1788277986
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt
    name: HaGeZi Threat Intelligence Feeds
    id: 1788277988
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt
    name: HaGeZi Dynamic DNS (DynDNS) Blocklist
    id: 1788278001
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt
    name: HaGeZi Badware Hoster Blocklist
    id: 1788277985
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt
    name: HaGeZi The World Most Abused TLDs
    id: 1788277987
  - enabled: true
    url: https://threatfox.abuse.ch/downloads/hostfile/
    name: ThreatFox Malware & Botnet C2 (abuse.ch)
    id: 1788278002
  - enabled: true
    url: https://urlhaus.abuse.ch/downloads/hostfile/
    name: Malicious URL Blocklist (URLhaus)
    id: 4
  - enabled: true
    url: https://phishing.army/download/phishing_army_blocklist_extended.txt
    name: Phishing Army Extended
    id: 6
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt
    name: Phishing URL Blocklist (PhishTank and OpenPhish)
    id: 1788277983
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt
    name: Dandelion Sprout Anti-Malware List
    id: 1788277984
  - enabled: true
    url: https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
    name: WindowsSpyBlocker (Telemetry & Spy)
    id: 12
  - enabled: true
    url: https://big.oisd.nl
    name: OISD Big (Zero False-Positive Protection)
    id: 1788278003
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt
    name: AdGuard Tracking Protection Filter
    id: 3
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt
    name: uBlock₀ filters – Badware risks
    id: 1788277996
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt
    name: ShadowWhisperer Malware List
    id: 1788277993
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt
    name: Stalkerware Indicators List
    id: 1788277994
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
    name: The Big List of Hacked Malware Web Sites
    id: 1788277995
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt
    name: Scam Blocklist by DurableNapkin
    id: 1788277992
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt
    name: NoCoin Filter List (Anti-Cryptomining)
    id: 1788277990
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_68.txt
    name: HaGeZi URL Shortener Blocklist
    id: 1788277989
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt
    name: HaGeZi Allowlist Referral
    id: 1788277955
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt
    name: HaGeZi Apple Tracker Blocklist
    id: 1788277957
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt
    name: HaGeZi Gambling Blocklist
    id: 1788277958
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt
    name: HaGeZi OPPO & Realme Tracker Blocklist
    id: 1788277959
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt
    name: HaGeZi Samsung Tracker Blocklist
    id: 1788277960
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt
    name: HaGeZi Vivo Tracker Blocklist
    id: 1788277961
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt
    name: HaGeZi Windows/Office Tracker Blocklist
    id: 1788277962
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt
    name: HaGeZi Xiaomi Tracker Blocklist
    id: 1788277963
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt
    name: Perflyst and Dandelion Sprout Smart-TV Blocklist
    id: 1788277965`;

const whitelist = 'whitelist_filters: []';

const newUserRules = `user_rules:
  - '@@||steamrip.com^'
  - '@@||pivigames.blog^'
  - '@@||elenemigos.com^'
  - '@@||zonaleros.com^'
  - '@@||filekeeper.net^'
  - '@@||router.parklogic.com^'
  - '@@||accounts.google.com^$important'
  - '@@||oauth2.googleapis.com^$important'
  - '@@||www.gstatic.com^$important'
  - '@@||gstatic.com^$important'
  - '@@||www.google.com^$important'
  - '@@||google.com^$important'
  - '@@||googleusercontent.com^$important'
  - '@@||googleapis.com^$important'
  - '@@||daily-cloudcode-pa.googleapis.com^$important'
  - '@@||antigravity.google^$important'
  - '@@||gemini.google.com^$important'
  - '||use-application-dns.net^$dnsrewrite=NXDOMAIN'
  - '||mask.icloud.com^$dnsrewrite=NXDOMAIN'
  - '||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN'
  - '||events.data.microsoft.com^'
  - '||mobile.events.data.microsoft.com^'
  - '||self.events.data.microsoft.com^'
  - '||v10.events.data.microsoft.com^'
  - '||v20.events.data.microsoft.com^'
  - '||browser.events.data.microsoft.com^'
  - '||watson.telemetry.microsoft.com^'
  - '||activity.windows.com^'
  - '||telemetry.microsoft.com^'
  - '||diagnostics.support.microsoft.com^'
  - '||settings-win.data.microsoft.com^'
  - '||feedback.windows.com^'
  - '||cortana.ai^'
  - '||search.msn.com^'
  - '||nexusrules.office.net^'
  - '||telecommand.telemetry.microsoft.com^'
  - '||telecommand.telemetry.microsoft.com.nsatc.net^'
  - '||onesettings-db5p.metron.live.com.nsatc.net^'
  - '||msedge.api.cdp.microsoft.com^'
  - '||nf.smartscreen.microsoft.com^'
  - '||nimbus.bitdefender.net^'
  - '||catch-nimbus.bitdefender.net^$important'`;

// dhcp to end is line 362 (index 361) to end
const tail = lines.slice(361).join('\n');

const fullNewConfig = [head, newDns, middle, newFilters, whitelist, newUserRules, tail].join('\n');
fs.writeFileSync('C:\\AdGuardHome\\AdGuardHome_new.yaml', fullNewConfig, 'utf8');
console.log('Successfully written C:\\AdGuardHome\\AdGuardHome_new.yaml');
