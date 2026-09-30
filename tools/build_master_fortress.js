const fs = require('fs');
const path = require('path');

const ADGUARD_DIR = process.env.FORTRESS_DIR || 'C:\\AdGuardHome';
let originalFile = process.env.CONFIG_SOURCE || process.argv[2] || path.join(ADGUARD_DIR, 'AdGuardHome.yaml.bak');
const outputFile = process.env.CONFIG_TARGET || process.argv[3] || path.join(ADGUARD_DIR, 'AdGuardHome_fortress.yaml');

if (!fs.existsSync(originalFile)) {
  const fallback = path.join(ADGUARD_DIR, 'AdGuardHome.yaml');
  if (fs.existsSync(fallback)) {
    originalFile = fallback;
  } else {
    console.error(`❌ Error: Source file not found at ${originalFile}`);
    console.error('Please specify a valid source config file via FORTRESS_DIR, CONFIG_SOURCE, or CLI argument.');
    process.exit(1);
  }
}

const original = fs.readFileSync(originalFile, 'utf8');
const lines = original.split(/\r?\n/);

// Lines 1-21: http, users, auth, etc.
const head = `http:
  pprof:
    port: 6060
    enabled: false
  doh:
    routes:
      - GET /dns-query
      - POST /dns-query
      - GET /dns-query/{ClientID}
      - POST /dns-query/{ClientID}
    insecure_enabled: false
  address: 0.0.0.0:80
  session_ttl: 24h
users:
  - name: __YOUR_USERNAME__
    password: __YOUR_BCRYPT_HASH__
auth_attempts: 3
block_auth_min: 30
http_proxy: ""
language: es
theme: dark`;

const newDns = `dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: true
  ratelimit: 40
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist:
    - 127.0.0.1
    - __YOUR_LOCAL_IP__
    # Add additional trusted LAN IPs below:
    # - 192.168.x.x
  refuse_any: true
  upstream_dns:
    - https://base.dns.mullvad.net/dns-query
    - tls://base.dns.mullvad.net
    - quic://dns.quad9.net
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
    - https://9.9.9.9/dns-query
    - https://1.1.1.2/dns-query
    - tls://9.9.9.9
    - tls://1.1.1.2
    - 9.9.9.9
    - 149.112.112.112
    - 1.1.1.2
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
    - localhost.bind
    - whoami.akamai.net
    - whoami.ultradns.net
    - porttest.dns-oarc.net
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
  bogus_nxdomain:
    - 92.242.140.21
    - 92.242.132.16
    - 92.242.132.24
    - 212.166.190.241
    - 212.166.190.242
    - 80.58.61.250
    - 80.58.61.254
    - 62.36.225.150
    - 146.112.61.106
    - 8.15.7.117
    - 8.15.7.118
    - 63.251.179.17
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
    - 0.0.0.0/8
    - 192.0.0.0/24
    - 198.18.0.0/15
    - 240.0.0.0/4
    - fd00::/8
    - fe80::/10
    - ::1/128
  use_private_ptr_resolvers: true
  local_ptr_upstreams:
    - __YOUR_GATEWAY_IP__
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: true
  serve_plain_dns: true
  hostsfile_enabled: true
  pending_requests:
    enabled: true`;

const newTls = `tls:
  enabled: true
  server_name: "adguard.home"
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  certificate_chain: ""
  private_key: ""
  certificate_path: "C:\\\\AdGuardHome\\\\cert.pem"
  private_key_path: "C:\\\\AdGuardHome\\\\key.pem"
  strict_sni_check: false`;

const newQuerylog = `querylog:
  dir_path: ""
  ignored:
    - arpa
    - local
    - home
    - lan
    - 0.in-addr.arpa
    - 127.in-addr.arpa
    - 254.169.in-addr.arpa
    - 2.0.192.in-addr.arpa
    - 100.51.198.in-addr.arpa
    - 113.0.203.in-addr.arpa
    - 255.255.255.255.in-addr.arpa
  interval: 1h
  size_memory: 500
  enabled: true
  ignored_enabled: true
  file_enabled: false
statistics:
  dir_path: ""
  ignored: []
  interval: 7d
  enabled: true
  ignored_enabled: false`;

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
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt
    name: HaGeZi Fake, Scam and Typosquatting
    id: 1788278020
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winstuff.txt
    name: HaGeZi Windows Native Spyware & Telemetry
    id: 1788278021
  - enabled: true
    url: https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt
    name: Blocklist.site Ransomware Protection
    id: 1788278010
  - enabled: true
    url: https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt
    name: Blocklist.site Fraud & Scam Protection
    id: 1788278011
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt
    name: HaGeZi Popup and Adware Blocklist
    id: 1788278012
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
    url: https://someonewhocares.org/hosts/hosts
    name: Dan Pollock Someonewhocares Hosts
    id: 1788278022
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
  # ==========================================
  # EXCEPCIONES Y SITIOS PERMITIDOS
  # ==========================================
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

  # ==========================================
  # CANARIOS ANTI-BYPASS DE NAVEGADORES Y APPLE
  # ==========================================
  - '||use-application-dns.net^$dnsrewrite=NXDOMAIN'
  - '||mask.icloud.com^$dnsrewrite=NXDOMAIN'
  - '||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN'

  # ==========================================
  # BLOQUEO DE TLDS DE ALTO RIESGO (PHISHING Y MALWARE)
  # ==========================================
  - '||*.zip^$deny'
  - '||*.mov^$deny'
  - '||*.country^$deny'
  - '||*.kim^$deny'
  - '||*.science^$deny'
  - '||*.gdn^$deny'
  - '||*.click^$deny'
  - '||*.link^$deny'
  - '||*.work^$deny'
  - '||*.men^$deny'
  - '||*.stream^$deny'
  - '||*.mom^$deny'

  # ==========================================
  # TELEMETRÍA Y ESPIONAJE DE WINDOWS 10 / 11
  # ==========================================
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
  - '||smartscreen-prod.microsoft.com^'
  - '||edge.activity.windows.com^'

  # ==========================================
  # TELEMETRÍA DE HARDWARE Y APLICACIONES
  # ==========================================
  - '||telemetry.nvidia.com^'
  - '||gfe.geforce.com^'
  - '||telemetry.gfe.nvidia.com^'
  - '||telemetry.intel.com^'
  - '||telemetry.hp.com^'
  - '||hp-telemetry.com^'
  - '||science.discord.com^'
  - '||tracking.discord.com^'
  - '||crashdump.spotify.com^'

  # ==========================================
  # ANTI-FINGERPRINTING & WEBRTC LEAKS
  # ==========================================
  - '||floc.google.com^'
  - '||fledge.google.com^'
  - '||topics.google.com^'
  - '||adservice.google.com^'
  - '||stunprotocol.org^$dnsrewrite=NXDOMAIN'
  - '||stun.counterpath.net^$dnsrewrite=NXDOMAIN'
  - '||stun.sipgate.net^$dnsrewrite=NXDOMAIN'

  # ==========================================
  # ANTI-CRIPTOMINADO Y BALIZAS
  # ==========================================
  - '||coinhive.com^'
  - '||coin-hive.com^'
  - '||crypto-loot.com^'
  - '||ping.chartbeat.net^'
  - '||beacon.krxd.net^'
  - '||beacon.scorecardresearch.com^'
  - '||sb.scorecardresearch.com^'

  # ==========================================
  # SMART TV & STREAMING TELEMETRÍA
  # ==========================================
  - '||lgtvcommon.com^'
  - '||aic-common.lgtvcommon.com^'
  - '||cooper.logs.roku.com^'
  - '||device-metrics-us.amazon.com^'
  - '||device-metrics-us-2.amazon.com^'

  # ==========================================
  # BITDEFENDER
  # ==========================================
  - '||nimbus.bitdefender.net^'
  - '||catch-nimbus.bitdefender.net^$important'`;

// Tail detection: dynamically find top-level key after user_rules/filters (dhcp:, clients:, etc.)
let tailIndex = -1;
for (let i = 21; i < lines.length; i++) {
  const line = lines[i];
  if (/^[a-z_]+:/.test(line) && (line.startsWith('dhcp:') || line.startsWith('clients:'))) {
    tailIndex = i;
    break;
  }
}
let tail = tailIndex !== -1 ? lines.slice(tailIndex).join('\n') : (lines.length > 361 ? lines.slice(361).join('\n') : '');

// Update rewrites in tail if custom IP is provided
const localIp = process.env.LOCAL_IP || '__YOUR_LOCAL_IP__';
tail = tail.replaceAll('192.168.0.125', localIp);
// Update blocked_response_ttl: 60 to 1800
tail = tail.replace(/blocked_response_ttl: 60/, 'blocked_response_ttl: 1800');

const fullFortress = [head, newDns, newTls, newQuerylog, newFilters, whitelist, newUserRules, tail].join('\n');

// Basic structural YAML validation
const requiredKeys = ['http:', 'dns:', 'tls:', 'querylog:', 'filters:', 'user_rules:'];
const missingKeys = requiredKeys.filter(k => !fullFortress.includes(k));
if (missingKeys.length > 0) {
  console.error(`❌ YAML Validation Error: Resulting config is missing essential sections: ${missingKeys.join(', ')}`);
  process.exit(1);
}

fs.writeFileSync(outputFile, fullFortress, 'utf8');
console.log(`Successfully written fortress configuration to ${outputFile}`);
