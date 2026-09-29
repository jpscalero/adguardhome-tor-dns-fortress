const fs = require('fs');

const CONFIG_PATH = 'C:\\AdGuardHome\\AdGuardHome.yaml';
let yaml = fs.readFileSync(CONFIG_PATH, 'utf8');

// 1. Add Quad9 DoQ to upstream_dns if not present
if (!yaml.includes('quic://dns.quad9.net')) {
  yaml = yaml.replace(
    'quic://dns.adguard-dns.com',
    'quic://dns.adguard-dns.com\n    - quic://dns.quad9.net'
  );
}

// 2. Bogus NXDOMAIN Protection (ISP DNS Hijacking Protection)
const bogusIps = [
  'bogus_nxdomain:',
  '    - 92.242.140.21',
  '    - 92.242.132.16',
  '    - 92.242.132.24',
  '    - 212.166.190.241',
  '    - 212.166.190.242',
  '    - 80.58.61.250',
  '    - 80.58.61.254',
  '    - 62.36.225.150',
  '    - 146.112.61.106',
  '    - 8.15.7.117',
  '    - 8.15.7.118',
  '    - 63.251.179.17'
].join('\n');
yaml = yaml.replace(/bogus_nxdomain:[\s\S]*?aaaa_disabled:/, bogusIps + '\n  aaaa_disabled:');

// 3. Blocked Response TTL to 1800 (30 mins) to prevent tracker hammering
yaml = yaml.replace(/blocked_response_ttl: 60/, 'blocked_response_ttl: 1800');

// 4. Querylog retention to 6h and size_memory to 2000
yaml = yaml.replace(/interval: 12h/, 'interval: 6h');
yaml = yaml.replace(/size_memory: 5000/, 'size_memory: 2000');

// 5. Expand ignored domains in querylog
const newIgnored = [
  'ignored:',
  '    - arpa',
  '    - local',
  '    - home',
  '    - lan',
  '    - 0.in-addr.arpa',
  '    - 127.in-addr.arpa',
  '    - 254.169.in-addr.arpa',
  '    - 2.0.192.in-addr.arpa',
  '    - 100.51.198.in-addr.arpa',
  '    - 113.0.203.in-addr.arpa',
  '    - 255.255.255.255.in-addr.arpa'
].join('\n');
yaml = yaml.replace(/ignored:[\s\S]*?interval: 6h/, newIgnored + '\n  interval: 6h');

// 6. Additional Security & Anti-Phishing Filter Lists
const extraFilters = `  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt
    name: HaGeZi Fake, Scam & Typosquatting Blocklist
    id: 1788278020
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winstuff.txt
    name: HaGeZi Windows Native Spyware & Telemetry
    id: 1788278021
  - enabled: true
    url: https://someonewhocares.org/hosts/hosts
    name: Dan Pollock Someonewhocares Hosts
    id: 1788278022
`;
yaml = yaml.replace(/^filters:\r?\n/m, `filters:\n${extraFilters}`);

// 7. Advanced Anti-Fingerprinting & Tracking Rules
const extraUserRules = `  # Anti-FLoC / Topics API Browser Tracking
  - '||floc.google.com^'
  - '||fledge.google.com^'
  - '||topics.google.com^'
  - '||adservice.google.com^'
  # Anti-Smart TV & Streaming Telemetry
  - '||lgtvcommon.com^'
  - '||aic-common.lgtvcommon.com^'
  - '||cooper.logs.roku.com^'
  - '||device-metrics-us.amazon.com^'
  - '||device-metrics-us-2.amazon.com^'
  # Anti-Beaconing & In-Browser Cryptomining
  - '||ping.chartbeat.net^'
  - '||beacon.krxd.net^'
  - '||beacon.scorecardresearch.com^'
  - '||sb.scorecardresearch.com^'
  - '||coinhive.com^'
  - '||coin-hive.com^'
  - '||crypto-loot.com^'
`;
yaml = yaml.replace(/^user_rules:\r?\n/m, `user_rules:\n${extraUserRules}`);

fs.writeFileSync(CONFIG_PATH, yaml, 'utf8');
console.log('AdGuardHome.yaml successfully updated with maximum security and privacy.');
