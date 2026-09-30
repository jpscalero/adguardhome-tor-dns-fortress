const fs = require('fs');
const path = require('path');

const ADGUARD_DIR = process.env.FORTRESS_DIR || 'C:\\AdGuardHome';
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(ADGUARD_DIR, 'AdGuardHome.yaml');

if (!fs.existsSync(CONFIG_PATH)) {
  console.error(`❌ Error: Configuration file not found at ${CONFIG_PATH}`);
  process.exit(1);
}

let yaml = fs.readFileSync(CONFIG_PATH, 'utf8');

// 1. HTTP Dashboard Security Hardening
yaml = yaml.replace(/session_ttl: 30d/, 'session_ttl: 24h');
yaml = yaml.replace(/auth_attempts: 5/, 'auth_attempts: 3');
yaml = yaml.replace(/block_auth_min: 15/, 'block_auth_min: 30');

// 2. Upstream DNS Hardening (Use Mullvad Base with malware/ad filter)
yaml = yaml.replace(
  'https://dns.mullvad.net/dns-query',
  'https://base.dns.mullvad.net/dns-query'
);
yaml = yaml.replace(
  'tls://dns.mullvad.net',
  'tls://base.dns.mullvad.net'
);

// 3. DNS Reconnaissance & Probing Blocked Hosts
const newBlockedHosts = [
  'blocked_hosts:',
  '    - version.bind',
  '    - id.server',
  '    - hostname.bind',
  '    - version.server',
  '    - authors.bind',
  '    - localhost.bind',
  '    - whoami.akamai.net',
  '    - whoami.ultradns.net',
  '    - porttest.dns-oarc.net'
].join('\n');
yaml = yaml.replace(/blocked_hosts:[\s\S]*?trusted_proxies:/, newBlockedHosts + '\n  trusted_proxies:');

// 4. DNS Rebinding Full Range Protection
const newPrivateNetworks = [
  'private_networks:',
  '    - 127.0.0.0/8',
  '    - 10.0.0.0/8',
  '    - 172.16.0.0/12',
  '    - 192.168.0.0/16',
  '    - 169.254.0.0/16',
  '    - 100.64.0.0/10',
  '    - 0.0.0.0/8',
  '    - 192.0.0.0/24',
  '    - 198.18.0.0/15',
  '    - 240.0.0.0/4',
  '    - fd00::/8',
  '    - fe80::/10',
  '    - ::1/128'
].join('\n');
yaml = yaml.replace(/private_networks:[\s\S]*?use_private_ptr_resolvers:/, newPrivateNetworks + '\n  use_private_ptr_resolvers:');

// 5. Query Log Privacy & Anti-Forensics (12h retention, ignore LAN noisy domains)
yaml = yaml.replace(
  /querylog:[\s\S]*?statistics:/,
  `querylog:
  dir_path: ""
  ignored:
    - arpa
    - local
    - home
    - lan
  interval: 12h
  size_memory: 5000
  enabled: true
  ignored_enabled: true
  file_enabled: false
statistics:`
);

// 6. Additional Elite Security & Privacy Filters
const extraFilters = `  - enabled: true
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
`;

// Insert extra filters right after filters:
yaml = yaml.replace(/^filters:\r?\n/m, `filters:\n${extraFilters}`);

// 7. Advanced Privacy & Anti-Telemetry User Rules
const extraUserRules = `  # Anti-Telemetry Hardware & Software
  - '||telemetry.nvidia.com^'
  - '||gfe.geforce.com^'
  - '||telemetry.gfe.nvidia.com^'
  - '||telemetry.intel.com^'
  - '||telemetry.hp.com^'
  - '||hp-telemetry.com^'
  - '||science.discord.com^'
  - '||tracking.discord.com^'
  - '||crashdump.spotify.com^'
  # Anti-WebRTC Silent IP Leak Stun Servers
  - '||stunprotocol.org^$dnsrewrite=NXDOMAIN'
  - '||stun.counterpath.net^$dnsrewrite=NXDOMAIN'
  - '||stun.sipgate.net^$dnsrewrite=NXDOMAIN'
  # Anti-SmartScreen URL Harvest
  - '||smartscreen-prod.microsoft.com^'
  - '||edge.activity.windows.com^'
`;

yaml = yaml.replace(/^user_rules:\r?\n/m, `user_rules:\n${extraUserRules}`);

fs.writeFileSync(CONFIG_PATH, yaml, 'utf8');
console.log('AdGuardHome.yaml successfully enhanced with advanced security and privacy policies.');
