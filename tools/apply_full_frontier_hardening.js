const fs = require('fs');
const path = require('path');

const ADGUARD_DIR = process.env.FORTRESS_DIR || 'C:\\AdGuardHome';
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(ADGUARD_DIR, 'AdGuardHome.yaml');

if (!fs.existsSync(CONFIG_PATH)) {
  console.error(`❌ Error: Configuration file not found at ${CONFIG_PATH}`);
  process.exit(1);
}

let yaml = fs.readFileSync(CONFIG_PATH, 'utf8');

const certPath = path.join(ADGUARD_DIR, 'cert.pem').replace(/\\/g, '\\\\');
const keyPath = path.join(ADGUARD_DIR, 'key.pem').replace(/\\/g, '\\\\');

// 1. Enable Local TLS (DoH on 443, DoT on 853, DoQ on 853)
const newTls = [
  'tls:',
  '  enabled: true',
  '  server_name: "adguard.home"',
  '  force_https: false',
  '  port_https: 443',
  '  port_dns_over_tls: 853',
  '  port_dns_over_quic: 853',
  '  port_dnscrypt: 0',
  '  dnscrypt_config_file: ""',
  '  certificate_chain: ""',
  '  private_key: ""',
  `  certificate_path: "${certPath}"`,
  `  private_key_path: "${keyPath}"`,
  '  strict_sni_check: false'
].join('\n');
yaml = yaml.replace(/tls:[\s\S]*?querylog:/, newTls + '\nquerylog:');

// 2. Amnesic Querylog (1h interval, 500 items max in RAM)
yaml = yaml.replace(/interval: 6h/, 'interval: 1h');
yaml = yaml.replace(/size_memory: 2000/, 'size_memory: 500');

// 3. Update bootstrap_dns to use 9.9.9.9 and 1.1.1.2 (safe against DoH port 443 blocks)
const newBootstrap = [
  'bootstrap_dns:',
  '    - https://9.9.9.9/dns-query',
  '    - https://1.1.1.2/dns-query',
  '    - tls://9.9.9.9',
  '    - tls://1.1.1.2',
  '    - 9.9.9.9',
  '    - 149.112.112.112',
  '    - 1.1.1.2'
].join('\n');
yaml = yaml.replace(/bootstrap_dns:[\s\S]*?fallback_dns:/, newBootstrap + '\n  fallback_dns:');

// 4. Block High-Risk Malicious TLDs in user_rules
const highRiskTldRules = `  # Bloqueo de TLDs de Alto Riesgo (Phishing, Malware, Spoofing)
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
`;
yaml = yaml.replace(/^user_rules:\r?\n/m, `user_rules:\n${highRiskTldRules}`);

fs.writeFileSync(CONFIG_PATH, yaml, 'utf8');
console.log(`AdGuardHome.yaml at ${CONFIG_PATH} updated with Local TLS, Amnesic Querylog, and High-Risk TLD blocks.`);
