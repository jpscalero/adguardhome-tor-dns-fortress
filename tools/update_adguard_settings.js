const fs = require('fs');
const path = require('path');

const ADGUARD_DIR = process.env.FORTRESS_DIR || 'C:\\AdGuardHome';
const configPath = process.env.CONFIG_PATH || path.join(ADGUARD_DIR, 'AdGuardHome.yaml');

if (!fs.existsSync(configPath)) {
  console.error(`❌ Error: Configuration file not found at ${configPath}`);
  process.exit(1);
}

let yaml = fs.readFileSync(configPath, 'utf8');

// Update ratelimit and whitelist
yaml = yaml.replace(/ratelimit: 0/, 'ratelimit: 40');
yaml = yaml.replace(
  /ratelimit_whitelist: \[\]/,
  'ratelimit_whitelist:\n    - 127.0.0.1\n    # Add your trusted local client IPs here, e.g.:\n    # - 192.168.1.100'
);

// Update bootstrap_dns
const newBootstrap = [
  'bootstrap_dns:',
  '    - https://9.9.9.9/dns-query',
  '    - https://1.1.1.1/dns-query',
  '    - tls://9.9.9.9',
  '    - tls://1.1.1.1',
  '    - 9.9.9.9',
  '    - 1.1.1.1'
].join('\n');

yaml = yaml.replace(/bootstrap_dns:[\s\S]*?fallback_dns:/, newBootstrap + '\n  fallback_dns:');

fs.writeFileSync(configPath, yaml, 'utf8');
console.log(`AdGuardHome.yaml at ${configPath} successfully updated with ratelimit and encrypted bootstrap.`);
