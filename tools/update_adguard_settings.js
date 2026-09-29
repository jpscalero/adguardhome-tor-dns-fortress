const fs = require('fs');

const path = 'C:\\AdGuardHome\\AdGuardHome.yaml';
let yaml = fs.readFileSync(path, 'utf8');

// Update ratelimit and whitelist
yaml = yaml.replace(/ratelimit: 0/, 'ratelimit: 40');
yaml = yaml.replace(
  /ratelimit_whitelist: \[\]/,
  'ratelimit_whitelist:\n    - 127.0.0.1\n    - 192.168.0.125\n    - 192.168.0.185\n    - 192.168.0.231'
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

fs.writeFileSync(path, yaml, 'utf8');
console.log('AdGuardHome.yaml successfully updated with ratelimit and encrypted bootstrap.');
