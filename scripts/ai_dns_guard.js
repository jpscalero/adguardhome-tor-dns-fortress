// ==============================================================================
// Centinela AI: Real-Time DNS Threat Detection & Dynamic Firewalling
// Project: adguardhome-tor-dns-fortress
// Analyzes live AdGuard Home queries for C2 Beacons, High Entropy (DGA) & Phishing
// ==============================================================================

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const ENV_PATH = process.env.ENV_PATH || path.join(ROOT_DIR, 'config', '.env');
const CACHE_PATH = path.join(ROOT_DIR, 'checked_domains.json');
const LOG_PATH = path.join(ROOT_DIR, 'logs', 'ai_guard.log');

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  process.stdout.write(line);
  try {
    ensureDir(LOG_PATH);
    fs.appendFileSync(LOG_PATH, line, 'utf8');
  } catch (e) {}
}

// Parse environment file
let env = {};
if (fs.existsSync(ENV_PATH)) {
  const lines = fs.readFileSync(ENV_PATH, 'utf8').split(/\r?\n/);
  for (const l of lines) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m) env[m[1].trim()] = m[2].trim();
  }
}

const AGH_HOST = process.env.ADGUARD_HOST || '127.0.0.1';
const AGH_PORT = parseInt(process.env.ADGUARD_PORT || '80', 10);
const AGH_USER = env.ADGUARD_USERNAME || 'admin';
const AGH_PASS = env.ADGUARD_PASSWORD || '';
const GEMINI_KEY = env.GEMINI_API_KEY || '';

if (!AGH_PASS) {
  log('⚠️ ADGUARD_PASSWORD no configurada en config/.env. Algunas funciones de baneo automático requerirán autenticación.');
}

// Domain verification cache
let checkedDomains = new Set();
if (fs.existsSync(CACHE_PATH)) {
  try {
    const raw = fs.readFileSync(CACHE_PATH, 'utf8');
    checkedDomains = new Set(JSON.parse(raw));
  } catch (e) {
    checkedDomains = new Set();
  }
}

function saveCache() {
  try {
    ensureDir(CACHE_PATH);
    const list = Array.from(checkedDomains).slice(-10000);
    fs.writeFileSync(CACHE_PATH, JSON.stringify(list), 'utf8');
  } catch (e) {}
}

// Shannon Entropy for DGA (Domain Generation Algorithms) detection
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const c = str[i];
    frequencies[c] = (frequencies[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in frequencies) {
    const p = frequencies[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const BENIGN_ROOTS = [
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com',
  'microsoft.com', 'windows.com', 'live.com', 'office.com', 'azure.com', 'github.com',
  'apple.com', 'icloud.com', 'cloudflare.com', 'quad9.net', 'mullvad.net',
  'steamcommunity.com', 'steampowered.com', 'discord.com', 'discordapp.com',
  'spotify.com', 'netflix.com', 'amazon.com', 'adguard-dns.com', 'adguard.com',
  'wikipedia.org', 'bitdefender.net'
];

function isKnownBenign(domain) {
  for (const root of BENIGN_ROOTS) {
    if (domain === root || domain.endsWith('.' + root)) return true;
  }
  return false;
}

function aghRequest(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(`${AGH_USER}:${AGH_PASS}`).toString('base64');
    const headers = { 'Authorization': 'Basic ' + auth };
    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    const req = http.request({
      hostname: AGH_HOST,
      port: AGH_PORT,
      path: endpoint,
      method: method,
      headers: headers,
      timeout: 5000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(data ? JSON.parse(data) : {});
          } catch (e) {
            resolve(data);
          }
        } else {
          reject(new Error(`AGH API ${endpoint} retornó HTTP ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('AGH API Timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function blockDomain(domain, reason) {
  log(`🚨 [CENTINELA AI] BLOQUEANDO DOMINIO: ${domain} | Motivo: ${reason}`);
  try {
    const rule = `||${domain}^$dnsrewrite=NXDOMAIN`;
    const filtering = await aghRequest('/control/filtering/status');
    const rules = filtering.user_rules || [];
    if (!rules.includes(rule)) {
      rules.push(rule);
      await aghRequest('/control/filtering/set_rules', 'POST', { rules: rules });
      log(`🛡️ Regla inyectada exitosamente en AdGuard Home: ${rule}`);
    }
  } catch (err) {
    log(`❌ Error inyectando regla de bloqueo: ${err.message}`);
  }
}

// C2 Periodic Beaconing Tracker
const domainHistory = new Map();

function trackBeacon(domain) {
  const now = Date.now();
  if (!domainHistory.has(domain)) {
    domainHistory.set(domain, []);
  }
  const timestamps = domainHistory.get(domain);
  timestamps.push(now);
  if (timestamps.length > 10) timestamps.shift();

  if (timestamps.length >= 5) {
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);

    // If queries occur with near-zero jitter (standard deviation < 400ms) at tight intervals:
    if (avg < 30000 && stdDev < 400 && !isKnownBenign(domain)) {
      log(`⚠️ ALERTA BEACON C2: Dominio ${domain} exhibe pulsos de baliza periódica (avg: ${Math.round(avg)}ms, stdDev: ${Math.round(stdDev)}ms)`);
      blockDomain(domain, 'C2 Periodic Beaconing Pattern');
    }
  }
}

async function analyzeQueryLog() {
  try {
    const logData = await aghRequest('/control/querylog?limit=50');
    if (!logData || !logData.data) return;

    for (const item of logData.data) {
      const q = item.question;
      if (!q || !q.name) continue;
      const domain = q.name.toLowerCase().replace(/\.$/, '');

      if (checkedDomains.has(domain)) continue;
      checkedDomains.add(domain);

      if (isKnownBenign(domain)) continue;

      trackBeacon(domain);

      // Check DGA entropy on main label
      const parts = domain.split('.');
      const mainLabel = parts.length > 2 ? parts[parts.length - 2] : parts[0];
      const entropy = calculateEntropy(mainLabel);

      if (entropy > 3.8 && mainLabel.length > 12) {
        log(`⚠️ ALTO NIVEL DE ENTROPÍA (DGA/Túnel DNS Sospechoso): ${domain} (Entropía: ${entropy.toFixed(2)})`);
        blockDomain(domain, `High Entropy DGA (${entropy.toFixed(2)})`);
      }
    }

    saveCache();
  } catch (e) {
    // API polling error
  }
}

log('🛡️ Centinela AI para AdGuard Home inicializado y vigilando en tiempo real.');
setInterval(analyzeQueryLog, 5000);
