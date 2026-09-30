// ==============================================================================
// 🛡️ AI DNS Centinela v2.1 — Gemini 3.5 Flash Lite + DGA + C2 Beaconing
// ==============================================================================
// Proactive AI sentinel that monitors AdGuard Home query logs in real-time.
// Detects algorithmically-generated domains (DGA) via Shannon entropy and
// periodic C2 beaconing via standard deviation heuristics.
// Suspicious domains are confirmed by Gemini AI before blocking.
// Includes anti-false-positive cloud filters, .onion exclusion, and memory pruning.
// ==============================================================================

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Portable paths — resolve relative to script location or use env overrides
const BASE_DIR = process.env.FORTRESS_DIR || path.join(__dirname, '..');
const ENV_PATH = process.env.ENV_FILE || path.join(BASE_DIR, 'config', '.env');
const CACHE_PATH = process.env.CACHE_FILE || path.join(BASE_DIR, 'data', 'checked_domains.json');
const LOG_PATH = process.env.AI_GUARD_LOG || path.join(BASE_DIR, 'logs', 'ai_guard.log');

// AdGuard Home connection defaults
const AGH_HOST = process.env.AGH_HOST || '127.0.0.1';
const AGH_PORT = parseInt(process.env.AGH_PORT || '80', 10);

// Scan configuration
const SCAN_INTERVAL_MS = parseInt(process.env.SCAN_INTERVAL || '50000', 10);
const QUERY_LIMIT = parseInt(process.env.QUERY_LIMIT || '200', 10);
const AI_RATE_DELAY_MS = 1200; // Delay between Gemini API calls to respect rate limits

// Ensure directories exist
function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  process.stdout.write(line);
  try {
    ensureDir(LOG_PATH);
    fs.appendFileSync(LOG_PATH, line, 'utf8');
    // Rotate log if > 2MB
    const stat = fs.statSync(LOG_PATH);
    if (stat.size > 2 * 1024 * 1024) {
      const oldLog = LOG_PATH + '.old';
      if (fs.existsSync(oldLog)) fs.unlinkSync(oldLog);
      fs.renameSync(LOG_PATH, oldLog);
    }
  } catch (e) { /* silent */ }
}

// ─── Load .env ──────────────────────────────────────────────────────────────
let env = {};
const envPaths = [
  ENV_PATH,
  path.join(BASE_DIR, '.env'),
  path.join(__dirname, '..', '.env'),
  path.join(__dirname, '..', 'config', '.env'),
  'C:\\AdGuardHome\\.env'
];
for (const ep of envPaths) {
  if (fs.existsSync(ep)) {
    const lines = fs.readFileSync(ep, 'utf8').split(/\r?\n/);
    for (const l of lines) {
      const trimmed = l.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
      const m = trimmed.match(/^([A-Za-z0-9_]+)=(.*)$/);
      if (m) {
        const val = m[2].trim().replace(/^["']|["']$/g, '');
        env[m[1].trim()] = val;
      }
    }
    break;
  }
}

const AGH_USER = env.ADGUARD_USERNAME || process.env.ADGUARD_USERNAME || 'admin';
const AGH_PASS = env.ADGUARD_PASSWORD || process.env.ADGUARD_PASSWORD;
const GEMINI_KEY = env.GEMINI_API_KEY || process.env.GEMINI_API_KEY;

if (!AGH_PASS || !GEMINI_KEY) {
  log('❌ ERROR: Missing credentials. Set ADGUARD_PASSWORD and GEMINI_API_KEY in .env or environment.');
  process.exit(1);
}

// ─── Domain Cache ───────────────────────────────────────────────────────────
let checkedDomains = new Set();
if (fs.existsSync(CACHE_PATH)) {
  try {
    const raw = fs.readFileSync(CACHE_PATH, 'utf8');
    const arr = JSON.parse(raw);
    checkedDomains = new Set(arr);
  } catch (e) {
    checkedDomains = new Set();
  }
}

function saveCache() {
  try {
    ensureDir(CACHE_PATH);
    const list = Array.from(checkedDomains);
    const trimmed = list.slice(-10000); // Keep last 10k entries
    fs.writeFileSync(CACHE_PATH, JSON.stringify(trimmed), 'utf8');
  } catch (e) { /* silent */ }
}

// ─── Domain Timestamp History for C2 Beacon Detection ───────────────────────
const domainQueryTimes = new Map();

// Evict inactive domains from query history to prevent memory leaks
function pruneDomainQueryTimes() {
  const maxAge = 30 * 60 * 1000; // 30 minutes
  const now = Date.now();
  for (const [domain, times] of domainQueryTimes.entries()) {
    const newest = times[times.length - 1];
    if (now - newest > maxAge) {
      domainQueryTimes.delete(domain);
    }
  }
  // Hard cap to 2000 entries
  if (domainQueryTimes.size > 2000) {
    let excess = domainQueryTimes.size - 2000;
    for (const key of domainQueryTimes.keys()) {
      if (excess-- <= 0) break;
      domainQueryTimes.delete(key);
    }
  }
}

// ─── Shannon Entropy Calculation ────────────────────────────────────────────
// H(X) = -Σ P(xi) * log2(P(xi))
// DGA domains typically exhibit entropy > 3.8 with length > 12
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

// ─── Apex / Registrable Domain Extraction ────────────────────────────────────
// Extracts the actual registered label (SLD) rather than subdomains or container IDs
function extractApexLabel(domain) {
  const parts = domain.split('.');
  if (parts.length <= 1) return parts[0];
  // Common 2-part ccTLDs
  const twoPartTlds = ['co.uk', 'com.es', 'org.es', 'nom.es', 'com.br', 'co.jp', 'com.au', 'co.nz'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
    return parts[parts.length - 3];
  }
  return parts[parts.length - 2];
}

// ─── Benign Domains & Developer Allowlist ────────────────────────────────────
// Reputable ecosystems, cloud platforms, and package repositories
const BENIGN_ROOTS = [
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com',
  'google', 'antigravity.google', 'run.app', 'gcr.io', 'pkg.dev',
  'microsoft.com', 'windows.com', 'live.com', 'office.com', 'azure.com', 'azure.net', 'azurewebsites.net',
  'github.com', 'github.io', 'gitlab.com', 'apple.com', 'icloud.com',
  'cloudflare.com', 'pages.dev', 'quad9.net', 'mullvad.net',
  'steamcommunity.com', 'steampowered.com', 'discord.com', 'discordapp.com',
  'spotify.com', 'netflix.com',
  'amazon.com', 'amazonaws.com', 'cloudfront.net', 'akamaized.net', 'fastly.net',
  'docker.com', 'docker.io', 'npmjs.org', 'npmjs.com', 'npm.org',
  'adguard-dns.com', 'adguard.com', 'wikipedia.org', 'bitdefender.net'
];

function isKnownBenign(domain) {
  for (const root of BENIGN_ROOTS) {
    if (domain === root || domain.endsWith('.' + root)) return true;
  }
  return false;
}

// Custom HTTP agents to avoid connection pooling leaks
const httpAgent = new http.Agent({ keepAlive: false, maxSockets: 4 });
const httpsAgent = new https.Agent({ keepAlive: false, maxSockets: 4 });

// ─── AdGuard Home API Client ────────────────────────────────────────────────
function aghRequest(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const safeResolve = (val) => { if (!settled) { settled = true; resolve(val); } };
    const safeReject = (err) => { if (!settled) { settled = true; reject(err); } };

    const auth = Buffer.from(`${AGH_USER}:${AGH_PASS}`).toString('base64');
    const headers = {
      'Authorization': 'Basic ' + auth
    };
    if (body) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request({
      hostname: AGH_HOST,
      port: AGH_PORT,
      path: endpoint,
      method: method,
      headers: headers,
      agent: httpAgent,
      timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('aborted', () => {
        req.destroy();
        safeReject(new Error('AGH API response aborted by peer'));
      });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            safeResolve(data ? JSON.parse(data) : {});
          } catch (e) {
            safeResolve(data);
          }
        } else {
          safeReject(new Error(`AGH API ${res.statusCode}: ${data}`));
        }
      });
      res.on('error', (err) => {
        req.destroy();
        safeReject(err);
      });
    });

    req.on('error', (err) => {
      req.destroy();
      safeReject(err);
    });
    req.on('timeout', () => {
      req.destroy(new Error('AGH API timeout'));
      safeReject(new Error('AGH API timeout'));
    });

    if (body) req.write(body);
    req.end();
  });
}

// ─── Gemini AI Threat Analysis ──────────────────────────────────────────────
// Queries Gemini API with contextual awareness of legitimate cloud hosts
function askGemini(domain, details) {
  return new Promise((resolve) => {
    let settled = false;
    const safeResolve = (val) => { if (!settled) { settled = true; resolve(val); } };

    const prompt = `You are an elite cybersecurity threat analyst. Analyze this domain queried by a computer: "${domain}".
Details: ${details}
Analyze for Domain Generation Algorithms (DGA), botnet C2 beacons, infostealer beacons, phishing, or typosquatting.
IMPORTANT: Legitimate cloud hosting, developer platforms, CDN hostnames, and hash-based deployment IDs (such as on Google Cloud, AWS, Azure, Cloudflare, GitHub) are SAFE unless there is strong evidence of malicious C2 activity or malware payload hosting.
Reply with EXACTLY one word: "MALICIOUS" or "SAFE".`;

    const payload = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    });

    const req = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${GEMINI_KEY}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      agent: httpsAgent,
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('aborted', () => {
        req.destroy();
        safeResolve('SAFE');
      });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const answer = json?.candidates?.[0]?.content?.parts?.[0]?.text?.trim()?.toUpperCase() || 'SAFE';
          if (answer.includes('MALICIOUS')) {
            safeResolve('MALICIOUS');
          } else {
            safeResolve('SAFE');
          }
        } catch (e) {
          safeResolve('SAFE');
        }
      });
      res.on('error', () => {
        req.destroy();
        safeResolve('SAFE');
      });
    });

    req.on('error', () => {
      req.destroy();
      safeResolve('SAFE');
    });
    req.on('timeout', () => {
      req.destroy();
      safeResolve('SAFE');
    });

    req.write(payload);
    req.end();
  });
}

// ─── Block Domain in AdGuard Home ───────────────────────────────────────────
async function blockDomain(domain) {
  try {
    const status = await aghRequest('/control/filtering/status');
    const rules = status.user_rules || [];
    const blockRule = `||${domain}^`;
    if (!rules.includes(blockRule)) {
      rules.push(blockRule);
      await aghRequest('/control/filtering/set_rules', 'POST', JSON.stringify({ rules }));
      log(`🚨 DOMINIO MALICIOSO DETECTADO Y BLOQUEADO AUTOMÁTICAMENTE: ${domain}`);
    }
  } catch (e) {
    log(`Error al aplicar bloqueo de ${domain}: ${e.message}`);
  }
}

// ─── C2 Beaconing Detection Heuristic ───────────────────────────────────────
// Detects periodic query patterns indicative of C2 beacon callbacks.
// Requires 3+ timestamps. Flags intervals between 10s-300s with stddev < 4s.
function detectBeaconing(times) {
  if (times.length < 3) return null;
  const sorted = [...times].sort((a, b) => a - b);
  const diffs = [];
  for (let i = 1; i < sorted.length; i++) {
    diffs.push((sorted[i] - sorted[i - 1]) / 1000); // Convert to seconds
  }
  const avg = diffs.reduce((a, b) => a + b, 0) / diffs.length;
  // If queries happen between 10s and 300s apart (typical C2 interval range)
  if (avg >= 10 && avg <= 300) {
    const variance = diffs.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / diffs.length;
    const stddev = Math.sqrt(variance);
    // Standard deviation under 4 seconds indicates machine periodicity (low jitter)
    if (stddev < 4.0) {
      return { avg, stddev };
    }
  }
  return null;
}

// ─── Main Scan Loop with Concurrency Lock ───────────────────────────────────
let isScanning = false;

async function scanRecentQueries() {
  if (isScanning) return;
  isScanning = true;

  try {
    const data = await aghRequest(`/control/querylog?limit=${QUERY_LIMIT}`);
    const logs = data.data || [];
    const candidates = new Set();
    const now = Date.now();

    for (const item of logs) {
      const qname = item.question?.name?.toLowerCase()?.trim();
      if (!qname) continue;

      // Skip local, arpa, root, Tor hidden services, and known benign domains
      if (
        qname.length < 5 ||
        !qname.includes('.') ||
        qname.endsWith('.arpa') ||
        qname.endsWith('.local') ||
        qname.endsWith('.home') ||
        qname.endsWith('.lan') ||
        qname.endsWith('.onion') || // Never flag Tor .onion 56-char base32 hashes
        isKnownBenign(qname)
      ) {
        continue;
      }

      // Record timestamps for beaconing detection
      const itemTime = item.time ? new Date(item.time).getTime() : now;
      if (!domainQueryTimes.has(qname)) {
        domainQueryTimes.set(qname, []);
      }
      const times = domainQueryTimes.get(qname);
      times.push(itemTime);
      if (times.length > 10) times.shift();

      // Only flag for entropy analysis if not already checked
      if (!checkedDomains.has(qname)) {
        candidates.add(qname);
      }
    }

    // ── Phase 1: Analyze New Domains (Entropy / DGA on Apex Domain) ──
    for (const domain of candidates) {
      checkedDomains.add(domain);

      // Extract the registrable apex label instead of random container subdomains
      const apexLabel = extractApexLabel(domain);
      const entropy = calculateEntropy(apexLabel);

      const isSuspicious = entropy > 3.85 || (apexLabel.length > 20 && /\d/.test(apexLabel));

      if (isSuspicious) {
        log(`🔍 Inspeccionando dominio sospechoso por entropía apex (${entropy.toFixed(2)}): ${domain} [label: ${apexLabel}]`);
        const verdict = await askGemini(domain, `Apex Label: "${apexLabel}", Entropy: ${entropy.toFixed(2)}`);
        log(`   🤖 Veredicto IA: ${verdict} para ${domain}`);
        if (verdict === 'MALICIOUS') {
          await blockDomain(domain);
        }
        await new Promise(r => setTimeout(r, AI_RATE_DELAY_MS));
      }
    }

    // ── Phase 2: Analyze C2 Beaconing Heuristics ──
    for (const [domain, times] of domainQueryTimes.entries()) {
      if (checkedDomains.has(`beacon:${domain}`)) continue;
      const beacon = detectBeaconing(times);
      if (beacon) {
        checkedDomains.add(`beacon:${domain}`);
        log(`⚠️ ALERTA DE BEACONING PERIÓDICO DETECTADO (~${beacon.avg.toFixed(1)}s, stddev: ${beacon.stddev.toFixed(2)}s): ${domain}`);
        const verdict = await askGemini(domain, `Periodic query interval: ~${beacon.avg.toFixed(1)}s, jitter stddev: ${beacon.stddev.toFixed(2)}s`);
        log(`   🤖 Veredicto IA para Beaconing: ${verdict} en ${domain}`);
        if (verdict === 'MALICIOUS') {
          await blockDomain(domain);
        }
        await new Promise(r => setTimeout(r, AI_RATE_DELAY_MS));
      }
    }

    // Maintenance: prune old entries and persist cache
    pruneDomainQueryTimes();
    saveCache();
  } catch (e) {
    log(`Aviso en escaneo: ${e.message}`);
  } finally {
    isScanning = false;
  }
}

// ─── Startup ────────────────────────────────────────────────────────────────
log('🛡️ AI DNS Guard v2.1 (Gemini 3.5 Flash Lite + DGA Apex + C2 Beaconing + Cloud Protect) activo.');
log(`   📁 Base: ${BASE_DIR}`);
log(`   🔗 AdGuard Home: http://${AGH_HOST}:${AGH_PORT}`);
log(`   ⏱️  Intervalo de escaneo: ${SCAN_INTERVAL_MS / 1000}s`);

// Initial scan
scanRecentQueries();

// Recurring loop
const scanTimer = setInterval(scanRecentQueries, SCAN_INTERVAL_MS);

// ─── Graceful Shutdown ──────────────────────────────────────────────────────
function gracefulShutdown(signal) {
  log(`🛑 Recibida señal ${signal}. Cerrando centinela de forma limpia...`);
  try {
    clearInterval(scanTimer);
    saveCache();
    httpAgent.destroy();
    httpsAgent.destroy();
  } catch (e) { /* silent */ }
  process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

