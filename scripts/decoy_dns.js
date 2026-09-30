// ==============================================================================
// DNS Decoy Traffic Generator (Whitewashing & Timing Analysis Obfuscation)
// Generates realistic, jittered background DNS queries through AdGuard Home + Tor
// ==============================================================================

const dns = require('dns');
const fs = require('fs');
const path = require('path');

// Target local AdGuard Home resolver
dns.setServers(['127.0.0.1']);

const BASE_DIR = process.env.FORTRESS_DIR || path.join(__dirname, '..');
const LOG_PATH = process.env.DECOY_LOG || path.join(BASE_DIR, 'logs', 'decoy.log');
const MAX_LOG_SIZE = 1 * 1024 * 1024; // 1MB

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    ensureDir(LOG_PATH);
    if (fs.existsSync(LOG_PATH) && fs.statSync(LOG_PATH).size > MAX_LOG_SIZE) {
      fs.unlinkSync(LOG_PATH);
    }
    fs.appendFileSync(LOG_PATH, line, 'utf8');
  } catch (e) {}
}

const ACADEMIC_DOMAINS = [
  // Academic & Research
  'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk', 'cam.ac.uk',
  'ethz.ch', 'epfl.ch', 'cern.ch', 'uam.es', 'upm.es', 'ub.edu',
  'tum.de', 'sorbonne-universite.fr', 'tudelft.nl', 'anu.edu.au',
  // Open Source & Science
  'kernel.org', 'debian.org', 'archlinux.org', 'gnu.org', 'apache.org',
  'python.org', 'rust-lang.org', 'golang.org', 'mozilla.org', 'fsf.org',
  'nasa.gov', 'esa.int', 'who.int', 'un.org', 'arxiv.org', 'gutenberg.org',
  'wikipedia.org', 'wikimedia.org', 'archive.org', 'libreoffice.org',
  // Technology, Documentation & Standards
  'ietf.org', 'w3.org', 'rfc-editor.org', 'iana.org', 'eff.org',
  'torproject.org', 'openssl.org', 'freebsd.org', 'openbsd.org',
  'gentoo.org', 'videolan.org', 'blender.org', 'gimp.org', 'inkscape.org',
  // Culture & Reference
  'loc.gov', 'europeana.eu', 'jstor.org', 'biodiversitylibrary.org',
  'metmuseum.org', 'louvre.fr', 'prado.es', 'rijksmuseum.nl',
  'smithsonianmag.com', 'nationalgeographic.com', 'nature.com', 'science.org'
];

const POPULAR_DOMAINS = [
  // News & Media
  'bbc.com', 'reuters.com', 'theguardian.com', 'elpais.com', 'lemonde.fr',
  'spiegel.de', 'dw.com', 'apnews.com', 'bloomberg.com', 'ft.com',
  // E-Commerce & Retail
  'amazon.com', 'ebay.com', 'aliexpress.com', 'walmart.com', 'target.com',
  // Streaming & Entertainment
  'netflix.com', 'spotify.com', 'twitch.tv', 'soundcloud.com', 'vimeo.com',
  // Sports & Weather
  'espn.com', 'marca.com', 'as.com', 'accuweather.com', 'weather.com',
  // Tech & Productivity
  'github.com', 'gitlab.com', 'stackoverflow.com', 'duckduckgo.com', 'proton.me'
];

let queryCount = 0;
let nextTimer = null;
let isDegraded = false;

// Pick a domain: 70% chance academic/science, 30% chance popular traffic
function pickRandomDomain() {
  const useAcademic = Math.random() < 0.70;
  const pool = useAcademic ? ACADEMIC_DOMAINS : POPULAR_DOMAINS;
  return pool[Math.floor(Math.random() * pool.length)];
}

function sendDecoyQuery() {
  if (isDegraded) return;

  const domain = pickRandomDomain();
  const sw = Date.now();

  dns.resolve4(domain, (err, addresses) => {
    queryCount++;
    const elapsed = Date.now() - sw;
    if (err) {
      log(`[DECOY #${queryCount}] Query: ${domain} (Fail: ${err.code}) [${elapsed}ms]`);
    } else {
      if (queryCount === 1 || queryCount % 10 === 0) {
        log(`[DECOY #${queryCount}] Query: ${domain} -> ${addresses[0]} [${elapsed}ms]`);
      }
    }

    // Dynamic jitter: random delay between 20 and 55 seconds to prevent traffic pattern fingerprinting
    const nextDelay = Math.floor(Math.random() * (55000 - 20000 + 1)) + 20000;
    nextTimer = setTimeout(sendDecoyQuery, nextDelay);
  });
}

process.on('uncaughtException', (err) => {
  log(`💥 Uncaught Exception: ${err.stack || err.message}`);
});
process.on('unhandledRejection', (reason) => {
  log(`💥 Unhandled Rejection: ${reason}`);
});

// ─── Initial Connectivity Verification with Exponential Backoff ─────────────
async function verifyConnectivity(retries = 5, delayMs = 5000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    log(`🔍 Comprobando conectividad DNS local (127.0.0.1) [Intento ${attempt}/${retries}]...`);
    const success = await new Promise((resolve) => {
      dns.resolve4('wikipedia.org', (err, addresses) => {
        if (!err && addresses && addresses.length > 0) {
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });

    if (success) {
      log('✅ Conectividad DNS con AdGuard Home confirmada. Iniciando generador de señuelos.');
      return true;
    }

    if (attempt < retries) {
      log(`⚠️ AdGuard Home no responde aún en 127.0.0.1. Reintentando en ${delayMs / 1000}s...`);
      await new Promise(r => setTimeout(r, delayMs));
      delayMs = Math.min(delayMs * 2, 30000); // Exponential backoff up to 30s
    }
  }
  return false;
}

// ─── Graceful Shutdown ──────────────────────────────────────────────────────
function gracefulShutdown(signal) {
  log(`🛑 Recibida señal ${signal}. Deteniendo generador de señuelos...`);
  if (nextTimer) clearTimeout(nextTimer);
  process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// ─── Startup ────────────────────────────────────────────────────────────────
log('🚀 Módulo de Tráfico Señuelo (DNS Decoy Whitewashing v2.0) inicializando.');

verifyConnectivity().then((online) => {
  if (online) {
    sendDecoyQuery();
  } else {
    isDegraded = true;
    log('❌ Falló la comprobación de conectividad tras múltiples intentos. Entrando en modo degradado (en espera del watchdog).');
  }
});
