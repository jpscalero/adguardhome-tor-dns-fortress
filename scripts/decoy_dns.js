// ==============================================================================
// DNS Decoy Traffic Generator (Whitewashing & Timing Analysis Obfuscation)
// Generates realistic, jittered background DNS queries through AdGuard Home + Tor
// ==============================================================================

const dns = require('dns');
const fs = require('fs');
const path = require('path');

// Target local AdGuard Home resolver
dns.setServers(['127.0.0.1']);

const LOG_PATH = process.env.DECOY_LOG || path.join(__dirname, '..', 'logs', 'decoy.log');
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

const DECOY_DOMAINS = [
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
  // General Culture & Neutral Non-Profit
  'loc.gov', 'europeana.eu', 'jstor.org', 'biodiversitylibrary.org',
  'metmuseum.org', 'louvre.fr', 'prado.es', 'rijksmuseum.nl',
  'smithsonianmag.com', 'nationalgeographic.com', 'nature.com', 'science.org'
];

let queryCount = 0;

function sendDecoyQuery() {
  const domain = DECOY_DOMAINS[Math.floor(Math.random() * DECOY_DOMAINS.length)];
  const sw = Date.now();

  dns.resolve4(domain, (err, addresses) => {
    queryCount++;
    const elapsed = Date.now() - sw;
    if (err) {
      log(`[DECOY #${queryCount}] Query: ${domain} (Fail: ${err.code}) [${elapsed}ms]`);
    } else {
      if (queryCount % 10 === 0) {
        log(`[DECOY #${queryCount}] Query: ${domain} -> ${addresses[0]} [${elapsed}ms]`);
      }
    }

    // Dynamic jitter: random delay between 20 and 55 seconds to prevent traffic pattern fingerprinting
    const nextDelay = Math.floor(Math.random() * (55000 - 20000 + 1)) + 20000;
    setTimeout(sendDecoyQuery, nextDelay);
  });
}

log('🚀 Módulo de Tráfico Señuelo (DNS Decoy Whitewashing) iniciado.');
sendDecoyQuery();
