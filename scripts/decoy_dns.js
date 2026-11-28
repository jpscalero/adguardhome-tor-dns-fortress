#!/usr/bin/env node
/*
 * Generador de trafico senuelo DNS para la fortaleza AdGuard + Tor.
 *
 * Reglas de seguridad:
 *  - Nunca termina porque AdGuard/Tor esten caidos: espera y reintenta.
 *  - Una sola consulta en vuelo; timeout duro y cancelacion del resolver.
 *  - Circuit breaker: tras 3 fallos seguidos deja de consultar 5 minutos.
 *  - No consulta si el puerto 53 local no esta abierto.
 *  - Estado persistente en data/decoy-status.json para el watchdog/doctor.
 *
 * Uso:
 *   node decoy_dns.js
 *   node decoy_dns.js --once
 *   node decoy_dns.js --domain example.com --log-file C:\AdGuardHome\logs\decoy.log
 */
'use strict';

const dns = require('dns');
const fs = require('fs');
const net = require('net');
const path = require('path');

function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--once') { out.once = true; continue; }
        if (!arg.startsWith('--')) continue;
        const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) { out[key] = next; i++; }
        else { out[key] = true; }
    }
    return out;
}

const opts = parseArgs(process.argv.slice(2));
const BASE_DIR = process.env.FORTRESS_DIR || path.join(__dirname, '..');
const AGH_HOST = String(opts.host || process.env.DECOY_HOST || '127.0.0.1');
const AGH_PORT = Number(opts.port || process.env.DECOY_PORT || 53);
const DNS_TIMEOUT_MS = Number(opts.timeout || process.env.DECOY_TIMEOUT || 8000);
const MIN_DELAY_MS = Number(opts.minDelay || 20000);
const MAX_DELAY_MS = Number(opts.maxDelay || 55000);
const FAILURE_PAUSE_MS = Number(opts.failurePause || 300000);
const MAX_CONSECUTIVE_FAILURES = Number(opts.maxFailures || 3);
const LOG_PATH = String(opts.logFile || process.env.DECOY_LOG || path.join(BASE_DIR, 'logs', 'decoy.log'));
const STATUS_PATH = String(opts.statusFile || process.env.DECOY_STATUS || path.join(BASE_DIR, 'data', 'decoy-status.json'));
const MAX_LOG_SIZE = 1 * 1024 * 1024;
const ONCE = Boolean(opts.once);

const ACADEMIC_DOMAINS = [
    'mit.edu', 'stanford.edu', 'harvard.edu', 'ox.ac.uk', 'cam.ac.uk',
    'ethz.ch', 'epfl.ch', 'cern.ch', 'uam.es', 'upm.es', 'ub.edu',
    'tum.de', 'sorbonne-universite.fr', 'tudelft.nl', 'anu.edu.au',
    'kernel.org', 'debian.org', 'archlinux.org', 'gnu.org', 'apache.org',
    'python.org', 'rust-lang.org', 'golang.org', 'mozilla.org', 'fsf.org',
    'nasa.gov', 'esa.int', 'who.int', 'un.org', 'arxiv.org', 'gutenberg.org',
    'wikipedia.org', 'wikimedia.org', 'archive.org', 'libreoffice.org',
    'ietf.org', 'w3.org', 'rfc-editor.org', 'iana.org', 'eff.org',
    'torproject.org', 'openssl.org', 'freebsd.org', 'openbsd.org',
    'gentoo.org', 'videolan.org', 'blender.org', 'gimp.org', 'inkscape.org',
    'loc.gov', 'europeana.eu', 'jstor.org', 'biodiversitylibrary.org',
    'metmuseum.org', 'louvre.fr', 'prado.es', 'rijksmuseum.nl',
    'smithsonianmag.com', 'nationalgeographic.com', 'nature.com', 'science.org'
];

const POPULAR_DOMAINS = [
    'bbc.com', 'reuters.com', 'theguardian.com', 'elpais.com', 'lemonde.fr',
    'spiegel.de', 'dw.com', 'apnews.com', 'bloomberg.com', 'ft.com',
    'amazon.com', 'ebay.com', 'aliexpress.com', 'walmart.com', 'target.com',
    'netflix.com', 'spotify.com', 'twitch.tv', 'soundcloud.com', 'vimeo.com',
    'espn.com', 'marca.com', 'as.com', 'accuweather.com', 'weather.com',
    'github.com', 'gitlab.com', 'stackoverflow.com', 'duckduckgo.com', 'proton.me'
];

let state = ONCE ? 'probe' : 'starting';
let queryCount = 0;
let successes = 0;
let failures = 0;
let consecutiveFailures = 0;
let lastError = null;
let lastQueryAt = null;
let lastSuccessAt = null;
let nextRunAt = null;
let stopping = false;
let sleepTimer = null;
let sleepResolve = null;
let currentResolver = null;
const startedAt = new Date().toISOString();

function ensureDir(filePath) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function log(message) {
    const line = `[${new Date().toISOString()}] ${message}\n`;
    process.stdout.write(line);
    try {
        ensureDir(LOG_PATH);
        if (fs.existsSync(LOG_PATH) && fs.statSync(LOG_PATH).size > MAX_LOG_SIZE) {
            const old = LOG_PATH + '.old';
            if (fs.existsSync(old)) fs.unlinkSync(old);
            fs.renameSync(LOG_PATH, old);
        }
        fs.appendFileSync(LOG_PATH, line, 'utf8');
    } catch (err) {
        // El log no debe tumbar el generador.
    }
}

function writeStatus() {
    const payload = {
        pid: process.pid,
        startedAt,
        updatedAt: new Date().toISOString(),
        state,
        host: AGH_HOST,
        port: AGH_PORT,
        queries: queryCount,
        successes,
        failures,
        consecutiveFailures,
        lastError,
        lastQueryAt,
        lastSuccessAt,
        nextRunAt,
        once: ONCE
    };
    try {
        ensureDir(STATUS_PATH);
        const tmp = STATUS_PATH + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
        fs.renameSync(tmp, STATUS_PATH);
    } catch (err) {
        // El estado es diagnostico; no debe tumbar el generador.
    }
}

function sleep(ms) {
    return new Promise((resolve) => {
        sleepResolve = resolve;
        sleepTimer = setTimeout(() => {
            sleepTimer = null;
            sleepResolve = null;
            resolve();
        }, ms);
    });
}

function wakeSleep() {
    if (sleepTimer) {
        clearTimeout(sleepTimer);
        sleepTimer = null;
    }
    if (sleepResolve) {
        const resolve = sleepResolve;
        sleepResolve = null;
        resolve();
    }
}

function testPort(port, timeoutMs) {
    return new Promise((resolve) => {
        const socket = net.connect({ host: AGH_HOST, port });
        let settled = false;
        const done = (ok) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(ok);
        };
        const timer = setTimeout(() => done(false), timeoutMs);
        socket.once('connect', () => { clearTimeout(timer); done(true); });
        socket.once('error', () => { clearTimeout(timer); done(false); });
        socket.once('timeout', () => { clearTimeout(timer); done(false); });
        socket.setTimeout(timeoutMs);
    });
}

function resolveWithTimeout(domain, timeoutMs) {
    return new Promise((resolve) => {
        const resolver = new dns.Resolver();
        currentResolver = resolver;
        const resolverServer = AGH_PORT === 53 ? AGH_HOST : (AGH_HOST + ':' + AGH_PORT);
        resolver.setServers([resolverServer]);
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (currentResolver === resolver) currentResolver = null;
            resolve(result);
        };
        const timer = setTimeout(() => {
            try { resolver.cancel(); } catch (err) { /* ya cerrado */ }
            finish({ ok: false, error: 'ETIMEOUT' });
        }, timeoutMs);
        try {
            resolver.resolve4(domain, (err, addresses) => {
                if (err) {
                    finish({ ok: false, error: err.code || err.message || 'EDNS' });
                } else if (!addresses || addresses.length === 0) {
                    finish({ ok: false, error: 'ENODATA' });
                } else {
                    finish({ ok: true, address: addresses[0] });
                }
            });
        } catch (err) {
            finish({ ok: false, error: err.code || err.message || 'EDNS' });
        }
    });
}

function pickRandomDomain() {
    const pool = Math.random() < 0.70 ? ACADEMIC_DOMAINS : POPULAR_DOMAINS;
    return pool[Math.floor(Math.random() * pool.length)];
}

async function ensureReady() {
    let waitMs = 15000;
    while (!stopping) {
        state = 'waiting-dns';
        writeStatus();
        if (!(await testPort(AGH_PORT, 1500))) {
            lastError = 'PORT53_CLOSED';
            log(`AdGuard no escucha en ${AGH_HOST}:${AGH_PORT}; reintento en ${Math.round(waitMs / 1000)}s.`);
        } else {
            const probe = await resolveWithTimeout('example.com', DNS_TIMEOUT_MS);
            if (probe.ok) {
                state = 'online';
                lastError = null;
                consecutiveFailures = 0;
                writeStatus();
                log('Conectividad DNS local confirmada; generador de senuelos activo.');
                return true;
            }
            lastError = probe.error;
            log(`AdGuard no resuelve aun (${probe.error}); reintento en ${Math.round(waitMs / 1000)}s.`);
        }
        nextRunAt = new Date(Date.now() + waitMs).toISOString();
        writeStatus();
        await sleep(waitMs);
        waitMs = Math.min(waitMs * 2, FAILURE_PAUSE_MS);
    }
    return false;
}

async function runOnce(domain) {
    const target = domain || pickRandomDomain();
    state = 'querying';
    lastQueryAt = new Date().toISOString();
    writeStatus();
    const result = await resolveWithTimeout(target, DNS_TIMEOUT_MS);
    queryCount++;
    if (result.ok) {
        successes++;
        consecutiveFailures = 0;
        lastSuccessAt = new Date().toISOString();
        lastError = null;
        log(`[DECOY #${queryCount}] ${target} -> ${result.address}`);
    } else {
        failures++;
        consecutiveFailures++;
        lastError = result.error;
        log(`[DECOY #${queryCount}] ${target} fallo: ${result.error}`);
    }
    writeStatus();
    return result;
}

async function mainLoop() {
    if (!(await ensureReady())) return;
    while (!stopping) {
        const domain = pickRandomDomain();
        await runOnce(domain);

        let delayMs;
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
            state = 'degraded';
            delayMs = FAILURE_PAUSE_MS;
            log(`Circuit breaker: ${consecutiveFailures} fallos seguidos; pausa de ${Math.round(delayMs / 1000)}s sin generar consultas.`);
            nextRunAt = new Date(Date.now() + delayMs).toISOString();
            writeStatus();
            await sleep(delayMs);
            if (!stopping) await ensureReady();
            continue;
        }

        if (consecutiveFailures > 0) {
            state = 'degraded';
            delayMs = Math.min(5000 * Math.pow(2, consecutiveFailures - 1), 60000);
        } else {
            state = 'online';
            delayMs = Math.floor(Math.random() * (MAX_DELAY_MS - MIN_DELAY_MS + 1)) + MIN_DELAY_MS;
        }
        nextRunAt = new Date(Date.now() + delayMs).toISOString();
        writeStatus();
        await sleep(delayMs);
    }
}

function shutdown(signal) {
    if (stopping) return;
    stopping = true;
    state = 'stopped';
    nextRunAt = null;
    writeStatus();
    log(`Deteniendo por ${signal}.`);
    try {
        if (currentResolver) currentResolver.cancel();
    } catch (err) { /* ya cerrado */ }
    wakeSleep();
    setTimeout(() => process.exit(0), 100);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGBREAK', () => shutdown('SIGBREAK'));
process.on('uncaughtException', (err) => {
    state = 'fatal';
    lastError = err.message || String(err);
    writeStatus();
    log(`Uncaught Exception: ${err.stack || err.message}`);
    setTimeout(() => process.exit(1), 100);
});
process.on('unhandledRejection', (err) => {
    lastError = err && err.message ? err.message : String(err);
    writeStatus();
    log(`Unhandled Rejection: ${err && err.stack ? err.stack : err}`);
});

(async () => {
    log(`Decoy DNS v3.0 iniciando (${AGH_HOST}:${AGH_PORT}, timeout ${DNS_TIMEOUT_MS}ms).`);
    if (ONCE) {
        const domain = String(opts.domain || 'example.com');
        const result = await runOnce(domain);
        state = result.ok ? 'online' : 'degraded';
        writeStatus();
        process.exit(result.ok ? 0 : 2);
    }
    await mainLoop();
})();
