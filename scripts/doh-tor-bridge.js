#!/usr/bin/env node
/*
 * Puente DNS-over-HTTPS sobre SOCKS5 (Tor) para AdGuard Home.
 *
 * AdGuard Home no puede enviar sus upstreams DNS por SOCKS5: `http_proxy`
 * solo cubre su cliente HTTP (listas, actualizaciones), no dnsproxy. Este
 * proceso recibe DNS normal en 127.0.0.1:5336 (UDP y TCP), lo empaqueta como
 * DoH y lo envia a un resolver por 127.0.0.1:9050. Ni AdGuard ni este puente
 * resuelven nombres fuera de Tor: el destino es una IP fija y el TLS se
 * valida contra el nombre del certificado.
 *
 * Quad9 retiro HTTP/1.1 de su DoH el 15/12/2025. Por eso este puente habla
 * HTTP/2 (ALPN h2) y, si un upstream falla, prueba el siguiente. Por defecto
 * usa Quad9 y Cloudflare como respaldo; ambos validan DNSSEC.
 *
 * Solo usa modulos nativos de Node (sin dependencias).
 *
 * Uso:
 *   node doh-tor-bridge.js
 *   node doh-tor-bridge.js --listen-port 5336 --socks-port 9050
 *   node doh-tor-bridge.js --upstream https://1.1.1.1/dns-query --sni cloudflare-dns.com
 */
'use strict';

const dgram = require('dgram');
const fs = require('fs');
const http2 = require('http2');
const net = require('net');
const path = require('path');
const tls = require('tls');
const { URL } = require('url');

function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--help' || arg === '-h') {
            out.help = true;
            continue;
        }
        if (!arg.startsWith('--')) continue;
        const eq = arg.indexOf('=');
        let key;
        let value;
        if (eq !== -1) {
            key = arg.slice(2, eq);
            value = arg.slice(eq + 1);
        } else {
            key = arg.slice(2);
            if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
                value = argv[++i];
            } else {
                value = true;
            }
        }
        key = key.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        out[key] = value;
    }
    return out;
}

const opts = parseArgs(process.argv.slice(2));

if (opts.help) {
    console.log([
        'Puente DNS-over-HTTPS sobre SOCKS5/Tor (HTTP/2)',
        '',
        '  --listen-host   127.0.0.1   Interfaz local (solo loopback)',
        '  --listen-port   5336        Puerto DNS local (UDP y TCP)',
        '  --socks-host    127.0.0.1   SOCKS5 de Tor (solo loopback)',
        '  --socks-port    9050        Puerto SOCKS5 de Tor',
        '  --upstream      URL[,URL]   DoH(s) de respaldo; por defecto Quad9 + Cloudflare',
        '  --sni           nombre      SNI para todos los upstreams (opcional)',
        '  --timeout       12000       Timeout total por consulta (ms)',
        '  --max-inflight  32          Consultas simultaneas maximas',
        '  --queue-limit   256         Consultas en cola antes de responder SERVFAIL',
        '  --status-file   data/doh-bridge-status.json',
        '  --log-file      (vacio)     Archivo de log opcional (sin nombres de dominio)'
    ].join('\n'));
    process.exit(0);
}

const LISTEN_HOST = String(opts.listenHost || '127.0.0.1');
const LISTEN_PORT = Number(opts.listenPort || 5336);
const SOCKS_HOST = String(opts.socksHost || '127.0.0.1');
const SOCKS_PORT = Number(opts.socksPort || 9050);
const TIMEOUT_MS = Number(opts.timeout || 12000);
const MAX_INFLIGHT = Number(opts.maxInflight || 32);
const QUEUE_LIMIT = Number(opts.queueLimit || 256);
const LOG_FILE = String(opts.logFile || '');
const STATUS_FILE = String(opts.statusFile || path.join(__dirname, 'data', 'doh-bridge-status.json'));

const DEFAULT_UPSTREAMS = [
    { url: 'https://9.9.9.9/dns-query', sni: 'dns.quad9.net' },
    { url: 'https://149.112.112.112/dns-query', sni: 'dns.quad9.net' },
    { url: 'https://1.1.1.1/dns-query', sni: 'cloudflare-dns.com' },
    { url: 'https://1.0.0.1/dns-query', sni: 'cloudflare-dns.com' }
];

const SNI_BY_HOST = {
    '9.9.9.9': 'dns.quad9.net',
    '149.112.112.112': 'dns.quad9.net',
    '1.1.1.1': 'cloudflare-dns.com',
    '1.0.0.1': 'cloudflare-dns.com',
    '94.140.14.14': 'dns.adguard-dns.com',
    '94.140.14.15': 'dns.adguard-dns.com'
};

function isLoopback(host) {
    return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function failStartup(message) {
    console.error('[doh-tor-bridge] ' + message);
    process.exit(2);
}

if (!isLoopback(LISTEN_HOST)) failStartup('--listen-host debe ser loopback (127.0.0.1 o ::1).');
if (!isLoopback(SOCKS_HOST)) failStartup('--socks-host debe ser loopback (127.0.0.1 o ::1).');
if (!Number.isInteger(LISTEN_PORT) || LISTEN_PORT < 1 || LISTEN_PORT > 65535) failStartup('--listen-port invalido.');
if (!Number.isInteger(SOCKS_PORT) || SOCKS_PORT < 1 || SOCKS_PORT > 65535) failStartup('--socks-port invalido.');
if (!Number.isInteger(TIMEOUT_MS) || TIMEOUT_MS < 2000) failStartup('--timeout invalido (minimo 2000 ms).');
if (!Number.isInteger(MAX_INFLIGHT) || MAX_INFLIGHT < 1) failStartup('--max-inflight invalido.');
if (!Number.isInteger(QUEUE_LIMIT) || QUEUE_LIMIT < 1) failStartup('--queue-limit invalido.');

const rawUpstreams = opts.upstream
    ? String(opts.upstream).split(',').map((s) => s.trim()).filter(Boolean)
    : DEFAULT_UPSTREAMS.map((u) => u.url);

const upstreams = [];
for (const raw of rawUpstreams) {
    let parsed;
    try {
        parsed = new URL(raw);
    } catch (err) {
        failStartup('Upstream invalido: ' + raw);
    }
    if (parsed.protocol !== 'https:') failStartup('El upstream debe ser https://: ' + raw);
    if (net.isIP(parsed.hostname) !== 4) {
        failStartup('El upstream debe usar una IPv4 fija (evita resolver nombres fuera de Tor): ' + raw);
    }
    if (parsed.username || parsed.password) failStartup('El upstream no debe llevar credenciales.');
    const sni = String(opts.sni || SNI_BY_HOST[parsed.hostname] || '').trim();
    if (!sni || net.isIP(sni)) {
        failStartup('Falta un SNI valido para ' + parsed.hostname + '. Usa --sni nombre-del-certificado.');
    }
    upstreams.push({
        host: parsed.hostname,
        port: Number(parsed.port || 443),
        path: parsed.pathname + parsed.search,
        sni,
        raw
    });
}
if (upstreams.length === 0) failStartup('No hay upstreams configurados.');

let lastLogKey = '';
let lastLogAt = 0;

function log(message, key) {
    const now = Date.now();
    if (key && key === lastLogKey && (now - lastLogAt) < 30000) return;
    lastLogKey = key || '';
    lastLogAt = now;
    const line = '[' + new Date().toISOString() + '] ' + message;
    console.log(line);
    if (!LOG_FILE) return;
    try {
        fs.appendFileSync(LOG_FILE, line + '\n', 'utf8');
    } catch (err) {
        // El log no debe tumbar el resolutor.
    }
}

if (LOG_FILE) {
    try {
        if (fs.statSync(LOG_FILE).size > 2 * 1024 * 1024) {
            const oldLog = LOG_FILE + '.old';
            if (fs.existsSync(oldLog)) fs.unlinkSync(oldLog);
            fs.renameSync(LOG_FILE, oldLog);
        }
    } catch (err) {
        // El archivo aun no existe.
    }
}

const startedAt = new Date().toISOString();
const status = {
    pid: process.pid,
    startedAt,
    listen: LISTEN_HOST + ':' + LISTEN_PORT,
    socks: SOCKS_HOST + ':' + SOCKS_PORT,
    protocol: 'h2',
    upstreams: upstreams.map((u) => u.raw + ' (sni=' + u.sni + ')'),
    totalQueries: 0,
    successes: 0,
    failures: 0,
    consecutiveFailures: 0,
    inflight: 0,
    queue: 0,
    lastSuccessAt: null,
    lastFailureAt: null,
    lastError: null,
    lastUpstream: null,
    updatedAt: startedAt
};
let lastStatusWrite = 0;

function writeStatus(force) {
    const now = Date.now();
    if (!force && (now - lastStatusWrite) < 1000) return;
    lastStatusWrite = now;
    status.updatedAt = new Date().toISOString();
    try {
        fs.mkdirSync(path.dirname(STATUS_FILE), { recursive: true });
        const tmp = STATUS_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(status, null, 2), 'utf8');
        fs.renameSync(tmp, STATUS_FILE);
    } catch (err) {
        // El estado es diagnostico; no debe tumbar el puente.
    }
}

writeStatus(true);

function encodeSocksHost(host) {
    const family = net.isIP(host);
    if (family === 4) {
        const parts = host.split('.').map(Number);
        return Buffer.from([0x01, parts[0], parts[1], parts[2], parts[3]]);
    }
    if (family === 6) {
        throw new Error('SOCKS5 IPv6 no soportado; usa un upstream IPv4.');
    }
    const name = Buffer.from(host, 'utf8');
    if (name.length > 255) throw new Error('Host SOCKS5 demasiado largo.');
    return Buffer.concat([Buffer.from([0x03, name.length]), name]);
}

function socksConnect(destHost, destPort, timeoutMs) {
    return new Promise((resolve, reject) => {
        const socket = net.connect({ host: SOCKS_HOST, port: SOCKS_PORT });
        let buffer = Buffer.alloc(0);
        let stage = 'greeting';
        let settled = false;
        const timer = setTimeout(() => fail(new Error('Timeout SOCKS5.')), timeoutMs);

        function cleanup() {
            clearTimeout(timer);
            socket.removeListener('data', onData);
            socket.removeListener('error', onError);
        }
        function fail(err) {
            if (settled) return;
            settled = true;
            cleanup();
            socket.destroy();
            reject(err);
        }
        function onError(err) {
            fail(err);
        }
        function onData(chunk) {
            buffer = Buffer.concat([buffer, chunk]);
            try {
                if (stage === 'greeting') {
                    if (buffer.length < 2) return;
                    if (buffer[0] !== 0x05) throw new Error('Version SOCKS5 invalida.');
                    if (buffer[1] !== 0x00) throw new Error('Tor no acepto el metodo sin autenticacion.');
                    buffer = buffer.subarray(2);
                    stage = 'connect';
                    const hostBuf = encodeSocksHost(destHost);
                    const portBuf = Buffer.alloc(2);
                    portBuf.writeUInt16BE(destPort, 0);
                    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), hostBuf, portBuf]));
                }
                if (stage === 'connect') {
                    if (buffer.length < 4) return;
                    if (buffer[0] !== 0x05) throw new Error('Respuesta SOCKS5 invalida.');
                    if (buffer[1] !== 0x00) throw new Error('SOCKS5 CONNECT rechazado (codigo ' + buffer[1] + ').');
                    const atyp = buffer[3];
                    let addrLen;
                    if (atyp === 0x01) addrLen = 4;
                    else if (atyp === 0x04) addrLen = 16;
                    else if (atyp === 0x03) {
                        if (buffer.length < 5) return;
                        addrLen = 1 + buffer[4];
                    } else {
                        throw new Error('SOCKS5 ATYP desconocido.');
                    }
                    const total = 4 + addrLen + 2;
                    if (buffer.length < total) return;
                    settled = true;
                    cleanup();
                    resolve(socket);
                }
            } catch (err) {
                fail(err);
            }
        }

        socket.on('connect', () => {
            socket.setNoDelay(true);
            socket.write(Buffer.from([0x05, 0x01, 0x00]));
        });
        socket.on('data', onData);
        socket.on('error', onError);
    });
}

function tlsConnect(socket, upstream, timeoutMs) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            socket.destroy();
            reject(new Error('Timeout TLS.'));
        }, timeoutMs);
        const secure = tls.connect({
            socket,
            servername: upstream.sni,
            rejectUnauthorized: true,
            ALPNProtocols: ['h2']
        }, () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (!secure.authorized) {
                secure.destroy();
                reject(new Error('Certificado TLS no valido.'));
                return;
            }
            if (secure.alpnProtocol !== 'h2') {
                secure.destroy();
                reject(new Error('El upstream no negocio HTTP/2 (ALPN=' + secure.alpnProtocol + ').'));
                return;
            }
            resolve(secure);
        });
        secure.on('error', (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(err);
        });
    });
}

function h2Post(secure, upstream, query, timeoutMs) {
    return new Promise((resolve, reject) => {
        let settled = false;
        let session = null;
        let request = null;
        let httpStatus = 0;
        const chunks = [];
        const timer = setTimeout(() => fail(new Error('Timeout DoH/HTTP2.')), timeoutMs);

        function cleanup() {
            clearTimeout(timer);
            if (request) {
                try { request.close(); } catch (err) { /* ya cerrado */ }
            }
            if (session) {
                try { session.close(); } catch (err) { /* ya cerrado */ }
            }
            if (!secure.destroyed) secure.destroy();
        }
        function fail(err) {
            if (settled) return;
            settled = true;
            cleanup();
            reject(err);
        }
        function finish() {
            if (settled) return;
            settled = true;
            cleanup();
            resolve(Buffer.concat(chunks));
        }

        try {
            session = http2.connect('https://' + upstream.sni, {
                createConnection: () => secure,
                settings: { enablePush: false }
            });
        } catch (err) {
            fail(err);
            return;
        }

        session.on('error', fail);
        session.on('goaway', (code) => fail(new Error('HTTP/2 GOAWAY ' + code + '.')));

        try {
            request = session.request({
                ':method': 'POST',
                ':path': upstream.path,
                ':authority': upstream.sni,
                'content-type': 'application/dns-message',
                'accept': 'application/dns-message',
                'content-length': query.length,
                'user-agent': 'AdGuardHome-Fortress-DoH-Tor/2.0'
            });
        } catch (err) {
            fail(err);
            return;
        }

        request.on('response', (headers) => {
            httpStatus = Number(headers[':status']);
            if (httpStatus !== 200) {
                fail(new Error('DoH devolvio HTTP ' + httpStatus + '.'));
            }
        });
        request.on('data', (chunk) => {
            chunks.push(Buffer.from(chunk));
        });
        request.on('end', () => {
            if (settled) return;
            if (httpStatus !== 200) {
                fail(new Error('DoH devolvio HTTP ' + httpStatus + '.'));
                return;
            }
            if (chunks.length === 0) {
                fail(new Error('DoH devolvio una respuesta vacia.'));
                return;
            }
            finish();
        });
        request.on('error', fail);
        request.setTimeout(timeoutMs, () => {
            try { request.close(http2.constants.NGHTTP2_CANCEL); } catch (err) { /* ya cerrado */ }
            fail(new Error('Timeout HTTP/2.'));
        });
        request.end(query);
    });
}

async function queryUpstream(upstream, query) {
    const deadline = Date.now() + TIMEOUT_MS;
    const remaining = () => Math.max(1, deadline - Date.now());
    let socket = null;
    try {
        socket = await socksConnect(upstream.host, upstream.port, remaining());
        const secure = await tlsConnect(socket, upstream, remaining());
        return await h2Post(secure, upstream, query, remaining());
    } catch (err) {
        if (socket && !socket.destroyed) socket.destroy();
        throw err;
    }
}

async function forward(query) {
    if (query.length < 12) throw new Error('Consulta DNS demasiado corta.');
    if (query.length > 65535) throw new Error('Consulta DNS demasiado grande.');
    let lastError = null;
    for (const upstream of upstreams) {
        try {
            const response = await queryUpstream(upstream, query);
            status.lastUpstream = upstream.raw;
            return response;
        } catch (err) {
            lastError = err;
            log('WARN upstream ' + upstream.raw + ': ' + err.message, 'upstream:' + upstream.raw + ':' + err.message);
        }
    }
    throw lastError || new Error('No hay upstream disponible.');
}

function makeServfail(query) {
    if (!Buffer.isBuffer(query) || query.length < 12) return null;
    const response = Buffer.from(query);
    response[2] = (response[2] | 0x80) & 0xfb; // QR=1, AA=0, TC=0, RD se conserva
    response[3] = (response[3] & 0xf0) | 0x02; // RA=1, RCODE=SERVFAIL
    response.writeUInt16BE(0, 6);
    response.writeUInt16BE(0, 8);
    response.writeUInt16BE(0, 10);
    return response;
}

let inflight = 0;
const queue = [];

function schedule(task) {
    if (inflight >= MAX_INFLIGHT) {
        if (queue.length >= QUEUE_LIMIT) {
            log('WARN cola llena; consulta descartada.', 'queue-full');
            return false;
        }
        queue.push(task);
        status.queue = queue.length;
        writeStatus(false);
        return true;
    }
    inflight++;
    status.inflight = inflight;
    Promise.resolve()
        .then(task)
        .catch((err) => log('ERROR ' + err.message, 'task:' + err.message))
        .finally(() => {
            inflight--;
            status.inflight = inflight;
            const next = queue.shift();
            status.queue = queue.length;
            writeStatus(false);
            if (next) schedule(next);
        });
    return true;
}

const udpServer = dgram.createSocket('udp4');
udpServer.on('message', (message, remote) => {
    if (message.length < 12) return;
    status.totalQueries++;
    const accepted = schedule(async () => {
        try {
            const response = await forward(message);
            status.successes++;
            status.consecutiveFailures = 0;
            status.lastSuccessAt = new Date().toISOString();
            status.lastError = null;
            if (!udpServer.closed) udpServer.send(response, remote.port, remote.address);
        } catch (err) {
            status.failures++;
            status.consecutiveFailures++;
            status.lastFailureAt = new Date().toISOString();
            status.lastError = err.message;
            log('ERROR UDP ' + err.message, 'udp:' + err.message);
            const servfail = makeServfail(message);
            if (servfail && !udpServer.closed) udpServer.send(servfail, remote.port, remote.address);
        } finally {
            writeStatus(false);
        }
    });
    if (!accepted) {
        const servfail = makeServfail(message);
        if (servfail && !udpServer.closed) udpServer.send(servfail, remote.port, remote.address);
    }
});
udpServer.on('error', (err) => {
    log('FATAL UDP ' + err.message, 'fatal:udp');
    process.exit(1);
});
udpServer.bind(LISTEN_PORT, LISTEN_HOST, () => {
    log('DNS local escuchando en ' + LISTEN_HOST + ':' + LISTEN_PORT + ' (UDP, HTTP/2).');
});

const tcpServer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.setTimeout(30000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 2) {
            const length = buffer.readUInt16BE(0);
            if (length === 0 || buffer.length < 2 + length) break;
            const query = Buffer.from(buffer.subarray(2, 2 + length));
            buffer = buffer.subarray(2 + length);
            status.totalQueries++;
            const accepted = schedule(async () => {
                try {
                    const response = await forward(query);
                    status.successes++;
                    status.consecutiveFailures = 0;
                    status.lastSuccessAt = new Date().toISOString();
                    status.lastError = null;
                    if (socket.destroyed) return;
                    const framed = Buffer.alloc(2 + response.length);
                    framed.writeUInt16BE(response.length, 0);
                    response.copy(framed, 2);
                    socket.write(framed);
                } catch (err) {
                    status.failures++;
                    status.consecutiveFailures++;
                    status.lastFailureAt = new Date().toISOString();
                    status.lastError = err.message;
                    log('ERROR TCP ' + err.message, 'tcp:' + err.message);
                    if (!socket.destroyed) {
                        const servfail = makeServfail(query);
                        if (servfail) {
                            const framed = Buffer.alloc(2 + servfail.length);
                            framed.writeUInt16BE(servfail.length, 0);
                            servfail.copy(framed, 2);
                            socket.write(framed);
                        }
                        socket.end();
                    }
                } finally {
                    writeStatus(false);
                }
            });
            if (!accepted && !socket.destroyed) {
                const servfail = makeServfail(query);
                if (servfail) {
                    const framed = Buffer.alloc(2 + servfail.length);
                    framed.writeUInt16BE(servfail.length, 0);
                    servfail.copy(framed, 2);
                    socket.write(framed);
                }
            }
        }
    });
});
tcpServer.on('error', (err) => {
    log('FATAL TCP ' + err.message, 'fatal:tcp');
    process.exit(1);
});
tcpServer.listen(LISTEN_PORT, LISTEN_HOST, () => {
    log('DNS local escuchando en ' + LISTEN_HOST + ':' + LISTEN_PORT + ' (TCP, HTTP/2).');
});

log('Puente DoH-over-Tor iniciado. SOCKS5 ' + SOCKS_HOST + ':' + SOCKS_PORT +
    '; upstreams: ' + upstreams.map((u) => u.raw + ' sni=' + u.sni).join(', '));
writeStatus(true);

function shutdown(signal) {
    log('Deteniendo por ' + signal + '.', 'shutdown:' + signal);
    try { udpServer.close(); } catch (err) { /* ya cerrado */ }
    try { tcpServer.close(); } catch (err) { /* ya cerrado */ }
    writeStatus(true);
    process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGBREAK', () => shutdown('SIGBREAK'));
process.on('uncaughtException', (err) => {
    log('FATAL ' + (err.stack || err), 'fatal:uncaught');
    writeStatus(true);
    process.exit(1);
});
process.on('unhandledRejection', (err) => {
    log('FATAL ' + (err && err.stack ? err.stack : err), 'fatal:rejection');
    writeStatus(true);
    process.exit(1);
});
