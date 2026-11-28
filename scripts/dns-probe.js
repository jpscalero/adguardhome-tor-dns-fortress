#!/usr/bin/env node
/*
 * Sonda DNS minima y portable para la fortaleza.
 *
 * Windows nslookup NO soporta -port, y Resolve-DnsName tampoco tiene -Port.
 * Esta sonda habla DNS por UDP o TCP contra el puerto exacto, sin depender
 * del resolver del sistema ni de herramientas externas.
 *
 * Uso:
 *   node dns-probe.js --name example.com --server 127.0.0.1 --port 5336
 *   node dns-probe.js --name dnssec-failed.org --server 127.0.0.1 --port 53 --dnssec
 *   node dns-probe.js --name example.com --server 127.0.0.1 --port 5336 --tcp
 *
 * Salida: JSON en stdout. Codigo 0 = NOERROR con respuesta; 2 = respuesta DNS
 * con error (p. ej. SERVFAIL); 1 = fallo de red/timeout.
 */
'use strict';

const dgram = require('dgram');
const net = require('net');

function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (!arg.startsWith('--')) continue;
        const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
            out[key] = next;
            i++;
        } else {
            out[key] = true;
        }
    }
    return out;
}

const opts = parseArgs(process.argv.slice(2));
const name = String(opts.name || 'example.com').trim().replace(/\.$/, '');
const server = String(opts.server || '127.0.0.1');
const port = Number(opts.port || 53);
const timeoutMs = Number(opts.timeout || 12000);
const useTcp = Boolean(opts.tcp);
const dnssec = Boolean(opts.dnssec);

if (!name || !Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('Parametros invalidos.');
    process.exit(1);
}

function buildQuery() {
    const labels = name.split('.');
    const parts = [];
    const id = Math.floor(Math.random() * 65535) + 1;
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(0x0100, 2); // RD
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(0, 6);
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(dnssec ? 1 : 0, 10); // ARCOUNT: OPT si DO
    parts.push(header);
    for (const label of labels) {
        const bytes = Buffer.from(label, 'ascii');
        if (bytes.length === 0 || bytes.length > 63) throw new Error('Etiqueta DNS invalida.');
        parts.push(Buffer.from([bytes.length]), bytes);
    }
    parts.push(Buffer.from([0]));
    const qtype = Buffer.alloc(4);
    qtype.writeUInt16BE(1, 0); // A
    qtype.writeUInt16BE(1, 2); // IN
    parts.push(qtype);
    if (dnssec) {
        const opt = Buffer.alloc(11);
        opt.writeUInt8(0, 0); // nombre raiz
        opt.writeUInt16BE(41, 1); // OPT
        opt.writeUInt16BE(4096, 3); // UDP payload
        opt.writeUInt32BE(0x00008000, 5); // DO
        opt.writeUInt16BE(0, 9); // RDLEN
        parts.push(opt);
    }
    return { id, packet: Buffer.concat(parts) };
}

function parseResponse(buffer) {
    if (buffer.length < 12) throw new Error('Respuesta DNS demasiado corta.');
    const id = buffer.readUInt16BE(0);
    const flags = buffer.readUInt16BE(2);
    const qd = buffer.readUInt16BE(4);
    const an = buffer.readUInt16BE(6);
    const ns = buffer.readUInt16BE(8);
    const ar = buffer.readUInt16BE(10);
    const rcode = flags & 0x000f;
    return { id, flags, qd, an, ns, ar, rcode, truncated: Boolean(flags & 0x0200) };
}

function udpQuery(id, packet) {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            try { socket.close(); } catch (err) { /* ya cerrado */ }
            reject(new Error('Timeout UDP.'));
        }, timeoutMs);
        function finish(err, value) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { socket.close(); } catch (closeErr) { /* ya cerrado */ }
            if (err) reject(err); else resolve(value);
        }
        socket.on('error', (err) => finish(err));
        socket.on('message', (message) => {
            try {
                if (message.length >= 2 && message.readUInt16BE(0) === id) finish(null, message);
            } catch (err) {
                finish(err);
            }
        });
        socket.send(packet, port, server, (err) => {
            if (err) finish(err);
        });
    });
}

function tcpQuery(id, packet) {
    return new Promise((resolve, reject) => {
        const socket = net.connect({ host: server, port });
        let buffer = Buffer.alloc(0);
        let settled = false;
        const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            socket.destroy();
            reject(new Error('Timeout TCP.'));
        }, timeoutMs);
        function finish(err, value) {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.destroy();
            if (err) reject(err); else resolve(value);
        }
        socket.on('connect', () => {
            const frame = Buffer.alloc(2 + packet.length);
            frame.writeUInt16BE(packet.length, 0);
            packet.copy(frame, 2);
            socket.write(frame);
        });
        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            if (buffer.length < 2) return;
            const length = buffer.readUInt16BE(0);
            if (buffer.length < 2 + length) return;
            const message = buffer.subarray(2, 2 + length);
            try {
                if (message.readUInt16BE(0) !== id) throw new Error('ID DNS no coincide.');
                finish(null, message);
            } catch (err) {
                finish(err);
            }
        });
        socket.on('error', (err) => finish(err));
    });
}

(async () => {
    const start = Date.now();
    let query;
    try {
        query = buildQuery();
        const response = useTcp ? await tcpQuery(query.id, query.packet) : await udpQuery(query.id, query.packet);
        const parsed = parseResponse(response);
        const result = {
            ok: parsed.rcode === 0 && parsed.an > 0,
            name,
            server,
            port,
            transport: useTcp ? 'tcp' : 'udp',
            dnssec,
            rcode: parsed.rcode,
            answers: parsed.an,
            authority: parsed.ns,
            additional: parsed.ar,
            truncated: parsed.truncated,
            bytes: response.length,
            elapsedMs: Date.now() - start,
            error: parsed.rcode === 0 ? null : 'DNS RCODE ' + parsed.rcode
        };
        console.log(JSON.stringify(result));
        process.exit(result.ok ? 0 : 2);
    } catch (err) {
        console.log(JSON.stringify({
            ok: false,
            name,
            server,
            port,
            transport: useTcp ? 'tcp' : 'udp',
            elapsedMs: Date.now() - start,
            error: err.message
        }));
        process.exit(1);
    }
})();
