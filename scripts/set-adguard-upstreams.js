#!/usr/bin/env node
/*
 * Ajusta los upstreams DNS de AdGuard Home por su API local.
 *
 * Evita editar AdGuardHome.yaml mientras el servicio lo tiene bloqueado.
 * La contrasena se lee de config/.env y NUNCA se imprime.
 *
 * Uso:
 *   node set-adguard-upstreams.js
 */
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const BASE_DIR = process.env.FORTRESS_DIR || path.join(__dirname, '..');
const ENV_PATHS = [
    process.env.ENV_FILE,
    path.join(BASE_DIR, 'config', '.env'),
    path.join(BASE_DIR, '.env'),
    'C:\\AdGuardHome\\config\\.env',
    'C:\\AdGuardHome\\.env'
].filter(Boolean);

function loadEnv() {
    const env = {};
    for (const file of ENV_PATHS) {
        try {
            if (!fs.existsSync(file)) continue;
            const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
            for (const line of lines) {
                const m = line.trim().match(/^([A-Za-z0-9_]+)=(.*)$/);
                if (m) env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
            }
            break;
        } catch (err) {
            // Probar la siguiente ruta.
        }
    }
    return env;
}

const env = loadEnv();
const host = process.env.AGH_HOST || env.AGH_HOST || '127.0.0.1';
const port = parseInt(process.env.AGH_PORT || env.AGH_PORT || '3000', 10);
const user = env.ADGUARD_USERNAME || process.env.ADGUARD_USERNAME || 'admin';
const pass = env.ADGUARD_PASSWORD || process.env.ADGUARD_PASSWORD;

const DESIRED_UPSTREAMS = [
    '127.0.0.1:5336',
    '[/onion/]127.0.0.1:5350'
];
const DESIRED_BOOTSTRAP = ['127.0.0.1:5336'];

function request(method, endpoint, body) {
    return new Promise((resolve, reject) => {
        const auth = Buffer.from(user + ':' + pass).toString('base64');
        const data = body ? JSON.stringify(body) : null;
        const headers = { Authorization: 'Basic ' + auth };
        if (data) {
            headers['Content-Type'] = 'application/json';
            headers['Content-Length'] = Buffer.byteLength(data);
        }
        const req = http.request({
            hostname: host,
            port,
            path: endpoint,
            method,
            headers,
            timeout: 10000
        }, (res) => {
            let text = '';
            res.on('data', (chunk) => { text += chunk; });
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(text ? JSON.parse(text) : {}); }
                    catch (err) { resolve(text); }
                } else {
                    reject(new Error('HTTP ' + res.statusCode + ': ' + text.slice(0, 300)));
                }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Timeout API AdGuard.')));
        if (data) req.write(data);
        req.end();
    });
}

function sanitize(cfg) {
    return {
        upstream_dns: cfg.upstream_dns,
        bootstrap_dns: cfg.bootstrap_dns,
        fallback_dns: cfg.fallback_dns,
        upstream_mode: cfg.upstream_mode,
        enable_dnssec: cfg.enable_dnssec,
        port: cfg.port
    };
}

(async () => {
    if (!pass) {
        console.error('Falta ADGUARD_PASSWORD en config/.env o en el entorno.');
        process.exit(2);
    }
    try {
        const current = await request('GET', '/control/dns_info');
        const before = sanitize(current);
        console.log('Antes: ' + JSON.stringify(before));
        const updated = {
            upstream_dns: DESIRED_UPSTREAMS,
            bootstrap_dns: DESIRED_BOOTSTRAP,
            fallback_dns: [],
            upstream_mode: 'parallel'
        };
        await request('POST', '/control/dns_config', updated);
        const after = await request('GET', '/control/dns_info');
        const clean = sanitize(after);
        console.log('Despues: ' + JSON.stringify(clean));
        const upstreams = Array.isArray(clean.upstream_dns) ? clean.upstream_dns : [];
        const publicOnes = upstreams.filter((u) => /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(String(u)) && !String(u).startsWith('127.'));
        const hasBridge = upstreams.some((u) => String(u).includes('127.0.0.1:5336'));
        const hasOnion = upstreams.some((u) => String(u).includes('5350'));
        if (publicOnes.length > 0) {
            console.error('ERROR: quedan upstreams publicos: ' + publicOnes.join(', '));
            process.exit(3);
        }
        if (!hasBridge || !hasOnion) {
            console.error('ERROR: faltan 5336 o 5350 en upstream_dns.');
            process.exit(4);
        }
        console.log('OK: solo puente Tor y .onion.');
    } catch (err) {
        console.error('No se pudo actualizar AdGuard: ' + err.message);
        process.exit(1);
    }
})();
