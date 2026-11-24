// Tests unitarios del centinela (sin red, sin admin, sin credenciales).
// Se ejecutan con: node --test tests/

const test = require('node:test');
const assert = require('node:assert');

const guard = require('../scripts/ai_dns_guard.js');

test('AI_MODE por defecto es aggregate (privacidad primero)', () => {
  assert.strictEqual(guard.AI_MODE, 'aggregate');
});

test('entropia de Shannon distingue dominio normal de cadena aleatoria', () => {
  assert.ok(guard.calculateEntropy('google') < 3.0);
  assert.ok(guard.calculateEntropy('q7w2e9r4t1y6u3i8o5p0') > 3.5);
  assert.strictEqual(guard.calculateEntropy(''), 0);
});

test('extraccion de apex en dominios de dos niveles', () => {
  assert.strictEqual(guard.extractApexLabel('cdn.example.com'), 'example');
  assert.strictEqual(guard.extractApexLabel('mail.empresa.com.es'), 'empresa');
  assert.strictEqual(guard.extractApexLabel('localhost'), 'localhost');
});

test('deteccion de beaconing con intervalos perfectos', () => {
  const base = 1700000000000;
  const times = [0, 1, 2, 3].map((i) => base + i * 10000);
  const beacon = guard.detectBeaconing(times);
  assert.ok(beacon, 'deberia detectar periodos de 10s');
  assert.ok(Math.abs(beacon.avg - 10) < 0.01);
  assert.ok(beacon.stddev < 0.01);
});

test('sin periodicidad no hay falso positivo de beaconing', () => {
  const base = 1700000000000;
  const times = [base, base + 5000, base + 55000, base + 200000];
  assert.strictEqual(guard.detectBeaconing(times), null);
});

test('menos de tres muestras no dispara beaconing', () => {
  assert.strictEqual(guard.detectBeaconing([1, 2]), null);
});

test('la redaccion no filtra el dominio original', () => {
  const out = guard.redactDomain('secreto-muy-privado.example.com');
  assert.ok(!out.includes('secreto'), 'no debe contener la etiqueta original');
  assert.ok(!out.includes('secreto-muy-privado'));
  assert.match(out, /^sha256:[0-9a-f]{20}/);
  assert.match(out, /tld=com/);
});

test('la redaccion es estable para el mismo dominio', () => {
  const a = guard.redactDomain('uno.example.com');
  const b = guard.redactDomain('uno.example.com');
  assert.strictEqual(a, b);
});

test('la redaccion cambia entre dominios distintos', () => {
  assert.notStrictEqual(
    guard.redactDomain('uno.example.com'),
    guard.redactDomain('dos.example.com'),
  );
});

test('heuristica local: cadena DGA larga se marca maliciosa', () => {
  const dga = 'q7w2e9r4t1y6u3i8o5p0a7s2d9f4g';
  assert.strictEqual(guard.heuristicVerdict(dga, guard.calculateEntropy(dga)), 'MALICIOUS');
});

test('heuristica local: dominios legitimos no se marcan', () => {
  for (const safe of ['google', 'wikipedia', 'microsoft', 'bancosantander']) {
    assert.strictEqual(
      guard.heuristicVerdict(safe, guard.calculateEntropy(safe)),
      'SAFE',
      `${safe} no deberia marcarse`,
    );
  }
});

test('allowlist reconoce subdominios de plataformas conocidas', () => {
  assert.strictEqual(guard.isKnownBenign('api.github.com'), true);
  assert.strictEqual(guard.isKnownBenign('algo.raro.example'), false);
});
