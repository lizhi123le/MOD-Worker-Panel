/**
 * smoke.mjs
 *
 * Functional gate for the obfuscated worker. Run: node smoke.mjs [reference] [artifact]
 *
 * Defaults: reference = output/_worker.reference.js (post-uglify, PRE obfuscation)
 *           artifact  = output/_worker.js         (post obfuscation)
 *
 * It loads both bundles in Node with Cloudflare-ish stubs (WebSocketPair,
 * cloudflare:sockets, fetch) and replays one realistic session against each:
 *
 *   /login, /panel, POST /panel (401), POST /login (wrong + right password),
 *   authenticated POST /panel, authenticated /panel, /sub/<uuid>, /fragsub/<uuid>,
 *   /logout, an unknown path (getMyIP) and two websocket upgrades (/, /tr).
 *
 * Both runs get a seeded Math.random and a frozen Date.now, so every response
 * must be byte-identical. Any difference means the obfuscation changed behaviour.
 *
 * Without a reference it asserts that the panel pages still contain their
 * expected content (auditing a downloaded _worker.js).
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'fs';
import { pathToFileURL } from 'url';
import { join } from 'path';

const FLAGS = process.argv.slice(2).filter((a) => a.startsWith('--'));
const POSITIONAL = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const REFERENCE = POSITIONAL[0] || 'output/_worker.reference.js';
const ARTIFACT = POSITIONAL[1] || 'output/_worker.js';
const TMP = 'output/_smoke';
const UUID = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'Testpass1';
const FIXED_NOW = 1735689600000; // 2025-01-01T00:00:00Z

// Let a pending WebSocket pipeTo() promise rot instead of killing the process.
// (uncaughtException is deliberately NOT swallowed: a real crash must fail the gate.)
process.on('unhandledRejection', (reason) => {
  console.log(`  note  unhandled rejection (ignored): ${reason && reason.message ? reason.message : reason}`);
});

// ------------------------------------------------------------------- CF stubs
class FakeWebSocket {
  constructor() {
    this.readyState = 1;
    this.listeners = {};
  }
  accept() {}
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  close() {}
  send() {}
}

function installStubs() {
  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = new FakeWebSocket();
      this[1] = new FakeWebSocket();
    }
  };

  // undici refuses status 101, which the proxy handlers legitimately return.
  const RealResponse = globalThis.Response;
  globalThis.Response = class extends RealResponse {
    constructor(body, init = {}) {
      if (init && init.status === 101) {
        super(null);
        Object.defineProperty(this, 'status', { value: 101 });
        Object.defineProperty(this, 'webSocket', { value: init.webSocket });
      } else {
        super(body, init);
      }
    }
  };

  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url.includes('ip-api.com')) {
      return new RealResponse(JSON.stringify({ status: 'success', query: '203.0.113.7', country: 'Testland', city: 'Testville' }), {
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.includes('cloudflare-dns.com')) {
      return new RealResponse(JSON.stringify({ Answer: [{ data: '1.1.1.1' }, { data: '2606:4700::1111' }] }), {
        headers: { 'content-type': 'application/json' },
      });
    }
    return new RealResponse(JSON.stringify({ ok: false, stubbed: true }), { headers: { 'content-type': 'application/json' } });
  };
}

function makeKv(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    store,
    async get(key, opts) {
      const value = store.has(key) ? store.get(key) : null;
      if (value === null) return null;
      if (opts && opts.type === 'json') return typeof value === 'string' ? JSON.parse(value) : value;
      return value;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

/** Wall-clock cost of the concealed-string path (GET /login). */
async function benchSession(modulePath, tag, rounds) {
  const env = {
    ID: UUID,
    PASS: 'trojan-secret',
    HASH: 'trojan-hash',
    DATABASE: 'KV',
    PROXYIP: '203.0.113.9',
    KV: makeKv({}),
  };
  const request = () => new Request('https://panel.example.com/login', { headers: { Host: 'panel.example.com' } });

  // Cold: module evaluation + the very first request. This is where every
  // concealed string is decrypted once (js-confuser caches per payload index),
  // so it is the number that matters for the Workers CPU/startup budget.
  const coldStart = performance.now();
  const mod = await import(pathToFileURL(modulePath).href + '?bench=' + tag);
  await (await mod.default.fetch(request(), env)).text();
  const cold = performance.now() - coldStart;

  for (let i = 0; i < 50; i++) await (await mod.default.fetch(request(), env)).text();
  const start = performance.now();
  for (let i = 0; i < rounds; i++) await (await mod.default.fetch(request(), env)).text();
  const warm = (performance.now() - start) / rounds;

  return { cold, warm };
}

// ---------------------------------------------------------------- preparation
function prepareBundle(sourcePath, name) {
  const raw = readFileSync(sourcePath, 'utf8');
  const rewritten = raw.replace(/from\s*(["'])cloudflare:sockets\1/g, 'from"./cf-sockets.mjs"');
  if (rewritten === raw && raw.includes('cloudflare:sockets')) {
    throw new Error(`${sourcePath}: could not rewrite the cloudflare:sockets import`);
  }
  const out = join(TMP, name);
  writeFileSync(out, rewritten);
  return out;
}

// -------------------------------------------------------------------- running
async function runSession(modulePath, tag) {
  const mod = await import(pathToFileURL(modulePath).href + '?run=' + tag);
  const handler = mod.default;

  const kv = makeKv({});
  const env = {
    ID: UUID,
    PASS: 'trojan-secret',
    HASH: 'trojan-hash',
    DATABASE: 'KV',
    PROXYIP: '203.0.113.9',
    KV: kv,
  };

  const origin = 'https://panel.example.com';
  const results = [];
  const errorPages = new Set();
  let cookie = null;

  const seeded = seededRandom(12345);
  const realRandom = Math.random;
  const realNow = Date.now;
  Math.random = seeded;
  Date.now = () => FIXED_NOW;

  const call = async (name, path, init = {}) => {
    let record;
    try {
      // Node's undici does not synthesise a Host header, but the worker reads it.
      const request = new Request(origin + path, {
        ...init,
        headers: { Host: 'panel.example.com', ...(init.headers || {}) },
      });
      const response = await handler.fetch(request, env);
      let body = null;
      try {
        body = await response.clone().text();
      } catch {
        body = '<unreadable>';
      }
      const setCookie = response.headers.get('set-cookie');
      if (setCookie && setCookie.includes('jwtToken=') && !setCookie.includes('Max-Age=0')) {
        cookie = setCookie.split(';')[0];
      }
      // Stack frames carry the build's own file name, line and mangled function
      // names, so they can never match between the two bundles. Collapse them
      // (on both sides, deterministically) and keep the error message itself.
      const normalizedBody = body === null ? null : body.replace(/\s+at\s[^\n]*/g, ' <frame>');
      if (typeof normalizedBody === 'string' && ERRORS.some((e) => normalizedBody.includes(e))) {
        errorPages.add(name);
      }
      record = {
        status: response.status,
        type: response.headers.get('content-type'),
        cookie: setCookie ? (/jwtToken=[^;]{10,}/.test(setCookie) ? '<jwt>' : setCookie) : null,
        body: normalizedBody,
      };
    } catch (error) {
      record = { threw: String(error && error.message ? error.message : error) };
    }
    results.push([name, record]);
  };

  const form = (fields) =>
    Object.entries(fields)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

  await call('GET /login', '/login');
  await call('GET /panel (no password set)', '/panel');
  await call('POST /panel (unauthenticated)', '/panel', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ remoteDNS: 'https://8.8.8.8/dns-query' }),
  });
  await call('POST /panel/password (first-run set)', '/panel/password', { method: 'POST', body: PASSWORD });
  await call('POST /login (wrong password)', '/login', { method: 'POST', body: 'wrong-password' });
  await call('POST /login (correct password)', '/login', { method: 'POST', body: PASSWORD });
  await call('POST /panel (authenticated)', '/panel', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookie || '' },
    // cleanIPs matters: every subscription generator takes its server addresses
    // from the Clean IP pool, so without it every subscription is empty.
    body: form({
      remoteDNS: 'https://8.8.8.8/dns-query',
      cleanIPs: '104.16.0.1,104.17.0.2',
      ports: '443,8443',
      vlessConfigs: 'true',
      trojanConfigs: 'true',
    }),
  });
  await call('GET /panel (authenticated)', '/panel', { headers: { cookie: cookie || '' } });
  await call('GET /logout', '/logout');

  // Subscription surface. Every variant is exercised even when the checkout does
  // not implement it (then both builds just return the same fallback).
  await call(`GET /sub/<uuid>`, `/sub/${UUID}`);
  await call(`GET /sub/<uuid>?app=singbox`, `/sub/${UUID}?app=singbox`);
  await call(`GET /sub/<uuid>?app=sfa`, `/sub/${UUID}?app=sfa`);
  await call(`GET /sub/<uuid>?app=xray`, `/sub/${UUID}?app=xray`);
  await call(`GET /sub/<uuid>?app=clash`, `/sub/${UUID}?app=clash`);
  await call(`GET /fragsub/<uuid>`, `/fragsub/${UUID}`);
  await call(`GET /fragsub/<uuid>?app=hiddify`, `/fragsub/${UUID}?app=hiddify`);

  await call('GET /unknown (getMyIP)', '/anything-else', { method: 'POST', body: '203.0.113.7' });
  await call('WS upgrade /', '/', { headers: { Upgrade: 'websocket', 'sec-websocket-protocol': 'earlyData' } });
  await call('WS upgrade /tr', '/tr', { headers: { Upgrade: 'websocket', 'sec-websocket-protocol': 'earlyData' } });

  // Mutating scenarios run last so they cannot spoil the authenticated flow.
  await call('POST /panel/password (too weak)', '/panel/password', { method: 'POST', body: 'weak' });
  for (let attempt = 1; attempt <= 6; attempt++) {
    await call(`POST /login (failure #${attempt})`, '/login', { method: 'POST', body: `wrong-${attempt}` });
  }

  Math.random = realRandom;
  Date.now = realNow;
  lastErrorPages = errorPages;
  return results;
}

/** Routes that answered with the panel's own error page during the last session. */
let lastErrorPages = new Set();
const ERRORS = ['Something went wrong!'];

/**
 * App-layer feature checks. Whether a checkout implements these is not part of
 * the obfuscation work, so an entry is enforced only when the reference build
 * (same source, no obfuscation) exhibits it. SMOKE_STRICT=on forces enforcement,
 * SMOKE_STRICT=off disables the block entirely.
 */
const FEATURES = {
  'POST /login (failure #6)': (result) => result.status === 429,
};
const STRICT_MODE = process.env.SMOKE_STRICT === 'on' ? 'on' : process.env.SMOKE_STRICT === 'off' ? 'off' : 'auto';

/** Content expectations used when there is no reference to compare against. */
const EXPECTED = {
  'GET /login': ['<!DOCTYPE html>', '<title>Login</title>', 'Enter your password'],
  'GET /panel (no password set)': ['<!DOCTYPE html>', 'FULL NORMAL SUB'],
  'GET /panel (authenticated)': ['<!DOCTYPE html>', 'FULL NORMAL SUB'],
  'GET /sub/<uuid>?app=sfa': ['"outbounds"', '"route"'],
  'GET /sub/<uuid>': (result) => result.status === 200 && (result.body || '').length > 0,
  'GET /fragsub/<uuid>': (result) => result.status === 200 && (result.body || '').length > 0,
};

// ----------------------------------------------------------------------- main
installStubs();
mkdirSync(TMP, { recursive: true });
writeFileSync(
  join(TMP, 'cf-sockets.mjs'),
  'export function connect() { throw new Error("cloudflare:sockets connect() is not available in the smoke test"); }\n'
);

let failures = 0;
try {
  const artifactPath = prepareBundle(ARTIFACT, 'artifact.mjs');
  let referencePath = null;
  if (existsSync(REFERENCE)) referencePath = prepareBundle(REFERENCE, 'reference.mjs');

  const artifactResults = await runSession(artifactPath, 'artifact');
  const artifactErrorPages = new Set(lastErrorPages);
  const referenceResults = referencePath ? await runSession(referencePath, 'reference') : null;
  const referenceErrorPages = new Set(lastErrorPages);
  console.log(`smoke: ${artifactResults.length} requests against ${ARTIFACT}`);

  // A route that answers with the panel error page is broken; say so loudly even
  // when both builds agree (parity would otherwise report a misleading PASS).
  for (const name of artifactErrorPages) {
    const alsoBrokenInSource = referenceErrorPages.has(name);
    console.log(
      `  WARN  ${name} answered with the panel error page` +
        (alsoBrokenInSource ? ' (identical in the un-obfuscated build: source bug, not obfuscation)' : ' (DIFFERENT from the reference!)')
    );
  }

  // App-layer feature checks (see FEATURES): enforced when the reference build
  // shows the feature, skipped when this checkout simply does not have it.
  const find = (results, name) => results?.find(([scenario]) => scenario === name)?.[1];
  if (STRICT_MODE !== 'off') {
    for (const [name, assertion] of Object.entries(FEATURES)) {
      const artifact = find(artifactResults, name);
      const reference = find(referenceResults, name);
      if (!artifact) {
        failures++;
        console.log(`  FAIL  ${name} (scenario missing)`);
      } else if (STRICT_MODE === 'on' || (reference && assertion(reference))) {
        if (assertion(artifact)) {
          console.log(`  PASS  ${name} (status ${artifact.status})`);
        } else {
          failures++;
          console.log(`  FAIL  ${name} (unexpected: ${describe(artifact)})`);
        }
      } else if (!reference) {
        console.log(`  WARN  ${name} (no reference to confirm the feature; observed ${describe(artifact)})`);
      } else {
        console.log(`  SKIP  ${name} (this checkout does not implement it; observed ${describe(artifact)})`);
      }
    }
  }

  if (referenceResults) {
    if (referenceResults.length !== artifactResults.length) {
      console.log('  FAIL  request counts differ');
      failures++;
    }
    for (let i = 0; i < artifactResults.length; i++) {
      const [nameA, a] = referenceResults[i];
      const [nameB, b] = artifactResults[i];
      if (nameA !== nameB) {
        console.log(`  FAIL  scenario order differs at #${i}: ${nameA} vs ${nameB}`);
        failures++;
        continue;
      }
      if (JSON.stringify(a) === JSON.stringify(b)) {
        console.log(`  PASS  ${nameB}`);
      } else {
        failures++;
        console.log(`  FAIL  ${nameB}`);
        console.log(`        reference: ${describe(a)}`);
        console.log(`        artifact : ${describe(b)}`);
        if (typeof a.body === 'string' && typeof b.body === 'string') {
          let offset = 0;
          while (offset < a.body.length && offset < b.body.length && a.body[offset] === b.body[offset]) offset++;
          console.log(`        first difference at offset ${offset}:`);
          console.log(`          reference: ${JSON.stringify(a.body.slice(Math.max(0, offset - 40), offset + 120))}`);
          console.log(`          artifact : ${JSON.stringify(b.body.slice(Math.max(0, offset - 40), offset + 120))}`);
        }
      }
    }
  } else {
    for (const [name, result] of artifactResults) {
      const expects = EXPECTED[name];
      const body = result.body || '';
      const ok = typeof expects === 'function'
        ? expects(result)
        : Array.isArray(expects) && expects.every((marker) => body.includes(marker));
      if (expects && ok) {
        console.log(`  PASS  ${name} (content markers found)`);
      } else if (expects) {
        failures++;
        console.log(`  FAIL  ${name} (unexpected content, ${describe(result)})`);
      } else {
        console.log(`  SKIP  ${name} (no expectation without a reference)`);
      }
    }
  }

  if (FLAGS.includes('--bench')) {
    const rounds = 400;
    const artifact = await benchSession(artifactPath, 'artifact', rounds);
    console.log(`\nbench: GET /login, ${rounds} warm iterations (Node wall clock, a proxy for Worker CPU)`);
    console.log(`  ${ARTIFACT.padEnd(34)} cold ${artifact.cold.toFixed(2)} ms   warm ${artifact.warm.toFixed(3)} ms/request`);
    if (referencePath) {
      const reference = await benchSession(referencePath, 'reference', rounds);
      console.log(`  ${REFERENCE.padEnd(34)} cold ${reference.cold.toFixed(2)} ms   warm ${reference.warm.toFixed(3)} ms/request`);
      console.log(
        `  overhead: cold +${(artifact.cold - reference.cold).toFixed(2)} ms   ` +
          `warm +${(artifact.warm - reference.warm).toFixed(3)} ms/request (x${(artifact.warm / reference.warm).toFixed(2)})`
      );
    }
  }
} finally {
  rmSync(TMP, { recursive: true, force: true });
}

function describe(result) {
  if (result.threw) return `threw(${result.threw})`;
  const body = result.body === null ? 'null' : `${result.body.length} bytes`;
  return `status=${result.status} type=${result.type} cookie=${result.cookie} body=${body}`;
}

console.log(failures === 0 ? 'smoke: OK - behaviour matches the pre-obfuscation build' : `smoke: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
