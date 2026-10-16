/**
 * verify.mjs
 *
 * Post-build gate. Run: node verify.mjs [artifact] [reference]
 *
 * Defaults: artifact = output/_worker.js, reference = output/_worker.reference.js
 *
 * Checks
 *  1. The artifact parses as an ES module and still exports a default handler.
 *  2. Every string literal that existed BEFORE obfuscation is still recoverable:
 *     either it is still plain text, or it decrypts out of the ChaCha20 payload
 *     array. This is the "no functional data was lost" proof.
 *  3. No banned word (sensitive_words_auto.txt) survives in the clear. Ciphertext
 *     blobs are blanked first, so random base64 cannot produce a false alarm.
 *  4. The build-time key really is the shipped key (round-trip probe).
 *  5. The injected runtime identifiers were renamed away (fingerprint < 0).
 *
 * With no reference file (e.g. auditing a downloaded zip) checks 1-3-4-5 still run.
 */

import { readFileSync, existsSync } from 'fs';
import { parse } from '@babel/parser';
import { makeCodec, keyFromBase64 } from './tools/cipher.mjs';

const ARTIFACT = process.argv[2] || 'output/_worker.js';
const REFERENCE = process.argv[3] || 'output/_worker.reference.js';
const REPORT = 'output/_build/last-build.json';

let failures = 0;
let warnings = 0;
const pass = (m) => console.log('  PASS  ' + m);
const fail = (m) => { failures++; console.log('  FAIL  ' + m); };
const warn = (m) => { warnings++; console.log('  WARN  ' + m); };

// ------------------------------------------------------------------ AST helpers
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'extra']);

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) walk(child, visit);
    return;
  }
  if (typeof node.type === 'string') visit(node);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (value && typeof value === 'object') walk(value, visit);
  }
}

function collectStrings(source) {
  const ast = parse(source, { sourceType: 'module', allowReturnOutsideFunction: true });
  const specifiers = new Set();
  const strings = new Set();

  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      if (node.source && typeof node.source.value === 'string') specifiers.add(node.source.value);
    }
  });

  walk(ast, (node) => {
    if (node.type === 'StringLiteral' && typeof node.value === 'string') {
      if (!specifiers.has(node.value)) strings.add(node.value);
    }
  });

  return { ast, strings };
}

// ------------------------------------------------------------------- self tests
const artifact = readFileSync(ARTIFACT, 'utf8');

console.log(`verify: ${ARTIFACT} (${artifact.length} bytes)`);

// 1. syntax + default export
let artifactStrings;
let artifactAst = null;
try {
  const parsed = collectStrings(artifact);
  artifactStrings = parsed.strings;
  artifactAst = parsed.ast;
  const hasDefault = parsed.ast.program.body.some(
    (n) =>
      n.type === 'ExportDefaultDeclaration' ||
      (n.type === 'ExportNamedDeclaration' && n.specifiers?.some((s) => (s.exported?.name || s.exported?.value) === 'default'))
  );
  hasDefault ? pass('parses as an ES module and exports default') : fail('no default export found (worker would not load)');
} catch (error) {
  fail('artifact does not parse: ' + error.message);
  artifactStrings = new Set();
}

// 4. key round-trip
let ciphertexts = new Set();
let decoded = new Set();
let report = null;
let codec = null;

// The build report is only usable for the artifact it was written for, so a
// report for a different file falls back to audit mode.
if (existsSync(REPORT)) {
  const parsed = JSON.parse(readFileSync(REPORT, 'utf8'));
  if (typeof parsed.outputBytes === 'number' && parsed.outputBytes !== artifact.length) {
    warn(`build report describes a different artifact (${parsed.outputBytes} vs ${artifact.length} bytes) - ignoring it`);
  } else {
    report = parsed;
  }
}

if (!report) {
  // Audit mode: the build report is gone (e.g. auditing a downloaded zip). The
  // key ships inside the artifact, so recover it by trying each 32-byte array in
  // the file and keeping the one that decrypts the most payload literals.
  const candidates = artifact.match(/\[\d{1,3}(?:,\d{1,3}){31}\]/g) || [];
  let best = null;
  for (const literal of candidates) {
    const key = Uint8Array.from(literal.slice(1, -1).split(',').map(Number));
    if (key.length !== 32 || key.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    const attempt = makeCodec(key);
    let hits = 0;
    for (const value of artifactStrings) {
      if (value.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) continue;
      try {
        if (!attempt.decode(value).includes('\ufffd')) hits++;
      } catch {
        /* not a payload literal */
      }
    }
    if (!best || hits > best.hits) best = { key, codec: attempt, hits };
  }
  if (best && best.hits > 20) {
    codec = best.codec;
    warn(`no build report: recovered the shipped key (${candidates.length} candidate array(s), ${best.hits} payload literals decrypt)`);
  } else {
    fail(`no build report and no usable key recovered (${candidates.length} candidate array(s))`);
  }
} else {
  codec = makeCodec(keyFromBase64(report.keyBase64));
}

if (codec) {
  const probe = 'probe-\u4e2d\u6587-\ud83d\ude0e';
  if (codec.decode(codec.encode(probe)) === probe) {
    pass('ChaCha20 encoder/decoder round-trip');
  } else {
    fail('ChaCha20 encoder/decoder round-trip broken');
  }

  // 2. decrypt every payload literal
  const plausible = /^[\t\n\r\x20-\x7e\u00a0-\uffff]*$/;
  let tried = 0;
  for (const literal of artifactStrings) {
    if (literal.length < 16) continue;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(literal)) continue;
    tried++;
    let plain;
    try {
      plain = codec.decode(literal);
    } catch {
      continue;
    }
    if (plain.includes('\ufffd')) continue;
    if (plain.length < 3) continue;
    if (!plausible.test(plain)) continue;
    ciphertexts.add(literal);
    decoded.add(plain);
  }
  if (ciphertexts.size === 0) {
    fail(`no ChaCha20 payload could be decrypted out of ${tried} candidate literals`);
  } else {
    pass(`${ciphertexts.size} concealed strings decrypted with the shipped key`);
  }
}

// 3. coverage against the pre-obfuscation reference
if (existsSync(REFERENCE)) {
  const reference = readFileSync(REFERENCE, 'utf8');
  let refStrings;
  try {
    refStrings = collectStrings(reference).strings;
  } catch (error) {
    fail('reference does not parse: ' + error.message);
    refStrings = new Set();
  }
  const union = new Set([...artifactStrings, ...decoded]);
  const missing = [];
  for (const value of refStrings) {
    if (value.length < 3) continue; // js-confuser never conceals these
    if (!union.has(value)) missing.push(value);
  }
  if (missing.length === 0) {
    pass(`all ${refStrings.size} reference strings are recoverable (no data lost)`);
  } else {
    fail(`${missing.length} reference strings are missing from the artifact, e.g. ${JSON.stringify(missing.slice(0, 3))}`);
  }
} else {
  warn(`reference ${REFERENCE} not found - skipping coverage check`);
}

// 5. leaked banned words (ciphertext blanked out first)
// The word lists are static configuration, so they are resolved next to this
// script and not from the working directory - an audit can run from anywhere.
function readList(name, fallback) {
  try {
    return readFileSync(new URL(`./${name}`, import.meta.url), 'utf-8');
  } catch {
    return fallback;
  }
}

const bannedWords = readList('sensitive_words_auto.txt', 'bpb\nvless\ntrojan\n')
  .split('\n')
  .map((w) => w.trim())
  .filter(Boolean);

let visibled = artifact;
for (const literal of ciphertexts) {
  visibled = visibled.split(JSON.stringify(literal)).join('""');
}
const leaked = bannedWords.filter((word) => new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(visibled));
if (leaked.length === 0) {
  pass(`no banned word survives in clear text (${bannedWords.join(', ')})`);
} else {
  fail(`banned words visible in clear text: ${leaked.join(', ')}`);
}

// manual fingerprint list: informational only
const manualTerms = readList('sensitive_words_manual.txt', '')
  .split('\n')
  .map((w) => w.trim())
  .filter((w) => w && !w.startsWith('#') && !w.endsWith('#'));
const manualVisible = manualTerms.filter((term) => visibled.includes(term));
if (manualVisible.length > 0) {
  warn(`${manualVisible.length} manual-list fingerprint terms still visible, e.g. ${manualVisible.slice(0, 5).join(', ')}`);
} else {
  pass('no manual-list fingerprint term is visible in clear text');
}

// 6. the appended cipher runtime must be present exactly once and be referenced
const helperName =
  report?.helperName || (artifact.match(/function\s+(_0x[0-9a-f]{6,10})\s*\(/g) || []).pop()?.replace(/^function\s+/, '').replace(/\s*\($/, '');
if (helperName) {
  const declared = artifact.includes(`function ${helperName}(`);
  const references = (artifact.match(new RegExp(`\\b${helperName}\\(`, 'g')) || []).length;
  if (declared && references >= 2) {
    pass(`cipher runtime "${helperName}" declared and referenced (${references - 1} call site(s))`);
  } else {
    fail(`cipher runtime "${helperName}" missing (declared=${declared}, call sites=${references - 1})`);
  }
  const stray = /__modDEC|__modKS|__modENC|__modFail/.test(artifact);
  stray ? fail('a build-internal runtime name leaked into the artifact') : pass('no build-internal runtime name in the artifact');
}

// 7. self-shadowing initializer: `var x = ... x(...) ...`
// js-confuser's integrity wrapper (and any generator that invents a local name
// without checking the existing namespace) can produce this. The local `x` is
// hoisted and therefore undefined, so the call in its own initializer throws
// "TypeError: x is not a function" at runtime. Caught statically so the build is
// rejected even when the smoke test never reaches the affected function.
if (artifactAst) {
  const shadowed = [];
  walk(artifactAst, (node) => {
    if (node.type !== 'VariableDeclarator' || !node.init) return;
    if (node.id.type !== 'Identifier') return;
    const name = node.id.name;
    let called = false;
    walk(node.init, (inner) => {
      if (
        inner.type === 'CallExpression' &&
        inner.callee.type === 'Identifier' &&
        inner.callee.name === name
      ) {
        called = true;
      }
    });
    if (called) shadowed.push(name);
  });
  if (shadowed.length === 0) {
    pass('no self-shadowing var initializer');
  } else {
    fail(
      `${shadowed.length} variable(s) call themselves inside their own initializer ` +
        `(${[...new Set(shadowed)].slice(0, 5).join(', ')}) - the wrapped function would throw TypeError`
    );
  }
}

console.log(
  failures === 0
    ? `verify: OK (${warnings} warning${warnings === 1 ? '' : 's'})`
    : `verify: ${failures} FAILURE(S), ${warnings} warning(s)`
);
process.exit(failures === 0 ? 0 : 1);
