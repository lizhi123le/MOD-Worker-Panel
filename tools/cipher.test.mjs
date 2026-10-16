/**
 * tools/cipher.test.mjs
 *
 * Regression tests for the payload cipher. Run with: node tools/cipher.test.mjs
 *
 * 1. RFC 8439 section 2.3.2 ChaCha20 block-function known-answer test.
 * 2. Encoder/decoder round-trip, including non-ASCII (the pipeline no longer
 *    strips Unicode, so the cipher must handle UTF-8 payloads).
 * 3. Ciphertext must be non-deterministic (fresh nonce per string).
 */

import { RUNTIME, KS_NAME, makeCodec, randomKey, buildDecoderSource } from './cipher.mjs';

let failures = 0;
function check(name, ok, extra = '') {
  if (ok) {
    console.log(`  PASS  ${name}`);
  } else {
    failures++;
    console.log(`  FAIL  ${name}${extra ? ' :: ' + extra : ''}`);
  }
}

// --- 1. RFC 8439 test vector -------------------------------------------------
const rfcKey = Array.from({ length: 32 }, (_, i) => i);
const rfcNonce8 = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a];
const rfcExpected =
  '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e' +
  'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e';

// The shipped keystream starts at counter 0; the RFC vector is block 1.
const counterPatched = RUNTIME.replace('var ctr = 0;', 'var ctr = 1;').replace(
  '__KEY__',
  '[' + rfcKey.join(',') + ']'
);
const ksFn = new Function(counterPatched + `;return ${KS_NAME};`)();
const rfcHex = Buffer.from(ksFn(rfcNonce8, 64)).toString('hex');
check('RFC 8439 ChaCha20 block vector', rfcHex === rfcExpected, rfcHex);

// --- 2. Round-trip ----------------------------------------------------------
const codec = makeCodec(randomKey());
const samples = [
  'vless://user@host:443?security=tls',
  'hello world',
  '\u26a0\ufe0f Troj\u0430n / \u4e2d\u6587\u9762\u677f / \ud83d\ude0e',
  'a',
  JSON.stringify({ remoteDNS: 'https://8.8.8.8/dns-query', e: '\u00e9\u00fc' }),
  'x'.repeat(5000),
];
let roundTripOk = true;
for (const s of samples) {
  const enc = codec.encode(s);
  const dec = codec.decode(enc);
  if (dec !== s) {
    roundTripOk = false;
    console.log(`        mismatch for ${JSON.stringify(s.slice(0, 40))} -> ${JSON.stringify(dec.slice(0, 40))}`);
  }
}
check('encode/decode round-trip (ASCII + Unicode + long)', roundTripOk);

// --- 3. Non-determinism -----------------------------------------------------
check('ciphertext is non-deterministic', codec.encode('same') !== codec.encode('same'));

// --- 4. Shipped decoder contains no string literals -------------------------
// If it did, js-confuser would conceal them and the decoder would need itself
// to bootstrap its own key.
const shipped = buildDecoderSource(randomKey());
// Empty literals are fine: js-confuser only conceals strings of length >= 3.
const literals = (shipped.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g) || []).filter((s) => s.length > 2);
check('shipped decoder has no string literals', literals.length === 0, literals.join(' '));
check('shipped decoder has no encoder', !shipped.includes('ENC'));

console.log(failures === 0 ? '\ncipher: all checks passed' : `\ncipher: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
