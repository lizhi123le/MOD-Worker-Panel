/**
 * tools/cipher.mjs
 *
 * Single source of truth for the payload cipher used by the obfuscation step.
 *
 * Design notes (why it looks like this):
 * - js-confuser's `stringConcealing` decoder must be SYNCHRONOUS (it is called
 *   inside expression position), so WebCrypto AES-GCM (async) cannot be used.
 *   ChaCha20 (RFC 8439) is a standard, synchronous stream cipher.
 * - Every concealed string gets its own random 8-byte nonce, prepended to the
 *   ciphertext -> no keystream reuse, no deterministic ciphertext.
 * - Ciphertext is carried as base64 so the generated JS string literals stay
 *   printable and compact (raw bytes would be escaped as \xNN and inflate 2x).
 * - The Worker-side runtime (RUNTIME) contains NO string literals on purpose:
 *   if it did, js-confuser would conceal them and the decoder would need itself
 *   to decode its own key/algorithm (a bootstrap deadlock).
 * - The Node-side codec is created by evaluating the very same RUNTIME source,
 *   so the encoder and the shipped decoder can never drift apart.
 */

import { randomBytes } from 'node:crypto';

export const KS_NAME = '__modKS';
export const DEC_NAME = '__modDEC';
export const ENC_NAME = '__modENC';

/**
 * Worker-side runtime. `__KEY__` is replaced with a 32-entry numeric array.
 * ENC is wrapped in markers so it can be stripped from the shipped copy.
 */
export const RUNTIME = `
function ${KS_NAME}(n8, len) {
  var key = __KEY__;
  var out = new Uint8Array(len);
  var st = new Uint32Array(16);
  var w = new Uint32Array(16);
  var ctr = 0;
  var o = 0;
  var i = 0;
  var j = 0;
  while (o < len) {
    st[0] = 1634760805; st[1] = 857760878; st[2] = 2036477234; st[3] = 1797285236;
    for (i = 0; i < 8; i++) {
      st[4 + i] = key[4 * i] | (key[4 * i + 1] << 8) | (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24);
    }
    st[12] = ctr++;
    st[13] = n8[0] | (n8[1] << 8) | (n8[2] << 16) | (n8[3] << 24);
    st[14] = n8[4] | (n8[5] << 8) | (n8[6] << 16) | (n8[7] << 24);
    st[15] = 0;
    for (i = 0; i < 16; i++) w[i] = st[i];
    for (i = 0; i < 10; i++) {
      qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
      qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
      var add = (w[i] + st[i]) >>> 0;
      var n = len - o;
      if (n > 4) n = 4;
      for (j = 0; j < n; j++) out[o + j] = (add >>> (8 * j)) & 255;
      o += n;
      if (o >= len) break;
    }
  }
  return out;
}
function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = (s[d] ^ s[a]) >>> 0; s[d] = ((s[d] << 16) | (s[d] >>> 16)) >>> 0;
  s[c] = (s[c] + s[d]) >>> 0; s[b] = (s[b] ^ s[c]) >>> 0; s[b] = ((s[b] << 12) | (s[b] >>> 20)) >>> 0;
  s[a] = (s[a] + s[b]) >>> 0; s[d] = (s[d] ^ s[a]) >>> 0; s[d] = ((s[d] << 8) | (s[d] >>> 24)) >>> 0;
  s[c] = (s[c] + s[d]) >>> 0; s[b] = (s[b] ^ s[c]) >>> 0; s[b] = ((s[b] << 7) | (s[b] >>> 25)) >>> 0;
}
function ${DEC_NAME}(s) {
  var raw = atob(s);
  var n = raw.length;
  var all = new Uint8Array(n);
  var i = 0;
  for (i = 0; i < n; i++) all[i] = raw.charCodeAt(i);
  var body = n - 8;
  var ks = ${KS_NAME}(all, body);
  var out = new Uint8Array(body);
  var ascii = true;
  for (i = 0; i < body; i++) {
    var b = all[8 + i] ^ ks[i];
    out[i] = b;
    if (b > 127) ascii = false;
  }
  if (ascii) {
    var str = '';
    for (i = 0; i < body; i++) str += String.fromCharCode(out[i]);
    return str;
  }
  return new TextDecoder().decode(out);
}
/*ENC-START*/
function ${ENC_NAME}(str) {
  var bytes = new TextEncoder().encode(str);
  var n8 = new Uint8Array(8);
  crypto.getRandomValues(n8);
  var ks = ${KS_NAME}(n8, bytes.length);
  var all = new Uint8Array(8 + bytes.length);
  all.set(n8, 0);
  var i = 0;
  for (i = 0; i < bytes.length; i++) all[8 + i] = bytes[i] ^ ks[i];
  var bin = '';
  for (i = 0; i < all.length; i++) bin += String.fromCharCode(all[i]);
  return btoa(bin);
}
/*ENC-END*/
`;

const ENC_BLOCK = /\/\*ENC-START\*\/[\s\S]*?\/\*ENC-END\*\//;

function keyLiteral(keyBytes) {
  return '[' + Array.from(keyBytes).join(',') + ']';
}

/** Full runtime (encoder + decoder) - used locally in Node. */
export function buildCodecSource(keyBytes) {
  return RUNTIME.replace('__KEY__', keyLiteral(keyBytes));
}

/**
 * Shipped runtime: decoder only, no encoder, no comments.
 *
 * `names` renames the two declared functions per build so the output does not
 * carry a fixed fingerprint. Names are substituted on word boundaries only.
 *
 * IMPORTANT: this source is appended to the bundle AFTER js-confuser has run.
 * js-confuser's `stringConcealing` also conceals *property names*
 * (`obj.prop` -> `obj[decoder(i)]`), so a decoder that lives inside the AST
 * would have to decode its own key to decode itself - it never terminates.
 * Keeping it outside the AST also keeps it free of any string literal.
 */
export function buildDecoderSource(keyBytes, names = { ks: KS_NAME, dec: DEC_NAME }) {
  let src = buildCodecSource(keyBytes).replace(ENC_BLOCK, '').trim();
  if (names.ks && names.ks !== KS_NAME) {
    src = src.replace(new RegExp(`\\b${KS_NAME}\\b`, 'g'), names.ks);
  }
  if (names.dec && names.dec !== DEC_NAME) {
    src = src.replace(new RegExp(`\\b${DEC_NAME}\\b`, 'g'), names.dec);
  }
  return src;
}

/** Per-build, per-file helper name (unbound during obfuscation, declared after). */
export function randomHelperName() {
  return '_0x' + randomBytes(4).toString('hex');
}

/** Build-time codec: { encode(str) -> base64, decode(base64) -> str }. */
export function makeCodec(keyBytes) {
  const factory = new Function(
    buildCodecSource(keyBytes) + `;return {e:${ENC_NAME},d:${DEC_NAME}};`
  );
  const { e, d } = factory();
  return { encode: e, decode: d };
}

export function randomKey() {
  return new Uint8Array(randomBytes(32));
}

export function keyToBase64(keyBytes) {
  return Buffer.from(keyBytes).toString('base64');
}

export function keyFromBase64(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
