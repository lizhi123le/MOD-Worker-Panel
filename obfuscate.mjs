/**
 * obfuscate.mjs
 *
 * Reads output/_worker.js (the wrangler/uglify build), applies js-confuser with a
 * per-build ChaCha20 string cipher, and writes the result back in place.
 *
 * What changed vs. the original implementation:
 *  - The custom string encoding is real ChaCha20 (RFC 8439) with a fresh key per
 *    build and a fresh 8-byte nonce per string, instead of `(x - SHIFT) % 128 ^ XOR`
 *    (a 16k-key-space, lossy, deterministic transform whose key was inlined).
 *  - `decode` is provided, so js-confuser round-trip validates EVERY concealed
 *    string and silently leaves an unconcealable one as plain text (fail-safe).
 *  - `stringConcealing: true` conceals all string literals instead of only the
 *    three words bpb/vless/trojan.
 *  - Hardening options (opaque predicates, control-flow flattening, integrity)
 *    are configurable through environment variables, see HARDENING below.
 *
 * HARDENING (env var -> default):
 *   HARDEN_STRINGS=true      conceal all strings + property names (false = legacy
 *                            3-word filter: only strings containing bpb/vless/trojan)
 *   HARDEN_OPAQUE=0.2        opaque predicate probability
 *   HARDEN_CFF=0             control flow flattening - MUST stay 0, it emits `with`
 *                            which is illegal in an ES module (js-confuser bug)
 *   HARDEN_INTEGRITY=false   per-function checksum lock - see the warning below
 *   HARDEN_ANTIDEBUG=false   debugger statement injection
 *   HARDEN_SELFDEFENDING=false
 *
 * WHY INTEGRITY IS OFF BY DEFAULT
 * js-confuser 2.0's integrity pass runs last and generates its wrapper locals
 * with a NameGen that does not know about the names renameVariables already
 * handed out. When they collide the wrapper shadows the hash function itself:
 *
 *   function dJ(){var aV=dJ.aU||(dJ.aU=aV(ba,9897108)); ... }   // aV === the hash fn
 *
 * which makes every call of the wrapped function throw
 * "TypeError: aV is not a function". It happens per build, so it is a lottery:
 * a build can be fine and the next one broken, in a path the smoke test may not
 * reach. verify.mjs statically rejects that shape, so turning the lock on is
 * gated - but a checksum guard is not worth a random production failure.
 */

import { default as JsConfuser } from 'js-confuser';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import {
  randomKey,
  keyToBase64,
  buildDecoderSource,
  makeCodec,
  randomHelperName,
} from './tools/cipher.mjs';

// ---------------------------------------------------------------- configuration
const WORKER_PATH = 'output/_worker.js';
const REPORT_PATH = 'output/_build/last-build.json';

function num(value, fallback) {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw new Error(`Invalid probability "${value}" (expected 0..1)`);
  }
  return n;
}
function bool(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return value !== 'false' && value !== '0';
}

const CONFIG = {
  concealAllStrings: bool(process.env.HARDEN_STRINGS, true),
  opaquePredicates: num(process.env.HARDEN_OPAQUE, 0.2),
  // Control flow flattening emits `with`, which is a syntax error in strict mode
  // and therefore in every ES module (Cloudflare Workers included). Keep it at 0.
  controlFlowFlattening: num(process.env.HARDEN_CFF, 0),
  integrity: bool(process.env.HARDEN_INTEGRITY, false),
  antiDebug: bool(process.env.HARDEN_ANTIDEBUG, false),
  selfDefending: bool(process.env.HARDEN_SELFDEFENDING, false),
};

if (CONFIG.controlFlowFlattening > 0 && process.env.HARDEN_ALLOW_CFF !== 'true') {
  throw new Error(
    'HARDEN_CFF > 0 is not usable for this bundle: js-confuser control-flow flattening emits a ' +
      '`with` statement (see controlFlowFlattening.ts t.withStatement), which is illegal in an ES ' +
      'module / strict mode. Set HARDEN_CFF=0, or HARDEN_ALLOW_CFF=true if you know your bundle is ' +
      'non-strict, or raise HARDEN_OPAQUE / HARDEN_INTEGRITY instead.'
  );
}

// ---------------------------------------------------------------------- helpers
const COUNTERMEASURE_NAME = '__modFail';

/** A lock failure must be loud but must never hang the isolate. */
const COUNTERMEASURE_SOURCE = `
function ${COUNTERMEASURE_NAME}() {
  throw new Error('integrity check failed: the script was modified after build');
}
`;

const sensitiveWords = readFileSync('sensitive_words_auto.txt', 'utf-8')
  .split('\n')
  .map((w) => w.trim().toLowerCase())
  .filter(Boolean);

// --------------------------------------------------------------------- pipeline
const key = randomKey();
const codec = makeCodec(key);

// The cipher runtime is appended to the bundle AFTER js-confuser has run, and it
// is referenced from the obfuscated code as an *unbound* global. Two reasons:
//
//  1. js-confuser's stringConcealing also conceals property names, so a decoder
//     inside the AST would need its own payload decoded before it could decode
//     anything - an infinite recursion.
//  2. An identifier that has no binding in the module is never renamed by
//     renameVariables, so the post-hoc declaration still binds.
//
// Function declarations are hoisted, and the ChaCha20 key lives inside the
// function body, so the runtime is callable from module-init time onwards.
const helperName = randomHelperName();
const keyStreamName = randomHelperName();
const runtimeSuffix = buildDecoderSource(key, { ks: keyStreamName, dec: helperName });

const sourceCode = readFileSync(WORKER_PATH, 'utf8');

// Only the integrity countermeasure has to exist in the AST (the Lock plugin
// looks it up by name). Its message string is concealed like any other, which is
// fine now that the decoder does not depend on the payload array.
let prepared = sourceCode;
if (CONFIG.integrity || CONFIG.antiDebug || CONFIG.selfDefending) {
  prepared = `${COUNTERMEASURE_SOURCE}\n${prepared}`;
}

// Concealed strings call this tiny per-block wrapper, which calls the appended runtime.
const options = {
  target: 'node',

  // REQUIRED for the string cipher
  stringConcealing: CONFIG.concealAllStrings
    ? true
    : (str) => sensitiveWords.some((word) => str.toLowerCase().includes(word)),

  customStringEncodings: [
    {
      code: `function {fnName}(str) { return ${helperName}(str); }`,
      encode: (str) => codec.encode(str),
      decode: (str) => codec.decode(str),
    },
  ],

  // Identifier/layout obfuscation
  renameVariables: true,
  renameGlobals: true,
  renameLabels: true,
  identifierGenerator: 'mangled',
  movedDeclarations: true,
  objectExtraction: true,
  compact: true,
  hexadecimalNumbers: true,
  astScrambler: true,

  // Deliberately disabled: no benefit here, and/or CPU/size cost on Workers
  calculator: false,
  deadCode: false,
  dispatcher: false,
  duplicateLiteralsRemoval: false,
  flatten: false,
  preserveFunctionLength: false,
  stringSplitting: false,
  stringCompression: false,
  globalConcealing: false,
  shuffle: false,
  variableMasking: false,
  minify: false, // conflicts with the CSS carried inside page strings
  rgf: false,

  // Hardening (probabilities, see HARDENING above)
  opaquePredicates: CONFIG.opaquePredicates,
  controlFlowFlattening: CONFIG.controlFlowFlattening,

  lock: {
    integrity: CONFIG.integrity,
    // A benign countermeasure: a tampered script fails loudly instead of
    // spinning in `while(true){}` and burning the isolate.
    countermeasures:
      CONFIG.integrity || CONFIG.antiDebug || CONFIG.selfDefending
        ? COUNTERMEASURE_NAME
        : undefined,
    antiDebug: CONFIG.antiDebug,
    selfDefending: CONFIG.selfDefending,
    tamperProtection: false, // requires non-strict mode; this bundle is an ES module
  },
};

const result = await JsConfuser.obfuscate(prepared, options);

// Append the cipher runtime. It is deliberately NOT obfuscated: it must not
// depend on the payload array it decodes.
const output = result.code + '\n' + runtimeSuffix + '\n';
writeFileSync(WORKER_PATH, output);

mkdirSync(dirname(REPORT_PATH), { recursive: true });
writeFileSync(
  REPORT_PATH,
  JSON.stringify(
    {
      keyBase64: keyToBase64(key),
      cipher: 'chacha20-rfc8439',
      nonceBytesPerString: 8,
      helperName,
      keyStreamName,
      config: CONFIG,
      sourceBytes: sourceCode.length,
      outputBytes: output.length,
    },
    null,
    2
  )
);

console.log(
  `concealed strings with ChaCha20 (cipher=${CONFIG.concealAllStrings ? 'all-literals' : 'sensitive-only'}` +
    `, opaque=${CONFIG.opaquePredicates}, cff=${CONFIG.controlFlowFlattening}, integrity=${CONFIG.integrity})`
);
