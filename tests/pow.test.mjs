// Shared proof-of-work vector with src/pow.rs (`shared_test_vector`), and the
// WASM search (pow.wasm) against the JS one.
//
//   node tests/pow.test.mjs [path/to/pow.wasm]     (default: dist/pow.wasm)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { powSeed, solve, hex, workHash, bytesToWords, leadingZeroBits } from '../web/sha256.js';
import { loadPowWasm, loadPowSearch } from '../web/pow-wasm.js';

const token = Buffer.alloc(41, 0x11).toString('base64url');
const sha = '22'.repeat(32);
const seed = await powSeed(token, sha);
assert.equal(hex(seed), 'dbc6fdbf9aa7073991a41989beb2d94337580fb52a8e5b345441762a1a59d48e');
const nonce = solve(seed, 12);
assert.equal(nonce, 449);
const words = workHash(bytesToWords(seed), 0, nonce);
assert.equal(Array.from(words, w => w.toString(16).padStart(8, '0')).join(''),
  '000c11e106daec4f44535aaede041cf9548d0c74f811c4f58dcda4cd880235fc');
assert.ok(leadingZeroBits(words) >= 12);

const bench = (label, fn) => {
  const started = performance.now();
  let n = 0;
  while (performance.now() - started < 1000) n += fn();
  const rate = n / ((performance.now() - started) / 1000);
  console.log(`${label}: ${(rate / 1e6).toFixed(2)} M hashes/s`);
  return rate;
};
const seedWords = bytesToWords(seed);
const out = new Uint32Array(8), w = new Uint32Array(64);
let next = 0;
const jsRate = bench('js  ', () => { for (let i = 0; i < 4096; i++) workHash(seedWords, 0, next++, out, w); return 4096; });

const wasmPath = process.argv[2] ?? new URL('../dist/pow.wasm', import.meta.url);
const bytes = readFileSync(wasmPath);
const solveWasm = await loadPowWasm(bytes);
const search = await loadPowSearch(bytes);
assert.equal(solveWasm(seed, 12), 449, 'wasm finds the shared vector');
assert.equal(solveWasm(seed, 0), 0);

// First solution in a range, by brute force in JS.
const firstJs = (s, hi, start, count, bits) => {
  const sw = bytesToWords(s);
  for (let i = 0; i < count; i++) {
    const h = workHash(sw, hi, (start + i) >>> 0, out, w);
    if (leadingZeroBits(h) >= bits) return i;
  }
  return -1;
};
for (let k = 0; k < 300; k++) {
  const s = randomBytes(32);
  const bits = 1 + (k % 14);
  assert.equal(solveWasm(s, bits), solve(s, bits), `seed ${hex(s)} bits ${bits}`);
}
// Every lane position, high nonce words, the top of the low word, and no hit.
for (const [hi, start, count, bits] of [[0, 0, 4096, 6], [7, 0, 4096, 8], [0xfffff, 0, 4096, 8],
  [0, 0xfffff000, 4096, 9], [3, 0xfffff000, 4096, 9], [0, 1234 * 4, 256, 30]]) {
  for (let k = 0; k < 20; k++) {
    const s = randomBytes(32);
    assert.equal(search(s, hi, start, count, bits), firstJs(s, hi, start, count, bits), `${hi}:${start} bits ${bits}`);
  }
}
const lanes = new Set();
for (let k = 0; lanes.size < 4 && k < 1000; k++) {
  const s = randomBytes(32);
  const found = search(s, 0, 0, 64, 3);
  assert.equal(found, firstJs(s, 0, 0, 64, 3));
  if (found >= 0) lanes.add(found % 4);
}
assert.equal(lanes.size, 4, 'solutions found in every SIMD lane');

let at = 0;
const wasmRate = bench('wasm', () => { search(seed, 1, at, 1 << 18, 32); at += 1 << 18; return 1 << 18; });
console.log(`pow vectors ok (js and wasm agree); wasm is ${(wasmRate / jsRate).toFixed(1)}x js`);
