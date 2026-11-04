// One of several workers that find many proof-of-work solutions together
// (downloads from the public dashboard): each searches its own part of the
// nonce space (the upper 32 bits are its `hi`) and reports every solution it
// finds until it is told to stop. With the WASM module (pow.wasm, SIMD)
// where the browser can run it, otherwise in plain JS.
import { powSeed, workHash, bytesToWords } from './sha256.js';
import { loadPowSearch } from './pow-wasm.js';

function jsSearch(seedBytes, hi, start, count, bits) {
  const seed = bytesToWords(seedBytes);
  const out = new Uint32Array(8), w = new Uint32Array(64);
  const shift = 32 - bits;
  for (let i = 0; i < count; i++) {
    workHash(seed, hi, (start + i) >>> 0, out, w);
    if (bits === 32 ? out[0] === 0 : (out[0] >>> shift) === 0) return i;
  }
  return -1;
}

const engine = (async () => {
  try {
    const res = await fetch(new URL('./pow.wasm', import.meta.url));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { name: 'wasm', search: await loadPowSearch(await res.arrayBuffer()), chunk: 1 << 20 };
  } catch (error) {
    console.warn('proof of work: using the JS solver:', error);
    return { name: 'js', search: jsSearch, chunk: 1 << 16 };
  }
})();

// The search being worked on; a stop (or a newer search) ends it between chunks.
let current = 0;
const pause = () => new Promise(resolve => setTimeout(resolve, 0));

self.onmessage = async ({ data }) => {
  if (data.type === 'stop') {
    if (current === data.id) current = 0;
    return;
  }
  const { id, token, sha256, bits, hi } = data;
  current = id;
  try {
    const seed = await powSeed(token, sha256);
    const { name, search, chunk } = await engine;
    for (let lo = 0; current === id && lo < 0x100000000; lo += chunk) {
      let start = lo;
      const end = Math.min(lo + chunk, 0x100000000);
      for (let off = search(seed, hi, start, end - start, bits); off >= 0; off = search(seed, hi, start, end - start, bits)) {
        self.postMessage({ id, nonce: hi * 0x100000000 + start + off, engine: name });
        start += off + 1;
        if (start >= end) break;
      }
      await pause(); // lets a stop message in
    }
  } catch (error) {
    self.postMessage({ id, error: String(error?.message ?? error) });
  }
};
