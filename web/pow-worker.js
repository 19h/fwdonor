// Solves proof-of-work challenges off the main thread: with the WASM module
// (pow.wasm, SIMD) where the browser can run it, otherwise in plain JS.
import { powSeed, solve as solveJs } from './sha256.js';
import { loadPowWasm } from './pow-wasm.js';

const engine = (async () => {
  try {
    const res = await fetch(new URL('./pow.wasm', import.meta.url));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { name: 'wasm', solve: await loadPowWasm(await res.arrayBuffer()) };
  } catch (error) {
    // No WASM SIMD (or the module didn't load): slower, same answer.
    console.warn('proof of work: using the JS solver:', error);
    return { name: 'js', solve: solveJs };
  }
})();

self.onmessage = async ({ data }) => {
  const { id, token, sha256, bits } = data;
  try {
    const seed = await powSeed(token, sha256);
    const { name, solve } = await engine;
    const started = performance.now();
    const nonce = solve(seed, bits);
    self.postMessage({ id, nonce, engine: name, elapsed: performance.now() - started });
  } catch (error) {
    self.postMessage({ id, error: String(error?.message ?? error) });
  }
};
