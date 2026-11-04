// Proof-of-work search with the WASM module (pow-wasm/, copied to pow.wasm):
// the same search as solve() in sha256.js, about four nonces per step.

// Nonces per call: keeps each call short without much call overhead.
const CHUNK = 1 << 20;

/** Compile the module; resolves to solve(seedBytes, bits) -> nonce. */
export async function loadPowWasm(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { memory, pow_seed: seedPtr, pow_search: search } = instance.exports;
  return function solveWasm(seedBytes, bits) {
    if (bits > 32) throw new Error(`unsupported difficulty ${bits}`);
    new Uint8Array(memory.buffer, seedPtr(), 32).set(seedBytes);
    for (let hi = 0; hi < 0x100000; hi++) {
      for (let lo = 0; lo < 0x100000000; lo += CHUNK) {
        const found = search(hi, lo, CHUNK, bits);
        if (found >= 0) return hi * 0x100000000 + lo + found;
      }
    }
    throw new Error('no proof of work found');
  };
}

/** Raw search, for tests: offset of the first solution in [start, start+count). */
export async function loadPowSearch(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { memory, pow_seed: seedPtr, pow_search: search } = instance.exports;
  return (seedBytes, hi, start, count, bits) => {
    new Uint8Array(memory.buffer, seedPtr(), 32).set(seedBytes);
    return search(hi, start >>> 0, count, bits);
  };
}
