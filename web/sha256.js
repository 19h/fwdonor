// Single-block SHA-256 for the proof-of-work search: hashes
// seed(32 bytes) ‖ nonce(u64 big-endian), a 40-byte message that always fits
// one 64-byte block. Mirrors src/pow.rs `work_hash`.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** Hash seed ‖ nonce; returns the 8 state words (big-endian digest words). */
export function workHash(seedWords, nonceHi, nonceLo, out = new Uint32Array(8), w = new Uint32Array(64)) {
  for (let i = 0; i < 8; i++) w[i] = seedWords[i];
  w[8] = nonceHi;
  w[9] = nonceLo;
  w[10] = 0x80000000;
  w[11] = w[12] = w[13] = w[14] = 0;
  w[15] = 40 * 8;
  for (let i = 16; i < 64; i++) {
    const a = w[i - 15], b = w[i - 2];
    const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3);
    const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let [a, b, c, d, e, f, g, h] = H0;
  for (let i = 0; i < 64; i++) {
    const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
    const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  out[0] = (H0[0] + a) | 0; out[1] = (H0[1] + b) | 0; out[2] = (H0[2] + c) | 0; out[3] = (H0[3] + d) | 0;
  out[4] = (H0[4] + e) | 0; out[5] = (H0[5] + f) | 0; out[6] = (H0[6] + g) | 0; out[7] = (H0[7] + h) | 0;
  return out;
}

export function bytesToWords(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const words = new Uint32Array(bytes.byteLength / 4);
  for (let i = 0; i < words.length; i++) words[i] = view.getUint32(i * 4);
  return words;
}

export function leadingZeroBits(words) {
  let bits = 0;
  for (const word of words) {
    if (word === 0) { bits += 32; continue; }
    return bits + Math.clz32(word);
  }
  return bits;
}

/** First nonce whose work hash has at least `bits` (≤ 32) leading zero bits. */
export function solve(seedBytes, bits, onProgress) {
  const seed = bytesToWords(seedBytes);
  const out = new Uint32Array(8), w = new Uint32Array(64);
  const shift = 32 - bits;
  for (let hi = 0; hi < 0x100000; hi++) {
    for (let lo = 0; lo <= 0xffffffff; lo++) {
      workHash(seed, hi, lo, out, w);
      if (bits === 32 ? out[0] === 0 : (out[0] >>> shift) === 0) return hi * 0x100000000 + lo;
      if (onProgress && (lo & 0xfffff) === 0 && lo) onProgress(hi * 0x100000000 + lo);
    }
  }
  throw new Error('no proof of work found');
}

export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

export function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.substr(i * 2, 2), 16);
  return out;
}

export function fromBase64Url(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
  const raw = atob(b64);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

/** seed = SHA256(token ‖ file_sha256), via WebCrypto. */
export async function powSeed(tokenB64, fileShaHex) {
  const token = fromBase64Url(tokenB64);
  const sha = fromHex(fileShaHex);
  const message = new Uint8Array(token.length + sha.length);
  message.set(token);
  message.set(sha, token.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', message));
}
