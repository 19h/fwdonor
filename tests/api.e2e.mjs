// API abuse checks against a running dry-run server (fresh process: the
// per-IP limits accumulate).   node tests/api.e2e.mjs http://127.0.0.1:18090
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { powSeed, solve, fromBase64Url } from '../web/sha256.js';

const base = process.argv[2] ?? 'http://127.0.0.1:18090';
const policy = await (await fetch(`${base}/api/policy`)).json();

async function call(method, path, body, headers = {}) {
  const res = await fetch(base + path, {
    method,
    headers: body && !(body instanceof Uint8Array) ? { 'content-type': 'application/json', ...headers } : headers,
    body: body instanceof Uint8Array ? body : body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}
  return { status: res.status, data, retryAfter: res.headers.get('retry-after') };
}

const sha = buf => createHash('sha256').update(buf).digest('hex');

async function admit(file, { name = 'fw.bin', mutateToken, nonceOverride, reuse } = {}) {
  const challenge = reuse ?? (await call('GET', '/api/challenge')).data;
  let token = challenge.token;
  if (mutateToken) token = mutateToken(token);
  const nonce = nonceOverride ?? solve(await powSeed(challenge.token, sha(file)), challenge.bits);
  const res = await call('POST', '/api/uploads', {
    name, size: file.length, sha256: sha(file), username: 'api_test', token, nonce, zrax_rev: policy.zrax_rev,
  });
  return { ...res, challenge, nonce };
}

// A small, valid ELF-ish file is not needed for admission tests: any bytes.
const blob = randomBytes(5000);

// 1. Forged nonce.
let r = await admit(blob, { nonceOverride: 1 });
assert.equal(r.status, 403, 'forged nonce');

// 2. Tampered difficulty byte (token[24]) breaks the MAC.
r = await admit(blob, {
  mutateToken: t => {
    const raw = fromBase64Url(t);
    raw[24] = 1;
    return Buffer.from(raw).toString('base64url');
  },
});
assert.equal(r.status, 403, 'tampered difficulty');

// 3. Replay: same token + nonce twice.
const ok = await admit(blob, { name: 'replay.bin' });
assert.equal(ok.status, 201, `admitted: ${JSON.stringify(ok.data)}`);
r = await call('POST', '/api/uploads', {
  name: 'replay.bin', size: blob.length, sha256: sha(blob), username: '', token: ok.challenge.token, nonce: ok.nonce, zrax_rev: policy.zrax_rev,
});
assert.equal(r.status, 403, 'replayed token');

// 4. Wrong chunk length, oversized chunk, completing early.
const id = ok.data.id;
r = await call('PUT', `/api/uploads/${id}/0`, new Uint8Array(10));
assert.equal(r.status, 400, 'short chunk');
r = await call('PUT', `/api/uploads/${id}/0`, new Uint8Array(blob.length + 1));
assert.equal(r.status, 400, 'long chunk');
r = await call('PUT', `/api/uploads/${id}/5`, new Uint8Array(10));
assert.equal(r.status, 400, 'index out of range');
r = await call('POST', `/api/uploads/${id}/complete`);
assert.equal(r.status, 409, 'complete before all chunks');

// 5. Upload garbage claiming to be firmware: server verification rejects it.
r = await call('PUT', `/api/uploads/${id}/0`, new Uint8Array(blob));
assert.equal(r.status, 204);
r = await call('POST', `/api/uploads/${id}/complete`);
assert.equal(r.status, 202);
let status;
for (let i = 0; i < 50; i++) {
  status = (await call('GET', `/api/uploads/${id}`)).data;
  if (status.state !== 'verifying') break;
  await new Promise(res => setTimeout(res, 100));
}
assert.equal(status.state, 'rejected', JSON.stringify(status));
console.log('server rejected garbage:', status.reason);

// 6. Concurrency: a third simultaneous upload from one address is refused.
const a = await admit(randomBytes(3000), { name: 'a.bin' });
const b = await admit(randomBytes(3000), { name: 'b.bin' });
const c = await admit(randomBytes(3000), { name: 'c.bin' });
assert.equal(a.status, 201);
assert.equal(b.status, 201);
assert.equal(c.status, 429, `third concurrent: ${c.status} ${JSON.stringify(c.data)}`);
assert.ok(Number(c.retryAfter) > 0, 'Retry-After on 429');
await call('DELETE', `/api/uploads/${a.data.id}`);
await call('DELETE', `/api/uploads/${b.data.id}`);

// 7. Checksum mismatch (bytes differ from the declared hash) also rejects,
// and three rejections ban the address.
const d = await admit(randomBytes(3000), { name: 'd.bin' });
assert.equal(d.status, 201);
await call('PUT', `/api/uploads/${d.data.id}/0`, new Uint8Array(randomBytes(3000)));
await call('POST', `/api/uploads/${d.data.id}/complete`);
for (let i = 0; i < 50; i++) {
  status = (await call('GET', `/api/uploads/${d.data.id}`)).data;
  if (status.state !== 'verifying') break;
  await new Promise(res => setTimeout(res, 100));
}
assert.deepEqual([status.state, status.reason], ['rejected', 'checksum mismatch']);
const e = await admit(randomBytes(3000), { name: 'e.bin' });
await call('PUT', `/api/uploads/${e.data.id}/0`, new Uint8Array(randomBytes(3000)));
await call('POST', `/api/uploads/${e.data.id}/complete`);
await new Promise(res => setTimeout(res, 500));
r = await admit(randomBytes(3000), { name: 'f.bin' });
assert.equal(r.status, 403, `banned after 3 rejections: ${r.status} ${JSON.stringify(r.data)}`);

// 8. Known-hash lookup validates its input and reports nothing for new files.
r = await call('POST', '/api/known', { sha256: ['zz'] });
assert.equal(r.status, 400, 'bad hash');
r = await call('POST', '/api/known', { sha256: Array(1001).fill('00'.repeat(32)) });
assert.equal(r.status, 400, 'too many hashes');
r = await call('POST', '/api/known', { sha256: [sha(randomBytes(64))] });
assert.deepEqual(r.data, { known: {} });

// 9. Stale client.
r = await call('POST', '/api/uploads', { name: 'x', size: 100, sha256: '00'.repeat(32), token: 'x', nonce: 0, zrax_rev: 'old' });
assert.equal(r.status, 409);
assert.equal(r.data.error, 'stale_client');

console.log('api e2e ok');
