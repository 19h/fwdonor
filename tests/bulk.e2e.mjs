// Bulk donations end to end against a server this test starts (and kills):
// grants, chunked uploads that survive a crash and a restart, a write lost in
// the crash being detected and sent again, quota, duplicates, a changed file,
// discarding, and revoking.
//
//   node tests/bulk.e2e.mjs <fwdonor binary> [port]
//
// Run scripts/build.sh first so dist/ has the bulk pages.
import { mkdtempSync, readFileSync, writeFileSync, existsSync, openSync, writeSync, closeSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const [serverBin, port = '18098'] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = data => createHash('sha256').update(data).digest('hex');
const MiB = 1024 * 1024;

const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-bulk-e2e-'));
const store = path.join(work, 'bulk');
writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"
public_url = "http://127.0.0.1:${port}"

[bulk]
dir = "${store}"
chunk_bytes = ${MiB}
min_free_bytes = 0

[telegram]
dry_run = true
`);
const log = openSync(path.join(work, 'server.log'), 'a');
let server = null;
process.on('exit', () => server?.kill('SIGKILL'));

async function start() {
  server = spawn(serverBin, ['--config', path.join(work, 'fwdonor.toml'), 'serve'], { stdio: ['ignore', log, log] });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return;
    } catch {}
    await sleep(100);
  }
  throw new Error('server did not come up');
}

async function stop(signal) {
  const proc = server;
  const exited = new Promise(resolve => proc.once('exit', resolve));
  proc.kill(signal);
  await exited;
}

async function call(method, url, body, headers = {}) {
  const res = await fetch(`${base}${url}`, {
    method,
    headers: body ? { 'content-type': 'application/json', ...headers } : headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

const putChunk = (token, id, index, bytes, hash = sha(bytes)) =>
  fetch(`${base}/api/bulk/${token}/uploads/${id}/${index}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/octet-stream', 'x-chunk-sha256': hash },
    body: bytes,
  });

const chunkOf = (data, i, size = MiB) => data.subarray(i * size, Math.min(data.length, (i + 1) * size));

async function sendChunks(token, id, data, indices, parallel = 4) {
  const queue = [...indices];
  await Promise.all(Array.from({ length: parallel }, async () => {
    for (let i = queue.shift(); i !== undefined; i = queue.shift()) {
      const res = await putChunk(token, id, i, chunkOf(data, i));
      assert.equal(res.status, 204, `chunk ${i}: ${res.status} ${await res.text()}`);
    }
  }));
}

const missing = (bitmapB64, count) => {
  const bytes = Buffer.from(bitmapB64, 'base64');
  const out = [];
  for (let i = 0; i < count; i++) if (!((bytes[i >> 3] >> (i & 7)) & 1)) out.push(i);
  return out;
};

async function waitStored(token, id, data, { allowResend = false } = {}) {
  let resent = 0;
  for (let i = 0; i < 400; i++) {
    const { status, data: st } = await call('GET', `/api/bulk/${token}/uploads/${id}`);
    assert.equal(status, 200);
    if (st.state === 'stored' || st.state === 'duplicate') return { ...st, resent };
    if (st.state === 'receiving') {
      const gaps = missing(st.received, st.chunks);
      if (gaps.length) {
        assert.ok(allowResend, `unexpectedly missing chunks ${gaps}`);
        resent += gaps.length;
        await sendChunks(token, id, data, gaps);
      }
    }
    await sleep(50);
  }
  throw new Error('upload was never stored');
}

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();

// ---- admin page and grants
const key = readFileSync(path.join(work, 'runtime', 'admin.key'), 'utf8').trim();
assert.equal(key.length, 43);
assert.equal((await fetch(`${base}/g/${key}`)).status, 200, 'admin page');
const adminHtml = await (await fetch(`${base}/g/${key}`)).text();
assert.ok(adminHtml.includes('grant.js'), 'admin page is the built grant page');
assert.equal((await fetch(`${base}/g/${'x'.repeat(43)}`)).status, 404, 'wrong admin key');
assert.equal((await call('GET', `/api/admin/${'x'.repeat(43)}/grants`)).status, 404);
assert.equal((await call('POST', `/api/admin/${key}/grants`, { name: 'bad name', ceiling_bytes: 5 })).status, 400);

const ceiling = 100_000_000;
const created = await call('POST', `/api/admin/${key}/grants`, { name: 'Sonic', ceiling_bytes: ceiling, note: 'e2e' });
assert.equal(created.status, 201);
const token = created.data.token;
assert.equal(token.length, 22);
const page = await fetch(`${base}/r/${token}`);
assert.equal(page.status, 200);
assert.equal(page.headers.get('x-robots-tag'), 'noindex, nofollow');
assert.ok((await page.text()).includes('bulk.js'));
assert.equal((await fetch(`${base}/r/${'A'.repeat(22)}`)).status, 404, 'unknown grant');
let info = (await call('GET', `/api/bulk/${token}`)).data;
assert.deepEqual([info.name, info.ceiling, info.used, info.reserved], ['Sonic', ceiling, 0, 0]);

// ---- a 40 MB file: half of it, a crash, a write "lost" in the crash, the rest
const big = randomBytes(40_000_000 + 1234);
const bigSha = sha(big);
const chunks = Math.ceil(big.length / MiB);
const init = await call('POST', `/api/bulk/${token}/uploads`,
  { name: 'big.img', path: 'dumps/big.img', size: big.length, last_modified: 1700000000000 },
  { 'x-forwarded-for': '203.0.113.7' });
assert.equal(init.status, 201, JSON.stringify(init.data));
const id = init.data.id;
assert.equal(init.data.chunks, chunks);
await sendChunks(token, id, big, [...Array(20).keys()]);
assert.equal((await putChunk(token, id, 25, chunkOf(big, 25), sha('nope'))).status, 422, 'wrong chunk hash');
assert.equal((await putChunk(token, id, 0, chunkOf(big, 1))).status, 409, 'a different chunk where one was received');
assert.equal((await putChunk(token, id, chunks + 3, chunkOf(big, 0))).status, 400, 'index out of range');
info = (await call('GET', `/api/bulk/${token}`)).data;
assert.equal(info.reserved, big.length, 'the unfinished upload reserves its size');
assert.equal(info.unfinished.length, 1);

console.log('-- crash (SIGKILL) with 20 of', chunks, 'chunks received');
await stop('SIGKILL');
const partial = path.join(store, '.partial', id);
assert.ok(existsSync(path.join(partial, 'data')), 'partial upload kept');
// Chunks past the last hash checkpoint are checked against their hashes after
// a crash (the ones before it were fsynced before the checkpoint was written).
const statePath = path.join(partial, 'hash.state');
const checkpointed = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')).next : 0;
const lost = Math.max(7, checkpointed);
assert.ok(lost < 20, 'a received chunk past the checkpoint');
const fd = openSync(path.join(partial, 'data'), 'r+');
writeSync(fd, Buffer.alloc(MiB), 0, MiB, lost * MiB);
closeSync(fd);
await start();

// The page drops the file again: the server resumes the upload it kept.
const again = await call('POST', `/api/bulk/${token}/uploads`, { name: 'big.img', path: 'dumps/big.img', size: big.length, last_modified: 1700000000000 });
assert.equal(again.status, 200);
assert.equal(again.data.id, id, 'same upload resumed');
assert.ok(again.data.resumed);
assert.ok(again.data.samples.length >= 1);
for (const [index, hash] of again.data.samples) assert.equal(hash, sha(chunkOf(big, index)), 'samples match the file');
// The hasher may already have found the zeroed chunk and dropped it.
const gaps = missing(again.data.received, chunks);
const droppedEarly = gaps.includes(lost);
assert.equal(gaps.length, chunks - 20 + (droppedEarly ? 1 : 0));
await sendChunks(token, id, big, gaps);
const done = await waitStored(token, id, big, { allowResend: true });
assert.equal(done.state, 'stored');
assert.equal(done.sha256, bigSha, 'stored under the hash of the whole file');
assert.ok(droppedEarly || done.resent >= 1, 'the chunk zeroed in the crash was asked for again');
assert.deepEqual(readFileSync(path.join(store, bigSha)), big, 'stored file is the original');
const record = JSON.parse(readFileSync(path.join(store, `${bigSha}.json`), 'utf8'));
assert.deepEqual(
  [record.sha256, record.size, record.token, record.name, record.original_name, record.original_path, record.ip],
  [bigSha, big.length, token, 'Sonic', 'big.img', 'dumps/big.img', '203.0.113.7'],
);
assert.ok(record.ips.includes('127.0.0.1'), 'later chunks came from another address');
assert.ok(!existsSync(partial), 'partial removed');
console.log(`-- stored after the crash; chunk ${lost} (zeroed) was asked for again ${droppedEarly ? 'when resuming' : 'while hashing'}`);

// ---- graceful restart mid-upload: the hash checkpoint is saved and used
const second = randomBytes(12 * MiB + 77);
const s1 = await call('POST', `/api/bulk/${token}/uploads`, { name: 'second.bin', size: second.length });
assert.equal(s1.status, 201);
await sendChunks(token, s1.data.id, second, [0, 1, 2, 3, 4, 5, 6, 7]);
for (let i = 0; (await call('GET', `/api/bulk/${token}/uploads/${s1.data.id}`)).data.hashed_bytes < 8 * MiB; i++) {
  assert.ok(i < 200, 'server hash follows the received chunks');
  await sleep(25);
}
await stop('SIGTERM');
const state = JSON.parse(readFileSync(path.join(store, '.partial', s1.data.id, 'hash.state'), 'utf8'));
assert.equal(state.next, 8, 'checkpoint written at shutdown');
await start();
const s2 = await call('POST', `/api/bulk/${token}/uploads`, { name: 'second.bin', size: second.length });
assert.equal(s2.data.id, s1.data.id);
assert.equal(s2.data.hashed_bytes, 8 * MiB, 'hash resumes from the checkpoint');
await sendChunks(token, s1.data.id, second, missing(s2.data.received, s2.data.chunks));
assert.equal((await waitStored(token, s1.data.id, second)).sha256, sha(second));

// ---- the same file again: not stored twice, not counted
const used = (await call('GET', `/api/bulk/${token}`)).data.used;
assert.equal(used, big.length + second.length);
const dup = await call('POST', `/api/bulk/${token}/uploads`, { name: 'second-copy.bin', size: second.length, fresh: true });
await sendChunks(token, dup.data.id, second, [...Array(dup.data.chunks).keys()]);
assert.equal((await waitStored(token, dup.data.id, second)).state, 'duplicate');
info = (await call('GET', `/api/bulk/${token}`)).data;
assert.deepEqual([info.used, info.reserved, info.files], [used, 0, 2], 'a duplicate costs nothing');
assert.equal(info.recent[0].original_name, 'second.bin');

// ---- quota
const left = ceiling - used;
const tooBig = await call('POST', `/api/bulk/${token}/uploads`, { name: 'huge.img', size: left + 1 });
assert.deepEqual([tooBig.status, tooBig.data.error], [409, 'quota'], JSON.stringify(tooBig.data));
const fits = await call('POST', `/api/bulk/${token}/uploads`, { name: 'fits.img', size: left });
assert.equal(fits.status, 201);
const noRoom = await call('POST', `/api/bulk/${token}/uploads`, { name: 'tiny.bin', size: 1 });
assert.equal(noRoom.data.error, 'quota', 'the unfinished upload reserves the rest');
assert.equal((await call('DELETE', `/api/bulk/${token}/uploads/${fits.data.id}`)).status, 204);
assert.equal((await call('GET', `/api/bulk/${token}`)).data.reserved, 0, 'discarding frees the reservation');
assert.equal((await call('POST', `/api/bulk/${token}/uploads`, { name: 'empty', size: 0 })).status, 400);

// ---- deploys aren't held back by bulk uploads
const health = (await call('GET', '/api/health')).data;
assert.equal(health.active, 0);
assert.equal(typeof health.bulk_unfinished, 'number');

// ---- revoking
const open = await call('POST', `/api/bulk/${token}/uploads`, { name: 'late.bin', size: 3 * MiB });
const list = (await call('GET', `/api/admin/${key}/grants`)).data;
const listed = list.grants.find(g => g.token === token);
assert.deepEqual([listed.name, listed.note, listed.files, listed.unfinished], ['Sonic', 'e2e', 2, 1]);
assert.ok(list.disk.total > 0);
assert.equal((await call('DELETE', `/api/admin/${key}/grants/${token}`)).status, 204);
assert.equal((await fetch(`${base}/r/${token}`)).status, 404, 'revoked link page');
assert.equal((await call('GET', `/api/bulk/${token}`)).data.error, 'revoked');
assert.equal((await putChunk(token, open.data.id, 0, randomBytes(MiB))).status, 403);
await sleep(200);
assert.ok(!existsSync(path.join(store, '.partial', open.data.id)), 'unfinished upload of a revoked link discarded');
assert.ok(existsSync(path.join(store, bigSha)), 'stored files stay');

await stop('SIGTERM');
rmSync(work, { recursive: true });
console.log('bulk e2e ok');
