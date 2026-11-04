// The store classified again after a zrax update, against a dry-run server
// this test starts. The store is seeded as if an older zrax had classified
// it, with posts in the supergroup:
//
// - an AArch64 ELF the old zrax took for raw MIPS code (the record and the
//   post change),
// - noise the old zrax took for Dalvik (unclassified: hidden but kept, and
//   its post says so),
// - an ELF the old zrax rejected (accepted again: visible),
// - a file the last run was classifying when the process died (left as it is).
//
// Then a restart has nothing left to do.
//
//   node tests/reclassify.e2e.mjs <fwdonor binary> [port]
//
// Run scripts/build.sh first (the server serves dist/).
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, openSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

const [serverBin, portArg] = process.argv.slice(2);
if (!serverBin) {
  console.error('usage: node tests/reclassify.e2e.mjs <fwdonor binary> [port]');
  process.exit(2);
}
const port = Number(portArg ?? 18097);
const base = `http://127.0.0.1:${port}`;
const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-reclassify-'));
const store = path.join(work, 'firmwares');
const runtime = path.join(work, 'runtime');
mkdirSync(store, { recursive: true });
mkdirSync(runtime, { recursive: true });
const sha = b => createHash('sha256').update(b).digest('hex');
const CHAT = -1003917356862;
const OLD = '0.0.0@0000000';

// A minimal AArch64 ELF executable; `tag` makes each one a different file.
function elf(tag) {
  const head = Buffer.alloc(0x200);
  head.write('\x7fELF', 0, 'latin1');
  head[4] = 2;
  head[5] = 1;
  head[6] = 1;
  head.writeUInt16LE(2, 16);
  head.writeUInt16LE(183, 18);
  head.writeUInt32LE(1, 20);
  head.writeBigUInt64LE(0x200n, 24);
  head.writeBigUInt64LE(64n, 32);
  head.writeUInt16LE(64, 52);
  head.writeUInt16LE(56, 54);
  head.writeUInt16LE(1, 56);
  head.writeUInt32LE(1, 64);
  head.writeUInt32LE(5, 68);
  head.writeBigUInt64LE(0x400n, 64 + 32);
  head.writeBigUInt64LE(0x400n, 64 + 40);
  const code = Buffer.alloc(512);
  for (let i = 0; i < 512; i += 8) Buffer.from([0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5]).copy(code, i);
  return Buffer.concat([head, code, Buffer.from(tag)]);
}

const summary = isa => ({
  format: 'raw', format_name: 'Raw code', format_variant: null, isa, isa_name: isa, isa_tag: isa, bitwidth: 32,
  endianness: 'little', confidence: 0.6, source: 'heuristic', variant: null, slices: [], metadata: [], basis: 'isa', zrax: OLD,
});

const ledger = [];
function seed(n, name, bytes, isa, extra = {}) {
  const h = sha(bytes);
  const at = 1793646000 + n;
  writeFileSync(path.join(store, h), bytes);
  const record = {
    sha256: h, size: bytes.length, name: 'seeder', original_name: name, zrax: summary(isa), received_at: at, source: 'upload',
    telegram: { chat_id: CHAT, message_id: n << 20, posted_at: at }, ...extra,
  };
  writeFileSync(path.join(store, `${h}.json`), JSON.stringify(record, null, 2));
  ledger.push({ sha256: h, name, size: bytes.length, username: 'seeder', format: 'raw', isa, message_id: n << 20, posted_at: at });
  return h;
}
const wrong = seed(1, 'wrong.elf', elf('wrong'), 'mips');
const noise = seed(2, 'noise.bin', Buffer.alloc(8192), 'dalvik');
const back = seed(3, 'back.elf', elf('back'), 'mips', { unclassified: { zrax: OLD, since: 1793646003, reason: 'unrecognized by zrax' } });
const died = seed(4, 'died.elf', elf('died'), 'mips');
writeFileSync(path.join(runtime, 'posted.jsonl'), ledger.map(e => JSON.stringify(e)).join('\n') + '\n');
writeFileSync(path.join(runtime, 'reclassify.inflight'), `${died}\n`);

writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${runtime}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${store}"

[bulk]
dir = "${path.join(work, 'bulk')}"
min_free_bytes = 0

[telegram]
dry_run = true
`);
const logPath = path.join(work, 'server.log');
const log = openSync(logPath, 'a');
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

async function stop() {
  const exited = new Promise(resolve => server.once('exit', resolve));
  server.kill('SIGTERM');
  await exited;
}

async function get(url, expect = 200) {
  const res = await fetch(`${base}${url}`);
  const text = await res.text();
  assert.equal(res.status, expect, `${url}: ${res.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

async function waitFor(what, fn, timeout = 60000) {
  const until = Date.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

const record = h => JSON.parse(readFileSync(path.join(store, `${h}.json`), 'utf8'));
const edits = () => readFileSync(logPath, 'utf8').split('\n').filter(l => l.includes('dry run, would edit'));

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}

console.log('-- first start: the store is classified again');
await start();
const key = readFileSync(path.join(runtime, 'dashboard.key'), 'utf8').trim();
const dash = (p, expect) => get(`/api/dash/${key}${p}`, expect);
const s = await waitFor('the reclassification', async () => {
  const v = await dash('/summary');
  return v.reclassify?.state === 'finished' && v.reclassify.edits.pending === 0 && v;
});
const r = s.reclassify;
assert.equal(r.zrax, s.zrax, 'brought to the current zrax');
assert.deepEqual([r.total, r.todo, r.done], [4, 4, 4]);
assert.deepEqual([r.changed, r.unclassified, r.restored, r.errors, r.hidden], [1, 1, 1, 1, 1], JSON.stringify(r));
assert.equal(r.edits.edited, 3, 'three posts edited (dry run)');
assert.equal(s.files, 3, 'the unclassified file is not counted');
assert.deepEqual(s.unclassified, { files: 1, bytes: 8192 });
assert.equal(s.older_zrax, 1, 'the file zrax gave no answer on keeps its old classification');

console.log('-- records');
const w = record(wrong);
assert.deepEqual([w.zrax.format, w.zrax.isa, w.checked.zrax], ['elf', 'a_arch64', s.zrax]);
const n = record(noise);
assert.equal(n.unclassified.zrax, s.zrax);
assert.equal(n.zrax.isa, 'dalvik', 'the last accepted classification stays');
assert.ok(existsSync(path.join(store, noise)), 'the unclassified file stays on disk');
const b = record(back);
assert.equal(b.unclassified, undefined, 'accepted again');
assert.equal(b.zrax.isa, 'a_arch64');
const d = record(died);
assert.equal(d.checked.error, 'the process died while classifying it');
assert.equal(d.zrax.isa, 'mips', 'left as it was');
for (const h of [wrong, noise, back]) assert.ok(record(h).telegram.shows, `the record knows what post ${h.slice(0, 8)} shows`);
assert.equal(readFileSync(path.join(runtime, 'reclassify.inflight'), 'utf8').trim(), '');

console.log('-- dashboards and statistics');
assert.equal((await dash('/query?q=noise')).total, 0);
assert.equal((await dash('/query')).total, 3);
assert.equal((await dash('/query?isa=dalvik')).total, 0);
await dash(`/files/${noise}`, 404);
await dash(`/files/${noise}/download`, 404);
await get(`/api/dashboard/files/${noise}`, 404);
assert.equal((await get('/api/dashboard/summary')).files, 3);
assert.equal((await get('/api/dashboard/summary')).unclassified, undefined, 'the public summary has no unclassified count');
const pubWrong = await get(`/api/dashboard/files/${wrong}`);
for (const k of ['checked', 'unclassified', 'source']) assert.equal(pubWrong.record[k], undefined, k);
assert.equal(pubWrong.record.telegram.shows, undefined);
assert.equal((await dash(`/files/${back}`)).row.isa, 'a_arch64', 'visible again');
const stats = await get('/api/stats');
assert.equal(stats.files, 3);
const isa = k => stats.isas.find(i => i.isa === k)?.files ?? 0;
assert.deepEqual([isa('a_arch64'), isa('mips'), isa('dalvik')], [2, 1, 0], JSON.stringify(stats.isas.filter(i => i.files)));

console.log('-- the posts');
const lines = edits();
assert.equal(lines.length, 3, lines.join('\n'));
const text = readFileSync(logPath, 'utf8');
for (const id of [1, 2, 3]) assert.ok(lines.some(l => l.includes(`${CHAT}/${id << 20}`)), `post ${id} edited`);
const noiseEdit = text.slice(text.indexOf(`${CHAT}/${2 << 20}`)).split("\n").slice(0, 10).join("\n");
assert.match(noiseEdit, /no longer classified by zrax [^:]+: unrecognized by zrax/);
assert.match(noiseEdit, /earlier: Raw code · dalvik/);
assert.match(noiseEdit, /#unclassified #fwdonor/);
assert.doesNotMatch(noiseEdit, /#dalvik/);
const wrongEdit = text.slice(text.indexOf(`${CHAT}/${1 << 20}`)).split("\n").slice(0, 10).join("\n");
assert.match(wrongEdit, /#a_arch64 #elf #fwdonor|#aarch64 #elf #fwdonor/);

console.log('-- a restart has nothing left to do');
await stop();
assert.ok(!existsSync(path.join(runtime, 'reclassify.inflight')), 'a clean shutdown clears the in-flight list');
await start();
const again = await waitFor('the second run', async () => {
  const v = await dash('/summary');
  return v.reclassify?.state === 'finished' && v;
});
assert.deepEqual([again.reclassify.todo, again.reclassify.hidden, again.files], [0, 1, 3]);
await sleep(500);
assert.equal(edits().length, 3, 'no more edits');
await stop();
console.log('reclassify e2e: ok');
