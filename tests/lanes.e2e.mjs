// The two post queues against a dry-run server this test starts: fwdonate's
// uploads wait in the background lane (no spool space, donors taking turns)
// while a web donation made meanwhile is posted next. The backlog survives a
// SIGTERM (the post in progress finishes first, nothing is posted twice) and
// a SIGKILL (it resumes from its sidecars).
//
//   node tests/lanes.e2e.mjs <fwdonor binary> <fwdonate binary> [port]
import { readFileSync, readdirSync, writeFileSync, mkdirSync, mkdtempSync, openSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { powSeed, solve } from '../web/sha256.js';

const [serverBin, clientBin, portArg] = process.argv.slice(2);
if (!serverBin || !clientBin) {
  console.error('usage: node tests/lanes.e2e.mjs <fwdonor binary> <fwdonate binary> [port]');
  process.exit(2);
}
const port = Number(portArg ?? 18095);
const base = `http://127.0.0.1:${port}`;
const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-lanes-'));
const sha = b => createHash('sha256').update(b).digest('hex');

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

// Two donors' collections.
const owner = new Map();
function collection(donor, n) {
  const dir = path.join(work, donor);
  mkdirSync(dir);
  for (let i = 0; i < n; i++) {
    const bytes = elf(`${donor}-${i}`);
    writeFileSync(path.join(dir, `${donor}-${i}.elf`), bytes);
    owner.set(sha(bytes), donor);
  }
  return dir;
}
const alice = collection('alice', 10);
const bob = collection('bob', 10);

writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.join(work, 'no-dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[bulk]
dir = "${path.join(work, 'bulk')}"
min_free_bytes = 0

[telegram]
dry_run = true
`);
const serverLog = path.join(work, 'server.log');
const logFd = openSync(serverLog, 'a');
const logText = () => readFileSync(serverLog, 'utf8').replace(/\x1b\[[0-9;]*m/g, '');
let server = null;
process.on('exit', () => server?.kill('SIGKILL'));

async function start() {
  server = spawn(serverBin, ['--config', path.join(work, 'fwdonor.toml'), 'serve'], { stdio: ['ignore', logFd, logFd] });
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

async function call(method, route, body) {
  const res = await fetch(base + route, {
    method,
    headers: body && !(body instanceof Uint8Array) ? { 'content-type': 'application/json' } : {},
    body: body instanceof Uint8Array ? body : body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}
  return { status: res.status, data };
}
const health = async () => (await call('GET', '/api/health')).data;
const ledger = () => {
  try {
    return readFileSync(path.join(work, 'runtime', 'posted.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  } catch {
    return [];
  }
};

async function init(file, username, lane) {
  const policy = (await call('GET', '/api/policy')).data;
  const challenge = (await call('GET', '/api/challenge')).data;
  const nonce = solve(await powSeed(challenge.token, sha(file)), challenge.bits);
  return call('POST', '/api/uploads', {
    name: `${username}.elf`, size: file.length, sha256: sha(file), username, token: challenge.token, nonce,
    zrax_rev: policy.zrax_rev, ...(lane ? { lane } : {}),
  });
}

// Upload one file through the API; returns its id once it is verified.
async function donate(file, username, lane) {
  const r = await init(file, username, lane);
  assert.equal(r.status, 201, `admitted: ${JSON.stringify(r.data)}`);
  const { id } = r.data;
  assert.equal((await call('PUT', `/api/uploads/${id}/0`, new Uint8Array(file))).status, 204);
  assert.equal((await call('POST', `/api/uploads/${id}/complete`)).status, 202);
  for (let i = 0; i < 100; i++) {
    const status = (await call('GET', `/api/uploads/${id}`)).data;
    if (status.state !== 'verifying' && status.state !== 'receiving') return { id, status };
    await sleep(100);
  }
  throw new Error('not verified');
}

function runClient(donor, dir) {
  const child = spawn(clientBin, ['--server', base, '-n', donor, dir], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout.on('data', d => { stdout += d; });
  child.stderr.on('data', () => {});
  return new Promise(resolve => child.once('exit', code => resolve({ code, stdout })));
}

async function until(what, check, timeout = 120000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting: ${what}`);
    await sleep(100);
  }
}

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();

// 1. Two donors' runs, one after the other. Each is done once its files are
//    verified, long before they are posted.
for (const [donor, dir] of [['alice', alice], ['bob', bob]]) {
  const t = Date.now();
  const run = await runClient(donor, dir);
  assert.equal(run.code, 0, `${donor}'s run exited with ${run.code}:\n${run.stdout}`);
  assert.equal(run.stdout.split('\n').filter(l => l.startsWith('donated')).length, 10, `${donor}: 10 donated`);
  console.log(`-- ${donor}: 10 files handed over in ${Date.now() - t} ms`);
}
let h = await health();
console.log(`-- backlog: ${h.background} waiting (${h.background_bytes} bytes), ${ledger().length} posted`);
assert.ok(h.background >= 10, `most files still wait for their post (${h.background})`);
assert.equal(h.queued, 0, 'nothing in the web queue');
assert.equal(h.spooled_bytes, 0, 'the backlog holds no spool space');
assert.ok(h.background_bytes > 0);
assert.deepEqual(readdirSync(path.join(work, 'spool')), [], 'nothing in the spool');

// 2. A waiting hash is known as queued, and can't be uploaded again.
const posted = () => new Set(ledger().map(e => e.sha256));
const lastBob = elf('bob-9');
assert.ok(!posted().has(sha(lastBob)));
const known = (await call('POST', '/api/known', { sha256: [sha(lastBob)] })).data.known[sha(lastBob)];
assert.deepEqual(known, { in_progress: true, queued: true }, 'known: waiting for its post');
const again = await init(lastBob, 'mallory');
assert.equal(again.status, 409);
assert.equal(again.data.error, 'duplicate');
assert.match(again.data.message, /waiting for its post/);

// 3. A background upload through the API reports its lane and no position.
const api = elf('carol-0');
owner.set(sha(api), 'carol');
const bg = await donate(api, 'carol', 'background');
assert.equal(bg.status.state, 'queued');
assert.equal(bg.status.lane, 'background');
assert.equal(bg.status.position, undefined);

// 4. A web donation is posted next, ahead of the backlog.
const web = elf('web-0');
owner.set(sha(web), 'webby');
const w = await donate(web, 'webby');
// Posted already, or being posted now, when it was queued: at most one more.
const before = ledger().length;
assert.equal(w.status.state, 'queued', JSON.stringify(w.status));
assert.equal(w.status.lane, undefined, 'web donations report no lane');
assert.equal(w.status.position, 1);
await until('the web donation is posted', async () => (await call('GET', `/api/uploads/${w.id}`)).data.state === 'posted', 30000);
const at = ledger().findIndex(e => e.sha256 === sha(web));
assert.ok(at >= 0 && Math.abs(at - before) <= 1, `posted right after the post in progress (${at - before} later)`);
h = await health();
assert.ok(h.background > 0, `the backlog was still waiting (${h.background})`);
console.log(`-- web donation posted ${at - before} post(s) after it was verified, ${h.background} still in the background lane`);

// 5. SIGTERM while a background file is being posted: the post finishes
//    before the server exits, and isn't posted again after the restart.
const mark = logText().length;
const postingId = await until('a background post starts', () => logText().slice(mark).match(/dry run, would post [^\n]*\.posting-([0-9a-f]{24})\//)?.[1], 20000);
await stop('SIGTERM');
const shutdown = logText().slice(mark);
const done = shutdown.match(new RegExp(`id=${postingId}[^\\n]*\\bposted\\b|\\bposted\\b[^\\n]*id=${postingId}`));
assert.ok(done, `the post in progress finished:\n${shutdown}`);
assert.ok(shutdown.indexOf('shutting down') >= 0 && shutdown.indexOf('shutting down') < done.index, 'it finished after the signal');
assert.ok(!shutdown.includes('exiting anyway'), 'the poster stopped in time');
const left = readdirSync(path.join(work, 'runtime', 'background')).length;
console.log(`-- SIGTERM: ${postingId} posted before exiting, ${left} sidecar(s) left`);
await start();
const resumed = logText().match(/(\d+) from fwdonate waiting in the background/g).at(-1);
assert.equal(resumed, `${left} from fwdonate waiting in the background`);
const unique = l => new Set(l.map(e => e.sha256)).size === l.length;
await until('two more posts after the restart', () => ledger().length >= before + 4, 30000);
assert.ok(unique(ledger()), 'nothing posted twice across the SIGTERM');

// 6. Donors take turns: from bob's first post on, alice and bob alternate
//    while both have files waiting.
const turns = ledger().map(e => owner.get(e.sha256)).filter(d => d === 'alice' || d === 'bob');
const firstBob = turns.indexOf('bob');
for (let i = firstBob; i + 1 < turns.length; i++) {
  if (turns[i] === turns[i + 1]) {
    const other = turns[i] === 'alice' ? 'bob' : 'alice';
    const waiting = [...owner].filter(([h, d]) => d === other && !posted().has(h));
    assert.equal(waiting.length, 0, `${turns[i]} posted twice in a row while ${other} waited: ${turns.join(' ')}`);
  }
}

// 7. SIGKILL with the backlog waiting: it resumes and everything is posted.
h = await health();
assert.ok(h.background > 0, 'still a backlog to kill');
await stop('SIGKILL');
const kept = readdirSync(path.join(work, 'runtime', 'background')).length;
await start();
h = await health();
assert.ok(h.background > 0 && h.background <= kept, `resumed ${h.background} of ${kept} sidecar(s)`);
await until('the backlog drains', async () => {
  const s = await health();
  return !s.background && !s.active && !s.queued && [...owner.keys()].every(k => posted().has(k));
}, 180000);
const final = ledger();
assert.deepEqual([...new Set(final.map(e => e.sha256))].sort(), [...owner.keys()].sort(), 'everything posted');
for (const e of final) assert.equal(e.username, owner.get(e.sha256), 'credited to its donor');
if (!unique(final)) console.log(`-- note: ${final.length - owner.size} repost(s) after the SIGKILL (at-least-once delivery)`);
assert.deepEqual(readdirSync(path.join(work, 'runtime', 'background')), [], 'no sidecars left');
assert.ok(!readdirSync(path.join(work, 'firmwares')).some(n => n.startsWith('.')), 'no .posting-* left in the store');
assert.equal((await health()).spooled_bytes, 0);
console.log(`-- order: ${final.map(e => owner.get(e.sha256)[0]).join('')}`);

await stop('SIGTERM');
rmSync(work, { recursive: true });
console.log('lanes e2e ok');
