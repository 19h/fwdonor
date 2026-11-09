// The live dashboards against a dry-run server this test starts: the summary
// pushed over server-sent events (public and private), only when it changes;
// the caps per address and in total; polls and identical queries sharing one
// computation; gzipped query results; a load of LOAD streams (memory per
// stream, how fast a change reaches all of them); shutdown with streams open.
// With PLAYWRIGHT set, the page too: it streams, updates without reloading,
// lets go of its stream in a hidden tab, and polls when turned down.
//
//   [PLAYWRIGHT=…/playwright/index.mjs] [LOAD=2000] node tests/live.e2e.mjs <fwdonor binary> [port]
import { readFileSync, writeFileSync, mkdtempSync, openSync, rmSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { Agent, request } from 'node:http';

const [serverBin, portArg] = process.argv.slice(2);
if (!serverBin) {
  console.error('usage: node tests/live.e2e.mjs <fwdonor binary> [port]');
  process.exit(2);
}
const port = Number(portArg ?? 18089);
const base = `http://127.0.0.1:${port}`;
const LOAD = Number(process.env.LOAD ?? 2000);
const PER_ADDRESS = 4;
const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-live-'));
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

const config = path.join(work, 'fwdonor.toml');
writeFileSync(config, `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"
firmware_backfill = false

[live]
max_streams = ${LOAD + 40}
streams_per_address = ${PER_ADDRESS}
interval_ms = 500

[bulk]
dir = "${path.join(work, 'bulk')}"
min_free_bytes = 0

[telegram]
dry_run = true
`);
const serverLog = path.join(work, 'server.log');
const logFd = openSync(serverLog, 'a');
let server = null;
process.on('exit', () => server?.kill('SIGKILL'));
const strip = s => s.replace(/\x1b\[[0-9;]*m/g, '');

async function start() {
  server = spawn(serverBin, ['--config', config, 'serve'], { stdio: ['ignore', logFd, logFd] });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return;
    } catch {}
    await sleep(100);
  }
  throw new Error('server did not come up');
}
try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();
const key = execFileSync(serverBin, ['--config', config, 'dashboard-url'], { encoding: 'utf8' }).trim().split('/d/')[1];
const token = readFileSync(path.join(work, 'runtime', 'import.key'), 'utf8').trim();
const PRIV = `/api/dash/${key}`;
const PUB = '/api/dashboard';

// Streams over plain node:http (each its own connection, as through the proxy).
const agent = new Agent({ keepAlive: false, maxSockets: Infinity });
let fakeIp = 0;
const nextIp = () => `10.${(fakeIp >> 16) & 255}.${(fakeIp >> 8) & 255}.${fakeIp++ & 255}`;
function stream(route, { ip } = {}) {
  return new Promise((resolve, reject) => {
    const headers = ip ? { 'x-forwarded-for': ip } : {};
    const req = request(`${base}${route}`, { agent, headers }, res => {
      const s = { status: res.statusCode, headers: res.headers, events: [], raw: '', ended: false, waiters: new Set(), close: () => req.destroy() };
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        if (s.raw.length < 4096) s.raw += chunk.slice(0, 4096);
        buf += chunk;
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = { event: 'message', data: '', at: Date.now() };
          let any = false;
          for (const line of block.split('\n')) {
            const [k, ...rest] = line.split(':');
            const v = rest.join(':').replace(/^ /, '');
            if (k === 'event') ev.event = v;
            else if (k === 'data') { ev.data += v; any = true; }
          }
          if (!any) continue;
          if (ev.event === 'summary') ev.json = JSON.parse(ev.data);
          s.events.push(ev);
          for (const w of s.waiters) w();
        }
      });
      const end = () => { s.ended = true; for (const w of s.waiters) w(); };
      res.on('end', end);
      res.on('close', end);
      res.on('error', end);
      resolve(s);
    });
    req.on('error', reject);
    req.end();
  });
}
function next(s, pred, ms = 5000, from = 0) {
  return new Promise((resolve, reject) => {
    const check = () => {
      const ev = s.events.slice(from).find(pred);
      if (ev) { cleanup(); resolve(ev); } else if (s.ended) { cleanup(); reject(new Error('stream ended')); }
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error(`no matching event in ${ms} ms`)); }, ms);
    const cleanup = () => { clearTimeout(timer); s.waiters.delete(check); };
    s.waiters.add(check);
    check();
  });
}
const json = async (route, init) => {
  const res = await fetch(base + route, init);
  return { status: res.status, headers: res.headers, data: await res.json().catch(() => ({})) };
};
async function until(what, fn, ms = 10000) {
  const t = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}
const streamsOpen = async () => (await json(`${PRIV}/summary`)).data.live?.streams;

// One donation through the API, with the import token (no proof of work).
let donated = 0;
async function donate() {
  const bytes = elf(`live-${donated++}-${randomBytes(4).toString('hex')}`);
  const policy = (await json('/api/policy')).data;
  const auth = { authorization: `Bearer ${token}` };
  const init = await json('/api/uploads', {
    method: 'POST', headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({ name: `live-${donated}.elf`, size: bytes.length, sha256: sha(bytes), username: 'watcher', zrax_rev: policy.zrax_rev }),
  });
  assert.equal(init.status, 201, JSON.stringify(init.data));
  assert.equal((await fetch(`${base}/api/uploads/${init.data.id}/0`, { method: 'PUT', body: bytes })).status, 204);
  assert.equal((await fetch(`${base}/api/uploads/${init.data.id}/complete`, { method: 'POST' })).status, 202);
}

await until('the catalog', async () => (await json(`${PUB}/summary`)).data.ready);

// 1. The public stream: the latest summary at once, public fields only.
const pub = await stream(`${PUB}/live`);
assert.equal(pub.status, 200);
assert.equal(pub.headers['content-type'], 'text/event-stream');
const first = await next(pub, e => e.event === 'summary');
assert.match(pub.raw, /^retry: \d+\n\n/);
assert.equal(first.json.public, true);
assert.equal(first.json.refresh, 10);
for (const hidden of ['queue', 'arriving', 'disk', 'live', 'bulk', 'firmware_dir', 'stored']) assert.ok(!(hidden in first.json), `public frame has ${hidden}`);
const files0 = first.json.files;

// 2. The private stream: the server's state, every second; a wrong key gets 404.
const priv = await stream(`${PRIV}/live`);
const p1 = await next(priv, e => e.event === 'summary');
assert.ok('queue' in p1.json && 'arriving' in p1.json && p1.json.live.streams >= 2, JSON.stringify(p1.json.live));
await next(priv, e => e.event === 'summary', 2500, priv.events.indexOf(p1) + 1);
assert.equal((await stream(`/api/dash/${'x'.repeat(43)}/live`)).status, 404);
console.log('-- streams: the latest summary at once, public fields only on the public one');

// 3. A change reaches the stream; nothing is sent while nothing changes.
let seen = pub.events.length;
await sleep(1500);
assert.equal(pub.events.slice(seen).filter(e => e.event === 'summary').length, 0, 'no frame without a change');
let t = Date.now();
await donate();
const changed = await next(pub, e => e.event === 'summary' && e.json.files === files0 + 1, 15000, seen);
console.log(`-- a donation reached the public stream ${changed.at - t} ms after it was sent`);

// 4. Polls get the same frames, and many at once share one computation.
const polls = await Promise.all(Array.from({ length: 50 }, () => json(`${PUB}/summary`)));
assert.ok(polls.every(p => p.status === 200 && p.data.files === files0 + 1));
assert.equal(new Set(polls.map(p => JSON.stringify(p.data))).size, 1, 'one frame for all');
const privPoll = await json(`${PRIV}/summary`);
assert.ok(privPoll.data.queue && privPoll.data.live, 'the private poll has the server state');

// 5. Queries: identical ones computed once and shared, gzipped when asked.
const qs = '?limit=50&facets=1&tree=family,isa,format&sort=time:desc';
const results = await Promise.all(Array.from({ length: 30 }, () => fetch(`${base}${PUB}/query${qs}`, { headers: { 'accept-encoding': 'identity' } }).then(r => r.text())));
assert.equal(new Set(results).size, 1, 'one result for all');
const gz = await new Promise((resolve, reject) => {
  request(`${base}${PUB}/query${qs}`, { headers: { 'accept-encoding': 'gzip' } }, res => {
    const chunks = [];
    res.on('data', c => chunks.push(c));
    res.on('end', () => resolve({ headers: res.headers, body: Buffer.concat(chunks) }));
  }).on('error', reject).end();
});
assert.equal(gz.headers['content-encoding'], 'gzip');
assert.equal(gunzipSync(gz.body).toString(), results[0]);
assert.equal((await json(`${PRIV}/query${qs}`)).status, 200);
assert.equal((await json(`${PUB}/query?limit=x`)).status, 400, 'bad parameters still fail');
console.log(`-- queries: 30 identical ones answered alike, ${results[0].length} B or ${gz.body.length} B gzipped`);

// 6. Caps: per address (429) and in total (503); a closed stream frees its slot.
const ip = nextIp();
const mine = await Promise.all(Array.from({ length: PER_ADDRESS }, () => stream(`${PUB}/live`, { ip })));
assert.ok(mine.every(s => s.status === 200));
const refused = await stream(`${PUB}/live`, { ip });
assert.equal(refused.status, 429);
mine[0].close();
await until('the slot to be freed', async () => {
  const s = await stream(`${PUB}/live`, { ip });
  if (s.status === 200) { mine[0] = s; return true; }
  return false;
}, 30000);
console.log('-- caps: the 5th stream from one address is refused, a closed one frees its slot');
for (const s of mine) s.close();

// 7. Load: LOAD streams from as many addresses.
const rss = () => Number(execFileSync('ps', ['-o', 'rss=', '-p', String(server.pid)], { encoding: 'utf8' }).trim()) * 1024;
await until('streams to close', async () => (await streamsOpen()) <= 2, 30000);
const before = rss();
t = Date.now();
const crowd = [];
for (let i = 0; i < LOAD; i += 200) {
  crowd.push(...(await Promise.all(Array.from({ length: Math.min(200, LOAD - i) }, () => stream(`${PUB}/live`, { ip: nextIp() })))));
}
assert.ok(crowd.every(s => s.status === 200), `refused: ${crowd.filter(s => s.status !== 200).length}`);
await Promise.all(crowd.map(s => next(s, e => e.event === 'summary', 20000)));
const opened = Date.now() - t;
await sleep(1000);
const after = rss();
const perStream = (after - before) / LOAD;
assert.equal(await streamsOpen(), LOAD + 2);
const frame = (await json(`${PUB}/summary`)).data;
assert.equal(frame.refresh, Math.max(10, Math.min(300, Math.floor((LOAD + 1) / 20))), 'the refresh hint grows with viewers');
const marks = crowd.map(s => s.events.length);
t = Date.now();
await donate();
await Promise.all(crowd.map((s, i) => next(s, e => e.event === 'summary' && e.json.files === files0 + 2, 20000, marks[i])));
const fanout = Date.now() - t;
assert.ok(perStream < 64 * 1024, `${Math.round(perStream)} B per stream`);
console.log(`-- load: ${LOAD} streams open in ${opened} ms, ${Math.round(perStream / 1024)} KiB each (RSS ${Math.round(before / 2 ** 20)} → ${Math.round(after / 2 ** 20)} MiB); a donation reached all of them ${fanout} ms after it was sent`);
for (const s of crowd) s.close();

// 8. The page (with Playwright).
if (process.env.PLAYWRIGHT) {
  const { chromium } = await import(process.env.PLAYWRIGHT);
  await until('the crowd to leave', async () => (await streamsOpen()) <= 2, 30000);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const asked = [];
  page.on('request', r => asked.push(new URL(r.url()).pathname));
  await page.goto(`${base}/dashboard`);
  await page.waitForFunction(() => document.getElementById('updated').textContent.startsWith('live · '), null, { timeout: 10000 });
  // Everything, not only firmware (the test's files are programs).
  await page.click('#scope [data-scope="all"]');
  await page.waitForFunction(() => document.querySelectorAll('#files-rows .name').length > 0, null, { timeout: 10000 });
  const shown = async () => Number((await page.textContent('#s-files')).replace(/\D/g, ''));
  const before = await shown();
  await donate();
  await page.waitForFunction(n => Number(document.getElementById('s-files').textContent.replace(/\D/g, '')) === n, before + 1, { timeout: 10000 });
  // The table follows within its refresh time (10 s here) without a reload.
  await page.waitForFunction(() => [...document.querySelectorAll('#files-rows .name')].some(e => e.textContent.startsWith(`live-`) && e.closest('tr').classList.contains('new')), null, { timeout: 20000 });
  assert.ok(!asked.some(p => p.endsWith('/summary')), 'the page streams instead of polling');
  console.log('-- page: streams, the counters and the table follow a donation without a reload');

  // A hidden tab lets go of its stream after 30 s and catches up when shown.
  const visibility = hidden => page.evaluate(h => {
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => h });
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => (h ? 'hidden' : 'visible') });
    document.dispatchEvent(new Event('visibilitychange'));
  }, hidden);
  await visibility(true);
  await until('the hidden tab to close its stream', async () => (await streamsOpen()) === 2, 45000);
  await donate();
  await sleep(1000);
  await visibility(false);
  await page.waitForFunction(n => Number(document.getElementById('s-files').textContent.replace(/\D/g, '')) === n, before + 2, { timeout: 10000 });
  console.log('-- page: a hidden tab lets go of its stream and catches up when shown');

  // Turned down (this address has no room): the page polls instead.
  const hogs = await Promise.all(Array.from({ length: PER_ADDRESS }, () => stream(`${PUB}/live`)));
  const polled = await browser.newPage();
  const asked2 = [];
  polled.on('request', r => asked2.push(new URL(r.url()).pathname));
  await polled.goto(`${base}/dashboard`);
  await polled.waitForFunction(() => /^updated /.test(document.getElementById('updated').textContent), null, { timeout: 15000 });
  assert.ok(asked2.some(p => p.endsWith('/summary')), 'it polls');
  const n = Number((await polled.textContent('#s-files')).replace(/\D/g, ''));
  await donate();
  await polled.waitForFunction(m => Number(document.getElementById('s-files').textContent.replace(/\D/g, '')) === m, n + 1, { timeout: 20000 });
  for (const s of hogs) s.close();
  console.log('-- page: turned down, it polls and still follows');
  await browser.close();
}

// 9. Shutdown with streams open: they end and the server exits at once.
const open = await Promise.all(Array.from({ length: 20 }, () => stream(`${PUB}/live`, { ip: nextIp() })));
await Promise.all(open.map(s => next(s, e => e.event === 'summary')));
t = Date.now();
server.kill('SIGTERM');
await new Promise(resolve => server.once('exit', resolve));
server = null;
const took = Date.now() - t;
await until('the streams to end', async () => open.every(s => s.ended), 3000);
assert.ok(took < 2500, `shutdown took ${took} ms`);
assert.ok(!strip(readFileSync(serverLog, 'utf8')).includes('requests still open'), 'nothing held the shutdown');
console.log(`-- shutdown: 20 streams ended, the server exited in ${took} ms`);
agent.destroy();
rmSync(work, { recursive: true });
console.log('live e2e ok');
