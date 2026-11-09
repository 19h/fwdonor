// The import token against a dry-run server this test starts: the policy
// tells fwdonate how many uploads it may run at once, uploads with the token
// skip the proof of work and share their own pool (`import_concurrent`)
// instead of the address's, and leave a quarter of the spool to the page.
// Then fwdonate with --token runs many more than 4 at once.
//
//   node tests/import.e2e.mjs <fwdonor binary> <fwdonate binary> [port]
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, openSync, rmSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { powSeed, solve } from '../web/sha256.js';

const [serverBin, clientBin, portArg] = process.argv.slice(2);
if (!serverBin || !clientBin) {
  console.error('usage: node tests/import.e2e.mjs <fwdonor binary> <fwdonate binary> [port]');
  process.exit(2);
}
const port = Number(portArg ?? 18092);
const base = `http://127.0.0.1:${port}`;
const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-import-'));
const sha = b => createHash('sha256').update(b).digest('hex');
const MiB = 1024 * 1024;

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
dist_dir = "${path.join(work, 'no-dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[limits]
spool_cap_bytes = ${400 * MiB}

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

async function call(method, route, body, token) {
  const headers = {};
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(base + route, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}
  return { status: res.status, data };
}

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();

// 1. The token: created at the first start, printed by `fwdonor import-token`.
const token = readFileSync(path.join(work, 'runtime', 'import.key'), 'utf8').trim();
assert.match(token, /^[A-Za-z0-9_-]{43}$/);
assert.equal(execFileSync(serverBin, ['--config', config, 'import-token'], { encoding: 'utf8' }).trim(), token);

// 2. The policy says how many uploads at once.
let r = await call('GET', '/api/policy');
assert.equal(r.status, 200);
assert.deepEqual([r.data.max_parallel, r.data.import], [4, false], 'per address');
r = await call('GET', '/api/policy', null, token);
assert.deepEqual([r.data.max_parallel, r.data.import], [32, true], 'with the token');
r = await call('GET', '/api/policy', null, `${token.slice(0, -1)}x`);
assert.equal(r.status, 401);
assert.equal(r.data.error, 'import_token');
r = await fetch(`${base}/api/policy`, { headers: { authorization: 'Basic dXNlcjpwYXNz' } });
assert.equal(r.status, 200, 'other schemes (cached Basic credentials) are no token at all');
assert.equal((await r.json()).import, false);

// 3. Admission: no proof of work with the token, 32 at once, its own pool.
const zrax_rev = (await call('GET', '/api/policy')).data.zrax_rev;
const init = (size, extra, auth) =>
  call('POST', '/api/uploads', { name: 'fw.bin', size, sha256: sha(randomBytes(32)), username: 'importer', zrax_rev, lane: 'background', ...extra }, auth);
r = await init(1000, {});
assert.equal(r.status, 403, 'without the token, the proof of work is required');
assert.equal(r.data.error, 'pow');
r = await init(1000, {}, 'wrong');
assert.equal(r.status, 401, 'a wrong token is refused, not taken for an address');
const open = [];
for (let i = 0; i < 32; i++) {
  r = await init(1000, {}, token);
  assert.equal(r.status, 201, `import upload ${i + 1}: ${JSON.stringify(r.data)}`);
  open.push(r.data.id);
}
r = await init(1000, {}, token);
assert.equal(r.status, 429, 'the 33rd waits');
assert.equal(r.data.error, 'limited');
// The address still has its own 4 (with the proof of work).
async function pageInit(size) {
  const challenge = (await call('GET', '/api/challenge')).data;
  const hash = sha(randomBytes(32));
  const nonce = solve(await powSeed(challenge.token, hash), challenge.bits);
  return call('POST', '/api/uploads', { name: 'page.bin', size, sha256: hash, username: 'page', token: challenge.token, nonce, zrax_rev });
}
r = await pageInit(1000);
assert.equal(r.status, 201, `the page's own slot: ${JSON.stringify(r.data)}`);
await call('DELETE', `/api/uploads/${r.data.id}`);
for (const id of open) await call('DELETE', `/api/uploads/${id}`);

// 4. Imports may reserve 3/4 of the spool (300 of 400 MiB); the page the rest.
r = await init(250 * MiB, {}, token);
assert.equal(r.status, 201);
const big = r.data.id;
r = await init(60 * MiB, {}, token);
assert.equal(r.status, 503, `past 3/4 of the spool: ${JSON.stringify(r.data)}`);
assert.equal(r.data.error, 'busy');
r = await pageInit(140 * MiB);
assert.equal(r.status, 201, `the page may use the last quarter: ${JSON.stringify(r.data)}`);
await call('DELETE', `/api/uploads/${r.data.id}`);
await call('DELETE', `/api/uploads/${big}`);
assert.equal((await call('GET', '/api/health')).data.spooled_bytes, 0);
console.log('-- API: no proof of work, 32 at once in their own pool, 3/4 of the spool');

// 5. fwdonate with the token: far more than 4 files at once.
const dir = path.join(work, 'collection');
mkdirSync(dir);
const files = new Set();
for (let i = 0; i < 64; i++) {
  const bytes = Buffer.concat([elf(`import-${i}`), randomBytes(2 * MiB)]);
  writeFileSync(path.join(dir, `fw-${i}.elf`), bytes);
  files.add(sha(bytes));
}
function runClient(args, env = {}) {
  const child = spawn(clientBin, ['--server', base, '-n', 'importer', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, FWDONOR_TOKEN: '', ...env },
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', d => { stdout += d; });
  child.stderr.on('data', d => { stderr += d; });
  return new Promise(resolve => child.once('exit', code => resolve({ code, stdout, stderr })));
}
let most = 0, polling = true;
const poll = (async () => {
  while (polling) {
    try {
      most = Math.max(most, (await call('GET', '/api/health')).data.active);
    } catch {}
    await sleep(20);
  }
})();
const t = Date.now();
const run = await runClient(['-j', '40', dir], { FWDONOR_TOKEN: token });
polling = false;
await poll;
assert.equal(run.code, 0, `fwdonate --token exited with ${run.code}:\n${run.stderr}`);
assert.match(run.stderr, /the server allows 32 uploads at once from this client; using --jobs 32/);
assert.match(run.stderr, /import token, 32 at once/);
assert.equal(run.stdout.split('\n').filter(l => l.startsWith('donated')).length, files.size, run.stdout);
assert.ok(most > 4, `more than 4 uploads at once (saw ${most})`);
assert.ok(most <= 33, `at most 32 uploads (and a post) at once (saw ${most})`);
const admitted = readFileSync(serverLog, 'utf8').replace(/\x1b\[[0-9;]*m/g, '').split('\n').filter(l => l.includes('upload admitted') && l.includes('importer'));
assert.ok(admitted.filter(l => l.includes('import=true')).length >= files.size, 'admitted as imports');
console.log(`-- fwdonate --token: ${files.size} files (${files.size * 2} MiB) in ${Date.now() - t} ms, up to ${most} at once`);

// 6. Without the token, -j above 4 is cut to 4; a wrong token stops at once.
const plain = await runClient(['-j', '10', '--dry-run', dir]);
assert.equal(plain.code, 0, plain.stderr);
assert.match(plain.stderr, /allows 4 uploads at once from this client; the server's import token \(--token\) allows more; using --jobs 4/);
const wrong = await runClient(['--token', 'not-the-token', dir]);
assert.notEqual(wrong.code, 0);
assert.match(wrong.stderr, /doesn't accept this import token/);
assert.equal(wrong.stdout, '', 'nothing uploaded');

server.kill('SIGTERM');
await new Promise(resolve => server.once('exit', resolve));
server = null;
rmSync(work, { recursive: true });
console.log('import e2e ok');
