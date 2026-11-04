// fwdonate against a dry-run server that keeps crashing and restarting:
// every firmware file must end up posted, nothing else uploaded, and a second
// run must find everything already in the collection. By default the client
// has at most two files in the server's Telegram queue; with --no-wait it
// hands over everything at once.
//
//   node tests/client.e2e.mjs <fwdonor binary> <fwdonate binary> <dir-with-files> [port]
//
// <dir-with-files> needs aarch64-tool.elf and mips_gzip.uimage (see
// tests/browser.e2e.mjs); the test derives its files from them.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, openSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const [serverBin, clientBin, dir, port = '18099'] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = data => createHash('sha256').update(data).digest('hex');

const work = mkdtempSync(path.join(tmpdir(), 'fwdonate-e2e-'));
const donate = path.join(work, 'donate');
const firmware = new Set();
const put = (rel, data, isFirmware) => {
  const file = path.join(donate, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, data);
  if (isFirmware) firmware.add(sha(data));
  return file;
};
// Distinct ELFs (trailing bytes don't change what zrax sees), a few large
// uImages for multi-chunk uploads, copies, junk, and a nested tree.
const elf = readFileSync(path.join(dir, 'aarch64-tool.elf'));
const uimage = readFileSync(path.join(dir, 'mips_gzip.uimage'));
for (let i = 0; i < 36; i++) put(`elves/${i % 4}/tool-${i}.elf`, Buffer.concat([elf, randomBytes(64 + i)]), true);
for (let i = 0; i < 3; i++) put(`big/image-${i}.uimage`, Buffer.concat([uimage, randomBytes(14 * 1024 * 1024 + i)]), true);
const single = put('single/one.elf', Buffer.concat([elf, randomBytes(99)]), true);
put('elves/copy-of-0.elf', readFileSync(path.join(donate, 'elves/0/tool-0.elf')), false);
for (let i = 0; i < 10; i++) put(`junk/noise-${i}.bin`, randomBytes(5000 + i), false);
put('junk/readme.txt', Buffer.from('not firmware\n'.repeat(100)), false);
symlinkSync(path.join(donate, 'elves'), path.join(donate, 'link-to-elves'));

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
const log = openSync(serverLog, 'a');
let server = null;

// Never leave a server behind (a later run would talk to it).
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

function runClient(args) {
  const child = spawn(clientBin, ['--server', base, '-n', 'cli_e2e', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', d => { stdout += d; });
  child.stderr.on('data', d => { stderr += d; process.stderr.write(`  | ${d}`); });
  const done = new Promise(resolve => child.once('exit', code => resolve({ code, stdout, stderr })));
  return { child, done };
}

// Largest Telegram queue seen while a client runs.
async function watchQueue(done) {
  let max = 0, finished = false;
  done.then(() => { finished = true; });
  while (!finished) {
    try {
      max = Math.max(max, (await (await fetch(`${base}/api/health`)).json()).queued);
    } catch {}
    await sleep(100);
  }
  return max;
}

const admitted = () => (readFileSync(serverLog, 'utf8').match(/upload admitted/g) ?? []).length;

// Every donated image is kept (firmwares/<sha256>), with a record that says
// where it was posted and nothing about the sender's address.
function checkStore(expected) {
  const store = path.join(work, 'firmwares');
  const names = readdirSync(store);
  assert.ok(!names.some(n => n.startsWith('.') || n.endsWith('.tmp')), 'no temporary files in the store');
  const kept = names.filter(n => !n.endsWith('.json'));
  assert.deepEqual(kept.sort(), [...expected].sort(), 'the store holds exactly the donated firmware');
  for (const hash of kept) {
    assert.equal(sha(readFileSync(path.join(store, hash))), hash, 'stored bytes match the hash');
    const record = JSON.parse(readFileSync(path.join(store, `${hash}.json`), 'utf8'));
    assert.equal(record.sha256, hash);
    assert.equal(record.name, 'cli_e2e');
    assert.equal(record.source, 'upload');
    assert.ok(record.original_name && record.zrax?.format, `record has the file name and zrax result: ${JSON.stringify(record)}`);
    assert.equal(record.telegram?.message_id, 0, `record notes the (dry-run) post: ${JSON.stringify(record)}`);
    assert.ok(!('ip' in record), 'no address in the record');
  }
}
async function waitForAdmitted(n, timeout = 120000) {
  const until = Date.now() + timeout;
  while (admitted() < n) {
    if (Date.now() > until) throw new Error(`fewer than ${n} uploads admitted`);
    await sleep(50);
  }
}

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();
const first = runClient([donate, single, path.join(donate, 'elves/1')]);
const firstQueue = watchQueue(first.done);

await waitForAdmitted(3);
console.log('-- crash (SIGKILL), down 4 s');
await stop('SIGKILL');
await sleep(4000);
await start();

await waitForAdmitted(admitted() + 6);
console.log('-- restart (SIGTERM), down 1.5 s');
await stop('SIGTERM');
await sleep(1500);
await start();

await waitForAdmitted(admitted() + 5);
console.log('-- two quick crashes');
await stop('SIGKILL');
await sleep(300);
await start();
await sleep(1500);
await stop('SIGKILL');
await sleep(2500);
await start();

const result = await first.done;
const maxQueued = await firstQueue;
console.log(result.stdout.trim().split('\n').map(l => `  > ${l}`).join('\n'));
assert.equal(result.code, 0, `first run exited with ${result.code}`);
const lines = result.stdout.trim().split('\n');
assert.equal(lines.filter(l => l.startsWith('donated')).length, firmware.size, 'every firmware file reported donated');
assert.equal(lines.filter(l => l.startsWith('known')).length, 1, 'the copy is reported as a duplicate');
assert.ok(!lines.some(l => /^(failed|rejected)/.test(l)), 'nothing failed or was rejected');
assert.ok(maxQueued <= 2, `at most 2 files waited for Telegram at once (saw ${maxQueued})`);

const ledger = readFileSync(path.join(work, 'runtime', 'posted.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
assert.deepEqual([...new Set(ledger.map(e => e.sha256))].sort(), [...firmware].sort(), 'the ledger holds exactly the firmware');
assert.ok(ledger.every(e => e.username === 'cli_e2e'), 'credited to the donor name');
if (ledger.length !== firmware.size) console.log(`-- note: ${ledger.length - firmware.size} repost(s) after a crash (at-least-once delivery)`);
assert.equal(readdirSync(path.join(work, 'spool')).length, 0, 'spool is empty');
checkStore(firmware);
const uploads = admitted();

const second = await runClient([donate]).done;
assert.equal(second.code, 0);
assert.ok(!second.stdout.split('\n').some(l => l.startsWith('donated')), 'second run donates nothing');
assert.equal(second.stdout.trim().split('\n').filter(l => l.startsWith('known')).length, firmware.size + 1);
assert.equal(admitted(), uploads, 'second run uploads nothing');

// --no-wait: everything goes to the server's queue as fast as it uploads.
const more = [];
for (let i = 0; i < 12; i++) more.push(put(`more/extra-${i}.elf`, Buffer.concat([elf, randomBytes(300 + i)]), true));
const third = runClient(['--no-wait', path.join(donate, 'more')]);
const thirdQueue = await watchQueue(third.done);
const thirdResult = await third.done;
assert.equal(thirdResult.code, 0);
assert.equal(thirdResult.stdout.trim().split('\n').filter(l => l.startsWith('donated')).length, more.length);
assert.ok(thirdQueue > 2, `--no-wait queued more than 2 at once (saw ${thirdQueue})`);
// --no-wait leaves before its files are posted: let the queue drain.
for (let i = 0; ; i++) {
  const health = await (await fetch(`${base}/api/health`)).json();
  if (!health.queued && !health.active) break;
  assert.ok(i < 600, 'the queue drains');
  await sleep(100);
}
checkStore(firmware);
console.log(`-- largest Telegram queue: ${maxQueued} waiting for posts, ${thirdQueue} with --no-wait`);

const resumed = [...readFileSync(serverLog, 'utf8').matchAll(/(\d+) job\(s\) resumed/g)].map(m => Number(m[1]));
console.log(`-- first run: ${uploads} uploads admitted for ${firmware.size - more.length} files; jobs resumed per start: ${resumed.join(' ')}`);
await stop('SIGTERM');
rmSync(work, { recursive: true });
console.log('client e2e ok');
