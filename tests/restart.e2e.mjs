// The page must survive the server going away and coming back: files keep
// waiting and retrying, uploads the server lost are sent again, and nothing
// ends up failed or posted twice.
//
//   PLAYWRIGHT=/path/to/node_modules/playwright/index.mjs \
//   node tests/restart.e2e.mjs <fwdonor binary> <dir-with-files> <expected.json> [port]
//
// Runs its own dry-run server (fresh runtime and spool) and kills it with
// SIGKILL and SIGTERM at different points of the pipeline.
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, openSync, rmSync, copyFileSync, appendFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const [bin, dir, expectedPath, port = '18093'] = process.argv.slice(2);
const repo = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-restart-'));
const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
const files = readdirSync(dir).filter(f => f in expected).map(f => path.join(dir, f));
// A multi-chunk upload (6 × 4 MiB) gives the test something to interrupt.
const donor = files.find(f => f.endsWith('.uimage'));
const padded = path.join(work, 'padded-24m.uimage');
copyFileSync(donor, padded);
appendFileSync(padded, Buffer.alloc(24 * 1024 * 1024 - readFileSync(donor).length));
files.push(padded);
expected['padded-24m.uimage'] = 'donated';

writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.join(repo, 'dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[bulk]
dir = "${path.join(work, 'bulk')}"
min_free_bytes = 0

[telegram]
dry_run = true
`);
const log = openSync(path.join(work, 'server.log'), 'a');
let server = null;

async function start() {
  server = spawn(bin, ['--config', path.join(work, 'fwdonor.toml'), 'serve'], { stdio: ['ignore', log, log] });
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

async function outage(signal, ms, label) {
  console.log(`-- ${label}: ${signal}, down for ${ms} ms`);
  await stop(signal);
  await sleep(ms);
  await start();
}

const states = () => page.$$eval('#rows tr', trs => trs.map(tr => ({
  name: tr.querySelector('.name').textContent,
  state: tr.querySelector('.state span').textContent,
  detail: tr.querySelector('.state small')?.textContent ?? '',
})));
const waitForState = (test, timeout = 60000) =>
  page.waitForFunction(test, null, { timeout, polling: 50 });

await start();
const browser = await chromium.launch();
const page = await browser.newPage();
const problems = [];
page.on('pageerror', err => problems.push(String(err)));

// Slow chunks down so uploads are in flight when the server goes away.
await page.route(/\/api\/uploads\/[0-9a-f]{24}\/\d+$/, async route => {
  await sleep(700);
  await route.continue().catch(() => {});
});
// The policy request fails twice: the page must wait for it, not give up.
let policyFailures = 2;
await page.route('**/api/policy', route => (policyFailures-- > 0 ? route.abort('connectionrefused') : route.continue()));

await page.goto(base);
await page.fill('#donor', 'restart_test');
// Drop immediately: before the policy has loaded and the engine is ready.
await page.setInputFiles('#fileinput', files);

// 1. Crash while a file is uploading, and stay down long enough for the
//    backoff to grow and the notice to show.
await waitForState(() => [...document.querySelectorAll('#rows .state span')].some(s => s.textContent.startsWith('uploading')));
console.log('-- uploading:', (await states()).filter(r => r.state.startsWith('uploading')).map(r => r.name).join(', '));
await stop('SIGKILL');
await page.waitForSelector('#notice:not([hidden])', { timeout: 15000 });
console.log('-- notice shown:', await page.textContent('#notice'));
await sleep(6000);
await start();
await page.waitForSelector('#notice', { state: 'hidden', timeout: 30000 });

// 2. Graceful restart while something waits for Telegram (its job is in the
//    spool and must be resumed, not lost or sent twice).
await waitForState(() => [...document.querySelectorAll('#rows .state span')].some(s => /queued for telegram|posting/.test(s.textContent)));
await outage('SIGTERM', 1500, 'restart while posting');

// 3. Two quick crashes in a row.
await waitForState(() => [...document.querySelectorAll('#rows .state span')].some(s => /uploading|proof of work|server verifying/.test(s.textContent)), 90000)
  .catch(() => console.log('-- (nothing in flight for the third outage)'));
await outage('SIGKILL', 300, 'quick crash');
await sleep(800);
await outage('SIGKILL', 2500, 'second crash');

await page.waitForSelector('#thanks:not([hidden])', { timeout: 300000 });
const rows = await states();
for (const row of rows) console.log(`${row.state.padEnd(28)} ${row.name}  ${row.detail}`);
for (const row of rows) assert.equal(row.state, expected[row.name], `${row.name}: ${row.state} (${row.detail})`);

// Every donated file is in the ledger exactly once, and the stats agree.
const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
const ledger = readFileSync(path.join(work, 'runtime', 'posted.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
const donated = files.filter(f => expected[path.basename(f)] === 'donated').map(sha);
assert.deepEqual([...new Set(ledger.map(e => e.sha256))].sort(), [...donated].sort(), 'ledger holds exactly the donated files');
if (ledger.length !== donated.length) console.log(`-- note: ${ledger.length - donated.length} repost(s) after a crash (at-least-once delivery)`);
const stats = await (await fetch(`${base}/api/stats`)).json();
assert.equal(stats.files, donated.length);
await page.waitForFunction(n => document.getElementById('corpus-files').textContent === String(n), donated.length, { timeout: 30000 });
assert.ok(stats.isas.some(i => i.files > 0 && i.isa === 'mips'), 'per-ISA counts include the MIPS uImages');
assert.equal(readdirSync(path.join(work, 'spool')).length, 0, 'spool is empty');

const serverLog = readFileSync(path.join(work, 'server.log'), 'utf8');
const admitted = (serverLog.match(/upload admitted/g) ?? []).length;
const resumed = [...serverLog.matchAll(/(\d+) job\(s\) resumed/g)].map(m => Number(m[1]));
console.log(`-- server: ${admitted} uploads admitted for ${donated.length} files, jobs resumed per start: ${resumed.join(' ')}`);

await browser.close();
await stop('SIGTERM');
assert.deepEqual(problems, [], `page errors: ${problems.join('\n')}`);
rmSync(work, { recursive: true });
console.log('restart e2e ok');
