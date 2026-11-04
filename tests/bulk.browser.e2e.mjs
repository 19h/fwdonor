// The bulk pages in a real browser, against a server this test starts: issue a
// link on the admin page, upload a large file on the link's page, close the
// tab in the middle, open the link again, drop the file again, and check that
// it continues and is stored intact.
//
//   PLAYWRIGHT=/path/to/node_modules/playwright/index.mjs \
//     node tests/bulk.browser.e2e.mjs <fwdonor binary> [screenshot dir] [port]
//
// Run scripts/build.sh first (the pages come from dist/).
import { mkdtempSync, readFileSync, writeFileSync, openSync, writeSync, closeSync, existsSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const [serverBin, shots, port = '18097'] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-bulk-browser-'));
const store = path.join(work, 'bulk');
writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[bulk]
dir = "${store}"
min_free_bytes = 0

[telegram]
dry_run = true
`);

// A 600 MB file of random data (75 chunks of 8 MiB), hashed as it is written.
const file = path.join(work, 'firmware-dump.img');
const hash = createHash('sha256');
const fd = openSync(file, 'w');
for (let i = 0; i < 60; i++) {
  const block = randomBytes(10_000_000);
  hash.update(block);
  writeSync(fd, block);
}
closeSync(fd);
const fileSha = hash.digest('hex');
const fileSize = 600_000_000;

const log = openSync(path.join(work, 'server.log'), 'a');
const server = spawn(serverBin, ['--config', path.join(work, 'fwdonor.toml'), 'serve'], { stdio: ['ignore', log, log] });
process.on('exit', () => server.kill('SIGKILL'));
for (let i = 0; ; i++) {
  try {
    if ((await fetch(`${base}/api/health`)).ok) break;
  } catch {}
  if (i > 100) throw new Error('server did not come up');
  await sleep(100);
}
const key = readFileSync(path.join(work, 'runtime', 'admin.key'), 'utf8').trim();

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
const errors = [];
async function openPage() {
  const p = await context.newPage();
  p.on('pageerror', e => errors.push(e.message));
  p.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  p.on('dialog', d => d.accept());
  return p;
}
let page = await openPage();

// ---- admin page: issue a link
await page.goto(`${base}/g/${key}`);
await page.fill('#g-name', 'Sonic');
await page.fill('#g-amount', '2');
await page.fill('#g-note', 'browser test');
await page.click('#g-submit');
await page.waitForSelector('#grant-result:not([hidden])');
const link = await page.textContent('#r-url');
assert.match(link, new RegExp(`^${base}/r/[A-Za-z0-9_-]{22}$`));
await page.waitForFunction(() => document.querySelectorAll('#grant-rows tr').length === 1);
assert.match(await page.textContent('#grant-rows'), /Sonic.*browser test.*2 GB/s);
if (shots) await page.screenshot({ path: path.join(shots, 'bulk-admin.png'), fullPage: true });

// ---- the link's page
await page.goto(link);
await page.waitForFunction(() => document.querySelector('#donor').value === 'Sonic');
assert.ok(await page.isDisabled('#donor'), 'donor name is fixed');
assert.equal(await page.$('#corpus'), null, 'no corpus statistics');
assert.match(await page.textContent('#quota'), /2\.00 GB in total/);

await page.setInputFiles('#fileinput', file);
await page.waitForFunction(() => /uploading/.test(document.querySelector('#rows').textContent));
// Let it get a good way in, then close the tab in the middle of the transfer.
// (Locally the whole file takes seconds: close right away, screenshots later.)
await page.waitForFunction(() => parseFloat(document.querySelector('#t-pct').textContent) >= 30, null, { polling: 20, timeout: 120000 });
const before = await page.textContent('#t-pct');
// Close the tab mid-transfer (as if the browser quit) and open the link again.
await page.close({ runBeforeUnload: false });
page = await openPage();
await page.goto(link);
await page.waitForFunction(() => document.querySelector('#donor').value === 'Sonic');
await page.waitForSelector('#unfinished:not([hidden])');
assert.match(await page.textContent('#unfinished-rows'), /firmware-dump\.img/);
const quota = await page.textContent('#quota-reserved');
assert.equal(quota.trim(), '600 MB', 'the unfinished upload is reserved');
if (shots) await page.screenshot({ path: path.join(shots, 'bulk-unfinished.png'), fullPage: true });

// Drop it again: it continues.
await page.setInputFiles('#fileinput', file);
await page.waitForFunction(() => /uploading/.test(document.querySelector('#rows .label')?.textContent ?? ''));
if (shots) await page.screenshot({ path: path.join(shots, 'bulk-uploading.png'), fullPage: true });
await page.waitForFunction(() => /stored/.test(document.querySelector('#rows .label')?.textContent ?? ''), null, { timeout: 180000 });
const activity = await page.textContent('#log');
assert.match(activity, /continuing the unfinished upload at \d/, 'resumed, not restarted');
const sent = await page.textContent('#streams');
const sessionBytes = parseFloat(sent.match(/([\d.]+) MB sent this session/)?.[1] ?? 'NaN') * 1e6;
assert.ok(sessionBytes < fileSize * 0.75, `only the rest was sent after reopening (${sent})`);
const shown = await page.textContent('#rows .sha');
assert.equal(shown, fileSha, 'page shows the stored hash');
assert.ok(existsSync(path.join(store, fileSha)), 'stored under its hash');
const record = JSON.parse(readFileSync(path.join(store, `${fileSha}.json`), 'utf8'));
assert.deepEqual([record.name, record.original_name, record.size], ['Sonic', 'firmware-dump.img', fileSize]);
await page.waitForFunction(() => /600 MB/.test(document.querySelector('#quota-used').textContent), null, { timeout: 15000 });
await page.waitForSelector('#unfinished[hidden]', { state: 'attached' });
if (shots) await page.screenshot({ path: path.join(shots, 'bulk-done.png'), fullPage: true });
assert.deepEqual(errors, [], 'no page errors');
console.log(`-- tab closed at ${before}, reopened, resumed, stored ${fileSha.slice(0, 16)}…`);

await browser.close();
server.kill('SIGTERM');
rmSync(work, { recursive: true });
console.log('bulk browser e2e ok');
