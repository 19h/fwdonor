// The dashboard pages in a real browser, against a dry-run server this test
// starts with generated data (a ledger, store records and files, one bulk
// upload): the tree filters the table, facets include and exclude, sorting,
// a histogram brush, the detail drawer with its entropy chart and hex, keys,
// the URL hash restoring the view after a reload, and the bulk tab.
//
//   PLAYWRIGHT=/path/to/node_modules/playwright/index.mjs \
//     node tests/dashboard.browser.e2e.mjs <fwdonor binary> [screenshot dir] [port]
//
// Run scripts/build.sh first (the pages come from dist/).
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, openSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const [serverBin, shots, port = '18094'] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = data => createHash('sha256').update(data).digest('hex');

// ---- data: 400 posts, 150 of them in the store
const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-dash-browser-'));
mkdirSync(path.join(work, 'runtime'));
mkdirSync(path.join(work, 'firmwares'));
const ISAS = [['arm', 'ARM (32-bit)', 32], ['a_arch64', 'AArch64 (ARM64)', 64], ['i8051', 'Intel 8051', 8], ['mcs96', 'Intel MCS-96', 16],
  ['c166', 'Infineon C166', 16], ['tricore', 'Infineon TriCore', 32], ['mips', 'MIPS (32-bit)', 32]];
const DONORS = ['anonymous', 'anonymous', 'anonymous', 'bang1338', 'theubusu'];
const ledger = [];
const t0 = 1793646600;
for (let n = 0; n < 400; n++) {
  const isa = ISAS[n % ISAS.length];
  const format = n % 5 === 0 ? 'elf' : 'raw';
  const stored = n % 8 < 3;
  const data = Buffer.concat([randomBytes(512 + n * 37), Buffer.alloc(256 + n * 11), Buffer.from(`firmware build ${n} version 1.${n % 7}\0`)]);
  const entry = {
    sha256: stored ? sha(data) : sha(Buffer.from(`ledger-only-${n}`)), name: `fw_${String(n).padStart(3, '0')}.${format === 'elf' ? 'elf' : 'bin'}`,
    size: stored ? data.length : 4096 * (n + 1), username: DONORS[n % DONORS.length], format, isa: isa[0], isas: [isa[0]],
    message_id: (n + 2) * 2 ** 20, posted_at: t0 + n * 150,
  };
  ledger.push(entry);
  if (!stored) continue;
  writeFileSync(path.join(work, 'firmwares', entry.sha256), data);
  writeFileSync(path.join(work, 'firmwares', `${entry.sha256}.json`), JSON.stringify({
    sha256: entry.sha256, size: entry.size, name: entry.username, original_name: entry.name, received_at: entry.posted_at, source: 'telegram',
    telegram: { chat_id: -1003917356862, message_id: entry.message_id, posted_at: entry.posted_at },
    zrax: {
      format, format_name: format === 'elf' ? 'ELF' : 'Raw binary', format_variant: null, isa: isa[0], isa_name: isa[1], isa_tag: isa[0],
      bitwidth: isa[2], endianness: 'little', confidence: 0.5 + (n % 50) / 100, source: 'heuristic', variant: null,
      slices: format === 'elf' ? [{ label: 'Segment 0', isa: isa[0], isa_name: isa[1], bitwidth: isa[2], offset: 0, size: 512 }] : [],
      metadata: [{ label: 'Entry Point', value: `0x${(n * 4096).toString(16)}` }], basis: 'isa', zrax: '0.1.0@ea12aed',
    },
  }));
}
// Other binaries people donate (known from the ledger only, so by name).
for (const [n, name, format] of [[400, 'libcamera_3.so', 'elf'], [401, 'libaudio.so.1', 'elf'], [402, 'setup.exe', 'pe']]) {
  ledger.push({
    sha256: sha(Buffer.from(`other-${n}`)), name, size: 2000 + n, username: 'bang1338', format, isa: 'a_arch64', isas: ['a_arch64'],
    message_id: (n + 2) * 2 ** 20, posted_at: t0 + n * 150,
  });
}
writeFileSync(path.join(work, 'runtime', 'posted.jsonl'), ledger.map(e => JSON.stringify(e)).join('\n') + '\n');
writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[bulk]
dir = "${path.join(work, 'bulk')}"
chunk_bytes = 1048576
min_free_bytes = 0

[pow]
bits = 16

[telegram]
dry_run = true
`);

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
const key = readFileSync(path.join(work, 'runtime', 'dashboard.key'), 'utf8').trim();
const admin = readFileSync(path.join(work, 'runtime', 'admin.key'), 'utf8').trim();
const api = async q => (await fetch(`${base}/api/dash/${key}${q}`)).json();

// One bulk file.
const grant = await (await fetch(`${base}/api/admin/${admin}/grants`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Sonic', ceiling_bytes: 1e9 }),
})).json();
const bulkData = randomBytes(1500 * 1024);
const up = await (await fetch(`${base}/api/bulk/${grant.token}/uploads`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'nand.bin', path: 'phone/nand.bin', size: bulkData.length }),
})).json();
for (let i = 0; i < up.chunks; i++) {
  const c = bulkData.subarray(i * 1048576, (i + 1) * 1048576);
  await fetch(`${base}/api/bulk/${grant.token}/uploads/${up.id}/${i}`, { method: 'PUT', headers: { 'x-chunk-sha256': sha(c) }, body: c });
}

console.log('-- data ready, starting the browser');
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
const errors = [];
page.on('pageerror', e => errors.push(String(e)));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
const shot = async name => shots && page.screenshot({ path: path.join(shots, `dash-${name}.png`) });
const total = async () => Number((await page.textContent('#count')).replace(/,/g, ''));
const waitTotal = async n => page.waitForFunction(x => Number(document.getElementById('count').textContent.replace(/,/g, '')) === x, n);

await page.goto(`${base}/d/${key}`);
await page.waitForSelector('#files-rows tr[data-sha]');
assert.equal(await total(), 400);
assert.equal(await page.locator('#files-rows tr[data-sha]').count(), 100);
await shot('1-overview');
// Live updates (tested in dashboard.e2e.mjs) would redraw under the clicks.
await page.click('#live');
assert.equal(await page.locator('#live.on').count(), 0);

console.log('-- overview');
// The tree: Infineon → C166 and TriCore.
const infineon = page.locator('#tree > li > .node', { hasText: 'Infineon' });
const infineonCount = Number((await infineon.locator('.n').textContent()).replace(/,/g, ''));
assert.equal(infineonCount, (await api('/query?family=infineon&limit=1')).total);
await infineon.click();
await waitTotal(infineonCount);
assert.match(await page.textContent('#chips'), /family: Infineon/);
assert.match(page.url(), /family=infineon/);
assert.equal(await page.locator('#tree li.on > ul > li').count(), 2, 'the selected family opens');
await page.locator('#tree li.on > ul > li > .node', { hasText: 'TriCore' }).click();
await waitTotal((await api('/query?isa=tricore&limit=1')).total);
await page.locator('#tree li.on > ul > li.on > .node').click(); // again: cleared
await waitTotal(400);

// A format under one ISA is that node only, not the same format under every ISA.
const intel = page.locator('#tree > li > .node', { hasText: 'Intel MCS' });
await intel.click();
await page.waitForFunction(() => location.hash.includes('family=mcs'));
for (const label of ['Intel 8051', 'Intel MCS-96']) {
  await page.locator('#tree > li.on > ul > li > .node', { hasText: label }).locator('.twisty').click();
}
const isaLi = page.locator('#tree > li.on > ul > li').filter({ has: page.locator('.node', { hasText: 'Intel 8051' }) });
const rawNode = isaLi.locator('ul > li > .node', { hasText: 'Raw' });
const rawCount = Number((await rawNode.locator('.n').textContent()).replace(/,/g, ''));
await rawNode.click();
await waitTotal(rawCount);
assert.equal(rawCount, (await api('/query?family=mcs&isa=i8051&format=raw&limit=1')).total);
assert.equal(await page.locator('#tree li.on').count(), 3, 'family, ISA and format: one path');
assert.equal(await page.locator('#tree li.on > .node .lbl', { hasText: 'Raw' }).count(), 1, 'one Raw lit, not every Raw');
assert.equal(await page.locator('#tree > li.on > ul > li.on > .node', { hasText: 'Intel MCS-96' }).count(), 0, 'the sibling ISA is not selected');
assert.equal(await page.locator('#tree > li.on > ul > li .node .lbl', { hasText: 'Raw' }).count(), 2, 'the other Raw is still shown');
assert.match(await page.textContent('#crumbs'), /ISA: Intel 8051.*format: Raw/s);
await shot('1b-tree-path');
await rawNode.click(); // again: cleared
await waitTotal(400);

// Firmware first; the other binaries are one click away.
assert.match(await page.textContent('#scope button.on'), /^firmware 400$/);
assert.match(await page.textContent('#scope'), /other binaries 3.*all 403/s);
await page.click('#scope [data-scope="other"]');
await waitTotal(3);
assert.match(page.url(), /kind=%21firmware/);
assert.match(await page.textContent('#files-rows'), /libcamera_3\.so/);
assert.match(await page.textContent('#facets'), /shared library/);
await shot('1c-other-binaries');
await page.click('#scope [data-scope="all"]');
await waitTotal(403);
assert.match(page.url(), /kind=all/);
await page.reload();
await page.waitForSelector('#files-rows tr[data-sha]');
await waitTotal(403);
assert.match(await page.textContent('#scope button.on'), /^all/);
await page.click('#live'); // the reload turned it back on
await page.click('#scope [data-scope="firmware"]');
await waitTotal(400);
assert.ok(!page.url().includes('kind='), 'firmware is the default view');

console.log('-- tree');
// Facets: alt-click leaves a value out.
const anon = (await api('/query?donor=anonymous&limit=1')).total;
await page.locator('#facets li[data-dim="donor"][data-key="anonymous"]').click({ modifiers: ['Alt'] });
await waitTotal(400 - anon);
assert.match(await page.textContent('#chips'), /donor ≠ anonymous/);

console.log('-- facets');
// Sorting: size, largest first; then by name.
await page.click('#files-head th[data-sort="size"]');
await page.waitForFunction(() => location.hash.includes('sort=size%3Adesc'));
const largest = (await api('/query?donor=!anonymous&sort=size:desc&limit=1')).rows[0].sha256;
await page.waitForFunction(s => document.querySelector('#files-rows tr[data-sha]')?.dataset.sha === s, largest);

console.log('-- sorting');
// A brush across the size chart.
// A new table can change the page's scrollbar and so the charts' width, which
// redraws them: drag once they have been quiet for a moment.
const settled = sel => page.evaluate(selector => new Promise(resolve => {
  let timer;
  const observer = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(done, 500); });
  function done() { observer.disconnect(); resolve(); }
  observer.observe(document.querySelector(selector), { childList: true, subtree: true });
  timer = setTimeout(done, 500);
}), sel);
await page.evaluate(() => document.getElementById('h-size').scrollIntoView({ block: 'center' }));
await settled('#h-size');
const sizeChart = page.locator('#h-size svg');
const chartBox = await sizeChart.boundingBox();
await sizeChart.hover({ position: { x: 2, y: chartBox.height / 2 } });
await page.mouse.down();
await sizeChart.hover({ position: { x: chartBox.width * 0.45, y: chartBox.height / 2 } });
await page.mouse.up();
await page.waitForFunction(() => location.hash.includes('size='));
await page.waitForFunction(() => document.getElementById('chips').textContent.includes('size '));
const brushed = await total();
assert.ok(brushed > 0 && brushed < 400 - anon, `brush narrows (${brushed})`);
await shot('2-filtered');

console.log('-- brush');
// The detail drawer: entropy, hex, strings; ] moves on; the hash keeps it.
await page.locator('#facets li[data-dim="status"][data-key="stored"]').click();
await page.waitForFunction(() => document.getElementById('chips').textContent.includes('status: stored'));
await page.waitForSelector('#files-rows tr[data-sha]');
const first = await page.locator('#files-rows tr[data-sha]').first().getAttribute('data-sha');
await page.locator('#files-rows tr[data-sha] td.c-name').first().click();
await page.waitForSelector('#d-inspect svg.entropy');
await page.waitForSelector('#d-hex pre.hexdump');
assert.match(await page.textContent('#d-strings'), /firmware build \d+ version/);
assert.match(await page.textContent('#d-body'), /kind\s*firmware/);
assert.match(page.url(), new RegExp(`open=${first}`));
const name1 = await page.textContent('#d-name');
await shot('3-drawer');
await page.keyboard.press(']');
await page.waitForFunction(n => document.getElementById('d-name').textContent !== n && document.getElementById('d-name').textContent !== 'loading…', name1);
const opened = new URL(page.url()).hash.match(/open=([0-9a-f]{64})/)[1];
assert.notEqual(opened, first);

console.log('-- drawer');
// Reload: filters, sort and the open file come back.
const chipsBefore = await page.textContent('#chips');
await page.reload();
await page.waitForSelector('#d-inspect svg.entropy');
await page.waitForSelector('#files-rows tr[data-sha]');
assert.equal(await page.textContent('#chips'), chipsBefore);
assert.equal(await page.locator('#files-rows tr.opened').getAttribute('data-sha'), opened);
await page.keyboard.press('Escape');
assert.equal(await page.isHidden('#drawer'), true);
assert.ok(!page.url().includes('open='));

console.log('-- reload');
// Keys: / searches.
await page.keyboard.press('/');
await page.keyboard.type('fw_007');
await page.waitForFunction(() => document.getElementById('count').textContent !== '');
await page.click('#chips .chip.clear');
await page.fill('#search', 'fw_007');
await waitTotal(1);

console.log('-- search');
// The bulk tab.
await page.click('.tabs a[data-tab="bulk"]');
await page.waitForSelector('#file-rows tr');
assert.match(await page.textContent('#grant-rows'), /Sonic/);
assert.match(await page.textContent('#file-rows'), /nand\.bin/);
assert.match(await page.textContent('#tree'), /phone/);
await shot('4-bulk');

// The public dashboard, from the donation page's link: no key, no bulk, no
// origin or status, no operational panels; downloads after a proof of work.
console.log('-- public');
await page.goto(base);
await page.click('header a[href="/dashboard"]');
await page.waitForURL(`${base}/dashboard`);
await page.waitForSelector('#files-rows tr[data-sha]');
assert.equal(await total(), 400);
assert.equal(await page.isHidden('nav.tabs'), true, 'no bulk tab');
assert.equal(await page.isVisible('.donate-link'), true);
assert.equal(await page.isHidden('#arriving-panel'), true);
for (const id of ['s-stored', 's-backfill', 's-queue', 's-disk']) assert.equal(await page.isHidden(`#${id}`), true, id);
assert.equal(await page.locator('#facets li[data-dim="origin"], #facets li[data-dim="status"]').count(), 0, 'no origin or status facet');
assert.equal(await page.locator('#columns [data-col="origin"], #columns [data-col="status"]').count(), 0);
assert.equal(await page.locator('#tree-levels option[value="origin"]').count(), 0);
assert.equal(await page.isHidden('#x-rsync'), true);
await shot('5-public');
await page.fill('#search', 'fw_016');
await waitTotal(1);
await page.locator('#files-rows tr[data-sha] td.c-name').first().click();
await page.waitForSelector('#d-inspect svg.entropy');
assert.ok(!(await page.textContent('#d-body')).includes(work), 'no server paths');
const wanted = ledger.find(e => e.name === 'fw_016.bin');
const [download] = await Promise.all([page.waitForEvent('download', { timeout: 60000 }), page.click('#d-body [data-download]')]);
assert.equal(download.suggestedFilename(), 'fw_016.bin');
const saved = path.join(work, 'downloaded.bin');
await download.saveAs(saved);
assert.equal(sha(readFileSync(saved)), wanted.sha256, 'the file, after the proof of work');
await shot('6-public-drawer');
assert.deepEqual(errors, [], 'no page errors');
await browser.close();
server.kill('SIGTERM');
console.log('dashboard browser e2e ok');
process.exit(0);
