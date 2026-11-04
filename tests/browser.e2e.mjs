// End-to-end test of the real page against a running (dry-run) server.
//
//   PLAYWRIGHT=/path/to/node_modules/playwright/index.mjs \
//   node tests/browser.e2e.mjs http://127.0.0.1:18090 <dir-with-files> <expected.json>
//
// expected.json maps file names to "donated" | "skipped" | "already in the collection".
import { readFileSync, readdirSync, mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
const [base, dir, expectedPath] = process.argv.slice(2);
const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
const files = readdirSync(dir).filter(f => f in expected).map(f => path.join(dir, f));

const browser = await chromium.launch();
const page = await browser.newPage();
const problems = [];
page.on('console', msg => {
  // The duplicate check answers 409 by design; Chrome logs it as a failed load.
  if (msg.type() === 'error' && !msg.text().includes('status of 409')) problems.push(msg.text());
});
page.on('pageerror', err => problems.push(String(err)));

await page.goto(base);
await page.waitForFunction(() => document.getElementById('engine').textContent.startsWith('engine'), null, { timeout: 30000 });
await page.fill('#donor', 'e2e tester!');
assert.equal(await page.inputValue('#donor'), 'e2etester', 'donor name is sanitized as typed');

async function dropAndWait(paths) {
  await page.setInputFiles('#fileinput', paths);
  await page.waitForSelector('#thanks:not([hidden])', { timeout: 180000 });
  return page.$$eval('#rows tr', trs => trs.map(tr => ({
    name: tr.querySelector('.name').textContent,
    state: tr.querySelector('.state span').textContent,
    detail: tr.querySelector('.state small')?.textContent ?? '',
    cls: tr.className,
  })));
}

const rows = await dropAndWait(files);
for (const row of rows) console.log(`${row.state.padEnd(28)} ${row.name}  ${row.detail}`);
for (const row of rows) assert.equal(row.state, expected[row.name], `${row.name}: ${row.state} (${row.detail})`);
console.log('thanks:', (await page.textContent('#thanks')).replace(/\s+/g, ' '));

// Dropping a donated file again is recognized before any upload, with the
// date it was donated; a renamed copy in the same drop is skipped locally.
await page.click('#clear');
const donated = files.find(f => expected[path.basename(f)] === 'donated');
const copyDir = mkdtempSync(path.join(tmpdir(), 'fwdonor-e2e-'));
const copy = path.join(copyDir, `copy of ${path.basename(donated)}`);
copyFileSync(donated, copy);
const again = await dropAndWait([donated, copy]);
for (const row of again) console.log(`${row.state.padEnd(28)} ${row.name}  ${row.detail}`);
assert.equal(again[0].state, 'already in the collection');
assert.match(again[0].detail, /^donated on \d{4}-\d{2}-\d{2}$/);
assert.equal(again[1].state, 'duplicate in this drop');
assert.match(await page.textContent('#thanks'), /already in the collection, so it was not uploaded again/);
rmSync(copyDir, { recursive: true });

// The donor name persists across reloads.
await page.reload();
assert.equal(await page.inputValue('#donor'), 'e2etester');

await browser.close();
assert.deepEqual(problems, [], `console errors: ${problems.join('\n')}`);
console.log('browser e2e ok');
