// The firmware dashboard against a dry-run server this test starts: images
// donated with fwdonate plus ledger entries that never reached the store,
// bulk uploads (one stored, one unfinished), the query API (filters, facets,
// tree, matrix, sorting, paging), details, inspection, downloads with Range,
// exports, live updates, a restart, and that no response ever carries an
// address, a grant token, a grant note or the admin key.
//
//   node tests/dashboard.e2e.mjs <fwdonor binary> <fwdonate binary> <dir-with-files> [port]
//
// <dir-with-files> as for tests/client.e2e.mjs. Run scripts/build.sh first.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, openSync, readdirSync, copyFileSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const [serverBin, clientBin, dir, port = '18096'] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = data => createHash('sha256').update(data).digest('hex');
const MiB = 1024 * 1024;

const work = mkdtempSync(path.join(tmpdir(), 'fwdonor-dash-e2e-'));
const donate = path.join(work, 'donate');
const donated = new Map(); // sha256 → file path
const put = (rel, data) => {
  const file = path.join(donate, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, data);
  donated.set(sha(data), file);
  return file;
};
const elf = readFileSync(path.join(dir, 'aarch64-tool.elf'));
for (let i = 0; i < 6; i++) put(`elves/tool-${i}.elf`, Buffer.concat([elf, randomBytes(40 + i)]));

// A minimal AArch64 ELF64 (type 2 or 3) whose one load segment carries
// `payload`, with PT_INTERP (a program) or PT_DYNAMIC + DT_NEEDED (a library).
function makeElf({ etype, interp, needed }, payload) {
  const data = Buffer.alloc(0x200);
  const phdrs = [];
  if (interp) {
    data.write(`${interp}\0`, 0);
    phdrs.push([3, 0x200, interp.length + 1]);
  }
  if (needed) {
    const strtab = 0x200 + 0x40;
    [[1n, 1n], [5n, BigInt(strtab)], [0n, 0n]].forEach(([tag, val], i) => {
      data.writeBigUInt64LE(tag, i * 16);
      data.writeBigUInt64LE(val, i * 16 + 8);
    });
    data.write(`\0${needed}\0`, 0x40);
    phdrs.push([2, 0x200, 48]);
  }
  phdrs.unshift([1, 0, 0x400 + payload.length]);
  const head = Buffer.alloc(0x200);
  head.write('\x7fELF', 0, 'latin1');
  head[4] = 2;
  head[5] = 1;
  head[6] = 1;
  head.writeUInt16LE(etype, 16);
  head.writeUInt16LE(183, 18);
  head.writeUInt32LE(1, 20);
  head.writeBigUInt64LE(0x400n, 24);
  head.writeBigUInt64LE(64n, 32);
  head.writeUInt16LE(64, 52);
  head.writeUInt16LE(56, 54);
  head.writeUInt16LE(phdrs.length, 56);
  phdrs.forEach(([type, off, size], i) => {
    const at = 64 + i * 56;
    head.writeUInt32LE(type, at);
    head.writeUInt32LE(type === 1 ? 5 : 4, at + 4);
    for (const field of [8, 16, 24]) head.writeBigUInt64LE(BigInt(off), at + field);
    for (const field of [32, 40]) head.writeBigUInt64LE(BigInt(size), at + field);
  });
  return Buffer.concat([head, data, payload]);
}
// Not firmware, but welcome: a shared library and a program (the six tool
// ELFs are relocatable objects).
const libDemo = put('apps/libdemo.so', makeElf({ etype: 3, needed: 'libc.so' }, elf));
const demoTool = put('apps/demo-tool', makeElf({ etype: 2, interp: '/lib/ld-linux-aarch64.so.1' }, elf));
for (const f of ['mips_gzip.uimage', 'image.trx', 'krnl.im4p', 'sample.fd']) {
  mkdirSync(path.join(donate, 'misc'), { recursive: true });
  copyFileSync(path.join(dir, f), path.join(donate, 'misc', f));
  donated.set(sha(readFileSync(path.join(dir, f))), path.join(donate, 'misc', f));
}
writeFileSync(path.join(donate, 'misc', 'noise.bin'), randomBytes(6000)); // not firmware

// What zrax finds in each donated file: the ISA counts the index must show.
const verdicts = execFileSync(serverBin, ['check', '--json', ...donated.values()], { encoding: 'utf8' })
  .trim().split('\n').map(l => JSON.parse(l).result);
const isaSets = verdicts.map(v => new Set([v.isa, ...v.slices.map(s => s.isa)].filter(Boolean)));
const anyIsa = isa => isaSets.filter(set => set.has(isa)).length;
const primaryIsa = isa => verdicts.filter(v => v.isa === isa).length;

// Posts from before the firmware store: two in the old basic group (ids
// start again in the supergroup), one in the supergroup.
mkdirSync(path.join(work, 'runtime'), { recursive: true });
const legacy = [
  { sha256: sha(Buffer.from('old-1')), name: 'bios_v1.rom', size: 65536, username: 'oldtimer', format: 'raw', isa: 'mcs96', message_id: 5 << 20, posted_at: 1793646000 },
  { sha256: sha(Buffer.from('old-2')), name: 'ecu.bin', size: 262144, username: 'anonymous', format: 'raw', isa: 'c166', message_id: 6 << 20, posted_at: 1793646100 },
  { sha256: sha(Buffer.from('old-3')), name: 'ecu.bin', size: 131072, username: 'oldtimer', format: 'elf', isa: 'tricore', isas: ['tricore', 'arm'], message_id: 2 << 20, posted_at: 1793650000 },
];
writeFileSync(path.join(work, 'runtime', 'posted.jsonl'), legacy.map(e => JSON.stringify(e)).join('\n') + '\n');

writeFileSync(path.join(work, 'fwdonor.toml'), `bind = "127.0.0.1:${port}"
dist_dir = "${path.resolve('dist')}"
runtime_dir = "${path.join(work, 'runtime')}"
spool_dir = "${path.join(work, 'spool')}"
firmware_dir = "${path.join(work, 'firmwares')}"

[bulk]
dir = "${path.join(work, 'bulk')}"
chunk_bytes = ${MiB}
min_free_bytes = 0

[pow]
bits = 12

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

async function stop() {
  const exited = new Promise(resolve => server.once('exit', resolve));
  server.kill('SIGTERM');
  await exited;
}

function runClient(args) {
  const child = spawn(clientBin, ['--server', base, '-n', 'dash_e2e', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', d => { out += d; });
  child.stderr.on('data', d => { out += d; });
  return new Promise(resolve => child.once('exit', code => resolve({ code, out })));
}

// Every dashboard answer is kept for the privacy check at the end.
const seen = [];
async function dash(pathAndQuery, { expect = 200, raw = false, headers = {} } = {}) {
  const res = await fetch(`${base}/api/dash/${key}${pathAndQuery}`, { headers });
  const body = Buffer.from(await res.arrayBuffer());
  if (!pathAndQuery.includes('/download')) seen.push({ url: pathAndQuery, text: body.toString('utf8') });
  assert.equal(res.status, expect, `${pathAndQuery}: ${res.status} ${body.toString().slice(0, 300)}`);
  return raw ? { res, body } : JSON.parse(body.toString());
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

try {
  await fetch(`${base}/api/health`);
  throw new Error(`something is already listening on port ${port}`);
} catch (e) {
  if (e.message.includes('already listening')) throw e;
}
await start();
const key = readFileSync(path.join(work, 'runtime', 'dashboard.key'), 'utf8').trim();
const adminKey = readFileSync(path.join(work, 'runtime', 'admin.key'), 'utf8').trim();
assert.equal(key.length, 43);
assert.notEqual(key, adminKey, 'the dashboard has its own key');

// ---- pages and keys
for (const bad of ['x'.repeat(43), adminKey]) {
  assert.equal((await fetch(`${base}/d/${bad}`)).status, 404, 'wrong key: no page');
  assert.equal((await fetch(`${base}/api/dash/${bad}/summary`)).status, 404, 'wrong key: no API');
}
assert.equal((await fetch(`${base}/g/${key}`)).status, 404, 'the dashboard key is not the admin key');
for (const [url, script] of [[`/d/${key}`, 'dash.js'], [`/d/${key}/bulk`, 'dash-bulk.js']]) {
  const res = await fetch(`${base}${url}`);
  assert.equal(res.status, 200, url);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.match(res.headers.get('x-robots-tag'), /noindex/);
  const html = await res.text();
  assert.ok(html.includes(script), `${url} is the built page`);
  assert.ok(!html.includes(adminKey));
}

// ---- donations
const run = await runClient([donate]);
assert.equal(run.code, 0, run.out);
const expected = donated.size + legacy.length;
const summary = await waitFor('the donations in the index', async () => {
  const s = await dash('/summary');
  return s.ready && s.files === expected && s.queued === 0 && s.stored.files === donated.size ? s : null;
});
assert.equal(summary.pending.files, legacy.length);
assert.equal(summary.backfill.state, 'off', 'no Telegram, no backfill');
assert.equal(summary.named_donors, 2);
assert.ok(summary.wanted.length > 20 && !summary.wanted.some(w => w.isa === 'a_arch64'));
assert.equal(summary.ledger, expected);
assert.ok(Array.isArray(summary.arriving));
console.log(`-- ${donated.size} donated, ${legacy.length} known from the ledger only`);

// ---- queries
const all = await dash('/query?facets=1&tree=family,isa,format&matrix=isa,format');
assert.equal(all.total, expected);
const times = all.rows.map(r => r.received_at);
assert.deepEqual(times, [...times].sort((a, b) => b - a), 'newest first');
const donors = Object.fromEntries(all.facets.donor.values.map(v => [v.key, v.files]));
assert.deepEqual(donors, { dash_e2e: donated.size, oldtimer: 2, anonymous: 1 });
const arm = all.tree.nodes.find(n => n.key === 'arm');
assert.ok(arm, 'an ARM family node');
const a64 = arm.children.find(n => n.key === 'a_arch64');
assert.equal(a64.files, anyIsa('a_arch64'), 'every file with AArch64 code');
assert.equal(a64.children.find(n => n.key === 'elf').files, 8, 'the eight AArch64 ELFs');
assert.ok(all.tree.nodes.find(n => n.key === 'infineon').files >= 2, 'C166 and TriCore');
assert.ok(all.matrix.rows.length >= 4 && all.matrix.cols.some(c => c.key === 'elf'));
assert.ok(all.hist.size.length && all.hist.time.buckets.length && all.hist.conf.length === 10);

const count = async q => (await dash(`/query?${q}`)).total;
const tool0Sha = () => [...donated].find(([, f]) => f.endsWith('tool-0.elf'))[0];
assert.equal(await count('isa=a_arch64'), anyIsa('a_arch64'));
assert.equal(await count('isa=a_arch64&isa_mode=primary'), primaryIsa('a_arch64'));
assert.equal(await count('isa=!a_arch64'), expected - anyIsa('a_arch64'));
assert.equal(await count('isa=arm') - await count('isa=arm&isa_mode=primary'), 1, 'the TriCore image with an ARM slice');
assert.equal(await count('origin=ledger'), 3);
assert.equal(await count('status=pending'), 3);
assert.equal(await count('status=stored'), donated.size);
assert.equal(await count('donor=oldtimer,anonymous'), 3);
assert.equal(await count('donor=!dash_e2e&format=elf'), 1);
assert.equal(await count('multi=1'), 1 + isaSets.filter(set => set.size > 1).length);
assert.equal(await count('ext=elf'), 6);
assert.equal(await count('ext=so'), 1);
assert.equal(await count('q=ecu.bin'), 2);
assert.equal(await count(`q=${legacy[0].sha256.slice(0, 10)}`), 1, 'sha prefix');
assert.equal(await count('size=..70000&origin=ledger'), 1);
assert.equal(await count(`time=..${1793647000}`), 2);

// Kinds: firmware, or the other binaries (decided from the files' headers).
const kinds = Object.fromEntries(all.facets.kind.values.map(v => [v.key, v.files]));
assert.deepEqual(kinds, { firmware: expected - 8, object: 6, library: 1, program: 1 });
assert.equal(await count('kind=firmware'), expected - 8);
assert.equal(await count('kind=!firmware'), 8);
assert.equal(await count('kind=library,program'), 2);
const libRow = (await dash('/query?kind=library')).rows[0];
assert.deepEqual([libRow.name, libRow.kind], ['libdemo.so', 'library']);
assert.deepEqual((await dash(`/files/${libRow.sha256}`)).kind, { key: 'library', label: 'shared library', why: 'ELF shared object, needs libc.so' });
assert.equal((await dash(`/files/${sha(readFileSync(demoTool))}`)).kind.why, 'ELF, interpreter /lib/ld-linux-aarch64.so.1');
assert.equal((await dash(`/files/${tool0Sha()}`)).kind.why, 'relocatable ELF');
assert.equal((await dash(`/files/${legacy[2].sha256}`)).kind.key, 'firmware', 'ledger only: by its name');
assert.deepEqual((await dash('/summary')).kinds, { firmware: expected - 8, program: 1, library: 1, object: 6, package: 0 });
const kindTree = await dash('/query?tree=kind,isa');
assert.deepEqual(kindTree.tree.nodes.map(n => n.key), ['firmware', 'object', 'program', 'library']);

const facetsUnderFilter = await dash('/query?donor=oldtimer&facets=1');
assert.equal(facetsUnderFilter.facets.donor.values.length, 3, 'a facet ignores its own filter');
assert.equal(facetsUnderFilter.facets.donor.values.find(v => v.key === 'oldtimer').sel, 'in');
assert.deepEqual(facetsUnderFilter.facets.format.values.map(v => v.key).sort(), ['elf', 'raw']);

const bySize = await dash('/query?sort=size:desc&limit=4');
const sizes = bySize.rows.map(r => r.size);
assert.deepEqual(sizes, [...sizes].sort((a, b) => b - a));
const page2 = await dash('/query?sort=size:desc&limit=4&offset=4');
assert.ok(page2.rows[0].size <= sizes[3] && !page2.rows.some(r => bySize.rows.some(x => x.sha256 === r.sha256)), 'pages do not overlap');
const byName = await dash('/query?sort=name,size:desc');
const ecus = byName.rows.filter(r => r.name === 'ecu.bin');
assert.ok(ecus[0].size > ecus[1].size, 'second key');
assert.equal((await dash('/query?sort=bogus', { expect: 400 })).error, 'bad_request');
await dash('/files/nothex', { expect: 400 });
await dash(`/files/${'0'.repeat(64)}`, { expect: 404 });

// Links: supergroup posts have one (dry run: message 0, none); the basic group's don't.
const sg = (await dash(`/files/${legacy[2].sha256}`)).row;
assert.equal(sg.telegram, 'https://t.me/c/3917356862/2');
assert.equal((await dash(`/files/${legacy[0].sha256}`)).row.telegram, null);

// ---- details, inspection, downloads
const [someSha, someFile] = [...donated].find(([, f]) => f.endsWith('mips_gzip.uimage'));
const bytes = readFileSync(someFile);
const detail = await dash(`/files/${someSha}`);
assert.equal(detail.row.status, 'stored');
assert.equal(detail.record.sha256, someSha);
assert.ok(detail.record.zrax.format && detail.path.endsWith(someSha));
const ecuDetail = await dash(`/files/${legacy[1].sha256}`);
assert.equal(ecuDetail.record, null);
assert.equal(ecuDetail.path, null);
assert.deepEqual(ecuDetail.same_name.map(r => r.sha256), [legacy[2].sha256]);
await dash(`/files/${legacy[1].sha256}/inspect`, { expect: 404 });
await dash(`/files/${legacy[1].sha256}/download`, { expect: 404 });

const inspect = await dash(`/files/${someSha}/inspect`);
assert.equal(inspect.size, bytes.length);
assert.equal(inspect.head, bytes.subarray(0, 1024).toString('hex'));
assert.equal(inspect.entropy.points.length, 256);
assert.ok(inspect.entropy.points.every(p => p >= 0 && p <= 8));
assert.ok(inspect.strings.length > 0);
const [off, str] = inspect.strings[0];
assert.equal(bytes.subarray(off, off + str.length).toString("latin1"), str);

const dl = await dash(`/files/${someSha}/download`, { raw: true });
assert.equal(sha(dl.body), someSha);
assert.match(dl.res.headers.get('content-disposition'), /attachment; filename="mips_gzip.uimage"/);
const part = await dash(`/files/${someSha}/download`, { raw: true, expect: 206, headers: { range: 'bytes=100-1099' } });
assert.deepEqual(part.body, bytes.subarray(100, 1100));
assert.equal(part.res.headers.get('content-range'), `bytes 100-1099/${bytes.length}`);
const tool0 = [...donated].find(([, f]) => f.endsWith('tool-0.elf'))[0];
assert.match((await dash(`/files/${tool0}/download`, { raw: true })).res.headers.get('content-disposition'), /filename\*=UTF-8''tool-0\.elf/);

// ---- exports
const text = async q => (await dash(`/export?${q}`, { raw: true })).body.toString();
const sums = (await text('as=sha256sum')).trim().split('\n');
assert.equal(sums.length, donated.size);
for (const line of sums) {
  const [hash, name] = line.split(/\s+/);
  assert.equal(hash, name);
  assert.equal(sha(readFileSync(path.join(work, 'firmwares', hash))), hash);
}
const rsync = (await text('as=rsync')).trim().split('\n');
assert.equal(rsync.length, 2 * donated.size);
const csv = (await text('as=csv&sort=size:desc')).trim().split('\n');
assert.equal(csv.length, expected + 1);
assert.ok(csv[0].startsWith('sha256,name,size,donor,kind,isa,'));
assert.equal((await text('as=csv&kind=library')).trim().split('\n')[1].split(',')[4], 'library');
assert.equal(Number(csv[1].split(',')[2]), sizes[0], 'in the requested order');
const nd = (await text('as=ndjson&origin=!ledger')).trim().split('\n').map(l => JSON.parse(l));
assert.equal(nd.length, donated.size);
assert.ok(nd.every(r => r.record?.zrax), 'full records');
assert.equal((await text('as=csv&isa=a_arch64')).trim().split('\n').length, 1 + anyIsa('a_arch64'));
const xres = (await dash('/export?as=rsync', { raw: true })).res;
assert.match(xres.headers.get('content-disposition'), /fwdonor-firmware-\d{4}-\d{2}-\d{2}\.files\.txt/);
await dash('/export?as=zip', { expect: 400 });

// ---- live: a new donation shows up
const before = (await dash('/summary')).version;
const late = put('late/new.elf', Buffer.concat([elf, randomBytes(77)]));
assert.equal((await runClient([late])).code, 0);
await waitFor('the new file', async () => (await dash('/summary')).version > before && (await count('q=new.elf')) === 1);

// ---- bulk
const call = async (method, url, body) => {
  const res = await fetch(`${base}${url}`, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, data: await res.json().catch(() => ({})) };
};
const note = 'private-note-for-the-admin-page';
const grant = (await call('POST', `/api/admin/${adminKey}/grants`, { name: 'Sonic', ceiling_bytes: 100 * MiB, note })).data;
const token = grant.token;
const putChunk = (id, i, data) => fetch(`${base}/api/bulk/${token}/uploads/${id}/${i}`, {
  method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-chunk-sha256': sha(data) }, body: data,
});
const big = randomBytes(2 * MiB + 1234);
const up = (await call('POST', `/api/bulk/${token}/uploads`, { name: 'dump.img', path: 'dumps/2026/dump.img', size: big.length, last_modified: 1790000000000 })).data;
for (let i = 0; i < up.chunks; i++) assert.equal((await putChunk(up.id, i, big.subarray(i * MiB, (i + 1) * MiB))).status, 204);
await waitFor('the bulk file stored', async () => (await call('GET', `/api/bulk/${token}/uploads/${up.id}`)).data.state === 'stored');
const half = randomBytes(3 * MiB);
const open = (await call('POST', `/api/bulk/${token}/uploads`, { name: 'half.img', size: half.length })).data;
assert.equal((await putChunk(open.id, 0, half.subarray(0, MiB))).status, 204);

const bv = await dash('/bulk');
assert.equal(bv.grants.length, 1);
assert.equal(bv.grants[0].name, 'Sonic');
assert.match(bv.grants[0].id, /^[0-9a-f]{8}$/);
assert.equal(bv.grants[0].files, 1);
assert.equal(bv.grants[0].unfinished, 1);
assert.equal(bv.files.length, 1);
assert.deepEqual([bv.files[0].sha256, bv.files[0].path, bv.files[0].grant], [sha(big), 'dumps/2026/dump.img', bv.grants[0].id]);
assert.ok(bv.files[0].started_at && bv.files[0].completed_at >= bv.files[0].started_at && bv.files[0].last_modified === 1790000000000);
assert.equal(bv.uploads.length, 1);
assert.equal(bv.uploads[0].received_count, 1);
assert.equal(bv.uploads[0].chunks, 3);
const bdl = await dash(`/bulk/${sha(big)}/download`, { raw: true });
assert.equal(sha(bdl.body), sha(big));
assert.match(bdl.res.headers.get('content-disposition'), /filename="dump.img"/);
const bpart = await dash(`/bulk/${sha(big)}/download`, { raw: true, expect: 206, headers: { range: `bytes=${MiB}-` } });
assert.deepEqual(bpart.body, big.subarray(MiB));
await dash(`/bulk/${'1'.repeat(64)}/download`, { expect: 404 });
const bsum = (await dash(`/bulk/export?as=sha256sum&grant=${bv.grants[0].id}`, { raw: true })).body.toString();
assert.equal(bsum, `${sha(big)}  ${sha(big)}\n`);
assert.equal((await dash('/bulk/export?as=sha256sum&grant=00000000', { raw: true })).body.length, 0);
assert.ok((await dash('/summary')).bulk.files === 1);
console.log('-- bulk view: one stored, one unfinished');

// ---- the public dashboard: no key, no bulk, no origin, no operations
async function pub(pathAndQuery, { expect = 200, raw = false, headers = {}, method = 'GET' } = {}) {
  const res = await fetch(`${base}/api/dashboard${pathAndQuery}`, { headers, method });
  const body = Buffer.from(await res.arrayBuffer());
  if (!pathAndQuery.includes('/download')) seen.push({ url: `public ${pathAndQuery}`, text: body.toString('utf8') });
  assert.equal(res.status, expect, `public ${pathAndQuery}: ${res.status} ${body.toString().slice(0, 300)}`);
  return raw ? { res, body } : JSON.parse(body.toString());
}
{
  const res = await fetch(`${base}/dashboard`);
  assert.equal(res.status, 200, 'the public page needs no key');
  const html = await res.text();
  assert.ok(html.includes('dash.js') && !html.includes('noindex'), 'the dashboard page, indexable');
  assert.equal((await fetch(`${base}/dashboard/`, { redirect: 'manual' })).status, 308);
  const home = await (await fetch(`${base}/`)).text();
  assert.ok(home.includes('href="/dashboard"'), 'the donation page links to it');
}
const ps = await pub('/summary');
assert.equal(ps.files, (await dash('/summary')).files);
for (const k of ['stored', 'pending', 'queued', 'unrecovered', 'backfill', 'arriving', 'queue', 'disk', 'firmware_dir', 'bulk', 'ledger', 'older_zrax']) {
  assert.ok(!(k in ps), `the public summary has no ${k}`);
}
const pq = await pub('/query?facets=1&tree=family,origin,isa&matrix=isa,status&sort=origin:desc,size:desc&origin=ledger&status=pending');
assert.equal(pq.total, ps.files, 'origin and status filters are ignored');
assert.deepEqual(pq.tree.levels, ['family', 'isa']);
assert.ok(!pq.matrix, 'no matrix over a hidden dimension');
assert.ok(!('origin' in pq.facets) && !('status' in pq.facets) && 'donor' in pq.facets);
for (const r of pq.rows) {
  assert.ok(!('origin' in r) && !('status' in r) && !('reason' in r) && typeof r.stored === 'boolean');
}
assert.equal(pq.rows[0].size, Math.max(...pq.rows.map(r => r.size)), 'sorted by size (the origin key is dropped)');
const pd = await pub(`/files/${someSha}`);
assert.equal(pd.row.stored, true);
assert.ok(!('path' in pd) && !('source' in pd.record) && pd.record.zrax);
assert.equal((await pub(`/files/${legacy[1].sha256}`)).row.stored, false);
assert.equal((await pub('/query?kind=!firmware')).total, 9, 'the late object file too');
assert.equal((await pub(`/files/${sha(readFileSync(libDemo))}`)).kind.key, 'library');
assert.equal(ps.kinds.library, 1);
assert.equal((await pub(`/files/${someSha}/inspect`)).head, inspect.head);
await pub('/bulk', { expect: 404, raw: true });
await pub('/export?as=rsync', { expect: 400 });
const pcsv = (await pub('/export?as=csv', { raw: true })).body.toString().trim().split('\n');
assert.equal(pcsv[0], 'sha256,name,size,donor,kind,isa,isas,family,format,variant,bits,endian,confidence,class,basis,slices,stored,received_at,posted_at,telegram,zrax');
assert.equal(pcsv.length, ps.files + 1);
const pnd = (await pub('/export?as=ndjson', { raw: true })).body.toString().trim().split('\n').map(l => JSON.parse(l));
assert.ok(pnd.every(r => !('origin' in r) && !('status' in r) && !(r.record && 'source' in r.record)));
assert.equal((await pub('/export?as=sha256sum', { raw: true })).body.toString().trim().split('\n').length, donated.size);

// Downloads need a proof of work bound to the file, six bits harder than an upload's.
const lz = h => { let n = 0; for (const b of h) { if (b === 0) { n += 8; continue; } return n + Math.clz32(b) - 24; } return n; };
const workBits = (token, hexSha, nonce) => {
  const seed = createHash('sha256').update(Buffer.concat([Buffer.from(token, 'base64url'), Buffer.from(hexSha, 'hex')])).digest();
  const buf = Buffer.alloc(40);
  seed.copy(buf);
  buf.writeBigUInt64BE(BigInt(nonce), 32);
  return lz(createHash('sha256').update(buf).digest());
};
// The first `count` solutions of `bits` (from nonce `from` on).
const solveMany = (token, hexSha, bits, count, from = 0) => {
  const out = [];
  for (let n = from; out.length < count; n++) if (workBits(token, hexSha, n) >= bits) out.push(n);
  return out;
};
const ch = await pub('/challenge');
assert.deepEqual([ch.bits, ch.proofs], [14, 16], '16 solutions of pow.bits + 6 - 4 bits (as much work as pow.bits + 6)');
const dlUrl = (file, token, nonces) => `/files/${file}/download?token=${token}&nonces=${nonces.join(',')}`;
assert.equal((await pub(`/files/${someSha}/download`, { expect: 403, raw: true })).res.status, 403, 'no proof, no file');
const nonces = solveMany(ch.token, someSha, ch.bits, 16);
await pub(dlUrl(someSha, ch.token, nonces.slice(0, 15)), { expect: 403 });
await pub(dlUrl(someSha, ch.token, [nonces[0], ...nonces.slice(0, 15)]), { expect: 403 }); // a repeat
await pub(dlUrl(someSha, ch.token, [...nonces].reverse()), { expect: 403 });
const otherFile = solveMany(ch.token, tool0, ch.bits, 16);
if (otherFile.some(n => workBits(ch.token, someSha, n) < ch.bits)) await pub(dlUrl(someSha, ch.token, otherFile), { expect: 403 });
const weak = solveMany(ch.token, someSha, ch.bits - 2, 16);
if (weak.some(n => workBits(ch.token, someSha, n) < ch.bits)) await pub(dlUrl(someSha, ch.token, weak), { expect: 403 });
const pdl = await pub(dlUrl(someSha, ch.token, nonces), { raw: true });
assert.equal(sha(pdl.body), someSha);
assert.match(pdl.res.headers.get('content-disposition'), /filename="mips_gzip.uimage"/);
const again2 = await pub(dlUrl(someSha, ch.token, nonces), { raw: true, expect: 206, headers: { range: 'bytes=5-' } });
assert.deepEqual(again2.body, bytes.subarray(5), 'the same proof resumes the download');
assert.equal((await pub(dlUrl(someSha, ch.token, nonces), { raw: true, method: 'HEAD' })).res.status, 200);
await pub(dlUrl(legacy[1].sha256, ch.token, solveMany(ch.token, legacy[1].sha256, ch.bits, 16)), { expect: 404 });
const uploadChallenge = await (await fetch(`${base}/api/challenge`)).json();
assert.equal(uploadChallenge.bits, 12);
await pub(dlUrl(someSha, uploadChallenge.token, solveMany(uploadChallenge.token, someSha, 14, 16)), { expect: 403 });
console.log('-- public dashboard: corpus only, downloads behind a proof of work');

// ---- a restart rebuilds the index from the ledger and the store
const total = (await dash('/summary')).files;
await stop();
await start();
const again = await waitFor('the index after a restart', async () => {
  const s = await dash('/summary');
  return s.ready ? s : null;
});
assert.equal(again.files, total);
assert.equal(again.pending.files, 3);
assert.equal(await count('isa=a_arch64'), anyIsa('a_arch64') + 1);

// ---- nothing private in any dashboard answer
const forbidden = [token, adminKey, note];
const walk = (v, where) => {
  if (Array.isArray(v)) return v.forEach(x => walk(x, where));
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      assert.ok(k !== 'ip' && k !== 'ips', `${where} has an address field`);
      walk(x, where);
    }
  }
};
for (const { url, text: body } of seen) {
  for (const f of forbidden) assert.ok(!body.includes(f), `${url} contains ${f === token ? 'the grant token' : f === adminKey ? 'the admin key' : 'the note'}`);
  if (url.includes('ndjson')) body.trim().split('\n').filter(Boolean).forEach(l => walk(JSON.parse(l), url));
  else if (body.startsWith('{') || body.startsWith('[')) walk(JSON.parse(body), url);
}
console.log(`-- ${seen.length} dashboard answers checked: no addresses, tokens, notes or admin key`);
await stop();
console.log('dashboard e2e ok');
