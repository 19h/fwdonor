// fwdonor page: classify dropped files with zrax, upload recognized
// firmware (proof of work + chunked upload), and follow each to Telegram.
import { esc, fmtSize, isaName, fmtEndianShort, fmtFormatName } from './format.js';
import { judge } from './policy.js';
import { ZRAX_REV } from './build-info.js';
import { startCorpus, corpusChanged } from './corpus.js';
import { MAX_BACKOFF_S, sleep, proxyError, transient, describe, backoff, itemsFromDrop } from './common.js';

const $ = id => document.getElementById(id);
const USERNAME_KEY = 'fwdonor.username';
const UPLOAD_CONCURRENCY = 2;
const POLL_MS = 2000;
const RECYCLE_AFTER_BYTES = 128 * 1024 * 1024;
// A file the server accepted but then could not post is sent this many times.
const SERVER_FAILURE_ATTEMPTS = 3;

const FINAL = new Set(['skip', 'posted', 'duplicate', 'rejected', 'failed']);
const PHASES = {
  queued: ['queued', '[ ]', 'queued'],
  analyzing: ['working', '[*]', 'analyzing'],
  skip: ['skip', '[-]', 'skipped'],
  waiting: ['queued', '[ ]', 'recognized · waiting to upload'],
  backoff: ['queued', '[~]', 'waiting'],
  pow: ['working', '[*]', 'proof of work'],
  uploading: ['working', '[^]', 'uploading'],
  verifying: ['working', '[*]', 'server verifying'],
  telegram: ['working', '[>]', 'queued for telegram'],
  posting: ['working', '[>]', 'posting to telegram'],
  posted: ['ok', '[+]', 'donated'],
  duplicate: ['dup', '[=]', 'already in the collection'],
  rejected: ['bad', '[x]', 'rejected by server'],
  failed: ['bad', '[!]', 'failed'],
};

let policy = null;
let resolvePolicy;
const policyReady = new Promise(resolve => { resolvePolicy = resolve; });
// The server runs a different zrax build: nothing more can be donated from this page.
let stale = false;
let engineVersion = '';
const rows = new Map();
let nextRow = 1;
const analysisQueue = [];
let analyzing = false;
const uploadQueue = [];
let activeUploads = 0;
let thanksShownFor = 0;
// sha256 → the row that represents it in this page session (dedup within drops).
const bySha = new Map();

// ---------------------------------------------------------------- donor name

const donor = $('donor');
function donorName() {
  return donor.value.trim();
}
donor.value = localStorage.getItem(USERNAME_KEY) ?? '';
donor.addEventListener('input', () => {
  const clean = donor.value.replace(/^@/, '').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 32);
  if (clean !== donor.value) donor.value = clean;
  localStorage.setItem(USERNAME_KEY, clean);
});

// ---------------------------------------------------------------- banners

let bannerKind = null;

function banner(html, { warn = false, reload = false, kind = 'error' } = {}) {
  const el = $('banner');
  el.className = `error-banner${warn ? ' warn' : ''}`;
  el.innerHTML = html + (reload ? ' <button type="button" id="reload">reload</button>' : '');
  el.hidden = false;
  bannerKind = kind;
  if (reload) $('reload').onclick = () => location.reload();
}

function hideBanner(kind) {
  if (bannerKind !== kind) return;
  $('banner').hidden = true;
  bannerKind = null;
}

// Shown while the server can't be reached (usually: it is restarting).
let downSince = 0;

function serverDown() {
  if (downSince) return;
  downSince = Date.now();
  const el = $('notice');
  el.textContent = 'Lost contact with the server (it is probably restarting). Keep this tab open: '
    + 'everything waiting here continues by itself as soon as it is back.';
  el.hidden = false;
  summarize();
}

function serverUp() {
  if (!downSince) return;
  downSince = 0;
  $('notice').hidden = true;
  summarize();
}

function setStatus(text) {
  $('status').textContent = text;
}

// ---------------------------------------------------------------- workers

let worker = null;
let workerReady = null;
const pendingAnalysis = new Map();

function startWorker() {
  worker = new Worker(new URL('./analyze-worker.js', import.meta.url), { type: 'module' });
  workerReady = new Promise((resolve, reject) => {
    worker.addEventListener('message', ({ data }) => {
      if (data.type === 'ready') resolve(data.version);
      else if (data.type === 'boot-error') reject(new Error(data.error));
      else if (data.type === 'result') {
        const done = pendingAnalysis.get(data.id);
        pendingAnalysis.delete(data.id);
        done?.(data);
      }
    });
  });
  worker.addEventListener('error', event => {
    event.preventDefault();
    for (const [id, done] of pendingAnalysis) done({ id, payload: null, error: 'analysis crashed' });
    pendingAnalysis.clear();
    worker.terminate();
    startWorker();
  });
}

function analyzeFile(row) {
  return new Promise(resolve => {
    pendingAnalysis.set(row.id, resolve);
    worker.postMessage({ id: row.id, file: row.file });
  });
}

const powWorker = new Worker(new URL('./pow-worker.js', import.meta.url), { type: 'module' });
const pendingPow = new Map();
let powSeq = 0;
powWorker.addEventListener('message', ({ data }) => {
  const done = pendingPow.get(data.id);
  pendingPow.delete(data.id);
  if (!done) return;
  if (data.error) done.reject(new Error(data.error));
  else done.resolve(data.nonce);
});

function solvePow(token, sha256, bits) {
  return new Promise((resolve, reject) => {
    const id = ++powSeq;
    pendingPow.set(id, { resolve, reject });
    powWorker.postMessage({ id, token, sha256, bits });
  });
}

// ---------------------------------------------------------------- API

async function request(path, init) {
  let res;
  try {
    res = await fetch(path, init);
  } catch (cause) {
    // Connection refused or reset, offline, ...: no HTTP status at all.
    serverDown();
    const err = new Error('server unreachable');
    err.cause = cause;
    throw err;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.code = data.error;
    err.retryAfter = Number(res.headers.get('retry-after')) || 0;
    if (proxyError(err)) serverDown();
    else serverUp();
    throw err;
  }
  serverUp();
  return data;
}

function api(method, path, body) {
  return request(path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}

// Run `fn` until it succeeds or fails for a non-transient reason, waiting
// 1, 2, 4 … 20 s (or the server's Retry-After, capped) between attempts.
async function persist(fn, onWait) {
  for (let failures = 1; ; failures++) {
    try {
      return await fn();
    } catch (err) {
      if (!transient(err)) throw err;
      const wait = backoff(failures, err.retryAfter);
      onWait?.(err, wait);
      await sleep(wait * 1000);
    }
  }
}

// ---------------------------------------------------------------- known hashes

// Coalesce lookups so a folder of files costs a handful of requests.
const knownWaiters = new Map();
let knownTimer = null;

function checkKnown(sha256) {
  return new Promise(resolve => {
    const waiters = knownWaiters.get(sha256) ?? [];
    waiters.push(resolve);
    knownWaiters.set(sha256, waiters);
    knownTimer ??= setTimeout(flushKnown, 150);
  });
}

async function flushKnown() {
  knownTimer = null;
  const batch = [...knownWaiters].slice(0, 1000);
  for (const [sha] of batch) knownWaiters.delete(sha);
  if (knownWaiters.size) knownTimer = setTimeout(flushKnown, 0);
  let known = {};
  try {
    known = (await persist(() => api('POST', '/api/known', { sha256: batch.map(([sha]) => sha) }))).known ?? {};
  } catch {
    // The server repeats the check when the upload is admitted.
  }
  for (const [sha, waiters] of batch) for (const resolve of waiters) resolve(known[sha] ?? null);
}

function markKnown(row, known) {
  row.dupKind = 'known';
  if (known.posted_at) setPhase(row, 'duplicate', `donated on ${known.date}`);
  else setPhase(row, 'duplicate', 'someone is donating this right now');
}

// ---------------------------------------------------------------- rows

// Mirrors clean_variant in src/telegram/poster.rs.
function formatLabel(format) {
  const name = fmtFormatName(format.format);
  const v = (format.variant_name ?? '').trim();
  return v && !v.includes('{') && v.toLowerCase() !== name.toLowerCase() ? `${name} (${v})` : name;
}

function cellsFor(row) {
  const p = row.payload;
  if (!p || p.error) return ['—', '—', '—', '—'];
  const prim = p.primary ?? {};
  const slices = (p.slices ?? []).filter(s => typeof s.isa === 'string');
  let isa = '—';
  if (typeof prim.isa === 'string') isa = isaName(prim.isa);
  if (slices.length > 1) isa = [...new Set(slices.map(s => isaName(s.isa)))].join(' + ');
  else if (isa === '—' && slices.length === 1) isa = isaName(slices[0].isa);
  const concrete = typeof prim.isa === 'string';
  const bits = concrete ? `${prim.bitwidth || '?'} · ${fmtEndianShort(prim.endianness)}` : '—';
  const conf = concrete ? `${(prim.confidence * 100).toFixed(1)}%` : '—';
  return [formatLabel(p.format), isa, bits, conf];
}

function render(row) {
  const [cls, glyph, label] = PHASES[row.phase];
  const [format, isa, bits, conf] = cellsFor(row);
  const dir = row.path.includes('/') ? row.path.slice(0, row.path.lastIndexOf('/')) : '';
  let state = esc(row.label ?? label);
  // Width is set through CSSOM below: the CSP forbids inline style attributes.
  const meter = row.phase === 'uploading' ? '<div class="meter"><i></i></div>' : '';
  row.el.className = cls;
  row.el.innerHTML = `<td class="st">${glyph}</td>`
    + `<td><span class="name" title="${esc(row.path)}">${esc(row.file.name)}</span>${dir ? `<span class="sub">${esc(dir)}</span>` : ''}</td>`
    + `<td class="num">${fmtSize(row.size)}</td><td>${esc(format)}</td><td>${esc(isa)}</td><td>${esc(bits)}</td><td class="num">${esc(conf)}</td>`
    + `<td><div class="state"><span>${state}</span>${meter}${row.detail ? `<small>${esc(row.detail)}</small>` : ''}</div></td>`;
  const bar = row.el.querySelector('.meter > i');
  if (bar) bar.style.width = `${(row.progress * 100).toFixed(1)}%`;
}

function setPhase(row, phase, detail = '', label = null) {
  row.phase = phase;
  row.detail = detail;
  row.label = label;
  render(row);
  summarize();
}

function summarize() {
  const all = [...rows.values()];
  const count = phase => all.filter(r => r.phase === phase).length;
  const done = all.filter(r => FINAL.has(r.phase)).length;
  $('count').textContent = all.length;
  const working = all.length - done;
  const parts = [
    ['donated', count('posted')],
    ['in progress', working],
    ['skipped', count('skip')],
    ['already donated', count('duplicate')],
    ['failed', count('failed') + count('rejected')],
  ].filter(([, n]) => n > 0);
  $('tallies').innerHTML = parts.map(([k, n]) => `<span><b>${n}</b> ${k}</span>`).join('');
  const progress = $('progress');
  progress.max = Math.max(1, all.length);
  progress.value = done;
  $('results').hidden = all.length === 0;
  if (downSince && working) setStatus(`waiting for the server · ${working} in progress`);
  else if (working === 0) setStatus(all.length ? 'idle' : 'ready');
  else if (activeUploads) setStatus(`uploading ${activeUploads} file${activeUploads > 1 ? 's' : ''} · ${working} in progress`);
  else setStatus(`${working} in progress`);
  maybeThanks();
}

function maybeThanks() {
  const all = [...rows.values()];
  if (!all.length || all.some(r => !FINAL.has(r.phase))) return;
  const posted = all.filter(r => r.phase === 'posted');
  const dupes = all.filter(r => r.phase === 'duplicate' && r.dupKind !== 'local').length;
  const twins = all.filter(r => r.phase === 'duplicate' && r.dupKind === 'local').length;
  const skipped = all.filter(r => r.phase === 'skip').length;
  const key = all.length * 1e6 + posted.length * 1e3 + dupes * 10 + twins;
  if (key === thanksShownFor) return;
  thanksShownFor = key;
  const el = $('thanks');
  if (!posted.length && !dupes && !twins) {
    el.hidden = true;
    if (skipped) setStatus('none of these files were recognized as firmware');
    return;
  }
  const name = donorName() || 'anonymous donor';
  const bytes = posted.reduce((sum, r) => sum + r.size, 0);
  const lines = [];
  if (posted.length) lines.push(`${posted.length} image${posted.length > 1 ? 's' : ''} (${fmtSize(bytes)}) donated to the zrax corpus, credited to ${name}.`);
  if (dupes) lines.push(`${dupes} ${dupes > 1 ? 'were' : 'was'} already in the collection, so ${dupes > 1 ? 'they were' : 'it was'} not uploaded again.`);
  if (twins) lines.push(`${twins} duplicate cop${twins > 1 ? 'ies' : 'y'} in this drop ${twins > 1 ? 'were' : 'was'} skipped.`);
  if (skipped) lines.push(`${skipped} unrecognized file${skipped > 1 ? 's were' : ' was'} skipped and never left your browser.`);
  el.innerHTML = `<strong>${posted.length ? `thank you, ${esc(name)}!` : 'thanks anyway!'}</strong>`
    + lines.map(l => `<span>${esc(l)}</span>`).join('');
  el.hidden = false;
}

// ---------------------------------------------------------------- pipeline

function enqueue(items) {
  // Files dropped before the policy arrives (or while paused) simply wait.
  if (stale || !items.length) return;
  $('thanks').hidden = true;
  const tbody = $('rows');
  const fragment = document.createDocumentFragment();
  for (const { file, path } of items) {
    const row = { id: nextRow++, file, path: path || file.name, size: file.size, phase: 'queued', progress: 0, el: document.createElement('tr') };
    rows.set(row.id, row);
    render(row);
    fragment.appendChild(row.el);
    analysisQueue.push(row);
  }
  tbody.appendChild(fragment);
  summarize();
  pumpAnalysis();
}

async function pumpAnalysis() {
  if (analyzing) return;
  analyzing = true;
  try {
    await workerReady;
  } catch (err) {
    banner(`The analysis engine failed to load: ${esc(err.message)}`, { reload: true });
    analyzing = false;
    return;
  }
  await policyReady;
  while (analysisQueue.length) {
    const row = analysisQueue.shift();
    if (!rows.has(row.id)) continue;
    if (row.size > policy.max_file_bytes) {
      setPhase(row, 'skip', `too large (limit ${$('limit').textContent})`);
      continue;
    }
    if (row.size < policy.min_file_bytes) {
      setPhase(row, 'skip', 'too small');
      continue;
    }
    setPhase(row, 'analyzing');
    setStatus(`analyzing ${row.file.name}`);
    const result = await analyzeFile(row);
    if (!result.payload) {
      // A trap may have left the WASM instance unusable: start fresh.
      worker.terminate();
      startWorker();
      await workerReady.catch(() => {});
      setPhase(row, 'failed', `analysis crashed: ${result.error}`);
      continue;
    }
    row.payload = result.payload;
    row.sha256 = result.sha256;
    if (row.size > RECYCLE_AFTER_BYTES) {
      // WASM memory only grows: drop the worker after a big file so the tab
      // doesn't keep holding hundreds of MiB.
      worker.terminate();
      startWorker();
    }
    const verdict = judge(result.payload, policy.policy);
    if (!verdict.accept) {
      setPhase(row, 'skip', verdict.reason);
      continue;
    }
    const twin = bySha.get(row.sha256);
    if (twin && rows.has(twin.id) && !['failed', 'rejected'].includes(twin.phase)) {
      row.dupKind = 'local';
      setPhase(row, 'duplicate', `same file as ${twin.path}`, 'duplicate in this drop');
      continue;
    }
    bySha.set(row.sha256, row);
    setPhase(row, 'waiting', verdict.basis === 'container' ? 'firmware container' : '');
    checkKnown(row.sha256).then(known => {
      if (known) {
        markKnown(row, known);
      } else {
        uploadQueue.push(row);
        pumpUploads();
      }
    });
  }
  analyzing = false;
  summarize();
}

function pumpUploads() {
  while (activeUploads < UPLOAD_CONCURRENCY && uploadQueue.length) {
    const row = uploadQueue.shift();
    if (!rows.has(row.id)) continue;
    activeUploads++;
    donate(row)
      .catch(err => setPhase(row, 'failed', err.message || String(err)))
      .finally(() => {
        activeUploads--;
        pumpUploads();
        summarize();
      });
  }
}

// The server lost the upload (it restarted): send the file again.
class Restart extends Error {}

function goStale() {
  if (stale) return;
  stale = true;
  banner('This page is out of date with the server. Reload it to keep donating.', { warn: true, reload: true, kind: 'stale' });
  $('dropzone').disabled = true;
}

async function admit(row) {
  for (let failures = 1; ; failures++) {
    if (stale) throw new Error('this page is out of date; reload it and drop the file again');
    setPhase(row, 'pow');
    try {
      const challenge = await api('GET', '/api/challenge');
      const nonce = await solvePow(challenge.token, row.sha256, challenge.bits);
      return await api('POST', '/api/uploads', {
        name: row.file.name,
        size: row.size,
        sha256: row.sha256,
        username: donorName(),
        token: challenge.token,
        nonce,
        zrax_rev: ZRAX_REV,
      });
    } catch (err) {
      if (err.code === 'duplicate') return { duplicate: err.message };
      if (err.code === 'stale_client') {
        goStale();
        throw new Error('this page is out of date; reload it and drop the file again');
      }
      // A rejected proof is usually a challenge from before a server restart.
      if (err.code === 'pow' && failures === 1) continue;
      if (err.code !== 'pow' && !transient(err)) throw err;
      const wait = backoff(failures, err.retryAfter);
      setPhase(row, 'backoff', `${describe(err)} · retrying in ${wait}s`);
      await sleep(wait * 1000);
    }
  }
}

async function putChunk(id, index, blob) {
  await request(`/api/uploads/${id}/${index}`, { method: 'PUT', body: blob });
}

async function lookupKnown(sha256) {
  const { known } = await persist(() => api('POST', '/api/known', { sha256: [sha256] }));
  return known?.[sha256] ?? null;
}

// Our upload id is gone, so the server restarted. It may have posted the file
// first, may still be posting it from its spool, or may have lost it.
async function afterRestart(row) {
  row.uploadId = null;
  for (;;) {
    const known = await lookupKnown(row.sha256);
    if (known?.posted_at) {
      setPhase(row, 'posted');
      corpusChanged();
      return null;
    }
    if (!known) throw new Restart('the server restarted');
    setPhase(row, 'telegram', 'the server restarted · waiting for it to finish this file');
    await sleep(POLL_MS * 2);
  }
}

async function uploadOnce(row) {
  const init = await admit(row);
  if (init.duplicate) {
    row.dupKind = 'known';
    setPhase(row, 'duplicate', init.duplicate);
    return null;
  }
  row.uploadId = init.id;
  row.progress = 0;
  setPhase(row, 'uploading', '', 'uploading 0%');
  const percent = () => `uploading ${Math.round(row.progress * 100)}%`;
  let status;
  try {
    for (let i = 0; i < init.chunks; i++) {
      const start = i * init.chunk_size;
      const end = Math.min(row.size, start + init.chunk_size);
      await persist(
        () => putChunk(init.id, i, row.file.slice(start, end)),
        (err, wait) => setPhase(row, 'uploading', `${describe(err)} · retrying in ${wait}s`, percent()),
      );
      row.progress = end / row.size;
      setPhase(row, 'uploading', '', percent());
    }
    status = await persist(
      () => api('POST', `/api/uploads/${init.id}/complete`),
      (err, wait) => setPhase(row, 'verifying', `${describe(err)} · retrying in ${wait}s`),
    );
  } catch (err) {
    // Unknown id, or a session that expired while the server was unreachable.
    if (err.status === 404 || (err.status === 409 && ['state', 'incomplete'].includes(err.code))) {
      throw new Restart('the server lost this upload');
    }
    throw err;
  }
  for (;;) {
    switch (status.state) {
      case 'receiving':
        throw new Restart('the server lost part of this upload');
      case 'verifying':
        setPhase(row, 'verifying');
        break;
      case 'queued':
        setPhase(row, 'telegram', status.position ? `position ${status.position}` : '');
        break;
      case 'posting':
        setPhase(row, 'posting');
        break;
      case 'posted':
        row.uploadId = null;
        setPhase(row, 'posted');
        corpusChanged();
        return null;
      case 'rejected':
        row.uploadId = null;
        setPhase(row, 'rejected', status.reason);
        return null;
      case 'failed':
        row.uploadId = null;
        return { failed: status.reason || 'the server could not post this file' };
    }
    await sleep(POLL_MS);
    try {
      status = await persist(
        () => api('GET', `/api/uploads/${init.id}`),
        (err, wait) => setPhase(row, row.phase, `${describe(err)} · retrying in ${wait}s`, row.label),
      );
    } catch (err) {
      if (err.status === 404) return afterRestart(row);
      throw err;
    }
  }
}

async function donate(row) {
  for (let serverFailures = 0; ;) {
    let outcome;
    try {
      outcome = await uploadOnce(row);
    } catch (err) {
      if (!(err instanceof Restart)) throw err;
      row.uploadId = null;
      setPhase(row, 'backoff', `${err.message} · sending the file again`);
      await sleep(1000);
      continue;
    }
    if (!outcome?.failed) return;
    if (++serverFailures >= SERVER_FAILURE_ATTEMPTS) {
      setPhase(row, 'failed', outcome.failed);
      return;
    }
    setPhase(row, 'backoff', `${outcome.failed} · trying again in ${MAX_BACKOFF_S}s`);
    await sleep(MAX_BACKOFF_S * 1000);
  }
}

// ---------------------------------------------------------------- input

let dragDepth = 0;
const overlay = $('drag-overlay');
const hasFiles = event => [...(event.dataTransfer?.types ?? [])].includes('Files');
window.addEventListener('dragenter', event => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  dragDepth++;
  overlay.hidden = stale;
});
window.addEventListener('dragover', event => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = stale ? 'none' : 'copy';
});
window.addEventListener('dragleave', event => {
  if (!hasFiles(event)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) overlay.hidden = true;
});
window.addEventListener('drop', event => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  dragDepth = 0;
  overlay.hidden = true;
  itemsFromDrop(event.dataTransfer).then(enqueue, err => banner(`Could not read the dropped files: ${esc(err.message)}`));
});
window.addEventListener('blur', () => {
  dragDepth = 0;
  overlay.hidden = true;
});

const fileInput = $('fileinput');
$('dropzone').addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  enqueue([...fileInput.files].map(file => ({ file, path: file.name })));
  fileInput.value = '';
});

$('clear').addEventListener('click', () => {
  for (const [id, row] of rows) {
    if (FINAL.has(row.phase)) {
      row.el.remove();
      rows.delete(id);
      if (bySha.get(row.sha256) === row) bySha.delete(row.sha256);
    }
  }
  thanksShownFor = 0;
  $('thanks').hidden = true;
  summarize();
});

const uploading = () => [...rows.values()].filter(r => r.uploadId && r.phase === 'uploading');
window.addEventListener('beforeunload', event => {
  if ([...rows.values()].some(r => !FINAL.has(r.phase) && r.phase !== 'queued')) event.preventDefault();
});
window.addEventListener('pagehide', () => {
  for (const row of uploading()) fetch(`/api/uploads/${row.uploadId}`, { method: 'DELETE', keepalive: true });
});

// ---------------------------------------------------------------- boot

// The server answers with the zrax revision this page must have to upload:
// its own while that is still accepted after a zrax update.
const POLICY_URL = `/api/policy?rev=${ZRAX_REV}`;

function applyPolicy(next) {
  policy = next;
  const mib = policy.max_file_bytes / 1048576;
  $('limit').textContent = Number.isInteger(mib) ? `${mib} MiB` : fmtSize(policy.max_file_bytes);
  $('status-zrax').textContent = `zrax ${policy.zrax}`;
  if (policy.zrax_rev !== ZRAX_REV) {
    goStale();
    return;
  }
  if (policy.paused) {
    if (bannerKind !== 'paused') {
      banner('Donations are paused right now. Files you add wait here and upload by themselves once donations resume.', { warn: true, kind: 'paused' });
    }
  } else {
    hideBanner('paused');
    if (policy.zrax_latest && policy.zrax_latest !== ZRAX_REV && !bannerKind) {
      banner('zrax was updated on the server. This page keeps donating with the classifier it loaded; '
        + 'reload once your files are done to get the new one.', { warn: true, reload: true, kind: 'update' });
    }
  }
}

// Notice pauses ending (and server updates) without a reload.
async function watchPolicy() {
  for (;;) {
    await sleep(policy.paused ? MAX_BACKOFF_S * 1000 : 60000);
    try {
      applyPolicy(await api('GET', POLICY_URL));
    } catch {
      // Unreachable for now: uploads report that themselves.
    }
  }
}

async function boot() {
  startWorker();
  startCorpus();
  const first = await persist(
    () => api('GET', POLICY_URL),
    (err, wait) => setStatus(`waiting for the server · ${describe(err)} · retrying in ${wait}s`),
  );
  applyPolicy(first);
  resolvePolicy();
  summarize();
  watchPolicy();
  try {
    engineVersion = await workerReady;
    $('engine').textContent = `engine ${engineVersion} · ${ZRAX_REV.slice(0, 7)}`;
  } catch (err) {
    banner(`The analysis engine failed to load: ${esc(err.message)}`, { reload: true });
    $('dropzone').disabled = true;
  }
}

boot();
