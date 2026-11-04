// Bulk donation page (/r/<token>): upload files of any size to the server in
// chunks, resumably, and show in detail how the transfer is going.
//
// Every file is split into the server's chunk size. Chunks from all open
// files share one pool of parallel requests whose size adapts to how fast
// chunks go through. Each chunk carries its SHA-256, and the server hashes the
// whole file as it arrives, so it is stored under its hash moments after the
// last chunk. If anything breaks off, dropping the same file again continues
// the upload the server kept (after checking a few chunks to be sure it really
// is the same file).
import { esc } from './format.js';
import { sleep, proxyError, transient, describe, backoff, itemsFromDrop } from './common.js';

const $ = id => document.getElementById(id);
const TOKEN = location.pathname.split('/').filter(Boolean)[1] ?? '';
const API = `/api/bulk/${encodeURIComponent(TOKEN)}`;

const START_STREAMS = 4;
const MAX_STREAMS = 8;
// The proxy gives every request 120 s; a chunk slower than this is a sign to
// run fewer in parallel.
const SLOW_CHUNK_MS = 60000;
const FAST_CHUNK_MS = 15000;
const CHUNK_TIMEOUT_MS = 115000;
const MAX_OPEN_FILES = 8;
const MAX_OPENING = 2;
const CHECKSUM_RETRIES = 5;
const POLL_MS = 1000;
const PROGRESS_POLL_MS = 3000;
const GRANT_REFRESH_MS = 10000;
const TICK_MS = 250;
const SPEED_WINDOW_MS = 5000;
const SPARK_SECONDS = 300;
const LOG_MAX = 200;

const ACTIVE = new Set(['opening', 'checking', 'uploading', 'finishing', 'hashing']);
const FINAL = new Set(['stored', 'duplicate', 'skipped', 'failed']);
const LOOK = {
  queued: ['queued', '[ ]', 'queued'],
  opening: ['working', '[*]', 'starting'],
  checking: ['working', '[*]', 'checking the unfinished upload'],
  uploading: ['working', '[^]', 'uploading'],
  finishing: ['working', '[*]', 'confirming with the server'],
  hashing: ['working', '[#]', 'server hashing'],
  stored: ['ok', '[+]', 'stored'],
  duplicate: ['dup', '[=]', 'already stored'],
  skipped: ['skip', '[-]', 'skipped'],
  failed: ['bad', '[!]', 'failed'],
};

// ---------------------------------------------------------------- formatting

function size(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1000) return `${Math.round(bytes)} B`;
  const units = ['kB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let u = -1;
  do {
    v /= 1000;
    u++;
  } while (v >= 1000 && u < units.length - 1);
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[u]}`;
}

const rate = bps => (bps > 0 ? `${size(bps)}/s` : '—');
const percent = (part, whole) => (whole > 0 ? `${((100 * part) / whole).toFixed(part < whole && (100 * part) / whole > 99.9 ? 2 : 1)}%` : '—');

function duration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const s = Math.round(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const pad = n => String(n).padStart(2, '0');
  return h ? `${h}:${pad(m)}:${pad(s % 60)}` : `${m}:${pad(s % 60)}`;
}

function ago(unix) {
  const s = Date.now() / 1000 - unix;
  if (s < 90) return 'just now';
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

const clock = () => new Date().toTimeString().slice(0, 8);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

function decodeBitmap(b64, count) {
  const bytes = Uint8Array.from(atob(b64 ?? ''), c => c.charCodeAt(0));
  const have = new Uint8Array(count);
  for (let i = 0; i < count; i++) have[i] = (bytes[i >> 3] >> (i & 7)) & 1;
  return have;
}

// ---------------------------------------------------------------- notices

let stopped = false;

function banner(html, { warn = false } = {}) {
  const el = $('banner');
  el.className = `error-banner${warn ? ' warn' : ''}`;
  el.innerHTML = html;
  el.hidden = false;
}

const logEntries = [];
function log(text, kind = '') {
  const li = document.createElement('li');
  li.className = kind;
  li.innerHTML = `<time>${clock()}</time><span>${esc(text)}</span>`;
  const list = $('log');
  list.prepend(li);
  logEntries.push(li);
  while (logEntries.length > LOG_MAX) logEntries.shift().remove();
  $('log-count').textContent = logEntries.length;
  $('log-section').hidden = false;
}

// ---------------------------------------------------------------- server state

const server = { failures: 0, downSince: 0, resumeAt: 0, error: null };

function noteFailure(err) {
  server.failures++;
  server.error = err;
  if (!server.downSince && (!err.status || proxyError(err))) {
    server.downSince = Date.now();
    log(`lost contact with the server (${describe(err)}); everything continues by itself once it is back`, 'warn');
  }
}

function noteSuccess() {
  if (server.downSince) log(`the server is back after ${duration((Date.now() - server.downSince) / 1000)}`, 'ok');
  server.failures = 0;
  server.downSince = 0;
  server.error = null;
}

function httpError(status, data, retryAfter) {
  const err = new Error(data?.message || `HTTP ${status}`);
  err.status = status;
  err.code = data?.error;
  err.retryAfter = Number(retryAfter) || 0;
  return err;
}

async function request(method, path, body) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (cause) {
    const err = new Error('server unreachable');
    err.cause = cause;
    noteFailure(err);
    throw err;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = httpError(res.status, data, res.headers.get('retry-after'));
    if (transient(err)) noteFailure(err);
    else noteSuccess();
    linkGone(err);
    throw err;
  }
  noteSuccess();
  return data;
}

// Retry transient failures forever, at most MAX_BACKOFF_S apart.
async function persist(fn, onWait) {
  for (let failures = 1; ; failures++) {
    if (stopped) throw new Error('stopped');
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

// The grant was revoked or the link is wrong: nothing more can happen here.
function linkGone(err) {
  if (stopped || !(err.code === 'revoked' || err.code === 'invalid_link')) return false;
  stopped = true;
  for (const row of rows) for (const slot of row.inflight.values()) slot.xhr?.abort();
  banner(`${esc(err.message)}. Nothing more can be uploaded with it; files already stored stay stored.`);
  $('dropzone').disabled = true;
  $('pick-files').disabled = true;
  $('pick-folder').disabled = true;
  log(err.message, 'bad');
  return true;
}

// ---------------------------------------------------------------- grant

let grant = null;

function applyGrant(info) {
  grant = info;
  $('donor').value = info.name;
  $('grant-label').textContent = `for ${info.name}`;
  $('status-grant').textContent = `credited to ${info.name}`;
  document.title = `fwdonor · bulk donation · ${info.name}`;
  const free = Math.max(0, info.ceiling - info.used - info.reserved);
  $('quota-total').textContent = `${size(info.ceiling)} in total`;
  $('quota-used').textContent = size(info.used);
  $('quota-reserved').textContent = size(info.reserved);
  $('quota-free').textContent = size(free);
  const share = n => `${Math.min(100, (100 * n) / Math.max(1, info.ceiling)).toFixed(2)}%`;
  $('quota-used-bar').style.width = share(info.used);
  $('quota-reserved-bar').style.width = share(info.reserved);
  $('quota-bar').setAttribute('aria-label', `${size(info.used)} stored, ${size(info.reserved)} in progress, ${size(free)} free of ${size(info.ceiling)}`);
  $('quota-files').textContent = info.files ? `${info.files} file${info.files > 1 ? 's' : ''} stored with this link` : '';
  renderUnfinished();
  renderStored();
}

async function refreshGrant() {
  if (stopped) return;
  try {
    applyGrant(await request('GET', API));
  } catch {
    // Unreachable for now: the transfer panel says so.
  }
}

function renderUnfinished() {
  const mine = new Set(rows.filter(r => r.uploadId && !FINAL.has(r.state)).map(r => r.uploadId));
  const list = (grant?.unfinished ?? []).filter(u => !mine.has(u.id));
  $('unfinished').hidden = list.length === 0;
  $('unfinished-count').textContent = list.length;
  $('unfinished-rows').innerHTML = list.map(u => `<tr>
      <td><span class="name" title="${esc(u.path)}">${esc(u.name)}</span>${u.path !== u.name ? `<span class="sub">${esc(u.path)}</span>` : ''}</td>
      <td class="num">${size(u.size)}</td>
      <td class="num">${percent(u.received_bytes, u.size)} <span class="muted">${size(u.received_bytes)}</span></td>
      <td>${ago(u.last_activity)}</td>
      <td><button type="button" class="discard" data-id="${esc(u.id)}">discard</button></td>
    </tr>`).join('');
}

$('unfinished-rows').addEventListener('click', async event => {
  const button = event.target.closest('button.discard');
  if (!button) return;
  const u = grant?.unfinished.find(x => x.id === button.dataset.id);
  if (!u || !confirm(`Discard the unfinished upload of ${u.name} (${percent(u.received_bytes, u.size)} received)?`)) return;
  button.disabled = true;
  try {
    await request('DELETE', `${API}/uploads/${u.id}`);
    log(`discarded the unfinished upload of ${u.path}`);
  } catch (err) {
    if (err.status !== 404) log(`could not discard ${u.path}: ${describe(err)}`, 'bad');
  }
  refreshGrant();
});

function renderStored() {
  const recent = grant?.recent ?? [];
  $('stored').hidden = recent.length === 0;
  $('stored-count').textContent = grant?.files ?? 0;
  $('stored-rows').innerHTML = recent.map(f => `<tr>
      <td><span class="name" title="${esc(f.original_path)}">${esc(f.original_name)}</span></td>
      <td class="num">${size(f.size)}</td>
      <td>${new Date(f.at * 1000).toISOString().slice(0, 16).replace('T', ' ')}</td>
      <td><code class="sha" title="${esc(f.sha256)}">${esc(f.sha256)}</code></td>
    </tr>`).join('');
}

// ---------------------------------------------------------------- rows

const rows = [];
let nextRow = 1;

function newRow(file, path) {
  const row = {
    id: nextRow++,
    file,
    path: path || file.name,
    size: file.size,
    state: 'queued',
    detail: '',
    uploadId: null,
    fresh: false,
    chunkSize: 0,
    chunks: 0,
    have: null,
    pending: [],
    inflight: new Map(),
    doneBytes: 0,
    hashedBytes: 0,
    resumedBytes: 0,
    wire: 0,
    samples: [],
    speed: 0,
    checksumRetries: 0,
    reopen: false,
    sha256: null,
    el: document.createElement('tr'),
    dirty: true,
  };
  row.el.innerHTML = `<td class="st"></td>
    <td><span class="name"></span><span class="sub"></span></td>
    <td class="num size"></td>
    <td class="progress"><div class="progress-line"><span class="bytes"></span><span class="pct"></span></div><canvas class="chunkmap"></canvas></td>
    <td class="num speed"></td><td class="num eta"></td>
    <td><div class="state"><span class="label"></span><small class="detail"></small><code class="sha"></code></div></td>`;
  const q = sel => row.el.querySelector(sel);
  row.ui = {
    st: q('.st'), name: q('.name'), sub: q('.sub'), size: q('.size'), bytes: q('.bytes'), pct: q('.pct'),
    map: q('.chunkmap'), speed: q('.speed'), eta: q('.eta'), label: q('.label'), detail: q('.detail'), sha: q('.sha'),
  };
  row.ui.name.textContent = file.name;
  row.ui.name.title = row.path;
  const dir = row.path.includes('/') ? row.path.slice(0, row.path.lastIndexOf('/')) : '';
  row.ui.sub.textContent = dir;
  row.ui.sub.hidden = !dir;
  row.ui.size.textContent = size(row.size);
  return row;
}

function setState(row, state, detail = '') {
  row.state = state;
  row.detail = detail;
  row.dirty = true;
}

function flightBytes(row) {
  let n = 0;
  for (const slot of row.inflight.values()) n += slot.loaded;
  return n;
}

const COLORS = {};
function readColors() {
  const css = getComputedStyle(document.documentElement);
  for (const [key, name] of [['empty', '--surface-inset'], ['done', '--accent'], ['partial', '--mag-700'],
    ['flight', '--paper-100'], ['hashed', '--sig-ok'], ['line', '--ink-500'], ['dup', '--sig-info']]) {
    COLORS[key] = css.getPropertyValue(name).trim();
  }
}

function drawChunkMap(row) {
  const canvas = row.ui.map;
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
  const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
  if (canvas.width !== w || canvas.height !== h) {
    canvas.width = w;
    canvas.height = h;
  }
  const ctx = canvas.getContext('2d');
  const finished = row.state === 'stored' || row.state === 'duplicate';
  ctx.fillStyle = COLORS.empty;
  ctx.fillRect(0, 0, w, h);
  const bar = h - Math.max(1, Math.round(2 * dpr));
  if (finished) {
    ctx.fillStyle = row.state === 'duplicate' ? COLORS.dup : COLORS.done;
    ctx.fillRect(0, 0, w, bar);
  } else if (row.chunks && row.have) {
    const per = row.chunks / w;
    for (let x = 0; x < w; x++) {
      const from = Math.floor(x * per);
      const to = Math.max(from + 1, Math.floor((x + 1) * per));
      let got = 0;
      let flying = false;
      for (let i = from; i < to && i < row.chunks; i++) {
        got += row.have[i];
        if (row.inflight.has(i)) flying = true;
      }
      const span = Math.min(to, row.chunks) - from;
      if (flying) ctx.fillStyle = COLORS.flight;
      else if (got === span) ctx.fillStyle = COLORS.done;
      else if (got) ctx.fillStyle = COLORS.partial;
      else continue;
      ctx.fillRect(x, 0, 1, bar);
    }
  }
  // Underneath: how far the server's hash of the whole file has come.
  const hashed = finished ? 1 : row.size ? row.hashedBytes / row.size : 0;
  ctx.fillStyle = COLORS.hashed;
  ctx.fillRect(0, bar, Math.round(w * hashed), h - bar);
}

function render(row) {
  const [cls, glyph, label] = LOOK[row.state];
  row.el.className = cls;
  row.ui.st.textContent = glyph;
  const done = row.state === 'stored' || row.state === 'duplicate' ? row.size : row.doneBytes + flightBytes(row);
  row.ui.bytes.textContent = `${size(Math.min(done, row.size))}`;
  row.ui.pct.textContent = percent(Math.min(done, row.size), row.size);
  const moving = row.state === 'uploading' && row.inflight.size > 0;
  row.ui.speed.textContent = moving ? rate(row.speed) : '';
  row.ui.eta.textContent = moving && row.speed > 0 ? duration((row.size - done) / row.speed) : '';
  let text = label;
  if (row.state === 'uploading') text = `uploading · ${row.inflight.size} stream${row.inflight.size === 1 ? '' : 's'}`;
  if (row.state === 'hashing') text = `server hashing ${percent(row.hashedBytes, row.size)}`;
  row.ui.label.textContent = text;
  row.ui.detail.textContent = row.detail;
  row.ui.detail.hidden = !row.detail;
  row.ui.sha.textContent = row.sha256 ?? '';
  row.ui.sha.title = row.sha256 ? 'sha256 (click to copy)' : '';
  row.ui.sha.hidden = !row.sha256;
  drawChunkMap(row);
  row.dirty = false;
}

$('rows').addEventListener('click', event => {
  const sha = event.target.closest('code.sha');
  if (!sha?.textContent) return;
  navigator.clipboard?.writeText(sha.textContent).then(() => {
    sha.classList.add('copied');
    setTimeout(() => sha.classList.remove('copied'), 900);
  }, () => {});
});

// ---------------------------------------------------------------- scheduling

let streams = START_STREAMS;
let maxStreams = MAX_STREAMS;
let fastRun = 0;
let inflight = 0;
let pumpTimer = null;

function pumpLater(ms) {
  if (pumpTimer) return;
  pumpTimer = setTimeout(() => {
    pumpTimer = null;
    pump();
  }, ms);
}

function pump() {
  if (stopped) return;
  const now = Date.now();
  if (server.resumeAt > now) {
    pumpLater(server.resumeAt - now);
  } else {
    while (inflight < streams) {
      const row = rows.find(r => r.state === 'uploading' && !r.reopen && r.pending.length);
      if (!row) break;
      sendChunk(row, row.pending.shift());
    }
  }
  // Open further files while the pool would otherwise run dry.
  const uploading = rows.filter(r => r.state === 'uploading');
  const pendingChunks = uploading.reduce((n, r) => n + r.pending.length, 0);
  const opening = rows.filter(r => r.state === 'opening' || r.state === 'checking').length;
  const open = rows.filter(r => ACTIVE.has(r.state)).length;
  if (pendingChunks < streams && opening < MAX_OPENING && open < MAX_OPEN_FILES) {
    const next = rows.find(r => r.state === 'queued');
    if (next) {
      openFile(next);
      pump();
    }
  }
}

function adaptStreams(ms) {
  if (ms > SLOW_CHUNK_MS && streams > 1) {
    streams--;
    fastRun = 0;
    log(`chunks are slow (${Math.round(ms / 1000)} s each): ${streams} parallel stream${streams > 1 ? 's' : ''} from now on`);
  } else if (ms < FAST_CHUNK_MS) {
    if (++fastRun >= streams * 2 && streams < maxStreams) {
      streams++;
      fastRun = 0;
    }
  } else {
    fastRun = 0;
  }
}

async function sampleMatches(row, samples) {
  for (const [index, expected] of samples) {
    const start = index * row.chunkSize;
    const buf = await row.file.slice(start, Math.min(row.size, start + row.chunkSize)).arrayBuffer();
    if (hex(await crypto.subtle.digest('SHA-256', buf)) !== expected) return false;
  }
  return true;
}

async function openFile(row) {
  setState(row, 'opening');
  try {
    for (;;) {
      const init = await persist(
        () => request('POST', `${API}/uploads`, {
          name: row.file.name,
          path: row.path,
          size: row.size,
          last_modified: row.file.lastModified || null,
          fresh: row.fresh,
        }),
        (err, wait) => setState(row, 'opening', `${describe(err)} · retrying in ${wait}s`),
      );
      row.uploadId = init.id;
      row.chunkSize = init.chunk_size;
      row.chunks = init.chunks;
      if (init.resumed) {
        setState(row, 'checking');
        let same = false;
        try {
          same = await sampleMatches(row, init.samples ?? []);
        } catch (err) {
          throw Object.assign(new Error('the file can no longer be read (moved or changed?)'), { cause: err });
        }
        if (!same) {
          log(`${row.path}: the unfinished upload with this name holds a different file, so this one starts from the beginning`, 'warn');
          row.fresh = true;
          continue;
        }
      }
      row.have = decodeBitmap(init.received, row.chunks);
      row.doneBytes = init.received_bytes;
      row.hashedBytes = init.hashed_bytes;
      row.pending = [];
      for (let i = 0; i < row.chunks; i++) if (!row.have[i]) row.pending.push(i);
      if (init.resumed) {
        row.resumedBytes = init.received_bytes;
        log(`${row.path}: continuing the unfinished upload at ${percent(init.received_bytes, row.size)} (${size(row.size - init.received_bytes)} to go)`, 'ok');
        setState(row, 'uploading', `resumed at ${percent(init.received_bytes, row.size)}`);
      } else {
        setState(row, 'uploading');
      }
      renderUnfinished();
      if (!row.pending.length) finishFile(row);
      return;
    }
  } catch (err) {
    if (stopped) return;
    if (err.code === 'quota') return failRow(row, err.message);
    failRow(row, describe(err));
  } finally {
    pump();
  }
}

function sendChunk(row, index) {
  const slot = { loaded: 0, started: performance.now(), xhr: null };
  row.inflight.set(index, slot);
  inflight++;
  row.dirty = true;
  (async () => {
    const start = index * row.chunkSize;
    const end = Math.min(row.size, start + row.chunkSize);
    let buf;
    try {
      buf = await row.file.slice(start, end).arrayBuffer();
    } catch {
      throw Object.assign(new Error('the file can no longer be read (moved or changed?)'), { unreadable: true });
    }
    const hash = hex(await crypto.subtle.digest('SHA-256', buf));
    await putChunk(row, index, buf, hash, slot);
    row.have[index] = 1;
    row.doneBytes += end - start;
    row.detail = '';
    adaptStreams(performance.now() - slot.started);
  })()
    .catch(err => chunkFailed(row, index, err))
    .finally(() => {
      row.inflight.delete(index);
      inflight--;
      row.dirty = true;
      if (row.reopen && !row.inflight.size) {
        row.reopen = false;
        row.uploadId = null;
        setState(row, 'queued', row.detail);
      } else if (row.state === 'uploading' && !row.pending.length && !row.inflight.size) {
        finishFile(row);
      }
      pump();
    });
}

function putChunk(row, index, buf, hash, slot) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    slot.xhr = xhr;
    xhr.open('PUT', `${API}/uploads/${row.uploadId}/${index}`);
    xhr.setRequestHeader('content-type', 'application/octet-stream');
    xhr.setRequestHeader('x-chunk-sha256', hash);
    xhr.timeout = CHUNK_TIMEOUT_MS;
    const count = loaded => {
      const delta = loaded - slot.loaded;
      if (delta <= 0) return;
      slot.loaded = loaded;
      row.wire += delta;
      wire += delta;
    };
    xhr.upload.onprogress = event => count(event.loaded);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        count(buf.byteLength);
        noteSuccess();
        resolve();
        return;
      }
      let data = {};
      try {
        data = JSON.parse(xhr.responseText);
      } catch {}
      const err = httpError(xhr.status, data, xhr.getResponseHeader('retry-after'));
      if (transient(err)) noteFailure(err);
      else noteSuccess();
      reject(err);
    };
    xhr.onerror = () => {
      const err = new Error('server unreachable');
      noteFailure(err);
      reject(err);
    };
    xhr.ontimeout = () => {
      const err = new Error('chunk timed out');
      err.timeout = true;
      noteFailure(err);
      reject(err);
    };
    xhr.onabort = () => reject(Object.assign(new Error('aborted'), { aborted: true }));
    xhr.send(buf);
  });
}

function chunkFailed(row, index, err) {
  if (stopped || err.aborted) return;
  if (linkGone(err)) return;
  // Already starting over or given up: the other chunks' errors add nothing.
  if (row.reopen || row.state !== 'uploading') return;
  if (err.unreadable) return failRow(row, err.message);
  if (err.timeout || err.status === 408) {
    const before = streams;
    streams = Math.max(1, Math.floor(streams / 2));
    fastRun = 0;
    if (streams < before) log(`a chunk timed out: ${streams} parallel stream${streams > 1 ? 's' : ''} from now on`, 'warn');
  }
  if (transient(err) || err.timeout) {
    row.pending.unshift(index);
    const wait = err.status === 429 ? Math.max(1, err.retryAfter) : backoff(server.failures, err.retryAfter);
    server.resumeAt = Math.max(server.resumeAt, Date.now() + wait * 1000);
    row.detail = `${describe(err)} · retrying in ${wait}s`;
    return;
  }
  if (err.code === 'checksum') {
    row.pending.unshift(index);
    if (++row.checksumRetries > CHECKSUM_RETRIES) return failRow(row, 'chunks keep arriving damaged; check the connection and drop the file again');
    log(`${row.path}: chunk ${index} arrived damaged, sending it again`, 'warn');
    return;
  }
  if (err.code === 'changed') {
    log(`${row.path}: the file changed since its upload began, so it starts again from the beginning`, 'warn');
    const id = row.uploadId;
    request('DELETE', `${API}/uploads/${id}`).catch(() => {});
    row.fresh = true;
    return reopen(row, 'the file changed · starting again');
  }
  if (err.code === 'state') {
    // Complete already (all chunks arrived through another request).
    row.have[index] = 1;
    return;
  }
  if (err.status === 404) {
    log(`${row.path}: the server no longer has this upload (expired or discarded); starting it again`, 'warn');
    return reopen(row, 'the server lost this upload · starting again');
  }
  failRow(row, describe(err));
}

// Drop the current upload id once the chunks still in flight are back, then
// open the file again (which resumes whatever the server still has).
function reopen(row, detail) {
  row.pending = [];
  row.detail = detail;
  if (row.inflight.size) row.reopen = true;
  else {
    row.uploadId = null;
    setState(row, 'queued', detail);
  }
}

function failRow(row, message) {
  for (const slot of row.inflight.values()) slot.xhr?.abort();
  row.pending = [];
  setState(row, 'failed', message);
  log(`${row.path}: ${message}`, 'bad');
  pump();
}

async function finishFile(row) {
  if (row.state === 'finishing' || row.state === 'hashing') return;
  setState(row, 'finishing');
  for (let polls = 0; ; polls++) {
    let st;
    try {
      st = await persist(
        () => request('GET', `${API}/uploads/${row.uploadId}`),
        (err, wait) => { row.detail = `${describe(err)} · retrying in ${wait}s`; row.dirty = true; },
      );
    } catch (err) {
      if (stopped) return;
      if (err.status === 404) return reopen(row, 'the server lost this upload · starting again');
      return failRow(row, describe(err));
    }
    row.hashedBytes = st.hashed_bytes;
    row.detail = '';
    if (st.state === 'stored' || st.state === 'duplicate') {
      row.sha256 = st.sha256;
      row.doneBytes = row.size;
      setState(row, st.state, st.state === 'duplicate' ? 'the server already had this exact file; it does not count against the quota' : '');
      log(st.state === 'stored'
        ? `${row.path}: stored (${size(row.size)}, sha256 ${st.sha256.slice(0, 16)}…)`
        : `${row.path}: the server already had this file (sha256 ${st.sha256.slice(0, 16)}…)`, st.state === 'stored' ? 'ok' : '');
      refreshGrant();
      pump();
      return;
    }
    if (st.state === 'receiving') {
      const have = decodeBitmap(st.received, row.chunks);
      const missing = [];
      for (let i = 0; i < row.chunks; i++) if (!have[i]) missing.push(i);
      if (missing.length) {
        row.have = have;
        row.doneBytes = st.received_bytes;
        row.pending = missing;
        log(`${row.path}: the server asked for ${missing.length} chunk${missing.length > 1 ? 's' : ''} again`, 'warn');
        setState(row, 'uploading');
        pump();
        return;
      }
    }
    setState(row, 'hashing');
    // Small files are stored within moments: look again soon, then calmly.
    await sleep(Math.min(POLL_MS, 100 * 2 ** polls));
  }
}

// ---------------------------------------------------------------- live numbers

let wire = 0;
// Time with chunks in flight (for the average) and with anything to do.
let activeMs = 0;
let busyMs = 0;
let lastProgressPoll = 0;
const wireSamples = [];
const spark = new Array(SPARK_SECONDS).fill(0);
let sparkSecond = 0;
let sparkWire = 0;
let lastTick = performance.now();
let wakeLock = null;

function speedOf(samples, now, value) {
  samples.push([now, value]);
  while (samples.length > 2 && now - samples[0][0] > SPEED_WINDOW_MS) samples.shift();
  const [t0, v0] = samples[0];
  return now > t0 ? ((value - v0) * 1000) / (now - t0) : 0;
}

function totals() {
  let total = 0;
  let done = 0;
  let stored = 0;
  let counted = 0;
  for (const r of rows) {
    if (r.state === 'skipped') continue;
    counted++;
    if (r.state === 'failed') continue;
    total += r.size;
    if (r.state === 'stored' || r.state === 'duplicate') {
      done += r.size;
      stored++;
    } else {
      done += Math.min(r.size, r.doneBytes + flightBytes(r));
    }
  }
  return { total, done, stored, counted };
}

function drawSpark() {
  const canvas = $('spark');
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
  const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
  if (canvas.width !== w || canvas.height !== h) {
    canvas.width = w;
    canvas.height = h;
  }
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const peak = Math.max(...spark, 1);
  ctx.fillStyle = COLORS.partial;
  ctx.strokeStyle = COLORS.done;
  ctx.lineWidth = Math.max(1, dpr);
  ctx.beginPath();
  ctx.moveTo(0, h);
  for (let i = 0; i < SPARK_SECONDS; i++) ctx.lineTo((i / (SPARK_SECONDS - 1)) * w, h - (spark[i] / peak) * (h - 2 * dpr));
  ctx.lineTo(w, h);
  ctx.closePath();
  ctx.globalAlpha = 0.5;
  ctx.fill();
  ctx.globalAlpha = 1;
  ctx.stroke();
  $('spark-label').textContent = peak > 1 ? `peak ${rate(peak)} · last ${SPARK_SECONDS / 60} min` : '';
}

async function holdWake(active) {
  if (active && !wakeLock && document.visibilityState === 'visible' && navigator.wakeLock) {
    try {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } catch {
      // Not allowed (battery saver, …): uploads go on regardless.
    }
  } else if (!active && wakeLock) {
    wakeLock.release().catch(() => {});
    wakeLock = null;
  }
}

function tick() {
  const now = performance.now();
  const moving = inflight > 0;
  const anyActive = rows.some(r => ACTIVE.has(r.state) || r.state === 'queued');
  if (moving) activeMs += now - lastTick;
  if (anyActive) busyMs += now - lastTick;
  lastTick = now;
  if (now - lastProgressPoll > PROGRESS_POLL_MS) {
    lastProgressPoll = now;
    pollProgress();
  }
  const speed = speedOf(wireSamples, now, wire);
  for (const row of rows) {
    if (row.state !== 'uploading') continue;
    row.speed = speedOf(row.samples, now, row.wire);
    row.dirty = true;
  }
  const second = Math.floor(now / 1000);
  if (second !== sparkSecond) {
    if (sparkSecond) {
      for (let s = sparkSecond; s < second; s++) {
        spark.shift();
        spark.push(s === sparkSecond ? wire - sparkWire : 0);
      }
    }
    sparkSecond = second;
    sparkWire = wire;
  }

  const t = totals();
  $('transfer').hidden = rows.length === 0;
  $('t-done').textContent = size(t.done);
  $('t-total').textContent = size(t.total);
  $('t-pct').textContent = percent(t.done, t.total);
  $('t-speed').textContent = moving ? rate(speed) : '—';
  const avg = activeMs > 1000 ? (wire * 1000) / activeMs : 0;
  $('t-avg').textContent = rate(avg);
  const pace = speed > 0 ? speed : avg;
  $('t-eta').textContent = anyActive && pace > 0 ? duration((t.total - t.done) / pace) : '—';
  $('t-elapsed').textContent = duration(busyMs / 1000);
  $('t-files').textContent = `${t.stored} / ${t.counted}`;
  $('t-progress').max = Math.max(1, t.total);
  $('t-progress').value = t.done;
  $('streams').textContent = `${inflight} of ${streams} stream${streams > 1 ? 's' : ''} busy · ${size(wire)} sent this session`;

  const state = $('server-state');
  const wait = Math.max(0, Math.ceil((server.resumeAt - Date.now()) / 1000));
  if (stopped) {
    state.className = 'pill bad';
    state.textContent = 'stopped';
  } else if (server.downSince) {
    state.className = 'pill bad';
    state.textContent = `server unreachable for ${duration((Date.now() - server.downSince) / 1000)}${wait ? ` · retrying in ${wait}s` : ''}`;
  } else if (server.failures) {
    state.className = 'pill warn';
    state.textContent = `${describe(server.error)}${wait ? ` · retrying in ${wait}s` : ''}`;
  } else {
    state.className = 'pill ok';
    state.textContent = 'connected';
  }
  drawSpark();

  for (const row of rows) if (row.dirty) render(row);
  summarize(t, anyActive);
  holdWake(anyActive && moving);
}

// How far the server's whole-file hash has come, for the chunk maps (it
// follows the received part of each file while the upload runs).
async function pollProgress() {
  const uploading = rows.filter(r => r.state === 'uploading' && r.uploadId && !r.reopen).slice(0, 4);
  await Promise.all(uploading.map(async row => {
    try {
      const res = await fetch(`${API}/uploads/${row.uploadId}`);
      if (!res.ok) return;
      const st = await res.json();
      row.hashedBytes = st.hashed_bytes;
      row.dirty = true;
    } catch {
      // The chunk requests notice outages themselves.
    }
  }));
}

function summarize(t, anyActive) {
  const count = state => rows.filter(r => r.state === state).length;
  $('count').textContent = rows.length;
  $('results').hidden = rows.length === 0;
  const parts = [
    ['stored', count('stored')],
    ['in progress', rows.filter(r => ACTIVE.has(r.state)).length],
    ['queued', count('queued')],
    ['already stored', count('duplicate')],
    ['skipped', count('skipped')],
    ['failed', count('failed')],
  ].filter(([, n]) => n > 0);
  $('tallies').innerHTML = parts.map(([k, n]) => `<span><b>${n}</b> ${k}</span>`).join('');
  $('retry').hidden = count('failed') === 0;
  let status = 'ready';
  if (stopped) status = 'this link no longer works';
  else if (server.downSince) status = 'waiting for the server';
  else if (anyActive) status = `uploading · ${percent(t.done, t.total)} of ${size(t.total)}`;
  else if (rows.length) status = 'idle';
  $('status').textContent = status;
}

// ---------------------------------------------------------------- input

function enqueue(items) {
  if (stopped || !items.length) return;
  const fragment = document.createDocumentFragment();
  let added = 0;
  for (const { file, path } of items) {
    const p = path || file.name;
    const twin = rows.find(r => r.path === p && r.size === file.size && r.file.lastModified === file.lastModified && r.state !== 'failed');
    if (twin) continue;
    const row = newRow(file, p);
    if (file.size === 0) setState(row, 'skipped', 'empty file');
    rows.push(row);
    fragment.appendChild(row.el);
    added++;
  }
  $('rows').appendChild(fragment);
  if (added) log(`added ${added} file${added > 1 ? 's' : ''} (${size(items.reduce((n, i) => n + i.file.size, 0))})`);
  for (const row of rows) if (row.dirty) render(row);
  pump();
}

let dragDepth = 0;
const overlay = $('drag-overlay');
const hasFiles = event => [...(event.dataTransfer?.types ?? [])].includes('Files');
window.addEventListener('dragenter', event => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  dragDepth++;
  overlay.hidden = stopped;
});
window.addEventListener('dragover', event => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = stopped ? 'none' : 'copy';
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
const folderInput = $('folderinput');
$('dropzone').addEventListener('click', () => fileInput.click());
$('pick-files').addEventListener('click', () => fileInput.click());
$('pick-folder').addEventListener('click', () => folderInput.click());
for (const input of [fileInput, folderInput]) {
  input.addEventListener('change', () => {
    enqueue([...input.files].map(file => ({ file, path: file.webkitRelativePath || file.name })));
    input.value = '';
  });
}

$('retry').addEventListener('click', () => {
  for (const row of rows) {
    if (row.state !== 'failed') continue;
    row.uploadId = null;
    row.checksumRetries = 0;
    setState(row, 'queued');
  }
  pump();
});

$('clear').addEventListener('click', () => {
  for (let i = rows.length - 1; i >= 0; i--) {
    if (['stored', 'duplicate', 'skipped'].includes(rows[i].state)) {
      rows[i].el.remove();
      rows.splice(i, 1);
    }
  }
});

window.addEventListener('beforeunload', event => {
  if (rows.some(r => ACTIVE.has(r.state) || r.state === 'queued')) event.preventDefault();
});
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') holdWake(inflight > 0);
});

// ---------------------------------------------------------------- boot

async function boot() {
  readColors();
  setInterval(tick, TICK_MS);
  let info;
  try {
    info = await persist(
      () => request('GET', API),
      (err, wait) => { $('status').textContent = `waiting for the server · ${describe(err)} · retrying in ${wait}s`; },
    );
  } catch (err) {
    if (!stopped) banner(`This link could not be loaded: ${esc(describe(err))}`);
    return;
  }
  maxStreams = Math.max(1, Math.min(MAX_STREAMS, info.max_streams || MAX_STREAMS));
  streams = Math.min(streams, maxStreams);
  applyGrant(info);
  setInterval(refreshGrant, GRANT_REFRESH_MS);
}

boot();
