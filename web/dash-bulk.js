// Dashboard bulk view (/d/<key>/bulk): the bulk links (without their tokens
// or notes), uploads in progress with speed and a chunk map, and every stored
// bulk file as a tree of grants and folders plus a table.
import { $, API, KEY, api, esc, size, num, time, ago, copy, widths, setTabs, poll, banner, rate, duration } from './dash-common.js';

const STALLED_SECS = 120;
let view = null;
let grant = null;
let folder = null;
let query = '';
let sort = ['completed_at', true];
// Upload id → { at, received, hashed, speed } for speeds between polls.
const seen = new Map();

const COLS = [
  { key: 'name', label: 'name' },
  { key: 'grant_name', label: 'link' },
  { key: 'size', label: 'size', num: true },
  { key: 'sha256', label: 'sha256' },
  { key: 'completed_at', label: 'stored' },
  { key: 'duration', label: 'took', num: true },
  { key: 'speed', label: 'avg speed', num: true },
  { key: 'last_modified', label: 'modified' },
  { key: 'actions', label: '' },
];

function drawChunks(canvas, b64, chunks) {
  const bytes = Uint8Array.from(atob(b64 || ''), c => c.charCodeAt(0));
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
  const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  const css = getComputedStyle(document.documentElement);
  ctx.fillStyle = css.getPropertyValue('--ink-600').trim() || '#2e2823';
  ctx.fillRect(0, 0, w, h);
  ctx.fillStyle = css.getPropertyValue('--accent').trim() || '#ff3d8b';
  const has = i => (bytes[i >> 3] >> (i & 7)) & 1;
  for (let x = 0; x < w; x++) {
    const a = Math.floor((x * chunks) / w);
    const b = Math.max(a + 1, Math.floor(((x + 1) * chunks) / w));
    let n = 0;
    for (let i = a; i < b; i++) n += has(i);
    if (!n) continue;
    ctx.globalAlpha = n / (b - a);
    ctx.fillRect(x, 0, 1, h);
  }
  ctx.globalAlpha = 1;
}

function folderOf(path) {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

function filtered() {
  if (!view) return [];
  const needle = query.toLowerCase();
  return view.files.filter(f => (!grant || f.grant === grant)
    && (folder == null || folderOf(f.path) === folder || folderOf(f.path).startsWith(`${folder}/`))
    && (!needle || `${f.name}\n${f.path}\n${f.sha256}\n${f.grant_name}`.toLowerCase().includes(needle)));
}

function value(f, key) {
  switch (key) {
    case 'duration': return f.started_at ? f.completed_at - f.started_at : -1;
    case 'speed': return f.started_at && f.completed_at > f.started_at ? f.size / (f.completed_at - f.started_at) : -1;
    default: return f[key] ?? '';
  }
}

function renderStats(v) {
  const files = v.files.length;
  const bytes = v.files.reduce((a, f) => a + f.size, 0);
  $('s-files').textContent = num(files);
  $('s-files-sub').textContent = `bulk files stored · ${size(bytes)}`;
  const open = v.grants.filter(g => !g.revoked_at).length;
  $('s-links').textContent = num(open);
  $('s-links-sub').textContent = `open links${v.grants.length > open ? ` · ${v.grants.length - open} revoked` : ''}`;
  $('s-active').textContent = num(v.uploads.length);
  const active = v.uploads.filter(u => v.now - u.last_activity < STALLED_SECS).length;
  $('s-active-sub').textContent = `uploads in progress · ${num(active)} active`;
  const speed = v.uploads.reduce((a, u) => a + (seen.get(u.id)?.speed || 0), 0);
  $('s-speed').textContent = rate(speed);
  $('s-disk').textContent = size(v.disk.free);
  $('s-disk-sub').textContent = `free of ${size(v.disk.total)} · keeps ${size(v.disk.min_free)}`;
  $('s-claim').textContent = size(v.claimable);
  $('s-claim').classList.toggle('over', v.claimable + v.disk.min_free > v.disk.free);
  $('updated').textContent = `updated ${time(v.now, { seconds: true }).slice(11)}`;
  $('status').textContent = `${num(files)} files, ${size(bytes)} · ${num(v.uploads.length)} in progress`;
  const dir = v.dir;
  $('rsync-cmd').textContent = `rsync -a --partial --files-from=fwdonor-bulk.files.txt <server>:${dir}/ ./bulk/`;
}

function renderGrants(v) {
  $('grant-count').textContent = num(v.grants.length);
  $('grant-rows').innerHTML = v.grants.map(g => {
    const share = n => Math.min(100, (100 * n) / Math.max(1, g.ceiling)).toFixed(2);
    return `<tr data-grant="${esc(g.id)}" class="${g.revoked_at ? 'revoked' : ''} ${grant === g.id ? 'opened' : ''}">
      <td><strong>${esc(g.name)}</strong></td><td><code>${esc(g.id)}</code></td><td class="num">${size(g.ceiling)}</td>
      <td><div class="mini-quota"><i class="used" data-w="${share(g.used)}"></i><i class="reserved" data-w="${share(g.reserved)}"></i></div>
        <small>${size(g.used)}${g.reserved ? ` + ${size(g.reserved)} in progress` : ''} · ${share(g.used + g.reserved)}%</small></td>
      <td class="num">${num(g.files)}</td><td class="num">${num(g.unfinished)}</td><td>${time(g.created_at)}</td>
      <td>${g.last_at ? `${time(g.last_at)}<br><small>${ago(g.last_at, v.now)}</small>` : '–'}</td>
      <td>${g.revoked_at ? `<span class="pill bad">revoked</span><br><small>${time(g.revoked_at)}</small>` : '<span class="pill ok">open</span>'}</td></tr>`;
  }).join('') || '<tr><td colspan="9" class="muted">No bulk links yet.</td></tr>';
  widths($('grant-rows'));
}

function renderUploads(v) {
  const ups = v.uploads.filter(u => !grant || u.grant === grant);
  $('up-count').textContent = num(ups.length);
  $('up-rows').innerHTML = ups.map(u => {
    const s = seen.get(u.id) ?? {};
    const pct = (100 * u.received_bytes) / Math.max(1, u.size);
    const hashed = (100 * u.hashed_bytes) / Math.max(1, u.size);
    const idle = v.now - u.last_activity;
    const stalled = idle >= STALLED_SECS && u.received_bytes < u.size;
    const eta = s.speed > 0 ? (u.size - u.received_bytes) / s.speed : NaN;
    return `<tr data-up="${esc(u.id)}" class="${stalled ? 'stalled' : ''}">
      <td>${esc(u.grant_name)}</td>
      <td><span class="name" title="${esc(u.path)}">${esc(u.name)}</span><span class="sub">${esc(u.path !== u.name ? u.path : '')} ${u.phase}</span></td>
      <td class="num">${size(u.size)}</td>
      <td class="progress"><div class="progress-line"><span>${size(u.received_bytes)}</span><span>${pct.toFixed(1)}%</span></div>
        <canvas class="chunkmap" data-b64="${u.received}" data-chunks="${u.chunks}"></canvas></td>
      <td><div class="meter"><i data-w="${hashed.toFixed(1)}"></i></div><small>${hashed.toFixed(0)}%</small></td>
      <td class="num">${rate(s.speed)}</td><td class="num">${stalled ? '<span class="pill warn">stalled</span>' : duration(eta)}</td>
      <td class="num">${u.streams}</td><td>${time(u.started_at)}</td><td>${ago(u.last_activity, v.now)}</td></tr>`;
  }).join('') || '<tr><td colspan="10" class="muted">Nothing is being uploaded.</td></tr>';
  widths($('up-rows'));
  for (const c of $('up-rows').querySelectorAll('canvas.chunkmap')) drawChunks(c, c.dataset.b64, Number(c.dataset.chunks));
}

function renderTree(v) {
  // Grants › folders, with file counts and bytes.
  const root = new Map();
  for (const f of v.files) {
    const g = root.get(f.grant) ?? { label: f.grant_name, id: f.grant, files: 0, bytes: 0, kids: new Map() };
    root.set(f.grant, g);
    g.files++;
    g.bytes += f.size;
    let node = g;
    let acc = '';
    for (const part of folderOf(f.path).split('/').filter(Boolean)) {
      acc = acc ? `${acc}/${part}` : part;
      const kid = node.kids.get(part) ?? { label: part, path: acc, files: 0, bytes: 0, kids: new Map() };
      node.kids.set(part, kid);
      kid.files++;
      kid.bytes += f.size;
      node = kid;
    }
  }
  const build = (nodes, gid) => [...nodes].sort((a, b) => b.bytes - a.bytes).map(n => {
    const isGrant = n.id != null;
    const on = isGrant ? grant === n.id && folder == null : grant === gid && folder === n.path;
    return `<li role="treeitem" class="${on ? 'on' : ''}"><div class="node" data-grant="${esc(isGrant ? n.id : gid)}" ${isGrant ? '' : `data-folder="${esc(n.path)}"`}>
      <span class="twisty">${n.kids.size ? '▾' : '·'}</span><span class="lbl">${esc(n.label)}</span><span class="n">${num(n.files)} · ${size(n.bytes)}</span></div>
      ${n.kids.size ? `<ul role="group">${build(n.kids.values(), isGrant ? n.id : gid)}</ul>` : ''}</li>`;
  }).join('');
  $('tree').innerHTML = build(root.values(), null) || '<li class="muted">no files yet</li>';
}

function renderFiles() {
  const files = filtered().sort((a, b) => {
    const [key, desc] = sort;
    const x = value(a, key);
    const y = value(b, key);
    const o = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
    return desc ? -o : o;
  });
  $('file-count').textContent = num(files.length);
  $('file-sel').textContent = `${size(files.reduce((a, f) => a + f.size, 0))}${grant ? ` · link ${view.grants.find(g => g.id === grant)?.name ?? grant}` : ''}${folder != null ? ` · ${folder || '/'}` : ''}`;
  $('file-head').innerHTML = `<tr>${COLS.map(c => `<th class="${c.num ? 'num' : ''} ${c.key !== 'actions' ? 'sortable' : ''} ${sort[0] === c.key ? (sort[1] ? 'desc' : 'asc') : ''}" data-sort="${c.key}">${esc(c.label)}${sort[0] === c.key ? ` <i>${sort[1] ? '↓' : '↑'}</i>` : ''}</th>`).join('')}</tr>`;
  $('file-rows').innerHTML = files.slice(0, 2000).map(f => {
    const took = value(f, 'duration');
    const speed = value(f, 'speed');
    return `<tr><td><span class="name" title="${esc(f.path)}">${esc(f.name)}</span><span class="sub">${esc(f.path !== f.name ? f.path : '')}</span></td>
      <td>${esc(f.grant_name)}</td><td class="num">${size(f.size)}</td>
      <td><code class="sha" data-copy="${f.sha256}" title="copy">${f.sha256.slice(0, 16)}</code></td>
      <td>${time(f.completed_at)}</td><td class="num">${took >= 0 ? duration(took) : '–'}</td><td class="num">${speed >= 0 ? rate(speed) : '–'}</td>
      <td>${f.last_modified ? time(Math.floor(f.last_modified / 1000)) : '–'}</td>
      <td><div class="actions"><a class="button" href="${API}/bulk/${f.sha256}/download" download>download</a>
        <button type="button" data-copy="${esc(`${view.dir}/${f.sha256}`)}">path</button>
        <button type="button" data-curl="${f.sha256}" data-name="${esc(f.name)}">curl</button>
        ${f.in_firmware ? `<a href="/d/${KEY}#open=${f.sha256}&q=${f.sha256}" title="also donated as firmware">firmware ↗</a>` : ''}</div></td></tr>`;
  }).join('') || '<tr><td colspan="9" class="muted">No stored file matches.</td></tr>';
  const p = new URLSearchParams();
  if (grant) p.set('grant', grant);
  for (const [id, as] of [['x-csv', 'csv'], ['x-ndjson', 'ndjson'], ['x-sum', 'sha256sum'], ['x-rsync', 'rsync']]) {
    p.set('as', as);
    $(id).href = `${API}/bulk/export?${p}`;
  }
}

function render() {
  if (!view) return;
  renderStats(view);
  renderGrants(view);
  renderUploads(view);
  renderTree(view);
  renderFiles();
}

async function refresh() {
  let v;
  try {
    v = await api('/bulk');
    banner(null);
  } catch (err) {
    banner(err);
    throw err;
  }
  for (const u of v.uploads) {
    const s = seen.get(u.id);
    if (s && v.now > s.at) {
      const inst = Math.max(0, (u.received_bytes - s.received) / (v.now - s.at));
      s.speed = s.speed == null ? inst : 0.6 * s.speed + 0.4 * inst;
      s.at = v.now;
      s.received = u.received_bytes;
    } else if (!s) {
      seen.set(u.id, { at: v.now, received: u.received_bytes, speed: null });
    }
  }
  for (const id of seen.keys()) if (!v.uploads.some(u => u.id === id)) seen.delete(id);
  view = v;
  render();
}

setTabs();
document.addEventListener('tzchange', render);
$('grant-rows').addEventListener('click', ev => {
  const tr = ev.target.closest('tr[data-grant]');
  if (!tr) return;
  grant = grant === tr.dataset.grant ? null : tr.dataset.grant;
  folder = null;
  render();
});
$('tree').addEventListener('click', ev => {
  const n = ev.target.closest('.node');
  if (!n) return;
  const f = n.dataset.folder ?? null;
  if (grant === n.dataset.grant && folder === f) {
    grant = null;
    folder = null;
  } else {
    grant = n.dataset.grant;
    folder = f;
  }
  render();
});
$('folder-clear').addEventListener('click', () => {
  grant = null;
  folder = null;
  render();
});
$('search').addEventListener('input', () => {
  query = $('search').value.trim();
  renderFiles();
});
$('file-head').addEventListener('click', ev => {
  const th = ev.target.closest('[data-sort]');
  if (!th || th.dataset.sort === 'actions') return;
  const key = th.dataset.sort;
  sort = [key, sort[0] === key ? !sort[1] : ['size', 'completed_at', 'duration', 'speed', 'last_modified'].includes(key)];
  renderFiles();
});
$('file-rows').addEventListener('click', ev => {
  const c = ev.target.closest('[data-copy]');
  if (c) return copy(c.dataset.copy, c.tagName === 'BUTTON' ? c : null);
  const curl = ev.target.closest('[data-curl]');
  if (curl) {
    const url = `${location.origin}${API}/bulk/${curl.dataset.curl}/download`;
    const name = curl.dataset.name.replace(/'/g, "'\\''");
    copy(`until curl -fC - -o '${name}' '${url}'; do sleep 5; done`, curl);
  }
});
poll(refresh, 5000);
