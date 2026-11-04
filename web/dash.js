// Firmware dashboard (/d/<key>): every donated image, as a tree keyed by ISA
// (or any other dimensions), facets, charts, a matrix, a sortable table and a
// detail view with an entropy profile, hex and strings. All filtering happens
// on the server (/api/dash/<key>/query); the view lives in the URL hash.
import {
  $, API, KEY, PUBLIC, api, esc, size, num, time, ago, copy, saveText, widths, setTabs, histogram, poll, banner, svg, rate, pointer,
} from './dash-common.js';

const DIM_LABELS = {
  kind: 'kind', isa: 'ISA', family: 'family', format: 'format', variant: 'variant', donor: 'donor', ext: 'extension', bits: 'bits',
  endian: 'endianness', class: 'zrax source', basis: 'accepted for', origin: 'origin', status: 'status',
  zrax: 'zrax version', month: 'month', day: 'day',
};
const FILTER_DIMS = ['kind', 'isa', 'family', 'format', 'variant', 'donor', 'ext', 'bits', 'endian', 'class', 'basis', 'origin', 'status', 'zrax'];
// The public dashboard has no origin or store status (operational).
const HIDDEN_DIMS = PUBLIC ? ['origin', 'status'] : [];
const FACETS = ['kind', 'donor', 'format', 'status', 'origin', 'bits', 'endian', 'ext', 'class', 'basis', 'variant', 'zrax'].filter(d => !HIDDEN_DIMS.includes(d));
const TIME_DIMS = ['month', 'day'];
const FACET_SHOWN = 10;

const ALL_COLUMNS = [
  { key: 'name', label: 'name', sort: 'name', def: true },
  { key: 'isa', label: 'ISA', sort: 'isa', def: true },
  { key: 'bits', label: 'bits', sort: 'bits', def: true },
  { key: 'format', label: 'format', sort: 'format', def: true },
  { key: 'size', label: 'size', sort: 'size', def: true, num: true },
  { key: 'donor', label: 'donor', sort: 'donor', def: true },
  { key: 'received', label: 'received', sort: 'time', def: true },
  { key: 'status', label: 'status', sort: 'status', def: true },
  { key: 'sha', label: 'sha256', sort: 'sha' },
  { key: 'family', label: 'family', sort: 'family' },
  { key: 'variant', label: 'variant', sort: 'variant' },
  { key: 'conf', label: 'confidence', sort: 'conf', num: true },
  { key: 'class', label: 'zrax source', sort: 'class' },
  { key: 'basis', label: 'accepted for', sort: 'basis' },
  { key: 'slices', label: 'slices', sort: 'slices', num: true },
  { key: 'origin', label: 'origin', sort: 'origin' },
  { key: 'posted', label: 'posted', sort: 'posted' },
  { key: 'telegram', label: 'telegram' },
  { key: 'zrax', label: 'zrax', sort: 'zrax' },
  { key: 'ext', label: 'ext.', sort: 'ext' },
  { key: 'kind', label: 'kind', sort: 'kind' },
];
const COLUMNS = ALL_COLUMNS.filter(c => !HIDDEN_DIMS.includes(c.key));
const PREF_COLUMNS = PUBLIC ? 'fwdonor.dashboard.columns' : 'fwdonor.dash.columns';
const PREF_LIMIT = 'fwdonor.dash.limit';

// Firmware, or the programs, libraries, object files and packages people
// donate too: the scope switch picks one side (firmware by default).
const SCOPES = [
  { key: 'firmware', label: 'firmware', title: 'Firmware images only', f: () => ({ in: ['firmware'], out: [] }) },
  { key: 'other', label: 'other binaries', title: 'Programs, shared libraries, object files and software packages', f: () => ({ in: [], out: ['firmware'] }) },
  { key: 'all', label: 'all', title: 'Everything donated', f: () => ({ in: [], out: [] }) },
];
const KIND_PLURAL = { firmware: 'firmware', program: 'programs', library: 'shared libraries', object: 'object files', package: 'software packages' };
const sameFilter = (a, b) => a.in.length === b.in.length && a.out.length === b.out.length
  && a.in.every(x => b.in.includes(x)) && a.out.every(x => b.out.includes(x));
const kindFilter = s => s.f.kind ?? { in: [], out: [] };
// The scope a kind filter is (exactly), if any.
const exactScope = s => SCOPES.find(sc => sameFilter(kindFilter(s), sc.f()))?.key ?? null;
// The scope button to light up: "other" also for narrower non-firmware picks.
function scopeOf(s) {
  const f = kindFilter(s);
  const exact = exactScope(s);
  if (exact) return exact;
  return !f.in.includes('firmware') && (f.in.length || f.out.includes('firmware')) ? 'other' : null;
}

const endianShort = e => ({ little: 'LE', big: 'BE', bi: 'bi', mixed: 'mixed' }[e] ?? e ?? '');
// Whether the file is in the store (downloadable).
const isStored = r => (PUBLIC ? r.stored : r.status === 'stored' || r.status === 'queued');

// ------------------------------------------------------------------ state

const blank = () => ({
  q: '', f: { kind: SCOPES[0].f() }, isaMode: 'any', multi: false, size: null, time: null, conf: null,
  sort: [['time', true]], page: 0, limit: Number(localStorage.getItem(PREF_LIMIT)) || 100,
  tree: ['family', 'isa', 'format'], matrix: ['isa', 'format'], open: null,
});
let state = blank();
let data = null;
let summary = null;
let live = true;
let treeMetric = 'files';
let histMetric = 'files';
let openedAt = 0;
let cursor = -1;
let columns = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(PREF_COLUMNS));
    if (Array.isArray(saved) && saved.length) return saved.filter(k => COLUMNS.some(c => c.key === k));
  } catch {}
  return COLUMNS.filter(c => c.def).map(c => c.key);
})();
const selected = new Map();
let lastChecked = -1;
const expanded = new Set();
const openFacets = new Set();
const labels = {};

function rangeParam(r) {
  return `${r[0] ?? ''}..${r[1] ?? ''}`;
}

function filterParams(s) {
  const p = new URLSearchParams();
  if (s.q) p.set('q', s.q);
  for (const d of FILTER_DIMS) {
    const f = s.f[d];
    if (f && (f.in.length || f.out.length)) p.set(d, [...f.in, ...f.out.map(x => `!${x}`)].join(','));
  }
  if (s.isaMode !== 'any') p.set('isa_mode', s.isaMode);
  if (s.multi) p.set('multi', '1');
  for (const r of ['size', 'time', 'conf']) if (s[r]) p.set(r, rangeParam(s[r]));
  p.set('sort', s.sort.map(([k, desc]) => `${k}:${desc ? 'desc' : 'asc'}`).join(','));
  return p;
}

function hashOf(s) {
  const p = filterParams(s);
  // No kind means firmware (the default view), so "everything" is spelled out.
  const scope = exactScope(s);
  if (scope === 'firmware') p.delete('kind');
  else if (scope === 'all') p.set('kind', 'all');
  if (s.page) p.set('page', s.page);
  p.set('tree', s.tree.join(','));
  p.set('matrix', s.matrix.join(','));
  if (s.open) p.set('open', s.open);
  return p.toString();
}

function parseHash() {
  const s = blank();
  const p = new URLSearchParams(location.hash.slice(1));
  s.q = p.get('q') ?? '';
  for (const d of FILTER_DIMS) {
    const raw = p.get(d);
    if (!raw || HIDDEN_DIMS.includes(d)) continue;
    if (d === 'kind' && raw === 'all') {
      s.f.kind = SCOPES[2].f();
      continue;
    }
    const f = { in: [], out: [] };
    for (const v of raw.split(',').filter(Boolean)) (v.startsWith('!') ? f.out : f.in).push(v.replace(/^!/, ''));
    s.f[d] = f;
  }
  s.isaMode = p.get('isa_mode') === 'primary' ? 'primary' : 'any';
  s.multi = p.get('multi') === '1';
  for (const r of ['size', 'time', 'conf']) {
    const raw = p.get(r);
    if (!raw?.includes('..')) continue;
    const [a, b] = raw.split('..').map(x => (x === '' ? null : Number(x)));
    s[r] = [a, b];
  }
  const sort = p.get('sort');
  if (sort) s.sort = sort.split(',').map(x => x.split(':')).filter(([k]) => !HIDDEN_DIMS.includes(k)).map(([k, d]) => [k, d === 'desc']);
  if (!s.sort.length) s.sort = [['time', true]];
  s.page = Math.max(0, Number(p.get('page')) || 0);
  const tree = p.get('tree');
  if (tree) s.tree = tree.split(',').filter(d => DIM_LABELS[d] && !HIDDEN_DIMS.includes(d)).slice(0, 4);
  if (!s.tree.length) s.tree = ['family', 'isa', 'format'];
  const matrix = p.get('matrix')?.split(',');
  if (matrix?.length === 2 && matrix.every(d => DIM_LABELS[d] && !HIDDEN_DIMS.includes(d))) s.matrix = matrix;
  s.open = p.get('open');
  return s;
}

function writeHash() {
  history.replaceState(null, '', `#${hashOf(state)}`);
}

let queryTimer = null;
function update({ delay = 0, keepPage = false } = {}) {
  if (!keepPage) state.page = 0;
  writeHash();
  clearTimeout(queryTimer);
  queryTimer = setTimeout(runQuery, delay);
}

const fsel = dim => (state.f[dim] ??= { in: [], out: [] });

function toggle(dim, key, exclude) {
  const f = fsel(dim);
  const [list, other] = exclude ? [f.out, f.in] : [f.in, f.out];
  const i = list.indexOf(key);
  if (i >= 0) list.splice(i, 1);
  else {
    list.push(key);
    const j = other.indexOf(key);
    if (j >= 0) other.splice(j, 1);
  }
  update();
}

// ------------------------------------------------------------------ query

let queryCtl = null;
let queryBusy = false;
let lastQueryAt = 0;

async function runQuery() {
  queryCtl?.abort();
  queryCtl = new AbortController();
  const p = filterParams(state);
  p.set('offset', state.page * state.limit);
  p.set('limit', state.limit);
  p.set('facets', '1');
  p.set('tree', state.tree.join(','));
  if ($('matrix-panel').open) p.set('matrix', state.matrix.join(','));
  queryBusy = true;
  try {
    const result = await api(`/query?${p}`, { signal: queryCtl.signal });
    data = result;
    lastQueryAt = Date.now();
    for (const [dim, f] of Object.entries(data.facets ?? {})) {
      for (const v of f.values) (labels[dim] ??= {})[v.key] = v.label;
    }
    // Not in the middle of a drag across a chart: that waits for the end.
    if (pointer.down) window.addEventListener('pointerup', () => setTimeout(render), { once: true });
    else render();
    banner(null);
  } catch (err) {
    if (err.name === 'AbortError') return;
    if (err.code === 'indexing') {
      setTimeout(runQuery, 2000);
      return;
    }
    banner(err);
  } finally {
    queryBusy = false;
  }
}

const labelOf = (dim, key) => labels[dim]?.[key] ?? key;

// ------------------------------------------------------------------ render

function render() {
  renderScope();
  renderChips();
  renderTree();
  renderFacets();
  renderHists();
  renderMatrix();
  renderTable();
  exportLinks();
}

function renderChips() {
  const chips = [];
  if (state.q) chips.push({ text: `“${state.q}”`, clear: () => { state.q = ''; $('search').value = ''; } });
  for (const d of FILTER_DIMS) {
    const f = state.f[d];
    if (!f || (d === 'kind' && exactScope(state))) continue;
    for (const k of f.in) chips.push({ text: `${DIM_LABELS[d]}: ${labelOf(d, k)}`, clear: () => toggle(d, k, false), raw: true });
    for (const k of f.out) chips.push({ text: `${DIM_LABELS[d]} ≠ ${labelOf(d, k)}`, cls: 'out', clear: () => toggle(d, k, true), raw: true });
  }
  if (state.multi) chips.push({ text: 'multi-ISA', clear: () => { state.multi = false; $('multi').checked = false; } });
  if (state.isaMode === 'primary') chips.push({ text: 'primary ISA only', clear: () => { state.isaMode = 'any'; } });
  if (state.size) chips.push({ text: `size ${size(state.size[0] ?? 0)} – ${state.size[1] == null ? '∞' : size(state.size[1])}`, clear: () => { state.size = null; } });
  if (state.time) chips.push({ text: `received ${time(state.time[0])} – ${time(state.time[1])}`, clear: () => { state.time = null; } });
  if (state.conf) chips.push({ text: `confidence ${Math.round((state.conf[0] ?? 0) * 100)}–${Math.round((state.conf[1] ?? 1) * 100)}%`, clear: () => { state.conf = null; } });
  const host = $('chips');
  host.replaceChildren();
  chips.forEach(c => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `chip ${c.cls ?? ''}`;
    b.textContent = `${c.text} ×`;
    b.title = 'remove this filter';
    b.addEventListener('click', () => {
      c.clear();
      if (!c.raw) update();
    });
    host.append(b);
  });
  if (chips.length > 1) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'chip clear';
    b.textContent = 'clear all';
    b.addEventListener('click', () => {
      const keep = { sort: state.sort, tree: state.tree, matrix: state.matrix, limit: state.limit };
      state = { ...blank(), ...keep };
      $('search').value = '';
      $('multi').checked = false;
      update();
    });
    host.append(b);
  }
  $('total').textContent = data ? `${num(data.total)} files · ${size(data.bytes)}` : '';
  $('isa-mode').textContent = state.isaMode === 'any' ? 'any ISA' : 'primary ISA';
  $('isa-mode').classList.toggle('on', state.isaMode === 'primary');
}

function renderScope() {
  const counts = { firmware: 0, other: 0, all: 0 };
  for (const v of data?.facets?.kind?.values ?? []) {
    counts[v.key === 'firmware' ? 'firmware' : 'other'] += v.files;
    counts.all += v.files;
  }
  const on = scopeOf(state);
  const host = $('scope');
  host.replaceChildren(...SCOPES.map(sc => {
    const b = document.createElement('button');
    b.type = 'button';
    b.dataset.scope = sc.key;
    b.className = sc.key === on ? 'on' : '';
    b.title = sc.title;
    b.setAttribute('aria-pressed', String(sc.key === on));
    b.append(sc.label, ' ', Object.assign(document.createElement('span'), { className: 'n', textContent: data ? num(counts[sc.key]) : '' }));
    return b;
  }));
}

// ---- tree

// The time range of a month (YYYY-MM) or day (YYYY-MM-DD) node, as the server computes it.
function keyRange(dim, key) {
  const [y, m, d] = key.split('-').map(Number);
  if (dim === 'month') return [Date.UTC(y, m - 1, 1) / 1000, Date.UTC(y, m, 1) / 1000 - 1];
  const a = Date.UTC(y, m - 1, d) / 1000;
  return [a, a + 86399];
}

// Whether a node agrees with the filters of its dimension: nothing chosen
// there, or this value among those chosen.
function consistent(dim, key) {
  if (TIME_DIMS.includes(dim)) return !state.time || nodeSelected(dim, key);
  const inc = state.f[dim]?.in ?? [];
  return !inc.length || inc.includes(key);
}

function nodeSelected(dim, key) {
  if (TIME_DIMS.includes(dim)) {
    if (!state.time) return false;
    const [a, b] = keyRange(dim, key);
    return state.time[0] === a && state.time[1] === b;
  }
  return !!state.f[dim]?.in.includes(key);
}

function renderTreeLevels() {
  const host = $('tree-levels');
  host.replaceChildren();
  state.tree.forEach((dim, i) => {
    if (i) host.append(Object.assign(document.createElement('span'), { className: 'sep', textContent: '›' }));
    const sel = document.createElement('select');
    sel.title = `tree level ${i + 1}`;
    for (const [d, l] of Object.entries(DIM_LABELS)) if (!HIDDEN_DIMS.includes(d)) sel.add(new Option(l, d, false, d === dim));
    sel.addEventListener('change', () => {
      state.tree[i] = sel.value;
      state.tree = state.tree.filter((d, j) => state.tree.indexOf(d) === j);
      renderTreeLevels();
      update({ keepPage: true });
    });
    host.append(sel);
    if (state.tree.length > 1) {
      const x = Object.assign(document.createElement('button'), { type: 'button', textContent: '×', title: 'remove this level', className: 'lvl-x' });
      x.addEventListener('click', () => {
        state.tree.splice(i, 1);
        renderTreeLevels();
        update({ keepPage: true });
      });
      host.append(x);
    }
  });
  if (state.tree.length < 4) {
    const add = Object.assign(document.createElement('button'), { type: 'button', textContent: '+ level', className: 'lvl-add' });
    add.addEventListener('click', () => {
      state.tree.push(Object.keys(DIM_LABELS).find(d => !state.tree.includes(d) && !HIDDEN_DIMS.includes(d)));
      renderTreeLevels();
      update({ keepPage: true });
    });
    host.append(add);
  }
}

const collapsed = new Set();

function renderTree() {
  const tree = data?.tree;
  const host = $('tree');
  if (!tree) {
    host.replaceChildren();
    return;
  }
  const levels = tree.levels;
  const needle = $('tree-filter').value.trim().toLowerCase();
  const metric = treeMetric;
  const crumbs = [];
  const matches = node => !needle || `${node.label} ${node.key}`.toLowerCase().includes(needle);
  const kidsOf = node => (node.children ?? []).filter(c => !c.more);
  const anyMatch = node => matches(node) || kidsOf(node).some(anyMatch);
  // A node is selected only along a path the filters agree with: Raw under
  // one ISA is not every Raw. `path` ends with the node itself.
  const selWithin = (node, depth, path) => path.every(([d, k]) => consistent(d, k)) && kidsOf(node).some(c => {
    const dim = levels[depth + 1];
    return nodeSelected(dim, c.key) || selWithin(c, depth + 1, [...path, [dim, c.key]]);
  });

  function build(nodes, depth, chain) {
    const real = nodes.filter(n => !n.more);
    const max = Math.max(1, ...real.map(n => n[metric]));
    const items = [];
    for (const node of nodes) {
      if (node.more) {
        items.push(`<li class="more muted">… ${num(node.more)} more (narrow it down with filters)</li>`);
        continue;
      }
      if (needle && !anyMatch(node)) continue;
      const dim = levels[depth];
      const path = [...chain, [dim, node.key]];
      const id = JSON.stringify(path);
      const on = nodeSelected(dim, node.key) && chain.every(([d, k]) => consistent(d, k));
      const out = state.f[dim]?.out.includes(node.key);
      if (on) crumbs[depth] = { dim, node };
      const kids = kidsOf(node).length ? node.children : null;
      const auto = on || (kids && selWithin(node, depth, path)) || (needle && kids && kidsOf(node).some(anyMatch)) || (depth === 0 && real.length === 1);
      const open = kids && !collapsed.has(id) && (expanded.has(id) || auto);
      const share = (100 * node[metric]) / max;
      items.push(`<li role="treeitem" ${kids ? `aria-expanded="${!!open}"` : ''} class="${on ? 'on' : ''} ${out ? 'out' : ''}">
        <div class="node" data-path="${esc(id)}" title="${esc(DIM_LABELS[dim])}: ${esc(node.label)} · ${num(node.files)} files, ${size(node.bytes)}">
          <button type="button" class="twisty" ${kids ? '' : 'disabled'} tabindex="-1">${kids ? (open ? '▾' : '▸') : '·'}</button>
          <span class="lbl">${esc(node.label)}</span>
          <span class="track"><i data-w="${share.toFixed(1)}"></i></span>
          <span class="n">${metric === 'files' ? num(node.files) : size(node.bytes)}</span>
        </div>${open ? `<ul role="group">${build(node.children, depth + 1, path)}</ul>` : ''}</li>`);
    }
    return items.join('');
  }
  host.innerHTML = build(tree.nodes, 0, []) || '<li class="muted">nothing matches</li>';
  widths(host);
  const parts = crumbs.filter(Boolean);
  $('crumbs').innerHTML = parts.length
    ? parts.map(({ dim, node }) => `<span>${esc(DIM_LABELS[dim])}: <strong>${esc(node.label)}</strong></span>`).join(' › ')
    : '<span class="muted">click a node to filter, alt-click to leave it out</span>';
}

function treeClick(ev) {
  const nodeEl = ev.target.closest('.node');
  if (!nodeEl) return;
  const id = nodeEl.dataset.path;
  const chain = JSON.parse(id);
  if (ev.target.closest('.twisty')) {
    const li = nodeEl.parentElement;
    if (li.getAttribute('aria-expanded') === 'true') {
      collapsed.add(id);
      expanded.delete(id);
    } else {
      collapsed.delete(id);
      expanded.add(id);
    }
    renderTree();
    return;
  }
  const levels = data.tree.levels;
  const [dim, key] = chain[chain.length - 1];
  if (ev.altKey) {
    if (!TIME_DIMS.includes(dim)) toggle(dim, key, true);
    return;
  }
  // The node and its ancestors become the filters of the tree's levels
  // (deeper levels are cleared); clicking the selected node clears them.
  const already = chain.every(([d, k]) => nodeSelected(d, k) && (TIME_DIMS.includes(d) || state.f[d].in.length === 1))
    && levels.slice(chain.length).every(d => TIME_DIMS.includes(d) || !state.f[d]?.in.length);
  for (const d of levels) {
    if (TIME_DIMS.includes(d)) state.time = null;
    else fsel(d).in = [];
  }
  if (!already) {
    for (const [d, k] of chain) {
      if (TIME_DIMS.includes(d)) state.time = keyRange(d, k);
      else {
        fsel(d).in = [k];
        fsel(d).out = fsel(d).out.filter(x => x !== k);
      }
    }
  }
  update();
}

// ---- facets

function renderFacets() {
  const host = $('facets');
  if (!data?.facets) return;
  // ISA and family are the tree's, unless the tree shows other dimensions.
  const shown = [...['isa', 'family'].filter(d => !state.tree.includes(d)), ...FACETS];
  host.innerHTML = shown.map(dim => {
    const f = data.facets[dim];
    if (!f) return '';
    const values = f.values;
    const hasSel = values.some(v => v.sel);
    if (!values.length || (values.length === 1 && !hasSel && dim !== 'status' && dim !== 'donor')) {
      return values.length === 1
        ? `<div class="facet single panel"><div class="facet-head"><span>[ ${esc(DIM_LABELS[dim])} ]</span><span class="muted">${esc(values[0].label)}</span></div></div>`
        : '';
    }
    const all = openFacets.has(dim);
    const list = all ? values : values.slice(0, FACET_SHOWN);
    const max = Math.max(1, ...values.map(v => v[histMetric]));
    const rows = list.map(v => `<li class="${v.sel ?? ''}" data-dim="${dim}" data-key="${esc(v.key)}" title="${esc(v.label)}: ${num(v.files)} files, ${size(v.bytes)} (click: only these; alt-click: all but these)">
      <span class="lbl">${esc(v.label)}</span><span class="track"><i data-w="${((100 * v[histMetric]) / max).toFixed(1)}"></i></span>
      <span class="n">${histMetric === 'files' ? num(v.files) : size(v.bytes)}</span></li>`).join('');
    const more = values.length - list.length + (f.more || 0);
    return `<div class="facet panel"><div class="facet-head"><span>[ ${esc(DIM_LABELS[dim])} ]</span><span class="muted">${num(values.length + (f.more || 0))}</span>
      ${hasSel ? `<button type="button" class="facet-clear" data-clear="${dim}">clear</button>` : ''}</div>
      <ul>${rows}</ul>${more > 0 || all ? `<button type="button" class="facet-more" data-more="${dim}">${all ? 'fewer' : `all ${num(values.length)}${f.more ? ` (+${num(f.more)} not listed)` : ''}`}</button>` : ''}</div>`;
  }).join('');
  widths(host);
}

function facetClick(ev) {
  const more = ev.target.closest('[data-more]');
  if (more) {
    const d = more.dataset.more;
    if (openFacets.has(d)) openFacets.delete(d);
    else openFacets.add(d);
    renderFacets();
    return;
  }
  const clear = ev.target.closest('[data-clear]');
  if (clear) {
    delete state.f[clear.dataset.clear];
    update();
    return;
  }
  const li = ev.target.closest('li[data-key]');
  if (li) toggle(li.dataset.dim, li.dataset.key, ev.altKey);
}

// ---- charts

function renderHists() {
  const h = data?.hist;
  if (!h) return;
  const t = h.time;
  const timeBuckets = t.buckets.map(([files, bytes], i) => ({ lo: t.start + i * t.step, hi: t.start + (i + 1) * t.step - 1, files, bytes }));
  $('time-step').textContent = t.buckets.length ? `per ${t.step === 3600 ? 'hour' : t.step === 86400 ? 'day' : 'week'}` : '';
  histogram($('h-time'), timeBuckets, {
    metric: histMetric, selected: state.time, height: 72,
    label: b => (t.step === 3600 ? time(b.lo) : time(b.lo).slice(0, 10)),
    onSelect: (lo, hi) => { state.time = [lo, hi]; update(); },
  });
  histogram($('h-size'), h.size, {
    metric: histMetric, selected: state.size,
    label: b => `${size(b.lo)}–${size(b.hi)}`,
    onSelect: (lo, hi) => { state.size = [lo, hi]; update(); },
  });
  histogram($('h-conf'), h.conf, {
    metric: histMetric, selected: state.conf, scale: 'linear',
    label: b => `${Math.round(b.lo * 100)}–${Math.round(b.hi * 100)}%`,
    onSelect: (lo, hi) => { state.conf = [lo, hi]; update(); },
  });
  $('hist-metric').textContent = histMetric;
}

// ---- matrix

function renderMatrix() {
  const panel = $('matrix-panel');
  for (const [id, i] of [['matrix-a', 0], ['matrix-b', 1]]) {
    const sel = $(id);
    if (!sel.options.length) for (const [d, l] of Object.entries(DIM_LABELS)) if (!HIDDEN_DIMS.includes(d)) sel.add(new Option(l, d));
    sel.value = state.matrix[i];
  }
  const m = data?.matrix;
  const table = $('matrix');
  if (!panel.open || !m) {
    table.replaceChildren();
    return;
  }
  const max = Math.max(1, ...m.cells.flat());
  const heat = n => (n ? Math.min(5, 1 + Math.floor((Math.log(n) / Math.log(max + 1)) * 5)) : 0);
  table.innerHTML = `<thead><tr><th>${esc(DIM_LABELS[m.a])} \\ ${esc(DIM_LABELS[m.b])}</th>${m.cols.map(c => `<th class="num col" data-b="${esc(c.key)}" title="${esc(c.label)}: ${num(c.files)}">${esc(c.label)}</th>`).join('')}${m.more_cols ? `<th class="muted">+${m.more_cols}</th>` : ''}</tr></thead>
    <tbody>${m.rows.map((r, i) => `<tr><th data-a="${esc(r.key)}" title="${num(r.files)} files">${esc(r.label)}</th>${m.cells[i].map((n, j) => `<td class="num h${heat(n)}" data-a="${esc(r.key)}" data-b="${esc(m.cols[j].key)}" title="${esc(r.label)} × ${esc(m.cols[j].label)}: ${num(n)}">${n ? num(n) : ''}</td>`).join('')}</tr>`).join('')}
    ${m.more_rows ? `<tr><th class="muted">+${m.more_rows} more</th></tr>` : ''}</tbody>`;
}

function matrixClick(ev) {
  const cell = ev.target.closest('[data-a], [data-b]');
  if (!cell || !data?.matrix) return;
  const { a, b } = data.matrix;
  for (const [dim, key] of [[a, cell.dataset.a], [b, cell.dataset.b]]) {
    if (key == null) continue;
    if (TIME_DIMS.includes(dim)) continue;
    fsel(dim).in = [key];
    fsel(dim).out = fsel(dim).out.filter(x => x !== key);
  }
  update();
}

// ---- table

function cell(col, r) {
  switch (col) {
    case 'name': return `<span class="name" title="${esc(r.name)}">${esc(r.name)}</span><span class="sub">${r.sha256.slice(0, 16)}</span>`;
    case 'isa': return r.isa_name ? `${esc(r.isa_name)}${r.isas.length > 1 ? ` <span class="pill" title="${esc(r.isas.join(', '))}">+${r.isas.length - 1}</span>` : ''}` : '<span class="muted">–</span>';
    case 'bits': return r.bits ? `${r.bits} <span class="muted">${esc(endianShort(r.endian))}</span>` : '<span class="muted">–</span>';
    case 'format': return `${esc(r.format_name ?? r.format ?? '–')}`;
    case 'size': return size(r.size);
    case 'donor': return r.donor === 'anonymous' ? '<span class="muted">anonymous</span>' : esc(r.donor);
    case 'received': return `<time title="${ago(r.received_at)}">${time(r.received_at)}</time>`;
    case 'status': return `<span class="pill st-${r.status}" title="${esc(r.reason ?? '')}">${r.status}</span>`;
    case 'sha': return `<code>${r.sha256}</code>`;
    case 'family': return esc(r.family_name ?? '–');
    case 'variant': return esc(r.variant ?? '–');
    case 'conf': return r.confidence == null ? '–' : `${(r.confidence * 100).toFixed(0)}%`;
    case 'class': return esc(r.class ?? '–');
    case 'basis': return esc(r.basis ?? '–');
    case 'slices': return r.slices ? num(r.slices) : '';
    case 'origin': return esc(r.origin);
    case 'posted': return r.posted_at ? time(r.posted_at) : '–';
    case 'telegram': return r.telegram ? `<a href="${esc(r.telegram)}" target="_blank" rel="noopener noreferrer">post ↗</a>` : '–';
    case 'zrax': return esc(r.zrax ?? '–');
    case 'ext': return esc(r.ext ?? '');
    case 'kind': return r.kind === 'firmware' ? '<span class="muted">firmware</span>' : `<span class="pill kind-${esc(r.kind)}">${esc(labelOf('kind', r.kind))}</span>`;
    default: return '';
  }
}

function renderTable() {
  if (!data) return;
  const cols = COLUMNS.filter(c => columns.includes(c.key));
  const sortIndex = key => state.sort.findIndex(([k]) => k === key);
  $('files-head').innerHTML = `<tr><th class="sel"><input type="checkbox" id="sel-page" title="select this page"></th>${cols.map(c => {
    const i = c.sort ? sortIndex(c.sort) : -1;
    const dir = i >= 0 ? (state.sort[i][1] ? 'desc' : 'asc') : '';
    return `<th class="${c.num ? 'num' : ''} ${c.sort ? 'sortable' : ''} ${dir}" ${c.sort ? `data-sort="${c.sort}"` : ''} aria-sort="${dir ? `${dir}ending` : 'none'}">${esc(c.label)}${dir ? ` <i>${dir === 'desc' ? '↓' : '↑'}${state.sort.length > 1 ? i + 1 : ''}</i>` : ''}</th>`;
  }).join('')}</tr>`;
  $('files-rows').innerHTML = data.rows.map((r, i) => `<tr data-i="${i}" data-sha="${r.sha256}" class="${r.received_at > openedAt && openedAt ? 'new' : ''} ${i === cursor ? 'cursor' : ''} ${selected.has(r.sha256) ? 'picked' : ''} ${state.open === r.sha256 ? 'opened' : ''}">
    <td class="sel"><input type="checkbox" ${selected.has(r.sha256) ? 'checked' : ''} aria-label="select"></td>
    ${cols.map(c => `<td class="${c.num ? 'num' : ''} c-${c.key}">${cell(c.key, r)}</td>`).join('')}</tr>`).join('')
    || `<tr><td colspan="${cols.length + 1}" class="muted empty-row">No file matches these filters.</td></tr>`;
  const pageAll = data.rows.length && data.rows.every(r => selected.has(r.sha256));
  $('sel-page').checked = !!pageAll;
  $('count').textContent = num(data.total);
  const pages = Math.max(1, Math.ceil(data.total / state.limit));
  $('page-info').textContent = `page ${state.page + 1} of ${num(pages)} · ${num(state.page * state.limit + Math.min(1, data.rows.length))}–${num(state.page * state.limit + data.rows.length)}`;
  $('prev').disabled = state.page === 0;
  $('next').disabled = state.page + 1 >= pages;
  renderSelection();
}

function renderSelection() {
  $('sel-actions').hidden = selected.size === 0;
  $('sel-info').textContent = selected.size ? `${num(selected.size)} selected · ${size([...selected.values()].reduce((a, r) => a + r.size, 0))}` : '';
}

function renderColumns() {
  $('columns').innerHTML = COLUMNS.map(c => `<label class="check"><input type="checkbox" data-col="${c.key}" ${columns.includes(c.key) ? 'checked' : ''}> ${esc(c.label)}</label>`).join('')
    + '<button type="button" id="cols-reset">defaults</button>';
}

function exportLinks() {
  const p = filterParams(state);
  const link = as => `${API}/export?${p}&as=${as}`;
  $('x-csv').href = link('csv');
  $('x-ndjson').href = link('ndjson');
  $('x-sum').href = link('sha256sum');
  if (PUBLIC) return;
  $('x-rsync').href = link('rsync');
  const dir = summary?.firmware_dir ?? '/data/fwdonor/firmwares';
  $('rsync-cmd').textContent = `rsync -a --files-from=fwdonor-firmware.files.txt <server>:${dir}/ ./firmwares/`;
}

// ------------------------------------------------------------------ detail

let detailCtl = null;

function hexdump(hex, base = 0) {
  const bytes = hex.match(/../g)?.map(h => parseInt(h, 16)) ?? [];
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.slice(i, i + 16);
    const hexes = row.map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = row.map(b => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(base + i).toString(16).padStart(8, '0')}  ${hexes.slice(0, 23)}  ${hexes.slice(24)}  ${ascii}`);
  }
  return lines.join('\n');
}

function entropyChart(host, inspect, slices, fileSize) {
  host.replaceChildren();
  const pts = inspect.entropy.points;
  const w = Math.max(320, host.clientWidth || 560);
  const h = 120;
  const band = slices.length ? 18 : 0;
  const ch = h - band - 4;
  const root = svg('svg', { viewBox: `0 0 ${w} ${h}`, width: w, height: h, class: 'entropy' }, host);
  for (const y of [8, 7, 4]) {
    svg('line', { x1: 0, x2: w, y1: ch - (y / 8) * ch + 1, y2: ch - (y / 8) * ch + 1, class: `grid g${y}` }, root);
    svg('text', { x: 2, y: ch - (y / 8) * ch + 10, class: 'axis' }, root).textContent = `${y}`;
  }
  const step = w / Math.max(1, pts.length);
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${(i * step + step / 2).toFixed(1)},${(ch - (p / 8) * ch + 1).toFixed(1)}`).join('');
  svg('path', { d: `${d}L${w},${ch + 1}L0,${ch + 1}Z`, class: 'area' }, root);
  svg('path', { d, class: 'line' }, root);
  pts.forEach((p, i) => {
    const hit = svg('rect', { x: i * step, y: 0, width: step, height: ch, class: 'hit' }, root);
    const off = i * inspect.entropy.window;
    svg('title', {}, hit).textContent = `0x${off.toString(16)} (${size(off)}): ${p.toFixed(2)} bits/byte`;
  });
  slices.forEach((s, i) => {
    const x = (s.offset / Math.max(1, fileSize)) * w;
    const sw = Math.max(1, (s.size / Math.max(1, fileSize)) * w);
    const r = svg('rect', { x, y: ch + 4, width: sw, height: band - 4, class: `slice s${i % 6}` }, root);
    svg('title', {}, r).textContent = `${s.label ?? 'slice'}: ${s.isa_name ?? s.isa ?? 'no ISA'} @ 0x${s.offset.toString(16)}, ${size(s.size)}`;
  });
}

function kv(pairs) {
  return `<dl class="kv">${pairs.filter(([, v]) => v != null && v !== '').map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
}

async function openFile(sha, { focusRow = true } = {}) {
  state.open = sha;
  writeHash();
  const drawer = $('drawer');
  drawer.hidden = false;
  document.body.classList.add('drawer-open');
  for (const tr of $('files-rows').querySelectorAll('tr.opened')) tr.classList.remove('opened');
  const tr = $('files-rows').querySelector(`tr[data-sha="${sha}"]`);
  tr?.classList.add('opened');
  if (focusRow && tr) cursor = Number(tr.dataset.i);
  $('d-name').textContent = 'loading…';
  $('d-body').innerHTML = '';
  detailCtl?.abort();
  detailCtl = new AbortController();
  const signal = detailCtl.signal;
  let detail;
  try {
    detail = await api(`/files/${sha}`, { signal });
  } catch (err) {
    if (err.name === 'AbortError') return;
    $('d-name').textContent = 'not found';
    $('d-body').innerHTML = `<p class="muted">${esc(err.message)}</p>`;
    return;
  }
  renderDetail(detail);
  if (isStored(detail.row)) {
    try {
      const inspect = await api(`/files/${sha}/inspect`, { signal });
      renderInspect(detail, inspect);
    } catch (err) {
      if (err.name === 'AbortError') return;
      $('d-inspect').innerHTML = `<p class="muted">Could not look inside: ${esc(err.message)}</p>`;
    }
  }
}

function renderDetail(detail) {
  const r = detail.row;
  const z = detail.record?.zrax;
  $('d-name').textContent = r.name;
  $('d-name').title = r.name;
  const download = !isStored(r)
    ? '<span class="muted">not available yet</span>'
    : PUBLIC
      ? `<button type="button" class="primary" data-download="${r.sha256}" title="Your browser does a small proof of work first">download</button>`
      : `<a class="button primary" href="${API}/files/${r.sha256}/download" download>download</a>`;
  const slices = z?.slices ?? [];
  const metadata = z?.metadata ?? [];
  $('d-body').innerHTML = `
    <section class="d-actions">${download}
      <button type="button" data-copy="${r.sha256}">copy sha256</button>
      ${detail.path ? `<button type="button" data-copy="${esc(detail.path)}">copy server path</button>` : ''}
      ${r.telegram ? `<a href="${esc(r.telegram)}" target="_blank" rel="noopener noreferrer">Telegram post ↗</a>` : ''}
    </section>
    <section><h3>[ file ]</h3>${kv([
      ['sha256', `<code class="sha">${r.sha256}</code>`],
      ['size', `${size(r.size)} <span class="muted">(${num(r.size)} bytes)</span>`],
      ['original name', esc(r.name)],
      ['donor', esc(r.donor)],
      ['received', `${time(r.received_at, { seconds: true })} <span class="muted">${ago(r.received_at)}</span>`],
      ['posted', r.posted_at ? `${time(r.posted_at, { seconds: true })}${r.message_id ? ` <span class="muted">message ${r.message_id / 1048576}</span>` : ''}` : 'not yet'],
      ['origin', PUBLIC ? null : esc(r.origin)],
      ['status', PUBLIC ? null : `<span class="pill st-${r.status}">${r.status}</span>${r.reason ? `<br><small class="muted">${esc(r.reason)}</small>` : ''}`],
      ['stored at', detail.path ? `<code>${esc(detail.path)}</code>` : null],
    ])}</section>
    <section><h3>[ classification ]</h3>${kv([
      ['kind', detail.kind ? `${esc(detail.kind.label)}${detail.kind.why ? ` <span class="muted">${esc(detail.kind.why)}</span>` : ''}` : null],
      ['format', `${esc(z?.format_name ?? r.format_name ?? r.format ?? '–')}${z?.format_variant ? ` <span class="muted">${esc(z.format_variant)}</span>` : ''}`],
      ['ISA', r.isa_name ? `${esc(r.isa_name)} <span class="muted">${esc(r.isa)}</span>` : '–'],
      ['all ISAs', r.isas.length > 1 ? r.isas.map(i => `<span class="pill">${esc(labelOf('isa', i))}</span>`).join(' ') : null],
      ['family', esc(r.family_name ?? '–')],
      ['bits', r.bits ? `${r.bits}-bit ${esc(r.endian ?? '')}` : null],
      ['confidence', r.confidence == null ? null : `${(r.confidence * 100).toFixed(1)}%`],
      ['zrax source', esc(r.class ?? '')],
      ['variant', esc(z?.variant ?? '')],
      ['accepted for', esc(r.basis ?? '')],
      ['zrax', esc(r.zrax ?? (!isStored(r) ? 'not analyzed yet' : 'the current zrax no longer accepts it'))],
    ])}</section>
    <section><h3>[ quick filters ]</h3><div class="quick">
      ${r.kind ? `<button type="button" data-only="kind" data-key="${esc(r.kind)}">only ${esc(KIND_PLURAL[r.kind] ?? r.kind)}</button>` : ''}
      <button type="button" data-only="donor" data-key="${esc(r.donor)}">only ${esc(r.donor)}</button>
      ${r.isa ? `<button type="button" data-only="isa" data-key="${esc(r.isa)}">only ${esc(r.isa_name)}</button>` : ''}
      ${r.format ? `<button type="button" data-only="format" data-key="${esc(r.format)}">only ${esc(r.format_name ?? r.format)}</button>` : ''}
      <button type="button" data-search="${esc(r.name)}">same name</button></div></section>
    <section id="d-inspect"><h3>[ entropy ]</h3><p class="muted">${isStored(r) ? 'looking inside…' : 'available once the file is in the store'}</p></section>
    ${slices.length ? `<section><h3>[ slices ] <span class="muted">${num(slices.length)}</span></h3><div class="table-wrap"><table class="table compact"><thead><tr><th>label</th><th>ISA</th><th class="num">bits</th><th class="num">offset</th><th class="num">size</th></tr></thead><tbody>
      ${slices.slice(0, 500).map(s => `<tr><td>${esc(s.label ?? '')}</td><td>${esc(s.isa_name ?? s.isa ?? '–')}</td><td class="num">${s.bitwidth || ''}</td><td class="num"><code>0x${s.offset.toString(16)}</code></td><td class="num">${size(s.size)}</td></tr>`).join('')}
      </tbody></table></div></section>` : ''}
    ${metadata.length ? `<section><h3>[ metadata ]</h3>${kv(metadata.slice(0, 400).map(m => [m.label, esc(m.value)]))}</section>` : ''}
    ${detail.same_name.length ? `<section><h3>[ same name ] <span class="muted">${num(detail.same_name.length)}</span></h3><ul class="same">${detail.same_name.map(s => `<li><button type="button" data-open="${s.sha256}">${s.sha256.slice(0, 16)}</button> ${size(s.size)} · ${esc(s.isa_name ?? '–')} · ${esc(s.donor)} · ${time(s.received_at)}</li>`).join('')}</ul></section>` : ''}
    <section id="d-hex"></section><section id="d-strings"></section>`;
  $('d-body').dataset.sha = r.sha256;
}

function renderInspect(detail, inspect) {
  if ($('d-body').dataset.sha !== detail.row.sha256) return;
  const slices = detail.record?.zrax?.slices ?? [];
  const sec = $('d-inspect');
  sec.innerHTML = `<h3>[ entropy ] <span class="muted">bits per byte over the file${inspect.entropy.sampled ? ', sampled' : ''}${slices.length ? '; slices below' : ''}</span></h3><div class="entropy-host"></div>`;
  entropyChart(sec.querySelector('.entropy-host'), inspect, slices, inspect.size);
  $('d-hex').innerHTML = `<h3>[ first ${num(inspect.head.length / 2)} bytes ]</h3><pre class="hexdump">${esc(hexdump(inspect.head))}</pre>`;
  const strings = inspect.strings;
  $('d-strings').innerHTML = `<h3>[ strings ] <span class="muted">${num(strings.length)}${inspect.strings_truncated ? '+' : ''} in the first ${size(inspect.strings_scanned)}</span></h3>
    <input type="search" class="strings-filter" placeholder="filter strings" spellcheck="false">
    <ol class="strings">${strings.map(([o, s]) => `<li><code>0x${o.toString(16).padStart(6, '0')}</code> ${esc(s)}</li>`).join('')}</ol>`;
  $('d-strings').querySelector('.strings-filter').addEventListener('input', ev => {
    const needle = ev.target.value.toLowerCase();
    for (const li of $('d-strings').querySelectorAll('li')) li.hidden = needle && !li.textContent.toLowerCase().includes(needle);
  });
}

// Public downloads need a proof of work bound to the file: `proofs` solutions
// of `bits` each, found by one worker per core searching apart
// (pow-pool-worker.js). Many small solutions take a steady time.
const POW_WORKERS = Math.max(1, Math.min(navigator.hardwareConcurrency || 4, 16));
let powPool = null;
let powSeq = 0;

function solveMany(token, sha256, bits, count, onProgress) {
  powPool ??= Array.from({ length: POW_WORKERS }, () => new Worker(new URL('./pow-pool-worker.js', import.meta.url), { type: 'module' }));
  const id = ++powSeq;
  return new Promise((resolve, reject) => {
    const found = new Set();
    const finish = () => {
      for (const w of powPool) {
        w.removeEventListener('message', onMessage);
        w.postMessage({ type: 'stop', id });
      }
    };
    function onMessage({ data }) {
      if (data.id !== id) return;
      if (data.error) {
        finish();
        reject(new Error(data.error));
        return;
      }
      found.add(data.nonce);
      onProgress?.(Math.min(found.size, count));
      if (found.size >= count) {
        finish();
        resolve([...found].sort((a, b) => a - b).slice(0, count));
      }
    }
    powPool.forEach((w, hi) => {
      w.addEventListener('message', onMessage);
      w.postMessage({ type: 'search', id, token, sha256, bits, hi });
    });
  });
}

async function downloadWithProof(sha, button) {
  if (button.disabled) return;
  const label = 'download';
  button.disabled = true;
  try {
    button.textContent = 'proof of work…';
    const challenge = await api('/challenge');
    const started = performance.now();
    let done = 0;
    const show = () => {
      button.textContent = `proof of work… ${done}/${challenge.proofs} · ${((performance.now() - started) / 1000).toFixed(1)} s`;
    };
    const tick = setInterval(show, 100);
    const nonces = await solveMany(challenge.token, sha, challenge.bits, challenge.proofs, n => { done = n; show(); })
      .finally(() => clearInterval(tick));
    const elapsed = performance.now() - started;
    const url = `${API}/files/${sha}/download?token=${encodeURIComponent(challenge.token)}&nonces=${nonces.join(',')}`;
    const head = await fetch(url, { method: 'HEAD' });
    if (!head.ok) throw new Error(head.status === 403 ? 'the proof of work was not accepted' : `HTTP ${head.status}`);
    const a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.append(a);
    a.click();
    a.remove();
    button.textContent = `download started · ${(elapsed / 1000).toFixed(1)} s of work on ${POW_WORKERS} cores`;
  } catch (err) {
    button.textContent = `failed: ${err.message} (retry)`;
  } finally {
    setTimeout(() => {
      button.disabled = false;
      if (!button.textContent.startsWith('failed')) button.textContent = label;
    }, 2500);
  }
}

function closeDrawer() {
  $('drawer').hidden = true;
  document.body.classList.remove('drawer-open');
  state.open = null;
  writeHash();
  for (const tr of $('files-rows').querySelectorAll('tr.opened')) tr.classList.remove('opened');
}

function step(delta) {
  if (!data?.rows.length) return;
  const i = data.rows.findIndex(r => r.sha256 === state.open);
  const next = data.rows[Math.min(data.rows.length - 1, Math.max(0, (i < 0 ? cursor : i) + delta))];
  if (next) openFile(next.sha256);
}

// ------------------------------------------------------------------ summary

function renderSummary(s) {
  summary = s;
  if (!openedAt) openedAt = s.now;
  $('indexing').hidden = s.ready;
  if (!s.ready) {
    $('index-progress').max = Math.max(1, s.progress.total);
    $('index-progress').value = s.progress.done;
    $('index-text').textContent = `${num(s.progress.done)} of ${num(s.progress.total)}`;
  }
  $('s-files').textContent = num(s.files);
  const kinds = s.kinds ?? {};
  const firmware = kinds.firmware ?? 0;
  $('s-bytes').textContent = `images · ${size(s.bytes)} · ${num(firmware)} firmware + ${num(s.files - firmware)} other binaries`;
  $('s-recent').textContent = num(s.last_day);
  $('s-recent-sub').textContent = `last 24 h · ${num(s.last_hour)} in the last hour`;
  $('s-donors').textContent = num(s.named_donors);
  $('s-donors-sub').textContent = `named donors${s.donors > s.named_donors ? ' + anonymous' : ''}`;
  $('s-isas').textContent = num(s.isas);
  $('s-isas-sub').textContent = `ISAs · ${num(s.formats)} formats · ${num(s.wanted.length)} wanted`;
  $('updated').textContent = `updated ${time(s.now, { seconds: true }).slice(11)}`;
  $('status').textContent = s.ready ? `${num(s.files)} images, ${size(s.bytes)}` : 'indexing…';
  $('wanted-count').textContent = num(s.wanted.length);
  $('wanted').innerHTML = s.wanted.map(w => `<li title="${esc(w.isa)}">${esc(w.name)}</li>`).join('');
  if (PUBLIC) {
    $('status-zrax').textContent = `zrax ${s.zrax}`;
    return;
  }
  const pct = s.files ? (100 * s.stored.files) / s.files : 0;
  $('s-stored').textContent = `${pct.toFixed(pct >= 99.95 || pct === 0 ? 0 : 1)}%`;
  $('s-stored-sub').innerHTML = `${num(s.stored.files)} in the store · ${size(s.stored.bytes)}${s.pending.files ? ` · <a href="#" data-status="pending">${num(s.pending.files)} not yet</a>` : ''}`;
  $('cov-stored').dataset.w = s.files ? ((100 * (s.stored.files - s.queued)) / s.files).toFixed(2) : 0;
  $('cov-queued').dataset.w = s.files ? ((100 * s.queued) / s.files).toFixed(2) : 0;
  widths($('cov-stored').parentElement);
  const b = s.backfill;
  const bfText = {
    off: ['off', 'no Telegram backfill'],
    waiting: ['waiting', 'backfill starts shortly'],
    running: [`${num(b.done)}/${num(b.todo)}`, `backfill · ${num(b.restored)} restored, ${size(b.bytes)}${b.started_at ? `, ${rate(b.bytes / Math.max(1, s.now - b.started_at))}` : ''}`],
    finished: ['done', `backfill · ${num(b.restored)} restored${b.finished_at ? ` · ${ago(b.finished_at, s.now)}` : ''}`],
    failed: ['failed', 'backfill could not read the ledger'],
  }[b.state] ?? [b.state, 'backfill'];
  $('s-backfill').textContent = bfText[0];
  $('s-backfill-sub').innerHTML = `${esc(bfText[1])}${s.unrecovered ? ` · <a href="#" data-status="unrecovered">${num(s.unrecovered)} failed</a>` : ''}`;
  $('s-queue').textContent = num(s.queue.active);
  $('s-queue-sub').textContent = `arriving · ${num(s.queue.queued)} queued to post${s.queue.paused ? ' · PAUSED' : ''}`;
  $('s-disk').textContent = size(s.disk.free);
  $('s-disk-sub').textContent = `free of ${size(s.disk.total)}`;
  $('bulk-badge').textContent = s.bulk.files ? num(s.bulk.files) : '';
  $('status-zrax').textContent = `zrax ${s.zrax}${s.older_zrax ? ` · ${num(s.older_zrax)} classified by older versions` : ''} · ${num(s.ledger)} posts in the ledger`;

  $('arriving-count').textContent = num(s.arriving.length);
  $('arriving-rows').innerHTML = s.arriving.map(a => `<tr class="st-${a.state}"><td><span class="pill">${a.state}</span></td>
    <td><span class="name" title="${esc(a.name)}">${esc(a.name)}</span></td><td>${esc(a.donor)}</td><td class="num">${size(a.size)}</td>
    <td><div class="meter"><i data-w="${a.chunks ? ((100 * a.received) / a.chunks).toFixed(1) : 0}"></i></div></td>
    <td>${esc([a.format, a.isa].filter(Boolean).join(' · '))}</td><td class="num">${a.idle_secs}s</td></tr>`).join('')
    || '<tr><td colspan="7" class="muted">nothing right now</td></tr>';
  widths($('arriving-rows'));

}

async function refreshSummary() {
  try {
    const s = await api('/summary');
    banner(null);
    renderSummary(s);
    if (s.ready && !data && !queryBusy) runQuery();
    // Live: follow changes, at most every 10 s, never while a query runs.
    if (live && data && s.version !== data.version && !queryBusy && Date.now() - lastQueryAt > 9500) runQuery();
  } catch (err) {
    banner(err);
    throw err;
  }
}

// ------------------------------------------------------------------ events

function wire() {
  setTabs();
  $('search').value = state.q;
  $('multi').checked = state.multi;
  $('limit').value = String(state.limit);
  renderTreeLevels();
  renderColumns();

  $('search').addEventListener('input', () => {
    state.q = $('search').value.trim();
    update({ delay: 250 });
  });
  $('multi').addEventListener('change', () => {
    state.multi = $('multi').checked;
    update();
  });
  $('scope').addEventListener('click', ev => {
    const b = ev.target.closest('[data-scope]');
    if (!b) return;
    state.f.kind = SCOPES.find(sc => sc.key === b.dataset.scope).f();
    update();
  });
  $('isa-mode').addEventListener('click', () => {
    state.isaMode = state.isaMode === 'any' ? 'primary' : 'any';
    update();
  });
  $('tree-metric').addEventListener('click', () => {
    treeMetric = treeMetric === 'files' ? 'bytes' : 'files';
    $('tree-metric').textContent = treeMetric;
    renderTree();
  });
  $('hist-metric').addEventListener('click', () => {
    histMetric = histMetric === 'files' ? 'bytes' : 'files';
    renderHists();
    renderFacets();
  });
  $('tree-filter').addEventListener('input', renderTree);
  $('tree').addEventListener('click', treeClick);
  $('facets').addEventListener('click', facetClick);
  $('matrix').addEventListener('click', matrixClick);
  $('matrix-panel').addEventListener('toggle', () => {
    if ($('matrix-panel').open) runQuery();
  });
  for (const [id, i] of [['matrix-a', 0], ['matrix-b', 1]]) {
    $(id).addEventListener('change', () => {
      state.matrix[i] = $(id).value;
      update({ keepPage: true });
    });
  }
  $('live').addEventListener('click', () => {
    live = !live;
    $('live').classList.toggle('on', live);
    if (live) refreshNow();
  });
  $('limit').addEventListener('change', () => {
    state.limit = Number($('limit').value);
    localStorage.setItem(PREF_LIMIT, state.limit);
    update();
  });
  $('prev').addEventListener('click', () => { state.page = Math.max(0, state.page - 1); update({ keepPage: true }); });
  $('next').addEventListener('click', () => { state.page++; update({ keepPage: true }); });

  $('files-head').addEventListener('click', ev => {
    const th = ev.target.closest('[data-sort]');
    if (th) {
      const key = th.dataset.sort;
      const i = state.sort.findIndex(([k]) => k === key);
      const desc = ['size', 'time', 'posted', 'conf', 'slices'].includes(key);
      if (ev.shiftKey) {
        if (i >= 0) state.sort[i][1] = !state.sort[i][1];
        else state.sort.push([key, desc]);
      } else {
        state.sort = [[key, i === 0 && state.sort.length === 1 ? !state.sort[0][1] : desc]];
      }
      update();
      return;
    }
    if (ev.target.id === 'sel-page') {
      for (const r of data.rows) {
        if (ev.target.checked) selected.set(r.sha256, r);
        else selected.delete(r.sha256);
      }
      renderTable();
    }
  });
  $('files-rows').addEventListener('click', ev => {
    const tr = ev.target.closest('tr[data-sha]');
    if (!tr) return;
    const i = Number(tr.dataset.i);
    if (ev.target.closest('a')) return;
    if (ev.target.closest('td.sel')) {
      const pick = !selected.has(tr.dataset.sha);
      const [a, b] = ev.shiftKey && lastChecked >= 0 ? [Math.min(lastChecked, i), Math.max(lastChecked, i)] : [i, i];
      for (let j = a; j <= b; j++) {
        const r = data.rows[j];
        if (pick) selected.set(r.sha256, r);
        else selected.delete(r.sha256);
      }
      lastChecked = i;
      renderTable();
      return;
    }
    cursor = i;
    openFile(tr.dataset.sha);
  });
  $('columns').addEventListener('change', ev => {
    const key = ev.target.dataset.col;
    if (!key) return;
    columns = ev.target.checked ? COLUMNS.map(c => c.key).filter(k => k === key || columns.includes(k)) : columns.filter(k => k !== key);
    localStorage.setItem(PREF_COLUMNS, JSON.stringify(columns));
    renderTable();
  });
  $('columns').addEventListener('click', ev => {
    if (ev.target.id !== 'cols-reset') return;
    columns = COLUMNS.filter(c => c.def).map(c => c.key);
    localStorage.removeItem(PREF_COLUMNS);
    renderColumns();
    renderTable();
  });

  const selRows = () => [...selected.values()];
  $('sel-copy').addEventListener('click', ev => copy(selRows().map(r => r.sha256).join('\n'), ev.target));
  $('sel-csv').addEventListener('click', () => {
    const head = 'sha256,name,size,donor,kind,isa,isas,family,format,bits,endian,status,received_at,posted_at,telegram\n';
    const q = v => (v == null ? '' : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
    saveText('fwdonor-selection.csv', head + selRows().map(r => [r.sha256, r.name, r.size, r.donor, r.kind, r.isa, r.isas.join(' '), r.family, r.format, r.bits, r.endian, PUBLIC ? (r.stored ? 'stored' : 'not yet') : r.status, r.received_at, r.posted_at, r.telegram].map(q).join(',')).join('\n') + '\n', 'text/csv');
  });
  $('sel-sum').addEventListener('click', () => saveText('fwdonor-selection.sha256', selRows().filter(isStored).map(r => `${r.sha256}  ${r.sha256}\n`).join('')));
  $('sel-rsync').addEventListener('click', () => saveText('fwdonor-selection.files.txt', selRows().filter(isStored).map(r => `${r.sha256}\n${r.sha256}.json\n`).join('')));
  $('sel-clear').addEventListener('click', () => {
    selected.clear();
    renderTable();
  });

  for (const id of ['s-stored-sub', 's-backfill-sub']) {
    $(id).addEventListener('click', ev => {
      const a = ev.target.closest('[data-status]');
      if (!a) return;
      ev.preventDefault();
      state.f.status = { in: [a.dataset.status], out: [] };
      update();
    });
  }

  $('d-close').addEventListener('click', closeDrawer);
  $('d-prev').addEventListener('click', () => step(-1));
  $('d-next').addEventListener('click', () => step(1));
  $('d-body').addEventListener('click', ev => {
    const dl = ev.target.closest('[data-download]');
    if (dl) return downloadWithProof(dl.dataset.download, dl);
    const c = ev.target.closest('[data-copy]');
    if (c) return copy(c.dataset.copy, c);
    const o = ev.target.closest('[data-open]');
    if (o) return openFile(o.dataset.open, { focusRow: false });
    const only = ev.target.closest('[data-only]');
    if (only) {
      state.f[only.dataset.only] = { in: [only.dataset.key], out: [] };
      return update();
    }
    const s = ev.target.closest('[data-search]');
    if (s) {
      state.q = s.dataset.search;
      $('search').value = state.q;
      update();
    }
  });

  $('help-open').addEventListener('click', () => { $('help').hidden = false; });
  $('help-close').addEventListener('click', () => { $('help').hidden = true; });
  document.addEventListener('tzchange', () => {
    render();
    if (summary) renderSummary(summary);
  });
  document.addEventListener('keydown', keys);
  // Charts are drawn to their width: redraw when it changes (only then; a
  // redraw changes their height for a moment, which must not loop).
  let chartWidth = 0;
  new ResizeObserver(([entry]) => {
    const w = Math.round(entry.contentRect.width);
    if (w === chartWidth) return;
    chartWidth = w;
    if (!data) return;
    if (pointer.down) window.addEventListener('pointerup', () => setTimeout(renderHists), { once: true });
    else renderHists();
  }).observe($('h-time'));
  window.addEventListener('hashchange', () => {
    if (location.hash.slice(1) === hashOf(state)) return;
    state = parseHash();
    $('search').value = state.q;
    $('multi').checked = state.multi;
    renderTreeLevels();
    runQuery();
    if (state.open) openFile(state.open, { focusRow: false });
    else if (!$('drawer').hidden) closeDrawer();
  });
}

function moveCursor(delta) {
  if (!data?.rows.length) return;
  cursor = Math.min(data.rows.length - 1, Math.max(0, cursor + delta));
  for (const tr of $('files-rows').querySelectorAll('tr.cursor')) tr.classList.remove('cursor');
  const tr = $('files-rows').querySelector(`tr[data-i="${cursor}"]`);
  tr?.classList.add('cursor');
  tr?.scrollIntoView({ block: 'nearest' });
}

function keys(ev) {
  const typing = ev.target.closest('input, select, textarea');
  if (ev.key === 'Escape') {
    if (!$('help').hidden) $('help').hidden = true;
    else if (typing) ev.target.blur();
    else if (!$('drawer').hidden) closeDrawer();
    return;
  }
  if (typing || ev.metaKey || ev.ctrlKey || ev.altKey) return;
  const drawerOpen = !$('drawer').hidden;
  switch (ev.key) {
    case '/': ev.preventDefault(); $('search').focus(); break;
    case 'j': case 'ArrowDown': ev.preventDefault(); if (drawerOpen) step(1); else moveCursor(1); break;
    case 'k': case 'ArrowUp': ev.preventDefault(); if (drawerOpen) step(-1); else moveCursor(-1); break;
    case 'Enter': if (data?.rows[cursor]) openFile(data.rows[cursor].sha256); break;
    case 'x': {
      const r = data?.rows[cursor];
      if (r) {
        if (selected.has(r.sha256)) selected.delete(r.sha256);
        else selected.set(r.sha256, r);
        renderTable();
      }
      break;
    }
    case '[': if (drawerOpen) step(-1); else if (state.page > 0) { state.page--; update({ keepPage: true }); } break;
    case ']': if (drawerOpen) step(1); else if (!$('next').disabled) { state.page++; update({ keepPage: true }); } break;
    case 'l': case 'L': $('live').click(); break;
    case '?': $('help').hidden = !$('help').hidden; break;
    default:
  }
}

let refreshNow = () => {};
state = parseHash();
wire();
refreshNow = poll(refreshSummary, 5000);
if (state.open) openFile(state.open, { focusRow: false });
