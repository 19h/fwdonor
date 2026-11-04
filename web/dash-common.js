// Shared by the dashboard pages (/d/<key> and /d/<key>/bulk): the API client,
// formatting, small DOM and SVG helpers, and a histogram with a brush.
import { describe } from './common.js';

export { describe };
export { esc } from './format.js';

// The public dashboard (/dashboard) has no key and no operational parts.
export const PUBLIC = location.pathname.replace(/\/+$/, '') === '/dashboard';
export const KEY = PUBLIC ? '' : location.pathname.split('/').filter(Boolean)[1] ?? '';
export const API = PUBLIC ? '/api/dashboard' : `/api/dash/${encodeURIComponent(KEY)}`;
if (PUBLIC) document.body.classList.add('public');
export const $ = id => document.getElementById(id);

export async function api(path, { signal } = {}) {
  let res;
  try {
    res = await fetch(`${API}${path}`, { signal });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw Object.assign(new Error('server unreachable'), { status: 0 });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw Object.assign(new Error(data.message || `HTTP ${res.status}`), {
      status: res.status, code: data.error, retryAfter: Number(res.headers.get('retry-after')) || 0,
    });
  }
  return data;
}

// Decimal units, as on the grant pages.
export function size(bytes) {
  if (bytes == null) return '–';
  if (bytes < 1000) return `${bytes} B`;
  const units = ['kB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let u = -1;
  do {
    v /= 1000;
    u++;
  } while (v >= 1000 && u < units.length - 1);
  return `${Number(v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2))} ${units[u]}`;
}

export const num = n => (n ?? 0).toLocaleString('en-US');

export function rate(bytesPerSec) {
  return bytesPerSec > 0 ? `${size(Math.round(bytesPerSec))}/s` : '–';
}

export function duration(secs) {
  if (!(secs >= 0) || !Number.isFinite(secs)) return '–';
  if (secs < 60) return `${Math.round(secs)} s`;
  if (secs < 3600) return `${Math.floor(secs / 60)} min ${Math.round(secs % 60)} s`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ${Math.round((secs % 3600) / 60)} min`;
  return `${Math.floor(secs / 86400)} d ${Math.round((secs % 86400) / 3600)} h`;
}

// Times are UTC unless the page is switched to local time.
const PREF_TZ = 'fwdonor.dash.local';
export let localTime = localStorage.getItem(PREF_TZ) === '1';
export function setLocalTime(on) {
  localTime = on;
  localStorage.setItem(PREF_TZ, on ? '1' : '0');
}

export function time(unix, { seconds = false } = {}) {
  if (!unix) return '–';
  const d = new Date(unix * 1000);
  const pad = n => String(n).padStart(2, '0');
  const [y, mo, da, h, mi, s] = localTime
    ? [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()]
    : [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()];
  return `${y}-${pad(mo)}-${pad(da)} ${pad(h)}:${pad(mi)}${seconds ? `:${pad(s)}` : ''}`;
}

export function ago(unix, now = Date.now() / 1000) {
  if (!unix) return '–';
  const s = Math.max(0, now - unix);
  if (s < 90) return `${Math.round(s)} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function copy(text, button) {
  navigator.clipboard?.writeText(text).then(() => {
    if (!button) return;
    const label = button.textContent;
    button.textContent = 'copied';
    button.classList.add('copied');
    setTimeout(() => {
      button.textContent = label;
      button.classList.remove('copied');
    }, 1200);
  }, () => {});
}

// A file made in the page (selection exports).
export function saveText(name, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// Element widths go through the CSSOM: the CSP forbids style attributes.
export function widths(root) {
  for (const el of root.querySelectorAll('[data-w]')) el.style.width = `${el.dataset.w}%`;
}

export function setTabs() {
  for (const el of document.querySelectorAll('.private-only')) el.hidden = PUBLIC;
  for (const el of document.querySelectorAll('.public-only')) el.hidden = !PUBLIC;
  for (const a of document.querySelectorAll('[data-tab]')) {
    a.href = a.dataset.tab === 'bulk' ? `/d/${KEY}/bulk` : `/d/${KEY}`;
  }
  const local = $('tz');
  if (local) {
    local.textContent = localTime ? 'local time' : 'UTC';
    local.addEventListener('click', () => {
      setLocalTime(!localTime);
      local.textContent = localTime ? 'local time' : 'UTC';
      document.dispatchEvent(new Event('tzchange'));
    });
  }
}

const SVG = 'http://www.w3.org/2000/svg';
export function svg(tag, attrs = {}, parent) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (parent) parent.append(el);
  return el;
}

// Set while a chart is being dragged: redraws wait until it ends.
export const pointer = { down: false };

// A bar chart of buckets ({lo, hi, files, bytes}) in `host`. Dragging across
// bars (or clicking one) selects a range: onSelect(lo, hi). `selected` is the
// current [lo, hi] or null. `metric` is files or bytes; `label` formats a
// bucket's range for the tooltip.
export function histogram(host, buckets, { onSelect, selected, metric = 'files', label, height = 64, scale = 'sqrt' } = {}) {
  host.replaceChildren();
  if (!buckets.length) {
    host.textContent = 'no data';
    host.classList.add('empty');
    return;
  }
  host.classList.remove('empty');
  const w = Math.max(1, host.clientWidth || 600);
  const h = height;
  const root = svg('svg', { viewBox: `0 0 ${w} ${h}`, width: w, height: h, class: 'hist' }, host);
  const values = buckets.map(b => b[metric] ?? 0);
  const max = Math.max(1, ...values);
  const f = scale === 'sqrt' ? v => Math.sqrt(v / max) : v => v / max;
  const bw = w / buckets.length;
  const sel = svg('rect', { class: 'hist-sel', x: 0, y: 0, width: 0, height: h }, root);
  buckets.forEach((b, i) => {
    const bh = values[i] ? Math.max(1, f(values[i]) * (h - 2)) : 0;
    const inRange = selected && b.hi >= selected[0] && b.lo <= selected[1];
    const bar = svg('rect', {
      x: i * bw + (bw > 3 ? 0.5 : 0), y: h - bh, width: Math.max(0.5, bw - (bw > 3 ? 1 : 0)), height: bh,
      class: `hist-bar${inRange ? ' on' : ''}${selected && !inRange ? ' off' : ''}`,
    }, root);
    svg('title', {}, bar).textContent = `${label ? label(b) : `${b.lo}–${b.hi}`}: ${num(b.files)} files, ${size(b.bytes)}`;
    // A transparent target covers the whole column (tiny bars stay clickable).
    const hit = svg('rect', { x: i * bw, y: 0, width: bw, height: h, class: 'hist-hit', 'data-i': i }, root);
    svg('title', {}, hit).textContent = bar.firstChild.textContent;
  });
  if (!onSelect) return;
  let start = null;
  const index = ev => {
    const r = root.getBoundingClientRect();
    return Math.min(buckets.length - 1, Math.max(0, Math.floor(((ev.clientX - r.left) / r.width) * buckets.length)));
  };
  const show = (a, b) => {
    const [x, y] = a <= b ? [a, b] : [b, a];
    sel.setAttribute('x', x * bw);
    sel.setAttribute('width', (y - x + 1) * bw);
  };
  root.addEventListener('pointerdown', ev => {
    pointer.down = true;
    start = index(ev);
    root.setPointerCapture(ev.pointerId);
    show(start, start);
  });
  root.addEventListener('lostpointercapture', () => {
    pointer.down = false;
  });
  root.addEventListener('pointermove', ev => {
    if (start != null) show(start, index(ev));
  });
  root.addEventListener('pointerup', ev => {
    pointer.down = false;
    if (start == null) return;
    const end = index(ev);
    const [a, b] = start <= end ? [start, end] : [end, start];
    start = null;
    sel.setAttribute('width', 0);
    onSelect(buckets[a].lo, buckets[b].hi);
  });
}

// Polls `fn` every `ms`, waiting longer after failures; returns a function
// that polls right away.
export function poll(fn, ms) {
  let timer = null;
  let failures = 0;
  const run = async () => {
    clearTimeout(timer);
    try {
      await fn();
      failures = 0;
      timer = setTimeout(run, ms);
    } catch (err) {
      failures++;
      const wait = Math.min(20, err.retryAfter || 2 ** Math.min(failures - 1, 4)) * 1000;
      timer = setTimeout(run, Math.max(ms, wait));
    }
  };
  run();
  return run;
}

export function banner(err) {
  const el = $('banner');
  if (!el) return;
  if (!err) {
    el.hidden = true;
    return;
  }
  el.textContent = err.status === 404 && !PUBLIC ? 'This dashboard link is not valid (any more).' : `The server is not answering: ${describe(err)}. Retrying…`;
  el.hidden = false;
}
