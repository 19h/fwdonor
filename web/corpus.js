// Live corpus statistics: how much has been donated, files per ISA, and the
// ISAs zrax can recognize from raw code that the corpus still lacks.
import { esc, fmtSize, fmtFormatName } from './format.js';

const REFRESH_MS = 15000;
const WANTED_BELOW = 5;
const FEWEST = 10;
const TOP_ISAS = 12;
const TOP_FORMATS = 10;

const $ = id => document.getElementById(id);
const nf = new Intl.NumberFormat('en-US');
const calm = matchMedia('(prefers-reduced-motion: reduce)');

let timer = null;
let soon = null;
let expanded = false;
let latest = null;
let shownFiles = 0;
let tweenToken = 0;

// Count the big number up to its new value.
function countTo(el, from, to) {
  const token = ++tweenToken;
  if (calm.matches || from === to) {
    el.textContent = nf.format(to);
    return;
  }
  const start = performance.now();
  const duration = Math.min(1400, 400 + 25 * Math.abs(to - from));
  const step = now => {
    if (token !== tweenToken) return;
    const t = Math.min(1, (now - start) / duration);
    el.textContent = nf.format(Math.round(from + (to - from) * (1 - (1 - t) ** 3)));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function ago(secs) {
  if (secs < 60) return `${Math.max(0, secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86400)} d ago`;
}

function render(s) {
  $('corpus').hidden = false;
  countTo($('corpus-files'), shownFiles, s.files);
  shownFiles = s.files;
  $('corpus-bytes').textContent = s.bytes ? fmtSize(s.bytes) : '0 B';
  $('corpus-hour').textContent = nf.format(s.last_hour);
  const seen = s.isas.filter(i => i.files > 0);
  $('corpus-isa-count').textContent = nf.format(seen.length);
  $('corpus-last').textContent = s.last_at ? `last donation ${ago(s.now - s.last_at)}` : 'waiting for the first donation';

  // Files per ISA, largest first; containers without an ISA come last.
  const rows = seen.map(i => ({ name: i.name, files: i.files, bytes: i.bytes }));
  const shown = expanded ? rows : rows.slice(0, TOP_ISAS);
  if (s.no_isa.files && (expanded || rows.length <= TOP_ISAS)) {
    shown.push({ name: 'no ISA (container)', files: s.no_isa.files, bytes: s.no_isa.bytes, cls: 'none' });
  }
  const max = Math.max(1, ...shown.map(r => r.files));
  const list = $('corpus-isa-list');
  list.innerHTML = shown.length
    ? shown.map(r => `<li${r.cls ? ` class="${r.cls}"` : ''} title="${esc(r.name)}: ${nf.format(r.files)} image${r.files === 1 ? '' : 's'}, ${fmtSize(r.bytes)}">`
      + `<span class="n">${esc(r.name)}</span><span class="track"><i></i></span><span class="c">${nf.format(r.files)}</span></li>`).join('')
    : '<li class="none"><span class="n">nothing yet</span></li>';
  // Widths go through CSSOM: the CSP forbids inline style attributes.
  list.querySelectorAll('.track > i').forEach((bar, k) => {
    bar.style.width = `${Math.max(0.75, (shown[k].files / max) * 100)}%`;
  });
  const more = $('corpus-more');
  more.hidden = rows.length <= TOP_ISAS;
  more.textContent = expanded ? `show top ${TOP_ISAS}` : `show all ${rows.length}${s.no_isa.files ? ' + containers' : ''}`;

  // What to look for next: raw-code ISAs with few or no images. Once every
  // one has WANTED_BELOW, the ones with the fewest (ties at the cut included).
  const raw = s.isas.filter(i => i.raw)
    .sort((a, b) => a.files - b.files || a.name.localeCompare(b.name));
  let wanted = raw.filter(i => i.files < WANTED_BELOW);
  const fewest = !wanted.length && raw.length > 0;
  if (fewest) {
    const cut = raw[Math.min(FEWEST, raw.length) - 1].files;
    wanted = raw.filter(i => i.files <= cut);
  }
  $('corpus-raw-count').textContent = raw.length;
  $('corpus-wanted-count').textContent = wanted.length;
  $('corpus-wanted-why').textContent = fewest
    ? 'Every one has at least five images now. These have the fewest, so firmware for them still helps the most:'
    : 'These still have fewer than five images in the corpus, so firmware for them helps the most:';
  $('corpus-wanted').innerHTML = wanted.length
    ? wanted.map(i => `<li class="${i.files ? 'few' : 'zero'}" title="${i.files ? `${nf.format(i.files)} image${i.files === 1 ? '' : 's'} so far` : 'none yet'}">`
      + `${esc(i.name)}${i.files ? `<b>${nf.format(i.files)}</b>` : ''}</li>`).join('')
    : '<li class="few">nothing yet</li>';

  $('corpus-formats').innerHTML = s.formats.length
    ? '<span>formats</span>' + s.formats.slice(0, TOP_FORMATS)
      .map(f => `<span>${esc(f.format === 'raw' ? 'raw code' : fmtFormatName(f.format))} <b>${nf.format(f.files)}</b></span>`).join('')
      + (s.formats.length > TOP_FORMATS ? `<span>+${s.formats.length - TOP_FORMATS} more</span>` : '')
    : '';
}

async function refresh() {
  clearTimeout(timer);
  try {
    const res = await fetch('/api/stats', { cache: 'no-store' });
    if (res.ok) {
      latest = await res.json();
      render(latest);
    }
  } catch {
    // Keep showing the last numbers; the next tick tries again.
  }
  timer = setTimeout(tick, REFRESH_MS);
}

function tick() {
  if (document.visibilityState === 'visible') refresh();
  else timer = setTimeout(tick, REFRESH_MS);
}

export function startCorpus() {
  $('corpus-more').addEventListener('click', () => {
    expanded = !expanded;
    if (latest) render(latest);
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refresh();
  });
  refresh();
}

// One of our files was posted: refresh shortly (coalesced across a batch).
export function corpusChanged() {
  soon ??= setTimeout(() => {
    soon = null;
    refresh();
  }, 1500);
}
