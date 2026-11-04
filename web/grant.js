// Admin page (/g/<key>): issue bulk links (/r/<token>) with a fixed donor
// name and a storage ceiling, and see or revoke the existing ones.
import { esc } from './format.js';
import { describe } from './common.js';

const $ = id => document.getElementById(id);
const KEY = location.pathname.split('/').filter(Boolean)[1] ?? '';
const API = `/api/admin/${encodeURIComponent(KEY)}/grants`;

function size(bytes) {
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

const linkFor = token => `${location.origin}/r/${token}`;
const date = unix => new Date(unix * 1000).toISOString().slice(0, 16).replace('T', ' ');

async function api(method, path, body) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error('server unreachable');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function copy(text, button) {
  navigator.clipboard?.writeText(text).then(() => {
    const label = button.textContent;
    button.textContent = 'copied';
    setTimeout(() => { button.textContent = label; }, 1200);
  }, () => {});
}

let grants = [];

function render(data) {
  grants = data.grants;
  $('store-dir').textContent = data.dir;
  const live = grants.filter(g => !g.revoked_at).length;
  $('grant-count').textContent = `${live}${grants.length > live ? ` · ${grants.length - live} revoked` : ''}`;
  const over = data.claimable + data.disk.min_free > data.disk.free;
  $('disk').innerHTML = `disk: ${size(data.disk.free)} free of ${size(data.disk.total)} · open links can still claim `
    + `<span class="${over ? 'over' : ''}">${size(data.claimable)}</span>`;
  $('grant-rows').innerHTML = grants.map(g => {
    const share = n => `${Math.min(100, (100 * n) / Math.max(1, g.ceiling)).toFixed(2)}`;
    return `<tr class="${g.revoked_at ? 'revoked' : ''}">
      <td><strong>${esc(g.name)}</strong></td>
      <td class="note">${esc(g.note)}</td>
      <td class="num">${size(g.ceiling)}</td>
      <td><div class="mini-quota" data-used="${share(g.used)}" data-reserved="${share(g.reserved)}"><i class="used"></i><i class="reserved"></i></div>
        <small>${size(g.used)}${g.reserved ? ` + ${size(g.reserved)} in progress` : ''}</small></td>
      <td class="num">${g.files}</td>
      <td class="num">${g.unfinished}</td>
      <td>${date(g.created_at)}${g.revoked_at ? `<br><small>revoked ${date(g.revoked_at)}</small>` : ''}</td>
      <td>${g.revoked_at ? '' : `<div class="actions"><button type="button" data-copy="${esc(g.token)}">copy link</button>
        <button type="button" class="danger" data-revoke="${esc(g.token)}">revoke</button></div>`}</td>
    </tr>`;
  }).join('');
  // Widths through CSSOM: the CSP forbids inline style attributes.
  for (const bar of $('grant-rows').querySelectorAll('.mini-quota')) {
    bar.querySelector('.used').style.width = `${bar.dataset.used}%`;
    bar.querySelector('.reserved').style.width = `${bar.dataset.reserved}%`;
  }
  $('status').textContent = `${live} open link${live === 1 ? '' : 's'}`;
}

async function refresh() {
  try {
    render(await api('GET', API));
    $('banner').hidden = true;
  } catch (err) {
    $('banner').textContent = `Could not load the links: ${describe(err)}`;
    $('banner').hidden = false;
  }
}

$('grant-form').addEventListener('submit', async event => {
  event.preventDefault();
  const name = $('g-name').value.trim();
  const ceiling = Math.round(Number($('g-amount').value) * Number($('g-unit').value));
  $('g-error').textContent = '';
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) {
    $('g-error').textContent = 'the name must be 1 to 32 letters, digits, _ . or -';
    return;
  }
  if (!(ceiling > 0)) {
    $('g-error').textContent = 'the ceiling must be more than 0';
    return;
  }
  $('g-submit').disabled = true;
  try {
    const grant = await api('POST', API, { name, ceiling_bytes: ceiling, note: $('g-note').value });
    $('r-name').textContent = grant.name;
    $('r-ceiling').textContent = size(grant.ceiling);
    $('r-url').textContent = linkFor(grant.token);
    $('grant-result').hidden = false;
    $('g-name').value = '';
    $('g-note').value = '';
    refresh();
  } catch (err) {
    $('g-error').textContent = describe(err);
  } finally {
    $('g-submit').disabled = false;
  }
});

$('g-name').addEventListener('input', () => {
  const el = $('g-name');
  const clean = el.value.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 32);
  if (clean !== el.value) el.value = clean;
});

$('r-copy').addEventListener('click', event => copy($('r-url').textContent, event.target));

$('grant-rows').addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button) return;
  if (button.dataset.copy) {
    copy(linkFor(button.dataset.copy), button);
    return;
  }
  const token = button.dataset.revoke;
  const g = grants.find(x => x.token === token);
  if (!g || !confirm(`Revoke the link for ${g.name}? Its ${g.unfinished} unfinished upload(s) are discarded; the ${g.files} stored file(s) stay.`)) return;
  button.disabled = true;
  try {
    await api('DELETE', `${API}/${encodeURIComponent(token)}`);
  } catch (err) {
    alert(`Could not revoke: ${describe(err)}`);
  }
  refresh();
});

refresh();
setInterval(refresh, 15000);
