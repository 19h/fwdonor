// Shared by the donation page (app.js) and the bulk pages (bulk.js, grant.js):
// retry rules and reading dropped files and folders.

// Waiting for the server never gives up; it just never waits longer than this.
export const MAX_BACKOFF_S = 20;

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// The proxy answers for fwdonor while it is down (its own errors carry a code).
export const proxyError = err => [502, 503, 504].includes(err.status) && !err.code;

// Worth waiting for: no answer, proxy errors, server-side trouble, rate limits
// and pauses. Everything else (rejections, bad requests) is final.
export const transient = err => !err.status || err.status >= 500 || err.status === 408 || err.status === 429;

export function describe(err) {
  if (!err.status) return 'server unreachable';
  if (proxyError(err)) return 'server restarting';
  return err.message || `HTTP ${err.status}`;
}

// 1, 2, 4 … 20 s, or the server's Retry-After (capped).
export const backoff = (failures, retryAfter = 0) =>
  Math.min(MAX_BACKOFF_S, retryAfter > 0 ? retryAfter : 2 ** Math.min(failures - 1, 5));

// Files and folders from a drop, with their relative paths. Hidden entries
// inside folders (.DS_Store, .git …) are skipped.
export async function itemsFromDrop(dataTransfer) {
  // webkitGetAsEntry must be read synchronously inside the drop handler.
  const entries = [...dataTransfer.items]
    .filter(item => item.kind === 'file')
    .map(item => item.webkitGetAsEntry?.())
    .filter(Boolean);
  if (!entries.length) return [...dataTransfer.files].map(file => ({ file, path: file.name }));
  const out = [];
  const fileOf = entry => new Promise((resolve, reject) => entry.file(resolve, reject));
  const readBatch = reader => new Promise((resolve, reject) => reader.readEntries(resolve, reject));
  async function walk(entry, prefix) {
    if (entry.isFile) {
      out.push({ file: await fileOf(entry), path: prefix + entry.name });
      return;
    }
    if (!entry.isDirectory) return;
    const reader = entry.createReader();
    // readEntries returns at most ~100 entries per call.
    for (let batch = await readBatch(reader); batch.length; batch = await readBatch(reader)) {
      for (const child of batch) {
        if (child.name.startsWith('.')) continue;
        await walk(child, `${prefix}${entry.name}/`);
      }
    }
  }
  for (const entry of entries) await walk(entry, '');
  return out;
}
