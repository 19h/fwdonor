// Classifies one file at a time with zrax (WASM) and hashes it.
// zrax is built with panic=abort: a trap kills this worker, and the page
// replaces it and marks that file as failed.
import init, { classify, classifier_version } from './zrax.js';

const ready = init().then(
  () => self.postMessage({ type: 'ready', version: classifier_version() }),
  error => self.postMessage({ type: 'boot-error', error: String(error?.message ?? error) }),
);

self.onmessage = async ({ data }) => {
  const { id, file } = data;
  await ready;
  try {
    const buffer = await file.arrayBuffer();
    const started = performance.now();
    const payload = JSON.parse(classify(new Uint8Array(buffer)));
    const elapsed = performance.now() - started;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
    const sha256 = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
    self.postMessage({ type: 'result', id, payload, sha256, elapsed });
  } catch (error) {
    self.postMessage({ type: 'result', id, payload: null, error: String(error?.message ?? error) });
  }
};
