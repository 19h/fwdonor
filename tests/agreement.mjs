// Browser/server agreement: run zrax WASM + web/policy.js and the native
// `fwdonor check` over the same files; every accept/reject must match.
//
//   node tests/agreement.mjs <file-list.txt>      (one path per line)
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'target/release/fwdonor');
const { default: init, classify } = await import(path.join(root, 'vendor/zrax/pkg/zrax.js'));
const { judge } = await import(path.join(root, 'web/policy.js'));
await init({ module_or_path: readFileSync(path.join(root, 'vendor/zrax/pkg/zrax_bg.wasm')) });

const policy = JSON.parse(execFileSync(bin, ['policy'], { encoding: 'utf8' }));
const files = readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean);

const native = new Map();
for (let i = 0; i < files.length; i += 500) {
  const out = execFileSync(bin, ['check', '--json', ...files.slice(i, i + 500)], { encoding: 'utf8', maxBuffer: 1 << 28 });
  for (const line of out.trim().split('\n')) {
    const { path: p, result } = JSON.parse(line);
    native.set(p, result.verdict === 'accepted');
  }
}

let mismatches = 0, accepted = 0;
for (const file of files) {
  const size = statSync(file).size;
  let accept;
  if (size > policy.max_file_bytes) accept = false;
  else accept = judge(JSON.parse(classify(readFileSync(file))), policy.policy).accept;
  if (accept) accepted++;
  if (accept !== native.get(file)) {
    mismatches++;
    console.log(`MISMATCH wasm=${accept} native=${native.get(file)} ${file}`);
  }
}
console.log(`${files.length} files, ${accepted} accepted, ${mismatches} mismatches`);
process.exit(mismatches ? 1 : 0);
