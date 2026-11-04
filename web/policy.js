// Donation rule, mirrored from src/analyze.rs (`judge`). The server's copy is
// authoritative; both read the same lists from /api/policy, and
// tests/agreement.mjs checks the two agree over a corpus.

const GUESSED = new Set(['heuristic', 'combined']);

export function judge(payload, policy) {
  if (!payload || payload.error) {
    const error = String(payload?.error ?? 'analysis failed');
    if (/^(Heuristic analysis inconclusive|File too small)/.test(error)) {
      return { accept: false, reason: 'unrecognized by zrax' };
    }
    return { accept: false, reason: `malformed: ${error}` };
  }
  const format = typeof payload.format?.format === 'string' ? payload.format.format : 'unknown';
  if (policy.deny.includes(format)) return { accept: false, reason: `excluded format (${format})` };

  const p = payload.primary ?? {};
  const concrete = typeof p.isa === 'string';
  const guessed = GUESSED.has(p.source);
  const primaryOk = concrete && (!guessed || p.confidence >= policy.min_guess_confidence);
  const sliceOk = (payload.slices ?? []).some(s => typeof s.isa === 'string');

  if (primaryOk || sliceOk) return { accept: true, basis: 'isa' };
  if (policy.allow.includes(format)) return { accept: true, basis: 'container' };
  if (concrete) {
    const pct = v => Math.round(v * 100);
    return { accept: false, reason: `low-confidence guess (${pct(p.confidence)}% < ${pct(policy.min_guess_confidence)}%)` };
  }
  return { accept: false, reason: `no ISA found in ${format}` };
}
