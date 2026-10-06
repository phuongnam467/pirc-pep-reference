/**
 * Observability hooks — opt-in, dependency-free, purity-preserving.
 *
 * Design rules (see SPEC.md philosophy):
 *   - No global state, no singletons: a metrics registry is created
 *     explicitly and passed where it is wanted. Verifiers stay pure;
 *     determinism of verdicts can never depend on whether observation
 *     is enabled or not.
 *   - Fail-open ONLY for telemetry: recording never throws into the
 *     caller's path, because losing a metric must never change a
 *     security decision. (The inverse — letting telemetry alter
 *     verification — would be a trust-boundary violation.)
 *   - Bounded memory: stored latencies are capped by ring buffer, so a
 *     hostile request stream cannot grow the process without bound.
 *
 * Wire it anywhere:
 *   const m = createMetricsRegistry();
 *   verifyPiProof(proof, { registry, nonceStore, now, metrics: m });
 *   m.snapshot(); // → plain JSON-serializable object
 */

const LATENCY_CAP = 10_000;

export function createMetricsRegistry({ clock = () => Date.now() } = {}) {
  const kinds = new Map();
  const startedAt = clock();

  function kind(name) {
    let k = kinds.get(name);
    if (!k) {
      k = { total: 0, ok: 0, fail: 0, codes: Object.create(null), latencies: [] };
      kinds.set(name, k);
    }
    return k;
  }

  return {
    startedAt,

    /**
     * Record one observed operation.
     * @param {string} name      e.g. 'proof_verify'
     * @param {object} [fields]  { ok?: boolean, code?: string|null,
     *                             durationMs?: number }
     */
    record(name, { ok, code = null, durationMs = null } = {}) {
      try {
        const k = kind(name);
        k.total++;
        if (ok === true) k.ok++;
        else if (ok === false) k.fail++;
        if (code != null) k.codes[code] = (k.codes[code] || 0) + 1;
        if (Number.isFinite(durationMs) && durationMs >= 0) {
          if (k.latencies.length >= LATENCY_CAP) k.latencies.shift();
          k.latencies.push(durationMs);
        }
      } catch {
        /* telemetry must never break verification */
      }
    },

    /** Plain JSON object; stable key order; percentiles over capped samples. */
    snapshot() {
      const out = {
        schema: 'AUREVIA-Metrics/1',
        uptime_ms: Math.max(0, clock() - startedAt),
        kinds: {}
      };
      for (const name of [...kinds.keys()].sort()) {
        const k = kinds.get(name);
        const lat = [...k.latencies].sort((a, b) => a - b);
        const pct = (p) =>
          lat.length === 0
            ? null
            : Number(lat[Math.min(lat.length - 1, Math.max(0, Math.ceil((p / 100) * lat.length) - 1))].toFixed(3));
        const codes = {};
        for (const c of Object.keys(k.codes).sort()) codes[c] = k.codes[c];
        out.kinds[name] = {
          total: k.total,
          ok: k.ok,
          fail: k.fail,
          rejection_codes: codes,
          latency_ms: {
            samples: lat.length,
            p50: pct(50),
            p95: pct(95),
            p99: pct(99)
          }
        };
      }
      return out;
    }
  };
}

/** Convenience wrapper around a synchronous fn: records outcome + duration. */
export function timed(metrics, name, fn) {
  const t0 = performance.now();
  try {
    const result = fn();
    const d = performance.now() - t0;
    metrics.record(name, {
      ok: result?.ok === true ? true : result?.ok === false ? false : undefined,
      code: result?.code ?? null,
      durationMs: d
    });
    return result;
  } catch (err) {
    metrics.record(name, { ok: false, code: 'THREW', durationMs: performance.now() - t0 });
    throw err;
  }
}
