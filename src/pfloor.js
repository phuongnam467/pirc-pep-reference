import { CanonicalError } from './canonical.js';

/**
 * PiRC1 — Transparency Layer: Dynamic p_floor & x·y=k invariant tracking.
 *
 * Implements the ideas endorsed in the PiRC1 review:
 *  - "Dynamic p_floor Calculation: real-time calculation of the
 *    theoretical lower bound based on current circulating supply."
 *  - "Track the x·y=k invariant: monitoring the pool's health to
 *    ensure that p_floor remains mathematically intact."
 *
 * All functions are pure and side-effect free. Inputs are plain
 * numbers; callers are responsible for sourcing them from verifiable
 * feeds. Nothing here prices, values or endorses any asset: this is
 * descriptive AMM mathematics only.
 */

function assertPositiveFinite(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive finite number`);
  }
}

function assertNonNegativeFinite(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative finite number`);
  }
}

/**
 * Spot price of a constant-product pool.
 *
 *   spot = Q / R        (quote units per token)
 */
export function spotPrice(tokenReserve, quoteReserve) {
  assertPositiveFinite(tokenReserve, 'tokenReserve');
  assertPositiveFinite(quoteReserve, 'quoteReserve');
  return quoteReserve / tokenReserve;
}

/**
 * Dynamic theoretical floor price.
 *
 * If the entire circulating supply S were sold into the pool, the
 * marginal price after the last token lands is:
 *
 *   p_floor = (R · Q) / (R + S)²
 *
 * This is the worst-case mathematical lower bound implied by the
 * pool alone. It is dynamic: it moves with R, Q and S in real time.
 *
 * Returns both the marginal floor and the average realized price of
 * the hypothetical full dump:
 *
 *   avg = (Q − Q′) / S ,  where Q′ = k / (R + S)
 */
export function dynamicFloorPrice({ tokenReserve, quoteReserve, circulatingSupply }) {
  assertPositiveFinite(tokenReserve, 'tokenReserve');
  assertPositiveFinite(quoteReserve, 'quoteReserve');
  assertNonNegativeFinite(circulatingSupply, 'circulatingSupply');

  const k = tokenReserve * quoteReserve;

  if (circulatingSupply === 0) {
    return {
      invariant_k: k,
      spot_price: quoteReserve / tokenReserve,
      p_floor_marginal: quoteReserve / tokenReserve,
      p_floor_average_realized: quoteReserve / tokenReserve,
      floor_to_spot_ratio: 1,
      max_dumpable_share_of_pool: 0,
      formula: 'p_floor = (R·Q) / (R+S)²'
    };
  }

  const rNew = tokenReserve + circulatingSupply;
  const qNew = k / rNew;

  const pFloorMarginal = qNew / rNew;
  const avgRealized = (quoteReserve - qNew) / circulatingSupply;
  const spot = quoteReserve / tokenReserve;

  return {
    invariant_k: k,
    spot_price: spot,
    p_floor_marginal: pFloorMarginal,
    p_floor_average_realized: avgRealized,
    floor_to_spot_ratio: pFloorMarginal / spot,
    max_dumpable_share_of_pool: circulatingSupply / rNew,
    formula: 'p_floor = (R·Q) / (R+S)²'
  };
}

/**
 * x·y=k invariant health report over time-ordered snapshots.
 *
 * Each snapshot: { t: unix_ms, token_reserve, quote_reserve }.
 * The invariant may grow (compounded fees retained in-band) but any
 * decrease beyond `toleranceBps` basis points is flagged as an
 * extraction event, because a shrinking k mechanically lowers every
 * future p_floor.
 */
export function invariantReport(snapshots, { toleranceBps = 0 } = {}) {
  if (!Array.isArray(snapshots) || snapshots.length < 2) {
    throw new TypeError('snapshots must be an array of at least two entries');
  }

  for (const s of snapshots) {
    if (!Number.isSafeInteger(s.t)) {
      throw new TypeError('snapshot.t must be a unix-ms integer');
    }
    assertPositiveFinite(s.token_reserve, 'token_reserve');
    assertPositiveFinite(s.quote_reserve, 'quote_reserve');
  }

  const ordered = [...snapshots].sort((a, b) => a.t - b.t);
  const tolerance = toleranceBps / 10_000;

  const series = [];
  let violations = 0;
  let peakK = -Infinity;
  let maxDrawdownPct = 0;

  for (const s of ordered) {
    const k = s.token_reserve * s.quote_reserve;
    series.push({ t: s.t, k });
    if (k > peakK) peakK = k;

    const drawdownPct = ((peakK - k) / peakK) * 100;
    if (drawdownPct > maxDrawdownPct) maxDrawdownPct = drawdownPct;
  }

  for (let i = 1; i < series.length; i += 1) {
    const prev = series[i - 1].k;
    const curr = series[i].k;
    if (curr < prev * (1 - tolerance)) {
      violations += 1;
      series[i].extraction_detected = true;
    }
  }

  return {
    snapshot_count: series.length,
    invariant_series: series,
    current_k: series[series.length - 1].k,
    peak_k: peakK,
    max_drawdown_pct: Number(maxDrawdownPct.toFixed(6)),
    extraction_events: violations,
    healthy: violations === 0,
    rule: 'k may grow with retained fees; any decrease beyond tolerance flags liquidity extraction'
  };
}

/**
 * Floor-integrity check: does a candidate reserve change keep the
 * promised floor intact? Used by dashboards to answer "is p_floor
 * mathematically intact?" in real time.
 */
export function floorIntact({ before, after, minRatio = 0 }) {
  try {
    const b = dynamicFloorPrice(before);
    const a = dynamicFloorPrice(after);

    const ratioDelta = a.floor_to_spot_ratio - b.floor_to_spot_ratio;
    const floorGrewOrHeld = ratioDelta >= -Number.EPSILON;

    return {
      intact: floorGrewOrHeld && a.floor_to_spot_ratio >= minRatio,
      before_ratio: b.floor_to_spot_ratio,
      after_ratio: a.floor_to_spot_ratio,
      ratio_delta: ratioDelta
    };
  } catch (err) {
    if (err instanceof TypeError) throw err;
    throw new CanonicalError('floor integrity check failed');
  }
}
