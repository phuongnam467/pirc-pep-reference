import { WEIGHT_CEILINGS, ACTION_CLASSES } from './constants.js';

/**
 * PiRC1 — Transparency Layer: Engagement scoring engine.
 *
 * Implements the composite Engagement Score endorsed in the PiRC1
 * review of 3-participation.md:
 *
 *   1. Proof of Activity  (PoA)  — basic interactions
 *   2. Proof of Utility   (PoU)  — high-value actions
 *   3. Consistency Factor (CF)   — sustained engagement over bursts
 *
 * and the "Manifest of weighted actions" technical implementation:
 * each project declares a manifest mapping its action_ids to classes
 * and multipliers. The manifest is CLAMPED to the protocol ceilings,
 * so a project can weight down but never up.
 *
 * TRUST BOUNDARY: this engine consumes ONLY entries whose verdict is
 * a successful verifySignedEvent result ({ok:true}). Raw or
 * self-declared events are rejected by construction.
 */

const CLASS_ROLES = Object.freeze({
  C: 'PoA',
  B: 'PoU',
  A: 'PoU'
});

function assertVerifiedEntry(entry) {
  if (
    entry === null ||
    typeof entry !== 'object' ||
    Array.isArray(entry)
  ) {
    throw new TypeError('each entry must be { event, verdict }');
  }

  const { event, verdict } = entry;

  if (
    verdict === null ||
    typeof verdict !== 'object' ||
    verdict.ok !== true ||
    !Array.isArray(verdict.checks)
  ) {
    throw new TypeError(
      'verdict must be a successful verifySignedEvent result ({ok:true,...}) — raw or rejected events are never scored'
    );
  }

  if (
    event === null ||
    typeof event !== 'object' ||
    typeof event.app_id !== 'string' ||
    typeof event.action_id !== 'string' ||
    typeof event.timestamp !== 'number' ||
    !ACTION_CLASSES.includes(event.action_class)
  ) {
    throw new TypeError('entry.event is missing protocol fields');
  }
}

/**
 * Validate + clamp a project manifest.
 *
 * manifest: {
 *   [action_id]: { class: 'A'|'B'|'C', multiplier?: number in (0,1] }
 * }
 *
 * Effective points for one event = ceiling(class) x multiplier.
 */
export function compileManifest(manifest = {}) {
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new TypeError('manifest must be an object');
  }

  const compiled = new Map();

  for (const [actionId, spec] of Object.entries(manifest)) {
    if (typeof actionId !== 'string' || actionId.length === 0 || actionId.length > 128) {
      throw new TypeError('manifest action_id must be 1..128 chars');
    }

    if (spec === null || typeof spec !== 'object') {
      throw new TypeError(`manifest entry '${actionId}' must be an object`);
    }

    const { class: klass, multiplier } = spec;

    if (!ACTION_CLASSES.includes(klass)) {
      throw new TypeError(`manifest entry '${actionId}' has invalid class '${klass}'`);
    }

    let m = 1;
    if (multiplier !== undefined) {
      if (typeof multiplier !== 'number' || !Number.isFinite(multiplier) || multiplier <= 0 || multiplier > 1) {
        throw new TypeError(`manifest entry '${actionId}' multiplier must be in (0,1] — projects may weigh DOWN only`);
      }
      m = multiplier;
    }

    compiled.set(actionId, {
      role: CLASS_ROLES[klass],
      points: WEIGHT_CEILINGS[klass] * m,
      clamped: false
    });
  }

  return compiled;
}

function windowDay(ms) {
  return Math.floor(ms / 86_400_000);
}

/**
 * Compute the composite engagement score for one pioneer.
 *
 * @param {Array<{event:object, verdict:{ok:true}}>} verifiedResults
 * @param {object} opts
 * @param {Map|object} [opts.manifest]   compiled manifest (or raw object)
 * @param {number}     [opts.windowDays=30] consistency window length
 */
export function engagementScore(verifiedResults, { manifest, windowDays = 30 } = {}) {
  if (!Array.isArray(verifiedResults)) {
    throw new TypeError('verifiedResults must be an array');
  }

  if (!Number.isSafeInteger(windowDays) || windowDays < 1 || windowDays > 3650) {
    throw new TypeError('windowDays must be an integer in [1, 3650]');
  }

  const compiled =
    manifest instanceof Map
      ? manifest
      : manifest !== undefined
        ? compileManifest(manifest)
        : null;

  verifiedResults.forEach(assertVerifiedEntry);

  if (verifiedResults.length === 0) {
    return {
      pioneer_uid_hash: null,
      poa_points: 0,
      pou_points: 0,
      total_points: 0,
      consistency_factor: 0,
      active_days: 0,
      window_days: windowDays,
      score: 0,
      events_counted: 0,
      events_rejected_by_manifest: 0
    };
  }

  const uidHashes = new Set(verifiedResults.map((e) => e.event.pioneer_uid_hash));

  if (uidHashes.size !== 1) {
    throw new TypeError('all verified results must belong to exactly one pioneer_uid_hash');
  }

  let poa = 0;
  let pou = 0;
  let rejectedByManifest = 0;
  const days = new Set();

  for (const { event: ev } of verifiedResults) {
    let pts = WEIGHT_CEILINGS[ev.action_class];

    if (compiled) {
      const entry = compiled.get(ev.action_id);

      if (!entry) {
        rejectedByManifest += 1;
        continue;
      }

      pts = entry.points;
    }

    if (CLASS_ROLES[ev.action_class] === 'PoA') {
      poa += pts;
    } else {
      pou += pts;
    }

    days.add(windowDay(ev.timestamp));
  }

  // Consistency Factor: share of the declared window covered by at
  // least one VERIFIED active day. Bursts collapse toward the floor
  // (0.5); engaging throughout the whole window approaches 1.
  const coverage = Math.min(days.size / windowDays, 1);
  const consistencyFactor = Number((0.5 + 0.5 * coverage).toFixed(6));

  const totalPoints = poa + pou;

  return {
    pioneer_uid_hash: [...uidHashes][0],
    poa_points: Number(poa.toFixed(6)),
    pou_points: Number(pou.toFixed(6)),
    total_points: Number(totalPoints.toFixed(6)),
    consistency_factor: consistencyFactor,
    active_days: days.size,
    window_days: windowDays,
    score: Number((totalPoints * consistencyFactor).toFixed(6)),
    events_counted: verifiedResults.length - rejectedByManifest,
    events_rejected_by_manifest: rejectedByManifest
  };
}

/**
 * Rank pioneers by composite score.
 *
 * Input: array of {event, verdict} entries possibly covering many
 * pioneers. Returns leaderboard sorted by score desc; ties broken by
 * hash lexicographic order for determinism.
 */
export function leaderboard(verifiedResults, opts = {}) {
  const byPioneer = new Map();

  for (const entry of verifiedResults) {
    assertVerifiedEntry(entry);

    const key = entry.event.pioneer_uid_hash;

    if (!byPioneer.has(key)) byPioneer.set(key, []);
    byPioneer.get(key).push(entry);
  }

  const rows = [];

  for (const [hash, results] of byPioneer) {
    rows.push(engagementScore(results, opts));
  }

  rows.sort(
    (a, b) =>
      b.score - a.score ||
      (a.pioneer_uid_hash < b.pioneer_uid_hash ? -1 : 1)
  );

  return rows.map((row, i) => ({ rank: i + 1, ...row }));
}
