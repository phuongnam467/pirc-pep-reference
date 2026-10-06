import { dynamicFloorPrice, invariantReport } from './pfloor.js';
import { engagementScore, leaderboard } from './engagement.js';
import {
  ESCROW_ATTESTATION_VERSION,
  ESCROW_STATES,
  verifyRevocationAttestation
} from './escrow.js';

/**
 * PiRC1 — Transparency Dashboard engine.
 *
 * The concept endorsed in the review:
 *   'I like the term "Transparency Dashboard", and the concept it
 *    represents.' — providing Pioneers real-time confidence in the
 *    ecosystem's mathematical floor.
 *
 * assembleSnapshot() fuses the three transparency primitives into
 * ONE deterministic JSON snapshot that any app (e.g. Map-of-Pi) can
 * fetch, verify and render:
 *
 *   1. price_floor   — dynamic p_floor from circulating supply (x·y=k)
 *   2. pool_health   — invariant tracking: is p_floor intact?
 *   3. escrow_lock   — verifiable revocation status of escrow keys
 *   4. engagement    — PoA/PoU/Consistency leaderboard built ONLY
 *                      from registry-verified signed events
 *
 * TRUST BOUNDARY (unchanged): this module never invents data. Pool
 * numbers come from the caller's verifiable feed; engagement comes
 * only from events whose verdict.ok === true; escrow status comes
 * from an attestation that passes verifyRevocationAttestation.
 */

function escrowPublicView(attestation) {
  return {
    v: attestation.v,
    escrow_id: attestation.escrow_id,
    state: attestation.state,
    previous_key_fingerprint: attestation.previous_key_fingerprint,
    effective_at: attestation.effective_at,
    anchor: attestation.anchor
  };
}

/**
 * Build a full Transparency Dashboard snapshot.
 *
 * @param {object} input
 * @param {{tokenReserve:number, quoteReserve:number, circulatingSupply:number}} input.pool
 * @param {Array<{t:number, token_reserve:number, quote_reserve:number}>} [input.invariantSnapshots]
 * @param {object} [input.manifest]                    project manifest of weighted actions
 * @param {number} [input.windowDays=30]
 * @param {Array<{event:object, verdict:{ok:true}}>} input.verifiedEntries
 * @param {object} [input.attestation]                 escrow attestation object
 * @param {object} [input.registry]                    required when attestation is provided
 * @param {number} [input.now=Date.now()]
 */
export function assembleSnapshot(input) {
  if (input === null || typeof input !== 'object') {
    throw new TypeError('assembleSnapshot requires an options object');
  }

  const {
    pool,
    invariantSnapshots,
    manifest,
    windowDays = 30,
    verifiedEntries = [],
    attestation,
    registry,
    now = Date.now()
  } = input;

  if (pool === null || typeof pool !== 'object') {
    throw new TypeError('pool {tokenReserve, quoteReserve, circulatingSupply} is required');
  }

  const floor = dynamicFloorPrice({
    tokenReserve: pool.tokenReserve,
    quoteReserve: pool.quoteReserve,
    circulatingSupply: pool.circulatingSupply
  });

  let poolHealth = null;

  if (invariantSnapshots !== undefined) {
    poolHealth = invariantReport(invariantSnapshots);
  }

  let escrowLock = null;

  if (attestation !== undefined) {
    if (!registry) {
      throw new TypeError('registry is required to verify an escrow attestation');
    }

    const verdict = verifyRevocationAttestation(attestation, { registry, now });

    escrowLock = {
      verifiable: verdict.ok,
      ...escrowPublicView(attestation),
      checks: verdict.checks
    };
  }

  const board =
    verifiedEntries.length > 0
      ? leaderboard(verifiedEntries, { manifest, windowDays })
      : [];

  return {
    schema: 'PiRC1-TransparencyDashboard/1',
    generated_at: now,
    price_floor: {
      circulating_supply: pool.circulatingSupply,
      spot_price: Number(floor.spot_price.toFixed(12)),
      p_floor_marginal: Number(floor.p_floor_marginal.toFixed(12)),
      p_floor_average_realized: Number(floor.p_floor_average_realized.toFixed(12)),
      floor_to_spot_ratio: Number(floor.floor_to_spot_ratio.toFixed(12)),
      formula: floor.formula,
      disclaimer:
        'descriptive AMM mathematics over caller-supplied reserves; not a valuation, promise or advice'
    },
    pool_health: poolHealth,
    escrow_lock_status: escrowLock,
    engagement: {
      window_days: windowDays,
      method: 'PoA/PoU composite × Consistency Factor; inputs restricted to registry-verified signatures',
      leaderboard: board.map((row) => ({
        rank: row.rank,
        pioneer_uid_hash: row.pioneer_uid_hash,
        poa_points: row.poa_points,
        pou_points: row.pou_points,
        consistency_factor: row.consistency_factor,
        score: row.score
      }))
    }
  };
}

export { ESCROW_ATTESTATION_VERSION, ESCROW_STATES };
