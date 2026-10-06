// Public entry point — the stable import surface for `piproof` consumers.
// Subpath exports (see package.json) remain available for tree-shaking.
export { canonicalize, CanonicalError } from './canonical.js';
export {
  SPEC_VERSION,
  DOMAIN,
  TIMESTAMP_WINDOW_MS,
  WEIGHT_CEILINGS,
} from './constants.js';
export { hashUid, newEvent, signingBytes, signEvent } from './events.js';
export {
  createRegistry,
  registerApp,
  registerKey,
  revokeKey,
  markEligible,
} from './registry.js';
export { verifySignedEvent } from './verify.js';
export { InMemoryNonceStore } from './nonces.js';
export {
  PIPROOF_TYPE,
  PIPROOF_VERSION,
  registryRootHash,
  toPiProof,
  verifyPiProof,
} from './piproof.js';
export { normalizePolicy, evaluatePolicy } from './policy.js';
export { createPassport, verifyPassport } from './passport.js';
export { buildDisputeReport } from './dispute.js';
export * as court from './court.js';
export { createVerifier, toProofUri, parseProofUri } from './sdk.js';
