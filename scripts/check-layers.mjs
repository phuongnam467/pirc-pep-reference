#!/usr/bin/env node
// Layer governance for PiProof (v0.15) — see docs/LAYERS.md.
//
// Enforces the dependency-direction rule mechanically:
//     a module may only import from its own layer or lower.
// Every runtime module MUST be classified here; an unclassified module is a
// violation, so new code cannot silently escape the architecture.
//
// This is the reviewer-requested separation between the normative protocol
// stack and product/application semantics — enforced in CI, independent of
// physical file layout (physical regrouping is deliberately deferred until
// after the v1.0 freeze to keep the wire format and import paths stable).

import fs from 'node:fs';
import path from 'node:path';

const L = {
  // L0 — self-contained primitives: no relative imports allowed upward,
  // they depend on Node stdlib alone.
  0: {
    name: 'primitives',
    modules: [
      'canonical.js',   // PiProof Canonical Profile v1
      'constants.js',   // protocol constants & grammars
      'keys.js',        // Ed25519 glue (Node crypto)
      'web-ed25519.js', // pure-JS RFC 8032 verification (browser gateway)
      'schema.js',      // document shape validation
      'nonces.js',      // replay state (InMemory / File / Redis)
      'redis-nonces.js', // distributed replay state backend
      'observability.js' // opt-in metrics hooks, pure
    ]
  },
  // L1 — protocol core: documents, registries, verification verdicts.
  1: {
    name: 'protocol-core',
    modules: [
      'events.js',          // event construction, signing, uid hashing
      'registry.js',        // app/key eligibility registry
      'verify.js',          // verifySignedEvent pipeline
      'offline-verifier.js' // in-browser G1–G9 pipeline (public gateway)
    ]
  },
  // L2 — policy & evidence semantics: what a verdict MEANS for a relying party.
  2: {
    name: 'policy-evidence',
    modules: [
      'policy.js',          // narrowing checklist engine
      'policy-presets.js',  // frozen named presets (v1)
      'piproof.js',         // proofs, envelopes, epoch binding
      'passport.js',        // evidence passports
      'escrow.js',          // conditional-release escrows
      'pfloor.js',          // participation floor checks
      'court.js'            // decentralized verifiable arbitration (v0.18)
    ]
  },
  // L3 — application & adversarial layer: products built on the protocol.
  3: {
    name: 'application',
    modules: [
      'index.js',       // public entry point — re-exports across layers (v0.19)
      'dispute.js',     // deterministic evidence adjudication
      'sdk.js',         // developer surface (decide, URIs)
      'attacks.js',     // attack suite world-builder (test support)
      'engagement.js',  // engagement features
      'dashboard.js'    // dashboard aggregation
    ]
  },
  // L4 — presentation: humans and HTTP at the edge; may import everything.
  4: {
    name: 'presentation',
    modules: ['cli.js']
  }
};

const APP_ENTRYPOINTS = { 'app/server.mjs': 4 };

const layerOf = (() => {
  const m = new Map();
  for (const [depth, def] of Object.entries(L)) {
    for (const mod of def.modules) {
      if (m.has(mod)) fail(`module ${mod} classified twice`);
      m.set(mod, Number(depth));
    }
  }
  return m;
})();

function fail(msg) {
  console.error(`layer check: FAIL — ${msg}`);
  process.exit(1);
}

function extractRelativeImports(file) {
  const src = fs.readFileSync(file, 'utf8');
  const specs = [];
  for (const match of src.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)) {
    const spec = match[1];
    if (spec.startsWith('./') || spec.startsWith('../')) specs.push(spec);
  }
  return specs;
}

let edges = 0;
const violations = [];

const sources = [
  ...fs.readdirSync('src').filter((f) => f.endsWith('.js')).map((f) => `src/${f}`),
  ...Object.keys(APP_ENTRYPOINTS)
];

for (const file of sources) {
  const base = path.basename(file);
  const myLayer = layerOf.get(base) ?? APP_ENTRYPOINTS[file];
  if (myLayer === undefined) {
    violations.push(`${file}: UNCLASSIFIED module — add it to scripts/check-layers.mjs L{} map`);
    continue;
  }
  for (const spec of extractRelativeImports(file)) {
    const resolved = path.basename(path.resolve(path.dirname(file), spec));
    const depLayer = layerOf.get(resolved);
    if (depLayer === undefined) {
      violations.push(`${file} -> ${spec}: dependency '${resolved}' is unclassified`);
      continue;
    }
    edges++;
    if (depLayer > myLayer) {
      violations.push(
        `${file} (L${myLayer}) -> ${resolved} (L${depLayer}): upward import ` +
          `(L${myLayer} '${L[myLayer].name}' may not reach L${depLayer} '${L[depLayer].name}')`
      );
    }
  }
}

if (violations.length) {
  console.error(`layer check: ${violations.length} violation(s):`);
  for (const v of violations) console.error('  ' + v);
  process.exit(1);
}

console.log(
  `layer check OK: ${sources.length} modules across ${Object.keys(L).length} layers, ` +
    `${edges} edges, 0 violations`
);
