#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { formatAttackReport, runAttackSuite, makeWorld } from './attacks.js';
import { hashUid, newEvent, signEvent } from './events.js';
import { generateKeyPair } from './keys.js';
import { InMemoryNonceStore, FileNonceStore } from './nonces.js';
import { verifyPiProof, toPiProof } from './piproof.js';
import { createPassport, verifyPassport } from './passport.js';
import { buildDisputeReport } from './dispute.js';
import {
  initCourt, registerJudge, revokeJudge, setFeeBook,
  fileCase, submitEvidence, openDeliberation, castBallot,
  submitRefereeOpinion, tallyRound, openChallengeWindow,
  settleCase, replayArbitration, marketSnapshot
} from './court.js';
import { createRegistry, registerApp, registerKey, revokeKey, markEligible } from './registry.js';
import { verifySignedEvent } from './verify.js';
import { createVerifier, formatDecision } from './sdk.js';
import { listPolicyPresets } from './policy-presets.js';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        if (key in flags) {
          if (!Array.isArray(flags[key])) flags[key] = [flags[key]];
          flags[key].push(next);
        } else {
          flags[key] = next;
        }
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function printChecks(checks) {
  for (const c of checks) {
    const mark = c.pass ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    console.log(`  ${mark}  ${c.check}`);
  }
}

function printVerifyResult(result) {
  printChecks(result.checks);
  console.log('');
  if (result.ok) {
    console.log(`${BOLD}${GREEN}VERDICT: PASS (deterministic)${RESET}`);
  } else {
    console.log(`${BOLD}${RED}VERDICT: REJECT [${result.code}]${RESET}`);
  }
}

function printProofResult(result) {
  for (const s of result.steps) {
    const mark = s.pass ? `${GREEN} ✓ ${RESET}` : `${RED} ✗ ${RESET}`;
    console.log(` ${mark} ${s.label}${s.detail ? `  ${DIM}(${s.detail})${RESET}` : ''}`);
  }
  if (result.policy && result.policy.violations.length > 0) {
    console.log(`${RED}Policy violations:${RESET}`);
    for (const v of result.policy.violations) {
      console.log(`   ${RED}·${RESET} ${v.rule}: ${v.detail}`);
    }
  }
  console.log('');
  console.log(`${DIM}binding: ${result.binding ?? 'UNBOUND (malformed envelope)'}${RESET}`);
  if (result.ok) {
    console.log(`${BOLD}${GREEN}VERDICT: TRUSTED PROOF — don't trust the app, verify the proof.${RESET}`);
  } else {
    console.log(`${BOLD}${RED}VERDICT: INVALID PROOF [${result.code}]${RESET}`);
  }
}

function printPassportResult(result) {
  for (const s of result.steps) {
    const mark = s.pass ? `${GREEN} ✓ ${RESET}` : `${RED} ✗ ${RESET}`;
    console.log(` ${mark} ${s.label}${s.detail ? `  ${DIM}(${s.detail})${RESET}` : ''}`);
  }
  for (const r of result.results) {
    console.log(`\n${DIM}[ proof #${r.index + 1} ]${RESET}`);
    for (const s of r.steps) {
      const mark = s.pass ? `${GREEN} ✓ ${RESET}` : `${RED} ✗ ${RESET}`;
      console.log(` ${mark} ${s.label}${s.detail ? `  ${DIM}(${s.detail})${RESET}` : ''}`);
    }
    if (r.policy && r.policy.violations.length > 0) {
      console.log(`${RED}Policy violations:${RESET}`);
      for (const v of r.policy.violations) {
        console.log(`   ${RED}·${RESET} ${v.rule}: ${v.detail}`);
      }
    }
  }
  if (result.summary) {
    console.log('');
    const s = result.summary;
    console.log(
      `${DIM}subject: ${s.subject ?? '(none)'} · proofs valid: ${s.proofs_valid}/${s.proofs_total} · binding: ${s.binding} · evidence_root: ${s.evidence_root}${RESET}`
    );
  }
  console.log('');
  if (result.ok) {
    console.log(`${BOLD}${GREEN}VERDICT: PASSPORT VALID — proofs you can carry, evidence anyone can verify.${RESET}`);
  } else {
    console.log(`${BOLD}${RED}VERDICT: INVALID PASSPORT [${result.code}]${RESET}`);
  }
}

const HELP = `pep - Programmable Engagement Proofs reference implementation

Usage:
  node src/cli.js <command> [options]

Commands:
  keygen       --out keys/demo.json
  init-reg     --out registry.json --app demo-app
  add-key      --registry registry.json --app demo-app --key-id k-2026 --pub keys/demo.json
  revoke-key   --registry registry.json --app demo-app --key-id k-2026
  eligible     --registry registry.json --uid-hash <h1:hmac-tag>
  sign         --event event.json --key keys/demo.json [--out signed.json]
  verify       --event signed.json --registry registry.json [--nonces nonces.jsonl] [--now <unix-ms>]
  proof-export --event signed.json [--registry registry.json] [--epoch-bound] [--out proof.json]
  proof-verify --proof proof.json --registry registry.json [--policy policy.json]
               [--nonces nonces.jsonl] [--now <unix-ms>]
  passport-create --proof p1.json [--proof p2.json ...] [--subject tag]
                  [--policy policy.json] [--require-epoch-bound] [--now <unix-ms>]
                  [--out passport.json]
  passport-verify --passport passport.json --registry registry.json [--policy policy.json]
                  [--nonces nonces.jsonl] [--now <unix-ms>]
  dispute       --doc passport-or-proof.json [--registry registry.json] [--policy policy.json]
                [--nonces nonces.jsonl] [--now <unix-ms>] [--out dispute-report.json]
  decide        --proof proof.json --registry registry.json [--policy <preset|file>]
                [--nonces nonces.jsonl] [--now <unix-ms>]
  policies      list the frozen named policy presets (v0.14)
  attacks      run the full adversarial suite
  demo         end-to-end walkthrough
  court-demo   full arbitration scenario — judges, quorum, challenge, AI referee, multi-sig settlement

PiProof: a portable envelope around one signed PEP/1 event. Any party holding
the proof + the verifier's own registry copy can independently confirm every
claim without trusting the issuing application.

Binding classes: proofs exported WITH --registry are EPOCH_BOUND (pinned to
one registry generation); without it they are LOCAL (verify against whatever
trusted copy the verifier supplies). Policies can require epoch binding via
{"require_epoch_bound": true}.

AUREVIA Evidence Passport/1: one portable evidence record bundling PiProof
envelopes under a content-addressed evidence root — carry your evidence,
verify it anywhere.
`;

function cmdKeygen(flags) {
  const out = flags.out ?? 'keys/keypair.json';
  const opts = flags.seed ? { seed: String(flags.seed) } : {};
  writeJson(out, generateKeyPair(opts));
  console.log(`keypair written to ${out}${flags.seed ? ' (from provided seed)' : ''}`);
}

function cmdInitReg(flags) {
  const out = flags.out ?? 'registry.json';
  const registry = createRegistry();
  for (const app of String(flags.app ?? 'demo-app').split(',')) {
    registerApp(registry, app.trim());
  }
  writeJson(out, registry);
  console.log(`registry written to ${out}`);
}

function cmdAddKey(flags) {
  const registryFile = flags.registry ?? 'registry.json';
  const registry = readJson(registryFile);
  const keypair = readJson(flags.pub);
  registerKey(registry, flags.app, flags['key-id'], keypair.public_key_pem);
  writeJson(registryFile, registry);
  console.log(`key ${flags['key-id']} registered for app ${flags.app}`);
}

function cmdRevokeKey(flags) {
  const registryFile = flags.registry ?? 'registry.json';
  const registry = readJson(registryFile);
  revokeKey(registry, flags.app, flags['key-id']);
  writeJson(registryFile, registry);
  console.log(`key ${flags['key-id']} revoked for app ${flags.app}`);
}

function cmdEligible(flags) {
  const registryFile = flags.registry ?? 'registry.json';
  const registry = readJson(registryFile);
  markEligible(registry, flags['uid-hash']);
  writeJson(registryFile, registry);
  console.log(`user marked eligible`);
}

function cmdSign(flags) {
  const event = readJson(flags.event);
  const keypair = readJson(flags.key);
  const signed = signEvent(event, keypair.private_key_pem);
  if (flags.out) writeJson(flags.out, signed);
  else console.log(JSON.stringify(signed, null, 2));
  if (flags.out) console.log(`signed event written to ${flags.out}`);
}

function cmdVerify(flags) {
  const event = readJson(flags.event);
  const registry = readJson(flags.registry);
  const nonceStore = flags.nonces
    ? new FileNonceStore(flags.nonces)
    : new InMemoryNonceStore();
  const now = flags.now ? Number(flags.now) : Date.now();
  const result = verifySignedEvent(event, { registry, nonceStore, now });
  printVerifyResult(result);
  process.exitCode = result.ok ? 0 : 1;
}

function cmdCourtDemo() {
  const T0 = Date.now();
  const MIN = 60_000;

  console.log(`${BOLD}AUREVIA Arbitration Court — scripted scenario${RESET}`);
  console.log(`${DIM}decentralized verifiable arbitration: judges are keys, verdicts are multisig, every ruling replays${RESET}\n`);

  const reg = createRegistry();
  initCourt(reg);
  const signers = {};
  const mk = (id, opts) => {
    const kp = generateKeyPairSync('ed25519');
    registerJudge(reg, id, kp.publicKey.export({ type: 'spki', format: 'pem' }), { now: T0, ...opts });
    signers[id] = (msg) => edSign(null, msg, kp.privateKey);
  };
  for (const id of ['judge-ada', 'judge-boole', 'judge-cantor']) mk(id, { stake: 5 });
  mk('referee-tesla', { capabilities: ['referee'] });
  setFeeBook(reg, 'judge-ada', { general_dispute: 150, agent_dispute: 250 });
  setFeeBook(reg, 'judge-boole', { general_dispute: 200, agent_dispute: 200 });
  setFeeBook(reg, 'judge-cantor', { general_dispute: 175, agent_dispute: 300 });

  console.log(`${DIM}[1] judge roster — keys with stake + published fee books${RESET}`);
  for (const [id, j] of Object.entries(reg.court.judges)) {
    console.log(`   ${GREEN}✓${RESET} ${id.padEnd(14)} stake=${j.stake} caps=[${j.capabilities.join(',')}]`);
  }
  console.log(`   market clearing: ${JSON.stringify(marketSnapshot(reg, 1).clearing.general_dispute)}\n`);

  const c = fileCase(reg, {
    plaintiff: 'buyer-alice',
    defendant: 'merchant-mall',
    disputeReport: { type: 'AUREVIA-Dispute-Report', verdict: 'INVALID', subject: 'order-7712' }
  }, T0);
  submitEvidence(c, { submitter: 'defendant', kind: 'statement', payload: { text: 'service delivered; logs attached' } }, T0 + MIN);
  openDeliberation(reg, c, T0 + 2 * MIN);

  console.log(`${DIM}[2] case filed:${RESET} ${BOLD}${c.case_id}${RESET}`);
  console.log(`${DIM}[3] deliberation round 1 — ballots are signed attestations over the exact tally${RESET}`);

  castBallot(reg, c, { judge_id: 'judge-ada', verdict: 'AFFIRM', reasons: { basis: 'signature chain valid' } }, { sign: signers['judge-ada'], now: T0 + 3 * MIN });
  castBallot(reg, c, { judge_id: 'judge-boole', verdict: 'AFFIRM', reasons: { basis: 'policy satisfied' } }, { sign: signers['judge-boole'], now: T0 + 4 * MIN });
  castBallot(reg, c, { judge_id: 'judge-cantor', verdict: 'REVERSE', reasons: { basis: 'timestamp anomaly' } }, { sign: signers['judge-cantor'], now: T0 + 5 * MIN });

  try {
    castBallot(reg, c, { judge_id: 'referee-tesla', verdict: 'AFFIRM', reasons: {} }, { sign: signers['referee-tesla'], now: T0 + 6 * MIN });
  } catch (e) {
    console.log(`   ${RED}✗${RESET} AI referee tried to vote → rejected: ${e.code}  ${DIM}(AI argues, keys decide)${RESET}`);
  }
  submitRefereeOpinion(reg, c, {
    referee_id: 'referee-tesla',
    opinion: { summary: 'evidence supports AFFIRM', confidence_pct: 91 }
  }, { sign: signers['referee-tesla'], now: T0 + 7 * MIN });
  console.log(`   ${GREEN}✓${RESET} signed advisory opinion recorded as evidence only\n`);

  const tally = tallyRound(reg, c);
  console.log(`${DIM}[4] deterministic tally:${RESET} outcome=${tally.outcome} weights=A:${tally.weights.AFFIRM}/R:${tally.weights.REVERSE} quorum_met=${tally.quorum.met}\n`);

  openChallengeWindow(reg, c, T0 + 8 * MIN);
  const cert = settleCase(reg, c, { signers, now: T0 + 9 * MIN });
  console.log(`${DIM}[5] settlement — multi-signature anchor certificate over the exact tally bytes${RESET}`);
  console.log(`   signatures: ${cert.signatures.map((s) => s.judge_id).join(', ')}`);
  console.log(`   fees total: ${cert.fees.total} (integer units, canonical-safe)`);
  console.log(`   anchor: ${cert.anchor_payload.network} ← ${cert.anchor_payload.payload.slice(0, 72)}…\n`);

  const replay = replayArbitration(reg, c);
  console.log(replay.matches
    ? `${GREEN}${BOLD}REPLAY: every signature verified, every tally recomputed identically — trustless ✓${RESET}`
    : `${RED}${BOLD}REPLAY FAILED: ${replay.differences.join(', ')}${RESET}`);
}

function cmdDemo() {
  const world = makeWorld();
  console.log(`${BOLD}PiRC1-PEP Reference Demo${RESET}\n`);

  console.log(`${DIM}[1] backend signs a high-value engagement event (class A, weight 50)${RESET}`);
  const event = newEvent({
    app_id: 'demo-app',
    key_id: 'k-2026-active',
    action_class: 'A',
    action_id: 'complete_transaction',
    weight: 50,
    pioneer_uid: 'alice',
    uidSecret: world.uidSecret,
    now: Date.now()
  });
  const signed = signEvent(event, world.currentKey.private_key_pem);

  const store = new InMemoryNonceStore();
  console.log(`${DIM}[2] verifier checks it against the launchpad registry${RESET}`);
  printVerifyResult(verifySignedEvent(signed, { registry: world.registry, nonceStore: store }));

  console.log('');
  console.log(`${DIM}[3] attacker replays the exact same payload${RESET}`);
  const r2 = verifySignedEvent(signed, { registry: world.registry, nonceStore: store });
  console.log(`  ${BOLD}${RED}VERDICT: REJECT [${r2.code}]${RESET}`);

  console.log('');
  console.log(`${DIM}[4] attacker mutates the weight after signing${RESET}`);
  const mutated = { ...signed, weight: signed.weight + 100 };
  const r3 = verifySignedEvent(mutated, { registry: world.registry, nonceStore: store });
  console.log(`  ${BOLD}${RED}VERDICT: REJECT [${r3.code}]${RESET}`);
}

function cmdProofExport(flags) {
  const event = readJson(flags.event);
  const registry = flags.registry ? readJson(flags.registry) : null;
  if (flags['epoch-bound'] && registry === null) {
    console.error('--epoch-bound requires --registry: an epoch-bound proof must embed the registry_root of a specific registry generation');
    process.exitCode = 1;
    return;
  }
  const proof = toPiProof(event, { registry });
  if (flags.out) writeJson(flags.out, proof);
  else console.log(JSON.stringify(proof, null, 2));
  if (flags.out) {
    console.log(`PiProof written to ${flags.out}${proof.registry_root ? ' (EPOCH_BOUND)' : ' (LOCAL — no epoch pin)'}`);
  }
}

function cmdProofVerify(flags, posArg) {
  const proof = readJson(flags.proof ?? posArg);
  const registry = readJson(flags.registry);
  const policy = flags.policy ? readJson(flags.policy) : null;
  const nonceStore = flags.nonces
    ? new FileNonceStore(flags.nonces)
    : new InMemoryNonceStore();
  const now = flags.now ? Number(flags.now) : Date.now();
  const result = verifyPiProof(proof, { registry, nonceStore, now, policy });
  printProofResult(result);
  process.exitCode = result.ok ? 0 : 1;
}

function cmdPassportCreate(flags) {
  const proofFiles = Array.isArray(flags.proof) ? flags.proof : flags.proof ? [flags.proof] : [];
  if (proofFiles.length === 0) {
    console.error('passport-create requires at least one --proof file');
    process.exitCode = 1;
    return;
  }
  const proofs = proofFiles.map((f) => readJson(f));
  if (flags['require-epoch-bound']) {
    const local = proofs.filter((p) => p?.registry_root === undefined);
    if (local.length > 0) {
      console.error(`--require-epoch-bound: ${local.length} proof(s) lack registry_root and are LOCAL, not epoch-bound`);
      process.exitCode = 1;
      return;
    }
  }
  const policy = flags.policy ? readJson(flags.policy) : null;
  const passport = createPassport({
    proofs,
    subject: flags.subject ? String(flags.subject) : null,
    policy,
    createdAt: flags.now ? Number(flags.now) : Date.now()
  });
  if (flags.out) {
    const binding = proofs.every((p) => p?.registry_root !== undefined)
      ? 'EPOCH_BOUND'
      : proofs.every((p) => p?.registry_root === undefined) ? 'LOCAL' : 'MIXED';
    writeJson(flags.out, passport);
    console.log(`AUREVIA Evidence Passport written to ${flags.out} (${proofs.length} proof${proofs.length > 1 ? 's' : ''}, binding: ${binding})`);
  } else {
    console.log(JSON.stringify(passport, null, 2));
  }
}

function cmdPassportVerify(flags, posArg) {
  const passport = readJson(flags.passport ?? posArg);
  const registry = readJson(flags.registry);
  const policy = flags.policy ? readJson(flags.policy) : null;
  const nonceStore = flags.nonces
    ? new FileNonceStore(flags.nonces)
    : new InMemoryNonceStore();
  const now = flags.now ? Number(flags.now) : Date.now();
  const result = verifyPassport(passport, { registry, nonceStore, now, policyOverride: policy });
  printPassportResult(result);
  process.exitCode = result.ok ? 0 : 1;
}

function cmdDispute(flags, posArg) {
  const doc = readJson(flags.doc ?? posArg);
  const registry = flags.registry ? readJson(flags.registry) : null;
  const policy = flags.policy ? readJson(flags.policy) : null;
  const nonceStore = flags.nonces
    ? new FileNonceStore(flags.nonces)
    : new InMemoryNonceStore();
  const now = flags.now ? Number(flags.now) : Date.now();
  const report = buildDisputeReport({ doc, registry, nonceStore, now, policy });

  const MARK = { OK: `${GREEN}✓${RESET}`, VALID: `${GREEN}✓${RESET}`, INVALID: `${RED}✗${RESET}`, UNVERIFIABLE: `${BOLD}?${RESET}` };
  console.log(`${BOLD}AUREVIA Dispute Report${RESET} · ${DIM}v${report.version}${RESET}\n`);
  for (const c of report.chain) {
    const mark = MARK[c.status] ?? '?';
    const answer = typeof c.answer === 'object' && c.answer !== null
      ? JSON.stringify(c.answer)
      : String(c.answer);
    console.log(` ${mark} ${c.question.replace(/_/g, ' ')}  ${DIM}${answer.slice(0, 110)}${RESET}`);
  }
  console.log('');
  if (report.verdict === 'VALID') {
    console.log(`${BOLD}${GREEN}DISPUTE VERDICT: VALID${RESET}`);
  } else if (report.verdict === 'INVALID') {
    console.log(`${BOLD}${RED}DISPUTE VERDICT: INVALID${RESET}`);
  } else {
    console.log(`${BOLD}DISPUTE VERDICT: UNVERIFIABLE — this verifier lacks the inputs to adjudicate${RESET}`);
  }
  if (flags.out) {
    writeJson(flags.out, report);
    console.log(`report written to ${flags.out}`);
  }
  process.exitCode = report.verdict === 'VALID' ? 0 : report.verdict === 'INVALID' ? 1 : 2;
}

function cmdPolicies() {
  console.log(`${BOLD}Named Trust Policy presets${RESET} · ${DIM}version 1 · code-frozen${RESET}\n`);
  for (const p of listPolicyPresets()) {
    console.log(` ${GREEN}●${RESET} ${BOLD}${p.name}${RESET}`);
    console.log(`   ${DIM}${p.description}${RESET}`);
    console.log(`   ${DIM}rules: ${JSON.stringify(p.rules)}${RESET}`);
  }
  console.log(`\nUse with: ${DIM}pep decide --proof proof.json --registry registry.json --policy merchant-verification-v1${RESET}`);
}

function cmdDecide(flags, posArg) {
  const file = flags.proof ?? flags.passport ?? posArg;
  if (!file) {
    console.error('decide requires --proof <file> (or a positional file)');
    process.exitCode = 2;
    return;
  }
  let policyRef = null;
  if (flags.policy) {
    const asStr = String(flags.policy);
    policyRef = fs.existsSync(asStr) ? readJson(asStr) : asStr;
  }
  const registry = readJson(flags.registry);
  const nonceStore = flags.nonces ? new FileNonceStore(flags.nonces) : new InMemoryNonceStore();
  const now = flags.now ? Number(flags.now) : Date.now();
  const verifier = createVerifier({ registry, nonceStore, now });
  const doc = readJson(file);
  const decision = verifier.decide(doc, { policy: policyRef });
  for (const s of decision.result.steps ?? []) {
    const mark = s.pass === false ? `${RED} ✗ ${RESET}` : `${GREEN} ✓ ${RESET}`;
    console.log(` ${mark} ${s.label ?? s.check ?? ''}${s.detail ? `  ${DIM}(${s.detail})${RESET}` : ''}`);
  }
  console.log('');
  console.log(decision.decision === 'ALLOW'
    ? `${BOLD}${GREEN}DECISION: ALLOW${RESET}`
    : `${BOLD}${RED}DECISION: DENY${RESET}`);
  console.log(`${DIM}${formatDecision(decision)}${RESET}`);
  process.exitCode = decision.ok ? 0 : 1;
}

function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const command = positional[0];

  switch (command) {
    case 'keygen': return cmdKeygen(flags);
    case 'init-reg': return cmdInitReg(flags);
    case 'add-key': return cmdAddKey(flags);
    case 'revoke-key': return cmdRevokeKey(flags);
    case 'eligible': return cmdEligible(flags);
    case 'sign': return cmdSign(flags);
    case 'verify': return cmdVerify(flags);
    case 'proof-export': return cmdProofExport(flags);
    case 'proof-verify': return cmdProofVerify(flags, positional[1]);
    case 'passport-create': return cmdPassportCreate(flags);
    case 'passport-verify': return cmdPassportVerify(flags, positional[1]);
    case 'dispute': return cmdDispute(flags, positional[1]);
    case 'decide': return cmdDecide(flags, positional[1]);
    case 'policies': return cmdPolicies();
    case 'attacks': {
      const results = runAttackSuite();
      console.log(formatAttackReport(results));
      process.exitCode = results.every((r) => r.rejected) ? 0 : 1;
      return;
    }
    case 'demo': return cmdDemo();
    case 'court-demo': return cmdCourtDemo();
    default:
      console.log(HELP);
      process.exitCode = command ? 1 : 0;
  }
}

main();
