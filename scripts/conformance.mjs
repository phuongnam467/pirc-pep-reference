#!/usr/bin/env node
// PiProof conformance runner (v0.16).
//
// An implementation may claim "PiProof compatible" only by passing every row
// of the matrix below (docs/CONFORMANCE.md is normative):
//
//   row                          implementation          command
//   --------------------------   ---------------------   -------------------------------
//   canonical vectors (Node)     src/canonical.js        scripts/check-canonical-vectors.mjs
//   canonical vectors (Python)   cross-canonical.py      python scripts/cross-canonical.py
//   protocol core (Go)           sdk/go                  go test ./sdk/go/...
//   Ed25519 cross-verify (Py)    cross-verify.py         python scripts/cross-verify.py
//
// Usage: node scripts/conformance.mjs [--strict]
//   --strict : a missing toolchain counts as failure instead of SKIP.
// Exit code 0 iff all present implementations agree.
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const STRICT = process.argv.includes('--strict');

const rows = [];
function record(name, impl, status, detail = '') {
  rows.push({ name, impl, status, detail });
}

function run(cmd, cmdArgs, opts = {}) {
  return execFileSync(cmd, cmdArgs, { cwd: ROOT, encoding: 'utf8', stdio: 'pipe', ...opts });
}

function hasTool(cmd, args) {
  try {
    run(cmd, args);
    return true;
  } catch {
    return false;
  }
}

// 1 — Node canonical vectors (always present; it generates them).
try {
  run(process.execPath, ['scripts/check-canonical-vectors.mjs']);
  record('canonical interop vectors', 'Node (src/canonical.js)', 'PASS');
} catch (err) {
  record('canonical interop vectors', 'Node (src/canonical.js)', 'FAIL', String(err.stderr || err.message).slice(0, 300));
}

// 2 — Python canonicalizer.
if (hasTool('python', ['--version'])) {
  try {
    const out = run('python', ['scripts/cross-canonical.py']).trim().split('\n').pop();
    record('canonical interop vectors', 'Python (cross-canonical.py)', 'PASS', out);
  } catch (err) {
    record('canonical interop vectors', 'Python (cross-canonical.py)', 'FAIL', String(err.stdout || err.stderr || err.message).slice(0, 300));
  }
} else {
  record('canonical interop vectors', 'Python (cross-canonical.py)', STRICT ? 'FAIL' : 'SKIP', 'python not found');
}

// 3 — Go protocol core (canonical + schema + G1–G9 pipeline + attacks).
if (hasTool('go', ['version'])) {
  let passed = false;
  let detail = '';
  try {
    run('go', ['test', './...'], { cwd: path.join(ROOT, 'sdk', 'go') });
    passed = true;
  } catch (err) {
    // Some desktop App-Control policies block freshly built test binaries in
    // %TEMP% but allow them inside the repo — fall back to compile+execute.
    try {
      const bin = path.join(ROOT, 'sdk', 'go', 'piproof.test.exe');
      run('go', ['test', '-c', '-o', bin, '.'], { cwd: path.join(ROOT, 'sdk', 'go') });
      const out = run(bin, [], { cwd: path.join(ROOT, 'sdk', 'go') });
      passed = /PASS/.test(out);
      if (!passed) detail = out.slice(0, 300);
      try { execFileSync('cmd', ['/c', 'del', '/q', bin], { stdio: 'pipe' }); } catch { /* */ }
    } catch (err2) {
      detail = String(err2.stderr || err2.stdout || err2.message).slice(0, 300);
    }
  }
  record('protocol core: 16 vectors + valid event + 20 attacks + INV pins', 'Go (sdk/go)', passed ? 'PASS' : 'FAIL', detail);
} else {
  record('protocol core: 16 vectors + valid event + 20 attacks + INV pins', 'Go (sdk/go)', STRICT ? 'FAIL' : 'SKIP', 'go not found');
}

// 4 — Independent pure-Python RFC 8032 verifier over the signed event vector.
if (hasTool('python', ['--version'])) {
  try {
    run('python', ['scripts/cross-verify.py']);
    record('Ed25519 event verification', 'Python (cross-verify.py)', 'PASS');
  } catch (err) {
    record('Ed25519 event verification', 'Python (cross-verify.py)', 'FAIL', String(err.stdout || err.stderr || err.message).slice(0, 300));
  }
} else {
  record('Ed25519 event verification', 'Python (cross-verify.py)', STRICT ? 'FAIL' : 'SKIP', 'python not found');
}

// ---------------------------------------------------------------- report ---
const width = Math.max(...rows.map((r) => r.name.length)) + 2;
console.log('\nPiProof conformance matrix');
console.log('='.repeat(72));
for (const r of rows) {
  const mark = r.status === 'PASS' ? '✔' : r.status === 'SKIP' ? '○' : '✘';
  console.log(`${mark} ${r.status.padEnd(5)} ${r.name.padEnd(width)} ${r.impl}`);
  if (r.detail && r.status !== 'PASS') console.log(`    ${r.detail}`);
}
console.log('='.repeat(72));
const failed = rows.filter((r) => r.status === 'FAIL');
const skipped = rows.filter((r) => r.status === 'SKIP');
console.log(
  `${rows.length - failed.length - skipped.length}/${rows.length} conformance rows passed` +
    (skipped.length ? ` (${skipped.length} skipped)` : '') +
    (failed.length ? ` — ${failed.length} FAILED` : '')
);
process.exit(failed.length ? 1 : 0);
