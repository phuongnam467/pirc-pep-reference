// Gateway glue — runs in the visitor's browser under a strict CSP
// (no inline script). All verification is local; the ONLY network call is
// the public registry export from this same origin.

import { verifyEventOffline } from './offline-verifier.js';

const $ = (id) => document.getElementById(id);
const verdict = $('verdict');
const results = $('results');
const note = $('note');
let REGISTRY = null;
let REGISTRY_FP = '';

async function loadRegistry() {
  const res = await fetch('/registry.json', { cache: 'no-store' });
  if (!res.ok) throw new Error('registry export unavailable');
  const text = await res.text();
  REGISTRY = JSON.parse(text);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  REGISTRY_FP = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  $('reginfo').textContent = `trusted registry loaded · sha256 ${REGISTRY_FP.slice(0, 16)}…`;
}

function cell(q, status, answer) {
  const trQ = document.createElement('td');
  trQ.className = 'q';
  trQ.textContent = q;
  const trA = document.createElement('td');
  if (answer) {
    trA.className = 'mono';
    trA.textContent = String(answer).slice(0, 90);
  } else {
    trA.textContent = '—';
  }
  const trS = document.createElement('td');
  trS.className = 's ' + status;
  trS.textContent = status;
  return [trQ, trA, trS];
}

function renderChecks(container, heading, r) {
  const sep = document.createElement('div');
  sep.className = 'proofsep';
  sep.textContent = heading;
  container.appendChild(sep);
  const table = document.createElement('table');
  for (const c of r.checks) {
    const tr = document.createElement('tr');
    for (const td of cell(c.check, c.status, c.detail)) tr.appendChild(td);
    table.appendChild(tr);
  }
  container.appendChild(table);
}

function setVerdict(text, cls) {
  verdict.textContent = text;
  verdict.className = cls;
  verdict.classList.remove('hidden');
}

function summarize(rs) {
  const allOk = rs.every((r) => r.ok);
  const anyInvalid = rs.some((r) => !r.ok);
  if (anyInvalid) {
    const firstBad = rs.find((r) => !r.ok);
    setVerdict('INVALID ✗ — ' + firstBad.code, 'invalid');
    note.textContent =
      'At least one cryptographic layer definitively failed. Nothing about this ' +
      'document was trusted. Replay state is not consultable offline (gold row).';
    return;
  }
  setVerdict('VERIFIED OFFLINE ✓ — replay status unverifiable here', 'unverifiable');
  note.innerHTML =
    'Every checkable layer passed <em>inside your browser</em> against the published ' +
    '<code>registry.json</code> shown above. The gold NONCE_REPLAY row is the honest limit of ' +
    'offline verification: replay certainty requires a live verifier with shared nonce state. ' +
    'Timestamp freshness used YOUR clock — large device skew can mislabel it.';
}

function runDocument(doc) {
  results.classList.remove('hidden');

  if (doc && doc.type === 'AUREVIA-Evidence-Passport' && Array.isArray(doc.proofs)) {
    const rs = [];
    doc.proofs.forEach((p, i) => {
      const ev = p && p.event ? p.event : p;
      let r;
      try {
        r = verifyEventOffline(ev, { registry: REGISTRY });
      } catch (e) {
        r = { ok: false, code: 'SCHEMA', checks: [{ check: 'SCHEMA', status: 'INVALID', detail: String(e.message) }] };
      }
      rs.push(r);
      renderChecks(results, `PROOF ${i + 1}/${doc.proofs.length}`, r);
    });
    summarize(rs);
    return;
  }

  const ev = doc && doc.type === 'PiProof' && doc.event ? doc.event : doc;
  let r;
  try {
    r = verifyEventOffline(ev, { registry: REGISTRY });
  } catch (e) {
    r = { ok: false, code: 'SCHEMA', checks: [{ check: 'SCHEMA', status: 'INVALID', detail: String(e.message) }] };
  }
  if (doc && doc.type === 'PiProof' && doc.registry_root !== undefined && r.ok) {
    r.checks.splice(r.checks.length - 1, 0, {
      check: 'EPOCH_BINDING',
      status: 'UNVERIFIABLE',
      detail: 'registry_root is pinned to the issuing verifier epoch — offline pages cannot re-derive it'
    });
  }
  renderChecks(results, 'DOCUMENT', r);
  summarize([r]);
}

async function verifyText(text) {
  results.replaceChildren();
  note.textContent = '';
  if (!REGISTRY) {
    try {
      await loadRegistry();
    } catch {
      setVerdict('REGISTRY UNAVAILABLE', 'invalid');
      note.textContent = 'The public registry export could not be fetched from this origin.';
      return;
    }
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    setVerdict('UNREADABLE DOCUMENT', 'invalid');
    note.textContent = 'Input is not valid JSON.';
    return;
  }
  runDocument(doc);
}

$('verify').addEventListener('click', () => verifyText($('doc').value.trim()));
$('file').addEventListener('change', async (ev2) => {
  const f = ev2.target.files && ev2.target.files[0];
  if (f) $('doc').value = await f.text();
});

// deep link: /gateway#d=<base64url json>
const m = (location.hash || '').match(/#d=([A-Za-z0-9_-]+)/);
if (m) {
  try {
    const b = m[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(b + '='.repeat((4 - (b.length % 4)) % 4))
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    $('doc').value = json;
    verifyText(json);
  } catch {
    setVerdict('UNREADABLE LINK', 'unverifiable');
    note.textContent = 'The embedded document could not be decoded.';
  }
}
