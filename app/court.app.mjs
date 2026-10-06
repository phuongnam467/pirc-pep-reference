const $ = (sel) => document.querySelector(sel);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

async function j(url, opts) {
  const r = await fetch(url, opts);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error ?? r.status);
  return body;
}

function caseCard(c) {
  const card = el('div', 'case');
  const head = el('header');
  head.append(el('span', 'id', c.case_id), el('span', `badge ${c.status}`, c.status));
  card.append(head);

  const kv = el('dl', 'kv');
  kv.append(
    el('dt', null, 'parties'), el('dd', null, `${c.parties.plaintiff} vs ${c.parties.defendant}`),
    el('dt', null, 'division'), el('dd', null, c.division),
    el('dt', null, 'ballots'), el('dd', null, String(c.rounds.reduce((n, r) => n + r.ballots, 0))),
    el('dt', null, 'AI opinions'), el('dd', null, `${c.referee_opinions} (advisory only)`)
  );
  if (c.provisional_outcome) kv.append(el('dt', null, 'outcome'), el('dd', null, c.provisional_outcome));
  if (c.settlement) {
    kv.append(
      el('dt', null, 'verdict'), el('dd', null, `${c.settlement.verdict} · ${c.settlement.signatures}-of-panel multi-sig · fees ${c.settlement.total_fees}`),
      el('dt', null, 'anchor'), el('dd', null, `${c.settlement.anchor_payload.network} ← ${c.settlement.anchor_payload.payload.slice(0, 80)}…`)
    );
  }
  kv.append(
    el('dt', null, 'replay'),
    el('dd', c.replay.matches ? 'replay-ok' : 'replay-bad',
      c.replay.matches ? '✓ signatures verified, tally reproduced' : `✗ ${c.replay.differences.join(', ')}`)
  );
  card.append(kv);

  const det = el('details');
  det.append(el('summary', null, 'case timeline'));
  const pre = el('pre');
  pre.textContent = JSON.stringify(c.history, null, 2);
  det.append(pre);
  card.append(det);
  return card;
}

async function refresh() {
  try {
    const s = await j('/api/court/state');
    $('#market').textContent =
      `judges: ${s.market.active_judges} · open cases: ${s.market.open_demand}` +
      (s.market.clearing.general_dispute.median_fee != null
        ? ` · clearing fee: ${s.market.clearing.general_dispute.median_fee}`
        : '');
    const box = $('#cases');
    box.replaceChildren();
    if (!s.cases.length) {
      box.append(el('p', 'empty', 'no cases yet — run the scenario above.'));
      return;
    }
    for (const c of [...s.cases].reverse()) box.append(caseCard(c));
  } catch { /* host offline — leave last state */ }
}

$('#demoBtn').addEventListener('click', async () => {
  const btn = $('#demoBtn');
  btn.disabled = true;
  try {
    const run = await j('/api/court/demo-case', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const v = $('#verdict');
    v.classList.remove('hidden', 'bad');
    v.classList.add('ok');
    v.replaceChildren(
      el('h3', null, `Settled: ${run.tally_outcome}`),
      el('p', null, `multi-signature certificate signed by ${run.certificate.signatures.map((s) => s.judge_id).join(', ')}.`),
      el('p', null, `anchor payload (${run.certificate.anchor_payload.bytes} canonical bytes): ${run.certificate.anchor_payload.payload.slice(0, 120)}…`)
    );
    await refresh();
  } catch (e) {
    const v = $('#verdict');
    v.classList.remove('hidden', 'ok');
    v.classList.add('bad');
    v.replaceChildren(el('h3', null, 'scenario failed'), el('p', null, String(e.message)));
  } finally {
    btn.disabled = false;
  }
});

refresh();
