// WASM smoke driver — runs the Go-compiled verifier in Node and checks the
// full pipeline: accept, replay-burn across calls, and tamper rejection.
//   node wasm/smoke.mjs <GOROOT>
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const goroot = process.argv[2];
if (!goroot) {
  console.error('usage: node smoke.mjs <GOROOT>');
  process.exit(2);
}

// Go ≥1.24 ships the glue at $GOROOT/lib/wasm/wasm_exec.js (older: misc/wasm).
const glueCandidates = [
  join(goroot, 'lib', 'wasm', 'wasm_exec.js'),
  join(goroot, 'misc', 'wasm', 'wasm_exec.js'),
];
const glue = glueCandidates.find((p) => existsSync(p));
if (!glue) {
  console.error('wasm_exec.js not found under GOROOT');
  process.exit(2);
}
await import(pathToFileURL(glue).href);

const go = new Go();
const { instance } = await WebAssembly.instantiate(
  readFileSync(new URL('./piproof.wasm', import.meta.url)),
  go.importObject
);
go.run(instance);
await new Promise((r) => setTimeout(r, 100));

const P = globalThis.PiProofGo;
const eventText = readFileSync(
  new URL('../vectors/valid/signed-event.json', import.meta.url), 'utf8');
const registryText = readFileSync(
  new URL('../vectors/registry.json', import.meta.url), 'utf8');
const NOW = 1_755_860_000_000;

let fails = 0;
function check(name, cond, detail) {
  if (cond) console.log('PASS:', name);
  else { fails++; console.log('FAIL:', name, JSON.stringify(detail)); }
}

const r1 = P.verify(eventText, registryText, NOW, '[]');
check('accept valid event', r1.ok === true && r1.code === '', r1);

const r2 = P.verify(eventText, registryText, NOW + 1000, r1.nonce_state);
check('replay burned across calls (G9)',
  r2.ok === false && r2.code === 'REPLAY_DETECTED', r2);

const tampered = JSON.parse(eventText);
tampered.weight = tampered.weight + 1;
const r3 = P.verify(JSON.stringify(tampered), registryText, NOW, '[]');
check('tampered payload → INVALID_SIGNATURE',
  r3.ok === false && r3.code === 'INVALID_SIGNATURE', r3);

console.log(fails ? `wasm smoke: ${fails} FAILURE(S)` : 'wasm smoke: ALL GREEN');
process.exit(fails ? 1 : 0);
