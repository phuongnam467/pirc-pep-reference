# piproof.wasm

The Go verifier compiled to WebAssembly (`GOOS=js GOARCH=wasm`), giving
browsers and edge runtimes the exact G1–G9 pipeline used server-side.

The `.wasm` artifact is **not committed** — build it:

```bash
cd wasm && GOOS=js GOARCH=wasm go build -o piproof.wasm .
node smoke.mjs "$(go env GOROOT)"
```

## Browser/worker API

```js
// after loading wasm_exec.js glue + instantiating piproof.wasm:
const r = globalThis.PiProofGo.verify(eventText, registryText, nowMs, nonceStateJSON);
// r = { ok, code, gates, nonce_state }   nonce_state: JSON array of burned keys
```

Nonce state is owned by the caller; the module stays stateless between
calls. `smoke.mjs` proves acceptance, cross-call replay burn (G9), and
tamper rejection against the repository's public vectors.
