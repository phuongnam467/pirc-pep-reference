# Distribution — one protocol, seven channels

PiProof ships as a **protocol with reference implementations**, not as a
single library. Every channel below implements the identical G1–G9
pipeline defined in [`SPEC.md`](../SPEC.md) and is validated against the
same public vectors in `vectors/`.

| # | Channel | Path | Language / runtime | Install | Conformance |
|---|---------|------|--------------------|---------|-------------|
| 1 | npm package (reference) | root | JavaScript / Node ≥ 20 | `npm install piproof` *(post-publish)* | `npm run ci` |
| 2 | Python package | `sdk/python/` | Python ≥ 3.9, stdlib-only | `pip install ./sdk/python` | `sdk/python/test_sdk.py`, CI job `python-package` |
| 3 | Go module | `sdk/go/` | Go ≥ 1.22 | `go get github.com/EslaM-X/piproof/sdk/go` | `go test ./...`, CI job `conformance-go` |
| 4 | Rust crate | `sdk/rust/` | Rust (edition 2021) | add path/git dependency; crates.io *(planned)* | `cargo test`, CI job `rust-conformance` |
| 5 | WebAssembly | `wasm/` | Go → WASM | build artifact, load via `wasm_exec.js` glue | `wasm/smoke.mjs` in CI job `wasm-build` |
| 6 | HTTP service | `app/server.mjs` | any HTTP client | `npm start` then JSON over HTTP | [`HTTP_API.md`](HTTP_API.md) + app tests |
| 7 | CLI | `src/cli.js` | shell | `node src/cli.js --help` | `test/cli.test.js` |

## Channel contracts

- **Byte-exactness**: channels 1–5 produce/consume Canonical Profile v1.1
  bytes and reject identical inputs identically. Error **codes** are part
  of the contract; error *messages* may vary by language.
- **Statelessness**: every channel is decisive on G1–G8 from
  `(event, registry, now)` alone. G9 (replay) requires caller-owned state;
  each channel documents its store contract (see
  [`NONCE_STORES.md`](NONCE_STORES.md), and the WASM `nonce_state`
  round-trip).
- **No network at verify time**: none of the verifiers fetch anything.
  Registries are pinned inputs (`registry_root`), not lookups.

## Versioning

All channels version together with the repository tag (`vX.Y.Z`). The
Python `pyproject.toml`, Rust `Cargo.toml`, and WASM banner carry the same
version at release time. Breaking protocol changes require a new
Canonical Profile version per §12 of SPEC.md — never a silent edit.
