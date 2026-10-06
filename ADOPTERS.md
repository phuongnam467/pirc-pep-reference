# Adopters & independent implementations

> Listing here is earned, not claimed. See
> [`EXTERNAL_IMPLEMENTATION.md`](EXTERNAL_IMPLEMENTATION.md) for the bar.

| Implementation | Language | Maintainer | Conformance status | Notes |
|----------------|----------|------------|--------------------|-------|
| `piproof` (reference) | TypeScript-flavored Node.js | PiProof maintainers | 149/149 tests + fuzz + conformance | this repository |
| `piproof-sdk` | Python ≥3.9 (stdlib-only) | PiProof maintainers | 16/16 vectors + end-to-end + negatives (CI: python-package) | Ed25519 in pure Python |
| `sdk/go` | Go ≥1.22 | PiProof maintainers | unit + fuzz driver (CI: go-sdk) | stdlib crypto/ed25519 |
| `piproof` crate | Rust (edition 2021) | PiProof maintainers | vector suite via CI: rust-conformance | ed25519-dalek only; G9 honest-stateless |
| `piproof.wasm` | Go → WebAssembly | PiProof maintainers | smoke: accept / replay-burn / tamper (CI: wasm-build) | browser + edge runtimes |

## Third-party implementations

*(none yet — this table is intentionally short. The kit above exists so
the first external entry can be someone who never read our source.)*

## Why we publish the bar instead of claiming adoption

An ecosystem claim that cannot be independently checked is marketing.
Every row in the first table links to a CI job anyone can re-run; every
future third-party row will link to a merged PR whose diffs are the proof.
