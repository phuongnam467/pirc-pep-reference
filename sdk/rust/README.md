# piproof (Rust)

Independent Rust verifier for the PiProof protocol — see [`SPEC.md`](../../SPEC.md).

## Status

- Canonical JSON Profile v1.1: implemented **std-only** (hand-written
  scanner; lexical number rules, UTF-16 key ordering and duplicate-key
  rejection enforced exactly). Validated against all 16 interop vectors.
- PEP/1 verification: G1–G8 decisive, G9 reported honestly as
  UNVERIFIABLE (this library is stateless by design).
- Conformance suite: `cargo test` runs the repository's public vectors.

## Dependency policy

Production code depends on exactly two crates: `ed25519-dalek` (the Rust
ecosystem's standard curve implementation, analogous to Go's
`crypto/ed25519`) and `serde_json` (JSON value handling for registry and
event documents). Everything protocol-specific — the Canonical Profile
v1.1 scanner, the G1–G9 gate order, identifier/nonce/hash grammars — is
implemented in this crate, std-only, so the *protocol logic* stays
auditable in one file.

## Usage

```rust
let report = piproof::verify_signed_event(&event_json, &registry_json, now_ms)?;
assert!(report.ok);
```

## Note on local builds

Some locked-down Windows environments block execution of freshly compiled
artifacts (Application Control, os error 4551). CI is the authoritative
verification ground: the `rust-conformance` job runs `cargo test` on every
push across Ubuntu and Windows.
