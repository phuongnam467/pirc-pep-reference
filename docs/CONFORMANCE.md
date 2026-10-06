# PiProof Conformance — How to Claim "PiProof Compatible"

**Status:** normative since v0.16.

Anyone (person, company, or agent) may implement PiProof. This document
defines the *only* accepted way to claim compatibility with the protocol:
run the conformance matrix and publish the output verbatim.

## The conformance matrix

| # | Requirement | Evidence command | Pass condition |
|---|---|---|---|
| C1 | Canonical Profile v1.1 byte-exactness | `node scripts/check-canonical-vectors.mjs` | all interop vectors reproduce byte-for-byte |
| C2 | Cross-language canonical agreement | `python scripts/cross-canonical.py` | same vectors agree from an independent stdlib implementation |
| C3 | Protocol core reimplementation | `go test ./sdk/go/...` | 16 canonical vectors + valid event ACCEPTS + all 20 attack vectors reject with the exact expected codes + INV-01/INV-05/INV-08 pins |
| C4 | Independent Ed25519 verification | `python scripts/cross-verify.py` | RFC 8032 signature over the committed valid vector verifies |

One command runs everything present on your machine:

```
node scripts/conformance.mjs          # SKIPs absent toolchains
node scripts/conformance.mjs --strict # SKIP counts as failure
```

## Rules for claiming compatibility

1. You MUST run the full matrix against **this repository's vectors** —
   self-generated vectors prove nothing about interoperability.
2. You MUST publish the raw matrix output alongside the claim, including
   the commit SHA of the vectors repository you tested against.
3. You MAY claim: "passes the PiProof conformance matrix at commit `<sha>`".
4. You MUST NOT claim: "certified", "endorsed by", or "approved" — no such
   program exists, and SECURITY.md's audit-status honesty applies to any
   downstream claim as well.
5. A third-party implementation maintained by someone outside this
   repository's authors closes MATURITY.md row #13 — that is an open and
   explicitly welcomed contribution.

## Reference implementations held today

| Language | Location | Scope | Author overlap |
|---|---|---|---|
| Node.js | `src/` | full protocol + product layers | project author |
| Python 3 | `sdk/python/` (pip-installable), `scripts/cross-*.py` | protocol core, from scratch | project author |
| Go | `sdk/go/` | protocol core, from scratch (`crypto/ed25519` stdlib; single pinned dep `golang.org/x/text` because Go ships no Unicode tables) | project author |
| Rust | `sdk/rust/` | protocol core (std-only canonicalizer; `ed25519-dalek` for the curve); G9 honest-stateless | project author |
| WebAssembly | `wasm/` (Go→WASM) | browser/edge binding of the Go core | project author |

Four independently-written codebases plus one compiled binding agreeing
byte-for-byte is strong evidence the *specification* is implementable,
not merely that one codebase works. It is not a substitute for the
external audit gating v1.0 — and author-overlap is exactly why
[EXTERNAL_IMPLEMENTATION.md](EXTERNAL_IMPLEMENTATION.md) exists.
