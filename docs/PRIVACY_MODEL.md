# PiProof Privacy Model — Verification Without Disclosure

**Status:** normative since v0.17.

PiProof's privacy position is not a policy promise; it is enforced by where
the code runs and what the wire format contains. This document states that
position precisely, including its honest limits.

## The core principle

> **A verifier does not need to receive the document to verify it — so the
> gateway never asks for it.**

The offline verification gateway (`/gateway`) executes the complete G1–G9
pipeline inside the visitor's browser (`src/offline-verifier.js` running on
a pure-JS RFC 8032 implementation, `src/web-ed25519.js`). The only network
request the page makes is for the **public registry export**
(`/registry.json`) — data that is public by definition (public keys and
keyed-pseudonym tags). Signed documents, passports, and links containing
them have **no upload path whatsoever**: there is no endpoint on this origin
that accepts them from the page, and the page's strict Content-Security-
Policy (`default-src 'none'; connect-src 'self'`) makes exfiltration a
policy violation even by accident.

## Data inventory — who sees what

| Field | Issuer | Live verifier | Offline gateway | Retention |
|---|---|---|---|---|
| `app_id`, `key_id` | ✔ | ✔ | ✔ | public registry data |
| action class/id/weight | ✔ | ✔ | ✔ | lives in the signed event only |
| `timestamp`, `nonce` | ✔ | ✔ | ✔ | nonce burn state (live verifiers) |
| raw pioneer identity | ✔ issuer-side only | ✘ never leaves backend | ✘ absent from protocol | none beyond issuer |
| `pioneer_uid_hash` | ✔ | ✔ | ✔ | pseudonymous tag (below) |
| signature | ✔ | ✔ | ✔ | public |

The raw pioneer identifier **cannot** leak through any PiProof surface: the
wire format structurally excludes it (closed schema), and what replaces it
is a *keyed* pseudonym:

- `pioneer_uid_hash = "h1:" + HMAC-SHA256(serverSecret, NFC(uid))` — low-
  entropy UIDs are immune to dictionary recovery because the secret never
  leaves the backend;
- different deployments (or apps) with different secrets produce different
  tags for the same person — cross-app linkage requires deliberate secret
  sharing;
- the `h1:` version prefix enables secret rotation: bump to `h2:` under a
  new secret and old tags become unlinkable going forward. Rotation cadence
  is a deployment decision; this repository pins nothing.

## The gateway's honesty contract

1. **Documents are never transmitted.** Not uploaded, not logged, not
   embedded in error reports. There is nothing on the server to subpoena.
2. **The registry shown is the registry used.** The page displays the
   SHA-256 fingerprint of the exact `/registry.json` bytes every verdict
   was computed against.
3. **Unverifiable ≠ passed.** NONCE_REPLAY renders gold `UNVERIFIABLE`
   offline — replay certainty requires shared state no browser has. Epoch
   binding (`registry_root`) is likewise gold-labeled: it is pinned to the
   issuing verifier's epoch and cannot be re-derived here.
4. **Clock honesty.** Freshness uses the visitor's clock; the UI says so.
   A skewed device clock can mislabel freshness while every cryptographic
   layer stays authoritative.
5. **Short links stay ephemeral.** `/p/<id>` mappings live only in process
   memory, are capped, and expire with the process — by design since their
   introduction.

## Honest limits (what privacy this does NOT provide)

- **Within one deployment**, the same person produces the same
  `pioneer_uid_hash` until secrets rotate; a registry operator can track
  activity across events by that tag. That is inherent to eligibility
  gating and is stated, not hidden.
- Timestamps and nonces are unique per event and could correlate submissions
  observed at multiple points.
- The gateway verifies signatures against whatever registry the origin
  serves — a malicious mirror could serve a malicious registry. The
  displayed SHA-256 fingerprint exists precisely so third parties can pin
  and compare it. Trusting the fingerprint is equivalent to trusting the
  deployment.
- Zero-knowledge proofs (prove weight-class without weight, prove
  membership without the tag) remain **out of scope** for PEP/1 — the wire
  format is frozen. Any ZK work belongs to a future protocol generation,
  not retrofitted semantics.

## Non-goals

Anonymity networks, mixnets, or metadata resistance against a global
network observer are out of scope: the gateway's threat model is the
*verifying party learning the document*, not traffic analysis of the visit
itself.
