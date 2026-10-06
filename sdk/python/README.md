# piproof-sdk (Python)

Independent Python verifier for the PiProof protocol — see
[`SPEC.md`](../../SPEC.md). **Standard library only** — zero third-party
runtime dependencies, including Ed25519 (implemented in pure Python on
big integers, same approach as the reference `src/` implementation).

## Install

```bash
pip install ./sdk/python
```

## Library use

```python
from piproof_sdk import PiProofVerifier

v = PiProofVerifier(registry)          # registry = parsed JSON object
d = v.decide(proof_document)
print(d["decision"])                   # "ALLOW" | "DENY"
```

## CLI use

```bash
piproof-verify proof.json --registry registry.json \
    [--policy '{"preset":"..."}'] [--now 1755860000000]
```

## Conformance

`sdk/python/test_sdk.py` runs the repository's public interop vectors
(16 canonical-profile cases + end-to-end valid event + tamper / revoked /
wrong-epoch negatives) with no test framework. It is wired into CI as the
`python-package` job.
