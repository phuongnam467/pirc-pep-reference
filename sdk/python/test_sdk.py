#!/usr/bin/env python3
"""PiProof Python SDK conformance — runs the repository's public vectors
with zero test-framework dependencies. Exits 0 on success.

    python test_sdk.py            # from sdk/python, or anywhere via path
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from piproof_sdk import PiProofVerifier, canonicalize, load_json_text  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
NOW = 1_755_860_000_000


def registry_root(registry):
    return "r1:" + hashlib.sha256(
        canonicalize(registry).encode("utf-8")).hexdigest()


def main():
    failures = []

    # 1. Canonical Profile vectors — byte-exact or rejected.
    with open(os.path.join(ROOT, "vectors", "canonical", "index.json"),
              encoding="utf-8") as f:
        idx = json.load(f)
    for v in idx["vectors"]:
        vid = v["id"]
        try:
            parsed = load_json_text(v["input"])
            out = canonicalize(parsed)
            want = v["expected"].get("canonical")
            if want is None:
                failures.append(f"{vid}: expected rejection, got {out!r}")
            elif out != want:
                failures.append(f"{vid}: got {out!r}, want {want!r}")
        except Exception as e:  # noqa: BLE001
            want = v["expected"].get("error")
            if want is None:
                failures.append(f"{vid}: expected output, raised {e}")
            elif want not in str(e):
                failures.append(f"{vid}: error {e!r} lacks {want!r}")
    print(f"canonical vectors: {len(idx['vectors'])} checked")

    # 2. Valid signed event — end-to-end ALLOW with epoch binding.
    with open(os.path.join(ROOT, "vectors", "registry.json"),
              encoding="utf-8") as f:
        registry = load_json_text(f.read())
    with open(os.path.join(ROOT, "vectors", "valid", "signed-event.json"),
              encoding="utf-8") as f:
        event = load_json_text(f.read())

    proof = {
        "type": "PiProof",
        "version": 1,
        "created_at": event["timestamp"],
        "event": event,
        "registry_root": registry_root(registry),
    }
    v = PiProofVerifier(registry, now=NOW)
    res = v.decide(proof)
    if res["decision"] != "ALLOW":
        failures.append(f"valid proof denied: {res['code']} / {res['checks']}")
    else:
        print("valid signed event: ALLOW "
              f"(binding={res.get('binding')}, checks={len(res['checks'])})")

    # 3. Tampered payload must DENY with INVALID_SIGNATURE.
    tampered = dict(proof)
    tampered["event"] = dict(event, weight=event["weight"] + 1)
    res = v.decide(tampered)
    if res["decision"] != "DENY" or res["code"] != "INVALID_SIGNATURE":
        failures.append(f"tamper not caught as INVALID_SIGNATURE: {res['code']}")

    # 4. Revoked key must DENY before any signature work.
    revoked = dict(proof)
    revoked["event"] = dict(event, key_id="k-2025-retired")
    res = v.decide(revoked)
    if res["decision"] != "DENY" or res["code"] != "REVOKED_KEY":
        failures.append(f"revoked key not caught: {res['code']}")

    # 5. Wrong epoch (stale registry) must DENY on REGISTRY_ROOT.
    stale = dict(proof)
    stale["registry_root"] = "r1:" + "0" * 64
    res = v.decide(stale)
    if res["decision"] != "DENY" or res["code"] != "REGISTRY_ROOT":
        failures.append(f"wrong epoch not caught: {res['code']}")
    else:
        print("tamper/revoked/epoch negatives: all DENY correctly")

    if failures:
        for f in failures:
            print("FAIL:", f)
        sys.exit(1)
    print("python sdk conformance: ALL GREEN")


if __name__ == "__main__":
    main()
