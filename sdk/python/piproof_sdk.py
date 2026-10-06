#!/usr/bin/env python3
"""
PiProof Python SDK â€” independent verifier, standard library only.

Same pipeline as the Node implementation: closed schema, registry-gated
eligibility, PiProof Canonical Profile v1.1 bytes, RFC 8032 Ed25519, freshness,
weight ceilings, atomic nonce replay protection, epoch binding, and the
narrowing-only policy rule subset.

Library use:
    from piproof_sdk import PiProofVerifier
    v = PiProofVerifier(registry)
    d = v.decide(proof_dict, policy={"require_epoch_bound": True})
    d["decision"]  # "ALLOW" | "DENY"

CLI use:
    python piproof_sdk.py proof.json --registry registry.json \\
        [--policy '{"preset":"..."}'|'{"rules":...}'|file.json] \\
        [--state nonces.json] [--now <unix-ms>]

Exit codes: 0 ALLOW Â· 1 DENY Â· 2 usage/IO error.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time
import unicodedata

DOMAIN = b"PiRC1-PEP-v1\n"
TIMESTAMP_WINDOW_MS = 300_000
WEIGHT_CEILINGS = {"A": 100, "B": 10, "C": 1}
MAX_SAFE_INT = 2**53 - 1
PIPROOF_TYPE = "PiProof"
PIPROOF_VERSION = 1
ENVELOPE_KEYS = {"type", "version", "created_at", "event", "registry_root"}

# ---------------------------------------------------------------- Ed25519 ---
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


_D = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = ((y * y - 1) * _inv(_D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
        if (x * x - xx) % P != 0:
            raise ValueError("point not on curve")
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_B = [_xrecover(_BY), _BY % P]
_IDENT = [0, 1]


def _edwards_add(q, p):
    x1, y1 = q
    x2, y2 = p
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return [x3 % P, y3 % P]


def _scalarmult(pt, e):
    r = _IDENT
    while e > 0:
        if e & 1:
            r = _edwards_add(r, pt)
        pt = _edwards_add(pt, pt)
        e >>= 1
    return r


def _decode_point(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _xrecover(y)
    if x == 0 and sign != 0:
        raise ValueError("non-canonical point")
    if x & 1 != sign:
        x = P - x
    return [x, y]


def ed25519_verify(pub32, message, sig64):
    r_bytes, s_bytes = sig64[:32], sig64[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    try:
        a = _decode_point(pub32)
        r = _decode_point(r_bytes)
    except (ValueError, IndexError):
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pub32 + message).digest(), "little") % L
    return _scalarmult(_B, s) == _edwards_add(r, _scalarmult(a, k))


SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


def pem_to_raw32(pem):
    body = "".join(line for line in pem.strip().splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    if not der.startswith(SPKI_ED25519_PREFIX) or len(der) != 44:
        raise ValueError("not an Ed25519 SPKI PEM")
    return der[12:]


# ------------------------------------------- PiProof Canonical Profile v1.1 ---
MAX_DEPTH = 64


def _js_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append(f'\\u{o:04x}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(s):
    return s.encode('utf-16-be')


def canonicalize(value, depth=0):
    if depth > MAX_DEPTH:
        raise CanonicalError(f"canonicalization depth exceeded {MAX_DEPTH}")
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE_INT:
            raise CanonicalError(f"non-canonical number: {value}")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("floats are outside the profile")
    if isinstance(value, str):
        return _js_string(unicodedata.normalize('NFC', value))
    if isinstance(value, list):
        return '[' + ','.join(canonicalize(v, depth + 1) for v in value) + ']'
    if isinstance(value, dict):
        seen = set()
        for raw in value.keys():
            norm = unicodedata.normalize('NFC', raw)
            if norm in seen:
                raise CanonicalError(f'normalized key collision under NFC: "{raw}"')
            seen.add(norm)
        # Profile v1.1: sort NFC FORMS (utf-16-BE byte order), not raw keys â€”
        # mirrors src/canonical.js; keeps canon(parse(canon(x))) a fixed point.
        entries = sorted(
            ((unicodedata.normalize('NFC', raw), value[raw]) for raw in value.keys()),
            key=lambda pair: _utf16_key(pair[0]),
        )
        parts = [_js_string(norm) + ':' + canonicalize(val, depth + 1) for norm, val in entries]
        return '{' + ','.join(parts) + '}'
    raise CanonicalError(f"unsupported type: {type(value).__name__}")


class CanonicalError(ValueError):
    pass


class PolicyError(ValueError):
    pass


# ------------------------------------------------------------ policy subset ---
ACTION_CLASSES = ("A", "B", "C")


POLICY_RULES = (
    "issuer_allowlist", "action_classes", "min_weight", "max_weight",
    "max_age_ms", "require_kyc", "require_mainnet", "require_epoch_bound",
)


def normalize_policy(policy):
    if policy is None:
        return None
    if not isinstance(policy, dict):
        raise PolicyError("policy must be an object")
    unknown = set(policy.keys()) - set(POLICY_RULES) - {"preset"}
    if unknown:
        raise PolicyError(f"unknown policy rules: {sorted(unknown)}")
    out = {}
    if isinstance(policy.get("issuer_allowlist"), list):
        out["issuer_allowlist"] = list(policy["issuer_allowlist"])
    if isinstance(policy.get("action_classes"), list):
        out["action_classes"] = [c for c in policy["action_classes"] if c in ACTION_CLASSES]
    for k in ("min_weight", "max_weight", "max_age_ms"):
        v = policy.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INT:
            out[k] = v
    for k in ("require_kyc", "require_mainnet", "require_epoch_bound"):
        if isinstance(policy.get(k), bool):
            out[k] = policy[k]
    return out


PRESETS = {
    "merchant-verification-v1": {
        "action_classes": ["A", "B"], "min_weight": 5, "max_age_ms": 86_400_000,
        "require_kyc": True, "require_mainnet": True, "require_epoch_bound": True},
    "marketplace-seller-v1": {
        "action_classes": ["A"], "min_weight": 10, "max_age_ms": 43_200_000,
        "require_kyc": True, "require_mainnet": True, "require_epoch_bound": True},
    "agent-payment-v1": {
        "action_classes": ["A"], "min_weight": 1, "max_age_ms": 300_000,
        "require_kyc": True, "require_mainnet": True, "require_epoch_bound": True},
    "community-member-v1": {
        "action_classes": ["B", "C"], "min_weight": 1, "max_age_ms": 604_800_000,
        "require_kyc": True},
    "reward-eligibility-v1": {
        "min_weight": 1, "max_age_ms": 86_400_000,
        "require_kyc": True, "require_mainnet": True, "require_epoch_bound": True},
}


def resolve_policy(ref):
    """Accepts a preset name, {'preset': name}, an inline dict, or None."""
    if ref is None:
        return None
    if isinstance(ref, str):
        if ref in PRESETS:
            return dict(PRESETS[ref])
        raise PolicyError(f"unknown policy preset: {ref}")
    if isinstance(ref, dict):
        name = ref.get("preset")
        if isinstance(name, str):
            if name in PRESETS:
                return dict(PRESETS[name])
            raise PolicyError(f"unknown policy preset: {name}")
        return normalize_policy(ref)
    raise PolicyError("policy must be a preset name or an object")


# ---------------------------------------------------------------- verifier ---
class NonceStore:
    """Atomic within one process; persist via state_file in the CLI."""

    def __init__(self, state_file=None):
        self.state_file = state_file
        self.seen = set()
        if state_file and os.path.exists(state_file):
            with open(state_file, encoding="utf-8") as f:
                self.seen = set(json.load(f))

    def has(self, key):
        return key in self.seen

    def add(self, key):
        self.seen.add(key)
        if self.state_file:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(sorted(self.seen), f)


def _js_number_str(text):
    """Format a JSON number literal the way JavaScript Number.prototype.toString
    does, so rejection messages match the reference implementation's wording."""
    d = float(text)
    if d == int(d) and abs(d) < 1e21:
        return str(int(d))
    r = repr(d)
    if "e" not in r:
        return r
    mantissa, exp = r.split("e")
    sign = "+" if not exp.startswith("-") else ""
    return f"{mantissa}e{sign}{int(exp)}"


def _reject_float(text):
    raise CanonicalError(f"non-canonical number: {_js_number_str(text)}")


def load_json_text(text):
    return json.loads(text, parse_float=_reject_float)


class PiProofVerifier:
    def __init__(self, registry, nonce_store=None, now=None):
        if not isinstance(registry, dict):
            raise TypeError("registry must be a parsed registry object")
        self.registry = registry
        self.nonce_store = nonce_store if nonce_store is not None else NonceStore()
        self.now = now if now is not None else int(time.time() * 1000)

    # ---- event pipeline (mirrors src/verify.js step-for-step) -------------
    def _verify_event(self, event):
        checks = []

        def reject(check, code):
            checks.append((check, False))
            return False, code, checks

        required = {
            "v", "app_id", "key_id", "action_class", "action_id", "weight",
            "timestamp", "nonce", "pioneer_uid_hash", "eligibility", "signature",
        }
        if not isinstance(event, dict) or set(event.keys()) != required:
            return reject("SCHEMA", "SCHEMA")
        if event["v"] != 1:
            return reject("SCHEMA", "SCHEMA")
        checks.append(("SCHEMA", True))

        apps = self.registry.get("apps") or {}
        if event["app_id"] not in apps:
            return reject("APP_KNOWN", "UNKNOWN_APP")
        checks.append(("APP_KNOWN", True))

        key_rec = (apps[event["app_id"]].get("keys") or {}).get(event["key_id"])
        if key_rec is None:
            return reject("KEY_ACTIVE", "UNKNOWN_KEY")
        if key_rec.get("status") != "active":
            return reject("KEY_ACTIVE", "REVOKED_KEY")
        checks.append(("KEY_ACTIVE", True))

        body = {k: v for k, v in event.items() if k != "signature"}
        try:
            c1 = canonicalize(body)
            c2 = canonicalize(load_json_text(c1))
        except (CanonicalError, ValueError):
            return reject("CANONICALIZATION", "CANONICALIZATION")
        if c1 != c2:
            return reject("CANONICALIZATION", "CANONICALIZATION")
        checks.append(("CANONICALIZATION", True))

        try:
            sig = base64.b64decode(event["signature"], validate=True)
            pub = pem_to_raw32(key_rec["public_key_pem"])
        except Exception:
            return reject("SIGNATURE", "INVALID_SIGNATURE")
        if len(sig) != 64 or not ed25519_verify(pub, DOMAIN + c1.encode("utf-8"), sig):
            return reject("SIGNATURE", "INVALID_SIGNATURE")
        checks.append(("SIGNATURE", True))

        delta = self.now - event["timestamp"]
        if delta < -TIMESTAMP_WINDOW_MS:
            return reject("TIMESTAMP_FRESHNESS", "TIMESTAMP_IN_FUTURE")
        if delta > TIMESTAMP_WINDOW_MS:
            return reject("TIMESTAMP_FRESHNESS", "TIMESTAMP_EXPIRED")
        checks.append(("TIMESTAMP_FRESHNESS", True))

        if not isinstance(event["action_class"], str) or \
                event["action_class"] not in WEIGHT_CEILINGS or \
                event["weight"] > WEIGHT_CEILINGS[event["action_class"]]:
            return reject("WEIGHT_BOUND", "WEIGHT_OVERFLOW")
        checks.append(("WEIGHT_BOUND", True))

        elig = event.get("eligibility") or {}
        elig_rec = (self.registry.get("eligible_users") or {}).get(event["pioneer_uid_hash"])
        ok_self = elig.get("kyc_passed") is True and elig.get("mainnet_migrated") is True
        ok_registry = (
            elig_rec is not None
            and elig_rec.get("kyc_passed") is True
            and elig_rec.get("mainnet_migrated") is True
        )
        if not (ok_self and ok_registry):
            return reject("ELIGIBILITY", "INELIGIBLE_USER")
        checks.append(("ELIGIBILITY", True))

        nonce_key = f"{event['app_id']}:{event['nonce']}"
        if self.nonce_store.has(nonce_key):
            return reject("NONCE_REPLAY", "REPLAY_DETECTED")
        self.nonce_store.add(nonce_key)
        checks.append(("NONCE_REPLAY", True))

        return True, None, checks

    # ---- envelope + binding + policy --------------------------------------
    def verify_proof(self, proof, policy_ref=None):
        steps = []
        if not isinstance(proof, dict):
            steps.append(("PROOF_ENVELOPE", False))
            return {"ok": False, "code": "PROOF_ENVELOPE", "binding": None,
                    "checks": steps, "violations": []}
        keys = set(proof.keys())
        if keys - ENVELOPE_KEYS or not {"type", "version", "created_at", "event"} <= keys:
            steps.append(("PROOF_ENVELOPE", False))
            return {"ok": False, "code": "PROOF_ENVELOPE", "binding": None,
                    "checks": steps, "violations": []}
        if proof["type"] != PIPROOF_TYPE or proof["version"] != PIPROOF_VERSION or \
                not isinstance(proof["created_at"], int) or proof["created_at"] <= 0 or \
                not isinstance(proof["event"], dict):
            steps.append(("PROOF_ENVELOPE", False))
            return {"ok": False, "code": "PROOF_ENVELOPE", "binding": None,
                    "checks": steps, "violations": []}

        bound = "registry_root" in proof
        if bound and (not isinstance(proof["registry_root"], str)):
            steps.append(("PROOF_ENVELOPE", False))
            return {"ok": False, "code": "PROOF_ENVELOPE", "binding": None,
                    "checks": steps, "violations": []}
        binding = "EPOCH_BOUND" if bound else "LOCAL"
        steps.append(("PROOF_ENVELOPE", True))

        if bound:
            actual = "r1:" + hashlib.sha256(
                canonicalize(self.registry).encode("utf-8")).hexdigest()
            if actual != proof["registry_root"]:
                steps.append(("REGISTRY_ROOT", False))
                return {"ok": False, "code": "REGISTRY_ROOT", "binding": binding,
                        "checks": steps, "violations": []}
            steps.append(("REGISTRY_ROOT", True))

        ok, code, checks = self._verify_event(proof["event"])
        steps.extend(checks)

        violations = []
        policy = resolve_policy(policy_ref)
        if ok and policy is not None:
            ev = proof["event"]
            if policy.get("require_epoch_bound") and binding != "EPOCH_BOUND":
                violations.append({"rule": "require_epoch_bound",
                                   "detail": f"proof is {binding} â€” policy requires epoch pinning"})
            if "issuer_allowlist" in policy and ev["app_id"] not in policy["issuer_allowlist"]:
                violations.append({"rule": "issuer_allowlist",
                                   "detail": f"issuer {ev['app_id']} not on accepting list"})
            if "action_classes" in policy and ev["action_class"] not in policy["action_classes"]:
                violations.append({"rule": "action_class",
                                   "detail": f"class {ev['action_class']} not permitted"})
            if "min_weight" in policy and ev["weight"] < policy["min_weight"]:
                violations.append({"rule": "min_weight",
                                   "detail": f"weight {ev['weight']} < required {policy['min_weight']}"})
            if "max_weight" in policy and ev["weight"] > policy["max_weight"]:
                violations.append({"rule": "max_weight",
                                   "detail": f"weight {ev['weight']} > permitted {policy['max_weight']}"})
            if "max_age_ms" in policy and self.now - ev["timestamp"] > policy["max_age_ms"]:
                violations.append({"rule": "max_age",
                                   "detail": f"age {self.now - ev['timestamp']}ms exceeds {policy['max_age_ms']}ms"})
            elig = ev.get("eligibility") or {}
            if policy.get("require_kyc") and elig.get("kyc_passed") is not True:
                violations.append({"rule": "require_kyc", "detail": "KYC confirmation missing"})
            if policy.get("require_mainnet") and elig.get("mainnet_migrated") is not True:
                violations.append({"rule": "require_mainnet", "detail": "Mainnet flag missing"})
            if violations:
                ok, code = False, "POLICY"

        return {"ok": ok, "code": code, "binding": binding,
                "checks": steps, "violations": violations}

    def decide(self, document, policy_ref=None):
        res = self.verify_proof(document, policy_ref)
        preset_name = policy_ref if isinstance(policy_ref, str) else (
            policy_ref.get("preset") if isinstance(policy_ref, dict) and "preset" in policy_ref
            else ("inline" if policy_ref is not None else None))
        res["decision"] = "ALLOW" if res["ok"] else "DENY"
        res["policy_used"] = preset_name
        return res


# --------------------------------------------------------------------- cli ---
def main(argv=None):
    ap = argparse.ArgumentParser(description="PiProof Python SDK verifier")
    ap.add_argument("proof", help="path to a PiProof JSON file")
    ap.add_argument("--registry", required=True, help="path to registry JSON")
    ap.add_argument("--policy", default=None,
                    help="preset name, inline JSON rules, or a path to a policy JSON file")
    ap.add_argument("--state", default=None,
                    help="nonce state file (JSON array); enables cross-run replay detection")
    ap.add_argument("--now", type=int, default=None, help="unix-ms override")
    args = ap.parse_args(argv)

    try:
        with open(args.proof, encoding="utf-8") as f:
            proof = load_json_text(f.read())
        with open(args.registry, encoding="utf-8") as f:
            registry = json.load(f)
        policy_ref = args.policy
        if args.policy and os.path.exists(args.policy):
            with open(args.policy, encoding="utf-8") as f:
                policy_ref = load_json_text(f.read())
        elif args.policy and (args.policy.startswith("{") or args.policy in PRESETS):
            policy_ref = load_json_text(args.policy) if args.policy.startswith("{") else args.policy
        verifier = PiProofVerifier(registry, NonceStore(args.state), now=args.now)
        verdict = verifier.decide(proof, policy_ref)
    except (OSError, json.JSONDecodeError, CanonicalError, PolicyError) as err:
        print(json.dumps({"error": str(err)}))
        return 2

    print(json.dumps(verdict, indent=2))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
