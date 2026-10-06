package piproof

import (
	"regexp"
	"strconv"
)

// Schema validation mirrors src/schema.js exactly: closed world, exact key
// set, strict formats. Any deviation rejects at gate G1 before any semantic
// use — the property that keeps the V8 parser divergence (SECURITY.md)
// unreachable in PiProof pipelines.

var (
	hex32Re      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	b64SigRe     = regexp.MustCompile(`^[A-Za-z0-9+/]{85}[AQgw]==$`)
	uidHashRe    = regexp.MustCompile(`^h1:[A-Za-z0-9_-]{43}$`)
	appIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	keyIDRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	actionIDRe   = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9._:-]{1,127}$`)
)

var topLevelKeys = []string{
	"v", "app_id", "key_id", "action_class", "action_id", "weight",
	"timestamp", "nonce", "pioneer_uid_hash", "eligibility", "signature",
}

// ActionCeilings mirrors WEIGHT_CEILINGS in src/constants.js.
var ActionCeilings = map[string]int64{"A": 100, "B": 10, "C": 1}

// TimestampWindowMs mirrors TIMESTAMP_WINDOW_MS (±5 minutes).
const TimestampWindowMs int64 = 300_000

// Domain mirrors DOMAIN in src/constants.js.
const Domain = "PiRC1-PEP-v1"

func isObject(v *Value) bool { return v != nil && v.Kind == KindObject }

func getString(v *Value, key string) string {
	child, ok := v.Vals[key]
	if !ok || child.Kind != KindString {
		return ""
	}
	return child.Str
}

func getInt(v *Value, key string) (int64, bool) {
	child, ok := v.Vals[key]
	if !ok || child.Kind != KindNumber {
		return 0, false
	}
	n, err := strconv.ParseInt(string(child.Num), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// SchemaError returns "" when the event satisfies the closed schema, or a
// human-readable reason mirroring src/schema.js.
func SchemaError(e *Value) string {
	if !isObject(e) {
		return "event must be a JSON object"
	}
	present := make(map[string]bool, len(e.Keys))
	for _, k := range e.Keys {
		known := false
		for _, t := range topLevelKeys {
			if k == t {
				known = true
				break
			}
		}
		if !known {
			return "unknown field: " + k
		}
		present[k] = true
	}
	for _, t := range topLevelKeys {
		if !present[t] {
			return "missing field: " + t
		}
	}

	vn, ok := getInt(e, "v")
	if !ok || vn != 1 {
		return "unsupported spec version"
	}
	if !appIDRe.MatchString(getString(e, "app_id")) {
		return "app_id must match [a-z0-9][a-z0-9-]{2,63}"
	}
	if !keyIDRe.MatchString(getString(e, "key_id")) {
		return "key_id must match [a-zA-Z0-9][a-zA-Z0-9._-]{0,63}"
	}
	class := getString(e, "action_class")
	if _, ok := ActionCeilings[class]; !ok {
		return "action_class must be one of A|B|C"
	}
	if !actionIDRe.MatchString(getString(e, "action_id")) {
		return "action_id is malformed"
	}
	weight, ok := getInt(e, "weight")
	if !ok || weight < 1 || weight > MaxSafeInt {
		return "weight must be a positive safe integer"
	}
	ts, ok := getInt(e, "timestamp")
	if !ok || ts <= 0 {
		return "timestamp must be a positive integer (unix ms)"
	}
	if !hex32Re.MatchString(getString(e, "nonce")) {
		return "nonce must be 16 bytes of lowercase hex"
	}
	if !uidHashRe.MatchString(getString(e, "pioneer_uid_hash")) {
		return "pioneer_uid_hash must be a versioned HMAC tag (h1:<43 base64url chars>)"
	}
	if !b64SigRe.MatchString(getString(e, "signature")) {
		return "signature must be base64 of 64 bytes"
	}

	elig, ok := e.Vals["eligibility"]
	if !ok || !isObject(elig) {
		return "eligibility must be an object"
	}
	if len(elig.Keys) != 2 {
		return "eligibility fields must be exactly kyc_passed and mainnet_migrated"
	}
	for _, want := range []string{"kyc_passed", "mainnet_migrated"} {
		flag, ok := elig.Vals[want]
		if !ok || flag.Kind != KindBool {
			return "eligibility fields must be exactly kyc_passed and mainnet_migrated"
		}
	}
	return ""
}
