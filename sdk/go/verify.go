package piproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"crypto/x509"
	"fmt"
)

// Registry mirrors vectors/registry.json structure and src/registry.js
// semantics: apps hold named keys with a status; eligible_users maps an
// h1: HMAC tag to KYC/Mainnet flags. Lookups use plain map access on
// parsed JSON (no prototype chains exist in Go) preserving INV-10's intent:
// only exact own keys resolve.

type KeyEntry struct {
	PublicKeyPem string `json:"public_key_pem"`
	Status       string `json:"status"`
}

type AppEntry struct {
	Keys map[string]*KeyEntry `json:"keys"`
}

type EligibilityRecord struct {
	KYCPassed       bool `json:"kyc_passed"`
	MainnetMigrated bool `json:"mainnet_migrated"`
}

type Registry struct {
	Version       int                            `json:"version"`
	Apps          map[string]*AppEntry           `json:"apps"`
	EligibleUsers map[string]*EligibilityRecord  `json:"eligible_users"`
}

func LoadRegistry(data []byte) (*Registry, error) {
	reg := &Registry{}
	if err := json.Unmarshal(data, reg); err != nil {
		return nil, fmt.Errorf("registry is not valid JSON: %w", err)
	}
	if reg.Apps == nil {
		reg.Apps = map[string]*AppEntry{}
	}
	if reg.EligibleUsers == nil {
		reg.EligibleUsers = map[string]*EligibilityRecord{}
	}
	return reg, nil
}

// NonceSet is the minimal replay-state contract: atomic claim-or-fail.
// Within one goroutine world this is trivially atomic; concurrent fleets
// must back it with a shared authority (docs/NONCE_STORES.md).
type NonceSet struct{ claimed map[string]bool }

func NewNonceSet() *NonceSet { return &NonceSet{claimed: map[string]bool{}} }

// Claim returns true iff the key was absent (and is now burned).
func (n *NonceSet) Claim(key string) bool {
	if n.claimed[key] {
		return false
	}
	n.claimed[key] = true
	return true
}

// Verdict is the pipeline outcome: OK with empty Code on acceptance, or the
// first failing gate's ERROR code — identical strings to Node/Python.
type Verdict struct {
	OK    bool
	Code  string
	Gates string // human-readable trace, e.g. "SCHEMA✓ APP_KNOWN✗"
}

func reject(code string, gates ...string) Verdict {
	trace := ""
	for i, g := range gates {
		if i > 0 {
			trace += " "
		}
		trace += g + "✓"
	}
	trace += " " + code + "✗"
	return Verdict{OK: false, Code: code, Gates: trace}
}

func accept(gates ...string) Verdict {
	trace := ""
	for i, g := range gates {
		if i > 0 {
			trace += " "
		}
		trace += g + "✓"
	}
	return Verdict{OK: true, Gates: trace}
}

func parseEd25519Pub(pemStr string) (ed25519.PublicKey, bool) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, false
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, false
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	return pub, true
}

// Verify runs gates G1–G9 in order (docs/FORMAL_MODEL.md §2); first failure
// terminates with that gate's code and no state mutation. Only G9 writes.
func Verify(eventText string, reg *Registry, now int64, nonces *NonceSet) Verdict {
	if nonces == nil {
		return reject("SCHEMA", "G9")
	}

	ev, err := ParseOrdered(eventText)
	if err != nil || !isObject(ev) {
		return reject("SCHEMA", "G1")
	}
	if reason := SchemaError(ev); reason != "" {
		return reject("SCHEMA", "G1")
	}
	appID := getString(ev, "app_id")

	app, known := reg.Apps[appID]
	if !known {
		return reject("UNKNOWN_APP", "G1", "G2")
	}
	keyID := getString(ev, "key_id")
	var key *KeyEntry
	if app.Keys != nil {
		key = app.Keys[keyID]
	}
	if key == nil {
		return reject("UNKNOWN_KEY", "G1", "G2", "G3")
	}
	if key.Status != "active" {
		return reject("REVOKED_KEY", "G1", "G2", "G3")
	}

	// G4: canonical fixed point over the body without the signature field.
	body := &Value{Kind: KindObject, Vals: map[string]*Value{}, Keys: make([]string, 0, len(ev.Keys)-1)}
	for _, k := range ev.Keys {
		if k == "signature" {
			continue
		}
		body.Keys = append(body.Keys, k)
		body.Vals[k] = ev.Vals[k]
	}
	c1, err := Canonicalize(body, 0)
	if err != nil {
		return reject("CANONICALIZATION", "G1", "G2", "G3", "G4")
	}
	reparsed, err := ParseOrdered(c1)
	if err != nil {
		return reject("CANONICALIZATION", "G1", "G2", "G3", "G4")
	}
	c2, err := Canonicalize(reparsed, 0)
	if err != nil || c1 != c2 {
		return reject("CANONICALIZATION", "G1", "G2", "G3", "G4")
	}
	g1234 := []string{"G1", "G2", "G3", "G4"}

	// G5: Ed25519 over DOMAIN ‖ "\n" ‖ canonical body.
	sig, err := base64.StdEncoding.DecodeString(getString(ev, "signature"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return reject("INVALID_SIGNATURE", append(g1234, "G5")...)
	}
	pub, ok := parseEd25519Pub(key.PublicKeyPem)
	if !ok || !ed25519.Verify(pub, []byte(Domain+"\n"+c1), sig) {
		return reject("INVALID_SIGNATURE", append(g1234, "G5")...)
	}
	g5 := append(g1234, "G5")

	// G6: symmetric freshness window.
	ts, _ := getInt(ev, "timestamp")
	delta := now - ts
	if delta < -TimestampWindowMs {
		return reject("TIMESTAMP_IN_FUTURE", append(g5, "G6")...)
	}
	if delta > TimestampWindowMs {
		return reject("TIMESTAMP_EXPIRED", append(g5, "G6")...)
	}
	g6 := append(g5, "G6")

	// G7: class ceiling even under valid signatures.
	weight, _ := getInt(ev, "weight")
	class := getString(ev, "action_class")
	if weight > ActionCeilings[class] {
		return reject("WEIGHT_OVERFLOW", append(g6, "G7")...)
	}
	g7 := append(g6, "G7")

	// G8: registry-authoritative eligibility; payload flags never grant.
	elig := ev.Vals["eligibility"]
	selfDeclared := elig.Vals["kyc_passed"].Bool && elig.Vals["mainnet_migrated"].Bool
	rec := reg.EligibleUsers[getString(ev, "pioneer_uid_hash")]
	registryConfirmed := rec != nil && rec.KYCPassed && rec.MainnetMigrated
	if !selfDeclared || !registryConfirmed {
		return reject("INELIGIBLE_USER", append(g7, "G8")...)
	}
	g8 := append(g7, "G8")

	// G9: burn-on-pass nonce claim.
	nonceKey := appID + ":" + getString(ev, "nonce")
	if !nonces.Claim(nonceKey) {
		return reject("REPLAY_DETECTED", append(g8, "G9")...)
	}
	return accept(append(g8, "G9")...)
}
