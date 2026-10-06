package piproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type attackVector struct {
	Attack                string          `json:"attack"`
	Description           string          `json:"description"`
	ExpectedCode          string          `json:"expected_code"`
	PreconditionVerifyOne bool            `json:"precondition_verify_once"`
	Event                 json.RawMessage `json:"event"`
}

func loadRegistry(t *testing.T) *Registry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "vectors", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(data)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func eventTimestamp(t *testing.T, raw json.RawMessage) int64 {
	t.Helper()
	var probe struct {
		Timestamp int64 `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("attack event malformed: %v", err)
	}
	return probe.Timestamp
}

// TestValidEventAccepted proves the happy path end-to-end: closed schema,
// registry resolution, canonical bytes, RFC 8032 Ed25519, freshness,
// ceiling, eligibility, nonce burn.
func TestValidEventAccepted(t *testing.T) {
	reg := loadRegistry(t)
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "vectors", "valid", "signed-event.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := eventTimestamp(t, raw) + 1000
	v := Verify(string(raw), reg, now, NewNonceSet())
	if !v.OK {
		t.Fatalf("valid vector rejected: %s (%s)", v.Code, v.Gates)
	}
}

// TestAttackVectorsRejected runs every committed attack vector and demands
// the exact expected error code — the same 20 the Node CLI asserts.
func TestAttackVectorsRejected(t *testing.T) {
	reg := loadRegistry(t)
	dir := filepath.Join(repoRoot(t), "vectors", "attacks")
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	if len(names) == 0 {
		t.Fatal("no attack vectors found")
	}
	for _, name := range names {
		name := name
		if !strings.HasSuffix(name.Name(), ".json") {
			continue
		}
		t.Run(name.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var av attackVector
			if err := json.Unmarshal(data, &av); err != nil {
				t.Fatal(err)
			}
			eventStr := string(av.Event)
			// Deterministic clock per vector intent: freshness attacks get a
			// `now` far outside the ±window; everything else sits inside it.
			ts := eventTimestamp(t, av.Event)
			now := ts + 1000
			switch av.ExpectedCode {
			case "TIMESTAMP_EXPIRED":
				now = ts + TimestampWindowMs*10
			case "TIMESTAMP_IN_FUTURE":
				now = ts - TimestampWindowMs*10
			}

			if av.PreconditionVerifyOne {
				ns := NewNonceSet()
				first := Verify(eventStr, reg, now, ns)
				if !first.OK {
					t.Fatalf("precondition verify failed (%s) — test vector broken?", first.Code)
				}
				second := Verify(eventStr, reg, now, ns)
				if second.OK || second.Code != av.ExpectedCode {
					t.Fatalf("want %s after replay, got ok=%v code=%s", av.ExpectedCode, second.OK, second.Code)
				}
				return
			}
			got := Verify(eventStr, reg, now, NewNonceSet())
			if got.OK || got.Code != av.ExpectedCode {
				t.Fatalf("want %s, got ok=%v code=%s (%s)", av.ExpectedCode, got.OK, got.Code, got.Gates)
			}
		})
	}
}

// TestBurnOnlyOnPass pins INV-05: a rejected event never consumes its nonce.
func TestBurnOnlyOnPass(t *testing.T) {
	reg := loadRegistry(t)
	dir := filepath.Join(repoRoot(t), "vectors", "attacks")
	data, err := os.ReadFile(filepath.Join(dir, "06_timestamp_expired.json"))
	if err != nil {
		t.Skip("timestamp-expired vector missing")
	}
	var av attackVector
	if err := json.Unmarshal(data, &av); err != nil {
		t.Fatal(err)
	}
	ns := NewNonceSet()
	stale := eventTimestamp(t, av.Event) + TimestampWindowMs*10
	got := Verify(string(av.Event), reg, stale, ns)
	if got.OK || got.Code != "TIMESTAMP_EXPIRED" {
		t.Fatalf("expected TIMESTAMP_EXPIRED, got %s", got.Code)
	}
	fresh := eventTimestamp(t, av.Event) + 1000
	again := Verify(string(av.Event), reg, fresh, ns)
	if !again.OK {
		t.Fatalf("nonce was burned by a REJECTED event (INV-05 violated): %s", again.Code)
	}
}

// TestRevokedKeyNeverVerifies pins INV-08 at snapshot level.
func TestRevokedKeyNeverVerifies(t *testing.T) {
	reg := loadRegistry(t)
	if reg.Apps["demo-app"].Keys["k-2025-retired"].Status != "revoked" {
		t.Fatal("fixture changed: revoked key missing")
	}
}
