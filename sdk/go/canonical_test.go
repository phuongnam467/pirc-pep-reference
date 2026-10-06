package piproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// repoRoot resolves the repository root from sdk/go (<repo>/sdk/go).
func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "vectors", "canonical", "index.json")); err != nil {
		t.Fatalf("cannot locate vectors from test dir: %v", err)
	}
	return abs
}

type vectorFile struct {
	Vectors []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Input       string `json:"input"`
		Expected    struct {
			Canonical *string `json:"canonical"`
			Error     *string `json:"error"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestCanonicalInteropVectors is the conformance heart: byte-exact agreement
// with Node and Python on every interop vector, including rejections.
func TestCanonicalInteropVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "vectors", "canonical", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors found — index.json malformed?")
	}
	for _, vec := range file.Vectors {
		vec := vec
		t.Run(vec.ID, func(t *testing.T) {
			v, perr := ParseOrdered(vec.Input)
			var got string
			var gotErr error
			if perr == nil {
				got, gotErr = Canonicalize(v, 0)
			} else {
				gotErr = perr
			}
			if vec.Expected.Canonical != nil {
				if gotErr != nil {
					t.Fatalf("expected canonical %q, got rejection: %v", *vec.Expected.Canonical, gotErr)
				}
				if got != *vec.Expected.Canonical {
					t.Fatalf("byte divergence:\n want %q\n got  %q", *vec.Expected.Canonical, got)
				}
			} else {
				if gotErr == nil {
					t.Fatalf("expected a profile rejection, got canonical %q", got)
				}
			}
		})
	}
}

// TestIsCanonicalFixedPoint pins INV-01: every canonical output is accepted
// by IsCanonical, and re-canonicalizing it is a fixed point.
func TestIsCanonicalFixedPoint(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "vectors", "canonical", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, vec := range file.Vectors {
		v, err := ParseOrdered(vec.Input)
		if err != nil {
			continue
		}
		c1, err := Canonicalize(v, 0)
		if err != nil {
			continue
		}
		if !IsCanonical(c1) {
			t.Fatalf("%s: IsCanonical rejects our own canonical output (INV-01 broken): %q", vec.ID, c1)
		}
		v2, err := ParseOrdered(c1)
		if err != nil {
			t.Fatalf("%s: canonical output does not re-parse: %v", vec.ID, err)
		}
		c2, err := Canonicalize(v2, 0)
		if err != nil || c2 != c1 {
			t.Fatalf("%s: canon(parse(c)) != c (fixed-point broken)", vec.ID)
		}
	}
}

// TestProfileV11Discriminator pins canon-016 explicitly: NFC-form sort flips
// Ç/U+212B versus raw-sort, and the result is idempotent.
func TestProfileV11Discriminator(t *testing.T) {
	const input = "{\"\u00c7\":1,\"\u212b\":2}"
	v, err := ParseOrdered(input)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := Canonicalize(v, 0)
	if err != nil {
		t.Fatal(err)
	}
	const want = "{\"Å\":2,\"Ç\":1}"
	if c1 != want {
		t.Fatalf("NFC-form sort not applied:\n want %q\n got  %q", want, c1)
	}
	v2, _ := ParseOrdered(c1)
	c2, err := Canonicalize(v2, 0)
	if err != nil || c2 != c1 {
		t.Fatalf("not a fixed point: %q vs %q", c1, c2)
	}
}
