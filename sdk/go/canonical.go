// Package piproof is a from-scratch Go implementation of the PiProof
// protocol core: Canonical Profile v1.1 (docs/CANONICALIZATION.md), the
// closed event schema, and the G1–G9 verification pipeline
// (docs/FORMAL_MODEL.md) with Ed25519 verification per RFC 8032.
//
// It shares NO code with the Node and Python implementations; byte-exact
// agreement on the interop vectors in vectors/canonical/index.json and the
// attack vectors in vectors/attacks/ is the pass condition. It exists to
// prove the specification alone is sufficient to reimplement the protocol —
// see docs/CONFORMANCE.md.
//
// The single auxiliary dependency (golang.org/x/text) exists because Go's
// standard library contains no Unicode normalization tables; it plays the
// role unicodedata plays in Python's stdlib.
package piproof

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/unicode/norm"
)

// MaxDepth mirrors MAX_DEPTH in src/canonical.js: a resource guard so a
// hostile document can never drive unbounded recursion.
const MaxDepth = 64

// MaxSafeInt is 2^53-1, the largest integer exactly representable as an
// IEEE-754 double; the profile admits no other numbers.
const MaxSafeInt = int64(9007199254740991)

// CanonicalError mirrors Node's CanonicalError / Python's
// CanonicalProfileError: a rejection inside the profile itself.
type CanonicalError struct{ Msg string }

func (e *CanonicalError) Error() string { return e.Msg }

func canonErr(format string, args ...interface{}) error {
	return &CanonicalError{Msg: fmt.Sprintf(format, args...)}
}

// ValueKind discriminates parsed JSON values while preserving object key
// order (Go maps would randomize it).
type ValueKind int

const (
	KindNull ValueKind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Value is an ordered JSON value. Object keys are kept in parse order;
// duplicate keys keep the first position with the last value (documented
// platform semantics for Go's ecosystem, matching Python's json module).
type Value struct {
	Kind ValueKind
	Bool bool
	Num  json.Number
	Str  string
	Arr  []*Value
	Keys []string
	Vals map[string]*Value
}

// ParseOrdered parses JSON text preserving object key order. Numbers stay
// as json.Number text so profile validation sees the original literal.
func ParseOrdered(text string) (*Value, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (*Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return tokenToValue(dec, tok)
}

func tokenToValue(dec *json.Decoder, tok json.Token) (*Value, error) {
	switch t := tok.(type) {
	case nil:
		return &Value{Kind: KindNull}, nil
	case bool:
		return &Value{Kind: KindBool, Bool: t}, nil
	case json.Number:
		return &Value{Kind: KindNumber, Num: t}, nil
	case string:
		return &Value{Kind: KindString, Str: t}, nil
	case json.Delim:
		switch t {
		case '[':
			arr := &Value{Kind: KindArray}
			for dec.More() {
				child, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr.Arr = append(arr.Arr, child)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return arr, nil
		case '{':
			obj := &Value{Kind: KindObject, Vals: map[string]*Value{}}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("non-string object key")
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, dup := obj.Vals[key]; !dup {
					obj.Keys = append(obj.Keys, key)
				}
				obj.Vals[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
	default:
		return nil, fmt.Errorf("unexpected token %v", tok)
	}
}

// jsString reproduces JavaScript JSON.stringify escaping exactly for this
// profile: minimal escaping, control chars as \uXXXX, non-ASCII literal.
func jsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == 0x08:
			b.WriteString(`\b`)
		case r == 0x0C:
			b.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// utf16Less orders strings by UTF-16 code units — the ordering JavaScript's
// `<` uses on strings and the profile's sort basis.
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func validateNumber(n json.Number) (int64, error) {
	s := string(n)
	if s == "" {
		return 0, canonErr("non-canonical number: empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == 'e' || c == 'E' {
			return 0, canonErr("floats are outside the profile")
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 || v > MaxSafeInt {
		return 0, canonErr("non-canonical number: %s", s)
	}
	return v, nil
}

// Canonicalize serializes v to canonical bytes per Canonical Profile v1.1:
// non-negative safe integers only, NFC-normalized strings, object keys
// sorted by the UTF-16 order of their NFC forms, NFC key collisions
// rejected, depth capped.
func Canonicalize(v *Value, depth int) (string, error) {
	if depth > MaxDepth {
		return "", canonErr("canonicalization depth exceeded %d", MaxDepth)
	}
	switch v.Kind {
	case KindNull:
		return "null", nil
	case KindBool:
		if v.Bool {
			return "true", nil
		}
		return "false", nil
	case KindNumber:
		n, err := validateNumber(v.Num)
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(n, 10), nil
	case KindString:
		return jsString(norm.NFC.String(v.Str)), nil
	case KindArray:
		parts := make([]string, len(v.Arr))
		for i, child := range v.Arr {
			s, err := Canonicalize(child, depth+1)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case KindObject:
		seen := make(map[string]bool, len(v.Keys))
		type pair struct{ raw, norm string }
		pairs := make([]pair, 0, len(v.Keys))
		for _, raw := range v.Keys {
			n := norm.NFC.String(raw)
			if seen[n] {
				return "", canonErr("normalized key collision under NFC: %s", jsString(raw))
			}
			seen[n] = true
			pairs = append(pairs, pair{raw: raw, norm: n})
		}
		sort.SliceStable(pairs, func(i, j int) bool {
			return utf16Less(pairs[i].norm, pairs[j].norm)
		})
		out := make([]string, len(pairs))
		for i, p := range pairs {
			child, err := Canonicalize(v.Vals[p.raw], depth+1)
			if err != nil {
				return "", err
			}
			out[i] = jsString(p.norm) + ":" + child
		}
		return "{" + strings.Join(out, ",") + "}", nil
	default:
		return "", canonErr("unsupported kind")
	}
}

// IsCanonical reports whether text is already in canonical form.
func IsCanonical(text string) bool {
	v, err := ParseOrdered(text)
	if err != nil {
		return false
	}
	c, err := Canonicalize(v, 0)
	return err == nil && c == text
}
