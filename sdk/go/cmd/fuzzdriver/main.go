// Command fuzzdriver speaks the PiProof differential-fuzzing line protocol
// (the same one scripts/fuzz-diff-driver.py speaks) so the seeded fuzz suite
// in scripts/fuzz.mjs can cross-examine the Go implementation against Node
// and Python on identical bytes:
//
//	CANC\t<json>   → OK\t<canonical>   | ERR\tCanonicalError | ERR\tUnexpected:<Type>
//	PARSE\t<json>  → SHAPE\t<shape>    | ERR\tJSONParseError
//
// Responses are flushed immediately — a pipe default-buffers stdout, which
// would deadlock the interactive request/response loop.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	piproof "github.com/EslaM-X/piproof/sdk/go"
)

// shape mirrors nodeShape() / python shape(): structural fingerprint with
// keys rendered as k(<comma-separated code points>) in PARSE ORDER, "." for
// leaves, [..] for arrays.
func shape(v *piproof.Value) string {
	var b strings.Builder
	writeShape(&b, v)
	return b.String()
}

func writeShape(b *strings.Builder, v *piproof.Value) {
	switch v.Kind {
	case piproof.KindArray:
		b.WriteByte('[')
		for i, child := range v.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			writeShape(b, child)
		}
		b.WriteByte(']')
	case piproof.KindObject:
		b.WriteByte('{')
		for i, k := range v.Keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString("k(")
			for j, r := range k {
				if j > 0 {
					b.WriteByte(',')
				}
				b.WriteString(strconv.Itoa(int(r)))
			}
			b.WriteByte(')')
			writeShape(b, v.Vals[k])
		}
		b.WriteByte('}')
	default:
		b.WriteByte('.')
	}
}

func respond(w *bufio.Writer, line string) {
	w.WriteString(line)
	w.WriteByte('\n')
	w.Flush()
}

func main() {
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for {
		raw, err := in.ReadString('\n')
		if err != nil && raw == "" {
			return
		}
		line := strings.TrimRight(raw, "\r\n")
		if line == "" {
			continue
		}
		cmd := line
		payload := ""
		if idx := strings.Index(line, "\t"); idx >= 0 {
			cmd = line[:idx]
			payload = line[idx+1:]
		}
		switch cmd {
		case "CANC":
			v, perr := piproof.ParseOrdered(payload)
			if perr != nil {
				respond(out, "ERR\tJSONParseError")
				continue
			}
			c, cerr := piproof.Canonicalize(v, 0)
			if cerr != nil {
				if _, ok := cerr.(*piproof.CanonicalError); ok {
					respond(out, "ERR\tCanonicalError")
				} else {
					respond(out, "ERR\tUnexpected:"+fmt.Sprintf("%T", cerr))
				}
				continue
			}
			respond(out, "OK\t"+strings.ReplaceAll(c, "\n", "\\n"))
		case "PARSE":
			v, perr := piproof.ParseOrdered(payload)
			if perr != nil {
				respond(out, "ERR\tJSONParseError")
				continue
			}
			respond(out, "SHAPE\t"+shape(v))
		default:
			respond(out, "ERR\tUnknownCommand")
		}
	}
}
