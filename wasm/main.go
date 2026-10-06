// Command wasm is a WebAssembly binding for the Go PiProof verifier.
// It exposes the exact same G1–G9 pipeline as the server-side Go SDK to
// browsers and edge runtimes:
//
//	globalThis.PiProofGo.verify(eventText, registryText, nowMs, nonceStateJSON)
//	  -> { ok, code, gates, nonce_state }
//
// Nonce state goes in and comes out as a JSON array of claimed keys so the
// caller (page or worker) owns persistence — the module stays stateless
// between calls. The sdk/go NonceSet stays minimal; serialization lives
// here at the boundary.
package main

import (
	"encoding/json"
	"sort"
	"syscall/js"

	piproof "github.com/EslaM-X/piproof/sdk/go"
)

func verifyFunc(this js.Value, args []js.Value) any {
	if len(args) != 4 {
		return errResult("USAGE", "verify(eventText, registryText, nowMs, nonceStateJSON)")
	}
	eventText := args[0].String()
	registryText := args[1].String()
	now := int64(args[2].Float())
	nonceJSON := args[3].String()

	reg, err := piproof.LoadRegistry([]byte(registryText))
	if err != nil {
		return errResult("REGISTRY_MALFORMED", err.Error())
	}

	nonces := piproof.NewNonceSet()
	seen := map[string]bool{}
	if nonceJSON != "" {
		var claimed []string
		if err := json.Unmarshal([]byte(nonceJSON), &claimed); err != nil {
			return errResult("NONCE_STATE_MALFORMED", err.Error())
		}
		for _, k := range claimed {
			nonces.Claim(k)
			seen[k] = true
		}
	}

	v := piproof.Verify(eventText, reg, now, nonces)
	if v.OK {
		// Burn this event's nonce for future runs using the same key shape
		// Verify derives internally (app_id + ":" + nonce).
		if appID, nonce := extractAppNonce(eventText); appID != "" {
			seen[appID+":"+nonce] = true
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stateOut, _ := json.Marshal(keys)

	return map[string]any{
		"ok":          v.OK,
		"code":        v.Code,
		"gates":       v.Gates,
		"nonce_state": string(stateOut),
	}
}

func main() {
	js.Global().Set("PiProofGo", map[string]any{
		"version": "0.19.0",
		"verify":  js.FuncOf(verifyFunc),
	})
	select {} // keep the module resident; calls arrive via JS interop
}

func errResult(code, detail string) map[string]any {
	return map[string]any{"ok": false, "code": code, "gates": detail, "nonce_state": ""}
}

// extractAppNonce pulls app_id and nonce out of a canonical PEP/1 event
// without a full parse — the fields are flat top-level strings.
func extractAppNonce(eventText string) (string, string) {
	var ev struct {
		AppID string `json:"app_id"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(eventText), &ev); err != nil {
		return "", ""
	}
	return ev.AppID, ev.Nonce
}
