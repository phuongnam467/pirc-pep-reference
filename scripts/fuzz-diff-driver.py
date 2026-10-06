#!/usr/bin/env python3
"""Cross-language differential fuzz driver for PiProof (v0.15).

Reads NDJSON commands on stdin, one per line:

    CANC\t<json>   -> canonicalize with the independent Python implementation
                      OK\t<canonical bytes>     on success
                      ERR\t<error class>        on rejection
    PARSE\t<json>  -> json.loads and report the recursive KEY SHAPE
                      SHAPE\t<shape>            always (or ERR\tJSONParseError)

The Node fuzz harness feeds the SAME values through its own implementations
and requires byte-identical outcomes. Any divergence is either a
protocol-breaking bug in PiProof (both implementations wrong the same way)
or a RUNTIME parser divergence in one language's JSON.parse — which the
harness classifies separately (see SECURITY.md, "Runtime parser divergence").
"""
import json
import sys

# Pipes on Windows default to the locale codec (cp1252); the protocol speaks
# UTF-8, so pin stdio explicitly and keep newlines untranslated.
sys.stdin.reconfigure(encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8", newline="")

sys.path.insert(0, "sdk/python")
from piproof_sdk import CanonicalError, canonicalize  # noqa: E402


def shape(value):
    """Recursive structural fingerprint: keys (as codepoints) in document order."""
    if isinstance(value, dict):
        inner = ",".join(
            "k(" + ",".join(str(ord(c)) for c in k) + ")" + shape(v)
            for k, v in value.items()
        )
        return "{" + inner + "}"
    if isinstance(value, list):
        return "[" + ",".join(shape(v) for v in value) + "]"
    return "."


def main():
    # Explicit readline() loop: iterating sys.stdin.buffer read-aheads in
    # blocks and only yields at EOF, which deadlocks interactive
    # request/response round-trips over the pipe.
    while True:
        raw_line = sys.stdin.buffer.readline()
        if not raw_line:
            break
        line = raw_line.decode("utf-8").rstrip("\r\n")
        if not line:
            continue
        cmd, _, payload = line.partition("\t")
        try:
            value = json.loads(payload)
        except ValueError:
            print("ERR\tJSONParseError", flush=True)
            continue

        if cmd == "CANC":
            try:
                out = canonicalize(value)
                # NOTE: flush matters — a pipe default-buffers stdout, which
                # would deadlock the interactive request/response protocol.
                sys.stdout.write("OK\t" + out.replace("\n", "\\n") + "\n")
                sys.stdout.flush()
            except CanonicalError:
                print("ERR\tCanonicalError", flush=True)
            except Exception as exc:  # noqa: BLE001
                print("ERR\tUnexpected:" + type(exc).__name__, flush=True)
        elif cmd == "PARSE":
            print("SHAPE\t" + shape(value), flush=True)
        else:
            print("ERR\tUnknownCommand", flush=True)


if __name__ == "__main__":
    main()
