//! Conformance against the repository's public vectors — the same suite
//! the Node/Python/Go implementations must pass. Run from sdk/rust:
//!   cargo test

use serde_json::Value;

const VECTORS: &str = "../../vectors/canonical/index.json";
const REGISTRY: &str = "../../vectors/registry.json";
const VALID_EVENT: &str = "../../vectors/valid/signed-event.json";
const NOW: i64 = 1_755_860_000_000;

#[test]
fn canonical_profile_vectors_are_byte_exact_or_rejected() {
    let idx: Value = serde_json::from_str(
        &std::fs::read_to_string(VECTORS).expect("canonical vectors present"),
    )
    .unwrap();
    for v in idx["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let input = v["input"].as_str().unwrap();
        match piproof::canonicalize(input) {
            Ok(out) => {
                assert!(
                    v["expected"]["canonical"].is_string(),
                    "{id}: expected rejection, got {out}"
                );
                assert_eq!(
                    out,
                    v["expected"]["canonical"].as_str().unwrap(),
                    "vector {id} mismatch"
                );
            }
            Err(e) => {
                let want = v["expected"]["error"].as_str().unwrap_or_else(|| {
                    panic!("{id}: expected canonical output, library said {e}")
                });
                assert!(e.contains(want), "vector {id}: error '{e}' lacks '{want}'");
            }
        }
    }
}

#[test]
fn valid_signed_event_verifies_end_to_end() {
    let ev = std::fs::read_to_string(VALID_EVENT).unwrap();
    let reg = std::fs::read_to_string(REGISTRY).unwrap();
    let report = piproof::verify_signed_event(&ev, &reg, NOW).expect("pipeline ran");
    assert!(report.ok, "valid vector must verify; got {:?}", report.error_code);
    // honesty: stateless G9 must be UNVERIFIABLE, never green
    let g9 = report.steps.iter().find(|s| s.0 == "NONCE_REPLAY").unwrap();
    assert!(g9.2, "G9 must be unverifiable-flagged");
}

#[test]
fn tampered_payload_fails_with_invalid_signature() {
    let mut ev: Value = serde_json::from_str(
        &std::fs::read_to_string(VALID_EVENT).unwrap(),
    )
    .unwrap();
    ev["weight"] = Value::from(51);
    let reg = std::fs::read_to_string(REGISTRY).unwrap();
    let report =
        piproof::verify_signed_event(&ev.to_string(), &reg, NOW).expect("pipeline ran");
    assert_eq!(report.error_code.as_deref(), Some("INVALID_SIGNATURE"));
}

#[test]
fn revoked_key_is_rejected_before_signature_work() {
    let mut ev: Value = serde_json::from_str(
        &std::fs::read_to_string(VALID_EVENT).unwrap(),
    )
    .unwrap();
    ev["key_id"] = Value::from("k-2025-retired");
    let reg = std::fs::read_to_string(REGISTRY).unwrap();
    let report = piproof::verify_signed_event(&ev.to_string(), &reg, NOW).unwrap();
    assert_eq!(report.error_code.as_deref(), Some("REVOKED_KEY"));
}
