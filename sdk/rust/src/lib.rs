//! Independent Rust verifier for the PiProof protocol.
//!
//! Implements SPEC.md: Canonical JSON Profile v1.1 (std-only, lexical
//! rules enforced exactly) + PEP/1 event verification (G1"G8; G9 reported
//! honestly as UNVERIFIABLE because this library is stateless).
//!
//! Conformance is proven against the repository's public vectors
//! (`tests/conformance.rs`).

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use unicode_normalization::UnicodeNormalization;

/// Canonicalize raw JSON text per PiProof Canonical Profile v1.1.
/// Errors carry the same prefixes as the reference implementation
/// ("non-canonical number: ", "unsupported type: ") so conformance
/// vectors can match on them.
pub fn canonicalize(input: &str) -> Result<String, String> {
    let b = input.as_bytes();
    let mut p = Parser { b, i: 0 };
    p.skip_ws();
    let out = p.value()?;
    p.skip_ws();
    if p.i != b.len() {
        return Err(format!("trailing characters at byte {}", p.i));
    }
    Ok(out)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<String, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string_value(),
            Some(b't') => self.literal("true", "true"),
            Some(b'f') => self.literal("false", "false"),
            Some(b'n') => self.literal("null", "null"),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("unsupported type at byte {}", self.i)),
        }
    }

    fn literal(&mut self, word: &str, out: &str) -> Result<String, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(out.to_string())
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }

    fn number(&mut self) -> Result<String, String> {
        let start = self.i;
        let mut neg = false;
        // Profile v1.1: non-negative safe integers only -- a leading '-' is
        // rejected with the reference wording (echoing the whole literal).
        if self.peek() == Some(b'-') {
            neg = true;
            self.i += 1;
        }
        // integer grammar: 0 | [1-9][0-9]*
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(format!("invalid number at byte {}", start)),
        }
        // Fractions / exponents are outside the profile: consume the whole
        // token so the rejection can quote it the way the reference does.
        let mut frac = false;
        let mut expo = false;
        if self.peek() == Some(b'.') {
            frac = true;
            self.i += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(format!("invalid number at byte {}", self.i));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            expo = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(format!("invalid number at byte {}", self.i));
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        if neg {
            return Err(format!("non-canonical number: {}", text));
        }
        if !frac && !expo {
            // safe-integer bound: |n| <= 2^53-1
            if text.len() > 16 || (text.len() == 16 && text > "9007199254740991") {
                return Err(format!("non-canonical number: {}", text));
            }
            return Ok(text.to_string());
        }
        let v: f64 = text
            .parse()
            .map_err(|_| format!("invalid number at byte {}", start))?;
        Err(format!("non-canonical number: {}", js_number_str(v)))
    }
    /// Scan a JSON string and return its DECODED value (real characters,
    /// escapes resolved, surrogate pairs combined).
    fn string_decoded(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let esc = match self.peek() {
                        Some(e) => e,
                        None => return Err("unterminated escape".into()),
                    };
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                // surrogate pair
                                if self.b.get(self.i) == Some(&b'\\')
                                    && self.b.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err("invalid low surrogate".into());
                                    }
                                    let cp =
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(cp).ok_or("invalid code point")?
                                } else {
                                    return Err("lone high surrogate".into());
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("lone low surrogate".into());
                            } else {
                                char::from_u32(hi).ok_or("invalid \\u escape")?
                            };
                            out.push(ch);
                        }
                        _ => return Err(format!("bad escape \\{}", esc as char)),
                    }
                }
                Some(c) if c < 0x20 => {
                    return Err(format!("raw control character at byte {}", self.i))
                }
                Some(_) => {
                    // consume one UTF-8 encoded char
                    let rest = std::str::from_utf8(&self.b[self.i..])
                        .map_err(|_| "invalid UTF-8".to_string())?;
                    let ch = rest.chars().next().unwrap();
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    /// Scan a string value and emit its canonical encoding:
    /// NFC-normalize first, then minimal escaping.
    fn string_value(&mut self) -> Result<String, String> {
        let decoded = self.string_decoded()?;
        let norm: String = decoded.chars().nfc().collect();
        Ok(encode_json_string(&norm))
    }



    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("bad \\u: truncated".into());
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4])
            .map_err(|_| "bad \\u".to_string())?;
        let v = u32::from_str_radix(s, 16).map_err(|_| "bad \\u digits".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn array(&mut self) -> Result<String, String> {
        self.expect(b'[')?;
        let mut parts = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok("[]".into());
        }
        loop {
            self.skip_ws();
            parts.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
        Ok(format!("[{}]", parts.join(",")))
    }

    fn object(&mut self) -> Result<String, String> {
        self.expect(b'{')?;
        let mut members: Vec<(String, String)> = Vec::new();
        let mut raw_keys: Vec<String> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok("{}".into());
        }
        loop {
            self.skip_ws();
            // keys are NFC-normalized before duplicate checks and ordering
            let key_raw = self.string_decoded()?;
            let key_norm: String = key_raw.chars().nfc().collect();
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.value()?;
            if members.iter().any(|(k, _)| *k == key_norm) {
                if raw_keys.iter().any(|r| r == &key_raw) {
                    return Err(format!("duplicate object key: {}", key_raw));
                }
                // same NFC form, different raw spellings
                return Err(format!(
                    "normalized key collision under NFC: \"{}\"",
                    key_raw
                ));
            }
            members.push((key_norm, val));
            raw_keys.push(key_raw);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
        // Profile ordering = UTF-16 code-unit sequence (JS Array#sort),
        // which differs from code-point order for supplementary planes.
        members.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
        let body: Vec<String> = members
            .into_iter()
            .map(|(k, v)| format!("{}:{}", encode_json_string(&k), v))
            .collect();
        Ok(format!("{{{}}}", body.join(",")))
    }
}

/// Render an f64 the way JavaScript `Number.prototype.toString` does, for
/// rejection-message wording parity with the reference implementation.
/// Only called on values already known to be outside the profile.
fn js_number_str(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e21 {
        return format!("{}", v as i128);
    }
    if v.abs() >= 1e21 || v.abs() < 1e-6 {
        // exponential form, JS style: mantissa e [+|-] exponent
        let e = format!("{:e}", v); // e.g. "1.5e21", "1e-7"
        let (mant, exp) = e.split_once('e').unwrap();
        let mant = trim_number(mant);
        let n: i32 = exp.parse().unwrap();
        let sign = if n < 0 { '-' } else { '+' };
        return format!("{}e{}{}", mant, sign, n.abs());
    }
    // shortest round-trip decimal form (Rust's Display for f64 matches)
    format!("{}", v)
}

fn trim_number(s: &str) -> &str {
    if s.contains('.') {
        let s = s.trim_end_matches('0');
        s.trim_end_matches('.')
    } else {
        s
    }
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let av: Vec<u16> = a.encode_utf16().collect();
    let bv: Vec<u16> = b.encode_utf16().collect();
    av.cmp(&bv)
}

fn push_minimally_escaped(out: &mut String, ch: char) {
    match ch {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\u{0008}' => out.push_str("\\b"),
        '\u{000C}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if (c as u32) < 0x20 => {
            out.push_str(&format!("\\u{:04x}", c as u32));
        }
        c => out.push(c),
    }
}

/// Re-encode a decoded string with minimal escaping (canonical output form).
fn encode_json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        push_minimally_escaped(&mut out, ch);
    }
    out.push('"');
    out
}


// ---------------------------------------------------------------------------
// base64 (standard alphabet) -- tiny decoder, avoids a dependency
// ---------------------------------------------------------------------------

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [255u8; 256];
    for (i, c) in T.iter().enumerate() {
        rev[*c as usize] = i as u8;
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .take_while(|b| *b != b'=')
        .collect();
    if bytes.len() % 4 == 1 {
        return Err("bad base64 length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        let n = chunk.len();
        for c in chunk {
            let v = rev[*c as usize];
            if v == 255 {
                return Err(format!("bad base64 char {:?}", *c as char));
            }
            acc = (acc << 6) | v as u32;
        }
        acc <<= 6 * (4 - n);
        out.push((acc >> 16) as u8);
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// PEP/1 event verification (stateless: G1"G8 decisive, G9 UNVERIFIABLE)
// ---------------------------------------------------------------------------

pub const DOMAIN: &str = "PiRC1-PEP-v1";
pub const TIMESTAMP_WINDOW_MS: i64 = 300_000;

/// A pipeline report: ordered steps with pass/fail/unverifiable outcomes.
#[derive(Debug)]
pub struct Report {
    pub ok: bool,
    pub error_code: Option<String>,
    pub steps: Vec<(String, bool, bool, String)>, // (check, passed?, unverifiable?, detail)
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

fn nonce_ok(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

fn uid_hash_ok(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('h') else {
        return false;
    };
    let Some(pos) = rest.find(':') else {
        return false;
    };
    let (ver, val) = rest.split_at(pos);
    let val = &val[1..];
    !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit())
        && val.len() == 43
        && val.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn extract_pem_b64(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    b64_decode(&body).ok()
}

/// Verify a signed PEP/1 event (JSON text) against registry JSON text.
pub fn verify_signed_event(
    event_json: &str,
    registry_json: &str,
    now_ms: i64,
) -> Result<Report, String> {
    let ev: serde_json::Value =
        serde_json::from_str(event_json).map_err(|e| format!("SCHEMA: {}", e))?;
    let reg: serde_json::Value =
        serde_json::from_str(registry_json).map_err(|e| format!("registry parse: {}", e))?;

    let mut steps: Vec<(String, bool, bool, String)> = Vec::new();
    fn fail(steps: Vec<(String, bool, bool, String)>, code: &str) -> Result<Report, String> {
        Ok(Report { ok: false, error_code: Some(code.to_string()), steps })
    }

    // G1 SCHEMA -- closed key set + grammars
    const KEYS: [&str; 11] = [
        "v", "app_id", "key_id", "action_class", "action_id", "weight",
        "timestamp", "nonce", "pioneer_uid_hash", "eligibility", "signature",
    ];
    let obj = ev
        .as_object()
        .ok_or_else(|| "SCHEMA: not an object".to_string())?;
    for k in obj.keys() {
        if !KEYS.contains(&k.as_str()) {
            steps.push(("SCHEMA".into(), false, false, format!("unknown field {}", k)));
            return fail(steps, "SCHEMA");
        }
    }
    let get_s = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    macro_rules! need_s {
        ($k:expr) => {
            match get_s($k) {
                Some(v) => v,
                None => {
                    steps.push(("SCHEMA".into(), false, false, $k.to_string()));
                    return fail(steps, "SCHEMA");
                }
            }
        };
    }
    if obj.get("v").and_then(|v| v.as_i64()) != Some(1) {
        steps.push(("SCHEMA".into(), false, false, "unsupported version".into()));
        return fail(steps, "SCHEMA");
    }
    let app_id = need_s!("app_id");
    let key_id = need_s!("key_id");
    let action_class = need_s!("action_class");
    let action_id = need_s!("action_id");
    let nonce = need_s!("nonce");
    let uid_hash = need_s!("pioneer_uid_hash");
    if !(ident_ok(&app_id) && ident_ok(&key_id) && ident_ok(&action_id)) {
        steps.push(("SCHEMA".into(), false, false, "identifier grammar".into()));
        return fail(steps, "SCHEMA");
    }
    if !matches!(action_class.as_str(), "A" | "B" | "C") {
        steps.push(("SCHEMA".into(), false, false, "action_class".into()));
        return fail(steps, "SCHEMA");
    }
    if !nonce_ok(&nonce) {
        steps.push(("SCHEMA".into(), false, false, "nonce grammar".into()));
        return fail(steps, "SCHEMA");
    }
    if !uid_hash_ok(&uid_hash) {
        steps.push(("SCHEMA".into(), false, false, "uid hash grammar".into()));
        return fail(steps, "SCHEMA");
    }
    let weight = match obj.get("weight").and_then(|w| w.as_i64()) {
        Some(w) if w >= 1 => w,
        _ => {
            steps.push(("SCHEMA".into(), false, false, "weight".into()));
            return fail(steps, "SCHEMA");
        }
    };
    let timestamp = match obj.get("timestamp").and_then(|t| t.as_i64()) {
        Some(t) => t,
        None => {
            steps.push(("SCHEMA".into(), false, false, "timestamp".into()));
            return fail(steps, "SCHEMA");
        }
    };
    let elig = obj.get("eligibility").cloned().unwrap_or(serde_json::Value::Null);
    let sig_b64 = need_s!("signature");

    steps.push(("SCHEMA".into(), true, false, "closed schema ok".into()));

    // G2/G3 app+key
    let esc = |s: &str| s.replace('~', "~0").replace('/', "~1");
    let app_ptr = format!("/apps/{}", esc(&app_id));
    let key_ptr = format!("{}/keys/{}", app_ptr, esc(&key_id));
    if reg.pointer(&app_ptr).is_none() {
        steps.push(("APP_KNOWN".into(), false, false, app_id.clone()));
        return fail(steps, "UNKNOWN_APP");
    }
    steps.push(("APP_KNOWN".into(), true, false, app_id.clone()));
    let key_entry = match reg.pointer(&key_ptr) {
        Some(k) => k,
        None => {
            steps.push(("KEY_ACTIVE".into(), false, false, key_id.clone()));
            return fail(steps, "UNKNOWN_KEY");
        }
    };
    if key_entry.get("status").and_then(|s| s.as_str()) != Some("active") {
        steps.push(("KEY_ACTIVE".into(), false, false, "revoked".into()));
        return fail(steps, "REVOKED_KEY");
    }
    let pem = key_entry
        .get("public_key_pem")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "registry: missing pem".to_string())?;
    steps.push(("KEY_ACTIVE".into(), true, false, key_id.clone()));

    // G4 CANONICALIZATION -- body must re-canonicalize cleanly; the canonical
    // bytes are exactly what G5 signs, so a rejection here is load-bearing.
    let mut body = obj.clone();
    body.remove("signature");
    let body_text = serde_json::to_string(&body).unwrap();
    let canon = canonicalize(&body_text)?;
    steps.push(("CANONICALIZATION".into(), true, false, String::new()));

    // G5 SIGNATURE over DOMAIN \n canonical(body)
    let der = extract_pem_b64(pem).ok_or_else(|| "registry: bad pem".to_string())?;
    if der.len() != 44 {
        return Err(format!("unexpected SPKI length {}", der.len()));
    }
    let key32: [u8; 32] = der[12..44].try_into().map_err(|_| "key slice".to_string())?;
    let vk = VerifyingKey::from_bytes(&key32).map_err(|e| format!("bad key: {}", e))?;
    let sig_bytes = b64_decode(&sig_b64).map_err(|_| "INVALID_SIGNATURE".to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "INVALID_SIGNATURE".to_string())?;
    let msg = format!("{}\n{}", DOMAIN, canon);
    if vk.verify(msg.as_bytes(), &sig).is_err() {
        steps.push(("SIGNATURE".into(), false, false, String::new()));
        return fail(steps, "INVALID_SIGNATURE");
    }
    steps.push(("SIGNATURE".into(), true, false, String::new()));

    // G6 TIMESTAMP_FRESHNESS
    if timestamp < now_ms - TIMESTAMP_WINDOW_MS {
        steps.push(("TIMESTAMP_FRESHNESS".into(), false, false, "expired".into()));
        return fail(steps, "TIMESTAMP_EXPIRED");
    }
    if timestamp > now_ms + TIMESTAMP_WINDOW_MS {
        steps.push(("TIMESTAMP_FRESHNESS".into(), false, false, "future".into()));
        return fail(steps, "TIMESTAMP_IN_FUTURE");
    }
    steps.push(("TIMESTAMP_FRESHNESS".into(), true, false, String::new()));

    // G7 WEIGHT_BOUND
    let ceiling = match action_class.as_str() {
        "A" => 100,
        "B" => 10,
        _ => 1,
    };
    if weight > ceiling {
        steps.push(("WEIGHT_BOUND".into(), false, false, weight.to_string()));
        return fail(steps, "WEIGHT_OVERFLOW");
    }
    steps.push(("WEIGHT_BOUND".into(), true, false, String::new()));

    // G8 ELIGIBILITY
    let entry = reg.pointer(&format!("/eligible_users/{}", uid_hash.replace('~', "~0").replace('/', "~1")));
    let ok = match entry {
        Some(e) => e == &elig,
        None => false,
    };
    if !ok {
        steps.push(("ELIGIBILITY".into(), false, false, uid_hash.clone()));
        return fail(steps, "INELIGIBLE_USER");
    }
    steps.push(("ELIGIBILITY".into(), true, false, uid_hash.clone()));

    // G9 NONCE_REPLAY -- stateless honesty
    steps.push((
        "NONCE_REPLAY".into(),
        false,
        true,
        "UNVERIFIABLE -- stateless verifier cannot know replay history".into(),
    ));

    Ok(Report { ok: true, error_code: None, steps })
}
