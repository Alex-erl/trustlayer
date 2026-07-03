//! Canonical JSON + SHA-256, byte-for-byte compatible with the Elixir
//! `TrustLayer.Crypto` module and the JavaScript `trustlayer-verify` package.
//!
//! * objects — keys sorted lexicographically by their UTF-8 bytes, recursively
//! * arrays  — element order preserved
//! * scalars — standard JSON encoding
//!
//! The byte-wise key ordering matches Erlang/Elixir binary comparison exactly.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize a [`Value`] to canonical JSON.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    encode(value, &mut out);
    out
}

fn encode(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => encode_str(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_str(key, out);
                out.push(':');
                encode(&map[key.as_str()], out);
            }
            out.push('}');
        }
    }
}

/// RFC 8259 string escaping — delegated to serde_json so it matches the other
/// reference implementations (which use their platform JSON encoders).
fn encode_str(s: &str, out: &mut String) {
    let encoded = serde_json::to_string(s).expect("a string is always JSON-serializable");
    out.push_str(&encoded);
}

/// Lowercase hex SHA-256 of the canonical JSON of `value`.
pub fn canonical_hash(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

/// Lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(nibble(byte >> 4));
        hex.push(nibble(byte & 0x0f));
    }
    hex
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}
