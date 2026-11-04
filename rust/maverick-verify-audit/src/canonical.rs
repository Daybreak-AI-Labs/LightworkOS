//! Byte-exact reproduction of CPython `json.dumps(obj, sort_keys=True)`.
//!
//! The audit chain's hash is `sha256(json.dumps(payload, sort_keys=True,
//! default=str).encode("utf-8"))` over every row field EXCEPT `hash`/`sig`
//! (see `maverick.audit.signing`). To recompute that hash in Rust we must
//! serialize the parsed row to the *exact same bytes* CPython would. `serde_json`'s
//! own serializer differs (no space after `:`/`,`, `ensure_ascii=false`, ryu
//! float formatting), so we re-implement the relevant slice of CPython's encoder:
//!
//!   * separators `", "` and `": "` (the json.dumps default),
//!   * `ensure_ascii=True`: every non-ASCII scalar and every control char
//!     (`< 0x20`) **plus `0x7f`** is `\uXXXX` (lowercase hex); astral scalars
//!     become a UTF-16 surrogate pair (two `\uXXXX`); the C0 short escapes
//!     `\b \t \n \f \r \" \\` win where they apply; forward slash is NOT escaped,
//!   * object keys sorted by Unicode code point (== Rust `str` Ord, which orders
//!     by Unicode scalar value),
//!   * numbers emitted **verbatim from the source token** (via serde_json's
//!     `arbitrary_precision`), so Python's int/float `repr` (`1e+30`, `1.0`,
//!     `-0.0`, big ints) round-trips without us re-formatting it.
//!
//! `default=str` only matters on the *write* path (it stringifies datetimes etc.
//! before they ever reach JSON); by the time the verifier reads a row those
//! values are already JSON strings/numbers, so faithfully re-serializing the
//! parsed JSON is sufficient.

use serde_json::Value;

/// Serialize `v` exactly as `json.dumps(v, sort_keys=True)` would (UTF-8 bytes).
pub fn dumps_sorted(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // arbitrary_precision: Number's Display is the original literal token,
        // i.e. precisely the characters CPython's json.dump emitted for it.
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // json.dumps(sort_keys=True) orders keys by Python string comparison,
            // which compares by Unicode code point — identical to Rust's &str Ord.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_string(out, k);
                out.push_str(": ");
                // Unwrap safe: key came from this very map.
                write_value(out, map.get(*k).unwrap());
            }
            out.push('}');
        }
    }
}

/// Write a JSON string literal exactly as CPython's `ensure_ascii=True` encoder.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            // Printable ASCII (0x20..0x7e) goes through verbatim. Note forward
            // slash is intentionally NOT escaped (CPython leaves it bare), and
            // 0x7f (DEL) IS escaped below despite being "ASCII".
            c if (c as u32) >= 0x20 && (c as u32) <= 0x7e => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    push_u_escape(out, cp as u16);
                } else {
                    // Astral plane: emit a UTF-16 surrogate pair, matching how
                    // CPython (whose str is UCS-4 but whose JSON encoder emits
                    // surrogate pairs under ensure_ascii) renders it.
                    let v = cp - 0x10000;
                    let hi = 0xd800 + ((v >> 10) as u16);
                    let lo = 0xdc00 + ((v & 0x3ff) as u16);
                    push_u_escape(out, hi);
                    push_u_escape(out, lo);
                }
            }
        }
    }
    out.push('"');
}

/// Append `\uXXXX` with lowercase hex (CPython uses lowercase).
fn push_u_escape(out: &mut String, code: u16) {
    out.push_str("\\u");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[((code >> 12) & 0xf) as usize] as char);
    out.push(HEX[((code >> 8) & 0xf) as usize] as char);
    out.push(HEX[((code >> 4) & 0xf) as usize] as char);
    out.push(HEX[(code & 0xf) as usize] as char);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dumps(s: &str) -> String {
        // Parse with arbitrary_precision on so numbers keep their literal token.
        let v: Value = serde_json::from_str(s).unwrap();
        dumps_sorted(&v)
    }

    #[test]
    fn sorted_keys_and_separators() {
        // Matches Python: '{"a": 2, "b": 1, "key_id": "x", "prev_hash": ""}'
        let v = json!({"b": 1, "a": 2, "prev_hash": "", "key_id": "x"});
        assert_eq!(
            dumps_sorted(&v),
            r#"{"a": 2, "b": 1, "key_id": "x", "prev_hash": ""}"#
        );
    }

    #[test]
    fn ensure_ascii_escapes() {
        // ensure_ascii: every non-ASCII scalar escaped \uXXXX (lowercase).
        // Python: '{"u": "caf\\u00e9 \\u00e9 \\u4e2d"}'
        assert_eq!(
            dumps(r#"{"u":"café é 中"}"#),
            "{\"u\": \"caf\\u00e9 \\u00e9 \\u4e2d\"}"
        );
    }

    #[test]
    fn astral_surrogate_pair() {
        // U+1F600 -> UTF-16 surrogate pair. Python: '{"e": "\\ud83d\\ude00"}'
        assert_eq!(
            dumps("{\"e\":\"\u{1F600}\"}"),
            "{\"e\": \"\\ud83d\\ude00\"}"
        );
    }

    #[test]
    fn control_chars_and_del() {
        // 0x01,0x1f ->   ; 0x7f ->  ; slash bare ; short escapes.
        // Python: '{"c": "\\u0001\\u001f\\u007f/", "s": "a\\nb\\tq"}'
        let v = json!({"c": "\u{01}\u{1f}\u{7f}/", "s": "a\nb\tq"});
        assert_eq!(
            dumps_sorted(&v),
            "{\"c\": \"\\u0001\\u001f\\u007f/\", \"s\": \"a\\nb\\tq\"}"
        );
    }

    #[test]
    fn short_escapes() {
        // \b \t \n \f \r \" \\ keep their short forms. Python: "\b\t\n\f\r\"\\".
        let v = json!({"x": "\u{08}\t\n\u{0c}\r\"\\"});
        assert_eq!(dumps_sorted(&v), "{\"x\": \"\\b\\t\\n\\f\\r\\\"\\\\\"}");
    }

    #[test]
    fn numbers_verbatim() {
        // Big int and float exponent must round-trip as the source literal.
        assert_eq!(
            dumps(r#"{"big":100000000000000000000,"f":1.5,"e":1e+30}"#),
            r#"{"big": 100000000000000000000, "e": 1e+30, "f": 1.5}"#
        );
    }

    #[test]
    fn nested_arrays_objects() {
        assert_eq!(
            dumps(r#"{"nested":{"z":[1,2,{"k":"v"}],"a":null,"f":1.5}}"#),
            r#"{"nested": {"a": null, "f": 1.5, "z": [1, 2, {"k": "v"}]}}"#
        );
    }
}
