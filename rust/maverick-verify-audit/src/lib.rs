//! Independent verifier for Lightwork's Ed25519 hash-chained NDJSON audit log.
//!
//! This is a byte-exact port of `maverick.audit.signing.verify_chain` (the
//! Python source of truth). For every non-blank line of a day-file it confirms:
//!   1. the row parses as JSON (else `malformed`),
//!   2. `prev_hash` equals the previous row's `hash` (else `chain_mismatch`;
//!      genesis `prev_hash` is the empty string),
//!   3. `sha256(canonical_json(row_without_hash_and_sig))` equals `hash`
//!      (else `bad_hash`),
//!   4. `sig` is a valid Ed25519 signature, by the pubkey for `key_id`, over the
//!      32 RAW bytes of `hash` (NB: the hash *bytes*, not its hex text) — else
//!      `bad_signature`; an unknown key is `no_pubkey`.
//!
//! Reason vocabulary mirrored from Python: `malformed`, `unsigned`,
//! `chain_mismatch`, `bad_hash`, `bad_signature`, `no_pubkey`, plus the
//! file/setup-level `missing_file`, `no_crypto` (n/a here — crypto is always
//! linked), `unreadable_segment`.
//!
//! Pubkey lookup matches the Python layout: `<keys_dir>/<key_id>.pub` holding the
//! 32 raw public-key bytes, where `key_id` is `sha256(pub_bytes).hexdigest()[:16]`.
//! A `--pubkey <hex>` override pins a single externally-held key for true
//! third-party tamper-evidence (the Python `pubkey_hex` arg).

pub mod canonical;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One detected break in the chain. `line_no` is 1-indexed (0 for file/setup
/// level issues), matching Python's `ChainBreak`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    pub line_no: usize,
    pub reason: String,
    pub detail: String,
}

impl ChainBreak {
    fn new(line_no: usize, reason: &str, detail: impl Into<String>) -> Self {
        ChainBreak {
            line_no,
            reason: reason.to_string(),
            detail: detail.into(),
        }
    }
}

/// Where to find `<key_id>.pub` files, or a single pinned pubkey.
pub enum KeySource {
    /// Trust exactly this raw Ed25519 public key (hex), regardless of key_id.
    /// Mirrors Python `verify_chain(pubkey_hex=...)`.
    Pinned(String),
    /// Look each row's `key_id` up as `<dir>/<key_id>.pub`.
    KeysDir(PathBuf),
}

/// A 16-char lowercase-hex key id, the only shape the writer mints
/// (`sha256(pub)[:16]`). Enforced so a crafted `key_id` cannot escape the keys
/// dir via path traversal — the same guard as Python's `_KEY_ID_RE`.
fn is_valid_key_id(key_id: &str) -> bool {
    key_id.len() == 16
        && key_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn load_verifying_key(bytes: &[u8]) -> Option<VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Verify the chain in `text` (already-decoded NDJSON). Returns the breaks in
/// the order found; an empty vec means the chain is intact.
///
/// This is the parity surface: feed it the same bytes Python's `verify_chain`
/// reads and it returns the same verdict.
pub fn verify_chain_text(text: &str, keys: &KeySource) -> Vec<ChainBreak> {
    let mut breaks: Vec<ChainBreak> = Vec::new();
    let mut prev = String::new();
    let mut pubkey_cache: HashMap<String, Option<VerifyingKey>> = HashMap::new();

    // Resolve the pinned key once (its hex may itself be malformed).
    let pinned: Option<Option<VerifyingKey>> = match keys {
        KeySource::Pinned(hex) => Some(
            hex::decode(hex.trim())
                .ok()
                .and_then(|b| load_verifying_key(&b)),
        ),
        KeySource::KeysDir(_) => None,
    };

    for (idx, line) in text.lines().enumerate() {
        let n = idx + 1;
        if line.trim().is_empty() {
            continue;
        }
        // arbitrary_precision keeps number literals verbatim for the rehash.
        let data: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                breaks.push(ChainBreak::new(n, "malformed", e.to_string()));
                continue;
            }
        };
        let obj = match data.as_object() {
            Some(o) => o,
            None => {
                // A bare scalar/array line: Python's json.loads succeeds but
                // .get() on a non-dict would raise; treat as malformed.
                breaks.push(ChainBreak::new(n, "malformed", "row is not a JSON object"));
                continue;
            }
        };

        let row_hash = obj.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let sig = obj.get("sig").and_then(|v| v.as_str()).unwrap_or("");
        let row_prev = obj.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("");
        let key_id = obj.get("key_id").and_then(|v| v.as_str()).unwrap_or("");

        // Distinguish "honestly unsigned deployment" from tampering, exactly as
        // Python does: NONE of hash/sig/key_id present.
        let has_hash = obj.contains_key("hash");
        let has_sig = obj.contains_key("sig");
        let has_key_id = obj.contains_key("key_id");
        if !has_hash && !has_sig && !has_key_id {
            // Python keys this off truthiness of row_hash/sig/key_id; for the
            // all-absent case `contains_key` and truthiness agree.
            if matches!(keys, KeySource::Pinned(_)) || !row_prev.is_empty() {
                breaks.push(ChainBreak::new(
                    n,
                    "malformed",
                    "missing hash/sig/key_id (possible stripped signature fields)",
                ));
            } else {
                breaks.push(ChainBreak::new(
                    n,
                    "unsigned",
                    "row has no hash/sig/key_id (audit signing disabled)",
                ));
            }
            continue;
        }

        // Some-but-not-all signing fields present (or present-but-empty): the
        // vocabulary of real tampering. Python tests truthiness here, so an
        // empty-string hash/sig/key_id counts as missing.
        if row_hash.is_empty() || sig.is_empty() || key_id.is_empty() {
            breaks.push(ChainBreak::new(n, "malformed", "missing hash/sig/key_id"));
            continue;
        }

        if row_prev != prev {
            let exp = if prev.is_empty() {
                "(empty)".to_string()
            } else {
                truncate12(&prev)
            };
            breaks.push(ChainBreak::new(
                n,
                "chain_mismatch",
                format!("row prev={}... expected {}", truncate12(row_prev), exp),
            ));
        }

        // Recompute the hash over every field except hash/sig, canonically.
        let mut payload = obj.clone();
        payload.remove("hash");
        payload.remove("sig");
        let canon = canonical::dumps_sorted(&serde_json::Value::Object(payload));
        let expected_hash = hex::encode(Sha256::digest(canon.as_bytes()));
        if expected_hash != row_hash {
            breaks.push(ChainBreak::new(n, "bad_hash", "content rehash != row hash"));
        }

        // Locate the verifying key.
        let pub_opt: Option<VerifyingKey> = match &pinned {
            Some(p) => *p,
            None => {
                if let Some(cached) = pubkey_cache.get(key_id) {
                    *cached
                } else {
                    let loaded = match keys {
                        KeySource::KeysDir(dir) => load_key_from_dir(dir, key_id),
                        KeySource::Pinned(_) => unreachable!(),
                    };
                    pubkey_cache.insert(key_id.to_string(), loaded);
                    loaded
                }
            }
        };

        match pub_opt {
            None => {
                breaks.push(ChainBreak::new(
                    n,
                    "no_pubkey",
                    format!("key_id {:?}", key_id),
                ));
            }
            Some(vk) => {
                // Ed25519 signs the RAW 32 hash bytes (bytes.fromhex(row_hash)),
                // not the hex string. A non-hex / wrong-length sig or hash is a
                // break, never a panic — same as Python catching ValueError.
                match (hex::decode(sig), hex::decode(row_hash)) {
                    (Ok(sig_bytes), Ok(msg_bytes)) => match sig_bytes.as_slice().try_into() {
                        Ok(sig_arr) => {
                            let signature = Signature::from_bytes(sig_arr);
                            if vk.verify_strict(&msg_bytes, &signature).is_err() {
                                breaks.push(ChainBreak::new(
                                    n,
                                    "bad_signature",
                                    "Ed25519 verify failed",
                                ));
                            }
                        }
                        Err(_) => {
                            breaks.push(ChainBreak::new(
                                n,
                                "bad_signature",
                                "malformed sig/hash: bad signature length",
                            ));
                        }
                    },
                    _ => {
                        breaks.push(ChainBreak::new(
                            n,
                            "bad_signature",
                            "malformed sig/hash: non-hex sig or hash",
                        ));
                    }
                }
            }
        }

        prev = row_hash.to_string();
    }

    breaks
}

fn load_key_from_dir(dir: &Path, key_id: &str) -> Option<VerifyingKey> {
    if !is_valid_key_id(key_id) {
        return None;
    }
    let pub_path = dir.join(format!("{key_id}.pub"));
    if !pub_path.exists() {
        return None;
    }
    // Mirror Python's _load_pubkey: trust a local <id>.pub ONLY when its private
    // <id>.key sibling exists (this host generated the keypair) OR an
    // <id>.injected marker exists (provisioned out-of-band from a KMS, private
    // half deliberately absent). Without this, an attacker who can drop a lone
    // forged <id>.pub into the keys dir could re-sign tampered rows and have
    // them verify -- the exact forged-pubkey vector the Python source rejects.
    // (--pubkey/Pinned mode is the path for true third-party tamper-evidence.)
    let priv_path = dir.join(format!("{key_id}.key"));
    let injected_path = dir.join(format!("{key_id}.injected"));
    if !priv_path.exists() && !injected_path.exists() {
        return None;
    }
    let bytes = std::fs::read(pub_path).ok()?;
    load_verifying_key(&bytes)
}

fn truncate12(s: &str) -> String {
    s.chars().take(12).collect()
}

/// Read a (possibly path-given) audit day-file and verify its chain.
///
/// Unlike Python this does NOT transparently decrypt at-rest *sealed* segments
/// (that needs the tenant key, which an external auditor won't hold); a sealed
/// file is reported as `unreadable_segment` with a clear hint, so the verdict is
/// never a false "intact". Plaintext NDJSON — the format an auditor is handed —
/// verifies fully.
pub fn verify_file(path: &Path, keys: &KeySource) -> Vec<ChainBreak> {
    if !path.exists() {
        return vec![ChainBreak::new(
            0,
            "missing_file",
            path.display().to_string(),
        )];
    }
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return vec![ChainBreak::new(
                0,
                "unreadable_segment",
                format!("cannot read {}: {e}", path.display()),
            )]
        }
    };
    if is_sealed(&raw) {
        return vec![ChainBreak::new(
            0,
            "unreadable_segment",
            format!(
                "{} is an at-rest-sealed segment; decrypt it with `maverick audit verify` \
                 on the originating host (the seal key is not portable)",
                path.display()
            ),
        )];
    }
    let text = match String::from_utf8(raw) {
        Ok(t) => t,
        Err(e) => {
            return vec![ChainBreak::new(
                0,
                "unreadable_segment",
                format!("{} is not valid UTF-8: {e}", path.display()),
            )]
        }
    };
    verify_chain_text(&text, keys)
}

/// Detect the at-rest seal magic headers (mirrors `crypto_at_rest.is_sealed`),
/// so a sealed file fails closed instead of being mistaken for plaintext.
fn is_sealed(blob: &[u8]) -> bool {
    blob.starts_with(b"MVKAR1\n") || blob.starts_with(b"MVKAR2\n") || blob.starts_with(b"MVKTEN1\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key_id_guard() {
        assert!(is_valid_key_id("0123456789abcdef"));
        assert!(!is_valid_key_id("0123456789ABCDEF")); // uppercase rejected
        assert!(!is_valid_key_id("short"));
        assert!(!is_valid_key_id("../../etc/passwd0")); // 16 chars but non-hex
        assert!(!is_valid_key_id("0123456789abcde")); // 15 chars
    }

    #[test]
    fn unsigned_log_reports_unsigned() {
        let text = "{\"event\": \"x\"}\n{\"event\": \"y\"}\n";
        let breaks = verify_chain_text(text, &KeySource::KeysDir(PathBuf::from("/nonexistent")));
        assert_eq!(breaks.len(), 2);
        assert!(breaks.iter().all(|b| b.reason == "unsigned"));
    }

    #[test]
    fn pinned_unsigned_is_malformed_not_unsigned() {
        // With a trusted pubkey the caller expected signed rows: absence is
        // "stripped", i.e. malformed (matches Python).
        let text = "{\"event\": \"x\"}\n";
        let breaks = verify_chain_text(text, &KeySource::Pinned("00".repeat(32)));
        assert_eq!(breaks.len(), 1);
        assert_eq!(breaks[0].reason, "malformed");
    }

    #[test]
    fn malformed_json_line() {
        let text = "{not json}\n";
        let breaks = verify_chain_text(text, &KeySource::KeysDir(PathBuf::from("/x")));
        assert_eq!(breaks.len(), 1);
        assert_eq!(breaks[0].reason, "malformed");
    }

    #[test]
    fn lone_pubkey_is_not_trusted() {
        // A forged <id>.pub with no sibling .key and no .injected marker must
        // NOT be trusted (mirrors Python _load_pubkey's anti-forgery check).
        let dir = tempfile::tempdir().unwrap();
        let key_id = "0123456789abcdef";
        std::fs::write(dir.path().join(format!("{key_id}.pub")), [0u8; 32]).unwrap();
        assert!(load_key_from_dir(dir.path(), key_id).is_none());

        // With a sibling .key present, the .pub becomes trustworthy (a valid
        // 32-byte Ed25519 point loads; the all-zero point is itself valid).
        std::fs::write(dir.path().join(format!("{key_id}.key")), [0u8; 32]).unwrap();
        assert!(load_key_from_dir(dir.path(), key_id).is_some());
    }

    #[test]
    fn injected_marker_makes_pubkey_trusted() {
        // An out-of-band (KMS-provisioned) key has only <id>.pub + <id>.injected
        // (no private half on disk); that combination must be trusted.
        let dir = tempfile::tempdir().unwrap();
        let key_id = "fedcba9876543210";
        std::fs::write(dir.path().join(format!("{key_id}.pub")), [0u8; 32]).unwrap();
        assert!(load_key_from_dir(dir.path(), key_id).is_none());
        std::fs::write(dir.path().join(format!("{key_id}.injected")), b"").unwrap();
        assert!(load_key_from_dir(dir.path(), key_id).is_some());
    }
}
