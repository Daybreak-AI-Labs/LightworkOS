use ed25519_dalek::{Signer, SigningKey};
use maverick_verify_audit::{canonical, verify_chain_text, KeySource};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn reserved_number_objects_cannot_reuse_a_numeric_signature() {
    let private = SigningKey::from_bytes(&[13u8; 32]);
    let public = private.verifying_key();
    let keys = KeySource::Pinned(hex::encode(public.as_bytes()));
    let mut row = json!({
        "amount": 1,
        "nested": [{"value": 1}],
        "note": "$serde_json::private::Number",
        "event": "transfer",
        "key_id": hex::encode(Sha256::digest(public.as_bytes()))[..16],
        "prev_hash": ""
    });
    let digest = Sha256::digest(canonical::dumps_sorted(&row).as_bytes());
    row["hash"] = json!(hex::encode(digest));
    row["sig"] = json!(hex::encode(private.sign(&digest).to_bytes()));
    let original = row.to_string();
    assert!(verify_chain_text(&original, &keys).is_empty());
    for key in [
        r#""$serde_json::private::Number""#,
        r#""\u0024serde_json::private::Number""#,
        r#""$serde_json::private::\u004eumber""#,
    ] {
        for field in ["amount", "value"] {
            let forged = original.replace(
                &format!("\"{field}\":1"),
                &format!("\"{field}\":{{{key}:\"1\"}}"),
            );
            assert_ne!(forged, original);
            let breaks = verify_chain_text(&forged, &keys);
            assert!(
                !breaks.is_empty(),
                "a changed object reused a number's signature"
            );
        }
    }
}
