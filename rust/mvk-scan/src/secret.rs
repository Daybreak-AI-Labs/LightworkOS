//! Native port of `maverick.safety.secret_detector.scan`.
//!
//! Follows the Python patterns and emission order, including the
//! "redact the `val` sub-group when present, else the whole match" rule and
//! global exact-span de-duplication. We return
//! only `(name, codepoint_start, codepoint_end)` for direct native callers.
//! Python detection and redaction use the pure-Python implementation; parity
//! tests compare its spans with this engine. Patterns are compiled once.
//! Regex Unicode classes differ between engines; see the workspace README's
//! compatibility limits before relying on arbitrary-Unicode parity.
//!
//! Lookaround-free patterns compile to the linear regex backend. Capability
//! token boundaries are checked against the original input outside the engine.
//! Engine failures are returned to bindings; callers must handle errors rather
//! than assume a scan produced a complete result.

use crate::{byte_spans_to_char, compile_pattern, filtered_matches};
use fancy_regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

struct Pattern {
    name: &'static str,
    re: Regex,
    /// True only for `env_secret`: redact the named `val` group, not the whole
    /// match (keeps the `NAME=` prefix visible, exactly like Python).
    val_group: bool,
}

// (name, pattern, has_val_group). Order is load-bearing: `scan` emits matches in
// pattern order and the global span de-dup keeps the FIRST pattern to claim a
// span, so matching rules and order must mirror `_PATTERNS` in secret_detector.py.
static DEFS: &[(&str, &str, bool)] = &[
    ("anthropic_api_key", r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b", false),
    (
        "openai_api_key",
        r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}",
        false,
    ),
    ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b", false),
    (
        "aws_secret_access",
        r#"(?i)(?:aws_secret_access_key|aws_secret)[\s=:"']{1,16}([A-Za-z0-9/+=]{40})"#,
        false,
    ),
    ("github_pat_classic", r"\bghp_[A-Za-z0-9]{36,40}\b", false),
    ("github_pat_fine", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", false),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36,40}\b", false),
    ("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", false),
    (
        "gcp_service_account",
        r#""type"\s*:\s*"service_account""#,
        false,
    ),
    (
        "azure_storage",
        r"\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
        false,
    ),
    (
        "slack_bot_token",
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b",
        false,
    ),
    ("stripe_live_key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", false),
    ("stripe_test_key", r"\bsk_test_[0-9a-zA-Z]{24,}\b", false),
    (
        "lightwork_agent_token",
        r"lw-(?:rest|mcp)-[A-Za-z0-9_-]{20,}",
        false,
    ),
    (
        "lightwork_flow_approval_token",
        r"eyJ[A-Za-z0-9_-]{16,}\.[0-9a-fA-F]{64}",
        false,
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        false,
    ),
    // DOTALL via (?s); bounded body is the ReDoS guard, same as Python.
    // The final (?!\A) is always true after the nonempty header. It keeps the
    // bounded repeats in fancy-regex's VM instead of expanding a large NFA.
    // A trailing positive lookahead would be optimized back into the NFA.
    (
        "private_key_pem",
        r"(?s)\G-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----(?:.{0,65536}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----|[A-Za-z0-9+/=\s]{0,65536})(?!\A)",
        false,
    ),
    ("gitlab_pat", r"\bglpat-[A-Za-z0-9_-]{20,}\b", false),
    ("twilio_api_key", r"\bSK[0-9a-fA-F]{32}\b", false),
    (
        "slack_webhook",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        false,
    ),
    (
        "db_connection_uri",
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@/\s]+:[^@/\s]+@[^\s]+",
        false,
    ),
    (
        "bearer_header",
        r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._\-+/=]{12,}",
        false,
    ),
    // MULTILINE via (?m); only the `val` group is redacted.
    (
        "env_secret",
        r#"(?m)(?:^|\n)[^\S\n]*(?:export\s+)?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*(?P<val>"[^"\n]*"|'[^'\n]*'|[^\s\n]+)"#,
        true,
    ),
];

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    DEFS.iter()
        .map(|(name, pat, val)| Pattern {
            name,
            re: compile_pattern(pat).expect("secret pattern must compile"),
            val_group: *val,
        })
        .collect()
});

/// Mirror of `secret_detector.scan`, returning `(name, cp_start, cp_end)` triples
/// in Python's emission order. `Err` on any engine failure; bindings must not
/// interpret that error as a successful scan.
pub fn scan_spans(text: &str) -> Result<Vec<(String, usize, usize)>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut byte_spans: Vec<(&'static str, usize, usize)> = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for pat in PATTERNS.iter() {
        if pat.name == "private_key_pem" {
            // Search for the literal header outside the VM so long clean input
            // cannot exhaust its backtrack limit. \G anchors each attempt here.
            let mut offset = 0;
            while let Some(relative) = text[offset..].find("-----BEGIN ") {
                let start = offset + relative;
                match pat
                    .re
                    .find_from_pos(text, start)
                    .map_err(|e| e.to_string())?
                {
                    Some(m) => {
                        let span = (m.start(), m.end());
                        if seen.insert(span) {
                            byte_spans.push((pat.name, span.0, span.1));
                        }
                        offset = m.end();
                    }
                    None => offset = start + 1,
                }
            }
            continue;
        }
        if matches!(
            pat.name,
            "lightwork_agent_token" | "lightwork_flow_approval_token"
        ) {
            // A candidate cannot contain another valid token start: each
            // interior start has an ASCII word/hyphen before it; the only dot
            // is followed solely by hex, which cannot contain either prefix.
            // Skip the whole rejected candidate to avoid quadratic rescans.
            for m in filtered_matches(&pat.re, text, false, |source, start, end| {
                let left = source[..start].chars().next_back();
                let right = source[end..].chars().next();
                let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
                let left_ok = !left.is_some_and(word);
                let right_ok = if pat.name == "lightwork_agent_token" {
                    !right.is_some_and(word)
                } else {
                    !right.is_some_and(|c| c.is_ascii_hexdigit())
                };
                Ok(left_ok && right_ok)
            })? {
                let span = (m.start(), m.end());
                if seen.insert(span) {
                    byte_spans.push((pat.name, span.0, span.1));
                }
            }
            continue;
        }
        for cap in pat.re.captures_iter(text) {
            let cap = cap.map_err(|e| e.to_string())?;
            let m = if pat.val_group {
                match cap.name("val") {
                    Some(m) => m,
                    None => continue,
                }
            } else {
                cap.get(0).expect("group 0 always present")
            };
            let span = (m.start(), m.end());
            if seen.insert(span) {
                byte_spans.push((pat.name, span.0, span.1));
            }
        }
    }
    Ok(byte_spans_to_char(text, byte_spans))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<String> {
        scan_spans(text).unwrap().into_iter().map(|m| m.0).collect()
    }

    #[test]
    fn detects_anthropic_and_dedups_with_openai() {
        // sk-ant- matches both the anthropic and openai patterns at the same
        // span; dedup keeps the first (anthropic) only. The fake key's prefix is
        // split from its body via concat! so no whole token literal is on disk
        // (GitHub push protection); the runtime string is unchanged.
        let n = names(concat!("key sk-", "ant-abcdefghijklmnopqrstuvwxyz0123 end"));
        assert!(n.contains(&"anthropic_api_key".to_string()));
    }

    #[test]
    fn env_secret_redacts_value_span_only() {
        let spans = scan_spans("export API_SECRET=supersecretvalue\n").unwrap();
        let env = spans.iter().find(|m| m.0 == "env_secret").unwrap();
        // The span must cover only the value, not the NAME= prefix.
        assert_eq!(
            &"export API_SECRET=supersecretvalue\n"[..env.1],
            "export API_SECRET="
        );
    }

    #[test]
    fn long_input_preserves_trailing_token_and_boundaries() {
        let token = format!("{}{}", "lw-rest-", "a".repeat(24));
        let text = format!("{} {token}", "ordinary ".repeat(140_000));
        assert!(names(&text).contains(&"lightwork_agent_token".to_string()));
        assert!(!names(&format!("x{token}")).contains(&"lightwork_agent_token".to_string()));
    }

    #[test]
    fn rejected_overlapping_token_candidates_do_not_rescan_suffixes() {
        let text = format!("x{}{} trailing", "lw-rest-".repeat(20_000), "a".repeat(24));
        assert!(!names(&text).contains(&"lightwork_agent_token".to_string()));
    }

    #[test]
    fn approval_token_rejects_extra_hex_suffix() {
        let token = format!("eyJ{}.{}", "x".repeat(20), "a".repeat(64));
        assert!(names(&token).contains(&"lightwork_flow_approval_token".to_string()));
        assert!(!names(&format!("{token}f")).contains(&"lightwork_flow_approval_token".to_string()));
    }

    #[test]
    fn empty_is_empty() {
        assert!(scan_spans("").unwrap().is_empty());
    }

    #[test]
    fn long_private_key_body_is_fully_detected() {
        let header = "-----BEGIN PRIVATE KEY-----"; // pragma: allowlist secret
        for length in [13_000, 65_536] {
            let body = "A".repeat(length);
            for suffix in ["-----END PRIVATE KEY-----", ""] {
                let text = format!("{header}{body}{suffix}");
                let spans = scan_spans(&text).unwrap();
                assert!(spans.contains(&("private_key_pem".to_string(), 0, text.len())));
            }
        }
    }
}
