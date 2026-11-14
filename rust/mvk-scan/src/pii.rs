//! Native port of `maverick.safety.pii_detector.scan`.
//!
//! Port of the six anchored patterns (email, ssn, ipv4,
//! ipv6, phone_us, street_address) emitted in that order, then Luhn-validated
//! credit cards, then the SAME overlap-coalescing (stable sort by
//! `(start, -len)`, merge clusters keeping the first kind). The phone and SSN
//! patterns check lookaround boundaries outside their linear regex candidates.
//! We return `(kind, cp_start, cp_end)` for direct native callers. Python
//! detection and redaction remain pure Python; parity tests compare the spans.
//! Regex Unicode classes are not identical to Python's; the workspace README
//! records the known compatibility limits.

use crate::{byte_spans_to_char, compile_pattern, filtered_matches};
use fancy_regex::Regex;
use std::sync::LazyLock;

// (kind, pattern). Order is load-bearing for the stable-sort tie-break in
// `coalesce`, so it mirrors the tuple order in pii_detector.scan exactly.
static DEFS: &[(&str, &str)] = &[
    (
        "email",
        r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    (
        "ipv4",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    ),
    (
        "ipv6",
        // Compressed + full forms, alternatives ordered by DESCENDING trailing
        // hextet count so leftmost-first picks the longest — identical to the
        // Python ordering and its comments.
        r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:(?::[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::)",
    ),
    // The scan loop checks the leading digit boundary outside this pattern.
    (
        "phone_us",
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    ),
    (
        "street_address",
        r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Parkway|Pkwy|Place|Pl)\b",
    ),
];

// Credit-card candidate: a maximal run of >=13 digits with optional single
// space/dash separators, anchored on DIGIT boundaries (not \b). Luhn-checked
// per cc_run_has_card. Mirrors pii_detector._CC -- the old `\b...{13,19}\b`
// matched NOTHING for runs of >=20 digits, leaking concatenated cards.
static CC: &str = r"\d(?:[ -]*\d){12,}";

struct Compiled {
    kind: &'static str,
    re: Regex,
}

static PATTERNS: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    DEFS.iter()
        .map(|(kind, pat)| Compiled {
            kind,
            re: compile_pattern(pat).expect("pii pattern must compile"),
        })
        .collect()
});

static CC_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(CC).expect("cc pattern must compile"));

/// Luhn over a slice of decimal-digit VALUES (0-9). False unless length 13-19.
/// Mirrors `pii_detector._luhn_valid`.
fn luhn_over(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let parity = digits.len() % 2;
    let mut total = 0u32;
    for (i, &d) in digits.iter().enumerate() {
        let mut d = d as u32;
        if i % 2 == parity {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        total += d;
    }
    total.is_multiple_of(10) // Python: total % 10 == 0
}

fn luhn_contribution(digit: u8) -> u32 {
    let doubled = (digit as u32) * 2;
    if doubled > 9 {
        doubled - 9
    } else {
        doubled
    }
}

/// Mirror of `pii_detector._cc_run_has_card`: a normal-length run (<=19 digits)
/// is Luhn-checked whole; a longer run (>=20, the concatenation bypass) is
/// scanned with rolling Luhn sums for every 13-19 digit window. `Err` on a
/// non-ASCII Unicode digit so the caller falls back to pure Python (Rust can't
/// fold those like `int()`).
fn cc_run_has_card(run: &str) -> Result<bool, String> {
    let mut digits: Vec<u8> = Vec::with_capacity(run.len());
    for c in run.chars() {
        if c.is_ascii_digit() {
            digits.push((c as u8) - b'0');
        } else if c == ' ' || c == '-' {
            continue;
        } else {
            return Err("non-ascii digit in credit-card candidate".to_string());
        }
    }
    let n = digits.len();
    if n <= 19 {
        return Ok(luhn_over(&digits));
    }

    let doubled: Vec<u32> = digits.iter().map(|&d| luhn_contribution(d)).collect();
    for length in 13..=19usize {
        let mut raw_sums = [0u32, 0u32];
        let mut doubled_sums = [0u32, 0u32];
        for (idx, &digit) in digits.iter().take(length).enumerate() {
            let parity = idx % 2;
            raw_sums[parity] += digit as u32;
            doubled_sums[parity] += doubled[idx];
        }

        for start in 0..=(n - length) {
            let doubled_parity = (start + (length % 2)) % 2;
            let total = doubled_sums[doubled_parity] + raw_sums[1 - doubled_parity];
            if total.is_multiple_of(10) {
                return Ok(true);
            }

            if start == n - length {
                break;
            }
            let out_parity = start % 2;
            raw_sums[out_parity] -= digits[start] as u32;
            doubled_sums[out_parity] -= doubled[start];
            let in_idx = start + length;
            let in_parity = in_idx % 2;
            raw_sums[in_parity] += digits[in_idx] as u32;
            doubled_sums[in_parity] += doubled[in_idx];
        }
    }
    Ok(false)
}

/// Mirror of `pii_detector.scan`, returning coalesced `(kind, cp_start, cp_end)`
/// triples. `Err` on engine failure or Luhn ambiguity; bindings must handle
/// the error instead of treating it as a successful scan.
pub fn scan_spans(text: &str) -> Result<Vec<(String, usize, usize)>, String> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    // Raw byte-offset matches in Python's insertion order.
    let mut raw: Vec<(&'static str, usize, usize)> = Vec::new();
    for pat in PATTERNS.iter() {
        if matches!(pat.kind, "ssn" | "phone_us") {
            // Phone candidates have bounded length and may overlap after a
            // rejected leading digit; retry from the next character.
            for m in filtered_matches(&pat.re, text, true, |source, start, end| {
                if pat.kind == "ssn" {
                    let mut groups = source[start..end].split('-');
                    let area = groups.next().unwrap_or("");
                    let group = groups.next().unwrap_or("");
                    let serial = groups.next().unwrap_or("");
                    Ok(area != "000"
                        && area != "666"
                        && !area.starts_with('9')
                        && group != "00"
                        && serial != "0000")
                } else if let Some(ch) = source[..start].chars().next_back() {
                    static DIGIT: LazyLock<Regex> = LazyLock::new(|| {
                        compile_pattern(r"^\d$").expect("digit pattern must compile")
                    });
                    let mut encoded = [0; 4];
                    DIGIT
                        .is_match(ch.encode_utf8(&mut encoded))
                        .map(|is_digit| !is_digit)
                        .map_err(|e| e.to_string())
                } else {
                    Ok(true)
                }
            })? {
                raw.push((pat.kind, m.start(), m.end()));
            }
            continue;
        }
        for m in pat.re.find_iter(text) {
            let m = m.map_err(|e| e.to_string())?;
            raw.push((pat.kind, m.start(), m.end()));
        }
    }
    for m in CC_RE.find_iter(text) {
        let m = m.map_err(|e| e.to_string())?;
        if cc_run_has_card(m.as_str())? {
            raw.push(("credit_card", m.start(), m.end()));
        }
    }
    // Convert to codepoint spans BEFORE coalescing so the sort/merge runs in the
    // exact units Python uses (byte vs codepoint length can reorder equal-start
    // overlaps on non-ASCII input).
    let char_spans = byte_spans_to_char(text, raw);
    Ok(coalesce(char_spans))
}

/// Port of the coalescing tail of `pii_detector.scan`: stable sort by
/// `(start, -len)`, then merge each overlap cluster into one span keeping the
/// FIRST (sort-order) kind. `char_spans` is already in Python insertion order so
/// the stable sort breaks `(start, -len)` ties identically.
fn coalesce(mut char_spans: Vec<(String, usize, usize)>) -> Vec<(String, usize, usize)> {
    char_spans.sort_by(|a, b| {
        let la = a.2 - a.1;
        let lb = b.2 - b.1;
        a.1.cmp(&b.1).then(lb.cmp(&la)) // start asc, then length desc
    });
    let mut out: Vec<(String, usize, usize)> = Vec::new();
    for m in char_spans {
        match out.last_mut() {
            Some(prev) if m.1 < prev.2 => {
                // Overlaps the current cluster: extend its end if needed, keep kind.
                let merged_end = prev.2.max(m.2);
                if merged_end != prev.2 {
                    prev.2 = merged_end;
                }
            }
            _ => out.push(m),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<String> {
        scan_spans(text).unwrap().into_iter().map(|m| m.0).collect()
    }

    #[test]
    fn detects_email_and_ssn_and_ipv6() {
        assert_eq!(kinds("a@b.com"), vec!["email"]);
        assert_eq!(kinds("123-45-6789"), vec!["ssn"]);
        assert_eq!(kinds("addr 2001:db8::1 here"), vec!["ipv6"]);
    }

    #[test]
    fn ssn_rejects_invalid_area() {
        assert!(kinds("000-12-3456").is_empty());
        assert!(kinds("666-12-3456").is_empty());
    }

    #[test]
    fn phone_not_a_subrun_of_longer_number() {
        // (?<!\d) means a 13-digit run is not redacted as a phone.
        assert!(!kinds("1234567890123").contains(&"phone_us".to_string()));
    }

    #[test]
    fn long_input_preserves_trailing_ssn() {
        let text = format!("{} 123-45-6789", "ordinary ".repeat(140_000));
        assert!(kinds(&text).contains(&"ssn".to_string()));
    }

    #[test]
    fn phone_boundary_uses_unicode_decimal_digits() {
        assert!(!kinds("١5551234567").contains(&"phone_us".to_string()));
        assert!(kinds("²5551234567").contains(&"phone_us".to_string()));
        // Python retries inside the parentheses after rejecting the first
        // candidate; the first 5 is preceded by '(', not a digit.
        assert_eq!(
            scan_spans("١(555) 123-4567").unwrap(),
            vec![("phone_us".to_string(), 2, 15)]
        );
    }

    #[test]
    fn card_run_rejects_non_ascii_digits() {
        assert!(scan_spans("٤١١١١١١١١١١١١١١١").is_err());
    }

    #[test]
    fn credit_card_luhn() {
        assert_eq!(kinds("4111 1111 1111 1111"), vec!["credit_card"]);
        assert!(kinds("4111 1111 1111 1112").is_empty());
    }
}
