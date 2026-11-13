//! Native safety scanners — pure logic shared by the Python (PyO3) and
//! TypeScript (WASM) bindings. No FFI here.
//!
//! This is a faithful port of `maverick.safety.unicode_filter`: strip
//! zero-width, bidi-override (Trojan Source) and Unicode tag-block characters,
//! NFKC-normalizing first so look-alikes canonicalize. The Python module keeps
//! a pure fallback so behaviour is identical whether or not this is compiled in.

use unicode_normalization::UnicodeNormalization;

pub mod phash;
pub mod pii;
pub mod secret;

/// Compile a detector pattern with a generous delegate size limit.
///
/// Lookaround-free patterns delegate to `regex`. The PEM detector keeps its
/// `{0,65536}` repeats in the backtracking VM to avoid a large expanded NFA;
/// the limit here bounds construction of the remaining delegated patterns.
// `fancy_regex::Error` is a large enum, but this is called once per pattern at
// startup behind `.expect`, so the size is irrelevant.
#[allow(clippy::result_large_err)]
pub(crate) fn compile_pattern(pattern: &str) -> Result<fancy_regex::Regex, fancy_regex::Error> {
    fancy_regex::RegexBuilder::new(pattern)
        .delegate_size_limit(64 * (1 << 20))
        .build()
}

/// Search a lookaround-free candidate pattern, checking boundaries against the
/// original input. Where a valid match can overlap a rejected candidate, retry
/// one character after its start. Otherwise skip the rejected candidate to
/// avoid rescanning an unbounded suffix. Accepted matches are non-overlapping.
pub(crate) fn filtered_matches<'t>(
    re: &fancy_regex::Regex,
    text: &'t str,
    retry_overlaps: bool,
    accept: impl Fn(&str, usize, usize) -> Result<bool, String>,
) -> Result<Vec<fancy_regex::Match<'t>>, String> {
    let mut matches = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let Some(m) = re.find_from_pos(text, offset).map_err(|e| e.to_string())? else {
            break;
        };
        if accept(text, m.start(), m.end())? {
            offset = m.end();
            matches.push(m);
        } else if retry_overlaps {
            offset = m.start()
                + text[m.start()..]
                    .chars()
                    .next()
                    .expect("nonempty candidate")
                    .len_utf8();
        } else {
            offset = m.end();
        }
    }
    Ok(matches)
}

/// Convert regex byte offsets to **codepoint** indices, preserving input order.
///
/// Python's `re` reports `Match.span()` as indices into the `str` (a sequence of
/// Unicode codepoints); Rust's regex engines report byte offsets into the UTF-8
/// string. For ASCII they coincide, but any multi-byte char makes them diverge —
/// and the Python redactors splice with codepoint indices, so the native path
/// MUST return codepoint indices or redaction would corrupt non-ASCII text. One
/// pass over `char_indices` maps every needed byte offset (all of which fall on
/// char boundaries, since regex matches respect them) to its codepoint index.
pub(crate) fn byte_spans_to_char(
    text: &str,
    spans: Vec<(&'static str, usize, usize)>,
) -> Vec<(String, usize, usize)> {
    if spans.is_empty() {
        return Vec::new();
    }
    let mut wanted: Vec<usize> = spans.iter().flat_map(|s| [s.1, s.2]).collect();
    wanted.sort_unstable();
    wanted.dedup();
    let mut map: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut char_idx = 0usize;
    let mut wi = 0usize;
    for (byte, _) in text.char_indices() {
        while wi < wanted.len() && wanted[wi] == byte {
            map.insert(byte, char_idx);
            wi += 1;
        }
        char_idx += 1;
    }
    // Any remaining wanted offsets are at end-of-string (== text.len()).
    while wi < wanted.len() {
        map.insert(wanted[wi], char_idx);
        wi += 1;
    }
    spans
        .into_iter()
        .map(|(name, a, b)| (name.to_string(), map[&a], map[&b]))
        .collect()
}

/// Zero-width / invisible code points.
const ZERO_WIDTH: [u32; 5] = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF];

/// Bidirectional override block (the "Trojan Source" attack vector).
const BIDI_OVERRIDES: [u32; 12] = [
    0x200E, 0x200F, 0x061C, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
];

/// Unicode tag block (E0000–E007F): invisible, used for steganographic injection.
const TAG_BLOCK_START: u32 = 0xE0000;
const TAG_BLOCK_END: u32 = 0xE007F;

/// Result of [`normalize`]: cleaned text + the code points that were stripped +
/// the (order-preserving, de-duplicated) categories that actually fired.
pub struct UnicodeScanResult {
    pub cleaned: String,
    pub removed_codepoints: Vec<u32>,
    pub categories: Vec<String>,
}

fn category_for(cp: u32) -> Option<&'static str> {
    if ZERO_WIDTH.contains(&cp) {
        Some("zero_width")
    } else if BIDI_OVERRIDES.contains(&cp) {
        Some("bidi_override")
    } else if (TAG_BLOCK_START..=TAG_BLOCK_END).contains(&cp) {
        Some("tag_block")
    } else {
        None
    }
}

/// Strip dangerous Unicode and (optionally) NFKC-normalize first.
///
/// Mirrors `unicode_filter.normalize`: empty input is returned untouched;
/// otherwise NFKC runs (when `nfkc`), then each char is kept or recorded as
/// removed by category.
pub fn normalize(text: &str, nfkc: bool) -> UnicodeScanResult {
    if text.is_empty() {
        return UnicodeScanResult {
            cleaned: String::new(),
            removed_codepoints: Vec::new(),
            categories: Vec::new(),
        };
    }
    let source: String = if nfkc {
        text.nfkc().collect()
    } else {
        text.to_string()
    };
    let mut cleaned = String::with_capacity(source.len());
    let mut removed: Vec<u32> = Vec::new();
    let mut categories: Vec<String> = Vec::new();
    for ch in source.chars() {
        let cp = ch as u32;
        match category_for(cp) {
            Some(cat) => {
                removed.push(cp);
                if !categories.iter().any(|c| c == cat) {
                    categories.push(cat.to_string());
                }
            }
            None => cleaned.push(ch),
        }
    }
    UnicodeScanResult {
        cleaned,
        removed_codepoints: removed,
        categories,
    }
}

/// Cheap boolean check used by the shield's input scan; allocates nothing.
/// Matches `unicode_filter.has_dangerous_unicode` (no NFKC; raw text).
pub fn has_dangerous_unicode(text: &str) -> bool {
    text.chars().any(|ch| {
        let cp = ch as u32;
        ZERO_WIDTH.contains(&cp)
            || BIDI_OVERRIDES.contains(&cp)
            || (TAG_BLOCK_START..=TAG_BLOCK_END).contains(&cp)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_and_bidi_in_order() {
        let r = normalize("a\u{200b}b\u{202e}c", true);
        assert_eq!(r.cleaned, "abc");
        assert_eq!(r.removed_codepoints, vec![0x200B, 0x202E]);
        assert_eq!(r.categories, vec!["zero_width", "bidi_override"]);
    }

    #[test]
    fn nfkc_canonicalizes_lookalikes() {
        // U+FB01 (fi ligature) -> "fi"; full-width A -> "A".
        let r = normalize("\u{fb01}x\u{ff21}", true);
        assert_eq!(r.cleaned, "fixA");
        assert!(r.removed_codepoints.is_empty());
    }

    #[test]
    fn tag_block_detected_and_stripped() {
        assert!(has_dangerous_unicode("x\u{e0001}y"));
        let r = normalize("x\u{e0001}y", true);
        assert_eq!(r.cleaned, "xy");
        assert_eq!(r.categories, vec!["tag_block"]);
    }

    #[test]
    fn clean_text_is_untouched() {
        assert!(!has_dangerous_unicode("perfectly normal text"));
        let r = normalize("perfectly normal text", true);
        assert_eq!(r.cleaned, "perfectly normal text");
        assert!(!r.had_dangerous_helper());
    }

    impl UnicodeScanResult {
        fn had_dangerous_helper(&self) -> bool {
            !self.removed_codepoints.is_empty()
        }
    }
}
