//! TypeScript / edge (WASM) binding for `mvk-scan`. Build with
//! `wasm-pack build --target web` to get an npm package the plugin-ts SDK (and
//! any edge runtime — Workers, Deno, browser) can import. Same logic as the
//! Python path, from the same core crate.

use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct ScanResult {
    cleaned: String,
    #[serde(rename = "removedCodepoints")]
    removed_codepoints: Vec<u32>,
    categories: Vec<String>,
}

/// `hasDangerousUnicode(text): boolean`
#[wasm_bindgen(js_name = hasDangerousUnicode)]
pub fn has_dangerous_unicode(text: &str) -> bool {
    mvk_scan::has_dangerous_unicode(text)
}

/// `averageHashFromPixels(rgb, width, height): string` — 16 hex chars.
///
/// `rgb` is a flat row-major `[r, g, b, r, g, b, ...]` array (length
/// `width * height * 3`), matching `extensions/webgpu-vision/ahash.js`. Throws
/// on a length/dimension mismatch.
#[wasm_bindgen(js_name = averageHashFromPixels)]
pub fn average_hash_from_pixels(
    rgb: &[i32],
    width: usize,
    height: usize,
) -> Result<String, JsValue> {
    // Compute once with saturating mul and reuse: the guard already uses
    // saturating_mul, but the error path recomputing `width * height * 3` with
    // plain mul could overflow (panic in debug / wrap in release) on the 32-bit
    // wasm target precisely when dimensions are large.
    let expected = width.saturating_mul(height).saturating_mul(3);
    if rgb.len() != expected {
        return Err(JsValue::from_str(&format!(
            "expected {} rgb components, got {}",
            expected,
            rgb.len()
        )));
    }
    let pixels: Vec<(i64, i64, i64)> = rgb
        .chunks_exact(3)
        .map(|c| (c[0] as i64, c[1] as i64, c[2] as i64))
        .collect();
    mvk_scan::phash::average_hash_from_pixels(&pixels, width, height)
        .map_err(|e| JsValue::from_str(&e))
}

/// `averageHashFromRgbBytes(rgb, width, height): string` — like
/// `averageHashFromPixels` but takes a flat `Uint8Array` of RGB bytes
/// (length `width * height * 3`), which is what a canvas readback yields.
#[wasm_bindgen(js_name = averageHashFromRgbBytes)]
pub fn average_hash_from_rgb_bytes(
    rgb: &[u8],
    width: usize,
    height: usize,
) -> Result<String, JsValue> {
    mvk_scan::phash::average_hash_from_rgb_bytes(rgb, width, height)
        .map_err(|e| JsValue::from_str(&e))
}

/// `hamming(a, b): number` — bit distance between two 16-hex-char hashes.
#[wasm_bindgen]
pub fn hamming(a: &str, b: &str) -> Result<u32, JsValue> {
    mvk_scan::phash::hamming(a, b).map_err(|e| JsValue::from_str(&e))
}

/// `normalize(text, nfkc?): { cleaned, removedCodepoints, categories }`
#[wasm_bindgen]
pub fn normalize(text: &str, nfkc: Option<bool>) -> Result<JsValue, JsValue> {
    let r = mvk_scan::normalize(text, nfkc.unwrap_or(true));
    let out = ScanResult {
        cleaned: r.cleaned,
        removed_codepoints: r.removed_codepoints,
        categories: r.categories,
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct Span {
    /// detector name (secrets) / kind (PII)
    name: String,
    /// JavaScript string offsets (UTF-16 code units), suitable for `slice()`.
    start: usize,
    end: usize,
}

fn codepoint_to_utf16_offsets(
    text: &str,
    spans: &[(String, usize, usize)],
) -> std::collections::HashMap<usize, usize> {
    let mut wanted: Vec<usize> = spans
        .iter()
        .flat_map(|(_, start, end)| [*start, *end])
        .collect();
    wanted.sort_unstable();
    wanted.dedup();

    let mut offsets = std::collections::HashMap::with_capacity(wanted.len());
    let mut wanted_idx = 0usize;
    let mut utf16_idx = 0usize;

    for (codepoint_idx, ch) in text.chars().enumerate() {
        while wanted_idx < wanted.len() && wanted[wanted_idx] == codepoint_idx {
            offsets.insert(codepoint_idx, utf16_idx);
            wanted_idx += 1;
        }
        utf16_idx += ch.len_utf16();
    }

    while wanted_idx < wanted.len() {
        offsets.insert(wanted[wanted_idx], utf16_idx);
        wanted_idx += 1;
    }

    offsets
}

fn spans_to_js(text: &str, spans: Vec<(String, usize, usize)>) -> Result<JsValue, JsValue> {
    let offsets = codepoint_to_utf16_offsets(text, &spans);
    let out: Vec<Span> = spans
        .into_iter()
        .map(|(name, start, end)| Span {
            name,
            start: offsets[&start],
            end: offsets[&end],
        })
        .collect();
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// `secretScanSpans(text): [{ name, start, end }]` — returns JavaScript
/// string offsets (UTF-16 code units) suitable for `slice()`. Throws on engine
/// error.
#[wasm_bindgen(js_name = secretScanSpans)]
pub fn secret_scan_spans(text: &str) -> Result<JsValue, JsValue> {
    let spans = mvk_scan::secret::scan_spans(text).map_err(|e| JsValue::from_str(&e))?;
    spans_to_js(text, spans)
}

/// `piiScanSpans(text): [{ name, start, end }]` — returns JavaScript string
/// offsets (UTF-16 code units) suitable for `slice()`. Throws on engine error
/// or Luhn ambiguity.
#[wasm_bindgen(js_name = piiScanSpans)]
pub fn pii_scan_spans(text: &str) -> Result<JsValue, JsValue> {
    let spans = mvk_scan::pii::scan_spans(text).map_err(|e| JsValue::from_str(&e))?;
    spans_to_js(text, spans)
}
