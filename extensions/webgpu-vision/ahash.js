/* Perceptual 8x8 average-hash — the JavaScript twin of
 * packages/maverick-core/maverick/perceptual_hash.py.
 *
 * The algorithm is integer-only (BigInt for the wide compares/packing) so
 * JS and Python produce BIT-IDENTICAL hashes:
 *
 *   1. gray(p)   = r*299 + g*587 + b*114                (luma x1000, exact int)
 *   2. cells     = 8x8 grid; cell (cx, cy) covers x in [cx*w/8 .. (cx+1)*w/8)
 *                  (floor division; requires w >= 8 and h >= 8)
 *   3. bit       = 1 iff cell_sum * total_count > total_sum * cell_count
 *                  (cross-multiplied average comparison; ties are 0)
 *   4. pack      = row-major (cy outer), MSB first; render as 16 hex chars
 *
 * Both sides assert GRADIENT_HASH over the same synthetic gradient. This file
 * has no DOM dependency: it runs in a browser and under Node
 * (`node ahash.js --selftest`, used by the Python test suite).
 * Not a neural classifier — coarse luminance layout only.
 */
"use strict";

// Hash of syntheticGradient() — must equal maverick.perceptual_hash.GRADIENT_HASH.
const GRADIENT_HASH = "000001071f7fffff";

/**
 * 64-bit average-hash as 16 hex chars.
 * @param {Uint8ClampedArray|Uint8Array|number[]} rgba flat RGBA, row-major
 *   (canvas ImageData.data layout; the alpha channel is ignored)
 */
function averageHashFromRGBA(rgba, width, height) {
  if (width < 8 || height < 8) throw new Error("image must be at least 8x8");
  if (rgba.length !== width * height * 4) {
    throw new Error("expected " + width * height * 4 + " RGBA bytes, got " + rgba.length);
  }
  const n = width * height;
  const gray = new Int32Array(n); // max 254745, exact
  let totalSum = 0n;
  for (let i = 0; i < n; i++) {
    const g = rgba[i * 4] * 299 + rgba[i * 4 + 1] * 587 + rgba[i * 4 + 2] * 114;
    gray[i] = g;
    totalSum += BigInt(g);
  }
  const totalCount = BigInt(n);
  let bits = 0n;
  for (let cy = 0; cy < 8; cy++) {
    const y0 = Math.floor((cy * height) / 8);
    const y1 = Math.floor(((cy + 1) * height) / 8);
    for (let cx = 0; cx < 8; cx++) {
      const x0 = Math.floor((cx * width) / 8);
      const x1 = Math.floor(((cx + 1) * width) / 8);
      let cellSum = 0; // <= 254745 * cell pixels; safe below 2^53 for any sane image
      for (let y = y0; y < y1; y++) {
        const row = y * width;
        for (let x = x0; x < x1; x++) cellSum += gray[row + x];
      }
      const cellCount = BigInt((y1 - y0) * (x1 - x0));
      const bit = BigInt(cellSum) * totalCount > totalSum * cellCount ? 1n : 0n;
      bits = (bits << 1n) | bit;
    }
  }
  return bits.toString(16).padStart(16, "0");
}

/** Bit distance between two 16-hex-char hashes (0 identical .. 64 opposite). */
function hamming(a, b) {
  if (a.length !== 16 || b.length !== 16) {
    throw new Error("hashes must be 16 hex chars (64 bits)");
  }
  let x = BigInt("0x" + a) ^ BigInt("0x" + b);
  let d = 0;
  while (x) { d += Number(x & 1n); x >>= 1n; }
  return d;
}

/** The shared cross-language test image: a 64x64 two-axis RGB gradient. */
function syntheticGradient() {
  const out = new Uint8ClampedArray(64 * 64 * 4);
  let i = 0;
  for (let y = 0; y < 64; y++) {
    for (let x = 0; x < 64; x++) {
      out[i++] = x * 4;
      out[i++] = y * 4;
      out[i++] = (x + y) * 2;
      out[i++] = 255;
    }
  }
  return out;
}

/** Returns the gradient hash; throws if it doesn't match the shared constant. */
function selfTest() {
  const h = averageHashFromRGBA(syntheticGradient(), 64, 64);
  if (h !== GRADIENT_HASH) {
    throw new Error("self-test FAILED: got " + h + ", expected " + GRADIENT_HASH);
  }
  return h;
}

const api = { GRADIENT_HASH, averageHashFromRGBA, hamming, syntheticGradient, selfTest };

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
  if (typeof require !== "undefined" && require.main === module) {
    // `node ahash.js --selftest` — exercised by the Python cross-language test.
    console.log(selfTest());
  }
} else {
  globalThis.AHash = api;
}
