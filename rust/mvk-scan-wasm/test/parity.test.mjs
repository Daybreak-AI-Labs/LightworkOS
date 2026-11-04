// TypeScript/edge (WASM) parity: the wasm-pack package built from the SAME
// `mvk-scan` core must produce exactly what the Python and Rust paths do.
// Run: wasm-pack build --target nodejs --out-dir pkg --release && node --test
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasm = require("../pkg/mvk_scan_wasm.js");

const ZWSP = "​";
const RLO = "‮";
const TAG = "\u{e0001}";

test("hasDangerousUnicode matches the Python contract", () => {
  assert.equal(wasm.hasDangerousUnicode(`a${ZWSP}b`), true);
  assert.equal(wasm.hasDangerousUnicode(`a${RLO}b`), true);
  assert.equal(wasm.hasDangerousUnicode(`x${TAG}y`), true);
  assert.equal(wasm.hasDangerousUnicode("perfectly clean text"), false);
  assert.equal(wasm.hasDangerousUnicode(""), false);
});

test("normalize strips and reports identically to Python", () => {
  const r = wasm.normalize(`a${ZWSP}b${RLO}c`, true);
  assert.equal(r.cleaned, "abc");
  // 0x200B = 8203 (ZWSP), 0x202E = 8238 (RLO) -- same as the Python scanner.
  assert.deepEqual(r.removedCodepoints, [8203, 8238]);
  assert.deepEqual(r.categories, ["zero_width", "bidi_override"]);
});

test("normalize NFKC-canonicalizes look-alikes", () => {
  const r = wasm.normalize("ﬁx", true); // fi ligature -> fi
  assert.equal(r.cleaned, "fix");
  assert.deepEqual(r.removedCodepoints, []);
});

test("tag block is a stripped category", () => {
  const r = wasm.normalize(`x${TAG}y`, true);
  assert.equal(r.cleaned, "xy");
  assert.deepEqual(r.categories, ["tag_block"]);
});

test("empty and clean inputs are untouched", () => {
  assert.equal(wasm.normalize("", true).cleaned, "");
  const r = wasm.normalize("café résumé", true);
  assert.equal(r.cleaned, "café résumé");
  assert.deepEqual(r.categories, []);
});
