# Lightwork native core (`rust/`)

The Rust native core. Performance-critical scanning logic lives in one
pure-logic crate and is exposed to Python and TypeScript through thin bindings;
the agent loop, the tools and the 2,031 domain packs stay in Python.

```
mvk-scan/        core logic (pure Rust, no FFI) — the only place behaviour lives
mvk-scan-py/     PyO3 binding  -> Python extension module `maverick_native`
mvk-scan-wasm/   wasm-bindgen  -> npm/edge package (TypeScript, Workers, Deno)
```

## Why

The safety scanners run on **every** agent input and tool output and are pure
CPU — exactly the kind of hot, GIL-bound work that belongs in native code. The
unicode scanner (`maverick.safety.unicode_filter`) is a faithful port, and
Python keeps a **fallback shim**, so a build *without* the native wheel behaves
identically. The native module is a drop-in accelerator, never a new hard
dependency.

## Measured speedup (native vs pure Python, same machine)

The unicode scanner alone:

| call | input | speedup |
|---|---|---|
| `normalize` | ~30 B (a command) | **3.0×** |
| `normalize` | ~2 KB (a prompt) | **5.0×** |
| `normalize` | ~54 KB (a tool output) | **5.4×** |
| `has_dangerous_unicode` | ~54 KB | **50.7×** |

`has_dangerous_unicode` runs on *every* input; the per-char Python loop is the
worst case and Rust's short-circuit scan is ~50× faster. Even the smallest input
(where FFI overhead is highest) is 3×. These figures measure per-call latency.
For large normalization, secret/PII scan and image-hash inputs, the Python
bindings copy the input to owned Rust data and release the GIL during the
computation. Small calls and the short-circuit Unicode check retain it. The
figures above measure single-call latency; they do not establish
parallel throughput or an optimal detach threshold.

## Build

Python wheel (the `maverick_native` extension):

```bash
cd rust/mvk-scan-py
maturin build --release          # -> rust/target/wheels/maverick_native-*.whl
pip install ../target/wheels/maverick_native-*.whl
# maverick.safety.unicode_filter now uses it automatically; absent => pure Python
```

TypeScript / edge package (WASM):

```bash
cd rust/mvk-scan-wasm
wasm-pack build --target nodejs --out-dir pkg --release   # node/CommonJS
# or: --target web / --target bundler  for browsers / Workers / Deno
node --test test/parity.test.mjs                          # parity vs Python
```

Core unit tests: `cd rust && cargo test -p mvk-scan`.

## Modules

| core module | role | Python hot path | engine |
|---|---|---|---|
| `unicode` | accelerator | **wired in** (3–50× faster) | `unicode-normalization` |
| `secret` | edge/TS + parity | **pure `re`** (native was slower) | `fancy-regex` |
| `pii` | edge/TS + parity | **pure `re`** (native ~break-even) | `fancy-regex` |
| `phash` | accelerator | **wired in** (~28× on the file path) | pure int math |

### `phash` — perceptual image hash

`maverick.perceptual_hash` runs on **every screenshot** in computer-use: an 8×8
average-hash, pure integer arithmetic, with a per-pixel Python luma loop — the
same shape that made the unicode scanner a win. It's a faithful port (the
`GRADIENT_HASH` reference value is asserted identically in Rust, Python, and
`extensions/webgpu-vision/ahash.js`), with the Python kept as a fallback shim.

The speedup depends on the **FFI boundary**, not the loop. Handing the native
side a list of `width*height` Python tuples made it only ~1.4× (marshalling
dominated). The real hot path — `average_hash_file` — gets pixels from PIL, so
`average_hash_from_rgb_bytes` takes the raw `Image.tobytes()` buffer instead: the
whole image crosses FFI as one `bytes` object. Measured on the same machine:

| call | input | pure-Python | native | speedup |
|---|---|---|---|---|
| `average_hash_from_pixels` | 1280×800, list of tuples | 144 ms | 102 ms | 1.4× |
| `average_hash_from_rgb_bytes` | 1280×800, `bytes` buffer | 144 ms | 5.0 ms | **28×** |

So the tuple API stays the cross-language reference, and the **bytes** API is the
accelerator the file path uses. `test_native_phash_parity.py` keeps both
byte-for-byte identical to pure Python.

### `secret` and `pii` — detectors

Not every hot CPU module is a Rust win. Unlike the unicode scanner (a per-char *Python* loop),
the detectors already run on CPython's compiled `re`. Measured on the same
machine, the native port — 23 separate `fancy-regex` passes — was **~3× slower
for secrets** and roughly break-even for PII:

| scan | input | pure-Python `re` | native | result |
|---|---|---|---|---|
| `secret` | 2 KB / 60 KB (clean) | 0.44 / 12.9 ms | 1.31 / 39.4 ms | native **0.33×** |
| `pii` | 60 KB clean / dense | 32.6 / 30.1 ms | 30.8 / 27.6 ms | native ~1.06–1.09× |

So the detectors **stay pure `re` on the Python hot path** (the shield, the audit
log). The native build is retained for the **TypeScript / edge** runtimes
(Workers, Deno, browser) that have no `re` at all, where it's the only option —
and `test_native_detect_parity.py` compares its spans against Python. The `regex` crate can't do the PII phone/SSN look-behind /
look-ahead, hence `fancy-regex`; and the detectors are security-critical, so the
native side **fails safe** — any engine error, or a Luhn-ambiguous
non-ASCII-digit card candidate, raises rather than guessing.

## Parity

The core and PyO3 binding report spans as **codepoint** indices (Python
`re.span()` semantics). The WASM binding converts those spans to **UTF-16
code-unit** offsets for JavaScript string slicing, including non-ASCII text.

- `tests/test_native_unicode_parity.py` — unicode native path == pure Python.
- `tests/test_native_detect_parity.py` — the native extension's secret + PII
  output == pure-Python `scan`, plus a deterministic differential fuzz (an
  offline run over 24k inputs found zero mismatches).
- `tests/test_native_phash_parity.py` — native average-hash (tuple and bytes
  paths) == pure Python across a spread of shapes; falls back on bad dimensions.
- `mvk-scan-wasm/test/{parity,detect.parity}.test.mjs` — the WASM path == pure
  Python too.

Both bindings use the same `mvk-scan` core; parity tests also cover their offset conversions.
