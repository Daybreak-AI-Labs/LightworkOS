# JavaScript perceptual hash

`ahash.js` is the JavaScript twin of `maverick.perceptual_hash`: an 8x8
average-hash for "are these two screenshots the same screen?" comparisons, with
Hamming distance. It has no DOM dependency, so it runs in a browser and under
Node.

Both implementations use integer-only arithmetic and assert the same constant
(`000001071f7fffff`) over a shared synthetic gradient, so they produce
bit-identical hashes. The hash knows coarse luminance layout only; it is not a
vision model.

`node ahash.js --selftest` prints the gradient hash and exits non-zero on
mismatch. `packages/maverick-core/tests/test_perceptual_hash.py` asserts the
same constant from Python and, when `node` is on PATH, runs the self-test and
compares the outputs.
