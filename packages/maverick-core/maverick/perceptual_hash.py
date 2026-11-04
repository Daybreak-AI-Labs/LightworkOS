"""Perceptual image hashing — 8x8 average-hash + Hamming distance.

Answers "are these two screenshots the same screen?" without a vision model:
two images whose hashes are a few bits apart are near-duplicates; far apart
means the screen changed. This is a classic *perceptual hash*, not a neural
classifier — it has no notion of objects or text, only coarse luminance
layout. That is exactly the honest scope: cheap, local, deterministic.

The algorithm is specified in **integer arithmetic only** so the JavaScript
twin (``extensions/webgpu-vision/ahash.js``) produces bit-identical hashes —
no float rounding can diverge across languages:

  1. gray(p)   = r*299 + g*587 + b*114                  (luma x1000, exact int)
  2. cells     = 8x8 grid; cell (cx, cy) covers x in [cx*w//8, (cx+1)*w//8)
                 and y likewise (requires w >= 8 and h >= 8)
  3. bit       = 1 iff cell_sum * total_count > total_sum * cell_count
                 (cross-multiplied average comparison; ties are 0)
  4. pack      = row-major (cy outer), MSB first; render as 16 hex chars

Both sides assert ``GRADIENT_HASH`` over the same synthetic gradient, proving
the implementations agree. Pillow is imported lazily and ONLY by
``average_hash_file`` (the ``computer-use`` extra); the pixel-level API and
``hamming`` are dependency-free.
"""
from __future__ import annotations

from collections.abc import Sequence

# Hash of synthetic_gradient(64, 64) — asserted by tests here AND by
# extensions/webgpu-vision/ahash.js selfTest(). Change one, change both.
GRADIENT_HASH = "000001071f7fffff"


def average_hash_from_pixels(
    pixels: Sequence[tuple[int, int, int]], width: int, height: int,
) -> str:
    """64-bit average-hash of row-major RGB ``pixels``, as 16 hex chars."""
    if width < 8 or height < 8:
        raise ValueError("image must be at least 8x8")
    if len(pixels) != width * height:
        raise ValueError(f"expected {width * height} pixels, got {len(pixels)}")
    gray = [r * 299 + g * 587 + b * 114 for (r, g, b) in pixels]
    total_sum = sum(gray)
    total_count = width * height
    bits = 0
    for cy in range(8):
        y0, y1 = (cy * height) // 8, ((cy + 1) * height) // 8
        for cx in range(8):
            x0, x1 = (cx * width) // 8, ((cx + 1) * width) // 8
            cell_sum = 0
            for y in range(y0, y1):
                row = y * width
                cell_sum += sum(gray[row + x0:row + x1])
            cell_count = (y1 - y0) * (x1 - x0)
            bit = 1 if cell_sum * total_count > total_sum * cell_count else 0
            bits = (bits << 1) | bit
    return format(bits, "016x")


def average_hash_file(path: str) -> str:
    """Average-hash of an image file. Lazy-imports Pillow (computer-use extra)."""
    try:
        from PIL import Image
    except ImportError as e:
        raise ImportError(
            "Pillow not installed — python -m pip install -e './packages/maverick-core[computer-use]' "
            "to hash image files (average_hash_from_pixels needs no deps)"
        ) from e
    with Image.open(path) as im:
        im = im.convert("RGB")
        width, height = im.size
        raw = im.tobytes()
    # The native accelerator can hash the raw RGB buffer directly (one ``bytes``
    # object across FFI instead of width*height tuples); fall back to the
    # pure-Python pixel API when the wheel isn't built. Both are bit-identical.
    _native_bytes = getattr(_native, "average_hash_from_rgb_bytes", None)
    if _native_bytes is not None:
        try:
            return _native_bytes(raw, width, height)
        except Exception:
            pass
    pixels = list(zip(raw[0::3], raw[1::3], raw[2::3], strict=False))
    return average_hash_from_pixels(pixels, width, height)


def hamming(a: str, b: str) -> int:
    """Bit distance between two 16-hex-char hashes (0 identical .. 64 opposite)."""
    if len(a) != 16 or len(b) != 16:
        raise ValueError("hashes must be 16 hex chars (64 bits)")
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def synthetic_gradient() -> list[tuple[int, int, int]]:
    """The shared cross-language test image: a 64x64 two-axis RGB gradient."""
    return [
        (x * 4, y * 4, (x + y) * 2)
        for y in range(64)
        for x in range(64)
    ]


# --- Native fast path (optional) -------------------------------------------
# A Rust implementation (the ``maverick_native`` extension, built from
# ``rust/mvk-scan``) moves the per-pixel luma loop into Rust on the
# computer-use hot path (every screenshot is hashed). It is OPTIONAL: when the
# wheel isn't installed the pure-Python functions above are used unchanged, so
# behaviour is identical either way -- the native module is a drop-in
# accelerator, never a new dependency. The ``hasattr`` guards keep an older
# ``maverick_native`` (built before these symbols existed) from breaking.
try:  # pragma: no cover - import guard
    import maverick_native as _native
except Exception:  # pragma: no cover
    _native = None

if _native is not None and hasattr(  # pragma: no cover - active only with the wheel
    _native, "average_hash_from_pixels"
):
    _average_hash_from_pixels_py = average_hash_from_pixels

    def average_hash_from_pixels(  # noqa: F811
        pixels: Sequence[tuple[int, int, int]], width: int, height: int,
    ) -> str:
        try:
            return _native.average_hash_from_pixels(list(pixels), width, height)
        except Exception:
            # Any divergence (incl. the canonical ValueError on bad dimensions)
            # falls back to pure Python, which is the source of truth.
            return _average_hash_from_pixels_py(pixels, width, height)

if _native is not None and hasattr(_native, "hamming"):  # pragma: no cover
    _hamming_py = hamming

    def hamming(a: str, b: str) -> int:  # noqa: F811
        try:
            return _native.hamming(a, b)
        except Exception:
            return _hamming_py(a, b)
