"""The Rust ``maverick_native`` perceptual hash must be byte-identical to Python.

When the wheel (built from ``rust/mvk-scan``) is installed, ``perceptual_hash``
uses it on the computer-use hot path. These tests prove the native path produces
exactly the same hash string and Hamming distance as the pure-Python fallback --
so accelerating the path can never change behaviour. When the wheel isn't built,
the native-parity tests skip and only the pure-Python sanity check runs.
"""
from __future__ import annotations

import pytest
from maverick import perceptual_hash as ph

NATIVE = getattr(ph, "_native", None) is not None and hasattr(
    getattr(ph, "_native", None), "average_hash_from_pixels"
)

# A spread of shapes/contents: the shared gradient, a solid field, a sharp
# split, an off-square aspect ratio, and the 8x8 minimum.
_IMAGES = [
    (ph.synthetic_gradient(), 64, 64),
    ([(7, 7, 7)] * (32 * 16), 32, 16),
    ([(255, 255, 255) if i % 2 else (0, 0, 0) for i in range(40 * 40)], 40, 40),
    ([(i % 256, (2 * i) % 256, (3 * i) % 256) for i in range(13 * 21)], 13, 21),
    ([(0, 0, 0)] * 64, 8, 8),
]


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
@pytest.mark.parametrize("pixels,w,h", _IMAGES)
def test_native_hash_matches_pure_python(pixels, w, h):
    assert ph.average_hash_from_pixels(pixels, w, h) == ph._average_hash_from_pixels_py(
        pixels, w, h
    )


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_native_hamming_matches_pure_python():
    a = ph.average_hash_from_pixels(*_IMAGES[0])
    b = ph.average_hash_from_pixels(*_IMAGES[2])
    assert ph.hamming(a, b) == ph._hamming_py(a, b)


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_native_is_actually_engaged():
    assert ph.average_hash_from_pixels is not ph._average_hash_from_pixels_py


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_native_rejects_bad_dimensions_like_python():
    # Falls back to the pure-Python ValueError rather than leaking a native one.
    with pytest.raises(ValueError):
        ph.average_hash_from_pixels([(0, 0, 0)], 8, 8)


def test_pure_python_api_unchanged_by_shim():
    # The known cross-language reference hash must hold whether or not the
    # native module is present.
    assert ph.average_hash_from_pixels(ph.synthetic_gradient(), 64, 64) == ph.GRADIENT_HASH
    assert ph.hamming(ph.GRADIENT_HASH, ph.GRADIENT_HASH) == 0
    assert ph.hamming("0000000000000000", "ffffffffffffffff") == 64
