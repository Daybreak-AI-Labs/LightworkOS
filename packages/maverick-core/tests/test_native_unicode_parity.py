"""The Rust ``maverick_native`` scanner must be byte-identical to pure Python.

When the wheel (built from ``rust/mvk-scan``) is installed, the shield's
``unicode_filter`` uses it on the hot path. These tests prove the native path
produces exactly the same cleaned text, removed code points, categories, and
boolean as the pure-Python fallback -- so accelerating the path can never change
behaviour. When the wheel isn't built, the native-parity tests skip and only the
pure-Python sanity check runs.
"""
from __future__ import annotations

import sys
import threading

import pytest
from maverick.safety import unicode_filter as uf

_ZWSP, _RLO, _TAG = chr(0x200B), chr(0x202E), chr(0xE0001)

_BATTERY = [
    "",
    "plain ascii text",
    "café résumé naïve",
    f"a{_ZWSP}b",
    f"a{_RLO}b",
    f"x{_TAG}y",
    f"{_ZWSP}{_RLO}{_TAG}mixed{_ZWSP}",
    chr(0xFB01) + "x",
    chr(0xFF21) + chr(0xFF22),
    "emoji 😀 and CJK 漢字 stay",
    "newlines\nand\ttabs are fine",
    f"trojan {_RLO}source{_RLO} attack",
    "🇺🇸 flag sequence",
]

NATIVE = getattr(uf, "_native", None) is not None


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
@pytest.mark.parametrize("text", _BATTERY)
def test_native_matches_pure_python(text):
    native = uf.normalize(text)
    pure = uf._normalize_py(text)
    assert native.cleaned == pure.cleaned
    assert native.removed_codepoints == pure.removed_codepoints
    assert native.categories == pure.categories
    assert native.had_dangerous == pure.had_dangerous
    assert uf.has_dangerous_unicode(text) == uf._has_dangerous_unicode_py(text)


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_native_is_actually_engaged():
    assert uf._native is not None
    assert uf.normalize is not uf._normalize_py


@pytest.mark.skipif(not NATIVE, reason="maverick_native wheel not built in this env")
def test_large_native_normalization_allows_another_python_thread_to_progress():
    """A large scan detaches while its Rust-only work is running."""
    ready = threading.Event()
    begin = threading.Event()
    progressed = threading.Event()

    def other_thread():
        ready.set()
        begin.wait()
        progressed.set()

    thread = threading.Thread(target=other_thread, daemon=True)
    thread.start()
    assert ready.wait(5)
    old_interval = sys.getswitchinterval()
    payload = "a" * 2_000_000
    try:
        # Suppress normal bytecode time-slicing between begin.set() and the
        # native call. The other thread can run while the native call detaches.
        sys.setswitchinterval(5.0)
        begin.set()
        cleaned, removed, categories = uf._native.normalize(payload, False)
        ran_during_call = progressed.is_set()
    finally:
        sys.setswitchinterval(old_interval)
        begin.set()
        thread.join(timeout=5)
    assert ran_during_call
    assert cleaned == payload
    assert removed == [] and categories == []


def test_pure_python_api_unchanged_by_shim():
    r = uf.normalize(f"a{_ZWSP}b{_RLO}c")
    assert r.cleaned == "abc"
    assert r.had_dangerous
    assert r.categories == ["zero_width", "bidi_override"]
    assert uf.has_dangerous_unicode(_TAG)
    assert not uf.has_dangerous_unicode("perfectly clean")
    assert uf.normalize("").cleaned == ""
