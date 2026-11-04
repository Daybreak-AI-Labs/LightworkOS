"""capability_leak_fuzzer: detect tools running without required capabilities."""
from __future__ import annotations

from maverick.tools.capability_leak_fuzzer import capability_leak_fuzzer


def _fuzz(granted, tools):
    return capability_leak_fuzzer().fn(
        {"op": "fuzz", "granted": granted, "tools": tools}
    )


def test_all_requirements_held_passes():
    out = _fuzz(
        ["net", "fs"],
        [{"tool": "http_fetch", "requires": "net"},
         {"tool": "write_file", "requires": "fs"}],
    )
    assert "LEAKS: none" in out
    assert out.rstrip().endswith("PASS")


def test_missing_capability_is_a_leak():
    out = _fuzz(
        [],  # nothing granted
        [{"tool": "http_fetch", "requires": "net"}],
    )
    assert "LEAKS (1)" in out
    assert "http_fetch: runs WITHOUT required ['net']" in out
    assert "FAIL" in out


def test_over_grant_reported():
    out = _fuzz(
        ["net", "fs", "admin"],  # admin never required
        [{"tool": "http_fetch", "requires": "net"},
         {"tool": "write_file", "requires": "fs"}],
    )
    assert "OVER-GRANTS (1): ['admin']" in out
    # over-grants alone are not a failure.
    assert out.rstrip().endswith("PASS")


def test_list_requires_partial_leak():
    out = _fuzz(
        ["net"],  # has net but not fs
        [{"tool": "uploader", "requires": ["net", "fs"]}],
    )
    assert "uploader: runs WITHOUT required ['fs']" in out
    assert "FAIL" in out


def test_no_requirements_never_leaks():
    out = _fuzz([], [{"tool": "compute"}])
    assert "LEAKS: none" in out
    assert out.rstrip().endswith("PASS")


def test_deterministic_repeatable():
    args = (["net"], [{"tool": "a", "requires": "fs"},
                      {"tool": "b", "requires": "net"}])
    assert _fuzz(*args) == _fuzz(*args)


def test_errors():
    t = capability_leak_fuzzer()
    assert t.fn({"op": "fuzz", "tools": []}).startswith("ERROR")  # no granted
    assert t.fn({"op": "fuzz", "granted": []}).startswith("ERROR")  # no tools
    assert t.fn({"op": "nope", "granted": [], "tools": []}).startswith("ERROR")
    assert t.fn({"op": "fuzz", "granted": [], "tools": [{"requires": "x"}]}).startswith("ERROR")
