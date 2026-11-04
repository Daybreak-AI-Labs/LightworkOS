"""whats_changed: human-readable before/after digest."""
from __future__ import annotations

from maverick.tools.whats_changed import whats_changed


def _run(**kw):
    return whats_changed().fn(kw)


def test_diff_added_removed_changed():
    out = _run(op="diff",
               before={"a": 1, "b": 2, "drop": "x"},
               after={"a": 1, "b": 99, "new": "y"})
    assert out.startswith("CHANGED: +1 added, -1 removed, ~1 changed")
    assert "+ new: y" in out
    assert "- drop: x" in out
    assert "~ b: 2 -> 99" in out


def test_diff_no_changes():
    out = _run(op="diff", before={"a": 1}, after={"a": 1})
    assert out.startswith("NO CHANGES")


def test_diff_text_counts():
    out = _run(op="diff_text",
               before_str="line1\nline2\nline3",
               after_str="line1\nCHANGED\nline3\nline4")
    assert out.startswith("CHANGED:")
    # line2 -> CHANGED (1 add + 1 remove) plus added line4 = +2 / -1.
    assert "+2 line(s) added" in out
    assert "-1 line(s) removed" in out


def test_diff_text_identical():
    out = _run(op="diff_text", before_str="same\ntext", after_str="same\ntext")
    assert out.startswith("NO CHANGES")


def test_default_op_is_diff():
    out = _run(before={"a": 1}, after={"a": 2})
    assert out.startswith("CHANGED") and "~ a: 1 -> 2" in out


def test_errors():
    t = whats_changed()
    assert t.fn({"op": "diff", "before": "nope", "after": {}}).startswith("ERROR")
    assert t.fn({"op": "diff_text", "before_str": 1, "after_str": "x"}).startswith("ERROR")
    assert t.fn({"op": "bogus"}).startswith("ERROR")
