"""outline_writer: long-form writing pipeline (outline->draft->polish)."""
from __future__ import annotations

from maverick.tools.outline_writer import outline_writer


def _run(**kw):
    return outline_writer().fn(kw)


def test_outline_default_five_sections():
    out = _run(op="outline", topic="Distributed Systems")
    lines = out.splitlines()
    assert lines[0].startswith("Outline: Distributed Systems (5 sections)")
    numbered = [ln for ln in lines if ln[:1].isdigit()]
    assert len(numbered) == 5
    assert numbered[0] == "1. Introduction to Distributed Systems"
    assert "Distributed Systems" in numbered[-1]


def test_outline_custom_count_and_deterministic():
    a = _run(op="outline", topic="Caching", sections=3)
    b = _run(op="outline", topic="Caching", sections=3)
    assert a == b  # deterministic
    assert len([ln for ln in a.splitlines() if ln[:1].isdigit()]) == 3


def test_expand_skeleton_has_specs_and_targets():
    out = _run(
        op="expand",
        outline=["Introduction to X", "Analysis of X"],
        words_per_section=200,
    )
    assert "2 section(s)" in out and "~400 words total" in out
    assert out.count("[paragraph:") == 2
    assert out.count("target_words: 200") == 2
    assert "## 1. Introduction to X" in out


def test_expand_default_words():
    out = _run(op="expand", outline=["Only Heading"])
    assert "target_words: 150" in out
    assert "~150 words total" in out


def test_checklist_is_fixed_list():
    out = _run(op="checklist")
    assert out.startswith("Polish checklist:")
    assert out.count("[ ]") == 8
    assert "Thesis" in out


def test_outline_rejects_unbounded_section_count():
    # A model-supplied huge integer must not hang/OOM the in-process agent:
    # _outline is O(sections) in CPU and memory (mirrors synthetic_data's cap).
    assert _run(op="outline", topic="x", sections=50_000_000).startswith("ERROR")
    assert _run(op="outline", topic="x", sections=101).startswith("ERROR")
    ok = _run(op="outline", topic="x", sections=100)  # cap itself still works
    assert ok.startswith("Outline:")
    assert len([ln for ln in ok.splitlines() if ln[:1].isdigit()]) == 100


def test_errors():
    assert _run(op="outline").startswith("ERROR")  # missing topic
    assert _run(op="outline", topic="x", sections=0).startswith("ERROR")
    assert _run(op="expand").startswith("ERROR")  # missing outline
    assert _run(op="expand", outline=["", "  "]).startswith("ERROR")  # all blank
    assert _run(op="bogus").startswith("ERROR")
