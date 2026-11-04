"""model_card: render/validate an LLM model card."""
from __future__ import annotations

from maverick.tools.model_card import model_card


def _run(**kw):
    return model_card().fn(kw)


_FULL = {
    "model": "maverick-1",
    "provider": "ACME",
    "intended_use": "coding agent",
    "limitations": "may hallucinate",
}


def test_render_full():
    out = _run(op="render", training_cutoff="2026-01",
               eval_scores={"swe": 0.7, "math": 0.9}, **_FULL)
    assert out.startswith("OK")
    assert "Model Card: maverick-1" in out
    assert "Provider: ACME" in out
    assert "Training cutoff: 2026-01" in out
    assert "swe: 0.7" in out and "math: 0.9" in out


def test_render_minimal_no_optional():
    out = _run(op="render", **_FULL)
    assert out.startswith("OK")
    assert "Training cutoff" not in out
    assert "Eval scores" not in out


def test_render_missing_field_errors():
    partial = dict(_FULL)
    del partial["limitations"]
    out = _run(op="render", **partial)
    assert out.startswith("ERROR") and "limitations" in out


def test_validate_ok():
    out = _run(op="validate", **_FULL)
    assert out.startswith("OK") and "all required fields present" in out


def test_validate_missing_multiple():
    out = _run(op="validate", model="m", provider="p")
    assert out.startswith("INVALID")
    assert "intended_use" in out and "limitations" in out


def test_blank_field_counts_as_missing():
    partial = dict(_FULL)
    partial["model"] = "   "
    assert _run(op="validate", **partial).startswith("INVALID")


def test_unknown_op():
    assert _run(op="nope", **_FULL).startswith("ERROR")
