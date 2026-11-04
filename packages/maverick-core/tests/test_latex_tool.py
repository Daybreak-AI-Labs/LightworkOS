"""LaTeX entry-point validation and private job lifecycle, no native TeX claims."""
from __future__ import annotations

import pytest
from maverick.tools import document_processing
from maverick.tools import latex_tool as latex_module
from maverick.tools.latex_tool import latex_tool, to_mathml

from test_support.document_jobs import install_backend


def test_mathml_conversion():
    pytest.importorskip("latex2mathml")
    out = to_mathml(r"x^2 + 1")
    assert "<math" in out and "</math>" in out


def test_mathml_op_via_tool():
    pytest.importorskip("latex2mathml")
    assert "<math" in latex_tool(None).fn({"op": "mathml", "latex": r"\frac{a}{b}"})


def test_render_success(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    out = latex_tool(backend).fn({"op": "render", "latex": "customer document", "out": "out/paper.pdf"})
    assert out.startswith("rendered PDF") and "SHA-256" in out
    assert (tmp_path / "out/paper.pdf").read_bytes() == b"%PDF-1.4 fixture"
    assert state["requests"][0]["input_name"] == "input.tex"


def test_render_engine_missing(monkeypatch, tmp_path):
    backend, _ = install_backend(monkeypatch, tmp_path, mode="missing_engine")
    out = latex_tool(backend).fn({"op": "render", "latex": "customer document", "out": "x.pdf"})
    assert out.startswith("ERROR") and "installed" in out
    assert not (tmp_path / "x.pdf").exists()


def test_empty_latex():
    assert latex_tool(None).fn({"op": "mathml", "latex": "  "}).startswith("ERROR")


@pytest.mark.parametrize("op", ["mathml", "render"])
@pytest.mark.parametrize("source", [5, [1, 2], {"latex": "x"}, True])
def test_invalid_source_is_refused_before_conversion(monkeypatch, op, source):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid source reached the converter or document engine")

    monkeypatch.setattr(latex_module, "to_mathml", unexpected)
    monkeypatch.setattr(document_processing, "run_document_job", unexpected)
    out = latex_tool(None).fn({"op": op, "latex": source})
    assert out.startswith("ERROR") and "string" in out


@pytest.mark.parametrize("source", [r"\frac{1}", "x^", r"\sqrt{"])
def test_malformed_math_returns_actionable_error(source):
    pytest.importorskip("latex2mathml")
    out = latex_tool(None).fn({"op": "mathml", "latex": source})
    assert out.startswith("ERROR") and "LaTeX" in out


@pytest.mark.parametrize("outcome", ["success", "nonzero", "io_error", "missing_output", "stale_job"])
def test_render_cleans_private_scratch_on_every_outcome(monkeypatch, tmp_path, outcome):
    backend, state = install_backend(monkeypatch, tmp_path, mode=outcome)
    dest = tmp_path / "out.pdf"
    dest.write_bytes(b"prior reviewed report")
    out = latex_tool(backend).fn({"op": "render", "latex": "private customer document", "out": "out.pdf"})
    assert state["stages"] and all(not path.exists() for path in state["stages"])
    if outcome == "success":
        assert out.startswith("rendered PDF")
        assert dest.read_bytes() == b"%PDF-1.4 fixture"
    else:
        assert out.startswith("ERROR")
        assert dest.read_bytes() == b"prior reviewed report"


def test_invalid_destination_is_refused_before_engine(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    out = latex_tool(backend).fn({"op": "render", "latex": "customer document", "out": "../escaped.pdf"})
    assert out.startswith("ERROR") and "escape" in out.lower()
    assert state["calls"] == []
    assert not (tmp_path.parent / "escaped.pdf").exists()
