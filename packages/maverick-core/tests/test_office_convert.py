"""Office entry-point contracts; selected-backend fake, no native conversion."""
from __future__ import annotations

import pytest
from maverick.tools.office_convert import office_convert

from test_support.document_jobs import install_backend


@pytest.mark.parametrize("op,target,expected", [
    ("convert", "PDF", "PDF"), ("to_pdf", None, "pdf"), ("to_text", None, "txt"),
])
def test_conversion_uses_private_backend_job_and_verified_output(monkeypatch, tmp_path, op, target, expected):
    backend, state = install_backend(monkeypatch, tmp_path)
    source = tmp_path / "report.docx"
    source.write_bytes(b"immutable Office input fixture")
    args = {"op": op, "input_path": "report.docx"}
    if target:
        args["to"] = target
    out = office_convert(backend).fn(args)
    assert out.startswith("wrote ") and "SHA-256" in out and "test-only-1" in out
    assert source.read_bytes() == b"immutable Office input fixture"
    assert state["requests"][0]["target"] == expected
    assert state["requests"][0]["operation"] == "convert"
    assert all(not path.exists() for path in state["stages"])


def test_outdir_honored(monkeypatch, tmp_path):
    backend, _ = install_backend(monkeypatch, tmp_path)
    (tmp_path / "report.docx").write_bytes(b"source fixture")
    out = office_convert(backend).fn({"op": "convert", "input_path": "report.docx", "to": "pdf", "outdir": "out"})
    assert "out/report.pdf" in out.replace("\\", "/")
    assert (tmp_path / "out/report.pdf").read_bytes() == b"%PDF-1.4 fixture"


@pytest.mark.parametrize("mode", ["missing_engine", "missing_output", "nonzero", "bad_digest", "timeout"])
def test_no_success_claim_or_overwrite_on_failed_job(monkeypatch, tmp_path, mode):
    backend, state = install_backend(monkeypatch, tmp_path, mode=mode)
    (tmp_path / "report.docx").write_bytes(b"source fixture")
    destination = tmp_path / "report.pdf"
    destination.write_bytes(b"previous reviewed output")
    out = office_convert(backend).fn({"op": "to_pdf", "input_path": "report.docx"})
    assert out.startswith("ERROR"), out
    assert destination.read_bytes() == b"previous reviewed output"
    assert state["stages"] and all(not path.exists() for path in state["stages"])


@pytest.mark.parametrize("args,reason", [
    ({"op": "convert", "input_path": "report.docx", "to": "-flag"}, "invalid target format"),
    ({"op": "convert", "input_path": "-evil.docx", "to": "pdf"}, "may not begin"),
    ({"op": "to_pdf", "input_path": "../escaped.docx"}, "escapes"),
    ({"op": "convert", "to": "pdf"}, "input_path"),
    ({"op": "to_pdf", "input_path": "report.docx", "outdir": "../escape"}, "escapes"),
])
def test_invalid_request_stops_before_execution(monkeypatch, tmp_path, args, reason):
    backend, state = install_backend(monkeypatch, tmp_path)
    out = office_convert(backend).fn(args)
    assert out.startswith("ERROR") and reason in out
    assert state["calls"] == []


def test_missing_input_is_actionable(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    out = office_convert(backend).fn({"op": "to_pdf", "input_path": "missing.docx"})
    assert out.startswith("ERROR") and "FileNotFoundError" in out
    assert state["calls"] == []


def test_formats_lists_common():
    out = office_convert().fn({"op": "formats"})
    assert "pdf" in out and "docx" in out and "input formats" in out


def test_unknown_op():
    assert office_convert().fn({"op": "frobnicate"}).startswith("ERROR: unknown op")


def test_registered():
    from maverick.tools import base_registry

    class World:
        pass

    class Sandbox:
        workdir = "."

    names = set(getattr(base_registry(world=World(), sandbox=Sandbox()), "_tools", {}).keys())
    assert "office_convert" in names
