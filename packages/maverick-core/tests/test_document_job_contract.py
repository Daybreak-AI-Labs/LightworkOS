"""Staged selected-backend contract with explicit outcomes and no native calls."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick.sandbox import document_engine as engine
from maverick.tools import document_processing as jobs
from maverick.tools.ocr import ocr
from maverick.tools.office_convert import office_convert

from test_support.document_jobs import install_backend


@pytest.mark.parametrize("operation", ["convert", "image_ocr", "latex"])
def test_each_tool_job_verifies_non_host_visible_backend_outputs(monkeypatch, tmp_path, operation):
    backend, state = install_backend(monkeypatch, tmp_path)
    request = {"operation": operation, "target": "pdf", "input_suffix": "docx", "engine": "tectonic", "language": "eng"}
    result = jobs.run_document_job(request, b"customer input", backend,
                                   destination=None if operation == "image_ocr" else "result.pdf")
    assert state["calls"] and state["requests"][0]["operation"] == operation
    assert all(not path.exists() for path in state["stages"])
    if operation == "image_ocr":
        assert result == "OCR text 120000"
    else:
        assert result.startswith("wrote ") and "SHA-256" in result
        assert (tmp_path / "result.pdf").read_bytes() == b"%PDF-1.4 fixture"


@pytest.mark.parametrize("mode", ["missing_output", "bad_digest", "stale_job", "wrong_type",
                                  "changed_input", "timeout", "nonzero", "io_error", "missing_engine"])
def test_failed_jobs_preserve_prior_artifact_and_cleanup(monkeypatch, tmp_path, mode):
    backend, state = install_backend(monkeypatch, tmp_path, mode=mode)
    output = tmp_path / "result.pdf"
    output.write_bytes(b"prior reviewed artifact")
    with pytest.raises((RuntimeError, OSError, ValueError)):
        jobs.run_document_job({"operation": "latex", "engine": "tectonic"}, b"customer input", backend, destination="result.pdf")
    assert output.read_bytes() == b"prior reviewed artifact"
    assert all(not path.exists() for path in state["stages"])


def test_local_destination_change_is_not_overwritten(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    output = tmp_path / "result.pdf"
    output.write_bytes(b"prior")
    state["during_job"] = lambda: output.write_bytes(b"newer customer version")
    with pytest.raises(RuntimeError, match="destination changed"):
        jobs.run_document_job({"operation": "latex", "engine": "tectonic"}, b"source", backend, destination="result.pdf")
    assert output.read_bytes() == b"newer customer version"


def test_preexisting_job_output_is_not_treated_as_success(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    with jobs._worker(backend, {"operation": "latex", "engine": "tectonic"}) as (stage, worker):
        (stage / "input.tex").write_bytes(b"source")
        (stage / "rendered.pdf").write_bytes(b"stale artifact")
        with pytest.raises(RuntimeError, match="stale output"):
            jobs._execute(stage, worker)
    assert state["calls"] == []


def test_host_without_engine_does_not_preempt_selected_backend(monkeypatch, tmp_path):
    backend, state = install_backend(monkeypatch, tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    (tmp_path / "report.docx").write_bytes(b"input placeholder; engine is a contract fake")
    result = office_convert(backend).fn({"op": "to_pdf", "input_path": "report.docx"})
    assert result.startswith("wrote ") and state["calls"]
    (tmp_path / "image.png").write_bytes(b"image placeholder")
    assert ocr(backend).fn({"op": "extract", "path": "image.png"}) == "OCR text 120000"


def test_actual_worker_dispatch_checks_backend_capability_before_operation(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    job = jobs.DocumentJob.create({"operation": "latex"})
    data = b"source"
    (tmp_path / job.input_name).write_bytes(data)
    request = {"operation": "latex", "engine": "tectonic", **job.manifest(),
               "input_bytes": len(data), "input_sha256": hashlib.sha256(data).hexdigest()}
    (tmp_path / "request.json").write_text(json.dumps(request))
    monkeypatch.setattr(engine.shutil, "which", lambda name: None)
    monkeypatch.setattr(engine, "latex", lambda request: pytest.fail("missing engine reached execution"))
    assert engine.main() == 2
    assert "not installed in the selected document backend" in json.loads((tmp_path / "result.json").read_text())["error"]


def test_backend_input_digest_is_checked_before_capability_or_execution(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    job = jobs.DocumentJob.create({"operation": "latex"})
    (tmp_path / job.input_name).write_bytes(b"changed")
    request = {"operation": "latex", "engine": "tectonic", **job.manifest(), "input_bytes": 4, "input_sha256": "0" * 64}
    (tmp_path / "request.json").write_text(json.dumps(request))
    monkeypatch.setattr(engine, "_capabilities", lambda request: pytest.fail("changed input reached capability probe"))
    assert engine.main() == 2
    assert "input changed" in json.loads((tmp_path / "result.json").read_text())["error"]


def test_legacy_local_worker_is_explicit_and_pdf_ocr_keeps_its_container_rule(monkeypatch, tmp_path):
    from maverick.sandbox.local import LocalBackend

    with jobs._worker(LocalBackend(tmp_path), {"operation": "latex"}, allow_local=True) as (stage, worker):
        assert isinstance(worker, LocalBackend) and worker.workdir == stage
    with pytest.raises(RuntimeError, match="Docker, Podman or Kubernetes"):
        with jobs._worker(LocalBackend(tmp_path), {"operation": "ocr"}):
            pytest.fail("OCR unexpectedly enabled on host")
