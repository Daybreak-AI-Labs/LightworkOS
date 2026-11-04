"""Owned-worker lifecycle: tiny local Python children and UNO interface fakes.

These tests do not qualify an installed Office, OCR, or TeX engine.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from maverick.sandbox import document_engine as engine
from maverick.tools.document_processing import DocumentJob


def test_worker_command_output_is_bounded_while_process_runs(monkeypatch):
    monkeypatch.setattr(engine, "_deadline", None)
    monkeypatch.setattr(engine, "_MAX_COMMAND_OUTPUT", 1024)
    with pytest.raises(ValueError, match="output exceeds"):
        engine._run([sys.executable, "-I", "-c", "import sys; sys.stdout.write('x'*200000)"])


def test_worker_deadline_reaps_child(monkeypatch):
    created = []
    real_popen = subprocess.Popen

    def launch(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(engine.subprocess, "Popen", launch)
    monkeypatch.setattr(engine, "_deadline", time.monotonic() + .05)
    with pytest.raises(subprocess.TimeoutExpired):
        engine._run([sys.executable, "-I", "-c", "import time; time.sleep(20)"], timeout=10)
    assert created and created[0].poll() is not None


def test_worker_reports_command_failure_without_claiming_output(monkeypatch):
    monkeypatch.setattr(engine, "_deadline", None)
    with pytest.raises(RuntimeError, match="exit code 3"):
        engine._run([sys.executable, "-I", "-c", "raise SystemExit(3)"])
    assert engine._run([sys.executable, "-I", "-c", "print('local process fixture')"]).strip() == "local process fixture"


@pytest.mark.parametrize("failure", [None, "connect", "load", "close"])
def test_office_process_cleanup_and_macro_policy_on_each_outcome(monkeypatch, failure):
    events, properties = [], {}

    class Process:
        def poll(self):
            return None

        def terminate(self):
            events.append("terminate")

        def wait(self, timeout):
            events.append("wait")

    class Document:
        def close(self, deliver_ownership):
            events.append("close")
            if failure == "close":
                raise RuntimeError("close failed")

    class Desktop:
        def loadComponentFromURL(self, url, target, flags, values):
            properties.update((prop.Name, prop.Value) for prop in values)
            if failure == "load":
                raise RuntimeError("load failed")
            return Document()

    def connect(uno, pipe):
        if failure == "connect":
            raise RuntimeError("connect failed")
        return SimpleNamespace(ServiceManager=SimpleNamespace(createInstanceWithContext=lambda *args: Desktop()))

    uno = SimpleNamespace(createUnoStruct=lambda *args: SimpleNamespace())
    monkeypatch.setitem(sys.modules, "uno", uno)
    monkeypatch.setattr(engine, "_connect", connect)
    monkeypatch.setattr(engine.subprocess, "Popen", lambda *args, **kwargs: Process())
    if failure:
        with pytest.raises(RuntimeError, match="failed"):
            with engine._office_document("input.docx", readonly=True):
                pass
    else:
        with engine._office_document("input.docx", readonly=True):
            assert properties == {"Hidden": True, "ReadOnly": True, "MacroExecutionMode": 0, "UpdateDocMode": 0}
    assert events[-2:] == ["terminate", "wait"]


def test_worker_dispatch_binds_manifest_to_produced_bytes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    job = DocumentJob.create({"operation": "latex"})
    data = b"immutable source"
    (tmp_path / job.input_name).write_bytes(data)
    request = {"operation": "latex", "engine": "pdflatex", **job.manifest(),
               "input_bytes": len(data), "input_sha256": hashlib.sha256(data).hexdigest()}
    (tmp_path / "request.json").write_text(json.dumps(request))
    monkeypatch.setattr(engine, "_capabilities", lambda request: "fixture version 1")

    def operation(request):
        (tmp_path / request["output_name"]).write_bytes(b"%PDF-fixture")
        return {"engine": "fixture"}

    monkeypatch.setattr(engine, "latex", operation)
    assert engine.main() == 0
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["job_id"] == job.job_id and result["input_sha256"] == request["input_sha256"]
    assert result["output"]["sha256"] == hashlib.sha256(b"%PDF-fixture").hexdigest()
    assert result["output"]["bytes"] == len(b"%PDF-fixture")
    assert result["engine_version"] == "fixture version 1"


@pytest.mark.parametrize("selected", ["pdflatex", "tectonic"])
def test_latex_flags_disable_network_or_shell_and_confine_outputs(monkeypatch, tmp_path, selected):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "input.tex").write_text("plain source")
    calls = []

    def run(argv, timeout):
        calls.append(argv)
        (tmp_path / "input.pdf").write_bytes(b"%PDF-fixture")

    monkeypatch.setattr(engine, "_run", run)
    monkeypatch.setattr(engine.os, "environ", {})
    result = engine.latex({"engine": selected, "input_name": "input.tex", "output_name": "rendered.pdf", "timeout": 2})
    assert result["engine"] == selected
    assert (tmp_path / "rendered.pdf").exists()
    assert calls[0][0] == selected
    assert ("--only-cached" in calls[0] and "--untrusted" in calls[0]) if selected == "tectonic" else "-no-shell-escape" in calls[0]
    assert engine.os.environ == {"openin_any": "p", "openout_any": "p", "shell_escape": "f"}


def test_latex_external_file_directive_is_refused_before_engine(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "input.tex").write_text(r"\input{/private/customer-file}")
    monkeypatch.setattr(engine, "_run", lambda *args, **kwargs: pytest.fail("external input executed"))
    with pytest.raises(ValueError, match="external file/process"):
        engine.latex({"engine": "pdflatex", "input_name": "input.tex"})
