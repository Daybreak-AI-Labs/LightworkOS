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



def _isolation(monkeypatch, available):
    """Pretend the host does (or does not) allow ``unshare -rn``."""
    from maverick.tools import document_processing as dp

    monkeypatch.setattr(dp, "_NETWORK_ISOLATION", {})
    monkeypatch.setattr(dp.sys, "platform", "linux")
    monkeypatch.setattr(dp.shutil, "which", lambda name: "/usr/bin/unshare" if name == "unshare" else None)
    probes = []

    def probe(self, cmd, timeout=None, stdin=None):
        probes.append(cmd)
        from maverick.sandbox.local import ExecResult
        return ExecResult("", "", 0 if available else 1)
    return probes, probe


@pytest.mark.parametrize("available", [True, False])
def test_local_conversion_runs_only_inside_a_network_namespace(monkeypatch, tmp_path, available):
    # LibreOffice fetches linked images and objects; on the host that is
    # unchecked network access driven by an untrusted document.
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import document_processing as dp

    probes, probe = _isolation(monkeypatch, available)
    monkeypatch.setattr(LocalBackend, "exec", probe)
    assert dp.local_network_isolation() == (("/usr/bin/unshare", "-rn") if available else None)
    dp.local_network_isolation()
    assert probes == [["/usr/bin/unshare", "-rn", "true"]]  # probed once
    tool = office_convert(LocalBackend(tmp_path))
    ops = tool.input_schema["properties"]["op"]["enum"]
    assert ("to_pdf" in ops) is available
    assert available or "Docker, Podman or Kubernetes" in tool.description
    runs = []
    monkeypatch.setattr(LocalBackend, "exec", lambda self, cmd, timeout=None, stdin=None: runs.append(cmd))
    (tmp_path / "page.html").write_text('<img src="http://127.0.0.1:9/linked.png">')
    out = tool.fn({"op": "to_pdf", "input_path": "page.html"})
    assert out.startswith("ERROR") and not (tmp_path / "page.pdf").exists()
    if available:
        assert len(runs) == 1 and runs[0].startswith("/usr/bin/unshare -rn ")
    else:
        assert runs == [] and "Docker, Podman or Kubernetes" in out


def _python_with_uno():
    import shutil
    import subprocess
    import sys
    for python in (sys.executable, shutil.which("python3")):
        if python and subprocess.run([python, "-c", "import uno"], capture_output=True).returncode == 0:
            return python
    return None


def test_local_conversion_cannot_reach_a_listener(monkeypatch, tmp_path):
    import http.server
    import shutil
    import subprocess
    import sys
    import threading

    python = _python_with_uno()
    if not (sys.platform.startswith("linux") and shutil.which("soffice") and python
            and subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode == 0):
        pytest.skip("needs LibreOffice with Python UNO and unprivileged network namespaces")
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import document_processing as dp

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    monkeypatch.setattr(dp, "_NETWORK_ISOLATION", {})
    monkeypatch.setattr(dp.sys, "executable", python)
    (tmp_path / "page.html").write_text(
        f'<html><head><link rel="stylesheet" href="http://127.0.0.1:{port}/s.css"></head>'
        f'<body background="http://127.0.0.1:{port}/bg.png"><p>hello</p>'
        f'<img src="http://127.0.0.1:{port}/linked.png"></body></html>')
    try:
        out = office_convert(LocalBackend(tmp_path)).fn({"op": "to_pdf", "input_path": "page.html"})
    finally:
        server.shutdown()
    assert out.startswith("wrote "), out
    assert (tmp_path / "page.pdf").read_bytes().startswith(b"%PDF-")
    assert hits == []
