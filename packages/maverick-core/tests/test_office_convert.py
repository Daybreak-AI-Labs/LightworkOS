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




class _Host:
    """A fake host: which launches succeed, and what the local exec saw."""

    def __init__(self, monkeypatch, *, namespace=0, uno=None):
        from maverick.sandbox.local import ExecResult, LocalBackend
        from maverick.tools import document_processing as dp

        self.calls, self.namespace, self.uno = [], namespace, uno or {}
        monkeypatch.setattr(dp, "_LOCAL_LAUNCH", {})
        monkeypatch.setattr(dp.sys, "platform", "linux")
        monkeypatch.setattr(dp.shutil, "which", lambda name: "/usr/bin/unshare" if name == "unshare" else None)
        monkeypatch.setattr(dp, "_uno_pythons", lambda: ["/venv/python", "/usr/bin/python3"])

        def exec_(backend, cmd, timeout=None, stdin=None):
            self.calls.append(cmd)
            if isinstance(cmd, str):  # the worker run itself
                return None
            code = self.namespace if cmd[2] == "true" else self.uno.get(cmd[2], 1)
            return ExecResult("", "", code)
        monkeypatch.setattr(LocalBackend, "exec", exec_)


def test_local_launch_needs_a_namespace_and_a_python_that_imports_uno(monkeypatch):
    from maverick.tools import document_processing as dp

    host = _Host(monkeypatch, uno={"/usr/bin/python3": 0})
    assert dp.local_convert_launch() == (("/usr/bin/unshare", "-rn", "/usr/bin/python3", "-I"), None)
    assert host.calls[1:] == [["/usr/bin/unshare", "-rn", py, "-I", "-c", "import uno"]
                              for py in ("/venv/python", "/usr/bin/python3")]
    host.calls.clear()
    assert dp.local_convert_launch()[0] and host.calls == []  # success is kept
    host = _Host(monkeypatch)
    assert dp.local_convert_launch() == (None, dp.NO_LOCAL_UNO)
    host = _Host(monkeypatch, namespace=1)
    assert dp.local_convert_launch() == (None, dp.NO_LOCAL_ISOLATION)


def test_a_failed_probe_is_retried_later_and_a_timeout_is_not_kept(monkeypatch):
    from maverick.tools import document_processing as dp

    clock = [1000.0]
    monkeypatch.setattr(dp.time, "monotonic", lambda: clock[0])
    host = _Host(monkeypatch, namespace=124)
    assert dp.local_convert_launch()[0] is None
    host.namespace = 0
    host.uno["/venv/python"] = 0
    assert dp.local_convert_launch()[0] is not None  # a timeout was not remembered
    host = _Host(monkeypatch, namespace=1)
    assert dp.local_convert_launch()[0] is None
    host.namespace = 0
    host.uno["/venv/python"] = 0
    assert dp.local_convert_launch()[0] is None  # a failure is kept briefly
    clock[0] += dp._FAILURE_RETRY_SECONDS + 1
    assert dp.local_convert_launch()[0] == ("/usr/bin/unshare", "-rn", "/venv/python", "-I")


@pytest.mark.parametrize("uno", [{"/usr/bin/python3": 0}, {}])
def test_local_conversion_is_offered_only_when_it_can_run(monkeypatch, tmp_path, uno):
    # LibreOffice fetches linked images and objects; on the host that is
    # unchecked network access driven by an untrusted document.
    from maverick.sandbox.local import LocalBackend

    host = _Host(monkeypatch, uno=uno)
    available = bool(uno)
    tool = office_convert(LocalBackend(tmp_path))
    assert ("to_pdf" in tool.input_schema["properties"]["op"]["enum"]) is available
    assert available or "Python bridge" in tool.description
    (tmp_path / "page.html").write_text('<img src="http://127.0.0.1:9/linked.png">')
    out = tool.fn({"op": "to_pdf", "input_path": "page.html"})
    assert out.startswith("ERROR") and not (tmp_path / "page.pdf").exists()
    runs = [cmd for cmd in host.calls if isinstance(cmd, str)]
    if available:
        assert len(runs) == 1 and runs[0].startswith("/usr/bin/unshare -rn /usr/bin/python3 -I engine.py")
    else:
        assert runs == [] and "Python bridge" in out


def test_other_backends_offer_conversion_only_where_it_runs(monkeypatch, tmp_path):
    from maverick.sandbox.docker import DockerBackend

    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    docker = office_convert(DockerBackend(workdir=tmp_path))
    assert "to_pdf" in docker.input_schema["properties"]["op"]["enum"]

    class SSHBackend:
        workdir = tmp_path
    other = office_convert(SSHBackend())
    assert other.input_schema["properties"]["op"]["enum"] == ["formats"]
    assert "Docker, Podman or Kubernetes" in other.description


def test_local_conversion_with_this_python_converts_or_is_not_offered(tmp_path):
    # No interpreter patching: whatever runs these tests is the real worker
    # candidate, and LibreOffice must not reach a local listener.
    import http.server
    import shutil
    import threading

    from maverick.sandbox.local import LocalBackend
    from maverick.tools import document_processing as dp

    dp._LOCAL_LAUNCH.clear()
    tool = office_convert(LocalBackend(tmp_path))
    launch, reason = dp.local_convert_launch()
    if launch is None:
        assert tool.input_schema["properties"]["op"]["enum"] == ["formats"] and reason in tool.description
        return
    if not shutil.which("soffice"):
        pytest.skip("LibreOffice is not installed")
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
    (tmp_path / "page.html").write_text(
        f'<html><head><link rel="stylesheet" href="http://127.0.0.1:{port}/s.css"></head>'
        f'<body background="http://127.0.0.1:{port}/bg.png"><p>hello</p>'
        f'<img src="http://127.0.0.1:{port}/linked.png"></body></html>')
    try:
        out = tool.fn({"op": "to_pdf", "input_path": "page.html"})
    finally:
        server.shutdown()
    assert out.startswith("wrote "), out
    assert (tmp_path / "page.pdf").read_bytes().startswith(b"%PDF-")
    assert hits == []
