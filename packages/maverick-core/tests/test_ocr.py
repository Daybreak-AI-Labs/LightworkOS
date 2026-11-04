"""ocr extract_url must stream the HTTP body with a hard byte ceiling, not
buffer the whole thing into memory.

Regression: the fetch used `safe_get`, which materializes `resp.content`
(the entire body) inside the client -- so a model-supplied URL to a multi-GB
or endless resource was fully loaded into memory with no cap at all. It now
streams via `safe_client(...).stream` with a content-length precheck and an
incremental 50 MiB ceiling, mirroring view_image / pdf_reader.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

from maverick.tools import ocr as ocr_mod


class _FakeStreamResp:
    def __init__(self, chunks, headers, status_code=200):
        self._chunks = chunks
        self.headers = headers
        self.status_code = status_code

    def iter_bytes(self):
        yield from self._chunks

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeClient:
    def __init__(self, resp):
        self._resp = resp

    def stream(self, method, url):
        return self._resp

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _SB:
    def __init__(self, workdir):
        self.workdir = workdir


def _patch(monkeypatch, resp):
    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "safe_client", lambda url, **k: _FakeClient(resp))


def test_extract_url_caps_without_reading_whole_body(monkeypatch):
    consumed = {"chunks": 0}

    def chunks():
        for _ in range(200):  # 200 x 1 MiB available; cap is 50 MiB
            consumed["chunks"] += 1
            yield b"x" * (1024 * 1024)

    _patch(monkeypatch, _FakeStreamResp(chunks(), {"content-type": "image/png"}))
    out = ocr_mod._op_extract_url(
        "https://example.com/big.png", "eng", "tesseract", "", None)
    assert out.startswith("ERROR") and "cap" in out
    # Stopped shortly after crossing 50 MiB -- did NOT read all 200 chunks.
    assert consumed["chunks"] <= 52


def test_extract_url_rejects_on_content_length_without_streaming(monkeypatch):
    pulled = {"n": 0}

    def chunks():
        pulled["n"] += 1
        yield b"x"

    headers = {"content-type": "image/png",
               "content-length": str(200 * 1024 * 1024)}
    _patch(monkeypatch, _FakeStreamResp(chunks(), headers))
    out = ocr_mod._op_extract_url(
        "https://example.com/huge.png", "eng", "tesseract", "", None)
    assert out.startswith("ERROR") and "cap" in out
    assert pulled["n"] == 0  # rejected on content-length, never streamed


def test_extract_url_normal_body_reaches_ocr(monkeypatch, tmp_path):
    seen = {}

    def fake_extract(path, lang, backend, hf_model, sandbox):
        p = Path(path)
        seen["blob"] = p.read_bytes()
        seen["suffix"] = p.suffix
        return "OCRTEXT"

    monkeypatch.setattr(ocr_mod, "_op_extract", fake_extract)
    _patch(monkeypatch,
           _FakeStreamResp([b"\x89PNG", b"img"], {"content-type": "image/png"}))
    out = ocr_mod._op_extract_url(
        "https://example.com/ok.png", "eng", "tesseract", "", _SB(tmp_path))
    assert out == "OCRTEXT"
    assert seen["blob"] == b"\x89PNGimg"
    assert seen["suffix"] == ".png"


def test_extract_url_http_error_status(monkeypatch):
    _patch(monkeypatch,
           _FakeStreamResp([], {"content-type": "image/png"}, status_code=404))
    out = ocr_mod._op_extract_url(
        "https://example.com/gone.png", "eng", "tesseract", "", None)
    assert out.startswith("ERROR: image fetch 404")


def _sb(tmp_path):
    """A stand-in sandbox whose workdir is the test's tmp_path, so the
    spec-path confinement allows the in-workspace spec file."""
    return types.SimpleNamespace(workdir=str(tmp_path))


# ---------- OCR tool ----------

def test_ocr_requires_op():
    from maverick.tools.ocr import ocr
    assert "op is required" in ocr().fn({})


def test_ocr_extract_validates_path():
    from maverick.tools.ocr import ocr
    out = ocr().fn({"op": "extract"})
    assert "requires path" in out


def test_ocr_missing_tesseract(tmp_path, monkeypatch):
    from test_support.document_jobs import install_backend

    backend, state = install_backend(monkeypatch, tmp_path, mode="missing_engine")
    img = tmp_path / "x.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.chdir(tmp_path)
    from maverick.tools.ocr import ocr
    out = ocr(backend).fn({"op": "extract", "path": str(img)})
    assert "engine not installed in selected backend" in out
    assert state["requests"][0]["operation"] == "image_ocr"


def test_ocr_extract_runs_tesseract(tmp_path, monkeypatch):
    from test_support.document_jobs import install_backend

    backend, state = install_backend(monkeypatch, tmp_path)
    img = tmp_path / "x.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.chdir(tmp_path)
    from maverick.tools.ocr import ocr
    out = ocr(backend).fn({"op": "extract", "path": str(img), "lang": "eng+deu"})
    assert out == "OCR text 120000"
    assert state["requests"][0]["operation"] == "image_ocr"
    assert state["requests"][0]["language"] == "eng+deu"
    assert len(state["calls"]) == 1


def test_ocr_hf_backend_requires_token(tmp_path, monkeypatch):
    img = tmp_path / "x.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HUGGINGFACE_API_TOKEN", raising=False)
    fake_httpx = types.ModuleType("httpx")
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.ocr import ocr
    out = ocr().fn({"op": "extract", "path": str(img), "backend": "hf"})
    assert "HUGGINGFACE_API_TOKEN" in out


def test_ocr_hf_cannot_borrow_operator_token_in_authenticated_enterprise(
    tmp_path, monkeypatch,
):
    import asyncio

    from maverick.tools import ToolRegistry
    from maverick.tools.ocr import ocr

    img = tmp_path / "x.png"
    img.write_bytes(b"fake")
    monkeypatch.setenv("HUGGINGFACE_API_TOKEN", "operator-global-secret")
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    called = []
    monkeypatch.setattr(
        "maverick.tools._ssrf.safe_client",
        lambda *_a, **_k: called.append(True),
    )
    reg = ToolRegistry(principal="user:alice")
    reg.register(ocr(_sb(tmp_path)))

    out = asyncio.run(reg.run("ocr", {
        "op": "extract", "path": str(img), "backend": "hf",
    }))

    assert out.startswith("REFUSED (credentials)")
    assert "operator-global-secret" not in out
    assert called == []


def test_ocr_extract_blocks_path_escape():
    from maverick.tools.ocr import ocr
    out = ocr().fn({"op": "extract", "path": "/etc/hosts"})
    assert "path escapes workspace" in out


def test_ocr_extract_url_blocks_private():
    # safe_client resolves 127.0.0.1, sees it's non-public, and refuses (offline).
    from maverick.tools.ocr import ocr
    out = ocr().fn({"op": "extract_url", "url": "http://127.0.0.1:8000/a.png"})
    assert "refusing to fetch" in out and "127.0.0.1" in out


def test_ocr_extract_url_uses_workspace_tempfile(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/tesseract")
    monkeypatch.setattr("maverick.tools.ocr._run_tesseract", lambda *_a, **_k: "ok")

    class _Resp:
        status_code = 200
        headers = {"content-type": "image/png"}

        def iter_bytes(self):
            yield b"\x89PNG\r\n\x1a\n"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Client:
        def stream(self, method, url):
            return _Resp()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    # Patch the SSRF-safe client (pins the connection) rather than httpx.
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", lambda url, **kw: _Client())

    from maverick.tools.ocr import ocr
    out = ocr().fn({"op": "extract_url", "url": "http://example.com/a.png"})
    assert out == "ok"
