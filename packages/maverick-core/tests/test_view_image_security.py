"""Vision calls use the run budget and configured model, within the workspace."""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

import pytest
from maverick.budget import Budget, BudgetExceeded
from maverick.tools import ToolRegistry
from maverick.tools.view_image import view_image


def test_view_image_passes_budget_and_uses_operator_model(tmp_path, monkeypatch):
    from maverick.llm import LLM

    (tmp_path / "image.png").write_bytes(b"image")
    monkeypatch.setenv("MAVERICK_VISION_MODEL", "configured:vision")
    seen = {}
    def init(self, model=None):
        seen["model"] = model
    def complete(self, **kwargs):
        seen["budget"] = kwargs["budget"]
        return SimpleNamespace(text="a picture")
    monkeypatch.setattr(LLM, "__init__", init)
    monkeypatch.setattr(LLM, "complete", complete)
    budget = Budget()
    tool = view_image(SimpleNamespace(workdir=tmp_path), budget=budget)
    assert tool.fn({"source": "image.png"}) == "a picture"
    assert seen == {"model": "configured:vision", "budget": budget}
    assert "model" not in tool.input_schema["properties"]
    assert "configured by the operator" in tool.fn({"source": "image.png", "model": "attacker:model"})
    assert "active run budget" in view_image(SimpleNamespace(workdir=tmp_path)).fn({"source": "image.png"})


def test_view_image_propagates_budget_stop_through_registry(tmp_path, monkeypatch):
    from maverick.llm import LLM

    (tmp_path / "image.png").write_bytes(b"image")
    monkeypatch.setattr(LLM, "__init__", lambda self, model=None: None)
    def stop(self, **kwargs):
        raise BudgetExceeded("run budget exhausted")
    monkeypatch.setattr(LLM, "complete", stop)
    registry = ToolRegistry()
    registry.register(view_image(SimpleNamespace(workdir=tmp_path), budget=Budget()))
    with pytest.raises(BudgetExceeded, match="run budget exhausted"):
        asyncio.run(registry.run("view_image", {"source": "image.png"}))


def test_view_image_confines_local_source_to_task_workspace(tmp_path, monkeypatch):
    from maverick.tools.view_image import _load_image

    workspace = tmp_path / "task"
    workspace.mkdir()
    (workspace / "inside.png").write_bytes(b"inside")
    (tmp_path / "outside.png").write_bytes(b"outside")
    monkeypatch.chdir(tmp_path)
    sandbox = SimpleNamespace(workdir=workspace)
    assert _load_image("inside.png", sandbox)[0] == b"inside"
    assert _load_image("../outside.png", sandbox) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_view_image_rejects_fifo_without_blocking(tmp_path):
    from maverick.tools.view_image import _load_image

    os.mkfifo(tmp_path / "image.png")
    assert _load_image("image.png", SimpleNamespace(workdir=tmp_path)) is None


class _FakeStreamResp:
    def __init__(self, chunks, headers):
        self._chunks = chunks
        self.headers = headers

    def raise_for_status(self):
        pass

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


def _patch(monkeypatch, resp):
    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "safe_client", lambda url, **k: _FakeClient(resp))


def test_view_image_caps_without_reading_whole_body(monkeypatch):
    from maverick.tools import view_image as vi
    consumed = {"chunks": 0}

    def chunks():
        for _ in range(100):  # 100 x 1 MiB available; cap is 20 MiB
            consumed["chunks"] += 1
            yield b"x" * (1024 * 1024)

    _patch(monkeypatch, _FakeStreamResp(chunks(), {"content-type": "image/png"}))
    assert vi._load_image("https://example.com/big.png") is None
    # Stopped shortly after crossing 20 MiB -- did NOT read all 100 chunks.
    assert consumed["chunks"] <= 22


def test_view_image_rejects_on_content_length_without_streaming(monkeypatch):
    from maverick.tools import view_image as vi
    pulled = {"n": 0}

    def chunks():
        pulled["n"] += 1
        yield b"x"

    headers = {"content-type": "image/png", "content-length": str(50 * 1024 * 1024)}
    _patch(monkeypatch, _FakeStreamResp(chunks(), headers))
    assert vi._load_image("https://example.com/huge.png") is None
    assert pulled["n"] == 0  # rejected on content-length, never streamed


def test_view_image_returns_bytes_and_mime_on_normal_body(monkeypatch):
    from maverick.tools import view_image as vi
    resp = _FakeStreamResp([b"\x89PNG", b"data"], {"content-type": "image/png"})
    _patch(monkeypatch, resp)
    out = vi._load_image("https://example.com/ok.png")
    assert out == (b"\x89PNGdata", "image/png")


def test_local_image_uses_the_supplied_workspace(tmp_path, monkeypatch):
    from maverick.tools.view_image import _load_image

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "image.png").write_bytes(b"workspace image")
    (tmp_path / "outside.png").write_bytes(b"outside image")
    monkeypatch.chdir(tmp_path)

    assert _load_image("image.png", workdir=workspace) == (b"workspace image", "image/png")
    assert _load_image("../outside.png", workdir=workspace) is None


# ---------- view_image ----------

def test_view_image_rejects_empty_source():
    from maverick.tools.view_image import view_image
    assert "source is required" in view_image().fn({"source": ""}).lower()


def test_view_image_missing_file(tmp_path):
    from types import SimpleNamespace

    from maverick.budget import Budget
    from maverick.tools.view_image import view_image
    out = view_image(sandbox=SimpleNamespace(workdir=tmp_path), budget=Budget(max_dollars=1)).fn(
        {"source": str(tmp_path / "missing.png")}
    )
    assert "could not load" in out.lower()
