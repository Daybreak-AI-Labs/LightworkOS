"""Tests for the Replicate tool (maverick.tools.replicate_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def test_replicate_rejects_traversal_model():
    from maverick.tools.replicate_tool import _op_run
    assert "invalid model" in _op_run({"model": "../predictions/x"})
    assert "invalid model" in _op_run({"model": "noslash"})


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for n, v in methods.items():
        setattr(mod, n, v)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body, *, text=None):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = text if text is not None else str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = text if text is not None else str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode())
    return r


# ---------- Replicate ----------

def test_replicate_requires_op():
    from maverick.tools.replicate_tool import replicate_tool
    assert "op is required" in replicate_tool().fn({})


def test_replicate_missing_token(monkeypatch):
    monkeypatch.delenv("REPLICATE_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock(), post=MagicMock())
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool().fn({"op": "predict_get", "prediction_id": "p1"})
    assert "REPLICATE_API_TOKEN" in out


def test_replicate_run_creates_prediction(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    # version resolve (GET) then create (POST)
    get_resp = _resp(200, {"latest_version": {"id": "ver123"}})
    post_resp = _resp(201, {"id": "pred1", "status": "starting"})
    _fake_httpx(monkeypatch,
                get=MagicMock(return_value=get_resp),
                post=MagicMock(return_value=post_resp))
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool().fn({
        "op": "run", "model": "stability-ai/sdxl", "input": {"prompt": "cat"},
    })
    assert "pred1" in out and "starting" in out


def test_replicate_cancel_dry_run(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool().fn({"op": "cancel", "prediction_id": "p1"})
    assert "DRY RUN" in out


def test_replicate_models_search_passes_the_egress_check(monkeypatch):
    import maverick.egress_guard as egress_guard

    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    request = MagicMock()
    _fake_httpx(monkeypatch, request=request)
    checked: list[str] = []

    def _deny(url):
        checked.append(url)
        raise RuntimeError("egress denied")

    monkeypatch.setattr(egress_guard, "_check", _deny)
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool().fn({"op": "models", "query": "upscaler"})
    assert out.startswith("ERROR") and checked and not request.called
