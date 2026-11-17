"""Tests for the Replicate tool (maverick.tools.replicate_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

from maverick.budget import Budget


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
    assert "op is required" in replicate_tool(budget=Budget()).fn({})


def test_replicate_missing_token(monkeypatch):
    monkeypatch.delenv("REPLICATE_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock(), post=MagicMock())
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool(budget=Budget()).fn({"op": "predict_get", "prediction_id": "p1"})
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
    out = replicate_tool(budget=Budget()).fn({
        "op": "run", "model": "stability-ai/sdxl", "input": {"prompt": "cat"},
    })
    assert "pred1" in out and "starting" in out


def test_replicate_cancel_dry_run(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.replicate_tool import replicate_tool
    out = replicate_tool(budget=Budget()).fn({"op": "cancel", "prediction_id": "p1"})
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
    out = replicate_tool(budget=Budget()).fn({"op": "models", "query": "upscaler"})
    assert out.startswith("ERROR") and checked and not request.called


def test_replicate_wait_is_charged_for_the_seconds_it_ran(monkeypatch):
    # A prediction polled to the end is charged for its reported compute time
    # at the [budget.tool_prices] per-second price; without waiting, the
    # seconds are unknown, so the per-call safety ceiling is charged.
    import os

    import pytest
    from maverick import config
    from maverick.budget import DEFAULT_UNPRICED_TOOL_CALL_DOLLARS

    home = os.environ["MAVERICK_HOME"]
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[budget.tool_prices]\nreplicate = { dollars = 0.01, per = "second" }\n')
    config.reset_config_cache()
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    done = {"id": "pred1", "status": "succeeded", "output": ["x.png"],
            "metrics": {"predict_time": 2.5}}
    get = MagicMock(side_effect=[_resp(200, {"latest_version": {"id": "v1"}}), _resp(200, done),
                                 _resp(200, {"latest_version": {"id": "v1"}})])
    _fake_httpx(monkeypatch, get=get, post=MagicMock(return_value=_resp(201, {"id": "pred1"})))
    from maverick.tools.replicate_tool import replicate_tool
    budget = Budget()
    tool = replicate_tool(budget=budget)
    assert "succeeded" in tool.fn({"op": "run", "model": "o/m", "input": {}, "wait": True})
    assert budget.dollars == pytest.approx(0.025)
    assert "created prediction" in tool.fn({"op": "run", "model": "o/m", "input": {}})
    assert budget.dollars == pytest.approx(0.025 + DEFAULT_UNPRICED_TOOL_CALL_DOLLARS)


def test_replicate_priced_per_second_cannot_spend_past_the_limit(monkeypatch):
    # The seconds a prediction runs are known only afterwards. The call holds
    # all the run has left, so nothing else can spend it, and a polled
    # prediction is cancelled once it has used that much. The charge is the
    # real time it ran.
    import os

    import pytest
    from maverick import config

    home = os.environ["MAVERICK_HOME"]
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[budget.tool_prices]\nreplicate = { dollars = 0.01, per = "second" }\n')
    config.reset_config_cache()
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    import maverick.tools.replicate_tool as rt
    clock = {"now": 1000.0}
    monkeypatch.setattr(rt.time, "time", lambda: clock["now"])
    monkeypatch.setattr(rt.time, "sleep", lambda s: clock.__setitem__("now", clock["now"] + 5))
    budget = Budget(max_dollars=0.15)
    held, posts = [], []

    def get(url, **_kw):
        if url.endswith("/models/o/m"):
            return _resp(200, {"latest_version": {"id": "v1"}})
        held.append(budget._reserved)
        if any(u.endswith("/cancel") for u in posts):
            return _resp(200, {"id": "p1", "status": "canceled", "metrics": {"predict_time": 15.0}})
        return _resp(200, {"id": "p1", "status": "processing"})

    def post(url, **_kw):
        posts.append(url)
        return _resp(201, {"id": "p1", "status": "starting"})

    _fake_httpx(monkeypatch, get=MagicMock(side_effect=get), post=MagicMock(side_effect=post))
    out = rt.replicate_tool(budget=budget).fn({"op": "run", "model": "o/m", "input": {}, "wait": True})
    assert "canceled" in out and posts[-1].endswith("/predictions/p1/cancel")
    assert held[0] == pytest.approx(0.15)
    assert budget.dollars == pytest.approx(0.15) and budget._reserved == 0


def test_replicate_unreported_seconds_charge_everything_held_and_say_so(monkeypatch):
    # Priced per second, a prediction not waited for never reports its
    # seconds. It is charged everything the run had left, not the small
    # per-call ceiling, and the cost line says why and how to fix it.
    import os

    import pytest
    from maverick import config

    home = os.environ["MAVERICK_HOME"]
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[budget.tool_prices]\nreplicate = { dollars = 0.01, per = "second" }\n')
    config.reset_config_cache()
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8_xx")
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, {"latest_version": {"id": "v1"}})),
                post=MagicMock(return_value=_resp(201, {"id": "p1", "status": "starting"})))
    from maverick.tools.replicate_tool import replicate_tool
    budget = Budget(max_dollars=0.5)
    assert "created prediction" in replicate_tool(budget=budget).fn({"op": "run", "model": "o/m", "input": {}})
    assert budget.dollars == pytest.approx(0.5)
    summary = budget.summary()
    assert "Replicate did not report its real usage" in summary
    assert "everything the run had left was charged" in summary
    assert "Prices for paid tool services" in summary
