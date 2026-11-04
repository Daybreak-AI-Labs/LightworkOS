"""'Get two viewpoints': the debate runs only as an admitted, capped, audited run."""
from __future__ import annotations

import json
import os
import re
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import config
from maverick.paths import tenant_scope
from maverick_dashboard import rbac
from maverick_dashboard import viewpoints_api as api

TENANT = "viewpoints-workspace"
JUDGE = json.dumps({"winner": "Skeptic", "reason": "The risks outweigh the gain.", "key_argument": "Mondays are busy."})


class FakeLLM:
    """Stands in at the model boundary; spends through the real Budget."""

    made: list = []
    calls: list = []
    budgets: list = []
    fail: Exception | None = None

    def __init__(self, model=None):
        self.model = model
        FakeLLM.made.append(model)

    def _provider_client_config(self, provider):
        # The review binds the current connection's identity, not its secret.
        return SimpleNamespace(fingerprint="test-connection:" + provider)

    def complete(self, *, system, messages, budget=None, max_tokens=4096, model=None, **_):
        FakeLLM.calls.append(self.model)
        if FakeLLM.fail is not None:
            raise FakeLLM.fail
        FakeLLM.budgets.append(budget)
        budget.check()
        budget.record_tokens(400, 120)
        text = JUDGE if "impartial judge" in system else "Argument about " + messages[0]["content"][10:40]
        return SimpleNamespace(text=text)


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "private"
    home.mkdir()
    cfg = tmp_path / "config.toml"
    cfg.write_text("")
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.reset_config_cache()
    rbac.set_role("user:owner", "operator")
    rbac.set_role("user:viewer", "viewer")
    import maverick.audit as audit
    import maverick.llm as llm
    from maverick_dashboard import app as dashboard
    dashboard._goal_times.clear()
    dashboard._goal_times_global.clear()
    FakeLLM.made, FakeLLM.calls, FakeLLM.budgets, FakeLLM.fail = [], [], [], None
    roles, rows = [], []
    monkeypatch.setattr(llm, "LLM", FakeLLM)
    monkeypatch.setattr(llm, "model_for_role", lambda role: roles.append(role) or "anthropic:configured-analyst")
    from maverick_dashboard import _shared
    from maverick_dashboard import viewpoints_requests as native
    monkeypatch.setattr(native, "model_for_role", llm.model_for_role)
    monkeypatch.setattr(api, "require_provider_or_400", lambda role=None: None)
    monkeypatch.setattr(_shared, "require_provider_or_400", lambda role=None: None)
    monkeypatch.setattr(audit, "audit_event", lambda kind, **data: rows.append({"kind": kind, **data}) or True)
    application = FastAPI()

    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=TENANT):
            return await call_next(request)

    application.include_router(api.router)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield SimpleNamespace(client=client, cfg=cfg, roles=roles, audit=rows)
    config.reset_config_cache()


class _Answer:
    """The saved answer of an original request, read like a response."""

    def __init__(self, body):
        self.status_code, self._body = 200, body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _ask(env, *, headers=None, question="Should we move the team meeting to Mondays?", **extra):
    """Review and start a viewpoints request as Chat does, then read its saved answer."""
    import time

    client = env.client
    current = client.get("/api/v1/viewpoints", headers=headers)
    if current.status_code != 200:
        return current
    state = current.json()
    review = client.post("/api/v1/viewpoints/review", headers=headers, json={
        "question": question, **extra, "context": state["context"], "revision": state.get("revision", "0" * 64)})
    if review.status_code != 200:
        return review
    started = client.post("/api/v1/viewpoints/apply", headers=headers,
                          json={"token": review.json()["token"], "confirmed": True})
    if started.status_code != 200:
        return started
    original = "/api/v1/viewpoints/requests/" + review.json()["operation"]
    body, deadline = started.json(), time.time() + 15
    while not body["confirmed"]:
        assert time.time() < deadline, body
        time.sleep(0.02)
        body = client.get(original, headers=headers).json()
    return _Answer(body["result"])


def _runs(env):
    return [row for row in env.audit if row["kind"] == "viewpoints_run"]


def test_debate_runs_on_role_model_under_capped_bound_budget_and_is_settled(env):
    from maverick.quotas import UsageLedger

    response = _ask(env, rounds=1)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["ran"] is True and data["verdict"] == "against" and data["rounds"] == 1
    assert [turn["side"] for turn in data["turns"]] == ["for", "against"]
    assert data["reason"] == "The risks outweigh the gain." and data["key_point"] == "Mondays are busy."
    assert data["cost"] > 0
    assert set(env.roles) == {"analyst"} and set(FakeLLM.made) == {"anthropic:configured-analyst"}
    assert FakeLLM.calls == ["anthropic:configured-analyst"] * 3
    budget = FakeLLM.budgets[0]
    assert len(FakeLLM.budgets) == 3 and all(b is budget for b in FakeLLM.budgets)
    assert budget.max_dollars == api.MAX_DOLLARS
    assert budget._organization_principal == "user:owner"
    assert [row["phase"] for row in _runs(env)] == ["start", "end"]
    assert all(row["actor"] == "user:owner" for row in _runs(env))
    assert _runs(env)[1]["outcome"] == "finished"
    # Settled to the usage ledger that spending limits read, in this workspace only.
    with tenant_scope(tenant=TENANT):
        assert UsageLedger().usage("user:owner")["dollars"] == pytest.approx(budget.dollars)
    with tenant_scope(tenant="another-workspace"):
        assert UsageLedger().usage("user:owner")["dollars"] == 0


def test_a_lower_configured_task_cap_wins(env):
    env.cfg.write_text("[budget]\nmax_dollars = 0.25\n")
    config.reset_config_cache()
    assert _ask(env).json()["ran"] is True
    assert FakeLLM.budgets[0].max_dollars == 0.25


def test_spending_limit_reached_before_start_runs_nothing(env, monkeypatch):
    import maverick.spending_limits as limits

    message = "Your spending limit of $5.00 per day has been reached ($5.00 spent today)."
    monkeypatch.setattr(limits, "start_refusal", lambda principal: message)
    refused = _ask(env)
    assert refused.status_code == 409 and refused.json() == {"detail": message}
    assert FakeLLM.calls == [] and _runs(env) == []


def test_limits_and_caps_hit_mid_run_stop_it_plainly(env):
    from maverick.budget import BudgetExceeded
    from maverick.spending_limits import SpendingLimitReached

    FakeLLM.fail = SpendingLimitReached("The workspace spending limit has been reached.")
    assert _ask(env).json() == {"ran": False, "message": "The workspace spending limit has been reached."}
    FakeLLM.fail = BudgetExceeded("projected $1.20 > $1.00")
    data = _ask(env).json()
    assert data["ran"] is False and "at most $1.00" in data["message"]
    assert [row["outcome"] for row in _runs(env) if row["phase"] == "end"] == ["stopped", "stopped"]


def test_emergency_stop_and_audit_refusal_start_nothing(env, monkeypatch):
    import maverick.audit as audit
    from maverick import killswitch
    from maverick.audit import AuditRefused

    def halted(**_):
        raise killswitch.Halted("synthetic stop", "manual")

    monkeypatch.setattr(killswitch, "check", halted)
    halted_answer = _ask(env)
    assert halted_answer.status_code == 409 and "emergency stop" in halted_answer.json()["detail"]
    monkeypatch.setattr(killswitch, "check", lambda **_: None)

    def refuse(kind, **data):
        raise AuditRefused("signed chain required")

    monkeypatch.setattr(audit, "audit_event", refuse)
    data = _ask(env).json()
    assert data["ran"] is False and "activity log" in data["message"]
    assert FakeLLM.calls == []


def test_permission_origin_validation_and_provider_setup(env, monkeypatch):
    assert _ask(env, **{}).status_code == 200
    FakeLLM.calls.clear()
    viewer = _ask(env, question="Is this wise?", headers={"X-Test-User": "viewer"})
    assert viewer.status_code == 403
    foreign = _ask(env, question="Is this wise?", headers={"Origin": "https://elsewhere.example"})
    assert foreign.status_code == 403
    assert _ask(env, question="  \n   ").status_code == 422
    assert _ask(env, rounds=4).status_code == 422
    assert _ask(env, model="anthropic:chosen-by-browser").status_code == 422
    assert FakeLLM.calls == []

    def missing(role=None):
        raise HTTPException(400, "anthropic route missing: api_key")

    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "require_provider_or_400", missing)
    response = _ask(env)
    assert response.status_code == 400 and "api_key" not in response.text
    assert "AI is not connected for viewpoints" in response.json()["detail"]


def test_failed_turns_and_unreadable_verdicts_read_plainly(env, monkeypatch):
    calls = {"n": 0}

    def flaky(self, *, system, messages, budget=None, **_):
        calls["n"] += 1
        if "impartial judge" in system:
            return SimpleNamespace(text="not a verdict")
        if calls["n"] == 1:
            raise RuntimeError("provider exploded at /v1/messages")
        return SimpleNamespace(text="A fair point.")

    monkeypatch.setattr(FakeLLM, "complete", flaky)
    data = _ask(env, rounds=1).json()
    assert data["turns"][0]["text"] == "This side could not answer this time."
    assert "exploded" not in json.dumps(data)
    assert data["verdict"] == "draw" and "couldn't be read" in data["reason"]


def test_chat_page_offers_two_viewpoints_plainly(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import onboarding_state

    from test_support.plain_language import developer_terms

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard._world_cache.clear()
    def verdict(name):
        return lambda: {"verdict": name, "verdict_label": "", "badge_class": "ok", "reason": "", "next_action": None,
                        "summary": "", "providers": [], "configured_count": 0, "connected_count": 0, "total": 0}

    monkeypatch.setattr(onboarding_state, "workspace_readiness", verdict("ready"))
    client = TestClient(dashboard.app, base_url="http://127.0.0.1")
    page = client.get("/chat")
    assert page.status_code == 200
    assert 'id="vp-form"' in page.text and "Get two viewpoints" in page.text
    assert 'id="vp-rounds"' in page.text and 'for="vp-question"' in page.text
    assert "/static/lightwork-viewpoints.js" in page.text
    assert developer_terms(page.text) == []
    script = client.get("/static/lightwork-viewpoints.js")
    assert script.status_code == 200 and "/api/v1/viewpoints" in script.text
    monkeypatch.setattr(onboarding_state, "workspace_readiness", verdict("not_ready"))
    # Without a ready AI connection the saved answers stay readable, but nothing
    # can start until the page reads a ready connection; setup is offered.
    not_ready = client.get("/chat").text
    assert 'id="vp-saved"' in not_ready and 'id="vp-setup"' in not_ready
    assert re.search(r'<button type="submit" class="btn btn--primary" id="vp-run" disabled>', not_ready)
