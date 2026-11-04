"""Dispatch a goal AS a fleet agent from the operator console.

POST /api/v1/fleets/<fleet>/run runs a governed goal under the agent's RBAC
role capability + its own audit principal (``agent:<fleet>.<agent>``),
mirroring ``maverick fleet run`` -- so the oversight control plane governs the
work. Owner-scoped; mutating POST carries a same-origin Origin (CSRF contract).

Hermetic: OIDC off, HOME/MAVERICK_HOME + DEFAULT_DB isolated, the route-readiness
gate and rate limiter stubbed, and run_goal_in_thread replaced with a capturing
stub so no real goal runs.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _save_team(client, key):
    """Review and save a department team the way Update team does."""
    context = client.get("/api/v1/department-team-updates/context").json()["context"]
    review = client.post("/api/v1/department-team-updates/review",
                         json={"department": key, "expected_context": context})
    assert review.status_code == 200, review.text
    saved = client.post("/api/v1/department-team-updates/save",
                        json={"token": review.json()["token"], "confirmed": True})
    from maverick.fleet import load_fleet
    return review.json()["preview"], saved, load_fleet("dept-" + key)


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick_dashboard.api as api
    monkeypatch.setattr(api, "require_provider_or_400", lambda **kwargs: None)
    import maverick_dashboard.app as dash_app
    monkeypatch.setattr(dash_app, "check_goal_rate_limit", lambda request: None)


def _save_fleet(owner=""):
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    save_fleet(Fleet(name="acme", owner=owner, agents=(
        FleetAgent("researcher", "analyst", "digs through sources"),
        FleetAgent("coder", "engineer"),
    )))


def _enable_oidc_principal_map(monkeypatch):
    import maverick_dashboard.auth as auth
    from maverick_dashboard import rbac

    rbac.set_role("user:dana", "operator")
    rbac.set_role("user:eve", "operator")

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        ),
    )


def _stub_runner(monkeypatch):
    calls: list[dict] = []

    def _stub(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return "ok"

    import maverick.runner as runner
    monkeypatch.setattr(runner, "run_goal_in_thread", _stub)
    return calls


def test_dispatch_runs_agent_under_role_capability(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    _save_fleet(owner="user:dana")
    calls = _stub_runner(monkeypatch)

    r = _client().post("/api/v1/fleets/acme/run",
                       headers={"Authorization": "Bearer dana"},
                       json={"agent": "coder", "prompt": "ship the build"})
    assert r.status_code == 201, r.text
    body = r.json()
    gid = body["goal_id"]
    assert body["principal"] == "agent:acme.coder"
    assert body["role"] == "engineer"

    # Resource ownership and exact agent execution authority are both durable.
    from maverick.world_model import WorldModel
    g = WorldModel(tmp_path / "world.db").get_goal(gid)
    assert g is not None and g.owner == "user:dana"
    assert g.execution_principal == "agent:acme.coder"

    # the run is recorded against the fleet for the supervisor trail
    from maverick.fleet import load_runs
    assert any(rr["agent"] == "coder" and rr["goal_id"] == gid
               for rr in load_runs("acme"))

    # the background runner got the role-scoped capability + the agent principal
    assert calls, "expected run_goal_in_thread to be scheduled"
    kw = calls[0]["kwargs"]
    assert kw["user_id"] == "agent:acme.coder"
    assert kw["capability"] is not None
    assert kw["capability"].principal == "agent:acme.coder"


def test_authenticated_owner_can_observe_real_principal_bound_fleet_run(
    monkeypatch,
    tmp_path,
):
    """Exercise the route through the real runner binding boundary.

    Only the expensive swarm body is replaced; ``run_goal_in_thread`` performs
    its real durable principal check before the stub marks the row complete.
    """
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    _save_fleet(owner="user:dana")

    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, trace_pin
    from maverick import sandbox as sandbox_mod

    observed: dict[str, str] = {}

    class _Sandbox:
        def close(self):
            return None

    def _finish_without_provider(*args, **kwargs):
        world = args[1]
        goal_id = args[3]
        goal = world.get_goal(goal_id)
        observed["owner"] = goal.owner
        observed["execution_principal"] = goal.execution_principal
        observed["capability_principal"] = kwargs["capability"].principal
        world.set_goal_status(goal_id, "done", result="finished")
        return "DONE."

    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", _Sandbox)
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kw: budget_mod.Budget())
    monkeypatch.setattr(trace_pin, "pin_trace", lambda *_a, **_kw: None)
    monkeypatch.setattr(orchestrator, "run_goal_sync", _finish_without_provider)

    client = _client()
    owner_headers = {
        "Authorization": "Bearer dana",
        "Origin": "http://127.0.0.1",
    }
    response = client.post(
        "/api/v1/fleets/acme/run",
        json={"agent": "coder", "prompt": "ship the governed build"},
        headers=owner_headers,
    )
    assert response.status_code == 201, response.text
    goal_id = response.json()["goal_id"]

    assert observed == {
        "owner": "user:dana",
        "execution_principal": "agent:acme.coder",
        "capability_principal": "agent:acme.coder",
    }
    visible = client.get(
        f"/api/v1/goals/{goal_id}",
        headers={"Authorization": "Bearer dana"},
    )
    assert visible.status_code == 200, visible.text
    assert visible.json()["status"] == "done"
    hidden = client.get(
        f"/api/v1/goals/{goal_id}",
        headers={"Authorization": "Bearer eve"},
    )
    assert hidden.status_code == 404


def test_dispatch_attenuates_legacy_bad_roles_to_caller_capability(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "role_assignments": {"user:eve": "restricted"},
            "roles": {"restricted": {"allow_tools": ["read_file"]}},
        },
    )
    import maverick_dashboard.api as api
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:eve")
    monkeypatch.setattr(api, "is_dashboard_admin", lambda p: False)
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    save_fleet(Fleet(name="acme", owner="user:eve", agents=(
        FleetAgent("blank", ""),
        FleetAgent("ghost", "ghost"),
    )))
    calls = _stub_runner(monkeypatch)

    for agent in ("blank", "ghost"):
        r = _client().post(
            "/api/v1/fleets/acme/run",
            json={"agent": agent, "prompt": "try to run shell"},
        )
        assert r.status_code == 201, r.text

    for agent, call in zip(("blank", "ghost"), calls, strict=True):
        cap = call["kwargs"]["capability"]
        assert cap.principal == f"agent:acme.{agent}"
        assert cap.permits("read_file") is True
        assert cap.permits("shell") is False


def test_dispatch_preserves_explicit_zero_budget(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    calls = _stub_runner(monkeypatch)

    r = _client().post(
        "/api/v1/fleets/acme/run",
        json={"agent": "coder", "prompt": "do no paid work", "max_dollars": 0.0},
    )
    assert r.status_code == 201, r.text
    assert calls, "expected the local dispatcher to be scheduled"
    assert calls[0]["kwargs"]["max_dollars"] == 0.0


# With no operator ceiling the request is still bounded by the REST safety ceiling
# ($100) POST /goals applies; it must not pass straight through.
@pytest.mark.parametrize("ceiling,expected", [(None, 100.0), (25.0, 25.0), (0.0, 0.0)])
def test_dispatch_uses_only_configured_budget_ceiling(monkeypatch, tmp_path, ceiling, expected):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    calls = _stub_runner(monkeypatch)
    from maverick import runner

    monkeypatch.setattr(runner, "configured_goal_ceiling_dollars", lambda: ceiling)
    response = _client().post("/api/v1/fleets/acme/run", json={
        "agent": "coder", "prompt": "run the authorized work", "max_dollars": 10_000.0,
    })
    assert response.status_code == 201, response.text
    assert len(calls) == 1
    assert calls[0]["kwargs"]["max_dollars"] == expected


def test_dispatch_unknown_agent_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    _stub_runner(monkeypatch)
    r = _client().post("/api/v1/fleets/acme/run",
                       json={"agent": "ghost", "prompt": "x"})
    assert r.status_code == 404


def test_dispatch_unknown_fleet_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _stub_runner(monkeypatch)
    r = _client().post("/api/v1/fleets/nope/run",
                       json={"agent": "coder", "prompt": "x"})
    assert r.status_code == 404


def test_dispatch_requires_prompt(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    _stub_runner(monkeypatch)
    r = _client().post("/api/v1/fleets/acme/run",
                       json={"agent": "coder", "prompt": "   "})
    assert r.status_code == 400


def test_dispatch_owner_scoped_404_for_non_owner(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet(owner="user:dana")
    _stub_runner(monkeypatch)
    # A non-owner, non-admin caller can't dispatch to (or even see) the fleet.
    import maverick_dashboard.api as api
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:eve")
    monkeypatch.setattr(api, "is_dashboard_admin", lambda p: False)
    r = _client().post("/api/v1/fleets/acme/run",
                       json={"agent": "coder", "prompt": "x"})
    assert r.status_code == 404  # cross-owner fleet hidden, never revealed


def test_fleets_page_has_run_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    text = _client().get("/fleets").text
    assert 'class="fleet-run-form' in text
    assert "/api/v1/fleets/" in text  # the dispatch target


@pytest.mark.parametrize("caller", ["local", "admin"])
def test_other_owner_fleet_mutations_are_hidden_before_effects(monkeypatch, tmp_path, caller):
    _isolate(monkeypatch, tmp_path)
    _save_fleet(owner="user:dana")
    calls = _stub_runner(monkeypatch)
    headers = {}
    if caller == "admin":
        _enable_oidc_principal_map(monkeypatch)
        from maverick_dashboard import rbac
        rbac.set_role("user:boss", "admin")
        headers = {"Authorization": "Bearer boss"}
    import maverick_dashboard.api as api
    provider_checks = []
    monkeypatch.setattr(api, "require_provider_or_400", lambda: provider_checks.append(True))
    client = _client()
    assert client.post("/api/v1/fleets/acme/run", headers=headers,
                       json={"agent": "coder", "prompt": "x"}).status_code == 404
    assert client.post("/api/v1/fleets/acme/agents", headers=headers,
                       json={"pack": "gtm_demand_gen", "role": "researcher"}).status_code == 404
    assert client.post("/api/v1/fleets", headers=headers,
                       json={"name": "acme", "agents": []}).status_code == 404
    assert client.delete("/api/v1/fleets/acme", headers=headers).status_code == 404
    from maverick.fleet import load_fleet, load_runs
    fleet = load_fleet("acme")
    assert fleet.owner == "user:dana" and len(fleet.agents) == 2
    assert not calls and not provider_checks and not load_runs("acme")


def test_deployed_department_agent_runs_under_domain_capability(monkeypatch, tmp_path):
    """A department-deployed agent carries its specialist pack and runs under that
    pack's capability envelope (least privilege per domain), not just its role."""
    _isolate(monkeypatch, tmp_path)
    calls = _stub_runner(monkeypatch)
    c = _client()

    # Self-host fail-open entitlement: deploy the Sales & GTM department.
    _preview, r, fleet = _save_team(c, "sales_gtm")
    assert r.status_code == 200, r.text
    agent = next(a for a in fleet.agents if a.name == "gtm_deal_inspection")
    assert agent.domain == "gtm_deal_inspection"  # bound to its pack
    assert not any(a.name == "gtm_demand_gen" for a in fleet.agents)

    rr = c.post("/api/v1/fleets/dept-sales_gtm/run",
                json={"agent": "gtm_deal_inspection", "prompt": "inspect pipeline risks"})
    assert rr.status_code == 201, rr.text

    # The dispatched capability enforces the pack's hard denials (shell/write).
    cap = calls[-1]["kwargs"]["capability"]
    assert "shell" in cap.deny_tools
    assert "write_file" in cap.deny_tools


# --- A department specialist runs AS its specialist -------------------------
#
# Deploying a department hands each pack's agent its pack name in
# ``FleetAgent.domain``. Giving that agent a task used to queue a goal with no
# domain at all, so the run was an unbriefed generic orchestrator wearing the
# specialist's name: the pack's persona, refusals, workflow and deliverable
# contract never reached the model.

_SPECIALIST_PERSONA = "You are the Ledger Reviewer specialist. Quote every figure you use."


class _RecordingLLM:
    """LLM stand-in: records each request and ends the run immediately."""

    model = "fake:test"

    def __init__(self):
        self.calls: list[dict] = []

    def _reply(self, system, tools):
        from maverick.llm import LLMResponse

        self.calls.append({"system": system, "tools": tools})
        return LLMResponse(
            text="FINAL: done", thinking=None, tool_calls=[], stop_reason="end_turn",
        )

    def complete(self, system, messages, tools=None, **_kw):
        return self._reply(system, tools)

    async def complete_async(self, system, messages, tools=None, **_kw):
        return self._reply(system, tools)


def _install_specialist_pack(monkeypatch, tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "ledger_reviewer.toml").write_text(
        'name = "ledger_reviewer"\n'
        'compartment = "ledger"\n'
        'description = "Reviews ledgers."\n'
        f'persona = "{_SPECIALIST_PERSONA}"\n'
        'allow_tools = ["read_file", "web_search", "write_file"]\n'
        'deny_tools = ["shell"]\n'
        'max_risk = "high"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(packs))


def _save_specialist_fleet(domain="ledger_reviewer"):
    from maverick.fleet import Fleet, FleetAgent, save_fleet

    save_fleet(Fleet(name="dept-ledger", owner="", agents=(
        FleetAgent("ledger_reviewer", "analyst", "reviews ledgers", domain=domain),
        FleetAgent("plain", "analyst", "no specialist pack"),
    )))


def test_specialist_agent_goal_is_stamped_with_its_pack(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _install_specialist_pack(monkeypatch, tmp_path)
    _save_specialist_fleet()
    _stub_runner(monkeypatch)
    c = _client()

    r = c.post("/api/v1/fleets/dept-ledger/run",
               json={"agent": "ledger_reviewer", "prompt": "review the March ledger"})
    assert r.status_code == 201, r.text
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    assert world.get_goal(r.json()["goal_id"]).domain == "ledger_reviewer"

    # An agent that carries no specialist pack still runs as a plain agent.
    r2 = c.post("/api/v1/fleets/dept-ledger/run",
                json={"agent": "plain", "prompt": "tidy the notes"})
    assert r2.status_code == 201, r2.text
    assert not world.get_goal(r2.json()["goal_id"]).domain


def test_fleets_show_missing_specialist_action_and_refuse_assignment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _install_specialist_pack(monkeypatch, tmp_path)
    pack = tmp_path / "packs" / "ledger_reviewer.toml"
    with pack.open("a", encoding="utf-8") as handle:
        handle.write('\n[[workflow]]\nname = "lookup"\ntools = ["web_search"]\n')
    _save_specialist_fleet()
    from maverick import domain_edit

    monkeypatch.setattr(domain_edit, "_configured_tool_names", lambda: frozenset({"read_file"}))
    calls = _stub_runner(monkeypatch)
    page = _client().get("/fleets")
    assert page.status_code == 200
    assert "Needs Web search" in page.text
    assert 'value="ledger_reviewer" disabled' in page.text
    assert 'href="/settings/all?id=capabilities.web_search"' in page.text

    denied = _client().post("/api/v1/fleets/dept-ledger/run", json={
        "agent": "ledger_reviewer", "prompt": "review the March ledger",
    })
    assert denied.status_code == 409
    assert "needs setup" in denied.json()["detail"]
    assert not calls
    from maverick.world_model import WorldModel

    assert WorldModel(tmp_path / "world.db").list_goals() == []


def test_specialist_agent_run_reaches_the_model_as_the_specialist(monkeypatch, tmp_path):
    """The real orchestrator runs the goal: the specialist's persona is what the
    model is briefed with, and the run stays inside the role's grant."""
    _isolate(monkeypatch, tmp_path)
    _install_specialist_pack(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"roles": {"analyst": {"allow_tools": ["read_file"], "max_risk": "low"}}},
    )
    _save_specialist_fleet()

    from maverick import budget as budget_mod
    from maverick import domain as domain_mod
    from maverick import llm as llm_mod
    from maverick import sandbox as sandbox_mod
    from maverick import trace_pin

    class _Sandbox:
        def close(self):
            return None

    llm = _RecordingLLM()
    roots: list = []
    real_build = domain_mod.agent_from_profile

    def _capture_root(profile, ctx, task, **kw):
        agent = real_build(profile, ctx, task, **kw)
        roots.append(agent)
        return agent

    monkeypatch.setattr(llm_mod, "LLM", lambda: llm)
    monkeypatch.setattr(sandbox_mod, "build_sandbox", _Sandbox)
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kw: budget_mod.Budget())
    monkeypatch.setattr(trace_pin, "pin_trace", lambda *_a, **_kw: None)
    monkeypatch.setattr(domain_mod, "agent_from_profile", _capture_root)

    r = _client().post("/api/v1/fleets/dept-ledger/run",
                       json={"agent": "ledger_reviewer", "prompt": "review the March ledger"})
    assert r.status_code == 201, r.text

    assert llm.calls, "the goal never reached the model"
    assert _SPECIALIST_PERSONA in llm.calls[0]["system"]
    # The pack allows web_search and write_file; the agent's role does not.
    assert len(roots) == 1
    cap = roots[0].capability
    assert cap.permits("read_file") is True
    assert cap.permits("web_search") is False
    assert cap.permits("write_file") is False
    assert cap.principal == "agent:dept-ledger.ledger_reviewer"


def test_deployed_department_specialist_reaches_model_with_persona_and_capability(
    monkeypatch, tmp_path,
):
    """The customer deploy→assign→run path uses the shipped specialist pack."""
    _isolate(monkeypatch, tmp_path)
    from maverick import budget as budget_mod
    from maverick import domain as domain_mod
    from maverick import llm as llm_mod
    from maverick import sandbox as sandbox_mod
    from maverick import trace_pin

    class _Sandbox:
        def close(self):
            return None

    llm = _RecordingLLM()
    roots = []
    real_build = domain_mod.agent_from_profile

    def capture_root(profile, ctx, task, **kwargs):
        agent = real_build(profile, ctx, task, **kwargs)
        roots.append(agent)
        return agent

    monkeypatch.setattr(llm_mod, "LLM", lambda: llm)
    monkeypatch.setattr(sandbox_mod, "build_sandbox", _Sandbox)
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kw: budget_mod.Budget())
    monkeypatch.setattr(trace_pin, "pin_trace", lambda *_a, **_kw: None)
    monkeypatch.setattr(domain_mod, "agent_from_profile", capture_root)

    client = _client()
    from maverick_dashboard.plain_labels import pack_display_name

    preview, deployed, fleet = _save_team(client, "sales_gtm")
    assert deployed.status_code == 200, deployed.text
    assert any(agent.name == "gtm_deal_inspection" and agent.domain == "gtm_deal_inspection"
               for agent in fleet.agents)
    assert any(row["Specialist"] == pack_display_name("gtm_demand_gen") and row["Reason"] == "Needs Web search"
               for row in preview["Setup still needed"])

    assigned = client.post("/api/v1/fleets/dept-sales_gtm/run", json={
        "agent": "gtm_deal_inspection", "prompt": "Inspect pipeline risks",
    })
    assert assigned.status_code == 201, assigned.text
    from maverick.world_model import WorldModel

    goal = WorldModel(tmp_path / "world.db").get_goal(assigned.json()["goal_id"])
    assert goal.domain == "gtm_deal_inspection"
    assert llm.calls and "Deal Inspection Agent" in llm.calls[0]["system"]
    assert len(roots) == 1
    assert roots[0].capability.principal == "agent:dept-sales_gtm.gtm_deal_inspection"
    assert not roots[0].capability.permits("shell")


def test_specialist_agent_whose_pack_is_gone_is_refused_not_run_generically(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _install_specialist_pack(monkeypatch, tmp_path)
    _save_specialist_fleet(domain="removed_specialist")
    calls = _stub_runner(monkeypatch)

    r = _client().post("/api/v1/fleets/dept-ledger/run",
                       json={"agent": "ledger_reviewer", "prompt": "review the March ledger"})
    assert r.status_code == 400, r.text
    assert "removed_specialist" not in r.text  # no internal pack id in customer copy
    assert not calls, "nothing may be queued for a specialist that cannot run"
    from maverick.world_model import WorldModel
    assert WorldModel(tmp_path / "world.db").list_goals() == []
