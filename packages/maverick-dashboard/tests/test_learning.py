"""The Learning surface: status of the learning systems + the accumulated,
per-tenant learning (Operating Record + grounded outcomes + self-taught skills).

Read-only and owner-scoped; the numbers on /learning and /api/v1/learning match.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

_TABLE = "| Week | Net |\n| --- | ---: |\n| W1 | 300 |\n"


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import consequence, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    consequence.reset_shared()
    return world_model.WorldModel(tmp_path / "world.db")


def test_learning_api_reports_governed_components_on_and_dgm_off_by_default(
    tmp_path, monkeypatch,
):
    monkeypatch.delenv("MAVERICK_CONSEQUENCE", raising=False)
    _isolate(tmp_path, monkeypatch)
    data = client.get("/api/v1/learning").json()
    keys = {c["key"] for c in data["components"]}
    assert {"consequence", "reflexion", "dreaming", "capture", "data_engine"} <= keys
    assert data["components_total"] == len(data["components"])
    assert all(c["on"] is (c["key"] != "budget_tuning") for c in data["components"])
    assert data["components_on"] == data["components_total"] - 1
    assert data["dgm"]["requested"] is False
    assert data["dgm"]["state"] == "off"
    assert data["dgm"]["research_only"] is True
    assert data["dgm"]["live_adoption"] is False
    assert set(data["accumulated"]) >= {
        "decisions", "human_decisions", "approvals",
        "departments",
    }


def test_feature_switches_use_live_subsystem_defaults(tmp_path, monkeypatch):
    for name in (
        "MAVERICK_DREAMING",
        "MAVERICK_SELF_IMPROVEMENT",
        "MAVERICK_SELF_HARNESS",
        "MAVERICK_FLEET_MEMORY",
        "MAVERICK_REHEARSAL",
        "MAVERICK_FLOWS",
    ):
        monkeypatch.delenv(name, raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick import dreaming, fleet_memory, rehearsal, self_harness, self_improvement
    from maverick.config import reset_config_cache

    reset_config_cache()
    rows = {
        row["section"]: row["enabled"]
        for row in client.get("/api/v1/features/switches").json()["switches"]
    }
    assert rows["dreaming"] is dreaming.enabled() is True
    assert rows["self_improvement"] is self_improvement.enabled() is True
    assert rows["self_harness"] is self_harness.enabled() is True
    assert rows["rehearsal"] is rehearsal.enabled() is True
    assert rows["fleet_memory"] is fleet_memory.enabled()


def test_rehearsal_safety_controls_and_learning_switch_share_live_state(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_REHEARSAL", raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick import rehearsal
    from maverick.config import reset_config_cache
    from maverick_dashboard.settings_catalog import BY_ID
    from maverick_dashboard.settings_store import set_catalog_values

    assert BY_ID["rehearsal.enable"].group == "Safety"
    assert BY_ID["rehearsal.mode"].default == "observe"
    reset_config_cache()
    assert rehearsal.enabled() is True
    assert rehearsal.enforcing() is False

    set_catalog_values({("rehearsal", "mode"): "hold"})
    assert rehearsal.enforcing() is True
    set_catalog_values({("rehearsal", "enable"): False})
    assert rehearsal.enabled() is False
    assert rehearsal.enforcing() is False
    rows = {
        row["section"]: row["enabled"]
        for row in client.get("/api/v1/features/switches").json()["switches"]
    }
    assert rows["rehearsal"] is False

    set_catalog_values({("rehearsal", "enable"): True,
                        ("rehearsal", "mode"): "observe"})
    assert rehearsal.enabled() is True
    assert rehearsal.enforcing() is False


def test_feature_switch_read_after_write_and_environment_pin(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DREAMING", raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick.config import reset_config_cache

    reset_config_cache()
    disabled = client.post(
        "/api/v1/features/switches",
        json={"section": "dreaming", "enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json() == {"section": "dreaming", "enabled": False}

    monkeypatch.setenv("MAVERICK_DREAMING", "1")
    reset_config_cache()
    refused = client.post(
        "/api/v1/features/switches",
        json={"section": "dreaming", "enabled": False},
    )
    assert refused.status_code == 409
    rows = {
        row["section"]: row["enabled"]
        for row in client.get("/api/v1/features/switches").json()["switches"]
    }
    assert rows["dreaming"] is True


def test_scoped_caller_does_not_see_deployment_wide_counts(tmp_path, monkeypatch):
    # A specific tenant (owner not None) must NOT see deployment-level learned
    # skills / grounded outcomes attributed as its own -- those are admin-only.
    _isolate(tmp_path, monkeypatch)
    from maverick_dashboard import api
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    acc = client.get("/api/v1/learning").json()["accumulated"]
    assert "grounded_outcomes" not in acc and "learned_capabilities" not in acc
    assert {"decisions", "human_decisions", "approvals", "departments"} <= set(acc)


def test_consequence_flag_flips_component_on(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    _isolate(tmp_path, monkeypatch)
    data = client.get("/api/v1/learning").json()
    comp = {c["key"]: c["on"] for c in data["components"]}
    assert comp["consequence"] is True
    assert data["components_on"] >= 1


def test_signoff_grounds_locally_without_exposing_unscoped_totals(tmp_path, monkeypatch):
    # End to end: a human sign-off becomes a grounded outcome the
    # Learning view counts -- the loop from human judgement to accumulated asset.
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    w = _isolate(tmp_path, monkeypatch)
    gid = w.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result=_TABLE)
    episode = w.start_episode(gid)
    assert "grounded_outcomes" not in client.get("/api/v1/learning").json()["accumulated"]
    r = client.post(
        f"/api/v1/goals/{gid}/signoff",
        json={
            "decision": "approved",
            "expected_updated_at": w.get_goal(gid).updated_at,
        },
    )
    assert r.status_code == 200
    from maverick import consequence
    assert consequence.resolve(gid, episode) is not None
    assert "grounded_outcomes" not in client.get("/api/v1/learning").json()["accumulated"]


def test_enable_all_learning_flips_every_component(tmp_path, monkeypatch):
    # env vars unset so the config overlay controls; one POST turns the whole
    # loop on, and it persists + reverses.
    for v in ("MAVERICK_CONSEQUENCE", "MAVERICK_REFLEXION", "MAVERICK_DREAMING",
              "MAVERICK_TRAJECTORY_CAPTURE", "MAVERICK_DATA_ENGINE"):
        monkeypatch.delenv(v, raising=False)
    from maverick.config import reset_config_cache
    self = _isolate(tmp_path, monkeypatch)  # noqa: F841 (world not needed here)
    reset_config_cache()
    total = client.get("/api/v1/learning").json()["components_total"]
    assert client.get("/api/v1/learning").json()["components_on"] == total - 1
    r = client.post("/api/v1/learning", json={"enabled": False})
    assert r.status_code == 200 and r.json()["components_on"] == 0
    assert client.get("/api/v1/learning").json()["components_on"] == 0
    client.post("/api/v1/learning", json={"enabled": True})
    assert client.get("/api/v1/learning").json()["components_on"] == total


def test_flow_improvements_do_not_expose_unscoped_workspace_totals(tmp_path, monkeypatch):
    # A forward flow self-rewrite (the loop enacting a proposal) shows up as a
    # counted improvement for an admin caller; auto-reverts don't inflate it.
    _isolate(tmp_path, monkeypatch)
    from maverick.flow import evolution_log
    assert "flow_self_improvements" not in client.get("/api/v1/learning").json()["accumulated"]
    evolution_log.record_apply("f", "a", "action", "agent", 2, source="auto-apply")   # sticks
    evolution_log.record_apply("f", "b", "action", "agent", 2, source="auto-apply")   # then undone
    evolution_log.record_apply("f", "b", "agent", "action", 3, source="auto-revert")
    acc = client.get("/api/v1/learning").json()["accumulated"]
    assert evolution_log.improvement_count() == 1
    assert "flow_self_improvements" not in acc


def test_flow_autonomy_is_its_own_opt_in_not_the_blanket_button(tmp_path, monkeypatch):
    # The autonomous flow loop is deliberately NOT part of the blanket learning
    # toggle: flipping "turn all learning on" must leave [flows] auto_* untouched.
    for v in ("MAVERICK_CONSEQUENCE", "MAVERICK_REFLEXION", "MAVERICK_DREAMING",
              "MAVERICK_TRAJECTORY_CAPTURE", "MAVERICK_DATA_ENGINE", "MAVERICK_FLOWS_AUTO"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")   # engine on so the section renders
    from maverick.config import reset_config_cache
    _isolate(tmp_path, monkeypatch)
    reset_config_cache()
    snap = client.get("/api/v1/learning").json()
    assert snap["flow_autonomy"] == {"engine_on": True, "auto_evolve": False, "auto_apply": False}
    client.post("/api/v1/learning", json={"enabled": True})            # blanket button
    reset_config_cache()
    assert client.get("/api/v1/learning").json()["flow_autonomy"]["auto_evolve"] is False


def test_flow_autonomy_toggle_enables_the_loop(tmp_path, monkeypatch):
    for v in ("MAVERICK_FLOWS_AUTO",):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    from maverick.config import reset_config_cache
    _isolate(tmp_path, monkeypatch)
    reset_config_cache()
    from maverick_dashboard import settings_store
    # Automatic forward apply is retired: suggestions always need review.
    refused = client.post("/api/v1/learning/flow-autonomy", json={"auto_apply": True})
    assert refused.status_code == 422
    assert "always need a person's review" in refused.json()["detail"]
    assert "flows" not in settings_store.load_overlay()
    # turning auto_evolve on sticks; auto_apply stays off and true is still refused
    snap = client.post("/api/v1/learning/flow-autonomy", json={"auto_evolve": True}).json()
    assert snap["flow_autonomy"] == {"engine_on": True, "auto_evolve": True, "auto_apply": False}
    assert client.post("/api/v1/learning/flow-autonomy",
                       json={"auto_evolve": True, "auto_apply": True}).status_code == 422
    snap = client.post("/api/v1/learning/flow-autonomy", json={"auto_apply": False}).json()
    assert snap["flow_autonomy"] == {"engine_on": True, "auto_evolve": True, "auto_apply": False}
    snap = client.post("/api/v1/learning/flow-autonomy", json={"auto_evolve": False}).json()
    assert snap["flow_autonomy"]["auto_apply"] is False
    assert settings_store.load_overlay()["flows"]["auto_apply"] is False


def test_flow_autonomy_requires_global_admin(tmp_path, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    for v in ("MAVERICK_FLOWS_AUTO",):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    _isolate(tmp_path, monkeypatch)
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice") == "admin"
        r = client.post("/api/v1/learning/flow-autonomy", json={"auto_evolve": True})
    finally:
        reset_tenant(tok)

    assert r.status_code == 403


def test_learning_page_renders_flow_autonomy_toggles_when_engine_on(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    from maverick.config import reset_config_cache
    _isolate(tmp_path, monkeypatch)
    reset_config_cache()
    t = client.get("/learning").text
    # Automatic undo is the only automatic control; suggestions wait for a
    # complete human review, so there is no automatic-apply switch.
    assert 'id="lrn-auto-evolve"' in t and 'id="lrn-auto-apply"' not in t
    assert "Workflow improvements" in t and "Suggestions wait for complete review" in t


def test_learning_page_hides_flow_autonomy_when_engine_off(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    from maverick.config import reset_config_cache
    _isolate(tmp_path, monkeypatch)
    reset_config_cache()
    t = client.get("/learning").text
    # engine off -> the section still renders (admin) with an in-app ON button
    # (the `flows` feature switch), not the live toggles and no config-file copy.
    assert "Turn on workflows first" in t
    assert 'id="lrn-flows-on"' in t
    assert 'scroll-margin-top: var(--space-7)' in t
    assert "/learning#lrn-flows-on" in client.get("/flows/designer").text
    assert "/learning#lrn-flows-on" in client.get("/flows/analytics").text
    assert "[flows]" not in t
    assert 'id="lrn-auto-evolve"' not in t


def test_learning_page_has_enable_button(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    t = client.get("/learning").text
    assert 'id="lrn-enable"' in t and "Turn core learning on" in t


def test_dgm_is_a_separate_acknowledged_research_toggle(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick.config import reset_config_cache
    from maverick_dashboard import settings_store

    reset_config_cache()
    assert client.post("/api/v1/learning/dgm", json={"enabled": True}).status_code == 400
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )
    assert response.status_code == 200
    status = response.json()["dgm"]
    assert status["requested"] is True
    assert status["state"] == "blocked"  # no attested evaluator/corpus/surface
    assert status["live_adoption"] is False
    assert settings_store.load_overlay()["self_modify"] == {"enable": True}

    # The blanket learning control never arms or disarms DGM.
    client.post("/api/v1/learning", json={"enabled": False})
    assert client.get("/api/v1/learning").json()["dgm"]["requested"] is True
    response = client.post("/api/v1/learning/dgm", json={"enabled": False})
    assert response.status_code == 200
    assert response.json()["dgm"]["requested"] is False


def test_dgm_environment_override_is_dashboard_locked(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_MODIFY", "0")
    _isolate(tmp_path, monkeypatch)
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )
    assert response.status_code == 409
    assert "MAVERICK_SELF_MODIFY" in response.json()["detail"]


def test_dgm_config_overlay_is_dashboard_locked(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    policy = tmp_path / "operator.toml"
    policy.write_text("[self_modify]\nenable = false\n")
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(policy))
    from maverick.config import reset_config_cache
    reset_config_cache()
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )
    assert response.status_code == 409
    assert "MAVERICK_CONFIG_OVERLAY" in response.json()["detail"]


def test_dgm_audit_failure_rolls_back_control(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr("maverick.audit.record_global", lambda *a, **k: False)
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )
    assert response.status_code == 503
    from maverick_dashboard import settings_store
    assert not (settings_store.load_overlay().get("self_modify") or {}).get("enable", False)
    from maverick.config import reset_config_cache
    reset_config_cache()
    assert client.get("/api/v1/learning").json()["dgm"]["requested"] is False


def test_dgm_authorization_is_durable_before_enable_is_observable(
    tmp_path, monkeypatch,
):
    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick import self_modify
    observed = []

    def audit_before_publish(*_args, **_kwargs):
        observed.append(self_modify.enabled())
        return True

    monkeypatch.setattr("maverick.audit.record_global", audit_before_publish)
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )

    assert response.status_code == 200
    assert observed == [False]
    assert self_modify.enabled() is True


def test_dgm_failed_authorization_never_writes_enable_bit(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    from maverick_dashboard import settings_store
    writes = []
    original_write = settings_store._write
    monkeypatch.setattr(
        settings_store, "_write",
        lambda data: writes.append(data) or original_write(data),
    )
    monkeypatch.setattr("maverick.audit.record_global", lambda *_a, **_k: False)

    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )

    assert response.status_code == 503
    assert writes == []


def test_dgm_audit_captures_acknowledgement_and_actor(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    captured = []
    monkeypatch.setattr(
        "maverick.audit.record_global",
        lambda kind, **payload: captured.append((kind, payload)) or True,
    )
    response = client.post(
        "/api/v1/learning/dgm",
        json={"enabled": True, "acknowledge_research_only": True},
    )
    assert response.status_code == 200
    assert captured[-1][1]["acknowledged"] is True
    assert captured[-1][1]["actor"] == "local"


def test_dgm_and_learning_controls_require_global_admin(tmp_path, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
    _isolate(tmp_path, monkeypatch)
    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    token = set_tenant("acme")
    try:
        learning = client.post("/api/v1/learning", json={"enabled": False})
        dgm = client.post(
            "/api/v1/learning/dgm",
            json={"enabled": True, "acknowledge_research_only": True},
        )
    finally:
        reset_tenant(token)
    assert learning.status_code == 403
    assert dgm.status_code == 403


def test_learning_page_has_separate_dgm_risk_card(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    text = client.get("/learning").text
    assert 'id="lrn-dgm"' in text
    assert "Experimental: let Lightwork try improving its own code" in text
    assert "It can never install them" in text


def test_learning_page_renders_the_moat(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    t = client.get("/learning").text
    assert "core learning components are on" in t
    assert "Review each feature below to decide which ones to use" in t
    # The static tiles became a live board: the accumulated-judgement card
    # and its container render client-side from /api/v1/learning.
    assert "Accumulated judgement" in t
    assert 'id="bd-acc"' in t
    assert "recorded outcomes of its own work" in t


def test_learning_page_is_configured_in_app_not_in_server_files(tmp_path, monkeypatch):
    # Every learning system is switched from the page itself (the feature-switch
    # API); the old "edit the server configuration" admin block and the config-key
    # strings ([section] enable / MAVERICK_* env hints) must be gone from the UI.
    _isolate(tmp_path, monkeypatch)
    t = client.get("/learning").text
    assert 'id="lrn-switches"' in t                  # in-page ON/OFF switch list
    assert "/api/v1/features/switches" in t          # wired to the existing API
    assert "For administrators" not in t
    assert "server configuration" not in t
    assert "[self_learning] enable" not in t and "MAVERICK_SELF_LEARNING" not in t
    # Component -> switch-section map ships without exposing config keys.
    assert 'id="lrn-switch-members"' in t
    # threat_hunt / env_hunt switches belong to the Security page, not here.
    assert "threat_hunt" in t and "env_hunt" in t    # named only in the exclusion list


def test_learning_policy_authority_is_separate_from_owned_content(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    from maverick_dashboard import api, auth
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:admin")
    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: True)
    data = api._learning_snapshot(None)
    assert data["dgm"] is not None and data["flow_autonomy"] is not None
    assert "grounded_outcomes" not in data["accumulated"]
    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: False)
    data = api._learning_snapshot(None)
    assert data["dgm"] is None and data["flow_autonomy"] is None
