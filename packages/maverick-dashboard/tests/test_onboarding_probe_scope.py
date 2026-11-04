"""Setup progress reads only the workspace evidence it actually needs."""
from types import SimpleNamespace

from maverick import domain, domain_edit
from maverick_dashboard import onboarding_state


def _unexpected_catalog():
    raise AssertionError("The bundled editor catalog is unnecessary here")


def test_empty_and_malformed_overrides_do_not_hydrate_catalog(tmp_path, monkeypatch):
    calls = []

    def catalog_probe():
        calls.append(True)
        return []

    monkeypatch.setattr(domain, "user_dir", lambda: tmp_path)
    monkeypatch.setattr(domain_edit, "list_agents", catalog_probe)
    assert onboarding_state._has_user_agent() is False
    assert calls == []
    (tmp_path / "broken.toml").write_text("this is not valid TOML [", encoding="utf-8")
    assert onboarding_state._has_user_agent() is False
    assert calls == []


def test_override_probe_rechecks_scope_and_deletion(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    source = first / "specialist.toml"
    source.write_text('name = "specialist"\npersona = "Local fixture"\n', encoding="utf-8")
    active = [first]
    calls = []
    monkeypatch.setattr(domain, "user_dir", lambda: active[0])

    def current_roster():
        calls.append(active[0])
        return [{"is_override": True}]

    monkeypatch.setattr(domain_edit, "list_agents", current_roster)
    assert onboarding_state._has_user_agent() is True
    active[0] = second
    assert onboarding_state._has_user_agent() is False
    active[0] = first
    source.unlink()
    assert onboarding_state._has_user_agent() is False
    assert calls == [first]


def test_parseable_override_still_requires_resolved_agent(tmp_path, monkeypatch):
    calls = []

    def unresolved_roster():
        calls.append(True)
        return [{"is_override": False}]

    (tmp_path / "specialist.toml").write_text('name = "specialist"\n', encoding="utf-8")
    monkeypatch.setattr(domain, "user_dir", lambda: tmp_path)
    monkeypatch.setattr(domain_edit, "list_agents", unresolved_roster)
    assert onboarding_state._has_user_agent() is False
    assert calls == [True]


def test_existing_owned_task_completes_built_step_without_catalog(monkeypatch):
    owners = []

    def owned_goals(*, owner, **kwargs):
        owners.append(owner)
        return [SimpleNamespace(id=1)] if owner == "user:alice" else []

    monkeypatch.setattr(onboarding_state, "selected_model_route_state", lambda: {
        "configured": False, "status": "incomplete", "detail": "No model configured"})
    monkeypatch.setattr(onboarding_state, "_preflight_state", lambda profile, **kwargs: {"ready": False})
    monkeypatch.setattr(onboarding_state, "_has_user_template", _unexpected_catalog)
    monkeypatch.setattr(onboarding_state, "_has_user_agent", _unexpected_catalog)
    world = SimpleNamespace(list_goals=owned_goals)
    reviewed = {"complete": False, "detail": "No approval", "status": "incomplete"}
    state = onboarding_state.build(world, owner="user:alice", reviewed_outcome=reviewed)
    assert state["steps"][1]["done"] is True
    assert state["steps"][2]["done"] is True
    assert state["steps"][3]["done"] is False
    assert owners == ["user:alice"]

    # Another principal must still evaluate their own current setup evidence.
    monkeypatch.setattr(onboarding_state, "_has_user_template", lambda: False)
    monkeypatch.setattr(onboarding_state, "_has_user_agent", lambda: False)
    other = onboarding_state.build(world, owner="user:bob", reviewed_outcome=reviewed)
    assert other["steps"][1]["done"] is False
    assert other["steps"][2]["done"] is False
    assert owners == ["user:alice", "user:bob"]


def test_build_reuses_provider_inventory_and_rechecks_next_request(tmp_path, monkeypatch):
    from maverick import config, operator_preflight

    verdicts = iter(("ready", "not_ready"))
    inventories = []
    profiles = []

    def current_readiness():
        verdict = next(verdicts)
        inventories.append(verdict)
        return {
            "verdict": verdict,
            "reason": "Connected" if verdict == "ready" else "The connection changed",
            "next_action": None if verdict == "ready" else {
                "label": "Open providers", "href": "/providers",
            },
        }

    def preflight(profile):
        profiles.append(profile)
        return SimpleNamespace(to_dict=lambda: {
            "ready": True,
            "checks": [{"id": "provider", "status": "ready"}],
        })

    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.toml")
    monkeypatch.setattr(operator_preflight, "collect", preflight)
    monkeypatch.setattr(onboarding_state, "workspace_readiness", current_readiness)
    monkeypatch.setattr(onboarding_state, "selected_model_route_state", lambda: {"configured": True})
    monkeypatch.setattr(onboarding_state, "_has_user_template", lambda: False)
    monkeypatch.setattr(onboarding_state, "_has_user_agent", lambda: False)
    # Keep this regression focused on inventory reuse and the real provider
    # verdict overlay, without importing the dashboard just for check labels.
    monkeypatch.setattr(onboarding_state, "_with_plain_checks", lambda payload: payload)
    world = SimpleNamespace(list_goals=lambda **kwargs: [])
    reviewed = {"complete": False, "detail": "No approval", "status": "incomplete"}

    first = onboarding_state.build(world, reviewed_outcome=reviewed)
    assert inventories == ["ready"]
    assert first["runtime_ready"] is True
    assert first["assurance_ready"] is True
    assert first["steps"][0]["done"] is True

    # A second request must not inherit the previous request's ready badge.
    second = onboarding_state.build(world, reviewed_outcome=reviewed)
    assert inventories == ["ready", "not_ready"]
    assert profiles == ["run", "cockpit", "run", "cockpit"]
    assert second["runtime_ready"] is False
    assert second["assurance_ready"] is False
    assert second["steps"][0]["done"] is False
    for key in ("runtime_preflight", "assurance_preflight"):
        assert second[key]["checks"][0]["status"] == "blocked"
        assert second[key]["checks"][0]["detail"] == "The connection changed"
