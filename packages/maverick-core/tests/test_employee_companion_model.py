"""Draft runtime regression cases. All provider and accounting seams are mocked.

Authored for the companion MVP; execution is deferred at the user's request.
"""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick import employee_companion_model as companion
from maverick.connections import current_principal
from maverick.llm import LLMResponse
from maverick.paths import current_tenant_id_strict, tenant_scope


@pytest.fixture
def route_environment(tmp_path, monkeypatch):
    from maverick import enterprise

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(companion, "offline_model_for_role", lambda role: "openai:test-writer")
    monkeypatch.setattr(companion, "require_model_allowed", lambda model: model)
    monkeypatch.setattr(enterprise, "assert_provider_allowed", lambda provider: None)
    monkeypatch.setattr(companion.LLM, "_provider_client_config",
                        lambda self, provider: SimpleNamespace(fingerprint="admitted"))
    with tenant_scope(tenant="companion-test"):
        yield companion.prepare_route()


@pytest.fixture
def runtime(route_environment, monkeypatch):
    from maverick import orchestrator
    from maverick.tenant import provider_admission

    calls = []
    records = []
    budget = SimpleNamespace(max_output_tokens=2000, check=lambda: None)
    monkeypatch.setattr(companion, "_turn_budget", lambda: budget)
    monkeypatch.setattr(companion, "_check_admission", lambda actor, tenant: None)

    class Settlement:
        def __init__(self, **kwargs):
            records.append(("created", kwargs))

        def record(self):
            records.append(("recorded", current_tenant_id_strict(), current_principal()))

    @contextmanager
    def scope(chosen_budget, actor):
        assert chosen_budget is budget
        assert actor == current_principal() == "user:alice"
        assert current_tenant_id_strict() == "companion-test"
        yield

    def complete(self, **kwargs):
        calls.append(kwargs)
        kwargs["dispatch_guard"]()
        kwargs["dispatch_guard"]()  # Multiple checks do not consume a second turn.
        return LLMResponse(text="A proposed draft.", thinking="private reasoning",
                           tool_calls=[], stop_reason="end_turn", raw={"secret": "raw"})

    monkeypatch.setattr(orchestrator, "_QuotaUsageSettlement", Settlement)
    monkeypatch.setattr(provider_admission, "run_scope", scope)
    monkeypatch.setattr(companion.LLM, "complete", complete)
    return SimpleNamespace(route=route_environment, calls=calls, records=records)


def _generate(runtime, **overrides):
    kwargs = {
        "actor": "user:alice", "tenant": "companion-test", "route": runtime.route,
        "message": "Help me draft a reply", "history": [], "tasks": [],
        "dispatch_guard": lambda: None,
    }
    kwargs.update(overrides)
    return companion.generate_draft(**kwargs)


def test_prepare_route_does_not_construct_or_call_a_client(route_environment, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("route preparation must not initialize or call a provider")

    monkeypatch.setattr(companion.LLM, "_get_client", forbidden)
    monkeypatch.setattr(companion.LLM, "complete", forbidden)
    assert companion.prepare_route() == route_environment
    assert set(vars(route_environment)) == {"model", "provider", "fingerprint", "tenant"}


@pytest.mark.parametrize("provider", ["codex_cli", "unknown-plugin"])
def test_executable_or_unreviewed_provider_is_refused(route_environment, monkeypatch, provider):
    monkeypatch.setattr(companion, "offline_model_for_role", lambda role: f"{provider}:test")
    with pytest.raises(companion.CompanionModelUnavailable, match="cannot provide"):
        companion.prepare_route()


def test_route_revalidation_refuses_another_tenant(route_environment):
    with tenant_scope(tenant="companion-other"):
        with pytest.raises(companion.CompanionModelUnavailable, match="route changed"):
            companion.validate_route(route_environment)


def test_route_revalidation_refuses_provider_configuration_rotation(route_environment, monkeypatch):
    monkeypatch.setattr(companion.LLM, "_provider_client_config",
                        lambda self, provider: SimpleNamespace(fingerprint="rotated"))
    with pytest.raises(companion.CompanionModelUnavailable, match="route changed"):
        companion.validate_route(route_environment)
    with pytest.raises(companion.CompanionModelUnavailable, match="configuration changed"):
        companion._PinnedDraftLLM(route_environment)._provider_client_config("openai")


def test_draft_uses_single_attempt_existing_runtime_and_safe_context(runtime):
    output = _generate(
        runtime,
        tasks=[{"goal_id": 17, "title": "Write outline", "status": "active",
                "result": "must not reach provider", "connector_secret": "also excluded"}],
        history=[{"message": "A prior question", "response": "A prior draft",
                  "source_refs": ["task:17"], "private_metadata": "excluded"}],
    )
    assert output == "A proposed draft."
    call = runtime.calls[0]
    assert call["tools"] is None
    assert call["_no_failover"] is True
    assert call["max_physical_attempts"] == 1
    assert call["max_tokens"] == 2000
    content = call["messages"][0]["content"]
    assert '"id":17' in content and '"title":"Write outline"' in content
    assert "A prior question" in content and "A prior draft" in content
    assert "must not reach provider" not in content
    assert "connector_secret" not in content and "private_metadata" not in content
    assert runtime.records[-1] == ("recorded", "companion-test", "user:alice")


def test_authority_revoked_at_physical_dispatch_refuses_and_settles(runtime):
    checks = 0

    def guard():
        nonlocal checks
        checks += 1
        if checks >= 2:
            raise PermissionError("revoked")

    with pytest.raises(PermissionError, match="revoked"):
        _generate(runtime, dispatch_guard=guard)
    assert runtime.records[-1][0] == "recorded"


def test_guard_refusal_before_budget_never_starts_a_model_turn(runtime):
    def denied():
        raise PermissionError("revoked")

    with pytest.raises(PermissionError, match="revoked"):
        _generate(runtime, dispatch_guard=denied)
    assert runtime.calls == runtime.records == []


def test_provider_failure_still_settles(runtime, monkeypatch):
    def failed(*args, **kwargs):
        raise RuntimeError("synthetic provider failure")

    monkeypatch.setattr(companion.LLM, "complete", failed)
    with pytest.raises(RuntimeError, match="synthetic"):
        _generate(runtime)
    assert runtime.records[-1][0] == "recorded"


def test_unexpected_tool_response_is_not_published_or_executed(runtime, monkeypatch):
    monkeypatch.setattr(companion.LLM, "complete", lambda *args, **kwargs: LLMResponse(
        text="I sent a message", thinking=None, tool_calls=[object()], stop_reason="tool_use"))
    with pytest.raises(companion.CompanionModelUnavailable, match="usable draft"):
        _generate(runtime)
    assert runtime.records[-1][0] == "recorded"


@pytest.mark.parametrize("overrides", [
    {"actor": "system:admin"}, {"tenant": "another-tenant"}, {"message": "x" * 4001},
])
def test_invalid_identity_or_input_never_reaches_provider(runtime, overrides):
    with pytest.raises(companion.CompanionModelUnavailable):
        _generate(runtime, **overrides)
    assert runtime.calls == runtime.records == []


def test_preview_caps_never_raise_configured_limits(monkeypatch):
    captured = {}
    monkeypatch.setattr(companion, "resolve_budget_caps", lambda: {
        "max_dollars": 0.01, "max_input_tokens": 9000,
        "max_output_tokens": 250, "max_wall_seconds": 12, "max_tool_calls": 4,
    })

    def budget(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(**kwargs, check=lambda: None)

    monkeypatch.setattr(companion, "budget_from_config", budget)
    companion._turn_budget()
    assert captured == {"max_dollars": 0.01, "max_input_tokens": 9000,
                        "max_output_tokens": 250, "max_wall_seconds": 12,
                        "max_tool_calls": 0}


def test_context_is_bounded_and_only_projects_known_fields():
    context = companion._bounded_context(
        [{"message": "x" * 4000, "response": "y" * 12000, "source_refs": []}] * 50,
        [{"goal_id": i, "title": "z" * 4000, "status": "active"} for i in range(100)],
    )
    assert len(context) < 29000
    assert "z" * 401 not in context
