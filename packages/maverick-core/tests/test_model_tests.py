"""Local synthetic fixtures only. No SDK client or live provider is used."""
from __future__ import annotations

import asyncio
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from maverick import model_tests as tests

CONTEXT = "a" * 64


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import budget, config, orchestrator
    from maverick.tenant import provider_admission
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(tests, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(config, "load_config", lambda: {"models": {"capability_tests": True}})
    monkeypatch.setattr(tests, "route", lambda model: {"model": model, "provider": "openai", "fingerprint": "old", "tenant": "test"})
    monkeypatch.setattr(tests, "limits", lambda: dict(tests.CAPS))
    monkeypatch.setattr(tests, "_admission", lambda actor, tenant: None)
    fake_budget = SimpleNamespace(max_output_tokens=64, dollars=.001, check=lambda: None)
    monkeypatch.setattr(budget, "budget_from_config", lambda **caps: fake_budget)
    settled = []
    monkeypatch.setattr(orchestrator, "_QuotaUsageSettlement", lambda **kwargs: SimpleNamespace(record=lambda: settled.append(kwargs)))
    monkeypatch.setattr(provider_admission, "run_scope", lambda budget, actor: nullcontext())
    calls = []
    async def complete(self, **kwargs):
        calls.append(kwargs)
        kwargs["dispatch_guard"]()
        return SimpleNamespace(text="LIGHTWORK_TEST_READY", tool_calls=[])
    monkeypatch.setattr(tests.PinnedTestLLM, "complete_async", complete)
    return SimpleNamespace(calls=calls, settled=settled, path=tmp_path)


def prepared():
    return tests.prepare(CONTEXT, "openai:synthetic-model", "generation", lambda: None)


def execute(row, guard=lambda: None):
    tests.claim(CONTEXT, row["id"], guard)
    asyncio.run(tests.run(CONTEXT, row["id"], "user:alice", "test", guard))
    return tests.get(CONTEXT, row["id"])


def test_review_does_not_generate_and_duplicate_execute_never_replays(env):
    row = prepared()
    assert env.calls == []
    final = execute(row)
    assert final["state"] == "passed"
    assert env.calls[0]["max_physical_attempts"] == 1
    assert env.calls[0]["_no_failover"] is True
    assert env.calls[0]["tools"] is None
    assert env.calls[0]["max_tokens"] == 64
    assert env.settled
    recovered, claimed = tests.claim(CONTEXT, row["id"], lambda: None)
    assert not claimed and recovered["state"] == "passed"
    asyncio.run(tests.run(CONTEXT, row["id"], "user:alice", "test", lambda: None))
    assert len(env.calls) == 1
    stored = tests._path(CONTEXT).read_text(encoding="utf-8")
    assert "LIGHTWORK_TEST_READY" not in stored
    assert "route" not in tests.public(final)


def test_interrupted_call_remains_unknown_and_cannot_replay(env, monkeypatch):
    async def fail(self, **kwargs):
        env.calls.append(kwargs)
        raise TimeoutError("synthetic secret body should not leak")
    monkeypatch.setattr(tests.PinnedTestLLM, "complete_async", fail)
    row = prepared()
    assert execute(row)["state"] == "unknown"
    assert tests.claim(CONTEXT, row["id"], lambda: None)[1] is False
    assert "synthetic secret" not in json.dumps(tests.history(CONTEXT))
    assert len(env.calls) == 1


def test_cancel_before_dispatch_costs_nothing_and_after_dispatch_is_unknown(env, monkeypatch):
    row = prepared()
    tests.cancel(CONTEXT, row["id"], lambda: None)
    assert execute(row)["state"] == "cancelled"
    assert not env.calls
    row = prepared()
    cancelled = []
    async def wait(self, **kwargs):
        env.calls.append(kwargs)
        tests.cancel(CONTEXT, row["id"], lambda: None)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
    monkeypatch.setattr(tests.PinnedTestLLM, "complete_async", wait)
    assert execute(row)["state"] == "unknown"
    assert cancelled == [True]
    assert len(env.calls) == 1


def test_route_rotation_revocation_and_expiry_refuse_before_generation(env, monkeypatch):
    row = prepared()
    monkeypatch.setattr(tests, "route", lambda model: {"model": model, "fingerprint": "rotated"})
    with pytest.raises(ValueError, match="changed"):
        tests.claim(CONTEXT, row["id"], lambda: None)
    assert not env.calls
    tests._edit(CONTEXT, lambda checks: checks[row["id"]].update(expires_at=0))
    with pytest.raises(ValueError, match="expired"):
        tests.claim(CONTEXT, row["id"], lambda: None)
    with pytest.raises(PermissionError):
        tests.claim(CONTEXT, row["id"], lambda: (_ for _ in ()).throw(PermissionError("revoked")))


def test_policy_change_after_claim_refuses_and_scopes_receipts(env, monkeypatch):
    row = prepared()
    tests.claim(CONTEXT, row["id"], lambda: None)
    monkeypatch.setattr(tests, "policy", lambda: (_ for _ in ()).throw(PermissionError("off")))
    asyncio.run(tests.run(CONTEXT, row["id"], "user:alice", "test", lambda: None))
    assert tests.get(CONTEXT, row["id"])["state"] == "refused"
    assert not env.calls
    assert tests.history("b" * 64) == []


def test_configured_caps_only_narrow_and_snapshot_timeouts_are_private(monkeypatch):
    from maverick.budget import resolve_budget_caps
    from maverick.providers.configuration import ProviderConfig
    del resolve_budget_caps
    monkeypatch.setattr("maverick.budget.resolve_budget_caps", lambda: {"max_dollars": .001, "max_output_tokens": 20})
    assert tests.limits()["max_dollars"] == .001
    assert tests.limits()["max_input_tokens"] == 2048
    raw = ProviderConfig("secret", "https://example.invalid", (), None, (("MAVERICK_LLM_READ_TIMEOUT", "90"),), "original")
    monkeypatch.setattr(tests.LLM, "_provider_client_config", lambda self, provider: raw)
    monkeypatch.setattr(tests, "current_tenant_id_strict", lambda: "test")
    llm = tests.PinnedTestLLM({"model": "openai:synthetic", "provider": "openai", "tenant": "test", "fingerprint": "original"})
    bounded = llm._provider_client_config("openai")
    assert bounded.environment_dict()["MAVERICK_LLM_READ_TIMEOUT"] == "15"
    assert raw.environment_dict()["MAVERICK_LLM_READ_TIMEOUT"] == "90"
    assert bounded.fingerprint != raw.fingerprint
    assert bounded.api_key == raw.api_key


def test_synthetic_image_has_actual_png_and_no_customer_context():
    import base64
    messages, expected = tests.sample({"kind": "vision", "id": "a" * 32})
    content = messages[0]["content"]
    assert base64.b64decode(content[0]["source"]["data"]).startswith(b"\x89PNG")
    assert expected in {"RED", "GREEN", "BLUE"}
    assert set(content[0]["source"]) == {"type", "media_type", "data"}


def test_ambiguous_restart_receipt_and_corrupt_storage_fail_closed(env):
    row = prepared()
    tests.claim(CONTEXT, row["id"], lambda: None)
    assert tests.claim(CONTEXT, row["id"], lambda: None)[1] is False
    tests._path(CONTEXT).write_text("broken", encoding="utf-8")
    with pytest.raises(ValueError):
        prepared()
    assert not env.calls


def test_missed_terminal_receipt_is_reported_unknown_without_replay(env):
    row = prepared()
    tests.claim(CONTEXT, row["id"], lambda: None)
    tests._edit(CONTEXT, lambda checks: checks[row["id"]].update(started_at=0))
    public = tests.public(tests.get(CONTEXT, row["id"]))
    assert public["state"] == "unknown" and public["may_still_be_running"]
    assert tests.claim(CONTEXT, row["id"], lambda: None)[1] is False
    assert not env.calls


def test_revocation_before_publication_cannot_publish_a_successful_sample(env, monkeypatch):
    row = prepared()
    allowed = [True]
    def guard():
        if not allowed[0]:
            raise PermissionError("revoked")
    async def reply(self, **kwargs):
        env.calls.append(kwargs)
        allowed[0] = False
        return SimpleNamespace(text="LIGHTWORK_TEST_READY", tool_calls=[])
    monkeypatch.setattr(tests.PinnedTestLLM, "complete_async", reply)
    result = execute(row, guard)
    assert result["state"] == "unknown" and "sample_matched" not in result
    assert len(env.calls) == 1
