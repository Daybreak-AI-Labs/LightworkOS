"""Provider failover — opt-in, default off."""
from __future__ import annotations

import asyncio

import pytest
from maverick import provider_failover as pf
from maverick.llm import LLM

# ---- pure helpers -----------------------------------------------------------

def test_failover_returns_first_success():
    calls = []
    out = pf.failover([
        ("a", lambda: (_ for _ in ()).throw(RuntimeError("a down"))),
        ("b", lambda: calls.append("b") or "B-ok"),
        ("c", lambda: calls.append("c") or "C-ok"),
    ])
    assert out == "B-ok" and calls == ["b"]   # c never tried


def test_failover_all_fail_reraises_last():
    with pytest.raises(RuntimeError, match="second"):
        pf.failover([
            ("a", lambda: (_ for _ in ()).throw(RuntimeError("first"))),
            ("b", lambda: (_ for _ in ()).throw(RuntimeError("second"))),
        ])


def test_failover_should_retry_false_reraises_immediately():
    tried = []
    with pytest.raises(ValueError, match="fatal"):
        pf.failover(
            [("a", lambda: (_ for _ in ()).throw(ValueError("fatal"))),
             ("b", lambda: tried.append("b"))],
            should_retry=lambda e: not isinstance(e, ValueError),
        )
    assert tried == []   # never advanced past the non-retryable error


def test_failover_empty_raises():
    with pytest.raises(ValueError, match="no attempts"):
        pf.failover([])


def test_llm_retry_policy_rejects_control_exceptions():
    from maverick.budget import BudgetExceeded
    from maverick.enterprise import EgressBlocked
    from maverick.preflight import PreflightFailed

    assert pf.should_retry_llm_error(RuntimeError("provider down")) is True
    assert pf.should_retry_llm_error(BudgetExceeded("over budget")) is False
    assert pf.should_retry_llm_error(EgressBlocked("openai")) is False
    assert pf.should_retry_llm_error(PreflightFailed("tiny", 10, 8, 2)) is False


def test_failover_does_not_amplify_sdk_wrapped_egress_block():
    from maverick.enterprise import EgressBlocked

    fallback_calls = []

    def blocked():
        try:
            raise EgressBlocked("openai")
        except EgressBlocked as exc:
            raise ConnectionError("provider connection failed") from exc

    with pytest.raises(ConnectionError, match="provider connection failed"):
        pf.failover(
            [
                ("primary", blocked),
                ("fallback", lambda: fallback_calls.append("dispatched")),
            ],
            should_retry=pf.should_retry_llm_error,
        )
    assert fallback_calls == []


def test_afailover_returns_first_success():
    async def boom():
        raise RuntimeError("down")

    async def ok():
        return "ok"

    out = asyncio.run(pf.afailover([("a", boom), ("b", ok)]))
    assert out == "ok"


# ---- config-driven chain ----------------------------------------------------

def test_fallback_models_reads_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"provider_failover": {"chains": {"a:m1": ["b:m2", "a:m1", "c:m3"]}}})
    # the primary is filtered out of its own chain
    assert pf.fallback_models("a:m1") == ["b:m2", "c:m3"]
    assert pf.fallback_models("other") == []


def test_fallback_models_off_by_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert pf.fallback_models("a:m1") == []


# ---- LLM wiring (no real providers) -----------------------------------------

def test_complete_routes_through_failover_when_chain_set(monkeypatch):
    monkeypatch.setattr(pf, "fallback_models", lambda primary: ["b:m2"])
    seen = {}

    def _fake(attempts, **kw):
        seen["labels"] = [a[0] for a in attempts]
        return "ROUTED"

    monkeypatch.setattr(pf, "failover", _fake)
    out = LLM(model="a:m1").complete("sys", [{"role": "user", "content": "hi"}])
    assert out == "ROUTED"
    assert seen["labels"] == ["a:m1", "b:m2"]   # primary first, then the fallback


def test_complete_skips_failover_when_no_chain(monkeypatch):
    monkeypatch.setattr(pf, "fallback_models", lambda primary: [])

    def _boom(*a, **k):
        raise AssertionError("failover must not run when no chain is configured")

    monkeypatch.setattr(pf, "failover", _boom)
    # Original path runs; stub the provider client so we don't hit the network.
    sentinel = object()
    monkeypatch.setattr(LLM, "_get_client",
                        lambda self, provider: type("C", (), {"complete": lambda *a, **k: sentinel})())
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
    out = LLM(model="anthropic:claude-sonnet-4-6").complete(
        "sys",
        [{"role": "user", "content": "hi"}],
    )
    assert out is sentinel


def test_complete_async_routes_through_afailover_when_chain_set(monkeypatch):
    monkeypatch.setattr(pf, "fallback_models", lambda primary: ["b:m2"])

    async def _fake_afailover(attempts, **kw):
        return [a[0] for a in attempts]

    monkeypatch.setattr(pf, "afailover", _fake_afailover)
    labels = asyncio.run(
        LLM(model="a:m1").complete_async("sys", [{"role": "user", "content": "hi"}]))
    assert labels == ["a:m1", "b:m2"]


def test_llm_failover_does_not_retry_budget_exceeded(monkeypatch):
    from maverick.budget import BudgetExceeded

    monkeypatch.setattr(
        pf,
        "fallback_models",
        lambda primary: ["openai:gpt-5.4"],
    )
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
    calls = []

    class _Client:
        def __init__(self, provider):
            self.provider = provider

        def complete(self, **kwargs):
            calls.append(self.provider)
            if self.provider == "anthropic":
                raise BudgetExceeded("input tokens 2 > 1")
            return "fallback should not run"

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: _Client(provider))

    with pytest.raises(BudgetExceeded, match="input tokens"):
        LLM(model="anthropic:claude-sonnet-4-6").complete(
            "sys",
            [{"role": "user", "content": "hi"}],
        )
    assert calls == ["anthropic"]


def test_llm_failover_does_not_retry_budget_exceeded_async(monkeypatch):
    from maverick.budget import Budget, BudgetExceeded

    monkeypatch.setattr(
        pf,
        "fallback_models",
        lambda primary: ["openai:gpt-5.4"],
    )
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
    calls = []

    class _Client:
        def __init__(self, provider):
            self.provider = provider

        async def complete_async(self, **kwargs):
            calls.append(self.provider)
            if self.provider == "anthropic":
                raise BudgetExceeded("input tokens 2 > 1")
            return "fallback should not run"

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: _Client(provider))

    with pytest.raises(BudgetExceeded, match="input tokens"):
        asyncio.run(
            LLM(model="anthropic:claude-sonnet-4-6").complete_async(
                "sys",
                [{"role": "user", "content": "hi"}],
                budget=Budget(max_dollars=100.0),
            )
        )
    assert calls == ["anthropic"]


# ---- circuit-breaker enforcement -------------------------------------------

def test_open_breaker_short_circuits_dispatch_and_fails_over(monkeypatch):
    """An OPEN provider breaker must fast-fail BEFORE the client is called and
    let the failover chain reach the next model."""
    from maverick import circuit_breaker as cb

    cb.reset_all()
    # Trip the primary provider's breaker OPEN (threshold=1, long cooldown so it
    # can't tick back to HALF_OPEN mid-test).
    br = cb.get("llm:anthropic", failure_threshold=1, cooldown_seconds=999)
    br.record_failure()
    assert br.state is cb.CircuitState.OPEN

    monkeypatch.setattr(
        pf,
        "fallback_models",
        lambda primary: ["openai:gpt-5.4"],
    )
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
    calls = []

    class _Client:
        def __init__(self, provider):
            self.provider = provider

        def complete(self, **kwargs):
            calls.append(self.provider)
            return f"ok:{self.provider}"

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: _Client(provider))
    try:
        out = LLM(model="anthropic:claude-sonnet-4-6").complete(
            "sys", [{"role": "user", "content": "hi"}])
        # anthropic's client was NEVER invoked (breaker OPEN); failover reached
        # openai, whose breaker is CLOSED.
        assert calls == ["openai"]
        assert out == "ok:openai"
    finally:
        cb.reset_all()


def test_open_breaker_fast_fails_when_no_chain(monkeypatch):
    """No failover chain: an OPEN breaker surfaces CircuitOpen instead of
    dispatching (fast-fail rather than a dead-provider timeout)."""
    from maverick import circuit_breaker as cb

    cb.reset_all()
    cb.get("llm:anthropic", failure_threshold=1, cooldown_seconds=999).record_failure()

    monkeypatch.setattr(pf, "fallback_models", lambda primary: [])
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)

    def _boom_client(*a, **k):
        raise AssertionError("client must not be called while breaker is OPEN")

    monkeypatch.setattr(
        LLM, "_get_client",
        lambda self, provider: type("C", (), {"complete": _boom_client})())
    try:
        with pytest.raises(cb.CircuitOpen):
            LLM(model="anthropic:claude-sonnet-4-6").complete(
                "sys", [{"role": "user", "content": "hi"}])
    finally:
        cb.reset_all()


def test_breaker_internal_error_does_not_block_healthy_call(monkeypatch):
    """CRITICAL fail-safe: if the breaker object itself errors, the call must
    proceed -- breaker bookkeeping never blocks an otherwise healthy call."""
    from maverick import circuit_breaker as cb

    def _explode(*a, **k):
        raise RuntimeError("breaker registry exploded")

    # Break the breaker lookup used by BOTH the enforcer and the recorder.
    monkeypatch.setattr(cb, "get", _explode)
    monkeypatch.setattr(pf, "fallback_models", lambda primary: [])
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
    calls = []

    class _Client:
        def complete(self, **kwargs):
            calls.append("dispatched")
            return "healthy"

    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: _Client())
    out = LLM(model="anthropic:claude-sonnet-4-6").complete(
        "sys", [{"role": "user", "content": "hi"}])
    assert out == "healthy"
    assert calls == ["dispatched"]  # breaker error failed OPEN -> call proceeded


# ---- which model answered (the conversation says when the backup answered) ----

def _served_by_backup_llm():
    from maverick.llm import LLMResponse

    class _Primary(LLM):
        def complete(self, system, messages, **kw):
            if kw.get("_no_failover"):
                if kw["model"] == "a:m1":
                    raise RuntimeError("primary down")
                return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")
            return super().complete(system, messages, **kw)

        async def complete_async(self, system, messages, **kw):
            if kw.get("_no_failover"):
                if kw["model"] == "a:m1":
                    raise RuntimeError("primary down")
                return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")
            return await super().complete_async(system, messages, **kw)

    return _Primary(model="a:m1")


def test_a_response_from_the_backup_model_says_so(monkeypatch):
    monkeypatch.setattr(pf, "fallback_models", lambda primary: ["b:m2"])
    resp = _served_by_backup_llm().complete("sys", [{"role": "user", "content": "hi"}])
    assert resp.text == "ok"
    assert resp.served_model == "b:m2"
    assert resp.fallback_from == "a:m1"


def test_an_async_response_from_the_backup_model_says_so(monkeypatch):
    monkeypatch.setattr(pf, "fallback_models", lambda primary: ["b:m2"])
    resp = asyncio.run(_served_by_backup_llm().complete_async(
        "sys", [{"role": "user", "content": "hi"}]))
    assert resp.served_model == "b:m2"
    assert resp.fallback_from == "a:m1"


def test_a_response_from_the_main_model_claims_no_fallback(monkeypatch):
    from maverick.llm import LLMResponse

    monkeypatch.setattr(pf, "fallback_models", lambda primary: ["b:m2"])

    class _Healthy(LLM):
        def complete(self, system, messages, **kw):
            if kw.get("_no_failover"):
                return LLMResponse(text="main", thinking=None, tool_calls=[], stop_reason="end_turn")
            return super().complete(system, messages, **kw)

    resp = _Healthy(model="a:m1").complete("sys", [{"role": "user", "content": "hi"}])
    assert resp.text == "main"
    assert resp.fallback_from is None


# --- failover cannot dispatch a model outside the admin allow-list ---

def _point_overlay(monkeypatch, tmp_path):
    from maverick import runtime_overrides
    monkeypatch.setattr(
        runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    return runtime_overrides


# --- failover feeds the cooldown ledger so order_chain can skip ------

@pytest.fixture
def _policy_window(monkeypatch):
    from maverick import failover_policy as fp
    monkeypatch.setattr(fp, "_policy_cfg",
                        lambda: {"cooldown_s": 100, "cooldown_after": 1})
    fp.reset_shared_ledger()
    yield fp
    fp.reset_shared_ledger()


def test_allowlist_filter_drops_disallowed_fallbacks(monkeypatch, tmp_path):
    from maverick.llm import _allowlist_filter_fallbacks
    ro = _point_overlay(monkeypatch, tmp_path)
    ro.set_allowed_models(["anthropic:claude-sonnet-4-6"])

    chain = ["anthropic:claude-opus-4-8", "anthropic:claude-sonnet-4-6"]
    assert _allowlist_filter_fallbacks(chain) == ["anthropic:claude-sonnet-4-6"]


def test_model_for_role_accepts_bare_vs_qualified_allowlist(monkeypatch, tmp_path):
    # Regression: the resolved model may be bare ("claude-sonnet-4-6") while the
    # allow-list stores it provider-qualified ("anthropic:claude-sonnet-4-6").
    # An exact-membership check wrongly rejected it and substituted; canonical
    # comparison must treat the two spellings as the same allowed model.
    from maverick import llm
    ro = _point_overlay(monkeypatch, tmp_path)
    ro.set_allowed_models(["anthropic:claude-sonnet-4-6"])
    monkeypatch.setattr(llm, "_resolve_model_for_role", lambda role, **_selection: "claude-sonnet-4-6")
    assert llm.model_for_role("orchestrator") == "claude-sonnet-4-6"


def test_model_for_role_fallback_is_cheapest_not_lexicographic(monkeypatch, tmp_path):
    # Regression: when neither the resolved model nor DEFAULT_MODEL is allowed,
    # the fallback must be the CHEAPEST allowed model, not sorted(allow)[0].
    # Here opus ($25/out) sorts before the far cheaper direct deepseek flash ($0.28),
    # so lexicographic-first would force the most expensive allowed model.
    from maverick import llm
    ro = _point_overlay(monkeypatch, tmp_path)
    ro.set_allowed_models(["anthropic:claude-opus-4-8", "deepseek:deepseek-v4-flash"])
    monkeypatch.setattr(llm, "_resolve_model_for_role", lambda role, **_selection: "openai:gpt-5.5")
    assert llm.model_for_role("bulk") == "deepseek:deepseek-v4-flash"


def test_model_for_role_fallback_prefers_zero_cost_local_models(monkeypatch, tmp_path):
    # Regression: the allow-list fallback must use the same zero-cost semantics
    # as budget accounting for local/subscription providers. Otherwise a local
    # allowed model can be skipped in favor of a paid hosted fallback.
    from maverick import llm

    ro = _point_overlay(monkeypatch, tmp_path)
    ro.set_allowed_models(["ollama:my-local", "deepseek:deepseek-v4-flash"])
    monkeypatch.setattr(llm, "_resolve_model_for_role", lambda role, **_selection: "openai:gpt-5.5")

    assert llm.model_for_role("bulk") == "ollama:my-local"


def test_cheapest_allowed_prefers_subscription_and_self_hosted_prefixes():
    # codex_cli is subscription-metered, while unknown vllm/tgi models are
    # self-hosted. All should rank as zero-cost ahead of a priced remote model.
    from maverick.llm import _cheapest_allowed

    hosted = "deepseek:deepseek-v4-flash"
    assert _cheapest_allowed(["codex_cli:gpt-5.5", hosted]) == "codex_cli:gpt-5.5"
    assert _cheapest_allowed(["vllm:z-local", hosted]) == "vllm:z-local"
    assert _cheapest_allowed(["tgi:z-local", hosted]) == "tgi:z-local"


def test_allowlist_filter_noop_without_allowlist(monkeypatch, tmp_path):
    from maverick.llm import _allowlist_filter_fallbacks
    _point_overlay(monkeypatch, tmp_path)  # no allow-list set -> unrestricted
    chain = ["anthropic:claude-opus-4-8", "openai:gpt-4.1"]
    assert _allowlist_filter_fallbacks(chain) == chain


def test_allowlist_filter_can_empty_the_chain(monkeypatch, tmp_path):
    # Every fallback disallowed -> empty chain -> the wiring skips failover and
    # runs only the (unchanged) primary, never a forbidden fallback.
    from maverick.llm import _allowlist_filter_fallbacks
    ro = _point_overlay(monkeypatch, tmp_path)
    ro.set_allowed_models(["anthropic:claude-sonnet-4-6"])
    assert _allowlist_filter_fallbacks(["openai:gpt-4.1", "gemini:g"]) == []


def test_failover_records_failure_into_cooldown_ledger(_policy_window):
    from maverick.provider_failover import failover

    def bad():
        raise RuntimeError("provider down")

    def good():
        return "ok"

    out = failover([("bad-model", bad), ("good-model", good)])
    assert out == "ok"
    led = _policy_window.shared_ledger()
    # The failed model is now cooling (threshold=1); the one that answered isn't.
    assert led.in_cooldown("bad-model") is True
    assert led.in_cooldown("good-model") is False


def test_failover_control_signal_does_not_cool(_policy_window):
    from maverick.provider_failover import failover

    def control_denied():
        raise ValueError("budget exceeded")

    # should_retry=False -> a deliberate control signal, not a provider failure;
    # the model must NOT be cooled for it.
    with pytest.raises(ValueError):
        failover([("m", control_denied)], should_retry=lambda e: False)
    assert _policy_window.shared_ledger().in_cooldown("m") is False


def test_afailover_records_failure_into_cooldown_ledger(_policy_window):
    import asyncio

    from maverick.provider_failover import afailover

    async def bad():
        raise RuntimeError("provider down")

    async def good():
        return "ok"

    out = asyncio.run(afailover([("bad-async", bad), ("good-async", good)]))
    assert out == "ok"
    led = _policy_window.shared_ledger()
    assert led.in_cooldown("bad-async") is True
    assert led.in_cooldown("good-async") is False
