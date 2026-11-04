"""Circuit breaker must only trip on genuine provider-transport failures.

Not every exception escaping ``client.complete`` is a provider failure:
``BudgetExceeded`` raised *after* a successful API call, ``UnpricedModelError``
and ordinary 4xx client errors are not. Counting them would let a single
fan-out goal that hits its dollar cap (N parallel sub-agents each raising
BudgetExceeded) trip the breaker and take the provider offline for every
concurrent goal and tenant sharing the process.
"""
from __future__ import annotations

import pytest


class _StatusError(Exception):
    def __init__(self, status_code, message="boom"):
        super().__init__(message)
        self.status_code = status_code


class TestIsProviderTransportFailure:
    def test_budget_exceeded_is_never_a_transport_failure(self):
        from maverick.budget import BudgetExceeded
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(BudgetExceeded("over cap")) is False

    def test_unpriced_model_error_is_never_a_transport_failure(self):
        """UnpricedModelError subclasses BudgetExceeded."""
        from maverick.budget import UnpricedModelError
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(UnpricedModelError("no rate")) is False

    def test_model_not_allowed_is_never_a_transport_failure(self):
        from maverick.llm import ModelNotAllowedError, _is_provider_transport_failure
        assert _is_provider_transport_failure(ModelNotAllowedError("denied")) is False

    def test_preflight_failed_is_never_a_transport_failure(self):
        from maverick.llm import _is_provider_transport_failure
        from maverick.preflight import PreflightFailed
        exc = PreflightFailed(model="claude-opus-4-8", estimated=500_000,
                              limit=200_000, max_tokens=4096)
        assert _is_provider_transport_failure(exc) is False

    def test_egress_blocked_is_never_a_transport_failure(self):
        from maverick.enterprise import EgressBlocked
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(EgressBlocked("denied host")) is False

    def test_4xx_client_error_is_never_a_transport_failure(self):
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(_StatusError(400, "bad request")) is False
        assert _is_provider_transport_failure(_StatusError(401, "unauthorized")) is False
        assert _is_provider_transport_failure(_StatusError(404, "not found")) is False

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_rate_limit_and_server_errors_are_transport_failures(self, status):
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(_StatusError(status)) is True

    def test_connection_error_is_a_transport_failure(self):
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(ConnectionError("connection reset")) is True

    def test_timeout_error_is_a_transport_failure(self):
        from maverick.llm import _is_provider_transport_failure
        assert _is_provider_transport_failure(TimeoutError("deadline exceeded")) is True


class TestFeedCircuitClassificationIntegration:
    """Prove the classification is actually wired into the dispatch path,
    not just defined and unused."""

    def _client_raising(self, exc):
        class _Client:
            def complete(self, **kwargs):
                raise exc
            async def complete_async(self, **kwargs):
                raise exc
        return _Client()

    @pytest.mark.parametrize("guard", ["cap", "accounting"])
    @pytest.mark.parametrize("asynchronous", [False, True])
    def test_local_accounting_refusal_does_not_change_provider_health(self, monkeypatch, guard, asynchronous):
        import asyncio
        from types import SimpleNamespace

        from maverick.budget import Budget
        from maverick.llm import LLM
        from maverick.provider_cost_cap import ProviderAccountingUnavailable, ProviderCapExceeded

        error = ProviderAccountingUnavailable() if guard == "accounting" else ProviderCapExceeded("anthropic", 10, 10, "2026-10")
        observed = []
        monkeypatch.setattr("maverick.llm._feed_circuit", lambda *args: observed.append("circuit"))
        monkeypatch.setattr("maverick.llm._note_bandit", lambda *args: observed.append("routing"))
        monkeypatch.setattr("maverick.provider_health.get", lambda: SimpleNamespace(record=lambda *args, **kwargs: observed.append("health")))
        monkeypatch.setattr("maverick.llm._run_preflight", lambda *args, **kwargs: None)
        monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda *args, **kwargs: None)
        monkeypatch.setattr(LLM, "_get_client", lambda self, provider: self._unused_client)
        client = SimpleNamespace(complete=lambda **kwargs: pytest.fail("A refused call cannot reach the provider"))

        def refuse(*args, **kwargs):
            raise error

        monkeypatch.setattr("maverick.llm._reserve_provider_call", refuse)
        llm = LLM(model="anthropic:claude-sonnet-4-6")
        llm._unused_client = client
        for _ in range(5):
            with pytest.raises(type(error)):
                method = llm.complete_async if asynchronous else llm.complete
                result = method("sys", [{"role": "user", "content": "hi"}], budget=Budget(max_dollars=100.0))
                if asynchronous:
                    asyncio.run(result)
        assert observed == []  # A local refusal neither trips nor resets shared health.

    def test_complete_feeds_circuit_success_false_for_budget_exceeded(self, monkeypatch):
        from maverick.budget import Budget, BudgetExceeded
        from maverick.llm import LLM

        recorded = []
        monkeypatch.setattr("maverick.llm._feed_circuit",
                            lambda provider, error: recorded.append((provider, error)))
        monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
        client = self._client_raising(BudgetExceeded("over cap"))
        monkeypatch.setattr(LLM, "_get_client", lambda self, provider: client)

        with pytest.raises(BudgetExceeded):
            LLM(model="anthropic:claude-sonnet-4-6").complete(
                "sys", [{"role": "user", "content": "hi"}],
                budget=Budget(max_dollars=100.0),
            )
        assert recorded == [("anthropic", False)]

    def test_complete_feeds_circuit_failure_true_for_rate_limit(self, monkeypatch):
        from maverick.budget import Budget
        from maverick.llm import LLM

        recorded = []
        monkeypatch.setattr("maverick.llm._feed_circuit",
                            lambda provider, error: recorded.append((provider, error)))
        monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None)
        client = self._client_raising(_StatusError(429, "rate limited"))
        monkeypatch.setattr(LLM, "_get_client", lambda self, provider: client)

        with pytest.raises(_StatusError):
            LLM(model="anthropic:claude-sonnet-4-6").complete(
                "sys", [{"role": "user", "content": "hi"}],
                budget=Budget(max_dollars=100.0),
            )
        assert recorded == [("anthropic", True)]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_native_dispatch_isolates_connection_outage_after_rotation(monkeypatch, asynchronous):
    import asyncio
    from types import SimpleNamespace

    from maverick import circuit_breaker
    from maverick.budget import Budget
    from maverick.llm import LLM

    route = {"base_url": "https://unavailable.fixture.invalid", "api_key": "fixture-key"}  # pragma: allowlist secret -- test fixture key
    calls = {}

    class Client:
        def __init__(self, address):
            self.address = address

        def complete(self, **kwargs):
            calls[self.address] = calls.get(self.address, 0) + 1
            if "unavailable" in self.address:
                raise TimeoutError("fixture connection timed out")
            return SimpleNamespace(content=[], input_tokens=0, output_tokens=0,
                                   cache_read_tokens=0, cache_write_tokens=0)

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    monkeypatch.setattr("maverick.llm._provider_config_snapshot", lambda _: (dict(route), {}))
    monkeypatch.setattr("maverick.providers.get_provider_client", lambda provider, **kwargs: Client(kwargs["base_url"]))
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda *args, **kwargs: None)
    circuit_breaker.reset_all()
    dispatcher = LLM(model="anthropic:claude-sonnet-4-6")

    def call():
        method = dispatcher.complete_async if asynchronous else dispatcher.complete
        result = method("fixture", [{"role": "user", "content": "hello"}], budget=Budget(max_dollars=100))
        return asyncio.run(result) if asynchronous else result

    try:
        for _ in range(5):
            with pytest.raises(TimeoutError):
                call()
        with pytest.raises(circuit_breaker.CircuitOpen):
            call()
        old_address = route["base_url"]
        route["base_url"] = "https://healthy.fixture.invalid"
        assert call().content == []
        states = circuit_breaker.snapshot()
        assert sorted(item["state"] for item in states) == ["closed", "open"]
        assert calls == {old_address: 5, route["base_url"]: 1}
        assert all("fixture-key" not in item["key"] and ".invalid" not in item["key"] for item in states)
        route["base_url"] = old_address
        with pytest.raises(circuit_breaker.CircuitOpen):
            call()  # Returning to the same unhealthy connection keeps its cooldown.
        assert calls[old_address] == 5
    finally:
        circuit_breaker.reset_all()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_llm_releases_locally_refused_probe_without_false_health(monkeypatch, asynchronous):
    import asyncio
    from types import SimpleNamespace

    from maverick import circuit_breaker
    from maverick.budget import Budget
    from maverick.llm import LLM, _enforce_circuit
    from maverick.provider_cost_cap import ProviderAccountingUnavailable

    calls = []

    class Client:
        def complete(self, **kwargs):
            calls.append("sent")
            with pytest.raises(circuit_breaker.CircuitOpen):
                _enforce_circuit("anthropic")  # The in-flight probe owns admission.
            return SimpleNamespace(content=[], input_tokens=0, output_tokens=0,
                                   cache_read_tokens=0, cache_write_tokens=0)

        async def complete_async(self, **kwargs):
            return self.complete(**kwargs)

    monkeypatch.setattr(LLM, "_get_client", lambda *args: Client())
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr("maverick.llm._enforce_provider_cap", lambda *args, **kwargs: None)

    def refuse(*args, **kwargs):
        raise ProviderAccountingUnavailable

    monkeypatch.setattr("maverick.llm._reserve_provider_call", refuse)
    circuit_breaker.reset_all()
    breaker = circuit_breaker.get("llm:anthropic", failure_threshold=1, cooldown_seconds=0)
    breaker.record_failure()
    dispatcher = LLM(model="anthropic:claude-sonnet-4-6")

    def call():
        method = dispatcher.complete_async if asynchronous else dispatcher.complete
        result = method("fixture", [{"role": "user", "content": "hello"}], budget=Budget(max_dollars=100))
        return asyncio.run(result) if asynchronous else result

    try:
        with pytest.raises(ProviderAccountingUnavailable):
            call()
        assert breaker.state is circuit_breaker.CircuitState.HALF_OPEN
        assert breaker.snapshot()["total_failures"] == 1 and not calls
        monkeypatch.setattr("maverick.llm._reserve_provider_call", lambda *args, **kwargs: None)
        call()  # A refused local attempt released, rather than wedged, the probe.
        assert calls == ["sent"] and breaker.state is circuit_breaker.CircuitState.CLOSED
    finally:
        circuit_breaker.reset_all()
