"""Tests for the provider-failover policy engine: error classification,
class-gated retry, cooldown ledger, chain ordering, and the v1-compat default."""
from __future__ import annotations

import pytest
from maverick import failover_policy as fp


class _StatusErr(Exception):
    def __init__(self, status_code: int, msg: str = "x"):
        super().__init__(msg)
        self.status_code = status_code


class TestClassify:
    def test_status_codes_win(self):
        assert fp.classify_error(_StatusErr(401)) == "auth"
        assert fp.classify_error(_StatusErr(403)) == "auth"
        assert fp.classify_error(_StatusErr(429)) == "rate_limit"
        assert fp.classify_error(_StatusErr(404)) == "bad_request"
        assert fp.classify_error(_StatusErr(503)) == "server"

    def test_message_heuristics(self):
        assert fp.classify_error(RuntimeError("Request timed out")) == "timeout"
        assert fp.classify_error(RuntimeError("rate limit exceeded")) == "rate_limit"
        assert fp.classify_error(RuntimeError("invalid api key")) == "auth"
        assert fp.classify_error(ConnectionError("connection refused")) == "network"
        assert fp.classify_error(RuntimeError("502 Bad Gateway")) == "server"
        assert fp.classify_error(RuntimeError("mystery")) == "other"

    def test_timeout_type(self):
        assert fp.classify_error(TimeoutError()) == "timeout"


class TestPolicyShouldRetry:
    def test_no_policy_table_keeps_v1_semantics(self, monkeypatch):
        monkeypatch.setattr(fp, "_policy_cfg", dict)
        # v1: ANY non-control exception fails over -- even auth.
        assert fp.policy_should_retry(_StatusErr(401)) is True
        assert fp.policy_should_retry(RuntimeError("boom")) is True

    def test_policy_gates_by_class(self, monkeypatch):
        monkeypatch.setattr(
            fp, "_policy_cfg",
            lambda: {"failover_on": ["rate_limit", "timeout"]},
        )
        assert fp.policy_should_retry(_StatusErr(429)) is True
        assert fp.policy_should_retry(TimeoutError()) is True
        assert fp.policy_should_retry(_StatusErr(401)) is False   # auth: fail fast
        assert fp.policy_should_retry(RuntimeError("mystery")) is False  # other off

    def test_control_signals_never_fail_over(self, monkeypatch):
        from maverick.budget import BudgetExceeded
        monkeypatch.setattr(fp, "_policy_cfg", lambda: {"failover_on": ["other"]})
        assert fp.policy_should_retry(BudgetExceeded("cap")) is False

    def test_bogus_classes_fall_back_to_default(self, monkeypatch):
        monkeypatch.setattr(fp, "_policy_cfg", lambda: {"failover_on": ["banana"]})
        assert fp.failover_classes() == frozenset(
            {"rate_limit", "timeout", "network", "server", "other"})


class TestCooldownLedger:
    def test_threshold_then_cooldown_then_expiry(self):
        now = [0.0]
        led = fp.CooldownLedger(window_s=60, threshold=2, clock=lambda: now[0])
        led.record_failure("openai:gpt")
        assert not led.in_cooldown("openai:gpt")  # 1 strike < threshold
        led.record_failure("openai:gpt")
        assert led.in_cooldown("openai:gpt")      # tripped
        now[0] = 61.0
        assert not led.in_cooldown("openai:gpt")  # window elapsed
        # strikes were reset by expiry: one more failure doesn't re-trip
        led.record_failure("openai:gpt")
        assert not led.in_cooldown("openai:gpt")

    def test_success_clears_strikes(self):
        led = fp.CooldownLedger(window_s=60, threshold=2, clock=lambda: 0.0)
        led.record_failure("m")
        led.record_success("m")
        led.record_failure("m")
        assert not led.in_cooldown("m")

    def test_zero_window_disables(self):
        led = fp.CooldownLedger(window_s=0, threshold=1, clock=lambda: 0.0)
        led.record_failure("m")
        assert not led.in_cooldown("m")

    def test_validation(self):
        with pytest.raises(ValueError):
            fp.CooldownLedger(window_s=-1)
        with pytest.raises(ValueError):
            fp.CooldownLedger(window_s=1, threshold=0)


class TestOrderChain:
    def test_filters_cooled_models_keeps_order(self):
        led = fp.CooldownLedger(window_s=60, threshold=1, clock=lambda: 0.0)
        led.record_failure("b")
        assert fp.order_chain(["a", "b", "c"], led) == ["a", "c"]

    def test_all_cooled_returns_original(self):
        led = fp.CooldownLedger(window_s=60, threshold=1, clock=lambda: 0.0)
        for m in ("a", "b"):
            led.record_failure(m)
        assert fp.order_chain(["a", "b"], led) == ["a", "b"]


class TestSharedLedger:
    def test_built_from_config_and_resettable(self, monkeypatch):
        fp.reset_shared_ledger()
        monkeypatch.setattr(
            fp, "_policy_cfg", lambda: {"cooldown_s": 30, "cooldown_after": 1})
        led = fp.shared_ledger()
        assert led.window_s == 30 and led.threshold == 1
        assert fp.shared_ledger() is led  # cached
        fp.reset_shared_ledger()
        monkeypatch.setattr(fp, "_policy_cfg", dict)
        led2 = fp.shared_ledger()
        assert led2.window_s == 0  # cooldowns off by default
        fp.reset_shared_ledger()
