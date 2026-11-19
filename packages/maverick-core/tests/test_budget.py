"""Budget cap tests."""
from __future__ import annotations

import logging
import pickle
from datetime import datetime, timedelta, timezone

import maverick.budget as budget_mod
import pytest
from maverick.budget import (
    Budget,
    BudgetExceeded,
    UnpricedModelError,
    _lookup_price,
)


def test_budget_under_caps():
    b = Budget(max_dollars=1.0, max_input_tokens=10_000)
    b.record_tokens(1000, 500)
    assert b.input_tokens == 1000
    assert b.output_tokens == 500
    assert b.dollars < 1.0


def test_budget_input_token_excess():
    b = Budget(max_input_tokens=100)
    with pytest.raises(BudgetExceeded):
        b.record_tokens(200, 0)


def test_budget_output_token_excess():
    b = Budget(max_output_tokens=100)
    with pytest.raises(BudgetExceeded):
        b.record_tokens(0, 200)


def test_budget_tool_call_excess():
    b = Budget(max_tool_calls=2)
    b.record_tool_call()
    b.record_tool_call()
    with pytest.raises(BudgetExceeded):
        b.record_tool_call()


def test_budget_summary_contains_expected_fields():
    b = Budget()
    s = b.summary()
    assert "tokens" in s
    assert "wall" in s
    assert "tools" in s


@pytest.fixture(autouse=True)
def _reset_unpriced_warned():
    saved = set(budget_mod._UNPRICED_WARNED)
    budget_mod._UNPRICED_WARNED.clear()
    yield
    budget_mod._UNPRICED_WARNED.clear()
    budget_mod._UNPRICED_WARNED.update(saved)


def test_known_model_priced_from_table():
    in_rate, out_rate = _lookup_price("claude-sonnet-4-6")
    assert (in_rate, out_rate) == (3.0, 15.0)


def test_unknown_model_estimate_warns_once_then_falls_back(monkeypatch, caplog):
    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    monkeypatch.setattr("maverick.config.get_budget_overrides", dict)
    with caplog.at_level(logging.WARNING, logger="maverick.budget"):
        first = _lookup_price("totally-made-up-model", estimate_only=True)
        second = _lookup_price("totally-made-up-model", estimate_only=True)
    assert first == second == (3.0, 15.0)  # documented Sonnet fallback estimate
    unpriced = [r for r in caplog.records if "no verified price" in r.getMessage()]
    assert len(unpriced) == 1  # warned once, not per call


def test_none_model_does_not_warn(monkeypatch, caplog):
    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    with caplog.at_level(logging.WARNING, logger="maverick.budget"):
        assert _lookup_price(None) == (3.0, 15.0)
    assert not [r for r in caplog.records if "no verified price" in r.getMessage()]


def test_strict_pricing_raises_on_unknown_model(monkeypatch):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    with pytest.raises(UnpricedModelError, match="no verified"):
        _lookup_price("totally-made-up-model")


def test_admin_ceiling_prices_only_its_exact_route_and_survives_other_settings(
    monkeypatch, tmp_path,
):
    from maverick import runtime_overrides as ro

    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    today = datetime.now(timezone.utc).date()
    ro.set_model_rate(
        "openai_compatible:client-model", input_per_mtok=4.0,
        output_per_mtok=12.0, source="Customer contract R1",
        as_of=today.isoformat(), valid_until=(today + timedelta(days=30)).isoformat(),
        approved_by="operator@example.com",
    )
    ro.disable_tool("shell")
    quote = budget_mod._lookup_price_quote("openai_compatible:client-model")
    assert quote.rates == (4.0, 12.0)
    assert quote.verified is False
    assert quote.rate_card_version == "operator-ceiling-v1"
    assert Budget(max_dollars=20).record_tokens(
        1_000_000, 1_000_000, model="openai_compatible:client-model",
    ).dollars == 16.0
    assert Budget(max_dollars=10).record_tokens(
        0, 0, model="openai_compatible:client-model",
        cache_read_tok=1_000_000, cache_read_mult=0.1,
    ).dollars == 4.0  # an unknown gateway never inherits a cache discount
    with pytest.raises(UnpricedModelError):
        _lookup_price("azure:client-model")
    with pytest.raises(ValueError, match="zero-cost"):
        ro.set_model_rate(
            "openai_compatible:free-claim", input_per_mtok=0,
            output_per_mtok=0, source="Unverified claim",
            as_of=today.isoformat(), valid_until=today.isoformat(),
            approved_by="operator@example.com",
        )
    ro.clear_model_rate("openai_compatible:client-model")
    with pytest.raises(UnpricedModelError):
        _lookup_price("openai_compatible:client-model")


def test_expired_operator_ceiling_stops_before_dispatch(monkeypatch, tmp_path):
    from maverick import runtime_overrides as ro

    path = tmp_path / "runtime-overrides.toml"
    monkeypatch.setattr(ro, "OVERRIDES_PATH", path)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    ro.set_model_rate(
        "openai_compatible:client-model", input_per_mtok=4.0,
        output_per_mtok=12.0, source="Customer contract R1",
        as_of=yesterday.isoformat(), valid_until=today.isoformat(),
        approved_by="operator@example.com",
    )
    current = path.read_text(encoding="utf-8")
    expired = current.replace(
        f'"valid_until" = "{today.isoformat()}"',
        f'"valid_until" = "{yesterday.isoformat()}"',
        1,
    )
    assert expired != current
    path.write_text(expired, encoding="utf-8")
    with pytest.raises(UnpricedModelError):
        _lookup_price("openai_compatible:client-model")


def test_strict_pricing_allows_known_and_selfhosted(monkeypatch):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    # A table model is fine.
    assert _lookup_price("claude-sonnet-4-6") == (3.0, 15.0)
    # A self-hosted ($0) model is priced, not refused.
    assert _lookup_price("ollama:llama-4-maverick") == (0.0, 0.0)


_CEILING = budget_mod._SELF_HOSTED_PUBLIC_CEILING


@pytest.mark.parametrize("table,env,expected", [
    ({}, {}, (0.0, 0.0)),  # default localhost
    ({"base_url": "http://10.0.0.5:11434"}, {}, (0.0, 0.0)),
    ({"base_url": "http://ollama:11434"}, {}, (0.0, 0.0)),  # compose service name
    ({"base_url": "http://100.101.1.2:11434"}, {}, (0.0, 0.0)),  # Tailscale / CGNAT
    ({"base_url": "http://gpu.tail1234.ts.net:11434"}, {}, (0.0, 0.0)),  # MagicDNS
    ({"base_url": "http://gpu.home:11434"}, {}, (0.0, 0.0)),
    ({"base_url": "http://gpu.corp:11434"}, {}, (0.0, 0.0)),
    ({"base_url": "http://gpu.example.org:11434"}, {}, _CEILING),  # not known private
    ({}, {"VLLM_BASE_URL": "https://api.openai.com"}, _CEILING),
    ({"base_url": "https://api.openai.com"}, {}, _CEILING),
    ({"base_url": "https://gpu.example.com", "price_per_mtok": [0.5, 1.5]}, {}, (0.5, 1.5)),
    ({"base_url": "https://gpu.example.com", "price_per_mtok": "free"}, {}, (0.0, 0.0)),
    ({"base_url": "https://gpu.example.com", "price_per_mtok": "cheap"}, {}, _CEILING),
])
def test_self_hosted_route_is_free_only_on_a_private_address(monkeypatch, caplog, table, env, expected):
    """DR 8: a self-hosted adapter pointed at a public address may be a paid
    service. Without a price or an explicit "free", charge a safety ceiling and
    say so, so the spending limit still holds."""
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    for name in ("VLLM_BASE_URL", "TGI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("maverick.config.get_provider_config", lambda provider: dict(table))
    budget_mod._UNPRICED_WARNED.clear()
    provider = "vllm" if env else "ollama"
    with caplog.at_level(logging.WARNING, logger="maverick.budget"):
        quote = budget_mod._lookup_price_quote(f"{provider}:some-model")
    assert quote.rates == expected
    assert ("public address" in caplog.text) is (expected == _CEILING)


@pytest.mark.parametrize("url,private", [
    ("http://134744072:11434/v1", False),  # 8.8.8.8 written as one number
    ("http://0x08080808:11434", False),  # 8.8.8.8 in hex
    ("http://[::ffff:8.8.8.8]:11434", False),
    ("http://0177.0.0.1:11434", True),  # octal loopback
    ("http://127.1:11434", True),
    ("http://2130706433:11434", True),  # 127.0.0.1 as one number
    ("http://0x7f000001:11434", True),
    ("http://[fd00::5]:11434", True),  # unique local
    ("http://169.254.169.254", False),  # cloud metadata is not a model server
    ("http://ollama:11434", True),  # a real single-label name
])
def test_ip_literals_are_classified_by_address_not_by_name(url, private):
    """The OS resolver turns numeric hosts into addresses without DNS; price
    them by the address, never by the single-label name rule."""
    assert budget_mod._is_private_endpoint(url) is private


def test_ceiling_charge_is_named_in_the_cap_error_and_cost_line(monkeypatch):
    """A cap tripped by the safety ceiling says so and names the fix."""
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda provider: {"base_url": "https://gpu.example.org"})
    budget = Budget(max_dollars=1.0)
    with pytest.raises(budget_mod.BudgetExceeded) as exceeded:
        for _ in range(3):
            budget.record_tokens(0, 10_000, model="ollama:llama3")
    for text in (str(exceeded.value), budget.summary()):
        assert "safety ceiling" in text and "ollama:llama3" in text
        assert "mark it free" in text
    budget.mark_usage_estimated()
    assert "estimated" in budget.summary()


def test_doctor_names_a_public_self_hosted_server_without_a_price(monkeypatch, capsys):
    import maverick.health as health

    tables = {"ollama": {"base_url": "https://gpu.example.com"},
              "vllm": {"base_url": "http://127.0.0.1:8000"}}
    for name in ("VLLM_BASE_URL", "TGI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda provider: dict(tables.get(provider, {})))
    health._FAILURES.clear()
    health._check_self_hosted_prices()
    out = capsys.readouterr().out
    assert "ollama price" in out and "gpu.example.com" in out and "price_per_mtok" in out
    assert "cannot tell" in out and "not on this machine" not in out
    assert "vllm" not in out and "tgi" not in out
    assert health._FAILURES == []  # advisory, not a failure


def test_strict_pricing_prices_openrouter_models_the_provider_lists_as_free(monkeypatch):
    """OpenRouter's own listing says a model costs $0 for prompt and completion
    (its ``:free`` and stealth preview models). That published rate must price
    the run at zero under strict billing instead of refusing it as unpriced,
    while anything OpenRouter prices above zero, or never listed, still fails
    closed, and the same id on another provider is not free by association."""
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    from maverick import model_discovery
    monkeypatch.setattr(
        model_discovery, "free_models",
        lambda provider: ["stealth/union-alpha"] if provider == "openrouter" else [],
    )
    assert _lookup_price("openrouter:stealth/union-alpha") == (0.0, 0.0)
    quote = budget_mod._lookup_price_quote("openrouter:stealth/union-alpha")
    assert quote.evidence_id == "openrouter-advertised-free-tier-policy-2026-09-16"
    assert quote.verified is True and quote.rates == (0.0, 0.0)
    with pytest.raises(UnpricedModelError, match="no verified"):
        _lookup_price("openrouter:vendor/paid-model")
    with pytest.raises(UnpricedModelError, match="no verified"):
        _lookup_price("openai:stealth/union-alpha")


def test_strict_pricing_survives_a_broken_discovery_cache(monkeypatch):
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    from maverick import model_discovery

    def boom(_provider):
        raise RuntimeError("cache unreadable")

    monkeypatch.setattr(model_discovery, "free_models", boom)
    with pytest.raises(UnpricedModelError, match="no verified"):
        _lookup_price("openrouter:stealth/union-alpha")


def test_strict_pricing_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_BILLING_STRICT", raising=False)
    monkeypatch.setattr("maverick.config.get_budget_overrides",
                        lambda: {"strict_pricing": True})
    with pytest.raises(UnpricedModelError):
        _lookup_price("totally-made-up-model")


def test_cache_hit_rate_consolidates_across_providers():
    b = Budget(max_dollars=1000.0, max_input_tokens=10_000_000)
    # No traffic yet -> 0.0, never divides by zero.
    assert b.cache_hit_rate() == 0.0
    # 200 billable input + 800 cache-read => 80% served from cache.
    b.record_tokens(200, 10, cache_read_tok=800)
    assert b.cache_hit_rate() == 0.8
    stats = b.cache_stats()
    assert stats["cache_read_tokens"] == 800
    assert stats["billable_input_tokens"] == 200
    assert stats["hit_rate"] == 0.8
    assert "hit_rate" in b.summary()


@pytest.mark.parametrize(
    "bad_multiplier",
    [float("nan"), float("inf"), float("-inf"), -0.1, True, "unpriced"],
)
def test_cache_read_multiplier_rejects_invalid_values_before_mutation(bad_multiplier):
    budget = Budget(max_dollars=0.000_001)
    before = budget.summary(), budget.dollars, budget.pricing_snapshot()

    with pytest.raises(BudgetExceeded, match="cache read multiplier"):
        budget.record_tokens(
            0,
            0,
            cache_read_tok=1,
            cache_read_mult=bad_multiplier,
        )

    assert (budget.summary(), budget.dollars, budget.pricing_snapshot()) == before
    budget.dollars = budget.max_dollars
    with pytest.raises(BudgetExceeded):
        budget.reserve(0.000_001)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("dollars", float("nan")),
        ("dollars", float("inf")),
        ("_reserved", float("nan")),
        ("input_tokens", -1),
        ("output_tokens", 1.5),
        ("tool_calls", True),
    ],
)
def test_check_rejects_corrupted_accounting_state(field, bad_value):
    budget = Budget()
    setattr(budget, field, bad_value)

    with pytest.raises(BudgetExceeded, match="invalid"):
        budget.check()


def test_restore_rejects_nonfinite_accounting_state():
    original = Budget()
    state = original.__getstate__()
    state["dollars"] = float("nan")
    restored = Budget.__new__(Budget)

    with pytest.raises(BudgetExceeded, match="invalid dollars"):
        restored.__setstate__(state)


def test_token_operation_replays_once_after_budget_is_serialized():
    budget = Budget(max_output_tokens=10, max_dollars=100)
    operation = "a" * 64
    first = budget.record_tokens(
        0, 1, model="codex_cli:gpt-5.5", operation_id=operation,
    )
    restored = pickle.loads(pickle.dumps(budget))
    replayed = restored.record_tokens(
        0, 1, model="codex_cli:gpt-5.5", operation_id=operation,
    )

    assert replayed == first
    assert restored.output_tokens == 1
    assert restored.dollars == budget.dollars
    with pytest.raises(BudgetExceeded, match="different usage"):
        restored.record_tokens(
            0, 2, model="codex_cli:gpt-5.5", operation_id=operation,
        )
    assert restored.output_tokens == 1


def test_restore_rejects_corrupted_token_operation_state():
    original = Budget()
    state = original.__getstate__()
    state["_token_operations"] = {
        "b" * 64: {
            "request": "c" * 64,
            "dollars": float("nan"),
            "pricing_evidence": {},
            "failure": None,
        },
    }
    restored = Budget.__new__(Budget)

    with pytest.raises(BudgetExceeded, match="stored token charge"):
        restored.__setstate__(state)


class TestCacheTtlNormalization:
    def test_trailing_space_normalized(self):
        from maverick.budget import _cache_write_mult_from_ttl
        assert _cache_write_mult_from_ttl("1h ") == 2.0
        assert _cache_write_mult_from_ttl(" 1h") == 2.0

    def test_uppercase_normalized(self):
        from maverick.budget import _cache_write_mult_from_ttl
        assert _cache_write_mult_from_ttl("1H") == 2.0

    def test_duration_parsing_handles_unknown_strings(self):
        from maverick.budget import _cache_write_mult_from_ttl
        # 30 minutes > 5m → 1h rate
        assert _cache_write_mult_from_ttl("30m") == 2.0
        # 2h > 1h → 1h rate (the upper tier)
        assert _cache_write_mult_from_ttl("2h") == 2.0
        # 7200s = 2h → 1h rate
        assert _cache_write_mult_from_ttl("7200s") == 2.0
        # 5m or below → 5m rate
        assert _cache_write_mult_from_ttl("5m") == 1.25
        assert _cache_write_mult_from_ttl("1m") == 1.25

    def test_unknown_garbage_defaults_to_5m(self):
        from maverick.budget import _cache_write_mult_from_ttl
        assert _cache_write_mult_from_ttl("forever") == 1.25
        assert _cache_write_mult_from_ttl("") == 1.25
        assert _cache_write_mult_from_ttl(None) == 1.25


class TestBudgetPickling:
    def test_round_trip_preserves_counters(self):
        from maverick.budget import Budget
        from maverick.llm import MODEL_SONNET

        b = Budget(max_dollars=100.0)
        b.record_tokens(10_000, 1000, model=MODEL_SONNET)
        original_dollars = b.dollars

        # multiprocessing.Pool ships via pickle.
        data = pickle.dumps(b)
        b2 = pickle.loads(data)
        assert b2.input_tokens == 10_000
        assert b2.output_tokens == 1000
        assert abs(b2.dollars - original_dollars) < 0.001
        # The new Budget has its own monotonic clock + lock.
        assert b2.elapsed() >= 0
        b2.record_tokens(1000, 100, model=MODEL_SONNET)
        # Both lock and counter survived.
        assert b2.input_tokens == 11_000


    def test_round_trip_preserves_elapsed_for_wall_cap(self):
        from maverick.budget import Budget, BudgetExceeded

        b = Budget(max_wall_seconds=0.01)
        # Exhaust wall-time budget before serialization.
        while b.elapsed() <= 0.02:
            pass
        try:
            b.check()
        except BudgetExceeded:
            pass
        else:
            raise AssertionError("pre-pickle budget should already be exceeded")

        b2 = pickle.loads(pickle.dumps(b))
        # Must remain exceeded after unpickle (no timer reset bypass).
        try:
            b2.check()
        except BudgetExceeded:
            pass
        else:
            raise AssertionError("post-unpickle wall cap bypassed")


# ---------- Budget separates cache tokens from input cap ----------

def test_input_cap_not_eaten_by_cache_reads():
    """A long cached prompt shouldn't prematurely trip max_input_tokens."""
    from maverick.budget import Budget
    from maverick.llm import MODEL_SONNET

    b = Budget(max_dollars=100.0, max_input_tokens=200_000)
    # 5x re-runs against a 100k-token cached system prompt: 500k cached
    # reads, only 1000 actual billable input each time.
    for _ in range(5):
        b.record_tokens(
            1_000, 1_000, model=MODEL_SONNET,
            cache_read_tok=100_000,
        )
    # Billable input is 5_000; cache reads were 500_000.
    assert b.input_tokens == 5_000
    assert b.cache_read_tokens == 500_000
    # The cap on billable input was NEVER tripped.


@pytest.mark.parametrize("table,priced", [
    ({"base_url": "http://127.0.0.1:1234/v1"}, False),  # LM Studio, not marked
    ({"base_url": "http://127.0.0.1:1234/v1", "price_per_mtok": "free"}, True),
    ({"base_url": "http://192.168.1.20:8080/v1", "price_per_mtok": "free"}, True),
    ({"base_url": "https://api.groq.com/openai/v1", "price_per_mtok": "free"}, False),
    ({"price_per_mtok": "free"}, False),  # no address: nothing to vouch for
    ({"base_url": "http://169.254.169.254/v1", "price_per_mtok": "free"}, False),
])
def test_openai_compatible_server_is_free_only_when_marked_and_private(monkeypatch, table, priced):
    """An OpenAI-compatible server also fronts paid gateways, so it is never free
    on its own address alone; an owner may mark one on this computer or a
    private network free. Unmarked or public, it still stops before spending."""
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "1")
    monkeypatch.delenv("OPENAI_COMPATIBLE_BASE_URL", raising=False)
    monkeypatch.setattr("maverick.config.get_provider_config", lambda provider: dict(table))
    if priced:
        assert budget_mod._lookup_price_quote("openai_compatible:local-model").rates == (0.0, 0.0)
        assert budget_mod.self_hosted_price_state("openai_compatible") == "marked_free"
    else:
        with pytest.raises(UnpricedModelError):
            budget_mod._lookup_price_quote("openai_compatible:local-model")
        assert budget_mod.self_hosted_price_state("openai_compatible") == "needs_price"
