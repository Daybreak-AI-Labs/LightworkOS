"""Per-model + cache-aware budget pricing.

The v0.1.x Budget hardcoded Sonnet pricing for every call. An Opus run
under max_dollars=5 let ~$25 of real spend through; Anthropic cache
read tokens were billed at full price (overcharging readers 10x) while
cache writes were billed at base rate (undercharging by 25%). These
tests pin the corrected math.
"""
from __future__ import annotations

import pytest
from maverick.budget import Budget
from maverick.llm import MODEL_HAIKU, MODEL_OPUS, MODEL_SONNET


def test_opus_priced_at_opus_rate():
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # Opus 4.7 May 2026 list = $5 in + $25 out per Mtok, not the legacy
    # Opus 4.0/4.1 rates of $15/$75. Verified against
    # https://platform.claude.com/docs/en/about-claude/pricing and against
    # vals.ai's measured $2.42/test for Opus 4.7 on SWE-bench Verified.
    # 1M input + 1M output = $5 + $25 = $30.
    b.record_tokens(1_000_000, 1_000_000, model=MODEL_OPUS)
    assert abs(b.dollars - 30.0) < 0.001


def test_sonnet_priced_at_sonnet_rate():
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # 1M input + 1M output on Sonnet = $3 in + $15 out = $18
    b.record_tokens(1_000_000, 1_000_000, model=MODEL_SONNET)
    assert abs(b.dollars - 18.0) < 0.001


def test_haiku_priced_at_haiku_rate():
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # Haiku 4.5 May 2026 list = $1.00 in + $5.00 out per Mtok.
    # 1M input + 1M output = $1 + $5 = $6 (was under-reported at $4.80
    # while the file claimed (0.80, 4.0)).
    b.record_tokens(1_000_000, 1_000_000, model=MODEL_HAIKU)
    assert abs(b.dollars - 6.0) < 0.001


def test_unknown_model_cannot_be_billed_at_sonnet_fallback():
    from maverick.budget import UnpricedModelError

    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    with pytest.raises(UnpricedModelError):
        b.record_tokens(1_000_000, 0, model="provider:unknown-future-model")
    assert b.dollars == 0.0
    assert b.input_tokens == 0


def test_router_selectable_models_bill_at_real_rate_not_fallback():
    """Every model the cost-router can SELECT must bill at its canonical
    rate, not the Sonnet $3/$15 fallback.

    cost_router._PRICING is reconciled to llm.MODEL_PRICES (one source of
    truth), so every router id lives in MODEL_PRICES and the
    rates are derived from it. This walks the router's own table and asserts
    Budget bills each id at the MODEL_PRICES rate -- catching any future id
    that drifts out of the canonical catalog and silently bills at fallback.
    """
    from maverick.budget import UnpricedModelError
    from maverick.cost.router import _PRICING
    from maverick.llm import MODEL_PRICES, MODEL_PRICING_PROVIDER

    saw_non_fallback = False
    for _provider, model, _tier, _in, _out in _PRICING:
        assert model in MODEL_PRICES, f"{model} not in canonical MODEL_PRICES"
        pin, pout = MODEL_PRICES[model]
        b = Budget(max_dollars=1e9, max_input_tokens=10_000_000,
                   max_output_tokens=10_000_000)
        if not MODEL_PRICING_PROVIDER.rates[model].verified:
            with pytest.raises(UnpricedModelError):
                b.record_tokens(1_000_000, 1_000_000, model=model)
            assert b.dollars == 0.0
            continue
        b.record_tokens(1_000_000, 1_000_000, model=model)
        assert abs(b.dollars - (pin + pout)) < 0.001, (
            f"{model}: billed ${b.dollars:.2f}, expected ${pin + pout:.2f}"
        )
        if abs((pin + pout) - 18.0) > 0.001:
            saw_non_fallback = True
    # Guard against a vacuous pass where every router id happens to equal the
    # $18 fallback (which would hide a real fallback regression).
    assert saw_non_fallback


def test_no_model_uses_fallback_rate():
    """Back-compat: callers that don't pass model get the legacy rate."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    b.record_tokens(1_000_000, 0)
    assert abs(b.dollars - 3.0) < 0.001


def test_cache_read_is_one_tenth_of_input():
    """Anthropic bills cache reads at 0.1x of input rate."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # 1M cache reads on Opus 4.7 = $5 * 0.1 = $0.50
    b.record_tokens(0, 0, model=MODEL_OPUS, cache_read_tok=1_000_000)
    assert abs(b.dollars - 0.5) < 0.001


def test_cache_write_5m_is_one_and_a_quarter_input():
    """Anthropic bills 5m-TTL cache writes at 1.25x of input rate."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # 1M cache writes on Sonnet = $3 * 1.25 = $3.75
    b.record_tokens(0, 0, model=MODEL_SONNET, cache_write_tok=1_000_000)
    assert abs(b.dollars - 3.75) < 0.001


def test_cache_write_1h_is_two_x_input():
    """Anthropic bills 1h-TTL cache writes at 2.0x (not 1.25x)."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # 1M cache writes on Sonnet at 1h = $3 * 2.0 = $6.00
    b.record_tokens(
        0, 0, model=MODEL_SONNET,
        cache_write_tok=1_000_000, cache_write_ttl="1h",
    )
    assert abs(b.dollars - 6.0) < 0.001


def test_cache_write_split_bills_each_tier_at_its_own_multiplier():
    """One call can write BOTH a 1h breakpoint (system/tools) and a
    5m breakpoint (messages) at once. Before this, the combined total was
    billed at a single multiplier (whichever cache_write_ttl the caller
    passed) -- forcing the whole write to 2.0x when only part of it was
    really 1h, or to 1.25x when only part was really 5m. Passing the split
    counts must bill each tier correctly regardless of one another."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # Sonnet: 500k @ 5m ($3 * 1.25 = $3.75/Mtok -> $1.875) +
    #         500k @ 1h ($3 * 2.0  = $6.00/Mtok -> $3.00) = $4.875.
    # A single combined-total call (cache_write_tok=1_000_000) at either
    # ttl alone would give $3.75 or $6.00 -- neither matches.
    b.record_tokens(
        0, 0, model=MODEL_SONNET,
        cache_write_5m_tok=500_000, cache_write_1h_tok=500_000,
    )
    assert abs(b.dollars - 4.875) < 0.001
    assert b.cache_write_tokens == 1_000_000


def test_cache_write_split_ignores_stale_combined_fields():
    """When the split is present, a caller-passed cache_write_tok/ttl (e.g.
    a stale fallback value computed alongside the split) must not also be
    billed -- the split is authoritative, not additive."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    b.record_tokens(
        0, 0, model=MODEL_SONNET,
        cache_write_tok=1_000_000, cache_write_ttl="1h",
        cache_write_5m_tok=1_000_000, cache_write_1h_tok=0,
    )
    # Only the 5m split should bill: $3 * 1.25 = $3.75, not the $6.00 the
    # ignored cache_write_tok=1_000_000/ttl="1h" combination would give.
    assert abs(b.dollars - 3.75) < 0.001


def test_cache_tokens_tracked_separately_from_input_cap():
    """max_input_tokens measures BILLABLE input only — cache reads/writes
    have their own counters. A heavy-caching workload should not be
    prematurely cap-killed for tokens it's getting at 0.1x rate."""
    b = Budget(max_dollars=100.0, max_input_tokens=2_500_000)
    b.record_tokens(
        1_000_000, 0, model=MODEL_SONNET,
        cache_read_tok=1_000_000, cache_write_tok=500_000,
    )
    assert b.input_tokens == 1_000_000
    assert b.cache_read_tokens == 1_000_000
    assert b.cache_write_tokens == 500_000


def test_opus_run_actually_hits_the_dollar_cap():
    """An Opus call past max_dollars must raise — proves Opus is billed at
    the actual Opus rate, not silently downgraded to fallback."""
    import pytest
    from maverick.budget import BudgetExceeded
    b = Budget(max_dollars=3.0)
    # Opus 4.7 @ $5/Mtok input: 1M input = $5.00 > $3 cap → BudgetExceeded.
    with pytest.raises(BudgetExceeded):
        b.record_tokens(1_000_000, 0, model=MODEL_OPUS)


def test_nullsafe_record_tokens_handles_none():
    """Anthropic occasionally returns None in usage on streaming
    refusals. The prior code raised TypeError and the instance counted
    as $0 spent (silent under-bill)."""
    b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
    # Should not raise even though both tokens are None.
    b.record_tokens(None, None, model=MODEL_SONNET)  # type: ignore[arg-type]
    assert b.dollars == 0.0
    assert b.input_tokens == 0
    assert b.output_tokens == 0


def test_wall_clock_uses_monotonic_clock():
    """budget.elapsed() must use a monotonic clock so NTP jumps
    don't bypass max_wall_seconds."""
    import time
    b = Budget(max_dollars=5.0, max_wall_seconds=3600.0)
    # elapsed() must be >= 0 even if wall clock has jumped backward.
    # Hard to simulate NTP jump in a unit test, but at least ensure the
    # implementation exists and returns sensible numbers.
    elapsed1 = b.elapsed()
    time.sleep(0.01)
    elapsed2 = b.elapsed()
    assert elapsed2 >= elapsed1
    assert elapsed1 >= 0.0


def test_record_tokens_thread_safe():
    """Concurrent record_tokens calls must not
    lose updates. Without the lock, `self.dollars += ...` races and
    silently undercounts (it's a load-then-store, not atomic)."""
    import threading

    from maverick.llm import MODEL_SONNET

    b = Budget(
        max_dollars=1000.0,
        max_input_tokens=100_000_000,
        max_output_tokens=100_000_000,
        max_tool_calls=100_000,
    )

    def worker():
        for _ in range(100):
            b.record_tokens(1000, 100, model=MODEL_SONNET)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 8 threads × 100 iterations × 1000 input tokens = 800_000 input tokens.
    assert b.input_tokens == 800_000, (
        f"input_tokens race detected: expected 800000, got {b.input_tokens}"
    )
    # 8 × 100 × 100 = 80_000 output tokens.
    assert b.output_tokens == 80_000


def test_record_tool_call_thread_safe():
    import threading
    b = Budget(max_dollars=100.0, max_tool_calls=100_000)

    def worker():
        for _ in range(500):
            b.record_tool_call()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert b.tool_calls == 2_000


def test_absorb_rolls_up_all_counters():
    """best_of_n folds each attempt's spend into the parent. The rollup must
    include cache tokens + tool_calls, not just dollars/in/out (the prior
    inline `+=` dropped them, under-reporting the parent's spend)."""
    parent = Budget(max_dollars=1000.0, max_input_tokens=10**9,
                    max_output_tokens=10**9, max_tool_calls=10**6)
    child = Budget(max_dollars=1000.0, max_input_tokens=10**9,
                   max_output_tokens=10**9, max_tool_calls=10**6)
    child.record_tokens(100, 50, model=MODEL_SONNET,
                        cache_read_tok=200, cache_write_tok=20)
    child.record_tool_call()
    child.record_tool_call()

    parent.absorb(child)
    assert parent.input_tokens == 100
    assert parent.output_tokens == 50
    assert parent.cache_read_tokens == 200
    assert parent.cache_write_tokens == 20
    assert parent.tool_calls == 2
    assert abs(parent.dollars - child.dollars) < 1e-9


def test_absorb_raises_when_aggregate_over_cap():
    """When the rolled-up spend exceeds a parent cap, absorb raises so
    best_of_n stops spawning attempts -- and the spend is still recorded."""
    import pytest
    from maverick.budget import BudgetExceeded

    parent = Budget(max_dollars=5.0)
    child = Budget(max_dollars=1000.0, max_input_tokens=10**9, max_output_tokens=10**9)
    child.record_tokens(1_000_000, 1_000_000, model=MODEL_SONNET)  # $18 on Sonnet
    with pytest.raises(BudgetExceeded):
        parent.absorb(child)
    # Counters were added BEFORE the cap check -> parent reflects the spend.
    assert abs(parent.dollars - 18.0) < 0.001


def test_cache_read_default_is_anthropic_tenth_rate():
    # Default (no cache_read_mult) bills cache reads at 0.1x input rate.
    b = Budget(max_dollars=1e9, max_input_tokens=10_000_000)
    b.record_tokens(0, 0, model=MODEL_OPUS, cache_read_tok=1_000_000)
    # Opus input = $5/Mtok -> 0.1x -> $0.50
    assert abs(b.dollars - 0.5) < 1e-6


def test_cache_read_openai_half_rate_is_5x_default():
    # Non-Anthropic cache reads are ~0.5x, not 0.1x. Passing the
    # OpenAI multiplier bills 5x the Anthropic-default amount for the same read.
    from maverick.budget import CACHE_READ_MULT_OPENAI
    assert CACHE_READ_MULT_OPENAI == 0.5
    b = Budget(max_dollars=1e9, max_input_tokens=10_000_000)
    b.record_tokens(0, 0, model=MODEL_OPUS, cache_read_tok=1_000_000,
                    cache_read_mult=CACHE_READ_MULT_OPENAI)
    # 0.5x of $5/Mtok = $2.50 (5x the 0.1x default of $0.50).
    assert abs(b.dollars - 2.5) < 1e-6


def test_older_opus_tiers_priced_at_opus_not_sonnet():
    # claude-opus-4-5/4-6 must not fall through to the Sonnet fallback
    # ($3/$15) -- a ~40% output-cost undercount. They bill at the Opus $5/$25
    # rate like 4.7/4.8.
    for model in ("claude-opus-4-5", "claude-opus-4-6", "claude-opus-4-7"):
        b = Budget(max_dollars=1e9, max_output_tokens=10_000_000)
        b.record_tokens(0, 1_000_000, model=model)
        assert abs(b.dollars - 25.0) < 1e-6, (model, b.dollars)
    # Sonnet stays at its own $15 rate (no accidental Opus bump).
    b = Budget(max_dollars=1e9, max_output_tokens=10_000_000)
    b.record_tokens(0, 1_000_000, model="claude-sonnet-4-6")
    assert abs(b.dollars - 15.0) < 1e-6


class TestOpusPricing:
    """Opus 4.7 is $5/$25 per Mtok — NOT $15/$75 (those were legacy
    Opus 4.0/4.1 rates). Cross-check: vals.ai measures Opus 4.7 at $2.42/test on SWE-bench
    Verified, which reconciles ONLY with $5/$25 pricing.
    """

    def test_opus_input_priced_at_5_per_mtok(self):
        b = Budget(max_dollars=100.0, max_input_tokens=10_000_000)
        b.record_tokens(1_000_000, 0, model=MODEL_OPUS)
        assert abs(b.dollars - 5.0) < 0.001

    def test_opus_output_priced_at_25_per_mtok(self):
        b = Budget(max_dollars=100.0, max_input_tokens=10_000_000, max_output_tokens=10_000_000)
        b.record_tokens(0, 1_000_000, model=MODEL_OPUS)
        assert abs(b.dollars - 25.0) < 0.001

    def test_opus_cache_read_at_one_tenth_5(self):
        b = Budget(max_dollars=100.0, max_input_tokens=10_000_000)
        b.record_tokens(0, 0, model=MODEL_OPUS, cache_read_tok=1_000_000)
        # $5 input × 0.1 = $0.50
        assert abs(b.dollars - 0.5) < 0.001
