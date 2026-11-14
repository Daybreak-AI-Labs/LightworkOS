"""Tests for start preflight checks (maverick.preflight)."""
from __future__ import annotations

import pytest

# ---------- preflight ----------

def test_preflight_context_limit_known_model():
    from maverick.preflight import context_limit
    # Opus 4.7 is a 1M-context model, not 200k --
    # https://platform.claude.com/docs/en/build-with-claude/context-windows.
    assert context_limit("claude-opus-4-7") == 1_000_000
    assert context_limit("gpt-5.4-nano") == 32_000
    assert context_limit("kimi-k2") == 128_000


def test_preflight_context_limit_unknown_falls_back():
    from maverick.preflight import context_limit
    # Unknown id with no family prefix match -> 32k default.
    assert context_limit("totally-made-up-model-xyz") == 32_000


def test_preflight_context_limit_dated_and_unknown_ids_are_conservative():
    from maverick.preflight import PreflightFailed, context_limit, preflight
    # A dated id inherits its base model's window, not the first claude entry.
    assert context_limit("claude-sonnet-4-5-20250929") == 200_000
    assert context_limit("claude-opus-4-8-20260101") == 1_000_000
    # An unknown claude id gets the smallest Claude window in the table.
    assert context_limit("claude-3-5-haiku-latest") == 200_000
    # Warn mode never raises, even when max_tokens alone exceeds the window.
    assert preflight(model="my-local-llm", system="", messages=[],
                     max_tokens=32_000, strict=False) == 0
    with pytest.raises(PreflightFailed):
        preflight(model="my-local-llm", system="", messages=[], max_tokens=32_000)


def test_preflight_estimate_tokens_zero_for_empty():
    from maverick.preflight import estimate_tokens
    assert estimate_tokens("") == 0


def test_preflight_estimate_tokens_grows_with_length():
    from maverick.preflight import estimate_tokens
    small = estimate_tokens("hi")
    big = estimate_tokens("hi " * 1000)
    assert big > small


def test_preflight_under_budget_succeeds():
    from maverick.preflight import preflight
    estimated = preflight(
        model="claude-sonnet-4-6",
        system="be brief",
        messages=[{"role": "user", "content": "hello"}],
        max_tokens=2048,
    )
    assert estimated > 0


def test_preflight_over_budget_strict_raises():
    from maverick.preflight import PreflightFailed, preflight
    # Build a payload bigger than the 32k default for unknown models.
    huge = "x" * 200_000
    with pytest.raises(PreflightFailed) as exc:
        preflight(
            model="unknown-model",
            system=huge,
            messages=[{"role": "user", "content": "ok"}],
            max_tokens=2048,
            strict=True,
        )
    err = exc.value
    assert err.estimated > 0
    assert err.limit == 32_000


def test_preflight_over_budget_non_strict_warns_but_returns():
    """strict=False: log warning instead of raising."""
    from maverick.preflight import preflight
    huge = "x" * 200_000
    est = preflight(
        model="unknown-model",
        system=huge,
        messages=[],
        max_tokens=2048,
        strict=False,
    )
    assert est > 0  # didn't raise


def test_preflight_tools_count_toward_estimate():
    from maverick.preflight import preflight
    tools = [{
        "name": "x",
        "description": "Y" * 5000,
        "input_schema": {"properties": {}},
    }]
    with_tools = preflight(
        model="claude-sonnet-4-6", system="", messages=[],
        tools=tools, max_tokens=2048, strict=False,
    )
    without_tools = preflight(
        model="claude-sonnet-4-6", system="", messages=[],
        tools=None, max_tokens=2048, strict=False,
    )
    assert with_tools > without_tools
