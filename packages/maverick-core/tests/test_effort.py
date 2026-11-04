"""Per-role reasoning effort (output_config.effort) — the cost/latency lever."""
from __future__ import annotations

import pytest
from maverick import effort
from maverick.effort import effort_for_model, effort_for_role, effort_supported

OPUS = "claude-opus-4-8"
SONNET = "claude-sonnet-4-6"
HAIKU = "claude-haiku-4-5"
SONNET45 = "claude-sonnet-4-5"
OPUS5 = "claude-opus-5"
SONNET5 = "claude-sonnet-5"
FABLE51 = "claude-fable-5-1"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("MAVERICK_EFFORT"):
            monkeypatch.delenv(k, raising=False)
    # Default: no config, feature off.
    monkeypatch.setattr(effort, "_config_effort", dict)


# ---- model gating ----------------------------------------------------------

def test_effort_supported_matrix():
    assert effort_supported(OPUS) is True
    assert effort_supported(SONNET) is True
    assert effort_supported(HAIKU) is False     # haiku 4.5 rejects effort
    assert effort_supported(SONNET45) is False  # sonnet 4.5 rejects effort


def test_effort_supported_current_generation():
    # Opus 5 / Sonnet 5 / Fable 5.1 were unknown to this predicate --
    # verified against https://platform.claude.com/docs/en/build-with-claude/effort
    # ("Supported models" list).
    assert effort_supported(OPUS5) is True
    assert effort_supported(SONNET5) is True
    assert effort_supported(FABLE51) is True


def test_xhigh_and_max_on_current_generation(monkeypatch):
    # All three support both xhigh and max (same source as above).
    monkeypatch.setenv("MAVERICK_EFFORT", "xhigh")
    assert effort_for_role("coder", OPUS5) == "xhigh"
    assert effort_for_role("coder", SONNET5) == "xhigh"
    assert effort_for_role("coder", FABLE51) == "xhigh"
    monkeypatch.setenv("MAVERICK_EFFORT", "max")
    assert effort_for_role("coder", OPUS5) == "max"
    assert effort_for_role("coder", SONNET5) == "max"
    assert effort_for_role("coder", FABLE51) == "max"


def test_off_by_default():
    # Nothing configured -> None (omit effort, API default applies).
    assert effort_for_role("orchestrator", OPUS) is None
    assert effort_for_role("researcher", SONNET) is None


# ---- enabling via config ---------------------------------------------------

def test_enabled_applies_builtin_profile(monkeypatch):
    monkeypatch.setattr(effort, "_config_effort", lambda: {"enabled": True})
    # Critical roles stay high; bulk roles drop.
    assert effort_for_role("orchestrator", OPUS) == "high"
    assert effort_for_role("coder", SONNET) == "high"
    assert effort_for_role("researcher", SONNET) == "medium"
    assert effort_for_role("reflector", OPUS) == "low"
    # Unknown role -> no default -> None.
    assert effort_for_role("mystery", OPUS) is None


def test_enabled_but_unsupported_model_returns_none(monkeypatch):
    monkeypatch.setattr(effort, "_config_effort", lambda: {"enabled": True})
    assert effort_for_role("orchestrator", HAIKU) is None
    assert effort_for_role("researcher", SONNET45) is None


# ---- precedence ------------------------------------------------------------

def test_per_role_env_wins(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT_ORCHESTRATOR", "low")
    monkeypatch.setenv("MAVERICK_EFFORT", "max")
    assert effort_for_role("orchestrator", OPUS) == "low"


def test_global_env_applies_to_all_roles(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT", "medium")
    assert effort_for_role("orchestrator", OPUS) == "medium"
    assert effort_for_role("coder", SONNET) == "medium"


def test_config_per_role_and_default(monkeypatch):
    monkeypatch.setattr(effort, "_config_effort",
                        lambda: {"orchestrator": "max", "default": "low"})
    assert effort_for_role("orchestrator", OPUS) == "max"
    assert effort_for_role("coder", OPUS) == "low"  # falls to default


# ---- clamping (never 400) --------------------------------------------------

def test_xhigh_clamped_off_opus_78(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT", "xhigh")
    assert effort_for_role("coder", OPUS) == "xhigh"      # opus 4.8 supports it
    assert effort_for_role("coder", SONNET) == "high"     # sonnet -> clamp down


def test_max_clamped_off_opus_tier(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT", "max")
    assert effort_for_role("coder", OPUS) == "max"        # opus 4.8 supports max
    # Sonnet 4.6 supports "max" too (verified against
    # https://platform.claude.com/docs/en/build-with-claude/effort) -- it
    # must not be wrongly clamped down to "high" here.
    assert effort_for_role("coder", SONNET) == "max"
    # Sonnet 4.5 doesn't support effort at all (see test_effort_supported_matrix).
    assert effort_for_role("coder", SONNET45) is None


def test_invalid_level_is_ignored(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT", "turbo")
    assert effort_for_role("orchestrator", OPUS) is None


def test_preselected_effort_clamps_for_actual_model():
    # Provider failover can pass a primary model's resolved effort to a fallback;
    # the fallback model must still get its own model-specific ceiling.
    assert effort_for_model("xhigh", OPUS) == "xhigh"
    assert effort_for_model("xhigh", SONNET) == "high"
    assert effort_for_model("max", SONNET) == "max"  # Sonnet 4.6 supports max
    assert effort_for_model("medium", HAIKU) is None


# ---- provider request shaping ----------------------------------------------

def test_effort_lands_in_anthropic_output_config(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    from maverick.providers.anthropic_provider import AnthropicClient
    p = AnthropicClient()
    msgs = [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
    # Supported model -> effort threads into output_config.
    kw = p._build_request("sys", msgs, None, 4096, None, OPUS, "medium")
    assert kw["output_config"]["effort"] == "medium"
    # No effort -> no output_config key (unchanged request).
    assert p._build_request("sys", msgs, None, 4096, None, OPUS, None).get("output_config") is None
    # Unsupported model -> effort is dropped defensively (never 400).
    assert p._build_request("sys", msgs, None, 4096, None, HAIKU, "medium").get("output_config") is None
    # Stale primary-model effort is re-clamped for the actual fallback model.
    kw = p._build_request("sys", msgs, None, 4096, None, SONNET, "xhigh")
    assert kw["output_config"]["effort"] == "high"


def test_sync_failover_reclamps_effort_for_fallback(monkeypatch):
    from maverick import provider_failover
    from maverick.llm import LLM, LLMResponse

    calls = []

    class FakeClient:
        def complete(self, **kwargs):
            calls.append({"model": kwargs["model"], "effort": kwargs.get("effort")})
            if kwargs["model"] == OPUS:
                raise RuntimeError("primary down")
            return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(provider_failover, "fallback_models", lambda primary: [SONNET])
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())

    resp = LLM(model=OPUS).complete("sys", [{"role": "user", "content": "hi"}], effort="xhigh")

    assert resp.text == "ok"
    assert calls == [
        {"model": OPUS, "effort": "xhigh"},
        {"model": SONNET, "effort": "high"},
    ]


def test_async_failover_reclamps_effort_for_fallback(monkeypatch):
    from maverick import provider_failover
    from maverick.llm import LLM, LLMResponse

    calls = []

    class FakeClient:
        async def complete_async(self, **kwargs):
            calls.append({"model": kwargs["model"], "effort": kwargs.get("effort")})
            if kwargs["model"] == OPUS:
                raise RuntimeError("primary down")
            return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(provider_failover, "fallback_models", lambda primary: [SONNET])
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: FakeClient())

    import asyncio

    async def run_call():
        return await LLM(model=OPUS).complete_async(
            "sys", [{"role": "user", "content": "hi"}], effort="xhigh"
        )

    resp = asyncio.run(run_call())

    assert resp.text == "ok"
    assert calls == [
        {"model": OPUS, "effort": "xhigh"},
        {"model": SONNET, "effort": "high"},
    ]


# --- Pack-authored effort tier (DomainProfile.effort) -----------------------

_M = "claude-opus-4-8"  # an effort-supporting model


def test_pack_effort_ignored_when_feature_off(monkeypatch):
    # A pack's tier never turns the feature on -- off stays off.
    monkeypatch.setattr(effort, "_config_effort", dict)
    assert effort_for_role("finance_sox", _M, pack_default="high") is None


def test_pack_effort_applies_when_enabled(monkeypatch):
    monkeypatch.setattr(effort, "_config_effort", lambda: {"enabled": True})
    assert effort_for_role("finance_sox", _M, pack_default="high") == "high"


def test_pack_effort_beats_global_default(monkeypatch):
    # A pack's tier is more specific than the deployment-wide default.
    monkeypatch.setattr(effort, "_config_effort",
                        lambda: {"enabled": True, "default": "low"})
    assert effort_for_role("finance_sox", _M, pack_default="high") == "high"
    # ...but a pack with no tier still gets the global default.
    assert effort_for_role("cx_status_page", _M) == "low"


def test_per_role_override_still_beats_pack_effort(monkeypatch):
    monkeypatch.setenv("MAVERICK_EFFORT_FINANCE_SOX", "low")
    monkeypatch.setattr(effort, "_config_effort", lambda: {"enabled": True})
    assert effort_for_role("finance_sox", _M, pack_default="high") == "low"
