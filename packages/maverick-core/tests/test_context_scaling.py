"""Model-scaled context sizing (context_scaling) + preflight declared windows."""
from __future__ import annotations

from maverick import context_scaling as cs
from maverick.preflight import context_limit


def _clear_env(monkeypatch):
    for var in (
        "MAVERICK_CONTEXT_MODEL_SCALED",
        "MAVERICK_MODEL_CONTEXT_WINDOW",
        "MAVERICK_AGENT_MAX_TOKENS",
    ):
        monkeypatch.delenv(var, raising=False)


class TestModelWindow:
    def test_known_model(self, monkeypatch):
        _clear_env(monkeypatch)
        # Opus 4.8 is a 1M-context model, not 200k.
        assert cs.model_window("claude-opus-4-8") == 1_000_000

    def test_million_token_model(self, monkeypatch):
        _clear_env(monkeypatch)
        assert cs.model_window("gemini-3-pro") == 1_000_000

    def test_env_override_wins(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_MODEL_CONTEXT_WINDOW", "750000")
        assert cs.model_window("claude-opus-4-8") == 750_000
        assert cs.model_window("totally-unknown-model") == 750_000


class TestScaledBounds:
    def test_200k_window_scales_up_from_legacy(self, monkeypatch):
        _clear_env(monkeypatch)
        # claude-opus-4-5 has the 200k window this test scales from
        # (claude-opus-4-8 is a 1M-context model).
        model = "claude-opus-4-5"
        assert cs.history_turns(model) == 50           # 200k // 4000
        assert cs.history_turn_chars(model) == 800     # 200k // 250
        assert cs.compact_window_turns(model) == 200   # 200k // 1000
        assert cs.compact_target_tokens(model) == 25_000
        assert cs.router_threshold_tokens(model) == 180_000
        assert cs.tool_result_bytes(model) == 32_000  # baseline == 200k case

    def test_1m_window_scales_further(self, monkeypatch):
        _clear_env(monkeypatch)
        model = "gemini-3-pro"
        assert cs.history_turns(model) == 200          # ceiling
        assert cs.history_turn_chars(model) == 4_000
        assert cs.compact_target_tokens(model) == 125_000
        assert cs.router_threshold_tokens(model) == 900_000
        assert cs.max_output_tokens(model) == 32_000   # ceiling
        assert cs.tool_result_bytes(model) == 160_000

    def test_small_window_keeps_legacy_floors(self, monkeypatch):
        _clear_env(monkeypatch)
        model = "moonshot-v1-8k"
        assert cs.history_turns(model) == cs.LEGACY_HISTORY_TURNS
        assert cs.history_turn_chars(model) == cs.LEGACY_HISTORY_TURN_CHARS
        assert cs.compact_target_tokens(model) == cs.LEGACY_COMPACT_TARGET_TOKENS
        assert cs.max_output_tokens(model) == cs.LEGACY_MAX_OUTPUT_TOKENS
        assert cs.tool_result_bytes(model) == cs.LEGACY_TOOL_RESULT_BYTES
        # ...but the router now fires BEFORE the tiny window overflows,
        # instead of never (the old hard 200k default).
        assert cs.router_threshold_tokens(model) == 7_200

    def test_disabled_pins_legacy_everywhere(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_CONTEXT_MODEL_SCALED", "0")
        model = "gemini-3-pro"
        assert cs.history_turns(model) == cs.LEGACY_HISTORY_TURNS
        assert cs.history_turn_chars(model) == cs.LEGACY_HISTORY_TURN_CHARS
        assert cs.compact_window_turns(model) == cs.LEGACY_COMPACT_WINDOW_TURNS
        assert cs.compact_target_tokens(model) == cs.LEGACY_COMPACT_TARGET_TOKENS
        assert cs.router_threshold_tokens(model) == 200_000
        assert cs.max_output_tokens(model) == cs.LEGACY_MAX_OUTPUT_TOKENS
        assert cs.tool_result_bytes(model) == cs.LEGACY_TOOL_RESULT_BYTES

    def test_explicit_max_tokens_env_wins(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_AGENT_MAX_TOKENS", "9999")
        assert cs.max_output_tokens("gemini-3-pro") == 9999


class TestDeclaredWindows:
    def test_config_declared_window_wins_over_fallback(self, monkeypatch):
        import maverick.config as config
        monkeypatch.setattr(
            config, "load_config",
            lambda: {"context": {"model_windows": {"my-vllm-model": 500_000}}},
        )
        assert context_limit("my-vllm-model") == 500_000
        # And context_scaling picks it up through context_limit.
        _clear_env(monkeypatch)
        assert cs.model_window("my-vllm-model") == 500_000

    def test_bad_declared_entry_is_skipped(self, monkeypatch):
        import maverick.config as config
        monkeypatch.setattr(
            config, "load_config",
            lambda: {"context": {"model_windows": {"weird": "not-a-number"}}},
        )
        assert context_limit("weird") == 32_000  # falls to the safe default


class TestAgentWiring:
    def test_explicit_tool_result_cap_wins_outright(self, monkeypatch):
        _clear_env(monkeypatch)
        # An explicit cap (env / patched constant) wins, even to shrink.
        import maverick.agent as agent_mod
        from maverick.agent import _tool_result_limit
        monkeypatch.setattr(agent_mod, "_MAX_TOOL_RESULT_BYTES", 50_000)
        assert _tool_result_limit("gemini-3-pro") == 50_000

    def test_tool_result_limit_scales_without_env(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.delenv("MAVERICK_MAX_TOOL_RESULT_BYTES", raising=False)
        from maverick.agent import _tool_result_limit
        assert _tool_result_limit("gemini-3-pro") == 160_000
        # Claude-opus-4-5 (not 4-8, which is a 1M-context model) is
        # the genuine 200k baseline case.
        assert _tool_result_limit("claude-opus-4-5") == 32_000


class TestRouterWiring:
    def test_route_uses_model_scaled_threshold(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_RETRIEVAL_ROUTER", "1")
        monkeypatch.delenv("MAVERICK_ROUTER_THRESHOLD_TOKENS", raising=False)
        # Declare a tiny window so the scaled threshold (90%) trips on a
        # payload the old hard 200k default would have passed through.
        monkeypatch.setenv("MAVERICK_MODEL_CONTEXT_WINDOW", "100")
        from maverick.long_context_router import route
        # >24 shards at the 2000-char default so top-k (12) actually drops some.
        text = ("alpha protocol details here. " + "filler words only. " * 20) * 120
        out = route(text, "alpha protocol")
        assert "long-context router" in out
        assert len(out) < len(text)

    def test_route_explicit_threshold_still_wins(self, monkeypatch):
        _clear_env(monkeypatch)
        monkeypatch.setenv("MAVERICK_RETRIEVAL_ROUTER", "1")
        monkeypatch.setenv("MAVERICK_MODEL_CONTEXT_WINDOW", "100")
        # An explicit operator threshold beats the scaled default.
        monkeypatch.setenv("MAVERICK_ROUTER_THRESHOLD_TOKENS", "10000000")
        from maverick.long_context_router import route
        # >24 shards at the 2000-char default so top-k (12) actually drops some.
        text = ("alpha protocol details here. " + "filler words only. " * 20) * 120
        assert route(text, "alpha protocol") == text
