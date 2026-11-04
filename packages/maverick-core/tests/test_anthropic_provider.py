"""Tests for the Anthropic provider: request shaping, cache TTLs, extended and
interleaved thinking, tool ordering and usage accounting.
"""
from __future__ import annotations

import logging

# ---- MAVERICK_TEMPERATURE is read by the Anthropic provider ----

class TestTemperatureWiredThrough:
    def test_build_request_includes_temperature_when_env_set(self, monkeypatch):
        from maverick.providers.anthropic_provider import AnthropicClient
        # Avoid touching the real anthropic client constructor.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        monkeypatch.setenv("MAVERICK_TEMPERATURE", "0.85")
        client = AnthropicClient()
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=128,
            thinking_budget=None,
            model="claude-sonnet-4-6",
        )
        assert kwargs.get("temperature") == 0.85

    def test_build_request_no_temperature_when_unset(self, monkeypatch):
        from maverick.providers.anthropic_provider import AnthropicClient
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        monkeypatch.delenv("MAVERICK_TEMPERATURE", raising=False)
        client = AnthropicClient()
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=128,
            thinking_budget=None,
            model="claude-sonnet-4-6",
        )
        assert "temperature" not in kwargs

    def test_build_request_no_temperature_when_thinking_enabled(self, monkeypatch):
        # Thinking models reject explicit temperature; gate must hold.
        from maverick.providers.anthropic_provider import AnthropicClient
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        monkeypatch.setenv("MAVERICK_TEMPERATURE", "0.9")
        client = AnthropicClient()
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=128,
            thinking_budget=4000,
            model="claude-opus-4-7",
        )
        assert "temperature" not in kwargs


class TestCacheTTL:
    def test_coding_mode_defaults_to_5m(self, monkeypatch):
        from maverick.providers.anthropic_provider import _default_cache_ttl
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        monkeypatch.delenv("MAVERICK_ANTHROPIC_CACHE_TTL", raising=False)
        assert _default_cache_ttl() == "5m"

    def test_non_coding_mode_defaults_to_1h(self, monkeypatch):
        from maverick.providers.anthropic_provider import _default_cache_ttl
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        monkeypatch.delenv("MAVERICK_ANTHROPIC_CACHE_TTL", raising=False)
        assert _default_cache_ttl() == "1h"

    def test_explicit_env_override_wins(self, monkeypatch):
        from maverick.providers.anthropic_provider import _default_cache_ttl
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        monkeypatch.setenv("MAVERICK_ANTHROPIC_CACHE_TTL", "30m")
        assert _default_cache_ttl() == "30m"


class TestThinkingBudgetWiredThrough:
    def test_anthropic_provider_passes_thinking_to_kwargs(self, monkeypatch):
        from maverick.providers.anthropic_provider import AnthropicClient
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        c = AnthropicClient()
        kwargs = c._build_request(
            system="s", messages=[{"role": "user", "content": "hi"}],
            tools=None, max_tokens=128, thinking_budget=8000,
            model="claude-sonnet-4-6",
        )
        assert kwargs.get("thinking") == {
            "type": "enabled", "budget_tokens": 8000,
        }
        # Max tokens auto-grew to thinking_budget + 1024.
        assert kwargs["max_tokens"] >= 8000 + 1024

    def test_no_thinking_when_unset(self, monkeypatch):
        from maverick.providers.anthropic_provider import AnthropicClient
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        c = AnthropicClient()
        kwargs = c._build_request(
            system="s", messages=[{"role": "user", "content": "hi"}],
            tools=None, max_tokens=128, thinking_budget=None,
            model="claude-sonnet-4-6",
        )
        assert "thinking" not in kwargs


class TestCacheTtlConsistent:
    def test_messages_breakpoint_uses_default_ttl_5m_in_coding(self, monkeypatch):
        from maverick.providers.anthropic_provider import (
            _add_messages_cache_breakpoint,
        )
        monkeypatch.delenv("MAVERICK_ANTHROPIC_CACHE_TTL", raising=False)
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        msgs = [
            {"role": "user", "content": "first turn"},
            {"role": "assistant", "content": "response"},
            {"role": "user", "content": "second turn"},
        ]
        out = _add_messages_cache_breakpoint(msgs)
        # The first user message gets the breakpoint.
        target = out[0]
        cc = target["content"][0]["cache_control"]
        assert cc["ttl"] == "5m", (
            "in coding mode the messages breakpoint should also be 5m, "
            "matching system/tools — prior code hardcoded 1h here, "
            "causing Budget over-bill on write surcharge"
        )

    def test_messages_breakpoint_uses_5m_in_normal_mode(self, monkeypatch):
        # The message breakpoint re-anchors to a new position every turn, so
        # its cache WRITE is paid per turn and the re-read lands seconds later
        # on the next turn. 5m TTL (1.25x write) covers that; the prior 1h
        # (2x write) bought nothing unless turns stalled. System/tools keep
        # the 1h interactive TTL via _default_cache_ttl; an explicit
        # MAVERICK_ANTHROPIC_CACHE_TTL / _MSG_CACHE_TTL still wins.
        from maverick.providers.anthropic_provider import (
            _add_messages_cache_breakpoint,
        )
        monkeypatch.delenv("MAVERICK_ANTHROPIC_CACHE_TTL", raising=False)
        monkeypatch.delenv("MAVERICK_ANTHROPIC_MSG_CACHE_TTL", raising=False)
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        msgs = [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "second"},
        ]
        out = _add_messages_cache_breakpoint(msgs)
        cc = out[0]["content"][0]["cache_control"]
        assert cc["ttl"] == "5m"

    def test_explicit_env_var_wins(self, monkeypatch):
        from maverick.providers.anthropic_provider import (
            _add_messages_cache_breakpoint,
        )
        monkeypatch.setenv("MAVERICK_ANTHROPIC_CACHE_TTL", "1h")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")  # would default to 5m
        msgs = [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "second"},
        ]
        out = _add_messages_cache_breakpoint(msgs)
        cc = out[0]["content"][0]["cache_control"]
        assert cc["ttl"] == "1h"


class TestToolsSorted:
    def test_tools_sorted_for_cache_determinism(self):
        from maverick.providers.anthropic_provider import _cached_tools
        tools = [
            {"name": "zebra", "input_schema": {}},
            {"name": "apple", "input_schema": {}},
            {"name": "mango", "input_schema": {}},
        ]
        out = _cached_tools(tools)
        names = [t["name"] for t in out]
        assert names == ["apple", "mango", "zebra"]

    def test_tools_sort_is_stable_across_calls(self):
        from maverick.providers.anthropic_provider import _cached_tools
        a = [{"name": "x"}, {"name": "y"}, {"name": "z"}]
        b = [{"name": "z"}, {"name": "y"}, {"name": "x"}]
        # Same input set, different order → same canonical output.
        ax = _cached_tools(a)
        bx = _cached_tools(b)
        assert [t["name"] for t in ax] == [t["name"] for t in bx]

    def test_last_tool_after_sort_gets_cache_control(self):
        from maverick.providers.anthropic_provider import _cached_tools
        tools = [
            {"name": "zebra"},
            {"name": "apple"},
        ]
        out = _cached_tools(tools)
        # After sort, last is "zebra" — must carry the cache breakpoint.
        assert out[-1]["name"] == "zebra"
        assert "cache_control" in out[-1]
        # Earlier ones don't have it.
        assert "cache_control" not in out[0]


class TestInterleavedThinkingHeader:
    """Header policy per Anthropic May 2026 docs.
    Opus 4.7 + Sonnet 4.6 + Haiku 4.5: adaptive thinking is built-in,
    NO header needed (and Opus 4.7 rejects manual `enabled`).
    Sonnet 4.5 / Opus 4.5: header still required to get interleaved.
    """

    def test_header_required_for_sonnet_4_5(self):
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-sonnet-4-5",
        )
        beta = kwargs.get("extra_headers", {}).get("anthropic-beta", "")
        assert "interleaved-thinking-2025-05-14" in beta

    def test_header_required_for_opus_4_5(self):
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-opus-4-5",
        )
        beta = kwargs.get("extra_headers", {}).get("anthropic-beta", "")
        assert "interleaved-thinking-2025-05-14" in beta

    def test_header_NOT_set_for_sonnet_4_6(self):
        """4.6+ has interleaved automatic in adaptive mode — header would
        be deprecated noise."""
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-sonnet-4-6",
        )
        beta = kwargs.get("extra_headers", {}).get("anthropic-beta", "")
        assert "interleaved-thinking" not in beta

    def test_opus_4_7_uses_adaptive_not_enabled(self):
        """Opus 4.7 returns 400 on `thinking={"type":"enabled"}`. We must
        send `adaptive` instead."""
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-opus-4-7",
        )
        thinking = kwargs.get("thinking", {})
        assert thinking.get("type") == "adaptive", (
            f"Opus 4.7 must use adaptive thinking; got {thinking}"
        )
        # No header for 4.7 either.
        beta = kwargs.get("extra_headers", {}).get("anthropic-beta", "")
        assert "interleaved-thinking" not in beta

    def test_opus_4_7_defaults_to_adaptive_even_without_budget(self):
        """Opus 4.7 only supports adaptive — if caller doesn't ask for
        thinking, we still emit adaptive so the model can think when
        it judges it useful."""
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model="claude-opus-4-7",
        )
        thinking = kwargs.get("thinking", {})
        assert thinking.get("type") == "adaptive"

    def test_header_not_added_for_legacy_pre_4x_model(self):
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model="claude-3-5-sonnet-20241022",
        )
        beta = kwargs.get("extra_headers", {}).get("anthropic-beta", "")
        assert "interleaved-thinking" not in beta


class TestNullsafeUsage:
    def test_record_handles_none_usage_fields(self, monkeypatch):
        """If Anthropic returns None in usage fields (streaming refusal),
        _parse_response must not crash."""
        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _FakeUsage:
            input_tokens = None
            output_tokens = None
            cache_creation_input_tokens = None
            cache_read_input_tokens = None

        class _FakeResp:
            content = []
            usage = _FakeUsage()
            stop_reason = "end_turn"

        budget = Budget(max_dollars=10.0)
        resp = client._parse_response(_FakeResp(), budget, model="claude-sonnet-4-6")
        # Should not raise; budget records 0 spend.
        assert budget.dollars == 0.0
        assert resp.text == ""


class TestInterleavedThinkingOrder:
    """_parse_response must keep the model's ORIGINAL block
    order (thinking interleaved with tool_use) and echo redacted_thinking
    back. Anthropic rejects a rearranged thinking sequence on the next
    request: "thinking blocks in the latest assistant message cannot be
    modified ... must remain as they were in the original response."
    """

    @staticmethod
    def _block(**kw):
        b = type("_Block", (), {})()
        for k, v in kw.items():
            setattr(b, k, v)
        return b

    def test_content_blocks_preserve_interleaved_order(self):
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _Resp:
            usage = None
            stop_reason = "tool_use"

        resp = _Resp()
        resp.content = [
            self._block(type="thinking", thinking="reason A", signature="sigA"),
            self._block(type="tool_use", id="t1", name="shell", input={"cmd": "ls"}),
            self._block(type="redacted_thinking", data="RD=="),
            self._block(type="thinking", thinking="reason B", signature="sigB"),
            self._block(type="tool_use", id="t2", name="read", input={"path": "x"}),
            self._block(type="text", text="done"),
        ]
        out = client._parse_response(resp, None, model="claude-opus-4-7")

        # Original interleaving preserved (the bug hoisted all thinking
        # to the front, producing thinking,thinking,text,tool_use,tool_use).
        types = [b["type"] for b in out.content_blocks]
        assert types == [
            "thinking", "tool_use", "redacted_thinking",
            "thinking", "tool_use", "text",
        ], f"original order not preserved: {types}"
        # Per-block signatures kept.
        assert out.content_blocks[0]["signature"] == "sigA"
        assert out.content_blocks[3]["signature"] == "sigB"
        # redacted_thinking echoed verbatim (was silently dropped before).
        assert out.content_blocks[2] == {"type": "redacted_thinking", "data": "RD=="}
        # Bucketed back-compat fields still populated for other callers.
        assert out.text == "done"
        assert [tc.id for tc in out.tool_calls] == ["t1", "t2"]
        assert [t[0] for t in out.thinking_blocks] == ["reason A", "reason B"]

    def test_thinking_block_without_signature_omits_key(self):
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _Resp:
            usage = None
            stop_reason = "end_turn"

        resp = _Resp()
        resp.content = [
            self._block(type="thinking", thinking="t", signature=None),
            self._block(type="text", text="hi"),
        ]
        out = client._parse_response(resp, None, model="claude-opus-4-7")
        assert "signature" not in out.content_blocks[0]


class TestAnthropicProviderRobust:
    def test_resp_usage_none_does_not_crash(self):
        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _Resp:
            content = []
            usage = None
            stop_reason = "end_turn"

        budget = Budget(max_dollars=10.0)
        # Must not raise even when usage is None entirely.
        resp = client._parse_response(_Resp(), budget, model="claude-sonnet-4-6")
        assert resp.text == ""
        assert budget.dollars == 0.0

    def test_string_usage_values_dont_crash(self):
        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _Usage:
            input_tokens = "100"
            output_tokens = "20"
            cache_creation_input_tokens = None
            cache_read_input_tokens = None

        class _Resp:
            content = []
            usage = _Usage()
            stop_reason = "end_turn"

        budget = Budget(max_dollars=10.0)
        client._parse_response(_Resp(), budget, model="claude-sonnet-4-6")
        # Should have coerced "100"→100; ~$0.001 spent.
        assert budget.input_tokens == 100

    def test_split_cache_creation_ttl_bills_each_tier(self):
        """Usage.cache_creation.{ephemeral_5m,ephemeral_1h}_input_tokens
        must be read and passed through so a call that writes both a 1h
        (system/tools) and a 5m (messages) breakpoint bills each tier at its
        own rate, instead of the whole cache_creation_input_tokens total at
        one multiplier."""
        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _CacheCreation:
            ephemeral_5m_input_tokens = 500_000
            ephemeral_1h_input_tokens = 500_000

        class _Usage:
            input_tokens = 0
            output_tokens = 0
            cache_creation_input_tokens = 1_000_000
            cache_read_input_tokens = 0
            cache_creation = _CacheCreation()

        class _Resp:
            content = []
            usage = _Usage()
            stop_reason = "end_turn"

        budget = Budget(max_dollars=100.0, max_input_tokens=10_000_000,
                        max_output_tokens=10_000_000)
        client._parse_response(_Resp(), budget, model="claude-sonnet-4-6")
        # Sonnet: 500k @ 5m (1.25x) + 500k @ 1h (2.0x) = $1.875 + $3.00 = $4.875.
        # The old single-multiplier path (whole 1M at _default_cache_ttl(),
        # 1h in interactive mode) would give $6.00 instead.
        assert abs(budget.dollars - 4.875) < 0.001
        assert budget.cache_write_tokens == 1_000_000

    def test_string_usage_garbage_does_not_crash(self):
        from maverick.budget import Budget
        from maverick.providers.anthropic_provider import AnthropicClient

        client = AnthropicClient.__new__(AnthropicClient)

        class _Usage:
            input_tokens = "not_a_number"
            output_tokens = 50

        class _Resp:
            content = []
            usage = _Usage()
            stop_reason = "end_turn"

        budget = Budget(max_dollars=10.0)
        # Must not raise — defensive _safe_int returns 0.
        client._parse_response(_Resp(), budget, model="claude-sonnet-4-6")
        assert budget.input_tokens == 0
        assert budget.output_tokens == 50

    def test_duplicate_tool_names_no_crash(self):
        from maverick.providers.anthropic_provider import _cached_tools
        tools = [
            {"name": "shell", "input_schema": {}},
            {"name": "shell", "input_schema": {}},  # duplicate
            {"name": None, "input_schema": {}},     # malformed
        ]
        # Must not raise on None name.
        out = _cached_tools(tools)
        assert len(out) == 3
        assert "cache_control" in out[-1]


class TestOpus47AdaptiveThinking:
    """Opus 4.7 rejects manual `thinking={"type":"enabled"}` with 400.
    Must use `adaptive`. Verified at platform.claude.com/docs/.../adaptive-thinking."""

    def test_opus_47_with_budget_uses_adaptive(self):
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-opus-4-7",
        )
        assert kwargs.get("thinking", {}).get("type") == "adaptive"
        # No budget_tokens — adaptive auto-sizes.
        assert "budget_tokens" not in kwargs.get("thinking", {})

    def test_opus_47_without_budget_still_adaptive(self):
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=None,
            model="claude-opus-4-7",
        )
        assert kwargs.get("thinking", {}).get("type") == "adaptive"

    def test_sonnet_46_uses_enabled_mode(self):
        """Sonnet 4.6 supports both 'enabled' and 'adaptive'; we use
        explicit 'enabled' with budget_tokens for callsites that pass
        thinking_budget."""
        from maverick.providers.anthropic_provider import AnthropicClient
        client = AnthropicClient.__new__(AnthropicClient)
        kwargs = client._build_request(
            system="sys",
            messages=[{"role": "user", "content": "hi"}],
            tools=None,
            max_tokens=4096,
            thinking_budget=8000,
            model="claude-sonnet-4-6",
        )
        thinking = kwargs.get("thinking", {})
        assert thinking.get("type") == "enabled"
        assert thinking.get("budget_tokens") == 8000


class TestLowCacheWarning:
    """The min cacheable block on Opus 4.6/4.5 and Haiku 4.5 is 4096 tokens
    (2048 for Opus 4.7; 1024 for everything else, including the current
    defaults Sonnet 4.6 and Opus 4.8), so a small enough system+tools block
    won't actually cache. Operators need to see this in logs.

    The table used to put Sonnet 4.6/4.5 and Opus 4.7/4.8 at the 4096
    minimum too (verified wrong against
    https://platform.claude.com/docs/en/build-with-claude/prompt-caching:
    Opus 4.7 is 2048, the rest are 1024)."""

    def test_min_cache_tokens_for_modern_models(self):
        from maverick.providers.anthropic_provider import _min_cache_tokens
        assert _min_cache_tokens("claude-opus-4-7") == 2048
        assert _min_cache_tokens("claude-opus-4-6") == 4096
        assert _min_cache_tokens("claude-opus-4-5") == 4096
        assert _min_cache_tokens("claude-opus-4-8") == 1024
        assert _min_cache_tokens("claude-sonnet-4-6") == 1024
        assert _min_cache_tokens("claude-sonnet-4-5") == 1024
        assert _min_cache_tokens("claude-haiku-4-5") == 4096

    def test_min_cache_tokens_for_current_generation_models(self):
        from maverick.providers.anthropic_provider import _min_cache_tokens
        assert _min_cache_tokens("claude-opus-5") == 512
        assert _min_cache_tokens("claude-sonnet-5") == 1024
        assert _min_cache_tokens("claude-fable-5-1") == 512

    def test_min_cache_tokens_for_legacy_models(self):
        from maverick.providers.anthropic_provider import _min_cache_tokens
        assert _min_cache_tokens("claude-3-5-sonnet-20241022") == 1024
        assert _min_cache_tokens("claude-opus-4-1") == 1024

    def test_warning_emitted_for_small_prompt(self, caplog):
        from maverick.providers import anthropic_provider as ap
        # Reset the once-per-process flag for this test.
        ap._LOW_CACHE_WARNING_EMITTED.clear()
        client = ap.AnthropicClient.__new__(ap.AnthropicClient)
        # Emitted at DEBUG (not WARNING) so it doesn't bleed onto the consumer
        # CLI's terminal mid-run; capture at DEBUG to assert it still fires.
        with caplog.at_level(logging.DEBUG, logger=ap.__name__):
            client._build_request(
                system="short system prompt",
                messages=[{"role": "user", "content": "hi"}],
                tools=[{"name": "x", "input_schema": {}}],
                max_tokens=1024,
                thinking_budget=None,
                model="claude-sonnet-4-6",
            )
        assert any("prompt cache no-op" in r.message for r in caplog.records), (
            "expected low-cache warning to be logged"
        )
        ap._LOW_CACHE_WARNING_EMITTED.clear()

    def test_warning_emitted_only_once_per_model(self, caplog):
        from maverick.providers import anthropic_provider as ap
        ap._LOW_CACHE_WARNING_EMITTED.clear()
        client = ap.AnthropicClient.__new__(ap.AnthropicClient)
        with caplog.at_level(logging.DEBUG, logger=ap.__name__):
            for _ in range(5):
                client._build_request(
                    system="short",
                    messages=[{"role": "user", "content": "hi"}],
                    tools=None,
                    max_tokens=1024,
                    thinking_budget=None,
                    model="claude-sonnet-4-6",
                )
        cache_warnings = [r for r in caplog.records if "prompt cache" in r.message]
        assert len(cache_warnings) == 1
        ap._LOW_CACHE_WARNING_EMITTED.clear()
