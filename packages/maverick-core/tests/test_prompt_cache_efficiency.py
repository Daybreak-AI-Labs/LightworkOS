"""Prompt-cache efficiency: block-based secondary breakpoint, message-tier
TTL, prewarm minimum gate, and tool-cache side-effect invalidation.

- The secondary message breakpoint counts CONTENT BLOCKS, not messages:
  Anthropic's cache lookback walks 20 content blocks, and a few agentic turns
  with many parallel tool_results exceed that window long before 24 messages,
  leaving the chain cold so each turn re-writes the full prefix.
- The message-tier breakpoint re-anchors every turn (its write is paid per
  turn), so it uses the 5m TTL (1.25x), which covers the seconds-later
  re-read, not the 1h TTL (2x write surcharge).
- prewarm() does not bill ~1.8k input tokens when system+tools sit under the
  model's 4096-token cache minimum, where it would warm nothing.
- The tool-output cache invalidates on writes: a cached read_file does not
  survive an apply_patch to the same file.
"""
from __future__ import annotations

from maverick.providers.anthropic_provider import (
    AnthropicClient,
    _add_messages_cache_breakpoint,
    _mark_user_message,
    _msg_cache_ttl,
)


def _marks(messages: list[dict]) -> int:
    n = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            n += sum(1 for b in c if isinstance(b, dict) and "cache_control" in b)
    return n


def _turn(i: int, results_per_turn: int = 1) -> list[dict]:
    uses = [{"type": "tool_use", "id": f"t{i}_{j}", "name": "x", "input": {}}
            for j in range(results_per_turn)]
    res = [{"type": "tool_result", "tool_use_id": f"t{i}_{j}", "content": "r"}
           for j in range(results_per_turn)]
    return [{"role": "assistant", "content": uses},
            {"role": "user", "content": res}]


class TestSecondaryBreakpointBlocks:
    def test_short_history_single_mark(self):
        msgs = [{"role": "user", "content": "goal"}]
        for i in range(3):
            msgs += _turn(i)
        out = _add_messages_cache_breakpoint(msgs)
        assert _marks(out) == 1

    def test_block_heavy_short_history_gets_secondary(self):
        # Only 9 messages (old trigger: >=24) but 4 fan-out turns x 8 blocks
        # exceed the 20-block lookback — the secondary must fire on BLOCKS.
        msgs = [{"role": "user", "content": "goal"}]
        for i in range(4):
            msgs += _turn(i, results_per_turn=8)
        assert len(msgs) < 24
        out = _add_messages_cache_breakpoint(msgs)
        assert _marks(out) == 2

    def test_long_many_message_history_still_gets_secondary(self):
        msgs = [{"role": "user", "content": "goal"}]
        for i in range(14):
            msgs += _turn(i)
        out = _add_messages_cache_breakpoint(msgs)
        assert _marks(out) == 2

    def test_secondary_sits_within_lookback_of_primary(self):
        msgs = [{"role": "user", "content": "goal"}]
        for i in range(14):
            msgs += _turn(i)
        out = _add_messages_cache_breakpoint(msgs)
        marked = [i for i, m in enumerate(out)
                  if isinstance(m.get("content"), list)
                  and any("cache_control" in b for b in m["content"]
                          if isinstance(b, dict))]
        assert len(marked) == 2
        lo, hi = marked
        gap_blocks = sum(
            len(m["content"]) if isinstance(m.get("content"), list) else 1
            for m in out[lo + 1: hi + 1])
        assert 1 <= gap_blocks <= 20


class TestMessageTierTTL:
    def test_default_message_ttl_is_5m(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_ANTHROPIC_CACHE_TTL", raising=False)
        monkeypatch.delenv("MAVERICK_ANTHROPIC_MSG_CACHE_TTL", raising=False)
        monkeypatch.delenv("MAVERICK_CODING_MODE", raising=False)
        assert _msg_cache_ttl() == "5m"
        marked = _mark_user_message({"role": "user", "content": "hi"})
        assert marked["content"][-1]["cache_control"]["ttl"] == "5m"

    def test_explicit_global_ttl_still_wins(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ANTHROPIC_CACHE_TTL", "1h")
        monkeypatch.delenv("MAVERICK_ANTHROPIC_MSG_CACHE_TTL", raising=False)
        assert _msg_cache_ttl() == "1h"

    def test_message_tier_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_ANTHROPIC_CACHE_TTL", "1h")
        monkeypatch.setenv("MAVERICK_ANTHROPIC_MSG_CACHE_TTL", "5m")
        assert _msg_cache_ttl() == "5m"


class TestPrewarmMinGate:
    def _client_with_spy(self):
        client = AnthropicClient.__new__(AnthropicClient)
        calls = []

        class _Msgs:
            def create(self, **kw):
                calls.append(kw)
                raise RuntimeError("stop after capture")

        class _C:
            messages = _Msgs()

        client.client = _C()
        return client, calls

    def test_undersized_prompt_skips_the_paid_call(self):
        client, calls = self._client_with_spy()
        # ~2k chars => ~500 tokens, far under the 4096 minimum for 4.6:
        # the warm would write nothing; it must not bill a call at all.
        ok = client.prewarm("s" * 2_000, tools=None, model="claude-sonnet-4-6")
        assert ok is False
        assert calls == []

    def test_oversized_prompt_attempts_the_warm(self):
        client, calls = self._client_with_spy()
        client.prewarm("s" * 40_000, tools=None, model="claude-sonnet-4-6")
        assert len(calls) == 1  # gate passed; the (spy) call was made


class TestToolCacheSideEffectInvalidation:
    class _Read:
        name = "read_file"
        parallel_safe = True

    class _Write:
        name = "apply_patch"
        parallel_safe = False

    def test_side_effect_purges_cached_reads(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        from maverick.cache import tool as tool_cache

        tool_cache.reset()
        tool_cache.store_cached(self._Read(), {"path": "a.py"}, "old contents")
        hit, _ = tool_cache.get_cached(self._Read(), {"path": "a.py"})
        assert hit
        tool_cache.note_side_effect(self._Write())
        hit, _ = tool_cache.get_cached(self._Read(), {"path": "a.py"})
        assert not hit

    def test_read_tools_do_not_purge(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        from maverick.cache import tool as tool_cache

        tool_cache.reset()
        tool_cache.store_cached(self._Read(), {"path": "a.py"}, "contents")
        tool_cache.note_side_effect(self._Read())
        hit, _ = tool_cache.get_cached(self._Read(), {"path": "a.py"})
        assert hit
