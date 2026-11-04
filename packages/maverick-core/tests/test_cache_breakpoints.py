"""Messages cache breakpoints: primary + a secondary on long histories.

A single long agentic turn can append >20 content blocks; Anthropic's 20-block
lookback then strands the chain. A second breakpoint inside the window keeps it
warm — while never exceeding the 4-breakpoint hard limit (system+tools+2).
"""
from __future__ import annotations

from maverick.providers.anthropic_provider import _add_messages_cache_breakpoint


def _marks(messages):
    n = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            n += sum(1 for b in c if isinstance(b, dict) and "cache_control" in b)
    return n


def _conv(n):
    """n user/assistant pairs + a final user turn."""
    msgs = []
    for i in range(n):
        msgs.append({"role": "user", "content": [{"type": "text", "text": f"u{i}"}]})
        msgs.append({"role": "assistant", "content": [{"type": "text", "text": f"a{i}"}]})
    msgs.append({"role": "user", "content": [{"type": "text", "text": "final"}]})
    return msgs


def test_short_history_one_breakpoint():
    out = _add_messages_cache_breakpoint(_conv(3))  # 7 messages
    assert _marks(out) == 1


def test_long_history_two_breakpoints():
    out = _add_messages_cache_breakpoint(_conv(20))  # 41 messages
    assert _marks(out) == 2


def test_never_exceeds_two_marks():
    for n in (1, 5, 12, 20, 40, 80):
        out = _add_messages_cache_breakpoint(_conv(n))
        assert _marks(out) <= 2, n


def test_secondary_is_an_earlier_user_message():
    out = _add_messages_cache_breakpoint(_conv(20))
    marked = [i for i, m in enumerate(out)
              if isinstance(m.get("content"), list)
              and any("cache_control" in b for b in m["content"])]
    assert len(marked) == 2
    # Both on user-role messages, and the secondary precedes the primary.
    assert all(out[i]["role"] == "user" for i in marked)
    primary, secondary = max(marked), min(marked)
    assert secondary < primary
    # Final (volatile) user message is never marked.
    assert primary < len(out) - 1


def test_stale_marks_are_stripped_first():
    msgs = _conv(20)
    # Inject stale breakpoints from prior turns.
    msgs[0]["content"][0]["cache_control"] = {"type": "ephemeral"}
    msgs[2]["content"][0]["cache_control"] = {"type": "ephemeral"}
    out = _add_messages_cache_breakpoint(msgs)
    assert _marks(out) == 2  # stale ones gone; only our two remain
