"""Tests for the context compactor (maverick.context_compactor)."""
from __future__ import annotations

import sys
import types

from maverick import context_compactor as cc

# --- embedding ranking keeps head turns on vector shortfall ------

class _ShortEmbedder:
    """Embedder that yields a query vector but FEWER doc vectors than asked,
    mimicking empty-text / batching shortfalls."""

    def __init__(self, model_name=None):
        self._first = True

    def embed(self, texts):
        texts = list(texts)
        # The query call passes a single string; yield one vector for it.
        if len(texts) == 1:
            yield [1.0, 0.0]
            return
        # The doc call: deliberately yield one fewer vector than requested.
        for _ in texts[:-1]:
            yield [1.0, 0.0]


def test_embedding_shortfall_keeps_all_head_turns(monkeypatch):
    head = [
        {"role": "user", "content": "first turn about apples"},
        {"role": "assistant", "content": "second turn about oranges"},
        {"role": "user", "content": "third turn about pears"},
    ]

    # _score_by_embedding does ``from fastembed import TextEmbedding`` at
    # call time; inject a fake module so the import resolves to our stub.
    fake_mod = types.ModuleType("fastembed")
    fake_mod.TextEmbedding = _ShortEmbedder
    monkeypatch.setitem(sys.modules, "fastembed", fake_mod)
    scored = cc._score_by_embedding(head, "fruit query", None)

    # Every head turn must be represented exactly once -- none dropped.
    assert len(scored) == len(head)
    assert sorted(i for _, i, _ in scored) == [0, 1, 2]
    # The turn lacking a vector (index 2) is KEPT with max score, not culled.
    last = next(s for s, i, _ in scored if i == 2)
    assert last == float("inf")


# --- budget exhaustion drops tail turns, never blanks them -------

def test_fit_recent_to_budget_drops_rather_than_blanks():
    # Three turns, each ~5 tokens; budget only fits the newest one.
    messages = [
        {"role": "user", "content": "aaaa bbbb cccc dddd"},
        {"role": "assistant", "content": "eeee ffff gggg hhhh"},
        {"role": "user", "content": "iiii jjjj kkkk llll"},
    ]
    newest_cost = cc._approx_tokens(cc._message_text(messages[-1]))
    fitted, _ = cc._fit_recent_to_budget(messages, newest_cost)

    # Only the newest turn survives; older turns are dropped outright.
    assert fitted == [messages[-1]]
    # No empty-content turn was appended.
    assert all(cc._message_text(m) != "" for m in fitted)


def test_fit_recent_to_budget_no_blank_partial_when_exhausted():
    messages = [
        {"role": "user", "content": "x" * 40},
        {"role": "assistant", "content": "y" * 40},
    ]
    # Budget fits the newest turn exactly, leaving zero for the older one.
    newest_cost = cc._approx_tokens(cc._message_text(messages[-1]))
    fitted, remaining = cc._fit_recent_to_budget(messages, newest_cost)
    assert remaining == 0
    assert len(fitted) == 1
    assert cc._message_text(fitted[0]) == messages[-1]["content"]


# ---------- Context compactor ----------

def test_compactor_passes_through_under_budget():
    from maverick.context_compactor import compact
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
    ]
    out = compact(msgs, target_tokens=1000)
    assert out.messages == msgs
    assert out.dropped == []
    assert out.kept_marker is None


def test_compactor_drops_least_relevant_when_over_budget():
    from maverick.context_compactor import compact
    msgs = []
    # 10 old turns about completely unrelated topics (low relevance).
    for i in range(10):
        msgs.append({"role": "user",
                     "content": f"old topic {i}: " + "padding " * 50})
        msgs.append({"role": "assistant",
                     "content": f"reply about topic {i}: " + "filler " * 50})
    # Current user message about a different topic.
    msgs.append({"role": "user", "content": "current question about feature X"})
    msgs.append({"role": "assistant", "content": "reply about feature X"})

    out = compact(msgs, target_tokens=200, preserve_tail=2)
    assert out.tokens_after <= out.tokens_before
    assert len(out.dropped) > 0
    assert out.kept_marker is not None
    assert "compacted" in out.kept_marker
    # The last two turns are always preserved verbatim.
    assert out.messages[-2:] == msgs[-2:]


def test_compactor_keeps_most_relevant_older_turn():
    from maverick.context_compactor import compact
    msgs = [
        # Highly relevant older turn (shares vocab with the query)
        {"role": "user", "content": "tell me about feature X and its history"},
        {"role": "assistant", "content": "feature X dates back to 2024 ..."},
        # Filler older turns — heavy enough to push over the budget.
        *[
            {"role": "user",
             "content": f"weather report number {i} " + ("padding " * 60)}
            for i in range(8)
        ],
        # The tail / current focus
        {"role": "user", "content": "now explain feature X again briefly"},
    ]
    out = compact(msgs, target_tokens=80, preserve_tail=1)
    # Drop happened.
    assert out.dropped
    # The relevant first turn survives (in either order).
    survived = [m for m in out.messages if "history" in str(m.get("content", ""))]
    assert survived, "the most-relevant old turn should be kept"


def test_compactor_empty_history():
    from maverick.context_compactor import compact
    r = compact([], target_tokens=100)
    assert r.messages == []
    assert r.dropped == []
    assert r.tokens_before == r.tokens_after == 0


def test_compactor_estimate_tokens_increases_with_text():
    from maverick.context_compactor import estimate_tokens
    short = estimate_tokens([{"role": "user", "content": "hi"}])
    long = estimate_tokens([{"role": "user", "content": "hi " * 500}])
    assert long > short


class TestCompactorPreservesSystem:
    def test_system_message_never_dropped(self):
        from maverick.context_compactor import compact
        # One system message + many low-relevance head turns + a tail. Force
        # a tiny budget so the culler would otherwise drop the system msg.
        msgs = [{"role": "system", "content": "CRITICAL SYSTEM RULES " * 50}]
        for i in range(20):
            msgs.append({"role": "user", "content": f"unrelated chatter {i} " * 20})
            msgs.append({"role": "assistant", "content": f"reply {i} " * 20})
        msgs.append({"role": "user", "content": "the current question"})
        res = compact(msgs, target_tokens=200, preserve_tail=2)
        roles = [m.get("role") for m in res.messages]
        assert "system" in roles, "system message was dropped"
        # And it is the same system content.
        sys_msgs = [m for m in res.messages if m.get("role") == "system"]
        assert sys_msgs and sys_msgs[0]["content"].startswith("CRITICAL SYSTEM RULES")


def test_over_budget_tail_is_trimmed_even_when_only_system_precedes_it():
    messages = [{"role": "system", "content": "rules"},
                {"role": "user", "content": "a" * 40_000}]
    result = cc.compact(messages, target_tokens=1000, preserve_tail=1)
    assert result.tokens_after <= 1000
