"""Compaction strategy selection (v3/v5/v7/v8 dispatcher).

Unconfigured behavior must be byte-identical to ``compact_messages``; a
configured strategy dispatches; a failing strategy falls back (fail-open).
"""
from __future__ import annotations

import base64
from types import SimpleNamespace

import maverick.config as cfg
from maverick.compaction import compact_messages
from maverick.compaction.plugins import compact_with
from maverick.compaction.strategies import (
    STRATEGIES,
    compact_with_strategy,
    configured_strategy,
)


def _traj(big: bool = True) -> list[dict]:
    blob = "X" * 9000 if big else "small"
    msgs: list[dict] = [{"role": "user", "content": "GOAL: deploy parser-service."}]
    for i in range(6):
        msgs.append({"role": "assistant", "content": [
            {"type": "text", "text": f"parser-service depends on redis (step {i})"},
            {"type": "tool_use", "id": f"t{i}", "name": "shell",
             "input": {"cmd": f"echo {i}"}},
        ]})
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": blob},
        ]})
    msgs.append({"role": "user", "content": "recent question"})
    msgs.append({"role": "assistant", "content": "recent answer"})
    return msgs


class TestConfiguredStrategy:
    def test_default_is_empty(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
        monkeypatch.setattr(cfg, "load_config", dict)
        assert configured_strategy() == ""

    def test_env_selects_each_strategy(self, monkeypatch):
        for name in STRATEGIES:
            monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", name)
            assert configured_strategy() == name

    def test_env_invalid_value_means_default(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "lerned")
        monkeypatch.setattr(cfg, "load_config", dict)
        assert configured_strategy() == ""

    def test_config_selects(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
        monkeypatch.setattr(
            cfg, "load_config",
            lambda: {"context": {"compaction_strategy": "Graph"}},
        )
        assert configured_strategy() == "graph"

    def test_config_invalid_value_means_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
        monkeypatch.setattr(
            cfg, "load_config",
            lambda: {"context": {"compaction_strategy": "everything"}},
        )
        assert configured_strategy() == ""

    def test_env_beats_config(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "streaming")
        monkeypatch.setattr(
            cfg, "load_config",
            lambda: {"context": {"compaction_strategy": "graph"}},
        )
        assert configured_strategy() == "streaming"


class TestDispatch:
    def test_unconfigured_is_byte_identical_to_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
        monkeypatch.setattr(cfg, "load_config", dict)
        msgs = _traj()
        assert compact_with_strategy(msgs) == compact_messages(msgs)
        out = compact_with_strategy(msgs, keep_recent=2, max_tool_bytes=100)
        assert out == compact_messages(msgs, keep_recent=2, max_tool_bytes=100)

    def test_unknown_explicit_strategy_uses_default(self):
        msgs = _traj()
        assert compact_with_strategy(msgs, strategy="bogus") == compact_messages(msgs)

    def test_graph_strategy_via_env(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "graph")
        out = compact_with_strategy(_traj(), keep_recent=2)
        assert "<graph-digest" in str(out[1]["content"])
        assert "parser-service --depends_on--> redis" in str(out[1]["content"])

    def test_multimodal_strategy_stubs_media(self, monkeypatch):
        import base64
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "multimodal")
        data = base64.b64encode(b"\x00" * 5000).decode("ascii")
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "user", "content": [{
                "type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": data},
            }]},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "recent"},
            {"role": "assistant", "content": "done"},
        ]
        out = compact_with_strategy(msgs, keep_recent=2)
        blk = out[1]["content"][0]
        assert blk["type"] == "text"
        assert "[image:" in blk["text"]

    def test_streaming_strategy_emits_running_summary(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "streaming")
        out = compact_with_strategy(_traj(big=False), conversation_id="c1", keep_recent=2)
        assert "<stream-summary" in str(out[1]["content"])
        assert out[0] == _traj(big=False)[0]

    def test_learned_strategy_uses_injected_llm(self, monkeypatch, fake_llm, make_llm_response):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "learned")
        fake_llm.scripted = [make_llm_response("THE DIGEST")]
        out = compact_with_strategy(_traj(), llm=fake_llm, keep_recent=2)
        assert "<learned-digest" in str(out[1]["content"])
        assert "THE DIGEST" in str(out[1]["content"])

    def test_failing_strategy_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "graph")

        def boom(*a, **kw):
            raise RuntimeError("strategy exploded")

        monkeypatch.setattr("maverick.compaction.graph.compact_graph", boom)
        msgs = _traj()
        assert compact_with_strategy(msgs) == compact_messages(msgs)

    def test_llm_backed_strategies_receive_budget(self, monkeypatch):
        class BudgetLLM:
            def __init__(self):
                self.calls: list[dict] = []

            def complete(self, **kwargs):
                self.calls.append(kwargs)
                return SimpleNamespace(text="alpha | relates_to | beta")

        budget = object()
        for strategy in ("learned", "streaming", "graph"):
            llm = BudgetLLM()
            compact_with_strategy(
                _traj(big=False),
                strategy=strategy,
                llm=llm,
                budget=budget,
                conversation_id=f"budget-{strategy}",
                keep_recent=2,
            )
            assert llm.calls
            assert all(call["budget"] is budget for call in llm.calls)

        monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "multimodal")
        llm = BudgetLLM()
        data = base64.b64encode(b"\x00" * 5000).decode("ascii")
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "user", "content": [{
                "type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": data},
            }]},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "recent"},
            {"role": "assistant", "content": "done"},
        ]
        compact_with(msgs, llm=llm, budget=budget, keep_recent=2)
        assert llm.calls
        assert all(call["budget"] is budget for call in llm.calls)
