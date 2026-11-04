"""Compaction plug-in API: registry, dispatch, fail-safe to built-in."""
from __future__ import annotations

import pytest
from maverick.compaction import plugins as cp


@pytest.fixture(autouse=True)
def _restore_registry():
    saved = dict(cp._REGISTRY)
    yield
    cp._REGISTRY.clear()
    cp._REGISTRY.update(saved)


class _Marker:
    name = "marker"

    def compact(self, messages, **kw):
        return [{"role": "system", "content": f"compacted {len(messages)}"}]


def _msgs(n):
    return [{"role": "user", "content": f"m{i}"} for i in range(n)]


def test_builtin_registered_by_default():
    assert "heuristic" in cp.available()
    assert cp.get("heuristic") is not None


def test_register_and_dispatch():
    cp.register(_Marker())
    out = cp.compact_with(_msgs(5), strategy="marker")
    assert out == [{"role": "system", "content": "compacted 5"}]


def test_default_uses_heuristic(monkeypatch):
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    # short message list -> heuristic returns it unchanged
    msgs = _msgs(3)
    assert cp.compact_with(msgs) == msgs


def test_unknown_strategy_fails_safe_to_builtin(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "does-not-exist")
    msgs = _msgs(3)
    # falls back to heuristic (returns short list unchanged), not an error
    assert cp.compact_with(msgs) == msgs


def test_config_selects_strategy(monkeypatch):
    cp.register(_Marker())
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"context": {"compaction_strategy": "marker"}})
    out = cp.compact_with(_msgs(2))
    assert out[0]["content"] == "compacted 2"


def test_env_overrides_config(monkeypatch):
    cp.register(_Marker())
    monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "marker")
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"context": {"compaction_strategy": "heuristic"}})
    assert cp.compact_with(_msgs(2))[0]["content"] == "compacted 2"


def test_register_duplicate_rejected():
    cp.register(_Marker())
    with pytest.raises(ValueError, match="already registered"):
        cp.register(_Marker())
    cp.register(_Marker(), replace=True)  # replace is allowed


def test_register_validates_strategy():
    class _NoName:
        compact = lambda self, m, **k: m  # noqa: E731

    with pytest.raises(ValueError, match="non-empty string"):
        cp.register(_NoName())


def _hybrid_window(n=12, chars=4000):
    """A window big enough to be worth compacting (> _HYBRID_RECORD_MIN_CHARS)
    whose old tool_results the built-in shrink will digest."""
    msgs = [{"role": "user", "content": "brief"}]
    for i in range(n):
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": "x" * chars}]})
    return msgs


def test_hybrid_flag_changes_strategy_selection(monkeypatch, tmp_path):
    """The punchlist behavioral test: flipping [compaction] hybrid changes
    which registered strategy actually runs."""
    from random import Random

    from maverick.compaction.hybrid import STRATEGIES, HybridPicker

    calls = []

    class _SpyGraph:
        name = "graph"

        def compact(self, messages, **kw):
            calls.append(self.name)
            return [{"role": "system", "content": "graph-compacted"}]

    cp.register(_SpyGraph(), replace=True)
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)

    msgs = _hybrid_window()
    picker = HybridPicker(epsilon=0.0, rng=Random(0),
                          ledger_path=tmp_path / "ledger.json")
    # Teach the ledger that "retrieval" wins for this shape (>= _MIN_PULLS
    # each so the bandit exploits rather than explores under-pulled arms).
    for s in STRATEGIES:
        for _ in range(3):
            picker.record(msgs, s, success=(s == "retrieval"))
    monkeypatch.setattr(cp, "_hybrid_picker", lambda: picker)

    # Flag off -> built-in path; the spy strategy is never consulted.
    monkeypatch.delenv("MAVERICK_COMPACTION_HYBRID", raising=False)
    cp.compact_with(msgs)
    assert calls == []

    # Flag on -> picker picks "retrieval" -> mapped to the registered "graph".
    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    out = cp.compact_with(msgs)
    assert calls == ["graph"]
    assert out == [{"role": "system", "content": "graph-compacted"}]


def test_hybrid_records_outcomes_into_ledger(monkeypatch, tmp_path):
    from random import Random

    from maverick.compaction.hybrid import HybridPicker, bucket_key, extract_features

    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    picker = HybridPicker(epsilon=0.0, rng=Random(0),
                          ledger_path=tmp_path / "ledger.json")
    monkeypatch.setattr(cp, "_hybrid_picker", lambda: picker)

    msgs = _hybrid_window()  # 48k chars of stale tool output -> shrinkable
    cp.compact_with(msgs)
    stats = picker._bandit.stats(bucket_key(extract_features(msgs)))
    pulled = {a: v for a, v in stats.items() if v["pulls"]}
    assert len(pulled) == 1  # exactly one outcome recorded for the picked arm
    assert next(iter(pulled.values()))["mean_reward"] == 1.0  # it shrank


def test_hybrid_skips_recording_tiny_windows(monkeypatch, tmp_path):
    from random import Random

    from maverick.compaction.hybrid import HybridPicker

    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    ledger = tmp_path / "ledger.json"
    monkeypatch.setattr(
        cp, "_hybrid_picker",
        lambda: HybridPicker(epsilon=0.0, rng=Random(0), ledger_path=ledger))

    msgs = _msgs(3)
    assert cp.compact_with(msgs) == msgs  # tiny window passes through
    assert not ledger.exists()  # nothing to learn from an uncompactable window


def test_explicit_strategy_beats_hybrid_and_warns_once(monkeypatch, caplog):
    import logging

    cp.register(_Marker())
    monkeypatch.setattr(cp, "_HYBRID_SHADOWED_WARNED", False)
    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    monkeypatch.setenv("MAVERICK_COMPACTION_STRATEGY", "marker")
    with caplog.at_level(logging.WARNING, logger="maverick.compaction.plugins"):
        out = cp.compact_with(_msgs(2))
        cp.compact_with(_msgs(2))  # second call must not warn again
    assert out == [{"role": "system", "content": "compacted 2"}]
    shadow_warnings = [r for r in caplog.records if "hybrid" in r.getMessage()]
    assert len(shadow_warnings) == 1


def test_hybrid_fails_open_to_builtin(monkeypatch, caplog):
    import logging

    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)

    class _Boom:
        def pick(self, messages):
            raise RuntimeError("boom")

    monkeypatch.setattr(cp, "_hybrid_picker", _Boom)
    msgs = _msgs(3)
    with caplog.at_level(logging.WARNING, logger="maverick.compaction.plugins"):
        assert cp.compact_with(msgs) == msgs  # built-in passthrough, no raise
    assert [r for r in caplog.records if "failed open" in r.getMessage()]


def test_hybrid_flag_off_default_path_unchanged(monkeypatch, caplog):
    import logging

    monkeypatch.delenv("MAVERICK_COMPACTION_HYBRID", raising=False)
    monkeypatch.delenv("MAVERICK_COMPACTION_STRATEGY", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    msgs = _msgs(3)
    with caplog.at_level(logging.WARNING, logger="maverick.compaction.plugins"):
        assert cp.compact_with(msgs) == msgs
    assert not [r for r in caplog.records if "hybrid" in r.getMessage()]


def test_heuristic_strategy_actually_compacts():
    # a long list with a big tool_result should get digested by the built-in
    big = "x" * 100000
    msgs = [{"role": "user", "content": "brief"}]
    for i in range(20):
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": big}]})
    out = cp.compact_with(msgs, strategy="heuristic", max_tool_bytes=1000,
                          keep_recent=3)
    # the body shrank (older tool_results digested)
    assert sum(len(str(m)) for m in out) < sum(len(str(m)) for m in msgs)
