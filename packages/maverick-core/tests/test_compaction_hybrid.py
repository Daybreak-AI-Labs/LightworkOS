"""Compaction v6 hybrid: learned strategy picker. Deterministic PRNG, offline.

Fail-open is the contract under test as much as learning: a broken window,
ledger, or weights file must always yield a usable strategy, never a raise.
"""
from __future__ import annotations

import json
from random import Random

from maverick.compaction.hybrid import (
    FALLBACK_STRATEGY,
    FEATURE_NAMES,
    STRATEGIES,
    WEIGHTS_SCHEMA,
    HybridPicker,
    bucket_key,
    default_strategy,
    enabled,
    extract_features,
    fit,
    load_weights,
    pick_strategy,
    save_weights,
)
from maverick.file_lock import private_path_is_restricted


def _window(n=30, *, tool_chars=0, code=False, tools=(), span=0.0):
    """Synthetic message window with controllable shape."""
    msgs = []
    for i in range(n):
        content: list | str = [{"type": "text", "text": "discussing the plan " * 40}]
        if code and i % 2 == 0:
            content[0]["text"] += "\n```py\nprint(1)\n```\n```\nx\n```"
        if tools and i % 3 == 0:
            name = tools[i % len(tools)]
            content.append({"type": "tool_use", "id": f"t{i}", "name": name,
                            "input": {}})
            content.append({"type": "tool_result", "tool_use_id": f"t{i}",
                            "content": "r" * (tool_chars or 1)})
        msg = {"role": "user" if i % 2 else "assistant", "content": content}
        if span:
            msg["ts"] = 1000.0 + (span * i / max(1, n - 1))
        msgs.append(msg)
    return msgs


# ------------------------------------------------------------- features ----

def test_extract_features_counts_shape_only():
    msgs = _window(12, tool_chars=5000, code=True, tools=("shell", "read"),
                   span=120.0)
    f = extract_features(msgs)
    assert f["messages"] == 12
    assert 0.0 < f["tool_ratio"] < 1.0
    assert f["code_density"] > 0
    assert f["distinct_tools"] == 2
    assert f["age_span"] == 120.0
    # Deterministic + identical for identical windows.
    assert f == extract_features(_window(12, tool_chars=5000, code=True,
                                         tools=("shell", "read"), span=120.0))


def test_extract_features_tolerates_garbage():
    f = extract_features([None, "text", {"content": 42}, {}])  # type: ignore
    assert f["messages"] == 2  # the dicts; non-dicts skipped
    assert f["tool_ratio"] == 0.0 and f["distinct_tools"] == 0


def test_bucket_key_is_stable_and_decodable_shape():
    f = extract_features(_window(30, tool_chars=4000, tools=("shell",)))
    key = bucket_key(f)
    assert key == bucket_key(f)
    parts = key.split("|")
    assert len(parts) == len(FEATURE_NAMES)
    assert [p[0] for p in parts] == ["m", "r", "c", "t", "a"]


# --------------------------------------------------- cold start + ladder ----

def test_cold_start_uses_existing_ladder(tmp_path):
    picker = HybridPicker(ledger_path=tmp_path / "ledger.json", rng=Random(7))
    msgs = _window(30, code=True)  # ladder: has_code -> structural
    strategy, reason = picker.pick(msgs)
    assert strategy == "structural"
    assert "cold-start ladder" in reason

    tiny = _window(2)  # ladder: tokens < 4000 -> truncate
    strategy2, _ = picker.pick(tiny)
    assert strategy2 == "truncate"


def test_default_strategy_matches_ladder_registry():
    assert default_strategy(extract_features(_window(2))) == "truncate"
    assert default_strategy(extract_features(_window(30, code=True))) == "structural"
    long_prose = extract_features(_window(60))
    assert default_strategy(long_prose) in STRATEGIES


# ----------------------------------------------------- ledger + bandit -----

def test_ledger_learns_and_persists_0600(tmp_path):
    path = tmp_path / "ledger.json"
    picker = HybridPicker(epsilon=0.0, rng=Random(0), ledger_path=path)
    msgs = _window(30, code=True)
    # Outcomes: summarize succeeds, every other strategy fails (>= 2 pulls
    # each so the bandit exploits rather than explores under-pulled arms).
    for s in STRATEGIES:
        for _ in range(3):
            picker.record(msgs, s, success=(s == "summarize"))
    strategy, reason = picker.pick(msgs)
    assert strategy == "summarize"
    assert "ledger" in reason
    assert private_path_is_restricted(path)

    # A fresh picker over the same ledger file exploits the same knowledge.
    again = HybridPicker(epsilon=0.0, rng=Random(0), ledger_path=path)
    assert again.pick(msgs)[0] == "summarize"


def test_record_ignores_unknown_strategy(tmp_path):
    picker = HybridPicker(ledger_path=tmp_path / "l.json")
    picker.record(_window(5), "not-a-strategy", success=True)
    assert not (tmp_path / "l.json").exists()


def test_pick_fails_open_on_broken_input(tmp_path, monkeypatch):
    picker = HybridPicker(ledger_path=tmp_path / "l.json")
    strategy, reason = picker.pick(None)  # type: ignore[arg-type]
    assert strategy in STRATEGIES
    # And even an internal explosion falls open to the structural default.
    monkeypatch.setattr("maverick.compaction.hybrid.extract_features",
                        lambda m: (_ for _ in ()).throw(RuntimeError("boom")))
    strategy2, reason2 = picker.pick(_window(3))
    assert strategy2 == FALLBACK_STRATEGY
    assert "fail-open" in reason2


# ------------------------------------------------------ offline trainer ----

def test_fit_pure_python_weights_roundtrip(tmp_path):
    ledger_path = tmp_path / "ledger.json"
    picker = HybridPicker(epsilon=0.0, rng=Random(0), ledger_path=ledger_path)
    code_msgs = _window(30, code=True, tools=("shell",), tool_chars=3000)
    prose_msgs = _window(60)
    for _ in range(4):
        picker.record(code_msgs, "structural", success=True)
        picker.record(code_msgs, "summarize", success=False)
        picker.record(prose_msgs, "summarize", success=True)
        picker.record(prose_msgs, "structural", success=False)

    weights = fit(ledger_path, now=1_750_000_000.0)
    assert weights["schema"] == WEIGHTS_SCHEMA
    assert weights["features"] == list(FEATURE_NAMES) + ["bias"]
    assert set(weights["strategies"]) == {"structural", "summarize"}
    assert all(len(ws) == len(FEATURE_NAMES) + 1
               for ws in weights["strategies"].values())

    wpath = tmp_path / "weights.json"
    save_weights(weights, wpath)
    assert private_path_is_restricted(wpath)
    assert private_path_is_restricted(wpath.parent, 0o700)
    assert load_weights(wpath) is not None

    # A picker consulting the weights separates the two shapes (epsilon=0).
    trained = HybridPicker(epsilon=0.0, rng=Random(0),
                           ledger_path=tmp_path / "fresh.json",
                           weights_path=wpath)
    s_code, r_code = trained.pick(code_msgs)
    s_prose, _ = trained.pick(prose_msgs)
    assert s_code == "structural" and "weights" in r_code
    assert s_prose == "summarize"


def test_load_weights_rejects_bad_files(tmp_path):
    assert load_weights(None) is None
    assert load_weights(tmp_path / "missing.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert load_weights(bad) is None
    bad.write_text(json.dumps({"schema": "other/9", "strategies": {}}))
    assert load_weights(bad) is None
    bad.write_text(json.dumps({"schema": WEIGHTS_SCHEMA,
                               "strategies": {"structural": [1, 2]}}))  # wrong dim
    assert load_weights(bad) is None


def test_epsilon_exploration_uses_injected_prng(tmp_path):
    wpath = tmp_path / "w.json"
    save_weights({"schema": WEIGHTS_SCHEMA,
                  "features": list(FEATURE_NAMES) + ["bias"],
                  "strategies": {"structural": [0.0] * 6}}, wpath)

    class AlwaysExplore(Random):
        def random(self):
            return 0.0  # < epsilon -> explore branch

    picker = HybridPicker(epsilon=0.5, rng=AlwaysExplore(3), weights_path=wpath)
    _, reason = picker.pick(_window(10))
    assert "explore" in reason


def test_no_torch_required():
    import sys

    import maverick.compaction.hybrid  # noqa: F401  (already imported above)
    assert "torch" not in sys.modules
    doc = " ".join((sys.modules["maverick.compaction.hybrid"].__doc__ or "").split())
    assert "no torch" in doc.lower()
    assert "not a pretrained model" in doc


# -------------------------------------------------------------- the knob ----

def test_disabled_by_default_falls_back_to_ladder(monkeypatch):
    monkeypatch.delenv("MAVERICK_COMPACTION_HYBRID", raising=False)
    assert enabled() is False
    strategy, reason = pick_strategy(_window(30, code=True))
    assert strategy == "structural"
    assert "hybrid disabled" in reason


def test_env_knob_enables(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_COMPACTION_HYBRID", "1")
    assert enabled() is True
    picker = HybridPicker(ledger_path=tmp_path / "l.json", rng=Random(1))
    strategy, _ = pick_strategy(_window(30, code=True), picker=picker)
    assert strategy in STRATEGIES
