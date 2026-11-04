"""Cost-aware routing v3: contextual-bandit learning + epsilon-greedy policy."""
from __future__ import annotations

from random import Random

from maverick.cost.bandit import ContextualBandit, context_key, pick


def _bandit(seed=0, epsilon=0.0, path=None):
    return ContextualBandit(epsilon=epsilon, rng=Random(seed), path=path)


def test_cold_start_explores_each_arm():
    b = _bandit()
    ctx = "coder:t1"
    seen = set()
    # _MIN_PULLS=2, so the first pulls cover every arm at least twice.
    for _ in range(8):
        a = b.choose(ctx, ["openai:x", "anthropic:y"])
        seen.add(a)
        b.record(ctx, a, 1.0)
    assert seen == {"openai:x", "anthropic:y"}


def test_exploits_best_reward_when_greedy():
    b = _bandit(epsilon=0.0)
    ctx = "coder:t1"
    arms = ["cheap:good", "pricey:bad"]
    # Warm both past _MIN_PULLS with cheap:good clearly better.
    for _ in range(3):
        b.record(ctx, "cheap:good", 10.0)
        b.record(ctx, "pricey:bad", 1.0)
    # Greedy (epsilon 0) always picks the best mean.
    assert all(b.choose(ctx, arms) == "cheap:good" for _ in range(20))


def test_epsilon_explores_sometimes():
    b = _bandit(seed=1, epsilon=1.0)  # always explore
    ctx = "coder:t1"
    for _ in range(3):
        b.record(ctx, "a", 5.0)
        b.record(ctx, "b", 1.0)
    picks = {b.choose(ctx, ["a", "b"]) for _ in range(20)}
    assert picks == {"a", "b"}  # epsilon=1 reaches both


def test_record_outcome_reward():
    b = _bandit()
    ctx = "x:t0"
    b.record_outcome(ctx, "free:win", success=True, dollars=0.0001)
    b.record_outcome(ctx, "costly:win", success=True, dollars=10.0)
    b.record_outcome(ctx, "any:fail", success=False, dollars=0.01)
    s = b.stats(ctx)
    assert s["free:win"]["mean_reward"] > s["costly:win"]["mean_reward"]
    assert s["any:fail"]["mean_reward"] == 0.0


def test_single_arm_and_empty():
    b = _bandit()
    assert b.choose("c", ["only:one"]) == "only:one"
    assert b.choose("c", []) is None


def test_persistence_roundtrip(tmp_path):
    path = tmp_path / "bandit.json"
    b1 = _bandit(path=path)
    b1.record("ctx", "arm:a", 3.0)
    b1.record("ctx", "arm:a", 5.0)
    # A fresh bandit at the same path reloads the learned table.
    b2 = _bandit(path=path)
    assert b2.stats("ctx")["arm:a"]["pulls"] == 2
    assert b2.stats("ctx")["arm:a"]["mean_reward"] == 4.0


def test_pick_defers_to_fallback_when_off(monkeypatch):
    monkeypatch.delenv("MAVERICK_ROUTING_BANDIT", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    assert pick("coder", 1, ["a", "b"], fallback=lambda: "v2pick") == "v2pick"


def test_pick_chooses_within_viable_arms(monkeypatch):
    monkeypatch.setenv("MAVERICK_ROUTING_BANDIT", "1")
    b = _bandit(epsilon=0.0)
    for _ in range(3):
        b.record(context_key("coder", 1), "anthropic:opus", 9.0)
        b.record(context_key("coder", 1), "openai:gpt", 1.0)
    # v3 only reorders within v2's viable set, never outside it.
    assert pick("coder", 1, ["anthropic:opus", "openai:gpt"], bandit=b) == "anthropic:opus"
    # Cold context -> fallback.
    assert pick("writer", 2, ["x:y"], bandit=b) == "x:y"  # single arm


def test_context_key():
    assert context_key("coder", 1) == "coder:t1"
    assert context_key("", 2) == "default:t2"


def test_record_is_concurrency_safe(tmp_path):
    """Separate bandit instances at one path (≈ separate processes) must
    accumulate, not clobber: each record reloads under a cross-process lock
    before applying its delta."""
    import threading

    p = tmp_path / "bandit.json"
    n, per = 8, 25

    def worker():
        b = ContextualBandit(rng=Random(0), path=p)
        for _ in range(per):
            b.record("ctx", "arm", 1.0)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = ContextualBandit(rng=Random(0), path=p)
    assert final.stats("ctx")["arm"]["pulls"] == n * per
    assert list(tmp_path.glob("*.tmp")) == []
