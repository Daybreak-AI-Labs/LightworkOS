"""Tests for the time-limited regex helper (maverick.tools._regex_guard)."""
from __future__ import annotations

import subprocess

import pytest
from maverick.tools import _regex_guard as rg


def _spy_popen(monkeypatch) -> list:
    procs: list = []
    real = subprocess.Popen

    def _popen(*a, **kw):
        procs.append(real(*a, **kw))
        return procs[-1]

    monkeypatch.setattr(rg.subprocess, "Popen", _popen)
    return procs


def test_timeout_kills_the_child(monkeypatch):
    procs = _spy_popen(monkeypatch)
    with pytest.raises(rg.PatternTimeout):
        rg.guarded_search("(a+)+$", "a" * 40 + "b", timeout_s=0.3)
    assert len(procs) == 1 and procs[0].poll() is not None


def test_results_invalid_patterns_and_fast_path(monkeypatch):
    procs = _spy_popen(monkeypatch)
    assert rg.guarded_search("abc", "xxabcxx") is True  # no quantifier: in-process
    assert procs == []
    assert rg.guarded_search_all([r"\d+", "z+"], "a1") == [True, False]
    assert len(procs) == 1 and procs[0].returncode == 0
    with pytest.raises(rg.PatternInvalid) as e:
        rg.guarded_search_all(["ok", "[bad"], "x")
    assert e.value.index == 1
    with pytest.raises(rg.PatternInvalid):
        rg.guarded_search("a" * 1001, "a")


def test_search_pairs_checks_every_pair_in_one_child(monkeypatch):
    from maverick.tools import _regex_guard as guard

    spawned = []
    real = guard._run_child
    monkeypatch.setattr(guard, "_run_child", lambda *a, **k: spawned.append(1) or real(*a, **k))
    pairs = [("^[a-z0-9-]+$", f"name-{i}") for i in range(100)] + [("^[a-z0-9-]+$", "Not Valid!"), ("!", "x!")]
    assert guard.guarded_search_pairs(pairs, timeout_s=5.0) == [True] * 100 + [False, True]
    assert spawned == [1]
    with pytest.raises(guard.PatternTimeout):
        guard.guarded_search_pairs([("^(a+)+$", "a" * 40 + "!")], timeout_s=0.5)
