"""Bounds on the multi-agent fan-out/fan-in text paths.

Regression target: a child's full FINAL was (a) posted to the blackboard
uncapped — re-rendered into every later worker's first turn via
``bb.render(40)``, the classic O(K^2) swarm re-send — and (b) concatenated
whole into the orchestrator's ``spawn_swarm`` tool result with no per-child
or total cap, where it persists for every subsequent orchestrator turn.
``Blackboard.render`` also had no per-entry bound, so one oversized post
dominated every brief that included it.
"""
from __future__ import annotations

from types import SimpleNamespace

from maverick.agent import AgentResult, _finding_excerpt
from maverick.blackboard import Blackboard
from maverick.tools.spawn import _format_swarm_results


class TestFindingExcerpt:
    def test_short_final_unchanged(self):
        assert _finding_excerpt("done: the answer is 42") == "done: the answer is 42"

    def test_long_final_capped_with_pointer(self):
        out = _finding_excerpt("x" * 10_000)
        assert len(out) < 2_000
        assert "truncated" in out

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_FINDING_POST_MAX_CHARS", "300")
        out = _finding_excerpt("y" * 1_000)
        assert len(out) < 500


class TestRenderEntryCap:
    def test_oversized_entry_bounded_in_render(self):
        bb = Blackboard()
        bb.post("w1", "finding", "z" * 20_000)
        bb.post("w2", "observation", "small note")
        out = bb.render(40)
        assert len(out) < 3_000
        assert "small note" in out
        assert "[w1/finding]" in out

    def test_small_entries_unchanged(self):
        bb = Blackboard()
        bb.post("a", "plan", "step one then two")
        assert "step one then two" in bb.render(10)

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_BB_RENDER_ENTRY_CHARS", "50")
        bb = Blackboard()
        bb.post("a", "finding", "q" * 400)
        out = bb.render(10)
        assert len(out) < 200


class TestSwarmResultCaps:
    def _parent(self):
        return SimpleNamespace(ctx=SimpleNamespace(quarantine=None))

    def _child(self, name):
        return SimpleNamespace(role="researcher", name=name)

    def test_small_results_untouched(self):
        children = [self._child("c1")]
        results = [AgentResult(final="short answer")]
        out = _format_swarm_results(self._parent(), children, results, False)
        assert "short answer" in out

    def test_per_child_cap(self):
        children = [self._child("c1"), self._child("c2")]
        results = [AgentResult(final="a" * 50_000), AgentResult(final="tail-marker")]
        out = _format_swarm_results(self._parent(), children, results, False)
        assert len(out) < 12_000
        assert "truncated" in out
        assert "tail-marker" in out  # later children not starved by the first

    def test_total_cap_bounds_wide_fanout(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_SWARM_CHILD_RESULT_CHARS", "1000")
        monkeypatch.setenv("MAVERICK_SWARM_RESULTS_TOTAL_CHARS", "2500")
        children = [self._child(f"c{i}") for i in range(8)]
        results = [AgentResult(final=f"child{i} " + "b" * 5_000) for i in range(8)]
        out = _format_swarm_results(self._parent(), children, results, False)
        assert len(out) < 4_000
        # every child still gets a line (identity preserved), even if elided
        for i in range(8):
            assert f"c{i}" in out

    def test_error_and_blocked_lines_pass_through(self):
        children = [self._child("c1"), self._child("c2")]
        results = [AgentResult(error="boom"), AgentResult(blocked_on_user=True)]
        out = _format_swarm_results(self._parent(), children, results, False)
        assert "ERROR: boom" in out and "BLOCKED_ON_USER" in out
