"""Tests for the process reward models (maverick.prm)."""
from __future__ import annotations

# ---------- PRM ----------

class TestNullPRM:
    def test_returns_neutral(self):
        from maverick.prm import NullPRM, StepContext
        prm = NullPRM()
        out = prm.score(StepContext(goal_id=1, step_index=0, role="researcher"))
        assert out.promise == 0.5
        assert out.progress == 0.0
        assert out.confidence == 0.0


class TestHeuristicPRM:
    def test_error_strongly_negative(self):
        from maverick.prm import HeuristicPRM, StepContext
        out = HeuristicPRM().score(StepContext(
            goal_id=1, step_index=0, role="coder", error="something broke",
        ))
        assert out.promise < 0
        assert out.progress <= 0

    def test_final_strongly_positive(self):
        from maverick.prm import HeuristicPRM, StepContext
        out = HeuristicPRM().score(StepContext(
            goal_id=1, step_index=5, role="orchestrator", is_final=True,
        ))
        assert out.promise >= 0.9
        assert out.progress > 0

    def test_tool_success_positive_progress(self):
        from maverick.prm import HeuristicPRM, StepContext
        out = HeuristicPRM().score(StepContext(
            goal_id=1, step_index=2, role="researcher",
            tool_name="read_file", tool_succeeded=True,
        ))
        assert out.promise > 0.5
        assert out.progress > 0

    def test_tool_failure_negative_progress(self):
        from maverick.prm import HeuristicPRM, StepContext
        out = HeuristicPRM().score(StepContext(
            goal_id=1, step_index=2, role="researcher",
            tool_name="shell", tool_succeeded=False,
        ))
        assert out.promise > 0  # still some hope; not as negative as error
        assert out.progress < 0

    def test_thinking_decays(self):
        from maverick.prm import HeuristicPRM, StepContext
        out = HeuristicPRM().score(StepContext(
            goal_id=1, step_index=10, role="researcher", prior_step_score=0.8,
        ))
        # Decay vs prior, but never below floor 0.3.
        assert 0.3 <= out.promise <= 0.8


class TestRemotePRMFallback:
    def test_falls_back_when_no_httpx(self, monkeypatch):
        """Without httpx the remote PRM degrades to heuristic, never blocks."""
        # Force ImportError on httpx.
        import sys

        from maverick.prm import RemotePRM, StepContext
        monkeypatch.setitem(sys.modules, "httpx", None)
        prm = RemotePRM(endpoint="http://localhost:8888")
        out = prm.score(StepContext(
            goal_id=1, step_index=0, role="coder", error="boom",
        ))
        # Falls through to HeuristicPRM, which gives error=-0.5
        assert out.promise < 0


class TestBuildFromEnv:
    def test_default_is_null(self, monkeypatch):
        from maverick.prm import NullPRM, build_from_env
        monkeypatch.delenv("MAVERICK_PRM", raising=False)
        prm = build_from_env()
        assert isinstance(prm, NullPRM)

    def test_heuristic_via_env(self, monkeypatch):
        from maverick.prm import HeuristicPRM, build_from_env
        monkeypatch.setenv("MAVERICK_PRM", "heuristic")
        prm = build_from_env()
        assert isinstance(prm, HeuristicPRM)

    def test_remote_without_endpoint_falls_back(self, monkeypatch):
        from maverick.prm import HeuristicPRM, build_from_env
        monkeypatch.setenv("MAVERICK_PRM", "remote")
        monkeypatch.delenv("MAVERICK_PRM_ENDPOINT", raising=False)
        prm = build_from_env()
        # No endpoint set -> we fall back to heuristic with a warning.
        assert isinstance(prm, HeuristicPRM)
