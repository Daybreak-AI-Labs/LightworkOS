"""Hindsight: learning-regression detection over learned-state snapshots."""
from __future__ import annotations

from types import SimpleNamespace

from maverick import dreaming, hindsight, reflexion
from maverick.file_lock import private_path_is_restricted


def _make_state(tmp_path, name, *, reflexions=(), insights=(), skills=()):
    """Build a learned-state directory shaped like a dream snapshot."""
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    rpath = d / "reflexions.ndjson"
    for goal, dom in reflexions:
        reflexion.record(goal_text=goal, failure_class="agent_error",
                         failure_msg="m", reflection="lesson body",
                         domain=dom, path=rpath)
    if insights:
        ipath = d / "insights.ndjson"
        dreaming.append_insights([
            dreaming.DreamInsight(ts=1.0, kind="failure_pattern", domain=dom,
                                  text=text, evidence=3)
            for text, dom in insights
        ], path=ipath)
    if skills:
        sk = d / "learned-skills"
        sk.mkdir()
        for skname, body in skills:
            (sk / f"{skname}.md").write_text(body, encoding="utf-8")
    return d


class TestCoverage:
    def test_reflexion_provides_coverage(self, tmp_path):
        d = _make_state(tmp_path, "s", reflexions=[
            ("reconcile the quarterly ledger totals", "finance_sox"),
        ])
        cov = hindsight.coverage_under(
            "reconcile the quarterly ledger totals", d, domain="finance_sox",
        )
        assert cov.covered and cov.reflexion

    def test_skill_provides_coverage(self, tmp_path):
        d = _make_state(tmp_path, "s", skills=[
            ("ledger-reconcile", "# Reconcile ledger totals\nreconcile "
             "quarterly ledger totals each period"),
        ])
        cov = hindsight.coverage_under(
            "reconcile the quarterly ledger totals", d,
        )
        assert cov.covered and cov.skill == "ledger-reconcile"

    def test_empty_state_is_uncovered(self, tmp_path):
        d = _make_state(tmp_path, "empty")
        assert hindsight.coverage_under("anything at all", d).covered is False

    def test_missing_dir_is_uncovered(self, tmp_path):
        cov = hindsight.coverage_under("x", tmp_path / "nope")
        assert cov.covered is False


class _World:
    def __init__(self, goals):
        self._goals = goals

    def list_goals(self, status=None, limit=100, order="desc"):
        gs = self._goals
        if status:
            gs = [g for g in gs if getattr(g, "status", "") == status]
        return gs[:limit]


def _goal(title, status="blocked", domain="finance_sox"):
    return SimpleNamespace(title=title, description="", status=status,
                           domain=domain)


class TestReplay:
    def test_detects_gain(self, tmp_path):
        # Older state: empty. Newer state: covers the goal.
        before = _make_state(tmp_path, "before")
        after = _make_state(tmp_path, "after", reflexions=[
            ("reconcile the quarterly ledger totals", "finance_sox"),
        ])
        world = _World([_goal("reconcile the quarterly ledger totals")])
        report = hindsight.replay(world, before=before, after=after)
        assert report.n_goals == 1
        assert report.covered_before == 0 and report.covered_now == 1
        assert report.gained and not report.regressed

    def test_detects_regression(self, tmp_path):
        # The newer state LOST the lesson (retired skill / pruned reflexion):
        # this is the signal the engine exists to surface.
        before = _make_state(tmp_path, "before", reflexions=[
            ("reconcile the quarterly ledger totals", "finance_sox"),
        ])
        after = _make_state(tmp_path, "after")
        world = _World([_goal("reconcile the quarterly ledger totals")])
        report = hindsight.replay(world, before=before, after=after)
        assert report.regressed and not report.gained
        assert "reconcile" in report.regressed[0]
        assert "regressed" in report.summary().lower()

    def test_unchanged_is_neither(self, tmp_path):
        state = _make_state(tmp_path, "s", reflexions=[
            ("reconcile the quarterly ledger totals", "finance_sox"),
        ])
        world = _World([_goal("reconcile the quarterly ledger totals")])
        report = hindsight.replay(world, before=state, after=state)
        assert not report.gained and not report.regressed
        assert report.covered_before == report.covered_now == 1

    def test_status_filter_replays_only_failures_by_default(self, tmp_path):
        before = _make_state(tmp_path, "before")
        after = _make_state(tmp_path, "after", reflexions=[
            ("reconcile the ledger", "finance_sox"),
        ])
        world = _World([
            _goal("reconcile the ledger", status="blocked"),
            _goal("reconcile the ledger", status="done"),
        ])
        # Default status="blocked": only the failed goal is replayed.
        assert hindsight.replay(world, before=before, after=after).n_goals == 1
        # all goals:
        assert hindsight.replay(
            world, before=before, after=after, status=None,
        ).n_goals == 2


class TestLedger:
    def test_ledger_and_audit_row(self, tmp_path, monkeypatch):
        rows = []
        import maverick.audit as audit_pkg
        monkeypatch.setattr(audit_pkg, "record",
                            lambda kind, **kw: rows.append((kind, kw)) or True)
        report = hindsight.HindsightReport(
            n_goals=3, covered_now=2, covered_before=1,
            gained=["SECRET-GAINED payroll token"],
            regressed=["SECRET-REGRESSED customer data"],
        )
        path = tmp_path / "hindsight.ndjson"
        assert hindsight.write_ledger(
            report, before_label="snap1", path=path, now=5.0,
        ) is True
        import json
        line = json.loads(path.read_text().strip())
        assert line["before"] == "snap1" and line["covered_now"] == 2
        assert line["gained"] == 1 and line["regressed"] == 1
        text = path.read_text()
        assert "SECRET-GAINED" not in text
        assert "SECRET-REGRESSED" not in text
        assert private_path_is_restricted(path, 0o600)
        assert private_path_is_restricted(path.parent, 0o700)
        assert rows and rows[0][0] == "learning_update"
        assert rows[0][1]["replay"] == "hindsight"
