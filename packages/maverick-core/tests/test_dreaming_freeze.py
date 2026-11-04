"""The calibration learning-freeze interlock must gate the dreaming
consolidation path (skills + insights), not just rehearse()."""
from __future__ import annotations

import pytest
from maverick import dreaming, reflexion

# A real dream cycle records signed start/completion receipts.
pytestmark = pytest.mark.usefixtures("signed_audit")


class _Profile:
    def __init__(self, description=""):
        self.description = description
        self.persona = ""


PROFILES = {"finance_sox": _Profile("SOX ICFR control testing and reconciliation")}


def _two_clustered_failures(path):
    for goal in ("erp export timed out on batches", "erp export timed out in demo"):
        reflexion.record(goal_text=goal, failure_class="agent_error",
                         failure_msg="timeout", reflection="r",
                         domain="finance_sox", path=path)


def _run(tmp_path):
    return dreaming.dream_cycle(
        None, profiles=PROFILES, reflexion_path=tmp_path / "reflexions.ndjson",
        insights_path=tmp_path / "insights.ndjson",
        skill_store=tmp_path / "skills",
        skill_stats_path=tmp_path / "skill_stats.json",
    )


def test_unfrozen_consolidates_insights(tmp_path, monkeypatch):
    monkeypatch.setattr(dreaming, "settings", lambda: {"enable": True, "min_cluster": 2})
    monkeypatch.setattr("maverick.calibration.learning_frozen", lambda: False)
    _two_clustered_failures(tmp_path / "reflexions.ndjson")
    report = _run(tmp_path)
    assert report.learning_frozen is False
    assert report.insights_written >= 1   # baseline: it would learn


def test_frozen_verifier_blocks_consolidation(tmp_path, monkeypatch):
    # The headline interlock: a frozen (distrusted) verifier must stop the
    # consolidation that writes live, recallable behavior -- otherwise the
    # grader's drift gets baked into learned skills/insights.
    monkeypatch.setattr(dreaming, "settings", lambda: {"enable": True, "min_cluster": 2})
    monkeypatch.setattr("maverick.calibration.learning_frozen", lambda: True)
    _two_clustered_failures(tmp_path / "reflexions.ndjson")
    report = _run(tmp_path)
    assert report.learning_frozen is True
    assert report.insights_written == 0
    assert report.skills_distilled == 0
    assert dreaming.load_insights(tmp_path / "insights.ndjson") == []  # nothing written


def test_frozen_verifier_does_not_retire_insights(tmp_path):
    # The interlock is two-sided: a frozen (distrusted) verifier must not DELETE
    # learned state either. resolve_contradictions retires insights on verifier-
    # labeled successes, so it must be gated the same way consolidation is.
    ipath = tmp_path / "insights.ndjson"
    dreaming.append_insights([dreaming.DreamInsight(
        ts=100.0, kind="failure_pattern", domain="finance_sox",
        text="erp export timeout batch reconciliation failed repeatedly",
        evidence=3,
    )], path=ipath)
    # Two successes NEWER than the insight whose tokens it fully covers -> the
    # unfrozen path retires it (min_successes=2).
    successes = [{"t": 200.0, "goal": "erp export"},
                 {"t": 200.0, "goal": "erp export"}]
    cfg = {"contradiction_successes": 2, "prune": False, "user_notes": False}

    def run(frozen):
        rep = dreaming.DreamReport()
        rep.learning_frozen = frozen
        dreaming._maintenance_phases(
            rep, cfg, successes, None, insights_path=ipath,
            reflexion_path=None, user_notes_path=None, now=300.0)
        return rep.insights_retired

    # Frozen: the contradicted insight survives (retirement skipped).
    assert run(True) == 0
    assert dreaming.load_insights(ipath) != []
    # Unfrozen baseline: the identical inputs DO retire it.
    assert run(False) >= 1
    assert dreaming.load_insights(ipath) == []
