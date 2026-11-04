"""Orchestrator auto-records a structured deliverable as a versioned artifact on
goal completion (best-effort, deduped). Tests the helper directly."""
from __future__ import annotations

import pytest
from maverick.deliverable import render_deliverable
from maverick.domain import available_domains
from maverick.orchestrator import _record_deliverable_artifact
from maverick.world_model import WorldModel

TBL = "| Week | Net |\n| --- | --- |\n| W1 | 300 |"


def _structured_table_domain():
    """A real pack whose declared shape renders TBL as a structured table."""
    for name, prof in available_domains().items():
        r = render_deliverable(prof.output.shape, TBL)
        if r.structured and r.table:
            return name, prof.output.deliverable
    return None, None


def test_records_versioned_artifact_and_dedups(tmp_path):
    name, label = _structured_table_domain()
    if name is None:
        pytest.skip("no structured-table domain pack available")
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("forecast", domain=name)
    _record_deliverable_artifact(w, g, TBL)
    _record_deliverable_artifact(w, g, TBL)                       # identical -> no new version
    assert [a["version"] for a in w.latest_artifacts(g)] == [1]
    _record_deliverable_artifact(w, g, TBL.replace("300", "350"))  # changed -> v2
    latest = w.latest_artifacts(g)[0]
    assert latest["version"] == 2 and latest["versions"] == 2
    assert latest["title"] == label and latest["kind"] == "table"


def test_noop_for_generic_goal(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("plain")  # no domain -> no contract -> no artifact
    _record_deliverable_artifact(w, g, "some result")
    assert w.latest_artifacts(g) == []


def test_noop_for_empty_result(tmp_path):
    name, _ = _structured_table_domain()
    if name is None:
        pytest.skip("no structured-table domain pack available")
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("g", domain=name)
    _record_deliverable_artifact(w, g, None)
    _record_deliverable_artifact(w, g, "")
    assert w.latest_artifacts(g) == []
