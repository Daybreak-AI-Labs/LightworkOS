"""Flow learning evidence must survive the longest supported tenant namespace."""
from __future__ import annotations

import os

import pytest
from maverick.flow import evolution_log, node_outcomes, node_tools
from maverick.paths import reset_tenant, set_tenant


@pytest.mark.parametrize("signal", ["evolution", "outcome", "tool"])
def test_learning_signal_round_trips_in_deep_tenant(tmp_path, monkeypatch, signal):
    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    tenant = "t" * 200  # longest portable tenant path segment
    token = set_tenant(tenant)
    try:
        if signal == "evolution":
            path = evolution_log._path()
            assert os.name != "nt" or len(str(path)) > 260
            evolution_log.record_apply(
                "flow", "node", "action", "agent", 2,
                revision="revision", before_revision="before", after_revision="after",
            )
            rows = evolution_log.history("flow", "node", revision="revision")
            assert len(rows) == 1 and rows[0]["after_revision"] == "after"
        elif signal == "outcome":
            path = node_outcomes._path()
            assert os.name != "nt" or len(str(path)) > 260
            node_outcomes.record(
                "flow", "node", "action", 0.75,
                revision="revision", cohort="cohort",
            )
            assert len(node_outcomes.series(
                "flow", "node", revision="revision", cohort="cohort",
            )) == 1
        else:
            path = node_tools._path()
            assert os.name != "nt" or len(str(path)) > 260
            node_tools.record(
                "flow", "node", ["tool"], revision="revision", cohort="cohort",
            )
            assert node_tools.dominant_tool(
                "flow", "node", revision="revision", cohort="cohort",
                min_support=1,
            ) == "tool"
    finally:
        reset_tenant(token)
