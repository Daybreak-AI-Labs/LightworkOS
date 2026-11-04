"""Concurrent soak of the out-of-process dispatch substrate: zero-loss,
exactly-once under contention, clean drain."""
from __future__ import annotations

import pytest
from maverick import control_data_plane_soak as soak

# Six worker threads contending on one SQLite queue: on a two-core CI runner a
# second xdist worker on the same box starves the lock waits into "database
# is locked", which the soak rightly reports as a finding. CI runs this file in
# the serial phase (see .github/workflows/ci.yml) so the box is its own.
pytestmark = pytest.mark.heavy_concurrency


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")


def test_soak_holds_under_concurrency(tmp_path):
    ev = soak.run_soak(tmp_path, goals=40, workers=4)
    assert ev["proof"]["ok"] is True
    assert ev["data_plane"]["done"] == 40
    assert ev["data_plane"]["duplicates"] == 0          # exactly-once
    assert ev["data_plane"]["lost"] == 0                # zero-loss
    assert ev["data_plane"]["queue_remaining"] == 0     # clean drain
    assert ev["data_plane"]["worker_errors"] == []
    assert ev["control_plane"]["goals_pending_after_submit"] == 40


def test_exactly_once_executed_total_matches_goals(tmp_path):
    ev = soak.run_soak(tmp_path, goals=50, workers=6)
    assert ev["data_plane"]["executed_total"] == 50     # not one more, not one less
    assert ev["proof"]["exactly_once_under_contention"] is True


def test_soak_above_queue_list_cap(tmp_path):
    # >100 goals: JobQueue.list() caps at 100, so the harness must count with a
    # fleet-sized limit -- regression for the cap bug the soak itself surfaced.
    ev = soak.run_soak(tmp_path, goals=130, workers=6)
    assert ev["control_plane"]["enqueued"] == 130
    assert ev["proof"]["ok"] is True
    assert ev["data_plane"]["done"] == 130


def test_single_worker_still_drains(tmp_path):
    ev = soak.run_soak(tmp_path, goals=20, workers=1)
    assert ev["proof"]["ok"] is True
    assert ev["data_plane"]["done"] == 20
