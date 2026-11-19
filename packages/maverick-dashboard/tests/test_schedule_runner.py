"""The dashboard runs due Automations schedules itself.

On a README install a schedule created on the Automations page never ran:
the dashboard only ran its automation worker when other features were on, and
`lightwork worker` drained the shared root queue while the schedule was in the
workspace's own queue.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from maverick_dashboard import schedule_runner


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(schedule_runner, "_workspaces", lambda: ["local"])
    yield tmp_path
    schedule_runner.stop(timeout=5)


def test_a_due_schedule_runs_inside_its_workspace(home, monkeypatch):
    from maverick import runner
    from maverick.job_queue import JobQueue
    from maverick.paths import current_tenant_id, tenant_scope
    from maverick.world_model import WorldModel

    ran = []
    done = threading.Event()

    def fake_run(goal_id, **kwargs):
        ran.append((goal_id, current_tenant_id()))
        done.set()
        return "done"

    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)
    with tenant_scope(tenant="local"):
        JobQueue().enqueue("start_goal", {"text": "Reply with the single word SCHEDULED.",
                                          "title": "E2E schedule test"}, run_at=time.time() - 1)
    assert schedule_runner.start() is True
    assert done.wait(20), "the due schedule never ran"
    goal_id, tenant = ran[0]
    assert tenant == "local"
    with tenant_scope(tenant="local"):
        assert WorldModel().get_goal(goal_id).title == "E2E schedule test"


def test_scheduling_turned_off_starts_nothing(home, monkeypatch):
    monkeypatch.setattr("maverick.config.get_features", lambda: {"scheduling": False})
    assert schedule_runner.start() is False


def test_tasks_sent_to_separate_workers_leave_the_queue_to_them(home, monkeypatch):
    from maverick import runner

    monkeypatch.setattr(runner, "get_dispatcher", lambda: SimpleNamespace(submit=lambda *a, **k: None))
    assert schedule_runner.start() is False
