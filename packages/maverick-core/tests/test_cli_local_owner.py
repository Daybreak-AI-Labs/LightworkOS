"""Tasks started from the command line belong to the installation's owner.

`lightwork start` (the README's first command) created goals with no owner.
Once the owner set up named sign-in, the dashboard hid those goals from them
(404), so command-line work was invisible in the dashboard.
"""
from __future__ import annotations

import json

import pytest
from maverick.cli import _local_owner


def _claim(home, **row):
    claim = {"schema": "lightwork.local-owner.v1", "status": "ready", "email": "owner@lightwork.test",
             "salt": "0" * 32, "password_hash": "0" * 64, "failures": 0, "locked_until": 0, "created_at": 0}
    claim.update(row)
    (home / "dashboard-owner.json").write_text(json.dumps(claim), encoding="utf-8")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    return tmp_path


def test_the_owner_owns_command_line_tasks(home):
    _claim(home)
    assert _local_owner.goal_owner() == "user:owner@lightwork.test"


@pytest.mark.parametrize("row", [{"status": "pending"}, {"schema": "other"}, {"email": "no-at-sign"},
                                 {"email": 7}])
def test_an_unfinished_or_malformed_claim_names_no_owner(home, row):
    _claim(home, **row)
    assert _local_owner.goal_owner() == ""


def test_without_an_owner_tasks_stay_ownerless(home):
    assert _local_owner.goal_owner() == ""


def test_lightwork_start_records_the_owner(home, monkeypatch):
    from click.testing import CliRunner
    from maverick import cli
    from maverick.world_model import WorldModel

    _claim(home)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-used")  # passes preflight; no call is made
    db = home / "world.db"
    created = []
    real_create = WorldModel.create_goal

    def recording(self, *args, **kwargs):
        goal_id = real_create(self, *args, **kwargs)
        created.append(self.get_goal(goal_id).owner)
        raise SystemExit(0)  # stop before any model is called

    monkeypatch.setattr(WorldModel, "create_goal", recording)
    CliRunner().invoke(cli.main, ["--db", str(db), "start", "Reply with exactly: CLI OK", "--max-dollars", "0.1"])
    assert created == ["user:owner@lightwork.test"]


def test_the_worker_drains_the_owner_workspace_queue(home, monkeypatch):
    # `schedule add` and the dashboard write the owner's workspace queue, but
    # the worker never adopted that workspace, so it drained the root queue.
    from click.testing import CliRunner
    from maverick import cli, worker
    from maverick.paths import current_tenant_id

    monkeypatch.setattr("maverick.tenant.registry.owner_workspace_id", lambda: "local")
    seen = []

    class FakeWorker:
        def __init__(self, *a, **k):
            seen.append(current_tenant_id())
            self.queue = type("Q", (), {"db_path": "x"})()

        def run_until_empty(self, *a, **k):
            return 0

        def run_forever(self):
            return None

    monkeypatch.setattr(worker, "Worker", FakeWorker)
    CliRunner().invoke(cli.main, ["--db", str(home / "world.db"), "worker", "--once"])
    assert seen == ["local"]
