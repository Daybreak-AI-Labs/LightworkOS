"""Clock-independent force reclaim without changing positive-age protection."""
from contextlib import contextmanager

import pytest
from maverick.world_model import WorldModel


@pytest.fixture(params=["sqlite", "postgres"])
def reclaim_world(request, tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_ORPHAN_RECLAIM_SECONDS", raising=False)
    world = WorldModel(tmp_path / "world.db")
    if request.param == "sqlite":
        yield world, world, None
        world.close()
        return

    # Execute real Postgres reclaim SQL against a local dialect shim. This
    # checks predicates/parameters and encryption branches, not live PG locks.
    from maverick.world_model_backends import postgres

    outside_scope = world.create_goal("outside tenant scope", "")
    monkeypatch.setattr(postgres, "_tenant_scope", lambda: ("id != %s", [outside_scope]))
    monkeypatch.setattr(postgres, "_mutation_tenant_scope", lambda: ("id != %s", [outside_scope]))

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def execute(self, sql, params):
            self.cursor.execute(sql.replace("GREATEST(", "MAX(").replace("%s", "?"), params)

        @property
        def rowcount(self):
            return self.cursor.rowcount

        def fetchall(self):
            return self.cursor.fetchall()

    @contextmanager
    def transaction():
        with world._writing() as connection:
            yield Cursor(connection.cursor())

    pg = postgres.PostgresWorldModel.__new__(postgres.PostgresWorldModel)
    monkeypatch.setattr(pg, "_tx", transaction)
    yield world, pg, outside_scope
    world.close()


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("clock_delta", [0.0, -60.0])
def test_zero_age_reclaims_logical_future_versions(
    reclaim_world, monkeypatch, encrypted, clock_delta,
):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    monkeypatch.setattr("maverick.world_model.time.time", lambda: 1_000_000.0)
    world, reclaimer, outside_scope = reclaim_world
    active = world.create_goal("active", "")
    pending = world.create_goal("pending", "")
    done = world.create_goal("finished", "")
    world.set_goal_status(active, "active", result="partial")
    world.set_goal_status(pending, "pending")
    world.set_goal_status(done, "done", result="complete")
    version = world.get_goal(active).updated_at
    monkeypatch.setattr("maverick.world_model.time.time", lambda: 1_000_000.0 + clock_delta)
    assert version > 1_000_000.0 + clock_delta

    # Positive timeouts still protect fresh/future-version sibling goals.
    assert reclaimer.reclaim_orphan_goals(max_age_seconds=1) == 0
    assert world.get_goal(active).updated_at == version
    assert reclaimer.reclaim_orphan_goals(max_age_seconds=0) == 2
    assert world.get_goal(active).status == "blocked"
    assert world.get_goal(active).updated_at > version
    assert world.get_goal(active).result == "partial [process restarted mid-run]"
    assert world.get_goal(pending).status == "blocked"
    assert world.get_goal(done).status == "done"
    if outside_scope is not None:
        assert world.get_goal(outside_scope).status == "pending"


@pytest.mark.parametrize("encrypted", [False, True])
def test_positive_age_waits_until_logical_version_reaches_cutoff(reclaim_world, monkeypatch, encrypted):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    monkeypatch.setattr("maverick.world_model.time.time", lambda: 1_000_000.0)
    world, reclaimer, _ = reclaim_world
    gid = world.create_goal("live sibling", "")
    world.set_goal_status(gid, "active")
    version = world.get_goal(gid).updated_at
    monkeypatch.setattr("maverick.world_model.time.time", lambda: version + 59.0)
    assert reclaimer.reclaim_orphan_goals(max_age_seconds=60) == 0
    monkeypatch.setattr("maverick.world_model.time.time", lambda: version + 60.0)
    assert reclaimer.reclaim_orphan_goals(max_age_seconds=60) == 1
    assert world.get_goal(gid).status == "blocked"
