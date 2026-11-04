"""Per-goal ownership (schema v11) -- the foundation for multi-user dashboard
authz. The world model stores + filters by an owner principal; the access
*policy* (owner match / admin / legacy) lives in the dashboard layer.
"""
from __future__ import annotations

import concurrent.futures
import sqlite3
import threading
from contextlib import contextmanager

import pytest
from maverick.world_model import SCHEMA_VERSION, WorldModel


def test_schema_version_is_current(tmp_path):
    assert SCHEMA_VERSION == 51  # bump when adding a migration
    assert WorldModel(tmp_path / "w.db").schema_version == SCHEMA_VERSION


def test_create_goal_stores_owner(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal(
        "t",
        owner="user:alice",
        execution_principal="agent:worker",
    )
    assert w.get_goal(gid).owner == "user:alice"
    assert w.get_goal(gid).execution_principal == "agent:worker"


def test_goal_domain_roundtrip(tmp_path):
    # v14: department attribution. Unset stays '', set persists, and
    # set_goal_domain records the department a run executed as.
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("t")
    assert w.get_goal(gid).domain == ""
    gid2 = w.create_goal("t2", domain="finance_sox")
    assert w.get_goal(gid2).domain == "finance_sox"
    w.set_goal_domain(gid, "gtm_sales_eng")
    assert w.get_goal(gid).domain == "gtm_sales_eng"


def test_default_owner_is_empty(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    assert w.get_goal(w.create_goal("t")).owner == ""


def test_goal_execution_binding_is_durable_idempotent_and_mismatch_safe(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("t", owner="user:human-owner")
    principal = "user:auth0|tenant/María 李"

    assert w.bind_goal_execution_principal(gid, principal) is True
    assert w.bind_goal_execution_principal(gid, principal) is True
    assert w.bind_goal_execution_principal(gid, "user:different") is False
    assert w.get_goal(gid).execution_principal == principal
    assert w.get_goal(gid).owner == "user:human-owner"


@pytest.mark.parametrize("principal", [" padded", "line\nbreak", "x" * 513, 7])
def test_goal_execution_principal_validation_is_at_the_store_boundary(
    tmp_path,
    principal,
):
    world = WorldModel(tmp_path / "w.db")
    goal_id = world.create_goal("unbound")

    with pytest.raises(ValueError, match="invalid execution principal"):
        world.bind_goal_execution_principal(goal_id, principal)
    with pytest.raises(ValueError, match="invalid execution principal"):
        world.create_goal("invalid", execution_principal=principal)

    assert world.get_goal(goal_id).execution_principal == ""


def test_blank_execution_principal_remains_the_legacy_unbound_default(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    goal_id = world.create_goal("unbound", execution_principal="")

    assert world.get_goal(goal_id).execution_principal == ""
    with pytest.raises(ValueError, match="invalid execution principal"):
        world.bind_goal_execution_principal(goal_id, "")


def test_concurrent_goal_execution_binding_has_one_winner(tmp_path):
    db = tmp_path / "w.db"
    first = WorldModel(db)
    second = WorldModel(db)
    gid = first.create_goal("t")
    barrier = threading.Barrier(2)

    def bind(world, principal):
        barrier.wait(timeout=5)
        return principal, world.bind_goal_execution_principal(gid, principal)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(
            lambda pair: bind(*pair),
            ((first, "user:first"), (second, "user:second")),
        ))

    assert sum(int(ok) for _principal, ok in outcomes) == 1
    winner = next(principal for principal, ok in outcomes if ok)
    assert first.get_goal(gid).execution_principal == winner


def test_explicit_goal_selectors_preserve_both_principal_fields(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    root = world.create_goal("root")
    child = world.create_goal(
        "needle child",
        parent_id=root,
        owner="user:human-owner",
        execution_principal="agent:worker",
    )
    world.set_goal_status(child, "done", result="needle result")

    selected = [
        world.search_goals("needle")[0],
        next(goal for goal in world.candidate_goals(False, owner="user:human-owner") if goal.id == child),
        world.subgoals(root)[0],
    ]

    assert all(goal.owner == "user:human-owner" for goal in selected)
    assert all(goal.execution_principal == "agent:worker" for goal in selected)


def test_list_goals_owner_filter(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    a = w.create_goal("a", owner="user:alice")
    b = w.create_goal("b", owner="user:bob")
    u = w.create_goal("u")  # legacy / unowned
    assert {g.id for g in w.list_goals(owner="user:alice")} == {a}
    assert {g.id for g in w.list_goals(owner="")} == {u}        # unowned only
    assert {g.id for g in w.list_goals()} == {a, b, u}          # None = all
    # owner + status compose
    w.set_goal_status(a, "done")
    assert {g.id for g in w.list_goals(status="done", owner="user:alice")} == {a}
    assert w.list_goals(status="done", owner="user:bob") == []


def test_signoff_record_and_read(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    assert w.signoff_for(gid) is None                      # unreviewed
    w.set_goal_status(gid, "done", result="draft")
    w.record_signoff(gid, "approved", decided_by="user:alice", note="ties out")
    s = w.signoff_for(gid)
    assert s["decision"] == "approved"
    assert s["decided_by"] == "user:alice"
    assert s["note"] == "ties out"                          # note round-trips (encrypted)


def test_signoff_latest_decision_wins(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="draft")
    assert w.record_signoff(
        gid, "rejected", decided_by="user:bob", note="rework week 3",
    ) is True
    assert w.record_signoff(gid, "rejected", decided_by="user:bob") is False
    assert w.record_signoff(
        gid, "approved", decided_by="user:alice",
    ) is True  # supersedes
    s = w.signoff_for(gid)
    assert s["decision"] == "approved" and s["decided_by"] == "user:alice"
    assert s["note"] is None                                # the new decision's (empty) note


def test_concurrent_identical_signoff_has_one_authoritative_transition(tmp_path):
    db = tmp_path / "w.db"
    first = WorldModel(db)
    second = WorldModel(db)
    gid = first.create_goal("forecast", domain="finance_cash13w")
    first.set_goal_status(gid, "done", result="draft")
    version = first.get_goal(gid).updated_at
    barrier = threading.Barrier(2)

    def approve(world):
        barrier.wait(timeout=5)
        return world.record_signoff(
            gid,
            "approved",
            decided_by="user:alice",
            expected_updated_at=version,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        changed = list(pool.map(approve, (first, second)))

    assert sorted(changed) == [False, True]
    assert first.signoff_for(gid)["decision"] == "approved"


def test_signoffs_for_goals_batch(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    a = w.create_goal("a", domain="finance_cash13w")
    b = w.create_goal("b", domain="finance_cash13w")
    c = w.create_goal("c", domain="finance_cash13w")  # unreviewed
    for gid in (a, b, c):
        w.set_goal_status(gid, "done", result=f"draft-{gid}")
    w.record_signoff(a, "approved")
    w.record_signoff(b, "rejected")
    assert w.signoffs_for_goals([a, b, c]) == {a: "approved", b: "rejected"}
    assert w.signoffs_for_goals([]) == {}


def test_signoff_requires_finished_immutable_payload(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    with pytest.raises(ValueError, match="not finished"):
        w.record_signoff(gid, "approved")

    w.set_goal_status(gid, "done", result="v1")
    reviewed = w.get_goal(gid)
    w.record_signoff(
        gid,
        "approved",
        expected_updated_at=reviewed.updated_at,
    )
    assert w.signoff_for(gid)["decision"] == "approved"

    # A result rewrite invalidates approval, and a stale reviewer version can
    # no longer land a decision over the replacement bytes.
    w.set_goal_status(gid, "done", result="v2")
    assert w.signoff_for(gid) is None
    with pytest.raises(ValueError, match="changed"):
        w.record_signoff(
            gid,
            "approved",
            expected_updated_at=reviewed.updated_at,
        )


def test_new_artifact_version_invalidates_signoff(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="draft")
    reviewed = w.get_goal(gid)
    w.record_signoff(gid, "approved")

    w.add_artifact(gid, "table", "Forecast", "v1")

    assert w.signoff_for(gid) is None
    with pytest.raises(ValueError, match="changed"):
        w.record_signoff(
            gid,
            "approved",
            expected_updated_at=reviewed.updated_at,
        )


@pytest.mark.parametrize("mutation", ["result", "artifact"])
@pytest.mark.parametrize("clock_delta", [0.0, -60.0])
def test_stalled_or_backwards_clock_cannot_reapprove_replaced_payload(
    tmp_path, monkeypatch, mutation, clock_delta,
):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="reviewed version")
    reviewed = w.get_goal(gid)
    w.record_signoff(gid, "approved", expected_updated_at=reviewed.updated_at)
    monkeypatch.setattr("maverick.world_model.time.time", lambda: reviewed.updated_at + clock_delta)

    if mutation == "result":
        w.set_goal_status(gid, "done", result="replacement version")
    else:
        w.add_artifact(gid, "table", "Forecast", "new unreviewed attachment")

    assert w.get_goal(gid).updated_at > reviewed.updated_at
    assert w.signoff_for(gid) is None
    # Other metadata writes must not reset the version to the old clock value.
    w.set_goal_title(gid, "Updated forecast title")
    w.set_goal_parent(gid, None)
    w.set_goal_project(gid, None)
    with pytest.raises(ValueError, match="changed"):
        w.record_signoff(gid, "approved", expected_updated_at=reviewed.updated_at)
    current = w.get_goal(gid)
    assert w.record_signoff(gid, "approved", expected_updated_at=current.updated_at)


def test_concurrent_payload_writers_get_distinct_review_versions_on_one_clock_tick(tmp_path, monkeypatch):
    db = tmp_path / "w.db"
    first, second = WorldModel(db), WorldModel(db)
    gid = first.create_goal("forecast", domain="finance_cash13w")
    first.set_goal_status(gid, "done", result="initial")
    initial = first.get_goal(gid).updated_at
    monkeypatch.setattr("maverick.world_model.time.time", lambda: initial)
    barrier = threading.Barrier(2)

    def change(world):
        barrier.wait(timeout=5)
        world.set_goal_status(gid, "done", result="replacement")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(change, (first, second)))
    # Both DB-authoritative updates must advance the version, not read the
    # same value then overwrite one another with a duplicate version.
    assert first.get_goal(gid).updated_at >= initial + 0.0000015


@pytest.mark.parametrize("mutation", ["result", "artifact"])
@pytest.mark.parametrize("clock_delta", [0.0, -60.0])
def test_postgres_payload_version_contract_on_stalled_clock(tmp_path, monkeypatch, mutation, clock_delta):
    """Execute Postgres mutator SQL through a local dialect shim, without a DSN.

    This covers UPDATE/version binding compatibility, not live Postgres locking
    or advisory locks; the real backend suite still requires MAVERICK_PG_DSN.
    """
    from maverick.world_model_backends import postgres

    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("forecast", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result="reviewed version")
    reviewed = w.get_goal(gid)
    w.record_signoff(gid, "approved", expected_updated_at=reviewed.updated_at)
    monkeypatch.setattr(postgres.time, "time", lambda: reviewed.updated_at + clock_delta)
    monkeypatch.setattr(postgres, "_tenant_scope", lambda: ("", []))
    # This SQLite dialect shim has no tenant_id column; production mutations
    # still use the exact-tenant predicate rather than the read predicate.
    monkeypatch.setattr(postgres, "_mutation_tenant_scope", lambda column="tenant_id": ("", []))

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def execute(self, sql, params):
            if "pg_advisory_xact_lock" not in sql:
                self.cursor.execute(sql.replace("GREATEST(", "MAX(").replace("%s", "?"), params)

        @property
        def rowcount(self):
            return self.cursor.rowcount

        def fetchone(self):
            return self.cursor.fetchone()

    @contextmanager
    def transaction():
        with w._writing() as connection:
            yield Cursor(connection.cursor())

    pg = postgres.PostgresWorldModel.__new__(postgres.PostgresWorldModel)
    monkeypatch.setattr(pg, "_tx", transaction)
    if mutation == "result":
        pg.set_goal_status(gid, "done", result="unreviewed replacement")
    else:
        pg.add_artifact(gid, "table", "Forecast", "unreviewed attachment")
    assert w.get_goal(gid).updated_at > reviewed.updated_at
    assert w.signoff_for(gid) is None
    pg.set_goal_title(gid, "Updated forecast")
    pg.set_goal_parent(gid, None)
    pg.set_goal_project(gid, None)
    with pytest.raises(ValueError, match="changed"):
        w.record_signoff(gid, "approved", expected_updated_at=reviewed.updated_at)


def test_artifact_versioning_and_latest(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("forecast", domain="finance_cash13w")
    w.add_artifact(g, "table", "Cash forecast", "| W | Net |\n| - | - |\n| 1 | 300 |")
    w.add_artifact(g, "table", "Cash forecast", "| W | Net |\n| - | - |\n| 1 | 350 |")  # v2
    w.add_artifact(g, "markdown", "Memo", "# Memo\nUp 50.")
    # all versions retained, ordered by title then version
    allv = [(a["title"], a["version"]) for a in w.artifacts_for_goal(g)]
    assert allv == [("Cash forecast", 1), ("Cash forecast", 2), ("Memo", 1)]
    # latest = newest version per title, with a count + decrypted content
    latest = {a["title"]: a for a in w.latest_artifacts(g)}
    assert latest["Cash forecast"]["version"] == 2
    assert latest["Cash forecast"]["versions"] == 2
    assert "350" in latest["Cash forecast"]["content"]   # content round-trips (encrypted)
    assert latest["Memo"]["kind"] == "markdown" and latest["Memo"]["versions"] == 1


def test_artifacts_absent_is_empty(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("plain")
    assert w.artifacts_for_goal(g) == []
    assert w.latest_artifacts(g) == []


def test_list_goals_domain_filter(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    f1 = w.create_goal("forecast", domain="finance_cash13w")
    f2 = w.create_goal("forecast 2", domain="finance_cash13w")
    other = w.create_goal("other", domain="bank_cecl_allowance")
    generic = w.create_goal("generic")  # no domain
    assert {g.id for g in w.list_goals(domain="finance_cash13w")} == {f1, f2}
    assert {g.id for g in w.list_goals(domain="bank_cecl_allowance")} == {other}
    assert {g.id for g in w.list_goals(domain="")} == {generic}  # unattributed only
    # domain + owner compose
    w.set_goal_domain(f1, "finance_cash13w")  # idempotent; keep attribution
    assert {g.id for g in w.list_goals(domain="finance_cash13w", limit=1, order="desc")} == {f2}


def test_migration_adds_owner_to_a_v10_db(tmp_path):
    # A real pre-owner (v10) DB: goals table without `owner`, version pinned 10.
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE goals(
            id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER,
            title TEXT NOT NULL, description TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL, updated_at REAL NOT NULL,
            deadline REAL, result TEXT);
        CREATE TABLE schema_version(version INTEGER);
        INSERT INTO schema_version(version) VALUES(10);
        INSERT INTO goals(title, status, created_at, updated_at)
            VALUES('legacy', 'done', 0, 0);
        """
    )
    conn.commit()
    conn.close()

    w = WorldModel(db)  # opening runs the v11 (owner) migration and any later
    assert w.schema_version == SCHEMA_VERSION
    legacy = w.get_goal(1)
    assert legacy is not None and legacy.owner == ""   # migrated default
    assert legacy.execution_principal == ""
    gid = w.create_goal("new", owner="user:x")
    assert w.get_goal(gid).owner == "user:x"
