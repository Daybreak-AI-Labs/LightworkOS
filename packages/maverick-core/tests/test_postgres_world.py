"""PostgresWorldModel round-trip — runs only when MAVERICK_PG_DSN is set.

Skipped locally and in the normal test matrix (no Postgres available); the
dedicated CI ``postgres`` job stands up a Postgres service + DSN and runs this.
It's the first DB-backed test for the Postgres backend and the harness future
method-parity work can extend (so parity is testable, not shipped blind).
"""
from __future__ import annotations

import importlib.util
import os
import uuid
from types import SimpleNamespace

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = [pytest.mark.usefixtures("postgres_test_dsn"), pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)]


@pytest.fixture
def world():
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    try:
        yield w
    finally:
        w.close()


def test_signoff_for_is_scoped_to_the_active_tenant(world):
    from maverick.paths import tenant_scope

    tenant = "signoff-" + uuid.uuid4().hex
    other = tenant + "-other"
    try:
        with tenant_scope(tenant=tenant):
            gid = world.create_goal("reviewed goal")
            world.set_goal_status(gid, "done", result="ok")
            assert world.record_signoff(gid, "approved", decided_by="rev")
            assert world.signoff_for(gid)["decision"] == "approved"
        with tenant_scope(tenant=other):
            assert world.signoff_for(gid) is None
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM signoffs WHERE goal_id IN "
                           "(SELECT id FROM goals WHERE tenant_id=%s)", (tenant,))
            cursor.execute("DELETE FROM goals WHERE tenant_id=%s", (tenant,))


@pytest.mark.parametrize("encrypted", [False, True])
def test_goal_search_enforces_owner_and_preserves_project_metadata(world, monkeypatch, encrypted):
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    marker = "owner-search-" + uuid.uuid4().hex
    with tenant_scope(tenant=marker):
        try:
            project = world.create_project("project", owner="user:alice", domain="finance")
            alice = world.create_goal(marker, owner="user:alice", domain="finance", project_id=project)
            bob = world.create_goal(marker, owner="user:bob")
            anonymous = world.create_goal(marker)
            assert [goal.id for goal in world.search_goals(marker, owner="user:alice")] == [alice]
            assert [goal.id for goal in world.search_goals(marker, owner="user:bob")] == [bob]
            assert [goal.id for goal in world.search_goals(marker, owner="")] == [anonymous]
            assert {goal.id for goal in world.search_goals(marker)} == {alice, bob, anonymous}
            reads = [world.get_goal(alice), *world.search_goals(marker, owner="user:alice"),
                     *world.list_goals(owner="user:alice", domain="finance", project_id=project)]
            assert len(reads) == 3
            assert all(goal.domain == "finance" and goal.project_id == project for goal in reads)
        finally:
            # The service is shared by this test module; later encryption tests
            # deliberately use different keys. Remove only this unique fixture
            # tenant's rows so their unscoped scans never encounter our key.
            with world._tx() as cursor:
                cursor.execute("DELETE FROM goals WHERE tenant_id=%s", (marker,))
                cursor.execute("DELETE FROM projects WHERE tenant_id=%s", (marker,))


def test_shared_goal_lookup_batch_preserves_tenant_scope(world):
    from maverick.paths import tenant_scope
    from maverick.world_model import goals_by_id

    tenant = "lookup-" + uuid.uuid4().hex
    other = tenant + "-other"
    try:
        with tenant_scope(tenant=tenant):
            own = world.create_goal("own goal")
        with tenant_scope(tenant=other):
            foreign = world.create_goal("foreign goal")
        with tenant_scope(tenant=tenant):
            found = goals_by_id(world, [own, foreign, own])
            assert set(found) == {own}
            assert found[own].title == "own goal"
            assert goals_by_id(world, []) == {}
        with tenant_scope(tenant=other):
            assert set(goals_by_id(world, [own, foreign])) == {foreign}
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM goals WHERE tenant_id IN (%s, %s)", (tenant, other))


@pytest.mark.parametrize("encrypted", [False, True])
def test_goal_batch_limits_queries_and_preserves_encryption(world, monkeypatch, encrypted):
    from unittest.mock import patch

    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    tenant = "lookup-batch-" + uuid.uuid4().hex
    try:
        with tenant_scope(tenant=tenant):
            own = world.create_goal("batch title", description="private description")
            # IDs below zero cannot overlap the serial-generated goal IDs.
            requested = [own, own, *range(-1000, 0)]
            with patch.object(world, "_tx", wraps=world._tx) as transaction:
                result = world.get_goals(requested)
            assert transaction.call_count == 1
            assert set(result) == {own}
            assert result[own].title == "batch title"
            assert result[own].description == "private description"
            assert world.get_goals([]) == {}
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM goals WHERE tenant_id=%s", (tenant,))


def test_shoring_completion_and_approval_context_are_tenant_scoped(world, monkeypatch):
    from maverick.logging_config import _goal_id_var, reset_goal_context, set_goal_context
    from maverick.paths import tenant_scope
    from maverick.world_model_backends import postgres

    marker = "shoring-" + uuid.uuid4().hex
    other = marker + "-other"
    clock = [1_800_000_000.0]
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: clock[0]))
    try:
        with tenant_scope(tenant=marker):
            goal = world.create_goal("Invoice", domain="finance_ap")
            clock[0] += 3600
            world.set_goal_status(goal, "done", result="Paid")
            clock[0] += 3600
            world.set_goal_status(goal, "done", result="Payment checked")
            metrics = world.shoring_measurements("finance_ap", since=0, until=clock[0])
            assert metrics["delivered"] == 1 and metrics["max_turnaround_hours"] == 1
            with world._tx() as cursor:
                cursor.execute("UPDATE goals SET completed_at=NULL WHERE id=%s AND tenant_id=%s", (goal, marker))
            clock[0] += 3600
            world.set_goal_status(goal, "done", result="Legacy deliverable edited")
            metrics = world.shoring_measurements("finance_ap", since=0, until=clock[0] + 1)
            assert metrics["delivered"] == 1 and metrics["legacy_completion_count"] == 1
            assert metrics["max_turnaround_hours"] is None
            tokens = set_goal_context(goal_id=goal)
            try:
                approval = world.create_approval("payment", detail="support")
                with tenant_scope(tenant=other):
                    with pytest.raises(ValueError, match="approval goal is unavailable"):
                        world.create_approval("finance_ap", scope="finance_ap")
            finally:
                reset_goal_context(tokens)
            with tenant_scope(tenant=other):
                no_goal = _goal_id_var.set(None)
                try:
                    foreign = world.create_approval("finance_ap", scope="finance_ap")
                    assert world.get_approval(foreign).department == ""
                    assert world.shoring_measurements("finance_ap", since=0, until=clock[0])["delivered"] == 0
                finally:
                    _goal_id_var.reset(no_goal)
            records = [world.get_approval(approval), *world.pending_approvals(), *world.list_approvals()]
            assert all(row.department == "finance_ap" and row.goal_id == goal for row in records)
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM approvals WHERE tenant_id IN (%s, %s)", (marker, other))
            cursor.execute("DELETE FROM goals WHERE tenant_id IN (%s, %s)", (marker, other))


def test_connection_timeouts_and_operator_options_survive_real_reconnect(monkeypatch):
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv("MAVERICK_PG_IDLE_TX_TIMEOUT_MS", "60000")
    dsn = make_conninfo(_DSN, options="-c statement_timeout=12345 -c application_name=lightwork-test")
    with PostgresWorldModel(dsn) as database:
        for reconnect in (False, True):
            if reconnect:
                database.conn.close()
            with database._tx() as cursor:
                cursor.execute("SELECT current_setting('statement_timeout'), "
                               "current_setting('idle_in_transaction_session_timeout'), "
                               "current_setting('application_name')")
                assert cursor.fetchone() == ("12345ms", "1min", "lightwork-test")


def test_provider_admission_is_atomic_across_shared_connections(monkeypatch):
    """Real PostgreSQL CI service; distinct connections race one provider period."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, local

    from maverick import provider_cost_cap as cap
    from maverick.world_model_backends.postgres import PostgresWorldModel

    provider = "acceptance-" + uuid.uuid4().hex
    worlds = [PostgresWorldModel(dsn=_DSN) for _ in range(2)]
    current = local()
    barrier = Barrier(2)
    monkeypatch.setattr(cap, "caps_from_config", lambda: {provider: 20.0})
    monkeypatch.setattr(cap, "period_from_config", lambda: "day")
    monkeypatch.setattr(cap, "_shared_world", lambda: current.world)
    worlds[0].add_provider_spend(worlds[0].provider_cap_period("day"), provider, 18)

    def admit(index):
        current.world = worlds[index]
        barrier.wait(timeout=5)
        try:
            return cap.reserve(provider, 2, now=0, request_id=f"attempt-{index}")
        except cap.ProviderCapExceeded:
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            holds = [item for item in pool.map(admit, range(2)) if item is not None]
        assert len(holds) == 1
        cap.settle(holds[0], 1)
        cap.settle(holds[0], 1)
        current.world = worlds[1]
        assert cap.check(provider, now=0).spent == 19
        assert cap.check(provider, now=0).reserved == 0
    finally:
        for database in worlds:
            database.close()


def test_provider_operation_attempt_is_global_across_shared_connections(monkeypatch):
    """Two providers cannot each admit the same tenant/work operation attempt."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, local

    from maverick import provider_cost_cap as cap
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    suffix = uuid.uuid4().hex
    providers = [f"attempt-openai-{suffix}", f"attempt-anthropic-{suffix}"]
    operation_id = f"shared-operation-{suffix}"
    worlds = [PostgresWorldModel(dsn=_DSN) for _ in range(2)]
    current = local()
    barrier = Barrier(2)
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "period_from_config", lambda: "day")
    monkeypatch.setattr(cap, "_shared_world", lambda: current.world)

    def admit(index):
        current.world = worlds[index]
        barrier.wait(timeout=5)
        try:
            with tenant_scope(tenant="postgres-attempt-race"), cap.work_item_scope(
                f"goal:{suffix}"
            ):
                return cap.reserve(
                    providers[index],
                    1,
                    request_id=f"attempt-{suffix}-{index}",
                    operation_id=operation_id,
                    category="inference",
                    attempt_no=1,
                )
        except cap.ProviderAttemptAlreadyAdmitted:
            return None

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            holds = [item for item in pool.map(admit, range(2)) if item is not None]
        assert len(holds) == 1
        cap.settle(holds[0], 1)
    finally:
        for database in worlds:
            database.close()


def test_goal_lifecycle(world):
    gid = world.create_goal("build the thing", description="desc")
    assert isinstance(gid, int)

    g = world.get_goal(gid)
    assert g is not None
    assert g.title == "build the thing"
    assert g.description == "desc"
    assert g.status == "pending"

    # A pending goal is "open" -> appears in the active list; resolving it drops it.
    assert any(x.id == gid for x in world.list_active_goals())
    world.set_goal_status(gid, "done", result="shipped")
    g2 = world.get_goal(gid)
    assert g2.status == "done"
    assert g2.result == "shipped"
    assert not any(x.id == gid for x in world.list_active_goals())


def test_status_only_update_preserves_result(world):
    # COALESCE(%s, result): a later status-only update (result=None) must not
    # wipe an existing result.
    gid = world.create_goal("g")
    world.set_goal_status(gid, "running", result="partial")
    world.set_goal_status(gid, "done")
    assert world.get_goal(gid).result == "partial"


def test_goal_execution_claim_is_atomic(world):
    gid = world.create_goal("claim exactly once")

    assert world.claim_goal_for_run(gid) is True
    assert world.get_goal(gid).status == "active"
    assert world.claim_goal_for_run(gid) is False


def test_legacy_event_goal_is_held_at_both_postgres_start_boundaries(world):
    from maverick.event_admission import LegacyEventGoalHeld

    local = world.create_goal("old local")
    world.record_goal_origin(local, "event", "orders")
    with pytest.raises(LegacyEventGoalHeld):
        world.set_goal_status(local, "active")
    assert world.get_goal(local).status == "blocked"

    remote = world.create_goal("old remote", owner="user:alice")
    world.record_goal_origin(remote, "event", "orders")
    assert not world.claim_goal_for_run(remote, expected_owner="user:bob")
    assert world.get_goal(remote).status == "pending"
    assert not world.claim_goal_for_run(remote, expected_owner="user:alice")
    assert world.get_goal(remote).status == "blocked"

    current = world.create_goal("missing current receipt")
    world.record_goal_origin(current, "event_v2", "orders")
    assert not world.claim_goal_for_run(current)
    assert world.get_goal(current).status == "blocked"


@pytest.mark.parametrize("status", ["pending", "active", "running", "blocked", "done", "cancelled"])
def test_admission_refusal_preserves_terminal_results_and_tenant_authority(world, status):
    from maverick.paths import tenant_scope

    tenant = "admission-" + uuid.uuid4().hex
    with tenant_scope(tenant=tenant):
        gid = world.create_goal("allowance admission")
        world.set_goal_status(gid, "done", result="original")
        world.record_signoff(gid, "approved")
        # Include repair of an existing stale sign-off on a non-terminal row.
        with world._tx() as cursor:
            cursor.execute("UPDATE goals SET status=%s WHERE id=%s", (status, gid))
        before = world.get_goal(gid)
    with tenant_scope(tenant=tenant + "-other"):
        assert world.block_goal_admission(gid, result="wrong tenant") is False
    with tenant_scope(tenant=tenant):
        eligible = status not in {"done", "cancelled"}
        assert world.block_goal_admission(gid, result="allowance refused") is eligible
        after = world.get_goal(gid)
        if eligible:
            assert after.status == "blocked" and after.result == "allowance refused"
            assert after.updated_at > before.updated_at
            with world._tx() as cursor:
                cursor.execute("SELECT completed_at FROM goals WHERE id=%s", (gid,))
                assert cursor.fetchone()[0] is None
            assert world.signoff_for(gid) is None
        else:
            assert after == before
            assert world.signoff_for(gid)["decision"] == "approved"


def test_goal_execution_claim_honors_expected_owner(world):
    gid = world.create_goal("owner-scoped claim", owner="agent:alice")

    assert world.claim_goal_for_run(gid, expected_owner="agent:bob") is False
    assert world.get_goal(gid).status == "pending"
    assert world.claim_goal_for_run(gid, expected_owner="agent:alice") is True
    assert world.get_goal(gid).status == "active"


def test_goal_execution_principal_binding_is_mismatch_safe(world):
    gid = world.create_goal("bind execution principal", owner="user:human-owner")
    principal = "user:auth0|tenant/María 李"

    assert world.bind_goal_execution_principal(gid, principal) is True
    assert world.bind_goal_execution_principal(gid, principal) is True
    assert world.bind_goal_execution_principal(gid, "user:different") is False
    assert world.get_goal(gid).owner == "user:human-owner"
    assert world.get_goal(gid).execution_principal == principal


def test_get_missing_goal_returns_none(world):
    assert world.get_goal(999_999_999) is None


def test_episode_round_trip(world):
    # No episode-read method on the PG backend yet; the assertion is that the
    # insert + update commit without raising (and return a real id).
    gid = world.create_goal("episodic")
    eid = world.start_episode(gid)
    assert isinstance(eid, int)
    world.end_episode(
        eid, "did the thing", "success",
        cost_dollars=0.02, input_tokens=10, output_tokens=5, tool_calls=2,
    )


def test_events_round_trip(world):
    gid = world.create_goal("eventful")
    e1 = world.append_event(gid, "orch", "note", "hello")
    e2 = world.append_event(gid, "coder", "tool", "ran ls")
    assert e1 < e2

    events = world.goal_events(gid)
    assert [e.content for e in events] == ["hello", "ran ls"]  # id ASC

    # since_id filter excludes events at/below the cursor.
    after = world.goal_events(gid, since_id=e1)
    assert [e.content for e in after] == ["ran ls"]

    world.append_event(gid, "verifier", "decision", "accepted")
    recent = world.recent_goal_events(gid, limit=2)
    assert [e.content for e in recent] == ["ran ls", "accepted"]


def test_facts_upsert_overwrites(world):
    world.upsert_fact("pg:color", "blue")
    world.upsert_fact("pg:color", "green")  # ON CONFLICT(key) -> update
    assert world.get_facts().get("pg:color") == "green"


def test_facts_newest_write_order_survives_clock_rollback(
    world, monkeypatch,
):
    from maverick.world_model_backends import postgres

    prefix = f"pg:order:{uuid.uuid4().hex}:"
    key_a, key_b = prefix + "a", prefix + "b"
    times = iter((1_000.0, 1_001.0, 999.0))
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: next(times)))

    world.upsert_fact(key_a, "first")
    world.upsert_fact(key_b, "second")
    world.upsert_fact(key_a, "updated last")

    keys = list(world.get_facts())
    assert keys.index(key_a) < keys.index(key_b)
    assert len(world.list_facts(prefix, limit=10)) == 2


def test_facts_matching_is_prefix_scoped(world):
    world.upsert_fact("user:alice:email", "a@x.com")
    world.upsert_fact("user:alice:phone", "555")
    world.upsert_fact("user:bob:email", "b@x.com")
    world.upsert_fact("global:tz", "UTC")  # not user-scoped

    assert set(world.facts_matching("alice")) == {"user:alice:email", "user:alice:phone"}
    assert world.facts_matching("") == {}  # empty token matches nothing


def test_delete_facts_matching_scoped(world):
    world.upsert_fact("user:carol:email", "c@x.com")
    world.upsert_fact("user:carol:ssn", "secret")
    world.upsert_fact("user:dave:email", "d@x.com")

    deleted = world.delete_facts_matching("carol")
    assert deleted == ["user:carol:email", "user:carol:ssn"]  # sorted keys
    remaining = world.get_facts()
    assert "user:carol:email" not in remaining
    assert remaining.get("user:dave:email") == "d@x.com"  # other users untouched


def test_list_goals_filter_and_order(world):
    g1 = world.create_goal("first")
    g2 = world.create_goal("second")
    world.set_goal_status(g2, "done")

    done = world.list_goals(status="done")
    assert any(x.id == g2 for x in done)
    assert all(x.status == "done" for x in done)  # filter applied

    desc = world.list_goals(order="desc", limit=100)
    ids = [x.id for x in desc]
    assert ids.index(g2) < ids.index(g1)  # later id first in DESC order


def test_list_goals_filters_by_domain_and_project_id(world):
    # Parity with SQLite's list_goals(domain=..., project_id=...) --
    # the dashboard's project-detail page and domain-scoped inbox both call
    # these kwargs, which this backend previously rejected with a TypeError.
    pid = world.create_project("Q3 Migration")
    g_in_project = world.create_goal("member of the project")
    world.set_goal_project(g_in_project, pid)
    g_outside_project = world.create_goal("not in the project")

    g_finance = world.create_goal("finance domain goal")
    world.set_goal_domain(g_finance, "finance")
    g_no_domain = world.create_goal("no domain")

    by_project = world.list_goals(project_id=pid)
    assert {x.id for x in by_project} == {g_in_project}
    assert g_outside_project not in {x.id for x in by_project}

    by_domain = world.list_goals(domain="finance")
    assert g_finance in {x.id for x in by_domain}
    assert g_no_domain not in {x.id for x in by_domain}


def test_recent_goals_by_domain_matches_one_query_per_domain(world):
    # The Results page asks for every deliverable pack's latest runs at once;
    # one grouped query must give the answer the per-pack loop gave.
    tag = uuid.uuid4().hex[:8]
    busy, quiet, empty = f"busy_{tag}", f"quiet_{tag}", f"empty_{tag}"
    busy_ids = [
        world.create_goal(f"busy {i}", owner="user:alice" if i % 2 else "user:bob", domain=busy)
        for i in range(7)
    ]
    world.create_goal("quiet one", domain=quiet, owner="user:alice")
    domains = [busy, quiet, empty]

    got = world.recent_goals_by_domain(domains)
    assert [g.id for g in got[busy]] == busy_ids[::-1][:5]
    assert [g.title for g in got[quiet]] == ["quiet one"]
    assert empty not in got
    for owner in (None, "user:alice", "user:bob", "user:nobody"):
        looped = {d: world.list_goals(domain=d, owner=owner, limit=5, order="desc") for d in domains}
        assert world.recent_goals_by_domain(domains, owner=owner) == {
            d: goals for d, goals in looped.items() if goals
        }
    assert world.recent_goals_by_domain([]) == {}


def test_active_goal(world):
    gid = world.create_goal("to-activate")
    world.set_goal_status(gid, "active")
    a = world.active_goal()
    assert a is not None
    assert a.status in ("active", "blocked")


def test_list_episodes_and_total_spend(world):
    gid = world.create_goal("spendy")
    eid = world.start_episode(gid)
    world.end_episode(
        eid, "s", "success",
        cost_dollars=1.5, input_tokens=100, output_tokens=50, tool_calls=3,
    )
    eps = world.list_episodes(goal_id=gid)
    assert any(x.id == eid and x.cost_dollars == 1.5 for x in eps)

    totals = world.total_spend()
    assert totals["dollars"] >= 1.5   # this run's ended episode counts
    assert totals["runs"] >= 1


def test_total_spend_accepts_owner_kwarg(world):
    """total_spend(owner=...) used to
    raise TypeError on this backend -- it took no owner argument at all,
    while the SQLite backend (and /api/v1/spend, external-agent spend
    records) call it with one."""
    token = uuid.uuid4().hex
    alice = f"user:spend-alice:{token}"
    bob = f"user:spend-bob:{token}"

    alice_gid = world.create_goal("alice spend", owner=alice)
    world.end_episode(world.start_episode(alice_gid), "done", "success",
                      cost_dollars=2.0, input_tokens=10, output_tokens=5)
    bob_gid = world.create_goal("bob spend", owner=bob)
    world.end_episode(world.start_episode(bob_gid), "done", "success",
                      cost_dollars=9.0, input_tokens=20, output_tokens=8)

    alice_totals = world.total_spend(owner=alice)
    assert alice_totals["dollars"] == 2.0
    assert alice_totals["runs"] == 1

    bob_totals = world.total_spend(owner=bob)
    assert bob_totals["dollars"] == 9.0

    # None is still the deployment-wide admin view (unfiltered by owner).
    admin_totals = world.total_spend()
    assert admin_totals["dollars"] >= 11.0


def test_create_goal_accepts_domain_and_project_id(world):
    """create_goal(domain=..., project_id=...)
    must not raise TypeError on this backend -- checkpoint sub-goal spawning
    and the finance CLI pass both kwargs, matching the SQLite signature."""
    project_id = world.create_project("Q3 rollout", owner="admin@corp.test")
    gid = world.create_goal(
        "spawn under a domain and project",
        domain="finance",
        project_id=project_id,
    )
    assert isinstance(gid, int)
    with world._tx() as cur:
        cur.execute("SELECT domain, project_id FROM goals WHERE id = %s", (gid,))
        domain, stored_project_id = cur.fetchone()
    assert domain == "finance"
    assert stored_project_id == project_id
    # project_status_counts (an existing read path) sees the goal as scoped
    # to the project, proving the write actually took.
    assert world.project_status_counts(project_id).get("pending") == 1


def test_list_episodes_owner_scope_matches_sqlite(world):
    import uuid

    token = uuid.uuid4().hex
    alice = f"user:alice:{token}"
    bob = f"user:bob:{token}"

    alice_gid = world.create_goal("alice-owned run", owner=alice)
    alice_eid = world.start_episode(alice_gid)
    world.end_episode(alice_eid, "done", "success", cost_dollars=1.25)

    bob_gid = world.create_goal("bob-owned run", owner=bob)
    bob_eid = world.start_episode(bob_gid)
    world.end_episode(bob_eid, "done", "success", cost_dollars=7.5)

    legacy_gid = world.create_goal("legacy owner default")
    legacy_eid = world.start_episode(legacy_gid)
    world.end_episode(legacy_eid, "done", "success", cost_dollars=0.5)

    assert [e.id for e in world.list_episodes(owner=alice)] == [alice_eid]
    assert [e.id for e in world.list_episodes(owner=bob)] == [bob_eid]
    assert world.list_episodes(owner=f"user:nobody:{token}") == []

    # Owner and goal scopes are cumulative: Alice cannot select Bob's run by id.
    assert world.list_episodes(goal_id=bob_gid, owner=alice) == []

    # None retains the admin/auth-off view; the empty owner retains legacy rows.
    admin_ids = {e.id for e in world.list_episodes(limit=10_000)}
    assert {alice_eid, bob_eid, legacy_eid} <= admin_ids
    legacy_ids = {e.id for e in world.list_episodes(limit=10_000, owner="")}
    assert legacy_eid in legacy_ids

    # The create path stores ownership and the migration default, not only the
    # read query's shape.
    with world._tx() as cur:
        cur.execute(
            "SELECT id, owner FROM goals WHERE id IN (%s, %s, %s)",
            (alice_gid, bob_gid, legacy_gid),
        )
        owners = dict(cur.fetchall())
    assert owners == {alice_gid: alice, bob_gid: bob, legacy_gid: ""}


def test_goal_reads_are_owner_scoped(world):
    import uuid

    token = uuid.uuid4().hex
    alpha = f"agent:alpha:{token}"
    bravo = f"agent:bravo:{token}"
    alpha_gid = world.create_goal("alpha private", owner=alpha)
    bravo_gid = world.create_goal("bravo private", owner=bravo)

    assert world.get_goal(alpha_gid).owner == alpha
    assert {g.id for g in world.list_goals(owner=alpha)} == {alpha_gid}
    assert {g.id for g in world.list_goals(owner=bravo)} == {bravo_gid}
    assert world.list_goals(owner=f"agent:nobody:{token}") == []


def test_ask_answer_open_questions(world):
    gid = world.create_goal("needs input")
    qid = world.ask("which region?", goal_id=gid)
    assert isinstance(qid, int)

    # open before answering
    opens = world.open_questions(goal_id=gid)
    assert [q.id for q in opens] == [qid]
    assert opens[0].question == "which region?"
    assert opens[0].answer is None

    assert world.answer(qid, "us-east-1") is True
    # answering removes it from the open set
    assert all(q.id != qid for q in world.open_questions(goal_id=gid))

    # all_questions still shows it, now answered
    allq = world.all_questions(gid)
    answered = [q for q in allq if q.id == qid][0]
    assert answered.answer == "us-east-1"
    assert answered.answered_at is not None


def test_answer_unknown_question_id_returns_false(world):
    # Parity with SQLite: a typo'd id is reported, not a false success.
    assert world.answer(987_654_321, "nope") is False


def test_answer_is_atomically_scoped_to_goal_owner(world):
    gid = world.create_goal("owned question", owner="agent:alpha")
    qid = world.ask("private?", goal_id=gid)

    assert world.answer(qid, "stolen", expected_owner="agent:bravo") is False
    assert [q.id for q in world.open_questions(gid)] == [qid]
    assert world.answer(qid, "mine", expected_owner="agent:alpha") is True


def test_approval_queue_lifecycle(world):
    aid = world.create_approval("rm -rf /tmp/x", risk="high", scope="shell", detail="cleanup")
    assert isinstance(aid, int)

    a = world.get_approval(aid)
    assert a is not None
    assert a.action == "rm -rf /tmp/x"
    assert a.risk == "high"
    assert a.provenance is None
    assert a.status == "pending"
    assert a.decided_at is None

    assert any(x.id == aid for x in world.pending_approvals())

    assert world.decide_approval(aid, "approved") is True
    decided = world.get_approval(aid)
    assert decided.status == "approved"
    assert decided.decided_at is not None
    assert all(x.id != aid for x in world.pending_approvals())  # left the queue

    # a second decision on an already-decided row is a no-op
    assert world.decide_approval(aid, "denied") is False


def test_approval_webhook_events_reach_subscribers_only_after_commit(world, monkeypatch):
    """A subscriber to approval events gets a delivery for each one, and each
    delivery starts only once a second connection can read the committed row."""
    import psycopg
    from maverick import approval_notify, audit, webhooks
    from maverick import webhook_subscriptions as subs
    from maverick.tools import _ssrf

    monkeypatch.delenv("MAVERICK_WEBHOOK_SUBSCRIPTIONS", raising=False)
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")
    monkeypatch.setattr(webhooks, "_load_config_outbound", lambda: ([], None))
    monkeypatch.setattr(approval_notify, "approval_created", lambda *a, **k: None)
    seen: list[tuple[str, dict]] = []

    def committed_state(executor, fn, delivery_id):
        with psycopg.connect(_DSN) as other:
            rows = other.execute("SELECT id, status FROM approvals ORDER BY id").fetchall()
        seen.append((delivery_id, dict(rows)))
        return True

    monkeypatch.setattr(webhooks, "_submit", committed_state)
    sub = subs.create_subscription("https://hooks.example.com/a", events=["approval.*"],
                                   world=world)

    single = world.create_approval("payment", risk="high", detail="support")
    assert world.decide_approval(single, "approved", decided_by="ana") is True
    audited = world.create_approval("refund", risk="high", detail="support")
    event = world.decide_approval_audited(audited, "denied", decided_by="ben")
    assert event is not None and event.final_status == "denied"
    assert world.mark_approval_audit_delivered(event.event_id) is True

    deliveries = {d["id"]: d for d in subs.list_deliveries(world=world, subscription_id=sub["id"])}
    told = [(deliveries[delivery_id]["event_type"], state) for delivery_id, state in seen]
    assert told == [
        ("approval.created", {single: "pending"}),
        ("approval.decided", {single: "approved"}),
        ("approval.created", {single: "approved", audited: "pending"}),
        ("approval.decided", {single: "approved", audited: "denied"}),
    ]


def test_only_a_held_decision_is_undone_and_settling_it_makes_it_final(world, monkeypatch):
    import time

    from maverick import webhook_events

    sent = []
    monkeypatch.setattr(webhook_events, "emit", lambda event, **kw: sent.append((event, kw)))

    def decide(aid, status, who):
        event = world.decide_approval_audited(aid, status, decided_by=who)
        assert event is not None and world.mark_approval_audit_delivered(event.event_id)

    acts_at_once = world.create_approval("codebase_merge", risk="high", provenance="codebase")
    decide(acts_at_once, "approved", "ana")
    assert world.undo_approval_decision(acts_at_once, undone_by="ana", within_seconds=30) == "final"
    assert world.get_approval(acts_at_once).undo_hold is None

    held = world.create_approval("rm -rf /tmp/x", risk="high", undoable=True)
    assert world.get_approval(held).undo_hold == "open"
    assert world.settle_approval_decision(held, decided_before=time.time()).status == "pending"  # nothing yet
    decide(held, "approved", "ana")
    assert world.undo_approval_decision(held, undone_by="ana", within_seconds=30) == "undone"
    assert world.get_approval(held).status == "pending"
    assert [kw["payload"]["previous_status"] for event, kw in sent if event == "approval.undone"] == ["approved"]

    decide(held, "denied", "ben")
    assert world.settle_approval_decision(held, decided_before=time.time() - 60).undo_hold == "open"
    settled = world.settle_approval_decision(held, decided_before=time.time())
    assert settled.status == "denied" and settled.undo_hold == "settled"
    assert world.undo_approval_decision(held, undone_by="ben", within_seconds=300) == "too_late"

    stopped = world.create_approval("send", risk="high", undoable=True)
    assert world.decide_approval(stopped, "denied", decided_by="system:task-stopped") is True
    assert world.undo_approval_decision(stopped, undone_by="ana", within_seconds=30) == "final"


def test_the_undo_window_closes_at_its_end_even_on_an_equal_clock_reading(world, monkeypatch):
    # Same boundary as the SQLite backend: a clock that reads the decision and
    # the undo alike (a coarse Windows clock) is still inside a zero window,
    # and the window ends exactly at decided_at + within_seconds.
    import time

    aid = world.create_approval("wire-funds", risk="high", undoable=True)
    event = world.decide_approval_audited(aid, "approved", decided_by="ana")
    assert event is not None and world.mark_approval_audit_delivered(event.event_id)
    decided_at = world.get_approval(aid).decided_at
    clock = {"now": decided_at}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    assert world.undo_approval_decision(aid, undone_by="ana", within_seconds=0) == "too_late"
    clock["now"] = decided_at + 30
    assert world.undo_approval_decision(aid, undone_by="ana", within_seconds=30) == "too_late"
    clock["now"] = decided_at + 29.5
    assert world.undo_approval_decision(aid, undone_by="ana", within_seconds=30) == "undone"
    assert world.get_approval(aid).status == "pending"


def test_decide_approval_rejects_bad_status(world):
    aid = world.create_approval("do thing")
    with pytest.raises(ValueError, match="approved.*denied"):
        world.decide_approval(aid, "maybe")


def test_child_writes_are_tenant_scoped(world):
    """Child rows (episodes/events/turns/messages/questions/attachments) carry no
    tenant_id; they inherit tenancy through their goal/conversation FK and reads
    enforce it via a JOIN. The WRITES must too: a tenant must not inject a child
    row onto another tenant's goal/conversation by id. Regression for the
    unscoped PG child-write methods."""
    from maverick.paths import reset_tenant, set_tenant

    tok = set_tenant("acme")
    try:
        gid = world.create_goal("acme-goal")
        conv = world.get_or_create_conversation("sms", "acme-user")
        eid = world.start_episode(gid)  # happy path within the tenant works
        assert isinstance(eid, int)
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        # id-returning child writes against acme's ids are rejected.
        for call in (
            lambda: world.start_episode(gid),
            lambda: world.append_event(gid, "orch", "note", "x"),
            lambda: world.ask("q?", goal_id=gid),
            lambda: world.add_attachment(gid, "f.txt", "text/plain", 1, "ab", "/tmp/f"),
            lambda: world.append_turn(conv.id, "user", "x"),
        ):
            with pytest.raises(ValueError):
                call()
        # void writes silently no-op (don't raise, don't land).
        world.append_message(gid, "user", "sneaky")
        world.end_episode(eid, "done", "success")  # acme's episode; globex can't end it
    finally:
        reset_tenant(tok)

    tok = set_tenant("acme")
    try:
        eps = world.list_episodes(goal_id=gid)
        assert len(eps) == 1                 # no globex episode landed
        assert eps[0].ended_at is None       # globex's end_episode was a no-op
    finally:
        reset_tenant(tok)


def test_decide_approval_is_tenant_scoped(world):
    """A tenant must not decide another tenant's parked high-risk action.

    The approve/deny dashboard endpoints pass a raw id with no ownership gate,
    so decide_approval itself has to scope to the active tenant (like
    get_approval / pending_approvals do)."""
    from maverick.paths import reset_tenant, set_tenant

    tok = set_tenant("acme")
    try:
        aid = world.create_approval("rm -rf", risk="high")
    finally:
        reset_tenant(tok)

    # Another tenant cannot see it...
    tok = set_tenant("globex")
    try:
        assert all(x.id != aid for x in world.pending_approvals())
        # ...and cannot decide it either (this must not return True).
        assert world.decide_approval(aid, "approved") is False
    finally:
        reset_tenant(tok)

    # The owning tenant still can, and it's still pending until they do.
    tok = set_tenant("acme")
    try:
        assert world.get_approval(aid).status == "pending"
        assert world.decide_approval(aid, "approved") is True
    finally:
        reset_tenant(tok)


# ---------- reclaim_orphan_goals + schema_version ----------

def test_reclaim_orphan_goals(world):
    g = world.create_goal("orphan")
    world.set_goal_status(g, "active")
    # max_age_seconds=0 -> the just-touched active goal qualifies as stale.
    n = world.reclaim_orphan_goals(max_age_seconds=0)
    assert n >= 1
    assert world.get_goal(g).status == "blocked"


def test_reclaim_includes_goal_exactly_at_cutoff(world, monkeypatch):
    from maverick.world_model_backends import postgres as postgres_module

    monkeypatch.setattr(postgres_module.time, "time", lambda: 1_000.0)
    g = world.create_goal("orphan-at-exact-cutoff")
    world.set_goal_status(g, "active")

    assert world.reclaim_orphan_goals(max_age_seconds=0) >= 1
    assert world.get_goal(g).status == "blocked"


def test_reclaim_skips_fresh_goals(world):
    g = world.create_goal("fresh")
    world.set_goal_status(g, "active")
    # A 1-hour staleness window must NOT reclaim a goal touched just now.
    world.reclaim_orphan_goals(max_age_seconds=3600)
    assert world.get_goal(g).status == "active"


def test_schema_version_is_int(world):
    assert isinstance(world.schema_version, int)
    assert world.schema_version >= 1


# ---------- conversations / turns (multi-turn channel memory) ----------

def test_get_or_create_conversation_is_idempotent(world):
    c1 = world.get_or_create_conversation("telegram", "u123")
    c2 = world.get_or_create_conversation("telegram", "u123")
    assert c1.id == c2.id  # same (channel, user_id) -> same row
    assert c1.channel == "telegram" and c1.user_id == "u123"
    # A different user is a distinct conversation.
    c3 = world.get_or_create_conversation("telegram", "other")
    assert c3.id != c1.id


def test_tenant_conversation_is_its_own_row_beside_a_legacy_one(world, monkeypatch):
    # With strict isolation off, the compatibility read also matches a legacy
    # NULL-tenant row for the same user; returning it made append_turn fail.
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    user = "conv-" + uuid.uuid4().hex
    tenant = "convt-" + uuid.uuid4().hex
    try:
        with tenant_scope(tenant=None):
            legacy = world.get_or_create_conversation("slack", user)
        with tenant_scope(tenant=tenant):
            own = world.get_or_create_conversation("slack", user)
            assert own.id != legacy.id
            assert world.get_or_create_conversation("slack", user).id == own.id
            world.append_turn(own.id, "user", "hello")
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM turns WHERE conversation_id IN "
                           "(SELECT id FROM conversations WHERE user_id=%s)", (user,))
            cursor.execute("DELETE FROM conversations WHERE user_id=%s", (user,))


def test_append_and_recent_turns_chronological(world):
    conv = world.get_or_create_conversation("discord", "alice")
    world.append_turn(conv.id, "user", "hello")
    world.append_turn(conv.id, "assistant", "hi there")
    world.append_turn(conv.id, "user", "how are you")
    turns = world.recent_turns(conv.id, limit=20)
    # Ascending (chronological) order, ready for a chat prompt.
    assert [t.content for t in turns] == ["hello", "hi there", "how are you"]
    assert [t.role for t in turns] == ["user", "assistant", "user"]
    # limit returns the most-recent N, still ascending.
    last2 = world.recent_turns(conv.id, limit=2)
    assert [t.content for t in last2] == ["hi there", "how are you"]


def test_append_turn_rejects_bad_role(world):
    conv = world.get_or_create_conversation("slack", "bob")
    with pytest.raises(ValueError):
        world.append_turn(conv.id, "system", "nope")


def test_list_conversations_filter_by_channel(world):
    world.get_or_create_conversation("matrix", "x")
    world.get_or_create_conversation("matrix", "y")
    world.get_or_create_conversation("signal", "z")
    matrix = world.list_conversations(channel="matrix")
    assert {c.user_id for c in matrix} >= {"x", "y"}
    assert all(c.channel == "matrix" for c in matrix)
    # Unfiltered returns at least everything we created.
    assert len(world.list_conversations()) >= 3


def test_prune_conversations_removes_idle_and_their_turns(world):
    from maverick.paths import tenant_scope

    with tenant_scope(tenant="retention-test"):
        conv = world.get_or_create_conversation("email", "prune-me")
        world.append_turn(conv.id, "user", "old message")
        # idle_for_seconds=0 -> the just-touched conversation counts as idle.
        removed = world.prune_conversations(idle_for_seconds=0)
        assert removed >= 1
        # Its turns are gone too (no orphans).
        assert world.recent_turns(conv.id) == []
        assert not any(c.id == conv.id for c in world.list_conversations())


def test_prune_conversations_keeps_fresh(world):
    from maverick.paths import tenant_scope

    with tenant_scope(tenant="retention-test"):
        conv = world.get_or_create_conversation("email", "keep-me")
        world.prune_conversations(idle_for_seconds=3600)  # 1h window
        assert any(c.id == conv.id for c in world.list_conversations())


# ---------- messages, attachments, dedup, pruning ----------

def test_append_message(world, monkeypatch):
    # Search_messages was removed (zero production callers on either
    # backend; its FTS index/GIN index remain in the schema only because the
    # additive-only migration policy blocks dropping them -- see
    # append_message's own comment). append_message itself is still the only
    # thing under test here. Encryption off so the raw column is plaintext
    # (this test isn't about sealing -- test_at_rest_encryption_seals_columns_
    # and_round_trips covers that).
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    g = world.create_goal("has-messages")
    world.append_message(g, "user", "the quick brown fox jumps")
    world.append_message(g, "assistant", "a lazy dog sleeps soundly")
    with world._tx() as cur:
        cur.execute(
            "SELECT role, content FROM messages WHERE goal_id = %s ORDER BY id",
            (g,),
        )
        rows = cur.fetchall()
    assert [r[0] for r in rows] == ["user", "assistant"]
    assert rows[0][1] == "the quick brown fox jumps"


def test_attachments_add_and_list(world):
    g = world.create_goal("with-files")
    aid = world.add_attachment(g, "report.pdf", "application/pdf", 1234, "abc123", "/tmp/r.pdf")
    assert isinstance(aid, int)
    atts = world.list_attachments(g)
    assert len(atts) == 1
    a = atts[0]
    assert a.filename == "report.pdf" and a.mime == "application/pdf"
    assert a.size_bytes == 1234 and a.sha256 == "abc123" and a.path == "/tmp/r.pdf"
    # Scoped to the goal.
    assert world.list_attachments(world.create_goal("other")) == []


def test_processed_message_idempotency(world):
    g = world.create_goal("dedup")
    first = world.mark_message_processed("sms", "SM123", goal_id=g)
    second = world.mark_message_processed("sms", "SM123", goal_id=g)
    assert first is True   # first write -> run the goal
    assert second is False  # duplicate -> skip
    assert world.is_processed_message("sms", "SM123") is True
    assert world.is_processed_message("sms", "never") is False
    assert world.lookup_processed_message("sms", "SM123") == g
    assert world.lookup_processed_message("sms", "never") is None


def test_lookup_processed_message_null_goal_returns_zero(world):
    # Row exists but goal_id is null -> 0 (distinct from None = no row).
    world.mark_message_processed("email", "msg-1", goal_id=None)
    assert world.lookup_processed_message("email", "msg-1") == 0


def test_prune_goal_events(world, monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends import postgres

    clock = [1_000.0]
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: clock[0]))

    with tenant_scope(tenant="retention-test"):
        g = world.create_goal("eventful-prune")
        world.append_event(g, "orch", "note", "old")
        clock[0] += 1
        removed = world.prune_goal_events(older_than_seconds=0)
        assert removed >= 1
        assert world.goal_events(g) == []


def test_prune_processed_messages(world):
    from maverick.paths import tenant_scope

    with tenant_scope(tenant="retention-test"):
        world.mark_message_processed("sms", "to-prune")
        removed = world.prune_processed_messages(older_than_seconds=0)
        assert removed >= 1
        assert world.is_processed_message("sms", "to-prune") is False


def test_erase_conversations_deletes_pg_rows(world, monkeypatch):
    from maverick.attachment_submissions import SubmissionStore
    from maverick.erasure_receipts import (
        RECEIPT_STORES,
        build_manifest,
        persist_erasure_closure,
        persist_receipt,
    )
    from maverick.erasure_verify import verify_erasure
    from maverick.paths import current_tenant_id

    conv = world.get_or_create_conversation("gdpr-pg", "erase-me")
    parent = SubmissionStore(world).create(
        token="private-submission", fingerprint="private-content-fingerprint",
        owner="erase-me", title="parent-delete", description="private request", manifest=[],
    )["goal_id"]
    child = world.create_goal("child-delete", parent_id=parent)
    grandchild = world.create_goal("grandchild-delete", parent_id=child)
    world.append_turn(conv.id, "user", "private text", goal_id=parent)
    world.append_turn(conv.id, "assistant", "private reply", goal_id=child)
    world.append_message(parent, "user", "private message")
    world.append_event(parent, "agent", "note", "private event")
    world.add_attachment(parent, "secret.txt", "text/plain", 6, "abc", "/tmp/secret.txt")
    world.mark_message_processed("gdpr-pg", "external-1", goal_id=parent)
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    episode = world.start_episode(grandchild)
    world.upsert_fact(
        f"derived-private-{episode}",
        "private episode-derived fact",
        episode_id=episode,
    )
    world.add_artifact(grandchild, "text", "report", "private artifact")
    world.ask("private question", goal_id=grandchild)
    world.create_share_link(grandchild, created_by="reviewer")
    world.record_goal_origin(grandchild, "webhook", "private-origin")
    world.set_goal_status(grandchild, "done", result="private result")
    # Human-edit receipts are part of the signed erasure scope as well.
    # Create one through the native transaction, then prove it is removed.
    from maverick.goal_mutations import edit_result

    edit_result(world, grandchild, text="private revised result",
                expected_updated_at=world.get_goal(grandchild).updated_at,
                operation_id=uuid.uuid4().hex, actor="erase-me")
    world.record_signoff(grandchild, "approved", decided_by="reviewer")

    plan = world.plan_conversation_erasure([conv.id])
    assert plan["goal_ids"] == [parent, child, grandchild]
    manifest = build_manifest(
        tenant_id=current_tenant_id() or "shared",
        conversation_ids=plan["conversation_ids"],
        goal_ids=plan["goal_ids"],
        episode_ids=plan["episode_ids"],
    )
    receipt = persist_receipt(world, manifest)
    assert all(
        world.count_erasure_receipt_store(
            store,
            manifest["conversation_ids"],
            manifest["goal_ids"],
            manifest["episode_ids"],
        ) > 0
        for store in RECEIPT_STORES
    )

    goal_ids, attachment_paths, removed_turns = world.erase_conversations(
        [conv.id],
        expected_conversation_ids=plan["conversation_ids"],
        expected_goal_ids=plan["goal_ids"],
        expected_episode_ids=plan["episode_ids"],
    )

    assert goal_ids == {parent, child, grandchild}
    assert attachment_paths == ["/tmp/secret.txt"]
    assert removed_turns == 2
    assert world.recent_turns(conv.id) == []
    assert all(c.id != conv.id for c in world.list_conversations("gdpr-pg"))
    assert world.get_goal(parent) is None
    assert world.get_goal(child) is None
    assert world.get_goal(grandchild) is None
    assert world.is_processed_message("gdpr-pg", "external-1") is False
    assert all(
        world.count_erasure_receipt_store(
            store,
            manifest["conversation_ids"],
            manifest["goal_ids"],
            manifest["episode_ids"],
        ) == 0
        for store in RECEIPT_STORES
    )
    persist_erasure_closure(
        world,
        receipt,
        expected_tenant=current_tenant_id() or "shared",
    )
    proof = verify_erasure(
        "erase-me",
        channel="gdpr-pg",
        receipt=receipt,
        world=world,
    )
    assert proof["clean"] is True
    assert proof["durable_proof"] is True


def test_erase_conversations_fact_scrub_is_tenant_scoped(world):
    """The GDPR erase scrubs the subject's ``user:<channel>:<user>:`` facts by key
    prefix. Facts are UNIQUE per (tenant, key), so the scrub must be tenant-scoped:
    erasing acme's "alice on sms" must NOT delete globex's identically-keyed fact.
    Regression for the cross-tenant over-deletion in erase_conversations (the same
    class delete_facts_matching guards, in a sibling path that missed it)."""
    from maverick.paths import reset_tenant, set_tenant

    key = "user:sms:alice:preference"
    # globex holds the same-key fact for ITS own alice.
    tok = set_tenant("globex")
    try:
        world.upsert_fact(key, "globex-alice-pref")
    finally:
        reset_tenant(tok)

    # acme erases its alice's conversation (subject = sms/alice), scrubbing its fact.
    tok = set_tenant("acme")
    try:
        conv = world.get_or_create_conversation("sms", "alice")
        world.upsert_fact(key, "acme-alice-pref")
        world.erase_conversations([conv.id])
        assert world.get_fact(key) is None
    finally:
        reset_tenant(tok)

    # globex's identically-keyed fact is untouched.
    tok = set_tenant("globex")
    try:
        assert world.get_fact(key) == "globex-alice-pref"
    finally:
        reset_tenant(tok)


# ----- connection pooling (opt-in) -----

def test_pooled_backend_crud_and_pool_object(monkeypatch):
    """With [world_model] pool_size > 0 the backend uses a psycopg_pool pool;
    CRUD still works and self._pool is wired (self.conn is None)."""
    pytest.importorskip("psycopg_pool")
    monkeypatch.setenv("MAVERICK_PG_POOL_SIZE", "3")
    from maverick.world_model_backends.postgres import PostgresWorldModel
    w = PostgresWorldModel(dsn=_DSN)
    try:
        assert w._pool is not None and w.conn is None
        gid = w.create_goal("pooled-goal", description="via pool")
        got = w.get_goal(gid)
        assert got is not None and got.title == "pooled-goal"
        w.set_goal_status(gid, "done", result="ok")
        assert w.get_goal(gid).status == "done"
    finally:
        w.close()


# ----- Row-Level Security (opt-in) -----

def _disable_rls(dsn):
    """Tear down RLS so the opt-in test doesn't leak FORCE RLS into other
    tests sharing the database."""
    import psycopg
    from maverick.world_model_backends.postgres import _TENANT_TABLES
    with psycopg.connect(dsn, autocommit=True) as c, c.cursor() as cur:
        for t in _TENANT_TABLES:
            cur.execute(f"DROP POLICY IF EXISTS mvk_tenant_isolation ON {t}")
            cur.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
            cur.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")


def test_rls_enforces_tenant_isolation_at_db_level(monkeypatch):
    """With RLS on, a tenant-scoped transaction sees ONLY its own rows even on
    a RAW query that carries no app-layer predicate — i.e. the database, not
    just _tenant_scope, enforces the boundary. No active tenant sees no rows
    through the fail-closed policy.

    RLS is bypassed for superusers and table owners-without-FORCE, so this must
    connect as a dedicated NON-superuser role to actually exercise the policy
    (the CI/test DSN role is a superuser). The owner applies the policy; the
    app role only enforces it."""
    import psycopg
    from maverick.paths import reset_tenant, set_tenant
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv("MAVERICK_PG_RLS", "1")
    # Install/apply the owner schema before granting rights on existing tables.
    # Each test now starts from its own empty database.
    PostgresWorldModel(dsn=_DSN).close()
    # 1. Create a non-superuser app role with DML rights (as the owner/superuser).
    with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mvk_rls_app")
        cur.execute("CREATE ROLE mvk_rls_app LOGIN PASSWORD 'rlspw' NOSUPERUSER NOBYPASSRLS")  # pragma: allowlist secret
        cur.execute("GRANT USAGE, CREATE ON SCHEMA public TO mvk_rls_app")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mvk_rls_app")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mvk_rls_app")

    app_dsn = make_conninfo(_DSN, user="mvk_rls_app", password="rlspw")  # pragma: allowlist secret
    # 2. Owner applies RLS; 3. app role (non-superuser) enforces it.
    PostgresWorldModel(dsn=_DSN).close()
    w = PostgresWorldModel(dsn=app_dsn)
    try:
        tok = set_tenant("rls_alpha")
        try:
            a = w.create_goal("alpha-secret")
        finally:
            reset_tenant(tok)
        tok = set_tenant("rls_beta")
        try:
            b = w.create_goal("beta-secret")
        finally:
            reset_tenant(tok)

        # RAW count (no _tenant_scope) under alpha -> RLS must hide beta's row.
        tok = set_tenant("rls_alpha")
        try:
            with w._tx() as cur:
                cur.execute("SELECT count(*) FROM goals WHERE id IN (%s, %s)", (a, b))
                visible = int(cur.fetchone()[0])
        finally:
            reset_tenant(tok)
        assert visible == 1, "RLS should expose only the active tenant's row"

        # No active tenant gets an impossible GUC sentinel, so RLS fails closed.
        with w._tx() as cur:
            cur.execute("SELECT count(*) FROM goals WHERE id IN (%s, %s)", (a, b))
            assert int(cur.fetchone()[0]) == 0
    finally:
        w.close()
        _disable_rls(_DSN)
        with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
            cur.execute("REASSIGN OWNED BY mvk_rls_app TO CURRENT_USER")
            cur.execute("DROP OWNED BY mvk_rls_app")
            cur.execute("DROP ROLE IF EXISTS mvk_rls_app")


# --- Backend parity (SQLite v13 -> v20 catch-up) -----------------------------

def test_set_goal_domain_and_v14_schema(world):
    from maverick.world_model_backends.postgres import _PG_SCHEMA_VERSION
    assert _PG_SCHEMA_VERSION >= 14
    gid = world.create_goal("domain-tagged goal")
    world.set_goal_domain(gid, "finance")  # v14 goals.domain column


def test_halt_durable_clear_failure_rolls_back_locked_generation(world):
    prior = world.active_halt()
    if prior is not None:
        world.disarm_halt(expected_generation=prior["generation"])

    try:
        world.arm_halt("incident", source="postgres-test")
        observed = world.active_halt()
        callbacks = []

        def _local_clear_failure():
            callbacks.append("attempted")
            raise OSError("local clear failed")

        with pytest.raises(OSError, match="local clear failed"):
            world.disarm_halt(
                expected_generation=observed["generation"],
                durable_clear=_local_clear_failure,
            )

        assert callbacks == ["attempted"]
        assert world.active_halt() == observed
    finally:
        current = world.active_halt()
        if current is not None:
            world.disarm_halt(expected_generation=current["generation"])


def test_search_goals_matches_title_desc_result_case_insensitive(world):
    import uuid
    tok = uuid.uuid4().hex[:10]
    g1 = world.create_goal(f"Fix the {tok} export", description="urgent")
    world.create_goal("unrelated cleanup")
    g3 = world.create_goal("note", description=f"see {tok} for context")
    hits = {g.id for g in world.search_goals(tok.upper())}  # case-insensitive
    assert g1 in hits and g3 in hits
    # bounded + ordered newest-first
    assert all(isinstance(g.title, str) for g in world.search_goals(tok))
    assert world.search_goals("   ") == []


def test_count_facts_and_stale_keys(world):
    import time as _t
    import uuid
    base = world.count_facts()
    k = f"k-{uuid.uuid4().hex[:8]}"
    world.upsert_fact(k, "v")
    assert world.count_facts() == base + 1
    assert k in world.stale_fact_keys(_t.time() + 100)        # cutoff in future
    assert k not in world.stale_fact_keys(_t.time() - 10_000)  # cutoff in past


def test_list_approvals_newest_first(world, monkeypatch):
    from maverick.world_model_backends import postgres

    # Equal timestamps need a deterministic tie-breaker, including on clocks
    # with coarse resolution. Do not sleep to make an unstable query pass.
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: 1_000.0))
    a1 = world.create_approval("act-one", risk="high")
    a2 = world.create_approval("act-two", risk="low")
    ids = [a.id for a in world.list_approvals()]
    assert a1 in ids and a2 in ids
    assert ids.index(a2) < ids.index(a1)  # newest (a2) first
    assert [row.id for row in world.list_approvals(limit=1)] == [a2]


def test_release_processed_message_allows_retry(world):
    import uuid
    ext = uuid.uuid4().hex
    assert world.mark_message_processed("sms", ext) is True
    assert world.is_processed_message("sms", ext) is True
    world.release_processed_message("sms", ext)
    assert world.is_processed_message("sms", ext) is False
    # released -> a retry can claim it again
    assert world.mark_message_processed("sms", ext) is True


def test_recent_event_contents(world):
    gid = world.create_goal("evented goal")
    world.append_event(gid, "agent-x", "note", "hello-corpus")
    assert "hello-corpus" in world.recent_event_contents(limit=100)


def test_projects_crud_and_goal_membership(world):
    pid = world.create_project("Migration Q3", description="d", owner="al", domain="eng")
    assert isinstance(pid, int)
    p = world.get_project(pid)
    assert p is not None and p["name"] == "Migration Q3"
    assert p["owner"] == "al" and p["domain"] == "eng" and p["status"] == "active"

    g1 = world.create_goal("member 1")
    g2 = world.create_goal("member 2")
    world.set_goal_project(g1, pid)
    world.set_goal_project(g2, pid)
    world.set_goal_status(g2, "done")
    assert world.project_status_counts(pid) == {"pending": 1, "done": 1}

    listed = {pr["id"]: pr for pr in world.list_projects()}
    assert listed[pid]["goal_count"] == 2

    # clearing membership drops it from the counts
    world.set_goal_project(g2, None)
    assert world.project_status_counts(pid) == {"pending": 1}


def test_get_missing_project_returns_none(world):
    assert world.get_project(999_999_999) is None


def test_artifacts_versioning_and_latest(world):
    gid = world.create_goal("produces deliverables")
    a1 = world.add_artifact(gid, "markdown", "Report", "v1 body")
    a2 = world.add_artifact(gid, "markdown", "Report", "v2 body")  # same title -> v2
    a3 = world.add_artifact(gid, "code", "script.py", "print(1)")
    assert a1 != a2 != a3

    allv = world.artifacts_for_goal(gid)
    report_versions = [a["version"] for a in allv if a["title"] == "Report"]
    assert report_versions == [1, 2]  # ordered by title, version

    latest = {a["title"]: a for a in world.latest_artifacts(gid)}
    assert latest["Report"]["content"] == "v2 body"
    assert latest["Report"]["versions"] == 2
    assert latest["script.py"]["versions"] == 1


def test_share_links_lifecycle(world):
    gid = world.create_goal("shared goal")
    lid, token = world.create_share_link(gid, created_by="al")
    assert isinstance(lid, int) and token
    assert world.resolve_share_link(token) == gid
    assert world.resolve_share_link("bogus") is None
    links = world.share_links_for_goal(gid)
    assert links[0]["id"] == lid and links[0]["active"] is True
    # revoke -> no longer resolves, marked revoked/inactive
    assert world.revoke_share_link(lid, goal_id=gid) is True
    assert world.resolve_share_link(token) is None
    assert world.share_links_for_goal(gid)[0]["active"] is False
    # expired link does not resolve
    _, t2 = world.create_share_link(gid, ttl_seconds=-1)
    assert world.resolve_share_link(t2) is None


def test_signoffs_round_trip_and_batch(world):
    g1 = world.create_goal("deliverable 1")
    g2 = world.create_goal("deliverable 2")
    world.set_goal_status(g1, "done", result="draft 1")
    world.set_goal_status(g2, "done", result="draft 2")
    assert world.signoff_for(g1) is None
    assert world.record_signoff(
        g1, "approved", decided_by="al", note="ok",
    ) is True
    assert world.record_signoff(g1, "approved", decided_by="al") is False
    s = world.signoff_for(g1)
    assert s["decision"] == "approved" and s["decided_by"] == "al" and s["note"] == "ok"
    # a later decision replaces the earlier one (one row per goal)
    world.record_signoff(g1, "rejected", decided_by="bo")
    assert world.signoff_for(g1)["decision"] == "rejected"
    world.record_signoff(g2, "approved")
    assert world.signoffs_for_goals([g1, g2, 999]) == {g1: "rejected", g2: "approved"}
    assert world.signoffs_for_goals([]) == {}


def test_goal_origins(world):
    import uuid
    ref = f"sched-{uuid.uuid4().hex[:8]}"
    g1 = world.create_goal("auto 1")
    world.record_goal_origin(g1, "schedule", ref)
    g2 = world.create_goal("auto 2")
    world.record_goal_origin(g2, "schedule", ref)
    world.set_goal_status(g2, "done")
    ids = [g.id for g in world.goals_for_origin("schedule", ref)]
    assert g1 in ids and g2 in ids and ids == sorted(ids, reverse=True)
    assert world.origin_status_counts("schedule", ref) == {"pending": 1, "done": 1}


@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra not installed (at-rest sealing needs AES-256-GCM)",
)
def test_at_rest_encryption_seals_columns_and_round_trips(world, monkeypatch, tmp_path):
    """With encryption on, sensitive columns are AES-256-GCM ciphertext on disk
    yet read back as plaintext (Postgres at-rest sealing)."""
    import psycopg
    from maverick import crypto_at_rest as car

    # Enable at-rest with an isolated key under tmp.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "at_rest.key")
    assert car.at_rest_enabled() is True

    gid = world.create_goal("SENSITIVE-TITLE-xyz", "SENSITIVE-DESC-xyz")
    world.set_goal_status(gid, "active", result="SENSITIVE-RESULT-xyz")
    world.upsert_fact("enc:k", "SENSITIVE-FACT-xyz")

    # Reads transparently decrypt. (get_fact reads only this key, so the
    # assertion doesn't depend on other rows' key/plaintext state.)
    g = world.get_goal(gid)
    assert g.title == "SENSITIVE-TITLE-xyz"
    assert g.result == "SENSITIVE-RESULT-xyz"
    assert world.get_fact("enc:k") == "SENSITIVE-FACT-xyz"
    # Search still finds it (scan-then-decrypt under encryption).
    assert gid in [x.id for x in world.search_goals("sensitive-title")]

    # Raw columns are sealed ciphertext, never plaintext.
    c = psycopg.connect(_DSN)
    title, result = c.execute(
        "SELECT title, result FROM goals WHERE id=%s", (gid,)).fetchone()
    val = c.execute("SELECT value FROM facts WHERE key=%s", ("enc:k",)).fetchone()[0]
    c.close()
    assert title.startswith("MVKBND1:") and "SENSITIVE-TITLE-xyz" not in title
    assert result.startswith("MVKBND1:") and "SENSITIVE-RESULT-xyz" not in result
    assert val.startswith("MVKBND1:") and "SENSITIVE-FACT-xyz" not in val


def test_goal_status_counts_and_ping(world):
    # Backend-agnostic /metrics + /healthz helpers: status histogram + liveness.
    before = world.goal_status_counts()
    gid = world.create_goal("count me")
    world.set_goal_status(gid, "running")
    after = world.goal_status_counts()
    assert after.get("running", 0) == before.get("running", 0) + 1
    assert world.ping() is True


def test_goal_status_counts_scope_same_owner_to_workspace_and_legacy_root(world, monkeypatch):
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    marker = "status-" + uuid.uuid4().hex[:12]
    other = marker + "-other"
    owner = "user:" + marker
    try:
        before_root = sum(world.goal_status_counts().values())
        world.create_goal("legacy root", owner=owner)
        with tenant_scope(tenant=marker):
            world.create_goal("one", owner=owner)
        with tenant_scope(tenant=other):
            world.create_goal("two", owner=owner)
            world.create_goal("three", owner=owner)
        assert sum(world.goal_status_counts(owner=owner).values()) == 1
        assert sum(world.goal_status_counts().values()) == before_root + 1
        with tenant_scope(tenant=marker):
            assert sum(world.goal_status_counts(owner=owner).values()) == 1
        with tenant_scope(tenant=other):
            assert sum(world.goal_status_counts(owner=owner).values()) == 2
        monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
        with tenant_scope(tenant=marker):
            assert sum(world.goal_status_counts(owner=owner).values()) == 2
    finally:
        with world._tx() as cursor:
            cursor.execute("DELETE FROM goals WHERE tenant_id IN (%s, %s)", (marker, other))
            cursor.execute("DELETE FROM goals WHERE tenant_id IS NULL AND owner=%s", (owner,))


def test_rate_events_window_count(world):
    import time
    now = time.time()
    key = f"rl-{int(now*1e6)}"
    world.record_rate_event(key, now - 30)
    world.record_rate_event(key, now - 10)
    world.record_rate_event(key, now)
    # Window = last 60s -> all 3; tighter window -> fewer.
    assert world.count_rate_events(key, now - 60) == 3
    assert world.count_rate_events(key, now - 20) == 2
    assert world.count_rate_events(key, now + 5) == 0
    # An unrelated key sees none of them.
    assert world.count_rate_events("rl-other", now - 60) == 0


def test_concurrent_migrate_does_not_race(world):
    # Advisory lock (audit follow-up): many replicas migrating the same DB at
    # once must not error -- Postgres CREATE/ALTER ... IF NOT EXISTS DDL is not
    # concurrency-safe without serialization. Each thread opens its own backend
    # (its own connection) and runs migration on construction.
    import threading

    from maverick.world_model_backends.postgres import (
        _PG_SCHEMA_VERSION,
        PostgresWorldModel,
    )

    errs: list[str] = []

    def go():
        try:
            w = PostgresWorldModel(dsn=_DSN)
            w.close()
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], f"concurrent migration raced: {errs}"
    assert world.schema_version == _PG_SCHEMA_VERSION


# ---------- Postgres backend at-rest / tenant parity ----------

@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra not installed (at-rest sealing needs AES-256-GCM)",
)
def test_reclaim_orphan_goals_preserves_sealed_result(world, monkeypatch, tmp_path):
    """Under at-rest encryption, reclaim must append the marker THROUGH the seal
    layer. The old bulk `result = COALESCE(result,'') || ' [marker]'` SQL
    concatenated plaintext onto ciphertext, corrupting the sealed result so it
    no longer decrypts -- the deliverable was permanently lost on crash
    recovery. (Mirrors the SQLite backend's at-rest branch.)"""
    from maverick import crypto_at_rest as car
    from maverick.world_model_backends import postgres as postgres_module

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "at_rest.key")
    monkeypatch.setattr(postgres_module.time, "time", lambda: 1_000.0)
    assert car.at_rest_enabled() is True

    gid = world.create_goal("orphan-enc")
    world.set_goal_status(gid, "active", result="SEALED-RESULT-keepme")

    n = world.reclaim_orphan_goals(max_age_seconds=0)
    assert n >= 1

    g = world.get_goal(gid)
    assert g.status == "blocked"
    # The original result is still readable (decryptable) and the marker is on it.
    assert "SEALED-RESULT-keepme" in g.result
    assert "[process restarted mid-run]" in g.result


def test_delete_facts_matching_is_tenant_scoped(world):
    """A GDPR erase for a subject in one tenant must not delete another tenant's
    fact that happens to share the same key. The DELETE keyed only on `key` (no
    tenant predicate) over-deleted across tenants; the read side was already
    scoped, so the write side has to match."""
    from maverick.paths import reset_tenant, set_tenant

    key = "user:telegram:alice:preference"
    tok = set_tenant("acme")
    try:
        world.upsert_fact(key, "acme-alice-value")
    finally:
        reset_tenant(tok)
    tok = set_tenant("globex")
    try:
        world.upsert_fact(key, "globex-alice-value")
    finally:
        reset_tenant(tok)

    # acme erases its alice: only acme's row goes.
    tok = set_tenant("acme")
    try:
        removed = world.delete_facts_matching("telegram:alice")
        assert key in removed
        assert world.get_fact(key) is None
    finally:
        reset_tenant(tok)
    # globex's identically-keyed fact is untouched.
    tok = set_tenant("globex")
    try:
        assert world.get_fact(key) == "globex-alice-value"
    finally:
        reset_tenant(tok)


def test_fact_compatibility_read_prefers_tenant_row_over_newer_legacy(
    world, monkeypatch
):
    """Legacy NULL fallback must never overwrite an explicit tenant belief."""
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    key = f"tenant-precedence:{uuid.uuid4().hex}"
    tok = set_tenant("acme")
    try:
        world.upsert_fact(key, "acme", trust_tier=3)
    finally:
        reset_tenant(tok)
    # Write legacy later so write order alone would select the wrong row.
    world.upsert_fact(key, "legacy-newer", trust_tier=0)

    tok = set_tenant("acme")
    try:
        assert world.get_fact(key) == "acme"
        assert world.get_facts()[key] == "acme"
        assert world.get_facts_with_trust()[key] == ("acme", 3)
    finally:
        reset_tenant(tok)


def test_subject_fact_erasure_purges_readable_legacy_rows(world, monkeypatch):
    """Art.17 scope must cover legacy rows exposed by compatibility reads."""
    from maverick import world_model as wm
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    subject = f"sms:{uuid.uuid4().hex}"
    key = f"user:{subject}:email"
    world.upsert_fact(key, "legacy@example.test")

    tok = set_tenant("acme")
    try:
        assert world.facts_matching(subject) == {
            key: "legacy@example.test"
        }
        assert world.delete_facts_matching(subject) == [key]
        assert world.facts_matching(subject) == {}
        assert world.fact_history_matching(subject) == {}
    finally:
        reset_tenant(tok)

    assert world.get_fact(key) is None
    assert world.fact_history(key) == []


def test_history_precedence_projects_effective_legacy_and_tenant_timeline(
    world, monkeypatch,
):
    """Legacy history resumes outside exact tenant validity windows."""
    from maverick import world_model as wm
    from maverick.paths import reset_tenant, set_tenant
    from maverick.world_model_backends import postgres

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    times = iter((100.0, 200.0, 300.0))
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: next(times)))
    subject = f"sms:{uuid.uuid4().hex}"
    key = f"user:{subject}:email"

    world.upsert_fact(key, "legacy")
    tok = set_tenant("acme")
    try:
        world.upsert_fact(key, "own")
        assert world.delete_fact(key) == 1

        assert world.get_fact(key, as_of=150.0) == "legacy"
        assert world.get_fact(key, as_of=250.0) == "own"
        assert world.get_fact(key, as_of=350.0) == "legacy"

        history = world.fact_history(key)
        assert [
            (version.value, version.valid_from, version.valid_to)
            for version in history
        ] == [
            ("legacy", 300.0, None),
            ("own", 200.0, 300.0),
            ("legacy", 100.0, 200.0),
        ]
        exported = world.fact_history_matching(subject)[key]
        assert [
            (version.value, version.valid_from, version.valid_to)
            for version in exported
        ] == list(reversed([
            ("legacy", 300.0, None),
            ("own", 200.0, 300.0),
            ("legacy", 100.0, 200.0),
        ]))
    finally:
        world.delete_facts_matching(subject)
        reset_tenant(tok)


def test_history_limit_applies_after_effective_precedence_projection(
    world, monkeypatch,
):
    """Hidden recent legacy rows cannot evict older point-readable history."""
    from maverick import world_model as wm
    from maverick.paths import reset_tenant, set_tenant
    from maverick.world_model_backends import postgres

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    times = iter((100.0, 105.0, 110.0, 120.0))
    monkeypatch.setattr(postgres, "time", SimpleNamespace(time=lambda: next(times)))
    subject = f"sms:{uuid.uuid4().hex}"
    key = f"user:{subject}:email"

    world.upsert_fact(key, "legacy-visible")
    tok = set_tenant("acme")
    try:
        world.upsert_fact(key, "own")
    finally:
        reset_tenant(tok)
    # These are newer raw legacy versions, but the own interval hides both.
    world.upsert_fact(key, "legacy-hidden-1")
    world.upsert_fact(key, "legacy-hidden-2")

    tok = set_tenant("acme")
    try:
        history = world.fact_history(key, limit=2)
        assert [
            (version.value, version.valid_from, version.valid_to)
            for version in history
        ] == [
            ("own", 105.0, None),
            ("legacy-visible", 100.0, 105.0),
        ]
        assert world.get_fact(key, as_of=102.0) == "legacy-visible"
        assert world.get_fact(key, as_of=115.0) == "own"
    finally:
        world.delete_facts_matching(subject)
        reset_tenant(tok)


def test_unbound_fact_reads_exclude_named_tenants(world, monkeypatch):
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    unique = uuid.uuid4().hex
    key_a = f"tenant-a:{unique}"
    key_b = f"tenant-b:{unique}"
    key_root = f"legacy:{unique}"
    try:
        with tenant_scope(tenant="acme"):
            world.upsert_fact(key_a, "workspace-a-private")
        with tenant_scope(tenant="globex"):
            world.upsert_fact(key_b, "workspace-b-private")
        world.upsert_fact(key_root, "legacy-visible")
        assert world.get_fact(key_a) is None
        assert world.get_fact(key_b) is None
        facts = world.get_facts()
        assert key_a not in facts and key_b not in facts
        assert facts[key_root] == "legacy-visible"
        with tenant_scope(tenant="acme"):
            assert world.get_fact(key_a) == "workspace-a-private"
            assert world.get_fact(key_b) is None
        with tenant_scope(tenant="globex"):
            assert world.get_fact(key_b) == "workspace-b-private"
            assert world.get_fact(key_a) is None
    finally:
        with tenant_scope(tenant="acme"):
            world.delete_fact(key_a)
        with tenant_scope(tenant="globex"):
            world.delete_fact(key_b)
        world.delete_fact(key_root)


def test_unbound_fact_delete_mutates_only_legacy_null_row(world, monkeypatch):
    """The unbound admin read view is not authority to delete named tenants."""
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    key = f"exact-delete:{uuid.uuid4().hex}"
    for tenant, value in (("acme", "a"), ("globex", "g")):
        tok = set_tenant(tenant)
        try:
            world.upsert_fact(key, value)
        finally:
            reset_tenant(tok)
    world.upsert_fact(key, "legacy")

    assert world.delete_fact(key) == 1
    for tenant, value in (("acme", "a"), ("globex", "g")):
        tok = set_tenant(tenant)
        try:
            assert world.get_fact(key) == value
        finally:
            reset_tenant(tok)


def test_unbound_temporal_upsert_does_not_close_named_tenant_history(
    world, monkeypatch
):
    from maverick import world_model as wm
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "0")
    key = f"exact-history:{uuid.uuid4().hex}"
    tok = set_tenant("acme")
    try:
        world.upsert_fact(key, "acme")
    finally:
        reset_tenant(tok)

    world.upsert_fact(key, "legacy")
    with world._tx() as cur:
        cur.execute(
            "SELECT tenant_id, COUNT(*) FROM fact_history "
            "WHERE key = %s AND valid_to IS NULL GROUP BY tenant_id",
            (key,),
        )
        open_by_tenant = {row[0]: int(row[1]) for row in cur.fetchall()}
    assert open_by_tenant["acme"] == 1
    assert open_by_tenant[None] == 1


def test_fact_write_sequence_crosses_32_bit_limit(world):
    """The logical write clock remains valid beyond SERIAL's signed limit."""
    key = f"write-seq:{uuid.uuid4().hex}"
    with world._tx() as cur:
        cur.execute("SELECT pg_get_serial_sequence('facts', 'write_seq')")
        sequence = cur.fetchone()[0]
        cur.execute("SELECT COALESCE(MAX(write_seq), 0) FROM facts")
        current = int(cur.fetchone()[0])
        floor = max(current, 2_147_483_646)
        cur.execute("SELECT setval(%s, %s, true)", (sequence, floor))

    world.upsert_fact(key, "before")
    world.upsert_fact(key, "after")
    with world._tx() as cur:
        cur.execute("SELECT write_seq FROM facts WHERE key = %s", (key,))
        write_seq = int(cur.fetchone()[0])
    assert write_seq > 2_147_483_647
    assert world.get_fact(key) == "after"


@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra not installed (at-rest sealing needs AES-256-GCM)",
)
def test_search_facts_matches_value_under_encryption(world, monkeypatch, tmp_path):
    """With encryption on, `value` is ciphertext, so a SQL LIKE over it can never
    match the plaintext query. search_facts must scan by key prefix then decrypt
    + substring-match in Python, and return PLAINTEXT (not ciphertext)."""
    from maverick import crypto_at_rest as car

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "at_rest.key")
    assert car.at_rest_enabled() is True

    world.upsert_fact("srch:color", "the user prefers MAGENTA")
    hits = world.search_facts("srch:", "magenta")
    assert ("srch:color", "the user prefers MAGENTA") in hits


def test_concurrent_add_artifact_no_duplicate_versions(world):
    # Per-key advisory lock: N threads appending the same (goal, title) must get
    # N distinct, gapless versions -- not duplicates from a MAX(version)+1 race.
    import threading

    from maverick.world_model_backends.postgres import PostgresWorldModel

    gid = world.create_goal("artifact-race")
    n = 12
    barrier = threading.Barrier(n)
    errs: list[str] = []

    def go():
        try:
            w = PostgresWorldModel(dsn=_DSN)
            barrier.wait()  # maximize overlap on the read-modify-write
            w.add_artifact(gid, "text", "report", "body")
            w.close()
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    threads = [threading.Thread(target=go) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], errs
    versions = sorted(a["version"] for a in world.artifacts_for_goal(gid)
                      if a["title"] == "report")
    assert versions == list(range(1, n + 1)), versions  # distinct + gapless


def test_concurrent_upsert_fact_single_open_window(world, monkeypatch):
    # Per-key advisory lock: concurrent temporal upserts of one key must leave
    # exactly ONE open history window (valid_to IS NULL), not several.
    import threading

    from maverick import world_model as wm
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)

    key = f"k-{id(object())}"
    n = 12
    barrier = threading.Barrier(n)
    errs: list[str] = []

    def go(i):
        try:
            w = PostgresWorldModel(dsn=_DSN)
            barrier.wait()
            w.upsert_fact(key, f"v{i}", trust_tier=(i % 5) + 1)
            w.close()
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], errs
    with world._tx() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM fact_history WHERE key = %s AND valid_to IS NULL",
            (key,),
        )
        open_windows = cur.fetchone()[0]
    assert open_windows == 1, f"expected exactly one open window, got {open_windows}"


def test_concurrent_temporal_upsert_delete_matches_live_state(world, monkeypatch):
    """The per-key lock must make live state and the open window agree."""
    import threading

    from maverick import world_model as wm
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    key = f"pg:upsert-delete:{uuid.uuid4().hex}"
    world.upsert_fact(key, "initial")
    barrier = threading.Barrier(2)
    errors: list[str] = []

    def upsert():
        try:
            candidate = PostgresWorldModel(dsn=_DSN)
            barrier.wait()
            candidate.upsert_fact(key, "concurrent")
            candidate.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    def delete():
        try:
            candidate = PostgresWorldModel(dsn=_DSN)
            barrier.wait()
            candidate.delete_fact(key)
            candidate.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=upsert), threading.Thread(target=delete)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == [], errors
    assert all(not thread.is_alive() for thread in threads)
    current = world.get_fact(key)
    history = world.fact_history(key, limit=10)
    open_rows = [version for version in history if version.valid_to is None]
    assert bool(current is not None) == bool(open_rows)
    if current is not None:
        assert len(open_rows) == 1
        assert open_rows[0].value == current
    assert all(
        version.valid_to is None or version.valid_to >= version.valid_from
        for version in history
    )


def test_concurrent_subject_purge_serializes_temporal_upsert(world, monkeypatch):
    """A matching upsert linearizes after the live + history purge."""
    import threading
    from contextlib import contextmanager

    from maverick import world_model as wm
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: True)
    subject = f"sms:{uuid.uuid4().hex}"
    seed_key = f"user:{subject}:seed"
    concurrent_key = f"user:{subject}:concurrent"
    world.upsert_fact(seed_key, "erase")

    eraser = PostgresWorldModel(dsn=_DSN)
    writer = PostgresWorldModel(dsn=_DSN)
    lock_acquired = threading.Event()
    release_purge = threading.Event()
    writer_started = threading.Event()
    writer_done = threading.Event()
    errors: list[str] = []
    removed: list[str] = []
    original_tx = eraser._tx

    class PausingCursor:
        def __init__(self, cursor):
            self._cursor = cursor

        def execute(self, sql, params=None):
            result = self._cursor.execute(sql, params)
            if sql.startswith("LOCK TABLE fact_history, facts"):
                lock_acquired.set()
                if not release_purge.wait(timeout=10):
                    raise TimeoutError("test did not release subject-purge lock")
            return result

        def __getattr__(self, name):
            return getattr(self._cursor, name)

    @contextmanager
    def paused_tx():
        with original_tx() as cursor:
            yield PausingCursor(cursor)

    monkeypatch.setattr(eraser, "_tx", paused_tx)

    def purge():
        try:
            removed.extend(eraser.delete_facts_matching(subject))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"purge: {exc!r}")

    def upsert():
        writer_started.set()
        try:
            writer.upsert_fact(concurrent_key, "survives")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"upsert: {exc!r}")
        finally:
            writer_done.set()

    purge_thread = threading.Thread(target=purge)
    writer_thread = threading.Thread(target=upsert)
    try:
        purge_thread.start()
        assert lock_acquired.wait(timeout=10)
        writer_thread.start()
        assert writer_started.wait(timeout=10)
        assert not writer_done.wait(timeout=0.2)
        release_purge.set()
        purge_thread.join(timeout=10)
        writer_thread.join(timeout=10)

        assert errors == []
        assert not purge_thread.is_alive()
        assert not writer_thread.is_alive()
        assert removed == [seed_key]
        assert world.get_fact(seed_key) is None
        assert world.fact_history(seed_key) == []
        assert world.get_fact(concurrent_key) == "survives"
        [current] = world.fact_history(concurrent_key)
        assert current.value == "survives"
        assert current.valid_to is None
    finally:
        release_purge.set()
        if purge_thread.ident is not None:
            purge_thread.join(timeout=10)
        if writer_thread.ident is not None:
            writer_thread.join(timeout=10)
        eraser.close()
        writer.close()
        world.delete_facts_matching(subject)


def test_answer_cannot_cross_tenant(world, monkeypatch):
    # A tenant must not answer (overwrite) another tenant's question by id.
    # RLS defaults off, so app-level _tenant_scope is the only guard.
    from maverick.world_model_backends import postgres as pg

    monkeypatch.setattr(pg, "_active_tenant", lambda: "tA")
    gid_a = world.create_goal("a-goal")
    qid_a = world.ask("secret question?", gid_a)

    monkeypatch.setattr(pg, "_active_tenant", lambda: "tB")
    assert world.answer(qid_a, "tB was here") is False  # no row under tB's scope

    monkeypatch.setattr(pg, "_active_tenant", lambda: "tA")
    qa = [q for q in world.all_questions(gid_a) if q.id == qid_a]
    assert qa and qa[0].answer is None  # still unanswered; not overwritten


def test_recent_event_contents_is_tenant_scoped(world, monkeypatch):
    from maverick.world_model_backends import postgres as pg

    monkeypatch.setattr(pg, "_active_tenant", lambda: "evA")
    ga = world.create_goal("evt-a")
    world.append_event(ga, "agent", "note", "TENANT_A_ONLY_SECRET")

    monkeypatch.setattr(pg, "_active_tenant", lambda: "evB")
    gb = world.create_goal("evt-b")
    world.append_event(gb, "agent", "note", "tenant_b_event")
    contents = world.recent_event_contents(limit=1000)
    assert "TENANT_A_ONLY_SECRET" not in contents  # no cross-tenant read
    assert "tenant_b_event" in contents


def test_erase_conversations_cannot_cross_tenant(world, monkeypatch):
    from maverick.world_model_backends import postgres as pg

    monkeypatch.setattr(pg, "_active_tenant", lambda: "erA")
    conv_a = world.get_or_create_conversation("chan", "userA").id

    monkeypatch.setattr(pg, "_active_tenant", lambda: "erB")
    goals, paths, turns = world.erase_conversations([conv_a])
    assert goals == set() and paths == [] and turns == 0  # nothing erased

    monkeypatch.setattr(pg, "_active_tenant", lambda: "erA")
    assert any(c.id == conv_a for c in world.list_conversations())  # survived


def test_fk_readers_are_tenant_scoped(world, monkeypatch):
    # Defense-in-depth: artifact/share-link/signoff/origin readers must not
    # return another tenant's rows even if handed a foreign goal_id directly.
    from maverick.world_model_backends import postgres as pg

    monkeypatch.setattr(pg, "_active_tenant", lambda: "fkA")
    ga = world.create_goal("a")
    world.set_goal_status(ga, "done", result="draft")
    world.add_artifact(ga, "text", "rep", "secretA")
    world.create_share_link(ga, created_by="a")
    world.record_signoff(ga, "approved", decided_by="a")
    world.record_goal_origin(ga, "schedule", "shared-ref")

    monkeypatch.setattr(pg, "_active_tenant", lambda: "fkB")
    # Tenant B hands tenant A's goal id to each reader -> empty.
    assert world.artifacts_for_goal(ga) == []
    assert world.share_links_for_goal(ga) == []
    assert world.signoffs_for_goals([ga]) == {}
    # origin_status_counts for the colliding ref must not see A's goals.
    assert world.origin_status_counts("schedule", "shared-ref") == {}

    # Tenant A still sees its own.
    monkeypatch.setattr(pg, "_active_tenant", lambda: "fkA")
    assert len(world.artifacts_for_goal(ga)) == 1
    assert len(world.share_links_for_goal(ga)) == 1
    assert world.signoffs_for_goals([ga]) == {ga: "approved"}
    assert world.origin_status_counts("schedule", "shared-ref")  # non-empty


def test_named_tenant_cannot_mutate_legacy_or_link_foreign_rows(world, monkeypatch):
    from maverick.world_model_backends import postgres as pg

    tenant = "mutation-" + uuid.uuid4().hex
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)
    active = [None]
    monkeypatch.setattr(pg, "_active_tenant", lambda: active[0])
    legacy = world.create_goal("legacy")
    legacy_project = world.create_project("legacy project")
    active[0] = tenant
    own = world.create_goal("own")
    own_project = world.create_project("own project")
    conversation = world.get_or_create_conversation("channel", tenant).id
    try:
        world.set_goal_project(own, own_project)
        assert world.get_goal(own).project_id == own_project
        assert world.add_artifact(own, "text", "own report", "data") > 0
        assert world.append_turn(conversation, "user", "message", goal_id=own) > 0
        world.set_goal_title(legacy, "changed")
        assert world.get_goal(legacy).title == "legacy"  # compatibility read only
        with pytest.raises(ValueError):
            world.add_artifact(legacy, "text", "report", "data")
        with pytest.raises(ValueError):
            world.start_episode(legacy)
        with pytest.raises(ValueError):
            world.append_turn(conversation, "user", "message", goal_id=legacy)
        with pytest.raises(ValueError):
            world.create_goal("foreign child", parent_id=legacy)
        with pytest.raises(ValueError):
            world.create_goal("foreign project", project_id=legacy_project)
        world.set_goal_parent(own, legacy)
        assert world.get_goal(own).parent_id is None
        world.set_goal_project(own, legacy_project)
        assert world.get_goal(own).project_id == own_project
    finally:
        with world._tx() as cur:
            cur.execute("DELETE FROM turns WHERE conversation_id=%s", (conversation,))
            cur.execute("DELETE FROM conversations WHERE id=%s", (conversation,))
            cur.execute("DELETE FROM artifacts WHERE goal_id IN (%s,%s)", (legacy, own))
            cur.execute("DELETE FROM goals WHERE id IN (%s,%s)", (legacy, own))
            cur.execute("DELETE FROM projects WHERE id IN (%s,%s)", (legacy_project, own_project))


def test_erase_conversations_deletes_all_goal_child_rows(world):
    # GDPR erase of a goal that carries a row in EVERY child table referencing
    # goals(id). Postgres enforces FKs per statement (no ON DELETE CASCADE), so
    # DELETE FROM goals fails unless artifacts/share_links/signoffs/goal_origins
    # are deleted first -- the erase must not raise ForeignKeyViolation and roll
    # the whole subject deletion back, leaving all their data intact.
    import time
    conv = world.get_or_create_conversation("slack", f"erase-{time.time()}")
    gid = world.create_goal("secret goal")
    world.append_turn(conv.id, "user", "please remember this", goal_id=gid)
    world.add_artifact(gid, "text", "report", "secret content")
    world.create_share_link(gid, created_by="x")
    world.set_goal_status(gid, "done", result="draft")
    world.record_signoff(gid, "approved", decided_by="x")
    world.record_goal_origin(gid, "webhook", "ext-ref")

    goals, _paths, removed_turns = world.erase_conversations([conv.id])

    assert gid in goals
    assert removed_turns >= 1
    # The goal and every one of its child rows must be gone.
    assert world.get_goal(gid) is None
    assert world.artifacts_for_goal(gid) == []
    assert world.share_links_for_goal(gid) == []
    assert world.signoffs_for_goals([gid]) == {}


def test_query_rewrites_sqlite_paramstyle_and_buckets_days(world):
    """The dashboard boards write SQLite-paramstyle SQL once and run it on
    either backend; this is the live Postgres half of that contract."""
    title = f"portable-{uuid.uuid4().hex[:8]}"
    gid = world.create_goal(title, description="")
    world.set_goal_status(gid, "done", result="ok")

    rows = world.query(
        "SELECT status, COUNT(*) AS n FROM goals WHERE id = ? GROUP BY status", (gid,)
    )
    assert len(rows) == 1
    assert rows[0][0] == "done" and rows[0]["status"] == "done" and rows[0]["n"] == 1
    (status, n), = rows
    assert (status, n) == ("done", 1)

    # A literal % (LIKE) alongside a placeholder must not be read as a marker.
    like = world.query(
        "SELECT COUNT(*) FROM goals WHERE id = ? AND COALESCE(owner, '') NOT LIKE 'agent:%'",
        (gid,),
    )
    assert like[0][0] == 1

    (day_row,) = world.query(
        f"SELECT {world.sql_day_from_epoch('created_at')} AS day FROM goals WHERE id = ?", (gid,)
    )
    assert len(day_row["day"]) == 10 and day_row["day"][4] == "-"

    # A failing statement must roll back and leave the shared connection usable.
    import psycopg

    with pytest.raises(psycopg.Error):
        world.query("SELECT * FROM no_such_table_here WHERE id = ?", (1,))
    assert world.query("SELECT COUNT(*) FROM goals WHERE id = ?", (gid,))[0][0] == 1


def test_results_page_and_monthly_spend_match_the_sqlite_backend(world):
    # list_goal_results and total_spend(since=) existed only on SQLite: on this
    # backend /deliverables raised AttributeError and the month's spend read $0.
    import time

    token = uuid.uuid4().hex
    owner = f"user:results:{token}"
    finished = world.create_goal("finished report", owner=owner)
    world.set_goal_status(finished, "done", result="the report")
    world.create_goal("still running", owner=owner)
    subtask = world.create_goal("subtask", owner=owner, parent_id=finished)
    world.set_goal_status(subtask, "done", result="part of it")
    other = world.create_goal("someone else's", owner=f"user:other:{token}")
    world.set_goal_status(other, "done", result="theirs")
    results = world.list_goal_results(owner=owner)
    assert [goal.id for goal in results] == [finished]
    assert results[0].result == "the report"

    before = time.time()
    world.end_episode(world.start_episode(finished), "done", "success",
                      cost_dollars=3.0, input_tokens=1, output_tokens=1)
    assert world.total_spend(owner=owner, since=before - 1)["dollars"] == 3.0
    assert world.total_spend(owner=owner, since=time.time() + 60)["dollars"] == 0
