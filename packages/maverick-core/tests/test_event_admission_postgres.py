"""Native PostgreSQL event admission, rollback, tenant predicates and forced RLS."""
from __future__ import annotations

import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from maverick import event_admission
from maverick.paths import tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel


def _admit(world):
    return event_admission.admit(world, "same-event", "one", "one", owner="user:synthetic",
                                 origin="orders", trigger_key="same-trigger")


def test_native_pg_concurrent_admission_commits_one_goal(postgres_test_dsn):
    with PostgresWorldModel(postgres_test_dsn):
        pass
    def run(_):
        with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
            return _admit(world)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(run, range(2)))
    assert first == second
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        assert len(world.list_goals()) == 1
        assert event_admission.pending(world, "same-trigger") == [("same-event", first[0], "pending")]


def test_native_pg_trigger_edit_cannot_interleave_execution_claim(
    postgres_test_dsn, tmp_path, monkeypatch,
):
    from maverick.templates import Template
    from maverick.world_model_backends import postgres
    from maverick_dashboard import event_poll, event_triggers_store, triggers_store

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    template = triggers_store.snapshot_from_template(
        Template(name="orders-template", title="Order {{title}}",
                 body="Process {{title}}", params=["title"]),
    )
    trigger = event_triggers_store.set_trigger(
        "orders", "orders-template", "http_json", owner="user:alice",
        tenant="alpha", config={"url": "https://first.example.test"},
        template_snapshot=template,
    )
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        goal, _ = event_admission.admit(
            world, "event-one", "Order one", "Process one", owner="user:alice",
            origin="orders", trigger_key=event_poll._trigger_key(trigger),
            origin_kind="event_v2",
        )

    validated = Event()
    release_claim = Event()
    edit_started = Event()
    edit_finished = Event()
    original = postgres.compatible_event_goal

    def paused_proof(*args):
        result = original(*args)
        validated.set()
        assert release_claim.wait(5)
        return result

    def claim():
        with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
            return world.claim_goal_for_run(goal, expected_owner="user:alice")

    def edit():
        edit_started.set()
        event_triggers_store.set_trigger(
            "orders", "orders-template", "http_json", owner="user:alice",
            tenant="alpha", config={"url": "https://second.example.test"},
            template_snapshot=template,
        )
        edit_finished.set()

    monkeypatch.setattr(postgres, "compatible_event_goal", paused_proof)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            started = pool.submit(claim)
            assert validated.wait(10)
            edited = pool.submit(edit)
            assert edit_started.wait(5)
            assert not edit_finished.wait(0.1)
            release_claim.set()
            assert started.result(timeout=10)
            edited.result(timeout=10)
        with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
            assert world.get_goal(goal).status == "active"
    finally:
        release_claim.set()


def test_native_pg_receipts_are_exact_tenant_scoped_even_without_rls(postgres_test_dsn, monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant="alpha"):
            alpha = _admit(world)
            assert event_admission.transition(world, "same-event", "pending", "delivered")
        with tenant_scope(tenant="beta"):
            beta = _admit(world)
            assert beta[0] != alpha[0]
            assert event_admission.pending(world, "same-trigger") == [("same-event", beta[0], "pending")]
        with tenant_scope(tenant="alpha"):
            assert _admit(world) == (alpha[0], "delivered")
            assert event_admission.pending(world, "same-trigger") == []


def test_native_pg_receipt_failure_rolls_back_goal_and_origin(postgres_test_dsn):
    psycopg = pytest.importorskip("psycopg")
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        with psycopg.connect(postgres_test_dsn) as conn:
            conn.execute("ALTER TABLE event_goal_admissions ADD CONSTRAINT synthetic_reject CHECK(goal_id<0)")
        with pytest.raises(psycopg.errors.CheckViolation):
            _admit(world)
        assert world.list_goals() == []
        assert world.goals_for_origin("event", "orders") == []
        with psycopg.connect(postgres_test_dsn) as conn:
            conn.execute("ALTER TABLE event_goal_admissions DROP CONSTRAINT synthetic_reject")
        assert _admit(world)[1] == "pending"


def test_native_pg_poll_batch_survives_reopen_and_is_tenant_scoped(postgres_test_dsn):
    candidate = {"events": [{"id": "one", "private": "synthetic-content"}], "event_ids": ["one"],
                 "cursor": "next", "cursor_format": 1, "before_cursor": "old", "before_format": 0}
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        saved = event_admission.poll_batch(world, "same-trigger", candidate)
    with PostgresWorldModel(postgres_test_dsn) as world:
        with tenant_scope(tenant="beta"):
            assert event_admission.poll_batch(world, "same-trigger") is None
            event_admission.complete_poll_batch(world, "same-trigger", saved["batch_digest"])
        with tenant_scope(tenant="alpha"):
            assert event_admission.poll_batch(world, "same-trigger") == saved
            event_admission.complete_poll_batch(world, "same-trigger", "wrong-digest")
            assert event_admission.poll_batch(world, "same-trigger") == saved
            event_admission.complete_poll_batch(world, "same-trigger", saved["batch_digest"])
            assert event_admission.poll_batch(world, "same-trigger") is None


def test_native_non_bypass_rls_hides_event_receipts(postgres_test_dsn, monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    role = "mvk_event_" + uuid.uuid4().hex[:12]
    password = secrets.token_urlsafe(24)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE")
                      .format(sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
            dsn = make_conninfo(postgres_test_dsn, user=role, password=password, options=f"-c search_path={role}")
            monkeypatch.setenv("MAVERICK_PG_RLS", "1")
            monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
            with PostgresWorldModel(dsn) as world:
                with tenant_scope(tenant="alpha"):
                    alpha = _admit(world)
                    event_admission.poll_batch(world, "same-trigger", {"events": [{"id": "alpha"}]})
                with tenant_scope(tenant="beta"):
                    beta = _admit(world)
                    assert alpha[0] != beta[0]
                    with world._tx() as cursor:
                        cursor.execute("SELECT goal_id FROM event_goal_admissions")
                        assert cursor.fetchall() == [(beta[0],)]
                        cursor.execute("SELECT trigger_key FROM event_trigger_batches")
                        assert cursor.fetchall() == []
                with tenant_scope(tenant=None), world._tx() as cursor:
                    cursor.execute("SELECT goal_id FROM event_goal_admissions")
                    assert cursor.fetchall() == []
        finally:
            admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
