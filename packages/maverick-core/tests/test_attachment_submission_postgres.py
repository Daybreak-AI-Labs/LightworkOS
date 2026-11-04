"""Native PostgreSQL receipts, concurrent quotas and non-bypass RLS isolation."""
from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import attachments
from maverick.attachment_submissions import SubmissionStore
from maverick.paths import tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"), reason="requires isolated PostgreSQL fixture")


def _create(world):
    return SubmissionStore(world).create(token="same-request", fingerprint="a" * 64, owner="user:alice",
                                         title="Review", description="Private source", manifest=[])


def test_native_submission_is_in_signed_erasure_scope_and_cascades(postgres_test_dsn):
    from maverick.erasure_receipts import build_manifest, load_verified_receipt, persist_receipt

    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        receipt = _create(world)
        conversation = world.get_or_create_conversation("web", "alice")
        world.append_turn(conversation.id, "user", "private source", goal_id=receipt["goal_id"])
        plan = world.plan_conversation_erasure([conversation.id])
        signed = persist_receipt(world, build_manifest(
            tenant_id="shared", conversation_ids=plan["conversation_ids"],
            goal_ids=plan["goal_ids"], episode_ids=plan["episode_ids"],
        ))
        assert "attachment_submissions" in signed["expected_stores"]
        assert "same-request" not in str(signed) and "user:alice" not in str(signed)
        assert world.count_erasure_receipt_store(
            "attachment_submissions", plan["conversation_ids"], plan["goal_ids"], plan["episode_ids"],
        ) == 1
        world.erase_conversations([conversation.id], expected_goal_ids=plan["goal_ids"])
        recovered = load_verified_receipt(world, signed["receipt_id"], expected_tenant="shared")
        assert recovered == signed
        assert world.count_erasure_receipt_store(
            "attachment_submissions", recovered["conversation_ids"], recovered["goal_ids"], recovered["episode_ids"],
        ) == 0
        assert SubmissionStore(world).lookup(token="same-request", owner="user:alice") is None


def test_native_postgres_atomic_retry_and_concurrent_quota(postgres_test_dsn, monkeypatch, tmp_path):
    monkeypatch.setattr(attachments, "MAX_GOAL_BYTES", 5)
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        first = _create(world)
        assert world.get_goal(first["goal_id"]).status == "draft"
    def submit(index):
        with PostgresWorldModel(dsn=postgres_test_dsn) as world:
            receipt = _create(world)
            try:
                attachment = world.add_attachment(receipt["goal_id"], f"{index}.txt", "text/plain", 3,
                                                  hashlib.sha256(str(index).encode()).hexdigest(), str(tmp_path / f"{index}.txt"))
            except attachments.AttachmentRejected:
                attachment = None
            return receipt["goal_id"], attachment
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(submit, range(3)))
    assert {goal for goal, _ in results} == {first["goal_id"]}
    assert sum(attachment is not None for _, attachment in results) == 1
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        assert len(world.list_goals()) == 1 and len(world.list_attachments(first["goal_id"])) == 1
        store = SubmissionStore(world)
        store.update(first["key"], state="ready", message="Ready")
        assert store.claim_dispatch(first["key"])
        assert not store.claim_dispatch(first["key"])


def test_native_postgres_receipt_error_rolls_back_goal(postgres_test_dsn, monkeypatch):
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        store = SubmissionStore(world)
        execute = store.execute
        def fail(connection, sql, parameters=()):
            if sql.startswith("INSERT INTO attachment_submissions"):
                raise OSError("receipt unavailable")
            return execute(connection, sql, parameters)
        monkeypatch.setattr(store, "execute", fail)
        with pytest.raises(OSError):
            store.create(token="failure", fingerprint="a" * 64, owner="user:alice", title="Review", description="Source", manifest=[])
        assert world.list_goals() == []


def test_native_postgres_api_key_atomic_admission_and_read_reconciliation(postgres_test_dsn):
    from fastapi import HTTPException
    from maverick_dashboard.api_schemas import GoalIn
    from maverick_dashboard.goal_submission import lookup_receipt, reserve_api

    def reserve(index):
        with PostgresWorldModel(dsn=postgres_test_dsn) as world:
            return reserve_api(world, key="api-original-key", owner="user:alice",
                payload=GoalIn(title="Review", max_dollars=1),
                title="Review", description="Complete instructions", domain=None, caps={"max_dollars": 1})

    with ThreadPoolExecutor(max_workers=3) as executor:
        receipts = list(executor.map(reserve, range(6)))
    assert len({r["goal_id"] for r in receipts}) == 1 and sum(r["created"] for r in receipts) == 1
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        receipt, goal = lookup_receipt(world, key="api-original-key", owner="user:alice", kind="api")
        assert receipt["state"] == goal.status == "draft"  # acceptance never claims execution
        assert len(world.list_goals()) == 1
        with pytest.raises(HTTPException) as denied:
            lookup_receipt(world, key="api-original-key", owner="user:bob", kind="api")
        assert denied.value.status_code == 404
        with pytest.raises(HTTPException) as conflict:
            reserve_api(world, key="api-original-key", owner="user:alice",
                payload=GoalIn(title="Review", max_dollars=2),
                title="Review", description="Complete instructions", domain=None, caps={"max_dollars": 2})
        assert conflict.value.status_code == 409 and len(world.list_goals()) == 1


def test_native_non_bypass_rls_hides_other_tenant_receipts_and_rejects_attachment(postgres_test_dsn, monkeypatch, tmp_path):
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    role = "mvk_submission_" + uuid.uuid4().hex[:12]
    password = secrets.token_urlsafe(24)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE")
                      .format(sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
            dsn = make_conninfo(postgres_test_dsn, user=role, password=password, options=f"-c search_path={role}")
            monkeypatch.setenv("MAVERICK_PG_RLS", "1")
            monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
            with PostgresWorldModel(dsn=dsn) as world:
                with tenant_scope(tenant="tenant-a"):
                    first = _create(world)
                    assert SubmissionStore(world).for_goal(first["goal_id"])["key"] == first["key"]
                    assert SubmissionStore(world).lookup(token="same-request", owner="user:alice")["goal_id"] == first["goal_id"]
                    assert SubmissionStore(world).lookup(token="same-request", owner="user:bob") is None
                with tenant_scope(tenant="tenant-b"):
                    second = _create(world)
                    assert second["goal_id"] != first["goal_id"]
                    store = SubmissionStore(world)
                    assert store.for_goal(first["goal_id"]) is None
                    assert store.lookup(token="same-request", owner="user:alice")["goal_id"] == second["goal_id"]
                    assert not store.claim_dispatch(first["key"])
                    with pytest.raises(attachments.AttachmentRejected):
                        world.add_attachment(first["goal_id"], "other.txt", "text/plain", 3, "0" * 64, str(tmp_path / "other.txt"))
                    with world._tx() as cursor:
                        cursor.execute("SELECT goal_id FROM attachment_submissions")
                        assert cursor.fetchall() == [(second["goal_id"],)]
        finally:
            admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
