"""Native local PostgreSQL channel journal authority and independent workers."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import crypto_at_rest, governed_records
from maverick.config import reset_config_cache
from maverick.paths import tenant_scope
from maverick_channels.base import IncomingMessage
from maverick_channels.delivery import DeliveryJournal


@pytest.fixture
def channel_pg_dsn(postgres_test_dsn):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    name = "mvk_ch_" + uuid.uuid4().hex[:16]
    password = secrets.token_urlsafe(32)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS").format(
            sql.Identifier(name), sql.Literal(password)))
        connection.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(name), sql.Identifier(name)))
    try:
        yield make_conninfo(postgres_test_dsn, user=name, password=password, options=f"-c search_path={name}")
    finally:
        with psycopg.connect(postgres_test_dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))
            connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
def pg_authority(channel_pg_dsn, monkeypatch, tmp_path):
    key = hashlib.sha256(b"channel-delivery-native-pg-fixture").digest()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", channel_pg_dsn)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    reset_config_cache()
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    yield
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    reset_config_cache()


def _admit(tenant="tenant-a", account="fixture-account"):
    with tenant_scope(tenant=tenant):
        journal = DeliveryJournal()
        assert journal.store._backend().kind == "postgres"
        return journal.admit(IncomingMessage(user_id="alice", text="Question", channel="fixture"),
                             external_id="provider-id", account=account)


def test_native_channel_intake_and_execution_claim_have_one_owner(pg_authority):
    # Initialize schema before concurrent workers, matching startup qualification.
    first = _admit()
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(lambda _: _admit(), range(8)))
    assert {row["id"] for row in receipts} == {first["id"]}

    def claim(_):
        with tenant_scope(tenant="tenant-a"):
            journal = DeliveryJournal()
            return journal.claim_execution(journal.get(first["id"]))
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(claim, range(8)))
    assert sum(row is not None for row in claims) == 1


def test_native_channel_tenant_and_account_identity_never_cross(pg_authority):
    first, other_account, other_tenant = _admit(), _admit(account="other-account"), _admit(tenant="tenant-b")
    assert len({first["id"], other_account["id"], other_tenant["id"]}) == 3
    with tenant_scope(tenant="tenant-b"):
        journal = DeliveryJournal()
        assert journal.get(first["id"]) is None
        assert journal.claim_execution(other_tenant)
    with tenant_scope(tenant="tenant-a"):
        journal = DeliveryJournal()
        assert journal.get(other_tenant["id"]) is None
        assert journal.claim_execution(first)
        assert journal.claim_execution(other_account)
