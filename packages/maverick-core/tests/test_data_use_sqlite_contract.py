"""Shared persistence guarantees of the two data-use authorities."""

import os
import sqlite3
import stat
import sys

import pytest
from maverick.data_use_governance import DataUseGovernanceStore
from maverick.data_use_provider_adapters import ProviderBindingStore
from maverick.sqlite_authority import configure_authority_connection


@pytest.fixture(params=[DataUseGovernanceStore, ProviderBindingStore])
def store(request, tmp_path):
    return request.param(tmp_path / "authority" / "authority.sqlite")


def test_private_connection_configuration_and_closure(store):
    if os.name == "posix":
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    with store._connect() as conn:
        assert conn.isolation_level is None
        assert conn.row_factory is sqlite3.Row
        expected = {
            "busy_timeout": 10000,
            "journal_mode": "delete",
            "synchronous": 2,
            "foreign_keys": 1,
            "trusted_schema": 0,
            "secure_delete": 1,
        }
        for pragma, value in expected.items():
            assert conn.execute(f"PRAGMA {pragma}").fetchone()[0] == value
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        conn.execute("SELECT 1")


def test_immediate_transaction_commits_rolls_back_and_excludes_other_writers(store):
    with store._connect() as conn:
        conn.execute("CREATE TABLE contract_probe (value TEXT)")
    with store._transaction() as conn:
        conn.execute("INSERT INTO contract_probe VALUES ('committed')")
        with sqlite3.connect(store.path, timeout=0, isolation_level=None) as other:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")

    with pytest.raises(KeyboardInterrupt), store._transaction() as conn:
        conn.execute("INSERT INTO contract_probe VALUES ('rolled back')")
        raise KeyboardInterrupt

    with store._connect() as conn:
        assert [row[0] for row in conn.execute("SELECT value FROM contract_probe")] == ["committed"]


def test_private_file_and_connection_overrides_remain_effective(store, monkeypatch):
    module = sys.modules[type(store).__module__]
    original_file_check = module.ensure_private_file
    original_connect = store._connect
    calls = []

    def check_file(path, mode):
        calls.append((path, mode))
        return original_file_check(path, mode)

    def connect():
        calls.append("connect")
        return original_connect()

    monkeypatch.setattr(module, "ensure_private_file", check_file)
    monkeypatch.setattr(store, "_connect", connect)
    with store._transaction() as conn:
        conn.execute("SELECT 1")
    assert calls == ["connect", (store.path, 0o600)]


@pytest.mark.parametrize("foreign_keys", [False, True])
def test_shared_authority_policy_preserves_foreign_key_choice(foreign_keys):
    with sqlite3.connect(":memory:") as conn:
        configure_authority_connection(conn, foreign_keys=foreign_keys)
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == int(foreign_keys)
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_shared_consent_authority_closes_connection_on_policy_failure(monkeypatch, tmp_path):
    from maverick import consent_storage

    class BrokenConnection:
        closed = False

        def execute(self, statement):
            if statement == "PRAGMA foreign_keys=ON":
                raise sqlite3.OperationalError("cannot apply policy")

        def close(self):
            self.closed = True

    connection = BrokenConnection()
    monkeypatch.setattr(consent_storage, "shared", lambda: True)
    monkeypatch.setattr(consent_storage, "connect", lambda *args, **kwargs: connection)
    with pytest.raises(sqlite3.OperationalError, match="cannot apply policy"):
        with consent_storage.authority_connection(
            tmp_path / "ignored.sqlite", ensure_directory=lambda path: None,
            ensure_file=lambda path, mode: None,
        ):
            pytest.fail("a failed policy must not expose a connection")
    assert connection.closed
