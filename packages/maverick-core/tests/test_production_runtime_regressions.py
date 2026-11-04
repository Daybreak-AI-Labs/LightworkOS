"""Production-start regressions: authority, recovery, logs and DB connections.

All stores are temporary and all connection objects are local test doubles.
"""
from __future__ import annotations

import logging
import sys
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from maverick import config, logging_config, orchestrator, outcome_pilot_start_gate
from maverick.budget import Budget
from maverick.world_model import WorldModel


@pytest.mark.parametrize("encoding", ["hex", "base64"])
def test_shared_key_digest_cli_hashes_decoded_key_without_exposing_it(monkeypatch, encoding):
    import base64
    import hashlib

    from click.testing import CliRunner
    from maverick.cli import main

    key = bytes(range(32))
    encoded = key.hex() if encoding == "hex" else base64.b64encode(key).decode("ascii")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", encoded)
    result = CliRunner().invoke(main, ["shared-key-digest"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == "sha256:" + hashlib.sha256(key).hexdigest()
    assert encoded not in result.output


def test_shared_key_digest_cli_refuses_missing_key(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    result = CliRunner().invoke(main, ["shared-key-digest"])
    assert result.exit_code == 1 and "not set" in result.output


@pytest.mark.parametrize("status", ["pending", "active", "in_progress", "running"])
def test_admission_failure_is_visible_for_authorized_runnable_goal(tmp_path, monkeypatch, status):
    def refuse(*_args):
        raise outcome_pilot_start_gate.OutcomePilotAdmissionRequired("admission unavailable")

    monkeypatch.setattr(outcome_pilot_start_gate, "require_work_item_admission", refuse)
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("work", owner="user:alice", execution_principal="user:alice")
        world.set_goal_status(goal_id, status)
        result = orchestrator.run_goal_sync(None, world, Budget(), goal_id, user_id="alice")
        assert result == "BLOCKED: admission unavailable"
        goal = world.get_goal(goal_id)
        assert goal.status == "blocked" and goal.result == "admission unavailable"
        assert world.list_episodes(goal_id=goal_id) == []


@pytest.mark.parametrize("status", ["blocked", "done", "cancelled", "failed"])
def test_admission_failure_preserves_recovery_and_terminal_results(tmp_path, monkeypatch, status):
    def refuse(*_args):
        raise outcome_pilot_start_gate.OutcomePilotAdmissionRequired("admission unavailable")

    monkeypatch.setattr(outcome_pilot_start_gate, "require_work_item_admission", refuse)
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("work", owner="user:alice", execution_principal="user:alice")
        world.set_goal_status(goal_id, status, result="retained recovery or completed result")
        before = world.get_goal(goal_id)
        events = world.goal_events(goal_id)
        orchestrator.run_goal_sync(None, world, Budget(), goal_id, user_id="alice")
        assert world.get_goal(goal_id) == before
        assert world.goal_events(goal_id) == events


def test_admission_failure_cannot_mutate_another_principals_goal(tmp_path, monkeypatch):
    def refuse(*_args):
        raise outcome_pilot_start_gate.OutcomePilotAdmissionRequired("admission unavailable")

    monkeypatch.setattr(outcome_pilot_start_gate, "require_work_item_admission", refuse)
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("work", owner="user:alice", execution_principal="user:alice")
        before = world.get_goal(goal_id)
        orchestrator.run_goal_sync(None, world, Budget(), goal_id, user_id="mallory")
        assert world.get_goal(goal_id) == before
        assert world.goal_events(goal_id) == []


def test_corrected_overlay_key_clears_error_without_rewriting_cached_toml(tmp_path, monkeypatch):
    path = tmp_path / config.DASHBOARD_OVERRIDES_BASENAME
    path.write_text('value = "MVKAR1:synthetic"\n', encoding="utf-8")

    def unavailable(_tree):
        raise ValueError("test key unavailable")

    monkeypatch.setattr(config, "_unseal_config_tree", unavailable)
    assert config._load_config_file(path) == {}
    assert str(path) in config._source_errors([path])
    cached = config._toml_cache[str(path)]
    monkeypatch.setattr(config, "_unseal_config_tree", lambda _tree: {"value": "recovered"})
    assert config._load_config_file(path) == {"value": "recovered"}
    assert config._toml_cache[str(path)] is cached
    assert config._source_errors([path]) == {}


def test_plaintext_fallback_does_not_clear_malformed_overlay_error(tmp_path):
    path = tmp_path / config.DASHBOARD_OVERRIDES_BASENAME
    path.write_text('[broken\n', encoding="utf-8")
    assert config._load_config_file(path) == {}
    assert str(path) in config._source_errors([path])


@pytest.mark.parametrize("formatter", [logging.Formatter, logging_config.JsonFormatter])
@pytest.mark.parametrize("cached_traceback", [False, True])
def test_text_and_json_logging_scrub_messages_and_cached_tracebacks(formatter, cached_traceback):
    synthetic_key = "sk-ant-" + "x" * 30
    try:
        raise ValueError("provider rejected " + synthetic_key)
    except ValueError:
        record = logging.LogRecord("test", logging.ERROR, __file__, 1,
                                   "response %s", (synthetic_key,), sys.exc_info())
    if cached_traceback:
        logging.Formatter().format(record)
    record.stack_info = "stack context " + synthetic_key
    assert logging_config._ContextFilter().filter(record)
    rendered = formatter().format(record)
    assert synthetic_key not in rendered
    assert "[REDACTED" in rendered
    assert "ValueError" in rendered
    assert synthetic_key not in record.stack_info


def _pg_world(monkeypatch, *, dsn="postgresql://localhost/test", pool_size=0):
    pytest.importorskip("psycopg")
    from maverick.postgres_io import BoundedConnection
    from maverick.world_model_backends import postgres

    calls = []

    def connect(value, **kwargs):
        calls.append((value, kwargs))
        return SimpleNamespace(closed=False)

    monkeypatch.setattr(BoundedConnection, "connect", connect)
    monkeypatch.setattr(postgres, "_pool_size", lambda: pool_size)
    monkeypatch.setattr(postgres, "_rls_enabled", lambda: False)
    monkeypatch.setattr(postgres.PostgresWorldModel, "_migrate", lambda _self: None)
    return postgres.PostgresWorldModel(dsn), calls


@pytest.mark.parametrize("existing", ["-c search_path=customer,public", "-c statement_timeout=123 -c search_path=customer,public"])
def test_postgres_retains_operator_options_and_timeouts_after_reconnect(monkeypatch, existing):
    monkeypatch.delenv("MAVERICK_PG_STATEMENT_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("MAVERICK_PG_IDLE_TX_TIMEOUT_MS", raising=False)
    monkeypatch.setenv("MAVERICK_PG_IO_TIMEOUT_SECONDS", "0.25")
    dsn = "postgresql://localhost/test?options=" + quote(existing, safe="")
    world, calls = _pg_world(monkeypatch, dsn=dsn)
    monkeypatch.setenv("MAVERICK_PG_IO_TIMEOUT_SECONDS", "1")
    world.conn.closed = True
    world._reconnect_if_broken()
    assert len(calls) == 2 and calls[0] == calls[1]
    options = calls[0][1]["options"]
    assert options.startswith(existing)
    assert options.count("statement_timeout=") == 1
    assert "idle_in_transaction_session_timeout=60000" in options
    assert calls[0][1]["autocommit"] is False
    assert calls[0][1]["io_timeout_seconds"] == 0.25


def test_postgres_timeout_detection_ignores_user_and_database_names(monkeypatch):
    monkeypatch.delenv("PGOPTIONS", raising=False)
    world, calls = _pg_world(monkeypatch, dsn="postgresql://statement_timeout@localhost/idle_in_transaction_session_timeout")
    assert "statement_timeout=30000" in calls[0][1]["options"]
    assert "idle_in_transaction_session_timeout=60000" in calls[0][1]["options"]
    assert world.path is None


@pytest.mark.parametrize("raw,expected", [("garbage", 30_000), ("-1", 30_000), ("2147483648", 30_000), ("0", 0), ("1500", 1500)])
def test_postgres_timeout_env_is_bounded(monkeypatch, raw, expected):
    monkeypatch.delenv("PGOPTIONS", raising=False)
    monkeypatch.setenv("MAVERICK_PG_STATEMENT_TIMEOUT_MS", raw)
    _world, calls = _pg_world(monkeypatch)
    assert f"statement_timeout={expected}" in calls[0][1]["options"]


def test_postgres_pool_keeps_libpq_environment_options(monkeypatch):
    pool_module = pytest.importorskip("psycopg_pool")
    monkeypatch.setenv("PGOPTIONS", "-c search_path=customer,public -cstatement_timeout=987")
    pools = []

    def pool(dsn, **kwargs):
        pools.append((dsn, kwargs))
        return SimpleNamespace()

    monkeypatch.setattr(pool_module, "ConnectionPool", pool)
    _world, direct = _pg_world(monkeypatch, pool_size=2)
    assert direct == [] and len(pools) == 1
    options = pools[0][1]["kwargs"]["options"]
    assert options.startswith("-c search_path=customer,public -cstatement_timeout=987")
    assert options.count("statement_timeout=") == 1
    assert "idle_in_transaction_session_timeout=60000" in options
