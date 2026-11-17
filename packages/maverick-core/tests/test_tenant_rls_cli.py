"""`maverick tenant rls-preflight` / `tenant backfill` CLI wiring.

The DB work is unit-tested in test_pg_rls.py against a fake connection; here we
just assert the CLI resolves the DSN, surfaces the report, and fails cleanly with
no DSN -- monkeypatching pg_rls so no live Postgres is needed.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.world_model_backends import pg_rls


class _Conn:
    def close(self):
        pass


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)


def test_preflight_no_dsn_errors():
    res = CliRunner().invoke(main, ["tenant", "rls-preflight"])
    assert res.exit_code == 2
    assert "no Postgres DSN" in res.output


def test_preflight_reports_ownership_and_legacy_rows(monkeypatch):
    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "preflight", lambda conn: {
        "role": "app",
        "tables": {"goals": {"owner": "app", "owned_by_current_role": True,
                             "null_tenant_rows": 5},
                   "event_trigger_batches": {"owner": "app", "owned_by_current_role": True,
                                             "null_tenant_rows": 0, "empty_tenant_rows": 2}},
        "ready": False,
    })
    res = CliRunner().invoke(main, ["tenant", "rls-preflight"])
    assert res.exit_code == 0, res.output
    assert "role: app" in res.output
    assert "goals: owned, 5 legacy NULL-tenant row(s)" in res.output
    assert "2 legacy empty-tenant event row(s)" in res.output
    assert "NOT READY" in res.output


def test_preflight_says_how_it_counted_and_what_it_could_not(monkeypatch):
    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "preflight", lambda conn: {
        "role": "app",
        "tables": {"goals": {"owner": "app", "owned_by_current_role": True,
                             "null_tenant_rows": 0, "empty_tenant_rows": 0,
                             "counted_by": "owner_no_force"},
                   "facts": {"owner": "dba", "owned_by_current_role": False,
                             "null_tenant_rows": None, "empty_tenant_rows": None,
                             "counted_by": None}},
        "ready": False,
    })
    res = CliRunner().invoke(main, ["tenant", "rls-preflight"])
    assert res.exit_code == 0, res.output
    assert "counted as: " + pg_rls.COUNT_METHODS["owner_no_force"] in res.output
    assert "facts: NOT owned (owner=dba), NOT COUNTED" in res.output
    assert "Some tables were not counted" in res.output
    assert "NOT READY" in res.output


def test_preflight_names_a_busy_table_without_blaming_the_login(monkeypatch):
    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "preflight", lambda conn: {
        "role": "app",
        "tables": {"goals": {"owner": "app", "owned_by_current_role": True,
                             "null_tenant_rows": None, "empty_tenant_rows": None,
                             "counted_by": None, "not_counted": "busy"}},
        "orphans": {"questions": {"rows": 3, "parent": "goals", "counted_by": "owner",
                                  "not_counted": None}},
        "ready": False,
    })
    res = CliRunner().invoke(main, ["tenant", "rls-preflight"])
    assert "goals: owned, could not count: the table was busy" in res.output
    assert "hides" not in res.output and "Run this check as the table owner" not in res.output
    assert "Run the check again" in res.output
    assert "questions: 3 row(s) with no goals row" in res.output
    assert "orphaned rows no workspace can see" in res.output


def test_preflight_ready_says_ready(monkeypatch):
    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "preflight", lambda conn: {
        "role": "app", "tables": {}, "ready": True,
    })
    res = CliRunner().invoke(main, ["tenant", "rls-preflight"])
    assert res.exit_code == 0, res.output
    assert "READY: set [world_model] rls = true" in res.output


def test_backfill_reports_assigned_rows(monkeypatch):
    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "backfill",
                        lambda conn, tid, dry_run=False: {"goals": 3, "facts": 2})
    res = CliRunner().invoke(main, ["tenant", "backfill", "--tenant", "acme"])
    assert res.exit_code == 0, res.output
    assert "assigned 5 row(s) to tenant 'acme'" in res.output


def test_backfill_requires_tenant():
    res = CliRunner().invoke(main, ["tenant", "backfill"])
    assert res.exit_code != 0
    assert "tenant" in res.output.lower()


def test_backfill_no_dsn_errors():
    res = CliRunner().invoke(main, ["tenant", "backfill", "--tenant", "acme"])
    assert res.exit_code == 2
    assert "no Postgres DSN" in res.output


def test_backfill_says_writes_wait_and_how_long_it_may_take(monkeypatch):
    """The backfill holds back writes to the records it re-seals. The help,
    the preview and the real run each say so, and the preview gives the count
    of encrypted values and a rough duration."""
    class Report(dict):
        encrypted_values = 250_000

    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "backfill", lambda conn, tid, dry_run=False: Report(goals=3))
    runner = CliRunner()
    help_text = " ".join(runner.invoke(main, ["tenant", "backfill", "--help"]).output.split())
    assert "wait while it runs" in help_text and "quiet period" in help_text
    preview = runner.invoke(main, ["tenant", "backfill", "--tenant", "acme", "--dry-run"]).output
    assert "250,000 encrypted value(s) would be re-sealed" in preview
    assert "about 1 minute" in preview and "wait while it runs" in preview
    real = runner.invoke(main, ["tenant", "backfill", "--tenant", "acme"]).output
    assert real.index("wait until this finishes") < real.index("assigned 3 row(s)")
    assert "250,000 encrypted value(s) re-sealed" in real


@pytest.mark.parametrize("sqlstate, words", [
    ("55P03", "busy writing"), ("40P01", "collided with other work"), (None, "stopped the backfill")])
def test_backfill_database_error_is_reported_in_plain_words(monkeypatch, sqlstate, words):
    """A lock timeout, a deadlock or a dropped connection is not a traceback:
    the command says that nothing was changed and that it can run again."""
    class DatabaseError(Exception):
        pass

    def stopped(conn, tid, dry_run=False):
        error = DatabaseError("canceling statement due to lock timeout")
        error.sqlstate = sqlstate
        raise error

    monkeypatch.setattr(pg_rls, "resolve_dsn", lambda dsn=None: "x")
    monkeypatch.setattr(pg_rls, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pg_rls, "backfill", stopped)
    res = CliRunner().invoke(main, ["tenant", "backfill", "--tenant", "acme"])
    assert res.exit_code == 2 and res.exception.__class__ is SystemExit, res.output
    assert words in res.output and "Nothing was changed" in res.output
    assert "run it again" in res.output and "Traceback" not in res.output
    # Anything that is not a database error is still raised as it was.
    monkeypatch.setattr(pg_rls, "backfill", lambda *a, **k: (_ for _ in ()).throw(KeyError("bug")))
    assert isinstance(CliRunner().invoke(main, ["tenant", "backfill", "--tenant", "acme"]).exception,
                      KeyError)
