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
