"""`maverick doctor` must exit nonzero when a check fails, and report the
world DB the runtime actually opens.

(1) Red ✗ rows must make doctor exit nonzero, so `maverick doctor && deploy`
and CI health gates can detect a broken install; (2) the world-db row must not
use a frozen ~/.maverick/world.db, or under MAVERICK_HOME or a tenant it would
report a path the runtime never touches.
"""
from __future__ import annotations

import maverick.health as h
from click.testing import CliRunner
from maverick.cli import main


def test_doctor_exits_nonzero_when_a_check_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    res = CliRunner().invoke(main, ["doctor"])
    # No provider key configured -> at least one ✗ row -> nonzero exit.
    assert res.exit_code == 1, res.output
    assert "need attention" in res.output


def test_diagnose_returns_zero_when_every_check_is_green(monkeypatch):
    # Force every check to emit no ✗ row; diagnose() must return 0 (exit 0).
    monkeypatch.setattr(h, "_check_config", dict)
    monkeypatch.setattr(h, "_check_anthropic", lambda: h._row(h.GREEN, "anthropic", "ok"))
    monkeypatch.setattr(h, "_check_openai", lambda: None)
    monkeypatch.setattr(h, "_check_sandbox", lambda cfg: None)
    monkeypatch.setattr(h, "_check_channels", lambda cfg: None)
    monkeypatch.setattr(h, "_check_world_db", lambda: None)
    monkeypatch.setattr(h, "_check_shield", lambda: None)
    assert h.diagnose() == 0


def test_diagnose_counts_each_failed_check(monkeypatch):
    monkeypatch.setattr(h, "_check_config", dict)
    monkeypatch.setattr(h, "_check_anthropic", lambda: h._row(h.RED, "anthropic", "no key"))
    monkeypatch.setattr(h, "_check_openai", lambda: None)
    monkeypatch.setattr(h, "_check_sandbox", lambda cfg: h._row(h.RED, "sandbox", "broken"))
    monkeypatch.setattr(h, "_check_channels", lambda cfg: None)
    monkeypatch.setattr(h, "_check_world_db", lambda: None)
    monkeypatch.setattr(h, "_check_shield", lambda: None)
    assert h.diagnose() == 2  # two ✗ rows


def test_doctor_world_db_row_follows_maverick_home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    res = CliRunner().invoke(main, ["doctor"])
    # The world-db row must point under MAVERICK_HOME, not ~/.maverick.
    assert f"{tmp_path}" in res.output


def test_channel_check_skips_scalar_entries(monkeypatch):
    rows = []
    monkeypatch.setattr(h, "_row", lambda *a, **k: rows.append(a))
    h._check_channels({"channels": {"default": "slack"}})
    assert rows == []


def test_doctor_does_not_look_for_records_without_a_workspace_on_sqlite(monkeypatch, tmp_path):
    """Only a shared Postgres store mixes workspaces in one table; a SQLite
    world has one file per workspace, so the doctor never runs that check."""
    from maverick.world_model_backends import pg_rls

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.setattr(pg_rls, "shared_legacy_rows",
                        lambda world: (_ for _ in ()).throw(AssertionError("checked on SQLite")))
    rows = []
    monkeypatch.setattr(h, "_row", lambda *a, **k: rows.append(a))
    h._check_world_db()
    assert [r[1] for r in rows] == ["world-db"] and rows[0][0] == h.GREEN


def _workspace(tenant_id, plan):
    from maverick.tenant.registry import create_tenant
    return create_tenant(tenant_id, plan=plan, allocate_suffix=True)


def test_doctor_reports_the_owner_workspace_the_cli_uses(monkeypatch, tmp_path):
    """After owner setup the CLI and dashboard share the owner's workspace."""
    from maverick.billing import SELF_HOSTED_PLAN

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    rec = _workspace("local", SELF_HOSTED_PLAN)
    res = CliRunner().invoke(main, ["doctor"])
    assert str(tmp_path / "tenants" / rec.id / "world.db") in res.output
    assert f"commands here use the {rec.id} workspace" in res.output


def test_doctor_warns_when_cli_work_lands_outside_every_workspace(monkeypatch, tmp_path):
    from maverick.billing import SELF_HOSTED_PLAN

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    _workspace("local", SELF_HOSTED_PLAN)
    _workspace("acme", "free")
    res = CliRunner().invoke(main, ["doctor"])
    assert "commands here use the shared space" in res.output
    assert "do not show in a workspace" in res.output
