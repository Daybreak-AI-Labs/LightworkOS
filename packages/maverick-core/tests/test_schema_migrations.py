"""Online schema migrations: statement classification, plan, gate, lint."""
from __future__ import annotations

from maverick.schema_migrations import (
    classify,
    online_only,
    plan,
    render,
    validate,
)


def test_classify_online_shapes():
    assert classify("ALTER TABLE approvals ADD COLUMN claimed_by TEXT") == "online"
    assert classify("CREATE INDEX IF NOT EXISTS idx_x ON t(a)") == "online"
    assert classify("CREATE TABLE IF NOT EXISTS t (id INTEGER)") == "online"
    assert (
        classify("CREATE TRIGGER IF NOT EXISTS immutable BEFORE UPDATE ON t BEGIN "
                 "SELECT RAISE(ABORT, 'immutable'); END")
        == "online"
    )
    assert classify("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')") == "online"
    assert classify("") == "online"  # documented placeholder bump
    assert classify("   ") == "online"


def test_classify_offline_shapes():
    assert classify("ALTER TABLE t DROP COLUMN old") == "offline"
    assert classify("ALTER TABLE t RENAME TO t2") == "offline"
    assert classify("CREATE INDEX idx ON t(a)") == "offline"      # not IF NOT EXISTS
    assert classify("CREATE TABLE t (id INTEGER)") == "offline"   # not IF NOT EXISTS
    assert classify("CREATE TRIGGER immutable BEFORE UPDATE ON t BEGIN END") == "offline"
    assert classify("UPDATE t SET a = 1") == "offline"
    assert classify("DELETE FROM t WHERE a = 1") == "offline"
    assert classify("DROP TABLE t") == "offline"
    assert classify("DROP TRIGGER immutable") == "offline"


def test_classify_unknown_fails_closed():
    assert classify("PRAGMA foreign_keys = ON") == "unknown"


def test_plan_orders_pending_steps():
    migs = {
        2: ["ALTER TABLE t ADD COLUMN a TEXT"],
        3: ["CREATE INDEX IF NOT EXISTS i ON t(a)", "UPDATE t SET a = 'x'"],
    }
    steps = plan(1, 3, migrations=migs)
    assert [s.version for s in steps] == [2, 3, 3]
    assert [s.kind for s in steps] == ["online", "online", "offline"]
    # Nothing pending when already current.
    assert plan(3, 3, migrations=migs) == []


def test_online_only_gate():
    online = plan(1, 2, migrations={2: ["ALTER TABLE t ADD COLUMN a TEXT"]})
    assert online_only(online) is True
    mixed = plan(1, 2, migrations={2: ["UPDATE t SET a = 1"]})
    assert online_only(mixed) is False
    # unknown fails closed.
    unk = plan(1, 2, migrations={2: ["VACUUM"]})
    assert online_only(unk) is False


def test_validate_real_migration_table():
    # The shipped world-model migration table must be clean.
    assert validate() == []


def test_validate_detects_gaps_and_unclassifiable():
    bad = {1: [], 3: ["ALTER TABLE t ADD COLUMN a TEXT"]}  # missing v2
    problems = validate(bad)
    assert any("non-contiguous" in p for p in problems)
    unk = {1: ["WHO KNOWS WHAT THIS IS"]}
    assert any("unclassifiable" in p for p in validate(unk))


def test_render():
    assert "no pending migrations" in render([])
    online = plan(1, 2, migrations={2: ["ALTER TABLE t ADD COLUMN a TEXT"]})
    assert "ONLINE-SAFE" in render(online)
    offline = plan(1, 2, migrations={2: ["UPDATE t SET a = 1"]})
    assert "MAINTENANCE WINDOW" in render(offline)


def test_schema_plan_command_registered():
    from maverick.cli import main
    assert "schema-plan" in main.commands


def test_schema_plan_command_runs(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick import cli as cli_mod
    r = CliRunner().invoke(cli_mod.main, ["schema-plan"])
    assert r.exit_code == 0, r.output
    # A fresh DB opens already-current -> nothing pending.
    assert "current" in r.output or "pending" in r.output


def test_ci_gate_passes_on_the_shipped_table():
    from maverick.schema_migrations import main
    assert main(["--ci"]) == 0  # the shipped migrations lint clean


def test_ci_gate_fails_on_an_unclassifiable_migration(monkeypatch):
    from maverick import schema_migrations as sm
    monkeypatch.setattr(sm, "_default_migrations",
                        lambda: {1: ["ALTER TABLE t ADD COLUMN a TEXT"], 2: ["PRAGMA foo"]})
    assert sm.main(["--ci"]) == 1
    # Without --ci it reports the problem but does not fail the build.
    assert sm.main([]) == 0
