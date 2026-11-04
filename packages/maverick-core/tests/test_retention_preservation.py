"""Internal preservation gates; authored for deferred execution."""
import contextlib
import hashlib
import json
import sqlite3

import pytest
from maverick.audit import preservation, retention


def test_preservation_reads_every_case_even_when_feature_disabled(tmp_path, monkeypatch):
    from maverick import paths
    path = tmp_path / "rights.sqlite3"
    monkeypatch.setattr(paths, "data_dir", lambda *a, **kw: path)
    monkeypatch.setattr(paths, "current_tenant_id", lambda: "workspace")
    with contextlib.closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE rights_cases(tenant_id TEXT,case_id TEXT,payload_json TEXT,integrity_sha256 TEXT)")
        for n in range(1002):
            payload = {"tenant_id": "workspace", "legal_hold": n == 1001, "retention_blocks_deletion": False}
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            connection.execute("INSERT INTO rights_cases VALUES(?,?,?,?)", ("workspace", str(n), encoded, hashlib.sha256(encoded.encode()).hexdigest()))
    snapshot = preservation.preservation_snapshot()
    assert snapshot["blocked"]
    assert snapshot["legal_holds"] == 1
    assert "case_id" not in snapshot


def test_core_purge_fails_closed_for_hold_and_unreadable_ledger(monkeypatch):
    calls = []
    monkeypatch.setattr(retention, "purge_world_messages", lambda **kw: calls.append(kw))
    monkeypatch.setattr(preservation, "preservation_snapshot", lambda: {"blocked": True})
    with pytest.raises(retention.RetentionScopeError):
        retention.enforce(config={"messages_days": 1}, _fleet_child=True)
    assert calls == []
    def unavailable():
        raise OSError("locked")
    monkeypatch.setattr(preservation, "preservation_snapshot", unavailable)
    with pytest.raises(retention.RetentionScopeError):
        retention.enforce(config={"messages_days": 1}, _fleet_child=True)
    assert calls == []


# ---- maverick gc and the Tidy up action honour privacy-rights case holds ----------

class _RecordingWorld:
    """Stands in for a world model; records every broad purge that reaches it."""

    def __init__(self):
        self.calls = []

    def prune_conversations(self, **kwargs):
        self.calls.append(("conversations", kwargs))
        return 1

    def prune_goal_events(self, **kwargs):
        self.calls.append(("activity", kwargs))
        return 2

    def prune_processed_messages(self, **kwargs):
        self.calls.append(("duplicate_checks", kwargs))
        return 3

    def purge_goal_events_before(self, cutoff, dry_run=False):
        return 0


def _rights_ledger(path, cases):
    with contextlib.closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE rights_cases(tenant_id TEXT,case_id TEXT,payload_json TEXT,integrity_sha256 TEXT)")
        for case_id, payload in cases:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            connection.execute("INSERT INTO rights_cases VALUES(?,?,?,?)",
                               (payload["tenant_id"], case_id, encoded, hashlib.sha256(encoded.encode()).hexdigest()))


@pytest.fixture()
def privacy_ledger(tmp_path, monkeypatch):
    """The privacy-rights ledger, kept under the test's temp directory, inside workspace ``workspace``."""
    from maverick import ediscovery, paths

    path = tmp_path / "rights.sqlite3"
    real_data_dir = paths.data_dir
    monkeypatch.setattr(paths, "data_dir", lambda *parts, **kw: path if parts[:1] == ("privacy_automation",)
                        else real_data_dir(*parts, **kw))
    monkeypatch.setattr(ediscovery, "store_path", lambda tenant=None: tmp_path / "matters.sqlite3")
    with paths.tenant_scope(tenant="workspace"):
        yield path


@pytest.mark.parametrize("flag", ["legal_hold", "retention_blocks_deletion"])
def test_recorded_privacy_rights_hold_pauses_every_broad_purge(privacy_ledger, flag):
    from maverick import records_gc
    from maverick.ediscovery import LegalHoldApplies

    payload = {"tenant_id": "workspace", "legal_hold": False, "retention_blocks_deletion": False, flag: True}
    _rights_ledger(privacy_ledger, [("case-1", payload)])
    world = _RecordingWorld()
    with pytest.raises(LegalHoldApplies) as refused:
        records_gc.prune_world(world, days=1, events_days=1)
    assert str(refused.value) == "Recorded preservation holds block broad deletion in this workspace."
    assert world.calls == []


def test_unverifiable_privacy_rights_ledger_fails_closed_for_broad_purge(privacy_ledger):
    from maverick import records_gc
    from maverick.ediscovery import LegalHoldApplies

    privacy_ledger.write_bytes(b"this is not a sqlite ledger")
    world = _RecordingWorld()
    with pytest.raises(LegalHoldApplies) as refused:
        records_gc.prune_world(world, days=1, events_days=1)
    assert str(refused.value) == "Preservation holds could not be verified; no records were deleted."
    assert world.calls == []


def test_without_a_recorded_hold_broad_purge_removes_what_it_always_did(privacy_ledger):
    from maverick import records_gc

    world = _RecordingWorld()
    assert records_gc.prune_world(world, days=1, events_days=1) == (1, 2, 3)  # no ledger file at all
    assert [name for name, _ in world.calls] == ["conversations", "activity", "duplicate_checks"]

    _rights_ledger(privacy_ledger, [("case-1", {"tenant_id": "workspace", "legal_hold": False,
                                                 "retention_blocks_deletion": False})])
    world = _RecordingWorld()
    assert records_gc.prune_world(world, days=1, events_days=1) == (1, 2, 3)
    assert len(world.calls) == 3


def test_sweep_reports_a_privacy_rights_held_workspace_in_preview_and_run(privacy_ledger, monkeypatch):
    from types import SimpleNamespace

    from maverick import paths, records_gc
    from maverick.audit import preservation

    held = {"ws-a": True, "ws-b": False}
    monkeypatch.setattr(preservation, "preservation_snapshot",
                        lambda: {"blocked": held[paths.current_tenant_id()]})
    tenants = [SimpleNamespace(id="ws-a", display_name="Acme"), SimpleNamespace(id="ws-b", display_name="Beta")]
    worlds = {}

    def open_world():
        return worlds.setdefault(paths.current_tenant_id(), _RecordingWorld())

    for dry_run in (True, False):
        rows = {row["workspace"]: row for row in records_gc.sweep_workspaces(
            tenants, days=1, events_days=1, dry_run=dry_run, open_world=open_world)}
        assert rows["ws-a"]["held"] is True and rows["ws-a"]["conversations"] == 0
        assert rows["ws-a"]["activity"] == 0
        assert "held" not in rows["ws-b"]
        if not dry_run:
            assert rows["ws-b"]["conversations"] == 1
    assert worlds["ws-a"].calls == []
    assert [name for name, _ in worlds["ws-b"].calls] == ["conversations", "activity", "duplicate_checks"]


def test_maverick_gc_is_refused_under_a_recorded_hold_and_runs_without_one(privacy_ledger, tmp_path):
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    WorldModel(db).close()
    _rights_ledger(privacy_ledger, [("case-1", {"tenant_id": "workspace", "legal_hold": True,
                                                 "retention_blocks_deletion": False})])
    refused = CliRunner().invoke(cli_mod.main, ["--db", str(db), "gc", "--yes"])
    assert refused.exit_code != 0
    assert "Recorded preservation holds block broad deletion in this workspace." in refused.output

    privacy_ledger.unlink()  # no privacy-rights case is recorded any more
    ran = CliRunner().invoke(cli_mod.main, ["--db", str(db), "gc", "--yes"])
    assert ran.exit_code == 0, ran.output
    assert "pruned 0 conversation(s)" in ran.output


def test_hold_check_closes_every_ledger_connection(privacy_ledger, monkeypatch):
    """``with sqlite3.connect(...)`` commits but never closes, and CPython frees the
    connection only in a later cyclic GC pass, so the gc hold check kept the
    privacy-rights ledger open and unlink failed on Windows (WinError 32). Every
    connection the check opens must be closed when it returns."""
    from maverick import records_gc
    from maverick.ediscovery import LegalHoldApplies

    _rights_ledger(privacy_ledger, [("case-1", {"tenant_id": "workspace", "legal_hold": True,
                                                 "retention_blocks_deletion": False})])
    opened = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", recording_connect)
    try:
        with pytest.raises(LegalHoldApplies):
            records_gc.prune_world(_RecordingWorld(), days=1, events_days=1)
        assert opened, "the hold check should read the privacy-rights ledger"
        for connection in opened:
            with pytest.raises(sqlite3.ProgrammingError):  # a closed connection refuses work
                connection.execute("SELECT 1")
    finally:
        for connection in opened:
            connection.close()
