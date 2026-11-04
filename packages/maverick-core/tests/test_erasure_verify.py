"""Differential erasure verification: residual check + before/after proof."""
from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner
from maverick import erasure_verify
from maverick.cli import main
from maverick.world_model import WorldModel

# ---- differential (pure) ----

def test_differential_verified_when_after_clean_and_had_data():
    before = {"conversations": 1, "turns": 2, "goals": 1}
    after = {"conversations": 0, "turns": 0, "goals": 0}
    d = erasure_verify.differential(before, after)
    assert d["verified"] is True
    assert d["after_clean"] is True
    assert d["removed"]["turns"] == 2


def test_differential_not_verified_when_residual_remains():
    d = erasure_verify.differential({"turns": 2}, {"turns": 1})
    assert d["after_clean"] is False and d["verified"] is False
    assert d["removed"]["turns"] == 1


def test_differential_not_verified_when_nothing_to_remove():
    # after is clean but there was no data to begin with -> not a proof of erasure
    d = erasure_verify.differential({"turns": 0}, {"turns": 0})
    assert d["after_clean"] is True and d["verified"] is False


# ---- verify_erasure (over a monkeypatched export) ----

def test_verify_erasure_bare_zero_scan_is_indeterminate(monkeypatch):
    monkeypatch.setattr(
        "maverick.dsar.export_subject_data",
        lambda u, *, channel=None, tenant=None, strict=False: {
            "subject": {"user_id": u, "channel": channel},
            "counts": {"conversations": 0, "turns": 0, "goals": 0,
                       "episodes": 0, "audit_events": 0},
        },
    )
    rep = erasure_verify.verify_erasure("alice", channel="telegram")
    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["residual"] == {}
    assert rep["durable_proof"] is False
    assert rep["stores"]["conversations"] == {
        "checked": True,
        "count": 0,
        "error": None,
    }
    assert rep["stores"]["turns"]["checked"] is False
    assert "signed pre-delete erasure receipt" in rep["errors"]["turns"]


def test_verify_erasure_dirty(monkeypatch):
    monkeypatch.setattr(
        "maverick.dsar.export_subject_data",
        lambda u, *, channel=None, tenant=None, strict=False: {
            "subject": {"user_id": u, "channel": channel},
            "counts": {"conversations": 1, "turns": 3, "goals": 0},
        },
    )
    rep = erasure_verify.verify_erasure("alice", channel="telegram")
    assert rep["clean"] is False
    assert rep["residual"] == {"conversations": 1}
    assert rep["stores"]["conversations"] == {
        "checked": True,
        "count": 1,
        "error": None,
    }
    assert rep["stores"]["turns"]["checked"] is False


def test_verify_erasure_export_error_is_indeterminate(monkeypatch):
    def broken_export(*_args, **_kwargs):
        raise OSError("world database is locked")

    monkeypatch.setattr("maverick.dsar.export_subject_data", broken_export)
    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["conversations"]["checked"] is False
    assert rep["stores"]["conversations"]["count"] is None
    assert "world database is locked" in rep["stores"]["conversations"]["error"]
    assert "conversations" not in rep["counts"]


def test_verify_erasure_fact_store_error_is_not_zero(monkeypatch):
    monkeypatch.setattr(
        "maverick.dsar.export_subject_data",
        lambda user_id, *, channel=None, tenant=None, strict=False: {
            "subject": {"user_id": user_id, "channel": channel},
            "counts": {
                "conversations": 0,
                "turns": 0,
                "goals": 0,
                "episodes": 0,
                "audit_events": 0,
            },
        },
    )
    monkeypatch.setattr(
        "maverick.dsar._resolve_world",
        lambda _tenant, *, strict=False: None,
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["facts"] == {
        "checked": False,
        "count": None,
        "error": "RuntimeError: world-model fact store is unavailable",
    }
    assert "facts" not in rep["counts"]


def test_verify_erasure_configured_knowledge_error_is_not_zero(monkeypatch):
    monkeypatch.setattr(
        "maverick.dsar.export_subject_data",
        lambda user_id, *, channel=None, tenant=None, strict=False: {
            "subject": {"user_id": user_id, "channel": channel},
            "counts": {
                "conversations": 0,
                "turns": 0,
                "goals": 0,
                "episodes": 0,
                "audit_events": 0,
            },
        },
    )
    monkeypatch.setattr(erasure_verify, "_count_user_scoped_facts", lambda *a, **k: 0)
    monkeypatch.setattr("maverick.config.get_knowledge", lambda: {"enable": True})
    monkeypatch.setattr(
        "maverick.knowledge_admin.open_knowledge_base",
        lambda *, tenant=None, require_existing=False: None,
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["knowledge_chunks"] == {
        "checked": False,
        "count": None,
        "error": "KnowledgeUnavailable: configured knowledge store is unavailable",
    }
    assert "knowledge_chunks" not in rep["counts"]


def test_verify_erasure_missing_required_count_is_indeterminate(monkeypatch):
    monkeypatch.setattr(
        "maverick.dsar.export_subject_data",
        lambda user_id, *, channel=None, tenant=None, strict=False: {
            "subject": {"user_id": user_id, "channel": channel},
            "counts": {
                "conversations": 0,
                "turns": 0,
                "goals": 0,
                "episodes": 0,
            },
        },
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["stores"]["audit_events"]["checked"] is False
    assert "omitted required store" in rep["stores"]["audit_events"]["error"]


def test_internal_world_read_failure_is_indeterminate(monkeypatch):
    class BrokenWorld:
        def list_conversations(self, _channel):
            raise OSError("conversation index is corrupt")

        def facts_matching(self, _token):
            return {}

        def fact_history_matching(self, _token):
            return {}

    monkeypatch.setattr(
        "maverick.dsar._resolve_world",
        lambda _tenant, *, strict=False: BrokenWorld(),
    )
    monkeypatch.setattr(
        erasure_verify,
        "_count_user_scoped_facts",
        lambda *args, **kwargs: 0,
    )
    monkeypatch.setattr(
        erasure_verify,
        "_count_knowledge_chunks",
        lambda *args, **kwargs: 0,
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["conversations"]["checked"] is False
    assert "could not read subject conversations" in rep["errors"]["conversations"]


def test_internal_audit_read_failure_is_indeterminate(monkeypatch):
    class EmptyWorld:
        def list_conversations(self, _channel):
            return []

        def facts_matching(self, _token):
            return {}

        def fact_history_matching(self, _token):
            return {}

    def broken_audit_reader(*_args, **_kwargs):
        raise PermissionError("audit segment is unreadable")

    monkeypatch.setattr(
        "maverick.dsar._resolve_world",
        lambda _tenant, *, strict=False: EmptyWorld(),
    )
    monkeypatch.setattr(
        "maverick.audit.reader.iter_events",
        broken_audit_reader,
    )
    monkeypatch.setattr(
        erasure_verify,
        "_count_knowledge_chunks",
        lambda *args, **kwargs: 0,
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["audit_events"]["checked"] is False
    assert "could not read subject audit events" in rep["errors"]["audit_events"]


def test_malformed_audit_segment_is_not_a_verified_zero():
    from maverick.paths import data_dir

    audit_dir = data_dir("audit")
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "2026-01-01.ndjson").write_text(
        "{not valid JSON}\n",
        encoding="utf-8",
    )

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["indeterminate"] is True
    assert rep["stores"]["audit_events"]["checked"] is False
    assert "invalid audit JSON" in rep["errors"]["audit_events"]


def test_default_dsar_export_remains_fail_soft(monkeypatch):
    from maverick.dsar import export_subject_data

    class BrokenWorld:
        def list_conversations(self, _channel):
            raise OSError("world unavailable")

    monkeypatch.setattr(
        "maverick.dsar._resolve_world",
        lambda _tenant, *, strict=False: BrokenWorld(),
    )

    bundle = export_subject_data("alice", channel="telegram")

    assert bundle["counts"] == {
        "conversations": 0,
        "turns": 0,
        "goals": 0,
        "episodes": 0,
        "facts": 0,
        "fact_history": 0,
        "audit_events": 0,
    }


# ---- real end-to-end: seed -> verify dirty -> erase -> verify clean ----

def _world_db() -> Path:
    return Path.home() / ".maverick" / "world.db"


def _seed():
    wm = WorldModel(_world_db())
    conv = wm.get_or_create_conversation("telegram", "alice")
    gid = wm.create_goal("alice's goal", "do the alice thing")
    wm.append_turn(conv.id, "user", "alice secret", goal_id=gid)
    wm.close()


def test_end_to_end_erase_then_verify_clean():
    _seed()
    before = erasure_verify.verify_erasure("alice", channel="telegram")
    assert before["clean"] is False  # residual present before erase

    res = CliRunner().invoke(
        main, ["erase", "--channel", "telegram", "--user", "alice", "--yes"])
    assert res.exit_code == 0
    match = re.search(r"erasure receipt: ([0-9a-f]{32})", res.output)
    assert match is not None

    after = erasure_verify.verify_erasure(
        "alice",
        channel="telegram",
        receipt_id=match.group(1),
    )
    assert after["clean"] is True  # nothing left

    proof = erasure_verify.differential(before["counts"], after["counts"])
    assert proof["verified"] is True


def test_cli_erase_verify_without_receipt_is_indeterminate():
    # A bare subject scan cannot reconstruct the pre-delete goal closure.
    res = CliRunner().invoke(
        main, ["erase-verify", "--channel", "telegram", "--user", "nobody"])
    assert res.exit_code == 1
    assert "INDETERMINATE" in res.output


def test_cli_erase_verify_residual_exit_one():
    _seed()
    res = CliRunner().invoke(
        main, ["erase-verify", "--channel", "telegram", "--user", "alice"])
    assert res.exit_code == 1
    assert "RESIDUAL DATA" in res.output


def test_verify_erasure_counts_user_scoped_facts():
    wm = WorldModel(_world_db())
    wm.upsert_fact("user:telegram:alice:preference", "alice secret PII")
    wm.upsert_fact("user:telegram:bob:preference", "bob secret PII")
    wm.upsert_fact("global:telegram:alice", "not deliberately scoped")
    wm.close()

    rep = erasure_verify.verify_erasure("alice", channel="telegram")

    assert rep["clean"] is False
    assert rep["counts"]["facts"] == 1
    assert rep["residual"]["facts"] == 1


def test_cli_erase_verify_json_residual_exit_one():
    _seed()
    res = CliRunner().invoke(
        main, ["erase-verify", "--channel", "telegram", "--user", "alice", "--json"])
    assert res.exit_code == 1
    assert '"clean": false' in res.output


# --- erasure verify never certifies clean on an unresolved channel ---

def test_verify_erasure_indeterminate_without_channel():
    # No channel passed and no rows to disambiguate -> the export can't scope to
    # a subject, so the verdict must be indeterminate, not a false "clean".
    rep = erasure_verify.verify_erasure("ghost")
    assert rep.get("indeterminate") is True
    assert rep["clean"] is False


def test_verify_erasure_needs_pre_delete_receipt_even_with_concrete_channel():
    # A channel resolves direct subject stores, but cannot reconstruct goal IDs
    # after their attributing turns are gone. A bare scan therefore cannot
    # certify the complete goal graph.
    rep = erasure_verify.verify_erasure("nobody", channel="telegram")
    assert rep.get("indeterminate") is True
    assert rep["clean"] is False
    assert "erasure_receipt" in rep["errors"]
