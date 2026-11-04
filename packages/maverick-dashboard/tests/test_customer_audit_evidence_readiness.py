"""Actual customer audit handlers must preserve coverage and artifact identity."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re

import pytest
from fastapi.testclient import TestClient
from maverick import assessment, audit, privacy_ops, world_model
from maverick.audit.events import AuditEvent
from maverick.audit.writer import AuditLog
from maverick.file_lock import atomic_write_bytes
from maverick.paths import data_dir
from maverick.world_model import WorldModel
from maverick_dashboard import api, app


@pytest.fixture
def customer_audit(tmp_path, monkeypatch, request):
    from maverick.audit import signing

    # Dashboard tests also qualify the requested secure-default posture; the
    # core package's conftest does not apply to this sibling test directory.
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0"))
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(request.node.nodeid.encode()).hexdigest())
    signing._reset_injected_keypair_cache()
    log = AuditLog(data_dir("audit"), sign=True)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "review-world.db")
    world = WorldModel(tmp_path / "review-world.db")
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(app, "_world", lambda: world)
    monkeypatch.setattr(assessment, "list_saved", list)
    monkeypatch.setattr(assessment, "acceptance_metrics", lambda **kwargs: {"decided": 0})
    monkeypatch.setattr(privacy_ops, "enabled", lambda: False)
    monkeypatch.setattr(api, "_binder_finance_section", lambda: {
        "scope": "current_snapshot", "posture": {"disclaimer": "synthetic finance source"},
        "sod": {"conflicts": 0}, "licenses": {},
    })
    try:
        yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, log
    finally:
        world.close()
        # Production intentionally retains an injected key after consuming its
        # environment entry. A test must not pass that identity to the next one.
        signing._reset_injected_keypair_cache()


@pytest.mark.parametrize("unreadable", [b'{"torn":', b'[]\n', b'\xff\n'])
def test_search_reports_incomplete_day(customer_audit, unreadable):
    client, _world, log = customer_audit
    atomic_write_bytes(log.audit_dir / "2026-08-10.ndjson",
                       b'{"kind":"tool_call","name":"visible-needle"}\n' + unreadable)
    response = client.get("/api/v1/audit/grep?pattern=missing-needle&day=2026-08-10")
    assert response.status_code == 200
    body = response.json()
    assert body["total_matches"] == 0
    assert body["scan_complete"] is False
    assert body["read_report"]["failures"] > 0
    assert body["read_report"]["state"] in {"partial", "unreadable"}


def _digest(payload):
    return hashlib.sha256(json.dumps(
        {k: v for k, v in payload.items() if k != "artifact"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    ).encode()).hexdigest()


def test_binder_page_download_preserves_signed_digest(customer_audit):
    client, _world, _log = customer_audit
    response = client.get("/audit/binder?days=1")
    assert response.status_code == 200
    match = re.search(r'<script\b[^>]*\bid="binder-payload"[^>]*>(.*?)</script>', response.text, re.DOTALL)
    assert match
    payload = json.loads(match.group(1))
    assert payload["artifact"]["signature_state"] == "signed"
    assert _digest(payload) == payload["artifact"]["digest"]
    api_response = client.get("/api/v1/audit/binder?days=1")
    assert api_response.status_code == 200
    assert _digest(api_response.json()) == api_response.json()["artifact"]["digest"]


def test_kind_filter_empty_does_not_claim_empty_day(customer_audit):
    client, _world, log = customer_audit
    atomic_write_bytes(log.audit_dir / "2026-08-10.ndjson",
                       b'{"kind":"tool_call","name":"recorded action"}\n')
    response = client.get("/audit?day=2026-08-10&kind=consent_result")
    assert response.status_code == 200
    assert "No instrumented activity was recorded for this day" not in response.text
    assert "No events match the selected kind in the loaded tail" in response.text


def test_replay_includes_all_lifetime_days(customer_audit, monkeypatch):
    from maverick.audit import writer

    client, world, log = customer_audit
    goal = world.create_goal("Long-running customer task")
    started = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc).timestamp()
    ended = dt.datetime(2026, 2, 15, tzinfo=dt.timezone.utc).timestamp()
    with world._writing() as connection:
        connection.execute("UPDATE goals SET created_at=?,updated_at=? WHERE id=?", (started, ended, goal))

    class FixedClock(dt.datetime):
        moment = started + 3600

        @classmethod
        def now(cls, tz=None):
            return dt.datetime.fromtimestamp(cls.moment, tz=tz)

    monkeypatch.setattr(writer, "datetime", FixedClock)
    assert log.record(AuditEvent(ts=started + 3600, kind="goal_start", goal_id=goal, payload={"title": "Started"}))
    FixedClock.moment = ended - 3600
    assert log.record(AuditEvent(ts=ended - 3600, kind="tool_call", goal_id=goal, payload={"name": "late-customer-payment"}))
    response = client.get(f"/api/v1/replay/{goal}/evidence")
    assert response.status_code == 200
    body = response.json()
    assert [e["kind"] for e in body["timeline"]] == ["goal_start", "tool_call"]
    assert body["summary"]["tool_calls"] == 1
    assert body["read_report"]["failures"] == 0


def test_replay_discloses_partial_read(customer_audit):
    client, world, log = customer_audit
    goal = world.create_goal("Incomplete record")
    stamp = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc).timestamp()
    with world._writing() as connection:
        connection.execute("UPDATE goals SET created_at=?,updated_at=? WHERE id=?", (stamp, stamp + 60, goal))
    atomic_write_bytes(log.audit_dir / "2026-08-10.ndjson",
                       (json.dumps({"kind": "tool_call", "goal_id": goal, "ts": stamp}) + '\n{"torn":').encode())
    body = client.get(f"/api/v1/replay/{goal}/evidence").json()
    assert body["read_report"]["failures"] > 0
    assert body["chain"]["status"] != "verified"


def test_replay_reports_selected_day_disappearing_before_read(customer_audit, monkeypatch):
    from maverick_dashboard import control_plane

    client, world, log = customer_audit
    goal = world.create_goal("Selected evidence disappeared")
    stamp = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc).timestamp()
    with world._writing() as connection:
        connection.execute("UPDATE goals SET created_at=?,updated_at=? WHERE id=?", (stamp, stamp + 60, goal))
    path = log.audit_dir / "2026-08-10.ndjson"
    atomic_write_bytes(path, (json.dumps({"kind": "tool_call", "goal_id": goal, "ts": stamp}) + "\n").encode())
    select = control_plane._window_days

    def remove_after_selection(window):
        days = select(window)
        assert days == ["2026-08-10"]
        path.unlink()
        return days

    monkeypatch.setattr(control_plane, "_window_days", remove_after_selection)
    response = client.get(f"/api/v1/replay/{goal}/evidence")
    assert response.status_code == 200
    body = response.json()
    assert body["read_report"]["state"] == "unreadable"
    assert body["read_report"]["failures"] == 1
    assert body["chain"]["status"] == "incomplete"


@pytest.mark.parametrize("window", [(float("inf"), 123.0), (123.0, float("nan"))])
def test_replay_invalid_window_is_explicitly_unreadable(customer_audit, window):
    from maverick_dashboard.control_plane import build_replay

    result = build_replay(1, window=window)
    assert result["read_report"]["state"] == "unreadable"
    assert result["chain"]["status"] == "incomplete"


@pytest.mark.parametrize("sealed", [False, True], ids=["plaintext", "sealed"])
@pytest.mark.parametrize("initially_tampered", [False, True], ids=["valid_then_tampered", "tampered_then_restored"])
def test_replay_verifies_exact_rows_returned_despite_source_replacement(
    customer_audit, monkeypatch, sealed, initially_tampered,
):
    from maverick.audit import sealing
    from maverick.audit.segments import SegmentSnapshot, sealed_bytes

    client, world, log = customer_audit
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    goal = world.create_goal("Verify the returned evidence")
    stamp = dt.datetime.now(dt.timezone.utc).timestamp()
    assert log.record(AuditEvent(ts=stamp, kind="tool_call", goal_id=goal, payload={"name": "original-payment"}))
    path = log.audit_dir / f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%d}.ndjson"
    original = sealing.segment_text(path, fail_soft=False)
    tampered = original.replace("original-payment", "tampered-payment")
    assert tampered != original

    def encode(text):
        return sealed_bytes(text) if sealed else text.encode()

    atomic_write_bytes(path, encode(tampered if initially_tampered else original))
    close_snapshot = SegmentSnapshot.__exit__
    replacements = []

    def replace_after_extraction(snapshot, *exc):
        close_snapshot(snapshot, *exc)
        if snapshot.path == path and not replacements:
            # Both implementations finish reading a real, signed day-file.
            # The on-disk replacement happens at the previous extraction /
            # verification seam, after the captured reader validated its input.
            replacements.append(True)
            atomic_write_bytes(path, encode(original if initially_tampered else tampered))

    monkeypatch.setattr(SegmentSnapshot, "__exit__", replace_after_extraction)
    response = client.get(f"/api/v1/replay/{goal}/evidence")
    assert response.status_code == 200
    body = response.json()
    assert replacements == [True]
    assert body["timeline"][0]["summary"] == ("tampered-payment" if initially_tampered else "original-payment")
    assert body["chain"]["status"] == ("broken" if initially_tampered else "verified")
    assert body["chain"]["scope"] == "selected_segment_snapshots"
    assert body["chain"]["segment_status"] == body["chain"]["status"]
    assert body["chain"]["atomic_across_days"] is False
    assert body["chain"]["anchors"] == {
        "scope": "current_files_separate_read", "bound_to_timeline": False,
        "status": "no_breaks_found", "break_count": 0,
    }
    assert body["read_report"]["failures"] == 0
    assert body["read_report"]["verification"] == ("failed" if initially_tampered else "segment_chains_verified")
    if initially_tampered:
        assert any(break_["reason"] == "bad_hash" for break_ in body["chain"]["breaks"])


def test_replay_discloses_separate_anchor_failure_and_scope(customer_audit, monkeypatch):
    from maverick.audit import signing, writer

    client, world, log = customer_audit
    goal = world.create_goal("Missing anchored evidence")
    stamp = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc).timestamp()
    with world._writing() as connection:
        connection.execute("UPDATE goals SET created_at=?,updated_at=? WHERE id=?", (stamp, stamp + 60, goal))

    class FixedClock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime.fromtimestamp(stamp, tz=tz)

    monkeypatch.setattr(writer, "datetime", FixedClock)
    assert log.record(AuditEvent(ts=stamp, kind="tool_call", goal_id=goal, payload={"name": "anchored-payment"}))
    assert signing.ensure_anchors(log.audit_dir) == 1
    (log.audit_dir / signing.ANCHOR_FILENAME).unlink()
    body = client.get(f"/api/v1/replay/{goal}/evidence").json()
    assert body["chain"]["status"] == "broken"
    assert body["chain"]["segment_status"] == "verified"
    assert body["chain"]["anchors"]["status"] == "broken"
    assert body["chain"]["anchors"]["bound_to_timeline"] is False
    assert body["read_report"]["verification"] == "segment_chains_verified"
    page = client.get(f"/replay?goal={goal}")
    assert page.status_code == 200
    assert "anchor ledger is checked separately against current files" in page.text
    assert "not bound to this timeline" in page.text
    assert "atomic point-in-time snapshot" in page.text
    assert "Independent checkpoints are not checked" in page.text


@pytest.mark.parametrize("field,value", [
    ("ts", "invalid timestamp"), ("ts", []), ("ts", float("inf")),
    ("ts", True), ("kind", []), ("kind", {}),
])
def test_replay_malformed_event_metadata_preserves_valid_rows(customer_audit, field, value):
    from maverick.audit.signing import AuditSigner

    _client, world, log = customer_audit
    client = TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, raise_server_exceptions=False)
    goal = world.create_goal("Damaged event metadata")
    stamp = dt.datetime.now(dt.timezone.utc).timestamp()
    assert log.record(AuditEvent(ts=stamp, kind="tool_call", goal_id=goal, payload={"name": "readable-payment"}))
    path = log.audit_dir / f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%d}.ndjson"
    signer = AuditSigner(path)
    assert signer.write({"ts": stamp, "kind": "tool_call", "goal_id": goal, "name": "invalid-payment", field: value})

    response = client.get(f"/api/v1/replay/{goal}/evidence")
    assert response.status_code == 200
    body = response.json()
    assert [row["summary"] for row in body["timeline"]] == ["readable-payment"]
    assert body["chain"]["status"] in {"incomplete", "broken"}
    assert body["read_report"]["failures"] == 1
    assert any(item["reason"] == "invalid_event_metadata" for item in body["read_report"]["diagnostics"])
    page = client.get(f"/replay?goal={goal}")
    assert page.status_code == 200
    assert "readable-payment" in page.text
    assert "counts are incomplete" in page.text
