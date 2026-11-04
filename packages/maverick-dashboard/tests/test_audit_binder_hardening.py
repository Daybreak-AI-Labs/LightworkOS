"""Focused regression coverage for the audit Binder evidence boundary."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import api as dashboard_api
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


class _BinderWorld:
    def __init__(self, approvals: list[SimpleNamespace]) -> None:
        self.approvals = approvals
        self.requested_limit: int | None = None
        self.requested_window: tuple[float, float] | None = None

    def list_approvals(self, limit: int = 500) -> list[SimpleNamespace]:
        self.requested_limit = limit
        return list(self.approvals)

    def approvals_requested_between(self, since: float, until: float) -> list[SimpleNamespace]:
        self.requested_window = (since, until)
        return [a for a in self.approvals if since <= float(a.requested_at or 0) <= until]

    def approval_state(self, approval_id: int) -> dict[str, object]:
        return {
            "approved_count": 0,
            "approvers": [],
            "audit_pending_count": 0,
            "effective": False,
        }

    def approval_states(self, approvals) -> dict[int, dict[str, object]]:
        return {approval.id: self.approval_state(approval.id) for approval in approvals}


def _approval(approval_id: int, requested_at: float) -> SimpleNamespace:
    return SimpleNamespace(
        id=approval_id,
        action=f"action-{approval_id}",
        risk="medium",
        status="pending",
        requested_by="requester@example.test",
        requested_at=requested_at,
        decided_by=None,
        decided_at=None,
        approvals_required=1,
    )


def _assessment(
    assessment_id: str,
    *,
    created_at: float,
    decided_at: float | None = None,
) -> dict[str, object]:
    return {
        "id": assessment_id,
        "type": "pia",
        "subject": f"subject-{assessment_id}",
        "inherent_risk": "medium",
        "residual_risk": "low",
        "status": "approved" if decided_at is not None else "pending_review",
        "revision": 1,
        "template_digest": "a" * 64,
        "created_at": created_at,
        "decided_at": decided_at,
        "review_due": False,
    }


def _learning_record(record_id: int, decided_at: float) -> dict[str, object]:
    return {
        "id": f"learning-{record_id}",
        "type": "pia",
        "status": "approved",
        "created_at": decided_at - 60,
        "decided_at": decided_at,
        "followups": [],
    }


def _install_binder_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    now: float,
    segments: dict[Path, str],
    approvals: list[SimpleNamespace] | None = None,
    assessments: list[dict[str, object]] | None = None,
    learning: list[dict[str, object]] | None = None,
    chain_breaks: dict[Path, list[object]] | None = None,
    anchor_breaks: list[object] | None = None,
) -> SimpleNamespace:
    from maverick import assessment, audit, privacy_ops
    from maverick.audit import reader, sealing, signing

    log = SimpleNamespace(audit_dir=tmp_path / "audit", signing_enabled=False)
    world = _BinderWorld(approvals or [])
    segment_calls: list[Path] = []
    verify_calls: list[tuple[Path, str | None]] = []
    chain_breaks = chain_breaks or {}

    def read_segment(path: Path, *, fail_soft: bool = True) -> str:
        assert fail_soft is False
        segment_calls.append(path)
        return segments[path]

    def verify_segment(
        path: Path,
        pubkey_hex: str | None = None,
        *,
        segment: str | None = None,
    ) -> list[object]:
        assert pubkey_hex is None
        verify_calls.append((path, segment))
        return list(chain_breaks.get(path, []))

    monkeypatch.setattr(time, "time", lambda: now)
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    monkeypatch.setattr(reader, "day_files", lambda audit_dir: list(segments))
    monkeypatch.setattr(sealing, "segment_text", read_segment)
    monkeypatch.setattr(signing, "verify_chain", verify_segment)
    monkeypatch.setattr(
        signing,
        "verify_anchors",
        lambda audit_dir: list(anchor_breaks or []),
    )
    monkeypatch.setattr(dashboard_api, "_world", lambda: world)
    monkeypatch.setattr(assessment, "list_saved", lambda: list(assessments or []))
    monkeypatch.setattr(
        assessment,
        "_iter_saved_raw",
        lambda: iter(list(learning or [])),
    )
    monkeypatch.setattr(privacy_ops, "enabled", lambda: False)
    monkeypatch.setattr(
        dashboard_api,
        "_binder_finance_section",
        lambda: {"scope": "current_snapshot"},
    )
    return SimpleNamespace(
        log=log,
        world=world,
        segment_calls=segment_calls,
        verify_calls=verify_calls,
    )


def test_binder_exact_window_is_inclusive_uncapped_and_verifies_each_segment_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = 1_800_000_000.0
    cutoff = now - 86_400
    start_day = time.strftime("%Y-%m-%d", time.gmtime(cutoff))
    end_day = time.strftime("%Y-%m-%d", time.gmtime(now))
    start_path = tmp_path / "audit" / f"{start_day}.ndjson"
    end_path = tmp_path / "audit" / f"{end_day}.ndjson"
    segments = {
        start_path: "\n".join(
            json.dumps(row)
            for row in (
                {"ts": cutoff - 1, "kind": "before"},
                {"ts": cutoff, "kind": "at-cutoff"},
            )
        ),
        end_path: "\n".join(
            json.dumps(row)
            for row in (
                {"ts": cutoff + 1, "kind": "inside"},
                {"ts": now, "kind": "at-until"},
                {"ts": now + 1, "kind": "after"},
            )
        ),
    }

    approvals = [_approval(-1, cutoff - 1), _approval(1, cutoff)]
    approvals.extend(_approval(10 + index, cutoff + 1) for index in range(301))
    approvals.extend((_approval(1_000, now), _approval(1_001, now + 1)))

    assessments = [
        _assessment("before", created_at=cutoff - 1),
        _assessment("created-at-cutoff", created_at=cutoff),
        _assessment(
            "decided-at-cutoff",
            created_at=cutoff - 60,
            decided_at=cutoff,
        ),
    ]
    assessments.extend(
        _assessment(f"bulk-{index}", created_at=cutoff + 1)
        for index in range(301)
    )
    assessments.extend(
        (
            _assessment("created-at-until", created_at=now),
            _assessment("after", created_at=now + 1),
        )
    )

    learning = [_learning_record(-1, cutoff - 1), _learning_record(1, cutoff)]
    learning.extend(
        _learning_record(10 + index, cutoff + 1) for index in range(301)
    )
    learning.extend(
        (_learning_record(1_000, now), _learning_record(1_001, now + 1))
    )

    observed = _install_binder_sources(
        monkeypatch,
        tmp_path,
        now=now,
        segments=segments,
        approvals=approvals,
        assessments=assessments,
        learning=learning,
    )

    payload = dashboard_api._binder_payload(days=1)

    assert payload["window"]["since"] == cutoff
    assert payload["window"]["until"] == now
    assert payload["chain"]["events"] == 3
    assert payload["chain"]["first_ts"] == cutoff
    assert payload["chain"]["last_ts"] == now
    assert [row["events"] for row in payload["chain"]["files"]] == [1, 2]
    assert [row["records_in_file"] for row in payload["chain"]["files"]] == [2, 3]

    assert observed.segment_calls == [start_path, end_path]
    assert [path for path, _ in observed.verify_calls] == [start_path, end_path]
    for path, plaintext in observed.verify_calls:
        assert plaintext is segments[path]

    approval_ids = {row["id"] for row in payload["approvals"]}
    assert {-1, 1_001}.isdisjoint(approval_ids)
    assert {1, 1_000}.issubset(approval_ids)
    assert payload["approvals_total"] == 303
    assert payload["approvals_truncated"] is False
    assert observed.world.requested_window == (
        payload["window"]["since"], payload["window"]["until"],
    )

    assessment_ids = {row["id"] for row in payload["assessments"]}
    assert {"before", "after"}.isdisjoint(assessment_ids)
    assert {
        "created-at-cutoff",
        "decided-at-cutoff",
        "created-at-until",
    }.issubset(assessment_ids)
    assert payload["assessments_total"] == 304
    assert payload["assessments_truncated"] is False

    assert payload["learning"]["decided"] == 303
    assert payload["learning"]["first_pass"] == 303


def test_binder_includes_every_chain_break_and_anchor_break(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from maverick.audit.signing import ChainBreak

    now = 1_800_000_000.0
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    path = tmp_path / "audit" / f"{day}.ndjson"
    chain_breaks = [
        ChainBreak(index, "hash_mismatch", f"break-{index}")
        for index in range(1, 26)
    ]
    anchor_break = ChainBreak(7, "anchor_tip_mismatch", "saved tip differs")
    _install_binder_sources(
        monkeypatch,
        tmp_path,
        now=now,
        segments={path: json.dumps({"ts": now, "kind": "test"})},
        chain_breaks={path: chain_breaks},
        anchor_breaks=[anchor_break],
    )

    payload = dashboard_api._binder_payload(days=1)

    assert len(payload["chain"]["files"][0]["breaks"]) == 25
    assert payload["chain"]["anchor_breaks"] == [
        {
            "line": 7,
            "reason": "anchor_tip_mismatch",
            "detail": "saved tip differs",
        }
    ]
    assert payload["chain"]["verdict"] == "broken"
    assert payload["chain"]["intact"] is False


def test_binder_detached_signature_verifies_with_saved_public_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pytest.importorskip("cryptography")
    from maverick.audit import signing

    key_dir = tmp_path / "keys"
    monkeypatch.setattr(signing, "KEY_DIR", key_dir)
    monkeypatch.setattr(signing, "_injected_keypair", lambda: None)
    monkeypatch.setattr(signing, "_kms_wrapped_keypair", lambda: None)
    monkeypatch.setattr(signing, "require_offhost_signing", lambda: False)

    payload = {"schema_version": 2, "evidence": ["alpha", "beta"]}
    artifact = dashboard_api._binder_artifact(payload, signing_enabled=True)

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    assert artifact["digest"] == hashlib.sha256(canonical).hexdigest()
    assert artifact["signature_state"] == "signed"
    public_key = (key_dir / f"{artifact['key_id']}.pub").read_bytes().hex()
    digest = bytes.fromhex(str(artifact["digest"]))
    assert signing.verify_detached_digest(
        public_key,
        str(artifact["digest"]),
        str(artifact["signature"]),
    )
    tampered = bytearray.fromhex(str(artifact["signature"]))
    # Replacing the first byte with zero leaves a valid signature unchanged
    # when it already starts with 00. Flip a bit so tampering is guaranteed.
    tampered[0] ^= 1
    assert not signing.verify_detached_digest(
        public_key,
        str(artifact["digest"]),
        tampered.hex(),
    )
    # The signature is over a domain-separated message, not the bare
    # digest -- a plain verify_ed25519 against the raw digest bytes (what a
    # forged AuditSigner chain-row signature, or a federation envelope
    # signature, over this same digest would look like) must NOT verify.
    # A detached signature over the bare digest would make this fail.
    assert not signing.verify_ed25519(
        public_key,
        str(artifact["signature"]),
        digest,
    )


def test_binder_json_response_is_no_store_attachment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dashboard_api,
        "_binder_payload",
        lambda days: {
            "window_days": days,
            "artifact": {"binder_id": "0123456789abcdef"},
        },
    )

    response = client.get("/api/v1/audit/binder?days=30")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="lightwork-audit-binder-0123456789abcdef.json"'
    )
    assert response.json()["window_days"] == 30


def test_binder_shows_written_approval_actions_as_written(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from maverick import world_model
    from maverick.world_model import WorldModel

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard_api, "_world", lambda: world)
    world.create_approval("Pay invoice INV-20419 from Northwind Supply ($6,150.00)", risk="medium")
    world.create_approval("wire.transfer", risk="high")

    html = client.get("/audit/binder", params={"days": 30}).text

    # The cell reads as the request was written (its title attribute already
    # did); only an action name such as ``wire.transfer`` is made readable.
    assert ">Pay invoice INV-20419 from Northwind Supply ($6,150.00)</td>" in html
    assert "inv 20419" not in html
    assert ">Wire transfer</td>" in html
    world.close()


def test_binder_quorum_state_is_read_in_one_batch_and_matches_per_approval_reads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from maverick.safety import dual_control
    from maverick.world_model import WorldModel

    now = 1_800_000_000.0
    _install_binder_sources(monkeypatch, tmp_path, now=now, segments={})
    monkeypatch.setattr(dual_control, "allow_self_approval", lambda: False)
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard_api, "_world", lambda: world)
    quorum = world.create_approval(
        "wire $1M", risk="critical", approvals_required=2, requested_by="u:req",
    )
    world.decide_approval(quorum, "approved", decided_by="u:alice")
    world.decide_approval(quorum, "approved", decided_by="u:bob")
    refund = world.create_approval("refund $20", risk="medium", approvals_required=1)
    world.decide_approval_audited(refund, "approved", decided_by="u:carol")
    expected = {a.id: world.approval_state(a.id) for a in world.list_approvals(limit=50)}

    per_id_reads: list[int] = []
    real_state = WorldModel.approval_state

    def counting_state(self, approval_id):
        per_id_reads.append(approval_id)
        return real_state(self, approval_id)

    monkeypatch.setattr(WorldModel, "approval_state", counting_state)
    rows = {row["id"]: row for row in dashboard_api._binder_payload(days=1)["approvals"]}

    assert per_id_reads == []
    assert set(rows) == set(expected) == {quorum, refund}
    for approval_id, state in expected.items():
        row = rows[approval_id]
        assert row["approved_count"] == state["approved_count"]
        assert row["approvers"] == state["approvers"]
        assert row["audit_pending_count"] == state["audit_pending_count"]
        assert row["effective"] == state["effective"]
    assert rows[quorum]["approvers"] == ["u:alice", "u:bob"]
    assert rows[quorum]["effective"] is True
    assert rows[refund]["audit_pending_count"] == 1
