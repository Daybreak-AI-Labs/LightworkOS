"""HTTP contract for the audit-only, digest-only Evolution Ledger API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick.evolution_ledger import EvolutionLedgerError, build_promotion_receipt
from maverick.self_improvement import PromotionLedger, PromotionRecord
from maverick_dashboard import evolution_ledger_api as api

BASE = "/audit/evolution-ledger"


def _record(**overrides: object) -> PromotionRecord:
    values: dict[str, object] = {
        "id": "private-candidate-identifier",
        "rung": "code",
        "summary": "private promotion summary must not reach the dashboard",
        "baseline_score": 0.1,
        "candidate_score": 0.9,
        "promoted_at": 100.0,
        "approver_id": "a" * 16,
        "payload_sha256": "b" * 64,
        "approval_signature": "c" * 128,
        "model_risk_payload_sha256": "d" * 64,
        "samples": 8,
        "effect_ci_low": 0.1,
        "provenance": {
            "workspace_snapshot_sha256": "e" * 64,
            "raw_locator": "C:/private/path/never-expose",
        },
        "audit_payload": {"private_note": "never expose journal content"},
    }
    values.update(overrides)
    return PromotionRecord(**values)


def _client(monkeypatch: pytest.MonkeyPatch, *, permitted: bool = True) -> TestClient:
    def require(_request, permission: str) -> None:
        assert permission == "audit"
        if not permitted:
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(api, "require_permission", require)
    app = FastAPI()
    app.include_router(api.create_evolution_ledger_router())
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_history_checkpoint_native_prefix_roundtrip_and_replacement_refusal(tmp_path, monkeypatch):
    """An independently kept original catches validly rebuilt local history."""
    from maverick import learning_history_checkpoint as checkpoint
    from maverick_dashboard import product_operations_learning_history as copilot

    path = tmp_path / "checkpoint-source.json"
    ledger = PromotionLedger(path=path)
    original = _record()
    ledger.add(original)
    journal = Path(f"{path}.journal")
    lock = Path(f"{journal}.lock")
    lock.unlink(missing_ok=True)
    before = journal.read_bytes()
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (ledger, "available"))
    client = _client(monkeypatch)
    downloaded = client.get(f"{BASE}/checkpoint/download")
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.headers["cache-control"].startswith("no-store")
    retained_original = downloaded.text
    for private in (original.id, original.summary, original.approval_signature, "never expose journal content"):
        assert private not in retained_original
    assert journal.read_bytes() == before and not lock.exists()
    assert client.post(f"{BASE}/checkpoint/check", json={"checkpoint": retained_original}).json()["matches"] is True
    # Restoration mutates the compatibility projection, never the old event.
    ledger.mark_rolled_back(original.id, at=120)
    ledger.add(_record(id="a-later-change", promoted_at=130))
    checked = client.post(f"{BASE}/checkpoint/check", json={"checkpoint": retained_original})
    assert checked.status_code == 200 and checked.json()["matches"] is True
    assert checked.json()["later_records"] == 2
    status = client.get(f"{BASE}/checkpoint/status").json()
    assert status["record_count"] == 3 and status["adopted_changes"] == 2 and status["restorations"] == 1
    monkeypatch.setattr(copilot, "require_permission", lambda _request, _permission: None)
    assert copilot.checkpoint_snapshot(None, {}).details["record_count"] == 3
    assert copilot.prepare_checkpoint_download(None, {}, {}).native["download"]["href"].endswith("/checkpoint/download")
    assert copilot.prepare_checkpoint_check(None, {}, {}).native["choose_file"]["href"].endswith("#history-checkpoint")
    tampered = downloaded.json()
    tampered["record_count"] = 2
    assert client.post(f"{BASE}/checkpoint/check", json={"checkpoint": json.dumps(tampered)}).status_code == 422
    oversized = client.post(f"{BASE}/checkpoint/check", content=b"x" * 32769)
    assert oversized.status_code == 413 and len(oversized.content) < 1024
    # A replacement has a valid native chain. Local integrity alone accepts it,
    # but comparison with the independently retained original refuses it.
    replacement_path = tmp_path / "replacement.json"
    replacement = PromotionLedger(path=replacement_path)
    replacement.add(_record(summary="changed earlier contents"))
    replacement.add(_record(id="a-later-change", promoted_at=130))
    journal.write_bytes(Path(f"{replacement_path}.journal").read_bytes())
    checked = client.post(f"{BASE}/checkpoint/check", json={"checkpoint": retained_original})
    assert checked.status_code == 200 and checked.json()["matches"] is False
    # Also refuse a missing earliest event even when the remaining native
    # history was rebuilt with a completely valid chain.
    missing_path = tmp_path / "missing.json"
    missing = PromotionLedger(path=missing_path)
    missing.add(_record(id="a-later-change", promoted_at=130))
    journal.write_bytes(Path(f"{missing_path}.journal").read_bytes())
    assert client.post(f"{BASE}/checkpoint/check", json={"checkpoint": retained_original}).json()["matches"] is False
    journal.write_bytes(b"broken\n")
    assert client.post(f"{BASE}/checkpoint/check", json={"checkpoint": retained_original}).status_code == 409
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (PromotionLedger(), "available"))
    assert client.get(f"{BASE}/checkpoint/download").status_code == 409
    monkeypatch.setattr(checkpoint, "MAX_SOURCE_BYTES", 1)
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (missing, "available"))
    assert client.get(f"{BASE}/checkpoint/download").status_code == 409
    assert _client(monkeypatch, permitted=False).get(f"{BASE}/checkpoint/download").status_code == 403


def test_snapshot_is_digest_only_bounded_and_does_not_repair_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = tmp_path / "self_improvement.json"
    ledger = PromotionLedger(path=ledger_path)
    record = _record()
    ledger.add(record)
    assert ledger.mark_rolled_back(record.id, at=120.0)
    journal_path = Path(f"{ledger_path}.journal")
    before = {
        ledger_path: ledger_path.read_bytes(),
        journal_path: journal_path.read_bytes(),
    }
    lock_path = Path(f"{journal_path}.lock")
    lock_path.unlink(missing_ok=True)
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (ledger, "available"))

    response = _client(monkeypatch).get(f"{BASE}/snapshot")

    assert response.status_code == 200, response.text
    assert {path: path.read_bytes() for path in before} == before
    assert not lock_path.exists()
    payload = response.json()
    assert payload["schema"] == api.SNAPSHOT_SCHEMA
    assert payload["sources"] == {
        "promotion_ledger": "available",
        "dreaming": "not_exposed",
        "hindsight": "not_exposed",
        "proof": "not_exposed",
    }
    projection = payload["projection"]
    assert projection["schema"] == "lightwork.evolution-ledger-projection.v1"
    assert projection["entry_count"] == 2
    assert {entry["kind"] for entry in projection["entries"]} == {
        "promotion",
        "rollback",
    }
    rendered = json.dumps(payload, sort_keys=True)
    for private in (
        record.id,
        record.summary,
        record.approval_signature,
        "C:/private/path/never-expose",
        "never expose journal content",
    ):
        assert private not in rendered
    assert "e" * 64 in rendered
    client = _client(monkeypatch)
    for entry in projection["entries"]:
        downloaded = client.get(f"{BASE}/entries/{entry['entry_sha256']}/receipt")
        assert downloaded.status_code == 200
        assert downloaded.headers["cache-control"].startswith("no-store")
        assert downloaded.headers["content-disposition"].startswith("attachment;")
        assert downloaded.json()["receipt_sha256"] == entry["promotion_receipt_sha256"]
        checked = client.post(f"{BASE}/verify-receipt", json={"receipt": downloaded.text})
        assert checked.status_code == 200 and checked.json()["receipt_valid"] is True
        assert checked.json()["recorded_in_current_history"] is True
        assert checked.json()["approval_status"] == "not_verifiable_without_private_binding"
        for private in (record.id, record.summary, record.approval_signature, "C:/private/path/never-expose"):
            assert private not in downloaded.text
    assert client.get(f"{BASE}/entries/{'0' * 64}/receipt").status_code == 404
    other_receipt = build_promotion_receipt(_record(id="a-change-from-another-history"))
    other = client.post(f"{BASE}/verify-receipt", json={"receipt": json.dumps(other_receipt)})
    assert other.status_code == 200 and other.json()["receipt_valid"] is True
    assert other.json()["recorded_in_current_history"] is False
    from maverick_dashboard import product_operations_learning_history as copilot

    monkeypatch.setattr(copilot, "require_permission", lambda request, permission: None)
    current = copilot.snapshot(None, {})
    assert current.details["adopted_changes_shown"] == 1
    assert current.details["restorations_shown"] == 1
    assert copilot.prepare(None, {}, {}).native == current.details
    assert current.revision == copilot.snapshot(None, {}).revision
    assert record.id not in json.dumps(current.details)
    assert record.summary not in json.dumps(current.details)
    assert record.approval_signature not in json.dumps(current.details)
    with pytest.raises(HTTPException) as selection_error:
        copilot.snapshot(None, {"tenant": "other"})
    assert selection_error.value.status_code == 422

    def deny(request, permission):
        raise HTTPException(403, "Audit review is required")

    monkeypatch.setattr(copilot, "require_permission", deny)
    with pytest.raises(HTTPException) as denied:
        copilot.snapshot(None, {})
    assert denied.value.status_code == 403
    assert {path: path.read_bytes() for path in before} == before


def test_snapshot_names_an_absent_source_without_claiming_no_learning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (None, "not_present"))

    response = _client(monkeypatch).get(f"{BASE}/snapshot")

    assert response.status_code == 200
    projection = response.json()["projection"]
    assert projection["entries"] == []
    assert "promotion_ledger_not_present" in projection["limitations"]
    assert (
        "dreaming_hindsight_and_runtime_proof_sources_are_not_exposed_here"
        in projection["limitations"]
    )


def test_absent_named_tenant_source_does_not_admit_or_create_a_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening an audit view cannot create the tenant claim ``data_dir`` owns."""

    from maverick import paths

    home = tmp_path / "new-home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    token = paths.set_tenant("fresh-audit-tenant")
    try:
        source, state = api._promotion_ledger_source()
    finally:
        paths.reset_tenant(token)

    assert source is None and state == "not_present"
    assert not home.exists()


def test_snapshot_fails_closed_without_leaking_source_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable():
        raise EvolutionLedgerError("C:/private/ledger-path")

    monkeypatch.setattr(api, "_promotion_ledger_source", unavailable)

    response = _client(monkeypatch).get(f"{BASE}/snapshot")

    assert response.status_code == 503
    assert response.json()["detail"] == "Learning history is unavailable or its stored checks did not match. Select Refresh before relying on it."
    assert "private" not in response.text


def test_receipt_verification_is_digest_only_and_never_echoes_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = build_promotion_receipt(_record())
    monkeypatch.setattr(api, "_promotion_ledger_source", lambda: (None, "not_present"))
    client = _client(monkeypatch)

    verified = client.post(
        f"{BASE}/verify-receipt",
        json={"receipt": json.dumps(receipt)},
    )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["schema"] == api.RECEIPT_VERIFICATION_SCHEMA
    assert body["receipt_valid"] is True
    assert body["recorded_in_current_history"] is False
    assert body["receipt_sha256"] == receipt["receipt_sha256"]
    assert body["approval_status"] in {
        "not_recorded",
        "not_verifiable_without_private_binding",
    }
    assert "private-candidate-identifier" not in verified.text

    unsafe = dict(receipt)
    unsafe["raw_journal_content"] = "must never be returned"
    rejected = client.post(
        f"{BASE}/verify-receipt",
        json={"receipt": json.dumps(unsafe)},
    )
    assert rejected.status_code == 200
    assert rejected.json()["receipt_valid"] is False
    assert "must never be returned" not in rejected.text


def test_receipt_input_is_strict_bounded_and_all_routes_are_audit_gated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    permitted = _client(monkeypatch)
    duplicate = '{"schema":"x","schema":"y"}'
    assert permitted.post(f"{BASE}/verify-receipt", json={"receipt": duplicate}).status_code == 422
    assert (
        permitted.post(
            f"{BASE}/verify-receipt",
            json={"receipt": "{}", "approval_signature": "not-accepted"},
        ).status_code
        == 422
    )
    assert permitted.get(f"{BASE}/snapshot?debug=1").status_code == 404

    denied = _client(monkeypatch, permitted=False)
    assert denied.get(f"{BASE}/snapshot").status_code == 403
    assert denied.get(f"{BASE}/entries/{'0' * 64}/receipt").status_code == 403
    assert denied.post(f"{BASE}/verify-receipt", json={"receipt": "{}"}).status_code == 403
