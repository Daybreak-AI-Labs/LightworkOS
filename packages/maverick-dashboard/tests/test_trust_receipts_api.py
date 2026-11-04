"""HTTP contract of the Audit -> Trust Receipts console API: audit-gated, paths
never come from the browser, minting is a real signed export, verification
fails closed without a trusted key."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

pytest.importorskip("cryptography", reason="receipts are always signed")

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
BASE = "/api/v1/audit/receipts"
DAY = "2026-01-01"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import signing
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import api

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT",
                 "MAVERICK_TENANT_BY_USER", "MAVERICK_AUDIT_SIGNING_KEY",
                 "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    # Injected keys are consumed and cached once for the process. Clearing the
    # environment alone cannot undo a previous test's selected signer.
    signing._reset_injected_keypair_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()
    yield
    signing._reset_injected_keypair_cache()
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _write_day(rows=None):
    """A signed day-file under the isolated home, written by the real signer."""
    from maverick.audit.reader import resolve_audit_dir
    from maverick.audit.signing import AuditSigner
    audit_dir = resolve_audit_dir(None)
    audit_dir.mkdir(parents=True, exist_ok=True)
    signer = AuditSigner(audit_dir / f"{DAY}.ndjson")
    rows = rows or [
        {"ts": 1_767_225_600.0, "kind": "tool_call", "agent": "worker-0", "name": "read_file"},
        {"ts": 1_767_225_601.0, "kind": "governance_denied", "agent": "finance-0",
         "tool": "wire_transfer", "principal": "user:local", "rule": "deny_actions",
         "obligation_id": "gdpr-art32-outbound-transfer", "regulation": "GDPR",
         "article": "Art. 32"},
        {"ts": 1_767_225_602.0, "kind": "tool_call", "agent": "worker-0", "name": "http_get"},
    ]
    for row in rows:
        assert signer.write(dict(row))
    return [json.loads(line) for line in
            (audit_dir / f"{DAY}.ndjson").read_text().splitlines() if line.strip()]


@pytest.mark.parametrize("source", ["injected", "local"])
def test_status_reports_signing_key_and_days(monkeypatch, source):
    from maverick.audit import signing

    if source == "injected":
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", "ab" * 32)
    _write_day()
    r = client.get(f"{BASE}/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == "lightwork.trust-receipts-status.v1"
    assert body["signing_enabled"] is True
    assert body["key_custody"] == ("offhost" if source == "injected" else "colocated")
    assert body["key_id"] and body["pubkey"] and len(body["pubkey"]) == 64
    key_dir = signing._key_dir()
    assert (key_dir / f"{body['key_id']}.key").exists() is (source == "local")
    assert (key_dir / f"{body['key_id']}.injected").exists() is (source == "injected")
    assert any(k["key_id"] == body["key_id"] for k in body["trusted_keys"])
    assert body["days"] == [DAY]
    assert len(body["verifier_sha256"]) == 64


def test_rows_list_signed_rows_with_their_claim():
    written = _write_day()
    r = client.get(f"{BASE}/rows", params={"day": DAY})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3 and body["truncated"] is False
    denied = next(i for i in body["items"] if i["kind"] == "governance_denied")
    assert denied["signed"] is True and denied["hash"] == written[1]["hash"]
    assert denied["decision"] == "denied" and denied["tool"] == "wire_transfer"
    assert denied["position"] == 2
    filtered = client.get(f"{BASE}/rows", params={"day": DAY, "kind": "tool_call"}).json()
    assert [i["kind"] for i in filtered["items"]] == ["tool_call", "tool_call"]
    assert client.get(f"{BASE}/rows", params={"day": "2026-13-40"}).status_code == 422
    assert client.get(f"{BASE}/rows", params={"day": "../etc"}).status_code == 422
    assert client.get(f"{BASE}/rows", params={"day": DAY, "kind": "Bad Kind"}).status_code == 422


def test_mint_returns_a_signed_receipt_that_verifies_locally():
    written = _write_day()
    target = written[1]["hash"]
    r = client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": target})
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"].startswith("attachment; filename=\"trust-receipt-")
    receipt = r.json()
    assert receipt["kind"] == "maverick-trust-receipt"
    assert receipt["locator"] == {"day": DAY, "position": 2, "hash": target}
    assert receipt["claim"]["decision"] == "denied"
    assert receipt["claim"]["obligation_id"] == "gdpr-art32-outbound-transfer"
    assert len(receipt["chain"]["suffix_ndjson"]) == 1
    assert receipt["signature"]["key_id"]

    v = client.post(f"{BASE}/verify", json={"receipt": r.text})
    assert v.status_code == 200, v.text
    verdict = v.json()
    assert verdict["ok"] is True and verdict["depth"] == "signed"
    assert "LIGHTWORK TRUST RECEIPT" in verdict["report"]
    assert verdict["trusted_key_ids"]

    # Issuance is itself on the record.
    from maverick.audit.reader import iter_events
    kinds = [e.get("kind") for e in iter_events(all_days=True)]
    assert "trust_receipt_issued" in kinds


def test_mint_can_anchor_through_a_checkpoint_beside_the_audit_dir():
    written = _write_day()
    r = client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": written[0]["hash"],
                                          "anchor": True, "include_suffix": True})
    assert r.status_code == 200, r.text
    receipt = r.json()
    assert receipt["commitment"]["source"] == "checkpoint"
    digest = receipt["commitment"]["raw_sha256"]
    verdict = client.post(f"{BASE}/verify", json={"receipt": r.text, "anchor_digest": digest}).json()
    assert verdict["ok"] is True and verdict["depth"] == "anchored"
    wrong = client.post(f"{BASE}/verify", json={"receipt": r.text, "anchor_digest": "0" * 64}).json()
    assert wrong["ok"] is False


def test_mint_refuses_unknown_rows_and_bad_input():
    _write_day()
    r = client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": "a" * 64})
    assert r.status_code == 404
    assert client.post(f"{BASE}/mint", json={"day": "2026-02-30", "row_hash": "a" * 64}).status_code == 422
    assert client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": "short"}).status_code == 422
    assert client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": "a" * 64, "x": 1}).status_code == 422
    assert client.post(f"{BASE}/mint", json={"day": "2030-01-01", "row_hash": "a" * 64}).status_code == 404


def test_verify_fails_closed_without_a_trusted_key_and_catches_drift():
    written = _write_day()
    minted = client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": written[0]["hash"]})
    text, receipt = minted.text, minted.json()
    none = client.post(f"{BASE}/verify", json={"receipt": text, "use_local_keys": False}).json()
    assert none["ok"] is False and none["trusted_key_ids"] == []
    pasted = client.post(f"{BASE}/verify", json={
        "receipt": text, "use_local_keys": False, "keys": [receipt["signature"]["pubkey"]]}).json()
    assert pasted["ok"] is True
    # A stated claim that drifts from the row is rejected. A tool_call records
    # an attempt; only a paired successful tool_result proves execution.
    assert receipt["claim"]["decision"] == "attempted"
    drifted = json.loads(text)
    drifted["claim"]["decision"] = "denied"
    verdict = client.post(f"{BASE}/verify", json={"receipt": json.dumps(drifted)}).json()
    assert verdict["ok"] is False and "REJECTED" in verdict["report"]
    assert client.post(f"{BASE}/verify", json={"receipt": text, "keys": ["zz"]}).status_code == 422
    assert client.post(f"{BASE}/verify", json={"receipt": "[]"}).status_code == 422
    assert client.post(f"{BASE}/verify", json={"receipt": "{not json"}).status_code == 422
    assert client.post(f"{BASE}/verify", json={"receipt": {"kind": "x"}}).status_code == 422


def test_verify_takes_the_document_verbatim_because_reencoding_breaks_the_signature():
    """Found by driving the console in Chromium: JavaScript's JSON turns the
    float ``1767225600.0`` into ``1767225600``, and the canonical bytes the
    signature covers change with it. The endpoint therefore takes the receipt
    text as-is, like the CLI reads the file; a re-encoded copy is rejected."""
    written = _write_day()
    text = client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": written[0]["hash"]}).text

    def _normalise(value):
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, dict):
            return {k: _normalise(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_normalise(v) for v in value]
        return value

    reencoded = json.dumps(_normalise(json.loads(text)))
    assert reencoded != text
    assert client.post(f"{BASE}/verify", json={"receipt": text}).json()["ok"] is True
    rejected = client.post(f"{BASE}/verify", json={"receipt": reencoded}).json()
    assert rejected["ok"] is False and "signature" in rejected["reason"]


def test_verifier_download_is_the_standalone_module():
    r = client.get(f"{BASE}/verifier")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="trust_receipt_verify.py"'
    assert len(r.headers["x-verifier-sha256"]) == 64
    assert "import maverick" not in r.text and "def verify(" in r.text


def test_every_route_is_audit_gated(monkeypatch):
    from maverick_dashboard import trust_receipts_api as api_mod

    def _only(allowed):
        def _require(request, permission):
            if permission not in allowed:
                from fastapi import HTTPException
                raise HTTPException(status_code=403, detail="insufficient role")
        return _require

    monkeypatch.setattr(api_mod, "require_permission", _only({"view", "operate"}))
    assert client.get(f"{BASE}/status").status_code == 403
    assert client.get(f"{BASE}/rows", params={"day": DAY}).status_code == 403
    assert client.get(f"{BASE}/verifier").status_code == 403
    assert client.post(f"{BASE}/mint", json={"day": DAY, "row_hash": "a" * 64}).status_code == 403
    assert client.post(f"{BASE}/verify", json={"receipt": "{}"}).status_code == 403
    assert client.post(f"{BASE}/attestation", json={}).status_code == 403
    assert client.post(f"{BASE}/attestation/verify", json={"bundle": "{}"}).status_code == 403
    assert client.get(f"{BASE}/attestation/verifier").status_code == 403


def test_cross_origin_minting_is_refused_by_the_csrf_check():
    _write_day()
    foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://evil.example"})
    assert foreign.post(f"{BASE}/mint", json={"day": DAY, "row_hash": "a" * 64}).status_code == 403


def test_signed_proof_downloads_and_checks_against_this_installation():
    _write_day()
    r = client.post(f"{BASE}/attestation", json={"since_day": DAY})
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"] == 'attachment; filename="lightwork-proof.json"'
    bundle = r.text
    assert json.loads(bundle)["signature"]["sig"]
    checked = client.post(f"{BASE}/attestation/verify", json={"bundle": bundle})
    assert checked.status_code == 200, checked.text
    body = checked.json()
    assert body["ok"] is True and body["depth"] in {"signed", "corroborated"}
    assert {c["name"] for c in body["claims"]} >= {"policy_envelope", "authentic_history"}
    # A different trusted key fails closed.
    wrong = client.post(f"{BASE}/attestation/verify", json={"bundle": bundle, "key": "b" * 64,
                                                            "use_own_key": False})
    assert wrong.status_code == 200 and wrong.json()["ok"] is False
    assert client.post(f"{BASE}/attestation/verify",
                       json={"bundle": "not a proof"}).status_code == 422


def test_proof_checker_download_is_the_standalone_module():
    r = client.get(f"{BASE}/attestation/verifier")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="attestation_verify.py"'
    assert "import maverick" not in r.text
