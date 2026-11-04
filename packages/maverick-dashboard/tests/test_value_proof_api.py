"""Value and proof read-outs on the Spend and Savings pages: permissions,
workspace scoping, kernel behaviour and plain rendered wording."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
API = "/api/v1/value-proof"
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|capsule|attestation|telemetry|percentile)\b|/api/v1|HTTP \d{3}|maverick ",
    re.IGNORECASE,
)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def test_permissions_match_the_sensitivity(client, monkeypatch):
    _as(monkeypatch, "viewer")
    for path in ("/access", "/compounding", "/departments", "/earned-autonomy", "/fleet-memory",
                 "/record-stats", "/budget-tune", "/failures"):
        assert client.get(API + path).status_code == 200, path
    assert client.get(API + "/access").json() == {"admin": False, "audit": False}
    assert client.get(API + "/cost-retro").status_code == 403
    assert client.get(API + "/record-export").status_code == 403
    assert client.get(API + "/memory-export").status_code == 403
    assert client.post(API + "/earned-autonomy/revoke", json={"action": "x"}).status_code == 403
    _as(monkeypatch, "auditor", "user:auditor")
    assert client.get(API + "/cost-retro").status_code == 200
    assert client.get(API + "/record-export").status_code == 403


def test_spend_read_outs_use_the_kernel(client, monkeypatch):
    from maverick import budget_tuner, failure_telemetry
    from maverick.cost import retrospective as retro
    monkeypatch.setattr(retro, "retrospective", lambda world, top_n: {
        "total_spend": 12.5, "priced_goals": 3, "failed_spend": 2.5, "failed_share": 0.2,
        "top_concentration": 0.5, "observations": ["Most spend went to one task."],
        "top_goals": [{"goal_id": 7, "title": "Quarterly report", "cost": 9.0, "failed": False, "episodes": 2}]})
    out = client.get(API + "/cost-retro").json()
    assert out["costliest"][0] == {"task": 7, "title": "Quarterly report", "cost": 9.0, "failed": False}
    assert out["advice"] == ["Most spend went to one task."]

    monkeypatch.setattr(budget_tuner, "recommend_for_world", lambda world, pct, min_samples: {
        "default": {"recommended_max_dollars": 4.5, "samples": 9, "p90": 3.0}})
    assert client.get(API + "/budget-tune").json()["suggestions"] == [
        {"for": "Every task", "cap": 4.5, "typical_high": 3.0, "tasks": 9}]

    monkeypatch.setattr(failure_telemetry, "summarize", lambda: {"total": 3, "by_mode": {"budget": 2, "auth": 1}})
    reasons = client.get(API + "/failures").json()["reasons"]
    assert reasons == [{"reason": "Hit a spending limit", "count": 2},
                       {"reason": "Sign-in or permission problem", "count": 1}]


def test_spend_and_savings_tuning_matches_the_command_options(client, monkeypatch):
    from maverick import budget_tuner, compounding_metric
    from maverick.cost import retrospective as retro
    seen: dict = {}
    monkeypatch.setattr(budget_tuner, "recommend_for_world", lambda world, pct, min_samples: seen.update(
        pct=pct, min_samples=min_samples) or {"default": {"recommended_max_dollars": 6.0, "samples": 4, "p95": 5.0}})
    out = client.get(API + "/budget-tune", params={"percentile": 95, "min_samples": 3}).json()
    assert seen == {"pct": 95.0, "min_samples": 3}
    assert out["percentile"] == 95 and out["suggestions"][0]["typical_high"] == 5.0
    assert client.get(API + "/budget-tune", params={"percentile": 80}).status_code == 422
    monkeypatch.setattr(retro, "retrospective", lambda world, top_n: seen.update(top=top_n) or {
        "total_spend": 1.0, "priced_goals": 1, "failed_spend": 0.0, "failed_share": 0.0,
        "observations": [], "top_goals": []})
    client.get(API + "/cost-retro", params={"top": 25})
    assert seen["top"] == 25
    assert client.get(API + "/cost-retro", params={"top": 7}).status_code == 422
    monkeypatch.setattr(compounding_metric, "report_from_world", lambda world, window: seen.update(window=window) or [])
    client.get(API + "/compounding", params={"window": 10})
    assert seen["window"] == 10
    assert client.get(API + "/departments", params={"window": 4}).status_code == 422


def test_earned_autonomy_withdraw_is_admin_checked_and_recorded(client, monkeypatch):
    from maverick import earned_autonomy

    class _State:
        def __init__(self, action, graduated):
            self.action, self.graduated, self.hits, self.misses, self.streak = action, graduated, 12, 0, 12

    calls = []

    class _Engine:
        def status(self):
            return [_State("send_invoice", True)]

        def revoke(self, action, *, reason, principal):
            calls.append((action, principal))
            return True

    monkeypatch.setattr(earned_autonomy, "shared", lambda: _Engine())
    listed = client.get(API + "/earned-autonomy").json()
    assert listed["actions"][0]["name"] == "Send invoice" and listed["actions"][0]["auto_approved"] is False and listed["actions"][0]["evidence_qualified"] is True
    assert client.post(API + "/earned-autonomy/revoke", json={"action": "unknown"}).status_code == 404
    assert client.post(API + "/earned-autonomy/revoke", json={"action": "send_invoice"}).json()["revoked"] is True
    assert calls == [("send_invoice", "local:dashboard")]


def test_record_stats_are_workspace_scoped(client, monkeypatch):
    from maverick import world_model
    from maverick_dashboard import app as dash_app
    world = world_model.open_world()
    world.create_goal("Workspace-wide task")
    before = client.get(API + "/record-stats").json()
    assert before["tasks"] >= 1
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    dash_app._world_cache.clear()
    other = client.get(API + "/record-stats").json()
    assert other["tasks"] == 0


def test_record_download_and_check_round_trip(client):
    pytest.importorskip("cryptography")
    r = client.get(API + "/record-export")
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers["content-disposition"]
    good = client.post(API + "/record-verify", json={"document": r.text}).json()
    assert good["intact"] is True and good["from_this_installation"] is True
    tampered = json.loads(r.text)
    tampered["records"] = tampered.get("records", []) + [{"subject": "forged"}]
    bad = client.post(API + "/record-verify", json={"document": json.dumps(tampered)}).json()
    assert bad["intact"] is False
    assert client.post(API + "/record-verify", json={"document": "[1,2]"}).status_code == 422


def test_record_check_reports_a_foreign_capsule_as_intact_but_not_from_here(client):
    """The check page separates "unedited" from "made by this installation":
    a capsule another key signed is intact yet must never read as ours."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from maverick import operating_record as orec

    other = ed25519.Ed25519PrivateKey.generate()
    body = {"schema_version": 1, "ts": 1.0, "learned": {},
            "records": [{"ts": 1.0, "kind": "goal", "subject": "From elsewhere"}]}
    capsule = {**body, "key_id": "elsewhere",
               "pubkey": other.public_key().public_bytes(
                   encoding=serialization.Encoding.Raw,
                   format=serialization.PublicFormat.Raw).hex(),
               "sig": other.sign(orec._canonical(body)).hex()}

    out = client.post(API + "/record-verify", json={"document": json.dumps(capsule)}).json()

    assert out["intact"] is True and out["from_this_installation"] is False
    assert out["records"] == 1


def test_learning_statement_download_and_check(client):
    pytest.importorskip("cryptography")
    r = client.get(API + "/memory-export")
    assert r.status_code == 200, r.text
    out = client.post(API + "/memory-verify", json={"document": r.text}).json()
    assert out["intact"] is True and out["from_this_installation"] is True
    assert all(set(c) == {"claim", "result"} for c in out["claims"])
    from maverick.attestation import publisher_key
    key_id, pub = publisher_key()
    key_file = f"key_id: {key_id}\npubkey: {pub}\n"
    same = client.post(API + "/memory-verify", json={"document": r.text, "publisher_key": key_file}).json()
    assert same["intact"] is True
    other = "pubkey: " + "ab" * 32  # pragma: allowlist secret
    wrong = client.post(API + "/memory-verify", json={"document": r.text, "publisher_key": other}).json()
    assert wrong["intact"] is False and wrong["from_this_installation"] is False
    none = client.post(API + "/memory-verify", json={"document": r.text, "publisher_key": "no key here"})
    assert none.status_code == 422


def test_spend_and_savings_pages_show_the_new_sections_plainly(client):
    for path, marker, heading in (("/spend", 'id="vp-spend"', "Where spend went and what to do"),
                                  ("/savings", 'id="vp-proof"', "Proof of results")):
        page = client.get(path).text
        assert marker in page and "/static/lightwork-value-proof.js" in page
        own = page.split(marker, 1)[1].split(">", 1)[1].split("<style>", 1)[0]
        visible = re.sub(r"<script[\s\S]*?</script>|<[^>]+>", " ", own)
        assert heading in visible
        assert not _BANNED.search(visible), visible


def test_value_proof_script_is_served(client):
    r = client.get("/static/lightwork-value-proof.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert "window.confirm(" not in r.text and "mvConfirm" in r.text
