"""AI governance operations as buttons: the company rules for actions, apps
using the AI gateway, fairness and explainability checks (optionally saved as
evidence), the insurance evidence pack prepared in the background, and
regulatory alerts turned into impact records -- ``maverick governance show``,
``gateway``, ``explainability``, ``underwriting-pack export`` and
``regulatory-feed sync``."""
from __future__ import annotations

import hashlib
import html as _html
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/governance-ops"
BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|spearman|z_score|deny_actions)\b|/api/v1|"
    r"HTTP \d{3}|maverick |MAVERICK_|\[\w+\]",
    re.IGNORECASE,
)
CONFIG = """
[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = false

[explainability]
enable = true

[governance]
deny_actions = ["wire_transfer"]
require_human_min_risk = "high"
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import ops_file_jobs as ops_jobs

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    ops_jobs.reset_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    ops_jobs.reset_for_tests()
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _actions(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import writer

    seen: list[str] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(str(payload.get("action") or kind))
        return real(kind, **payload)
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _asset() -> str:
    from maverick import model_risk_assurance as mra

    observation = mra.ModelRiskAssuranceOfficer().observe_asset(
        asset_type="model", source="dash_test", source_id="screener", display_name="Screening model",
        version_digest=hashlib.sha256(b"screener-v1").hexdigest(), actor="inventory-operator",
        observed_at=time.time(), metadata={}, dependencies=[])
    return observation["asset_id"]


def test_company_rules_read_as_sentences(client, monkeypatch):
    body = client.get(f"{BASE}/policy").json()
    assert "Wire transfer is never allowed." in body["rules"]
    assert any("high-risk action or riskier waits for a person" in r for r in body["rules"])
    assert all(not BANNED.search(r) for r in body["rules"] + [body["summary"]])
    _as(monkeypatch, "viewer")
    assert client.get(f"{BASE}/policy").status_code == 200
    from maverick_dashboard import auth
    monkeypatch.setattr(auth, "has_permission", lambda request, permission: False)
    assert client.get(f"{BASE}/policy").status_code == 403


def test_gateway_callers_are_listed_without_request_contents(client, monkeypatch):
    from maverick import llm_gateway

    empty = client.get(f"{BASE}/gateway").json()
    assert empty["callers"] == [] and "off" in empty["summary"]
    llm_gateway._record_call(caller="c" * 64, model="gpt-test", status="ok", prompt_sha256="0" * 64,
                             usage={"prompt_tokens": 3}, now=time.time())
    body = client.get(f"{BASE}/gateway").json()
    assert len(body["callers"]) == 1
    row = body["callers"][0]
    assert row["app"] == "App cccccccc" and row["calls"] == 1 and row["last_result"] == "Answered"
    assert "0" * 64 not in json.dumps(body)
    _as(monkeypatch, "viewer")
    assert client.get(f"{BASE}/gateway").status_code == 403


def test_fairness_check_saves_honest_evidence_when_asked(client, monkeypatch):
    asset = _asset()
    assets = client.get(f"{BASE}/assets").json()["assets"]
    assert {"id": asset, "name": "Screening model"} in assets
    seen = _actions(monkeypatch)
    body = {"groups": [{"name": "Group A", "selected": 8, "total": 10},
                       {"name": "Group B", "selected": 4, "total": 10}], "asset_id": asset}
    r = client.post(f"{BASE}/fairness", json=body)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["passed"] is False and result["saved"] is True
    assert "Group B" in result["summary"] and not BANNED.search(result["summary"])
    assert "explainability_evidence" in seen
    from maverick import model_risk_assurance as mra
    evidence = [e for e in mra.list_evidence() if e.get("asset_id") == asset]
    assert evidence and evidence[-1]["result"] == "failed"
    # Bounded input.
    assert client.post(f"{BASE}/fairness", json={"groups": [body["groups"][0]]}).status_code == 422
    bad = {"groups": [{"name": "A", "selected": 11, "total": 10}, {"name": "B", "selected": 1, "total": 2}]}
    assert client.post(f"{BASE}/fairness", json=bad).status_code == 422
    assert client.post(f"{BASE}/fairness", json={**body, "asset_id": "../x"}).status_code == 422
    _as(monkeypatch, "viewer")
    assert client.post(f"{BASE}/fairness", json=body).status_code == 403


SHEET = "income,debt,score\n10,5,0.2\n20,4,0.4\n30,3,0.6\n40,2,0.8\n90,1,0.95\n"


def test_spreadsheet_checks_rank_inputs_and_explain_one_decision(client):
    ranked = client.post(f"{BASE}/sensitivity", json={"sheet": SHEET, "score_column": "score"}).json()
    assert ranked["decisions"] == 5 and ranked["saved"] is False
    assert {row["input"] for row in ranked["ranked"]} == {"income", "debt"}
    reasons = client.post(f"{BASE}/reasons", json={"sheet": SHEET, "row": 5, "top": 2}).json()
    assert reasons["reasons"][0]["input"] in {"income", "score"}
    assert reasons["reasons"][0]["direction"] == "above"
    assert client.post(f"{BASE}/sensitivity", json={"sheet": "a,b\n1,x\n2,3\n4,5\n"}).status_code == 422
    assert client.post(f"{BASE}/sensitivity", json={"sheet": SHEET, "score_column": "nope"}).status_code == 422
    assert client.post(f"{BASE}/reasons", json={"sheet": SHEET, "row": 50}).status_code == 422
    big = "a,b\n" + "1,2\n" * 5002
    assert client.post(f"{BASE}/sensitivity", json={"sheet": big}).status_code == 413


def test_checks_say_plainly_when_turned_off(client, tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    r = client.post(f"{BASE}/sensitivity", json={"sheet": SHEET})
    assert r.status_code == 503 and "turned off" in r.json()["detail"]


def _wait(client, url):
    for _ in range(300):
        state = client.get(url).json()
        if state["state"] != "running":
            return state
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_insurance_pack_is_prepared_in_the_background_then_downloaded(client, monkeypatch):
    _asset()
    seen = _actions(monkeypatch)
    started = client.post(f"{BASE}/underwriting-pack", json={})
    assert started.status_code == 202, started.text
    job = started.json()["job"]
    assert "underwriting_pack_export" in seen
    assert _wait(client, f"{BASE}/underwriting-pack/{job}")["state"] == "ready"
    download = client.get(f"{BASE}/underwriting-pack/{job}/download")
    assert download.status_code == 200
    assert download.headers["content-disposition"].startswith('attachment; filename="lightwork-insurance-evidence-')
    pack = download.json()
    assert pack["summary"]["inventory_count"] == 1
    # The same bytes the terminal command writes.
    assert download.text == json.dumps(pack, indent=2, sort_keys=True, default=str)
    # Someone else cannot see or fetch it.
    _as(monkeypatch, "operator", "user:other")
    assert client.get(f"{BASE}/underwriting-pack/{job}").status_code == 404
    assert client.get(f"{BASE}/underwriting-pack/{job}/download").status_code == 404
    assert client.get(f"{BASE}/underwriting-pack/not-a-job").status_code == 404
    _as(monkeypatch, "viewer", "user:vic")
    assert client.post(f"{BASE}/underwriting-pack", json={}).status_code == 403


def test_insurance_pack_failure_is_plain(client, tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    job = client.post(f"{BASE}/underwriting-pack", json={}).json()["job"]
    state = _wait(client, f"{BASE}/underwriting-pack/{job}")
    assert state["state"] == "failed" and "turn them on" in state["message"]
    assert client.get(f"{BASE}/underwriting-pack/{job}/download").status_code == 409


class _Alert:
    def __init__(self, alert_id, regimes=("eu_ai_act",), domains=()):
        self.alert_id, self.matched_regimes, self.matched_domains = alert_id, regimes, domains


def _feed(monkeypatch, alerts):
    from maverick import ai_regulatory_feed as feed
    from maverick.finance import regulatory_change

    class Engine:
        def __init__(self, path):
            self.path = path

        def list_alerts(self, *, status, limit):
            return [a for a in alerts if status == "accepted"]
    monkeypatch.setattr(regulatory_change, "RegulatoryChangeEngine", Engine)
    seen = []

    def sync_alert(alert, *, rules, actor, deliver):
        seen.append((alert.alert_id, rules, deliver))
        if alert.alert_id == "RA-2":
            return {"impact": None, "staleness": None, "notice": None}
        return {"impact": {"id": "ARI-1"},
                "staleness": {"id": "ARS-1", "stale_evidence_ids": ["MRE-1"]},
                "notice": {"id": "ARN-1", "delivery": {"status": "pending"}}}
    monkeypatch.setattr(feed, "sync_alert", sync_alert)
    return seen


def test_regulatory_alerts_become_impact_records_with_one_guided_rule(client, monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    seen = _feed(monkeypatch, [_Alert("RA-1"), _Alert("RA-2", regimes=(), domains=("lending",))])
    token = set_tenant("acme")
    try:
        preview = client.post(f"{BASE}/regulatory-feed/preview", json={"queue": "accepted"}).json()
        assert preview["alerts"] == 2
        assert [r["value"] for r in preview["regimes"]] == ["eu_ai_act"]
        assert [d["value"] for d in preview["domains"]] == ["lending"]
        body = {"queue": "accepted", "regimes": ["eu_ai_act"], "send_notices": False}
        assert client.post(f"{BASE}/regulatory-feed/sync", json=body).status_code == 409
        assert not seen
        assert client.post(f"{BASE}/regulatory-feed/sync",
                           json={**body, "regimes": [], "confirm": True}).status_code == 422
        assert client.post(f"{BASE}/regulatory-feed/sync",
                           json={**body, "regimes": ["bad value!"], "confirm": True}).status_code == 422
        actions = _actions(monkeypatch)
        done = client.post(f"{BASE}/regulatory-feed/sync", json={**body, "confirm": True})
        assert done.status_code == 200, done.text
        result = done.json()
        assert result["alerts"] == 2 and result["matched"] == 1 and result["stale_evidence"] == 1
        assert not BANNED.search(result["summary"])
        assert seen[0][1] == [{"rule_id": "dashboard-rule", "regimes": ["eu_ai_act"], "domains": [],
                               "asset_ids": []}]
        assert "regulatory_feed_sync" in actions
    finally:
        reset_tenant(token)


def test_regulatory_alerts_need_a_workspace_and_an_installation_admin(client, monkeypatch):
    _feed(monkeypatch, [_Alert("RA-1")])
    r = client.post(f"{BASE}/regulatory-feed/preview", json={"queue": "accepted"})
    assert r.status_code == 409 and "workspace" in r.json()["detail"]
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import rbac
    _as(monkeypatch, "viewer", "user:alice")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    token = set_tenant("acme")
    try:
        assert client.post(f"{BASE}/regulatory-feed/preview", json={"queue": "accepted"}).status_code == 403
        assert client.post(f"{BASE}/regulatory-feed/sync",
                           json={"regimes": ["eu_ai_act"], "confirm": True}).status_code == 403
    finally:
        reset_tenant(token)


def _section(page: str, root_id: str) -> str:
    start = page.index(f'id="{root_id}"')
    end = page.find("</section>", start)
    section = page[start:end if end > 0 else len(page)]
    section = re.sub(r"<(script|style)\b.*?</\1>", " ", section, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", section)))


def test_pages_show_the_new_controls_in_plain_words(client):
    assurance = client.get("/security/assurance").text
    for control in ("ops-gateway", "ops-fair-run", "ops-sens-run", "ops-reasons-run", "ops-pack-start",
                    "ops-sheet-file", "ops-explain-asset", "ops-pack-asset"):
        assert f'id="{control}"' in assurance
    assert not BANNED.search(_section(assurance, "ops-ai-gov"))
    obligations = client.get("/compliance/obligations").text
    for control in ("ops-feed-look", "ops-feed-run", "ops-feed-regimes", "ops-feed-notices"):
        assert f'id="{control}"' in obligations
    assert not BANNED.search(_section(obligations, "ops-feed"))
    permissions = client.get("/permissions").text
    assert 'id="ops-policy"' in permissions and "Company rules for actions" in permissions
