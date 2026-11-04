"""Setting up continuous-evidence collection from configured sources: every
identifier and fingerprint comes from the server; approval stays four-eyes."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import trc_continuous_evidence as evidence
from maverick_dashboard import trc_continuous_evidence_api as api
from maverick_dashboard import trc_setup_api as setup

API = "/api/v1/compliance/continuous-evidence"


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {"tenant": "tenant-a", "calls": [], "allowed": ["local_soc2_v1"], "deny": set()}
    database = tmp_path / "continuous-evidence.sqlite3"

    def permission(_request, name):
        state["calls"].append(name)
        if name in state["deny"]:
            raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(evidence, "require_enabled", lambda: None)
    monkeypatch.setattr(evidence, "enabled", lambda: True)
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    for module in (api, setup):
        monkeypatch.setattr(module, "require_permission", permission)
        monkeypatch.setattr(module, "require_global_permission", permission)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal=request.headers.get("X-Test-Subject", "author"))
        return await call_next(request)

    app.state.trc_continuous_evidence_store_factory = lambda **kw: evidence.ContinuousEvidenceStore(
        database, tenant_id=kw["tenant_id"], principal_resolver=kw["principal_resolver"],
        config_gate=lambda: None, clock=lambda: 1_800_000_000.0)
    app.state.trc_continuous_evidence_config_loader = lambda: {
        "tech_risk_compliance": {"enable": True, "continuous_evidence": {
            "enable": True, "enabled_collectors": list(state["allowed"])}}}
    app.include_router(api.router, prefix="/api/v1")
    app.include_router(setup.router)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), state


def test_local_checks_are_listed_without_fingerprints_or_scopes(environment):
    client, state = environment
    items = client.get(f"{API}/setup").json()["items"]
    assert [(i["key"], i["label"]) for i in items] == [("local-soc2", "Lightwork's own security checks")]
    assert "sha256" not in repr(items)
    assert not re.search(r"[0-9a-f]{64}", repr(items))
    assert state["calls"][-1] == "view"
    state["allowed"] = []
    assert client.get(f"{API}/setup").status_code in {403, 503}   # fails closed


def test_set_up_approve_by_someone_else_then_start(environment):
    client, state = environment
    assert client.post(f"{API}/setup/local-soc2/definition").status_code == 200
    assert state["calls"][-1] == "admin"
    # Pressing Set up twice does not create a second setup.
    assert client.post(f"{API}/setup/local-soc2/definition").status_code == 200
    definitions = client.get(f"{API}/definitions").json()["items"]
    assert [(d["definition_id"], d["state"]) for d in definitions] == [("local-soc2", "pending")]
    body = {"interval_seconds": 86_400, "retention_seconds": 31_536_000}
    assert client.post(f"{API}/setup/local-soc2/enrollment", json=body).status_code == 409
    own = client.post(f"{API}/definitions/local-soc2/versions/1/approve",
                      json={"expected_integrity_sha256": definitions[0]["integrity_sha256"]})
    assert own.status_code == 403
    other = client.post(f"{API}/definitions/local-soc2/versions/1/approve", headers={"X-Test-Subject": "reviewer"},
                        json={"expected_integrity_sha256": definitions[0]["integrity_sha256"]})
    assert other.status_code == 200, other.text
    started = client.post(f"{API}/setup/local-soc2/enrollment", json=body)
    assert started.status_code == 200, started.text
    enrollments = client.get(f"{API}/enrollments").json()["items"]
    assert [(e["enrollment_id"], e["state"]) for e in enrollments] == [("local-soc2", "active")]


def test_setup_needs_an_administrator_and_a_configured_source(environment):
    client, state = environment
    assert client.post(f"{API}/setup/aws-hub/definition").status_code == 404
    state["deny"] = {"admin"}
    assert client.post(f"{API}/setup/local-soc2/definition").status_code == 403
    assert client.post(f"{API}/setup/local-soc2/enrollment",
                       json={"interval_seconds": 86_400, "retention_seconds": 31_536_000}).status_code == 403
