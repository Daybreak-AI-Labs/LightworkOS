"""HTTP contract of the Cortex API (``/api/v1/cortex``): reads at the page's
``view`` floor, writes at ``operate``, every mutation same-origin, input
bounded at the boundary, and the kernel ``Result`` passed through verbatim
under its provenance envelope with the caller named by the authenticated
principal."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import cortex
from maverick_dashboard import cortex_api
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
BASE = "/api/v1/cortex"
_DEPOSIT = {"text": "Accruals over $25k need controller sign-off.", "kind": "knowledge",
            "collection": "finance", "source": "close-policy.md"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import api

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT",
                 "MAVERICK_TENANT_BY_USER", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_CORTEX"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _hit(source, kind, text, citation, score=1.0, **meta):
    return cortex.Hit(source, kind, text, citation, score, dict(meta))


@pytest.fixture
def recalled(monkeypatch):
    """A deterministic kernel: records every call, answers from three sources
    and refuses the fleet path the way the kernel does for internal callers."""
    calls: list[tuple[str, dict]] = []

    def _recall(query, **kw):
        calls.append((query, kw))
        wanted = tuple(kw.get("sources") or cortex.SOURCES)
        res = cortex.Result(query=query, tenant="acme", sources=wanted,
                            per_source=dict.fromkeys(wanted, 0))
        fixture_hits = (
            _hit("knowledge", "finance", "Accruals over $25k need controller sign-off.",
                 "finance/close-policy.md", 0.91, collection="finance"),
            _hit("knowledge", "finance", "Vendor onboarding needs a W-9.",
                 "finance/vendors.md", 0.62, collection="finance"),
            _hit("skills", "skill", "Run the close checklist.", "month-end-close", 1.0,
                 triggers=["close"], verified=True),
            _hit("record", "approval", "Release $6,000 vendor payment",
                 "record · approval · j.alvarez · 2026-01-01 00:00", 1.0, goal_id=7),
        )
        for source in wanted:
            if source == "knowledge" and callable(kw.get("knowledge_reader")):
                hits, denied = kw["knowledge_reader"](query, kw["k"])
                res.hits.extend(hits)
                res.per_source[source] = len(hits)
                if denied:
                    res.denied[source] = denied
                continue
            for hit in fixture_hits:
                if hit.source != source:
                    continue
                res.hits.append(hit)
                res.per_source[hit.source] += 1
        if "fleet" in wanted:
            res.denied["fleet"] = "fleet memory answers enrolled external agents"
        res.took_ms = 7
        res.audited = True
        return res

    monkeypatch.setattr(cortex, "recall", _recall)
    return calls


@pytest.fixture
def deposited(monkeypatch):
    calls: list[tuple[str, dict]] = []

    def _deposit(text, **kw):
        calls.append((text, kw))
        return True, "ingested"

    monkeypatch.setattr(cortex, "deposit", _deposit)
    return calls


def test_status_reports_every_source_and_the_posture():
    r = client.get(f"{BASE}/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == cortex_api.STATUS_SCHEMA
    assert isinstance(body["enabled"], bool)
    assert set(body["sources"]) == set(cortex.SOURCES)
    assert set(body["encryption"]) == {"at_rest", "per_tenant"}
    assert body["isolation"]["pooled_across_tenants"] is False


def test_recall_never_falls_back_to_raw_legacy_knowledge(recalled):
    r = client.post(f"{BASE}/recall", json={"query": "close accrual", "k": 3})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == cortex_api.RECALL_SCHEMA
    assert body["query"] == "close accrual" and body["tenant"] == "acme"
    assert body["sources"] == list(cortex.SOURCES)
    assert body["per_source"] == {
        "knowledge": 0, "skills": 1, "lessons": 0, "record": 1, "fleet": 0,
    }
    assert [h["source"] for h in body["hits"]] == ["skills", "record"]
    assert body["denied"] == {
        "fleet": "fleet memory answers enrolled external agents",
        "knowledge": (
            "Current source access could not be revalidated. "
            "Open Knowledge and request fresh access or evidence."
        ),
    }
    assert body["audited"] is True and body["took_ms"] == 7
    query, kw = recalled[0]
    assert query == "close accrual" and kw["k"] == 3 and kw["domain"] is None
    assert tuple(kw["sources"]) == cortex.SOURCES
    # internal, named "dashboard" when no principal is established (auth off)
    assert kw["caller"] == cortex.Caller(principal="dashboard")
    assert kw["caller"].external is False


def test_recall_narrows_sources_and_domain_and_dedupes(recalled):
    r = client.post(f"{BASE}/recall", json={
        "query": "vendor", "sources": ["record", "knowledge", "record"], "domain": "finance"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sources"] == ["record", "knowledge"]
    assert body["per_source"] == {"record": 1, "knowledge": 0}
    assert body["denied"] == {
        "knowledge": (
            "Current source access could not be revalidated. "
            "Open Knowledge and request fresh access or evidence."
        ),
    }
    _query, kw = recalled[0]
    assert tuple(kw["sources"]) == ("record", "knowledge") and kw["domain"] == "finance"
    assert kw["k"] == cortex_api.DEFAULT_K


def test_recall_uses_governed_exact_knowledge_and_discards_legacy_hits(
    recalled,
    monkeypatch,
):
    from maverick_dashboard import knowledge_access_api

    class Governed:
        def search(self, tenant, actor, *, query, purpose, limit):
            assert (tenant, actor, query, purpose, limit) == (
                "acme", "user:jo", "close", "product_research", 5,
            )
            return {
                "items": [{
                    "reference": {
                        "kind": "dataset", "asset_id": "close-policy", "version": "v7",
                        "manifest_sha256": "1" * 64,
                        "schema": "lightwork.research-registry-ref.v1",
                    },
                    "title": "Current close policy",
                    "summary": "Controller approval is required.",
                    "claim_state": "verified",
                    "source": {
                        "provenance_kind": "source",
                        "source_ref": "catalog:evidence-graph/node-7",
                    },
                    "eligibility": {
                        "fresh_until": 4_102_444_800.0,
                        "actor_authorization_sha256": "2" * 64,
                    },
                }],
            }

    monkeypatch.setattr(cortex_api, "caller_principal", lambda request: "user:jo")
    monkeypatch.setattr(cortex_api, "current_tenant_id_strict", lambda: "acme")
    monkeypatch.setattr(knowledge_access_api, "_service", lambda request: Governed())

    response = client.post(f"{BASE}/recall", json={"query": "close"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["per_source"]["knowledge"] == 1
    knowledge = [hit for hit in body["hits"] if hit["source"] == "knowledge"]
    assert len(knowledge) == 1
    assert knowledge[0]["text"] == "Controller approval is required."
    assert knowledge[0]["citation"] == "catalog:evidence-graph/node-7"
    assert knowledge[0]["meta"]["registry_reference"]["manifest_sha256"] == "1" * 64
    assert tuple(recalled[0][1]["sources"]) == cortex.SOURCES


def test_recall_names_the_authenticated_principal(recalled, monkeypatch):
    monkeypatch.setattr(cortex_api, "caller_principal", lambda request: "user:jo")
    assert client.post(f"{BASE}/recall", json={"query": "close"}).status_code == 200
    assert recalled[0][1]["caller"] == cortex.Caller(principal="user:jo")


def test_recall_bounds_its_input(recalled):
    post = lambda body: client.post(f"{BASE}/recall", json=body).status_code  # noqa: E731
    assert post({"query": "x" * cortex_api.MAX_QUERY}) == 200
    assert post({"query": "x" * (cortex_api.MAX_QUERY + 1)}) == 422
    assert post({"query": ""}) == 422
    assert post({"query": "   "}) == 422
    assert post({"query": 5}) == 422
    assert post({"query": "q", "k": 0}) == 422
    assert post({"query": "q", "k": cortex_api.MAX_K}) == 200
    assert post({"query": "q", "k": cortex_api.MAX_K + 1}) == 422
    assert post({"query": "q", "k": "5"}) == 422
    assert post({"query": "q", "sources": ["bogus"]}) == 422
    assert post({"query": "q", "sources": []}) == 422
    assert post({"query": "q", "sources": "knowledge"}) == 422
    assert post({"query": "q", "domain": "x" * 65}) == 422
    assert post({"query": "q", "domain": ""}) == 422
    assert post({"query": "q", "extra": 1}) == 422
    # only the in-bound calls reached the kernel
    assert len(recalled) == 2


def test_deposit_is_same_origin_only(deposited):
    r = client.post(f"{BASE}/deposit", json=_DEPOSIT)
    assert r.status_code == 200, r.text
    assert r.json() == {"schema": cortex_api.DEPOSIT_SCHEMA, "ok": True,
                        "reason": "ingested", "kind": "knowledge"}
    text, kw = deposited[0]
    assert text == _DEPOSIT["text"]
    assert kw["kind"] == "knowledge" and kw["collection"] == "finance"
    assert kw["source"] == "close-policy.md" and kw["domain"] is None
    assert kw["caller"] == cortex.Caller(principal="dashboard")
    # a cross-site page cannot write to the brain; neither can a request with
    # no Origin at all (the guard fails closed)
    foreign = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://evil.example"})
    assert foreign.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 403
    assert TestClient(app, base_url="http://127.0.0.1").post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 403
    assert len(deposited) == 1


def test_deposit_defaults_and_fleet_kind(deposited):
    r = client.post(f"{BASE}/deposit", json={"text": "  lesson  ", "kind": "fleet", "domain": "ops"})
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "fleet"
    text, kw = deposited[0]
    assert text == "lesson"
    assert kw["kind"] == "fleet" and kw["collection"] == "cortex"
    assert kw["source"] == "" and kw["domain"] == "ops"


def test_deposit_reports_a_kernel_refusal_without_raising(monkeypatch):
    monkeypatch.setattr(cortex, "deposit",
                        lambda text, **kw: (False, "cortex is disabled ([cortex] enable = true)"))
    r = client.post(f"{BASE}/deposit", json=_DEPOSIT)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is False and "disabled" in r.json()["reason"]


def test_deposit_bounds_its_input(deposited):
    post = lambda body: client.post(f"{BASE}/deposit", json=body).status_code  # noqa: E731
    assert post({"text": "x" * cortex_api.MAX_TEXT}) == 200
    assert post({"text": "x" * (cortex_api.MAX_TEXT + 1)}) == 422
    assert post({"text": ""}) == 422
    assert post({"text": "   "}) == 422
    assert post({"text": "x", "kind": "bogus"}) == 422
    assert post({"text": "x", "collection": "Bad Name"}) == 422
    assert post({"text": "x", "collection": "../etc"}) == 422
    assert post({"text": "x", "collection": "x" * 65}) == 422
    assert post({"text": "x", "source": "s" * 201}) == 422
    assert post({"text": "x", "domain": "d" * 65}) == 422
    assert post({"text": "x", "extra": 1}) == 422
    assert len(deposited) == 1


def test_reads_need_view_and_writes_need_operate(monkeypatch, recalled, deposited):
    def _only(allowed):
        def _require(request, permission):
            if permission not in allowed:
                from fastapi import HTTPException
                raise HTTPException(status_code=403, detail="insufficient role")
        return _require

    monkeypatch.setattr(cortex_api, "require_permission", _only({"view"}))
    assert client.get(f"{BASE}/status").status_code == 200
    assert client.post(f"{BASE}/recall", json={"query": "close"}).status_code == 200
    assert client.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 403
    monkeypatch.setattr(cortex_api, "require_permission", _only({"operate"}))
    assert client.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 200
    monkeypatch.setattr(cortex_api, "require_permission", _only({"audit"}))
    assert client.get(f"{BASE}/status").status_code == 403
    assert client.post(f"{BASE}/recall", json={"query": "close"}).status_code == 403
    assert client.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 403
    assert len(recalled) == 1 and len(deposited) == 1


def test_a_viewer_reads_the_brain_but_cannot_write_to_it(monkeypatch, recalled, deposited):
    """The real RBAC path: a stored viewer role, resolved by the auth layer."""
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vw", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vw")
    monkeypatch.setattr(cortex_api, "caller_principal", lambda request: "user:vw")
    assert client.get(f"{BASE}/status").status_code == 200
    r = client.post(f"{BASE}/recall", json={"query": "close"})
    assert r.status_code == 200, r.text
    assert recalled[0][1]["caller"].principal == "user:vw"
    assert client.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 403
    assert deposited == []
    rbac.set_role("user:op", "operator")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:op")
    monkeypatch.setattr(cortex_api, "caller_principal", lambda request: "user:op")
    assert client.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 200
    assert deposited[0][1]["caller"].principal == "user:op"


def test_unauthenticated_requests_are_refused_when_a_token_is_configured(monkeypatch, recalled):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    anonymous = TestClient(app, base_url="http://127.0.0.1")
    assert anonymous.get(f"{BASE}/status").status_code == 401
    assert anonymous.post(f"{BASE}/recall", json={"query": "close"}).status_code == 401
    assert anonymous.post(f"{BASE}/deposit", json=_DEPOSIT).status_code == 401
    assert recalled == []
    bearer = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer sekret"})
    assert bearer.get(f"{BASE}/status").status_code == 200
    assert bearer.post(f"{BASE}/recall", json={"query": "close"}).status_code == 200
