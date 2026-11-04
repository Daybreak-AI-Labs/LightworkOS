"""Bring-your-own-agent gateway over HTTP: admin enrollment + credential
minting on the dashboard surface, and the self-authenticated agent-facing
routes (minted bearer or platform-native credential — no session, no CSRF
surface, 404 while disabled)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import threading
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

# Crypto availability gate for the signed-identity tests (same probe as
# test_oidc / test_external_identity): if this sandbox's cryptography/PyJWT
# is broken they SKIP — CI has working crypto and is the real gate.
_CRYPTO_OK = True
_CRYPTO_SKIP_REASON = ""
try:  # noqa: SIM105
    import jwt  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    _probe = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _probe.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
except Exception as _e:  # pragma: no cover - env-dependent
    _CRYPTO_OK = False
    _CRYPTO_SKIP_REASON = (
        f"working cryptography/PyJWT unavailable: {type(_e).__name__}: {_e}")

requires_crypto = pytest.mark.skipif(not _CRYPTO_OK,
                                     reason=_CRYPTO_SKIP_REASON)

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import agent_trust, config, external_agents, world_model
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(agent_trust, "managed_path",
                        lambda: tmp_path / "agent_trust.json")
    monkeypatch.setattr(external_agents, "registry_path",
                        lambda: tmp_path / "external_agents.json")
    # Unrated action names take the high refusal floor, so the deployment
    # rates this fixture's platform actions and fake connector read the way an
    # operator classifies their own (wire_transfer/send_contract stay high).
    (tmp_path / "config.toml").write_text(
        '[security.tool_risk]\nresearch = "low"\ncrm_update = "medium"\n"fakecrm.read" = "low"\n',
        encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.mark.parametrize(("path", "maximum"), [
    ("/api/v1/external/runs", 256 * 1024),
    ("/api/v1/external/runtime/evaluate", 512 * 1024),
    ("/api/v1/external/discovery-sensors/sensor/observations", 64 * 1024),
    ("/api/v1/external/ai-vendor/submissions", 128 * 1024),
    ("/api/v1/external/red-team/campaign/results", 2 * 1024 * 1024),
])
def test_external_body_limit_applies_before_authentication(monkeypatch, path, maximum):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    response = client.post(path, content=b"{}", headers={"Content-Length": str(maximum + 1)})
    assert response.status_code == 413


def test_chunked_external_body_stops_reading_at_limit(monkeypatch):
    import httpx

    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    sent = []

    async def chunks():
        for i in range(3):
            sent.append(i)
            yield b"x" * (128 * 1024 + 1)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1") as requester:
            return await requester.post("/api/v1/external/runs", content=chunks())

    assert asyncio.run(run()).status_code == 413
    assert sent == [0, 1]


def test_signed_get_body_is_limited_before_authentication(monkeypatch):
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    response = client.request(
        "GET", "/api/v1/external/approvals/1", content=b"{}",
        headers={"Content-Length": str(256 * 1024 + 1), "X-Agent-Signature": "synthetic"},
    )
    assert response.status_code == 413


def test_slow_external_body_times_out_and_releases_capacity(monkeypatch):
    import httpx
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "0")
    monkeypatch.setattr(dash_app, "_EXTERNAL_BODY_SLOTS", 1)
    monkeypatch.setattr(dash_app, "_EXTERNAL_BODY_TIMEOUT_SECONDS", 0.03)

    async def slow():
        yield b"{"
        await asyncio.sleep(1)
        yield b"}"

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://127.0.0.1") as requester:
            first = await requester.post("/api/v1/external/runs", content=slow())
            second = await requester.post("/api/v1/external/runs", content=b"{}")
            return first.status_code, second.status_code

    first, second = asyncio.run(run())
    assert first == 408
    assert second != 503


def _enroll(**overrides):
    body = {"id": "sf-quotebot", "platform": "agentforce",
            "description": "quoting agent", "owner": "jordan@corp.test",
            "department": "sales", "max_risk": "medium", "max_dollars": 5.0}
    body.update(overrides)
    return client.post("/api/v1/external-agents", json=body)


def _mint() -> str:
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "rest"})
    assert r.status_code == 200
    return r.json()["token"]


def _stub_review_is_current(monkeypatch, assurance):
    """These stubbed records stand for a current reviewed declaration only
    while it is approved for the observed version. The full review binding
    (record digests, profile and hierarchy) is model_risk_assurance's own
    check, which hand-written stub records cannot satisfy."""
    monkeypatch.setattr(assurance._DEFAULT, "_declaration_is_current", lambda declaration, observation: (
        declaration.get("status") == "approved"
        and declaration.get("observed_version_digest") == observation.get("version_digest")))


def test_enroll_mint_and_roster_roundtrip():
    r = _enroll()
    assert r.status_code == 201
    assert r.json()["trust"] == "registered"
    token = _mint()
    assert token.startswith("lw-rest-")
    listing = client.get("/api/v1/external-agents").json()
    (row,) = listing["agents"]
    assert row["platform_label"] == "Salesforce Agentforce"
    assert row["credentials"] == ["rest"]
    # The token value never reappears on any read surface.
    assert token not in str(listing)
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["department"] == "sales"
    assert client.get("/api/v1/external-agents/ghost").status_code == 404


def test_connected_change_readback_and_copilot_use_safe_native_metadata_only(monkeypatch):
    from maverick import external_agents as xa
    from maverick_dashboard import product_operations as operations

    assert _enroll(description="Order helper").status_code == 201
    with xa._sidecar_locked():
        data = xa._load_sidecar()
        data["sf-quotebot"]["executions"] = {
            "synthetic-unknown": {"status": "indeterminate", "connector": "salesforce", "op": "patch",
                "created_at": time.time(), "finished_at": time.time(),
                "digest": "PRIVATE-SYNTHETIC-DIGEST", "path": "/private/customer/record", "body": {"private": "PRIVATE-SYNTHETIC-BODY"}},
            "synthetic-confirmed": {"status": "executed", "connector": "jira", "op": "post", "created_at": time.time()-1},
            "synthetic-accepted": {"status": "accepted", "connector": "jira", "op": "post", "created_at": time.time()-2},
        }
        xa._save_sidecar(data)
    before = xa.registry_path().read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Reading execution metadata must not repair an approval, write authority or contact a connector")

    monkeypatch.setattr(xa, "_save_sidecar", forbidden)
    monkeypatch.setattr(xa, "execute_status", forbidden)
    monkeypatch.setattr(xa, "_perform_execution", forbidden)
    response = client.get("/api/v1/external-agents/sf-quotebot")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    detail = response.json()
    assert detail["execution_readback"][0]["status"] == "Result unknown — check connected service"
    assert detail["execution_readback"][1]["status"] == "Request completed"
    assert detail["execution_readback"][2]["status"] == "Accepted; completion unconfirmed"
    assert "Completion has not been confirmed" in detail["execution_readback"][2]["notice"]
    assert detail["execution_readback"][0]["action"] == "Update"
    page = client.get("/external-agents/sf-quotebot")
    assert page.status_code == 200 and "Recent connected changes" in page.text
    assert page.headers["cache-control"] == "private, no-store"
    assert client.get("/static/lightwork-external-agent-executions.js").status_code == 200
    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"connections"})
    selection = {"kind": "external_agent", "id": "sf-quotebot"}
    catalog = client.post("/api/v1/copilot/product-operations/catalog",
        json={"page": "/external-agents/sf-quotebot", "selection": selection}).json()
    action = next(row for row in catalog["operations"] if row["id"] == "external_agents.execution_status")
    read = client.post("/api/v1/copilot/product-operations/prepare", json={
        "page": "/external-agents/sf-quotebot", "selection": selection, "operation": action["id"],
        "context": catalog["context"], "revision": action["revision"], "arguments": {}})
    assert read.status_code == 200 and read.json()["read_only"] is True
    assert "No connected service was contacted" in read.text
    combined = response.text + page.text + str(catalog) + read.text
    assert "PRIVATE-SYNTHETIC" not in combined and "/private/customer/record" not in combined
    assert xa.registry_path().read_bytes() == before


def test_enroll_validates_platform_and_surface():
    assert _enroll(platform="skynet").status_code == 400
    _enroll()
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "carrier-pigeon"})
    assert r.status_code == 422


def test_mint_step_up_approval_gate_over_http(tmp_path):
    _enroll()
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nmint_approval = true\n", encoding="utf-8")
    from maverick import config
    config.reset_config_cache()
    # First call parks the approval and answers 409 — no token minted.
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "rest"})
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "approval_required"
    assert "approval" in body["detail"]
    approval_id = body["approval_id"]
    row = client.get("/api/v1/external-agents").json()["agents"][0]
    assert row["credentials"] == []
    from maverick.world_model import WorldModel
    assert WorldModel().decide_approval(approval_id, "approved",
                                        decided_by="admin@corp.test") is True
    # Replaying the approved id mints; the approval is then spent (one-shot).
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "rest", "approval_id": approval_id})
    assert r.status_code == 200
    assert r.json()["token"].startswith("lw-rest-")
    r = client.post("/api/v1/external-agents/sf-quotebot/credentials",
                    json={"surface": "rest", "approval_id": approval_id})
    assert r.status_code == 400
    assert "one-shot" in r.json()["detail"]


def test_agent_facing_routes_require_the_rest_bearer():
    _enroll()
    token = _mint()
    # No session, no Origin — the bearer alone authenticates (self-auth path).
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/runs",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"title": "Quote for Northwind", "outcome": "success",
                        "summary": "sent", "cost_dollars": 1.25})
    assert r.status_code == 201
    body = r.json()
    assert body["ok"] is True and body["over_budget"] is False
    # The run is on the Operating Record, visible from the admin detail.
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["runs"] == 1
    assert detail["record"]["dollars"] == pytest.approx(1.25)
    # Missing/garbage bearer -> 401, never a fallback to ambient auth.
    assert bare.post("/api/v1/external/runs", json={}).status_code == 401
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": "Bearer lw-rest-wrong"},
                  json={"tool": "crm_update"})
    assert r.status_code == 401


def test_screen_flow_and_approval_poll_over_http():
    _enroll(max_risk="high")
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    ok = bare.post("/api/v1/external/screen", headers=hdr,
                   json={"tool": "crm_update", "detail": "update stage",
                         "risk": "low"}).json()
    assert ok["allowed"] is True
    parked = bare.post("/api/v1/external/screen", headers=hdr,
                       json={"tool": "send_contract", "risk": "high"}).json()
    assert parked["requires_approval"] is True
    poll = bare.get(f"/api/v1/external/approvals/{parked['approval_id']}",
                    params={"binding_sha256": parked["approval_binding_sha256"]},
                    headers=hdr)
    assert poll.status_code == 200
    assert poll.json()["status"] == "pending"
    assert (
        poll.json()["approval_binding_sha256"]
        == parked["approval_binding_sha256"]
    )
    stale = bare.get(
        f"/api/v1/external/approvals/{parked['approval_id']}",
        params={"binding_sha256": "0" * 64},
        headers=hdr,
    )
    assert stale.status_code == 409
    assert bare.get("/api/v1/external/approvals/999999",
                    headers=hdr).status_code == 404

    assert _enroll(
        id="other-agent", owner="other@corp.test", max_risk="high"
    ).status_code == 201
    other_token = client.post(
        "/api/v1/external-agents/other-agent/credentials",
        json={"surface": "rest"},
    ).json()["token"]
    cross_owner = bare.get(
        f"/api/v1/external/approvals/{parked['approval_id']}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert cross_owner.status_code == 404


def test_gateway_404s_while_disabled(monkeypatch):
    _enroll()
    token = _mint()
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"tool": "crm_update"})
    assert r.status_code == 404
    assert bare.get("/api/v1/external/openapi.json").status_code == 404
    page = client.get("/external-agents")
    assert page.status_code == 200
    assert 'href="/api/v1/external/openapi.json"' not in page.text
    assert "The connection file is available once the connection is open" in page.text


def test_openapi_artifact_describes_every_gateway_operation():
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    assert spec["openapi"].startswith("3.")
    assert set(spec["paths"]) == {
        "/api/v1/external/screen", "/api/v1/external/runs",
        "/api/v1/external/runtime/evaluate",
        "/api/v1/external/runs/start",
        "/api/v1/external/runs/{goal_id}/heartbeat",
        "/api/v1/external/runs/{goal_id}/finish",
        "/api/v1/external/memory/ingest",
        "/api/v1/external/memory/recall",
        "/api/v1/external/approvals/{approval_id}",
        "/api/v1/external/execute",
        "/api/v1/external/executions/{execution_id}",
        "/api/v1/external/executions/{execution_id}/commit"}


def test_external_runtime_guardrail_is_authenticated_exact_bound_and_transient(
    monkeypatch,
):
    from maverick import ai_runtime_guardrails as runtime
    from maverick import model_risk_assurance as assurance

    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    headers = {"Authorization": f"Bearer {token}"}
    asset_id = "MAA-" + ("a" * 32)
    digest = "b" * 64
    captured = []

    class Service:
        def evaluate(self, request):
            captured.append(request)
            return runtime.RuntimeGuardrailResult(
                decision="redact",
                redacted_content="email [REDACTED]",
                receipt={
                    "stage": "output",
                    "decision": "redact",
                    "categories": ["privacy"],
                    "rule_ids": ["pii/email"],
                    "control_ids": [],
                    "input_sha256": "c" * 64,
                    "output_sha256": "d" * 64,
                    "policy_sha256": "e" * 64,
                    "evaluated_at": 1_800_000_000.0,
                    "asset_binding": {
                        "tenant_ref": "TEN-" + ("f" * 24),
                        "asset_id": asset_id,
                        "asset_revision": 3,
                        "asset_version_digest": digest,
                    },
                },
            )

    monkeypatch.setattr(runtime, "enabled", lambda: True)
    monkeypatch.setattr(runtime, "default_service", Service())
    monkeypatch.setattr(
        runtime,
        "dynamic_risk_receipt",
        lambda _result: {"schema": "normalized-runtime-risk"},
    )
    monkeypatch.setattr(assurance, "enabled", lambda: True)
    _stub_review_is_current(monkeypatch, assurance)
    monkeypatch.setattr(
        assurance,
        "get_observation",
        lambda _asset_id: {
            "asset_id": asset_id,
            "revision": 3,
            "version_digest": digest,
            "identity": {"asset_type": "agent"},
        },
    )
    monkeypatch.setattr(
        assurance,
        "get_declaration",
        lambda _asset_id: {
            "asset_id": asset_id,
            "status": "approved",
            "observed_version_digest": digest,
            "risk_tier": "high",
            "risk_context": {
                "jurisdictions": ["us"],
                "data_classes": ["personal"],
                "deployment_types": ["production"],
                "tags": ["external"],
                "use_case_tags": ["support"],
            },
        },
    )
    raw = "email person@example.test"
    payload = {
        "stage": "output",
        "content": raw,
        "known_prompt": "answer the customer",
        "asset_id": asset_id,
        "asset_revision": 3,
        "asset_version_digest": digest,
    }
    response = bare.post(
        "/api/v1/external/runtime/evaluate",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 200
    result = response.json()
    assert result["decision"] == "redact"
    assert result["redacted_content"] == "email [REDACTED]"
    assert result["raw_content_persisted"] is False
    assert result["dynamic_risk_signal_recorded"] is False
    assert raw not in response.text
    assert captured[0].policy_context.risk_tier == "high"
    assert captured[0].policy_context.asset_types == ("agent",)

    stale = dict(payload, asset_revision=2)
    assert bare.post(
        "/api/v1/external/runtime/evaluate",
        headers=headers,
        json=stale,
    ).status_code == 409
    assert bare.post(
        "/api/v1/external/runtime/evaluate",
        json=payload,
    ).status_code == 401


def test_external_execute_runtime_gate_cannot_be_bypassed_when_enabled(monkeypatch):
    from maverick import ai_runtime_guardrails as runtime
    from maverick import external_agents
    from maverick import model_risk_assurance as assurance

    # Safeguard activity is retained per workspace; unbound mode refuses it.
    monkeypatch.setenv("MAVERICK_TENANT", "gateway-workspace")
    _enroll()
    token = _mint()
    headers = {"Authorization": f"Bearer {token}"}
    bare = TestClient(app, base_url="http://127.0.0.1")
    asset_id = "MAA-" + ("6" * 32)
    digest = "7" * 64
    executed = []

    class Service:
        @staticmethod
        def evaluate(request):
            assert request.stage == "action"
            assert request.action_name == "servicenow.post"
            return runtime.RuntimeGuardrailResult(
                decision="block",
                redacted_content=None,
                receipt={
                    "stage": "action",
                    "decision": "block",
                    "categories": ["policy"],
                    "rule_ids": ["policy/external-write/prohibit"],
                    "control_ids": [],
                    "input_sha256": "8" * 64,
                    "output_sha256": "9" * 64,
                    "policy_sha256": "a" * 64,
                    "evaluated_at": 1_800_000_000.0,
                    "asset_binding": {
                        "tenant_ref": runtime._tenant_ref(),
                        "asset_id": asset_id,
                        "asset_revision": 2,
                        "asset_version_digest": digest,
                    },
                },
            )

    monkeypatch.setattr(runtime, "enabled", lambda: True)
    # Recording the refusal checks the switch itself, as the enabled runtime does.
    monkeypatch.setattr(runtime, "require_enabled", lambda: None)
    monkeypatch.setattr(runtime, "default_service", Service())
    monkeypatch.setattr(assurance, "enabled", lambda: True)
    _stub_review_is_current(monkeypatch, assurance)
    monkeypatch.setattr(
        assurance,
        "get_observation",
        lambda _asset_id: {
            "asset_id": asset_id,
            "revision": 2,
            "version_digest": digest,
            "identity": {"asset_type": "agent"},
        },
    )
    monkeypatch.setattr(
        assurance,
        "get_declaration",
        lambda _asset_id: {
            "status": "approved",
            "observed_version_digest": digest,
            "risk_tier": "high",
            "risk_context": {},
        },
    )
    monkeypatch.setattr(
        external_agents,
        "execute",
        lambda *_args, **_kwargs: executed.append(True) or {"allowed": True},
    )
    detail = "sensitive transient action detail"
    payload = {
        "connector": "servicenow",
        "op": "post",
        "path": "/api/now/table/risk",
        "body": {"short_description": "governed finding"},
        "detail": detail,
        "runtime_asset_id": asset_id,
        "runtime_asset_revision": 2,
        "runtime_asset_version_digest": digest,
    }
    blocked = bare.post("/api/v1/external/execute", headers=headers, json=payload)
    assert blocked.status_code == 200
    assert blocked.json()["allowed"] is False
    assert blocked.json()["status"] == "block"
    assert detail not in blocked.text
    assert executed == []

    missing = dict(payload)
    missing.pop("runtime_asset_id")
    assert bare.post(
        "/api/v1/external/execute",
        headers=headers,
        json=missing,
    ).status_code == 409


def test_runtime_policy_mutation_before_core_boundary_blocks_provider(monkeypatch):
    from maverick import ai_runtime_guardrails as runtime
    from maverick import governed_rest
    from maverick import model_risk_assurance as assurance

    # Safeguard activity is retained per workspace; unbound mode refuses it.
    monkeypatch.setenv("MAVERICK_TENANT", "gateway-workspace")
    _enroll()
    token = _mint()
    headers = {"Authorization": f"Bearer {token}"}
    bare = TestClient(app, base_url="http://127.0.0.1")
    asset_id = "MAA-" + ("6" * 32)
    digest = "7" * 64
    state = {"risk_tier": "high"}
    initial_evaluated = threading.Event()
    mutation_done = threading.Event()
    calls = 0
    calls_lock = threading.Lock()

    class FakeConnector:
        def __init__(self):
            self.reads = []

        def read(self, params):
            self.reads.append(dict(params))
            return "stale effect"

    connector = FakeConnector()
    monkeypatch.setitem(
        governed_rest.GOVERNED_REST_FACTORIES,
        "fakecrm",
        lambda: connector,
    )
    monkeypatch.setenv("MAVERICK_EXTERNAL_CONNECTORS", "fakecrm")

    class Service:
        def evaluate(self, request):
            nonlocal calls
            with calls_lock:
                calls += 1
                current_call = calls
            risk_tier = request.policy_context.risk_tier
            result = runtime.RuntimeGuardrailResult(
                decision="allow",
                redacted_content=None,
                receipt={
                    "stage": "action",
                    "decision": "allow",
                    "categories": [],
                    "rule_ids": [],
                    "control_ids": [],
                    "input_sha256": "8" * 64,
                    "output_sha256": "8" * 64,
                    "policy_sha256": (
                        "a" * 64 if risk_tier == "high" else "b" * 64
                    ),
                    "evaluated_at": 1_800_000_000.0 + current_call,
                    "asset_binding": {
                        "tenant_ref": runtime._tenant_ref(),
                        "asset_id": asset_id,
                        "asset_revision": 2,
                        "asset_version_digest": digest,
                    },
                },
            )
            if current_call == 1:
                initial_evaluated.set()
                assert mutation_done.wait(5), "policy mutation did not complete"
            return result

    monkeypatch.setattr(runtime, "enabled", lambda: True)
    monkeypatch.setattr(runtime, "default_service", Service())
    monkeypatch.setattr(assurance, "enabled", lambda: True)
    _stub_review_is_current(monkeypatch, assurance)
    monkeypatch.setattr(
        assurance,
        "get_observation",
        lambda _asset_id: {
            "asset_id": asset_id,
            "revision": 2,
            "version_digest": digest,
            "identity": {"asset_type": "agent"},
        },
    )
    monkeypatch.setattr(
        assurance,
        "get_declaration",
        lambda _asset_id: {
            "status": "approved",
            "observed_version_digest": digest,
            "risk_tier": state["risk_tier"],
            "risk_context": {},
        },
    )

    def mutate_policy():
        try:
            assert initial_evaluated.wait(5), "initial runtime check did not run"
            state["risk_tier"] = "low"
        finally:
            mutation_done.set()

    mutation = threading.Thread(target=mutate_policy)
    mutation.start()
    try:
        response = bare.post(
            "/api/v1/external/execute",
            headers=headers,
            json={
                "connector": "fakecrm",
                "op": "get",
                "path": "/opportunities",
                "detail": "read the reviewed opportunity set",
                "runtime_asset_id": asset_id,
                "runtime_asset_revision": 2,
                "runtime_asset_version_digest": digest,
            },
        )
    finally:
        mutation_done.set()
        mutation.join(timeout=10)

    assert not mutation.is_alive()
    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["rule"] == "runtime_authority_changed"
    assert calls == 2
    assert connector.reads == []


def test_openapi_advertises_red_team_only_when_its_plane_is_enabled(monkeypatch):
    from maverick import red_team_assurance as rta

    monkeypatch.setattr(rta, "enabled", lambda: True)
    spec = TestClient(app, base_url="http://127.0.0.1").get("/api/v1/external/openapi.json").json()
    assert "/api/v1/external/red-team/{campaign_id}/cases" in spec["paths"]
    result = spec["paths"][
        "/api/v1/external/red-team/{campaign_id}/results"
    ]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert "target_artifact_sha256" in result["required"]
    assert "runner_instance_id" in result["required"]
    assert "lease_token" in result["required"]
    pull_parameters = spec["paths"][
        "/api/v1/external/red-team/{campaign_id}/cases"
    ]["get"]["parameters"]
    assert any(
        item["name"] == "runner_instance_id" and item["required"]
        for item in pull_parameters
    )
    assert spec["security"] == [{"bearer": []}]


def test_red_team_routes_preserve_agent_binding_and_do_not_echo_raw(monkeypatch):
    from maverick import red_team_assurance as rta

    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    headers = {"Authorization": f"Bearer {token}"}
    observed: dict = {}

    def cases(
        campaign_id,
        *,
        external_agent_id,
        runner_instance_id,
        limit,
        lease_seconds,
    ):
        observed["pull"] = (
            campaign_id,
            external_agent_id,
            runner_instance_id,
            limit,
            lease_seconds,
        )
        return {
            "campaign_id": campaign_id,
            "cases": [{
                "case_id": "RTCASE-one",
                "prompt": "synthetic probe",
                "runner_instance_id": runner_instance_id,
                "lease_token": f"rtl1.{'b' * 64}",
            }],
        }

    def submit(campaign_id, **kwargs):
        observed["submit"] = (campaign_id, kwargs)
        return {
            "id": "RTR-one",
            "case_id": kwargs["case_id"],
            "outcome": "passed",
            "response_commitment": "a" * 64,
        }

    monkeypatch.setattr(rta, "lease_cases_for_agent", cases)
    monkeypatch.setattr(rta, "submit_result", submit)

    pulled = bare.get(
        "/api/v1/external/red-team/RTC-one/cases"
        "?runner_instance_id=runner-one&limit=2&lease_seconds=180",
        headers=headers,
    )
    assert pulled.status_code == 200
    assert observed["pull"] == (
        "RTC-one", "sf-quotebot", "runner-one", 2, 180,
    )

    raw = "transient model output"
    submitted = bare.post(
        "/api/v1/external/red-team/RTC-one/results",
        headers=headers,
        json={
            "case_id": "RTCASE-one",
            "target_artifact_sha256": "a" * 64,
            "runner_instance_id": "runner-one",
            "lease_token": f"rtl1.{'b' * 64}",
            "response": raw,
            "tool_calls": [],
            "tool_trace_status": "complete",
        },
    )
    assert submitted.status_code == 201
    assert observed["submit"][1]["external_agent_id"] == "sf-quotebot"
    assert observed["submit"][1]["runner_instance_id"] == "runner-one"
    assert observed["submit"][1]["lease_token"] == f"rtl1.{'b' * 64}"
    assert observed["submit"][1]["response"] == raw
    assert raw not in submitted.text


def test_red_team_result_body_is_bounded_before_signed_auth():
    from maverick_dashboard import external_gateway

    response = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/red-team/RTC-one/results",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": str(
                external_gateway._MAX_RED_TEAM_HTTP_BODY_BYTES + 1  # noqa: SLF001
            ),
            "x-lightwork-agent-id": "untrusted-agent",
            "x-maverick-timestamp": "1700000000",
            "x-lightwork-nonce": "nonce-one",
            "x-lightwork-request-signature": "00",
        },
    )

    assert response.status_code == 413


def test_red_team_case_pull_body_is_bounded_before_signed_auth():
    from maverick_dashboard import external_gateway

    response = TestClient(app, base_url="http://127.0.0.1").request(
        "GET",
        "/api/v1/external/red-team/RTC-one/cases",
        content=b"{}",
        headers={
            "content-length": str(
                external_gateway._MAX_RED_TEAM_HTTP_BODY_BYTES + 1  # noqa: SLF001
            ),
            "x-lightwork-agent-id": "untrusted-agent",
            "x-maverick-timestamp": "1700000000",
            "x-lightwork-nonce": "nonce-one",
            "x-lightwork-request-signature": "00",
        },
    )

    assert response.status_code == 413


def test_memory_routes_over_http(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLEET_MEMORY", "1")
    monkeypatch.setenv("MAVERICK_AGENT_TRUST", "0")
    from maverick import fleet_memory
    monkeypatch.setattr(fleet_memory, "registry_path",
                        lambda: fleet_memory.inbox_dir().parent
                        / "agents.ndjson")
    _enroll(data_scopes=["sales"])
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    r = bare.post("/api/v1/external/memory/ingest", headers=hdr,
                  json={"kind": "success",
                        "goal_text": "Renewal quote accepted",
                        "reflection": "Bundling closed it"})
    assert r.status_code == 201, r.text
    r = bare.post("/api/v1/external/memory/recall", headers=hdr,
                  json={"query": "renewal quote"})
    assert r.status_code == 200
    assert "context" in r.json() and "reason" in r.json()
    denied = bare.post("/api/v1/external/memory/ingest", headers=hdr,
                       json={"kind": "success", "goal_text": "finance", "domain": "finance"})
    assert denied.status_code == 403
    denied = bare.post("/api/v1/external/memory/recall", headers=hdr,
                       json={"query": "finance", "domain": "finance"})
    assert denied.status_code == 200 and not denied.json()["context"]
    # The scorecard surfaces the contribution.
    page = client.get("/external-agents/sf-quotebot").text
    assert "Learning contributions" in page
    # Bad kind is schema-gated; no bearer is 401.
    assert bare.post("/api/v1/external/memory/ingest", headers=hdr,
                     json={"kind": "gossip", "goal_text": "x"}
                     ).status_code == 422
    assert bare.post("/api/v1/external/memory/recall",
                     json={"query": "x"}).status_code == 401


def test_console_page_renders_roster_and_forms():
    _enroll()
    page = client.get("/external-agents").text
    assert "Add an outside agent" in page
    assert 'id="xa-add"' in page
    assert "data-xa-mint" in page
    assert "Salesforce Agentforce" in page
    assert "Connect your platform" in page
    assert 'href="/api/v1/external/openapi.json"' in page


def test_admin_mutations_are_csrf_gated_but_gateway_is_not():
    # The ADMIN surface keeps the same-origin gate in no-token mode…
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/external-agents",
                     json={"id": "x", "platform": "custom"}).status_code == 403
    # …while the agent-facing prefix authenticates by bearer alone (asserted
    # in test_agent_facing_routes_require_the_rest_bearer).


def test_unenroll_over_http():
    _enroll()
    assert client.delete("/api/v1/external-agents/sf-quotebot").status_code == 204
    assert client.delete("/api/v1/external-agents/sf-quotebot").status_code == 404
    assert client.get("/api/v1/external-agents").json()["agents"] == []


def test_live_run_flow_over_http():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    start = bare.post("/api/v1/external/runs/start", headers=hdr,
                      json={"title": "Live quote", "summary": "working"})
    assert start.status_code == 201
    gid = start.json()["goal_id"]
    assert start.json()["heartbeat_seconds"] > 0
    hb = bare.post(f"/api/v1/external/runs/{gid}/heartbeat", headers=hdr)
    assert hb.status_code == 200 and hb.json()["continue"] is True
    fin = bare.post(f"/api/v1/external/runs/{gid}/finish", headers=hdr,
                    json={"outcome": "success", "summary": "sent",
                          "cost_dollars": 1.5, "steps": ["a"]})
    assert fin.status_code == 200
    assert fin.json()["over_budget"] is False
    # Closed run: heartbeat says stop, finish refuses.
    hb = bare.post(f"/api/v1/external/runs/{gid}/heartbeat", headers=hdr)
    assert hb.json()["continue"] is False
    fin = bare.post(f"/api/v1/external/runs/{gid}/finish", headers=hdr,
                    json={"outcome": "success", "summary": "again"})
    assert fin.status_code == 403
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["record"]["dollars"] == pytest.approx(1.5)


def test_scorecard_page_renders_and_404s_unknown():
    _enroll()
    page = client.get("/external-agents/sf-quotebot")
    assert page.status_code == 200
    assert "Spend and budget" in page.text
    assert "Salesforce Agentforce" in page.text
    assert client.get("/external-agents/ghost").status_code == 404


def test_boards_keep_external_agent_platform_segments_out_of_local_scope():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    bare.post("/api/v1/external/runs",
              headers={"Authorization": f"Bearer {token}"},
              json={"title": "Quote", "outcome": "success", "summary": "s",
                    "cost_dollars": 2.0})
    spend = client.get("/api/v1/dashboards/spend").json()
    # Ingested work belongs to the service principal, not the local operator.
    assert spend["by_platform"] == []
    wf = client.get("/api/v1/dashboards/workforce").json()
    assert wf["platforms"] == []
    # Explicitly unscoped internal calculations retain platform attribution;
    # HTTP owner filters must never silently opt into this scope.
    from maverick.world_model import open_world
    from maverick_dashboard.api import _external_platform_spend, _external_platform_workforce
    world = open_world()
    assert _external_platform_spend(world, None, 0) == [
        {"label": "Salesforce Agentforce", "cost": 2.0, "runs": 1}]
    (row,) = _external_platform_workforce(world, None)
    assert row["completed"] == 1 and row["spend"] == pytest.approx(2.0)


def test_idempotency_key_over_http():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"title": "Quote", "outcome": "success", "summary": "s",
            "cost_dollars": 1.0, "idempotency_key": "k-1"}
    first = bare.post("/api/v1/external/runs", headers=hdr, json=body).json()
    replay = bare.post("/api/v1/external/runs", headers=hdr, json=body).json()
    assert replay["goal_id"] == first["goal_id"]
    assert replay["duplicate"] is True
    detail = client.get("/api/v1/external-agents/sf-quotebot").json()
    assert detail["runs"] == 1


def test_gateway_rate_limit_trips_and_names_the_action(monkeypatch):
    from maverick_dashboard import external_gateway as gw
    _enroll()
    token = _mint()
    monkeypatch.setitem(gw._RATE_LIMITS, "screen", 3)
    monkeypatch.setattr(gw, "_rate_times", {})
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"tool": "research", "risk": "low"}
    for _ in range(3):
        assert bare.post("/api/v1/external/screen", headers=hdr,
                         json=body).status_code == 200
    r = bare.post("/api/v1/external/screen", headers=hdr, json=body)
    assert r.status_code == 429
    assert "screen" in r.json()["detail"]
    assert r.headers["Retry-After"] == "60"


def test_admin_release_and_reset_budget_routes():
    _enroll(max_risk="medium", max_dollars=1.0)
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    # Trip the containment via repeated ceiling breaches.
    for _ in range(5):
        bare.post("/api/v1/external/screen", headers=hdr,
                  json={"tool": "wire_transfer", "risk": "high"})
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "contained"
    r = client.post("/api/v1/external-agents/sf-quotebot/release", json={})
    assert r.status_code == 200
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "allow"
    # Over-budget -> reset restores service.
    bare.post("/api/v1/external/runs", headers=hdr,
              json={"title": "Big", "outcome": "success", "summary": "s",
                    "cost_dollars": 2.0})
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "budget"
    r = client.post("/api/v1/external-agents/sf-quotebot/reset-budget",
                    json={})
    assert r.status_code == 200
    verdict = bare.post("/api/v1/external/screen", headers=hdr,
                        json={"tool": "research", "risk": "low"}).json()
    assert verdict["rule"] == "allow"
    assert client.post("/api/v1/external-agents/ghost/release",
                       json={}).status_code == 404


def test_ordinary_admin_restore_and_release_refuse_security_containment():
    from maverick import agent_trust
    from maverick import external_agents as xa
    from maverick.revocation import shared

    assert _enroll().status_code == 201
    contained = shared().revoke(
        "agent:sf-quotebot", reason="soc: incident", protected=True,
    )
    assert agent_trust.set_revoked("sf-quotebot", True)
    assert xa.contain("sf-quotebot", contained_by="soc")

    restored = client.post(
        "/api/v1/trust/agents/sf-quotebot/revoke",
        json={"revoked": False},
    )
    assert restored.status_code == 409
    assert "security-contained" in restored.json()["detail"]
    released = client.post(
        "/api/v1/external-agents/sf-quotebot/release", json={},
    )
    assert released.status_code == 409
    assert "security-contained" in released.json()["detail"]

    assert shared().revoked()["agent:sf-quotebot"] == contained
    assert agent_trust.load_registry()["sf-quotebot"].revoked is True
    assert xa.containment_state("sf-quotebot") is True


# -- governed execution over HTTP ---------------------------------------------

class _FakeConn:
    """Recording governed-REST connector double — no network, no creds."""

    def __init__(self, write_result: str = "updated 1 record"):
        self.reads: list[dict] = []
        self.writes: list[dict] = []
        self.write_result = write_result

    def read(self, params):
        self.reads.append(dict(params))
        return "42 open opportunities"

    def preview_write(self, params):
        return f"would {params['op'].upper()} fakecrm{params['path']}"

    def write(self, params):
        self.writes.append(dict(params))
        return self.write_result


def _wire_fakecrm(monkeypatch):
    """Enable one fake connector for the execute tier (the factory is looked
    up at call time, so a setitem patch is enough)."""
    from maverick import governed_rest
    conn = _FakeConn()
    monkeypatch.setitem(governed_rest.GOVERNED_REST_FACTORIES, "fakecrm",
                        lambda: conn)
    monkeypatch.setenv("MAVERICK_EXTERNAL_CONNECTORS", "fakecrm")
    return conn


def _write_body(**kw):
    body = {"connector": "fakecrm", "op": "post",
            "path": "/opportunities/42", "body": {"stage": "closed-won"}}
    body.update(kw)
    return body


def test_execute_requires_bearer_before_validation():
    _enroll()
    bare = TestClient(app, base_url="http://127.0.0.1")
    # Even a body that could never validate gets 401, not 422 — the bearer
    # dependency resolves before the schema, so nothing leaks to strangers.
    assert bare.post("/api/v1/external/execute",
                     json={"op": "teleport"}).status_code == 401
    r = bare.post("/api/v1/external/execute",
                  headers={"Authorization": "Bearer lw-rest-wrong"},
                  json={"op": "teleport"})
    assert r.status_code == 401


def test_execute_routes_404_while_disabled(monkeypatch):
    _enroll()
    token = _mint()
    monkeypatch.delenv("MAVERICK_EXTERNAL_AGENTS", raising=False)
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    assert bare.post("/api/v1/external/execute", headers=hdr,
                     json=_write_body()).status_code == 404
    assert bare.get("/api/v1/external/executions/x",
                    headers=hdr).status_code == 404
    assert bare.post("/api/v1/external/executions/x/commit", headers=hdr,
                     json=_write_body()).status_code == 404


def test_execute_verdict_when_connector_not_enabled(monkeypatch):
    _enroll()
    token = _mint()
    monkeypatch.delenv("MAVERICK_EXTERNAL_CONNECTORS", raising=False)
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/execute",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"connector": "fakecrm", "op": "get",
                        "path": "/accounts"})
    # Denials are 200-with-verdict, never HTTP errors — typed rules travel.
    assert r.status_code == 200
    assert r.json()["allowed"] is False
    assert r.json()["rule"] == "connector_not_enabled"


def test_execute_read_end_to_end_over_http(monkeypatch):
    conn = _wire_fakecrm(monkeypatch)
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/execute",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"connector": "fakecrm", "op": "get",
                        "path": "/opportunities"})
    assert r.status_code == 200
    verdict = r.json()
    assert verdict["allowed"] is True and verdict["rule"] == "executed", verdict
    assert verdict["status"] == "executed"
    assert "42 open opportunities" in verdict["result"]
    assert conn.reads == [{"path": "/opportunities"}]


def test_write_park_poll_approve_and_commit_over_http(monkeypatch):
    conn = _wire_fakecrm(monkeypatch)
    _enroll(max_risk="high")
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    parked = bare.post("/api/v1/external/execute", headers=hdr,
                       json=_write_body()).json()
    assert parked["allowed"] is False
    assert parked["rule"] == "approval_required"
    assert parked["requires_approval"] is True
    eid = parked["execution_id"]
    assert conn.writes == []
    poll = bare.get(f"/api/v1/external/executions/{eid}", headers=hdr)
    assert poll.status_code == 200
    assert poll.json()["status"] == "pending"
    assert poll.json()["approval_status"] == "pending"
    from maverick.world_model import WorldModel
    assert WorldModel().decide_approval(parked["approval_id"], "approved",
                                        decided_by="admin@corp.test") is True
    done = bare.post(f"/api/v1/external/executions/{eid}/commit",
                     headers=hdr, json=_write_body()).json()
    assert done["allowed"] is True and done["rule"] == "executed"
    assert done["status"] == "executed"
    assert done["execution_id"] == eid
    assert conn.writes == [{"op": "post", "path": "/opportunities/42",
                            "body": {"stage": "closed-won"}}]


def test_write_park_idempotency_survives_replay_conflict_and_commit(monkeypatch):
    conn = _wire_fakecrm(monkeypatch)
    _enroll(max_risk="high")
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    request = _write_body(idempotency_key="pilot-change-001")

    parked = bare.post(
        "/api/v1/external/execute", headers=hdr, json=request,
    ).json()
    replay = bare.post(
        "/api/v1/external/execute", headers=hdr, json=request,
    ).json()
    assert replay["duplicate"] is True
    assert replay["execution_id"] == parked["execution_id"]
    assert replay["approval_id"] == parked["approval_id"]

    conflict = bare.post(
        "/api/v1/external/execute",
        headers=hdr,
        json=_write_body(
            body={"stage": "closed-lost"},
            idempotency_key="pilot-change-001",
        ),
    ).json()
    assert conflict["allowed"] is False
    assert conflict["rule"] == "idempotency_conflict"
    assert conn.writes == []

    from maverick.world_model import WorldModel
    assert WorldModel().decide_approval(
        parked["approval_id"], "approved", decided_by="admin@corp.test",
    ) is True
    committed = bare.post(
        f"/api/v1/external/executions/{parked['execution_id']}/commit",
        headers=hdr,
        json=_write_body(),
    ).json()
    assert committed["status"] == "executed"

    terminal_replay = bare.post(
        "/api/v1/external/execute", headers=hdr, json=request,
    ).json()
    assert terminal_replay["duplicate"] is True
    assert terminal_replay["execution_id"] == parked["execution_id"]
    assert terminal_replay["rule"] == "already_finished"
    assert terminal_replay["status"] == "executed"
    assert len(conn.writes) == 1


def test_commit_digest_mismatch_over_http(monkeypatch):
    conn = _wire_fakecrm(monkeypatch)
    _enroll(max_risk="high")
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    parked = bare.post("/api/v1/external/execute", headers=hdr,
                       json=_write_body()).json()
    eid = parked["execution_id"]
    r = bare.post(f"/api/v1/external/executions/{eid}/commit", headers=hdr,
                  json=_write_body(body={"stage": "closed-lost"}))
    assert r.status_code == 200
    assert r.json()["allowed"] is False
    assert r.json()["rule"] == "digest_mismatch"
    assert conn.writes == []


def test_execution_status_unknown_id_404s():
    _enroll()
    token = _mint()
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.get("/api/v1/external/executions/nope",
                 headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404


def test_execute_rate_limit_trips_and_commit_shares_the_bucket(monkeypatch):
    from maverick_dashboard import external_gateway as gw
    _wire_fakecrm(monkeypatch)
    _enroll()
    token = _mint()
    monkeypatch.setitem(gw._RATE_LIMITS, "execute", 2)
    monkeypatch.setattr(gw, "_rate_times", {})
    bare = TestClient(app, base_url="http://127.0.0.1")
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"connector": "fakecrm", "op": "get", "path": "/opportunities"}
    for _ in range(2):
        assert bare.post("/api/v1/external/execute", headers=hdr,
                         json=body).status_code == 200
    r = bare.post("/api/v1/external/execute", headers=hdr, json=body)
    assert r.status_code == 429
    assert "execute" in r.json()["detail"]
    assert r.headers["Retry-After"] == "60"
    # A commit can fire a write, so it draws from the same bucket.
    r = bare.post("/api/v1/external/executions/x/commit", headers=hdr,
                  json=_write_body())
    assert r.status_code == 429


# -- platform-native identity over HTTP ---------------------------------------

_ISSUER = "https://partner-idp.example.com"
_AUDIENCE = "lightwork-gateway"
_HMAC_REF = "XA_GATEWAY_TEST_SECRET"
_HMAC_SECRET = "gw-test-secret"  # pragma: allowlist secret
_SCREEN_BODY = b'{"tool": "crm_update", "risk": "low"}'


def _identity(**fields):
    """Attach platform-identity fields to the enrolled agent's trust entry
    (the same read-modify-write mint_token uses, so bearers survive)."""
    from maverick import external_agents as xa
    from maverick.agent_trust import lookup, put_agent
    entry = xa._entry_from_agent(lookup("sf-quotebot"))
    entry.update(fields)
    put_agent(entry)


def _ed25519_pair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return priv, pub_hex


def _envelope_headers(priv, body: bytes, *, nonce: str) -> dict:
    from maverick.external_identity import envelope_message
    ts = str(int(time.time()))
    sig = priv.sign(envelope_message("sf-quotebot", ts, nonce, body)).hex()
    return {"X-Lightwork-Agent-Id": "sf-quotebot",
            "X-Maverick-Timestamp": ts,
            "X-Lightwork-Nonce": nonce,
            "X-Lightwork-Request-Signature": sig,
            "Content-Type": "application/json"}


@requires_crypto
def test_envelope_auth_over_http():
    _enroll()
    priv, pub_hex = _ed25519_pair()
    _identity(pubkey=pub_hex)
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers=_envelope_headers(priv, _SCREEN_BODY, nonce="n-1"),
        content=_SCREEN_BODY)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


@requires_crypto
def test_envelope_replayed_nonce_is_401():
    _enroll()
    priv, pub_hex = _ed25519_pair()
    _identity(pubkey=pub_hex)
    hdr = _envelope_headers(priv, _SCREEN_BODY, nonce="n-replay")
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/api/v1/external/screen", headers=hdr,
                     content=_SCREEN_BODY).status_code == 200
    # A byte-identical replay carries a valid signature; the single-use
    # nonce is what refuses it — with the same generic 401.
    r = bare.post("/api/v1/external/screen", headers=hdr,
                  content=_SCREEN_BODY)
    assert r.status_code == 401


def _hmac_headers(body: bytes, *, ts: str | None = None) -> dict:
    ts = ts or str(int(time.time()))
    mac = hmac_mod.new(_HMAC_SECRET.encode(), f"{ts}.".encode() + body,
                       hashlib.sha256)
    return {"X-Lightwork-Agent-Id": "sf-quotebot",
            "X-Maverick-Timestamp": ts,
            "X-Maverick-Signature": "sha256=" + mac.hexdigest(),
            "Content-Type": "application/json"}


def test_hmac_auth_over_http(monkeypatch):
    monkeypatch.setenv(_HMAC_REF, _HMAC_SECRET)
    _enroll()
    _identity(hmac_secret_ref=_HMAC_REF)
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen",
                             headers=_hmac_headers(_SCREEN_BODY),
                             content=_SCREEN_BODY)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


def test_hmac_stale_timestamp_is_401(monkeypatch):
    monkeypatch.setenv(_HMAC_REF, _HMAC_SECRET)
    _enroll()
    _identity(hmac_secret_ref=_HMAC_REF)
    hdr = _hmac_headers(_SCREEN_BODY, ts=str(int(time.time()) - 4000))
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen", headers=hdr,
                             content=_SCREEN_BODY)
    assert r.status_code == 401


def _jwt_setup(tmp_path) -> bytes:
    """Pin issuer/audience + a PEM key file on the enrolled agent; return
    the matching private key for minting tokens."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    key_file = tmp_path / "partner.pem"
    key_file.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    _identity(jwt_issuer=_ISSUER, jwt_audience=_AUDIENCE,
              jwks_file=str(key_file))
    return priv_pem


def _jwt_token(priv_pem: bytes, **overrides) -> str:
    now = int(time.time())
    claims = {"sub": "sf-quotebot", "iss": _ISSUER, "aud": _AUDIENCE,
              "iat": now, "exp": now + 600}
    claims.update(overrides)
    return jwt.encode(claims, priv_pem, algorithm="RS256")


@requires_crypto
def test_jwt_auth_over_http(tmp_path):
    _enroll()
    priv_pem = _jwt_setup(tmp_path)
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers={"Authorization": f"Bearer {_jwt_token(priv_pem)}"},
        json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


@requires_crypto
def test_jwt_for_another_subject_is_401(tmp_path):
    """A validly-signed token whose sub names another agent never
    authenticates this one."""
    _enroll()
    priv_pem = _jwt_setup(tmp_path)
    token = _jwt_token(priv_pem, sub="other-bot")
    r = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/external/screen",
        headers={"Authorization": f"Bearer {token}"},
        json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 401


def test_bearer_still_works_alongside_strong_credentials():
    """require_signed defaults OFF: enrolling a pubkey does not strand an
    agent still calling with its minted bearer."""
    _enroll()
    token = _mint()
    _identity(pubkey="ab" * 32)
    r = TestClient(app, base_url="http://127.0.0.1").post("/api/v1/external/screen",
                             headers={"Authorization": f"Bearer {token}"},
                             json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is True


def test_require_signed_refuses_bearer_for_strong_credential_agents(tmp_path):
    from maverick import config
    _enroll()
    token = _mint()
    _identity(pubkey="ab" * 32)
    _enroll(id="langbot", platform="custom")
    r = client.post("/api/v1/external-agents/langbot/credentials",
                    json={"surface": "rest"})
    plain_token = r.json()["token"]
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nrequire_signed = true\n", encoding="utf-8")
    config.reset_config_cache()
    bare = TestClient(app, base_url="http://127.0.0.1")
    body = {"tool": "crm_update", "risk": "low"}
    # The pubkey-bearing agent must present its strong credential…
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"}, json=body)
    assert r.status_code == 401
    # …while a token-only agent keeps working.
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {plain_token}"},
                  json=body)
    assert r.status_code == 200, r.text


def test_require_signed_covers_hmac_only_agents(tmp_path):
    """An agent whose only strong credential is HMAC must also lose its
    bearer under require_signed — otherwise a leaked bearer keeps working
    against the very switch that was meant to retire it."""
    from maverick import config
    _enroll()
    token = _mint()
    _identity(hmac_secret_ref="SF_QUOTEBOT_HMAC")  # pragma: allowlist secret
    (tmp_path / "config.toml").write_text(
        "[external_agents]\nrequire_signed = true\n", encoding="utf-8")
    config.reset_config_cache()
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = bare.post("/api/v1/external/screen",
                  headers={"Authorization": f"Bearer {token}"},
                  json={"tool": "crm_update", "risk": "low"})
    assert r.status_code == 401


def test_outside_agent_pages_read_plainly_and_offer_actions():
    from test_support.plain_language import developer_terms

    _enroll()
    roster = client.get("/external-agents").text
    detail = client.get("/external-agents/sf-quotebot").text
    for page in (roster, detail):
        assert developer_terms(page) == []
        assert "docs/external-agents.md" not in page and "Mint credential" not in page
    # The agent's own page carries the actions the roster offers.
    for attr in ('data-xa-mint="sf-quotebot"', 'data-xa-revoke="sf-quotebot"', 'data-xa-remove="sf-quotebot"'):
        assert attr in detail
    assert "Create access key" in detail and "Block all access" in detail
    assert 'id="xa-owner"' in roster and 'id="xa-tools-add"' in roster
