"""Teach this flow: ``maverick flow operator`` and ``flow recipe`` in the app.

Learning runs the commands' own kernel functions on bounded input; results
come back as drafts that only the normal flow save persists. The reviewed
runs' evidence store is replaced by a small stand-in (the capture pipeline is
covered by its own tests); everything after it is the real kernel.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config
from maverick.flow import store
from maverick.flow.ir import Flow, FlowNode
from maverick.paths import tenant_scope
from maverick_dashboard import rbac

TENANT = "teach-workspace"
TOOLS = ["lookup_customer", "create_invoice"]


def _episode(identity, email, amount, customer_id, invoice_id):
    return {"id": identity, "inputs": {"email": email, "amount": amount}, "steps": [
        {"tool": "lookup_customer", "arguments": {"query": email}, "result": {"records": [{"id": customer_id}]}},
        {"tool": "create_invoice", "arguments": {"customer": {"id": customer_id}, "amount": amount},
         "result": {"invoice_id": invoice_id, "accepted": True}},
    ]}


EPISODES = {"run-a": _episode("run-a", "a@example.test", 120, "cust-a", "inv-a"),
            "run-b": _episode("run-b", "b@example.test", 250, "cust-b", "inv-b"),
            "run-c": _episode("run-c", "c@example.test", 75, "cust-c", "inv-c")}


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.reset_config_cache()
    rbac.set_role("user:owner", "operator")
    rbac.set_role("user:other", "operator")
    rbac.set_role("user:viewer", "viewer")
    from maverick_dashboard import api as api_module
    from maverick_dashboard import cli_ops_api
    from maverick_dashboard import flow_teach_ops_api as teach

    flow = Flow(id="billing", name="Billing", start="decide", owner="user:owner", nodes={
        "decide": FlowNode(id="decide", kind="agent", brief="Decide the discount", output="discount", next="check"),
        "check": FlowNode(id="check", kind="approval", prompt="Look up the price?", next="lookup"),
        "lookup": FlowNode(id="lookup", kind="action", tool="web_search"),
    })
    with tenant_scope(tenant=TENANT):
        saved = store.save_flow(flow)
    exported = []

    class Evidence:
        def export(self, ctx, flow_id, run_id):
            exported.append(run_id)
            return {"episode": EPISODES[run_id]}

        def get(self, ctx, flow_id, run_id, detail=False):
            return {"status": "accepted", "revision": 3, "episode_sha256": "e" * 64,
                    "training_available": False}

    monkeypatch.setattr(teach, "_episode_service", lambda request, flow_id, **kwargs: (
        Evidence(), SimpleNamespace(resource_owner="user:owner")))
    application = FastAPI()

    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=TENANT):
            return await call_next(request)

    application.include_router(api_module.router)
    application.include_router(cli_ops_api.router)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield SimpleNamespace(client=client, flow=saved, exported=exported)
    config.reset_config_cache()


def _as(user):
    return {"X-Test-User": user}


RULE = {"inputs": [{"name": "amount", "kind": "integer", "min": 0, "max": 1000}], "output_kind": "boolean",
        "constants": [100],
        "examples": [{"inputs": {"amount": 10}, "output": False}, {"inputs": {"amount": 500}, "output": True},
                     {"inputs": {"amount": 20}, "output": False}, {"inputs": {"amount": 900}, "output": True}]}


def test_overview_lists_ai_steps_actions_and_refuses_others(env):
    data = env.client.get("/api/v1/flows/billing/teach").json()
    assert [s["id"] for s in data["steps"]] == ["decide"] and data["tools"] == ["web_search"]
    assert data["flow"]["version"] == env.flow.version
    assert env.client.get("/api/v1/flows/billing/teach", headers=_as("other")).status_code == 404
    assert env.client.get("/api/v1/flows/billing/teach", headers=_as("viewer")).status_code == 403


def test_teaching_refuses_changed_flow_before_learning_but_accepts_current_form(env):
    context = env.client.get("/api/v1/flows/billing/teach").json()["flow"]["context"]
    changed_account = env.client.post("/api/v1/flows/billing/teach/rule/learn", json=RULE,
                                      headers={"X-Lightwork-Teaching-Context": "0" * 64})
    assert changed_account.status_code == 409 and "account changed" in changed_account.json()["detail"]
    stale = env.client.post("/api/v1/flows/billing/teach/rule/learn", json=RULE,
                           headers={"X-Lightwork-Flow-Version": str(env.flow.version + 1),
                                    "X-Lightwork-Flow-Revision": env.flow.revision})
    assert stale.status_code == 409 and "after review" in stale.json()["detail"]
    current = env.client.post("/api/v1/flows/billing/teach/rule/learn", json=RULE,
                             headers={"X-Lightwork-Flow-Version": str(env.flow.version),
                                      "X-Lightwork-Flow-Revision": env.flow.revision,
                                      "X-Lightwork-Teaching-Context": context})
    assert current.status_code == 200 and current.json()["summary"]["examples"] == 4


def test_learn_try_add_examples_attach_and_save_through_the_normal_save(env):
    learned = env.client.post("/api/v1/flows/billing/teach/rule/learn", json=RULE)
    assert learned.status_code == 200, learned.text
    artifact, summary = learned.json()["artifact"], learned.json()["summary"]
    assert summary["examples"] == 4 and summary["rules"] >= 1
    tried = env.client.post("/api/v1/flows/billing/teach/rule/try", json={"artifact": artifact, "inputs": {"amount": 800}})
    assert tried.status_code == 200 and "explanation" in tried.json()
    more = env.client.post("/api/v1/flows/billing/teach/rule/add-examples",
                           json={"artifact": artifact, "examples": [{"inputs": {"amount": 450}, "output": True}]})
    assert more.status_code == 200 and more.json()["summary"]["examples"] == 5
    attached = env.client.post("/api/v1/flows/billing/teach/rule/attach",
                               json={"artifact": more.json()["artifact"], "node_id": "decide"}).json()
    assert attached["saved"] is False and attached["published"] is False
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("billing").nodes["decide"].learned_operator is None, "attach only drafts"
    saved = env.client.post("/api/v1/flows", json={"flow": attached["draft"]})
    assert saved.status_code == 201, saved.text
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("billing").nodes["decide"].learned_operator is not None
    overview = env.client.get("/api/v1/flows/billing/teach").json()
    assert overview["steps"][0]["rule"]["examples"] == 5
    removed = env.client.post("/api/v1/flows/billing/teach/rule/remove", json={"node_id": "decide"}).json()
    assert Flow.from_dict(removed["draft"]).nodes["decide"].learned_operator is None


def test_combined_rules_and_plain_refusals(env):
    combined = env.client.post("/api/v1/flows/billing/teach/rule/learn", json={**RULE, "combined": True, "max_operations": 1})
    assert combined.status_code == 200, combined.text
    assert combined.json()["summary"]["combined"] is True
    clash = {**RULE, "examples": RULE["examples"] + [{"inputs": {"amount": 10}, "output": True}]}
    refused = env.client.post("/api/v1/flows/billing/teach/rule/learn", json=clash)
    assert refused.status_code == 400 and refused.json()["detail"] == "Two examples have the same inputs but different answers."
    too_many = {**RULE, "examples": [{"inputs": {"amount": i}, "output": i > 5} for i in range(65)]}
    assert env.client.post("/api/v1/flows/billing/teach/rule/learn", json=too_many).status_code == 422
    assert env.client.post("/api/v1/flows/billing/teach/rule/learn", json={**RULE, "extra": 1}).status_code == 422
    assert env.client.post("/api/v1/flows/billing/teach/rule/learn", json=RULE, headers=_as("other")).status_code == 404
    forged = env.client.post("/api/v1/flows/billing/teach/rule/try",
                             json={"artifact": {"schema": "lightwork.learned-operator.v1"}, "inputs": {"amount": 1}})
    assert forged.status_code == 200 and forged.json()["answered"] is False


def test_review_acceptance_alone_cannot_train_or_draft_a_recipe(env):
    learned = env.client.post("/api/v1/flows/billing/teach/recipe/learn",
                              json={"run_ids": ["run-a", "run-b"], "tools": TOOLS, "style": "plain"})
    assert learned.status_code == 409 and "Signed learning is not ready" in learned.json()["detail"]
    assert env.exported == []
    # Old raw artifacts cannot be submitted to the customer refinement/draft
    # routes after the signed lineage boundary was added.
    assert env.client.post("/api/v1/flows/billing/teach/recipe/refine",
                           json={"artifact": {}, "run_ids": ["run-c"]}).status_code == 422
    assert env.client.post("/api/v1/flows/billing/teach/recipe/draft",
                           json={"artifact": {}, "name": "Invoice customers"}).status_code == 422
    one = env.client.post("/api/v1/flows/billing/teach/recipe/learn", json={"run_ids": ["run-a"], "tools": TOOLS})
    assert one.status_code == 422


def test_signed_examples_refuse_forgeries_viewers_and_short_sets(env):
    checked = env.client.post("/api/v1/flow-teach/signed-copy/check", json={"bundle": {"body": {}, "signature": "x"}})
    assert checked.status_code == 200 and checked.json()["genuine"] is False
    assert env.client.post("/api/v1/flow-teach/signed-copy/check", json={"bundle": {}},
                           headers=_as("viewer")).status_code == 403
    assert env.client.post("/api/v1/flow-teach/signed/learn",
                           json={"bundles": [{}], "tools": TOOLS}).status_code == 422
    refused = env.client.post("/api/v1/flow-teach/signed/learn", json={"bundles": [{}, {}], "tools": TOOLS})
    assert refused.status_code == 400
    inspect = env.client.post("/api/v1/flow-teach/signed/inspect", json={"package": {"artifact": {}}})
    assert inspect.status_code == 400


def test_teach_page_renders_with_controls(env, monkeypatch):
    import maverick_dashboard.app as dashboard

    monkeypatch.setattr(dashboard, "templates", dashboard.templates)
    page = env.client.get("/flows/billing/teach")
    assert page.status_code == 200, page.text[:300]
    for needle in ("Teach a step from examples", "tr-learn", "Build a flow from reviewed runs", "sg-learn"):
        assert needle in page.text
    assert env.client.get("/flows/billing/teach", headers=_as("other")).status_code == 404


def test_recent_example_inbox_is_owner_scoped_and_links_to_exact_run(env, monkeypatch):
    monkeypatch.setattr(config, "get_flows", lambda: {"action_episode_capture": True})
    observed = []

    def recent(*, owner, limit, cursor):
        observed.append((owner, limit, cursor))
        if owner != "user:owner":
            return []
        return [SimpleNamespace(flow_id="billing", run_id="run-a", created=100.0,
                                updated=100.0, status="completed")]

    monkeypatch.setattr(store, "list_run_metadata", recent)
    page = env.client.get("/learning/examples")
    assert page.status_code == 200 and "lex-list" in page.text
    result = env.client.get("/api/v1/learning/examples")
    assert result.status_code == 200, result.text
    assert result.json()["examples"] == [{
        "flow_id": "billing", "run_id": "run-a", "flow_name": "Billing", "started": 100.0,
        "run_status": "completed", "status": "accepted", "training_available": False,
        "retain_until": None, "audit_status": None,
    }]
    assert observed == [("user:owner", 200, None)]
    assert env.client.get("/api/v1/learning/examples", headers=_as("other")).json()["examples"] == []
    assert env.client.get("/api/v1/learning/examples", headers=_as("viewer")).status_code == 403


def test_example_inbox_pages_older_runs_without_a_hidden_cutoff(env, monkeypatch):
    monkeypatch.setattr(config, "get_flows", lambda: {"action_episode_capture": True})
    runs = [SimpleNamespace(flow_id="billing", run_id=f"run-{index}", created=float(1000 - index),
                            updated=float(1000 - index), status="completed") for index in range(51)]

    def recent(*, owner, limit, cursor):
        assert owner == "user:owner" and limit == 200
        return [run for run in runs if cursor is None or (run.updated, run.run_id) < cursor][:limit]

    monkeypatch.setattr(store, "list_run_metadata", recent)
    first = env.client.get("/api/v1/learning/examples")
    assert first.status_code == 200 and len(first.json()["examples"]) == 50
    cursor = first.json()["next_cursor"]
    assert cursor
    older = env.client.get("/api/v1/learning/examples", params={"cursor": cursor})
    assert older.status_code == 200 and len(older.json()["examples"]) == 1
    assert older.json()["next_cursor"] is None
    assert env.client.get("/api/v1/learning/examples", params={"cursor": "not!valid"}).status_code == 422


def test_example_inbox_does_not_present_storage_failure_as_no_examples(env, monkeypatch):
    from maverick_dashboard import flow_teach_ops_api as teach

    monkeypatch.setattr(config, "get_flows", lambda: {"action_episode_capture": True})
    monkeypatch.setattr(store, "list_run_metadata", lambda **_kwargs: [
        SimpleNamespace(flow_id="billing", run_id="run-a", created=100.0, updated=100.0,
                        status="completed")])

    class Broken:
        def get(self, *_args):
            raise OSError("private store unavailable")

    monkeypatch.setattr(teach, "_episode_service", lambda *_args, **_kwargs: (
        Broken(), SimpleNamespace(resource_owner="user:owner")))
    failed = env.client.get("/api/v1/learning/examples")
    assert failed.status_code == 503
    assert "could not be checked" in failed.json()["detail"]
    assert "private store" not in failed.text
    flow_failed = env.client.get("/api/v1/flows/billing/teach/examples")
    assert flow_failed.status_code == 503 and "could not be checked" in flow_failed.json()["detail"]
    assert "private store" not in flow_failed.text


def test_copilot_reviewed_source_change_refuses_signed_issuance(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import api_flow_recipe_lineage as lineage
    from maverick_dashboard import flow_teach_ops_api as teach

    class Evidence:
        def get(self, *_args):
            return {"training_available": True, "revision": 4,
                    "episode_sha256": "e" * 64, "grant_sha256": "g" * 64}

        def export_signed(self, *_args, **_kwargs):
            pytest.fail("A changed reviewed source must not reach the signer.")

    context = SimpleNamespace(resource_owner="user:owner")
    monkeypatch.setattr(teach, "_signed_ready", lambda _flags: True)
    monkeypatch.setattr(teach, "_episode_service", lambda *_args, **_kwargs: (Evidence(), context))
    monkeypatch.setattr(lineage, "_service", lambda _request: (None, context))
    with pytest.raises(HTTPException) as error:
        teach._gather_signed(None, "billing", ["one"], expected_runs={"one": {
            "revision": 3, "episode": "e" * 64, "grant": "g" * 64}})
    assert error.value.status_code == 409 and "after review" in error.value.detail


def _key_trust(public_hex, issuer="caller-issuer"):
    import hashlib

    from maverick.flow import action_provenance as provenance

    key_id = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]
    return {"schema": provenance.TRUST_SCHEMA, "issuer": issuer, "tenant": TENANT,
            "purpose": provenance.PURPOSE, "keys": {key_id: public_hex}, "revoked_keys": []}, key_id


def test_a_copy_signed_with_a_key_the_caller_supplies_is_never_genuine(env, monkeypatch):
    # A caller who signs a forged example with their own key and uploads that
    # key as the "trust file" must not get it reported genuine, or learned from.
    import time

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from maverick.audit import signing
    from maverick.flow import action_provenance as provenance

    def public(private):
        return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    attacker = Ed25519PrivateKey.generate()
    caller_trust, key_id = _key_trust(public(attacker))
    workspace_trust, _ = _key_trust(public(Ed25519PrivateKey.generate()))
    monkeypatch.setattr(provenance, "local_trust", lambda tenant: workspace_trust)
    # The body's own validation is covered by the kernel's tests; this is about whose keys are trusted.
    monkeypatch.setattr(provenance, "validate_body", lambda body: body)
    body = {"schema": "forged", "tenant": TENANT, "issuer": "caller-issuer", "purpose": provenance.PURPOSE,
            "issued_at": time.time() - 10, "grant": {"use_until": time.time() + 3600}}
    digest = provenance.digest(body)
    message = signing.DETACHED_DIGEST_MESSAGE_VERSION.encode() + b"\x00" + bytes.fromhex(digest)
    bundle = {"body": body, "signature": {"algorithm": "Ed25519-SHA256", "digest": digest, "key_id": key_id,
                                          "message_version": signing.DETACHED_DIGEST_MESSAGE_VERSION,
                                          "signature": attacker.sign(message).hex()}}
    provenance.verify_bundle(bundle, trust=caller_trust, expected_tenant=TENANT, now=time.time())  # really signed

    checked = env.client.post("/api/v1/flow-teach/signed-copy/check", json={"bundle": bundle, "trust": caller_trust})
    assert checked.status_code == 200, checked.text
    assert checked.json()["genuine"] is False
    assert "signed by a key you supplied, not one this workspace trusts" in checked.json()["message"]
    assert env.client.post("/api/v1/flow-teach/signed-copy/check", json={"bundle": bundle}).json()["genuine"] is False
    for path, payload in (("/api/v1/flow-teach/signed/learn", {"bundles": [bundle, bundle], "tools": TOOLS}),
                          ("/api/v1/flow-teach/signed/refine", {"package": {}, "bundles": [bundle]}),
                          ("/api/v1/flow-teach/signed/inspect", {"package": {"artifact": {}}})):
        refused = env.client.post(path, json={**payload, "trust": caller_trust})
        assert refused.status_code == 400 and "this workspace trusts" in refused.json()["detail"], path
