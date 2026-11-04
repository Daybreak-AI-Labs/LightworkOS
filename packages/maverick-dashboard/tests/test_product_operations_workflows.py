"""Copilot can hand a reviewed release to the native learned run form only."""
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard import product_operations as ops
from maverick_dashboard import product_operations_workflows as workflows

BASE = "/api/v1/copilot/product-operations"
PAGE = "/flows/designer/owned"
SELECTION = {"kind": "flow", "id": "owned"}


def _harness(monkeypatch):
    state = {"published": True, "learned": True, "release": "a" * 64, "allowed": True,
             "deleted": False, "pending_forms": 0, "calls": []}

    def draft(_request, flow_id):
        state["calls"].append("draft")
        if not state["allowed"] or state["deleted"] or flow_id != "owned":
            raise HTTPException(404, "no such flow")
        return {"id": flow_id, "version": 2, "revision": "draft-2", "published": state["published"]}

    def published(_request, flow_id):
        state["calls"].append("published")
        if not state["allowed"] or state["deleted"] or flow_id != "owned":
            raise HTTPException(404, "no such flow")
        if not state["published"]:
            raise HTTPException(409, "not published")
        return {"flow": {"id": flow_id, "name": "Order review",
                         "learned_recipe": {"schema": "lightwork.action-recipe.v1"} if state["learned"] else None},
                "release_id": state["release"]}

    def retirement(_request, flow_id):
        state["calls"].append("retirement")
        if not state["allowed"] or state["deleted"] or flow_id != "owned":
            raise HTTPException(404, "no such flow")
        return {"id": flow_id, "name": "Order review", "version": 2,
                "revision": "draft-2", "published": state["published"],
                "release_id": state["release"] if state["published"] else "",
                "scheduled": state["published"], "connected_starts": 1,
                "pending_forms": state["pending_forms"], "active_runs": 1,
                "published_parent_flows": 0}

    def turn_off(_request, flow_id, payload):
        state["calls"].append("turn_off")
        if (not state["allowed"] or state["deleted"] or flow_id != "owned"
                or payload.expected_release_id != state["release"]):
            raise HTTPException(409, "flow changed")
        state["published"] = False
        return {"id": flow_id, "published": False}

    def delete(_request, flow_id, response, *, version, revision, expected_release_id):
        state["calls"].append("delete")
        if (not state["allowed"] or state["deleted"] or flow_id != "owned"
                or version != 2 or revision != "draft-2"
                or expected_release_id != (state["release"] if state["published"] else "")
                or state["pending_forms"]):
            raise HTTPException(409, "flow changed")
        state["deleted"] = True
        response.headers["X-Lightwork-Recovery-Copy"] = "cleared"

    monkeypatch.setattr(workflows.native, "get_flow_endpoint", draft)
    monkeypatch.setattr(workflows.native, "get_published_flow_endpoint", published)
    monkeypatch.setattr(workflows.native, "flow_retirement_preview_endpoint", retirement)
    monkeypatch.setattr(workflows.native, "unpublish_flow_endpoint", turn_off)
    monkeypatch.setattr(workflows.native, "delete_flow_endpoint", delete)
    monkeypatch.setattr(workflows.native, "run_flow_endpoint", lambda *_args: (_ for _ in ()).throw(
        AssertionError("review must never start work")))
    monkeypatch.setattr(ops, "_same_origin", lambda _request: None)
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "_context", lambda _request: "c" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in workflows.entries()})
    app = FastAPI()
    app.include_router(ops.router)
    return TestClient(app, base_url="http://127.0.0.1"), state


def test_published_learned_run_is_catalogued_and_prepared_without_execution(monkeypatch):
    client, state = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        item = catalog["operations"][0]
        assert item["id"] == "learning.workflow_run" and item["available"]
        result = client.post(BASE + "/prepare", json={"page": PAGE, "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"], "arguments": {}})
        assert result.status_code == 200
        review = result.json()
        assert review["read_only"] is True and "token" not in review
        assert review["details"] == {"flow_id": "owned", "release_id": "a" * 64, "name": "Order review"}
        assert "run" not in state["calls"]


def test_changed_release_unpublished_or_nonlearned_workflow_cannot_launch(monkeypatch):
    client, state = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        item = catalog["operations"][0]
        state["release"] = "b" * 64
        stale = client.post(BASE + "/prepare", json={"page": PAGE, "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"]})
        assert stale.status_code == 409
        state["published"] = False
        blocked = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        assert blocked["operations"][0]["available"] is False
        state["published"], state["learned"] = True, False
        blocked = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        assert blocked["operations"][0]["available"] is False
        state["allowed"] = False
        denied = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        assert denied["operations"] == []


def test_copilot_checks_the_same_recent_examples_without_a_mutation(monkeypatch):
    from maverick_dashboard import flow_teach_ops_api as teach

    client, _state = _harness(monkeypatch)
    rows = [{"flow_id": "owned", "run_id": "run-1", "flow_name": "Order review",
             "status": "awaiting_review", "training_available": False, "audit_status": "delivered"}]
    monkeypatch.setattr(teach, "learning_examples_inbox", lambda _request: {
        "examples": rows, "recent_only": False, "available": True})
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": "/learning/examples", "selection": {}}).json()
        item = catalog["operations"][0]
        assert item["id"] == "learning.examples_review" and item["available"]
        reviewed = client.post(BASE + "/prepare", json={"page": "/learning/examples", "selection": {},
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"], "arguments": {}})
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["read_only"] is True
        assert reviewed.json()["details"]["examples"][0]["href"] == "/flows/owned/runs/run-1"
        rows[0] = {**rows[0], "status": "accepted", "training_available": True}
        stale = client.post(BASE + "/prepare", json={"page": "/learning/examples", "selection": {},
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"], "arguments": {}})
        assert stale.status_code == 409


def test_copilot_turn_off_and_delete_require_fresh_review_and_confirmation(monkeypatch):
    client, state = _harness(monkeypatch)
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: value[len("sealed:"):])

    def review(operation):
        catalog = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        item = next(row for row in catalog["operations"] if row["id"] == operation)
        prepared = client.post(BASE + "/prepare", json={"page": PAGE, "selection": SELECTION,
            "operation": operation, "context": catalog["context"], "revision": item["revision"],
            "arguments": {}})
        assert prepared.status_code == 200, prepared.text
        return prepared.json()

    with client:
        turn_off = review("learning.workflow_turn_off")
        assert turn_off["read_only"] is False and "token" in turn_off
        denied = client.post(BASE + "/execute", json={"token": turn_off["token"], "confirmed": False})
        assert denied.status_code == 400 and state["published"] is True
        state["release"] = "b" * 64
        stale = client.post(BASE + "/execute", json={"token": turn_off["token"], "confirmed": True})
        assert stale.status_code == 409 and "turn_off" not in state["calls"]
        turned_off = client.post(BASE + "/execute", json={
            "token": review("learning.workflow_turn_off")["token"], "confirmed": True})
        assert turned_off.status_code == 200 and turned_off.json()["status"] == "confirmed"
        assert state["published"] is False
        state["pending_forms"] = 1
        blocked = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        deletion = next(row for row in blocked["operations"] if row["id"] == "learning.workflow_delete")
        assert deletion["available"] is False and "Automations" in deletion["blocked"]
        state["pending_forms"] = 0
        deleted = client.post(BASE + "/execute", json={
            "token": review("learning.workflow_delete")["token"], "confirmed": True})
        assert deleted.status_code == 200 and deleted.json()["status"] == "confirmed"
        assert state["deleted"] is True


def test_copilot_hardening_binds_input_and_saves_only_after_fresh_confirmation(monkeypatch):
    client, state = _harness(monkeypatch)
    state["version"] = 2
    state["revision"] = "draft-2"
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: value[len("sealed:"):])

    def draft(_request, flow_id):
        if not state["allowed"] or flow_id != "owned":
            raise HTTPException(404, "no such flow")
        return {"id": flow_id, "name": "Customer lookup", "start": "step",
                "version": state["version"], "revision": state["revision"],
                "inputs": [{"key": "customer", "label": "Customer name", "type": "text"}],
                "nodes": [{"id": "step", "kind": "agent", "brief": "Look up the customer"}]}

    def review(_request, flow_id, node_id, tool=""):
        draft(_request, flow_id)
        if node_id != "step":
            raise HTTPException(409, "suggestion changed")
        return {"flow_id": flow_id, "flow_name": "Customer lookup",
                "version": state["version"], "revision": state["revision"],
                "node_id": node_id, "node_label": "Look up customer", "from_kind": "agent",
                "to_kind": "action", "published": True, "inferred_tool": "web_search",
                "tool": "web_search", "description": "Search public pages",
                "fields": [{"name": "query", "label": "Query", "type": "string",
                            "required": True, "description": "What to search for"}],
                "sources": [{"key": "customer", "label": "Customer name", "origin": "input"}]}

    def apply(_request, flow_id, payload):
        state["calls"].append("apply")
        assert flow_id == "owned" and payload.node_id == "step"
        assert payload.tool == "web_search" and payload.params == {"query": "{{customer}}"}
        assert payload.version == state["version"] and payload.revision == state["revision"]
        state["version"] += 1
        return {"id": flow_id, "node_id": "step", "to_kind": "action", "version": state["version"]}

    monkeypatch.setattr(workflows.native, "get_flow_endpoint", draft)
    monkeypatch.setattr(workflows.native, "flow_apply_review_endpoint", review)
    monkeypatch.setattr(workflows.native, "apply_flow_proposal_endpoint", apply)
    selection = {"kind": "flow", "id": "owned", "node_id": "step"}

    def prepare():
        catalog = client.post(BASE + "/catalog", json={"page": PAGE, "selection": selection}).json()
        item = next(row for row in catalog["operations"] if row["id"] == "learning.workflow_harden")
        assert item["available"] and item["fields"][0]["label"] == "Query"
        assert item["fields"][0]["choices"][0]["value"] == ""
        response = client.post(BASE + "/prepare", json={"page": PAGE, "selection": selection,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {"query": "customer"}})
        assert response.status_code == 200, response.text
        return response.json()["token"]

    with client:
        token = prepare()
        assert "apply" not in state["calls"]
        state["version"] += 1
        stale = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert stale.status_code == 409 and "apply" not in state["calls"]
        token = prepare()
        denied = client.post(BASE + "/execute", json={"token": token, "confirmed": False})
        assert denied.status_code == 400 and "apply" not in state["calls"]
        done = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert done.status_code == 200, done.text
        assert done.json()["status"] == "confirmed" and state["version"] == 4
        assert state["calls"].count("apply") == 1


def _hardening_input(monkeypatch, kind, entered):
    """Prepare a fixed action with one numeric input; returns the saved params."""
    from maverick.governed_operations import digest
    from maverick_dashboard.product_operations import Snapshot

    review = {"flow_id": "owned", "flow_name": "Customer lookup", "version": 2, "revision": "draft-2",
              "node_id": "step", "node_label": "Look up customer", "from_kind": "agent",
              "to_kind": "action", "published": True, "tool": "web_search",
              "fields": [{"name": "limit", "label": "Limit", "type": kind, "required": True}],
              "sources": []}
    draft = {"id": "owned", "name": "Customer lookup", "start": "step", "version": 2,
             "revision": "draft-2", "nodes": [{"id": "step", "kind": "agent", "brief": "Look up"}]}
    monkeypatch.setattr(workflows, "harden_snapshot",
                        lambda _request, _selection: Snapshot(digest(review), "source", "summary"))
    monkeypatch.setattr(workflows.native, "flow_apply_review_endpoint", lambda *_args: review)
    monkeypatch.setattr(workflows.native, "get_flow_endpoint", lambda *_args: draft)
    selection = {"kind": "flow", "id": "owned", "node_id": "step"}
    return workflows.harden_prepare(None, selection, {"limit": entered}).native["params"]


def test_hardening_keeps_whole_numbers_exact_beyond_two_to_the_53(monkeypatch):
    # A float cannot hold 2**53 + 1; it must not be saved as 9007199254740992.
    assert _hardening_input(monkeypatch, "integer", "9007199254740993") == {"limit": 9007199254740993}
    assert _hardening_input(monkeypatch, "integer", 9007199254740993) == {"limit": 9007199254740993}
    assert _hardening_input(monkeypatch, "integer", " 25 ") == {"limit": 25}
    assert _hardening_input(monkeypatch, "integer", 25.0) == {"limit": 25}
    assert _hardening_input(monkeypatch, "number", "2.5") == {"limit": 2.5}


def test_hardening_refuses_integer_input_that_is_not_a_whole_number(monkeypatch):
    for entered in ("2.5", "1e400", "nan", "inf", "twelve", 2.5, True, "9" * 400):
        with pytest.raises(HTTPException) as exc:
            _hardening_input(monkeypatch, "integer", entered)
        assert exc.value.status_code == 422, entered


def test_copilot_teaching_reviews_exact_examples_then_hands_back_an_unapproved_recipe(monkeypatch):
    from maverick_dashboard import flow_teach_ops_api as teach

    client, state = _harness(monkeypatch)
    page = "/flows/owned/teach"
    rows = [{"run_id": name, "started": 100 + index, "status": "accepted", "can_learn": True,
             "revision": 3, "episode": "e" * 64, "grant": "g" * 64} for index, name in enumerate(["one", "two"])]
    monkeypatch.setattr(teach, "flow_teach_overview", lambda _request, flow_id: {
        "flow": {"id": flow_id, "name": "Order review", "version": 2, "revision": "draft-2"},
        "tools": ["lookup_customer"], "steps": []})
    monkeypatch.setattr(teach, "reviewed_examples", lambda *_args: {"runs": rows, "available": True})
    monkeypatch.setattr(teach, "_signed_ready", lambda _flags: True)
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + value)
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: value[len("sealed:"):])

    def learn(_request, flow_id, body, *, expected_runs):
        assert flow_id == "owned" and body.run_ids == ["one", "two"]
        assert expected_runs == {row["run_id"]: {key: row[key] for key in ("revision", "episode", "grant")} for row in rows}
        state["calls"].append("learn")
        return {"package": {"artifact": {"schema": "test"}}, "summary": {"runs": 2, "actions": ["lookup_customer"]}, "approved": False}

    monkeypatch.setattr(teach, "learn_reviewed_recipe", learn)

    def prepare(run_ids=None):
        catalog = client.post(BASE + "/catalog", json={"page": page, "selection": SELECTION}).json()
        item = catalog["operations"][0]
        assert item["id"] == "learning.workflow_teach" and item["available"]
        assert item["fields"][0]["kind"] == "multiselect"
        return client.post(BASE + "/prepare", json={"page": page, "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {"run_ids": run_ids or ["one", "two"], "tools": ["lookup_customer"], "style": "plain"}})

    with client:
        assert prepare(["one", "foreign"]).status_code == 409
        reviewed = prepare()
        assert reviewed.status_code == 200, reviewed.text
        token = reviewed.json()["token"]
        denied = client.post(BASE + "/execute", json={"token": token, "confirmed": False})
        assert denied.status_code == 400 and "learn" not in state["calls"]
        rows[0]["grant"] = "h" * 64
        stale = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert stale.status_code == 409 and "learn" not in state["calls"]
        finished = client.post(BASE + "/execute", json={"token": prepare().json()["token"], "confirmed": True})
        assert finished.status_code == 200, finished.text
        result = finished.json()
        assert result["status"] == "confirmed" and result["details"]["recipe"]["approved"] is False
        assert result["details"]["saved"] is False and result["details"]["published"] is False
        assert state["calls"].count("learn") == 1
        rows[0]["can_learn"] = False
        blocked = client.post(BASE + "/catalog", json={"page": page, "selection": SELECTION}).json()
        assert blocked["operations"][0]["available"] is False


def test_copilot_shared_teaching_forms_pin_the_current_step_and_flow_revision(monkeypatch):
    from maverick_dashboard import flow_teach_ops_api as teach

    client, _state = _harness(monkeypatch)
    overview = {"flow": {"id": "owned", "name": "Order review", "version": 2, "revision": "current-2"},
                "steps": [{"id": "decision", "ready": True, "rule": {"examples": 2}}], "tools": []}
    monkeypatch.setattr(teach, "flow_teach_overview", lambda *_args: overview)
    monkeypatch.setattr(teach, "reviewed_examples", lambda *_args: {"runs": [{"can_learn": True,
        "run_id": "one", "started": 100, "revision": 3, "episode": "e" * 64, "grant": "g" * 64}], "available": True})
    monkeypatch.setattr(teach, "_signed_ready", lambda _flags: True)
    selection = {"kind": "flow", "id": "owned", "node_id": "decision"}
    page = "/flows/owned/teach"
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": page, "selection": selection}).json()
        for identifier, mode in (("learning.workflow_refine", "recipe_refine"),
                                 ("learning.rule_teach", "rule_teach"), ("learning.rule_refine", "rule_refine")):
            item = next(row for row in catalog["operations"] if row["id"] == identifier)
            assert item["available"] and item["confirmation_required"] is False
            body = {"page": page, "selection": selection, "operation": identifier,
                    "context": catalog["context"], "revision": item["revision"], "arguments": {}}
            response = client.post(BASE + "/prepare", json=body)
            assert response.status_code == 200, response.text
            assert response.json()["read_only"] is True
            assert response.json()["details"] == {"flow_id": "owned", "version": 2, "revision": "current-2",
                                                 "context": None, "node_id": "decision", "mode": mode}
            overview["flow"]["revision"] = "changed"
            assert client.post(BASE + "/prepare", json=body).status_code == 409
            overview["flow"]["revision"] = "current-2"


def _listed(rows):
    return sorted((row["id"], row["available"], row.get("blocked", "")) for row in rows)


def test_the_workflow_builder_steps_mode_offers_the_same_flow_actions(monkeypatch):
    """/workflow-builder?mode=steps&flow=<id> is the designer's editor: Copilot
    offers the same Run, Turn off, Delete and Harden there, through the same
    adapters, native calls and checks. Without a saved flow nothing is offered."""
    client, state = _harness(monkeypatch)
    flow_actions = {"learning.workflow_run", "learning.workflow_harden",
                    "learning.workflow_turn_off", "learning.workflow_delete"}
    with client:
        designer = client.post(BASE + "/catalog", json={"page": PAGE, "selection": SELECTION}).json()
        steps = client.post(BASE + "/catalog", json={"page": "/workflow-builder", "selection": SELECTION}).json()
        assert flow_actions <= {row["id"] for row in designer["operations"]}
        assert _listed(steps["operations"]) == _listed(designer["operations"])
        item = next(row for row in steps["operations"] if row["id"] == "learning.workflow_run")
        prepared = client.post(BASE + "/prepare", json={"page": "/workflow-builder", "selection": SELECTION,
            "operation": item["id"], "context": steps["context"], "revision": item["revision"], "arguments": {}})
        assert prepared.status_code == 200 and prepared.json()["details"]["flow_id"] == "owned"
        # Describe-it mode (no saved flow): no flow action is listed, not even as unavailable.
        empty = client.post(BASE + "/catalog", json={"page": "/workflow-builder", "selection": {}}).json()
        assert not flow_actions & {row["id"] for row in empty["operations"]}
        # Access is still the native check: a flow this person may not open is never offered.
        state["allowed"] = False
        denied = client.post(BASE + "/catalog", json={"page": "/workflow-builder", "selection": SELECTION}).json()
        assert not flow_actions & {row["id"] for row in denied["operations"]}
