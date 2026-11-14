"""Dashboard endpoints for importing external automations into Lightwork.

Hermetic like the other dashboard tests: HOME/MAVERICK_HOME isolated to tmp,
USER_TEMPLATES (import-time bound) monkeypatched, the world DB under tmp. The
import feature is gated, so the gate env is set on.

Imports go through the complete protected review (automation_imports_api):
read the catalog's context, review the export, then confirm the sealed review.
The legacy one-step ``/api/v1/import/run`` refuses every write. Imports are
made by a signed-in person (alice, through the trusted proxy header).
"""
from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

API = "/api/v1/automation-imports"


def _client(user="alice"):
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Forwarded-User": user})


def _review(client, source, definitions, **choices):
    """Review an exported file; the response carries the sealed review."""
    context = client.get(API).json()["context"]
    return client.post(API + "/review", json={"context": context, "source": source, "mode": "file",
                                              "file_text": json.dumps(definitions), **choices})


def _apply(client, review):
    assert review.status_code == 200, review.text
    return client.post(API + "/apply", json={"token": review.json()["token"], "confirmed": True})


def _imported(client, source, definitions, **choices):
    applied = _apply(client, _review(client, source, definitions, **choices))
    assert applied.status_code == 200, applied.text
    assert applied.json()["confirmed"] is True, applied.json()
    return applied.json()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_AUTOMATION_IMPORT", "1")
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")
    import maverick_dashboard.auth as auth
    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")


N8N_WF = {
    "id": "1", "name": "Lead to Slack", "active": True,
    "nodes": [
        {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
        {"name": "Notify", "type": "n8n-nodes-base.slack", "parameters": {"operation": "post"}},
    ],
    "connections": {"Hook": {"main": [[{"node": "Notify"}]]}},
}


N8N_CRON_WF = {
    "id": "2", "name": "Daily digest", "active": True,
    "nodes": [
        {"name": "Every morning", "type": "n8n-nodes-base.cron",
         "parameters": {"cronExpression": "0 9 * * *"}},
        {"name": "Send email", "type": "n8n-nodes-base.emailSend",
         "parameters": {"operation": "send"}},
    ],
    "connections": {
        "Every morning": {"main": [[{"node": "Send email", "type": "main", "index": 0}]]},
    },
}


class _FakeQueue:
    last = None

    def __init__(self):
        self.enqueued = []
        type(self).last = self

    def enqueue(self, kind, payload, run_at=None):
        self.enqueued.append((kind, payload, run_at))
        return len(self.enqueued)


def test_sources_lists_modes():
    r = _client().get("/api/v1/import/sources")
    assert r.status_code == 200
    sources = {s["source"]: s["mode"] for s in r.json()["sources"]}
    # Platforms with an account reader can be read live; the rest need an export.
    assert sources["n8n"] == "definition-import"
    assert sources["zapier"] == "file-required"


def test_the_one_step_import_refuses_every_write():
    r = _client().post("/api/v1/import/run", json={"source": "n8n", "definitions": [N8N_WF]})
    assert r.status_code == 409
    assert "review every draft before saving" in r.json()["detail"]
    assert "No automation was imported" in r.json()["detail"]


def test_graph_repair_refuses_whole_batch_before_materializing_or_arming(monkeypatch):
    from copy import deepcopy
    from unittest.mock import Mock

    from maverick import automation_import
    from maverick_dashboard import automation_imports

    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    broken = deepcopy(N8N_WF)
    broken["id"] = "repair-needed"
    broken["name"] = "Repair needed"
    broken["nodes"][1] = {
        "name": "Notify", "type": "n8n-nodes-base.if", "parameters": {"conditions": {
            "conditions": [{"leftValue": "={{ $json.amount + 1 }}", "operator": "gt", "rightValue": 1}],
        }},
    }
    materialize = Mock(side_effect=AssertionError("batch preflight must precede every write"))
    monkeypatch.setattr(automation_import, "materialize", materialize)
    monkeypatch.setattr(automation_imports, "materialize", materialize)
    client = _client()
    response = _review(client, "n8n", [N8N_WF, broken], as_flows=True)
    assert response.status_code == 422, response.text
    assert "requires repair before execution" in response.json()["detail"]
    materialize.assert_not_called()


@pytest.mark.parametrize("expression", [
    {"equals": ["yes", "yes"]},
    {"equals": ["@triggerBody()?['customer.status']", "ready"]},
])
def test_wdl_reference_repair_refuses_batch_before_writes(monkeypatch, expression):
    from unittest.mock import Mock

    from maverick import automation_import
    from maverick_dashboard import automation_imports

    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    good = {"name": "valid", "actions": {"Compose": {"type": "Compose", "inputs": "ready"}}}
    broken = {"name": "repair", "actions": {
        "Check": {"type": "If", "expression": expression,
                  "actions": {"Compose": {"type": "Compose", "inputs": "ready"}}},
    }}
    materialize = Mock(side_effect=AssertionError("batch preflight must precede every write"))
    monkeypatch.setattr(automation_import, "materialize", materialize)
    monkeypatch.setattr(automation_imports, "materialize", materialize)
    response = _review(_client(), "power_automate", [good, broken], as_flows=True)
    assert response.status_code == 422, response.text
    assert "requires repair before execution" in response.json()["detail"]
    materialize.assert_not_called()


def test_run_creates_template_from_definitions():
    client = _client()
    body = _imported(client, "n8n", [N8N_WF])
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["template"].startswith("n8n-lead-to-slack-")
    assert item["status"] == "Instructions saved"
    # The template now exists, owned by the person who imported it.
    from maverick.templates import load_template
    assert load_template(item["template"]).owner == "user:alice"


def test_signed_in_importer_can_edit_own_workflow_but_another_user_cannot():
    from maverick.templates import load_template

    client = _client()
    headers = {"X-Forwarded-User": "alice"}
    name = _imported(client, "n8n", [N8N_WF])["items"][0]["template"]
    original = load_template(name)
    assert original.owner == "user:alice"

    edit = {
        "name": name, "title": "Updated workflow", "body": "Review the new lead.",
        "overwrite": True, "expected_generation": original.generation,
    }
    saved = client.post("/api/v1/workflows", headers=headers, json=edit)
    assert saved.status_code == 201, saved.text
    updated = load_template(name)
    assert updated.owner == "user:alice"
    assert updated.body == "Review the new lead."

    denied = client.post("/api/v1/workflows", headers={"X-Forwarded-User": "bob"}, json={
        **edit, "body": "Replace Alice's workflow.", "expected_generation": updated.generation,
    })
    assert denied.status_code == 403, denied.text
    assert load_template(name).body == "Review the new lead."


def test_review_writes_nothing():
    review = _review(_client(), "n8n", [N8N_WF])
    assert review.status_code == 200, review.text
    labels = [row["label"] for row in review.json()["changes"]]
    assert any(label.endswith("save choice") for label in labels)
    from maverick.templates import user_templates_dir
    assert not list(user_templates_dir().glob("*.md")) if user_templates_dir().exists() else True


def test_an_import_never_creates_a_webhook_trigger():
    # Starting from another service is a separate, ordinary Automations choice.
    _imported(_client(), "n8n", [N8N_WF])
    from maverick_dashboard import triggers_store
    assert triggers_store.list_triggers() == []


class _ActivationQueue(_FakeQueue):
    def __init__(self):
        super().__init__()
        _FakeQueue.last = self

    def admission_receipt(self, kind, payload, idempotency_key=None):
        return None

    def enqueue_once(self, kind, payload, idempotency_key=None, run_at=None, effect_guard=None):
        if effect_guard is not None:
            effect_guard()
        return self.enqueue(kind, payload, run_at)


def _ready_for_activation(monkeypatch, create_schedules=True):
    import maverick.config as cfg
    import maverick.job_queue as job_queue
    from maverick import templates, workflow_versions

    _FakeQueue.last = None
    monkeypatch.setattr(job_queue, "JobQueue", _ActivationQueue)
    real = cfg.get_features
    monkeypatch.setattr(cfg, "get_features", lambda: {**real(), "scheduling": True})
    monkeypatch.setattr(cfg, "get_automation_import", lambda: {"enable": True, "create_schedules": create_schedules})
    monkeypatch.setattr(workflow_versions, "enabled", lambda: True)
    # The imported draft is published as-is (Workflow builder's publication).
    monkeypatch.setattr(workflow_versions, "execution_template", lambda name: (templates.load_template(name), "v1"))


def _activate(client, imported, item=0):
    context = client.get(API).json()["context"]
    review = client.post(API + "/review-activation", json={"context": context, "original": imported["id"],
                                                         "item": item, "params": {}, "timezone": "UTC"})
    if review.status_code != 200:
        return review
    return _apply(client, review)


def test_an_import_never_arms_a_schedule_by_itself(monkeypatch):
    _ready_for_activation(monkeypatch)
    _imported(_client(), "n8n", [N8N_CRON_WF])
    assert _FakeQueue.last is None


def test_activating_an_imported_schedule_preserves_request_identity(monkeypatch):
    import maverick_dashboard.auth as auth

    _ready_for_activation(monkeypatch)
    monkeypatch.setattr(auth, "execution_user_id_from_request", lambda request: "alice")
    client = _client()
    imported = _imported(client, "n8n", [N8N_CRON_WF])
    assert imported["activation_choices"][0]["label"]
    activated = _activate(client, imported)
    assert activated.status_code == 200, activated.text
    assert activated.json()["confirmed"] is True
    payload = _FakeQueue.last.enqueued[0][1]
    assert payload["owner"] == "user:alice"
    assert payload["channel"] == "api"
    assert payload["user_id"] == "alice"
    assert payload["__cron__"] == "0 9 * * *"


def test_recreating_imported_schedules_follows_the_config_knob(monkeypatch):
    # [automation_import] create_schedules decides whether an imported
    # automation's schedule may be recreated at all (still reviewed each time).
    _ready_for_activation(monkeypatch, create_schedules=False)
    client = _client()
    imported = _imported(client, "n8n", [N8N_CRON_WF])
    refused = _activate(client, imported)
    assert refused.status_code == 409
    assert "Recreate imported schedules" in refused.json()["detail"]
    assert _FakeQueue.last is None


def test_gate_blocks_when_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUTOMATION_IMPORT", "0")
    r = _client().post("/api/v1/import/run", json={"source": "n8n", "definitions": [N8N_WF]})
    assert r.status_code == 403
    review = _review(_client(), "n8n", [N8N_WF])
    assert review.status_code == 409 and "Automation import is off" in review.json()["detail"]


def test_an_unsupported_record_refuses_the_whole_import():
    # One good + one malformed definition: nothing is saved, and nothing is
    # silently skipped.
    review = _review(_client(), "n8n", [N8N_WF, {"name": "broken", "nodes": "not-a-list"}])
    assert review.status_code == 422, review.text
    assert "Nothing was skipped or saved" in review.json()["detail"]


def test_unknown_source_is_refused():
    assert _review(_client(), "nope", [{}]).status_code == 422


def test_a_platform_without_an_account_reader_needs_an_export():
    client = _client()
    context = client.get(API).json()["context"]
    r = client.post(API + "/review", json={"context": context, "source": "zapier", "mode": "live"})
    assert r.status_code == 422
    assert "requires an exported file" in r.json()["detail"]


def test_automations_page_shows_import_section_when_enabled():
    r = _client().get("/automations")
    assert r.status_code == 200
    assert "Import from another platform" in r.text
    assert 'id="air-disabled" hidden' in r.text


def test_automations_page_says_import_is_off_when_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUTOMATION_IMPORT", "0")
    r = _client().get("/automations")
    assert r.status_code == 200
    # The section stays, saying it is off and where to turn it on; original
    # import history remains readable.
    assert 'id="air-disabled"' in r.text and "Automation import is off" in r.text
    # The page script shows that line from the catalog's state.
    assert _client().get(API).json()["enabled"] is False


def test_run_rejects_too_many_definitions():
    definitions = [dict(N8N_WF, id=str(i), name=f"WF {i}") for i in range(26)]
    assert _review(_client(), "n8n", definitions).status_code == 422


def test_run_rejects_oversized_definition():
    wf = dict(N8N_WF)
    wf["nodes"] = [
        {"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
        {
            "name": "Notify",
            "type": "n8n-nodes-base.slack",
            "parameters": {"operation": "post", "body": "x" * 65_000},
        },
    ]
    assert _review(_client(), "n8n", [wf]).status_code == 413


def test_import_as_flows_saves_graph_and_reports_fidelity(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    item = _imported(_client(), "n8n", [N8N_WF], as_flows=True)["items"][0]
    assert item["flow"]                                # a flow id came back
    assert item["status"] == "Instructions and visual draft saved"
    from maverick.flow import store
    flow = store.load_flow(item["flow"])
    assert flow is not None and flow.validate() == []


def test_import_as_flows_requires_flow_engine(monkeypatch):
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"enable": False})
    r = _review(_client(), "n8n", [N8N_WF], as_flows=True)
    assert r.status_code == 409
    assert "Visual workflows are off" in r.json()["detail"]


def test_import_as_flows_review_previews_without_saving(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    review = _review(_client(), "n8n", [N8N_WF], as_flows=True)
    assert review.status_code == 200, review.text
    labels = [row["label"] for row in review.json()["changes"]]
    assert any("Notify" in label for label in labels)   # the visual steps are reviewed
    from maverick.flow import store
    assert store.list_flows() == []                    # previewed, not persisted


def test_untranslatable_n8n_schedule_names_the_workflow_and_the_repair():
    fortnightly = {"id": "9", "name": "Fortnightly report", "active": True, "nodes": [{
        "name": "Schedule", "type": "n8n-nodes-base.scheduleTrigger",
        "parameters": {"rule": {"interval": [{"field": "weeks", "weeksInterval": 2}]}},
    }], "connections": {}}
    response = _review(_client(), "n8n", [N8N_WF, fortnightly])
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "Fortnightly report" in detail
    assert "interval cannot be represented exactly by cron" in detail
    assert "nothing was saved" in detail
