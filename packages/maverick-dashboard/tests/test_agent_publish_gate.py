"""Builders run a whole saved test set, and changed instructions publish only after it passes."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

API = "/api/v1/workforce-ops/test-suite"
PACK = "proc_po_chaser"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import learning_jobs

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    (tmp_path / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), tmp_path
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append(payload) or True)
    return rows


def _join_background_jobs():
    """Wait for the background job threads started so far to finish.

    The wait ends when the work does, so a slow machine waits longer but never
    fails on a clock, and the test does not sleep. The join timeout only stops a
    hung worker from hanging the suite; a thread still running then fails here.
    """
    from maverick_dashboard import learning_jobs

    for thread, _job in list(learning_jobs._workers):
        thread.join(timeout=120)
        assert not thread.is_alive(), thread.name


def _wait(app, response):
    assert response.status_code == 200, response.text
    job = response.json()["job"]
    _join_background_jobs()
    job = app.get("/api/v1/learning-ops/jobs/" + job["id"]).json()["job"]
    assert job["state"] not in {"admitted", "queued", "running", "stopping"}, job
    return job


def _save_tests(app, count):
    for index in range(count):
        row = app.post(API + "/customer", json={
            "specialist": PACK, "task": f"Purchase order example {index}: which supplier should we chase?",
            "includes": ["chase"], "excludes": [], "refusal": False, "citation": False})
        assert row.status_code == 200, row.text
    cases = app.get(API + "/customer", params={"specialist": PACK}).json()["cases"]
    return {row["id"]: row["revision"] for row in cases}


def _answers(monkeypatch, text="We should chase the supplier today."):
    from maverick import llm

    calls = []

    def answer(self, system, messages, **kwargs):
        calls.append(kwargs["budget"].max_dollars)
        kwargs["dispatch_guard"]()
        return llm.LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)
    return calls


def _current(app):
    return app.get("/api/v1/agents/" + PACK).json()


DRAFTS = "/api/v1/specialist-drafts"


def _decide(app, name, action, **fields):
    """Review, then confirm, one Agent Factory decision on a complete draft."""
    context = app.get(DRAFTS + "/history").json()["context"]
    review = app.post(DRAFTS + "/review", json={"name": name, "action": action, "context": context, **fields})
    if review.status_code != 200:
        return review
    return app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})


def _save_draft(app, name, entered):
    saved = _decide(app, name, "save", entered=entered)
    assert saved.status_code == 200 and saved.json()["confirmed"], saved.text
    return "SPD-" + saved.json()["operation"]


def _publish(app, name, entered, reason=""):
    """Publishing a retained complete draft is the only way a definition changes."""
    return _decide(app, name, "publish", selected=_save_draft(app, name, entered), reason=reason)


def _edit(app, persona, **extra):
    view = _current(app)
    body = {"expected_generation": view["generation"], "persona": persona}
    body.update(extra)
    return body


def test_a_whole_twenty_test_set_runs_in_one_bounded_run(client, monkeypatch):
    app, _tmp = client
    revisions = _save_tests(app, 20)
    calls = _answers(monkeypatch)
    job = _wait(app, app.post(API + "/customer/run", json={
        "specialist": PACK, "operation_id": "a" * 32, "case_revisions": revisions}))
    assert job["state"] == "done", job
    run = job["result"]["run"]
    assert run["total"] == 20 and run["passed"] == 20 and len(calls) == 20
    # Twenty questions are bounded at $0.05 each, never more than the configured caps.
    assert max(calls) <= 1.0
    assert run["instructions_key"]


def test_changed_instructions_need_a_passing_run_or_a_recorded_reason(client, monkeypatch, audit_rows):
    app, _tmp = client
    _save_tests(app, 2)
    new = "You chase overdue purchase orders and always name the supplier to chase."
    check = app.post("/api/v1/agents/" + PACK + "/publish-check", json=_edit(app, new))
    assert check.status_code == 200, check.text
    verdict = check.json()
    assert verdict["required"] and verdict["blocked"] and verdict["gate_on"]
    assert verdict["tests"] == 2 and verdict["latest"] is None
    assert verdict["tests_url"].startswith("/workforce?specialist=" + PACK)

    refused = _publish(app, PACK, {"persona": new})
    assert refused.status_code == 409 and "finished passing check" in refused.json()["detail"]
    assert _current(app)["persona"] != new
    short = _publish(app, PACK, {"persona": new}, reason="ok")
    assert short.status_code == 409 and "at least eight characters" in short.json()["detail"]
    assert _current(app)["persona"] != new

    published = _publish(app, PACK, {"persona": new}, reason="Urgent supplier change approved by finance")
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    assert _current(app)["persona"] == new
    logged = [row for row in audit_rows if row.get("verb") == "agent_published_without_passing_tests"]
    assert logged and logged[0]["reason"] == "Urgent supplier change approved by finance"
    assert logged[0]["specialist"] == PACK


def test_a_passing_comparison_of_the_exact_new_instructions_unlocks_publishing(client, monkeypatch, audit_rows):
    app, _tmp = client
    revisions = _save_tests(app, 2)
    _answers(monkeypatch)
    new = "You chase overdue purchase orders and always say which supplier to chase first."
    listed = app.get(API + "/customer", params={"specialist": PACK}).json()
    job = _wait(app, app.post(API + "/customer/compare", json={
        "specialist": PACK, "operation_id": "b" * 32, "case_ids": list(revisions),
        "case_revisions": revisions, "proposed_instructions": new,
        "baseline_revision": listed["baseline_revision"], "expected_context": listed["context"]}))
    assert job["state"] == "done", job
    verdict = app.post("/api/v1/agents/" + PACK + "/publish-check", json=_edit(app, new)).json()
    assert verdict["required"] and verdict["passing"] and not verdict["blocked"]
    assert verdict["latest"]["passed"] == 2 and verdict["latest"]["covers_all_tests"]
    # Publication accepts a finished passing check of the exact complete draft.
    draft = _save_draft(app, PACK, {"persona": new})
    checked = _decide(app, PACK, "check", selected=draft)
    assert checked.status_code == 200, checked.text
    # The background worker confirms the original admission when it starts.
    operation = checked.json()["operation"]
    _join_background_jobs()
    original = app.get(DRAFTS + "/originals/" + operation).json()
    assert original["confirmed"] and (original.get("run") or {}).get("state") in {"done", "failed", "stopped", "unknown"}, original
    run = original["run"]
    assert run["state"] == "done" and all(row["passed"] for row in run["results"]), run
    saved = _decide(app, PACK, "publish", selected=draft)
    assert saved.status_code == 200 and saved.json()["confirmed"], saved.text
    assert _current(app)["persona"] == new
    assert not [row for row in audit_rows if row.get("verb") in {
        "agent_published_without_passing_tests", "agent_draft_published_without_complete_check"}]

    # A different wording is a different set of instructions: it needs its own run.
    other = app.post("/api/v1/agents/" + PACK + "/publish-check", json=_edit(app, new + " Be brief."))
    assert other.json()["blocked"]


def test_a_failing_or_partial_run_does_not_count(client, monkeypatch):
    app, _tmp = client
    revisions = _save_tests(app, 3)
    _answers(monkeypatch, text="I would wait and see.")
    new = "You chase overdue purchase orders politely."
    listed = app.get(API + "/customer", params={"specialist": PACK}).json()
    _wait(app, app.post(API + "/customer/compare", json={
        "specialist": PACK, "operation_id": "c" * 32, "case_ids": list(revisions),
        "case_revisions": revisions, "proposed_instructions": new,
        "baseline_revision": listed["baseline_revision"], "expected_context": listed["context"]}))
    verdict = app.post("/api/v1/agents/" + PACK + "/publish-check", json=_edit(app, new)).json()
    assert verdict["blocked"] and verdict["latest"]["passed"] == 0
    assert "0 of 3" in verdict["message"]

    _answers(monkeypatch)
    first_two = dict(list(revisions.items())[:2])
    _wait(app, app.post(API + "/customer/compare", json={
        "specialist": PACK, "operation_id": "d" * 32, "case_ids": list(first_two),
        "case_revisions": first_two, "proposed_instructions": new,
        "baseline_revision": listed["baseline_revision"], "expected_context": listed["context"]}))
    partial = app.post("/api/v1/agents/" + PACK + "/publish-check", json=_edit(app, new)).json()
    assert partial["blocked"] and not partial["latest"]["covers_all_tests"]


def test_unchanged_instructions_new_agents_and_the_switched_off_gate_are_not_blocked(client, monkeypatch):
    app, tmp = client
    from maverick import config

    view = _current(app)
    # Unchanged instructions pass the instruction check...
    same = app.post("/api/v1/agents/" + PACK + "/publish-check", json={
        "expected_generation": view["generation"], "persona": view["persona"], "description": "Chases late POs"})
    assert same.status_code == 200 and not same.json()["blocked"], same.text
    # ...but publishing any change to a live specialist's complete definition
    # needs current acceptance or a separately recorded reason.
    entered = {"persona": view["persona"], "description": "Chases late POs"}
    assert _publish(app, PACK, entered).status_code == 409
    described = _publish(app, PACK, entered, reason="Description wording approved by procurement")
    assert described.status_code == 200 and described.json()["confirmed"], described.text
    # A brand-new agent has no earlier answers to protect.
    created = _publish(app, "acme_po_helper", {
        "description": "PO helper", "persona": "You help with purchase orders.",
        "allow_tools": ["read_file"], "max_risk": "low"})
    assert created.status_code == 200 and created.json()["confirmed"], created.text

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_factory]\nrequire_passing_tests = false\n", encoding="utf-8")
    config.reset_config_cache()
    off = _publish(app, PACK, {"persona": "You chase every late purchase order."})
    assert off.status_code == 200 and off.json()["confirmed"], off.text
    assert _current(app)["persona"] == "You chase every late purchase order."


def test_the_knob_defaults_on_and_stays_on_when_settings_are_unreadable(monkeypatch, tmp_path):
    from maverick import agent_publish_policy, config

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    try:
        assert agent_publish_policy.require_passing_tests() is True
        (tmp_path / "config.toml").write_text("[agent_factory]\nrequire_passing_tests = \"no\"\n", encoding="utf-8")
        config.reset_config_cache()
        assert agent_publish_policy.require_passing_tests() is True
        (tmp_path / "config.toml").write_text("[agent_factory]\nrequire_passing_tests = false\n", encoding="utf-8")
        config.reset_config_cache()
        assert agent_publish_policy.require_passing_tests() is False
    finally:
        config.reset_config_cache()


NEW = "acme_po_helper"
NEW_ENTERED = {"description": "PO helper", "persona": "You help with purchase orders.",
               "allow_tools": ["read_file"], "max_risk": "low"}


def _check_draft(app, name, draft):
    """Check a retained complete draft against its saved checks; wait for its confirmed outcome."""
    checked = _decide(app, name, "check", selected=draft)
    assert checked.status_code == 200, checked.text
    operation = checked.json()["operation"]
    _join_background_jobs()
    original = app.get(DRAFTS + "/originals/" + operation).json()
    assert original["confirmed"] and (original.get("run") or {}).get("state") in {"done", "failed", "stopped", "unknown"}, original
    return original


def test_a_new_specialist_needs_a_full_passing_run_on_its_exact_draft_when_switched_on(client, monkeypatch, audit_rows):
    app, tmp = client
    from maverick import config

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    draft = _save_draft(app, NEW, NEW_ENTERED)
    # A brand-new specialist can have saved checks before it is published.
    listed = app.get("/api/v1/workforce-ops/test-suite/specialists").json()["specialists"]
    assert any(row["value"] == NEW and "not published" in row["label"] for row in listed)

    # Without a saved check, a reason does not publish it.
    no_check = _decide(app, NEW, "publish", selected=draft, reason="Urgent PO helper needed by finance")
    assert no_check.status_code == 409 and "at least one saved check" in no_check.json()["detail"]
    assert "A reason cannot skip this" in no_check.json()["detail"]
    added = app.post(API + "/customer", json={"specialist": NEW, "task": "A PO has no matching receipt; what now?",
                                              "includes": ["receipt"], "excludes": [], "refusal": False, "citation": False})
    assert added.status_code == 200, added.text
    _answers(monkeypatch, text="Hold payment until a receipt matches.")
    # A saved check that nobody has run on this draft does not count either.
    not_run = _decide(app, NEW, "publish", selected=draft, reason="Urgent PO helper needed by finance")
    assert not_run.status_code == 409 and "full run" in not_run.json()["detail"]
    assert "A reason cannot skip this" in not_run.json()["detail"]
    assert app.get("/api/v1/agents/" + NEW).json().get("persona") != NEW_ENTERED["persona"]

    original = _check_draft(app, NEW, draft)
    assert original["run"]["state"] == "done" and all(row["passed"] for row in original["run"]["results"])
    published = _decide(app, NEW, "publish", selected=draft)
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    assert app.get("/api/v1/agents/" + NEW).json()["persona"] == NEW_ENTERED["persona"]
    assert not [row for row in audit_rows if row.get("verb") in {
        "agent_published_without_passing_tests", "agent_draft_published_without_complete_check"}]


def test_the_new_specialist_switch_leaves_the_default_and_existing_specialists_alone(client):
    app, tmp = client
    from maverick import config

    # Switched off (the default): a brand-new specialist publishes straight away, as before.
    created = _publish(app, NEW, NEW_ENTERED)
    assert created.status_code == 200 and created.json()["confirmed"], created.text
    # Switched on: an existing specialist's changes still take the reasoned route, not the new-specialist refusal.
    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    view = _current(app)
    described = _publish(app, PACK, {"persona": view["persona"], "description": "Chases late POs"},
                         reason="Description wording approved by procurement")
    assert described.status_code == 200 and described.json()["confirmed"], described.text
    assert "saved check" not in str(described.json())


BYPASS = "agent_publish.bypass_passing_tests"


def _approve(app, approval_id, who, monkeypatch):
    """A decision on the Approvals page: the card's binding and the typed acknowledgement, as the page sends them."""
    from maverick.approval_cards import decode_approval_detail
    from maverick_dashboard import api, auth
    from maverick_dashboard._shared import _world

    binding = decode_approval_detail(_world().get_approval(approval_id).detail)["binding_sha256"]
    with monkeypatch.context() as patch:  # the signed-in person is restored afterwards
        patch.setattr(auth, "caller_principal", lambda request: who)
        patch.setattr(api, "_supervisor", lambda request: who)
        return app.post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True, "confirmation": "approve"},
                        headers={"Origin": "http://127.0.0.1", "X-Lightwork-Approval-Binding": binding})


def test_a_reasoned_bypass_needs_another_administrator_when_switched_on(client, monkeypatch, audit_rows):
    app, tmp = client
    from maverick import config
    from maverick_dashboard import auth, rbac, specialist_drafts
    from maverick_dashboard._shared import _world

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nbypass_requires_second_person = true\n", encoding="utf-8")
    config.reset_config_cache()
    # Pack editing requires globally pinned admins, not just tenant RBAC roles.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:requester,user:reviewer")
    actor = {"who": "user:requester"}
    monkeypatch.setattr(auth, "caller_principal", lambda request: actor["who"])
    rbac.set_role("user:requester", "admin")
    rbac.set_role("user:reviewer", "admin")
    rbac.set_role("user:observer", "operator")
    _save_tests(app, 2)
    first = "You chase overdue purchase orders and always say which supplier to chase first."
    reason = "Urgent supplier change approved by finance"

    def approvals():
        return [row for row in _world().list_approvals(limit=50) if row.action == BYPASS]

    sent = _publish(app, PACK, {"persona": first}, reason=reason)
    assert sent.status_code == 409 and "Approvals page" in sent.json()["detail"], sent.text
    assert _current(app)["persona"] != first and len(approvals()) == 1
    waiting = _publish(app, PACK, {"persona": first}, reason=reason)
    assert waiting.status_code == 409 and "waiting for another administrator" in waiting.json()["detail"]
    assert len(approvals()) == 1  # the same request is reused, not duplicated
    aid = approvals()[0].id
    assert approvals()[0].requested_by == "user:requester" and approvals()[0].status == "pending"

    # The person who asked cannot approve it, and a person without administrator access cannot either.
    own = _approve(app, aid, "user:requester", monkeypatch)
    assert own.status_code == 403 and "another administrator" in own.json()["detail"]
    assert _approve(app, aid, "user:observer", monkeypatch).status_code == 403
    assert _world().get_approval(aid).status == "pending"

    approved = _approve(app, aid, "user:reviewer", monkeypatch)
    assert approved.status_code == 204, approved.text
    assert _world().get_approval(aid).status == "approved"
    actor["who"] = "user:requester"
    published = _publish(app, PACK, {"persona": first}, reason=reason)
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    assert _current(app)["persona"] == first
    logged = [row for row in audit_rows if row.get("verb") == "agent_published_without_passing_tests"]
    assert logged and logged[-1]["reason"] == reason and logged[-1]["approval"] == aid
    assert logged[-1]["requested_by"] == "user:requester" and logged[-1]["approved_by"] == "user:reviewer"
    requested = [row for row in audit_rows if row.get("verb") == "agent_publish_bypass_requested"]
    assert requested and requested[0]["actor"] == "user:requester" and requested[0]["reason"] == reason
    assert specialist_drafts.bypass_used(PACK, aid) is True


def test_an_approved_bypass_covers_one_publication_only(client, monkeypatch):
    app, tmp = client
    from maverick import config
    from maverick_dashboard import auth, rbac
    from maverick_dashboard._shared import _world

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nbypass_requires_second_person = true\n", encoding="utf-8")
    config.reset_config_cache()
    # Pack editing requires globally pinned admins, not just tenant RBAC roles.
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:requester,user:reviewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:requester")
    rbac.set_role("user:requester", "admin")
    rbac.set_role("user:reviewer", "admin")
    _save_tests(app, 2)
    first = "You chase overdue purchase orders and always say which supplier to chase first."
    second = "You chase overdue purchase orders and always name the buyer."
    reason = "Urgent supplier change approved by finance"
    _publish(app, PACK, {"persona": first}, reason=reason)
    aid = [row.id for row in _world().list_approvals(limit=50) if row.action == BYPASS][0]
    assert _approve(app, aid, "user:reviewer", monkeypatch).status_code == 204
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:requester")
    assert _publish(app, PACK, {"persona": first}, reason=reason).status_code == 200

    # A different change needs its own approval...
    other = _publish(app, PACK, {"persona": second}, reason="Buyer names requested by procurement")
    assert other.status_code == 409 and "Approvals page" in other.json()["detail"]
    other_id = max(row.id for row in _world().list_approvals(limit=50) if row.action == BYPASS)
    assert _approve(app, other_id, "user:reviewer", monkeypatch).status_code == 204
    assert _publish(app, PACK, {"persona": second}, reason="Buyer names requested by procurement").status_code == 200

    # ...and the first approval cannot be spent again to return to the first wording.
    again = _publish(app, PACK, {"persona": first}, reason=reason)
    assert again.status_code == 409 and "Approvals page" in again.json()["detail"], again.text
    assert _current(app)["persona"] == second


def test_an_administrator_can_read_a_bypass_card_to_decide_it(monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import auth, content_access

    card = SimpleNamespace(id=1, action=BYPASS, provenance="agent_publish.bypass.four_eyes.v1", status="pending",
                           requested_by="user:requester", scope=PACK, detail=None, goal_id=None)
    monkeypatch.setattr(auth, "api_key_permissions", lambda request: None)
    monkeypatch.setattr(auth, "has_permission", lambda request, permission, api_scope=None: permission == "admin")
    assert content_access.can_read_approval(object(), card, world=object()) is True


def test_an_administrator_who_may_not_edit_agents_cannot_read_a_bypass_card(monkeypatch):
    """Department-scoped administrators are not pack editors, so they cannot read the card either."""
    from types import SimpleNamespace

    from maverick_dashboard import auth, content_access

    card = SimpleNamespace(id=1, action=BYPASS, provenance="agent_publish.bypass.four_eyes.v1", status="pending",
                           requested_by="user:requester", scope=PACK, detail=None, goal_id=None)
    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(principal="user:dept-admin")))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:pack-editor")
    monkeypatch.setattr(auth, "api_key_permissions", lambda request: None)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:dept-admin")
    monkeypatch.setattr(auth, "has_permission", lambda request, permission, api_scope=None: permission == "admin")
    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: False)
    assert content_access.can_read_approval(request, card, world=object()) is False
    # The pack editor on the same roster still reads it.
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:pack-editor")
    request.state.principal.principal = "user:pack-editor"
    assert content_access.can_read_approval(request, card, world=object()) is True


def test_a_later_failing_run_on_the_same_draft_blocks_a_new_specialist_until_a_newer_run_passes(client, monkeypatch):
    app, tmp = client
    from maverick import config

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    draft = _save_draft(app, NEW, NEW_ENTERED)
    added = app.post(API + "/customer", json={"specialist": NEW, "task": "A PO has no matching receipt; what now?",
                                              "includes": ["receipt"], "excludes": [], "refusal": False, "citation": False})
    assert added.status_code == 200, added.text
    _answers(monkeypatch, text="Hold payment until a receipt matches.")
    assert _check_draft(app, NEW, draft)["run"]["state"] == "done"
    # A later run of the same draft fails: the newest full run decides, not an older pass.
    _answers(monkeypatch, text="Pay the supplier now.")
    failed = _check_draft(app, NEW, draft)
    assert failed["run"]["state"] == "done" and not any(row["passed"] for row in failed["run"]["results"])
    blocked = _decide(app, NEW, "publish", selected=draft)
    assert blocked.status_code == 409 and "full run" in blocked.json()["detail"], blocked.text
    assert app.get("/api/v1/agents/" + NEW).json().get("persona") != NEW_ENTERED["persona"]
    # A newer passing run on the same draft lets it through.
    _answers(monkeypatch, text="Hold payment until a receipt matches.")
    assert _check_draft(app, NEW, draft)["run"]["state"] == "done"
    published = _decide(app, NEW, "publish", selected=draft)
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    assert app.get("/api/v1/agents/" + NEW).json()["persona"] == NEW_ENTERED["persona"]


def _answers_using_input(monkeypatch, text, input_tokens):
    """Each answer records the input it used, so a run's spending limit is really tested."""
    from maverick import llm

    def answer(self, system, messages, **kwargs):
        kwargs["dispatch_guard"]()
        kwargs["budget"].record_tokens(input_tokens, 10)
        return llm.LLMResponse(text=text, thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)


def test_a_complete_draft_check_of_many_questions_gets_a_limit_that_grows_with_them(client, monkeypatch):
    app, tmp = client
    from maverick import config

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nrequire_for_new_specialists = true\nmax_cases_per_specialist = 30\n",
                                    encoding="utf-8")
    config.reset_config_cache()
    draft = _save_draft(app, NEW, NEW_ENTERED)
    for index in range(25):
        added = app.post(API + "/customer", json={"specialist": NEW, "task": f"Purchase order {index} has no matching receipt; what now?",
                                                  "includes": ["receipt"], "excludes": [], "refusal": False, "citation": False})
        assert added.status_code == 200, added.text
    # 500 input tokens per question is 12,500 in all: more than the old fixed 10,000 allowance, within 25 questions' allowance.
    _answers_using_input(monkeypatch, "Hold payment until a receipt matches.", 500)
    context = app.get(DRAFTS + "/history").json()["context"]
    review = app.post(DRAFTS + "/review", json={"name": NEW, "action": "check", "context": context, "selected": draft})
    assert review.status_code == 200, review.text
    limits = " ".join(str(row["after"]) for row in review.json()["changes"] if row["label"] == "Limits and consequences")
    assert "$1.25" in limits and "50,000 input tokens" in limits, limits
    original = _check_draft(app, NEW, draft)
    assert original["run"]["state"] == "done", original["run"]
    assert len(original["run"]["results"]) == 25 and all(row["passed"] for row in original["run"]["results"])
    published = _decide(app, NEW, "publish", selected=draft)
    assert published.status_code == 200 and published.json()["confirmed"], published.text


def test_business_setup_cannot_add_a_new_specialist_while_the_switch_is_on(client, audit_rows):
    app, tmp = client
    from maverick import config
    from maverick.agent_tests_policy import NEW_SPECIALIST_NEEDS_TESTS
    from maverick.domain import DomainProfile, available_domains
    from maverick_dashboard import business_agent_ops_api

    profile = DomainProfile(name="acme_setup_helper", persona="You help with setup.", allow_tools=["read_file"], max_risk="low")
    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    held = business_agent_ops_api._approve(profile, None, [], "user:admin", "user:admin")
    assert held == {"saved": False, "message": NEW_SPECIALIST_NEEDS_TESTS}
    assert "acme_setup_helper" not in available_domains()
    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    saved = business_agent_ops_api._approve(profile, None, [], "user:admin", "user:admin")
    assert saved["saved"] is True and "acme_setup_helper" in available_domains()


def test_a_chat_decision_on_a_bypass_follows_the_page_rules(client, monkeypatch, audit_rows):
    """Slack and Teams decide a reasoned bypass like the Approvals page: a pack editor, never the requester."""
    app, tmp = client
    from maverick import config
    from maverick.approval_cards import decode_approval_detail
    from maverick_dashboard import approval_decisions, auth, rbac
    from maverick_dashboard._shared import _world

    (tmp / "config.toml").write_text("[models]\ncapability_tests = true\n"
                                    "[agent_tests]\nbypass_requires_second_person = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:requester,user:reviewer")
    config.reset_config_cache()
    actor = {"who": "user:requester"}
    monkeypatch.setattr(auth, "caller_principal", lambda request: actor["who"])
    rbac.set_role("user:requester", "admin")
    rbac.set_role("user:reviewer", "admin")
    rbac.set_role("user:observer", "operator")
    _save_tests(app, 2)
    first = "You chase overdue purchase orders and always say which supplier to chase first."
    reason = "Urgent supplier change approved by finance"
    assert _publish(app, PACK, {"persona": first}, reason=reason).status_code == 409
    aid = [row.id for row in _world().list_approvals(limit=50) if row.action == BYPASS][0]
    binding = decode_approval_detail(_world().get_approval(aid).detail)["binding_sha256"]

    def chat(principal):
        return approval_decisions.decide_from_channel(
            approval_id=aid, status="approved", principal=principal, binding=binding, channel="slack",
            confirmed=True, acknowledgement={"acknowledged": True, "confirmation": "approve"}, world=_world())

    # A linked person who can operate but cannot edit agents is refused, with the reason in plain words.
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as observer:
        chat("user:observer")
    assert observer.value.status_code == 403 and "administrator who can edit agents" in observer.value.message
    # The person who asked is refused even though they are an administrator.
    with pytest.raises(approval_decisions.ApprovalDecisionRefused) as own:
        chat("user:requester")
    assert own.value.status_code == 403 and "You asked for this" in own.value.message
    assert _world().get_approval(aid).status == "pending"

    decided = chat("user:reviewer")
    assert decided["status"] == "approved" and decided["decided_by"] == "user:reviewer"
    actor["who"] = "user:requester"
    published = _publish(app, PACK, {"persona": first}, reason=reason)
    assert published.status_code == 200 and published.json()["confirmed"], published.text
    logged = [row for row in audit_rows if row.get("verb") == "agent_published_without_passing_tests"]
    assert logged[-1]["requested_by"] == "user:requester" and logged[-1]["approved_by"] == "user:reviewer"
    assert logged[-1]["approval"] == aid and logged[-1]["reason"] == reason
