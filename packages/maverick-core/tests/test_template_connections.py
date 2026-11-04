"""Synthetic accounts, real role store and native durable task/schedule admission."""
from __future__ import annotations

import asyncio
import json

import pytest
from maverick import config, connections, templates
from maverick import template_connections as selections
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import rbac

OWNER = "user:picker@example.test"


@pytest.fixture
def account(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setattr(templates, "USER_TEMPLATES", tmp_path / "templates")
    config.reset_config_cache()
    with tenant_scope(tenant="picker-team"):
        rbac.set_tenant_role("picker-team", OWNER, "operator", actor=OWNER)
        row = connections.set_connection("chosen", connector="slack_api", base_url="https://slack.com",
                                         token="synthetic-token", owner=OWNER)
        with WorldModel(tmp_path / "world.db") as world:
            yield world, row, selections.choices(OWNER)[0]
    config.reset_config_cache()


def test_picker_only_exact_owned_supported_accounts_without_secrets(account):
    _, _, choice = account
    connections.set_connection("colleague", connector="slack_api", token="other-secret", owner="user:other",
                               access="tenant")
    connections.set_connection("unsupported", connector="aws_s3", owner=OWNER)
    assert selections.choices(OWNER) == [choice]
    assert "synthetic-token" not in json.dumps(choice)
    ref = selections.decode(choice["value"])
    assert ref["owner"] == OWNER and ref["tenant"] == "picker-team"
    with pytest.raises(selections.SelectionUnavailable):
        selections.validate("user:other", [ref])
    with tenant_scope(tenant="other-team"), pytest.raises(selections.SelectionUnavailable):
        selections.validate(OWNER, [ref])


def test_template_render_default_prohibition_and_optional_condition(account):
    _, _, choice = account
    schema = {"version": 1, "fields": {"account": {"type": "connection", "required": True},
        "mode": {"type": "enum", "choices": ["yes", "no"], "default": "yes"}}}
    tpl = templates.save_user_template("picker", title="Review", body="Read {{account}} {{mode}}", owner=OWNER,
                                       parameter_schema=schema)
    assert tpl.render_for(OWNER, account=choice["value"])[1] == "Read chosen (slack_api) yes"
    with pytest.raises(selections.SelectionUnavailable):
        tpl.render(account=choice["value"])
    schema["fields"]["account"]["default"] = choice["value"]
    with pytest.raises(ValueError, match="cannot save a default"):
        templates.save_user_template("bad", title="Bad", body="{{account}} {{mode}}", parameter_schema=schema)
    schema["fields"]["account"]["default"] = ""
    schema["fields"]["account"]["show_when"] = {"field": "mode", "value": "yes"}
    tpl.parameter_schema = schema
    assert tpl.render_for(OWNER, mode="no")[1] == "Read  no"


def test_goal_pin_survives_reload_and_rotation_refuses_rebind(account, monkeypatch):
    world, row, choice = account
    ref = selections.decode(choice["value"])
    goal = world.create_goal("Use selected account", owner=OWNER, connection_references=[ref])
    assert selections.for_goal(world, goal) == [ref]
    child = world.create_goal("Continuation", parent_id=goal, owner=OWNER)
    assert selections.for_goal(world, child) == [ref]
    connections.set_connection("aaa-default", connector="slack_api", token="wrong-account", owner=OWNER)
    with selections.bind_goal(world, child, OWNER), connections.bind_principal(OWNER):
        assert connections.resolve("slack_api") == ("https://slack.com", "synthetic-token")
        from maverick.tools._rest_connector import _credential_config
        monkeypatch.setenv("SLACK_TOKEN", "ambient-wrong-account")
        assert _credential_config("slack_api", "SLACK_URL", "SLACK_TOKEN")[1] == "synthetic-token"
        connections.set_connection("chosen", connector="slack_api", token="new-token", owner=OWNER,
                                   expected_revision=row["revision"])
        with pytest.raises(selections.SelectionUnavailable):
            selections.recheck_active()
        with pytest.raises(selections.SelectionUnavailable):
            connections.resolve("slack_api")
    assert json.loads(world.goal_connection_selection(goal))["references"] == [ref]


def test_permission_revocation_prevents_model_or_tool_coroutine_creation(account):
    from types import SimpleNamespace

    from maverick.agent import Agent
    world, _, choice = account
    goal = world.create_goal("Bound", owner=OWNER, connection_references=[selections.decode(choice["value"])])
    called = []
    with selections.bind_goal(world, goal, OWNER):
        rbac.set_tenant_role("picker-team", OWNER, "viewer", actor=OWNER)
        with pytest.raises(selections.SelectionUnavailable, match="permission"):
            asyncio.run(Agent._await_wall_clock_guarded(SimpleNamespace(), lambda: called.append(True), in_flight_note="mid-tool-execution"))
    assert called == []


def test_atomic_submission_and_event_admission_keep_refs(account):
    from maverick.attachment_submissions import SubmissionStore
    from maverick.event_admission import admit_batch
    world, _, choice = account
    refs = [selections.decode(choice["value"])]
    receipt = SubmissionStore(world).create(token="picker-submission", fingerprint="reviewed", owner=OWNER,
        title="Draft", description="Exact account", manifest=[], connection_references=refs)
    assert world.get_goal(receipt["goal_id"]).status == "draft"
    assert selections.for_goal(world, receipt["goal_id"]) == refs
    admitted = admit_batch(world, [("event-key", "Event", "Selected account", refs)], owner=OWNER,
                           origin="picker", trigger_key="picker-trigger")
    assert selections.for_goal(world, admitted[0][1]) == refs


def test_schedule_permission_change_refuses_before_goal_or_runner(account, monkeypatch, tmp_path):
    from maverick import runner
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker
    world, _, choice = account
    queue = JobQueue(tmp_path / "jobs.db")
    called = []
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **k: called.append(True))
    refs = [selections.decode(choice["value"])]
    payload = {"title": "Occurrence", "text": "Use reviewed account", "owner": OWNER, "connection_references": refs}
    # Dispatch the real built-in handler after a native role change; no provider is invoked.
    from types import SimpleNamespace
    rbac.set_tenant_role("picker-team", OWNER, "viewer", actor=OWNER)
    worker = Worker(queue)
    with pytest.raises(selections.SelectionUnavailable):
        worker._dispatch(SimpleNamespace(kind="start_goal", payload=payload, id=1, attempts=1))
    assert called == [] and "goal_id" not in payload
    # A certain refusal never records an uncertain creation boundary.
    assert "_goal_creation_started" not in payload


def test_selected_drive_uses_exact_saved_account_and_refuses_writes(account, monkeypatch):
    from maverick.tools import _ambient_credential_denial, gdrive_tool
    world, _, _ = account
    connections.set_connection("drive-evidence", connector="gdrive", owner=OWNER,
                               base_url="https://www.googleapis.com", token="selected-drive-token")
    choice = next(row for row in selections.choices(OWNER) if row["name"] == "drive-evidence")
    ref = selections.decode(choice["value"])
    goal = world.create_goal("Read Drive", owner=OWNER, connection_references=[ref])
    monkeypatch.setenv("GDRIVE_ACCESS_TOKEN", "wrong-ambient-token")
    monkeypatch.setattr(gdrive_tool, "_op_create", lambda args: pytest.fail("selected Drive must not write"))
    with selections.bind_goal(world, goal, OWNER), connections.bind_principal(OWNER):
        assert _ambient_credential_denial("gdrive", OWNER) is None
        assert _ambient_credential_denial("jira", OWNER).startswith("REFUSED")
        assert gdrive_tool._token() == "selected-drive-token"
        assert gdrive_tool._run({"op": "create", "confirm": True}).startswith("REFUSED")
    with selections.bind_goal(world, goal, OWNER), pytest.raises(selections.SelectionUnavailable):
        selections.selected("gdrive", "user:other")
