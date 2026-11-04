"""Work operations from the command line, available in the app.

Covers ``journal list/revert``, ``export``, ``share`` (gist), ``schedule add``,
``template add``, ``onboard``, ``ekko run``, ``plan-reflect``, the debate job,
``tax update --url`` and the Cortex deposit collection choice. Each endpoint is
checked for permission refusal, the kernel call on success (stubbed only at
the model or network boundary), confirmation and bounded-input refusals and
its audit row; each touched page for its new controls and plain wording.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config, workspace_journal
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.paths import tenant_scope
from maverick.sandbox.local import LocalBackend
from maverick.tools.fs import write_text_contained
from maverick.world_model import WorldModel
from maverick_dashboard import rbac

TENANT = "work-ops-workspace"
TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
BANNED = re.compile(r"\b(tenant|principal|payload|endpoint|schema|UUID|SHA-256|idempotency|cron|JSON|maverick )\b")


def _wait(client, url, *, tries=200, headers=None):
    for _ in range(tries):
        data = client.get(url, headers=headers or {}).json()
        if data.get("state") != "running":
            return data
        time.sleep(0.02)
    raise AssertionError("job did not finish")


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "private"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[sandbox]\nworkdir = "{work.as_posix()}"\n')
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "1")
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:boss")
    config.reset_config_cache()
    workspace_journal._reset_for_tests()
    rbac.set_role("user:owner", "operator")
    rbac.set_role("user:other", "operator")
    rbac.set_role("user:viewer", "viewer")
    rbac.set_role("user:boss", "admin")
    import maverick.audit as audit
    from maverick_dashboard import api as api_module
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import cli_ops_api, viewpoints_api
    from maverick_dashboard.ops_jobs import JOBS
    JOBS.clear()
    dashboard._goal_times.clear()
    dashboard._goal_times_global.clear()
    world = WorldModel(tmp_path / "world.db")
    goal = world.create_goal("Tidy the quarterly notes", owner="user:owner")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    rows: list[dict] = []
    real = audit.audit_event

    def record(kind, **data):
        rows.append({"kind": kind, **data})
        return real(kind, **data)

    monkeypatch.setattr(audit, "audit_event", record)
    application = FastAPI()

    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", TENANT)):
            return await call_next(request)

    from maverick_dashboard import task_changes_api, task_file_recovery_api
    application.include_router(task_file_recovery_api.router)
    application.include_router(task_changes_api.router)
    application.include_router(api_module.router)
    application.include_router(viewpoints_api.router)
    application.include_router(cli_ops_api.router)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield SimpleNamespace(client=client, goal=goal, work=work, world=world, audit=rows, tmp=tmp_path, cfg=cfg)
    JOBS.clear()
    config.reset_config_cache()
    workspace_journal._reset_for_tests()


def _as(user):
    return {"X-Test-User": user}


# ---- journal list / undo ------------------------------------------------------

def _task_writes(env, writes):
    sandbox = LocalBackend(env.work)
    with tenant_scope(tenant=TENANT):
        tokens = set_goal_context(goal_id=env.goal)
        try:
            for name, text in writes:
                write_text_contained(sandbox, sandbox.workdir.resolve() / name, text)
        finally:
            reset_goal_context(tokens)


def _context(env):
    return env.client.get(f"/api/v1/task-files/{env.goal}/journal").json()["context"]


def test_journal_list_and_undo_restore_through_the_kernel(env):
    (env.work / "notes.txt").write_text("before\n")
    _task_writes(env, [("notes.txt", "after\n"), ("new.txt", "made by the task\n")])
    listing = env.client.get(f"/api/v1/task-files/{env.goal}/journal")
    assert listing.status_code == 200, listing.text
    data = listing.json()
    assert data["count"] == 2 and data["incomplete"] is False
    assert {(r["file"], r["change"]) for r in data["entries"]} == {("notes.txt", "existed"), ("new.txt", "created")}
    url = f"/api/v1/task-files/{env.goal}/journal/undo"
    preview = env.client.post(url, json={"context": data["context"], "preview": True}).json()
    assert preview["done"] is False and preview["restored"] == 1 and preview["removed"] == 1
    assert (env.work / "notes.txt").read_text() == "after\n", "a preview changes nothing"
    refused = env.client.post(url, json={"context": data["context"], "preview": False})
    assert refused.status_code == 409 and (env.work / "notes.txt").read_text() == "after\n"
    done = env.client.post(url, json={"context": data["context"], "preview": False, "confirm": True}).json()
    assert done["done"] is True and done["restored"] == 1 and done["removed"] == 1
    assert (env.work / "notes.txt").read_text() == "before\n" and not (env.work / "new.txt").exists()
    assert any(r["kind"] == "workspace_revert" for r in env.audit), "the kernel's signed audit row is written"


def test_journal_undo_refuses_other_people_viewers_and_forged_records(env):
    _task_writes(env, [("notes.txt", "after\n")])
    context = _context(env)
    url = f"/api/v1/task-files/{env.goal}/journal/undo"
    assert env.client.get(f"/api/v1/task-files/{env.goal}/journal", headers=_as("other")).status_code == 404
    assert env.client.post(url, json={"context": context, "preview": False, "confirm": True},
                           headers=_as("viewer")).status_code == 403
    outside = env.tmp / "outside"
    outside.mkdir()
    with tenant_scope(tenant=TENANT):
        folder = workspace_journal.goal_dir(env.goal)
    (folder / "000099.json").write_text(json.dumps({"seq": 99, "path": "evil.txt", "workdir": str(outside),
                                                    "existed": False, "blob": False}))
    refused = env.client.post(url, json={"context": context, "preview": False, "confirm": True}).json()
    assert refused["available"] is False and "outside" in refused["message"]
    assert (env.work / "notes.txt").read_text() == "after\n"


def test_journal_undo_rejects_a_stale_context_and_extra_fields(env):
    _task_writes(env, [("notes.txt", "after\n")])
    url = f"/api/v1/task-files/{env.goal}/journal/undo"
    assert env.client.post(url, json={"context": "0" * 64, "preview": True}).status_code == 409
    assert env.client.post(url, json={"context": _context(env), "preview": True, "extra": 1}).status_code == 422


# ---- export and gist share ----------------------------------------------------

def test_export_downloads_the_same_bundle_the_command_writes(env):
    from maverick.goal_bundle import build_goal_bundle

    response = env.client.get(f"/api/v1/goals/{env.goal}/export.json")
    assert response.status_code == 200
    assert 'filename="task-' in response.headers["content-disposition"]
    downloaded = response.json()
    command = json.loads(json.dumps(build_goal_bundle(env.world, env.goal), default=str))
    # Separate exports have distinct preparation times, but the same immutable contents.
    assert downloaded["manifest"].pop("snapshot_prepared_at") > 0
    assert command["manifest"].pop("snapshot_prepared_at") > 0
    assert downloaded == command
    import hashlib
    assert downloaded["manifest"]["sha256"] == hashlib.sha256(
        response.content.split(b',"manifest":', 1)[0] + b"}").hexdigest()
    assert env.client.get(f"/api/v1/goals/{env.goal}/export.json", headers=_as("other")).status_code == 404


def test_export_holds_back_draft_events_of_a_gated_task_until_a_reviewer_approves(env):
    # The bundle carries every event's content, so a gated pack's draft is
    # released only after sign-off even while the task has no saved result.
    world = env.world
    drafts = world.create_goal("Refresh the cash forecast", owner="user:owner", domain="finance_cash13w")
    world.append_event(drafts, "agent", "draft", "DRAFT cash forecast: week 1 closes at 1,200,000")
    url = f"/api/v1/goals/{drafts}/export.json"
    for status in ("running", "blocked"):
        world.set_goal_status(drafts, status)
        refused = env.client.get(url)
        assert refused.status_code == 403, status
        assert "reviewer must approve" in refused.json()["detail"]
    # The finished-without-sign-off case keeps its existing refusal.
    world.set_goal_status(drafts, "done", result="| a |\n| - |\n| 1 |")
    assert env.client.get(url).status_code == 403
    # A gated task that has recorded nothing yet has nothing to release.
    empty = world.create_goal("Another forecast", owner="user:owner", domain="finance_cash13w")
    assert env.client.get(f"/api/v1/goals/{empty}/export.json").status_code == 200
    # An ungated task is unaffected by its events.
    world.append_event(env.goal, "agent", "note", "plain progress")
    assert env.client.get(f"/api/v1/goals/{env.goal}/export.json").status_code == 200
    # Approval releases the bundle, events included.
    assert world.record_signoff(drafts, "approved", decided_by="user:boss",
                                expected_updated_at=world.get_goal(drafts).updated_at)
    released = env.client.get(url)
    assert released.status_code == 200
    assert any("DRAFT cash forecast" in event["content"] for event in released.json()["events"])


def test_gist_share_needs_confirmation_operate_and_audits_first(env, monkeypatch):
    import httpx
    from maverick.run_share import MissingGitHubToken
    from maverick_dashboard import goal_share_previews as sharing

    calls = []
    monkeypatch.setattr(sharing, "resolve_token", lambda: "test-gist-token")

    def account(url, **kwargs):
        assert url == "https://api.github.com/user"
        return httpx.Response(200, json={"login": "test-account"}, request=httpx.Request("GET", url))

    def upload(payload, token):
        assert token == "test-gist-token"
        assert payload["public"] is False
        assert any(row["kind"] == "goal_shared_gist" and row["phase"] == "dispatch"
                   for row in env.audit)
        calls.append(payload)
        return "https://gist.github.com/x/1"

    monkeypatch.setattr(httpx, "get", account)
    monkeypatch.setattr(sharing, "upload_payload", upload)
    url = f"/api/v1/goals/{env.goal}/share/gist"
    review = env.client.post(url + "/preview")
    assert review.status_code == 200, review.text
    preview = review.json()
    body = {"preview_id": preview["preview_id"], "sha256": preview["sha256"], "confirm": True}
    assert env.client.post(url, json={**body, "confirm": False}).status_code == 409
    assert env.client.post(url, json=body, headers=_as("viewer")).status_code == 403
    assert env.client.post(url, json=body, headers=_as("other")).status_code == 404
    assert calls == []
    data = env.client.post(url, json=body).json()
    assert data == {"shared": True, "url": "https://gist.github.com/x/1", "attempt": preview["preview_id"]}
    assert calls == [preview["payload"]]
    # Lost-response recovery returns the durable receipt and does not upload again.
    assert env.client.post(url, json=body).json() == data
    assert len(calls) == 1
    assert [row["phase"] for row in env.audit if row["kind"] == "goal_shared_gist"] == ["dispatch"]

    def disconnected():
        raise MissingGitHubToken("no GitHub token")

    monkeypatch.setattr(sharing, "resolve_token", disconnected)
    missing = env.client.post(url + "/preview")
    assert missing.status_code == 409 and "not connected" in missing.json()["detail"]


# ---- schedule add ------------------------------------------------------------

def _timetable(**extra):
    return {"repeat": "weekdays", "at": "08:30", "zone": "America/New_York", **extra}


def test_schedule_preview_builds_the_timetable_on_the_server(env):
    data = env.client.post("/api/v1/schedules/preview", json={"timetable": _timetable()}).json()
    assert data["cron"] == "30 8 * * 1-5" and data["zone"] == "America/New_York" and len(data["next_runs"]) == 3
    assert env.client.post("/api/v1/schedules/preview", json={"timetable": _timetable(zone="Mars/Base")}).status_code == 400
    bad = env.client.post("/api/v1/schedules/preview", json={"timetable": _timetable(advanced="61 * * * *")})
    assert bad.status_code == 400
    custom = env.client.post("/api/v1/schedules/preview", json={"timetable": _timetable(advanced="0  7 * * 0")}).json()
    assert custom["cron"] == "0 7 * * 0"
    assert env.client.post("/api/v1/schedules/preview", json={"timetable": _timetable()},
                           headers=_as("viewer")).status_code == 403


def test_schedule_add_task_and_rerun_carry_zone_owner_and_audit(env):
    from maverick.job_queue import JobQueue

    made = env.client.post("/api/v1/schedules/add", json={"what": "task", "text": "Summarise overnight email",
                                                          "timetable": _timetable()})
    assert made.status_code == 201, made.text
    assert made.json()["zone"] == "America/New_York" and made.json()["cron"] == "30 8 * * 1-5"
    rerun = env.client.post("/api/v1/schedules/add", json={"what": "rerun", "goal_id": env.goal,
                                                           "timetable": {"repeat": "monthly", "day_of_month": 3,
                                                                         "at": "07:00", "zone": "UTC"}})
    assert rerun.status_code == 201 and rerun.json()["kind"] == "run_goal"
    with tenant_scope(tenant=TENANT):
        jobs = {j.kind: j for j in JobQueue().list(status="pending")}
    assert jobs["start_goal"].payload["__tz__"] == "America/New_York" and jobs["start_goal"].payload["owner"] == "user:owner"
    assert jobs["run_goal"].payload["goal_id"] == env.goal and jobs["run_goal"].payload["__cron__"] == "0 7 3 * *"
    assert [r["what"] for r in env.audit if r["kind"] == "schedule_created"] == ["task", "rerun"]
    listed = env.client.get("/api/v1/schedules").json()["schedules"]
    assert {s["zone"] for s in listed} == {"America/New_York", "UTC"}


def test_schedule_add_refuses_foreign_tasks_viewers_and_unbounded_input(env):
    assert env.client.post("/api/v1/schedules/add", json={"what": "rerun", "goal_id": env.goal, "timetable": _timetable()},
                           headers=_as("other")).status_code == 404
    assert env.client.post("/api/v1/schedules/add", json={"what": "task", "text": "x", "timetable": _timetable()},
                           headers=_as("viewer")).status_code == 403
    assert env.client.post("/api/v1/schedules/add", json={"what": "task", "text": "x" * 16_001,
                                                          "timetable": _timetable()}).status_code == 422
    assert env.client.post("/api/v1/schedules/add", json={"what": "task", "text": "x",
                                                          "timetable": _timetable(days=list(range(8)))}).status_code == 422


# ---- community templates -----------------------------------------------------

def test_community_templates_list_and_admin_only_install(env, monkeypatch):
    import maverick.templates as templates

    entry = SimpleNamespace(name="weekly-digest", summary="A weekly summary", rating=4.5, ratings_count=2)
    monkeypatch.setattr(templates, "browse_templates", lambda: [entry, SimpleNamespace(name="../evil", summary="")])
    installed = []
    monkeypatch.setattr(templates, "install_template_from_catalog",
                        lambda name: installed.append(name) or SimpleNamespace(name=name, title="Weekly digest"))
    listing = env.client.get("/api/v1/templates/community").json()
    assert [t["name"] for t in listing["templates"]] == ["weekly-digest"] and listing["can_add"] is False
    url = "/api/v1/templates/community/add"
    assert env.client.post(url, json={"name": "weekly-digest", "confirm": True}).status_code == 403
    assert env.client.post(url, json={"name": "weekly-digest"}, headers=_as("boss")).status_code == 409
    assert env.client.post(url, json={"name": "../evil", "confirm": True}, headers=_as("boss")).status_code == 422
    assert installed == []
    added = env.client.post(url, json={"name": "weekly-digest", "confirm": True}, headers=_as("boss")).json()
    assert added["added"] is True and installed == ["weekly-digest"]
    assert any(r["kind"] == "template_added_from_library" for r in env.audit)
    monkeypatch.setattr(templates, "install_template_from_catalog",
                        lambda name: (_ for _ in ()).throw(ValueError("content hash mismatch")))
    assert "genuine" in env.client.post(url, json={"name": "weekly-digest", "confirm": True},
                                         headers=_as("boss")).json()["message"]


# ---- business specialist setup (onboard) ---------------------------------------

def test_business_setup_drafts_then_saves_only_after_confirmation(env, monkeypatch):
    base = "/api/v1/agents/business-setup"
    body = {"name": "Acme Bakery", "description": "We bake bread for cafes", "use_ai": False}
    assert env.client.post(base + "/draft", json=body, headers=_as("owner")).status_code == 403
    started = env.client.post(base + "/draft", json=body, headers=_as("boss"))
    assert started.status_code == 202, started.text
    job = started.json()["job"]
    draft = _wait(env.client, f"{base}/{job}?step=draft", headers=_as("boss"))
    # the client sees the plain draft; the pack itself stays on the server
    client_view = draft["result"]
    assert draft["state"] == "done" and client_view["ran"] is True and "_profile" not in client_view
    assert client_view["agent"]["name"] and not list((env.tmp / "domains").glob("*.toml"))
    assert env.client.post(f"{base}/{job}/approve", data={"confirm": "false"}, headers=_as("boss")).status_code == 409
    approve = env.client.post(f"{base}/{job}/approve", data={"confirm": "true"}, headers=_as("boss"))
    assert approve.status_code == 202, approve.text
    saved = _wait(env.client, f"{base}/{approve.json()['job']}?step=approve", headers=_as("boss"))["result"]
    assert saved["saved"] is True and list((env.tmp / "domains").glob("*.toml"))
    assert any(r["kind"] == "business_agent_approved" for r in env.audit)
    again = env.client.post(f"{base}/{job}/approve", data={"confirm": "true"}, headers=_as("boss"))
    assert again.status_code == 404, "a draft is approved at most once"


def test_business_setup_rejects_existing_specialist_names_before_drafting(env):
    from maverick.domain import available_domains

    base = "/api/v1/agents/business-setup/draft"
    before = available_domains()["hr_screening"]
    original = (before.persona, before.max_risk, before.allow_tools)
    response = env.client.post(base, json={"name": "HR Screening", "use_ai": False}, headers=_as("boss"))
    assert response.status_code == 409
    assert "HR Screening" in response.json()["detail"]
    assert "existing specialist and its safeguards have not changed" in response.json()["detail"]
    after = available_domains()["hr_screening"]
    assert (after.persona, after.max_risk, after.allow_tools) == original
    assert not list((env.tmp / "domains").glob("*.toml"))
    assert not any(row["kind"] == "business_agent_drafted" for row in env.audit)

    folder = env.tmp / "domains"
    folder.mkdir(exist_ok=True)
    existing = folder / "acme_bakery.toml"
    existing.write_text("existing draft", encoding="utf-8")
    response = env.client.post(base, json={"name": "Acme Bakery", "use_ai": False}, headers=_as("boss"))
    assert response.status_code == 409 and existing.read_text(encoding="utf-8") == "existing draft"


def _tool_gap_plan(env, monkeypatch):
    import maverick.provision as provision

    # Tool building is part of the governed self-learning loop; turn it on here.
    env.cfg.write_text(env.cfg.read_text() + "\n[self_learning]\nenable = true\ncreate_tools = true\n")
    config.reset_config_cache()

    plan = provision.ProvisioningPlan(profile_name="acme_books", gaps=[provision.CapabilityGap(
        kind="tool", need="invoice_lookup", resolution="generate_tool")])
    monkeypatch.setattr(provision, "analyze_profile", lambda profile, **_: plan)


def _approve_with_tools(env):
    base = "/api/v1/agents/business-setup"
    job = env.client.post(base + "/draft", json={"name": "Acme Books", "use_ai": False},
                          headers=_as("boss")).json()["job"]
    assert _wait(env.client, f"{base}/{job}?step=draft", headers=_as("boss"))["result"]["ran"] is True
    started = env.client.post(f"{base}/{job}/approve", data={"confirm": "true"}, headers=_as("boss"))
    assert started.status_code == 202, started.text
    return _wait(env.client, f"{base}/{started.json()['job']}?step=approve", headers=_as("boss"))["result"]


def test_business_setup_builds_tools_on_the_writer_model_under_a_budget(env, monkeypatch):
    import maverick.llm as llm

    _tool_gap_plan(env, monkeypatch)
    calls, roles = [], []

    class ToolLLM:
        def __init__(self, model=None):
            self.model = model

        def complete(self, *, system, messages, budget=None, **_):
            assert budget is not None, "tool generation always runs under a budget"
            budget.check()
            budget.record_tokens(300, 200)
            calls.append(budget)
            return SimpleNamespace(text="not a usable tool module")

    monkeypatch.setattr(llm, "LLM", ToolLLM)
    monkeypatch.setattr(llm, "model_for_role", lambda role: roles.append(role) or "anthropic:configured")
    saved = _approve_with_tools(env)
    assert saved["saved"] is True
    assert "writer" in roles and len(calls) == 1 and calls[0].dollars > 0
    assert calls[0].max_dollars <= 1.0
    assert [r["phase"] for r in env.audit if r["kind"] == "business_agent_tools"] == ["start", "end"]


def test_business_setup_adds_no_tools_when_the_budget_is_refused(env, monkeypatch):
    import maverick.llm as llm
    from maverick_dashboard import viewpoints_api

    _tool_gap_plan(env, monkeypatch)
    made = []
    monkeypatch.setattr(llm, "LLM", lambda model=None: made.append(model))

    def refuse(principal, max_dollars=1.0):
        raise viewpoints_api._Refused("Your spending limit for today has been reached.")

    monkeypatch.setattr(viewpoints_api, "_admit", refuse)
    saved = _approve_with_tools(env)
    assert saved["saved"] is True and made == []
    assert "spending limits" in saved["message"] and "spending limit for today" in saved["message"]
    assert not [r for r in env.audit if r["kind"] == "business_agent_tools"]


def test_business_setup_bounds_documents(env):
    base = "/api/v1/agents/business-setup"
    job = env.client.post(base + "/draft", json={"name": "Acme", "use_ai": False}, headers=_as("boss")).json()["job"]
    _wait(env.client, f"{base}/{job}?step=draft", headers=_as("boss"))
    files = [("documents", (f"d{i}.txt", b"x", "text/plain")) for i in range(11)]
    assert env.client.post(f"{base}/{job}/approve", data={"confirm": "true"}, files=files,
                           headers=_as("boss")).status_code == 413


# ---- Ekko recording ------------------------------------------------------------

def test_ekko_recording_needs_consent_enrollment_and_guided_capture(env, monkeypatch):
    body = {"events": json.dumps({"app": "excel", "action": "open"}) + "\n", "acknowledge_capture_scope": False}
    assert env.client.post("/api/v1/ekko/recording/import", json=body).status_code == 400
    body["acknowledge_capture_scope"] = True
    assert env.client.post("/api/v1/ekko/recording/import", json=body).status_code == 409  # Ekko is off
    assert env.client.post("/api/v1/ekko/recording/import", json=body, headers=_as("viewer")).status_code == 403
    too_big = {**body, "events": "x" * 1_000_001}
    assert env.client.post("/api/v1/ekko/recording/import", json=too_big).status_code == 422
    options = env.client.get("/api/v1/ekko/recording/options").json()
    assert options["activity_file"] is True and options["windows_active_app"] is False
    if not options["active_app"]:
        # This computer has no supported desktop recorder: nothing starts, and
        # the reply says why in the platform's own words.
        watch = env.client.post("/api/v1/ekko/recording/watch", json={"acknowledge_capture_scope": True})
        assert watch.status_code == 409
        assert watch.json()["detail"] == {"message": options["availability_message"], "not_started": True}
    # Even when a supported server desktop is present, a dashboard client
    # cannot establish that it owns that desktop.
    import maverick.ekko_foreground as foreground

    monkeypatch.setattr(foreground, "foreground_options", lambda: {
        "active_app": True, "observer": "linux_x11_foreground", "platform": "Linux",
        "availability_message": "Record recognized apps on the local Linux X11 desktop where Lightwork is installed."})
    monkeypatch.setattr(foreground, "foreground_observer", lambda: pytest.fail("no recorder may open before consent"))
    unacknowledged = env.client.post("/api/v1/ekko/recording/watch", json={"acknowledge_capture_scope": False})
    assert unacknowledged.status_code == 409 and unacknowledged.json()["detail"]["not_started"] is True
    off = env.client.post("/api/v1/ekko/recording/watch", json={"acknowledge_capture_scope": True})
    assert off.status_code == 409 and off.json()["detail"]["not_started"] is True  # Ekko is off


def test_ekko_recording_runs_the_daemon_over_the_uploaded_file(env, monkeypatch):
    import maverick.ekko_daemon as daemon_module
    from maverick_dashboard import ekko_routes

    policy = SimpleNamespace(capture_level="guided", fingerprint=lambda: "f" * 64)
    ran = {}

    class FakeDaemon:
        def __init__(self, *, store, observer, policy):
            ran["observer"] = observer
            self.accepted_events, self.blocked_events = 0, 0

        def run(self, *, stop_when, max_idle_sleep):
            assert max_idle_sleep == 1.0
            while ran["observer"].observe() is not None:
                self.accepted_events += 1
            assert stop_when()

        def stop(self):
            ran["stopped"] = True

    monkeypatch.setattr(ekko_routes, "_require_enabled_policy", lambda: {"enable": True})
    monkeypatch.setattr(ekko_routes, "_validated_enrolled_policy", lambda store: policy)
    monkeypatch.setattr(daemon_module, "EkkoDaemon", FakeDaemon)
    lines = "\n".join(json.dumps({"app": "excel", "action": "open"}) for _ in range(3)) + "\n"
    started = env.client.post("/api/v1/ekko/recording/import", json={"events": lines, "acknowledge_capture_scope": True})
    assert started.status_code == 202, started.text
    result = _wait(env.client, "/api/v1/ekko/recording/" + started.json()["job"])["result"]
    assert result == {"recorded": 3, "skipped": 0} and ran["stopped"] is True
    assert isinstance(ran["observer"], daemon_module.GuidedJsonlObserver)
    assert any(r.get("state") == "start_authorized" and r.get("observer") == "guided_jsonl" for r in env.audit)
    other = env.client.get("/api/v1/ekko/recording/" + started.json()["job"], headers=_as("other"))
    assert other.status_code == 404, "a recording's status is private to its owner"


# ---- planning steps (plan-reflect) and the debate job ------------------------------

class FakeLLM:
    def __init__(self, model=None):
        self.model = model

    def _provider_client_config(self, provider):
        # A reviewed viewpoints request binds the connection identity only.
        return SimpleNamespace(fingerprint="test-connection:" + provider)

    def complete(self, *, system, messages, budget=None, **_):
        budget.check()
        budget.record_tokens(100, 40)
        if "planner" in system:
            return SimpleNamespace(text='{"steps": ["Read the notes", "Write the summary"]}')
        if "reflector" in system:
            return SimpleNamespace(text='{"status": "done", "notes": "Looks complete"}')
        if "impartial judge" in system:
            return SimpleNamespace(text='{"winner": "Proponent", "reason": "Clearer", "key_argument": "Time"}')
        return SimpleNamespace(text="Did: " + messages[0]["content"][:30])


@pytest.fixture
def ai(env, monkeypatch):
    import maverick.llm as llm
    from maverick_dashboard import _shared, viewpoints_api

    roles = []
    monkeypatch.setattr(llm, "LLM", FakeLLM)
    monkeypatch.setattr(llm, "model_for_role", lambda role: roles.append(role) or "anthropic:configured")
    monkeypatch.setattr(_shared, "require_provider_or_400", lambda role=None: None)
    monkeypatch.setattr(viewpoints_api, "require_provider_or_400", lambda role=None: None)
    from maverick_dashboard import viewpoints_requests
    monkeypatch.setattr(viewpoints_requests, "LLM", FakeLLM)
    monkeypatch.setattr(viewpoints_requests, "model_for_role", llm.model_for_role)
    return roles


def test_planning_steps_trace_uses_the_orchestrator_role_and_changes_nothing(env, ai):
    url = f"/api/v1/goals/{env.goal}/planning-steps"
    assert env.client.post(url, json={"passes": 1}, headers=_as("viewer")).status_code == 403
    assert env.client.post(url, json={"passes": 1}, headers=_as("other")).status_code == 404
    assert env.client.post(url, json={"passes": 9}).status_code == 422
    started = env.client.post(url, json={"passes": 1})
    assert started.status_code == 202, started.text
    result = _wait(env.client, f"{url}/{started.json()['job']}")["result"]
    assert result["ran"] is True and result["plan"] == ["Read the notes", "Write the summary"]
    assert result["status"] == "done" and len(result["steps"]) == 2 and result["cost"] > 0
    assert ai == ["orchestrator"]
    assert [r["phase"] for r in env.audit if r["kind"] == "planning_steps_run"] == ["start", "end"]
    assert env.world.get_goal(env.goal).status != "running"


def test_viewpoints_job_runs_with_chosen_sides(env, ai):
    started = env.client.post("/api/v1/viewpoints/jobs", json={"question": "Should we open on Sundays?", "rounds": 1,
                                                               "for_side": "Sunday trade is worth it"})
    assert started.status_code == 202, started.text
    result = _wait(env.client, "/api/v1/viewpoints/jobs/" + started.json()["job"])["result"]
    assert result["ran"] is True and result["verdict"] == "for" and set(ai) == {"analyst"}
    assert env.client.get("/api/v1/viewpoints/jobs/" + started.json()["job"], headers=_as("other")).status_code == 404
    assert env.client.post("/api/v1/viewpoints/jobs", json={"question": "Why?", "for_side": "x" * 301}).status_code == 422


# ---- pages ------------------------------------------------------------------------

@pytest.mark.parametrize("template, needles", [
    ("task_file_recovery.html", ["tj-list", "tj-preview", "tj-undo", "lightwork-task-journal.js"]),
    ("trajectory.html", ["export.json", "goal-gist", "lightwork-goal-export.js"]),
    ("automations.html", ["auto-new-sched", "auto-new-zone", "Technical details", "lightwork-schedule-picker.js"]),
    ("templates_market.html", ["tplm-library-load", "lightwork-community-templates.js"]),
    ("agents.html", ["biz-draft", "biz-approve", "lightwork-business-agent.js"]),
    ("ekko.html", ["ekko-rec-import", "ekko-rec-watch", "lightwork-ekko-recording.js"]),
    ("chat_goal.html", ["ps-run", "Show planning steps", "lightwork-planning-steps.js"]),
    ("chat.html", ["vp-for", "vp-against"]),
    ("cortex.html", ["fa-cortex-collection"]),
    ("finance.html", ["tax-tables-url", "tax-tables-check-url"]),
    ("flow_teach.html", ["tr-learn", "rc-learn", "sg-learn", "lightwork-flow-teach.js"]),
])
def test_pages_offer_the_new_controls_in_plain_words(template, needles):
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    for needle in needles:
        assert needle in text
    for added in re.findall(r'<(?:section|details|div)[^>]*id="(?:task-journal|goal-export|auto-new-sched|tplm-library|'
                            r'biz-setup|ekko-recording|planning-steps)".*?</(?:section|details)>', text, re.DOTALL):
        visible = re.sub(r"<[^>]+>|\{\{.*?\}\}|\{%.*?%\}", " ", added)
        assert not BANNED.search(visible), BANNED.search(visible)


def test_scripts_are_served(env):
    from maverick_dashboard.cli_ops_api import ASSETS

    for name in ASSETS:
        response = env.client.get("/static/" + name)
        assert response.status_code == 200 and "javascript" in response.headers["content-type"]
