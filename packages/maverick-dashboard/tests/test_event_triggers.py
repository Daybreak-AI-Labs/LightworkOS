"""Polled event triggers: manage via /api/v1/event-triggers, drain via
/event-triggers/poll. Operate-gated + feature-knobbed + owner-scoped; the
built-in http_json source is driven with an injected fetch (no network)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    tdir = tmp_path / ".maverick" / "templates"
    tdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tdir)
    (tdir / "triage.md").write_text(
        "---\nowner: local\ntitle: Triage {{title}}\nparams:\n  - title\n---\nHandle {{title}}.\n",
        encoding="utf-8")


@pytest.fixture
def _no_real_run(monkeypatch):
    import maverick.runner as runner_mod
    monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **k: None)


def _feed(monkeypatch, box):
    import maverick.automation_events as ev
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: box[0])


# ---- store round-trip -------------------------------------------------------

def test_store_round_trip_and_cursor(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store as s
    rec = s.set_trigger("My Feed!", "triage", "http_json",
                        config={"url": "http://x"}, params={"title": "x"},
                        owner="user:alice")
    assert rec["name"] == "my-feed"
    got = s.get_trigger("my-feed")
    assert got["source"] == "http_json" and got["config"] == {"url": "http://x"}
    assert got["owner"] == "user:alice" and got["cursor"] == ""
    # cursor advances and re-save preserves it
    assert s.set_cursor("my-feed", "42") is True
    assert s.get_trigger("my-feed")["cursor"] == "42"
    s.set_trigger("My Feed!", "triage", "http_json", config={"url": "http://y"})
    assert s.get_trigger("my-feed")["cursor"] == "42"        # preserved on replace
    assert s.delete_trigger("my-feed", owner="user:bob") is False   # not bob's
    assert s.delete_trigger("my-feed", owner="user:alice") is True


def test_store_namespaces_same_public_name_by_tenant(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store as s

    s.set_trigger(
        "feed", "triage", "http_json", tenant="acme", owner="user:alice"
    )
    s.set_trigger(
        "feed", "triage", "http_json", tenant="globex", owner="user:alice"
    )

    assert s.get_trigger("feed") is None  # ambiguous outside a tenant context
    assert s.set_cursor("feed", "a-1", tenant="acme") is True
    assert s.get_trigger("feed", tenant="acme")["cursor"] == "a-1"
    assert s.get_trigger("feed", tenant="globex")["cursor"] == ""
    assert s.delete_trigger("feed", owner="user:alice", tenant="acme") is True
    assert s.get_trigger("feed", tenant="acme") is None
    assert s.get_trigger("feed", tenant="globex") is not None


def test_history_is_tenant_scoped_and_scrubs_notes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import trigger_events_store as tes

    token = set_tenant("acme")
    try:
        tes.record(
            "feed",
            "user:alice",
            tes.POLL_ERROR,
            note="Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456",  # pragma: allowlist secret
        )
    finally:
        reset_tenant(token)
    token = set_tenant("globex")
    try:
        tes.record("feed", "user:alice", tes.FIRED, fired=[2])
    finally:
        reset_tenant(token)

    acme = tes.history(owner="user:alice", tenant="acme")
    globex = tes.history(owner="user:alice", tenant="globex")
    assert [row["kind"] for row in acme] == [tes.POLL_ERROR]
    assert [row["kind"] for row in globex] == [tes.FIRED]
    assert "sk-proj-" not in acme[0]["note"]  # pragma: allowlist secret


# ---- management API ---------------------------------------------------------

def test_create_list_delete(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json",
        "config": {"url": "http://x/feed", "items_path": "items"}})
    assert r.status_code == 201, r.text
    assert r.json()["source"] == "http_json"
    listed = c.get("/api/v1/event-triggers").json()
    assert any(t["name"] == "triage" for t in listed["triggers"])
    assert "http_json" in listed["sources"] and listed["enabled"] is True
    assert c.delete("/api/v1/event-triggers/triage").status_code == 200
    assert c.delete("/api/v1/event-triggers/triage").status_code == 404


def test_create_rejects_unknown_source_and_missing_template(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "nope", "config": {}}).status_code == 400
    assert c.post("/api/v1/event-triggers", json={
        "template": "ghost", "source": "http_json", "config": {}}).status_code == 404


def test_feature_gate_off_403(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "0")
    c = _client()
    assert c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json", "config": {}}).status_code == 403
    assert c.post("/api/v1/event-triggers/poll").status_code == 403


# ---- poll runtime (end to end) ---------------------------------------------

def test_poll_baselines_then_fires_then_dedupes(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    box = [{"items": [{"id": "1", "title": "first"}]}]
    _feed(monkeypatch, box)
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json",
        "config": {"url": "http://x/feed", "items_path": "items", "id_field": "id"}})

    # first poll = baseline: cursor set to newest, nothing fires
    p0 = c.post("/api/v1/event-triggers/poll").json()
    assert p0["triggers"][0]["new_events"] == 0 and p0["triggers"][0]["fired"] == []

    # a new item appears -> it fires, the event field fills the {{title}} param
    box[0] = {"items": [{"id": "2", "title": "second"}, {"id": "1", "title": "first"}]}
    p1 = c.post("/api/v1/event-triggers/poll").json()
    assert p1["triggers"][0]["new_events"] == 1
    gid = p1["triggers"][0]["fired"][0]
    from maverick.world_model import DEFAULT_DB, WorldModel
    assert WorldModel(DEFAULT_DB).get_goal(gid).title == "Triage second"

    # polling again with no change fires nothing (cursor dedup)
    assert c.post("/api/v1/event-triggers/poll").json()["triggers"][0]["new_events"] == 0


def test_poll_uses_creation_time_template_snapshot(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    box = [{"items": [{"id": "1", "title": "first"}]}]
    _feed(monkeypatch, box)
    c = _client()
    response = c.post("/api/v1/event-triggers", json={
        "template": "triage",
        "source": "http_json",
        "config": {"url": "http://x/feed", "items_path": "items", "id_field": "id"},
    })
    assert response.status_code == 201, response.text
    c.post("/api/v1/event-triggers/poll")  # establish baseline

    import maverick.templates as tpl
    (tpl.USER_TEMPLATES / "triage.md").write_text(
        "---\nowner: local\ntitle: Replaced {{title}}\nparams:\n  - title\n---\n"
        "Run a different workflow for {{title}}.\n",
        encoding="utf-8",
    )
    box[0] = {
        "items": [
            {"id": "2", "title": "second"},
            {"id": "1", "title": "first"},
        ]
    }
    result = c.post("/api/v1/event-triggers/poll").json()["triggers"][0]
    from maverick.world_model import DEFAULT_DB, WorldModel

    goal = WorldModel(DEFAULT_DB).get_goal(result["fired"][0])
    assert goal.title == "Triage second"
    assert goal.description == "Handle second."


def test_poll_reports_source_error_without_crashing(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev

    def _boom(url, headers=None, timeout=15.0):
        raise ev.EventSourceError("unreachable")
    monkeypatch.setattr(ev, "_http_get_json", _boom)
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json", "config": {"url": "http://x"}})
    out = c.post("/api/v1/event-triggers/poll").json()
    assert any("poll failed" in n for n in out["triggers"][0]["notes"])


def test_history_records_fires_and_errors(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    box = [{"items": [{"id": "1", "title": "first"}]}]
    _feed(monkeypatch, box)
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json",
        "config": {"url": "http://x/feed", "items_path": "items", "id_field": "id"}})
    c.post("/api/v1/event-triggers/poll")                      # baseline: no row
    assert c.get("/api/v1/event-triggers/history").json()["history"] == []

    box[0] = {"items": [{"id": "2", "title": "second"}, {"id": "1", "title": "first"}]}
    c.post("/api/v1/event-triggers/poll")                      # fires -> a row
    hist = c.get("/api/v1/event-triggers/history").json()["history"]
    assert len(hist) == 1 and hist[0]["kind"] == "fired" and hist[0]["new_events"] == 1

    # a source error is recorded too
    import maverick.automation_events as ev
    monkeypatch.setattr(ev, "_http_get_json",
                        lambda *a, **k: (_ for _ in ()).throw(ev.EventSourceError("down")))
    c.post("/api/v1/event-triggers/poll")
    kinds = [r["kind"] for r in c.get("/api/v1/event-triggers/history").json()["history"]]
    assert "poll_error" in kinds                               # newest-first, error on top


def test_history_is_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import trigger_events_store as tes
    tes.record("mine", "user:alice", tes.FIRED, new_events=1, fired=[1])
    tes.record("theirs", "user:bob", tes.FIRED, new_events=1, fired=[2])
    from maverick_dashboard import api
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    names = [r["name"] for r in _client().get("/api/v1/event-triggers/history").json()["history"]]
    assert names == ["mine"]


def test_automations_page_shows_event_section_when_enabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    t = _client().get("/automations").text
    assert "Starts when new items arrive" in t and 'id="auto-event-form"' in t


def test_automations_page_hides_event_section_when_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "0")
    assert 'id="auto-event-form"' not in _client().get("/automations").text


def test_poll_and_fire_attributes_goal_to_trigger_owner(monkeypatch, tmp_path):
    # No request principal (the background path); the fired goal must still be
    # owned by the trigger's owner, so owner-scoped views see it.
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    import maverick.automation_events as ev
    from maverick.world_model import WorldModel
    from maverick_dashboard import event_poll
    from maverick_dashboard import event_triggers_store as s
    world = WorldModel(tmp_path / "world.db")

    box = [{"items": [{"id": "1", "title": "a"}]}]
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: box[0])
    s.set_trigger("feed", "triage", "http_json", owner="user:alice",
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})
    event_poll.poll_and_fire(world, [s.get_trigger("feed")], fire=lambda g: None)
    box[0] = {"items": [{"id": "2", "title": "b"}, {"id": "1", "title": "a"}]}
    event_poll.poll_and_fire(world, [s.get_trigger("feed")], fire=lambda g: None)
    assert [g.owner for g in world.list_goals()] == ["user:alice"]
    world.close()


def _reset_aq(monkeypatch, aq):
    # The queue/worker are module singletons; reset them so each test gets a
    # fresh automation-jobs.db under its own tmp MAVERICK_HOME.
    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])


def test_tick_polls_due_triggers_and_enqueues_durable_run_goal(monkeypatch, tmp_path):
    # The JobQueue tick handler polls due triggers and enqueues a durable
    # run_goal job per fired goal (retry + dead-letter), not a bare thread.
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import event_triggers_store as s
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(aq, "_due", lambda name, interval: True)   # ignore cadence in-test
    box = [{"items": [{"id": "1", "title": "a"}]}]
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: box[0])
    s.set_trigger("feed", "triage", "http_json",
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})
    aq._handle_tick(None)                                     # baseline: nothing fires
    assert aq.queue().counts().get("pending", 0) == 0
    box[0] = {"items": [{"id": "2", "title": "b"}, {"id": "1", "title": "a"}]}
    aq._handle_tick(None)                                     # new item -> a run_goal job
    jobs = aq.queue().list(status="pending")
    assert len(jobs) == 1 and jobs[0].kind == "run_goal"


def test_tick_runs_owned_trigger_with_owner_execution_identity(monkeypatch, tmp_path):
    # A background-tick fire for an owned trigger must carry the owner's
    # user_id/channel on the run_goal job, so the run is attributed to (and
    # quota-scoped to) the trigger owner instead of falling back to
    # `user:local`. An unowned trigger keeps the legacy bare payload.
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    import maverick.automation_events as ev
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import event_triggers_store as s
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(aq, "_due", lambda name, interval: True)
    box = {"x": {"items": [{"id": "1", "title": "a"}]},
           "y": {"items": [{"id": "1", "title": "a"}]}}
    monkeypatch.setattr(ev, "_http_get_json",
                        lambda url, headers=None, timeout=15.0: box["x" if "x" in url else "y"])
    s.set_trigger("owned", "triage", "http_json", owner="user:alice",
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})
    s.set_trigger("unowned", "triage", "http_json",
                  config={"url": "http://y", "items_path": "items", "id_field": "id"})
    aq._poll_due_triggers()                                   # baseline: nothing fires yet
    box["x"] = {"items": [{"id": "2", "title": "b"}, {"id": "1", "title": "a"}]}
    box["y"] = {"items": [{"id": "2", "title": "b"}, {"id": "1", "title": "a"}]}
    aq._poll_due_triggers()                                   # new item on each -> fires
    jobs = {j.payload["goal_id"]: j.payload for j in aq.queue().list(status="pending")}
    payloads = list(jobs.values())
    owned = [p for p in payloads if p.get("user_id") == "alice"]
    unowned = [p for p in payloads if "user_id" not in p]
    assert len(owned) == 1 and owned[0]["channel"] == "api"
    assert len(unowned) == 1


def test_tick_respects_per_trigger_interval(monkeypatch, tmp_path):
    # A trigger polled within its interval is skipped on the next tick.
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import event_triggers_store as s
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(ev, "_http_get_json",
                        lambda url, headers=None, timeout=15.0: {"items": [{"id": "1"}]})
    s.set_trigger("feed", "triage", "http_json", interval_seconds=3600,
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})
    assert aq._due("feed", 3600) is True                     # never polled -> due
    aq._handle_tick(None)                                     # polls + marks
    assert aq._due("feed", 3600) is False                    # within interval -> not due


def test_worker_starts_only_when_a_feature_is_on(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)                          # MAVERICK_EVENT_TRIGGERS=1
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    assert aq.start() is True                                 # a feature is on
    aq.stop()

    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "0")
    monkeypatch.setenv("MAVERICK_DREAMING", "0")
    monkeypatch.setenv("MAVERICK_DATA_ENGINE", "0")
    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")         # nightly self-coaching also uses it
    _reset_aq(monkeypatch, aq)
    assert aq.start() is False                                # nothing on -> no worker


def test_fired_goal_runs_via_durable_queue(monkeypatch, tmp_path):
    # A run_goal job on the automation queue is drained through the worker's
    # built-in handler -- the durable path that gets retry + dead-letter.
    _isolate(monkeypatch, tmp_path)
    import maverick.runner as runner_mod
    from maverick.worker import Worker
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    ran = []
    monkeypatch.setattr(runner_mod, "run_goal_in_thread",
                        lambda gid, **k: ran.append(gid) or "done")
    aq.queue().enqueue("run_goal", {"goal_id": 7})
    Worker(queue=aq.queue()).drain()
    assert ran == [7]


def test_failed_poll_leaves_trigger_due(monkeypatch, tmp_path):
    # A source error must NOT advance the due-marker, so the trigger retries on
    # the next tick instead of going dark for a full interval.
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import event_triggers_store as s
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(ev, "_http_get_json",
                        lambda *a, **k: (_ for _ in ()).throw(ev.EventSourceError("down")))
    s.set_trigger("feed", "triage", "http_json", interval_seconds=3600,
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})
    aq._handle_tick(None)
    assert aq._due("feed", 3600) is True          # errored -> not marked -> still due


def test_poll_runs_under_trigger_tenant(monkeypatch, tmp_path):
    # The poll (and any OAuth vault read inside it) must run under the tenant
    # that created the trigger, never the process-active tenant.
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick.paths import current_tenant_id
    from maverick_dashboard import event_poll
    from maverick_dashboard import event_triggers_store as s
    seen = {}

    def _fake(url, headers=None, timeout=15.0):
        seen["tenant"] = current_tenant_id()
        return {"items": [{"id": "1"}]}
    monkeypatch.setattr(ev, "_http_get_json", _fake)
    s.set_trigger("feed", "triage", "http_json", tenant="tenant:acme",
                  config={"url": "http://x", "items_path": "items", "id_field": "id"})

    from maverick.world_model import WorldModel
    opened = []
    def world_factory():
        world = WorldModel(tmp_path / "world.db")
        opened.append(world)
        return world
    try:
        result = event_poll.poll_and_fire(world_factory, [s.get_trigger("feed")], fire=lambda g: None)
    finally:
        for world in opened:
            world.close()
    assert not result[0]["poll_error"]
    assert seen["tenant"] == "tenant:acme"


def test_world_factory_resolves_after_trigger_tenant_is_pinned(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick.paths import current_tenant_id
    from maverick_dashboard import event_poll
    from maverick_dashboard import event_triggers_store as s

    monkeypatch.setattr(
        ev,
        "_http_get_json",
        lambda *a, **k: {"items": [{"id": "1"}]},
    )
    s.set_trigger(
        "feed",
        "triage",
        "http_json",
        tenant="acme",
        config={"url": "http://x", "items_path": "items", "id_field": "id"},
    )
    resolved = []

    from maverick.world_model import WorldModel
    opened = []
    def _world_factory():
        resolved.append(current_tenant_id())
        world = WorldModel(tmp_path / "world.db")
        opened.append(world)
        return world

    try:
        result = event_poll.poll_and_fire(
            _world_factory,
            [s.get_trigger("feed", tenant="acme")],
            fire=lambda _g: None,
        )
    finally:
        for world in opened:
            world.close()
    assert not result[0]["poll_error"]
    assert resolved == ["acme"]


def test_deprovisioned_trigger_owner_is_not_polled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.automation_events as ev
    from maverick_dashboard import event_poll
    from maverick_dashboard import event_triggers_store as s

    polled = []
    monkeypatch.setattr(
        ev,
        "_http_get_json",
        lambda *a, **k: polled.append(True) or {"items": []},
    )
    monkeypatch.setattr(
        "maverick_dashboard.scim_groups.active_for_principal", lambda _p: False
    )
    s.set_trigger(
        "feed",
        "triage",
        "http_json",
        owner="user:alice",
        config={"url": "http://x"},
    )

    result = event_poll.poll_and_fire(
        object(), [s.get_trigger("feed")], fire=lambda _g: None
    )[0]
    assert result["poll_error"] is True
    assert result["notes"] == ["trigger authorization unavailable"]
    assert polled == []


def test_poll_markers_are_tenant_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq

    acme = aq._trigger_poll_key({"name": "feed", "tenant": "acme"})
    globex = aq._trigger_poll_key({"name": "feed", "tenant": "globex"})
    assert acme != globex
    assert "acme" not in acme and "globex" not in globex


def test_all_skipped_events_record_no_fired_row(monkeypatch, tmp_path, _no_real_run):
    # A poll whose events all fail template render is NOT "fired" -- it records
    # event_skipped, not a misleading FIRED row (which the UI would count).
    _isolate(monkeypatch, tmp_path)
    box = [{"items": [{"id": "1"}]}]              # no 'title' -> render will skip
    _feed(monkeypatch, box)
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "template": "triage", "source": "http_json",
        "config": {"url": "http://x", "items_path": "items", "id_field": "id"}})
    c.post("/api/v1/event-triggers/poll")         # baseline
    box[0] = {"items": [{"id": "2"}, {"id": "1"}]}   # new event, still no title
    c.post("/api/v1/event-triggers/poll")
    kinds = [r["kind"] for r in c.get("/api/v1/event-triggers/history").json()["history"]]
    assert "event_skipped" in kinds and "fired" not in kinds


def test_reconcile_seeds_one_tick_and_is_idempotent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)                          # MAVERICK_EVENT_TRIGGERS=1
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    aq.reconcile()
    aq.reconcile()
    ticks = [j for j in aq.queue().list(status="pending") if j.kind == aq.TICK_KIND]
    assert len(ticks) == 1


def test_reconcile_seeds_flywheel_only_when_data_engine_on(monkeypatch, tmp_path):
    # The missing scheduled driver: enabling the data engine arms a recurring
    # flywheel_cycle so accumulated outcomes actually get consolidated.
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setenv("MAVERICK_DATA_ENGINE", "0")
    aq.reconcile()
    assert not [j for j in aq.queue().list(status="pending") if j.kind == aq.FLYWHEEL_KIND]
    monkeypatch.setenv("MAVERICK_DATA_ENGINE", "1")
    aq.reconcile()
    fly = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLYWHEEL_KIND]
    assert len(fly) == 1


def test_flywheel_handler_is_gated_and_fail_open(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    calls = []
    import maverick.flywheel as fw
    monkeypatch.setattr(fw, "maybe_run", lambda: calls.append(1))
    aq._handle_flywheel(None)          # maybe_run is itself gated; handler just drives it
    assert calls == [1]
    # a raising flywheel must not escape the handler (fail-open like the dream cycle)
    monkeypatch.setattr(fw, "maybe_run", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    aq._handle_flywheel(None)          # no raise


def test_recurring_learners_visit_shared_and_active_tenants_in_isolation(
    monkeypatch, tmp_path,
):
    """The one global cron must drive every private learning store explicitly.

    Poison the caller's ambient ContextVar and make one tenant's dream fail: the
    shared pass and remaining tenant must still run, and the caller scope must be
    restored afterwards.
    """
    from types import SimpleNamespace

    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    tenants = [
        SimpleNamespace(id="acme", active=True),
        SimpleNamespace(id="globex", active=True),
        SimpleNamespace(id="retired", active=False),
    ]
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", lambda: tenants)
    monkeypatch.setattr("maverick.tenant.registry.assert_tenant_active", lambda _t: None)

    from maverick import assessments, dreaming, flywheel
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick_dashboard import automation_queue as aq

    dream_calls = []
    assessment_calls = []
    flywheel_calls = []

    def _dream(_world):
        tenant = current_tenant_id() or ""
        dream_calls.append(tenant)
        if tenant == "acme":
            raise RuntimeError("tenant-local failure")

    monkeypatch.setattr(dreaming, "enabled", lambda: True)
    monkeypatch.setattr(dreaming, "dream_cycle", _dream)
    monkeypatch.setattr(assessments, "sweep_due",
                        lambda: assessment_calls.append(current_tenant_id() or ""))
    monkeypatch.setattr(flywheel, "maybe_run",
                        lambda: flywheel_calls.append(current_tenant_id() or ""))
    monkeypatch.setattr(aq, "_world", lambda: object())

    ambient = set_tenant("ambient-poison")
    try:
        aq._handle_dream(None)
        aq._handle_assess_sweep(None)
        aq._handle_flywheel(None)
        assert current_tenant_id() == "ambient-poison"
    finally:
        reset_tenant(ambient)

    assert dream_calls == ["", "acme", "globex"]
    assert assessment_calls == ["", "acme", "globex"]
    assert flywheel_calls == ["", "acme", "globex"]


def test_list_is_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import api, event_triggers_store
    event_triggers_store.set_trigger("mine", "triage", "http_json", owner="user:alice")
    event_triggers_store.set_trigger("theirs", "triage", "http_json", owner="user:bob")
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    names = {t["name"] for t in _client().get("/api/v1/event-triggers").json()["triggers"]}
    assert names == {"mine"}
