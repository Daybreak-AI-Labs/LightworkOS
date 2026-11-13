"""Inbound webhook triggers: manage via /api/v1/triggers, fire via /webhook/run.

Management is dashboard-authed + operate-gated + feature-knobbed; firing is
HMAC-signed exactly like /webhook/start and strictly narrower (it runs only an
operator-registered template, never arbitrary text). Hermetic: HOME is isolated
to tmp so the trigger registry, templates, and world model all live under tmp;
the background runner is stubbed so no real goal runs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

SECRET = "test-webhook-secret"  # pragma: allowlist secret


def _client():
    # Mutating /api/v1 requests in no-token mode need the same-origin CSRF header;
    # the HMAC-exempt /webhook/run ignores it.
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _sign_headers(body: bytes) -> dict:
    ts = str(int(time.time()))
    material = f"{ts}.".encode() + body
    sig = "sha256=" + hmac.new(SECRET.encode(), material, hashlib.sha256).hexdigest()
    return {"X-Maverick-Signature": sig, "X-Maverick-Timestamp": ts}


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_INBOUND_WEBHOOK_SECRET", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    tdir = tmp_path / ".maverick" / "templates"
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tdir)
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Weekly {{topic}} report\nparams:\n  - topic\n---\n"
        "Research {{topic}} and email the team.\n", encoding="utf-8")


@pytest.fixture
def _no_real_run(monkeypatch):
    import maverick.runner as runner_mod
    called = []

    def fake_run(
        goal_id, max_dollars=None, max_wall_seconds=None, max_depth=3, **_kwargs,
    ):
        called.append(goal_id)

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
    return called


def _configured(monkeypatch):
    monkeypatch.setenv("MAVERICK_INBOUND_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")  # pragma: allowlist secret


def _register(c, **kw):
    payload = {"template": "weekly-report", "params": {"topic": "rivals"}}
    payload.update(kw)
    r = c.post("/api/v1/triggers", json=payload)
    assert r.status_code == 201, r.text
    return r.json()["name"]


# ---- management REST ---------------------------------------------------------

def test_create_list_delete_trigger(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/api/v1/triggers",
               json={"template": "weekly-report", "params": {"topic": "rivals"}})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "weekly-report" and body["template"] == "weekly-report"
    assert body["params"] == {"topic": "rivals"} and body["webhook_url"] == "/webhook/run"
    assert body["secret_configured"] is False          # no [webhooks] secret here
    listed = c.get("/api/v1/triggers").json()
    assert any(t["name"] == "weekly-report" for t in listed["triggers"])
    assert listed["webhook_url"] == "/webhook/run"
    assert c.delete("/api/v1/triggers/weekly-report").status_code == 200
    assert c.delete("/api/v1/triggers/weekly-report").status_code == 404
    assert c.get("/api/v1/triggers").json()["triggers"] == []


def test_create_trigger_validates_template(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    # a missing required param fails at registration (render raises ValueError)
    assert c.post("/api/v1/triggers",
                  json={"template": "weekly-report"}).status_code == 400
    # an unknown template is a 404
    assert c.post("/api/v1/triggers",
                  json={"template": "nope", "params": {}}).status_code == 404


def _save_flow(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    saved = store.save_flow(Flow(id="triage", name="Triage", start="a", nodes={
        "a": FlowNode(id="a", kind="agent", brief="triage {{issue}}", output="r")}))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )


def _paused_event_run(run_id: str) -> None:
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode

    saved = store.save_flow(Flow(
        id="anyflow",
        name="Waiting",
        start="w",
        nodes={"w": FlowNode(id="w", kind="wait_event", prompt="callback")},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id=run_id,
        flow_id="anyflow",
        status="paused_event",
        cursor="w",
        definition_digest=release["definition_digest"],
        release_digest=release["release_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))


def test_create_flow_trigger_and_exclusivity(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_flow(monkeypatch)
    c = _client()
    r = c.post("/api/v1/triggers", json={"flow": "triage"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "triage" and body["flow"] == "triage" and body["template"] == ""
    # exactly one of template/flow
    assert c.post("/api/v1/triggers", json={
        "template": "weekly-report", "flow": "triage"}).status_code == 400
    assert c.post("/api/v1/triggers", json={}).status_code == 400
    # an unknown flow is a 404
    assert c.post("/api/v1/triggers", json={"flow": "nope"}).status_code == 404


def test_flow_trigger_requires_flow_engine(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"enable": False})
    assert _client().post("/api/v1/triggers",
                          json={"flow": "triage"}).status_code == 403


def test_webhook_fires_flow_trigger_with_idempotent_delivery(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    _save_flow(monkeypatch)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    c = _client()
    _register(c, template="", flow="triage", params=None)
    body = json.dumps({"trigger": "triage", "data": {"issue": "bug #7"},
                       "id": "evt-1"}).encode()
    r = c.post("/webhook/run", content=body,
               headers={**_sign_headers(body), "Content-Type": "application/json"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["flow"] == "triage" and out["trigger"] == "triage"
    run = store.load_run(out["run_id"])
    assert run.status == "queued" and run.input_data == {"issue": "bug #7"}
    assert run.idem_key == "webhook:triage:evt-1"
    # a queued flow_run job was armed for the worker
    jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RUN_KIND]
    assert len(jobs) == 1 and jobs[0].payload["flow_id"] == "triage"
    # re-delivery of the same event id returns the SAME run (no duplicate)
    r2 = c.post("/webhook/run", content=body,
                headers={**_sign_headers(body), "Content-Type": "application/json"})
    assert r2.status_code in (201, 409)       # delivery-id dedup may 409 first
    if r2.status_code == 201:
        assert r2.json()["run_id"] == out["run_id"]


def test_flow_trigger_runs_bound_published_revision_not_later_draft(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    _save_flow(monkeypatch)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    monkeypatch.setattr(aq, "_queue", None)
    client = _client()
    _register(client, template="", flow="triage", params=None)

    later = store.load_flow("triage")
    later.nodes["a"].brief = "unpublished replacement {{issue}}"
    saved = store.save_flow(
        later,
        expected_version=later.version,
        expected_revision=later.revision,
    )

    body = json.dumps({
        "trigger": "triage", "data": {"issue": "bug"}, "id": "bound-v1",
    }).encode()
    response = client.post(
        "/webhook/run",
        content=body,
        headers={**_sign_headers(body), "Content-Type": "application/json"},
    )
    assert response.status_code == 201, response.text
    run = store.load_run(response.json()["run_id"])
    pinned = store.load_flow_snapshot(run.definition_digest)
    assert pinned.version == 1
    assert pinned.nodes["a"].brief == "triage {{issue}}"

    # Publishing a different revision does not silently retarget an existing
    # trigger. It fails stale until an operator re-arms it against the new digest.
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    body2 = json.dumps({"trigger": "triage", "id": "bound-v2"}).encode()
    stale = client.post(
        "/webhook/run",
        content=body2,
        headers={**_sign_headers(body2), "Content-Type": "application/json"},
    )
    assert stale.status_code == 409
    assert "stale" in stale.json()["detail"]


def test_webhook_event_resume_continues_a_waiting_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _paused_event_run("wr1")
    body = json.dumps({"resume": "wr1", "data": {"payload": "cb-1"}}).encode()
    r = _client().post("/webhook/run", content=body,
                       headers={**_sign_headers(body), "Content-Type": "application/json"})
    assert r.status_code == 202, r.text
    jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RESUME_KIND]
    assert len(jobs) == 1
    assert jobs[0].payload["run_id"] == "wr1"
    assert jobs[0].payload["inputs"] == {"payload": "cb-1"}
    # a run that isn't waiting for an event can't be event-resumed
    store.save_run(store.FlowRun(run_id="wr2", flow_id="anyflow", status="completed"))
    body2 = json.dumps({"resume": "wr2"}).encode()
    r2 = _client().post("/webhook/run", content=body2,
                        headers={**_sign_headers(body2), "Content-Type": "application/json"})
    assert r2.status_code == 409


def test_webhook_event_resume_dedupes_repeat_delivery_id(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _paused_event_run("wd1")
    payload = {"resume": "wd1", "data": {"payload": "x"}, "id": "evt-dup"}
    body = json.dumps(payload).encode()
    r1 = _client().post("/webhook/run", content=body,
                        headers={**_sign_headers(body), "Content-Type": "application/json"})
    assert r1.status_code == 202
    # same delivery id again -> 409 duplicate (the dedup the trigger paths have)
    body2 = json.dumps(payload).encode()
    r2 = _client().post("/webhook/run", content=body2,
                        headers={**_sign_headers(body2), "Content-Type": "application/json"})
    assert r2.status_code == 409 and "duplicate" in r2.json()["detail"]


def test_webhook_flow_trigger_when_engine_off_is_409(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    _save_flow(monkeypatch)
    c = _client()
    _register(c, template="", flow="triage", params=None)
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"enable": False})
    body = json.dumps({"trigger": "triage"}).encode()
    r = c.post("/webhook/run", content=body,
               headers={**_sign_headers(body), "Content-Type": "application/json"})
    assert r.status_code == 409


def test_triggers_feature_off_403(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(config, "get_features", lambda: {**real(), "triggers": False})
    c = _client()
    assert c.post("/api/v1/triggers", json={
        "template": "weekly-report", "params": {"topic": "x"}}).status_code == 403
    assert c.get("/api/v1/triggers").status_code == 200    # read-only stays open


# ---- inbound /webhook/run (HMAC-signed) -------------------------------------

def test_webhook_run_fires_registered_template(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)
    body = json.dumps({"trigger": name}).encode()
    r = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 201, r.text
    goal_id = r.json()["goal_id"]
    assert _no_real_run == [goal_id]
    from maverick.world_model import DEFAULT_DB, WorldModel
    g = WorldModel(DEFAULT_DB).get_goal(goal_id)
    assert g is not None and g.title == "Weekly rivals report"   # rendered defaults


def test_webhook_run_uses_immutable_template_revision(monkeypatch, tmp_path, _no_real_run):
    """Editing a shared-name template cannot rewrite an already-armed trigger."""
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)

    import maverick.templates as tpl
    (tpl.USER_TEMPLATES / "weekly-report.md").write_text(
        "---\nowner: local\ntitle: Replaced {{topic}} workflow\nparams:\n  - topic\n---\n"
        "Run a materially different workflow for {{topic}}.\n",
        encoding="utf-8",
    )

    body = json.dumps({"trigger": name}).encode()
    response = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert response.status_code == 201, response.text
    from maverick.world_model import DEFAULT_DB, WorldModel

    goal = WorldModel(DEFAULT_DB).get_goal(response.json()["goal_id"])
    assert goal is not None
    assert goal.title == "Weekly rivals report"
    assert goal.description == "Research rivals and email the team."

    # Listings identify the pinned revision but never disclose its prompt body.
    listed = c.get("/api/v1/triggers").json()["triggers"][0]
    assert len(listed["template_revision"]) == 64
    assert "template_snapshot" not in listed


def test_webhook_run_refuses_legacy_name_only_binding(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    from maverick_dashboard import triggers_store

    triggers_store.set_trigger(
        "legacy", "weekly-report", {"topic": "rivals"}
    )
    body = json.dumps({"trigger": "legacy"}).encode()
    response = _client().post(
        "/webhook/run", content=body, headers=_sign_headers(body)
    )
    assert response.status_code == 409
    assert "binding" in response.json()["detail"]
    assert _no_real_run == []


def test_webhook_run_records_trigger_provenance(monkeypatch, tmp_path, _no_real_run):
    # v2: firing a trigger stamps goal_origins, so /automation-runs (same _world)
    # surfaces the spawned goal for the Automations run-history view.
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)
    body = json.dumps({"trigger": name}).encode()
    gid = c.post("/webhook/run", content=body, headers=_sign_headers(body)).json()["goal_id"]
    data = c.get("/api/v1/automation-runs", params={"kind": "trigger", "ref": name}).json()
    assert any(r["goal_id"] == gid for r in data["runs"])
    assert sum(data["summary"].values()) >= 1


def test_webhook_run_inbound_overrides_declared_param(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)            # default topic=rivals
    # inbound data overrides the DECLARED "topic"; an undeclared key is ignored
    body = json.dumps({"trigger": name, "data": {"topic": "acme", "evil": "x"}}).encode()
    r = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 201
    from maverick.world_model import DEFAULT_DB, WorldModel
    g = WorldModel(DEFAULT_DB).get_goal(r.json()["goal_id"])
    assert g.title == "Weekly acme report"


def test_webhook_run_unknown_trigger_404(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    body = json.dumps({"trigger": "ghost"}).encode()
    r = _client().post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 404
    assert _no_real_run == []


def test_webhook_run_bad_signature_403(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)
    body = json.dumps({"trigger": name}).encode()
    r = c.post("/webhook/run", content=body, headers={
        "X-Maverick-Signature": "sha256=bad",
        "X-Maverick-Timestamp": str(int(time.time())),
    })
    assert r.status_code == 403
    assert _no_real_run == []


def test_webhook_run_no_secret_fails_closed(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")  # pragma: allowlist secret; no webhook secret
    import maverick.webhooks as wh
    monkeypatch.setattr(wh, "_load_config_outbound", lambda: ([], None))
    c = _client()
    name = _register(c)                                       # managing needs no secret
    body = json.dumps({"trigger": name}).encode()
    r = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 401
    assert _no_real_run == []


def test_webhook_run_feature_off_404(monkeypatch, tmp_path, _no_real_run):
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(config, "get_features", lambda: {**real(), "triggers": False})
    body = json.dumps({"trigger": name}).encode()
    r = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 404
    assert _no_real_run == []


# ---- store slug / round-trip -------------------------------------------------

def test_store_slugifies_and_round_trips(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import triggers_store as ts
    rec = ts.set_trigger("My Weekly Report!", "weekly-report", {"topic": "rivals"})
    assert rec["name"] == "my-weekly-report"
    got = ts.get_trigger("my-weekly-report")
    assert got is not None and got["params"] == {"topic": "rivals"}
    with pytest.raises(ValueError):
        ts.set_trigger("!!!", "weekly-report", {})          # un-sluggable name


def test_mutations_refuse_to_overwrite_an_unparseable_file(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import triggers_store as ts
    ts.set_trigger("alpha", "weekly-report")
    path = ts._path()
    corrupt = path.read_text(encoding="utf-8") + "[[broken\n"
    path.write_text(corrupt, encoding="utf-8")

    with pytest.raises(RuntimeError):
        ts.set_trigger("gamma", "weekly-report")
    with pytest.raises(RuntimeError):
        ts.delete_trigger("alpha")
    assert path.read_text(encoding="utf-8") == corrupt


def test_concurrent_set_trigger_does_not_lose_triggers(monkeypatch, tmp_path):
    """set_trigger does a load-modify-save; without the lock concurrent creates
    clobber each other. All N distinct triggers must survive."""
    import threading

    from maverick_dashboard import triggers_store
    n = 16

    def add(i: int):
        triggers_store.set_trigger(f"trig-{i:03d}", "some-template")

    threads = [threading.Thread(target=add, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(triggers_store.list_triggers()) == n
    store_dir = triggers_store._path().parent
    assert list(store_dir.glob("*.tmp")) == []


# ---- governance / scoping fixes ---------------------------------------------

def test_webhook_run_honors_template_budget(monkeypatch, tmp_path):
    # A trigger fire must run the goal under the template's own budget/wall caps
    # rather than falling back to the global default.
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    import maverick.templates as tpl
    (tpl.USER_TEMPLATES / "cheap.md").write_text(
        "---\nowner: local\ntitle: Cheap\nbudget_dollars: 0.75\nbudget_wall_seconds: 120\n---\n"
        "Do a small thing.\n", encoding="utf-8")
    import maverick.runner as runner_mod
    seen = {}

    def fake_run(
        goal_id, max_dollars=None, max_wall_seconds=None, max_depth=3, **_kwargs,
    ):
        seen["dollars"] = max_dollars
        seen["wall"] = max_wall_seconds

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
    c = _client()
    assert c.post("/api/v1/triggers", json={"template": "cheap"}).status_code == 201
    body = json.dumps({"trigger": "cheap"}).encode()
    r = c.post("/webhook/run", content=body, headers=_sign_headers(body))
    assert r.status_code == 201, r.text
    assert seen["dollars"] == 0.75 and seen["wall"] == 120.0


def test_webhook_run_clamps_template_to_configured_operator_budget(monkeypatch, tmp_path):
    # A larger explicitly saved template cannot raise current operator limits.
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    import maverick.templates as tpl
    (tpl.USER_TEMPLATES / "huge.md").write_text(
        "---\nowner: local\ntitle: Huge\nbudget_dollars: 1000\nbudget_wall_seconds: 999999\n---\n"
        "Do a big thing.\n", encoding="utf-8")
    import maverick.runner as runner_mod
    monkeypatch.setattr(runner_mod, "configured_goal_ceiling_dollars", lambda: 100.0)
    monkeypatch.setattr(runner_mod, "configured_goal_ceiling_wall_seconds", lambda: 86400.0)
    seen = {}

    def fake_run(
        goal_id, max_dollars=None, max_wall_seconds=None, max_depth=3, **_kwargs,
    ):
        seen["dollars"] = max_dollars
        seen["wall"] = max_wall_seconds

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
    c = _client()
    assert c.post("/api/v1/triggers", json={"template": "huge"}).status_code == 201
    body = json.dumps({"trigger": "huge"}).encode()
    assert c.post("/webhook/run", content=body, headers=_sign_headers(body)).status_code == 201
    assert seen["dollars"] == 100.0 and seen["wall"] == 86400.0    # clamped down


def test_webhook_run_verifies_signature_before_feature_flag(monkeypatch, tmp_path, _no_real_run):
    # With triggers disabled, an UNSIGNED/bad request must be rejected as auth
    # (403), not leak the feature state via a distinct 404.
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    from maverick import config
    real = config.get_features
    monkeypatch.setattr(config, "get_features", lambda: {**real(), "triggers": False})
    body = json.dumps({"trigger": "whatever"}).encode()
    r = _client().post("/webhook/run", content=body, headers={
        "X-Maverick-Signature": "sha256=bad",
        "X-Maverick-Timestamp": str(int(time.time())),
    })
    assert r.status_code == 403
    assert _no_real_run == []


def test_webhook_run_dedupes_on_delivery_id(monkeypatch, tmp_path, _no_real_run):
    # A caller-supplied delivery id gives at-most-once: a repeat 409s, while a
    # DISTINCT id (or none) still fires. Ids are unique per test to avoid the
    # process-global dedup store leaking across tests.
    _isolate(monkeypatch, tmp_path)
    _configured(monkeypatch)
    c = _client()
    name = _register(c)
    b1 = json.dumps({"trigger": name, "id": "delivery-aaa"}).encode()
    assert c.post("/webhook/run", content=b1, headers=_sign_headers(b1)).status_code == 201
    # exact resend (same id) is rejected as a duplicate
    assert c.post("/webhook/run", content=b1, headers=_sign_headers(b1)).status_code == 409
    # a different id fires normally
    b2 = json.dumps({"trigger": name, "id": "delivery-bbb"}).encode()
    assert c.post("/webhook/run", content=b2, headers=_sign_headers(b2)).status_code == 201
    assert len(_no_real_run) == 2   # two goals, not three


def test_trigger_records_and_round_trips_owner(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import triggers_store as ts
    ts.set_trigger("t1", "weekly-report", {"topic": "x"}, owner="user:bob")
    got = ts.get_trigger("t1")
    assert got["owner"] == "user:bob"


def test_list_triggers_is_owner_scoped(monkeypatch, tmp_path):
    # A non-admin (goal_owner_filter -> principal) sees only its own triggers.
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import api, triggers_store
    triggers_store.set_trigger("mine", "weekly-report", {"topic": "x"}, owner="user:alice")
    triggers_store.set_trigger("theirs", "weekly-report", {"topic": "y"}, owner="user:bob")
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    names = {t["name"] for t in _client().get("/api/v1/triggers").json()["triggers"]}
    assert names == {"mine"}


def test_create_trigger_cannot_overwrite_another_owner(monkeypatch, tmp_path):
    # A non-admin must not hijack a trigger owned by another tenant by reusing
    # its slug; the existing trigger stays intact.
    _isolate(monkeypatch, tmp_path)
    from maverick import templates
    from maverick_dashboard import api, auth, rbac, triggers_store
    rbac.set_role("user:alice", "operator")
    template = templates.USER_TEMPLATES / "weekly-report.md"
    template.write_text(template.read_text(encoding="utf-8").replace(
        "owner: local", "owner: user:alice"), encoding="utf-8")
    triggers_store.set_trigger("shared", "weekly-report", {"topic": "x"}, owner="user:bob")
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    r = _client().post("/api/v1/triggers", json={
        "name": "shared", "template": "weekly-report", "params": {"topic": "y"}})
    assert r.status_code == 409
    got = triggers_store.get_trigger("shared")
    assert got["owner"] == "user:bob" and got["params"] == {"topic": "x"}   # untouched


def test_static_token_cannot_create_unrunnable_trigger_but_can_manage_existing(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token-for-tests")  # pragma: allowlist secret
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: True)
    from maverick_dashboard import triggers_store
    from maverick_dashboard.app import app

    c = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
                   "Authorization": "Bearer static-operator-token-for-tests"})  # pragma: allowlist secret
    body = {"template": "weekly-report", "params": {"topic": "rivals"}}
    refused = c.post("/api/v1/triggers", json=body)
    assert refused.status_code == 409
    assert "named account" in refused.json()["detail"]
    assert triggers_store.get_trigger("weekly-report") is None

    triggers_store.set_trigger("legacy", "weekly-report", {"topic": "x"}, owner="user:local")
    assert [t["name"] for t in c.get("/api/v1/triggers").json()["triggers"]] == ["legacy"]
    assert c.post("/api/v1/triggers", json={**body, "name": "legacy"}).status_code == 409
    assert triggers_store.get_trigger("legacy")["params"] == {"topic": "x"}
    assert c.delete("/api/v1/triggers/legacy").status_code == 200
    triggers_store.set_trigger("theirs", "weekly-report", {"topic": "y"}, owner="user:bob")
    assert c.get("/api/v1/triggers").json()["triggers"] == []
    assert c.delete("/api/v1/triggers/theirs").status_code == 404
    assert c.post("/api/v1/triggers", json={**body, "name": "theirs"}).status_code == 409
    assert triggers_store.get_trigger("theirs")["owner"] == "user:bob"
