"""Settings in plain language: readable model names and setting sources, the
reviewed webhook secret form, a switch for automatic model lists, the
task-limit choice, and the Maintenance tab's installation checks."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}

# Words a person must never see on these pages (config keys, env vars, CLI,
# raw ids and developer terms).
BANNED = (
    "MAVERICK_", "config.toml", "[models]", "environment:", "maverick ",
    "operator overlay", "tenant config", "payload", "endpoint", "schema",
    "SHA-256", "idempotency", "HTTP ", "provider:model", "openai:gpt",
    "Type a model id", "Base URL",
)


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<[^>]+>", " ", main)
    return _html.unescape(re.sub(r"\s+", " ", main))


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "maintenance-test")
    for name in ("MAVERICK_WEBHOOK_SECRET", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_MODEL_DISCOVERY",
                 "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick import client as bound_client
    from maverick import config
    config.reset_config_cache()
    bound_client.reset_client_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    # The process-wide client binding was read under this test's organisation;
    # forget it so later tests resolve their own (unbound) installation.
    bound_client.reset_client_cache()
    dash_app._world_cache.clear()


def _as_viewer(monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:vic", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic")


def test_settings_page_reads_as_plain_language(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    from maverick import config
    config.reset_config_cache()
    page = client.get("/settings").text
    text = visible_text(page)
    for word in BANNED:
        assert word not in text, word
    # Model names are readable; the exact id stays only in the option value.
    assert 'value="openai:gpt-5.4"' in page and "GPT-5.4 · OpenAI" in text
    # Where the OpenAI key came from, in words.
    assert "set on the computer running Lightwork" in text
    # Buttons for everything the page describes.
    for label in ("Test connection", "Refresh status", "Apply change", "Check readiness", "Run health check",
                  "Check installation settings", "Show background work",
                  "Check encryption", "Check services"):
        assert label in text, label
    assert "Where do I get a key?" in text
    assert 'data-settings-tab="maintenance"' in page


def test_model_label_and_source_label():
    from maverick_dashboard.plain_labels import model_label, source_label, unique_slug
    assert model_label("claude-opus-4-8") == "Claude Opus 4.8 · Anthropic"
    assert model_label("gemini:gemini-3.5-pro") == "Gemini 3.5 Pro · Google Gemini"
    assert source_label("environment:OPENAI_API_KEY") == "set on the computer running Lightwork"
    assert source_label("tenant config") == "set for this workspace"
    assert "MAVERICK" not in source_label("environment:MAVERICK_X")
    assert unique_slug("Acme — EU", {"acme-eu"}) == "acme-eu-2"
    assert unique_slug("123", set(), fallback="workspace") == "workspace-123"


def test_webhook_secret_changes_only_through_the_reviewed_form(client):
    # The one-click generator bypassed the reviewed change (current owner and
    # generation); the Settings card now saves a secret only after review.
    assert client.post("/settings/webhooks/generate").status_code in {404, 405}
    from maverick.webhooks import inbound_secret
    assert inbound_secret() is None
    page = client.get("/settings").text
    assert 'id="wh-form"' in page and 'id="webhook-generate"' not in page
    assert "Make a secret" not in visible_text(page)


def test_model_discovery_switch(client, monkeypatch):
    from maverick import model_discovery
    assert client.post("/settings/models/discovery", data={"enabled": "off"},
                       follow_redirects=False).status_code == 303
    from maverick import config
    config.reset_config_cache()
    assert model_discovery.discovery_enabled() is False
    assert "Turn on automatic model lists" in client.get("/settings").text
    client.post("/settings/models/discovery", data={"enabled": "on"}, follow_redirects=False)
    config.reset_config_cache()
    assert model_discovery.discovery_enabled() is True
    monkeypatch.setenv("MAVERICK_MODEL_DISCOVERY", "0")
    assert client.post("/settings/models/discovery", data={"enabled": "on"}).status_code == 409
    _as_viewer(monkeypatch)
    monkeypatch.delenv("MAVERICK_MODEL_DISCOVERY")
    assert client.post("/settings/models/discovery", data={"enabled": "on"}).status_code == 403


def test_task_limit_standard_choice(client):
    from maverick.runtime_overrides import budget_override, task_limits_override
    client.post("/settings/budget", data={"mode": "configured", "max_dollars": "3"}, follow_redirects=False)
    assert budget_override() == 3
    client.post("/settings/budget", data={"mode": "default", "max_dollars": "9"}, follow_redirects=False)
    assert budget_override() is None and task_limits_override() is True
    assert "each task follows your installation's standard limits" in client.get("/settings").text


# ---- Maintenance tab APIs ---------------------------------------------------

def test_system_checks_require_admin(client, monkeypatch):
    _as_viewer(monkeypatch)
    for path in ("readiness", "settings-check", "queue", "encryption", "diagnostics"):
        assert client.get(f"/api/v1/admin/system/{path}").status_code == 403, path
    assert client.post("/api/v1/admin/system/health-check").status_code == 403
    assert client.post("/api/v1/admin/system/encryption/new-key").status_code == 403
    assert client.post("/api/v1/admin/system/queue/1/resume", json={"attempts": 1}).status_code == 403


def test_readiness_rows_are_plain_with_fix_links(client):
    data = client.get("/api/v1/admin/system/readiness").json()
    keys = {row["key"] for row in data["checks"]}
    assert keys == {"spending", "separation", "encryption", "provider"}
    provider = next(r for r in data["checks"] if r["key"] == "provider")
    assert provider["ok"] is False and provider["fix_href"].startswith("/settings")
    for row in data["checks"]:
        for word in ("MAVERICK_", "[", "maverick "):
            assert word not in row["detail"], row


def test_settings_check_without_a_file(client):
    data = client.get("/api/v1/admin/system/settings-check").json()
    assert data["file_present"] is False and data["errors"] == 0
    assert "built-in settings" in data["summary"]


def test_settings_check_reports_problems_in_words(client):
    from maverick import config
    path = config.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[budget]\nmax_dollars = \"lots\"\n", encoding="utf-8")
    data = client.get("/api/v1/admin/system/settings-check").json()
    assert data["file_present"] is True
    assert data["errors"] >= 1 and "cannot be used" in data["summary"]
    assert data["technical"]  # exact findings kept for the collapsed details


def test_health_check_collects_rows_without_printing(client, monkeypatch):
    from maverick import health

    def fake_diagnose():
        health._FAILURES.clear()
        health._row(health.GREEN, "config", "found")
        health._row(health.RED, "world DB", "unreadable", "run maverick doctor")
        return len(health._FAILURES)
    monkeypatch.setattr(health, "diagnose", fake_diagnose)
    data = client.post("/api/v1/admin/system/health-check").json()
    assert data["healthy"] is False and data["problems"] == 1
    assert "maverick" not in data["summary"]
    assert [r["state"] for r in data["technical"]] == ["ok", "problem"]
    assert health._row is not None and health._row.__name__ == "_row"


def test_queue_lists_stopped_jobs_and_refuses_the_old_resume_shortcut(client, monkeypatch, tmp_path):
    from maverick import job_queue
    queue = job_queue.JobQueue(tmp_path / "jobs.db")
    monkeypatch.setattr(job_queue, "_default_db", lambda: tmp_path / "jobs.db")
    job_id = queue.enqueue("run_goal", {"goal_id": 1})
    with queue._conn() as c:
        c.execute("UPDATE jobs SET status='failed', attempts=2, recurrence_reconcile_required=1, "
                  "recurrence_payload=?, recurrence_id='r1' WHERE id=?",
                  ('{"cron": "0 9 * * *"}', job_id))
    data = client.get("/api/v1/admin/system/queue").json()
    stopped = data["stopped"][0]
    assert stopped["what"] == "Run a task" and stopped["needs_decision"] is True
    # A stale view (wrong attempt count) is refused, never resumed blind.
    assert client.post(f"/api/v1/admin/system/queue/{job_id}/resume", json={"attempts": 1}).status_code == 409
    assert TestClient(client.app, base_url="http://127.0.0.1").post(f"/api/v1/admin/system/queue/{job_id}/resume",
                                       json={"attempts": 2}).status_code == 403


def test_encryption_status_and_new_key_when_off(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    data = client.get("/api/v1/admin/system/encryption").json()
    assert data["enabled"] is False
    r = client.post("/api/v1/admin/system/encryption/review", json={"action": "rotate"})
    assert r.status_code == 409


def test_diagnostics_shape(client):
    data = client.get("/api/v1/admin/system/diagnostics").json()
    assert set(data) == {"paused_services", "recent_calls"}


# ---- review fixes: audit, redaction and the right world database ---------

@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    monkeypatch.setattr(audit, "record_global", capture)
    return rows


def _reviewed_encryption(client, monkeypatch, action):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:ada", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:ada")
    review = client.post("/api/v1/admin/system/encryption/review", json={"action": action})
    if review.status_code != 200:
        return review
    value = review.json()
    path = "new-key" if action == "rotate" else "protect-older"
    return client.post("/api/v1/admin/system/encryption/" + path, json={
        "context": value["context"], "review": value["token"], "operation": "b" * 32, "confirm": True})


def test_legacy_resume_cannot_bypass_native_review_or_change_work(client, monkeypatch, tmp_path, audit_rows):
    from maverick import job_queue
    from maverick_dashboard import auth
    monkeypatch.setattr(job_queue, "_default_db", lambda: tmp_path / "jobs.db")
    def forbidden(*args, **kwargs):
        raise AssertionError("The legacy shortcut must not change the native queue")

    monkeypatch.setattr(job_queue.JobQueue, "reconcile_recurrence", forbidden)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:ada")
    from maverick_dashboard import rbac
    rbac.set_role("user:ada", "admin")
    r = client.post("/api/v1/admin/system/queue/5/resume", json={"attempts": 2})
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["href"] == "/automations?recover_schedule=5"
    rows = [row for row in audit_rows if row.get("verb") == "queue_resume"]
    assert rows == []


def test_stopped_job_errors_are_redacted_like_the_action_center(client, monkeypatch, tmp_path):
    from maverick import job_queue
    monkeypatch.setattr(job_queue, "_default_db", lambda: tmp_path / "jobs.db")
    q = job_queue.JobQueue()
    q.enqueue("run_goal", {"title": "t"})
    job = q.claim()
    secret = "provider said: invalid x-api-key sk-ant-api03-" + "A" * 40  # pragma: allowlist secret
    q.fail(job.id, secret, max_attempts=1, expected_attempts=job.attempts)
    stopped = client.get("/api/v1/admin/system/queue").json()["stopped"][0]
    assert "sk-ant-api03-AAAA" not in stopped["technical"]
    assert "REDACTED" in stopped["technical"]
    summary = client.get("/api/v1/queue/summary").json()["failed_items"][0]
    assert stopped["technical"] == summary["detail"][:300]


def test_encryption_maintenance_uses_the_workspace_world(client, monkeypatch, tmp_path, audit_rows):
    from maverick import crypto_at_rest, encryption_migrate, paths
    from maverick_dashboard import system_checks_api as sc

    with paths.tenant_scope(tenant="acme"):
        from maverick_dashboard import _shared
        expected = _shared._world().path
        assert str(sc._world_db()) == str(expected)
        assert "acme" in str(sc._world_db())

    seen: list[str] = []

    def fake_migrate(db, dry_run=False, backup=False):
        seen.append(str(db))
        return {"turns.content": 3}

    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)
    monkeypatch.setattr(encryption_migrate, "migrate_world_db", fake_migrate)
    monkeypatch.setattr(sc, "_world_db", lambda: tmp_path / "chosen.db")
    (tmp_path / "chosen.db").write_bytes(b"")
    assert client.get("/api/v1/admin/system/encryption").json()["older_unprotected"] == 3
    r = _reviewed_encryption(client, monkeypatch, "protect")
    assert r.status_code == 200 and r.json()["protected"] == 3
    assert seen and all(path == str(tmp_path / "chosen.db") for path in seen)
    rows = [row for row in audit_rows if row.get("record_type") == "encryption_maintenance"]
    assert [row["action"] for row in rows] == ["maintenance_authorized", "maintenance_completed"]
    assert all(row["actor"] == "user:ada" for row in rows)


def test_encryption_maintenance_says_plainly_when_the_database_is_shared(
    client, monkeypatch, audit_rows,
):
    from maverick import crypto_at_rest, encryption_migrate
    from maverick import world_model_backends as backends

    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)

    def never(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("migrate must not run against a local file")

    monkeypatch.setattr(encryption_migrate, "migrate_world_db", never)
    data = client.get("/api/v1/admin/system/encryption").json()
    assert data["older_unprotected"] is None
    assert data["older_note"] and "cannot" in data["older_note"]
    r = _reviewed_encryption(client, monkeypatch, "protect")
    assert r.status_code == 409
    assert "protected" not in r.json()
    assert not [row for row in audit_rows if row.get("record_type") == "encryption_maintenance"]


def test_new_encryption_key_is_recorded(client, monkeypatch, audit_rows):
    from maverick import crypto_at_rest
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(crypto_at_rest, "rotate_at_rest_key", lambda **kwargs: None)
    r = _reviewed_encryption(client, monkeypatch, "rotate")
    assert r.status_code == 200, r.text
    rows = [row for row in audit_rows if row.get("record_type") == "encryption_maintenance"]
    assert [row["action"] for row in rows] == ["maintenance_authorized", "maintenance_completed"]
    assert all(row["actor"] == "user:ada" for row in rows)


# ---- one-button checks, the organisation's data, tidying up ----------------


def test_key_completion_waits_for_original_audit_without_repeating_rotation(client, monkeypatch):
    import maverick.audit as audit
    from maverick import crypto_at_rest

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(audit, "record_global", lambda kind, **value: value.get("action") != "maintenance_completed")
    result = _reviewed_encryption(client, monkeypatch, "rotate")
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "receipt_pending"
    assert "completed" in result.json()["message"]
    assert len(list(crypto_at_rest._keyring_dir().glob("*.key"))) == 1
    path = "/api/v1/admin/system/encryption/actions/" + "b" * 32
    assert client.get(path).json()["receipt"]["state"] == "receipt_pending"
    monkeypatch.setattr(audit, "record_global", lambda kind, **value: True)
    assert client.get(path).json()["receipt"]["state"] == "confirmed"
    assert len(list(crypto_at_rest._keyring_dir().glob("*.key"))) == 1


def test_key_review_requires_fresh_authentication_before_rotation(client, monkeypatch):
    from fastapi import HTTPException
    from maverick import crypto_at_rest
    from maverick_dashboard import step_up

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")

    def refuse(request, operation):
        assert operation == "rotate_keys"
        raise HTTPException(403, "Sign in with your authenticator again.")

    monkeypatch.setattr(step_up, "require_recent_mfa", refuse)
    response = client.post("/api/v1/admin/system/encryption/review", json={"action": "rotate"})
    assert response.status_code == 403
    assert not list(crypto_at_rest._keyring_dir().glob("*.key"))

def _as(monkeypatch, role: str, who: str):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def test_maintenance_page_offers_the_new_checks_in_plain_words(client):
    text = visible_text(client.get("/settings").text)
    for label in ("Check protections", "Check connections", "Check hardware", "Check add-ons",
                  "Show data status", "See what would be removed", "Tidy up old records",
                  "Your organisation's data"):
        assert label in text, label
    for word in BANNED:
        assert word not in text, word


def test_one_button_checks_need_the_audit_permission(client, monkeypatch):
    paths = ("enterprise-check", "offline-check", "hardware-check", "plugin-check")
    _as_viewer(monkeypatch)
    for path in paths:
        assert client.get(f"/api/v1/admin/system/{path}").status_code == 403, path
    _as(monkeypatch, "auditor", "user:aud")
    for path in paths:
        r = client.get(f"/api/v1/admin/system/{path}")
        assert r.status_code == 200, path
        body = r.json()
        assert body["summary"] and body["summary"][0].isalnum() and body["summary"].endswith(".")
        for word in ("[", "MAVERICK_", "maverick "):
            assert word not in body["summary"], (path, word)
    # Reading the organisation's data status is an installation administrator job.
    assert client.get("/api/v1/admin/system/client").status_code == 403


def test_regulated_deployment_check_keeps_kernel_wording_in_the_details(client, monkeypatch):
    from maverick import deployment
    monkeypatch.setattr(deployment, "verify_deployment", lambda: [
        deployment.GuaranteeCheck("Egress lock", False, "enable [enterprise] mode = true"),
        deployment.GuaranteeCheck("At-rest encryption", True, "sealed")])
    body = client.get("/api/v1/admin/system/enterprise-check").json()
    assert body["passed"] is False
    assert body["checks"] == [{"label": "Data cannot be sent to outside AI services", "ok": False},
                              {"label": "Saved data is encrypted", "ok": True}]
    assert "1 protection" in body["summary"]
    assert body["technical"][0]["text"] == "Egress lock: enable [enterprise] mode = true"


def test_offline_check_groups_findings_into_plain_reasons(client, monkeypatch):
    from maverick import air_gap
    monkeypatch.setattr(air_gap, "audit", lambda: {"clean": False, "violations": [
        "remote model(s) in use: claude", "[sandbox] allow_network is on",
        "[observability] sentry_dsn is set", "[sandbox] backend=local uses the host network"]})
    body = client.get("/api/v1/admin/system/offline-check").json()
    assert body["reasons"] == ["An AI model is reached over the internet.", "The task workspace can reach the network.",
                               "Error reports are sent to another computer."]
    assert len(body["technical"]) == 4


def test_plugin_check_names_each_mismatch(client, monkeypatch):
    from maverick import plugin_lock
    monkeypatch.setattr(plugin_lock, "verify_lock", lambda: {
        "ok": False, "unlocked": False, "drifted": [("acme-tools", "1.0", "1.2")],
        "missing": ["gone-plugin"], "unpinned": []})
    body = client.get("/api/v1/admin/system/plugin-check").json()
    assert body["ok"] is False and len(body["problems"]) == 2
    assert "acme-tools is a different version" in body["problems"][0]


def test_organisation_data_download_and_erase(client, monkeypatch, tmp_path, audit_rows):
    from maverick import client as client_binding
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", "00" * 32)  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client_binding.reset_client_cache()
    try:
        from maverick import world_model
        world = world_model.open_world()
        world.create_goal("Acme task")
        status = client.get("/api/v1/admin/system/client").json()
        assert status["bound"] is True and status["organisation"] == "acme"
        assert "Lightwork must be stopped" in status["summary"]
        assert "Other workspaces" in status["summary"]
        started = client.post("/api/v1/admin/system/client/export")
        assert started.status_code == 202, started.text
        job = started.json()["job"]
        import time as _time
        for _ in range(200):
            state = client.get(f"/api/v1/admin/system/client/export/{job}").json()
            if state["state"] != "running":
                break
            _time.sleep(0.05)
        assert state["state"] == "ready", state
        exported = client.get(f"/api/v1/admin/system/client/export/{job}/download")
        assert exported.status_code == 200, exported.text
        assert "attachment" in exported.headers["content-disposition"] and exported.content
        assert client.get("/api/v1/admin/system/client/export/" + "0" * 32).status_code == 404
        assert TestClient(client.app, base_url="http://127.0.0.1").post("/api/v1/admin/system/client/export").status_code == 403
        preview = client.get("/api/v1/admin/system/client/erase/preview").json()
        assert preview["organisation"] == "acme" and preview["files"] >= 1
        assert preview["keeps_activity_record"] is True
        assert all(area["label"] and area["files"] for area in preview["areas"])
        erase = "/api/v1/admin/system/client/erase"
        assert client.post(erase, json={"organisation": "acme", "confirm": False}).status_code == 409
        wrong = client.post(erase, json={"organisation": "other", "confirm": True})
        assert wrong.status_code == 409 and "changed" in wrong.json()["detail"]
        refused = client.post(erase, json={"organisation": "acme", "confirm": True,
                                           "keep_activity_record": True})
        assert refused.status_code == 409 and "Nothing was erased" in refused.json()["detail"]
        assert world.list_goals()
        # The kernel offboarding operation is exercised against a quiesced
        # client store. A live HTTP request must not attempt this.
        world.close()
        done = client_binding.erase_client(keep_audit=True, actor="test administrator")
        assert done["kept_audit"] is True
        from maverick.audit import verify_chain

        receipt_id = done["audit_event_id"]
        assert re.fullmatch(r"[0-9a-f]{32}", receipt_id)
        receipt_dir = tmp_path / "mvhome" / "client-erasure" / receipt_id
        receipt = receipt_dir / "events.ndjson"
        assert verify_chain(receipt, (receipt_dir / "verification-key.hex").read_text().strip()) == []
        import json

        events = [json.loads(line) for line in receipt.read_text().splitlines()]
        assert events[0]["kind"] == "client_erase_requested"
        assert events[-1]["kind"] == "client_erased"
        assert events[-1]["status"] == "completed"
        downloaded_receipt = client.get(f"/api/v1/admin/system/client/erase/receipt/{receipt_id}")
        assert downloaded_receipt.status_code == 200
        assert downloaded_receipt.headers["cache-control"] == "private, no-store"
        assert "attachment" in downloaded_receipt.headers["content-disposition"]
        assert downloaded_receipt.json()["events_ndjson"] == receipt.read_text()
        assert downloaded_receipt.json()["verification_key"] == (receipt_dir / "verification-key.hex").read_text().strip()
        assert client.get("/api/v1/admin/system/client/erase/receipt/not-a-receipt").status_code == 404
        receipt.write_text(receipt.read_text() + '{"kind":"forged"}\n')
        assert client.get(f"/api/v1/admin/system/client/erase/receipt/{receipt_id}").status_code == 503
        verbs = [row.get("verb") for row in audit_rows]
        assert verbs.count("client_export") == 1
    finally:
        monkeypatch.delenv("MAVERICK_CLIENT_ID")
        client_binding.reset_client_cache()


def test_erase_is_refused_without_a_named_organisation(client, monkeypatch):
    from maverick import client as client_binding
    client_binding.reset_client_cache()
    # The fixture binds this installation to another organisation.
    r = client.post("/api/v1/admin/system/client/erase", json={"organisation": "acme", "confirm": True})
    assert r.status_code == 409 and "nothing was erased" in r.json()["detail"].lower()
    _as_viewer(monkeypatch)
    assert client.post("/api/v1/admin/system/client/erase",
                       json={"organisation": "acme", "confirm": True}).status_code == 403
    assert client.post("/api/v1/admin/system/client/export").status_code == 403
    assert client.get("/api/v1/admin/system/client/erase/preview").status_code == 403


def test_live_erase_refuses_before_kernel_mutation(client, monkeypatch):
    from maverick import client as client_binding

    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    client_binding.reset_client_cache()
    monkeypatch.setattr(client_binding, "erase_client", lambda **_kwargs: pytest.fail("live erase reached the kernel"))
    try:
        response = client.post("/api/v1/admin/system/client/erase", json={
            "organisation": "acme", "confirm": True, "keep_activity_record": False,
        })
        assert response.status_code == 409
        assert "Nothing was erased" in response.json()["detail"]
    finally:
        client_binding.reset_client_cache()


def _old_conversation(user: str) -> None:
    import time as _time

    from maverick import world_model
    world = world_model.open_world()
    world.get_or_create_conversation("web", user)
    with world._writing() as conn:
        conn.execute("UPDATE conversations SET last_seen = ?", (_time.time() - 200 * 86400,))


def test_tidy_up_previews_then_removes_in_this_workspace_only(client, monkeypatch, audit_rows):
    _old_conversation("old-chat")
    preview = client.get("/api/v1/admin/system/cleanup/preview?days=90&activity_days=30").json()
    assert preview["conversations"] == 1
    assert client.get("/api/v1/admin/system/cleanup/preview?days=5&activity_days=30").status_code == 422
    assert client.post("/api/v1/admin/system/cleanup",
                       json={"days": 90, "activity_days": 30, "confirm": False}).status_code == 409
    # Another workspace sees none of this workspace's records.
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    dash_app._world_cache.clear()
    assert client.get("/api/v1/admin/system/cleanup/preview?days=90&activity_days=30").json()["conversations"] == 0
    monkeypatch.delenv("MAVERICK_TENANT")
    dash_app._world_cache.clear()
    done = client.post("/api/v1/admin/system/cleanup", json={"days": 90, "activity_days": 30, "confirm": True})
    assert done.status_code == 200 and done.json()["conversations"] == 1
    assert client.get("/api/v1/admin/system/cleanup/preview?days=90&activity_days=30").json()["conversations"] == 0
    rows = [row for row in audit_rows if row.get("verb") == "records_cleanup"]
    assert len(rows) == 1 and rows[0]["actor"] and rows[0]["conversations"] == 1
    assert TestClient(client.app, base_url="http://127.0.0.1").post("/api/v1/admin/system/cleanup",
                                       json={"days": 90, "activity_days": 30, "confirm": True}).status_code == 403
    _as_viewer(monkeypatch)
    assert client.get("/api/v1/admin/system/cleanup/preview?days=90&activity_days=30").status_code == 403
