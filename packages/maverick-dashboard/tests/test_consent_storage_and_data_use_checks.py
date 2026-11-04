"""Consent record storage settings and move, and the background data-use checks."""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
_ST = "consent_preferences.storage"
_DU = "data_use_governance.scheduler"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, consent_storage, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_TENANT", consent_storage.BACKEND_ENV, consent_storage.DEFAULT_DSN_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(consent_storage, "driver_available", lambda: True)
    config.reset_config_cache()
    consent_storage._reset_for_testing()
    yield
    consent_storage._reset_for_testing()
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **p: rows.append({"kind": kind, **p}))
    return rows


def _save(changes, confirm=True):
    from test_support.settings_pages import save_catalog

    return save_catalog(client, API, json={"changes": [{"id": k, "value": v} for k, v in changes.items()],
                                  "confirm": confirm})


# ------------------------------------------------------------- consent storage
def test_shared_consent_storage_needs_a_connection_first(audit_rows):
    r = _save({f"{_ST}.backend": "postgres"})
    assert r.status_code == 400 and "Shared consent database connection" in r.json()["message"]
    assert audit_rows == []


def test_switching_needs_confirmation_and_reaches_the_reader(audit_rows):
    from maverick import config, consent_storage

    dsn = "postgresql://consent@db.example.com/consent"  # pragma: allowlist secret
    first = _save({f"{_ST}.dsn": dsn, f"{_ST}.backend": "postgres"}, confirm=False)
    assert first.status_code == 409
    assert {c["id"] for c in first.json()["confirm"]} >= {f"{_ST}.backend"}
    r = _save({f"{_ST}.dsn": dsn, f"{_ST}.backend": "postgres"})
    assert r.status_code == 200 and dsn not in r.text and r.json()["restart"] is True
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert dsn not in stored  # sealed
    config.reset_config_cache()
    chosen = consent_storage.storage_settings()
    assert chosen.backend == "postgres" and chosen.dsn == dsn
    assert consent_storage.shared() is True
    assert all(a.get("new") == "set" for a in audit_rows if a.get("key") == "dsn")


def test_a_connection_set_on_the_server_is_enough_and_wins(monkeypatch, audit_rows):
    from maverick import config, consent_storage

    monkeypatch.setenv("ACME_CONSENT_DSN", "postgresql://env@db/consent")
    r = _save({f"{_ST}.dsn_secret_ref": "$ACME_CONSENT_DSN", f"{_ST}.backend": "postgres"})
    assert r.status_code == 200, r.text
    config.reset_config_cache()
    assert consent_storage.storage_settings().dsn == "postgresql://env@db/consent"


def test_the_driver_must_be_installed(monkeypatch, audit_rows):
    from maverick import consent_storage

    monkeypatch.setattr(consent_storage, "driver_available", lambda: False)
    r = _save({f"{_ST}.dsn": "postgresql://x@db/y", f"{_ST}.backend": "postgres"})
    assert r.status_code == 400 and "driver" in r.json()["message"]


def test_move_preview_and_refusal_while_records_are_in_files(audit_rows):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    ConsentPreferenceStore(data_dir("consent_preferences", "consent-preferences.sqlite3",
                                    tenant="acme"))
    preview = client.get("/api/v1/admin/installation/consent-records").json()
    assert preview["shared"] is False and preview["ready"] is False
    assert "first choose the shared database" in preview["summary"]
    assert [s["store"] for s in preview["stores"]] == ["Consent choices and receipts"]
    assert client.post("/api/v1/admin/installation/consent-records/move",
                       json={"confirm": True}).status_code == 409
    assert client.post("/api/v1/admin/installation/consent-records/move",
                       json={}).status_code == 409
    assert TestClient(app, base_url="http://127.0.0.1").post("/api/v1/admin/installation/consent-records/move",
                                json={"confirm": True}).status_code == 403
    assert audit_rows == []


def test_move_runs_as_a_background_job_with_activity_rows(monkeypatch, audit_rows):
    from maverick import consent_storage
    from maverick_dashboard import ops_admin_jobs

    monkeypatch.setattr(consent_storage, "shared", lambda: True)
    monkeypatch.setattr(consent_storage, "move_local_records", lambda: {
        "moved": [{"workspace": "acme", "store": "consent-preferences", "copied": 3}],
        "refused": [], "copied": 3, "seconds": 0.1})
    r = client.post("/api/v1/admin/installation/consent-records/move", json={"confirm": True})
    assert r.status_code == 200
    job = ops_admin_jobs.wait(r.json()["job"]["id"])
    assert job["state"] == "done" and job["result"]["copied"] == 3
    assert "Copied 3 consent records" in job["result"]["summary"]
    verbs = [a["verb"] for a in audit_rows if a["kind"] == "control_plane_action"]
    assert verbs == ["consent_records_move_requested", "consent_records_moved"]


def test_maintenance_page_offers_the_consent_move():
    page = client.get("/settings").text
    assert 'data-ops-run="consent"' in page and "Consent records" in page


# ------------------------------------------------------------- data-use checks
@pytest.fixture()
def checks(monkeypatch, tmp_path):
    from maverick import config

    def configure(**values):
        lines = ["[data_use_governance.scheduler]"] + [
            f"{k} = {str(v).lower() if isinstance(v, bool) else v}" for k, v in values.items()]
        config.config_path().parent.mkdir(parents=True, exist_ok=True)
        config.config_path().write_text("\n".join(lines) + "\n", encoding="utf-8")
        config.reset_config_cache()

    return configure


def test_checks_do_nothing_when_off(checks):
    from maverick_dashboard import data_use_scheduler

    ran = []
    assert data_use_scheduler.cycle("w1", runner=lambda: ran.append(1) or {}) is False
    assert data_use_scheduler.start_data_use_scheduler() is False
    assert ran == []


def test_checks_run_when_on_and_a_claim_prevents_a_second_run(checks, audit_rows):
    from maverick_dashboard import data_use_scheduler

    checks(enable=True, poll_seconds=3600)
    runs = []
    runner = lambda: runs.append(1) or {"findings": 2, "workspaces_checked": 1}  # noqa: E731
    assert data_use_scheduler.cycle("w1", runner=runner) is True
    assert data_use_scheduler.cycle("w2", runner=runner) is False  # not due again for an hour
    assert runs == [1]
    rows = [a for a in audit_rows if a.get("verb") == "data_use_checks_ran"]
    assert len(rows) == 1 and rows[0]["findings"] == 2
    store = data_use_scheduler.job_store()
    assert store.history()[0]["summary"]["findings"] == 2


def test_a_held_claim_blocks_another_process_until_its_lease_ends(checks):
    from maverick.data_use_checks import CheckJobStore

    now = [1000.0]
    store = CheckJobStore(data_use_scheduler_path(), clock=lambda: now[0])
    token = store.claim("w1", lease_seconds=60)
    assert token and store.claim("w2", lease_seconds=60) is None
    now[0] += 61  # the first process stopped without finishing
    takeover = store.claim("w2", lease_seconds=60)
    assert takeover
    assert store.complete(token, started_at=1000, outcome="done", summary={},
                          poll_seconds=60, history_limit=5) is False  # lost its claim
    assert store.complete(takeover, started_at=1061, outcome="done", summary={},
                          poll_seconds=60, history_limit=5) is True


def data_use_scheduler_path():
    from maverick.paths import data_dir

    return data_dir("data_use_governance", "background-checks.sqlite3", tenant=None)


def test_history_keeps_only_the_latest_runs(checks):
    from maverick.data_use_checks import CheckJobStore

    now = [0.0]
    store = CheckJobStore(data_use_scheduler_path(), clock=lambda: now[0])
    for index in range(7):
        now[0] += 100
        token = store.claim("w", lease_seconds=30)
        store.complete(token, started_at=now[0], outcome="done", summary={"n": index},
                       poll_seconds=5, history_limit=3)
    assert [h["summary"]["n"] for h in store.history()] == [6, 5, 4]


def test_the_checks_find_stale_decisions_and_ended_exceptions():
    from maverick.data_use_checks import check_workspace, summarize
    from maverick.data_use_governance import DataUseCorruptionError
    from maverick.data_use_policy_compiler import DataUseCompilationStale

    class Store:
        def unified_audit_records(self, tenant):
            raise DataUseCorruptionError("tampered")

        def list_records(self, tenant, kind, limit):
            if kind == "decision":
                return [{"decision_id": "d1", "outcome": "allow"},
                        {"decision_id": "d2", "outcome": "mask"},
                        {"decision_id": "d3", "outcome": "deny"}]
            return [{"state": "approved", "expires_at": 10.0},
                    {"state": "requested", "expires_at": 10.0},
                    {"state": "approved", "expires_at": 99_999.0}]

    class Compiler:
        def compile(self, tenant, decision_id):
            if decision_id == "d2":
                raise DataUseCompilationStale("stale")
            return {}

    counts = check_workspace(Store(), "acme", compiler=Compiler(), now=1000.0)
    assert counts["change_record_broken"] == 1 and counts["decisions_current"] == 1
    assert counts["decisions_stale"] == 1 and counts["exceptions_ended"] == 1
    assert counts["exceptions_lapsed"] == 1
    summary = summarize([("acme", counts), ("beta", None)])
    assert summary["findings"] == 4 and summary["workspaces_with_findings"] == ["acme"]
    assert summary["workspaces_failed"] == 1


def test_the_scheduler_starts_when_on_and_stops_at_shutdown(checks, monkeypatch):
    from maverick_dashboard import data_use_scheduler

    checks(enable=True, poll_seconds=5)
    ran = threading.Event()
    monkeypatch.setattr(data_use_scheduler, "run_pass", lambda: ran.set() or {})
    monkeypatch.setattr(data_use_scheduler, "cycle",
                        lambda worker_id: ran.set() or True)
    assert data_use_scheduler.start_data_use_scheduler() is True
    assert ran.wait(5)
    assert data_use_scheduler.stop_data_use_scheduler(timeout=5) is True
    assert data_use_scheduler._scheduler_thread is None


def test_settings_rows_reach_the_reader_and_status_route(checks, audit_rows):
    from maverick import config, data_use_checks

    r = _save({f"{_DU}.enable": True, f"{_DU}.poll_seconds": 600,
               f"{_DU}.lease_seconds": 120, f"{_DU}.history_limit": 10})
    assert r.status_code == 200, r.text
    config.reset_config_cache()
    assert data_use_checks.check_settings() == data_use_checks.CheckSettings(True, 600, 120, 10)
    status = client.get("/api/v1/data-use/background-checks")
    assert status.status_code == 200 and status.json()["enabled"] is True
    assert _save({f"{_DU}.enable": False}, confirm=False).status_code == 409
