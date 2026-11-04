"""Workforce, Tasks and Savings buttons for commands that were terminal-only:
the specialist inventory (and its download), the setup check, the test-suite
check, tasks coming due and adding an outside agent to shared memory."""
from __future__ import annotations

import json
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
API = "/api/v1/workforce-ops"
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|allow_tools|max_risk|"
    r"deny_tools|knowledge_sources|domain pack|pack|lint|mutator)\b|/api/v1|HTTP \d{3}|maverick ",
    re.IGNORECASE,
)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import learning_jobs
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_FLEET_MEMORY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit
    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True
    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _configure(body: str) -> None:
    from maverick import config
    with open(os.environ["MAVERICK_CONFIG"], "w", encoding="utf-8") as fh:
        fh.write(body + "\n")
    config.reset_config_cache()


def _wait(client, started, timeout: float = 60.0) -> dict:
    job = started.json()["job"]
    deadline = time.time() + timeout
    while job["state"] in ("admitted", "running", "stopping"):  # an admitted job has not started yet
        assert time.time() < deadline, job
        time.sleep(0.1)
        job = client.get(f"/api/v1/learning-ops/jobs/{job['id']}").json()["job"]
    return job


def test_changes_and_downloads_need_a_workspace_admin(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get(f"{API}/inventory/download").status_code == 403
    assert client.post(f"{API}/setup-check", json={}).status_code == 403
    assert client.post(f"{API}/outside-agents", json={"vendor": "custom", "name": "bot-1"}).status_code == 403
    for path in (f"{API}/inventory", f"{API}/test-suite", f"{API}/upcoming", f"{API}/outside-agents/vendors"):
        assert client.get(path).status_code == 200, path


def test_inventory_summarises_every_specialist_in_plain_words(client, monkeypatch, audit_rows):
    from maverick.departments import department_title

    inv = client.get(f"{API}/inventory").json()
    assert inv["specialists"] > 0 and inv["suites"]
    assert all(row["label"] == department_title(row["value"]) for row in inv["suites"])
    assert [row["label"] for row in inv["suites"]] == sorted(row["label"] for row in inv["suites"])
    assert inv["can_change_things_while_drafting"] == 0
    suite = inv["suites"][0]["value"]
    one = client.get(f"{API}/inventory", params={"suite": suite}).json()
    assert 0 < one["specialists"] <= inv["specialists"]
    assert client.get(f"{API}/inventory", params={"suite": "not-a-department"}).status_code == 422
    down = client.get(f"{API}/inventory/download", params={"suite": suite})
    assert down.status_code == 200 and "attachment" in down.headers["content-disposition"]
    doc = json.loads(down.text)
    assert doc["summary"]["packs"] == one["specialists"] and len(doc["packs"]) == one["specialists"]
    assert [r["verb"] for r in audit_rows] == ["specialist_inventory_download"]


def test_inventory_says_whether_independence_levels_are_on(client, monkeypatch):
    """The per-level split is only meaningful when levels are on, so the page
    needs to know which it is (it used to list the split either way)."""
    monkeypatch.delenv("MAVERICK_WORKFORCE_LEVELS", raising=False)
    assert client.get(f"{API}/inventory").json()["levels_enabled"] is False
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    assert client.get(f"{API}/inventory").json()["levels_enabled"] is True


def test_setup_check_runs_every_specialist_through_the_lint(client, monkeypatch):
    from maverick import domain
    real = domain.lint_profile
    seen: list[str] = []

    def lint(profile):
        seen.append(profile.name)
        errors, warnings = real(profile)
        if len(seen) == 1:
            errors = errors + ["allow_tools is empty: an empty allowlist grants ALL tools"]
        return errors, warnings
    monkeypatch.setattr(domain, "lint_profile", lint)
    done = _wait(client, client.post(f"{API}/setup-check", json={}))
    assert done["state"] == "done", done
    result = done["result"]
    assert result["specialists"] == len(seen) and result["must_fix"] >= 1
    first = result["findings"][0]
    assert "It has no list of allowed tools, so it could use every tool." in first["must_fix"]
    plain = " ".join(" ".join(f["must_fix"] + f["could_improve"]) for f in result["findings"])
    assert not _BANNED.search(plain), _BANNED.search(plain)


def test_test_suite_check_lists_cases_plainly(client):
    from maverick.domain_eval import GOLDEN_CASES
    d = client.get(f"{API}/test-suite").json()
    assert d["cases"] == len(GOLDEN_CASES) and d["problems"] == 0
    assert d["list"] and d["list"][0]["expects"]


def test_upcoming_tasks_are_overdue_first_and_scoped_to_the_person(client, monkeypatch):
    from maverick.world_model import open_world
    world = open_world()
    now = time.time()
    mine = world.create_goal("Renew the supplier contract", owner="user:ann")
    late = world.create_goal("File the quarterly return", owner="user:ann", domain="finance_vat")
    foreign = world.create_goal("Bob private task", owner="user:bob")
    far = world.create_goal("Plan next year", owner="user:ann")
    with world._writing() as conn:
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now + 3 * 86400, mine))
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now - 86400, late))
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now + 45 * 86400, far))
        conn.execute("UPDATE goals SET deadline=? WHERE id=?", (now - 2 * 86400, foreign))
    assert client.get(f"{API}/upcoming", params={"days": 30}).json()["tasks"] == []
    _as(monkeypatch, "viewer", "user:ann")
    rows = client.get(f"{API}/upcoming", params={"days": 30}).json()["tasks"]
    assert [r["title"] for r in rows] == ["File the quarterly return", "Renew the supplier contract"]
    assert rows[0]["overdue"] is True and rows[0]["department"] == "finance vat"
    assert len(client.get(f"{API}/upcoming", params={"days": 60}).json()["tasks"]) == 3
    assert client.get(f"{API}/upcoming", params={"days": 5}).status_code == 422
    _as(monkeypatch, "viewer", "user:ann")
    rows = client.get(f"{API}/upcoming", params={"days": 90}).json()["tasks"]
    assert sorted(r["title"] for r in rows) == [
        "File the quarterly return", "Plan next year", "Renew the supplier contract"]


def test_outside_agents_join_shared_memory_through_the_kernel(client, monkeypatch, audit_rows):
    from maverick import fleet_memory
    _configure("[fleet_memory]\nenable = false")
    off = client.post(f"{API}/outside-agents", json={"vendor": "custom", "name": "billing-bot"})
    assert off.status_code == 409 and "Turn on “Fleet memory” under Learning systems" in off.json()["detail"]
    _configure("[fleet_memory]\nenable = true")
    assert client.post(f"{API}/outside-agents", json={"vendor": "custom", "name": "../x"}).status_code == 422
    assert client.post(f"{API}/outside-agents", json={"vendor": "acme", "name": "bot"}).status_code == 422
    ok = client.post(f"{API}/outside-agents", json={"vendor": "salesforce", "name": "billing-bot",
                                                   "description": "Chases  invoices"})
    assert ok.json() == {"added": True, "agent": "billing-bot", "vendor": "Salesforce Agentforce"}
    assert [r["source"] for r in fleet_memory.roster()] == ["salesforce:billing-bot"]
    clash = client.post(f"{API}/outside-agents", json={"vendor": "microsoft", "name": "billing-bot"})
    assert clash.status_code == 409
    assert [r["verb"] for r in audit_rows if r.get("verb")] == ["fleet_memory_register", "fleet_memory_register"]


def test_pages_show_the_new_controls_in_plain_words(client):
    page = client.get("/workforce").text
    for control in ("wo-inv-suite", "wo-inv-download", "wo-lint-run", "wo-suite"):
        assert f'id="{control}"' in page, control
    own = page.split('id="wo-root"', 1)[1]
    visible = re.sub(r"<[^>]+>", " ", re.sub(r"<style[\s\S]*?</style>|<script[\s\S]*?</script>", " ", own))
    assert "What each agent and specialist can do" in visible
    assert not _BANNED.search(visible), _BANNED.search(visible)
    tasks = client.get("/goals").text
    assert 'id="wo-upcoming-root"' in tasks and 'id="wo-up-days"' in tasks
    savings = client.get("/savings").text
    assert 'id="vp-fleet-add"' in savings and 'id="vp-fleet-vendor"' in savings
