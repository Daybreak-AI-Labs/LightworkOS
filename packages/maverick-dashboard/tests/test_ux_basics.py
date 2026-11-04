"""Dashboard UX basics: the shell (sidebar, docs links, emergency-stop banner),
readable times, and an activity log that records every administrator change.
"""
from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

from test_support.channel_review import channel_review_token

_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick_dashboard.rbac as rbac
    roles_dir = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles_dir / "dashboard-users.json")
    monkeypatch.setattr(rbac, "tenant_store_path", lambda: roles_dir / "dashboard-tenant-roles.json")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=_ORIGIN)


def _logs(monkeypatch, tmp_path):
    """Separate workspace and deployment-wide chains, both under tmp."""
    import maverick.audit as audit
    from maverick.audit import reader, writer
    from maverick.audit.writer import AuditLog
    local = AuditLog(tmp_path / "audit-local")
    global_log = AuditLog(tmp_path / "audit-global")
    monkeypatch.setattr(audit, "default_audit_log", lambda: local)
    monkeypatch.setattr(writer, "default_audit_log", lambda: local)
    monkeypatch.setattr(audit, "global_audit_log", lambda: global_log)
    monkeypatch.setattr(writer, "global_audit_log", lambda: global_log)
    # The activity page streams signed segments through the reader rather
    # than using AuditLog.tail; direct the reader at the same fixture chain.
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda tenant: local.audit_dir)
    return local, global_log


# ---- shell -----------------------------------------------------------------

def test_shell_has_quick_links_docs_link_and_halt_banner():
    body = _client().get("/goals").text
    assert 'aria-label="Most used"' in body
    for href in ("/chat", "/goals", "/approvals", "/deliverables", "/settings"):
        assert f'<li><a href="{href}"' in body
    # One aria-current landmark for the active page, not two.
    assert body.count('aria-current="page"') == 1
    assert 'href="https://daybreak-ai-labs.github.io/LightworkOS/starter-goals/"' in body
    assert "Learn more about tasks in the documentation" in body
    assert 'id="halt-banner"' in body and "Work is stopped." in body
    assert "Work is not stopped" not in body


def test_chat_shell_and_error_page_carry_the_halt_banner():
    client = _client()
    assert 'id="halt-banner"' in client.get("/chat").text
    missing = client.get("/no-such-page", headers={"Accept": "text/html"})
    assert missing.status_code == 404
    assert 'id="halt-banner"' in missing.text
    assert "Work is not stopped" not in missing.text


def test_docs_mapping_prefers_the_most_specific_page():
    from maverick_dashboard.docs_links import DOCS_HOME, learn_more_for
    assert learn_more_for("/security/assurance")["url"] == DOCS_HOME + "MODEL_RISK_ASSURANCE/"
    assert learn_more_for("/security")["url"] == DOCS_HOME + "SECURITY_GRC/"
    assert learn_more_for("/goals/12/plan")["label"] == "tasks"
    assert learn_more_for("/no-such-page") is None


# ---- times -----------------------------------------------------------------

def test_datetime_filter_renders_a_time_element_with_date_and_zone():
    from maverick_dashboard.app import _format_datetime
    html = str(_format_datetime(1790790000))
    assert html.startswith('<time datetime="2026-09-30T')
    assert 'data-mv-time="1790790000.000"' in html
    assert "30 Sept 2026" in html and "UTC" in html
    assert str(_format_datetime(1790790000, "absolute")).count('data-mv-time-mode="absolute"') == 1
    assert _format_datetime(None) == "-"


def test_datetime_filter_reads_one_format_from_epochs_iso_text_and_calendar_days():
    from maverick_dashboard.app import _format_datetime
    # 2026-10-04 14:01:12 UTC: day without a leading zero, 24-hour clock, zone.
    assert ">4 Oct 2026, 14:01 UTC</time>" in str(_format_datetime(1791122472))
    iso = str(_format_datetime("2026-10-04T15:01:12+01:00", "absolute"))
    assert ">4 Oct 2026, 14:01 UTC</time>" in iso and 'data-mv-time="1791122472.000"' in iso
    assert ">4 Oct 2026, 14:01 UTC</time>" in str(_format_datetime("2026-10-04T14:01:12Z"))
    day = str(_format_datetime("2026-10-04", "date"))
    assert day == ('<time datetime="2026-10-04" data-mv-time="2026-10-04"'
                   ' data-mv-time-mode="date">4 Oct 2026</time>')
    assert ">4 Oct 2026</time>" in str(_format_datetime(1791122472, "date"))
    assert _format_datetime("not a time") == "not a time"


def test_plain_datetime_text_is_the_datetime_filter_text():
    from maverick_dashboard.plain_labels import datetime_text
    assert datetime_text(1791122472) == "4 Oct 2026, 14:01 UTC"
    assert datetime_text(1791122472, seconds=True) == "4 Oct 2026, 14:01:12 UTC"
    assert datetime_text(1791122472, date_only=True) == "4 Oct 2026"
    assert datetime_text(None) == datetime_text("soon") == datetime_text(True) == ""
    assert datetime_text(1790790000, date_only=True) == "30 Sept 2026"  # as browsers write it


def test_money_and_percent_filters_use_one_format():
    from maverick_dashboard.app import templates
    money, percent = templates.env.filters["money"], templates.env.filters["percent"]
    assert money(1234.5) == "$1,234.50"
    assert money(0) == money(None) == money("n/a") == "$0.00"
    assert money(-5) == "-$5.00"
    assert money(0.0004) == "under $0.01"
    assert money(0.003, decimals=4) == "$0.0030"  # labelled per-unit prices only
    assert money(75, currency="eur") == "EUR 75.00"
    assert percent(0) == "0%" and percent(37.46) == "37.5%" and percent(100.0) == "100%"
    assert percent(12.04) == "12%" and percent(None) == "0%"


# ---- activity log ----------------------------------------------------------

def test_activity_log_records_invites_channels_and_workspace_pauses(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    # Invites require a named administrator: the static token grants one.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "ux-basics-admin-token")  # pragma: allowlist secret
    local, global_log = _logs(monkeypatch, tmp_path)
    client = _client()
    client.headers["Authorization"] = "Bearer ux-basics-admin-token"

    r = client.post("/users/invite", data={"email": "bob@example.test", "role": "viewer"})
    assert r.status_code == 200, r.text
    assert "/auth/invite/" in r.text  # the one-time link is shown
    r = client.post("/channels/save", data={"channel": "slack", "enabled": "on",
                                            "review_token": channel_review_token(client),
                                            "app_token": "xapp-1", "bot_token": "xoxb-1"},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
    r = client.post("/api/v1/admin/tenants", json={"id": "acme", "display_name": "Acme"})
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/admin/tenants/acme/suspend")
    assert r.status_code == 200, r.text

    kinds = [e["kind"] for e in local.tail(50)]
    actions = [e.get("action") for e in local.tail(50)]
    assert "invite_created" in actions and "channel_saved" in actions
    assert "tenant_created" in [e["kind"] for e in global_log.tail(50)]
    assert "tenant_suspended" in [e["kind"] for e in global_log.tail(50)]
    assert "control_plane_action" in kinds
    # Secrets never reach the log: only the field names that were set.
    saved = next(e for e in local.tail(50) if e.get("action") == "channel_saved")
    assert "xoxb-1" not in str(saved) and saved["fields"] == ["app_token", "bot_token"]

    page = client.get("/audit").text
    assert "Invite created" in page
    assert "Channel saved" in page
    assert "bob@example.test" not in page  # the invite recipient is private content
    assert "xapp-1" not in page and "xoxb-1" not in page
    assert "Workspace paused" in page and "Workspace created" in page
    assert 'aria-labelledby="aud-deployment-title"' in page
    assert "Recent deployment activity" in page  # separate chain, outside workspace pagination
    # Newest first by default, with a toggle.
    assert "Showing newest first." in page and "order=oldest" in page
    workspace_table = page.split('<table id="audit-table">', 1)[1].split('</table>', 1)[0]
    rows = re.findall(r'data-mv-time="([0-9.]+)" data-mv-time-mode="absolute"', workspace_table)
    assert rows and rows == sorted(rows, reverse=True)
    oldest = client.get("/audit?order=oldest").text
    workspace_table_oldest = oldest.split('<table id="audit-table">', 1)[1].split('</table>', 1)[0]
    rows_asc = re.findall(r'data-mv-time="([0-9.]+)" data-mv-time-mode="absolute"', workspace_table_oldest)
    assert rows_asc == sorted(rows_asc)


def test_activity_log_hides_machine_ids_and_never_shows_raw_epochs(monkeypatch, tmp_path):
    local, _ = _logs(monkeypatch, tmp_path)
    from maverick.audit.events import AuditEvent
    now = time.time()
    local.record(AuditEvent(ts=now, kind="approval_decision", payload={
        "approval_event_id": "approval-v1-" + "ab12" * 16, "approval_id": 7,
        "status": "approved", "decided_by": "user:owner@example.com", "occurred_at": now}))
    page = _client().get("/audit").text
    assert "e+09" not in page
    assert "Approval decided" in page and "Approved" in page
    # The projected metadata view omits machine identifiers and the request's
    # content, but names the person who decided (governance evidence, like the
    # actor on undo and confirmation rows). The owner chose this on 4 October,
    # reversing the 1 October choice to leave the decider's name out. Its event
    # time is still rendered as a readable time.
    assert "approval-v1-" not in page
    assert re.search(r'Decided by</span>\s*<span class="aud-v">owner@example\.com</span>', page)
    assert "A person (name not shown)" not in page
    assert re.search(r'data-mv-time="[0-9.]+" data-mv-time-mode="absolute"', page)


# ---- task pages ------------------------------------------------------------

def _goal():
    from maverick_dashboard.app import _world
    w = _world()
    gid = w.create_goal("Summarize vendor contracts", "Summarize the top five vendor contracts")
    return w.get_goal(gid)


def test_goal_id_resolves_and_every_task_page_shares_the_tabs():
    client = _client()
    g = _goal()
    r = client.get(f"/goals/{g.id}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == f"/chat/goal/{g.id}"
    assert client.get("/goals/999999").status_code == 404
    for path in (f"/chat/goal/{g.id}", f"/goals/{g.id}/trajectory", f"/goals/{g.id}/plan", f"/goals/{g.id}/errors"):
        body = client.get(path).text
        assert 'aria-label="Task pages"' in body, path
        for tab in (f'href="/chat/goal/{g.id}"', f'href="/goals/{g.id}/trajectory"',
                    f'href="/goals/{g.id}/plan"', f'href="/goals/{g.id}/errors"'):
            assert tab in body, (path, tab)
        bar = body[body.index('aria-label="Task pages"'):]
        bar = bar[:bar.index("</nav>")]
        assert bar.count('aria-current="page"') == 1, path
    # A one-step task's plan page explains the missing map without claiming
    # the task already ran.
    plan = client.get(f"/goals/{g.id}/plan").text
    assert "This task has one step, so there is no map of smaller steps" in plan
    assert 'id="plan-tree-list"' in plan and "<noscript>" not in plan
    listing = client.get("/goals").text
    # The row link names its task for screen readers after the visible word.
    assert f'<a href="/chat/goal/{g.id}">Result<span class="sr-only">: Summarize vendor contracts</span></a>' in listing


# ---- owner creation --------------------------------------------------------

def test_fresh_install_opens_on_owner_creation_until_skipped(monkeypatch):
    from maverick_dashboard import local_owner
    monkeypatch.setattr(local_owner, "available", lambda request: True)
    client = _client()
    for path in ("/", "/start"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/auth/local-owner", path
    r = client.get("/start?owner=later", follow_redirects=False)
    assert r.status_code == 200 and "mvk_owner_later" in r.headers.get("set-cookie", "")
    client.cookies.set("mvk_owner_later", "1")
    assert client.get("/start", follow_redirects=False).status_code == 200


def test_owner_form_is_themed_with_confirm_and_show_passphrase(monkeypatch):
    from maverick_dashboard import local_owner
    monkeypatch.setattr(local_owner, "_local", lambda request, mutate=False: None)
    monkeypatch.setattr(local_owner, "available", lambda request: True)
    body = _client().get("/auth/local-owner").text
    assert 'lightwork.css' in body and 'class="public-shell' in body
    assert 'name="password2"' in body and 'id="owner-show"' in body
    assert 'id="owner-strength"' in body and 'href="/start?owner=later"' in body


def test_owner_setup_refuses_mismatched_passphrases(monkeypatch):
    from maverick_dashboard import local_owner
    monkeypatch.setattr(local_owner, "_local", lambda request, mutate=False: None)
    monkeypatch.setattr(local_owner, "available", lambda request: True)
    called = []
    monkeypatch.setattr(local_owner, "enroll", lambda *a, **k: called.append(k) or "token")
    r = _client().post("/auth/local-owner", data={"email": "o@example.com", "password": "a" * 20,
                                                  "password2": "b" * 20, "confirm": "yes"})
    assert r.status_code == 422 and "do not match" in r.text and not called


# ---- users, workspaces, results ----------------------------------------------

def test_departments_have_real_names_everywhere():
    from maverick.departments import department_title
    from maverick_dashboard import suite_grants
    for key in suite_grants.known_suites():
        title = department_title(key)
        assert " Cpg" not in title and "Esg" not in title and " Vc" not in title, key
    assert department_title("esg_sustainability") == "ESG & Sustainability"
    assert department_title("oil_gas") == "Oil & Gas"
    from maverick_dashboard import rbac
    rbac.set_role("user:pat@example.com", "viewer")  # the department picker needs a person to limit
    body = _client().get("/users").text
    assert "Food, Beverage &amp; Consumer Goods" in body and "Esg Sustainability" not in body
    assert "data-departments-filter" in body and "data-departments-all" in body


def test_workspaces_page_has_one_create_form_and_hides_plans_without_billing(monkeypatch):
    from maverick import billing_stripe
    monkeypatch.setattr(billing_stripe, "enabled", lambda: False)
    body = _client().get("/tenants").text
    assert 'id="tenant-add"' in body and 'id="tenant-keys"' in body
    assert 'id="tenant-onboard"' not in body and "Set up a new client in one step" not in body
    assert 'name="admin_email"' in body and 'id="tenant-invite"' in body
    assert 'name="plan"' not in body and "Enterprise" not in body
    assert "Advanced: workspace encryption keys" in body
    monkeypatch.setattr(billing_stripe, "enabled", lambda: True)
    assert 'name="plan"' in _client().get("/tenants").text


def test_results_page_shows_a_real_empty_state_and_a_typeahead():
    body = _client().get("/deliverables").text
    assert '<p class="mv-empty__title">No results yet</p>' in body
    assert '<a class="btn mv-empty__action" href="/chat">Start a task</a>' in body
    assert "deliverables in view" not in body and 'name="role"' not in body
    catalogue = _client().get("/deliverables?role=all").text
    assert "data-typeahead" in catalogue and "lightwork-typeahead.js" in catalogue


def test_channels_page_answers_json_for_the_inline_test(monkeypatch):
    from maverick_dashboard import channel_check_api, settings_store
    # Someone is permitted: a chat app with nobody on its list is refused before any test.
    settings_store.set_channel("slack", True, {"app_token": "xapp-1", "bot_token": "xoxb-1",
                                               "allowed_user_ids": "U01ABCDEF"})
    monkeypatch.setattr(channel_check_api, "check_credentials",
                        lambda name, cfg: (False, "the service did not accept the saved details"))
    # The chat app's own components are installed (the check under test is the
    # credential test, not this machine's optional Slack packages).
    from maverick_dashboard import integration_readiness
    monkeypatch.setattr(integration_readiness, "_channel_dependency",
                        lambda _name: integration_readiness.check("passed", "fixture", kind="channel_adapter"))
    client = _client()
    r = client.post("/channels/test", data={"channel": "slack"}, headers={"Accept": "application/json"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False and body["status"] == "Test failed" and "Test failed" in body["readiness_html"]
    page = client.get("/channels").text
    assert "1 turned on · 0 working · 1 failed" in page and "data-ch-result" in page


def test_setup_checks_are_worded_as_outcomes():
    from maverick_dashboard.onboarding_state import _plain_check
    check = _plain_check({"id": "evidence_graph", "label": "Evidence graph", "status": "attention"},
                         frozenset({"evidence_graph"}))
    assert check["title"] == "Evidence linking"
    assert check["fix_label"] == "Turn on evidence linking"
    assert check["summary"] == "Turn on evidence linking so reviews can cite the sources behind each result."
    # Provider checks keep their wording (owned by the provider-readiness work).
    provider = _plain_check({"id": "provider", "label": "Model provider", "status": "blocked"}, frozenset())
    assert provider["fix_label"] == "Add an AI provider key"
