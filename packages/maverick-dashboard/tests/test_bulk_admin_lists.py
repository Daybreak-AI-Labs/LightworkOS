"""Bulk work on the admin lists.

The six admin lists (people, agents, tool policies, approvals, privacy
requests and saved test questions) each offer filter, select all matching,
one counted confirmation and undo or a change report. The browser side is
tested in tests/js/bulk_actions.test.js and bulk_lists.test.js; this file
covers the server pieces: the privacy-request assignment the bulk Assign
uses (with its undo), the people a request can be assigned to, and that each
list's page carries the rows the bulk bar works on.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for name in ("MAVERICK_ENTERPRISE", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text("[privacy_ops]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    from maverick_dashboard import api, rbac
    from maverick_dashboard.app import app
    api._world_cache.clear()
    rbac.set_role("user:priya@corp.com", "operator", actor="user:setup")
    rbac.set_role("user:vic@corp.com", "viewer", actor="user:setup")
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _open_request(client) -> str:
    response = client.post("/api/v1/privacy/dsar", json={"subject_id": "jo@example.com", "kind": "access"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_assign_names_who_works_a_request_and_keeps_the_earlier_assignee_for_undo(client):
    request_id = _open_request(client)
    first = client.post(f"/api/v1/privacy/dsar/{request_id}/assign", json={"assignee": "user:priya@corp.com"})
    assert first.status_code == 200, first.text
    assert first.json()["assignee"] == "user:priya@corp.com"
    assert first.json()["previous_assignee"] == ""
    # Undo is the same call with the earlier value.
    undone = client.post(f"/api/v1/privacy/dsar/{request_id}/assign", json={"assignee": ""})
    assert undone.status_code == 200
    assert undone.json()["assignee"] == "" and undone.json()["previous_assignee"] == "user:priya@corp.com"


def test_only_someone_who_may_work_privacy_requests_can_be_assigned(client):
    request_id = _open_request(client)
    refused = client.post(f"/api/v1/privacy/dsar/{request_id}/assign", json={"assignee": "user:vic@corp.com"})
    assert refused.status_code == 422
    assert "can't work privacy requests" in refused.json()["detail"]
    missing = client.post("/api/v1/privacy/dsar/DSAR-0000000000/assign", json={"assignee": ""})
    assert missing.status_code == 404


def test_the_privacy_list_offers_bulk_rows_and_only_permitted_assignees(client):
    _open_request(client)
    page = client.get("/privacy").text
    assert 'id="pw-dsar-rows"' in page
    assert re.search(r'<tr data-bulk-id="DSAR-[0-9a-f]{10}" data-bulk-label="jo@example.com \(DSAR-', page)
    people = re.search(r'<script\b[^>]*\bid="pw-dsar-assignees"[^>]*>(.*?)</script>', page, re.DOTALL).group(1)
    assert "user:priya@corp.com" in people
    assert "user:vic@corp.com" not in people  # a viewer cannot work requests
    assert ">Assigned to</th>" in page


def test_people_directory_offers_only_holders_of_the_permission(client):
    from maverick_dashboard import people_directory

    operators = {p["principal"] for p in people_directory.candidates("operate")}
    assert "user:priya@corp.com" in operators and "user:vic@corp.com" not in operators
    assert people_directory.may("user:priya@corp.com", "operate")
    assert not people_directory.may("user:vic@corp.com", "operate")
    assert not people_directory.may("agent:helper", "operate")


@pytest.mark.parametrize(("template", "marker"), [
    ("templates/_approvals_queue.html", 'data-bulk-id="{{ a.id }}"'),
    ("templates/permissions.html", 'data-bulk-id="{{ t.name }}"'),
    ("templates/privacy.html", 'data-bulk-id="{{ r.id }}"'),
    ("templates/users.html", "data-bulk-pick"),
    ("static/lightwork-agent-control-plane.js", "tr.dataset.bulkId = row.principal"),
    ("static/lightwork-learning-test-cases.js", "box.dataset.bulkId=row.value"),
])
def test_each_admin_list_carries_bulk_rows(template, marker):
    assert marker in (PACKAGE / template).read_text(encoding="utf-8")


def test_approvals_never_offer_bulk_approve():
    queue = (PACKAGE / "templates/_approvals_queue.html").read_text(encoding="utf-8")
    bulk = queue[queue.index("Reject or send back many requests at once"):]
    bulk = bulk[:bulk.index("</script>")]
    assert "label: 'Reject'" in bulk and "label: 'Send back'" in bulk
    assert "'approve'" not in bulk and "label: 'Approve'" not in bulk


@pytest.mark.parametrize("template", ["templates/permissions.html", "templates/privacy.html",
                                      "templates/_approvals_queue.html"])
def test_inline_bulk_bars_wait_for_the_shared_helpers(template):
    # These pages' own scripts run before lightwork-ui.js (loaded at the end of
    # base.html), so wiring the bar at once found no mvBulk and drew nothing.
    source = (PACKAGE / template).read_text(encoding="utf-8")
    bulk = source[source.index("wireBulk"):]
    assert "document.addEventListener('DOMContentLoaded', wireBulk, {once: true})" in bulk


def test_a_page_script_runs_before_the_shared_helpers():
    base = (PACKAGE / "templates/base.html").read_text(encoding="utf-8")
    assert base.index("{% block content %}") < base.index("<script src=\"{{ asset('lightwork-ui.js') }}\"></script>")


def test_people_directory_never_offers_or_accepts_a_deprovisioned_account(client, monkeypatch):
    # Company sign-in (SCIM) turned Priya off: her role is still on file, but
    # she can no longer sign in, so a request is never assigned to her.
    from maverick_dashboard import people_directory, scim_groups

    monkeypatch.setattr(scim_groups, "active_check",
                        lambda: lambda principal: False if principal == "user:priya@corp.com" else None)
    operators = {p["principal"] for p in people_directory.candidates("operate")}
    assert "user:priya@corp.com" not in operators
    assert not people_directory.may("user:priya@corp.com", "operate")


def test_an_unreadable_company_directory_offers_nobody(client, monkeypatch):
    from maverick_dashboard import people_directory, scim_groups

    def broken():
        raise OSError("roster unreadable")

    monkeypatch.setattr(scim_groups, "active_check", broken)
    assert people_directory.candidates("operate") == []
    assert not people_directory.may("user:priya@corp.com", "operate")


def test_offering_people_reads_the_company_directory_once_not_per_person(client, monkeypatch):
    # The DSAR page lists every operator; each person's check re-read the
    # SCIM users and the retired ledger (twice), per person.
    from maverick_dashboard import people_directory, rbac, subject_directory

    for index in range(30):
        rbac.set_role(f"user:op{index}@corp.com", "operator", actor="user:setup")
    reads, real = [], subject_directory._load_retired
    monkeypatch.setattr(subject_directory, "_load_retired", lambda: reads.append(1) or real())
    operators = {p["principal"] for p in people_directory.candidates("operate")}
    assert len(operators) == 31 and len(reads) == 1
    reads.clear()
    assert people_directory.allowed({f"user:op{index}@corp.com" for index in range(30)} | {"user:vic@corp.com"},
                                    "operate") == {f"user:op{index}@corp.com" for index in range(30)}
    assert len(reads) == 1
