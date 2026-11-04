"""The record says who decided: activity log, CSV export and audit binder.

A person approves (and undoes, and approves again) a request on the Approvals
page; the activity log and its spreadsheet download name that person rather
than "Lightwork" (the owner's choice on 4 October), the undo is on the record
with who undid it, and the binder counts the approval and its approver.
"""
from __future__ import annotations

import csv
import io
import re
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
REQUESTER = "user:sam.lee@northwind.example"
APPROVER = "user:dana.admin@northwind.example"


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.world_model import WorldModel

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), world
    world.close()


def _approval(world, *, requested_by=None, undoable=False):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=requested_by or REQUESTER, workspace="local",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=time.time() + 600, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    approval_id = world.create_approval("shell", risk="high", scope="sandbox:/work",
                                        detail=encode_approval_detail(card), requested_by=requested_by,
                                        undoable=undoable)
    return approval_id, {"X-Lightwork-Approval-Binding": card["binding_sha256"]}


def _as(monkeypatch, principal):
    from maverick_dashboard import api

    monkeypatch.setattr(api, "_supervisor", lambda request: principal)


def _approve(client, approval_id, headers):
    response = client.post(f"/api/v1/approvals/{approval_id}/approve",
                           json={"acknowledged": True}, headers=headers)
    assert response.status_code == 204, response.text
    return response


def _visible(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _csv_rows(client):
    response = client.get("/api/v1/audit/download", params={"format": "csv"})
    assert response.status_code == 200, response.text
    return list(csv.reader(io.StringIO(response.text)))


def test_activity_log_and_download_name_the_person_who_decided(env, monkeypatch):
    # The owner chose on 4 October to name the decider in the activity log,
    # reversing the 1 October choice to leave the name out: who decided is
    # governance evidence, like the actor on undo and confirmation rows.
    client, world = env
    approval_id, headers = _approval(world)
    _as(monkeypatch, APPROVER)
    _approve(client, approval_id, headers)

    rows = _csv_rows(client)
    decided = [row for row in rows if row[1] == "Approval decided"]
    assert decided, rows
    assert decided[-1][2] == "dana.admin@northwind.example"
    assert not {"Lightwork", "A person (name not shown)"} & {row[2] for row in decided}

    html = client.get("/audit").text
    page = _visible(html)
    assert re.search(r"Approval decided\s+dana\.admin@northwind\.example", page), page[:2000]
    # A decision row names no task, so it shows a dash, not a link to nowhere.
    assert 'href="/chat/goal/"' not in html


def test_an_undo_is_on_the_record_with_who_undid_it(env, monkeypatch):
    client, world = env
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "30")
    approval_id, headers = _approval(world, undoable=True)
    _as(monkeypatch, APPROVER)
    _approve(client, approval_id, headers)
    undo = client.post(f"/api/v1/approvals/{approval_id}/undo")
    assert undo.status_code == 200, undo.text
    _approve(client, approval_id, headers)

    rows = _csv_rows(client)
    undone = [row for row in rows if row[1] == "Approval decision undone"]
    assert len(undone) == 1, rows
    assert undone[0][2] == "dana.admin@northwind.example"
    assert len([row for row in rows if row[1] == "Approval decided"]) == 2


def test_binder_counts_a_single_approval_and_its_approver(env, monkeypatch):
    client, world = env
    approval_id, headers = _approval(world)
    _as(monkeypatch, APPROVER)
    _approve(client, approval_id, headers)

    binder = client.get("/api/v1/audit/binder", params={"days": 30}).json()
    (row,) = [item for item in binder["approvals"] if item["id"] == approval_id]
    assert row["status"] == "approved"
    assert row["decided_by"] == APPROVER
    assert row["approved_count"] == 1
    assert row["approvers"] == [APPROVER]

    page = _visible(client.get("/audit/binder", params={"days": 30}).text)
    assert "1 of 1" in page
    assert "0 of 1" not in page


def test_a_rejection_does_not_count_as_an_approver(env, monkeypatch):
    client, world = env
    approval_id, _headers = _approval(world)
    _as(monkeypatch, APPROVER)
    assert client.post(f"/api/v1/approvals/{approval_id}/deny").status_code == 204

    binder = client.get("/api/v1/audit/binder", params={"days": 30}).json()
    (row,) = [item for item in binder["approvals"] if item["id"] == approval_id]
    assert row["status"] == "denied"
    assert row["approved_count"] == 0
    assert row["approvers"] == []


def test_approval_steps_read_plainly_in_the_log():
    from maverick_dashboard.audit_actions_api import event_details, event_label, event_who
    from maverick_dashboard.content_access import audit_metadata

    confirmed = audit_metadata({"kind": "consent_result", "agent": APPROVER, "actor": APPROVER,
                                "action": "approval_confirmation", "approval_id": 3,
                                "channel": "dashboard", "summary": "private words"})
    assert event_label(confirmed) == "Approval confirmed"
    assert event_who(confirmed) == "dana.admin@northwind.example"
    labels = [label for _key, label, _text in event_details(confirmed)]
    assert "Action" not in labels and "Chat app" not in labels
    assert "private words" not in str(confirmed)

    in_slack = audit_metadata({"kind": "approval_decision", "decided_by": APPROVER, "status": "approved",
                               "approval_id": 3, "channel": "slack", "self_approval": True})
    details = {label: text for _key, label, text in event_details(in_slack)}
    assert details["Chat app"] == "Slack"
    assert details["Approved own request"] == "Yes"
    assert details["Decided by"] == "dana.admin@northwind.example"
    assert event_who(in_slack) == "dana.admin@northwind.example"


def test_an_undo_row_names_the_earlier_decider_plainly():
    from maverick_dashboard.audit_actions_api import event_details, event_who
    from maverick_dashboard.content_access import audit_metadata

    undone = audit_metadata({"kind": "consent_result", "agent": REQUESTER, "actor": REQUESTER,
                             "action": "approval_decision_undone", "approval_id": 3,
                             "previous_status": "approved", "previously_decided_by": APPROVER})
    details = {label: text for _key, label, text in event_details(undone)}
    assert event_who(undone) == "sam.lee@northwind.example"
    assert details["Earlier decision by"] == "dana.admin@northwind.example"


def test_a_decider_whose_name_cannot_be_shown_is_still_a_person():
    # The fallback stays for a row whose recorded decider can't be shown
    # (here a value too long to be a sign-in name): a person decided, so the
    # row never credits Lightwork.
    from maverick_dashboard.audit_actions_api import event_who
    from maverick_dashboard.content_access import audit_metadata

    row = audit_metadata({"kind": "approval_decision", "decided_by": "user:" + "x" * 400,
                          "status": "approved", "approval_id": 4})
    assert "decided_by" not in row
    assert event_who(row) == "A person (name not shown)"
