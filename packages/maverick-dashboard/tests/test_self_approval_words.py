"""The words on an approval match the rule that is actually enforced.

With one approver (the default) the person who asked may approve their own
request: the card must not claim an independent decision is needed, the
confirmation says they are approving their own request, and the audit row
records it as a self-approval. Under two-person approval the requester's vote
does not count, and the card says so before they try.
"""
from __future__ import annotations

import csv
import io
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SAM = "user:sam.lee@northwind.example"
TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"


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


def _as(monkeypatch, principal):
    from maverick_dashboard import api, auth, content_access, rbac

    rbac.set_role(principal, "operator")
    monkeypatch.setattr(api, "_supervisor", lambda request: principal)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    # The requester owns the request's content, so they may read the card.
    monkeypatch.setattr(content_access, "can_read_approval", lambda request, approval, world=None: True)


def _as_administrator(monkeypatch):
    """Read the audit downloads as the local administrator (no sign-in)."""
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: None)


def _approval(world, *, required=1, requested_by=SAM):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=requested_by or SAM, workspace="local",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=time.time() + 600, known_effects=["Runs one command."],
        unresolved_assumptions=[], before="Not run.", after="Run once.", irreversible=True,
    )
    approval_id = world.create_approval("shell", risk="high", scope="sandbox:/work",
                                        detail=encode_approval_detail(card),
                                        approvals_required=required, requested_by=requested_by)
    return approval_id, {"X-Lightwork-Approval-Binding": card["binding_sha256"]}


def test_the_queue_never_claims_an_independent_decision_is_needed():
    source = (TEMPLATES / "_approvals_queue.html").read_text(encoding="utf-8")
    assert "An independent decision is needed" not in source


def test_a_single_approval_says_one_approval_and_marks_your_own_request(env, monkeypatch):
    client, world = env
    approval_id, _headers = _approval(world)
    _as(monkeypatch, SAM)

    state = client.get(f"/api/v1/approvals/{approval_id}/state").json()
    assert state["approvals_required"] == 1
    assert state["requested_by_you"] is True
    assert state["self_approval_counts"] is True

    page = client.get("/approvals").text
    card = re.search(rf'<article class="approval-item"[^>]*data-id="{approval_id}"[^>]*>', page)
    assert card is not None
    assert 'data-own-request="yes"' in card.group(0)
    assert "You&#39;re approving your own request." in page or "You're approving your own request." in page


def test_someone_elses_request_is_not_marked_as_yours(env, monkeypatch):
    client, world = env
    approval_id, _headers = _approval(world)
    _as(monkeypatch, "user:dana.admin@northwind.example")

    state = client.get(f"/api/v1/approvals/{approval_id}/state").json()
    assert state["requested_by_you"] is False
    page = client.get("/approvals").text
    card = re.search(rf'<article class="approval-item"[^>]*data-id="{approval_id}"[^>]*>', page)
    assert card is not None and "data-own-request" not in card.group(0)


def test_under_two_person_approval_the_requester_is_told_before_trying(env, monkeypatch):
    client, world = env
    monkeypatch.setattr("maverick.safety.dual_control.allow_self_approval", lambda: False)
    approval_id, _headers = _approval(world, required=2)
    _as(monkeypatch, SAM)

    state = client.get(f"/api/v1/approvals/{approval_id}/state").json()
    assert state["self_approval_counts"] is False
    page = client.get("/approvals").text
    card = page[page.index(f'data-id="{approval_id}"'):]
    card = card[:card.index("</article>")]
    approve = re.search(r'<button[^>]*data-action="approve"[^>]*>', card)
    assert approve is not None and "disabled" in approve.group(0)
    assert "You asked for this, so other people must approve it." in card


def test_approving_your_own_request_is_recorded_as_a_self_approval(env, monkeypatch):
    client, world = env
    approval_id, headers = _approval(world)
    _as(monkeypatch, SAM)
    response = client.post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True},
                           headers=headers)
    assert response.status_code == 204, response.text
    _as_administrator(monkeypatch)

    rows = list(csv.reader(io.StringIO(client.get("/api/v1/audit/download", params={"format": "csv"}).text)))
    decided = [row for row in rows if row[1] == "Approval decided"]
    assert decided and "Approved own request: Yes" in decided[-1][4], rows
    binder = client.get("/api/v1/audit/binder", params={"days": 30}).json()
    (row,) = [item for item in binder["approvals"] if item["id"] == approval_id]
    assert row["self_approved"] is True


def test_approving_someone_elses_request_is_not_a_self_approval(env, monkeypatch):
    client, world = env
    approval_id, headers = _approval(world, requested_by=None)
    _as(monkeypatch, "user:dana.admin@northwind.example")
    response = client.post(f"/api/v1/approvals/{approval_id}/approve", json={"acknowledged": True},
                           headers=headers)
    assert response.status_code == 204, response.text
    _as_administrator(monkeypatch)

    rows = list(csv.reader(io.StringIO(client.get("/api/v1/audit/download", params={"format": "csv"}).text)))
    decided = [row for row in rows if row[1] == "Approval decided"]
    assert decided and "Approved own request" not in decided[-1][4]
    binder = client.get("/api/v1/audit/binder", params={"days": 30}).json()
    (row,) = [item for item in binder["approvals"] if item["id"] == approval_id]
    assert row["self_approved"] is False
