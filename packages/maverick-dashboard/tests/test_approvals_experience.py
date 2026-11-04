"""Approvals as the core loop: stacked cards, confirmation, toast, undo.

Server side: high and critical risk approvals need an explicit
acknowledgement; undo returns a just-decided request to pending while the
agent is still waiting and is refused after the window; every decision,
confirmation, rejection reason and undo lands in the audit log as a plain
sentence. Page side: no table (a phone must not scroll sideways), an in-page
confirmation dialog, a "Decided just now" area with Undo.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
ACK = {"acknowledged": True}
ACK_CRITICAL = {"acknowledged": True, "confirmation": "approve"}
TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "maverick_dashboard" / "templates" / "_approvals_queue.html"
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "30")
    monkeypatch.delenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", raising=False)


@pytest.fixture
def recorded(monkeypatch):
    import maverick.audit as audit

    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit, "record", lambda kind, **p: events.append((kind, p)) or True)
    return events


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _queue(world, *, action="salesforce.update_records", risk="high"):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action=action,
        summary="Update 12 Salesforce account records",
        target_label="Salesforce: 12 account records",
        target={"object": "Account", "ids": ["001A", "001B"]},
        parameters={"field": "owner"},
        parameter_summary=["Change the owner of 12 accounts to Priya"],
        actor="user:alice",
        workspace="tenant-a",
        role="operator",
        authority_versions={"role_revision": "role-v1"},
        input_versions={"crm_snapshot": "snap-1"},
        credential_versions={"salesforce_token_sha256": "a" * 64},
        budget={"currency": "USD", "maximum": 2.0},
        expires_at=time.time() + 600,
        known_effects=["Account owners change in Salesforce."],
        unresolved_assumptions=[],
        before="The 12 accounts belong to Sam.",
        after="The 12 accounts belong to Priya.",
        irreversible=True,
    )
    # The consent wait's queue: it holds each decision for the undo window.
    aid = world.create_approval(
        action, risk=risk, scope="Salesforce accounts",
        detail=encode_approval_detail(card), provenance="consent", undoable=True,
    )
    return aid, {"X-Lightwork-Approval-Binding": card["binding_sha256"]}


# ---------------------------------------------------------------- confirmation

def test_high_risk_approve_needs_acknowledgement(tmp_path, recorded):
    w = _world(tmp_path)
    aid, binding = _queue(w)
    c = _client()

    bare = c.post(f"/api/v1/approvals/{aid}/approve", headers=binding)
    assert bare.status_code == 422
    assert "Confirm you have read what this action will do" in bare.json()["detail"]
    assert w.get_approval(aid).status == "pending"

    ok = c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK)
    assert ok.status_code == 204
    assert ok.headers["x-lightwork-decided-by"] == "operator"
    assert ok.headers["x-lightwork-undo-seconds"] == "30"
    assert w.get_approval(aid).status == "approved"

    kinds = [k for k, _ in recorded]
    import maverick.audit as audit

    assert audit.EventKind.CONSENT_RESULT in kinds and audit.EventKind.APPROVAL_DECISION in kinds
    confirmation = next(p for k, p in recorded if p.get("action") == "approval_confirmation")
    assert confirmation["approval_id"] == aid and confirmation["acknowledged"] is True
    assert "confirmed reading what" in confirmation["summary"]
    decision = next(p for k, p in recorded if k == audit.EventKind.APPROVAL_DECISION)
    assert decision["summary"] == "operator approved 'salesforce update records' (high risk)."


def test_critical_risk_needs_typed_confirmation(tmp_path, recorded):
    w = _world(tmp_path)
    aid, binding = _queue(w, action="shell.exec", risk="critical")
    c = _client()

    ticked = c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK)
    assert ticked.status_code == 422
    assert ticked.json()["detail"] == "Type APPROVE to confirm this critical action."

    typed = c.post(f"/api/v1/approvals/{aid}/approve", headers=binding,
                   json={"acknowledged": True, "confirmation": " Approve "})
    assert typed.status_code == 204
    assert w.get_approval(aid).status == "approved"


def test_medium_risk_stays_one_click(tmp_path, recorded):
    w = _world(tmp_path)
    aid, binding = _queue(w, action="email.send", risk="medium")
    r = _client().post(f"/api/v1/approvals/{aid}/approve", headers=binding)
    assert r.status_code == 204
    assert w.get_approval(aid).status == "approved"
    assert not [p for _, p in recorded if p.get("action") == "approval_confirmation"]


def test_acknowledgement_knob_can_be_turned_off(tmp_path, recorded, monkeypatch):
    monkeypatch.setenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", "0")
    w = _world(tmp_path)
    aid, binding = _queue(w, risk="critical")
    assert _client().post(f"/api/v1/approvals/{aid}/approve", headers=binding).status_code == 204


def test_reject_reason_is_audited(tmp_path, recorded):
    w = _world(tmp_path)
    aid, _binding = _queue(w)
    r = _client().post(f"/api/v1/approvals/{aid}/deny", json={"reason": "Wrong owner"})
    assert r.status_code == 204
    assert w.get_approval(aid).status == "denied"
    reason = next(p for _, p in recorded if p.get("action") == "approval_rejection_reason")
    assert reason["reason"] == "Wrong owner"
    assert reason["summary"].startswith("operator rejected 'salesforce update records'")


# ------------------------------------------------------------------------ undo

def test_undo_within_window_returns_to_pending_and_re_decision_is_new_audit_row(
    tmp_path, recorded,
):
    w = _world(tmp_path)
    aid, binding = _queue(w)
    c = _client()
    assert c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK).status_code == 204

    undo = c.post(f"/api/v1/approvals/{aid}/undo")
    assert undo.status_code == 200
    assert undo.json() == {
        "status": "pending", "previous_status": "approved", "undone_by": "operator",
        "approval_id": aid,
    }
    row = w.get_approval(aid)
    assert row.status == "pending" and row.decided_by is None and row.decided_at is None
    assert [a.id for a in w.pending_approvals()] == [aid]
    undone = next(p for _, p in recorded if p.get("action") == "approval_decision_undone")
    assert undone["previous_status"] == "approved"
    assert undone["summary"] == (
        "operator undid the approval of 'salesforce update records'; "
        "it is waiting for a decision again."
    )

    # Deciding again is a new decision with its own signed audit row, not a
    # replay of the retracted vote (the writer dedupes on approval_event_id).
    again = c.post(f"/api/v1/approvals/{aid}/deny")
    assert again.status_code == 204
    assert w.get_approval(aid).status == "denied"
    import maverick.audit as audit

    ids = [p["approval_event_id"] for k, p in recorded if k == audit.EventKind.APPROVAL_DECISION]
    assert len(ids) == 2 and ids[0] != ids[1]

    # Same vote again after a second undo: still a fresh identity.
    assert c.post(f"/api/v1/approvals/{aid}/undo").status_code == 200
    assert c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK).status_code == 204
    ids = [p["approval_event_id"] for k, p in recorded if k == audit.EventKind.APPROVAL_DECISION]
    assert len(ids) == 3 and len(set(ids)) == 3
    assert w.get_approval(aid).status == "approved"


def test_undo_after_window_is_refused_plainly(tmp_path, recorded, monkeypatch):
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    w = _world(tmp_path)
    aid, binding = _queue(w)
    c = _client()
    ok = c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK)
    assert ok.status_code == 204
    assert "x-lightwork-undo-seconds" not in ok.headers or ok.headers["x-lightwork-undo-seconds"] == "0"

    late = c.post(f"/api/v1/approvals/{aid}/undo")
    assert late.status_code == 409
    assert late.json()["detail"].startswith("Too late to undo: the agent has already been told")
    assert w.get_approval(aid).status == "approved"
    assert not [p for _, p in recorded if p.get("action") == "approval_decision_undone"]


def test_undo_needs_a_decision(tmp_path, recorded):
    w = _world(tmp_path)
    aid, _binding = _queue(w)
    c = _client()
    assert c.post(f"/api/v1/approvals/{aid}/undo").status_code == 409
    assert c.post(f"/api/v1/approvals/{aid}/undo").json()["detail"] == "There is no decision to undo yet."
    assert c.post("/api/v1/approvals/424242/undo").status_code == 404


# ------------------------------------------------------------------------ page

def test_page_renders_stacked_cards_with_confirmation_and_decided_area(tmp_path):
    w = _world(tmp_path)
    aid, _binding = _queue(w)
    text = _client().get("/approvals").text
    assert "<table" not in text.split('id="approval-queue"')[1].split("</article>")[0]
    assert f'<article class="approval-item" data-id="{aid}"' in text
    assert 'data-risk="high"' in text
    assert "High risk" in text and "Decide by" in text and "Requested by" in text
    assert "What it will do" in text and "Can&#39;t be undone" in text or "Can't be undone" in text
    assert 'id="approval-confirm"' in text and "Type APPROVE to confirm" in text
    assert "Decided just now" in text and 'class="btn approval-undo"' in text
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "window.confirm" not in source and "mvConfirm" not in source
    assert "mvToast" in text
    assert "/undo'" in text


def test_phone_layout_has_no_fixed_width_wider_than_a_phone():
    source = TEMPLATE.read_text(encoding="utf-8")
    style = source.split("<style>")[1].split("</style>")[0]
    assert "<table" not in source
    assert "overflow-x" not in style
    for raw in re.findall(r"min-width:\s*([^;]+);", style):
        value = raw.strip()
        if value == "0":
            continue
        number, unit = re.fullmatch(r"([\d.]+)(px|rem)", value).groups()
        px = float(number) * (16 if unit == "rem" else 1)
        assert px <= 390 - 32, f"min-width {value} does not fit a 390px phone"
    # The wide-screen bug: nothing may claim a viewport-relative floor.
    assert "vw" not in style


def test_oversight_console_shares_the_card_queue(tmp_path):
    w = _world(tmp_path)
    aid, _binding = _queue(w)
    r = _client().get("/oversight")
    assert r.status_code == 200
    assert f'<article class="approval-item" data-id="{aid}"' in r.text


def test_link_to_an_approval_no_longer_waiting_has_a_note_and_a_way_on(tmp_path):
    world = _world(tmp_path)
    waiting, _binding = _queue(world)
    page = _client().get("/approvals")
    assert page.status_code == 200
    assert f'id="approval-{waiting}"' in page.text
    # The note is in the page, hidden until the address names a missing card.
    assert '<p class="panel" id="approval-missing" role="status" hidden>' in page.text
    assert "This approval was already decided or no longer exists." in page.text
    assert 'href="#request-decision-history"' in page.text
    assert 'href="/audit">find it in the Activity log' in page.text


def test_decision_buttons_name_the_action_they_decide(tmp_path):
    w = _world(tmp_path)
    _queue(w, action="send_email", risk="medium")
    text = _client().get("/approvals").text
    # The card's plain summary names the action on both buttons.
    assert re.search(r'data-action="approve"[^>]*>Approve &#34;Update 12 Salesforce account records&#34;</button>', text)
    assert re.search(r'data-action="deny">Reject &#34;Update 12 Salesforce account records&#34;</button>', text)
    source = TEMPLATE.read_text(encoding="utf-8")
    # No bare yes or generic OK on any approval button or confirmation.
    assert "Yes, approve" not in source
    assert not re.search(r"okText:\s*['\"](OK|Yes|Confirm|Continue|Reject|Send back)['\"]", source)
    assert "tr('Approve \"{action}\"', {action: item.dataset.label" in source


def test_the_waiting_count_in_the_header_follows_the_queue(tmp_path):
    w = _world(tmp_path)
    _queue(w, risk="medium")
    _queue(w, action="send_email", risk="medium")
    text = _client().get("/approvals").text
    box = re.search(r'<div id="approvals-current-state"[^>]*>', text)
    assert box and 'data-flow-count="0"' in box.group(0) and 'data-private-count="0"' in box.group(0)
    assert "2 requests waiting" in text
    counter = (TEMPLATE.parent.parent / "static" / "lightwork-approvals-count.js").read_text(encoding="utf-8")
    assert "approvals-current-state" in counter and "MutationObserver" in counter
    assert "lightwork-approvals-count.js" in text
    # The page itself never carries "All clear" while requests wait.
    assert "All clear" not in text


def test_decision_labels_use_the_cards_plain_summary_then_the_step_words():
    from maverick_dashboard.approval_labels import action_label

    # The card's own plain summary names the action.
    assert action_label("shell", {"summary": "Run a command in the sandbox."}) == "Run a command in the sandbox"
    assert action_label("salesforce.update_records", {"summary": "Update 12 Salesforce account records"}) == \
        "Update 12 Salesforce account records"
    # A generic or overlong summary falls back to the plain step words.
    assert action_label("shell", {"summary": "Review this exact operation."}) == "Run a command"
    assert action_label("write_file", {"summary": "x" * 200}) == "Save a file"
    assert action_label("shell", None) == "Run a command"
    # Neither: the humanised action, as before.
    assert action_label("send_email", None) == "Send email"
    assert action_label("", None) == "Reviewed action"
    # A summary that is itself the request ("Approve the payment?") is not a name.
    assert action_label("send_email", {"summary": "Approve the reviewed customer change"}) == "Send email"
    assert action_label("flow.resume", {"summary": "Pay the March invoices?"}) == "Flow resume"


def test_the_queue_names_the_card_summary_on_its_buttons(tmp_path):
    w = _world(tmp_path)
    _queue(w, risk="medium")
    text = _client().get("/approvals").text
    assert 'Approve &#34;Update 12 Salesforce account records&#34;</button>' in text
    assert 'data-label="Update 12 Salesforce account records"' in text


def test_a_decision_nothing_waits_on_offers_no_undo_and_cannot_be_undone(tmp_path, recorded):
    # Settings changes, codebase merges, data-use checks and agent credentials
    # act on "approved" at once: undoing one would claim a retraction of an
    # effect that already happened.
    w = _world(tmp_path)
    aid = w.create_approval("codebase_merge", risk="high", scope="repo", provenance="codebase")
    c = _client()
    denied = c.post(f"/api/v1/approvals/{aid}/deny")
    assert denied.status_code == 204
    assert "x-lightwork-undo-seconds" not in denied.headers
    undo = c.post(f"/api/v1/approvals/{aid}/undo")
    assert undo.status_code == 409
    assert undo.json()["detail"].startswith("This decision can't be undone")
    assert w.get_approval(aid).status == "denied"
    assert not [p for _, p in recorded if p.get("action") == "approval_decision_undone"]


def test_undo_needs_the_same_access_as_deciding(tmp_path, recorded, monkeypatch):
    # A reviewer who may not open a private request's card may not reopen its
    # decision either.
    from maverick_dashboard import content_access

    w = _world(tmp_path)
    aid, binding = _queue(w)
    c = _client()
    assert c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK).status_code == 204
    monkeypatch.setattr(content_access, "can_read_approval", lambda *a, **k: False)
    undo = c.post(f"/api/v1/approvals/{aid}/undo")
    assert undo.status_code == 403
    assert w.get_approval(aid).status == "approved"


def test_undo_of_a_settings_request_needs_a_global_administrator(tmp_path, recorded, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import settings_quorum

    w = _world(tmp_path)
    aid, binding = _queue(w)
    c = _client()
    assert c.post(f"/api/v1/approvals/{aid}/approve", headers=binding, json=ACK).status_code == 204
    seen = []

    def decider(request, approval, who, *, approving):
        seen.append((approval.id, approving))
        raise HTTPException(status_code=403, detail="global administrator required")

    monkeypatch.setattr(settings_quorum, "require_decider", decider)
    undo = c.post(f"/api/v1/approvals/{aid}/undo")
    assert undo.status_code == 403 and seen == [(aid, False)]
    assert w.get_approval(aid).status == "approved"
