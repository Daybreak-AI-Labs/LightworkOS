"""Approval cards carry their approval progress from the server.

Approvals used to fetch /api/v1/approvals/<id>/state once per card after
load (21 requests for 20 cards) and append each answer as a role=status line,
re-laying out the page each time (1.1 s of blocked main thread on a phone).
The page now renders the same words in each card as plain text, behind the
same checks: the page's operate floor and the per-approval content check that
already decides which cards are shown.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


@pytest.fixture
def world(tmp_path):
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    yield w
    w.close()


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


def _viewer(monkeypatch, who, *, signed_in=False):
    """The person deciding. Unowned requests open in local mode (no sign-in);
    a request someone made opens for them once they are signed in."""
    from maverick_dashboard import api, auth, rbac

    if signed_in:
        monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
        rbac.set_role(who, "operator")
        monkeypatch.setattr(auth, "caller_principal", lambda request: who)
    monkeypatch.setattr(api, "_supervisor", lambda request: who)


def _approval(world, *, required=1, requested_by=None, risk="medium"):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="crm.update_records", summary="Update 3 account owners",
        target_label="CRM: 3 accounts", target={"ids": ["a", "b", "c"]},
        parameters={"field": "owner"}, parameter_summary=["Change 3 owners"],
        actor=requested_by or "user:requester", workspace="tenant-a", role="operator",
        authority_versions={"role_revision": "r1"}, input_versions={"snapshot": "s1"},
        credential_versions={}, budget={}, expires_at=time.time() + 600,
        known_effects=["Owners change."], unresolved_assumptions=[],
        before="Owned by Sam.", after="Owned by Priya.", irreversible=False,
    )
    return world.create_approval("crm.update_records", risk=risk, scope="CRM accounts",
                                 detail=encode_approval_detail(card),
                                 approvals_required=required, requested_by=requested_by)


def _sign(world, approval_id, approver):
    """Record one approving vote on an N-of-M approval (it stays pending)."""
    assert world.decide_approval(approval_id, "approved", decided_by=approver)
    assert world.get_approval(approval_id).status == "pending"


def _card(page, approval_id):
    start = page.index(f'<article class="approval-item" data-id="{approval_id}"')
    return page[start:page.index("</article>", start)]


def _words_from_state_api(state):
    """The sentence the page script used to build from the state API."""
    required = int(state["approvals_required"]) or 1
    words = ["One approval is needed." if required <= 1
             else f"{state['approved_count']} of {required} required approvals received."]
    if state["your_approval_recorded"]:
        words.append("Your approval is recorded.")
    elif state["requested_by_you"]:
        words.append("You asked for this, so other people must approve it." if not state["self_approval_counts"]
                     else "You asked for this, so approving it approves your own request." if required <= 1
                     else "You asked for this; your approval counts as one of them.")
    return " ".join(words)


@pytest.mark.parametrize(("required", "requested_by", "signed_by", "self_allowed", "expected"), [
    (1, None, [], False, "One approval is needed."),
    (2, None, ["user:other"], False, "1 of 2 required approvals received."),
    (2, None, ["user:me"], False, "1 of 2 required approvals received. Your approval is recorded."),
    # The card's own note (approval-own-note) says why; the line doesn't repeat it.
    (2, "user:me", [], False, "0 of 2 required approvals received."),
    (2, "user:me", [], True, "0 of 2 required approvals received. You asked for this; your approval counts as one of them."),
    (1, "user:me", [], False, "One approval is needed. You asked for this, so approving it approves your own request."),
])
def test_card_shows_the_progress_the_state_api_reports(world, monkeypatch, required, requested_by, signed_by,
                                                        self_allowed, expected):
    monkeypatch.setattr("maverick.safety.dual_control.allow_self_approval", lambda: self_allowed)
    _viewer(monkeypatch, "user:me", signed_in=requested_by == "user:me")
    aid = _approval(world, required=required, requested_by=requested_by)
    for approver in signed_by:
        _sign(world, aid, approver)
    client = _client()
    card = _card(client.get("/approvals").text, aid)
    line = f'<p class="approval-quorum" data-approval-quorum-status="1">{expected}</p>'
    assert line in card
    assert 'role="status"' not in line
    # The same words the page used to build from the state API.
    state = client.get(f"/api/v1/approvals/{aid}/state").json()
    if state.get("own_request_note"):
        assert f'id="approval-own-note-{aid}"' in card and state["own_request_note"] in card
    else:
        assert _words_from_state_api(state) == expected
    # A vote already recorded leaves Approve disabled, as the page script did.
    approve = card[card.index('data-action="approve"'):].split(">", 1)[0]
    if "user:me" in signed_by:
        assert " disabled" in approve
    elif requested_by is None:
        assert " disabled" not in approve


def test_page_makes_no_request_per_card(world, monkeypatch):
    _viewer(monkeypatch, "user:me")
    ids = [_approval(world) for _ in range(3)]
    page = _client().get("/approvals").text
    for aid in ids:
        assert "One approval is needed." in _card(page, aid)
    assert "/state'" not in page and '/state",' not in page
    assert "approvals/' + row.dataset.id" not in page


def test_oversight_console_shows_the_same_progress(world, monkeypatch):
    _viewer(monkeypatch, "user:me")
    aid = _approval(world, required=2)
    _sign(world, aid, "user:me")
    page = _client().get("/oversight")
    assert page.status_code == 200
    assert "1 of 2 required approvals received. Your approval is recorded." in _card(page.text, aid)


def test_progress_is_read_only_for_cards_the_viewer_may_open(world, monkeypatch):
    from maverick_dashboard import content_access

    _viewer(monkeypatch, "user:me")
    shown = _approval(world, required=2)
    private = _approval(world, required=3)
    real = content_access.can_read_approval
    monkeypatch.setattr(content_access, "can_read_approval",
                        lambda request, approval, world=None: approval.id != private and real(request, approval, world))
    read = []
    from maverick.world_model import WorldModel
    original = WorldModel.approval_state

    def spy(self, approval_id):
        read.append(approval_id)
        return original(self, approval_id)

    monkeypatch.setattr(WorldModel, "approval_state", spy)
    page = _client().get("/approvals").text
    assert "0 of 2 required approvals received." in _card(page, shown)
    assert f'data-id="{private}"' not in page and "0 of 3 required approvals received." not in page
    assert private not in read  # no state is read for a card the viewer cannot open
