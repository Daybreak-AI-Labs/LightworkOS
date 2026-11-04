"""Approval decisions from a chat channel share the dashboard's decision path,
carry the same signed audit, confirm twice for High/Critical, refuse what is
expired or decided, and tie chat accounts to Lightwork people."""
from __future__ import annotations

import time

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture
def recorded(monkeypatch):
    import maverick.audit as audit

    rows: list[tuple[str, dict]] = []
    monkeypatch.setattr(audit, "record", lambda kind, **p: rows.append((kind, p)) or True)
    return rows


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _card(action="browser.click", *, expires_in=300.0, irreversible=True, maximum=0.25,
          display_command=None):
    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action=action, summary="Approve the reviewed customer change",
        target_label="The customer settings page", target={"page": "x"},
        parameters={"secret": "never"},  # pragma: allowlist secret
        parameter_summary=["Press Save once"], actor="user:requester", workspace="t",
        role="operator", authority_versions={"r": "1"}, input_versions={"i": "1"},
        credential_versions={}, budget={"currency": "USD", "maximum": maximum},
        expires_at=time.time() + expires_in, known_effects=["The setting changes."],
        unresolved_assumptions=[], before="Unchanged.", after="Saved.",
        irreversible=irreversible,
        display_command=display_command,
    )


def _park(world, *, risk="medium", card=None, action="browser.click", **kw):
    from maverick.approval_cards import encode_approval_detail

    detail = encode_approval_detail(card) if card is not None else kw.pop("detail", "plain")
    return world.create_approval(action, risk=risk, detail=detail, **kw)


# ---------------------------------------------------------------- card content

def test_card_content_is_plain_language(tmp_path):
    from maverick.channel_approvals import card_content

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, risk="high", card=card)
    content = card_content(world.get_approval(aid))
    assert content["action"] == "Browser click"
    assert content["risk_label"] == "High risk"
    assert content["spending"] == "Up to $0.25"
    assert content["irreversible"] is True
    assert content["what_it_will_do"] == ["Press Save once"]
    assert content["decide_by"] == pytest.approx(card["expires_at"])
    assert content["status"] == "current"
    assert content["binding"] == card["binding_sha256"]
    assert content["needs_confirmation"] is True
    assert "never" not in str(content)


def test_card_content_marks_expired_legacy_and_invalid(tmp_path):
    from maverick.approval_cards import APPROVAL_DETAIL_PREFIX
    from maverick.channel_approvals import card_content

    world = _world(tmp_path)
    expired = _park(world, card=_card(expires_in=-1))
    legacy = _park(world, detail="wipe the build dir", action="rm_rf")
    broken = _park(world, detail=APPROVAL_DETAIL_PREFIX + "{not json")
    assert card_content(world.get_approval(expired))["status"] == "expired"
    legacy_content = card_content(world.get_approval(legacy))
    assert legacy_content["status"] == "legacy" and legacy_content["summary"] == "wipe the build dir"
    assert legacy_content["action"] == "Rm rf"
    assert card_content(world.get_approval(broken))["status"] == "invalid"


# ------------------------------------------------------------------ decisions

@pytest.mark.parametrize("channel", ["slack", "teams", "email"])
def test_private_command_cannot_be_approved_in_shared_channel(tmp_path, recorded, channel):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    card = _card(display_command="echo reviewed")
    aid = _park(world, card=card)
    with pytest.raises(ChannelApprovalRefused, match="Approvals page") as exc:
        decide_from_channel(world, aid, "approved", principal="user:alice", channel=channel,
                            binding=card["binding_sha256"])
    assert exc.value.reason == "dashboard_only"
    assert world.get_approval(aid).status == "pending"


def test_private_command_can_be_rejected_from_channel(tmp_path, recorded):
    from maverick.channel_approvals import decide_from_channel

    world = _world(tmp_path)
    card = _card(display_command="echo reviewed")
    aid = _park(world, card=card)
    result = decide_from_channel(world, aid, "denied", principal="user:alice", channel="slack",
                                 binding=card["binding_sha256"])
    assert result["status"] == "denied"


def test_full_length_command_survives_card_round_trip():
    from maverick.approval_cards import decode_approval_detail, encode_approval_detail

    command = "echo " + "x" * 3795
    card = _card(display_command=command)
    assert decode_approval_detail(encode_approval_detail(card))["display"]["command"] == command


def test_approve_from_slack_records_signed_audit_and_channel(tmp_path, recorded):
    from maverick.channel_approvals import decide_from_channel

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, card=card)
    result = decide_from_channel(world, aid, "approved", principal="user:alice",
                                 channel="slack", binding=card["binding_sha256"])
    assert result["effective"] is True and result["status"] == "approved"
    assert world.get_approval(aid).status == "approved"
    assert world.get_approval(aid).decided_by == "user:alice"
    kinds = [k for k, _ in recorded]
    assert kinds == ["approval_decision", "channel_approval_decision"]
    note = recorded[1][1]
    assert note["channel"] == "slack" and note["decided_by"] == "user:alice"
    assert note["approval_id"] == aid and note["effective"] is True


def test_reject_needs_no_card_binding(tmp_path, recorded):
    from maverick.channel_approvals import decide_from_channel

    world = _world(tmp_path)
    aid = _park(world, detail="legacy request")
    result = decide_from_channel(world, aid, "denied", principal="user:bob", channel="teams")
    assert result["status"] == "denied"
    assert recorded[1][1]["channel"] == "teams"


@pytest.mark.parametrize("change", ["claim", "card"])
def test_native_channel_rechecks_review_inside_vote_reservation(tmp_path, recorded, monkeypatch, change):
    from maverick import channel_approvals as channels
    from maverick.approval_cards import encode_approval_detail

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, card=card)
    native_vote = world.decide_approval_audited

    def changed_before_reservation(*args, **kwargs):
        if change == "claim":
            assert world.claim_approval(aid, "user:other-reviewer")
        else:
            replacement = _card(action="different.reviewed.action")
            with world._writing() as conn:
                conn.execute("UPDATE approvals SET detail = ? WHERE id = ?", (encode_approval_detail(replacement), aid))
        return native_vote(*args, **kwargs)

    monkeypatch.setattr(world, "decide_approval_audited", changed_before_reservation)
    with pytest.raises(channels.ChannelApprovalRefused) as refusal:
        channels.decide_from_channel(world, aid, "approved", principal="user:alice", channel="slack",
                                     binding=card["binding_sha256"])
    assert refusal.value.reason == "stale_card"
    assert world.get_approval(aid).status == "pending"
    assert world.get_approval_audit_event(world.approval_audit_event_id(aid, "approved", "user:alice")) is None
    assert recorded == []


def test_high_and_critical_need_a_second_confirmation(tmp_path, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, risk="critical", card=card, undoable=True)
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid, "approved", principal="user:alice", channel="slack",
                            binding=card["binding_sha256"])
    assert exc.value.reason == "confirm_required"
    assert world.get_approval(aid).status == "pending"
    assert recorded == []
    # Critical: the acknowledgement alone is not enough; APPROVE must be typed.
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid, "approved", principal="user:alice", channel="slack",
                            binding=card["binding_sha256"], confirmed=True)
    assert exc.value.reason == "typed_confirmation_required" and recorded == []
    result = decide_from_channel(world, aid, "approved", principal="user:alice", channel="slack",
                                 binding=card["binding_sha256"], confirmed=True,
                                 typed_confirmation=" approve ")
    assert world.get_approval(aid).status == "approved"
    assert result["undo_seconds"] == 30.0
    kinds = [k for k, _ in recorded]
    assert kinds == ["consent_result", "approval_decision", "channel_approval_decision"]
    ack = recorded[0][1]
    assert ack["action"] == "approval_confirmation" and ack["channel"] == "slack"
    assert ack["acknowledged"] is True and ack["typed_confirmation"] is True
    # High: the acknowledgement (confirm dialog) is enough; rejecting needs no typed word.
    high = _park(world, risk="high", card=_card())
    decide_from_channel(world, high, "denied", principal="user:alice", channel="slack",
                        confirmed=True)
    assert recorded[-3][1]["typed_confirmation"] is False


def test_acknowledgement_rule_can_be_switched_off(tmp_path, recorded, monkeypatch):
    from maverick.channel_approvals import decide_from_channel

    monkeypatch.setenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", "0")
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    world = _world(tmp_path)
    card = _card()
    aid = _park(world, risk="critical", card=card)
    result = decide_from_channel(world, aid, "approved", principal="user:alice", channel="slack",
                                 binding=card["binding_sha256"], confirmed=True)
    assert result["status"] == "approved" and result["undo_seconds"] == 0.0


def test_undo_uses_the_shared_rule_and_audit(tmp_path, recorded, monkeypatch):
    """Undo goes through the kernel's ``WorldModel.undo_approval_decision``: the
    request is pending again, the next vote is a new signed audit round."""
    from maverick.channel_approvals import (
        ChannelApprovalRefused,
        decide_from_channel,
        undo_decision,
        undo_seconds_left,
    )

    world = _world(tmp_path)
    aid = _park(world, detail="x", undoable=True)
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, aid, undone_by="user:a", channel="slack")
    assert exc.value.reason == "not_decided"
    first = decide_from_channel(world, aid, "denied", principal="user:a", channel="slack")
    assert 0 < undo_seconds_left(world.get_approval(aid)) <= 30
    result = undo_decision(world, aid, undone_by="user:a", channel="slack")
    assert result["status"] == "pending" and result["previous_status"] == "denied"
    note = recorded[-1]
    assert note[0] == "consent_result" and note[1]["action"] == "approval_decision_undone"
    assert note[1]["channel"] == "slack" and note[1]["previous_status"] == "denied"
    assert world.get_approval(aid).status == "pending"
    # Deciding again is a new audit round: a different signed event id.
    again = decide_from_channel(world, aid, "denied", principal="user:a", channel="slack")
    assert again["decision_id"] != first["decision_id"]
    assert world.get_approval(aid).status == "denied"
    # Outside the window the undo is refused plainly.
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, aid, undone_by="user:a", channel="slack")
    assert exc.value.reason == "too_late"
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, 9999, undone_by="user:a", channel="slack")
    assert exc.value.reason == "not_found"
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, aid, undone_by="", channel="slack")
    assert exc.value.reason == "unlinked"


def test_expired_stale_and_legacy_approvals_are_refused(tmp_path, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    card = _card(expires_in=-5)
    aid = _park(world, card=card)
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid, "approved", principal="user:a", channel="slack",
                            binding=card["binding_sha256"])
    assert exc.value.reason == "expired"
    fresh = _card()
    aid2 = _park(world, card=fresh)
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid2, "approved", principal="user:a", channel="slack",
                            binding="0" * 64)
    assert exc.value.reason == "stale_card"
    legacy = _park(world, detail="plain")
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, legacy, "approved", principal="user:a", channel="slack")
    assert exc.value.reason == "stale_card"
    assert recorded == []


def test_decided_unknown_and_settings_requests_are_refused(tmp_path, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, card=card)
    decide_from_channel(world, aid, "denied", principal="user:a", channel="slack")
    for target in (aid, 9999):
        with pytest.raises(ChannelApprovalRefused) as exc:
            decide_from_channel(world, target, "denied", principal="user:a", channel="slack")
        assert exc.value.reason == "not_pending"
    settings = world.create_approval("settings", detail="x", provenance="settings_quorum")
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, settings, "denied", principal="user:a", channel="slack")
    assert exc.value.reason == "dashboard_only"


def test_requester_cannot_approve_their_own_request(tmp_path, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, card=card, approvals_required=2, requested_by="user:req")
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid, "approved", principal="user:req", channel="slack",
                            binding=card["binding_sha256"])
    assert exc.value.reason == "vote_not_accepted"
    first = decide_from_channel(world, aid, "approved", principal="user:one", channel="slack",
                                binding=card["binding_sha256"])
    assert first["status"] == "pending"  # one of two votes


def test_unlinked_principal_and_bad_inputs(tmp_path):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    aid = _park(world, detail="x")
    with pytest.raises(ChannelApprovalRefused) as exc:
        decide_from_channel(world, aid, "denied", principal="", channel="slack")
    assert exc.value.reason == "unlinked"
    with pytest.raises(ValueError):
        decide_from_channel(world, aid, "maybe", principal="user:a", channel="slack")
    with pytest.raises(ValueError):
        decide_from_channel(world, aid, "denied", principal="user:a", channel="pigeon")


def test_dashboard_api_uses_the_shared_audit_delivery():
    from maverick import channel_approvals
    from maverick_dashboard import api

    assert api._audit_approval_decision is channel_approvals.audit_approval_decision


# ----------------------------------------------------------- announcements

def test_new_approval_is_announced_to_slack_when_configured(tmp_path, monkeypatch, recorded):
    from maverick import channel_approvals, slack_interactive

    world = _world(tmp_path)
    (tmp_path / "config.toml").write_text(
        '[channels.slack]\nbot_token = "xoxb-test-not-real"\napprovals_channel = "C123"\n')
    posted = {}
    monkeypatch.setattr(slack_interactive, "post_message",
                        lambda token, channel, text, blocks=None, thread_ts=None:
                        posted.update(token=token, channel=channel, blocks=blocks) or "1.2")
    aid = _park(world, risk="high", card=_card())
    outcomes = channel_approvals.announce_new_approval(world, aid)
    assert outcomes["slack"] is True
    # Teams (registered by maverick.approval_notify) is quiet when not configured.
    assert all(v is False for name, v in outcomes.items() if name != "slack")
    assert posted["channel"] == "C123" and posted["token"] == "xoxb-test-not-real"
    assert posted["blocks"][-1]["type"] == "actions"


def test_registered_announcer_and_missing_config_are_quiet(tmp_path, monkeypatch):
    from maverick import channel_approvals

    world = _world(tmp_path)
    aid = _park(world, detail="x")
    quiet = channel_approvals.announce_new_approval(world, aid)
    assert quiet["slack"] is False and all(v is False for v in quiet.values())
    seen = []
    previous = dict(channel_approvals._announcers)
    channel_approvals.register_approval_announcer("teams", lambda a, c: seen.append(c["id"]) or True)
    try:
        assert channel_approvals.announce_new_approval(world, aid)["teams"] is True
        assert seen == [aid]
    finally:
        channel_approvals.register_approval_announcer("teams", previous.get("teams"))
    assert channel_approvals.announce_new_approval(world, 9999) == {}


def test_world_model_announces_once_after_the_row_commits(tmp_path, monkeypatch):
    """The one call site: WorldModel.create_approval -> approval_notify (background
    thread) -> announce_new_approval; consent no longer announces on its own."""
    import inspect

    from maverick import approval_notify, channel_approvals
    from maverick.safety import consent

    started = []
    monkeypatch.setattr(approval_notify.threading, "Thread",
                        lambda **kw: started.append(kw) or type("T", (), {"start": lambda self: None})())
    monkeypatch.setattr(approval_notify, "announcements_configured", lambda: True)
    world = _world(tmp_path)
    aid = _park(world, detail="x")
    assert len(started) == 1 and started[0]["daemon"] is True
    assert "teams" in channel_approvals.registered_announcers()
    assert "announce_new_approval" not in inspect.getsource(consent)
    # Settings requests are decided on the dashboard only: no card anywhere.
    world.create_approval("settings", detail="x", provenance="settings_quorum")
    assert len(started) == 1
    assert aid


# ---------------------------------------------------------- identity linking

def test_identity_linking_by_admin_and_lookup(recorded):
    from maverick import channel_identities as ids

    ids.link("slack", "U123", "user:alice", actor="user:admin")
    assert ids.principal_for("slack", "U123") == "user:alice"
    assert ids.principal_for("slack", "U999") is None
    assert ids.principal_for("pigeon", "U123") is None
    assert [r["external_id"] for r in ids.links_for("user:alice")] == ["U123"]
    with pytest.raises(ids.ChannelIdentityError):
        ids.link("slack", "U123", "user:bob", actor="user:admin")
    ids.link("email", "Alice@Example.com", "user:alice", actor="user:admin")
    assert ids.principal_for("email", "alice@example.com") == "user:alice"
    assert set(ids.all_links()) == {"user:alice"}
    assert ids.unlink("slack", "U123", actor="user:admin") is True
    assert ids.unlink("slack", "U123", actor="user:admin") is False
    kinds = [k for k, _ in recorded]
    assert kinds == ["channel_identity_linked"] * 2 + ["channel_identity_unlinked"]
    assert recorded[0][1]["method"] == "admin"


def test_one_time_code_links_once_and_expires():
    from maverick import channel_identities as ids

    issued = ids.issue_link_code("user:alice", "slack", now=1000.0)
    code = issued["code"]
    assert len(code) == 8 and ids.store_path().read_text().count(code) == 0  # hashed
    assert ids.redeem_link_code("slack", "U1", "wrong", now=1001.0) is None
    assert ids.redeem_link_code("teams", "U1", code, now=1001.0) is None  # other channel
    assert ids.redeem_link_code("slack", "U1", code.lower(), now=1001.0) == "user:alice"
    assert ids.redeem_link_code("slack", "U2", code, now=1002.0) is None  # used
    later = ids.issue_link_code("user:alice", "slack", now=2000.0)["code"]
    assert ids.redeem_link_code("slack", "U3", later, now=2000.0 + ids.CODE_TTL_SECONDS + 1) is None


def test_self_unlink_only_removes_own_link():
    from maverick import channel_identities as ids

    ids.link("slack", "U1", "user:alice", actor="user:admin")
    assert ids.unlink("slack", "U1", actor="user:bob", expected_principal="user:bob") is False
    assert ids.unlink("slack", "U1", actor="user:alice", expected_principal="user:alice") is True


def test_user_preferences_defaults_validation_and_send_marker():
    from maverick import user_preferences as prefs

    row = prefs.get_preferences("user:alice")
    assert row["time_zone"] == "UTC" and row["digest_enabled"] is True and row["digest_hour"] == 8
    saved = prefs.set_preferences("user:alice", time_zone="Europe/London", digest_hour=7,
                                  email="Alice@Example.com", digest_enabled=False)
    assert saved["time_zone"] == "Europe/London" and saved["email"] == "alice@example.com"
    assert saved["digest_enabled"] is False
    for bad in ({"time_zone": "Mars/Olympus"}, {"digest_hour": 24}, {"email": "nope"},
                {"digest_enabled": "yes"}, {"unknown": 1}):
        with pytest.raises(prefs.UserPreferenceError):
            prefs.set_preferences("user:alice", **bad)
    prefs.mark_digest_sent("user:alice", "2026-09-30")
    assert prefs.get_preferences("user:alice")["last_digest_date"] == "2026-09-30"
    assert prefs.principals_with_preferences() == ["user:alice"]
    assert "UTC" in prefs.time_zone_choices()


# ----------------------------------------- malformed input and undo limits

def test_an_action_label_with_a_non_ascii_character_can_still_be_approved(tmp_path, recorded):
    from maverick.channel_approvals import decide_from_channel

    world = _world(tmp_path)
    card = _card(action="envoyer.résumé")
    aid = _park(world, card=card, action="envoyer.résumé")
    result = decide_from_channel(world, aid, "approved", principal="user:a", channel="slack",
                                 binding=card["binding_sha256"])
    assert result["status"] == "approved"


def test_a_queued_action_holding_a_lone_surrogate_is_a_stale_card_not_a_crash():
    from types import SimpleNamespace

    from maverick.approval_cards import encode_approval_detail
    from maverick.channel_approvals import ChannelApprovalRefused, require_current_card

    card = _card()
    approval = SimpleNamespace(detail=encode_approval_detail(card), action="browser.\ud800")
    with pytest.raises(ChannelApprovalRefused) as exc:
        require_current_card(approval, binding=card["binding_sha256"])
    assert exc.value.reason == "stale_card"


def test_an_undo_the_audit_log_refuses_is_a_refusal_not_a_server_error(tmp_path, recorded, monkeypatch):
    import maverick.audit as audit
    from maverick.channel_approvals import (
        ChannelApprovalRefused,
        decide_from_channel,
        undo_decision,
    )

    world = _world(tmp_path)
    aid = _park(world, detail="x", undoable=True)
    decide_from_channel(world, aid, "denied", principal="user:a", channel="slack")

    def refused(*args, **kwargs):
        raise audit.AuditRefused("policy requires off-host signing")

    monkeypatch.setattr(audit, "audit_event", refused)
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, aid, undone_by="user:a", channel="slack")
    assert exc.value.reason == "audit_failed"
    assert world.get_approval(aid).status == "pending"                 # the undo itself is not hidden


def test_an_unreadable_approval_state_never_claims_the_request_settled(tmp_path, recorded, monkeypatch):
    from maverick.channel_approvals import decide_from_channel

    world = _world(tmp_path)
    card = _card()
    aid = _park(world, card=card)
    monkeypatch.setattr(world, "approval_state", lambda approval_id: (_ for _ in ()).throw(OSError("busy")))
    result = decide_from_channel(world, aid, "approved", principal="user:a", channel="slack",
                                 binding=card["binding_sha256"])
    assert result["status"] == "pending" and result["effective"] is False and result["undo_seconds"] == 0.0


def test_a_chat_card_offers_no_undo_for_a_decision_nothing_waits_on(tmp_path, recorded):
    from maverick.channel_approvals import (
        ChannelApprovalRefused,
        decide_from_channel,
        undo_decision,
        undo_seconds_left,
    )

    world = _world(tmp_path)
    aid = _park(world, detail="x", provenance="codebase")
    result = decide_from_channel(world, aid, "denied", principal="user:a", channel="slack")
    assert result["effective"] and result["undo_seconds"] == 0.0
    assert undo_seconds_left(world.get_approval(aid)) == 0.0
    with pytest.raises(ChannelApprovalRefused) as exc:
        undo_decision(world, aid, undone_by="user:a", channel="slack")
    assert exc.value.reason == "final" and exc.value.status_code == 409
    assert world.get_approval(aid).status == "denied"
