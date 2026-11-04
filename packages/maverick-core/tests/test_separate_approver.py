"""A second person approves high-risk actions when one is available.

``[approval] separate_approver`` decides whether the person who asked for a
high or critical risk action may approve it themselves: ``"when_available"``
(the default) refuses that whenever someone else could decide the request,
``"always"`` refuses it even when nobody else can (the request then waits and
expires, which refuses the action), and ``"never"`` allows it. Allowed
self-approvals are recorded as such. The rule is enforced in the one shared
decision path (:func:`maverick.channel_approvals.record_vote`), so the
Approvals page, Slack and Teams all obey it. With two or more approvers the
quorum already brings in other people, and ``[security] allow_self_approval``
alone decides whether the requester's vote counts.
"""
from __future__ import annotations

import time

import pytest

REQUESTER = "user:sam.lee@northwind.example"
MANAGER = "user:dana.admin@northwind.example"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_TENANT", "MAVERICK_SEPARATE_APPROVER",
                 "MAVERICK_ALLOW_SELF_APPROVAL", "MAVERICK_APPROVALS_REQUIRED"):
        monkeypatch.delenv(name, raising=False)
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


@pytest.fixture
def others(monkeypatch):
    """Who else could decide a request: set ``others.people`` in a test."""
    from maverick import channel_approvals

    class Others:
        people: list[str] = []

    monkeypatch.setattr(channel_approvals, "other_approver_available",
                        lambda world, approval, requester: bool(Others.people))
    return Others


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _config(tmp_path, text: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def _park(world, *, risk="high", required=1, requested_by=REQUESTER, provenance=None):
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="shell", summary="Run one command in the sandbox.", target_label="sandbox:/work",
        target={"workdir": "/work"}, parameters={"command": "ls"},
        parameter_summary=["Runs the command once."], actor=requested_by or REQUESTER,
        workspace="local", role="operator", authority_versions={}, input_versions={},
        credential_versions={}, budget={}, expires_at=time.time() + 600,
        known_effects=["Runs one command."], unresolved_assumptions=[], before="Not run.",
        after="Run once.", irreversible=True,
    )
    approval_id = world.create_approval("shell", risk=risk, scope="sandbox:/work",
                                        detail=encode_approval_detail(card),
                                        approvals_required=required, requested_by=requested_by,
                                        provenance=provenance)
    return approval_id, card["binding_sha256"]


# ---------------------------------------------------------------- the setting

def test_the_default_is_when_another_approver_is_available():
    from maverick.safety.dual_control import separate_approver_mode

    assert separate_approver_mode() == "when_available"


@pytest.mark.parametrize("value", ["when_available", "always", "never"])
def test_each_mode_is_read_from_the_approval_section(tmp_path, value):
    from maverick.safety.dual_control import separate_approver_mode

    _config(tmp_path, f'[approval]\nseparate_approver = "{value}"\n')
    assert separate_approver_mode() == value


def test_the_environment_wins_and_an_unknown_value_fails_closed(tmp_path, monkeypatch):
    from maverick.safety.dual_control import separate_approver_mode

    _config(tmp_path, '[approval]\nseparate_approver = "never"\n')
    monkeypatch.setenv("MAVERICK_SEPARATE_APPROVER", "always")
    assert separate_approver_mode() == "always"
    monkeypatch.delenv("MAVERICK_SEPARATE_APPROVER")
    _config(tmp_path, '[approval]\nseparate_approver = "sometimes"\n')
    assert separate_approver_mode() == "always"


# ------------------------------------------------------------- who is refused

def test_requester_is_refused_when_another_approver_is_available(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    approval = world.get_approval(approval_id)
    others.people = [MANAGER]
    assert separate_approver_refusal(world, approval, REQUESTER) == (
        "Another approver is available, so someone else must approve this.")
    # Anyone else may approve, and the rule never touches a rejection.
    assert separate_approver_refusal(world, approval, MANAGER) == ""


def test_a_requester_who_is_the_only_approver_may_approve(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = []
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""


@pytest.mark.parametrize("risk", ["low", "medium"])
def test_lower_risk_requests_are_not_affected(tmp_path, others, risk):
    from maverick.channel_approvals import separate_approver_refusal

    world = _world(tmp_path)
    approval_id, _binding = _park(world, risk=risk)
    others.people = [MANAGER]
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""


def test_always_refuses_even_when_nobody_else_can_decide(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    _config(tmp_path, '[approval]\nseparate_approver = "always"\n')
    world = _world(tmp_path)
    approval_id, _binding = _park(world, risk="critical")
    others.people = []
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == (
        "You asked for this, so someone else must approve it.")


def test_never_lets_the_requester_approve(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    _config(tmp_path, '[approval]\nseparate_approver = "never"\n')
    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = [MANAGER]
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""


def test_a_request_with_no_known_requester_is_not_affected(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    world = _world(tmp_path)
    approval_id, _binding = _park(world, requested_by=None)
    others.people = [MANAGER]
    assert separate_approver_refusal(world, world.get_approval(approval_id), "operator") == ""


def test_the_kernel_without_the_dashboard_counts_nobody_else(tmp_path, monkeypatch):
    import builtins

    from maverick.channel_approvals import other_approver_available

    real_import = builtins.__import__

    def no_dashboard(name, *args, **kwargs):
        if name.startswith("maverick_dashboard"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    monkeypatch.setattr(builtins, "__import__", no_dashboard)
    assert other_approver_available(world, world.get_approval(approval_id), REQUESTER) is False


# ---------------------------------------------- the one shared decision path

def test_the_shared_vote_refuses_the_requester_with_a_plain_sentence(tmp_path, others, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, record_vote

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = [MANAGER]
    with pytest.raises(ChannelApprovalRefused) as refused:
        record_vote(world, approval_id, "approved", REQUESTER)
    assert refused.value.reason == "separate_approver"
    assert refused.value.status_code == 403
    assert refused.value.message == "Another approver is available, so someone else must approve this."
    assert world.get_approval(approval_id).status == "pending"
    assert world.pending_approval_audit_events(approval_id=approval_id, limit=10) == []
    # The requester can still reject (withdraw) their own request.
    event = record_vote(world, approval_id, "denied", REQUESTER)
    assert event.final_status == "denied"


def test_the_other_approver_decides_and_is_recorded(tmp_path, others, recorded):
    from maverick.channel_approvals import audit_approval_decision, record_vote

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = [MANAGER]
    event = record_vote(world, approval_id, "approved", MANAGER)
    assert audit_approval_decision(world, event) is True
    row = world.get_approval(approval_id)
    assert row.status == "approved" and row.decided_by == MANAGER
    decision = next(p for kind, p in recorded if kind == "approval_decision")
    assert decision["decided_by"] == MANAGER and "self_approval" not in decision


def test_a_one_person_installation_records_a_self_approval(tmp_path, others, recorded):
    from maverick.channel_approvals import audit_approval_decision, record_vote

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = []
    event = record_vote(world, approval_id, "approved", REQUESTER)
    assert audit_approval_decision(world, event) is True
    assert world.get_approval(approval_id).status == "approved"
    decision = next(p for kind, p in recorded if kind == "approval_decision")
    assert decision["self_approval"] is True


def test_a_retried_vote_keeps_its_accepted_outcome(tmp_path, others, recorded):
    # A self-approval accepted while the requester was the only approver is not
    # turned into a refusal by a retry after a colleague became available (the
    # first answer's acknowledgement was lost; the vote is already durable).
    from maverick.channel_approvals import record_vote

    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = []
    first = world.decide_approval_audited(approval_id, "approved", decided_by=REQUESTER)
    others.people = [MANAGER]
    again = record_vote(world, approval_id, "approved", REQUESTER)
    assert again.event_id == first.event_id


@pytest.mark.parametrize("allow_self", [False, True])
def test_with_two_approvers_the_quorum_rule_alone_decides(tmp_path, others, recorded,
                                                          monkeypatch, allow_self):
    from maverick.channel_approvals import ChannelApprovalRefused, record_vote

    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1" if allow_self else "0")
    world = _world(tmp_path)
    approval_id, _binding = _park(world, required=2)
    others.people = [MANAGER]
    if allow_self:
        # Two distinct people approve either way; the requester counts as one.
        event = record_vote(world, approval_id, "approved", REQUESTER)
        assert event.final_status is None
        assert record_vote(world, approval_id, "approved", MANAGER).final_status == "approved"
    else:
        with pytest.raises(ChannelApprovalRefused) as refused:
            record_vote(world, approval_id, "approved", REQUESTER)
        assert refused.value.reason == "vote_not_accepted"


def test_always_with_two_approvers_still_follows_the_quorum_rule(tmp_path, others, recorded,
                                                                monkeypatch):
    from maverick.channel_approvals import record_vote

    _config(tmp_path, '[approval]\nseparate_approver = "always"\n')
    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1")
    world = _world(tmp_path)
    approval_id, _binding = _park(world, required=2)
    others.people = []
    assert record_vote(world, approval_id, "approved", REQUESTER).final_status is None


# --------------------------------------------------------------------- Slack

def test_slack_obeys_the_rule(tmp_path, others, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    approval_id, binding = _park(world)
    others.people = [MANAGER]
    with pytest.raises(ChannelApprovalRefused) as refused:
        decide_from_channel(world, approval_id, "approved", principal=REQUESTER, channel="slack",
                            binding=binding, confirmed=True, acknowledged=True)
    assert refused.value.message == "Another approver is available, so someone else must approve this."
    assert world.get_approval(approval_id).status == "pending"
    result = decide_from_channel(world, approval_id, "approved", principal=MANAGER, channel="slack",
                                 binding=binding, confirmed=True, acknowledged=True)
    assert result["status"] == "approved" and result["decided_by"] == MANAGER


def test_a_refused_chat_vote_records_no_confirmation(tmp_path, others, recorded):
    from maverick.channel_approvals import ChannelApprovalRefused, decide_from_channel

    world = _world(tmp_path)
    approval_id, binding = _park(world)
    others.people = [MANAGER]
    with pytest.raises(ChannelApprovalRefused):
        decide_from_channel(world, approval_id, "approved", principal=REQUESTER, channel="teams",
                            binding=binding, confirmed=True, acknowledged=True)
    assert not [p for _kind, p in recorded if p.get("action") == "approval_confirmation"]


def test_a_slack_button_tells_the_requester_privately(tmp_path, others, recorded):
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value, handle_block_action

    world = _world(tmp_path)
    approval_id, binding = _park(world)
    others.people = [MANAGER]
    answer = handle_block_action(
        {"type": "block_actions", "user": {"id": "U1"},
         "actions": [{"action_id": ACTION_APPROVE, "value": encode_button_value(approval_id, binding)}]},
        world=world, principal_for=lambda _user: REQUESTER,
    )
    assert answer["response_type"] == "ephemeral"
    assert answer["text"] == "Another approver is available, so someone else must approve this."
    assert world.get_approval(approval_id).status == "pending"


def test_a_publication_bypass_is_never_approved_by_the_person_who_asked(tmp_path, others):
    """A reasoned bypass of the passing tests needs someone else in every mode, not only the default."""
    from maverick.channel_approvals import separate_approver_refusal

    bypass = "agent_publish.bypass.four_eyes.v1"
    others.people = []  # nobody else could decide it
    for mode in ("when_available", "always", "never"):
        _config(tmp_path, f'[approval]\nseparate_approver = "{mode}"\n')
        world = _world(tmp_path)
        approval_id, _binding = _park(world, provenance=bypass)
        assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == (
            "You asked for this, so someone else must approve it."), mode
        assert separate_approver_refusal(world, world.get_approval(approval_id), MANAGER) == ""
        world.close()


def test_an_ordinary_request_is_still_allowed_to_its_requester_when_switched_to_never(tmp_path, others):
    from maverick.channel_approvals import separate_approver_refusal

    _config(tmp_path, '[approval]\nseparate_approver = "never"\n')
    world = _world(tmp_path)
    approval_id, _binding = _park(world)
    others.people = []
    assert separate_approver_refusal(world, world.get_approval(approval_id), REQUESTER) == ""
    world.close()
