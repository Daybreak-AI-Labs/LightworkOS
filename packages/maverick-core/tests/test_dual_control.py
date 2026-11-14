"""N-of-M dual control (segregation of duties) over the approvals queue."""
from __future__ import annotations

import pytest
from maverick.safety import dual_control
from maverick.world_model import WorldModel


@pytest.fixture
def wm(tmp_path):
    return WorldModel(tmp_path / "w.db")


# --- config resolution ------------------------------------------------------

def test_required_approvals_default_is_one(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", dict)
    assert dual_control.required_approvals("high") == 1


def test_required_approvals_global_int(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": 2})
    assert dual_control.required_approvals("low") == 2


def test_required_approvals_per_risk_table(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": {"high": 2, "critical": 3,
                                                        "default": 1}})
    assert dual_control.required_approvals("critical") == 3
    assert dual_control.required_approvals("high") == 2
    assert dual_control.required_approvals("medium") == 1   # falls to default


def test_required_approvals_env_wins(monkeypatch):
    monkeypatch.setattr(dual_control, "_security_cfg",
                        lambda: {"approvals_required": 5})
    monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", "2")
    assert dual_control.required_approvals("high") == 2


def test_per_risk_minimums_only_add_approvers(monkeypatch):
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", lambda: {
        "approvals_required": 2,
        "approvals_required_by_risk": {"critical": 4, "low": 1},
    })
    assert dual_control.required_approvals("critical") == 4
    assert dual_control.required_approvals("low") == 2   # never fewer than the base
    assert dual_control.required_approvals("high") == 2
    monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", "3")
    assert dual_control.required_approvals("critical") == 3  # the environment still wins


def test_unparseable_env_does_not_lower_the_configured_quorum(monkeypatch):
    monkeypatch.setattr(dual_control, "_security_cfg", lambda: {"approvals_required": 2})
    for value in ("two", "0", "-1"):
        monkeypatch.setenv("MAVERICK_APPROVALS_REQUIRED", value)
        assert dual_control.required_approvals("high") == 2, value


def test_allow_self_approval_default_false(monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    monkeypatch.setattr(dual_control, "_security_cfg", dict)
    assert dual_control.allow_self_approval() is False
    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1")
    assert dual_control.allow_self_approval() is True


# --- single-approver (legacy) ----------------------------------------------

def test_single_approver_unchanged(wm):
    aid = wm.create_approval("delete prod", risk="high")          # required defaults to 1
    assert wm.decide_approval(aid, "approved", decided_by="u:a") is True
    assert wm.get_approval(aid).status == "approved"


# --- N-of-M quorum ----------------------------------------------------------

def test_two_distinct_approvers_required(wm):
    aid = wm.create_approval("wire $1M", risk="critical", approvals_required=2)
    assert wm.decide_approval(aid, "approved", decided_by="u:alice") is True
    assert wm.get_approval(aid).status == "pending"             # one vote: not yet
    assert wm.decide_approval(aid, "approved", decided_by="u:bob") is True
    assert wm.get_approval(aid).status == "approved"            # quorum met


def test_same_approver_counts_once(wm):
    aid = wm.create_approval("wire $1M", risk="critical", approvals_required=2)
    wm.decide_approval(aid, "approved", decided_by="u:alice")
    wm.decide_approval(aid, "approved", decided_by="u:alice")   # repeat -> idempotent
    assert wm.get_approval(aid).status == "pending"
    st = wm.approval_state(aid)
    assert st["approved_count"] == 1 and st["approvals_required"] == 2


def test_single_deny_rejects_even_under_quorum(wm):
    aid = wm.create_approval("wire $1M", risk="critical", approvals_required=2)
    wm.decide_approval(aid, "approved", decided_by="u:alice")
    assert wm.decide_approval(aid, "denied", decided_by="u:bob") is True
    assert wm.get_approval(aid).status == "denied"


def test_requester_cannot_self_approve(wm, monkeypatch):
    monkeypatch.setattr(dual_control, "allow_self_approval", lambda: False)
    aid = wm.create_approval("wire $1M", risk="critical", approvals_required=2,
                             requested_by="u:alice")
    # alice (the requester) tries to approve her own request -> barred.
    assert wm.decide_approval(aid, "approved", decided_by="u:alice") is False
    assert wm.approval_state(aid)["approved_count"] == 0
    # a different approver counts.
    assert wm.decide_approval(aid, "approved", decided_by="u:bob") is True
    assert wm.approval_state(aid)["approved_count"] == 1


def test_self_approval_allowed_when_configured(wm, monkeypatch):
    monkeypatch.setattr(dual_control, "allow_self_approval", lambda: True)
    # With self-approval allowed, the requester's own vote counts toward quorum.
    aid = wm.create_approval("y", risk="high", approvals_required=2,
                             requested_by="u:alice")
    assert wm.decide_approval(aid, "approved", decided_by="u:alice") is True
    assert wm.approval_state(aid)["approved_count"] == 1


def test_multiparty_requires_approver_identity(wm):
    aid = wm.create_approval("x", risk="critical", approvals_required=2)
    assert wm.decide_approval(aid, "approved", decided_by="") is False
    assert wm.decide_approval(aid, "approved", decided_by=None) is False


def test_decided_approval_is_terminal(wm):
    aid = wm.create_approval("x", risk="critical", approvals_required=2)
    wm.decide_approval(aid, "approved", decided_by="u:a")
    wm.decide_approval(aid, "approved", decided_by="u:b")       # -> approved
    # further votes on a decided approval are no-ops.
    assert wm.decide_approval(aid, "denied", decided_by="u:c") is False
    assert wm.get_approval(aid).status == "approved"


def test_approval_state_unknown_is_none(wm):
    assert wm.approval_state(99999) is None


# --- requester wiring: consent attributes the request to the goal owner -----
# The self-approval bar above is only reachable if `requested_by` is actually
# set on production approvals. The consent gate resolves it from the executing
# goal's owner (same namespace as the dashboard approver).

def test_consent_requester_resolves_goal_owner(wm):
    from maverick.logging_config import reset_goal_context, set_goal_context
    from maverick.safety import consent

    gid = wm.create_goal("ship", "d", owner="u:alice")
    assert consent._consent_requester(wm) is None          # outside any goal
    tokens = set_goal_context(goal_id=gid)
    try:
        assert consent._consent_requester(wm) == "u:alice"
    finally:
        reset_goal_context(tokens)
    assert consent._consent_requester(wm) is None           # restored


def test_consent_requester_unowned_goal_is_none(wm):
    from maverick.logging_config import reset_goal_context, set_goal_context
    from maverick.safety import consent

    gid = wm.create_goal("ship", "d", owner="")             # single-user / no-auth
    tokens = set_goal_context(goal_id=gid)
    try:
        assert consent._consent_requester(wm) is None
    finally:
        reset_goal_context(tokens)


def test_dashboard_consent_attributes_requester(wm, monkeypatch):
    import maverick.world_model as world_model
    from maverick.logging_config import reset_goal_context, set_goal_context
    from maverick.safety import consent

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: wm)
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "0")  # queue then time out
    captured: dict = {}
    real = wm.create_approval

    def _spy(*a, **k):
        captured.update(k)
        return real(*a, **k)

    monkeypatch.setattr(wm, "create_approval", _spy)
    gid = wm.create_goal("rm -rf /tmp/x", "d", owner="u:alice")
    tokens = set_goal_context(goal_id=gid)
    try:
        decision = consent._decide_via_dashboard("rm-rf", "high", "/tmp/x", "d", "test")
    finally:
        reset_goal_context(tokens)
    assert decision is None                       # timed out: no human decision
    assert captured.get("requested_by") == "u:alice"


def test_approval_states_batch_matches_per_id_state(wm, monkeypatch):
    # The audit binder reads quorum state for a whole window through one batch;
    # every entry must equal the per-id reader for the same approval.
    monkeypatch.setattr(dual_control, "allow_self_approval", lambda: True)
    pending = wm.create_approval("p", risk="high", approvals_required=2)
    quorum = wm.create_approval("q", risk="critical", approvals_required=2)
    solo = wm.create_approval("s", risk="low", approvals_required=1)
    wm.decide_approval(quorum, "approved", decided_by="u:alice")
    wm.decide_approval(quorum, "approved", decided_by="u:bob")   # quorum met
    wm.decide_approval_audited(solo, "approved", decided_by="u:carol")  # audit row pending
    listed = wm.list_approvals(limit=50)
    batch = wm.approval_states(listed)
    assert set(batch) == {pending, quorum, solo}
    for approval in listed:
        assert batch[approval.id] == wm.approval_state(approval.id)
    assert batch[pending]["approved_count"] == 0 and batch[pending]["effective"] is False
    assert batch[quorum]["approvers"] == ["u:alice", "u:bob"] and batch[quorum]["effective"]
    assert batch[solo]["effective"] is False and batch[solo]["audit_pending_count"] == 1
    assert wm.approval_states([]) == {}


def test_approvals_requested_between_is_the_python_window_filter(wm, monkeypatch):
    # The audit binder reads its window in SQL. Rows, order and every field must
    # equal list_approvals filtered on requested_at, for ties and both edges,
    # and only the window's rows may be decoded.
    import random

    from maverick import world_model

    rng = random.Random(7)
    ids = [wm.create_approval(f"a{i}", risk="low", approvals_required=1) for i in range(120)]
    stamps = [float(rng.choice([100, 150, 200, 200, 250, 300, 300.5, 400])) for _ in ids]
    with wm._writing() as conn:
        for approval_id, stamp in zip(ids, stamps, strict=True):
            conn.execute("UPDATE approvals SET requested_at = ? WHERE id = ?", (stamp, approval_id))
    everything = wm.list_approvals(limit=10_000)
    assert len(everything) == len(ids)
    for since, until in [(100.0, 300.0), (200.0, 200.0), (150.0, 150.0), (300.5, 1e12),
                         (0.0, 1e12), (401.0, 500.0), (300.0, 100.0)]:
        expected = [a for a in everything if since <= float(a.requested_at or 0) <= until]
        assert wm.approvals_requested_between(since, until) == expected

    decoded: list[int] = []
    real_decode = world_model._approvals_from_rows

    def spy(rows):
        decoded.append(len(rows))
        return real_decode(rows)

    monkeypatch.setattr(world_model, "_approvals_from_rows", spy)
    in_window = [a for a in everything if a.requested_at == 200.0]
    assert [a.id for a in wm.approvals_requested_between(200.0, 200.0)] == [a.id for a in in_window]
    assert decoded == [len(in_window)]
