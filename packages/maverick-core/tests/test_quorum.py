"""Quorum approval for config changes: propose -> approve -> approved flow,
separation of duties, protected-key matching, expiry via injected clock,
atomic persistence roundtrip. Offline and deterministic.
"""
from __future__ import annotations

import json

import pytest
from maverick import quorum
from maverick.file_lock import private_path_is_restricted


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_QUORUM_REQUIRED", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))


@pytest.fixture
def clock():
    """A mutable injected clock: ``clock.now[0]`` is the current time."""
    class _Clock:
        def __init__(self):
            self.now = [1_000_000.0]

        def __call__(self):
            return self.now[0]

    return _Clock()


@pytest.fixture
def store(tmp_path, clock):
    return quorum.ProposalStore(path=tmp_path / "proposals.json", clock=clock)


def _propose(store, change_id="chg-1", key="budget.max_dollars",
             proposer="alice", policy=None):
    return quorum.propose(change_id, key, 5.0, 500.0, proposer,
                          store=store, policy=policy or quorum.QuorumPolicy())


# --- protection matching ------------------------------------------------------

@pytest.mark.parametrize("key,protected", [
    ("safety.profile", True),
    ("safety.goal_risk_floor", True),
    ("governance.deny_actions", True),
    ("budget.max_dollars", True),
    ("plugins.allow", True),
    ("budget.max_tool_calls", False),
    ("models.orchestrator", False),
    ("safety", False),               # the glob is "safety.*", not "safety"
])
def test_default_protected_keys(key, protected):
    assert quorum.is_protected(key, quorum.QuorumPolicy()) is protected


def test_apply_gate_is_the_inverse_of_protection():
    policy = quorum.QuorumPolicy()
    assert quorum.apply_gate("models.orchestrator", policy=policy) is True
    assert quorum.apply_gate("budget.max_dollars", policy=policy) is False


# --- the full flow ------------------------------------------------------------

def test_propose_approve_approved_flow(store):
    _propose(store, proposer="alice")
    assert quorum.status("chg-1", store=store) == quorum.PENDING

    p = quorum.approve("chg-1", "bob", store=store)
    assert len(p.approvals) == 1 and not p.approved()
    assert quorum.status("chg-1", store=store) == quorum.PENDING

    p = quorum.approve("chg-1", "carol", store=store)
    assert p.approved()
    assert quorum.status("chg-1", store=store) == quorum.APPROVED
    # Approvals carry who + when.
    assert [a for a, _ in p.approvals] == ["bob", "carol"]
    assert all(isinstance(t, float) for _, t in p.approvals)


def test_self_approval_refused(store):
    _propose(store, proposer="alice")
    with pytest.raises(quorum.QuorumError, match="separation of duties"):
        quorum.approve("chg-1", "alice", store=store)
    with pytest.raises(quorum.QuorumError, match="separation of duties"):
        quorum.approve("chg-1", "  ALICE ", store=store)  # case/space games


def test_duplicate_approver_refused(store):
    _propose(store, proposer="alice")
    quorum.approve("chg-1", "bob", store=store)
    with pytest.raises(quorum.QuorumError, match="already approved"):
        quorum.approve("chg-1", "bob", store=store)
    with pytest.raises(quorum.QuorumError, match="already approved"):
        quorum.approve("chg-1", "Bob", store=store)


def test_unknown_proposal_and_blank_names(store):
    with pytest.raises(quorum.QuorumError, match="unknown proposal"):
        quorum.approve("nope", "bob", store=store)
    with pytest.raises(quorum.QuorumError, match="unknown proposal"):
        quorum.status("nope", store=store)
    with pytest.raises(quorum.QuorumError, match="named proposer"):
        _propose(store, change_id="chg-x", proposer="   ")
    with pytest.raises(quorum.QuorumError, match="named approver"):
        quorum.approve("chg-x", "", store=store)


def test_duplicate_change_id_refused(store):
    _propose(store)
    with pytest.raises(quorum.QuorumError, match="already exists"):
        _propose(store)


def test_concurrent_approvals_accumulate(store):
    """Two approvals racing on the same proposal must both land, not
    last-writer-wins clobber each other (the store's stated guarantee)."""
    import threading

    _propose(store, proposer="alice")
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def _approve(who):
        try:
            barrier.wait()  # maximize the load-modify-save overlap
            quorum.approve("chg-1", who, store=store)
        except Exception as e:  # noqa: BLE001 -- surfaced via the list below
            errors.append(e)

    threads = [threading.Thread(target=_approve, args=(w,))
               for w in ("bob", "carol")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    approvers = {a for a, _ in store.get("chg-1").approvals}
    assert approvers == {"bob", "carol"}  # both accumulated
    assert quorum.status("chg-1", store=store) == quorum.APPROVED


def test_required_snapshotted_at_propose_time(store):
    policy3 = quorum.QuorumPolicy(required=3)
    _propose(store, policy=policy3)
    quorum.approve("chg-1", "bob", store=store)
    quorum.approve("chg-1", "carol", store=store)
    # Even consulted with a looser policy later, the snapshot (3) governs.
    assert quorum.status("chg-1", store=store,
                         policy=quorum.QuorumPolicy(required=2)) == quorum.PENDING
    quorum.approve("chg-1", "dave", store=store)
    assert quorum.status("chg-1", store=store) == quorum.APPROVED


# --- expiry (injected clock) ----------------------------------------------------

def test_expiry_via_injected_clock(store, clock):
    _propose(store)
    quorum.approve("chg-1", "bob", store=store)
    clock.now[0] += 8 * 86400.0                      # ttl_days=7 -> stale
    assert quorum.status("chg-1", store=store) == quorum.EXPIRED
    with pytest.raises(quorum.QuorumError, match="expired"):
        quorum.approve("chg-1", "carol", store=store)


def test_approved_proposal_expires_via_status(store, clock):
    _propose(store)
    quorum.approve("chg-1", "bob", store=store)
    quorum.approve("chg-1", "carol", store=store)
    assert quorum.status("chg-1", store=store) == quorum.APPROVED

    clock.now[0] += 8 * 86400.0                      # ttl_days=7 -> stale
    assert quorum.status("chg-1", store=store) == quorum.EXPIRED


def test_not_expired_just_inside_ttl(store, clock):
    _propose(store)
    clock.now[0] += 7 * 86400.0                      # exactly the boundary
    assert quorum.status("chg-1", store=store) == quorum.PENDING


def test_prune_removes_only_stale(store, clock):
    _propose(store, change_id="old")
    clock.now[0] += 8 * 86400.0
    _propose(store, change_id="fresh")
    assert quorum.prune(store=store) == 1
    with pytest.raises(quorum.QuorumError, match="unknown proposal"):
        quorum.status("old", store=store)
    assert quorum.status("fresh", store=store) == quorum.PENDING


# --- persistence ----------------------------------------------------------------

def test_persistence_roundtrip(tmp_path, clock):
    store = quorum.ProposalStore(path=tmp_path / "proposals.json", clock=clock)
    _propose(store)
    quorum.approve("chg-1", "bob", store=store)

    reopened = quorum.ProposalStore(path=tmp_path / "proposals.json", clock=clock)
    p = reopened.get("chg-1")
    assert p is not None
    assert (p.key, p.old, p.new, p.proposer) == ("budget.max_dollars", 5.0, 500.0, "alice")
    assert p.approvals == (("bob", clock.now[0]),)
    quorum.approve("chg-1", "carol", store=reopened)
    assert quorum.status("chg-1", store=reopened) == quorum.APPROVED


def test_store_file_is_0600_atomic_json(tmp_path, clock):
    store = quorum.ProposalStore(path=tmp_path / "proposals.json", clock=clock)
    _propose(store)
    assert private_path_is_restricted(store.path, 0o600)
    assert private_path_is_restricted(store.path.parent, 0o700)
    assert json.loads(store.path.read_text(encoding="utf-8"))["chg-1"]["key"] \
        == "budget.max_dollars"
    # No temp-file droppings from the atomic write.
    assert list(tmp_path.glob("*.tmp")) == []


def test_corrupt_store_fails_soft(tmp_path, clock):
    path = tmp_path / "proposals.json"
    path.write_text("{ not json", encoding="utf-8")
    store = quorum.ProposalStore(path=path, clock=clock)
    assert store.get("anything") is None
    _propose(store)                                  # writes a fresh ledger
    assert quorum.status("chg-1", store=store) == quorum.PENDING


# --- config knobs -----------------------------------------------------------------

def test_policy_from_config_defaults():
    policy = quorum.policy_from_config()
    assert policy.required == 2
    assert policy.protected_keys == quorum.DEFAULT_PROTECTED_KEYS
    assert policy.ttl_days == 7.0


def test_policy_from_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[safety]\nquorum_required = 3\n"
        'quorum_protected_keys = ["models.*"]\nquorum_ttl_days = 1\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    policy = quorum.policy_from_config()
    assert policy.required == 3
    assert policy.protected_keys == frozenset({"models.*"})
    assert policy.ttl_days == 1.0
    assert quorum.is_protected("models.orchestrator", policy)
    assert not quorum.is_protected("budget.max_dollars", policy)
    # The quorum's own settings stay protected whatever the list says.
    for key in ("safety.quorum_required", "safety.quorum_protected_keys",
                "safety.quorum_ttl_days"):
        assert quorum.is_protected(key, policy)
        assert not quorum.apply_gate(key, policy=policy)


def test_required_env_wins(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[safety]\nquorum_required = 3\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_QUORUM_REQUIRED", "5")
    assert quorum.policy_from_config().required == 5


def test_bogus_config_falls_back(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[safety]\nquorum_required = "many"\nquorum_ttl_days = -2\n'
        "quorum_protected_keys = []\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    policy = quorum.policy_from_config()
    assert policy.required == 2
    assert policy.ttl_days == 7.0
    assert policy.protected_keys == quorum.DEFAULT_PROTECTED_KEYS


def test_ttl_above_the_approval_card_window_is_clamped(monkeypatch, tmp_path, caplog):
    """Approval cards last at most 7 days, so a longer quorum_ttl_days from a
    config file is clamped to 7 (with a warning) instead of promising more."""
    cfg = tmp_path / "config.toml"
    cfg.write_text("[safety]\nquorum_required = 2\nquorum_ttl_days = 30\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    with caplog.at_level("WARNING", logger="maverick.quorum"):
        policy = quorum.policy_from_config()
    assert policy.ttl_days == quorum.MAX_TTL_DAYS == 7.0
    assert "quorum_ttl_days" in caplog.text


def test_private_network_override_is_protected_whatever_the_policy_lists():
    """One admin flipping [tools] fetch_allow_private turns every agent tool
    into an intranet client at once, so it needs the quorum whenever one is
    configured, even when protected_keys was narrowed."""
    policy = quorum.QuorumPolicy(protected_keys=frozenset())
    assert quorum.is_protected("tools.fetch_allow_private", policy)
    assert quorum.is_protected("safety.quorum_required", policy)
    assert not quorum.is_protected("tools.fetch_respect_robots", policy)
