"""Right-to-explanation: governance decisions explained with counterfactuals."""
from __future__ import annotations

from maverick.tools.governance_explainer import governance_explainer


def _t():
    return governance_explainer()


def test_deny_action_explained():
    out = _t().fn({"op": "explain", "action": "wire_transfer",
                   "policy": {"deny_actions": ["wire_transfer"]}})
    assert "decision: DENY" in out
    assert "rule: deny_actions" in out
    assert "hard-deny list" in out
    assert "counterfactual:" in out and "deny_actions" in out


def test_require_human_explained():
    out = _t().fn({"op": "explain", "action": "release_payment",
                   "policy": {"require_human_actions": ["release_payment"]}})
    assert "decision: REQUIRE_HUMAN" in out
    assert "always requires a human approver" in out
    assert "proceeds now with a human approval" in out


def test_amount_tier_explained():
    out = _t().fn({"op": "explain", "action": "refund", "amount": 5000,
                   "currency": "USD",
                   "policy": {"require_human_above": {"refund": 1000}}})
    assert "decision: REQUIRE_HUMAN" in out
    assert "rule: require_human_above" in out
    assert "below the approval threshold" in out


def test_risk_floor_deny():
    out = _t().fn({"op": "explain", "action": "shell", "risk": "high",
                   "policy": {"deny_min_risk": "high"}})
    assert "decision: DENY" in out and "deny_min_risk" in out


def test_default_allow_no_counterfactual():
    out = _t().fn({"op": "explain", "action": "read_file", "risk": "low",
                   "policy": {}})
    assert "decision: ALLOW" in out
    assert "rule: default" in out
    assert "counterfactual:" not in out  # nothing to undo


def test_validation():
    t = _t()
    assert t.fn({"op": "explain"}).startswith("ERROR")
    assert t.fn({"op": "explain", "action": "x", "amount": "lots"}).startswith("ERROR")
    assert t.fn({"op": "bogus", "action": "x"}).startswith("ERROR")


def test_omitted_policy_does_not_load_live_config(monkeypatch):
    from maverick import governance

    captured = {}
    original_evaluate = governance.evaluate

    def _capture(action, *, risk=None, amount=None, currency="", policy=None, capability=None):
        captured["policy"] = policy
        return original_evaluate(
            action, risk=risk, amount=amount, currency=currency,
            policy=policy, capability=capability,
        )

    monkeypatch.setattr(governance, "evaluate", _capture)

    out = _t().fn({"op": "explain", "action": "wire_transfer"})

    assert "decision: ALLOW" in out
    assert captured["policy"] is not None
    assert captured["policy"].deny_actions == frozenset()


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "governance_explainer" in names
