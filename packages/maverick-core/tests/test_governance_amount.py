"""Amount-aware authorization in governance (finance-agent-suite §2.3)."""
from __future__ import annotations

import pytest
from maverick.governance import Decision, Policy, _amount_table, evaluate


def test_require_human_above_threshold():
    pol = Policy(require_human_above={"release_payment": 5000})
    assert evaluate("release_payment", amount=6000, policy=pol).decision is Decision.REQUIRE_HUMAN
    assert evaluate("release_payment", amount=4000, policy=pol).decision is Decision.ALLOW
    # exactly at the threshold is allowed (strictly above triggers)
    assert evaluate("release_payment", amount=5000, policy=pol).decision is Decision.ALLOW


def test_deny_above_threshold():
    pol = Policy(deny_above={"wire_transfer": 50000})
    assert evaluate("wire_transfer", amount=60000, policy=pol).decision is Decision.DENY
    assert evaluate("wire_transfer", amount=40000, policy=pol).decision is Decision.ALLOW


def test_wildcard_threshold_applies_to_all_actions():
    pol = Policy(require_human_above={"*": 1000})
    assert evaluate("any_action", amount=2000, policy=pol).decision is Decision.REQUIRE_HUMAN
    assert evaluate("any_action", amount=500, policy=pol).decision is Decision.ALLOW


def test_wildcard_floor_binds_lower_than_exact_action():
    # Strictest-wins: a "*" catch-all is a FLOOR, so a per-action key can only
    # tighten it, never loosen it. release_payment is gated at
    # min(10000, 1000)=1000, NOT its own higher 10000.
    pol = Policy(require_human_above={"*": 1000, "release_payment": 10000})
    # $5k release_payment trips the $1k catch-all floor; the higher per-action
    # threshold must not ALLOW it (that would be a money-movement bypass).
    assert evaluate("release_payment", amount=5000, policy=pol).decision is Decision.REQUIRE_HUMAN
    # Below the floor: still allowed.
    assert evaluate("release_payment", amount=500, policy=pol).decision is Decision.ALLOW
    # A different action falls back to the same wildcard floor.
    assert evaluate("post_note", amount=5000, policy=pol).decision is Decision.REQUIRE_HUMAN


def test_exact_action_tighter_than_wildcard_still_applies():
    # A per-action key STRICTER than "*" binds (min picks it): $200 wire gated.
    pol = Policy(require_human_above={"*": 5000, "wire_transfer": 100})
    assert evaluate("wire_transfer", amount=200, policy=pol).decision is Decision.REQUIRE_HUMAN
    # A non-wire action uses the looser $5k catch-all.
    assert evaluate("post_note", amount=200, policy=pol).decision is Decision.ALLOW


def test_deny_above_beats_require_human_above():
    pol = Policy(deny_above={"a": 100}, require_human_above={"a": 10})
    assert evaluate("a", amount=200, policy=pol).decision is Decision.DENY


def test_missing_amount_fails_closed_unless_trusted_caller_marks_not_applicable():
    deny = Policy(deny_above={"*": 1})
    human = Policy(require_human_above={"*": 1})
    assert evaluate("payment", policy=deny).decision is Decision.DENY
    assert evaluate("payment", policy=human).decision is Decision.REQUIRE_HUMAN
    assert evaluate("payment", amount=None, policy=Policy(
        deny_above={"*": 1}, require_human_above={"*": 1},
    )).decision is Decision.DENY
    assert evaluate("read_file", policy=deny, amount_unavailable=False).decision is Decision.ALLOW
    assert evaluate("other", policy=Policy(deny_above={"payment": 1})).decision is Decision.ALLOW
    assert evaluate("payment", amount=float("nan"), amount_unavailable=False,
                    policy=deny).decision is Decision.DENY


def test_reason_includes_amount_and_currency():
    pol = Policy(require_human_above={"pay": 5000})
    v = evaluate("pay", amount=9000, currency="USD", policy=pol)
    assert "9000" in v.reason and "USD" in v.reason
    assert v.rule == "require_human_above"


def test_amount_table_coercion():
    assert _amount_table({"a": 5, "b": 1.5}) == {"a": 5.0, "b": 1.5}
    assert _amount_table(1000) == {"*": 1000.0}      # bare number -> wildcard
    assert _amount_table(True) == {}                 # bool is not an amount
    assert _amount_table({"a": "nope"}) == {}        # non-numeric dropped
    assert _amount_table(None) == {}


def test_empty_policy_with_thresholds_not_empty():
    assert not Policy(require_human_above={"*": 1}).is_empty()
    assert Policy().is_empty()


def test_threshold_composes_with_capability_deny():
    from maverick.capability import Capability
    cap = Capability(principal="p", deny_tools=frozenset({"release_payment"}))
    pol = Policy(require_human_above={"release_payment": 5000})
    # capability deny wins over the (lower-precedence) amount gate
    v = evaluate("release_payment", amount=10, capability=cap, policy=pol)
    assert v.decision is Decision.DENY and v.rule == "capability"


@pytest.mark.parametrize("args", [
    {}, {"amount": None}, {"amount": -1}, {"amount": "nan"},
    {"amount": "inf"}, {"amount": True}, {"amount": 50, "currency": "EUR"},
])
def test_unverifiable_finance_amount_fails_closed(args):
    from maverick.governance import transaction_value

    for table, decision in [("deny_above", Decision.DENY),
                            ("require_human_above", Decision.REQUIRE_HUMAN)]:
        policy = Policy(**{table: {"*": 100}})
        amount, currency, unavailable = transaction_value("wire_transfer", args, policy)
        assert unavailable
        assert evaluate("wire_transfer", policy=policy, amount=amount,
                        currency=currency, amount_unavailable=unavailable).decision is decision


def test_refund_value_and_unknown_currency():
    from maverick.governance import transaction_value

    policy = Policy(deny_above={"*": 100})
    assert transaction_value("shopify", {"op": "refund_create", "amount_cents": 12500}, policy) == (125, "", False)
    for args in ({"op": "refund_create"}, {"op": "refund_create", "amount_cents": 0},
                 {"op": "refund_create", "amount_cents": 100, "currency": "JPY"}):
        assert transaction_value("shopify", args, policy)[2]
    assert transaction_value("stripe", {"op": "refund_create", "amount_cents": 1, "currency": "USD"}, policy)[2]
    assert transaction_value("stripe", {"op": "charges"}, policy)[2] is False
    assert transaction_value("shopify", {"op": "refund_create", "amount_cents": 2**53 + 1}, policy)[2]


def test_generic_connector_cannot_prove_value_with_a_decoy():
    from maverick.governance import transaction_value
    policy = Policy(deny_above={"*": 100})
    amount, currency, unavailable = transaction_value(
        "openapi_runner", {"amount": 1, "body": {"amount": 1000000}}, policy)
    assert evaluate("openapi_runner", policy=policy, amount=amount,
                    currency=currency, amount_unavailable=unavailable).decision is Decision.DENY


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), -1, True])
def test_direct_evaluate_rejects_invalid_amounts(amount):
    assert evaluate("wire_transfer", amount=amount,
                    policy=Policy(deny_above={"*": 100})).decision is Decision.DENY
