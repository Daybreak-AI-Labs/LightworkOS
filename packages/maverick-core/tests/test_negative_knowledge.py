"""Negative knowledge: mine causally-justified guardrails from triaged failures,
persist + consult them, and drop a rule when re-triage shows the harm is gone.
"""
from __future__ import annotations

from maverick import negative_knowledge as nk
from maverick.data_engine import FailureClass


def _fc(action, effect, ci_high, trustworthy=True):
    return FailureClass(action=action, count=5, mean_outcome=0.3, causal_effect=effect,
                        ci_low=effect - 0.1, ci_high=ci_high, trustworthy=trustworthy,
                        exemplars=((1, 1),))


def test_mine_only_confidently_harmful_classes():
    rails = nk.mine([
        _fc("X", -0.5, -0.2),                 # confidently harmful -> guardrail
        _fc("Y", -0.4, 0.1),                  # negative mean but CI crosses 0 -> no
        _fc("Z", -0.6, -0.3, trustworthy=False),  # shaky estimate -> no
    ])
    assert [g.action for g in rails] == ["X"]
    assert rails[0].justified and rails[0].severity == 0.5


def test_mine_orders_by_severity():
    rails = nk.mine([_fc("mild", -0.2, -0.05), _fc("severe", -0.7, -0.4)])
    assert [g.action for g in rails] == ["severe", "mild"]


def test_registry_update_consult_and_roundtrip(tmp_path):
    path = tmp_path / "g.json"
    reg = nk.GuardrailRegistry(path=path)
    reg.update(nk.mine([_fc("X", -0.5, -0.2)]))
    assert reg.consult("X") is not None and reg.consult("X").action == "X"
    assert reg.consult("never_seen") is None
    # persisted + reloaded
    reg2 = nk.GuardrailRegistry(path=path)
    assert reg2.consult("X") is not None
    from maverick.file_lock import private_path_is_restricted
    assert private_path_is_restricted(path)


def test_registry_ignores_valid_json_with_wrong_shape(tmp_path):
    path = tmp_path / "g.json"
    path.write_text("42", encoding="utf-8")
    assert nk.GuardrailRegistry(path=path).all() == []


def test_retriage_drops_a_rule_whose_harm_is_gone(tmp_path):
    reg = nk.GuardrailRegistry(path=tmp_path / "g.json")
    reg.update(nk.mine([_fc("X", -0.5, -0.2)]))
    assert reg.consult("X") is not None
    # re-triage: X no longer confidently harmful -> the guardrail is dropped.
    reg.update(nk.mine([_fc("X", -0.1, 0.05)]))
    assert reg.consult("X") is None


def test_consult_empty_registry_is_noop(tmp_path):
    reg = nk.GuardrailRegistry(path=tmp_path / "g.json")
    assert reg.consult("anything") is None and reg.all() == []
