"""A glob `[security.tool_risk]` override must not silently *lower* a built-in
risk classification: built-in risk is a floor that only an exact override can
drop. This closes the footgun where a broad wildcard (e.g. ``"s*" = "low"``)
declassifies dangerous built-ins like ``shell`` / ``wire_transfer``, defeating
max_risk ceilings and the governance risk gate.
"""
from __future__ import annotations

import importlib

from maverick.safety.tool_risk import tool_risk


def test_glob_cannot_lower_builtin_high():
    # A wildcard that would declassify a built-in HIGH tool is clamped to the
    # built-in floor.
    assert tool_risk("shell", {"s*": "low"}) == "high"
    assert tool_risk("wire_transfer", {"wire_*": "low"}) == "high"
    assert tool_risk("release_payment", {"*": "low"}) == "high"


def test_exact_override_still_lowers_builtin():
    # An explicit, exact operator decision is honored (precise intent).
    assert tool_risk("shell", {"shell": "low"}) == "low"
    assert tool_risk("wire_transfer", {"wire_transfer": "medium"}) == "medium"


def test_glob_can_still_raise_and_relax_non_builtins():
    # A glob may RAISE a built-in...
    assert tool_risk("read_file", {"read_*": "high"}) == "high"
    # ...and may still relax a non-built-in fail-safe (mcp_*), the documented
    # use case -- mcp tools are not in the built-in table, so no floor applies.
    assert tool_risk("mcp_other__write", {"mcp_*": "medium"}) == "medium"
    # An unknown tool is classified freely by a glob.
    assert tool_risk("acme_custom_tool", {"acme_*": "low"}) == "low"


def test_namespaced_action_inherits_its_namespaces_risk():
    # ``salesforce`` is a built-in HIGH connector, but the governed action that
    # actually posts to the system of record is named ``salesforce.write`` --
    # which was absent from the table and fell through to the ``medium``
    # default, slipping under a max_risk="medium" ceiling.
    assert tool_risk("salesforce.write", {}) == "high"
    assert tool_risk("servicenow.write", {}) == "high"
    assert tool_risk("salesforce", {}) == "high"


def test_namespace_inheritance_is_upward_only():
    # A suffix must never launder a namespace DOWN: inheriting ``low`` from
    # read_file would classify an unknown ``read_file.<something>`` below the
    # unrated high floor it is entitled to.
    assert tool_risk("read_file.thing", {}) == "high"
    assert tool_risk("read_file", {}) == "low"


def test_an_exact_override_still_beats_inherited_risk():
    # Operators keep a precise escape hatch for a namespaced read seat.
    assert tool_risk("salesforce.read", {"salesforce.read": "medium"}) == "medium"


def test_a_dotless_or_empty_namespace_changes_nothing():
    # Unrated names keep the high refusal floor, with or without a dot.
    assert tool_risk("totally_unknown_tool", {}) == "high"
    assert tool_risk(".leading_dot", {}) == "high"


def test_pinned_overrides_reads_config_once_per_block(monkeypatch):
    risk = importlib.import_module("maverick.safety.tool_risk")

    calls = {"n": 0}

    def _loader():
        calls["n"] += 1
        return {"shell": "low"}

    monkeypatch.setattr(risk, "_load_overrides", _loader)
    with risk.pinned_overrides():
        for _ in range(100):
            assert tool_risk("shell") == "low"
        with risk.pinned_overrides():  # nested: reuses the outer snapshot
            assert tool_risk("shell") == "low"
    assert calls["n"] == 1
    # Outside the block every call reads the live config again.
    tool_risk("shell")
    tool_risk("shell")
    assert calls["n"] == 3


def test_pinned_overrides_is_released_after_an_error(monkeypatch):
    risk = importlib.import_module("maverick.safety.tool_risk")

    monkeypatch.setattr(risk, "_load_overrides", lambda: {"shell": "low"})
    try:
        with risk.pinned_overrides():
            raise RuntimeError("build failed")
    except RuntimeError:
        pass
    assert risk._PINNED_OVERRIDES.get() is None
    monkeypatch.setattr(risk, "_load_overrides", dict)
    assert tool_risk("shell") == "high"


def test_explicit_overrides_argument_beats_the_pin(monkeypatch):
    risk = importlib.import_module("maverick.safety.tool_risk")

    monkeypatch.setattr(risk, "_load_overrides", lambda: {"shell": "low"})
    with risk.pinned_overrides():
        assert tool_risk("shell", {"shell": "critical"}) == "critical"


def test_audited_abstract_adapters_are_rated_medium_not_unknown():
    # The pack catalog's operator-provisioned read adapters are an audited
    # ratchet, so they keep a deliberate medium rating (never low) instead of
    # the high refusal floor an unknown name gets; an exact override still wins.
    from maverick.domain_prose_lint import ABSTRACT_ADAPTERS
    from maverick.safety.tool_risk import tool_risk, tool_risk_is_classified
    for name in ("ledger_read", "ehr_read", "get_account_summary"):
        assert name in ABSTRACT_ADAPTERS
        assert tool_risk(name, overrides={}) == "medium"
        assert tool_risk_is_classified(name, overrides={})
    assert tool_risk("ledger_read", overrides={"ledger_read": "high"}) == "high"
    assert tool_risk("customer_ledger_read", overrides={}) == "high"
    assert not tool_risk_is_classified("customer_ledger_read", overrides={})
