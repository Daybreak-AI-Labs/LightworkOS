"""First-owner deployment policy is an explicit wizard choice."""
from __future__ import annotations

import inspect

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover -- Python 3.10
    import tomli as tomllib

from maverick_installer import wizard


@pytest.mark.parametrize("enabled", [True, False])
def test_local_owner_choice_roundtrips_beside_department_policy(enabled):
    text = "\n".join(wizard._cfg_advanced({
        "local_owner_setup": enabled,
        "department_access": {"default_suites": ["finance"], "group_roles": {"Finance Team": "operator"}},
    }, providers=[]))
    cfg = tomllib.loads(text)
    assert cfg["dashboard"]["local_owner_setup"] is enabled
    assert cfg["dashboard"]["default_suites"] == ["finance"]
    assert cfg["dashboard"]["group_roles"] == {"Finance Team": "operator"}
    assert text.count("[dashboard]") == 1


def test_local_owner_wizard_discloses_identity_boundary():
    source = inspect.getsource(inspect.getmodule(wizard.pick_advanced))
    assert 'advanced["local_owner_setup"] = _q_confirm(' in source
    assert "named owner creates a local passphrase" in source
    assert "existing identity assignments" in source
