"""Signed evidence and mandatory governed lineage remain explicit choices."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_installer import wizard


@pytest.mark.parametrize("advanced", [False, True])
@pytest.mark.parametrize("enabled,required", [(False, False), (True, False), (True, True), (False, True)])
def test_lineage_wizard_preserves_separate_enable_policy_issuer_and_key_revocation(monkeypatch, advanced,
                                                                              enabled, required):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "Enable signed reviewed evidence" in prompt:
            return enabled
        if "Require governed reviewed lineage" in prompt:
            return required
        return "Enable the flow engine?" in prompt or prompt.startswith("Flow engine?")

    def text(prompt, *, default="", **kwargs):
        if "issuer ID" in prompt:
            return "customer-workspace:production"
        if "Revoked action-evidence" in prompt:
            return "0123456789abcdef, fedcba9876543210"
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    picked = wizard.pick_advanced() if advanced else wizard.pick_flows()
    lines = wizard._cfg_advanced(picked, []) if advanced else wizard._cfg_flows(picked)
    parsed = tomllib.loads("\n".join(lines))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    settings = config.get_flows()
    assert settings["action_recipe_lineage"] is enabled
    assert settings["require_action_recipe_lineage"] is required
    assert settings["action_evidence_issuer"] == ("customer-workspace:production" if enabled else "")
    assert settings["action_evidence_revoked_keys"] == (["0123456789abcdef", "fedcba9876543210"] if enabled else [])  # pragma: allowlist secret
    assert settings["action_recipes"] is False and settings["action_episode_capture"] is False
    selected = [p for p, d in prompts if "Enable signed reviewed evidence" in p and d is False]
    assert len(selected) == 1
    assert "not personal reviewer signatures" in selected[0] and "retention consent" in selected[0]


@pytest.mark.parametrize("issuer", ["https://issuer.example", "space here", "x" * 129, "bad\nissuer", "é"])
def test_lineage_wizard_rejects_invalid_issuer(monkeypatch, issuer):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: issuer)
    with pytest.raises(ValueError, match="issuer"):
        wizard._pick_action_recipe_lineage()


@pytest.mark.parametrize("revoked", ["short", "0123456789ABCDEF", "0123456789abcdef,", "0123456789abcdef,0123456789abcdef"])
def test_lineage_wizard_rejects_malformed_revocation_ids(monkeypatch, revoked):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda prompt, **kw: "issuer" if "issuer ID" in prompt else revoked)
    with pytest.raises(ValueError, match="revoked"):
        wizard._pick_action_recipe_lineage()


def test_blank_issuer_does_not_invent_a_signer_identity(monkeypatch):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: "")
    result = wizard._pick_action_recipe_lineage()
    assert result["action_evidence_issuer"] == "" and result["action_evidence_revoked_keys"] == []


def test_dedicated_lineage_settings_win_during_advanced_merge():
    dedicated = {"action_recipe_lineage": False, "require_action_recipe_lineage": True,
                 "action_evidence_issuer": "original", "action_evidence_revoked_keys": ["0123456789abcdef"]}
    advanced = {"flows_action_recipe_lineage": True, "flows_require_action_recipe_lineage": False,
                "flows_action_evidence_issuer": "replacement", "flows_action_evidence_revoked_keys": []}
    expected = dict(dedicated)
    wizard._fold_flow_operator_options(dedicated, advanced)
    assert dedicated == expected and advanced == {}
