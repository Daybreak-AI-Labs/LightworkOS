"""The assessment wizard collects account origins and names, never tokens."""
from __future__ import annotations

import pytest
from maverick_installer import wizard
from maverick_installer.wizard import assessments


@pytest.mark.parametrize("choice,provider,origin", [
    ("Salesforce contacts", "salesforce_contacts", "https://acme.my.salesforce.com"),
    ("ServiceNow users", "servicenow_users", "https://acme.service-now.com"),
])
def test_rights_source_requires_an_explicit_valid_instance(monkeypatch, choice, provider, origin):
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_args, **_kwargs: [choice])
    answers = iter([
        "http://acme.service-now.com", origin + "/private", origin + "@evil.example",
        origin + ":invalid", "https://[invalid", origin,
    ])
    monkeypatch.setattr(wizard, "_q_text", lambda *_args, **_kwargs: next(answers))
    selected = assessments._pick_privacy_rights_source_adapters()["providers"][provider]
    assert selected["origin"] == origin
    assert selected["enable"] is True

    monkeypatch.setattr(wizard, "_q_text", lambda *_args, **_kwargs: "")
    skipped = assessments._pick_privacy_rights_source_adapters()
    assert skipped["providers"][provider]["enable"] is False
    assert skipped["enable"] is False


@pytest.mark.parametrize("kind", ["destination", "native", "drop"])
def test_secret_prompts_reask_for_an_environment_name(monkeypatch, kind, capsys):
    answers = iter(["pasted-token.value", "${bad-name}", "SAFE_TOKEN"])

    def text(prompt, *, default="", **kwargs):
        if ("Environment variable holding the Salesforce" in prompt
                or prompt.startswith("Environment variable holding the native provider")
                or prompt.startswith("Secret-provider reference containing")
                or prompt.startswith("DROP principal-binding")):
            return next(answers)
        return default

    def confirm(prompt, *, default=False, **kwargs):
        return prompt.startswith((
            "Enable the Data Use Governance", "Configure a native Snowflake",
            "Enable provider-neutral Privacy Automation rights-request",
            "Enable California DROP",
        ))

    monkeypatch.setattr(wizard, "_q_text", text)
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *_args, **_kwargs: "snowflake")
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_args, **_kwargs: ["salesforce"])
    if kind == "destination":
        result = assessments._pick_consent_destinations()["salesforce"]["credential_secret_ref"]
        assert result == "${SAFE_TOKEN}"
    elif kind == "native":
        result = assessments._pick_data_use_governance()["snowflake"]["credential_secret_ref"]
        assert result == "$SAFE_TOKEN"
    else:
        result = assessments._pick_privacy_automation(assessments._ConsentChoices())
        assert result["drop_management"]["principal_binding_key_ref"] == "env:SAFE_TOKEN"
    assert "pasted-token.value" not in capsys.readouterr().out


_DROP_KEY_REFERENCES = [
    "env:SAFE_TOKEN", "kms://drop/key", "secret://drop/key", "vault://drop/key",
    "aws-kms://alias/drop", "azure-keyvault://vault/drop", "gcp-kms://projects/p/keys/k",
]
_NOT_DROP_KEY_REFERENCES = [
    "pasted-token.value", "${bad-name}", "env:bad", "vault://", "http://drop/key",
    "vault://drop key", "k" * 64,
]


@pytest.mark.parametrize("reference", _DROP_KEY_REFERENCES)
def test_drop_prompt_accepts_every_key_reference_the_consumer_accepts(monkeypatch, reference):
    answers = iter(["pasted-token.value", reference])

    def text(prompt, *, default="", **kwargs):
        return next(answers) if prompt.startswith("DROP principal-binding") else default

    monkeypatch.setattr(wizard, "_q_text", text)
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **_: prompt.startswith((
        "Enable provider-neutral Privacy Automation rights-request", "Enable California DROP")))
    result = assessments._pick_privacy_automation(assessments._ConsentChoices())
    assert result["drop_management"]["principal_binding_key_ref"] == reference


@pytest.mark.parametrize("reference", _DROP_KEY_REFERENCES + _NOT_DROP_KEY_REFERENCES)
def test_drop_key_reference_matches_the_dashboard_consumer(reference):
    from maverick.config_lint import _is_drop_principal_key_reference
    composition = pytest.importorskip("maverick_dashboard.privacy_drop_management_composition")
    try:
        composition._key_reference(reference)
        consumer_accepts = True
    except composition.DROPManagementConfigError:
        consumer_accepts = False
    assert _is_drop_principal_key_reference(reference) is consumer_accepts
