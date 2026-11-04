from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick.config_lint import lint_config
from maverick_installer import wizard


def test_wizard_emits_named_consent_destinations_with_secret_references(
    monkeypatch,
) -> None:
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable versioned property": True,
            "Enable downstream preference delivery": True,
            "Configure named Salesforce": True,
            "Enable Privacy Automation regulatory research": False,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    def checkbox(prompt, choices, default=None):
        if prompt.startswith("Select named consent delivery destinations"):
            return list(choices)
        return list(default or [])

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_checkbox", checkbox)
    monkeypatch.setattr(
        wizard,
        "_q_text",
        lambda _prompt, *, default="": default,
    )

    selected = wizard.pick_assessments()
    destinations = selected["consent_preferences"]["delivery"]["destinations"]
    assert destinations["enabled_providers"] == [
        "salesforce",
        "marketo",
        "adobe_experience_platform",
        "snowflake",
    ]
    assert destinations["salesforce"]["credential_secret_ref"] == (
        "${MAVERICK_SALESFORCE_CONSENT_TOKEN}"
    )
    assert destinations["adobe_experience_platform"]["credential_secret_ref"] == (
        "${MAVERICK_AEP_CONSENT_CREDENTIAL}"
    )
    assert destinations["marketo"]["message_id_field"] == "lightworkMessageId"

    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["delivery"]["destinations"] == destinations
    assert lint_config(parsed) == []


def test_wizard_keeps_named_adapters_absent_without_explicit_opt_in(
    monkeypatch,
) -> None:
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable downstream preference delivery": True,
            "Configure named Salesforce": False,
            "Enable Privacy Automation regulatory research": False,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda _prompt, *, default="": default)

    selected = wizard.pick_assessments()
    # Automatic delivery stays off unless separately chosen; no destination.
    assert selected["consent_preferences"]["delivery"] == {"enable": True, "worker": {"enable": False}}
