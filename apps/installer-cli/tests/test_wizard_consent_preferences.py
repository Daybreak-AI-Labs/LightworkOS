"""Installer reachability for the consumer Consent & Preferences module."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick.config_lint import lint_config
from maverick_installer import wizard


def test_pick_assessments_can_enable_consent_preferences(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable versioned property": True,
            "Enable governed website publish settings": True,
            "Enable the external consumer consent API": True,
            "Enable scheduled website tracker scanning": True,
            "Run the bounded consent scan scheduler": True,
            "Enable independently reviewed scan-to-cookie/privacy disclosure": True,
            "Enable bounded mobile and OTT/CTV application manifest analysis": True,
            "Enable GPC and DNT": True,
            "Enable advertising interoperability": False,
            "Enable downstream preference delivery": True,
            "Enable privacy-safe aggregate consent analytics": True,
            "Enable privacy-preserving consent A/B experiments": True,
            "Enable governed volunteered profile data": True,
            "Enable governed custom data-element indexes": True,
            "Enable governed bulk consent exports": True,
            "Enable the unified consumer Trust Center": True,
            "Enable Privacy Automation regulatory research": False,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(
        wizard,
        "_q_confirm",
        confirm,
    )
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()

    assert selected["consent_preferences"] == {
        "enable": True,
        "publishing": {
            "enable": True,
            "web_settings": {
                "enable": True,
                "retention_seconds": 31_536_000,
                "max_history": 250,
            },
        },
        "public_api": {"enable": True},
        "scanner": {
            "enable": True,
            "notice_proposals": {"enable": True},
            "scheduler": {
                "enable": True,
                "poll_seconds": 60,
                "enqueue_limit": 100,
                "claim_limit": 4,
                "tenant_limit": 1_000,
            },
        },
        "application_scanner": {
            "enable": True,
            "max_records": 25_000,
            "retention_seconds": 31_536_000,
        },
        "standards": {
            "gpc": True,
            "dnt": True,
            "gpp": False,
            "tcf": False,
            "google_consent_mode": False,
        },
        "delivery": {"enable": True, "worker": {"enable": False}},
        "analytics": {"enable": True},
        "experiments": {"enable": True},
        "profile_data": {
            "enable": True,
            "custom_index": {
                "enable": True,
                "key_secret_ref": "MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
                "key_version": 1,
                "max_indexes": 256,
                "max_page_size": 100,
                "retention_seconds": 31_536_000,
            },
        },
        "bulk_jobs": {
            "enable": True,
            "initial_credits": 10_000,
            "max_jobs": 10_000,
            "max_items_per_job": 10_000,
            "max_artifact_bytes": 16_777_216,
            "lease_seconds": 60,
            "retention_seconds": 31_536_000,
            "worker_batch_size": 100,
        },
        "trust_center": {"enable": True},
    }
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["scanner"]["scheduler"] == {
        "enable": True,
        "poll_seconds": 60,
        "enqueue_limit": 100,
        "claim_limit": 4,
        "tenant_limit": 1_000,
    }
    assert parsed["consent_preferences"]["scanner"]["notice_proposals"] == {"enable": True}
    assert parsed["consent_preferences"]["application_scanner"] == {
        "enable": True,
        "max_records": 25_000,
        "retention_seconds": 31_536_000,
    }
    assert parsed["consent_preferences"]["publishing"]["web_settings"] == {
        "enable": True,
        "retention_seconds": 31_536_000,
        "max_history": 250,
    }
    assert parsed["consent_preferences"]["trust_center"] == {"enable": True}
    assert parsed["consent_preferences"]["profile_data"]["custom_index"]["enable"] is True
    assert parsed["consent_preferences"]["bulk_jobs"]["worker_batch_size"] == 100
    assert lint_config(parsed) == []


def test_consent_preferences_is_explicit_opt_in(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation regulatory research"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(
        wizard,
        "_q_confirm",
        confirm,
    )
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()

    assert "consent_preferences" not in selected


def test_global_opt_out_is_reachable_only_through_consumer_rights_intake(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable versioned property": True,
            "Enable the external consumer consent API": True,
            "Enable the unified consumer Trust Center": True,
            "Enable provider-neutral Privacy Automation rights-request orchestration": True,
            "Enable authenticated consumer privacy-rights intake": True,
            "Enable the governed Global Opt-Out": True,
            "Enable Privacy Automation regulatory research": False,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()
    assert selected["consent_preferences"]["global_opt_out"] == {
        "enable": True,
        "retention_seconds": 31_536_000,
        "submission_ttl_seconds": 900,
        "max_records": 10_000,
    }
    assert selected["privacy_automation"]["rights_consumer_intake"]["enable"] is True

    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["global_opt_out"]["enable"] is True
    assert lint_config(parsed) == []


def test_consent_identity_pairing_is_explicit_and_surfaces_existing_oidc_contract(
    monkeypatch,
):
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable versioned property": True,
            "Enable the external consumer consent API": True,
            "Enable verified consumer identity federation": True,
            "Enable Privacy Automation regulatory research": False,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    def text(prompt, *, default=""):
        values = {
            "  Consumer OIDC issuer": "https://id.example.test",
            "  Consumer OIDC audience": "lightwork-consent",
            "  Pinned HTTPS JWKS origin": "https://keys.example.test",
        }
        return next(
            (answer for prefix, answer in values.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)

    selected = wizard.pick_assessments()
    identity = selected["consent_preferences"]["identity"]
    assert identity == {
        "enable": True,
        "issuer": "https://id.example.test",
        "audience": "lightwork-consent",
        "jwks_origin": "https://keys.example.test",
        "token_ttl_seconds": 600,
        "link_lifecycle_retention_seconds": 31_536_000,
    }
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["identity"] == identity
    assert lint_config(parsed) == []


def test_native_sdk_wizard_emits_closed_custody_and_required_integrations(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        answers = {
            "Enable consumer Consent & Preferences": True,
            "Enable versioned property": True,
            "Enable the external consumer consent API": True,
            "Enable verified consumer identity federation": True,
            "Enable advertising interoperability": False,
            "Enable the native mobile and OTT/CTV consent SDK runtime": True,
            "Require each native consent request to link": True,
            "Enable the unified consumer Trust Center": True,
            "Enable Privacy Automation regulatory research": False,
            "Enable provider-neutral Privacy Automation rights-request orchestration": True,
            "Enable authenticated consumer privacy-rights intake": True,
            "Require native SDK privacy-rights requests": True,
            "Enable the Data Use Governance": False,
        }
        return next(
            (answer for prefix, answer in answers.items() if prompt.startswith(prefix)),
            default,
        )

    def text(prompt, *, default=""):
        values = {
            "  Consumer OIDC issuer": "https://id.example.test",
            "  Consumer OIDC audience": "lightwork-native-consent",
            "  Pinned HTTPS JWKS origin": "https://id.example.test",
            "  Native receipt signing key id": "native-receipt-prod",
            "  Environment variable holding the native receipt root secret": (
                "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY"
            ),
        }
        return next(
            (answer for prefix, answer in values.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)

    selected = wizard.pick_assessments()
    native = selected["consent_preferences"]["native_sdk"]
    assert native == {
        "enable": True,
        "receipt_key_id": "native-receipt-prod",
        "receipt_key_revision": 1,
        "receipt_key_secret_ref": "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
        "max_applications": 1_000,
        "max_devices": 100_000,
        "max_requests": 1_000_000,
        "requests_per_minute": 120,
        "require_profile_linking": True,
        "require_rights_requests": True,
    }

    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["native_sdk"] == native
    assert parsed["privacy_automation"]["rights_consumer_intake"]["enable"] is True
    assert lint_config(parsed) == []


def test_config_writer_emits_separate_consent_preferences_section():
    rendered = wizard._cfg_assessments(
        {
            "consent_preferences": {
                "enable": True,
                "publishing": {
                    "enable": True,
                    "require_signed_publications": True,
                },
                "public_api": {"enable": False},
                "scanner": {"enable": False},
                "standards": {
                    "gpc": True,
                    "dnt": True,
                    "gpp": False,
                    "tcf": False,
                    "google_consent_mode": False,
                },
            }
        }
    )
    parsed = tomllib.loads("\n".join(rendered))

    assert parsed == {
        "consent_preferences": {
            "enable": True,
            "publishing": {
                "enable": True,
                "require_signed_publications": True,
            },
            "public_api": {"enable": False},
            "scanner": {"enable": False},
            "standards": {
                "gpc": True,
                "dnt": True,
                "gpp": False,
                "tcf": False,
                "google_consent_mode": False,
            },
        }
    }


def test_config_writer_keeps_legacy_boolean_consent_choice_compatible():
    rendered = wizard._cfg_assessments({"consent_preferences": True})
    parsed = tomllib.loads("\n".join(rendered))

    assert parsed == {"consent_preferences": {"enable": True}}


def test_shared_consent_storage_is_an_explicit_wizard_choice(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith(("Enable consumer Consent & Preferences", "Keep consent records")):
            return True
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")
    selected = wizard.pick_assessments()
    assert selected["consent_preferences"]["storage"] == {
        "backend": "postgres", "dsn_secret_ref": "$MAVERICK_CONSENT_PG_DSN"}
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["consent_preferences"]["storage"]["backend"] == "postgres"
    assert lint_config(parsed) == []
