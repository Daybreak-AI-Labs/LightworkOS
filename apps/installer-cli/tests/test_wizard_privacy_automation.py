"""Installer reachability for Privacy Automation data discovery."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick.config_lint import lint_config
from maverick_installer import wizard


def test_pick_assessments_can_enable_privacy_data_discovery(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation"):
            return True
        if prompt.startswith("Enable Privacy Automation regulatory research"):
            return True
        if prompt.startswith("Enable provider-neutral Privacy Automation rights-request"):
            return True
        if prompt.startswith("Enable one-time consumer delivery"):
            return True
        if prompt.startswith("Enable governed Privacy Automation notice"):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()
    assert selected["privacy_automation"] == {
        "enable": True,
        "data_discovery": {"enable": True},
        "regulatory_intelligence": {"enable": True},
        "rights_orchestration": {"enable": True},
        "rights_consumer_delivery": {
            "enable": True,
            "digest_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY",
            "export_signing_key_ref": (
                "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_EXPORT_KEY"
            ),
            "package_encryption_key_ref": "env:MAVERICK_ENCRYPTION_KEY",
            "server_grant_ttl_seconds": 30,
            "max_package_bytes": 16_777_216,
        },
        "rights_consumer_intake": {
            "enable": False,
            "request_ttl_seconds": 86_400,
            "retention_seconds": 31_536_000,
            "max_active_requests": 1_000,
            "max_active_requests_per_subject": 25,
        },
        "ott_ctv_rights": {"enable": False},
        "drop_management": {
            "enable": False,
            "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
            "retention_seconds": 31_536_000,
            "scheduler_enable": False,
            "scheduler_interval_seconds": 3_600,
            "scheduler_jitter_seconds": 60,
            "scheduler_retry_max_seconds": 900,
        },
        "notice_governance": {"enable": True},
    }
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    assert parsed["privacy_automation"]["enable"] is True
    assert parsed["privacy_automation"]["data_discovery"]["enable"] is True
    assert parsed["privacy_automation"]["regulatory_intelligence"]["enable"] is True
    assert parsed["privacy_automation"]["rights_orchestration"]["enable"] is True
    assert parsed["privacy_automation"]["rights_consumer_delivery"]["enable"] is True
    assert parsed["privacy_automation"]["rights_consumer_delivery"] == {
        "enable": True,
        "digest_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY",
        "export_signing_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_EXPORT_KEY",
        "package_encryption_key_ref": "env:MAVERICK_ENCRYPTION_KEY",
        "server_grant_ttl_seconds": 30,
        "max_package_bytes": 16_777_216,
    }
    assert parsed["privacy_automation"]["rights_consumer_intake"] == {
        "enable": False,
        "request_ttl_seconds": 86_400,
        "retention_seconds": 31_536_000,
        "max_active_requests": 1_000,
        "max_active_requests_per_subject": 25,
    }
    assert parsed["privacy_automation"]["ott_ctv_rights"]["enable"] is False
    assert parsed["privacy_automation"]["drop_management"] == {
        "enable": False,
        "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
        "retention_seconds": 31_536_000,
        "scheduler_enable": False,
        "scheduler_interval_seconds": 3_600,
        "scheduler_jitter_seconds": 60,
        "scheduler_retry_max_seconds": 900,
    }
    assert parsed["privacy_automation"]["notice_governance"]["enable"] is True
    assert "privacy_automation" not in parsed.get("assessments", {})
    assert lint_config(parsed) == []


def test_pick_assessments_can_enable_authenticated_consumer_rights_intake(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        enabled_prefixes = (
            "Enable consumer Consent & Preferences",
            "Enable versioned property",
            "Enable the external consumer consent API",
            "Enable the unified consumer Trust Center",
            "Enable provider-neutral Privacy Automation rights-request",
            "Enable authenticated consumer privacy-rights intake",
        )
        if prompt.startswith(enabled_prefixes):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return False

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()

    assert selected["consent_preferences"]["publishing"]["enable"] is True
    assert selected["consent_preferences"]["public_api"]["enable"] is True
    assert selected["consent_preferences"]["trust_center"]["enable"] is True
    assert selected["privacy_automation"]["rights_orchestration"]["enable"] is True
    assert selected["privacy_automation"]["rights_consumer_intake"] == {
        "enable": True,
        "request_ttl_seconds": 86_400,
        "retention_seconds": 31_536_000,
        "max_active_requests": 1_000,
        "max_active_requests_per_subject": 25,
    }
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    assert lint_config(parsed) == []


def test_privacy_data_discovery_is_explicit_opt_in(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation"):
            return False
        if prompt.startswith("Enable Privacy Automation regulatory research"):
            return False
        if prompt.startswith("Enable provider-neutral Privacy Automation rights-request"):
            return False
        if prompt.startswith("Enable one-time consumer delivery"):
            return False
        if prompt.startswith("Enable governed Privacy Automation notice"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")
    assert "privacy_automation" not in wizard.pick_assessments()


def test_ott_ctv_rights_is_reachable_only_with_consent_identity_authorities(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        enabled_prefixes = (
            "Enable consumer Consent & Preferences",
            "Enable versioned property",
            "Enable the external consumer consent API",
            "Enable verified consumer identity federation",
            "Enable the unified consumer Trust Center",
            "Enable provider-neutral Privacy Automation rights-request",
            "Enable the selector-free OTT/CTV service-client rights bridge",
        )
        if prompt.startswith(enabled_prefixes):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    def text(prompt, *, default="", **_kwargs):
        if "OIDC issuer" in prompt:
            return "https://id.example.test"
        if "OIDC audience" in prompt:
            return "lightwork-consent"
        if "JWKS origin" in prompt:
            return "https://keys.example.test"
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)

    selected = wizard.pick_assessments()
    assert selected["privacy_automation"]["ott_ctv_rights"] == {"enable": True}
    assert selected["consent_preferences"]["identity"]["enable"] is True
    assert selected["consent_preferences"]["trust_center"]["enable"] is True
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["privacy_automation"]["ott_ctv_rights"]["enable"] is True
    assert lint_config(parsed) == []


def test_drop_management_is_explicit_and_requires_rights_orchestration(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable provider-neutral Privacy Automation rights-request"):
            return True
        if prompt.startswith("Enable California DROP"):
            return True
        if prompt.startswith("Enable the managed DROP"):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return False

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()
    assert selected["privacy_automation"]["rights_orchestration"]["enable"] is True
    assert selected["privacy_automation"]["drop_management"] == {
        "enable": True,
        "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
        "retention_seconds": 31_536_000,
        "scheduler_enable": True,
        "scheduler_interval_seconds": 3_600,
        "scheduler_jitter_seconds": 60,
        "scheduler_retry_max_seconds": 900,
    }
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert lint_config(parsed) == []


def test_generated_stock_rights_source_config_is_real_and_lints_clean(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith(
            "Enable provider-neutral Privacy Automation rights-request"
        ):
            return True
        if prompt.startswith(
            "Enable production stock privacy-rights source adapters"
        ):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return False

    def checkbox(prompt, _choices, *, default=None, **_kwargs):
        if prompt == "Select privacy-rights source providers":
            return ["Microsoft Graph users"]
        return list(default or [])

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_checkbox", checkbox)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()
    source_config = selected["privacy_automation"]["rights_orchestration"][
        "source_adapters"
    ]
    assert source_config["enable"] is True
    assert source_config["lease_seconds"] == 60
    assert source_config["claim_history_retention_seconds"] == 86_400
    assert source_config["target_custody_retention_seconds"] == 2_592_000
    assert source_config["providers"] == {
        "microsoft_graph_users": {
            "enable": True,
            "source_id": "directory-graph",
            "origin": "https://graph.microsoft.com",
            "credential_ref": "env:GRAPH_RIGHTS_TOKEN",
            "capabilities": [
                "discover",
                "retrieve",
                "delete",
                "verify_delete",
            ],
        }
    }
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    assert parsed["privacy_automation"]["rights_orchestration"][
        "source_adapters"
    ] == source_config
    assert lint_config(parsed) == []


def test_generated_notice_publication_runtime_config_is_exact_and_lints_clean(
    monkeypatch,
):
    def confirm(prompt, *, default=False, **_kwargs):
        enabled = (
            "Enable consumer Consent & Preferences",
            "Enable versioned property",
            "Enable governed Privacy Automation notice",
            "Enable the local privacy-notice publication runtime",
            "Run the bounded local notice-publication scheduler",
        )
        if prompt.startswith(enabled):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return False

    def text(prompt, *, default="", **_kwargs):
        values = {
            "  Exact active tenant ID": "tenant-a",
            "  Publication binding name": "primary",
            "  Exact notice release ID": "privacy-main",
            "  Exact notice release consent-publication": "consent-binding:7",
            "  Exact Consent Publishing property ID": "property-main",
            "  Exact consent rule-group ID": "production-rules",
            "  Exact consent rule-group version": "7",
            "  Exact consent notice-resource ID": "privacy-notice",
            "  Exact consent notice-resource version": "4",
        }
        return next(
            (answer for prefix, answer in values.items() if prompt.startswith(prefix)),
            default,
        )

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)
    selected = wizard.pick_assessments()
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    runtime = parsed["privacy_automation"]["notice_governance"][
        "publication_runtime"
    ]
    assert runtime["active_tenants"] == ["tenant-a"]
    assert runtime["scheduler_enable"] is True
    assert runtime["bindings"]["primary"] == {
        "tenant_id": "tenant-a",
        "notice_id": "privacy-main",
        "consent_publication_ref": "consent-binding:7",
        "property_id": "property-main",
        "rule_group_id": "production-rules",
        "rule_group_version": 7,
        "notice_resource_id": "privacy-notice",
        "notice_resource_version": 4,
    }
    assert lint_config(parsed) == []


def test_pick_assessments_can_enable_the_public_rights_form(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation"):
            return True
        if prompt.startswith("Let people submit privacy requests from your website"):
            return True
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()
    form = selected["privacy_automation"]["public_rights_form"]
    assert form == {
        "enable": True,
        "verification_ttl_hours": 24,
        "status_ttl_days": 90,
        "requests_per_ip_per_hour": 5,
        "requests_per_email_per_day": 3,
        "internal_target_days": 30,
        "max_message_chars": 4000,
    }
    lines = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(lines))
    assert parsed["privacy_automation"]["public_rights_form"] == form
    assert lint_config(parsed) == []
