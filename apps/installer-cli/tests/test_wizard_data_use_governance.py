"""Installer reachability for the Data Use Governance authority."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick.config_lint import lint_config
from maverick_installer import wizard


def _provider_audit_config(
    *, enabled: bool, scheduler: bool = False, provider: str
):
    config = {
        "enable": enabled,
        "audit_window_seconds": 14_400 if enabled and provider == "snowflake" else 3_600,
        "retention_seconds": 31_536_000,
        "max_attempts": 5,
        "cursor_overlap_seconds": 300,
        "max_pages_per_read": 20,
        "scheduler": {
            "enable": scheduler,
            "poll_seconds": 60,
            "claim_limit": 10,
            "tenant_limit": 1_000,
            "lease_seconds": 120,
            "event_limit": 100,
            "retry_backoff_seconds": 30,
            "purge_limit": 100,
        },
    }
    if enabled and provider == "snowflake":
        config["snowflake_latency_watermark_seconds"] = 10_800
    return config


def test_pick_assessments_can_enable_data_use_without_provider_writes(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return True
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    selected = wizard.pick_assessments()

    assert selected["data_use_governance"] == {
        "enable": True,
        "compiler": {"enable": True},
    }
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    assert parsed["data_use_governance"] == {
        "enable": True,
        "compiler": {"enable": True},
    }
    assert lint_config(parsed) == []


def test_data_use_governance_is_explicit_opt_in(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")

    assert "data_use_governance" not in wizard.pick_assessments()


def test_pick_assessments_can_configure_native_provider_without_collecting_secret(
    monkeypatch,
):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return True
        if prompt.startswith("Configure a native Snowflake"):
            return True
        return default

    answers = iter(
        [
            "https://acct1.snowflakecomputing.com",
            "$LIGHTWORK_DATA_USE_PROVIDER_TOKEN",
            "4",
            "",
        ]
    )
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, **kwargs: "snowflake")
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: next(answers))

    selected = wizard.pick_assessments()
    product = selected["data_use_governance"]
    assert product["enforcement"]["enable"] is True
    assert product["enforcement"]["require_four_eyes"] is True
    assert product["provider_audit"] == _provider_audit_config(
        enabled=False,
        provider="snowflake",
    )
    assert product["snowflake"] == {
        "enable": True,
        "origin": "https://acct1.snowflakecomputing.com",
        "credential_secret_ref": "$LIGHTWORK_DATA_USE_PROVIDER_TOKEN",
        "credential_revision": 4,
        "timeout_seconds": 10,
        "max_response_bytes": 65_536,
    }
    rendered = wizard._cfg_assessments(selected)
    parsed = tomllib.loads("\n".join(rendered))
    assert parsed["data_use_governance"]["snowflake"]["credential_revision"] == 4
    assert lint_config(parsed) == []


def test_native_provider_can_enable_last_mile_audit_reconciliation(monkeypatch):
    prompts: list[str] = []

    def confirm(prompt, *, default=False, **_kwargs):
        prompts.append(prompt)
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return True
        if prompt.startswith("Configure a native Snowflake"):
            return True
        if prompt.startswith("Enable native provider audit-log ingestion"):
            return True
        if prompt.startswith("Run the bounded cross-tenant provider-audit"):
            return True
        return default

    answers = iter(
        [
            "https://workspace.cloud.databricks.com",
            "$LIGHTWORK_DATA_USE_PROVIDER_TOKEN",
            "2",
            "",
        ]
    )
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, **kwargs: "databricks")
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: next(answers))

    selected = wizard.pick_assessments()
    product = selected["data_use_governance"]
    assert product["provider_audit"] == _provider_audit_config(
        enabled=True,
        scheduler=True,
        provider="databricks",
    )
    assert "snowflake_latency_watermark_seconds" not in product["provider_audit"]
    assert product["databricks"]["credential_revision"] == 2
    assert product["databricks"]["timeout_seconds"] == 10
    assert any(
        "built-in typed audit transport" in prompt
        and "live provider acceptance remain separate" in prompt
        for prompt in prompts
    )

    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["data_use_governance"]["provider_audit"] == _provider_audit_config(
        enabled=True,
        scheduler=True,
        provider="databricks",
    )
    assert lint_config(parsed) == []


def test_snowflake_native_audit_emits_latency_watermark_and_safe_window(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return True
        if prompt.startswith("Configure a native Snowflake"):
            return True
        if prompt.startswith("Enable native provider audit-log ingestion"):
            return True
        return default

    answers = iter(
        [
            "https://acct1.snowflakecomputing.com",
            "$LIGHTWORK_DATA_USE_PROVIDER_TOKEN",
            "3",
            "",
        ]
    )
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *args, **kwargs: "snowflake")
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: next(answers))

    selected = wizard.pick_assessments()
    audit_config = selected["data_use_governance"]["provider_audit"]
    assert audit_config == _provider_audit_config(
        enabled=True,
        provider="snowflake",
    )

    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))
    assert parsed["data_use_governance"]["provider_audit"] == audit_config
    assert lint_config(parsed) == []


def test_pick_assessments_can_turn_on_background_data_use_checks(monkeypatch):
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith(("Enable the Data Use Governance", "Run the data-use checks")):
            return True
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "")
    selected = wizard.pick_assessments()
    assert selected["data_use_governance"]["scheduler"] == {
        "enable": True, "poll_seconds": 3_600, "lease_seconds": 900, "history_limit": 50}
    rendered = "\n".join(wizard._cfg_assessments(selected))
    parsed = tomllib.loads(rendered)
    assert parsed["data_use_governance"]["scheduler"]["enable"] is True
    assert not [f for f in lint_config(parsed) if "data_use_governance" in str(f)]
