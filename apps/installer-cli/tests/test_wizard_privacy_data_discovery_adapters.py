from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick.config_lint import lint_config
from maverick_installer import wizard


def test_pick_assessments_wires_stock_discovery_adapters_and_data_map(monkeypatch) -> None:
    enabled = (
        "Enable Privacy Automation structured",
        "Enable the bounded built-in privacy discovery source adapters",
        "Enable independently approved discovery-remediation outbox jobs",
        "Enable the managed privacy discovery remediation scheduler",
    )

    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith(enabled):
            return True
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation regulatory research"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    providers = [
        "aws_s3",
        "azure_blob",
        "google_cloud_storage",
        "snowflake_metadata",
        "servicenow_cmdb",
        "entra_assets",
    ]
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_args, **_kwargs: providers)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: kwargs.get("default", ""))

    selected = wizard.pick_assessments()
    parsed = tomllib.loads("\n".join(wizard._cfg_assessments(selected)))

    assert parsed["privacy_automation"]["data_discovery"] == {
        "enable": True,
        "adapters": {
            "enable": True,
            "enabled_providers": providers,
            "timeout_seconds": 15.0,
            "max_response_bytes": 8_388_608,
            "page_size": 250,
            "max_pages": 500,
            "max_attempts": 3,
            "max_polls": 8,
        },
        "remediation": {
            "enable": True,
            "max_attempts": 5,
            "retention_seconds": 2_592_000,
            "data_map": {
                "enable": True,
                "retention_seconds": 31_536_000,
            },
            "scheduler": {
                "enable": True,
                "interval_seconds": 60,
                "jitter_seconds": 10,
                "retry_max_seconds": 300,
                "tenant_limit": 1_000,
                "worker_limit": 10,
                "reconcile_limit": 10,
                "lease_seconds": 60,
            },
        },
    }
    assert lint_config(parsed) == []


def test_stock_discovery_adapters_stay_off_without_explicit_provider_selection(
    monkeypatch,
) -> None:
    def confirm(prompt, *, default=False, **_kwargs):
        if prompt.startswith("Enable Privacy Automation structured"):
            return True
        if prompt.startswith("Enable the bounded built-in privacy discovery source adapters"):
            return True
        if prompt.startswith("Enable consumer Consent & Preferences"):
            return False
        if prompt.startswith("Enable Privacy Automation regulatory research"):
            return False
        if prompt.startswith("Enable the Data Use Governance"):
            return False
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: kwargs.get("default", ""))

    selected = wizard.pick_assessments()
    data_discovery = selected["privacy_automation"]["data_discovery"]

    assert data_discovery == {"enable": True}
    assert lint_config(tomllib.loads("\n".join(wizard._cfg_assessments(selected)))) == []
