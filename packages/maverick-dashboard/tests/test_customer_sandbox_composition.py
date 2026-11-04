from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick.customer_sandbox_lifecycle import (
    CustomerSandboxConfigError,
    CustomerSandboxConflict,
)
from maverick.paths import reset_tenant, set_tenant
from maverick_dashboard import customer_sandbox_composition as composition

NOW = 2_100_000_000.0


def _tenant_config() -> dict[str, object]:
    return {
        "customer_sandbox_lifecycle": {"source_revision": 7},
        "ai_policy_management": {"enable": True, "provider": {"token": "drop"}},
        "ai_runtime_guardrails": {"enable": True},
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "identity": {"issuer": "https://drop.example", "token": "drop"},
        },
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True, "max_operations": 100},
            "snowflake": {"origin": "https://drop.example", "credential_secret_ref": "drop"},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
        },
        "tech_risk_compliance": {
            "enable": True,
            "scoping": {"enable": True},
        },
        "third_party_management": {
            "enable": True,
            "lifecycle": {"enable": True},
        },
    }


def test_six_suite_projection_uses_real_ai_sections_and_drops_provider_branches() -> None:
    assert frozenset(composition._AI_GOVERNANCE_SECTIONS) == (
        composition.AI_GOVERNANCE_SOURCE_SECTIONS
    )
    projected = composition._suite_configuration(_tenant_config())
    assert set(projected) == {
        "ai_governance",
        "consent_preferences",
        "data_use_governance",
        "privacy_automation",
        "tech_risk_compliance",
        "third_party_management",
    }
    assert projected["ai_governance"] == {
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
    }


def test_requested_source_tenant_not_ambient_context_is_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "maverick.tenant.registry.get_tenant",
        lambda tenant_id: SimpleNamespace(id=tenant_id, active=True),
    )
    monkeypatch.setattr(
        composition,
        "_load_global_authority_config",
        lambda: {"customer_sandbox_lifecycle": {"enable": True}},
    )

    def tenant_config(tenant_id: str):
        calls.append(tenant_id)
        return _tenant_config()

    monkeypatch.setattr(composition, "_load_source_tenant_config", tenant_config)
    token = set_tenant("tenant-a")
    try:
        source = composition._source_configuration("tenant-b")
    finally:
        reset_tenant(token)
    assert calls == ["tenant-b"]
    assert source.tenant_id == "tenant-b"
    assert source.revision == 7
    assert set(source.config) == set(composition.SUPPORTED_SANDBOX_MODULES)


def test_native_store_rejects_target_in_production_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def tenant(tenant_id: str):
        if tenant_id in {"production-a", "production-a-sandbox"}:
            return SimpleNamespace(id=tenant_id, active=True)
        return None

    monkeypatch.setattr("maverick.tenant.registry.get_tenant", tenant)
    monkeypatch.setattr(
        "maverick.tenant.registry.list_tenants",
        lambda: [tenant("production-a"), tenant("production-a-sandbox")],
    )
    monkeypatch.setattr(
        composition,
        "_load_global_authority_config",
        lambda: {"customer_sandbox_lifecycle": {"enable": True}},
    )
    monkeypatch.setattr(
        composition,
        "_load_source_tenant_config",
        lambda tenant_id: _tenant_config(),
    )
    monkeypatch.setattr(composition, "data_dir", lambda *_parts, **_kwargs: tmp_path)
    store = composition.build_customer_sandbox_store(
        principal_resolver=lambda: "global-admin",
        clock=lambda: NOW,
    )
    with pytest.raises(CustomerSandboxConflict, match="target_collision"):
        store.request_sandbox(
            "operation-1",
            source_tenant_id="production-a",
            target_sandbox_id="production-a-sandbox",
            module_allowlist=("ai_governance",),
            expires_at=NOW + 3_600,
            retained_until=NOW + 7_200,
            plan="sandbox-small",
            quota_bytes=8_192,
            idempotency_key="production-collision",
        )


def test_native_composition_can_request_ai_governance_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "maverick.tenant.registry.get_tenant",
        lambda tenant_id: (
            SimpleNamespace(id=tenant_id, active=True)
            if tenant_id == "production-a"
            else None
        ),
    )
    monkeypatch.setattr(
        "maverick.tenant.registry.list_tenants",
        lambda: [SimpleNamespace(id="production-a", active=True)],
    )
    monkeypatch.setattr(
        composition,
        "_load_global_authority_config",
        lambda: {"customer_sandbox_lifecycle": {"enable": True}},
    )
    monkeypatch.setattr(
        composition,
        "_load_source_tenant_config",
        lambda _tenant_id: _tenant_config(),
    )
    monkeypatch.setattr(composition, "data_dir", lambda *_parts, **_kwargs: tmp_path)
    store = composition.build_customer_sandbox_store(
        principal_resolver=lambda: "global-admin",
        clock=lambda: NOW,
    )
    record = store.request_sandbox(
        "operation-ai",
        source_tenant_id="production-a",
        target_sandbox_id="production-a-sandbox",
        module_allowlist=("ai_governance",),
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=8_192,
        idempotency_key="ai-governance-request",
    )
    assert record.module_allowlist == ("ai_governance",)
    assert record.source_revision == 7


def test_production_target_collision_uses_portable_namespace_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        SimpleNamespace(id="Tenant-A"),
        SimpleNamespace(id="caf\u00e9"),
    ]
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", lambda: records)
    assert composition._production_target_collision("tenant-a") is True
    assert composition._production_target_collision("cafe\u0301") is True
    assert composition._production_target_collision("tenant-b") is False


def test_fresh_corrupt_global_and_tenant_overlays_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[customer_sandbox_lifecycle]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    (tmp_path / "dashboard-config.toml").write_text(
        "[customer_sandbox_lifecycle\n",
        encoding="utf-8",
    )
    with pytest.raises(CustomerSandboxConfigError, match="source_invalid"):
        composition._load_global_authority_config()

    (tmp_path / "dashboard-config.toml").unlink()
    tenant_root = tmp_path / "tenants" / "tenant-a"
    tenant_root.mkdir(parents=True)
    (tenant_root / "config.toml").write_text("[consent_preferences\n", encoding="utf-8")
    with pytest.raises(CustomerSandboxConfigError, match="source_configuration_invalid"):
        composition._load_source_tenant_config("tenant-a")


def test_native_disabled_factory_is_no_create_but_reopens_existing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = {"enabled": False}
    monkeypatch.setattr(
        composition,
        "_load_global_authority_config",
        lambda: {"customer_sandbox_lifecycle": {"enable": gate["enabled"]}},
    )
    monkeypatch.setattr(composition, "data_dir", lambda *_parts, **_kwargs: tmp_path)
    app = FastAPI()
    composition.attach_customer_sandbox_composition(app)
    kwargs = {
        "principal_ref": "global-admin",
        "principal_resolver": lambda: "global-admin",
    }
    with pytest.raises(CustomerSandboxConfigError, match="existing_authority_invalid"):
        app.state.customer_sandbox_store_factory(**kwargs)
    assert list(tmp_path.iterdir()) == []

    gate["enabled"] = True
    created = app.state.customer_sandbox_store_factory(**kwargs)
    assert created.list_sandboxes() == ()
    gate["enabled"] = False
    reopened = app.state.customer_sandbox_store_factory(**kwargs)
    assert reopened.status()["enabled"] is False
    assert reopened.list_sandboxes() == ()


def test_parsed_wizard_output_provisions_six_suite_safe_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib

    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    assessment_lines = wizard._cfg_assessments(
        {
                "consent_preferences": {
                    "enable": True,
                    "publishing": {"enable": True, "require_signed_publications": True},
                    "public_api": {"enable": True},
                "delivery": {
                    "enable": True,
                    "max_attempts": 3,
                    "retry_base_seconds": 30,
                    "retry_max_seconds": 300,
                },
                "analytics": {
                    "enable": True,
                    "min_cohort_size": 20,
                    "retention_days": 30,
                },
                "edge_cache": {
                    "enable": True,
                    "max_age_seconds": 60,
                    "stale_if_error_seconds": 300,
                },
                "limits": {
                    "profile_page_size": 100,
                    "receipt_page_size": 100,
                    "request_body_bytes": 65_536,
                },
            },
            "data_use_governance": {
                "enable": True,
                "compiler": {"enable": True, "max_operations": 500},
                "scheduler": {"enable": True, "history_limit": 500},
            },
            "privacy_automation": {
                "enable": True,
                "data_discovery": {"enable": True},
            },
        }
    )
    security_lines = wizard._cfg_security_suite(
        {
            "customer_sandbox_lifecycle": True,
            "security_ops": True,
            "ai_cost_roi": True,
            "ai_policy_management": True,
            "tech_risk_compliance": {
                "enable": True,
                "continuous_evidence": {
                    "enable": True,
                    "enabled_collectors": ["local_soc2_v1"],
                    "scheduler": {"enable": True, "poll_seconds": 60},
                },
            },
            "third_party_management": {
                "enable": True,
                "intelligence": {
                    "enable": True,
                    "providers": {
                        "enable": True,
                        "enabled_providers": ["riskrecon"],
                        "timeout_seconds": 20,
                    },
                },
                "lifecycle": {"enable": True},
            },
        }
    )
    config = tomllib.loads("\n".join([*assessment_lines, *security_lines]))
    assert lint_config(config) == []
    monkeypatch.setattr(
        "maverick.tenant.registry.get_tenant",
        lambda tenant_id: (
            SimpleNamespace(id=tenant_id, active=True)
            if tenant_id == "production-a"
            else None
        ),
    )
    monkeypatch.setattr(
        "maverick.tenant.registry.list_tenants",
        lambda: [SimpleNamespace(id="production-a", active=True)],
    )
    monkeypatch.setattr(composition, "_load_global_authority_config", lambda: config)
    monkeypatch.setattr(composition, "_load_source_tenant_config", lambda _tenant: config)
    monkeypatch.setattr(composition, "data_dir", lambda *_parts, **_kwargs: tmp_path)
    principal = {"value": "requester"}
    store = composition.build_customer_sandbox_store(
        principal_resolver=lambda: principal["value"],
        clock=lambda: NOW,
    )
    record = store.request_sandbox(
        "wizard-six-suite",
        source_tenant_id="production-a",
        target_sandbox_id="production-a-sandbox",
        module_allowlist=tuple(sorted(composition.SUPPORTED_SANDBOX_MODULES)),
        expires_at=NOW + 3_600,
        retained_until=NOW + 7_200,
        plan="sandbox-small",
        quota_bytes=64 * 1024,
        idempotency_key="wizard-six-request",
    )
    principal["value"] = "approver"
    record = store.approve_sandbox(
        record.sandbox_id,
        expected_revision=record.revision,
        idempotency_key="wizard-six-approve",
    )
    principal["value"] = "operator"
    store.provision_sandbox(
        record.sandbox_id,
        expected_revision=record.revision,
        idempotency_key="wizard-six-provision",
    )
    raw = next(
        path
        for path in (tmp_path / "isolated-sandbox-workspaces").rglob("*-*.json")
        if path.parent.name == "snapshots"
    ).read_text()
    assert "retry_max_seconds" in raw
    assert "history_limit" in raw
    assert "local_soc2_v1" not in raw
    assert "riskrecon" not in raw


def test_shipped_app_mounts_customer_sandbox_control_plane() -> None:
    from maverick_dashboard.app import app

    paths = set(app.openapi()["paths"])
    assert "/api/v1/customer-sandboxes/status" in paths
    assert "/api/v1/customer-sandboxes/{sandbox_id}/abandon" in paths
    assert "/api/v1/customer-sandboxes/{sandbox_id}/destroy" in paths
    assert callable(app.state.customer_sandbox_store_factory)
    assert callable(app.state.customer_sandbox_capability_probe)
