"""Fresh-install operator preflight: stable, offline, and actionable."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from click.testing import CliRunner

_PROVIDER_ENV = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "MOONSHOT_API_KEY",
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "GROK_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "VLLM_BASE_URL",
    "TGI_BASE_URL",
    "OPENAI_COMPATIBLE_BASE_URL",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_AD_TOKEN",
    "AZURE_OPENAI_AUTH",
    "AZURE_OPENAI_TOKEN_SCOPE",
    "AZURE_OPENAI_DEPLOYMENT",
    "MAVERICK_MODEL_OVERRIDE",
)

_AUDIT_KEY_ENV = (
    "MAVERICK_AUDIT_SIGNING_KEY",
    "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED",
    "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY",
    "MAVERICK_KMS_KEY_ID",
)


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    from maverick import config, runtime_overrides
    from maverick.llm import ROLE_MODELS

    path = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_ROLES_FILE", str(tmp_path / "roles.toml"))
    monkeypatch.setattr(
        runtime_overrides,
        "OVERRIDES_PATH",
        tmp_path / "runtime-overrides.toml",
    )
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_EVIDENCE_GATEWAY", raising=False)
    for name in (*_PROVIDER_ENV, *_AUDIT_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    for role in ROLE_MODELS:
        monkeypatch.delenv(
            f"MAVERICK_MODEL_OVERRIDE_{role.upper()}",
            raising=False,
        )
    config.reset_config_cache()
    yield path
    config.reset_config_cache()


def _by_id(report):
    return {check.id: check for check in report.checks}


def _ed25519_keypair_bytes():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def _write_local_audit_keypair(key_dir, private_bytes, public_bytes):
    from maverick.file_lock import (
        atomic_write_bytes,
        ensure_private_directory,
    )

    ensure_private_directory(key_dir)
    key_id = hashlib.sha256(public_bytes).hexdigest()[:16]
    atomic_write_bytes(key_dir / f"{key_id}.key", private_bytes, mode=0o600)
    atomic_write_bytes(key_dir / f"{key_id}.pub", public_bytes, mode=0o644)
    return key_id


def test_missing_config_uses_effective_defaults_and_provider_remedy(isolated_config):
    from maverick.operator_preflight import collect

    report = collect()

    assert report.ready is False
    assert report.schema == "lightwork.operator-preflight.v1"
    assert _by_id(report)["config"].status == "ready"
    assert _by_id(report)["provider"].status == "blocked"
    assert report.next_action == "Lightwork Settings > Models"
    # No volatile timestamp: two reads produce the exact same automation shape.
    assert report.to_dict() == collect().to_dict()
    assert not (isolated_config.parent / "state").exists()


def test_run_profile_ready_with_local_provider(monkeypatch, isolated_config):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")
    isolated_config.write_text(
        "\n".join(
            [
                "[providers.ollama]",
                'base_url = "http://127.0.0.1:11434"',
                "[models]",
                'planner = "ollama:test-model"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    from maverick import config, providers
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    monkeypatch.setattr(
        preflight,
        "_dashboard_state",
        lambda *, required: preflight.Check(
            "dashboard", "Operator dashboard", "ready", "installed"
        ),
    )

    report = preflight.collect("run")

    assert report.ready is True
    assert report.blocker_count == 0
    assert _by_id(report)["provider"].status == "ready"
    # Cockpit-only features are honest attention items, not runtime blockers.
    assert _by_id(report)["evidence_gateway"].status == "attention"


def test_run_profile_accepts_keyless_global_local_route(
    monkeypatch, isolated_config,
):
    isolated_config.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "ollama:test-model")
    from maverick import config, providers
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    report = preflight.collect("run")

    assert _by_id(report)["provider"].status == "ready"
    assert _by_id(report)["model_routes"].status == "ready"


def test_cockpit_profile_requires_all_evidence_dependencies(
    monkeypatch, isolated_config
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")
    isolated_config.write_text(
        "\n".join(
            [
                "[providers.ollama]",
                'base_url = "http://127.0.0.1:11434"',
                "[models]",
                'planner = "ollama:test-model"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    from maverick import config, providers
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    monkeypatch.setattr(
        preflight,
        "_dashboard_state",
        lambda *, required: preflight.Check(
            "dashboard", "Operator dashboard", "ready", "installed"
        ),
    )

    report = preflight.collect("cockpit")

    assert report.ready is False
    checks = _by_id(report)
    assert checks["evidence_graph"].status == "blocked"
    assert checks["evidence_gateway"].status == "blocked"
    assert checks["model_risk_assurance"].status == "blocked"


def test_cockpit_profile_ready_when_dependencies_enabled(
    monkeypatch, isolated_config
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")
    monkeypatch.setenv("MAVERICK_TENANT", "test-company")
    isolated_config.write_text(
        "\n".join(
            [
                "[providers.ollama]",
                'base_url = "http://127.0.0.1:11434"',
                "[models]",
                'planner = "ollama:test-model"',
                "[evidence_graph]",
                "enable = true",
                "[evidence_gateway]",
                "enable = true",
                "[model_risk_assurance]",
                "enable = true",
                "gate_promotions = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    from maverick import config, providers
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    monkeypatch.setattr(
        preflight,
        "_dashboard_state",
        lambda *, required: preflight.Check(
            "dashboard", "Operator dashboard", "ready", "installed"
        ),
    )

    report = preflight.collect("cockpit")

    assert report.ready is True
    assert all(
        _by_id(report)[name].status == "ready"
        for name in (
            "tenant_scope",
            "evidence_graph",
            "evidence_gateway",
            "model_risk_assurance",
        )
    )


def test_cockpit_profile_requires_explicit_tenant_scope(
    monkeypatch, isolated_config
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")
    isolated_config.write_text(
        "\n".join(
            [
                "[providers.ollama]",
                'base_url = "http://127.0.0.1:11434"',
                "[models]",
                'planner = "ollama:test-model"',
                "[evidence_graph]",
                "enable = true",
                "[evidence_gateway]",
                "enable = true",
                "[model_risk_assurance]",
                "enable = true",
                "gate_promotions = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    from maverick import config, providers
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    monkeypatch.setattr(
        preflight,
        "_dashboard_state",
        lambda *, required: preflight.Check(
            "dashboard", "Operator dashboard", "ready", "installed"
        ),
    )

    report = preflight.collect("cockpit")

    assert report.ready is False
    tenant = _by_id(report)["tenant_scope"]
    assert tenant.status == "blocked"
    assert tenant.remediation == "maverick config edit"


def test_gateway_preflight_is_read_only_on_fresh_writable_home(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight

    monkeypatch.setenv("MAVERICK_TENANT", "preflight-fresh-company")
    client.reset_client_cache()
    state_root = isolated_config.parent / "state"
    checks = preflight._gateway_evidence_checks(
        {"evidence_gateway": {"enable": True}}
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "attention"
    assert by_id["gateway_trust_registry"].status == "attention"
    assert by_id["gateway_ledgers"].status == "attention"
    assert not state_root.exists()


def test_gateway_preflight_blocks_unwritable_first_use_parent(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight

    monkeypatch.setenv("MAVERICK_TENANT", "preflight-unwritable-company")
    client.reset_client_cache()
    real_access = preflight.os.access

    def denied_write(path, mode):
        if mode & preflight.os.W_OK:
            return False
        return real_access(path, mode)

    monkeypatch.setattr(preflight.os, "access", denied_write)
    checks = preflight._gateway_evidence_checks(
        {"evidence_gateway": {"enable": True}}
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert by_id["gateway_ledgers"].status == "blocked"


def test_gateway_preflight_rejects_invalid_injected_key_without_consuming_it(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight

    secret = "not-a-runtime-ed25519-key"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_TENANT", "invalid-injected-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", secret)
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert by_id["gateway_signing"].status == "blocked"
    assert secret not in " ".join(check.detail for check in checks)
    assert preflight.os.environ["MAVERICK_AUDIT_SIGNING_KEY"] == secret
    assert not (isolated_config.parent / "state").exists()


def test_gateway_preflight_accepts_valid_injected_key_read_only(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight

    private_bytes, _ = _ed25519_keypair_bytes()
    injected = base64.b64encode(private_bytes).decode("ascii")
    monkeypatch.setenv("MAVERICK_TENANT", "valid-injected-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", injected)
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "ready"
    assert by_id["gateway_signing"].status == "ready"
    assert preflight.os.environ["MAVERICK_AUDIT_SIGNING_KEY"] == injected
    assert not (isolated_config.parent / "state").exists()


def test_gateway_preflight_rejects_runtime_invalid_wrapped_envelope(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight

    wrapped = base64.b64encode(b"not-a-vault-runtime-envelope").decode("ascii")
    monkeypatch.setenv("MAVERICK_TENANT", "invalid-wrapped-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", wrapped)
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
            "kms": {"provider": "vault", "key_id": "audit-signing"},
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert by_id["gateway_signing"].status == "blocked"
    assert wrapped not in " ".join(check.detail for check in checks)
    assert (
        preflight.os.environ["MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"] == wrapped
    )
    assert not (isolated_config.parent / "state").exists()


def test_gateway_preflight_validates_wrapped_envelope_without_unwrapping(
    monkeypatch,
    isolated_config,
):
    from maverick import client, kms_backends
    from maverick import operator_preflight as preflight

    wrapped = base64.b64encode(
        kms_backends._VAULT_MAGIC + b"vault:v1:ciphertext"
    ).decode("ascii")
    monkeypatch.setenv("MAVERICK_TENANT", "valid-wrapped-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", wrapped)
    real_module_available = preflight._module_available
    monkeypatch.setattr(
        preflight,
        "_module_available",
        lambda name: (
            True if name == "hvac" else real_module_available(name)
        ),
    )

    def unexpected_unwrap(self, value, *, context=None):
        raise AssertionError("offline preflight must not call KMS unwrap")

    monkeypatch.setattr(
        kms_backends.VaultTransitKMS,
        "unwrap",
        unexpected_unwrap,
    )
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
            "kms": {"provider": "vault", "key_id": "audit-signing"},
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "ready"
    assert by_id["gateway_signing"].status == "ready"
    assert (
        preflight.os.environ["MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"] == wrapped
    )
    assert not (isolated_config.parent / "state").exists()


def test_gateway_preflight_validates_azure_envelope_without_unwrapping(
    monkeypatch,
    isolated_config,
):
    from maverick import client, kms_backends
    from maverick import operator_preflight as preflight

    wrapped = base64.b64encode(
        kms_backends._AZURE_MAGIC + b"opaque-azure-envelope"
    ).decode("ascii")
    monkeypatch.setenv("MAVERICK_TENANT", "valid-azure-wrapped-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", wrapped)
    real_module_available = preflight._module_available
    monkeypatch.setattr(
        preflight,
        "_module_available",
        lambda name: (
            True if name in {"azure.keyvault.keys.crypto", "azure.identity"}
            else real_module_available(name)
        ),
    )

    def unexpected_unwrap(self, value, *, context=None):
        raise AssertionError("offline preflight must not call KMS unwrap")

    monkeypatch.setattr(
        kms_backends.AzureKeyVaultKEK,
        "unwrap",
        unexpected_unwrap,
    )
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
            "kms": {
                "provider": "azure",
                "key_id": "https://acme-kv.vault.azure.net/keys/audit-kek",
            },
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "ready"
    assert by_id["gateway_signing"].status == "ready"
    assert (
        preflight.os.environ["MAVERICK_AUDIT_SIGNING_KEY_WRAPPED"] == wrapped
    )
    assert not (isolated_config.parent / "state").exists()


def test_gateway_preflight_blocks_azure_envelope_without_azure_identity(
    monkeypatch,
    isolated_config,
):
    from maverick import client, kms_backends
    from maverick import operator_preflight as preflight

    wrapped = base64.b64encode(
        kms_backends._AZURE_MAGIC + b"opaque-azure-envelope"
    ).decode("ascii")
    monkeypatch.setenv("MAVERICK_TENANT", "azure-identity-missing-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", wrapped)
    real_module_available = preflight._module_available
    monkeypatch.setattr(
        preflight,
        "_module_available",
        lambda name: (
            False if name == "azure.identity" else real_module_available(name)
        ),
    )
    client.reset_client_cache()

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
            "kms": {
                "provider": "azure",
                "key_id": "https://acme-kv.vault.azure.net/keys/audit-kek",
            },
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert "not installed" in by_id["gateway_key_custody"].detail
    assert wrapped not in " ".join(check.detail for check in checks)


def test_historical_injected_marker_is_not_current_offhost_custody(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight
    from maverick.file_lock import atomic_write_bytes, ensure_private_directory
    from maverick.paths import diagnostic_data_dir

    monkeypatch.setenv("MAVERICK_TENANT", "historical-injected-company")
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "1")
    client.reset_client_cache()
    _, public_bytes = _ed25519_keypair_bytes()
    key_dir = diagnostic_data_dir("audit", "keys")
    key_id = hashlib.sha256(public_bytes).hexdigest()[:16]

    ensure_private_directory(key_dir)
    atomic_write_bytes(key_dir / f"{key_id}.pub", public_bytes, mode=0o644)
    atomic_write_bytes(key_dir / f"{key_id}.injected", b"", mode=0o600)

    checks = preflight._gateway_evidence_checks(
        {
            "audit": {"require_offhost_key": True},
            "evidence_gateway": {"enable": True},
        }
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert by_id["gateway_signing"].status == "blocked"
    assert by_id["gateway_trust_registry"].status == "ready"


@pytest.mark.parametrize("invalid_private", ["wrong_length", "mismatched"])
def test_gateway_preflight_rejects_invalid_local_private_public_keypair(
    monkeypatch,
    isolated_config,
    invalid_private,
):
    from maverick import client
    from maverick import operator_preflight as preflight
    from maverick.paths import diagnostic_data_dir

    monkeypatch.setenv("MAVERICK_TENANT", f"invalid-local-{invalid_private}")
    client.reset_client_cache()
    private_bytes, public_bytes = _ed25519_keypair_bytes()
    if invalid_private == "wrong_length":
        private_bytes = private_bytes[:-1]
    else:
        private_bytes, _ = _ed25519_keypair_bytes()
    key_dir = diagnostic_data_dir("audit", "keys")
    _write_local_audit_keypair(key_dir, private_bytes, public_bytes)
    before = {
        path.name: path.read_bytes()
        for path in key_dir.iterdir()
        if path.is_file()
    }

    checks = preflight._gateway_evidence_checks(
        {"evidence_gateway": {"enable": True}}
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "blocked"
    assert by_id["gateway_signing"].status == "blocked"
    assert by_id["gateway_trust_registry"].status == "blocked"
    assert {
        path.name: path.read_bytes()
        for path in key_dir.iterdir()
        if path.is_file()
    } == before


def test_gateway_preflight_validates_local_keypair_without_mutating_it(
    monkeypatch,
    isolated_config,
):
    from maverick import client
    from maverick import operator_preflight as preflight
    from maverick.paths import diagnostic_data_dir

    monkeypatch.setenv("MAVERICK_TENANT", "valid-local-company")
    client.reset_client_cache()
    private_bytes, public_bytes = _ed25519_keypair_bytes()
    key_dir = diagnostic_data_dir("audit", "keys")
    _write_local_audit_keypair(key_dir, private_bytes, public_bytes)
    before = {
        path.name: path.read_bytes()
        for path in key_dir.iterdir()
        if path.is_file()
    }

    checks = preflight._gateway_evidence_checks(
        {"evidence_gateway": {"enable": True}}
    )

    by_id = {check.id: check for check in checks}
    assert by_id["gateway_key_custody"].status == "attention"
    assert by_id["gateway_signing"].status == "ready"
    assert by_id["gateway_trust_registry"].status == "ready"
    assert {
        path.name: path.read_bytes()
        for path in key_dir.iterdir()
        if path.is_file()
    } == before


def test_default_route_requires_its_own_provider_credential(
    monkeypatch, isolated_config
):
    isolated_config.write_text(
        "\n".join(
            [
                "[providers.ollama]",
                'base_url = "http://127.0.0.1:11434"',
                "[models]",
                'planner = "ollama:test-model"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    from maverick import config
    from maverick import operator_preflight as preflight

    config.reset_config_cache()
    report = preflight.collect("run")

    route = _by_id(report)["model_routes"]
    assert route.status == "blocked"
    assert "anthropic: ANTHROPIC_API_KEY" in route.detail
    assert "ollama" not in route.detail


def test_role_edit_route_matches_live_model_resolution(
    monkeypatch, isolated_config,
):
    isolated_config.write_text(
        '[models]\norchestrator = "anthropic:remote"\n',
        encoding="utf-8",
    )
    (isolated_config.parent / "roles.toml").write_text(
        '[orchestrator]\nmodel = "ollama:qwen3"\n',
        encoding="utf-8",
    )
    from maverick import config
    from maverick.llm import model_for_role, offline_model_for_role
    from maverick.operator_preflight import _role_configuration_missing

    config.reset_config_cache()
    cfg = config.load_config()
    assert model_for_role("orchestrator") == "ollama:qwen3"
    assert offline_model_for_role("orchestrator", config=cfg) == "ollama:qwen3"
    assert _role_configuration_missing("orchestrator", cfg) == ("ollama", ())


def test_dashboard_pin_route_matches_live_model_resolution(
    isolated_config,
):
    isolated_config.write_text("", encoding="utf-8")
    (isolated_config.parent / "runtime-overrides.toml").write_text(
        '[models]\norchestrator = "vllm:local-orchestrator"\n',
        encoding="utf-8",
    )
    from maverick import config
    from maverick.llm import model_for_role, offline_model_for_role
    from maverick.operator_preflight import _role_configuration_missing

    config.reset_config_cache()
    cfg = config.load_config()
    assert model_for_role("orchestrator") == "vllm:local-orchestrator"
    assert (
        offline_model_for_role("orchestrator", config=cfg)
        == "vllm:local-orchestrator"
    )
    assert _role_configuration_missing("orchestrator", cfg) == ("vllm", ())


def test_allowed_model_fallback_route_matches_live_model_resolution(
    isolated_config,
):
    isolated_config.write_text(
        '[models]\norchestrator = "anthropic:remote"\n',
        encoding="utf-8",
    )
    (isolated_config.parent / "runtime-overrides.toml").write_text(
        '[access]\nallowed_models = ["ollama:qwen3"]\n',
        encoding="utf-8",
    )
    from maverick import config
    from maverick.llm import model_for_role, offline_model_for_role
    from maverick.operator_preflight import _role_configuration_missing

    config.reset_config_cache()
    cfg = config.load_config()
    assert model_for_role("orchestrator") == "ollama:qwen3"
    assert offline_model_for_role("orchestrator", config=cfg) == "ollama:qwen3"
    assert _role_configuration_missing("orchestrator", cfg) == ("ollama", ())


def test_per_role_environment_override_precedes_global_in_preflight(
    monkeypatch, isolated_config,
):
    isolated_config.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:global")
    monkeypatch.setenv(
        "MAVERICK_MODEL_OVERRIDE_ORCHESTRATOR",
        "ollama:role-specific",
    )
    from maverick import config
    from maverick.llm import model_for_role, offline_model_for_role
    from maverick.operator_preflight import _role_configuration_missing

    config.reset_config_cache()
    cfg = config.load_config()
    assert model_for_role("orchestrator") == "ollama:role-specific"
    assert (
        offline_model_for_role("orchestrator", config=cfg)
        == "ollama:role-specific"
    )
    assert _role_configuration_missing("orchestrator", cfg) == ("ollama", ())


@pytest.mark.parametrize(
    ("auth_env", "auth_value"),
    [
        ("AZURE_OPENAI_AD_TOKEN", "static-entra-token"),
        ("AZURE_OPENAI_AUTH", "entra_id"),
    ],
)
def test_azure_route_accepts_entra_authentication(
    monkeypatch, isolated_config, auth_env, auth_value,
):
    from maverick.operator_preflight import _route_configuration_missing

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    monkeypatch.setenv(auth_env, auth_value)

    assert _route_configuration_missing("azure", {}) == ()


def test_azure_route_rejects_ambiguous_or_unknown_auth(
    monkeypatch, isolated_config,
):
    from maverick.operator_preflight import _route_configuration_missing

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "key")
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "token")
    assert _route_configuration_missing("azure", {}) == ("authentication",)

    monkeypatch.delenv("AZURE_OPENAI_API_KEY")
    monkeypatch.delenv("AZURE_OPENAI_AD_TOKEN")
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "not-a-real-mode")
    assert _route_configuration_missing("azure", {}) == ("authentication",)


@pytest.mark.parametrize(
    ("table", "environment", "expected"),
    [
        (
            {"auth_mode": "entra_id"},
            {"AZURE_OPENAI_AUTH": "api_key"},
            (),
        ),
        (
            {"auth_mode": "api_key", "api_key": "configured-key"},  # pragma: allowlist secret
            {"AZURE_OPENAI_AUTH": "entra_id"},
            (),
        ),
        (
            {"auth_mode": "unknown", "api_key": "configured-key"},  # pragma: allowlist secret
            {},
            ("authentication",),
        ),
        (
            {"auth_mode": "entra_id", "api_key": "configured-key"},
            {},
            ("authentication",),
        ),
        (
            {"auth_mode": "api_key"},
            {"AZURE_OPENAI_AD_TOKEN": "static-entra-token"},
            ("authentication",),
        ),
    ],
)
def test_azure_route_honors_config_auth_mode_like_runtime(
    monkeypatch,
    isolated_config,
    table,
    environment,
    expected,
):
    from maverick.operator_preflight import _route_configuration_missing

    for name in (
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_AD_TOKEN",
        "AZURE_OPENAI_AUTH",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    config = {
        "providers": {
            "azure": {
                "base_url": "https://res.openai.azure.com",
                **table,
            },
        },
    }
    assert _route_configuration_missing("azure", config) == expected


def test_cli_json_reports_corrupt_config_instead_of_resolving_world_storage(
    isolated_config,
):
    isolated_config.write_text("[client\ninvalid", encoding="utf-8")
    from maverick import config
    from maverick.cli import main

    config.reset_config_cache()
    result = CliRunner().invoke(main, ["preflight", "--json"])

    assert result.exit_code == 1
    body = json.loads(result.output)
    assert body["ready"] is False
    assert body["checks"][0]["id"] == "config"
    assert "invalid" in body["checks"][0]["detail"]
    assert "ClientBindingError" not in result.output


def test_preflight_json_never_echoes_provider_secret(isolated_config):
    secret = "sk-do-not-print-this-value"  # pragma: allowlist secret
    isolated_config.write_text(
        (
            "[providers.openai]\n"
            f'api_key = "{secret}"  # pragma: allowlist secret\n'
        ),
        encoding="utf-8",
    )
    from maverick import config
    from maverick.cli import main

    config.reset_config_cache()
    result = CliRunner().invoke(main, ["preflight", "--json"])

    assert secret not in result.output


def test_an_invalid_saved_config_points_every_blocked_check_at_the_config_fix(isolated_config):
    # The file exists, so `maverick init` refuses to run; every check blocked by
    # the invalid file must send the operator to the fix that works.
    from maverick import operator_preflight

    isolated_config.write_text("this is not = valid = toml", encoding="utf-8")
    checks = _by_id(operator_preflight.collect())
    assert checks["config"].status == "blocked"
    for check_id in ("provider", "model_routes", "storage"):
        assert checks[check_id].status == "blocked"
        assert checks[check_id].remediation == "maverick config-lint"
