"""Fail-closed configuration for governed specialist-model improvement."""
from __future__ import annotations

import pytest
from maverick import adapter_rung, config
from maverick.migrate import KNOWN_SECTIONS
from maverick.paths import tenant_scope


def test_model_improvement_defaults_are_inert(monkeypatch):
    monkeypatch.setattr(config, "load_config", dict)

    assert config.get_model_improvement() == {
        "enable": False,
        "allow_hosted": False,
        "allow_cross_tenant": False,
        "require_signed_receipt": True,
        "minimum_train_families": 20,
        "minimum_holdout_families": 20,
    }


def test_model_improvement_rejects_truthy_strings_and_low_family_floors(
    monkeypatch,
):
    monkeypatch.setattr(config, "load_config", lambda: {
        "model_improvement": {
            "enable": "true",
            "allow_hosted": "yes",
            "allow_cross_tenant": "on",
            "require_signed_receipt": "false",
            "minimum_train_families": 3,
            "minimum_holdout_families": True,
        },
    })

    settings = config.get_model_improvement()
    assert settings["enable"] is False
    assert settings["allow_hosted"] is False
    assert settings["allow_cross_tenant"] is False
    assert settings["require_signed_receipt"] is True
    assert settings["minimum_train_families"] == 20
    assert settings["minimum_holdout_families"] == 20


def test_model_improvement_accepts_explicit_bounded_controls(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {
        "model_improvement": {
            "enable": True,
            "allow_hosted": True,
            "allow_cross_tenant": False,
            "require_signed_receipt": True,
            "minimum_train_families": 50,
            "minimum_holdout_families": 75,
        },
    })

    settings = config.get_model_improvement()
    assert settings["enable"] is True
    assert settings["allow_hosted"] is True
    assert settings["allow_cross_tenant"] is False
    assert settings["require_signed_receipt"] is True
    assert settings["minimum_train_families"] == 50
    assert settings["minimum_holdout_families"] == 75


def test_model_improvement_is_a_known_config_section():
    assert "model_improvement" in KNOWN_SECTIONS


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (19, 20),
        (20, 20),
        (1_000_000, 1_000_000),
        (1_000_001, 1_000_000),
        (-1, 20),
        (20.0, 20),
        (False, 20),
    ],
)
def test_model_improvement_family_floor_boundaries(
    monkeypatch,
    configured,
    expected,
):
    monkeypatch.setattr(config, "load_config", lambda: {
        "model_improvement": {
            "minimum_train_families": configured,
            "minimum_holdout_families": configured,
        },
    })

    settings = config.get_model_improvement()
    assert settings["minimum_train_families"] == expected
    assert settings["minimum_holdout_families"] == expected


@pytest.fixture
def mutation_policy_home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    try:
        yield tmp_path
    finally:
        config.reset_config_cache()


def test_mutation_policy_single_tenant_requires_signed_receipts(
    mutation_policy_home,
):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\n"
        "enable = true\n"
        "allow_hosted = true\n"
        "require_signed_receipt = false\n"
        "minimum_train_families = 40\n"
        "minimum_holdout_families = 60\n",
        encoding="utf-8",
    )

    with pytest.raises(
        config.ModelImprovementConfigError,
        match="requires.*require_signed_receipt",
    ):
        config.get_model_improvement_mutation_policy()


def test_mutation_policy_tenant_strictest_wins(mutation_policy_home):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\n"
        "enable = true\n"
        "allow_hosted = true\n"
        "require_signed_receipt = false\n"
        "minimum_train_families = 50\n"
        "minimum_holdout_families = 20\n",
        encoding="utf-8",
    )
    tenant_file = mutation_policy_home / "tenants" / "acme" / "config.toml"
    tenant_file.parent.mkdir(parents=True)
    tenant_file.write_text(
        "[model_improvement]\n"
        "enable = true\n"
        "allow_hosted = false\n"
        "require_signed_receipt = true\n"
        "minimum_train_families = 20\n"
        "minimum_holdout_families = 75\n",
        encoding="utf-8",
    )

    with tenant_scope(tenant="acme"):
        assert config.get_model_improvement_mutation_policy() == {
            "enable": True,
            "allow_hosted": False,
            "allow_cross_tenant": False,
            "require_signed_receipt": True,
            "minimum_train_families": 50,
            "minimum_holdout_families": 75,
        }


def test_mutation_policy_tenant_cannot_raise_global_ceilings(
    mutation_policy_home,
):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\n"
        "enable = false\n"
        "allow_hosted = false\n",
        encoding="utf-8",
    )
    tenant_file = mutation_policy_home / "tenants" / "acme" / "config.toml"
    tenant_file.parent.mkdir(parents=True)
    tenant_file.write_text(
        "[model_improvement]\n"
        "enable = true\n"
        "allow_hosted = true\n",
        encoding="utf-8",
    )

    with tenant_scope(tenant="acme"):
        settings = config.get_model_improvement_mutation_policy()
    assert settings["enable"] is False
    assert settings["allow_hosted"] is False


def test_mutation_policy_active_tenant_requires_its_own_opt_in(
    mutation_policy_home,
):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\n"
        "enable = true\n"
        "allow_hosted = true\n",
        encoding="utf-8",
    )

    with tenant_scope(tenant="acme"):
        settings = config.get_model_improvement_mutation_policy()
    assert settings["enable"] is False
    assert settings["allow_hosted"] is False


@pytest.mark.parametrize(
    "bad_section",
    [
        {"enable": "true"},
        {"minimum_train_families": 19},
        {"require_signed_reciept": True},
        {"allow_cross_tenant": True},
    ],
)
def test_mutation_policy_rejects_invalid_or_unsupported_controls(
    monkeypatch,
    bad_section,
):
    monkeypatch.setattr(
        config,
        "_model_improvement_policy_sources",
        lambda: ({"model_improvement": bad_section}, None),
    )

    with pytest.raises(
        config.ModelImprovementConfigError,
        match="policy source is invalid",
    ):
        config.get_model_improvement_mutation_policy()


def test_mutation_policy_rejects_malformed_global_toml(mutation_policy_home):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\nenable =",
        encoding="utf-8",
    )

    with pytest.raises(
        config.ModelImprovementConfigError,
        match="policy source is invalid",
    ):
        config.get_model_improvement_mutation_policy()


def test_mutation_policy_rejects_malformed_tenant_toml(mutation_policy_home):
    (mutation_policy_home / "config.toml").write_text(
        "[model_improvement]\nenable = true\n",
        encoding="utf-8",
    )
    tenant_file = mutation_policy_home / "tenants" / "acme" / "config.toml"
    tenant_file.parent.mkdir(parents=True)
    tenant_file.write_text(
        "[model_improvement]\nenable =",
        encoding="utf-8",
    )

    with tenant_scope(tenant="acme"), pytest.raises(
        config.ModelImprovementConfigError,
        match="policy source is invalid",
    ):
        config.get_model_improvement_mutation_policy()


def test_malformed_toml_keeps_defaults_and_is_recorded_as_untrusted(
    monkeypatch,
    tmp_path,
):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "[model_improvement]\nenable = true\nrequire_signed_receipt =\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_file))
    config.reset_config_cache()
    try:
        settings = config.get_model_improvement()
        assert settings["enable"] is False
        assert settings["require_signed_receipt"] is True
        assert str(cfg_file) in config.config_source_errors()
    finally:
        config.reset_config_cache()


def test_malformed_toml_denies_training_and_adapter_promotion(
    monkeypatch,
    tmp_path,
):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "[model_improvement]\nallow_hosted = true\nrequire_signed_receipt =",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_file))
    config.reset_config_cache()
    try:
        with pytest.raises(
            config.ModelImprovementConfigError,
            match="policy source is invalid",
        ):
            config.get_model_improvement_mutation_policy()
        with pytest.raises(ValueError, match="policy source is invalid"):
            adapter_rung._model_improvement_policy()
    finally:
        config.reset_config_cache()
