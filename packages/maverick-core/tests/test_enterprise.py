"""Enterprise mode: egress lock + fail-closed safety defaults."""
from __future__ import annotations

import pytest
from maverick import capability
from maverick.enterprise import (
    EgressBlocked,
    assert_provider_allowed,
    enterprise_enabled,
    is_local_provider,
)
from maverick.safety import consent


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Start each test from a known-off state with an empty config."""
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    monkeypatch.delenv("MAVERICK_ENFORCE_CAPABILITIES", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_off_by_default():
    assert enterprise_enabled() is False


def test_env_enables_and_disables(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert enterprise_enabled() is True
    # An explicit falsey env force-disables even if config would enable it.
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    assert enterprise_enabled() is False


def test_config_enables(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"enterprise": {"mode": True}}
    )
    assert enterprise_enabled() is True


def test_policy_uncertainty_fails_closed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "maybe")
    assert enterprise_enabled() is True

    monkeypatch.delenv("MAVERICK_ENTERPRISE")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"mode": "false"}},
    )
    assert enterprise_enabled() is True


def test_unreadable_config_source_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.config_source_errors",
        lambda **_kwargs: {"config.toml": "unreadable"},
    )
    assert enterprise_enabled() is True


def test_local_provider_classification():
    assert is_local_provider("ollama")
    assert is_local_provider("local")  # alias -> ollama
    assert is_local_provider("vllm")
    assert is_local_provider("tgi")
    assert is_local_provider("Ollama")  # canonicalized
    assert not is_local_provider("anthropic")
    assert not is_local_provider("openai")


def test_egress_guard_is_noop_when_off():
    # No raise even for a cloud provider when enterprise mode is off.
    assert assert_provider_allowed("anthropic") is None


def test_egress_guard_blocks_cloud_when_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    with pytest.raises(EgressBlocked) as exc:
        assert_provider_allowed("anthropic")
    assert exc.value.provider == "anthropic"
    # Self-hosted providers pass.
    assert assert_provider_allowed("ollama") is None
    assert assert_provider_allowed("vllm") is None


def test_extra_local_providers_allow_listed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"local_providers": ["myvllm"]}},
    )
    assert is_local_provider("myvllm")
    assert assert_provider_allowed("myvllm") is None
    # Still blocks an un-listed cloud provider.
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("openai")


def test_extra_local_providers_cannot_allow_list_cloud_names(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"local_providers": ["openai", "claude"]}},
    )
    assert not is_local_provider("openai")
    assert not is_local_provider("anthropic")
    with pytest.raises(EgressBlocked) as exc:
        assert_provider_allowed("openai")
    assert exc.value.provider == "openai"


def test_openai_compatible_requires_local_endpoint_when_allow_listed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "enterprise": {"local_providers": ["custom"]},
            "providers": {
                "openai_compatible": {"base_url": "https://api.groq.com/openai/v1"}
            },
        },
    )
    assert not is_local_provider("custom")
    with pytest.raises(EgressBlocked) as exc:
        assert_provider_allowed("openai-compatible")
    assert exc.value.provider == "openai_compatible"


def test_openai_compatible_local_endpoint_can_be_allow_listed(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "enterprise": {"local_providers": ["custom"]},
            "providers": {
                "openai_compatible": {"base_url": "http://127.0.0.1:8000/v1"}
            },
        },
    )
    assert is_local_provider("custom")
    assert assert_provider_allowed("openai_compatible") is None


def test_consent_defaults_fail_closed_in_enterprise(monkeypatch):
    # Off -> auto-approve (unchanged behavior).
    assert consent._resolve_mode() == "auto-approve"
    # On -> ask (fail-closed; non-tty then denies).
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert consent._resolve_mode() == "ask"
    # An explicit consent mode still wins over the enterprise default.
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    assert consent._resolve_mode() == "dashboard"


def test_capabilities_forced_on_in_enterprise(monkeypatch):
    assert capability.capability_enforced() is False
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert capability.capability_enforced() is True


def test_local_provider_redirected_off_box_via_env_is_blocked(monkeypatch):
    # The egress-lock bypass: a "local" provider name (vllm) redirected to a
    # public endpoint by env must NOT satisfy the lock.
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("VLLM_BASE_URL", "https://exfil.attacker.example.com/v1")
    assert not is_local_provider("vllm")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("vllm")


def test_local_provider_redirected_off_box_via_config_is_blocked(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"providers": {"ollama": {"base_url": "https://1.2.3.4/v1"}}},
    )
    assert not is_local_provider("ollama")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("ollama")


def test_vllm_env_public_endpoint_cannot_be_masked_by_local_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("VLLM_BASE_URL", "https://exfil.attacker.example.com/v1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "providers": {"vllm": {"base_url": "http://localhost:8000/v1"}}
        },
    )
    assert not is_local_provider("vllm")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("vllm")


def test_tgi_env_public_endpoint_cannot_be_masked_by_local_config(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("TGI_BASE_URL", "https://exfil.attacker.example.com/v1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "providers": {"tgi": {"base_url": "http://localhost:8080/v1"}}
        },
    )
    assert not is_local_provider("tgi")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("tgi")


def test_vllm_config_public_endpoint_cannot_be_masked_by_local_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("VLLM_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "providers": {"vllm": {"base_url": "https://exfil.attacker.example/v1"}}
        },
    )
    assert not is_local_provider("vllm")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("vllm")


def test_tgi_config_public_endpoint_cannot_be_masked_by_local_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("TGI_BASE_URL", "http://127.0.0.1:8080/v1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "providers": {"tgi": {"base_url": "https://exfil.attacker.example/v1"}}
        },
    )
    assert not is_local_provider("tgi")
    with pytest.raises(EgressBlocked):
        assert_provider_allowed("tgi")


def test_local_provider_with_local_or_default_endpoint_still_passes(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("VLLM_BASE_URL", "http://localhost:8000/v1")
    assert is_local_provider("vllm")                 # explicit local endpoint
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    assert is_local_provider("vllm")                 # no endpoint -> localhost default


def test_allow_listed_custom_provider_pointed_off_box_is_blocked(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {
            "enterprise": {"local_providers": ["myvllm"]},
            "providers": {"myvllm": {"base_url": "https://gateway.public.example/v1"}},
        },
    )
    assert not is_local_provider("myvllm")           # vouched, but aimed off-box


# --- enterprise: env truthy-word must not silently disable -------------------

def test_enterprise_recognizes_affirmatives_and_negatives(monkeypatch):
    from maverick import enterprise
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    for v in ("1", "true", "on", "yes", "enable", "enabled", "y", "t"):
        monkeypatch.setenv("MAVERICK_ENTERPRISE", v)
        assert enterprise.enterprise_enabled() is True, v
    for v in ("0", "false", "off", "no", "disable", "disabled"):
        monkeypatch.setenv("MAVERICK_ENTERPRISE", v)
        assert enterprise.enterprise_enabled() is False, v


def test_enterprise_ambiguous_env_falls_through_to_config(monkeypatch):
    from maverick import enterprise
    # An unrecognized env value must NOT silently disable the control: config decides.
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"enterprise": {"mode": True}})
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "enabled-for-prod")
    assert enterprise.enterprise_enabled() is True
