"""Air-gapped preflight audit: flag remote providers / egress / sandbox network."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.air_gap import audit
from maverick.cli import main
from maverick.llm import ROLE_MODELS
from maverick.provider_local_first import is_local

# A model spec the local-first classifier recognizes as local.
_LOCAL = next((m for m in ("ollama:llama3", "vllm:x", "tgi:x", "local:x")
               if is_local(m)), "ollama:llama3")


def _all_local_models():
    return dict.fromkeys(ROLE_MODELS, _LOCAL)


def test_default_config_is_not_air_gapped():
    # No local override -> default role models are remote (Anthropic).
    rep = audit(config={})
    assert rep["clean"] is False
    assert any("remote model" in v for v in rep["violations"])
    assert any("egress is not deny-all" in v for v in rep["violations"])


def test_fully_local_with_deny_all_is_clean():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"}, "enterprise": {"mode": True}}
    rep = audit(config=cfg)
    assert rep["clean"] is True and rep["violations"] == []


def test_partial_local_override_still_flags_remote_defaults():
    # only one role overridden -> the rest keep remote defaults
    one = dict.fromkeys(list(ROLE_MODELS)[:1], _LOCAL)
    rep = audit(config={"models": one, "egress": {"deny": ["*"]},
                        "sandbox": {"backend": "docker"}})
    assert rep["clean"] is False
    assert any("remote model" in v for v in rep["violations"])


def test_flags_allow_all_egress():
    cfg = {"models": _all_local_models(), "egress": {"deny": [], "allow": []},
           "sandbox": {"backend": "docker"}}
    rep = audit(config=cfg)
    assert any("egress is not deny-all" in v for v in rep["violations"])


def test_flags_sandbox_network():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker", "allow_network": True}}
    rep = audit(config=cfg)
    assert any("allow_network" in v for v in rep["violations"])


def test_llm_section_does_not_hide_runtime_remote_defaults():
    cfg = {"llm": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("remote model" in v for v in rep["violations"])


def test_default_local_sandbox_is_not_air_gapped():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("backend=local" in v for v in rep["violations"])


def test_flags_backend_specific_sandbox_network():
    base = {"models": _all_local_models(), "egress": {"deny": ["*"]}}
    for sandbox in (
        {"backend": "devcontainer"},
        {"backend": "firecracker", "network": "egress-allow"},
        {"backend": "firecracker", "network": "bridge=br0"},
        {"backend": "ssh"},
    ):
        rep = audit(config={**base, "sandbox": sandbox})
        assert rep["clean"] is False
        assert any("sandbox" in v for v in rep["violations"])


def test_kubernetes_without_networkpolicy_assertion_is_flagged():
    # k8s egress is unprovable by static config; a bare kubernetes backend
    # (allow_network off) must NOT certify clean — a transient pod has full
    # egress unless an out-of-band deny-all NetworkPolicy is applied.
    base = {"models": _all_local_models(), "egress": {"deny": ["*"]}}
    rep = audit(config={**base, "sandbox": {"backend": "kubernetes"}})
    assert rep["clean"] is False
    assert any("backend=kubernetes" in v for v in rep["violations"])


def test_kubernetes_with_deny_all_networkpolicy_assertion_is_clean():
    # The only k8s config that actually runs air-gapped (deny-all NetworkPolicy
    # applied out-of-band + allow_network=true) must pass.
    base = {"models": _all_local_models(), "egress": {"deny": ["*"]},
            "enterprise": {"mode": True}}
    rep = audit(config={**base, "sandbox": {
        "backend": "kubernetes", "allow_network": True,
        "network_policy": "deny-all"}})
    assert rep["clean"] is True and rep["violations"] == []


def test_local_provider_pointed_offbox_is_flagged():
    # Every role -> ollama (a "local" provider name), but [providers.ollama]
    # base_url points at a public host. A name-only check would certify this
    # clean while every prompt left the box; endpoint validation must flag it.
    cfg = {"models": _all_local_models(),
           "providers": {"ollama": {"base_url": "https://exfil.example.com/v1"}},
           "egress": {"deny": ["*"]}, "sandbox": {"backend": "docker"}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("remote model" in v for v in rep["violations"])


def test_local_provider_loopback_endpoint_stays_clean():
    # A genuinely loopback local endpoint is proven local and stays clean.
    cfg = {"models": _all_local_models(),
           "providers": {"ollama": {"base_url": "http://127.0.0.1:11434/v1"}},
           "egress": {"deny": ["*"]}, "sandbox": {"backend": "docker"},
           "enterprise": {"mode": True}}
    rep = audit(config=cfg)
    assert rep["clean"] is True and rep["violations"] == []


def test_flags_sentry_dsn_telemetry_sink():
    # A telemetry sink outside the [egress] deny list.
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"},
           "observability": {"sentry_dsn": "https://k@o0.ingest.sentry.io/1"}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("sentry_dsn" in v for v in rep["violations"])


def test_flags_siem_dest_telemetry_sink():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"},
           "audit": {"siem_dest": "tcp://siem.example.com:514"}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("siem_dest" in v for v in rep["violations"])


def test_flags_outbound_webhook_telemetry_sink():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"},
           "webhooks": {"outbound": ["https://hooks.example.com/x"]}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("webhooks" in v.lower() for v in rep["violations"])


def _fully_local_with(observability: dict) -> dict:
    return {"models": _all_local_models(), "egress": {"deny": ["*"]},
            "sandbox": {"backend": "docker"}, "enterprise": {"mode": True},
            "observability": observability}


@pytest.mark.parametrize(("switch", "value"), [
    ("otel_exporter", "otlp"), ("otlp_metrics", True), ("otlp_metrics", "1")])
def test_flags_otlp_telemetry_switches_in_config(switch, value):
    # The All settings page writes these into [observability]; the audit reads the table.
    rep = audit(config=_fully_local_with({switch: value}))
    assert rep["clean"] is False
    assert any(switch in v for v in rep["violations"])


@pytest.mark.parametrize(("switch", "value"), [
    ("otel_exporter", ""), ("otel_exporter", False), ("otel_exporter", "false"),
    ("otel_exporter", "0"), ("otel_exporter", "off"), ("otel_exporter", "console"),
    ("otlp_metrics", False), ("otlp_metrics", "false"), ("otlp_metrics", "0"),
    ("otlp_metrics", "off")])
def test_off_otlp_telemetry_switches_stay_clean(switch, value):
    # A TOML false, or a word the runtime reads as off, is not a telemetry sink.
    assert audit(config=_fully_local_with({switch: value}))["clean"] is True


@pytest.mark.parametrize("value", [False, "false", "0", "off", ""])
def test_off_sentry_dsn_stays_clean(value):
    assert audit(config=_fully_local_with({"sentry_dsn": value}))["clean"] is True


def test_deny_all_egress_without_enterprise_mode_is_flagged():
    # The runtime egress guard (egress_guard.py, wrapping httpx/requests
    # across ~80 connectors and every provider SDK) only enforces default-deny
    # when enterprise mode is on -- enterprise.egress_permitted() returns True
    # unconditionally otherwise, whatever [egress] says. A config with
    # [egress] deny=["*"] and no [enterprise] section used to certify clean
    # while every connector could still reach the internet.
    from maverick import enterprise
    assert enterprise.egress_permitted("https://evil.example.com") is True, (
        "sanity check: the runtime guard permits egress with enterprise mode off"
    )
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("[enterprise] mode is not enabled" in v for v in rep["violations"])


def test_enterprise_mode_true_clears_the_egress_flag():
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"}, "enterprise": {"mode": True}}
    rep = audit(config=cfg)
    assert not any("[enterprise] mode is not enabled" in v for v in rep["violations"])


def test_nonempty_allowed_hosts_is_flagged_even_with_enterprise_mode_on():
    # allowed_hosts is a deliberate egress exception -- incompatible with
    # air-gapped, whether or not enterprise mode is otherwise engaged.
    cfg = {"models": _all_local_models(), "egress": {"deny": ["*"]},
           "sandbox": {"backend": "docker"},
           "enterprise": {"mode": True, "allowed_hosts": ["api.example.com"]}}
    rep = audit(config=cfg)
    assert rep["clean"] is False
    assert any("allowed_hosts" in v and "api.example.com" in v
               for v in rep["violations"])


def test_cli_airgap_check_fails_when_dirty(monkeypatch):
    monkeypatch.setattr("maverick.air_gap.audit",
                        lambda: {"clean": False, "violations": ["remote model(s) in use: x"]})
    res = CliRunner().invoke(main, ["airgap", "check"])
    assert res.exit_code == 1
    assert "NOT air-gapped" in res.output


def test_cli_airgap_check_passes_when_clean(monkeypatch):
    monkeypatch.setattr("maverick.air_gap.audit",
                        lambda: {"clean": True, "violations": []})
    res = CliRunner().invoke(main, ["airgap", "check"])
    assert res.exit_code == 0
    assert "AIR-GAPPED" in res.output
