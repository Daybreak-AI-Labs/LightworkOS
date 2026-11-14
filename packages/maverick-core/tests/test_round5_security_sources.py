"""Saved security policy and source boundaries retain their configured scope."""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    from maverick import config

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(config, "tenant_config_path", lambda: None)
    config.reset_config_cache()
    yield config, tmp_path
    config.reset_config_cache()


@pytest.mark.parametrize("scope", ["deployment_key_scope", "external_fleet_key_scope"])
def test_bound_shared_key_scopes_do_not_use_tenant_deks(monkeypatch, tmp_path, scope):
    from maverick import crypto_at_rest as crypto
    from maverick.paths import tenant_scope

    monkeypatch.setattr(crypto, "per_tenant_at_rest", lambda: True)
    monkeypatch.setattr(crypto, "_active_keyring_key", lambda: None)
    monkeypatch.setattr(crypto, "_keyring_dir", lambda: tmp_path)
    monkeypatch.setattr(crypto, "_load_or_create_key", lambda: b"d" * 32)
    monkeypatch.setattr(crypto, "_load_existing_key", lambda: b"d" * 32)
    monkeypatch.setattr(crypto, "_admitted_shared_key", lambda: b"f" * 32)
    monkeypatch.setattr("maverick.tenant.kms.tenant_dek", lambda tenant: b"t" * 32)
    with tenant_scope(tenant="alpha"), getattr(crypto, scope)():
        blob = crypto.seal_bound(b"shared evidence", "change", bind_tenant=False)
    with tenant_scope(tenant="beta"), getattr(crypto, scope)():
        assert crypto.unseal_bound(blob, "change") == b"shared evidence"
    assert blob[len(crypto._BOUND_MAGIC):][:1] == b"D"


@pytest.mark.parametrize("operation", ["seal", "unseal", "seal_bound", "unseal_bound", "reseal"])
def test_tenant_crypto_refuses_unreadable_binding(monkeypatch, operation):
    from maverick import crypto_at_rest as crypto
    from maverick import paths

    monkeypatch.setattr(crypto, "per_tenant_at_rest", lambda: True)
    monkeypatch.setattr(paths, "current_tenant_id", lambda: None)
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: None)
    monkeypatch.setattr("maverick.tenant.kms.tenant_dek", lambda tenant: b"t" * 32)
    monkeypatch.setattr("maverick.tenant.kms.seal_for_tenant", lambda tenant, data: crypto._TENANT_MAGIC + data)
    monkeypatch.setattr("maverick.tenant.kms.unseal_for_tenant", lambda tenant, data: data[len(crypto._TENANT_MAGIC):])
    original = crypto.seal(b"old")
    bound = crypto.seal_bound(b"old", "field")

    def unreadable():
        raise ValueError("client binding is unreadable")

    monkeypatch.setattr(paths, "current_tenant_id_strict", unreadable)
    calls = {"seal": lambda: crypto.seal(b"new"), "unseal": lambda: crypto.unseal(original),
             "seal_bound": lambda: crypto.seal_bound(b"new", "field"),
             "unseal_bound": lambda: crypto.unseal_bound(bound, "field"),
             "reseal": lambda: crypto.reseal(original, b"new")}
    with pytest.raises(ValueError, match="binding is unreadable"):
        calls[operation]()


def test_non_table_security_sections_are_reported_and_normalized(isolated_config):
    config, root = isolated_config
    path = root / "config.toml"
    path.write_text('safety = "x"\nsandbox = 3\n')
    assert config.get_safety()["scan_input"] is True
    assert isinstance(config.get_sandbox(), dict)
    assert config.load_config()["safety"] == {}
    assert config.load_config()["sandbox"] == {}
    error = config.config_source_errors()[str(path)]
    assert "safety" in error and "sandbox" in error
    path.write_text('[safety]\nprofile = "strict"\n[sandbox]\nbackend = "docker"\n')
    assert config.get_sandbox()["backend"] == "docker"
    assert not config.config_source_errors()


def test_model_improvement_sources_apply_dashboard_resets(isolated_config):
    config, root = isolated_config
    (root / "config.toml").write_text('[model_improvement]\nallow_training = true\n')
    config.dashboard_overrides_path().write_text('''[_dashboard_resets.training]
path = ["model_improvement", "allow_training"]
keep = []
entries = false
preserve_tables = false
remove_value = true
''')
    snapshot, _tenant = config._model_improvement_policy_sources()
    assert "allow_training" not in snapshot["model_improvement"]
    assert snapshot == config.load_global_config()


def test_governance_names_match_case_and_warn_on_unregistered(monkeypatch, caplog):
    from maverick import governance, tools

    monkeypatch.setattr(tools, "base_tool_names", lambda **kwargs: {"shell"})
    names = governance._policy_names({"deny_actions": [" SHELL ", "shel"]}, "deny_actions")
    assert "shel" in caplog.text
    policy = governance.Policy(deny_actions=names)
    assert governance.evaluate("ShElL", policy=policy).decision is governance.Decision.DENY
    assert governance.evaluate("read_file", policy=policy).decision is governance.Decision.ALLOW


def test_unshown_flat_recipient_lists_cannot_be_remembered():
    from maverick import ifc

    for arguments in ({"attendees": ["x@y"]}, {"payload": '{"attendees":["x@y"]}'},
                      {"custom": ["https://example.test/inbox"]}):
        shown, complete = ifc.shown_destination(arguments)
        assert not complete
        assert "x@y" not in shown
    assert ifc.shown_destination({"to": ["x@y"], "body": "hello"})[1]


def test_a2a_deny_tools_union_environment_and_config(monkeypatch):
    from maverick import a2a_tasks, agent_trust, config

    monkeypatch.setenv("MAVERICK_A2A_DENY_TOOLS", "shell")
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: {})
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (False, {}))
    for denied in ([], ["write_file"]):
        monkeypatch.setattr(config, "load_config", lambda denied=denied: {"a2a": {"deny_tools": denied}})
        capability = a2a_tasks._a2a_capability()
        assert capability.deny_tools == frozenset({"shell", *denied})


def test_consent_ledger_keys_are_excluded_at_root_and_tenant_scopes():
    from maverick import backup

    for name in ("consent.ledger.key", "tenants/acme/consent.ledger.key"):
        path = Path(name)
        assert backup._is_key_material(path)
        assert not backup._keys_included(path, False)
        assert backup._keys_included(path, True)
    assert not backup._is_key_material(Path("consent.ledger.jsonl"))


def test_airgap_audits_tenant_roles_mcp_and_federation(monkeypatch, tmp_path):
    from maverick import air_gap, role_edit
    from maverick.llm import ROLE_MODELS

    roles = tmp_path / "roles.toml"
    monkeypatch.setattr(role_edit, "roles_file", lambda: roles)
    local = {"models": dict.fromkeys(ROLE_MODELS, "ollama:local-test"),
             "egress": {"deny": ["*"]}, "enterprise": {"mode": True}, "sandbox": {"backend": "docker"}}
    assert air_gap.audit(config=local)["clean"]
    roles.write_text('[orchestrator]\nmodel = "openai:remote-test"\n')
    assert not air_gap.audit(config=local)["clean"]
    roles.unlink()
    for extra in ({"mcp_servers": {"remote": {"url": "https://public.example/mcp"}}},
                  {"federation": {"peers": [{"name": "remote", "target": "public.example:50051"}]}}):
        assert not air_gap.audit(config={**local, **extra})["clean"]
