"""Advanced setup keeps invalid answers recoverable and saved choices effective."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_installer import wizard
from maverick_installer.wizard import _common, advanced, assessments, security_suite


def _parsed(lines):
    return tomllib.loads("\n".join(lines))


def test_dynamic_names_and_strings_round_trip_without_toml_injection(monkeypatch):
    names = ['main site', 'eu.main', 'quoted"name', 'new\nline']
    values = {name: {"description": 'path\\with"quotes\n\t\x00\x7f'} for name in names}
    lines = []
    _common._append_nested_product_config(lines, "product.bindings", values)
    assert _parsed(lines)["product"]["bindings"] == values
    parsed = _parsed(wizard._cfg_security_suite({"enrichment_sources": names}))
    assert set(parsed["env_hunt"]["enrichment_sources"]) == set(names)
    injected = 'tenant"\nadded = true\n#'
    parsed = _parsed(advanced._cfg_advanced_quotas_and_tenancy({"client_id": injected}))
    assert parsed["client"] == {"id": injected, "enforce": True}
    sidecar = {"enable": True, "upstream_url": "https://mcp.example/mcp", "tools": {"eu.main": {}}}
    parsed = _parsed(advanced._cfg_advanced_external_agents_and_memory({"mcp_sidecar": sidecar}))
    from maverick_mcp.sidecar import SidecarConfig
    assert SidecarConfig.from_mapping(parsed["mcp_sidecar"]).tools[0].name == "eu.main"


def test_name_prompts_recover_and_keep_dotted_binding_and_client_ids(monkeypatch):
    answers = iter(['main site', 'eu.main'])
    monkeypatch.setattr(wizard, "_q_text", lambda p, default="": next(answers) if "binding name" in p else default)
    binding = assessments._pick_notice_publication_binding()
    assert binding.pop("binding_id") == "eu.main"
    lines = []
    _common._append_nested_product_config(lines, "privacy_automation.notice_governance.publication_runtime", {
        "enable": False, "active_tenants": [binding["tenant_id"]], "bindings": {"eu.main": binding},
    })
    from maverick.config_lint import _lint_privacy_notice_publication_runtime
    assert _lint_privacy_notice_publication_runtime(_parsed(lines)) == []
    answers = iter(['main site', 'EU.Main', 'eu.main'])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(answers))
    picked = advanced._pick_client_id()
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: _parsed(advanced._cfg_advanced_quotas_and_tenancy({"client_id": picked})))
    from maverick import client
    assert client._resolve() == "eu.main"
    answers = iter(['main site', 'eu.main'])
    assert security_suite._pick_enrichment_sources() == ['eu.main']


def test_oidc_reprompts_required_urls_and_masks_secrets(monkeypatch):
    text = iter(['', 'http://idp.example', 'https://idp.example', '', 'opaque-audience',
                 'http://keys.example', 'https://idp.example/keys', '', 'dashboard',
                 'http://dashboard.example/auth/callback', 'http://localhost:8080/auth/callback'])
    secret = iter(['', 'provider-secret', 'short', 's' * 32])
    seen = []
    def answer(prompt, **kwargs):
        assert "secret" not in prompt.lower()
        return next(text)
    monkeypatch.setattr(wizard, "_q_text", answer)
    monkeypatch.setattr(wizard, "_q_secret", lambda prompt: (seen.append(prompt), next(secret))[1])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: True)
    picked = advanced.pick_oidc()
    parsed = _parsed(advanced._cfg_advanced_oidc({"oidc": picked}))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    from maverick.oidc import load_oidc_config, login_enabled
    actual = load_oidc_config()
    assert actual.audience == "opaque-audience" and actual.session_secret == 's' * 32
    assert login_enabled(actual) and len(seen) == 4


@pytest.mark.parametrize("change", [
    {"audience": ""}, {"audience": None}, {"issuer": ""}, {"jwks_uri": "http://keys.example"},
    {"client_id": "dash", "client_secret": "provider", "redirect_uri": "https://dash.example/auth/callback", "session_secret": "short"},
])
def test_oidc_writer_refuses_incomplete_or_unsafe_enabled_config(change):
    oidc = {"enabled": True, "issuer": "https://idp.example", "audience": "opaque", "jwks_uri": "https://idp.example/keys", **change}
    with pytest.raises(ValueError, match="OIDC"):
        advanced._cfg_advanced_oidc({"oidc": oidc})


def test_monthly_spending_reprompts_and_currency_reaches_kernel(monkeypatch):
    answers = iter(['-1', 'garbage', 'nan', '1,00', '1000000001', '$500', '1,000'])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(answers))
    workspace = advanced._pick_monthly_limit("Workspace")
    person = advanced._pick_monthly_limit("Person")
    parsed = _parsed(advanced._cfg_advanced_quotas_and_tenancy({
        "spending_workspace_monthly": workspace, "spending_person_monthly": person,
    }))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    from maverick.spending_limits import _config_seed
    limits = _config_seed()
    assert limits["workspace"]["amount"] == 500 and limits["default"]["amount"] == 1000
    with pytest.raises(ValueError):
        advanced._cfg_advanced_quotas_and_tenancy({"spending_workspace_monthly": "-1"})


def test_audit_reward_no_reaches_kernel(monkeypatch):
    parsed = _parsed(advanced._cfg_advanced_verification_and_rewards({"audit_rewards": False}))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    assert config.get_reasoning_reward()["audit_rewards"] is False


@pytest.mark.parametrize("enabled", [False, True])
def test_deferred_tools_has_one_prompt_and_preferred_key(monkeypatch, enabled):
    prompts = []
    def confirm(prompt, *, default=False):
        prompts.append(prompt)
        return enabled if "deferred tool loading" in prompt.lower() else default
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    capabilities = wizard.pick_capabilities()
    runtime = advanced._pick_runtime_toggles()
    lines = wizard._cfg_capabilities({"deferred_tools": capabilities["deferred_tools"]}, False)
    lines += advanced._cfg_advanced_runtime_and_tools(runtime, [])
    parsed = _parsed(lines)
    assert sum("deferred tool loading" in p.lower() for p in prompts) == 1
    assert "deferred_loading" not in parsed.get("tools", {})
    assert config.get_deferred_tools(config=parsed) is enabled


def test_per_tenant_encryption_explains_unsaved_dependency(monkeypatch, capsys):
    monkeypatch.setattr(wizard, "_q_confirm", lambda p, **k: p.startswith("Per-tenant encryption keys?"))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    picked = advanced.pick_advanced()
    assert picked["encrypt_per_tenant"] is False
    assert "That answer was not saved" in " ".join(capsys.readouterr().out.split())


def test_self_harness_zero_prompt_matches_kernel_risk_cap(monkeypatch):
    prompts = []
    def text(prompt, *, default=""):
        prompts.append(prompt)
        return "corpus.json" if "Eval-corpus path" in prompt else "0" if "Spend cap" in prompt else default
    monkeypatch.setattr(wizard, "_q_text", text)
    monkeypatch.setattr(wizard, "_q_confirm", lambda p, **k: "Tune self-harness advanced paths" in p)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    picked = {"self_harness": True}
    advanced._ask_self_harness_followups(picked)
    parsed = _parsed(advanced._cfg_advanced_self_harness(picked))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    assert config.get_self_harness()["eval_budget_dollars"] == 5.0
    assert "0 = the risk-limited $5 ceiling" in next(p for p in prompts if "Spend cap" in p)


@pytest.mark.parametrize("url", [
    "http://localhost.evil.example/mcp", "http://127.0.0.1.evil.example/mcp",
    "http://localhost@evil.example/mcp", "https://localhost\\@evil.example/mcp",
    "https://", "http://[invalid]/mcp",
])
def test_sidecar_rejects_non_loopback_http_and_malformed_urls(monkeypatch, url):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: True)
    monkeypatch.setattr(wizard, "_q_text", lambda p, default="": url if "URL" in p else "search:low" if "Reviewed upstream" in p else default)
    assert advanced.pick_governed_mcp_sidecar() == {}
    with pytest.raises(ValueError, match="MCP sidecar"):
        advanced._cfg_advanced_external_agents_and_memory({"mcp_sidecar": {"enable": True, "upstream_url": url}})
    assert advanced._secure_or_loopback_url("http://[::1]:8787/mcp")
    assert advanced._secure_or_loopback_url("https://mcp.example/mcp")


def test_hunter_poll_reprompts_nonfinite_values(monkeypatch):
    answers = iter(['nan', 'inf', '1e400', 'bad', '120'])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(answers))
    assert security_suite._pick_hunter_poll_seconds() == 120
