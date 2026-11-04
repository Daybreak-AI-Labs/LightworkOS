"""Settings > All settings: the runtime rows (models, tools, work area, safety).

Every row in ``settings_catalog_runtime`` saves and reads back through the
catalog API into what the kernel's ``load_config`` returns; wrong values are
refused; secrets are sealed and never returned; loosening a protection needs a
confirmation; each change leaves an audit row. The readers this package had to
fix are exercised directly: the saved value changes what the kernel does.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_all_page as page
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_runtime as runtime
from maverick_dashboard.app import app

from test_support.settings_pages import save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
ROWS = runtime.entries(catalog.S, catalog.C, catalog.Column)
_ENV = sorted({name for s in ROWS for name in s.env} | {
    "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
    "MAVERICK_GATEWAY_TOKEN", "LLM_GATEWAY_UPSTREAM_TOKEN", "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_API_VERSION", "AWS_REGION", "AWS_DEFAULT_REGION", "MAVERICK_ENTERPRISE",
})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _live(source: str) -> list[str]:
    from maverick_dashboard import settings_all_page

    return [v for v, _label in settings_all_page._source_choices(source) if v]


# Values sent for rows whose control is not a single switch, choice or number,
# with the value the kernel then reads.
_WORDS = {
    "persona.addendum": "Always cite your sources.",
    "providers.anthropic.base_url": "https://gateway.example.com/anthropic",
    "providers.openai_compatible.base_url": "http://localhost:8000/v1",
    "providers.azure.base_url": "https://acme.openai.azure.com",
    "providers.azure.deployment": "gpt-deploy",
    "providers.azure.api_version": "2024-10-21",
    "providers.bedrock.region": "us-east-1",
    "providers.vertex.project_id": "acme-ai",
    "providers.vertex.region": "us-east5",
    "providers.vertex.model_id": "claude-haiku-4-5@20251001",
    "llm_gateway.anthropic_version": "2023-06-01",
    "sandbox.workdir": "/srv/lightwork/work",
    "sandbox.runtime": "runsc-debug",
    "sandbox.context": "prod-cluster",
    "sandbox.kubeconfig": "/etc/lightwork/kubeconfig",
    "sandbox.project_dir": "/srv/project",
    "plugins.ca_root_pubkey": "ab" * 32,
    "attachments.s3_bucket": "acme-attachments",
    "attachments.s3_prefix": "lightwork/",
    "knowledge.path": "/srv/lightwork/index.db",
    "knowledge.revision": "v2",
    "screening.sdn_path": "/srv/lists/sdn.txt",
    "memory.qdrant_url": "https://qdrant.example.com",
    "memory.weaviate_url": "https://weaviate.example.com",
    "observability.otel_endpoint": "https://otel.example.com/v1/traces",
    "shield.update_url": "https://rules.example.com/shield.json",
    "shield.update_pubkey": "cd" * 32,
    "memory.weaviate_grpc_host": "grpc.example.com",
    "models.embed": "BAAI/bge-base-en-v1.5",
    "models.clap": "laion/larger_clap_general",
    "model_proxy.upstream": "https://api.anthropic.com",
    "model_proxy.listen": "127.0.0.1:9876",
}
_LISTS = {
    "models.catalog": ["vllm:my-model"],
    "sandbox.ssh_args": ["-p2222"],
    "sandbox.extra_kubectl_args": ["--request-timeout=30s"],
    "egress.deny": ["169.254.169.254"],
    "egress.allow": ["api.example.com"],
    "plugins.ca_revoked": ["0123456789abcdef"],
    "attachments.extra_mime_prefixes": ["application/vnd.visio"],
    "tools.core_extra": ["scan_finance_anomalies"],
    "containment.deny_tools": ["github_issues"],
    "search.ladder": ["anthropic:claude-opus-4-8:0.3"],
    "mcp.allowed_origins": ["https://gateway.example.com"],
    "mcp.elicit_allowed_hosts": ["accounts.google.com"],
}
# Rows whose only other value is refused on purpose (with a plain reason).
_REFUSED = {"ekko.provider_egress"}


def _sample(setting) -> tuple[object, object]:  # noqa: C901 - one branch per control
    """(value sent, value the kernel reads) for a change away from the default."""
    sid = setting.id
    if sid in _WORDS:
        return _WORDS[sid], _WORDS[sid]
    if sid in _LISTS:
        return _LISTS[sid], _LISTS[sid]
    if setting.control == "toggle":
        return (not setting.default,) * 2
    if setting.control == "secret":
        return "s3cret-value-for-" + sid, "s3cret-value-for-" + sid
    if setting.control == "select":
        options = [v for v, _ in setting.choices] or _live(setting.choices_from)
        value = next(v for v in options if v != setting.default)
        return value, value
    if setting.control == "multiselect":
        value = [setting.choices[0][0]]
        return value, value
    if setting.control == "number":
        shown = setting.maximum if setting.minimum is None else setting.minimum
        if shown * setting.scale == setting.default:
            shown = setting.maximum
        stored = shown * setting.scale
        if setting.integer or float(stored).is_integer():
            stored = int(round(stored)) if setting.integer or isinstance(setting.default, int) \
                else stored
        return shown, stored
    if sid == "context.model_windows":
        model = _live("models")[0]
        return [{"name": model, "window": 64000}], {model: 64000}
    if sid == "routing.roles":
        return ([{"name": "coder", "tier": "cheap"}],
                {"coder": {"providers": [], "deny_providers": [], "tier": "cheap"}})
    if sid == "sandbox.tool":
        return ([{"name": "http_fetch", "allow_egress": ["api.example.com"]}],
                {"http_fetch": {"allow_egress": ["api.example.com"], "deny_egress": []}})
    if sid == "security.tool_risk":
        return [{"name": "mcp_*", "risk": "medium"}], {"mcp_*": "medium"}
    if sid == "lsp.servers":
        return [{"name": "python", "command": "pylsp"}], {"python": ["pylsp"]}
    if sid == "safety.constitution":
        return ([{"phrases": "launch codes, secret plan", "severity": "critical"}],
                [{"phrases": ["launch codes", "secret plan"], "severity": "critical"}])
    if setting.control == "rate":
        return {"count": 5, "seconds": 60}, "5/60"
    if sid == "tui.keys":
        return [{"name": "quit", "key": "x"}], {"quit": "x"}
    if sid == "director.profiles":
        return ([{"name": "supervised", "consent_mode": "dashboard", "budget_multiplier": 0.5,
                  "dollars": 5, "tool_calls": 50}],
                {"supervised": {"consent_mode": "dashboard", "budget_multiplier": 0.5,
                                "dollars": 5.0, "tool_calls": 50}})
    if sid == "env_hunt.enrichment_sources":
        return [{"name": "intel_feed", "enable": True}], {"intel_feed": {"enable": True}}
    if setting.control == "path":
        from pathlib import Path

        if setting.path_kind == "folder":
            folder = Path.home() / "places" / sid.replace(".", "-")
            folder.mkdir(parents=True, exist_ok=True)
            return str(folder), str(folder)
        found = Path.home() / (sid.replace(".", "-") + ".json")
        found.write_text("{}", encoding="utf-8")
        return str(found), str(found)
    raise AssertionError(f"no sample for {sid}")


def _bad(setting) -> object:
    """A value the catalog must refuse for this row."""
    control = setting.control
    if control == "toggle":
        return "yes"
    if control == "select":
        return "not-an-option"
    if control == "number":
        return setting.minimum - 1 if setting.minimum is not None else "lots"
    if control in {"text"}:
        return "<bad>"
    if control == "secret":
        return ""
    if control == "list":
        return ["<bad>"]
    if control == "multiselect":
        return ["nope"]
    if control == "table":
        return [{"name": "Not A Name!"}] if setting.row_kind == "named" else [{"name": "no-such-choice"}]
    if control == "rules":
        return [{"phrases": "", "severity": "high"}]
    if control == "rate":
        return {"count": 0, "seconds": 60}
    if control == "path":
        return "not/a/full/location.json"
    raise AssertionError(setting.id)


def _stored(tree, setting):
    present, value = catalog.lookup(tree, setting.path)
    assert present, setting.id
    return value


def test_every_runtime_row_is_in_the_catalog():
    ids = {s.id for s in ROWS}
    assert ids <= set(catalog.BY_ID)
    assert len(ids) == len(ROWS)
    assert all(s.group in catalog.GROUPS for s in ROWS)


# Saving a quorum turns on approvals for safety settings, the quorum itself
# included, so its reset is held for approval; voice unlock can't be turned on
# without its add-on. Both are tested on their own (test_settings_runtime_safety,
# test_settings_voice_unlock).
_GENERIC = [s for s in ROWS if s.id not in {"safety.quorum_required", "voice.biometric_unlock"}
            and s.id not in _REFUSED]


@pytest.mark.parametrize("setting", _GENERIC, ids=lambda s: s.id)
def test_row_saves_reads_back_and_resets(setting, audit_rows):
    sent, stored = _sample(setting)
    r = _save([{"id": setting.id, "value": sent}])
    if r.status_code == 409:
        assert catalog.weakens(setting, setting.default, stored) or setting.warning
        assert r.json()["confirm"][0]["id"] == setting.id
        r = _save([{"id": setting.id, "value": sent}], confirm=True)
    assert r.status_code == 200, r.text
    assert _stored(_loaded(), setting) == stored
    row = _row(setting.id)
    assert row["source"] == "here"
    if setting.secret:
        assert row["value"] is None and row["is_set"] is True
        assert stored not in r.text and stored not in client.get(API).text
        assert stored not in client.get("/settings/all", params={"id": setting.id}).text
        text = __import__("maverick.config", fromlist=["x"]).dashboard_overrides_path() \
            .read_text(encoding="utf-8")
        assert stored not in text and "MVKAR1:" in text
    kinds = [a["kind"] for a in audit_rows]
    assert kinds == ["setting_changed"]
    assert (audit_rows[0]["section"], audit_rows[0]["key"]) == (setting.section, setting.key)
    if setting.secret:
        assert audit_rows[0]["new"] == "set" and stored not in repr(audit_rows)
    r = _save([{"id": setting.id, "reset": True}], confirm=True)
    assert r.status_code == 200, r.text
    row = _row(setting.id)
    if row["source"] == "here":
        from maverick.config_resets import is_reset
        here = page._sources()["here"]
        if page._has_partial_default(setting):
            # Removing the value could let an older or legacy choice apply again,
            # so reset writes the product default itself and nothing else.
            assert catalog.lookup(here, setting.path) == (True, page._default_of(setting))
            assert row["value"] == page._default_of(setting)
        else:
            assert is_reset(here, setting), "Only the explicit product-default mask may remain after reset"
    else:
        assert row["source"] == "default"


@pytest.mark.parametrize("setting", ROWS, ids=lambda s: s.id)
def test_row_refuses_wrong_values(setting, audit_rows):
    r = _save([{"id": setting.id, "value": _bad(setting)}], confirm=True)
    assert r.status_code == 400, r.text
    assert r.json()["message"]
    assert audit_rows == []
    present, _ = catalog.lookup(_loaded(), setting.path)
    assert not present


_LOOSENING = [s for s in _GENERIC if s.warning]


@pytest.mark.parametrize("setting", _LOOSENING, ids=lambda s: s.id)
def test_loosening_needs_confirmation(setting, audit_rows):
    sent, _stored_value = _sample(setting)
    setup = None
    if setting.weaker == "shrink" and setting.default:
        sent = list(setting.default)[:1]  # fewer than the default list
    elif setting.weaker == "shrink":
        setup, sent = sent, []
    elif setting.control == "toggle":
        setup = (not setting.weaker) if setting.default is setting.weaker else None
        sent = setting.weaker
    elif setting.control == "select" and setting.order:
        setup = setting.order[0] if setting.default == setting.order[-1] else None
        sent = setting.order[-1]
    elif setting.control == "rate":
        setup, sent = {"count": 5, "seconds": 60}, None
    elif setting.weaker == "higher":
        setup, sent = setting.minimum, setting.maximum
    elif setting.weaker == "lower":
        setup, sent = setting.maximum, setting.minimum
    if setup is not None:
        assert _save([{"id": setting.id, "value": setup}], confirm=True).status_code == 200
    r = _save([{"id": setting.id, "value": sent}])
    assert r.status_code == 409, r.text
    assert r.json()["confirm"][0]["warning"] == setting.warning
    r = _save([{"id": setting.id, "value": sent}], confirm=True)
    assert r.status_code == 200, r.text
    assert audit_rows[-1]["confirmed"] is True


def test_environment_value_locks_the_row(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    row = _row("safety.consent_mode")
    assert row["locked"] is True and row["source"] == "deployment"
    r = _save([{"id": "safety.consent_mode", "value": "auto-approve"}], confirm=True)
    assert r.status_code == 409
    assert "safety" not in _loaded()


# ------------------------------------------------------------ fixed readers
def test_consent_mode_saved_here_gates_actions(monkeypatch, audit_rows):
    from maverick.safety import consent

    assert _save([{"id": "safety.consent_mode", "value": "auto-deny"}]).status_code == 200
    assert consent._resolve_mode("low") == "auto-deny"
    assert consent._resolve_mode("critical") == "auto-deny"
    r = _save([{"id": "safety.consent_mode", "value": "auto-approve"}], confirm=True)
    assert r.status_code == 200
    assert consent._resolve_mode("critical") == "auto-approve"
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    assert consent._resolve_mode("low") == "dashboard"  # the environment still wins


def test_autonomy_changes_are_logged_and_apply_to_the_next_decision(audit_rows):
    """A change to how agents may act is written to the activity record,
    with its before and after values, and the very next decision uses it: no
    restart and no wait."""
    from maverick.audit import EventKind
    from maverick.safety import consent

    assert _save([{"id": "safety.consent_mode", "value": "auto-deny"}]).status_code == 200
    logged = [row for row in audit_rows if row.get("key") == "consent_mode"]
    assert logged and logged[-1]["kind"] == EventKind.SETTING_CHANGED
    assert logged[-1]["section"] == "safety" and logged[-1]["new"] == "auto-deny"
    assert consent.require_consent("send_payment", risk="high", consult_ledger=False).granted is False
    r = _save([{"id": "safety.consent_mode", "value": "auto-approve"}], confirm=True)
    assert r.status_code == 200
    assert [row["new"] for row in audit_rows if row.get("key") == "consent_mode"][-1] == "auto-approve"
    assert consent.require_consent("send_payment", risk="high", consult_ledger=False).granted is True


def test_unknown_consent_mode_in_config_fails_closed(tmp_path):
    from maverick import config
    from maverick.safety import consent

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text('[safety]\nconsent_mode = "maybe"\n', encoding="utf-8")
    config.reset_config_cache()
    assert consent._resolve_mode("low") == "ask"


def test_blocked_phrases_reach_the_safety_checks(audit_rows):
    from maverick import config
    from maverick_shield.constitutional import parse_rules, scan

    row = {"phrases": "launch codes, Secret (plan)", "severity": "critical"}
    r = _save([{"id": "safety.constitution", "value": [row]}], confirm=True)
    assert r.status_code == 200, r.text
    rules = parse_rules(config.get_safety()["constitution"])
    assert len(rules) == 1 and rules[0].name == "launch codes, Secret (plan)"
    assert scan("share the LAUNCH CODES now", rules) == (True, "critical", [rules[0].name])
    # Phrases are matched as written, never as patterns.
    assert scan("secret plan", rules)[0] is False
    assert scan("the secret (plan) is", rules)[0] is True


def test_model_reading_limit_saved_with_the_service_name_applies():
    from maverick import preflight

    model = next(m for m in _live("models") if ":" in m)
    bare = model.split(":", 1)[1]
    r = _save([{"id": "context.model_windows", "value": [{"name": model, "window": 12345}]}])
    assert r.status_code == 200, r.text
    assert preflight.context_limit(bare) == 12345


def test_gateway_credentials_saved_here_are_used_and_env_wins(monkeypatch, audit_rows):
    from maverick import llm_gateway

    r = _save([{"id": "llm_gateway.upstream_url", "value": "https://api.example.com"},
               {"id": "llm_gateway.enable", "value": True},
               {"id": "llm_gateway.gateway_token", "value": "caller-pass-123"},
               {"id": "llm_gateway.upstream_token", "value": "upstream-key-456"}],
              confirm=True)
    assert r.status_code == 200, r.text
    assert llm_gateway.verify_gateway_bearer("caller-pass-123") is True
    assert llm_gateway.verify_gateway_bearer("wrong") is False
    settings = llm_gateway.get_llm_gateway_config()
    assert "caller-pass-123" not in repr(settings) and "upstream-key-456" not in repr(settings)
    _url, headers = llm_gateway._provider_upstream("openai", settings)
    assert headers["Authorization"] == "Bearer upstream-key-456"
    monkeypatch.setenv("MAVERICK_GATEWAY_TOKEN", "from-the-server")
    assert llm_gateway.verify_gateway_bearer("from-the-server") is True
    assert llm_gateway.verify_gateway_bearer("caller-pass-123") is False


def test_azure_and_bedrock_details_saved_here_reach_the_client(monkeypatch, audit_rows):
    from maverick import config
    from maverick.llm import LLM

    r = _save([{"id": "providers.azure.base_url", "value": "https://acme.openai.azure.com"},
               {"id": "providers.azure.api_key", "value": "azure-key-1"},
               {"id": "providers.azure.deployment", "value": "gpt-deploy"},
               {"id": "providers.bedrock.region", "value": "eu-west-1"},
               {"id": "providers.bedrock.endpoint", "value": "legacy"}], confirm=True)
    assert r.status_code == 200, r.text
    assert "deployment" not in config.azure_provider_configuration_missing(
        config.get_provider_config("azure"))
    env = dict(LLM()._provider_client_config("azure").provider_environment)
    assert env["AZURE_OPENAI_DEPLOYMENT"] == "gpt-deploy"
    env = dict(LLM()._provider_client_config("bedrock").provider_environment)
    assert env["AWS_REGION"] == "eu-west-1" and env["BEDROCK_ENDPOINT"] == "legacy"
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "from-env")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    assert dict(LLM()._provider_client_config("azure").provider_environment)[
        "AZURE_OPENAI_DEPLOYMENT"] == "from-env"
    assert dict(LLM()._provider_client_config("bedrock").provider_environment)[
        "AWS_REGION"] == "us-west-2"


def test_provider_switches_and_keys_share_the_settings_file(audit_rows):
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store.set_provider("anthropic", api_key="sk-ant-keep")  # pragma: allowlist secret
    r = _save([{"id": "providers.per_tenant_keys", "value": True},
               {"id": "providers.bedrock.endpoint", "value": "legacy"}], confirm=True)
    assert r.status_code == 200, r.text
    assert config.providers_per_tenant_keys() is True
    assert config.get_provider_config("anthropic")["api_key"] == "sk-ant-keep"  # pragma: allowlist secret
    assert config.get_provider_config("bedrock")["endpoint"] == "legacy"
    assert config.config_source_errors() == {}


def test_deferred_connectors_switch_reaches_the_agent(audit_rows):
    from maverick import config

    assert config.get_capabilities()["deferred_tools"] is True
    assert _save([{"id": "capabilities.deferred_tools", "value": False}]).status_code == 200
    assert config.get_capabilities()["deferred_tools"] is False


def test_unreadable_deferred_tools_environment_does_not_lock_the_switch(monkeypatch, audit_rows):
    """The kernel ignores a MAVERICK_DEFERRED_TOOLS value it cannot read, so
    the page must not present that value as a deployment lock."""
    from maverick import config

    monkeypatch.setenv("MAVERICK_DEFERRED_TOOLS", "sometimes")
    row = _row("capabilities.deferred_tools")
    assert row["locked"] is False and row["value"] is True, row
    assert _save([{"id": "capabilities.deferred_tools", "value": False}]).status_code == 200
    assert config.get_capabilities()["deferred_tools"] is False
    assert _row("capabilities.deferred_tools")["value"] is False
    # A value the kernel honours still locks the switch to that value.
    monkeypatch.setenv("MAVERICK_DEFERRED_TOOLS", "on")
    row = _row("capabilities.deferred_tools")
    assert row["locked"] is True and row["value"] is True, row
    assert config.get_capabilities()["deferred_tools"] is True


def test_plugin_settings_survive_other_plugin_writes(audit_rows):
    from maverick import plugins
    from maverick_dashboard import settings_store

    settings_store.set_plugin_install_allowed(True)
    settings_store.set_installable_plugins(["weather-plugin"])
    key = "cd" * 32
    r = _save([{"id": "plugins.ca_root_pubkey", "value": key},
               {"id": "plugins.ca_revoked", "value": ["0123456789abcdef"]},
               {"id": "plugins.isolation", "value": "subprocess"}], confirm=True)
    assert r.status_code == 200, r.text
    settings_store.set_plugin_install_allowed(False)
    loaded = _loaded()["plugins"]
    assert loaded["allow_install"] is False and loaded["installable"] == ["weather-plugin"]
    assert loaded["isolation"] == "subprocess"
    root, required, revoked = plugins._plugin_signing_policy()
    assert root == key and required is True and "0123456789abcdef" in revoked
    from maverick.plugin_isolation import isolation_mode

    assert isolation_mode() == "subprocess"


def test_sandbox_details_survive_the_work_area_type_selector(audit_rows):
    from maverick_dashboard import settings_store

    r = _save([{"id": "sandbox.api_key", "value": "e2b-key-1"},
               {"id": "sandbox.provider", "value": "e2b"}], confirm=True)
    assert r.status_code == 200, r.text
    settings_store.set_sandbox_backend("docker")
    loaded = _loaded()["sandbox"]
    expected = {"backend": "docker", "api_key": "e2b-key-1",  # pragma: allowlist secret
                "provider": "e2b"}
    assert loaded == expected
    stored = __import__("maverick.config", fromlist=["x"]).dashboard_overrides_path() \
        .read_text(encoding="utf-8")
    assert "e2b-key-1" not in stored


def _proxy_readback_command():
    args = [sys.executable, "-c", "import os; print(os.environ.get('HTTPS_PROXY') or 'none')"]
    return subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)


def test_locked_down_mode_applies_at_every_seam(tmp_path, audit_rows):
    from maverick.budget import resolve_budget_caps
    from maverick.sandbox import LocalBackend, build_sandbox
    from maverick.tools import base_registry
    from maverick.world_model import open_world

    r = _save([{"id": "containment.enabled", "value": True},
               {"id": "containment.max_wall_seconds", "value": 10},
               {"id": "containment.deny_tools", "value": ["read_file"]},
               {"id": "sandbox.workdir", "value": str(tmp_path / "work")}], confirm=True)
    assert r.status_code == 200, r.text
    # Tools that send data out, and the extra ones listed, are removed.
    world = open_world(None)
    reg = base_registry(world, LocalBackend(workdir=tmp_path))
    assert not reg._acl_allows("http_fetch") and not reg._acl_allows("read_file")
    assert "read_file" not in {t.name for t in reg.exposed()}
    assert reg._acl_allows("shell")
    # Every task is capped at the locked-down time limit.
    assert resolve_budget_caps(max_wall_seconds=7200)["max_wall_seconds"] == 600
    assert resolve_budget_caps(max_wall_seconds=60)["max_wall_seconds"] == 60
    # Commands run in a throwaway folder with the proxies pointed at a dead end.
    box = build_sandbox()
    folder = box.workdir
    assert folder != tmp_path / "work" and folder.is_dir()
    result = box.exec(_proxy_readback_command())
    assert result.stdout.strip() == "http://127.0.0.1:9"
    del box
    import gc

    gc.collect()
    assert not folder.exists()


def test_locked_down_mode_turns_container_internet_off():
    from maverick.containment import ContainmentProfile
    from maverick.sandbox import _contain

    held: list = []
    cfg, wd = _contain(ContainmentProfile(ephemeral_workspace=False), "docker",
                       {"allow_network": True}, __import__("pathlib").Path("/w"), held)
    assert cfg["allow_network"] is False and cfg["network"] == "egress-deny"
    assert wd == __import__("pathlib").Path("/w") and held == []
    cfg, wd = _contain(None, "docker", {"allow_network": True},
                       __import__("pathlib").Path("/w"), held)
    assert cfg == {"allow_network": True}


def test_locked_down_mode_off_changes_nothing(tmp_path):
    from maverick.budget import resolve_budget_caps
    from maverick.sandbox import build_sandbox

    assert resolve_budget_caps(max_wall_seconds=7200)["max_wall_seconds"] == 7200
    from maverick.sandbox.local import scrub_env

    box = build_sandbox(workdir=tmp_path)
    assert box.workdir == tmp_path
    expected = scrub_env().get("HTTPS_PROXY") or "none"
    assert box.exec(_proxy_readback_command()).stdout.strip() == expected


def test_request_fit_check_follows_the_setting(monkeypatch, audit_rows):
    from maverick import llm
    from maverick.preflight import PreflightFailed

    huge = [{"role": "user", "content": "word " * 400_000}]
    llm._run_preflight("claude-haiku-4-5", "", huge, None, 1000)  # default: warn only
    assert _save([{"id": "context.preflight", "value": "strict"}]).status_code == 200
    with pytest.raises(PreflightFailed):
        llm._run_preflight("claude-haiku-4-5", "", huge, None, 1000)
    monkeypatch.setenv("MAVERICK_PREFLIGHT", "off")  # the environment still wins
    llm._run_preflight("claude-haiku-4-5", "", huge, None, 1000)
    monkeypatch.delenv("MAVERICK_PREFLIGHT")
    r = _save([{"id": "context.preflight", "value": "off"}])
    assert r.status_code == 409
    assert _save([{"id": "context.preflight", "value": "off"}], confirm=True).status_code == 200
    llm._run_preflight("claude-haiku-4-5", "", huge, None, 1000)


# (row, value saved, reader call, what the reader returns then, the
# environment variable and a value that must win over the saved one)
def _switch_cases():
    from maverick import budget_receipts, llm, net_concurrency, observability, tool_token
    from maverick.orchestrator import _bon_early_exit
    from maverick.providers import anthropic_provider as ap
    from maverick.skill import stats
    from maverick.skills import url_install_allowed
    from maverick.tools import computer, database_tool, http_fetch, safe_media_args
    from maverick_channels.base import _max_inbound_chars
    from maverick_knowledge.parse import _int_env
    from maverick_shield import builtin_rules, guard

    return [
        ("search.early_exit", False, _bon_early_exit, False, "MAVERICK_BON_EARLY_EXIT", "1", True),
        ("skills.decay", False, stats._enabled, False, "MAVERICK_SKILL_DECAY", "1", True),
        ("skills.allow_url_install", True, url_install_allowed, True,
         "MAVERICK_ALLOW_SKILL_INSTALL", "0", False),
        ("tools.fetch_allow_private", True, lambda: http_fetch.is_blocked_host("10.0.0.7"),
         False, "MAVERICK_FETCH_ALLOW_PRIVATE", "0", True),
        ("tools.raw_media_args", True, lambda: safe_media_args(["-i", "/etc/passwd"]),
         ["-i", "/etc/passwd"], "MAVERICK_ALLOW_RAW_MEDIA_ARGS", "0", None),
        ("tools.database_max_rows", 25, database_tool._max_rows, 25,
         "MAVERICK_DATABASE_MAX_ROWS", "7", 7),
        ("tools.net_host_concurrency", 9, net_concurrency._cap, 9,
         "MAVERICK_NET_HOST_CONCURRENCY", "2", 2),
        ("budget.receipts", True, budget_receipts.enabled, True, "MAVERICK_BUDGET_RECEIPTS", "0", False),
        ("capabilities.per_call_token_ttl", 90, tool_token._ttl_seconds, 90.0,
         "MAVERICK_TOOL_TOKEN_TTL", "12", 12.0),
        ("cache.anthropic_ttl", "5m", ap._default_cache_ttl, "5m", "MAVERICK_ANTHROPIC_CACHE_TTL", "1h", "1h"),
        ("cache.anthropic_message_ttl", "1h", ap._msg_cache_ttl, "1h",
         "MAVERICK_ANTHROPIC_MSG_CACHE_TTL", "5m", "5m"),
        ("thinking.adaptive_floor", 4096, ap._adaptive_max_tokens_floor, 4096,
         "MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR", "16384", 16384),
        ("latency.read_timeout", 45, lambda: llm._configured_timeouts({}),
         {"MAVERICK_LLM_READ_TIMEOUT": "45.0"}, None, None, None),
        ("observability.otel_exporter", "otlp", observability._otel_enabled, True,
         "MAVERICK_OTEL_EXPORTER", "otlp", True),
        ("observability.otel_headers", "x-team=abc", observability._otlp_headers,
         {"x-team": "abc"}, "MAVERICK_OTEL_HEADERS", "x-env=1", {"x-env": "1"}),
        ("observability.otlp_metrics", True, observability._otlp_metrics_enabled, True,
         "MAVERICK_OTEL_METRICS", "1", True),
        ("observability.prometheus_port", 9109, observability._prometheus_enabled, True,
         None, None, None),
        ("computer_use.ocr", True, computer._ocr_enabled, True, "MAVERICK_COMPUTER_OCR", "0", False),
        ("computer_use.require_sandbox", True, computer._host_guard_required, True, None, None, None),
        ("chat.max_inbound_chars", 5000, _max_inbound_chars, 5000,
         "MAVERICK_MAX_INBOUND_CHARS", "2000", 2000),
        ("knowledge.max_pdf_pages", 12, lambda: _int_env("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", 5000),
         12, "MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", "3", 3),
        ("safety.max_scan_chars", 5000, builtin_rules._max_scan_chars, 5000,
         "MAVERICK_SHIELD_MAX_SCAN_CHARS", "7000", 7000),
        ("safety.decode_hidden", False, guard._decode_disabled, True,
         "MAVERICK_SHIELD_NO_DECODE", "0", False),
    ]


def test_ineffective_answer_reuse_switch_is_not_offered_on_the_page():
    # The standalone answer cache is not wired into customer work, so its
    # switch was removed rather than presented as a working feature.
    assert "cache.llm_responses" not in catalog.BY_ID


def test_former_environment_switches_take_effect_from_the_page(monkeypatch, audit_rows):
    for setting_id, value, read, expected, env_name, env_value, env_expected in _switch_cases():
        if env_name:
            monkeypatch.delenv(env_name, raising=False)
        setting = catalog.BY_ID[setting_id]
        sent = value / setting.scale if isinstance(value, (int, float)) \
            and not isinstance(value, bool) else value
        r = _save([{"id": setting_id, "value": sent}], confirm=True)
        assert r.status_code == 200, (setting_id, r.text)
        assert read() == expected, setting_id
        if env_name:
            monkeypatch.setenv(env_name, env_value)
            if env_expected is not None:
                assert read() == env_expected, setting_id
            monkeypatch.delenv(env_name)


def test_unset_switches_keep_todays_behaviour():
    from maverick import budget_receipts, observability, tool_token
    from maverick.cache import llm as llm_cache
    from maverick.orchestrator import _bon_early_exit
    from maverick.providers import anthropic_provider as ap
    from maverick.skills import url_install_allowed
    from maverick.tools import database_tool, http_fetch
    from maverick_shield import guard

    assert _bon_early_exit() is True
    assert llm_cache._enabled_via_env() is False
    assert url_install_allowed() is False
    assert http_fetch.is_blocked_host("10.0.0.7") is True
    assert database_tool._max_rows() == 1000
    assert budget_receipts.enabled() is False
    assert observability._otlp_metrics_enabled() is False
    assert tool_token._ttl_seconds() == 30.0
    assert ap._adaptive_max_tokens_floor() == 8192
    assert guard._decode_disabled() is False


def test_env_or_config_prefers_the_environment(monkeypatch):
    from maverick.env_setting import env_or_config, env_or_config_float, env_or_config_int

    assert env_or_config("MAVERICK_MAX_STEPS", "agent", "max_steps") is None
    assert _save([{"id": "agent.max_steps", "value": 40}], confirm=True).status_code == 200
    assert env_or_config("MAVERICK_MAX_STEPS", "agent", "max_steps") == "40"
    assert env_or_config_int("MAVERICK_MAX_STEPS", "agent", "max_steps", 1) == 40
    monkeypatch.setenv("MAVERICK_MAX_STEPS", "7")
    assert env_or_config_int("MAVERICK_MAX_STEPS", "agent", "max_steps", 1) == 7
    monkeypatch.setenv("MAVERICK_MAX_STEPS", "  ")  # blank counts as unset
    assert env_or_config_float("MAVERICK_MAX_STEPS", "agent", "max_steps", 1.0) == 40.0
    assert _save([{"id": "agent.parallel_tools", "value": False}]).status_code == 200
    assert env_or_config("MAVERICK_PARALLEL_TOOLS", "agent", "parallel_tools", "1") == "0"


def test_preferred_name_is_personal_and_never_reaches_other_agent_prompts(audit_rows):
    from maverick import config
    from maverick import experience_preferences as prefs
    from maverick.persona import render_persona_prompt

    assert render_persona_prompt() == ""
    assert "persona.user_name" not in catalog.BY_ID
    assert _save([{"id": "persona.user_name", "value": "Chris"}]).status_code == 400
    # Existing installation names are not allowed to impersonate every user.
    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text('[persona]\nuser_name = "Legacy person"\n', encoding="utf-8")
    config.reset_config_cache()
    assert render_persona_prompt() == ""
    prefs.save("user:chris", scope="personal", changes={"preferred_name": "Chris"},
               expected_revision=prefs.state("user:chris")["revision"])
    assert '"preferred_name": "Chris"' in prefs.prompt("user:chris")
    assert "Chris" not in prefs.prompt("user:someone-else")
    assert prefs.prompt("service:scheduled") == prefs.prompt("") == ""
    assert render_persona_prompt() == ""


def test_installer_placeholder_name_changes_nothing():
    from maverick import config
    from maverick.persona import render_persona_prompt

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text('[persona]\nuser_name = "you"\n', encoding="utf-8")
    config.reset_config_cache()
    assert render_persona_prompt() == ""


def test_shared_tool_results_use_the_redis_store_with_the_same_scope(monkeypatch, audit_rows):
    from maverick.cache import redis_tool
    from maverick.cache import tool as tool_cache

    kept: dict = {}

    class FakeRedis:
        def get(self, key):
            return kept.get(key)

        def set(self, key, value, *, nx=False):
            if not nx or key not in kept:
                kept[key] = value

        def setex(self, key, ttl, value):
            kept[key] = value

    monkeypatch.setattr(redis_tool.RedisToolCache, "_client", lambda self: FakeRedis())
    r = _save([{"id": "tools.output_cache", "value": True},
               {"id": "tools.output_cache_backend", "value": "redis"},
               {"id": "tools.output_cache_redis_url", "value": "redis://cache.internal:6379/0"}],
              confirm=True)
    assert r.status_code == 200, r.text

    class Tool:
        name = "repo_map"
        cacheable = True

    monkeypatch.setattr(tool_cache, "cacheable", lambda tool: True)
    tool_cache.reset()
    tool_cache.store_cached(Tool(), {"path": "."}, "tree", namespace="user:a")
    assert len(kept) == 2  # one scoped result and the shared generation
    assert "mvk:toolcache:generation" in kept
    tool_cache.reset()  # another server: nothing kept locally
    assert tool_cache.get_cached(Tool(), {"path": "."}, namespace="user:a") == (True, "tree")
    assert tool_cache.get_cached(Tool(), {"path": "."}, namespace="user:b") == (False, None)


def test_software_pins_are_recorded_then_checked(tmp_path, audit_rows):
    from maverick import supply_chain

    pins = tmp_path / "pins.json"
    assert supply_chain.startup_check(pins) is None and not pins.exists()
    r = _save([{"id": "safety.supply_chain_pinning", "value": True}])
    assert r.status_code == 200, r.text
    assert supply_chain.startup_check(pins) is None and pins.exists()
    report = supply_chain.startup_check(pins)
    assert report is not None and report.ok
