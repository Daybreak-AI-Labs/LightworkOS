"""Wizard answers survive publication and the runtime's own readers."""
from __future__ import annotations

import io
import json
import os

import pytest
from maverick import config
from maverick_installer import wizard
from rich.console import Console


def _paths(monkeypatch, tmp_path):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", tmp_path / "wizard-partial.json")
    monkeypatch.setattr(wizard, "console", Console(file=io.StringIO(), width=160))
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    monkeypatch.setattr(wizard, "smoke_test", lambda: True)
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)


def _write(monkeypatch, tmp_path, **overrides):
    _paths(monkeypatch, tmp_path)
    values = dict(providers=[], role_models={}, channels={}, safety={}, budget={},
                  sandbox={"backend": "local", "workdir": str(tmp_path / "work")}, keys={})
    values.update(overrides)
    wizard.write_config(**values)
    return config.load_config(wizard.CONFIG_FILE)


def _advanced(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(wizard, "pick_mode", lambda: "advanced")
    monkeypatch.setattr(wizard, "pick_deployment", lambda: "desktop")
    monkeypatch.setattr(wizard, "pick_providers", lambda: ["anthropic"])
    monkeypatch.setattr(wizard, "pick_models_per_role", lambda *args: {})
    monkeypatch.setattr(wizard, "pick_channels", lambda *args: ({}, set()))
    monkeypatch.setattr(wizard, "pick_sandbox", lambda: {
        "backend": "local", "workdir": str(tmp_path / "work")})
    for name in ("pick_advanced", "pick_security_suite", "pick_assessments", "pick_connectors", "pick_suites"):
        monkeypatch.setattr(wizard, name, dict)
    monkeypatch.setattr(wizard, "pick_monitoring", lambda: ({}, {}))
    monkeypatch.setattr(wizard, "collect_api_keys", lambda *args: {})
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: prompt.startswith("Write config"))
    monkeypatch.setattr(wizard, "_q_text", lambda prompt, **kw: kw.get("default", ""))
    monkeypatch.setattr(wizard, "_q_select", lambda prompt, choices, **kw: kw.get("default") or choices[0])


@pytest.mark.parametrize("custom_limits", [False, True])
def test_file_permissions_survive_with_or_without_custom_limits(monkeypatch, tmp_path, custom_limits):
    values = {"permission_filter": "by_email"}
    if custom_limits:
        values.update({key: default for key, _, default, _, _ in wizard._KNOWLEDGE_SOURCE_LIMITS})
    parsed = _write(monkeypatch, tmp_path, knowledge_sources=values)
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    assert config.get_knowledge_sources()["permission_filter"] == "by_email"
    assert config.get_knowledge_sources()["max_items"] == 64


def test_advanced_declined_learning_stays_disabled(monkeypatch, tmp_path):
    _advanced(monkeypatch, tmp_path)
    assert wizard.run() == 0
    assert config.get_self_learning(config=config.load_config(wizard.CONFIG_FILE))["enable"] is False


def test_fast_setup_writes_the_advertised_task_limits(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "wizard-test-value")
    assert wizard.run_fast() == 0
    parsed = config.load_config(wizard.CONFIG_FILE)
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    limits = config.get_budget_overrides()
    assert limits["max_dollars"] == 2.0
    assert limits["max_wall_seconds"] == 1800.0
    assert "$2" in wizard.console.file.getvalue() and "30 minutes" in wizard.console.file.getvalue()


def test_finance_amounts_accept_currency_and_separators_and_reask_junk(monkeypatch, tmp_path):
    answers = iter(["nonsense", "$50000", "NaN", "-1", "50,000", ""])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: prompt.startswith("Enable the finance suite"))
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    parsed = _write(monkeypatch, tmp_path, finance=wizard.pick_finance())
    assert parsed["governance"]["require_human_above"] == {"*": 50000.0}
    assert parsed["governance"]["deny_above"] == {"*": 50000.0}
    assert next(answers, None) is None


@pytest.mark.parametrize("value", ["first\nWIZARD_INJECTED=yes", "first\rWIZARD_INJECTED=yes"])
def test_env_writer_reasks_multiline_values_before_publishing(monkeypatch, tmp_path, value):
    monkeypatch.setenv("WIZARD_INJECTED", "")
    monkeypatch.delenv("WIZARD_INJECTED")
    monkeypatch.setenv("WIZARD_TEST_KEY", "")
    monkeypatch.delenv("WIZARD_TEST_KEY")
    answers = iter(["still\ninvalid", "replacement"])
    monkeypatch.setattr(wizard, "_q_secret", lambda *a, **kw: next(answers))
    _write(monkeypatch, tmp_path, keys={"WIZARD_TEST_KEY": value})
    config._load_env_file(wizard.ENV_FILE)
    assert os.environ["WIZARD_TEST_KEY"] == "replacement"
    assert "WIZARD_INJECTED" not in os.environ
    assert next(answers, None) is None


def test_typescript_commands_remain_argv_arrays(monkeypatch, tmp_path):
    from maverick.ts_plugin_host import _entry_command

    commands = [["node", 'C:\\my plugins\\"runner".js', "--quiet"], ["deno", "run", "plugin.ts"]]
    parsed = _write(monkeypatch, tmp_path, ts_plugins=commands)
    assert parsed["plugins"]["ts"] == commands
    assert [_entry_command(entry) for entry in parsed["plugins"]["ts"]] == commands


def test_web_search_backend_survives_resume_and_a_fresh_process(monkeypatch, tmp_path):
    _advanced(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_SEARCH_BACKEND", "")
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND")
    monkeypatch.setenv("BRAVE_API_KEY", "wizard-test-value")  # pragma: allowlist secret
    confirm = wizard._q_confirm
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: (
        True if prompt.startswith("Enable web search") else False if prompt.startswith("Write config")
        else confirm(prompt, **kw)))
    select = wizard._q_select
    monkeypatch.setattr(wizard, "_q_select", lambda prompt, choices, **kw: (
        "brave - search" if "Default backend" in prompt else select(prompt, choices, **kw)))
    assert wizard.run() == 0
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    assert wizard.run(resume=True) == 0
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    config._load_env_file(wizard.ENV_FILE)
    assert os.environ.get("MAVERICK_SEARCH_BACKEND") == "brave"
    assert config.load_config(wizard.CONFIG_FILE)["capabilities"]["web_search"] is True


def test_advanced_write_failure_reports_and_clears_bad_resume_state(monkeypatch, tmp_path):
    _advanced(monkeypatch, tmp_path)
    def fail(*args, **kwargs):
        raise ValueError("invalid saved answer")
    monkeypatch.setattr(wizard, "write_config", fail)
    assert wizard.run() == 1
    assert not wizard.PARTIAL_STATE_PATH.exists()
    assert "invalid saved answer" in wizard.console.file.getvalue()


def test_temporary_write_failure_keeps_the_resume_answers(monkeypatch, tmp_path):
    _advanced(monkeypatch, tmp_path)
    def fail(*args, **kwargs):
        raise OSError("No space left on device")
    monkeypatch.setattr(wizard, "write_config", fail)
    assert wizard.run() == 1
    assert json.loads(wizard.PARTIAL_STATE_PATH.read_text())["providers"] == ["anthropic"]
    assert "maverick init --resume" in wizard.console.file.getvalue()


def test_existing_secret_prompts_never_show_any_prefix(monkeypatch):
    from maverick.tools import enterprise_connectors

    secret = "sensitive-existing-value"  # pragma: allowlist secret
    monkeypatch.setenv("WIZARD_TEST_SECRET", secret)
    prompts = []
    monkeypatch.setattr(wizard, "_q_secret", lambda prompt: prompts.append(prompt) or "")
    assert wizard._ask_credential("WIZARD_TEST_SECRET", "Credential") == secret
    assert wizard.collect_api_keys([], {"WIZARD_TEST_SECRET"}) == {"WIZARD_TEST_SECRET": secret}
    monkeypatch.setattr(enterprise_connectors, "connector_catalog", lambda: [
        {"name": "example", "label": "Example", "env": [("WIZARD_TEST_SECRET", True)]}])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: "example")
    assert wizard.pick_connectors() == {"WIZARD_TEST_SECRET": secret}
    assert len(prompts) == 3
    assert all(secret[:4] not in prompt and "set" in prompt for prompt in prompts)


@pytest.mark.parametrize("mode", ["run_consumer", "run_express"])
@pytest.mark.parametrize("key", [False, True])
def test_completion_names_are_literal_markup(monkeypatch, tmp_path, mode, key):
    _paths(monkeypatch, tmp_path)
    answers = iter(["[/bold]", str(tmp_path / "work")])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    monkeypatch.setattr(wizard, "pick_governance_profile", lambda: wizard.DEFAULT_GOVERNANCE_PROFILE)
    monkeypatch.setattr(wizard, "_consumer_api_key", lambda: {"WIZARD_TEST_KEY": "value"} if key else {})
    monkeypatch.setattr(wizard, "_consumer_budget", lambda: {"max_dollars": 2.0})
    monkeypatch.setattr(wizard, "pick_first_outcome", lambda: "finance")
    assert getattr(wizard, mode)() == 0
    assert config.load_config(wizard.CONFIG_FILE)["persona"]["user_name"] == "[/bold]"
    assert "[/bold]" in wizard.console.file.getvalue()


def test_partial_state_excludes_connection_secrets_and_scrubs_legacy_files(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    state = {"deployment": "desktop", "knowledge": {"enable": True, "store": "pgvector", "dsn": "postgres://user:private@db/name"},  # pragma: allowlist secret
             "_notifications_pair": [{"backend": "ntfy", "ntfy_topic": "private-topic"}, []]}  # pragma: allowlist secret
    wizard._save_partial(state)
    assert json.loads(wizard.PARTIAL_STATE_PATH.read_text()) == {"deployment": "desktop"}
    assert "dsn" in state["knowledge"]  # current-run answers remain available to publish
    wizard.PARTIAL_STATE_PATH.write_text(json.dumps(state))
    assert wizard._load_partial() == {"deployment": "desktop"}
    assert json.loads(wizard.PARTIAL_STATE_PATH.read_text()) == {"deployment": "desktop"}
    parsed = _write(monkeypatch, tmp_path, knowledge=state["knowledge"], notifications=state["_notifications_pair"][0])
    assert parsed["knowledge"]["dsn"] == state["knowledge"]["dsn"]
    assert parsed["notifications"]["ntfy_topic"] == state["_notifications_pair"][0]["ntfy_topic"]


def test_keyed_search_backend_without_its_key_is_not_forced(monkeypatch, tmp_path):
    # A forced backend never falls back, so a keyless tavily answer would break search.
    _advanced(monkeypatch, tmp_path)
    for name in ("MAVERICK_SEARCH_BACKEND", "TAVILY_API_KEY"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    confirm = wizard._q_confirm
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: (
        True if prompt.startswith("Enable web search") else confirm(prompt, **kw)))
    assert wizard.run() == 0
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    config._load_env_file(wizard.ENV_FILE)
    assert "MAVERICK_SEARCH_BACKEND" not in os.environ
    assert config.load_config(wizard.CONFIG_FILE)["capabilities"]["web_search"] is True


def test_blank_or_padded_secret_answers_keep_or_trim_the_value(monkeypatch):
    import getpass

    q_secret = wizard._q_secret
    monkeypatch.setenv("WIZARD_TEST_SECRET", "existing-value")
    monkeypatch.setattr(wizard, "_q_secret", lambda prompt: "   ")
    kept = wizard.collect_api_keys([], {"WIZARD_TEST_SECRET"})
    assert kept == {"WIZARD_TEST_SECRET": "existing-value"}  # pragma: allowlist secret
    monkeypatch.setattr(wizard, "questionary", None)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "  pasted-value \t")
    assert q_secret("Key") == "pasted-value"


def test_resume_reasks_saved_advanced_answers_the_writer_rejects(monkeypatch, tmp_path):
    _advanced(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: False)
    assert wizard.run() == 0  # stopped before writing; answers saved
    state = json.loads(wizard.PARTIAL_STATE_PATH.read_text())
    state["advanced"] = {"spending_workspace_monthly": "abc", "anonymous_logs": True}
    wizard.PARTIAL_STATE_PATH.write_text(json.dumps(state))
    asked = []
    monkeypatch.setattr(wizard, "pick_advanced", lambda: asked.append(1) or {"anonymous_logs": True})
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kw: prompt.startswith("Write config"))
    assert wizard.run(resume=True) == 0
    assert asked == [1]
    assert "advanced questions again" in wizard.console.file.getvalue()
    assert config.load_config(wizard.CONFIG_FILE)["privacy"]["anonymous"] is True


def test_resume_says_when_saved_per_tenant_keys_are_dropped(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    state = {"advanced": {"encrypt_per_tenant": True, "anonymous_logs": True}}
    assert wizard._saved_advanced(state) == {"encrypt_per_tenant": False, "anonymous_logs": True}
    assert "require at-rest encryption" in wizard.console.file.getvalue()
