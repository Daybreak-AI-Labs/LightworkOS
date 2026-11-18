"""`maverick doctor` schema-lints the config so a mistyped key (e.g. a budget
cap typo that would otherwise run UNCAPPED) surfaces, not only in the dedicated
`maverick config-lint`. Advisory: findings are warnings, never failures."""
from __future__ import annotations

import maverick.health as h


def test_doctor_config_lint_flags_budget_typo(capsys):
    h._FAILURES.clear()
    h._check_config_lint({"budget": {"max_dollarss": 5.0}})
    out = capsys.readouterr().out
    assert "config-lint" in out
    assert "max_dollarss" in out          # the typo is named
    assert "✗" not in out                 # advisory (!), not a red failure
    assert h._FAILURES == []              # does not count toward the exit code


def test_doctor_config_lint_clean_config(capsys):
    h._FAILURES.clear()
    h._check_config_lint({"budget": {"max_dollars": 5.0}})
    out = capsys.readouterr().out
    assert "config-lint" in out and "no unknown" in out
    assert h._FAILURES == []


def test_doctor_config_lint_noop_on_empty_config(capsys):
    # corrupt / missing config -> _check_config already reported it; stay quiet
    h._FAILURES.clear()
    h._check_config_lint({})
    assert capsys.readouterr().out == ""
    assert h._FAILURES == []


def test_diagnose_wires_in_config_lint():
    import inspect
    assert "_check_config_lint" in inspect.getsource(h.diagnose)


def test_governance_tool_names_are_a_doctor_notice_that_never_blocks_a_strict_start(monkeypatch, capsys):
    from maverick import config_lint

    cfg = {"governance": {"deny_actions": ["browser_navigate", "mcp_github__delete_repo", "Computer",
                                           "shel"]}}
    pre_installed = {"governance": {"deny_actions": ["browser_navigate", "mcp_github__delete_repo"]}}
    with monkeypatch.context() as startup:
        startup.setattr("maverick.config.config_path", lambda: type("P", (), {"exists": lambda self: True})())
        startup.setattr("maverick.config._read_toml_raw", lambda p: pre_installed)
        config_lint.warn_config_at_startup(strict=True)  # no SystemExit
    h._FAILURES.clear()
    h._check_governance_tool_names(cfg)
    out = capsys.readouterr().out
    assert "shel" in out and h._FAILURES == []          # a misspelled built-in is shown
    assert "mcp_github__delete_repo" not in out          # MCP tools are not in the catalog
    assert "Computer" not in out                         # optional built-ins count, case-insensitively


# Field findings: doctor flagged the wizard's own ${ANTHROPIC_API_KEY} reference
# and the sealed key Settings saves as "inline secrets" -- it linted the loaded
# config, where the reference is already expanded and the seal already opened.
def test_doctor_does_not_flag_the_wizards_env_reference(monkeypatch, tmp_path, capsys):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-" + "x" * 40)  # pragma: allowlist secret
    (tmp_path / "config.toml").write_text(
        '[providers.anthropic]\napi_key = "${ANTHROPIC_API_KEY}"\n', encoding="utf-8")
    config.reset_config_cache()
    h._check_config_lint(config.load_config())
    assert "inline secret" not in capsys.readouterr().out


def test_doctor_does_not_flag_the_sealed_key_settings_saves(monkeypatch, tmp_path, capsys):
    from maverick import config, crypto_at_rest

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sealed = crypto_at_rest.seal_to_str("sk-ant-api03-" + "y" * 40)  # pragma: allowlist secret
    (tmp_path / "config.toml").write_text("[budget]\nmax_dollars = 2.0\n", encoding="utf-8")
    (tmp_path / "dashboard-config.toml").write_text(
        f'[providers.anthropic]\napi_key = "{sealed}"\n', encoding="utf-8")
    config.reset_config_cache()
    h._check_config_lint(config.load_config())
    assert "inline secret" not in capsys.readouterr().out


def test_doctor_still_flags_a_real_inline_secret(monkeypatch, tmp_path, capsys):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    (tmp_path / "config.toml").write_text(
        '[providers.anthropic]\napi_key = "sk-ant-api03-' + "z" * 40 + '"\n',  # pragma: allowlist secret
        encoding="utf-8")
    config.reset_config_cache()
    h._check_config_lint(config.load_config())
    assert "inline secret" in capsys.readouterr().out


def test_doctor_reads_the_key_saved_in_settings(monkeypatch, capsys):
    """After a key is saved in Settings, doctor must not say ANTHROPIC_API_KEY is
    not set and that this is "fine unless a role routes to anthropic"."""
    import sys
    import types

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda name: {"api_key": "sk-ant-api03-" + "k" * 40} if name == "anthropic" else {})  # pragma: allowlist secret
    seen = {}

    class Client:
        def __init__(self, api_key, max_retries):
            seen["key"] = api_key
            self.models = types.SimpleNamespace(list=lambda limit: iter([object()]))

    fake = types.SimpleNamespace(Anthropic=Client, AuthenticationError=type("AuthErr", (Exception,), {}))
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    h._FAILURES.clear()
    h._check_anthropic()
    out = capsys.readouterr().out
    assert "key validated" in out and "not set" not in out
    assert seen["key"].startswith("sk-ant-")


def test_doctor_names_roles_that_need_the_missing_anthropic_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("maverick.config.get_provider_config", lambda name: {})
    monkeypatch.setattr("maverick.config.any_provider_configured", lambda: True)
    monkeypatch.setattr("maverick.config.get_role_model", lambda role: "claude-sonnet-4-6")
    h._FAILURES.clear()
    h._ATTENTION.clear()
    h._check_anthropic()
    out = capsys.readouterr().out
    assert "fine unless" not in out
    assert "these roles use an Anthropic model: orchestrator" in out
    assert "anthropic" in h._ATTENTION
