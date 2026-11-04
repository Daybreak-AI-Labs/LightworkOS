"""Consumer-mode flow + first-screen picker."""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]


# ---------- pick_mode ----------


def test_new_install_budget_defaults_are_optional_and_explicit_choices_survive(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_select", lambda *_a, **kw: kw["default"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_a, **kw: kw["default"])
    assert wizard._consumer_budget() == {"max_dollars": 2.0, "max_wall_seconds": 1800.0}
    monkeypatch.setattr(wizard, "_q_text", lambda *_a, **kw: kw["default"])
    assert wizard.pick_budget() == {"max_dollars": 2.0, "max_wall_seconds": 1800.0,
                                    "max_tool_calls": 500, "strict_pricing": True,
                                    "guidance": True, "warnings": True,
                                    "warning_thresholds": [0.8, 0.95, 1.0]}
    monkeypatch.setattr(wizard, "_q_select", lambda *_a, **_kw: "$5")
    assert wizard._consumer_budget() == {"max_dollars": 5.0, "max_wall_seconds": 1800.0}
    monkeypatch.setattr(wizard, "_q_select", lambda *_a, **_kw: "No task limit")
    assert wizard._consumer_budget() == {"task_limits_enabled": False}


def test_custom_spending_cap_reasks_instead_of_saving_a_different_or_invalid_limit(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_select", lambda *_a, **_kw: "custom")
    answers = iter(["ten dollars", "-3", "NaN", "$10"])
    monkeypatch.setattr(wizard, "_q_text", lambda *_a, **_kw: next(answers))
    assert wizard._consumer_budget() == {"max_dollars": 10.0, "max_wall_seconds": 1800.0}


def test_advanced_task_limits_reask_invalid_dollars_time_and_calls(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *_a, **kw: kw["default"])
    answers = iter(["nonsense", "$4.50", "-1", "600", "0", "20", "0.8, 1.0"])
    monkeypatch.setattr(wizard, "_q_text", lambda *_a, **_kw: next(answers))
    budget = wizard.pick_budget()
    assert (budget["max_dollars"], budget["max_wall_seconds"], budget["max_tool_calls"]) == (4.5, 600.0, 20)

def test_pick_mode_default_is_consumer(monkeypatch):
    from maverick_installer import wizard
    captured = {}
    def fake_select(message, choices, default=None):
        captured["default"] = default
        return default
    monkeypatch.setattr(wizard, "_q_select", fake_select)
    mode = wizard.pick_mode()
    assert mode == "consumer"
    assert captured["default"].startswith("consumer")


def test_pick_mode_advanced_selectable(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_select",
                        lambda *a, **kw: "advanced - let me configure everything")
    assert wizard.pick_mode() == "advanced"


def test_pick_mode_express_selectable(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_select",
                        lambda *a, **kw: "express  - turn on all features, few questions")
    assert wizard.pick_mode() == "express"


# ---------- run_express: everything-on shortcut ----------

def test_run_express_enables_all_safe_features(monkeypatch, tmp_path: Path):
    """Express writes a single valid config that turns the safe single-user
    features ON and keeps host-dangerous ones OFF."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    rc = wizard.run_express()
    assert rc == 0

    # A duplicate table would raise here -- the whole config must parse.
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())

    # Product surfaces + the self-improvement lifecycle are ON.
    assert config["flows"]["enable"] is True
    assert config["connections"]["enable"] is True
    assert config["self_learning"]["enable"] is True
    assert config["durable"]["enabled"] is True
    assert config["reflexion"]["enable"] is True
    assert config["dreaming"]["enable"] is True
    assert config["data_engine"]["enable"] is True
    assert config["capabilities"]["web_search"] is True

    # Host-dangerous capabilities stay OFF (opt-in only).
    assert config["capabilities"]["computer_use"] is False
    assert config["capabilities"]["code_exec"] is False
    denied_tools = set(config["security"]["denied_tools"])
    assert denied_tools >= {
        "computer",
        "browser",
        "shell",
        "write_file",
        "apply_patch",
        "str_replace_editor",
        "ast_edit",
    }
    # Self-learning is on WITHOUT executable-tool or external-MCP autonomy.
    assert config["self_learning"]["create_tools"] is False
    assert config["self_learning"]["allow_mcp_acquisition"] is False
    assert config["self_learning"]["distill_local"] is True
    # DGM is a separate, explicit production decision even in express mode.
    assert "self_modify" not in config

    # The smoke-test canary: sandbox survives the round-trip (no [flows] dup).
    assert config["sandbox"]["backend"] == "local"


def test_run_express_docker_mode_keeps_host_mutation_tools_enabled(
    monkeypatch, tmp_path: Path,
):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_docker_available", lambda: True)

    rc = wizard.run_express()

    assert rc == 0
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    assert config["sandbox"]["backend"] == "docker"
    denied_tools = set(config["security"]["denied_tools"])
    assert denied_tools == {"computer", "browser"}


def test_run_express_routed_via_pick_mode(monkeypatch, tmp_path: Path):
    """Non-resume run() forks to run_express() when express is picked."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "pick_mode", lambda: "express")
    monkeypatch.setattr(wizard, "welcome", lambda: None)
    rc = wizard.run(fast=False, resume=False)
    assert rc == 0
    assert (tmp_path / ".maverick" / "config.toml").exists()


# ---------- run_consumer happy path ----------

def _stub_wizard_io(monkeypatch, tmp_path: Path, key: str = "sk-ant-test"):
    """Wire all the IO primitives the consumer flow touches."""
    from maverick_installer import wizard

    # The consumer flow is interactive; present an interactive stdin so run()'s
    # non-TTY guard doesn't short-circuit the prompt flow under pytest.
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    answers = iter([
        # user_name
        "Alex",
        # workdir
        str(tmp_path / "workspace"),
    ])
    # Each _q_text call pops the next answer.
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    monkeypatch.setattr(wizard, "_q_secret", lambda *a, **kw: key)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "$5")

    # Fix the config dir + skip the real preflight (uses console output).
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")
    monkeypatch.setattr(
        wizard, "VALIDATION_CACHE_PATH",
        tmp_path / ".maverick" / "validation-cache.json",
    )
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH",
                        tmp_path / ".maverick" / "wizard-partial.json")
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    # Pretend Docker is unavailable so the test is hermetic.
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)
    # Stub the validator so we don't hit Anthropic.
    monkeypatch.setattr(
        wizard, "_validate_anthropic_key", lambda k: (True, "validated"),
    )
    return wizard


def test_run_consumer_writes_safe_defaults(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    rc = wizard.run_consumer()
    assert rc == 0

    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    # Safe defaults.
    assert config["safety"]["profile"] == "strict"
    assert config["safety"]["block_threshold"] == "medium"
    assert config["sandbox"]["backend"] == "local"          # no docker
    assert "computer" in config["security"]["denied_tools"]
    assert "browser" in config["security"]["denied_tools"]
    assert "shell" in config["security"]["denied_tools"]
    assert "write_file" in config["security"]["denied_tools"]
    assert "ast_edit" in config["security"]["denied_tools"]
    assert config["retention"]["audit_days"] == 30
    assert config["rate_limits"]["web_search"] == "5/60"
    assert config["persona"]["user_name"] == "Alex"
    assert config["budget"]["max_dollars"] == 5.0
    assert config["budget"]["max_wall_seconds"] == 1800.0
    assert config["capabilities"]["web_search"] is True
    assert config["self_learning"]["enable"] is True
    assert config["self_learning"]["create_tools"] is False
    assert config["self_learning"]["allow_mcp_acquisition"] is False
    assert config["self_learning"]["distill_local"] is True
    assert "self_modify" not in config
    # No channels, no MCP, no plugins.
    assert "channels" not in config
    assert "mcp_servers" not in config
    assert "plugins" not in config

    # API key landed in .env at chmod 600.
    env = (tmp_path / ".maverick" / ".env").read_text()
    assert "ANTHROPIC_API_KEY=sk-ant-test" in env
    import os
    import stat
    mode = stat.S_IMODE((tmp_path / ".maverick" / ".env").stat().st_mode)
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert mode == 0o600


def test_run_consumer_skip_key_succeeds(monkeypatch, tmp_path: Path):
    """Empty key → wizard saves config without secrets, no crash."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path, key="")
    rc = wizard.run_consumer()
    assert rc == 0
    assert (tmp_path / ".maverick" / "config.toml").exists()
    # No .env created when no keys.
    assert not (tmp_path / ".maverick" / ".env").exists()


def test_run_consumer_docker_default_when_available(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_docker_available", lambda: True)
    wizard.run_consumer()
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    assert config["sandbox"]["backend"] == "docker"


def test_run_consumer_docker_mode_keeps_host_mutation_tools_enabled(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_docker_available", lambda: True)
    wizard.run_consumer()
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    denied = config["security"]["denied_tools"]
    assert "computer" in denied
    assert "browser" in denied
    assert "shell" not in denied
    assert "write_file" not in denied


def test_run_consumer_demo_command_runs_a_real_first_outcome(monkeypatch, tmp_path: Path, capsys):
    """The closing panel prints a real first task on sample data for the
    picked department, and never a hard-coded model (see
    test_wizard_first_outcome.py for the full step)."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    wizard.run_consumer()
    out = " ".join(capsys.readouterr().out.replace("│", " ").split())  # Rich wraps the panel
    # Finance's sample runs the three-way match exception clerk, a specialist
    # that reads the bundled sample files and starts on a fresh install.
    assert "maverick start --sample finance" in out
    assert "--model" not in out
    assert "File changes and program execution are off" in out
    assert "Permissions" in out and "Allow file work" in out
    assert "Setup complete" not in out


def test_run_consumer_creates_workdir(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    wizard.run_consumer()
    assert (tmp_path / "workspace").exists()


def test_run_consumer_install_failure_renders_branded_panel(monkeypatch, tmp_path: Path, capsys):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    def _boom(*a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(wizard, "write_config", _boom)
    rc = wizard.run_consumer()
    assert rc == 1
    out = capsys.readouterr().out
    assert "Setup hit a problem" in out
    assert "disk full" in out


# ---------- run() forks on mode ----------

def test_run_consumer_routed_via_pick_mode(monkeypatch, tmp_path: Path):
    """Non-resume run() asks for mode and forks to run_consumer() on default."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "pick_mode", lambda: "consumer")
    monkeypatch.setattr(wizard, "welcome", lambda: None)
    rc = wizard.run(fast=False, resume=False)
    assert rc == 0
    assert (tmp_path / ".maverick" / "config.toml").exists()


def test_run_resume_skips_mode_picker(monkeypatch, tmp_path: Path):
    """--resume implies an in-progress advanced flow; don't re-pick mode."""
    from maverick_installer import wizard
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    called = {"pick_mode": False, "run_consumer": False}
    monkeypatch.setattr(wizard, "pick_mode", lambda: (called.__setitem__("pick_mode", True) or "consumer"))
    monkeypatch.setattr(wizard, "run_consumer", lambda: (called.__setitem__("run_consumer", True) or 0))
    monkeypatch.setattr(wizard, "welcome", lambda: None)
    monkeypatch.setattr(wizard, "preflight", lambda: False)  # short-circuit
    wizard.run(fast=False, resume=True)
    assert called["pick_mode"] is False
    assert called["run_consumer"] is False


def test_run_aborts_with_guidance_when_not_a_tty(monkeypatch, tmp_path):
    """Non-interactive stdin (CI / Docker / `... | maverick init`) must yield
    actionable guidance and a clean exit, not questionary's terse 'Aborted!'."""
    import io

    from maverick_installer import wizard
    from rich.console import Console

    # A fresh installation: the config paths are resolved once at import, so a
    # real saved setup on the test machine must not answer for this case.
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")

    monkeypatch.setattr(
        wizard, "console",
        Console(file=io.StringIO(), force_terminal=False, no_color=True),
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc = wizard.run(fast=False, resume=False)
    assert rc == 1
    out = wizard.console.file.getvalue()
    assert "interactive terminal" in out
    assert "--fast" in out


def _lint_written_config(tmp_path: Path) -> list:
    from maverick.config import _read_toml_raw
    from maverick.config_lint import lint_config

    return lint_config(_read_toml_raw(tmp_path / ".maverick" / "config.toml") or {})


def test_consumer_wizard_output_lints_clean(monkeypatch, tmp_path: Path):
    """The wizard must never write a config its own linter warns about.

    Field finding: a wizard-written config warned "unknown section
    [event_triggers]" and "unknown key" on capabilities.ros and
    persona.user_name -- the product flagging its own output, which reads as
    breakage to the user.
    """
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    assert wizard.run_consumer() == 0
    findings = _lint_written_config(tmp_path)
    assert findings == [], [f.message for f in findings]


def test_express_wizard_output_lints_clean(monkeypatch, tmp_path: Path):
    """Same invariant for express mode (see the consumer variant above)."""
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    assert wizard.run_express() == 0
    findings = _lint_written_config(tmp_path)
    assert findings == [], [f.message for f in findings]
