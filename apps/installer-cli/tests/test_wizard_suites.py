"""The wizard's agent-suite step writes ``[suites]``, and the kernel reads it.

Rule-6 integrity: a wizard toggle must actually reach the feature -- here, the
factory's ``enabled_domains()`` consumes exactly the ``[suites]`` table the
wizard writes. Default (no customization) writes no section, so every suite
stays enabled.
"""
from __future__ import annotations

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _write(cfg_dir, monkeypatch, suites):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"},
        suites=suites,
    )
    return (cfg_dir / "config.toml").read_text()


def test_default_writes_no_suites_section(tmp_path, monkeypatch):
    # No customization -> no [suites] table -> kernel enables every suite.
    assert "[suites]" not in _write(tmp_path, monkeypatch, {})


def test_suite_choices_are_written(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"operations": True, "legal": False})
    assert tomllib.loads(cfg)["suites"] == {"operations": True, "legal": False}


def test_kernel_reads_what_the_wizard_writes(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"operations": False, "legal": True})
    parsed = tomllib.loads(cfg)
    from maverick.domain import _disabled_suites
    assert _disabled_suites(parsed) == {"operations"}
