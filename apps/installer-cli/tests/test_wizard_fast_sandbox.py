"""`maverick init --fast` must not write a docker config it can't run.

Hardcoding the docker sandbox on a host with no Docker daemon would make the
very next `maverick start` fail with "Docker not available" on a backend the
user never chose. run_fast() mirrors write_consumer_config: docker when the
daemon is up, else local.
"""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _stub_fast(monkeypatch, tmp_path: Path, *, docker: bool):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    monkeypatch.setattr(wizard, "welcome", lambda: None)
    # Must return True, not None: run_fast now checks the result, so a falsy
    # stub would fail the install these tests are not about. The smoke-test
    # contract itself is covered in test_wizard_fast_smoke.py.
    monkeypatch.setattr(wizard, "smoke_test", lambda: True)
    monkeypatch.setattr(wizard, "_docker_available", lambda: docker)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return wizard


def _config(tmp_path: Path) -> dict:
    return tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())


def _backend(tmp_path: Path) -> str:
    return _config(tmp_path)["sandbox"]["backend"]


def _denied_tools(tmp_path: Path) -> set[str]:
    return set(_config(tmp_path)["security"]["denied_tools"])


def test_fast_setup_falls_back_to_local_when_docker_down(monkeypatch, tmp_path):
    wizard = _stub_fast(monkeypatch, tmp_path, docker=False)
    assert wizard.run_fast() == 0
    assert _backend(tmp_path) == "local"
    assert _denied_tools(tmp_path) >= {
        "computer",
        "browser",
        "shell",
        "write_file",
        "apply_patch",
        "str_replace_editor",
        "ast_edit",
    }


def test_fast_setup_uses_docker_when_daemon_up(monkeypatch, tmp_path):
    wizard = _stub_fast(monkeypatch, tmp_path, docker=True)
    assert wizard.run_fast() == 0
    assert _backend(tmp_path) == "docker"
    assert _denied_tools(tmp_path) == {"computer", "browser"}
