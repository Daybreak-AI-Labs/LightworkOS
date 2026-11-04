"""`maverick init --fast` must not report success over a failed smoke test.

run_fast() called smoke_test() and discarded its bool, so the one command whose
whole promise is "trust this without answering questions" printed "Fast setup
finished" and exited 0 on a broken install. An installer that cannot fail is an
installer whose success carries no information.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_wizard_paths_honor_maverick_home(monkeypatch, tmp_path):
    from maverick_installer import wizard

    target = tmp_path / "isolated-home"
    monkeypatch.setenv("MAVERICK_HOME", str(target))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)

    config_dir, config_file, env_file = wizard._resolve_config_paths()
    assert config_dir == target
    assert config_file == target / "config.toml"
    assert env_file == target / ".env"


def test_explicit_config_path_wins_and_keeps_env_adjacent(monkeypatch, tmp_path):
    from maverick_installer import wizard

    target = tmp_path / "operator" / "lightwork.toml"
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "ignored"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(target))

    config_dir, config_file, env_file = wizard._resolve_config_paths()
    assert config_dir == target.parent
    assert config_file == target
    assert env_file == target.parent / ".env"


def test_lightwork_home_and_config_aliases_match_core_precedence(monkeypatch, tmp_path):
    from maverick_installer import wizard

    monkeypatch.delenv("MAVERICK_HOME", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.setenv("LIGHTWORK_HOME", str(tmp_path / "product-home"))
    monkeypatch.delenv("LIGHTWORK_CONFIG", raising=False)
    assert wizard._resolve_config_paths()[1] == tmp_path / "product-home" / "config.toml"

    target = tmp_path / "chosen" / "config.toml"
    monkeypatch.setenv("LIGHTWORK_CONFIG", str(target))
    assert wizard._resolve_config_paths()[1] == target
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "legacy-wins.toml"))
    assert wizard._resolve_config_paths()[1] == tmp_path / "legacy-wins.toml"


def test_fast_setup_writes_and_smoke_reads_the_explicit_config(tmp_path):
    """Exercise the real writer/loader contract in a fresh interpreter."""
    target = tmp_path / "operator" / "lightwork.toml"
    isolated_home = tmp_path / "profile"
    installer_root = Path(__file__).resolve().parents[1]
    core_root = Path(__file__).resolve().parents[3] / "packages" / "maverick-core"
    script = f"""
from pathlib import Path
from maverick_installer import wizard

wizard.preflight = lambda: True
wizard.welcome = lambda: None
wizard._docker_available = lambda: False
result = wizard.run_fast()

from maverick.config import config_path, load_config
expected = Path({str(target)!r})
assert result == 1  # Setup is saved, but a missing AI key cannot be reported ready.
assert wizard.CONFIG_FILE == expected
assert config_path() == expected
assert expected.is_file()
assert load_config()["sandbox"]["backend"] == "local"
"""
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "LIGHTWORK_HOME": str(tmp_path / "ignored-home"),
            "LIGHTWORK_CONFIG": str(target),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": os.pathsep.join((str(installer_root), str(core_root))),
        }
    )
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("MAVERICK_HOME", None)
    env.pop("MAVERICK_CONFIG", None)

    completed = subprocess.run(  # noqa: S603 - exact interpreter and test script
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "AI is not connected" in completed.stdout
    assert "Fast setup finished" not in completed.stdout


def _stub(monkeypatch, tmp_path: Path, *, smoke: bool):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path / ".maverick")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / ".maverick" / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".maverick" / ".env")
    monkeypatch.setattr(wizard, "preflight", lambda: True)
    monkeypatch.setattr(wizard, "welcome", lambda: None)
    monkeypatch.setattr(wizard, "_docker_available", lambda: False)
    monkeypatch.setattr(wizard, "smoke_test", lambda: smoke)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return wizard


def test_fast_setup_fails_when_the_smoke_test_fails(monkeypatch, tmp_path):
    wizard = _stub(monkeypatch, tmp_path, smoke=False)
    assert wizard.run_fast() == 1


def test_fast_setup_succeeds_when_the_smoke_test_passes(monkeypatch, tmp_path):
    """Control: rejection only means something if acceptance also works."""
    wizard = _stub(monkeypatch, tmp_path, smoke=True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert wizard.run_fast() == 0


def test_fast_setup_without_key_is_incomplete_even_if_config_smoke_passes(monkeypatch, tmp_path, capsys):
    wizard = _stub(monkeypatch, tmp_path, smoke=True)
    assert wizard.run_fast() == 1
    output = capsys.readouterr().out
    assert "AI is not connected" in output
    assert "Saved setup:" in output
    assert "Fast setup finished" not in output


def test_the_config_is_still_written_before_the_smoke_test_verdict(
        monkeypatch, tmp_path):
    """A failed smoke test must not leave the user with nothing to fix.

    write_config runs first deliberately: the operator needs the file on disk to
    inspect and correct. The failure is in the exit code and the message, not in
    withholding the artifact.
    """
    wizard = _stub(monkeypatch, tmp_path, smoke=False)
    assert wizard.run_fast() == 1
    assert (tmp_path / ".maverick" / "config.toml").is_file()


# ---------- wizard --fast flag ----------

def test_wizard_run_accepts_fast_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    from maverick_installer import wizard
    # Patch CONFIG_DIR / FILES so we write to tmp_path.
    wizard.CONFIG_DIR = tmp_path / ".maverick"
    wizard.CONFIG_FILE = wizard.CONFIG_DIR / "config.toml"
    wizard.ENV_FILE = wizard.CONFIG_DIR / ".env"
    # Fast setup now picks the sandbox by Docker availability; pin it up so
    # this test deterministically exercises the full docker-config path.
    monkeypatch.setattr(wizard, "_docker_available", lambda: True)

    rc = wizard.run(fast=True)
    assert rc == 0
    # Config got written.
    assert wizard.CONFIG_FILE.exists()
    body = wizard.CONFIG_FILE.read_text()
    assert "[providers.anthropic]" in body
    assert "[safety]" in body
    assert "[sandbox]" in body
    assert "backend = \"docker\"" in body
    # ENV stored the key.
    assert wizard.ENV_FILE.exists()
    env_body = wizard.ENV_FILE.read_text()
    assert "ANTHROPIC_API_KEY=sk-ant-test" in env_body


def test_wizard_run_default_still_interactive(tmp_path, monkeypatch):
    """run() without fast=True should NOT short-circuit -- it'd ask."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # We can't actually drive an interactive session in tests, but
    # we can verify the function signature accepts the kwarg.
    import inspect

    from maverick_installer.wizard import run
    sig = inspect.signature(run)
    assert "fast" in sig.parameters
    assert sig.parameters["fast"].default is False
