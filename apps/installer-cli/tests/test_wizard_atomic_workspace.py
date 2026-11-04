"""Setup must leave a usable workspace and complete active configuration files."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from maverick import file_lock
from maverick.sandbox.local import LocalBackend
from maverick_installer import wizard


@pytest.fixture
def setup(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setattr(wizard, "CONFIG_DIR", state)
    monkeypatch.setattr(wizard, "CONFIG_FILE", state / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", state / ".env")
    return dict(providers=[], role_models={}, channels={}, safety={}, budget={},
                sandbox={"backend": "local", "workdir": str(tmp_path / "new/nested/workspace")},
                keys={"SYNTHETIC_KEY": "new-value"})


def test_advanced_workspace_is_ready_for_first_local_command(setup):
    wizard.write_config(**setup)
    folder = Path(setup["sandbox"]["workdir"])
    assert folder.is_dir()
    result = LocalBackend(folder).exec("echo workspace-ready")
    assert result.exit_code == 0
    assert "workspace-ready" in result.stdout
    assert not list(folder.iterdir())


def test_unwritable_workspace_does_not_publish_successful_configuration(setup, monkeypatch):
    wizard.CONFIG_FILE.write_text('[sandbox]\nbackend="local"\n', encoding="utf-8")
    wizard.ENV_FILE.write_text("SYNTHETIC_KEY=old-value\n", encoding="utf-8")
    before = (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes())

    def denied(**_kwargs):
        raise PermissionError("workspace mount is read only")

    monkeypatch.setattr(wizard.tempfile, "TemporaryFile", denied)
    with pytest.raises(PermissionError):
        wizard.write_config(**setup)
    assert (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes()) == before


@pytest.mark.parametrize("name", ["config.toml", ".env"])
@pytest.mark.parametrize("stage", ["open", "write", "flush", "replace"])
def test_private_atomic_writer_preserves_old_active_file_on_failure(setup, monkeypatch, name, stage):
    target = wizard.CONFIG_DIR / name
    old = '[sandbox]\nbackend="local"\n' if name.endswith("toml") else "SYNTHETIC_KEY=old\n"
    target.write_text(old, encoding="utf-8")
    original_fdopen = os.fdopen

    class BrokenWriter:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.file.close()

        def __getattr__(self, attr):
            return getattr(self.file, attr)

        def write(self, text):
            self.file.write(text[:8])
            if stage == "write":
                raise OSError("injected write failure")
            return self.file.write(text[8:])

        def flush(self):
            self.file.flush()
            if stage == "flush":
                raise OSError("injected flush failure")

    def broken(*_args, **_kwargs):
        raise OSError("injected publication failure")

    with monkeypatch.context() as patch:
        if stage == "open":
            patch.setattr(file_lock, "_secure_mkstemp", broken)
        elif stage == "replace":
            patch.setattr(file_lock, "_windows_replace_open_fd" if os.name == "nt" else "_replace_with_retry", broken)
        else:
            patch.setattr(file_lock.os, "fdopen", lambda fd, mode="r", **kwargs: BrokenWriter(original_fdopen(fd, mode, **kwargs)))
        with pytest.raises(OSError):
            wizard._write_wizard_file(target, "complete-new-content\n")
    assert target.read_text(encoding="utf-8") == old
    assert not list(target.parent.glob(f".{name}-*.tmp"))
    wizard._write_wizard_file(target, "complete-new-content\n")
    assert target.read_text(encoding="utf-8") == "complete-new-content\n"
    before = target.stat().st_mtime_ns
    wizard._write_wizard_file(target, "complete-new-content\n")
    assert target.stat().st_mtime_ns == before


def test_failed_config_publication_restores_previous_environment_pair(setup, monkeypatch):
    wizard.write_config(**setup)
    before = (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes())
    setup["keys"] = {"SYNTHETIC_KEY": "replacement"}
    setup["budget"] = {"max_tool_calls": 42}
    original = file_lock.atomic_write_text

    def fail_config(path, text, **kwargs):
        if Path(path) == wizard.CONFIG_FILE:
            raise OSError("config replace refused")
        return original(path, text, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_text", fail_config)
    with pytest.raises(OSError, match="config replace"):
        wizard.write_config(**setup)
    assert (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes()) == before


def test_invalid_config_never_publishes_environment(setup):
    wizard.ENV_FILE.write_text("SYNTHETIC_KEY=old\n", encoding="utf-8")
    with pytest.raises(ValueError):
        wizard._publish_wizard_configuration("[not valid", "SYNTHETIC_KEY=new\n")
    assert wizard.ENV_FILE.read_text(encoding="utf-8") == "SYNTHETIC_KEY=old\n"


def test_remote_workspace_is_not_provisioned_on_installer_host(monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("remote workspace must not create local directories")

    monkeypatch.setattr(wizard.Path, "mkdir", unexpected)
    config = {"backend": "ssh", "host": "customer@remote", "workdir": "/remote/customer-job"}
    assert wizard._prepare_wizard_workspace(config) == config
