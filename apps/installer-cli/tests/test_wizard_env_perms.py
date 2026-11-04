"""Wizard env-file race fix — perms must be 0o600 from creation, not after."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch


def test_env_file_created_at_0600(tmp_path: Path, monkeypatch):
    """``write_text`` then ``chmod`` left a window where the file existed at 0644.

    The private temporary file and atomic replacement path
    eliminates the race: the file's first ``stat`` after creation must
    already be 0o600.
    """
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", tmp_path / "config.toml")

    # Patch the stat-on-create check by spying on the file inside write_config.
    observed_modes = []
    real_open = os.open

    def _watching_open(path, flags, mode=0o777):
        fd = real_open(path, flags, mode)
        # Only files this write CREATES must be private from their first
        # instant; opening an existing directory to fsync it is not creation.
        if flags & os.O_CREAT:
            try:
                observed_modes.append(stat.S_IMODE(os.stat(path).st_mode))
            except OSError:
                pass
        return fd

    with patch("maverick_installer.wizard.os.open", side_effect=_watching_open):
        from maverick_installer.wizard import write_config
        write_config(
            providers=["anthropic"],
            role_models={},
            channels={},
            safety={"profile": "balanced"},
            budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
            sandbox={"backend": "local", "workdir": str(tmp_path / "workspace")},
            keys={"ANTHROPIC_API_KEY": "sk-ant-test"},
            capabilities={},
        )

    # Both files (env + config) were created with 0o600.
    assert (tmp_path / ".env").exists()
    assert (tmp_path / "config.toml").exists()
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "config.toml").stat().st_mode) == 0o600
    # The atomic open observed 0o600 on first stat:
    assert observed_modes, "patched os.open never invoked"
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert all(m == 0o600 for m in observed_modes), f"saw modes {observed_modes!r}"


def test_env_file_overwrites_existing(tmp_path: Path, monkeypatch):
    """Re-running the wizard with the same keys must overwrite cleanly at 0o600."""
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", tmp_path / "config.toml")

    # Pre-create env at the wide mode the bug would leave it at.
    env = tmp_path / ".env"
    env.write_text("STALE=1\n")
    os.chmod(env, 0o644)

    from maverick_installer.wizard import write_config
    write_config(
        providers=["openai"],
        role_models={},
        channels={},
        safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": str(tmp_path / "workspace")},
        keys={"OPENAI_API_KEY": "sk-new"},
        capabilities={},
    )

    assert "OPENAI_API_KEY=sk-new" in env.read_text()
    assert "STALE" not in env.read_text()
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_existing_env_backup_created_at_0600(tmp_path: Path, monkeypatch):
    """Backups of secret-bearing env files must never be created world-readable."""
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", tmp_path / "config.toml")

    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_API_KEY=sk-old\n")
    os.chmod(env, 0o644)

    observed_backup_modes = []
    real_open = os.open

    def _watching_open(path, flags, mode=0o777):
        fd = real_open(path, flags, mode)
        if os.fspath(path).endswith(".bak.tmp"):
            try:
                observed_backup_modes.append(stat.S_IMODE(os.stat(path).st_mode))
            except OSError:
                pass
        return fd

    with patch("maverick_installer.wizard.os.open", side_effect=_watching_open):
        from maverick_installer.wizard import write_config

        write_config(
            providers=["anthropic"],
            role_models={},
            channels={},
            safety={"profile": "balanced"},
            budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
            sandbox={"backend": "local", "workdir": str(tmp_path / "workspace")},
            keys={"ANTHROPIC_API_KEY": "sk-new"},
            capabilities={},
        )

    backup = tmp_path / ".env.bak"
    assert backup.read_text() == "ANTHROPIC_API_KEY=sk-old\n"
    assert observed_backup_modes, "backup temp file was not created via os.open"
    if os.name != "nt":  # NTFS reports 0o666 regardless of the chmod
        assert all(m == 0o600 for m in observed_backup_modes)
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_identical_wizard_retry_does_not_rewrite_or_create_backups(
    tmp_path: Path, monkeypatch
):
    """An installer retry with the same answers is a custody check, not a write."""
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    kwargs = {
        "providers": ["anthropic"],
        "role_models": {},
        "channels": {},
        "safety": {"profile": "balanced"},
        "budget": {
            "max_dollars": 5.0,
            "max_wall_seconds": 600,
            "max_tool_calls": 30,
        },
        "sandbox": {"backend": "local", "workdir": str(tmp_path / "workspace")},
        "keys": {"ANTHROPIC_API_KEY": "sk-ant-test"},
        "capabilities": {},
    }
    wizard.write_config(**kwargs)
    config_before = wizard.CONFIG_FILE.stat()
    env_before = wizard.ENV_FILE.stat()

    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("identical retry must not open a wizard write path")

    # Workspace probes and the writer lock may open their own files; an
    # identical retry must still never publish either active configuration.
    monkeypatch.setattr("maverick.file_lock.atomic_write_text", unexpected_open)
    wizard.write_config(**kwargs)

    config_after = wizard.CONFIG_FILE.stat()
    env_after = wizard.ENV_FILE.stat()
    assert (config_after.st_ino, config_after.st_mtime_ns) == (
        config_before.st_ino,
        config_before.st_mtime_ns,
    )
    assert (env_after.st_ino, env_after.st_mtime_ns) == (
        env_before.st_ino,
        env_before.st_mtime_ns,
    )
    assert not (tmp_path / "config.toml.bak").exists()
    assert not (tmp_path / ".env.bak").exists()
