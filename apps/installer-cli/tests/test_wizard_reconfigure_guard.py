"""A setup retry must leave an existing customer's choices and keys intact."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick_installer import wizard


@pytest.fixture
def saved_setup(tmp_path, monkeypatch):
    home = tmp_path / "lightwork"
    home.mkdir()
    monkeypatch.setattr(wizard, "CONFIG_DIR", home)
    monkeypatch.setattr(wizard, "CONFIG_FILE", home / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", home / ".env")
    config = b"[feature_locks]\ncomputer_use = true\n[governance]\nprofile = 'custom'\n"
    secrets = b"ANTHROPIC_API_KEY=test\nCUSTOM_SECRET=test\n"
    wizard.CONFIG_FILE.write_bytes(config)
    wizard.ENV_FILE.write_bytes(secrets)
    return home, config, secrets


@pytest.mark.parametrize(
    "start",
    [
        lambda: wizard.run(),
        lambda: wizard.run(fast=True),
        lambda: wizard.run(resume=True),
        wizard.run_fast,
        wizard.run_consumer,
        wizard.run_express,
    ],
    ids=["standard", "fast-flag", "resume-flag", "fast-direct", "consumer-direct", "express-direct"],
)
def test_setup_retry_keeps_saved_choices_and_keys(saved_setup, monkeypatch, capsys, start):
    home, config, secrets = saved_setup

    def no_questions(*_args, **_kwargs):
        raise AssertionError("an existing setup must stop before the wizard asks questions")

    monkeypatch.setattr(wizard, "preflight", no_questions)
    monkeypatch.setattr(wizard, "pick_mode", no_questions)
    assert start() == 1
    assert wizard.CONFIG_FILE.read_bytes() == config
    assert wizard.ENV_FILE.read_bytes() == secrets
    assert not (home / "config.toml.bak").exists()
    assert not (home / ".env.bak").exists()
    notice = capsys.readouterr().out
    assert "saved setup files" in notice
    assert "Lightwork" in notice and "Settings" in notice


@pytest.mark.parametrize("existing", ["config.toml", ".env"])
def test_publish_rechecks_existing_files_while_locked(tmp_path, monkeypatch, existing):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    current = tmp_path / existing
    current.write_bytes(b"keep these bytes\n")

    with pytest.raises(FileExistsError, match="Nothing was replaced"):
        wizard._publish_wizard_configuration(
            "[safety]\nprofile = 'strict'\n",
            "ANTHROPIC_API_KEY=replacement\n",
            protect_existing=True,
        )

    assert current.read_bytes() == b"keep these bytes\n"
    assert not (tmp_path / "config.toml.bak").exists()
    assert not (tmp_path / ".env.bak").exists()
    assert not (tmp_path / (".env" if existing == "config.toml" else "config.toml")).exists()


def test_unreadable_setup_path_is_not_assumed_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    original_lstat = Path.lstat

    def unreadable(path, *args, **kwargs):
        if path == wizard.CONFIG_FILE:
            raise PermissionError("setup path is not readable")
        return original_lstat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", unreadable)
        assert wizard._existing_setup() is True


def test_a_setup_saved_meanwhile_leaves_the_work_folder_untouched(saved_setup, tmp_path):
    # Setup checks for a saved setup before the questions. One saved by
    # another installer while they were answered must still refuse the write,
    # before the work folder and the sample files are created.
    home, config, secrets = saved_setup
    workdir = tmp_path / "work"
    with pytest.raises(FileExistsError):
        wizard.write_consumer_config(user_name="Alex", keys={}, workdir=str(workdir),
                                     budget={"max_dollars": 2.0}, first_outcome="finance",
                                     protect_existing=True)
    assert not workdir.exists()
    assert wizard.CONFIG_FILE.read_bytes() == config and wizard.ENV_FILE.read_bytes() == secrets
