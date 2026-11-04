"""SSH setup must publish a usable structural contract without contacting SSH."""
from __future__ import annotations

import json
from pathlib import PurePosixPath

import pytest
from maverick.sandbox import build_sandbox
from maverick.sandbox.ssh import SSHBackend
from maverick_installer import wizard

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


@pytest.fixture
def config_files(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setenv("MAVERICK_CONFIG", str(wizard.CONFIG_FILE))
    monkeypatch.delenv("MAVERICK_DEPLOYMENT_ISOLATION", raising=False)
    return tmp_path


@pytest.mark.parametrize("destination", ["customer@server.example", "customer-server", "customer@[2001:db8::1]"])
def test_ssh_selection_roundtrips_to_runtime_without_network(config_files, monkeypatch, destination):
    def unexpected_connection(_self):
        raise AssertionError("setup must not contact SSH")

    monkeypatch.setattr(SSHBackend, "_verify_ssh", unexpected_connection)
    monkeypatch.setenv("MAVERICK_WORKDIR", str(config_files / "local-only"))
    monkeypatch.setattr(wizard, "_q_select", lambda *_args, **_kwargs: "ssh    - Remote machine")
    answers = iter(["", "customer@", f"  {destination}  "])

    def answer(label, *, default):
        if label == "  Remote workspace directory":
            assert default == "~/maverick-workspace"
            return default
        assert label == "  SSH destination (user@host or SSH config alias)"
        return next(answers)

    monkeypatch.setattr(wizard, "_q_text", answer)
    selected = wizard.pick_sandbox()
    wizard.write_config([], {}, {}, {}, {}, selected, {})
    saved = tomllib.loads(wizard.CONFIG_FILE.read_text(encoding="utf-8"))["sandbox"]
    assert saved["host"] == destination
    assert saved["workdir"] == "~/maverick-workspace"
    assert wizard.smoke_test() is True
    verified = []
    monkeypatch.setattr(SSHBackend, "_verify_ssh", lambda self: verified.append(self.host))
    backend = build_sandbox()
    assert backend.host == destination
    assert backend.workdir == PurePosixPath("~/maverick-workspace")
    assert verified == [destination]
    assert not (config_files / "local-only").exists()


@pytest.mark.parametrize("destination", [None, "", "  ", "customer@", "@server", "bad host", "-option", "user@-option", "ssh://server", "a@@server", "bad\0host"])
def test_invalid_ssh_destination_cannot_replace_existing_configuration(config_files, destination):
    wizard.CONFIG_FILE.write_text('[sandbox]\nbackend="local"\n', encoding="utf-8")
    wizard.ENV_FILE.write_text("SYNTHETIC_KEY=old\n", encoding="utf-8")
    before = (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes())
    selected = {"backend": "ssh", "workdir": "~/remote-work"}
    if destination is not None:
        selected["host"] = destination
    with pytest.raises(ValueError, match="SSH destination"):
        wizard.write_config([], {}, {}, {}, {}, selected, {"SYNTHETIC_KEY": "new"})
    assert (wizard.CONFIG_FILE.read_bytes(), wizard.ENV_FILE.read_bytes()) == before


@pytest.mark.parametrize("destination", [None, "", "user@", "bad host"])
def test_smoke_check_rejects_incomplete_saved_ssh_configuration(config_files, destination):
    body = '[sandbox]\nbackend="ssh"\nworkdir="~/remote-work"\n'
    if destination is not None:
        body += "host=" + json.dumps(destination) + "\n"
    wizard.CONFIG_FILE.write_text(body, encoding="utf-8")
    assert wizard.smoke_test() is False
