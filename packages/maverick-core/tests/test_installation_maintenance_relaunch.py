"""Independent native result windows must survive the frozen helper's cleanup."""
from __future__ import annotations

import ctypes
import importlib
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner


@pytest.mark.parametrize(
    "status", ["upgraded", "rolled_back", "repaired", "repair_recovered", "incomplete"],
)
@pytest.mark.parametrize("open_result", [True, False])
def test_result_window_resets_frozen_environment_without_changing_parent(
    tmp_path, monkeypatch, status, open_result,
):
    cli = importlib.import_module("maverick.cli")
    recovery = importlib.import_module("maverick.installation_recovery")
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "maverick-desktop.exe").write_bytes(b"not an executable")
    retained = tmp_path / "retained"
    retained.mkdir()
    environment = {
        "MAVERICK_HOME": str(tmp_path / "state"),
        "_PYI_ARCHIVE_FILE": str(retained / "maverick.exe"),
        "_PYI_APPLICATION_HOME_DIR": str(tmp_path / "expired-runtime"),
        "_PYI_PARENT_PROCESS_LEVEL": "1",
        "PYINSTALLER_RESET_ENVIRONMENT": "0",
    }
    before = dict(environment)
    monkeypatch.setattr(cli, "os", SimpleNamespace(name="nt", environ=environment))
    kernel = SimpleNamespace(OpenProcess=Mock(return_value=123),
                             WaitForSingleObject=Mock(return_value=0), CloseHandle=Mock())
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    monkeypatch.setattr(recovery, "inspect_grant", lambda _token: {"id": "a" * 32})
    monkeypatch.setattr(recovery, "_directory", lambda _identifier: retained)
    monkeypatch.setattr(recovery, "_read", lambda _path: {
        "installed_runtime": str(installed / "maverick.exe"), "status": status,
    })

    def execute(_token):
        if status == "incomplete":
            raise recovery.MaintenanceError("Synthetic maintenance failure")
        return {"status": status}

    monkeypatch.setattr(recovery, "execute", execute)
    launches = []
    monkeypatch.setattr(subprocess, "Popen", lambda args, **kwargs: launches.append((args, kwargs)))
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    result = CliRunner().invoke(cli.installation_maintenance_cmd, ["execute"], input=json.dumps({
        "authorization": "synthetic fixture", "parent_pid": 123, "open_result": open_result,
    }))
    assert result.exit_code == (1 if status == "incomplete" else 0), result.output
    assert environment == before
    kernel.WaitForSingleObject.assert_called_once_with(123, 60000)
    kernel.CloseHandle.assert_called_once_with(123)
    assert len(launches) == int(open_result)
    if open_result:
        args, kwargs = launches[0]
        target = retained if status == "incomplete" else installed
        assert args == [str(target / "maverick-desktop.exe"), "--maintenance-result", "a" * 32]
        assert kwargs["env"] == {**before, "PYINSTALLER_RESET_ENVIRONMENT": "1"}
        assert kwargs["env"] is not environment
        assert all(kwargs[name] == subprocess.DEVNULL for name in ("stdin", "stdout", "stderr"))
        assert kwargs["creationflags"] == 0x08000000


def test_native_repair_authorization_protocol_has_a_fixed_actor_and_confirmation(
    monkeypatch,
):
    cli = importlib.import_module("maverick.cli")
    recovery = importlib.import_module("maverick.installation_recovery")
    calls = []

    def authorize_repair(**kwargs):
        calls.append(kwargs)
        return {"id": "a" * 32, "operation": "repair"}

    monkeypatch.setattr(recovery, "authorize_repair", authorize_repair)
    result = CliRunner().invoke(
        cli.installation_maintenance_cmd,
        ["authorize-repair"],
        input=json.dumps({"confirm": True}),
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"id": "a" * 32, "operation": "repair"}
    assert calls == [{
        "actor": "native-desktop-repair",
        "confirm_all_workspaces": True,
    }]


def test_native_repair_capability_and_authorization_forward_the_exact_signed_identity(
    monkeypatch,
):
    cli = importlib.import_module("maverick.cli")
    recovery = importlib.import_module("maverick.installation_recovery")
    identity = {
        "runtime_sha256": "a" * 64,
        "installer_sha256": "b" * 64,
        "public_key": "installed-public-key",
        "version": "1.2.3",
    }
    capability_calls = []
    authorization_calls = []
    monkeypatch.setattr(
        recovery,
        "repair_capability",
        lambda **kwargs: capability_calls.append(kwargs) or {"compatible": True},
    )
    monkeypatch.setattr(
        recovery,
        "authorize_repair",
        lambda **kwargs: authorization_calls.append(kwargs) or {"operation": "repair"},
    )

    result = CliRunner().invoke(
        cli.installation_maintenance_cmd,
        ["repair-capability"],
        input=json.dumps(identity),
    )
    assert result.exit_code == 0, result.output
    assert capability_calls == [{
        "expected_runtime_sha256": "a" * 64,
        "expected_installer_sha256": "b" * 64,
        "expected_public_key": "installed-public-key",
        "expected_version": "1.2.3",
    }]

    result = CliRunner().invoke(
        cli.installation_maintenance_cmd,
        ["authorize-repair"],
        input=json.dumps({"confirm": True, **identity}),
    )
    assert result.exit_code == 0, result.output
    assert authorization_calls == [{
        "actor": "native-desktop-repair",
        "confirm_all_workspaces": True,
        **capability_calls[0],
    }]
