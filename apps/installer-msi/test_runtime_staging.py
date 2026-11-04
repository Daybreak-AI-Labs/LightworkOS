"""Local staging regressions; the MZ fixture is not an installable runtime."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location("runtime_staging", Path(__file__).with_name("stage_customer.py"))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

COHORT = {"version": "1.2.3", "packages": [{"distribution": "maverick"}]}


@pytest.fixture(autouse=True)
def synthetic_parent_environment(monkeypatch):
    # Failed assertion introspection must never render real host credentials.
    allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "PATH",
               "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"}
    for key in tuple(os.environ):
        if key.upper() not in allowed:
            monkeypatch.delenv(key)


@pytest.fixture
def runtime(tmp_path):
    binary = tmp_path / "runtime.exe"
    binary.write_bytes(b"MZ-inert-runtime-fixture")
    return binary


def complete(*_args, **_kwargs):
    return SimpleNamespace(stdout="maverick 1.2.3\n")


def test_runtime_checks_do_not_inherit_operator_paths_or_credentials(runtime, tmp_path, monkeypatch):
    operator = tmp_path / "operator"
    operator.mkdir()
    forbidden = ("MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_CLIENT_ID",
                 "MAVERICK_KEY_FILE", "LIGHTWORK_CHANNEL", "OPENAI_API_KEY", "AWS_PROFILE",
                 "PYTHONPATH", "PYTHONHOME", "PYINSTALLER_CONFIG_DIR", "HTTP_PROXY")
    for key in forbidden:
        monkeypatch.setenv(key, str(operator / "synthetic-value"))
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR",
                "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "PATH"):
        monkeypatch.setenv(key, str(operator))
    # Exercise the same fresh-process lookup that the workflow receives rather
    # than reusing pytest's already-cached host temporary directory.
    monkeypatch.setattr(stage.tempfile, "tempdir", None)
    observed = []

    def probe(_command, **kwargs):
        environment = kwargs["env"]
        assert not set(forbidden).difference({"MAVERICK_CONFIG"}) & set(environment)
        home = Path(environment["MAVERICK_HOME"])
        assert Path(environment["MAVERICK_CONFIG"]).is_relative_to(home)
        assert Path(environment["MAVERICK_CONFIG"]).is_file()
        work = Path(kwargs["cwd"])
        assert work == home.parent
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR",
                    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
            assert Path(environment[key]).is_dir()
            assert Path(environment[key]).is_relative_to(work)
        assert str(operator) not in environment["PATH"].split(os.pathsep)
        assert environment["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
        observed.append(home.parent)
        return complete()

    stage.verify_runtime(runtime, COHORT, run=probe)
    assert len(observed) == 4
    assert len(set(observed)) == 1
    assert not observed[0].exists()


def test_real_child_config_resolution_uses_only_synthetic_staging_home(runtime, tmp_path, monkeypatch):
    """A real Python child checks isolation; its version response is a test double."""
    operator = tmp_path / "operator.toml"
    operator.write_text('[agent]\nname = "outside-canary"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(operator))
    monkeypatch.setenv("MAVERICK_CONFIG_OVERLAY", str(operator))
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-staging-canary")  # pragma: allowlist secret
    script = (
        "import os; from pathlib import Path; from maverick.config import config_path, load_config; "
        "assert config_path().is_relative_to(Path(os.environ['MAVERICK_HOME'])); "
        "assert 'OPENAI_API_KEY' not in os.environ; assert 'MAVERICK_CONFIG_OVERLAY' not in os.environ; "
        "assert 'outside-canary' not in repr(load_config()); print('maverick 1.2.3')"
    )

    def probe(_command, **kwargs):
        return subprocess.run([sys.executable, "-I", "-c", script], **kwargs)

    stage.verify_runtime(runtime, COHORT, run=probe)
    assert operator.read_text(encoding="utf-8") == '[agent]\nname = "outside-canary"\n'


@pytest.mark.parametrize("changed_after", [1, 2, 3, 4])
def test_runtime_replaced_after_probe_cannot_receive_later_digest(runtime, changed_after):
    calls = []

    def replace_after_probe(command, **_kwargs):
        calls.append(command)
        if len(calls) == changed_after:
            runtime.write_bytes(b"MZ-replacement-not-tested-by-version")
        return complete()

    with pytest.raises(ValueError, match="changed during verification"):
        stage.verify_runtime(runtime, COHORT, run=replace_after_probe)
    assert len(calls) == changed_after


def test_runtime_digest_is_streamed_and_matches_probe_bytes(runtime, monkeypatch):
    expected = hashlib.sha256(runtime.read_bytes()).hexdigest()

    def refuse_whole_file(_self):
        raise AssertionError("runtime hashing must not allocate the whole executable")

    monkeypatch.setattr(Path, "read_bytes", refuse_whole_file)
    assert stage.verify_runtime(runtime, COHORT, run=complete) == {
        "sha256": expected, "bytes": runtime.stat().st_size,
    }


@pytest.mark.parametrize("version", ["256.0.0", "0.256.0", "1.2.65536", "1.2.-1", "01.2.3", "", "1.2.٣"])
def test_invalid_msi_version_fails_before_runtime_probe_or_output(runtime, tmp_path, monkeypatch, version):
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: pytest.fail("invalid package must not execute runtime"))
    key = base64.b64encode(b"untrusted comment: synthetic\n" + base64.b64encode(b"Ed" + bytes(40))).decode()
    output = tmp_path / "stage"
    with pytest.raises(ValueError, match="Windows desktop package version"):
        stage.stage(runtime, output, "https://updates.example.test/stable.json", key, fixture_version=version)
    assert not output.exists()


def test_highest_valid_msi_fixture_version_remains_explicitly_synthetic(runtime, tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: stage.runtime_metadata(runtime))
    key = base64.b64encode(b"untrusted comment: synthetic\n" + base64.b64encode(b"Ed" + bytes(40))).decode()
    path = stage.stage(runtime, tmp_path / "stage", "https://updates.example.test/stable.json", key,
                       fixture_version="255.255.65535")
    inventory = json.loads(path.with_name("runtime-inventory.json").read_text(encoding="utf-8"))
    assert inventory["version"] == "255.255.65535"
    assert inventory["acceptance_fixture"] is True
    assert inventory["publisher_signature_verified"] is False
    assert inventory["runtime"] == stage.runtime_metadata(runtime)


def test_highest_patch_base_fails_before_runtime_probe_or_output(runtime, tmp_path, monkeypatch):
    monkeypatch.setattr(stage.tomllib, "loads", lambda _: {**COHORT, "version": "1.2.65535"})
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: pytest.fail("invalid base must not execute runtime"))
    key = base64.b64encode(b"untrusted comment: synthetic\n" + base64.b64encode(b"Ed" + bytes(40))).decode()
    output = tmp_path / "stage"
    with pytest.raises(ValueError, match="patch must be below 65535"):
        stage.stage(runtime, output, "https://updates.example.test/stable.json", key)
    assert not output.exists()


def test_changed_staged_copy_never_publishes_config_or_inventory(runtime, tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "verify_runtime", lambda *_: stage.runtime_metadata(runtime))
    copy = stage.shutil.copyfile

    def replace_during_copy(source, destination):
        copy(source, destination)
        destination.write_bytes(b"MZ-unverified-replacement")

    monkeypatch.setattr(stage.shutil, "copyfile", replace_during_copy)
    key = base64.b64encode(b"untrusted comment: synthetic\n" + base64.b64encode(b"Ed" + bytes(40))).decode()
    output = tmp_path / "stage"
    with pytest.raises(ValueError, match="changed during copy"):
        stage.stage(runtime, output, "https://updates.example.test/stable.json", key)
    assert not (output / "tauri.customer.json").exists()
    assert not (output / "runtime-inventory.json").exists()


def test_isolation_directory_is_removed_after_probe_failure(runtime):
    observed = []

    def fail(_command, **kwargs):
        observed.append(Path(kwargs["env"]["MAVERICK_HOME"]))
        raise subprocess.CalledProcessError(1, "synthetic-check")

    with pytest.raises(subprocess.CalledProcessError):
        stage.verify_runtime(runtime, COHORT, run=fail)
    assert not observed[0].exists()
