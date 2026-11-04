"""Exercise real onefile cleanup across the native-result process boundary."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

FIXTURE = Path(__file__).with_name("fixtures") / "frozen_relaunch.py"
PAYLOAD = "Synthetic retained-helper relaunch: freshly extracted payload."


@pytest.mark.skipif(os.name != "nt", reason="Windows onefile bootloader lifecycle regression")
def test_frozen_helper_relaunch_requires_reset_before_the_independent_process(tmp_path):
    if importlib.util.find_spec("PyInstaller") is None:
        pytest.skip("PyInstaller is required; Windows customer packaging installs it explicitly")
    (tmp_path / "proof.txt").write_text(PAYLOAD, encoding="utf-8")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("_PYI_") and key != "PYINSTALLER_RESET_ENVIRONMENT"}
    log = tmp_path / "build.log"
    with log.open("wb") as output:
        build = subprocess.run(
            [sys.executable, "-I", "-m", "PyInstaller", "--clean", "--noconfirm",
             "--onefile", "--console", "--name", "lifecycle", "--add-data", "proof.txt:.",
             "--distpath", "dist", "--workpath", "build", "--specpath", ".", str(FIXTURE)],
            cwd=tmp_path, env=environment, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    assert build.returncode == 0, log.read_text(encoding="utf-8", errors="replace")[-8000:]
    executable = tmp_path / "dist" / "lifecycle.exe"
    reports = {}
    for mode in ("legacy", "reset"):
        output = tmp_path / mode
        output.mkdir()
        initial = subprocess.run(
            [str(executable), "launch", mode, str(output), sys.executable, str(FIXTURE)],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        assert initial.returncode == 0, initial.stderr.decode("utf-8", errors="replace")[-4096:]
        deadline = time.monotonic() + 55
        result = output / "result.json"
        while not result.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert result.is_file(), f"The {mode} mediator did not finish within its bounded lifetime"
        report = json.loads(result.read_text(encoding="utf-8"))
        original = json.loads((output / "initial.json").read_text(encoding="utf-8"))
        assert "error" not in report, report
        assert original["frozen"] and original["parent_environment_unchanged"]
        assert "PYINSTALLER_RESET_ENVIRONMENT" not in original["initial_environment"]
        assert original["initial_environment"]["_PYI_ARCHIVE_FILE"] == str(executable)
        assert report["mediator_frozen"] is False
        assert report["original_extraction_deleted"] is True
        assert report["inherited_environment"]["_PYI_APPLICATION_HOME_DIR"] == original["extraction"]
        assert report["inherited_environment"]["_PYI_ARCHIVE_FILE"] == str(executable)
        reports[mode] = report
    old, reset = reports["legacy"], reports["reset"]
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in old["inherited_environment"]
    assert old["returncode"] != 0 and "PYI-" in old["stderr"], old
    assert not (tmp_path / "legacy" / "child.json").exists()
    assert reset["inherited_environment"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert reset["returncode"] == 0 and "RELAUNCH_OK" in reset["stdout"], reset
    child = json.loads((tmp_path / "reset" / "child.json").read_text(encoding="utf-8"))
    assert child["frozen"] and child["extraction_exists"]
    assert child["extraction"] != reset["original_extraction"]
    assert child["payload"] == PAYLOAD
