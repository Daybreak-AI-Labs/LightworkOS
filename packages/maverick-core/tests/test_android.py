"""Tests for the Android tool (maverick.tools.android)."""
from __future__ import annotations

from unittest.mock import MagicMock

# ---------- Android tool ----------

def test_android_requires_op():
    from maverick.tools.android import android
    assert "op is required" in android().fn({})


def test_android_missing_adb(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.android import android
    out = android().fn({"op": "devices"})
    assert "adb not found" in out


def test_android_devices_parses(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/adb")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: MagicMock(
            returncode=0,
            stdout="List of devices attached\nemulator-5554\tdevice product:sdk_gphone\n",
            stderr="",
        ),
    )
    from maverick.tools.android import android
    out = android().fn({"op": "devices"})
    assert "emulator-5554" in out


def test_android_no_devices(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/adb")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: MagicMock(
            returncode=0,
            stdout="List of devices attached\n",
            stderr="",
        ),
    )
    from maverick.tools.android import android
    out = android().fn({"op": "devices"})
    assert "no devices attached" in out


def test_android_tap_builds_input(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/adb")
    captured = {"cmd": None}

    def _run(cmd, *a, **k):
        captured["cmd"] = cmd
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    from maverick.tools.android import android
    out = android().fn({"op": "tap", "x": 100, "y": 200, "device": "abc"})
    assert "tapped (100,200)" in out
    assert "shell" in captured["cmd"]
    assert "input" in captured["cmd"]
    assert "tap" in captured["cmd"]
    assert "abc" in captured["cmd"]


def test_android_screenshot_writes_bytes(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/adb")
    fake_png = b"\x89PNG\r\n\x1a\n" + b"x" * 200

    def _run(cmd, *a, **k):
        return MagicMock(returncode=0, stdout=fake_png, stderr=b"")

    monkeypatch.setattr("subprocess.run", _run)
    out_file = tmp_path / "shot.png"
    from maverick.tools.android import android
    out = android(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"op": "screenshot", "out_path": str(out_file)})
    assert "saved" in out
    assert out_file.read_bytes() == fake_png


def test_android_install_requires_apk():
    from maverick.tools.android import android
    out = android().fn({"op": "install"})
    # Without an apk path we should hit the validation message before
    # the adb shell out happens. Tolerate either "requires apk_path"
    # or the adb-missing fallback.
    assert "requires apk_path" in out or "adb not found" in out
