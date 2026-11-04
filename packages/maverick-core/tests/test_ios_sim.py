"""Tests for the iOS Simulator tool (maverick.tools.ios_sim)."""
from __future__ import annotations

import platform
from unittest.mock import MagicMock

# ---------- iOS Sim tool ----------

def test_ios_only_macos(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    from maverick.tools.ios_sim import ios_sim
    out = ios_sim().fn({"op": "list_devices"})
    assert "macOS" in out


def test_ios_missing_xcrun(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.ios_sim import ios_sim
    out = ios_sim().fn({"op": "list_devices"})
    assert "xcrun not found" in out


def test_ios_list_devices(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/xcrun")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: MagicMock(
            returncode=0,
            stdout="-- iOS 17.0 --\n  iPhone 15 (ABC-123) (Booted)\n",
            stderr="",
        ),
    )
    from maverick.tools.ios_sim import ios_sim
    out = ios_sim().fn({"op": "list_devices", "state": "booted"})
    assert "iPhone 15" in out


def test_ios_install_requires_app(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/xcrun")
    from maverick.tools.ios_sim import ios_sim
    out = ios_sim().fn({"op": "install", "device_id": "ABC"})
    assert "requires" in out and "app_path" in out


def test_ios_boot_calls_simctl(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/xcrun")
    captured = {"cmd": None}

    def _run(cmd, *a, **k):
        captured["cmd"] = cmd
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    from maverick.tools.ios_sim import ios_sim
    out = ios_sim().fn({"op": "boot", "device_id": "ABC-123"})
    assert "booted ABC-123" in out
    assert "simctl" in captured["cmd"] and "boot" in captured["cmd"]
