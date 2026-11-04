"""Hardware sensor tool: psutil (faked), /sys/class/thermal fallback, injected
reader; never fabricates a reading. Offline."""
from __future__ import annotations

import sys
import types

from maverick.tools import hardware_sensors as hs_mod
from maverick.tools.hardware_sensors import hardware_sensors


def _entry(**kw):
    return types.SimpleNamespace(**kw)


def _install_fake_psutil(monkeypatch, *, temps=None, fans=None, battery=None,
                         drop=()):
    mod = types.ModuleType("psutil")
    mod.sensors_temperatures = lambda: temps or {}
    mod.sensors_fans = lambda: fans or {}
    mod.sensors_battery = lambda: battery
    for name in drop:  # platforms without the API (e.g. macOS has no fans())
        delattr(mod, name)
    monkeypatch.setitem(sys.modules, "psutil", mod)


def test_injected_reader_full_read():
    def reader():
        return {"temperatures": ["cpu: 45.0 C"], "fans": ["fan1: 1200 RPM"],
                "battery": "88% (on battery)"}

    out = hardware_sensors(reader).fn({"op": "read"})
    assert "temperatures:\n  cpu: 45.0 C" in out
    assert "fans:\n  fan1: 1200 RPM" in out
    assert "battery: 88% (on battery)" in out


def test_injected_reader_op_filtering():
    def reader():
        return {"temperatures": ["cpu: 45.0 C"], "fans": [],
                "battery": "88% (plugged in)"}

    t = hardware_sensors(reader)
    thermal = t.fn({"op": "thermal"})
    assert "cpu: 45.0 C" in thermal and "battery" not in thermal
    battery = t.fn({"op": "battery"})
    assert battery == "battery: 88% (plugged in)"


def test_unknown_op_is_error():
    out = hardware_sensors(dict).fn({"op": "explode"})
    assert out.startswith("ERROR: unknown op")
    assert hardware_sensors(dict).fn({}).startswith("ERROR")


def test_psutil_temps_fans_battery(monkeypatch):
    _install_fake_psutil(
        monkeypatch,
        temps={"coretemp": [_entry(label="Package id 0", current=45.0,
                                   high=80.0, critical=100.0)],
               "acpitz": [_entry(label="", current=40.0, high=None, critical=None)]},
        fans={"dell_smm": [_entry(label="cpu_fan", current=2700)]},
        battery=_entry(percent=87.0, power_plugged=False, secsleft=7530),
    )
    out = hardware_sensors().fn({"op": "read"})
    assert "coretemp/Package id 0: 45.0 C (high 80.0, critical 100.0)" in out
    assert "acpitz/temp: 40.0 C" in out  # empty label gets a placeholder
    assert "dell_smm/cpu_fan: 2700 RPM" in out
    assert "battery: 87% (on battery), ~2h05m remaining" in out


def test_psutil_battery_plugged_no_eta(monkeypatch):
    _install_fake_psutil(
        monkeypatch,
        battery=_entry(percent=100.0, power_plugged=True, secsleft=-2),
    )
    out = hardware_sensors().fn({"op": "battery"})
    assert out == "battery: 100% (plugged in)"  # negative secsleft never shown


def test_no_psutil_sysfs_thermal_fallback(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)
    zone = tmp_path / "thermal_zone0"
    zone.mkdir()
    (zone / "type").write_text("x86_pkg_temp\n", encoding="utf-8")
    (zone / "temp").write_text("46500\n", encoding="utf-8")
    monkeypatch.setattr(hs_mod, "_SYS_THERMAL", tmp_path)
    out = hardware_sensors().fn({"op": "read"})
    assert "x86_pkg_temp: 46.5 C" in out
    # Fans/battery need psutil: labeled unavailable with the install hint.
    assert "fans: unavailable on this host (psutil not installed" in out
    assert "battery: unavailable on this host (psutil not installed" in out
    assert "packages/maverick-core[sensors]" in out


def test_sysfs_fallback_when_psutil_has_no_temps(tmp_path, monkeypatch):
    _install_fake_psutil(monkeypatch, temps={}, fans={}, battery=None)
    zone = tmp_path / "thermal_zone0"
    zone.mkdir()
    (zone / "type").write_text("soc\n", encoding="utf-8")
    (zone / "temp").write_text("51000\n", encoding="utf-8")
    monkeypatch.setattr(hs_mod, "_SYS_THERMAL", tmp_path)
    out = hardware_sensors().fn({"op": "thermal"})
    assert "soc: 51.0 C" in out


def test_sysfs_skips_unreadable_zones(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)
    good = tmp_path / "thermal_zone1"
    good.mkdir()
    (good / "type").write_text("good", encoding="utf-8")
    (good / "temp").write_text("30000", encoding="utf-8")
    bad = tmp_path / "thermal_zone0"
    bad.mkdir()
    (bad / "type").write_text("bad", encoding="utf-8")
    (bad / "temp").write_text("garbage", encoding="utf-8")  # not millidegrees
    monkeypatch.setattr(hs_mod, "_SYS_THERMAL", tmp_path)
    out = hardware_sensors().fn({"op": "thermal"})
    assert "good: 30.0 C" in out and "bad" not in out


def test_nothing_available_never_fabricates(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)
    monkeypatch.setattr(hs_mod, "_SYS_THERMAL", tmp_path / "empty")
    out = hardware_sensors().fn({"op": "read"})
    assert "temperatures: unavailable on this host" in out
    assert "fans: unavailable on this host" in out
    assert "battery: unavailable on this host" in out
    assert "RPM" not in out and " C" not in out and "%" not in out


def test_psutil_platform_without_sensor_apis(monkeypatch):
    # macOS psutil has no sensors_temperatures/sensors_fans at all.
    _install_fake_psutil(
        monkeypatch,
        battery=_entry(percent=55.0, power_plugged=False, secsleft=-1),
        drop=("sensors_temperatures", "sensors_fans"),
    )
    out = hardware_sensors().fn({"op": "read"})
    assert "temperatures: unavailable on this host" in out
    assert "fans: unavailable on this host" in out
    # psutil IS installed: no misleading install hint.
    assert "packages/maverick-core[sensors]" not in out
    assert "battery: 55% (on battery)" in out


def test_tool_metadata_and_schema():
    t = hardware_sensors()
    assert t.name == "hardware_sensors"
    assert t.parallel_safe is True  # read-only
    assert t.input_schema["properties"]["op"]["enum"] == ["read", "thermal", "battery"]
    assert "never invented" in t.description


def _registry_names(tmp_path, monkeypatch, config: str = ""):
    config_path = tmp_path / "config.toml"
    if config:
        config_path.write_text(config, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))

    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    return set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())


def test_base_registry_hardware_sensors_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_ENABLE_HARDWARE_SENSORS", raising=False)
    assert "hardware_sensors" not in _registry_names(tmp_path, monkeypatch)

    assert "hardware_sensors" in _registry_names(
        tmp_path, monkeypatch, "[tools]\nhardware_sensors = true\n"
    )

    monkeypatch.setenv("MAVERICK_ENABLE_HARDWARE_SENSORS", "1")
    assert "hardware_sensors" in _registry_names(tmp_path, monkeypatch)


def test_psutil_import_ignores_current_directory(tmp_path, monkeypatch):
    marker = tmp_path / "HOST_CODE_EXECUTED.txt"
    (tmp_path / "psutil.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n"
        "def sensors_battery():\n"
        "    return None\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "psutil", raising=False)

    hs_mod._psutil()
    assert not marker.exists()
