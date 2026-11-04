"""Embedded serial tool: port guard, write/read/query over a faked pyserial."""
from __future__ import annotations

import sys
import types

from maverick.tools.serial_tool import _valid_port, serial_tool


def _install_fake_serial(monkeypatch, *, read_data=b"", ports=()):
    calls: dict = {"opened": [], "written": []}

    class Serial:
        def __init__(self, port, baud, timeout=None):
            calls["opened"].append((port, baud, timeout))
            self._port = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def write(self, payload):
            calls["written"].append(payload)
            return len(payload)

        def read(self, n):
            return read_data[:n]

    serial_mod = types.ModuleType("serial")
    serial_mod.Serial = Serial
    tools_mod = types.ModuleType("serial.tools")
    lp_mod = types.ModuleType("serial.tools.list_ports")
    lp_mod.comports = lambda: list(ports)
    tools_mod.list_ports = lp_mod
    serial_mod.tools = tools_mod
    monkeypatch.setitem(sys.modules, "serial", serial_mod)
    monkeypatch.setitem(sys.modules, "serial.tools", tools_mod)
    monkeypatch.setitem(sys.modules, "serial.tools.list_ports", lp_mod)
    return calls


def test_valid_port_guard():
    assert _valid_port("/dev/ttyUSB0")
    assert _valid_port("/dev/ttyACM0")
    assert _valid_port("COM3")
    assert _valid_port("/dev/cu.usbserial-1420")
    assert _valid_port("/dev/serial/by-id/usb-foo")
    assert not _valid_port("/dev/serial/by-id/../../pts/0")
    assert not _valid_port("/dev/serial/by-id/..")
    assert not _valid_port("/dev/serial/by-id/.")
    assert not _valid_port("/dev/serial/by-id/usb-foo/extra")
    assert not _valid_port("/etc/passwd")
    assert not _valid_port("/dev/sda")
    assert not _valid_port("-oProxyCommand=evil")
    assert not _valid_port("")


def test_missing_pyserial(monkeypatch):
    monkeypatch.setitem(sys.modules, "serial", None)
    out = serial_tool().fn({"op": "list_ports"})
    assert out.startswith("ERROR") and "pyserial not installed" in out


def test_list_ports(monkeypatch):
    p = types.SimpleNamespace(device="/dev/ttyUSB0", description="FTDI")
    _install_fake_serial(monkeypatch, ports=[p])
    out = serial_tool().fn({"op": "list_ports"})
    assert "/dev/ttyUSB0" in out and "FTDI" in out


def test_list_ports_empty(monkeypatch):
    _install_fake_serial(monkeypatch, ports=[])
    assert serial_tool().fn({"op": "list_ports"}) == "no serial ports found"


def test_write(monkeypatch):
    calls = _install_fake_serial(monkeypatch)
    out = serial_tool().fn({"op": "write", "port": "/dev/ttyUSB0",
                            "data": "M114", "baud": 250000})
    assert out.startswith("wrote ") and "/dev/ttyUSB0" in out
    assert calls["opened"][0][:2] == ("/dev/ttyUSB0", 250000)
    assert calls["written"][0] == b"M114\n"  # eol appended


def test_write_rejects_bad_port(monkeypatch):
    _install_fake_serial(monkeypatch)
    out = serial_tool().fn({"op": "write", "port": "/etc/shadow", "data": "x"})
    assert out.startswith("ERROR") and "invalid serial port" in out


def test_write_requires_data(monkeypatch):
    _install_fake_serial(monkeypatch)
    out = serial_tool().fn({"op": "write", "port": "/dev/ttyUSB0"})
    assert out.startswith("ERROR") and "requires data" in out


def test_read(monkeypatch):
    _install_fake_serial(monkeypatch, read_data=b"ok temp=21.5")
    out = serial_tool().fn({"op": "read", "port": "/dev/ttyACM0", "bytes": 64})
    assert "temp=21.5" in out


def test_read_no_data(monkeypatch):
    _install_fake_serial(monkeypatch, read_data=b"")
    assert serial_tool().fn({"op": "read", "port": "/dev/ttyACM0"}) == "(no data)"


def test_query_writes_then_reads(monkeypatch):
    calls = _install_fake_serial(monkeypatch, read_data=b"X:0 Y:0 Z:0")
    out = serial_tool().fn({"op": "query", "port": "/dev/ttyUSB0", "data": "M114"})
    assert "X:0" in out
    assert calls["written"][0] == b"M114\n"


def test_default_baud(monkeypatch):
    calls = _install_fake_serial(monkeypatch)
    serial_tool().fn({"op": "write", "port": "/dev/ttyUSB0", "data": "x"})
    assert calls["opened"][0][1] == 115200


def test_unknown_op(monkeypatch):
    _install_fake_serial(monkeypatch)
    assert serial_tool().fn({"op": "nope"}).startswith("ERROR: unknown op")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "serial" in names
