"""Tests for the embedded_device tool (JTAG via OpenOCD + I2C protocol layer).

Offline: the openocd binary is faked via shutil.which, the shell is a
recording sandbox (asserts the argv that would run, never executing it), and
I2C goes through an injected fake bus. The [embedded] allow_flash knob is
exercised via a temp config file (MAVERICK_CONFIG).
"""
from __future__ import annotations

import shlex
from types import SimpleNamespace

import pytest
from maverick.tools.embedded_device import embedded_device, parse_dump


class RecordingSandbox:
    """Routes sandbox_run through .exec and records the shell string."""

    def __init__(self, workdir, *, exit_code=0, stdout="", stderr=""):
        self.workdir = str(workdir)
        self._res = SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=stderr)
        self.commands: list[str] = []

    def exec(self, cmd, timeout=None):
        self.commands.append(cmd)
        return self._res


@pytest.fixture
def have_openocd(monkeypatch):
    monkeypatch.setattr(
        "maverick.tools.embedded_device.shutil.which",
        lambda name: "/usr/bin/openocd" if name == "openocd" else None,
    )


@pytest.fixture
def no_config(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "missing.toml"))


@pytest.fixture
def flash_enabled(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[embedded]\nallow_flash = true\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


# ---------- JTAG ----------


def test_openocd_missing(monkeypatch, no_config):
    monkeypatch.setattr("maverick.tools.embedded_device.shutil.which", lambda name: None)
    t = embedded_device()
    out = t.fn({"op": "jtag_halt", "target": "target/stm32f4x.cfg"})
    assert out == "ERROR: openocd not found — install OpenOCD and connect a probe"


def test_sandbox_127_maps_to_missing(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path, exit_code=127, stderr="sh: openocd: not found")
    t = embedded_device(sandbox=sb)
    out = t.fn({"op": "jtag_halt", "target": "target/stm32f4x.cfg"})
    assert out.startswith("ERROR: openocd not found")


def test_halt_command_line(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path, stderr="target halted")
    t = embedded_device(sandbox=sb)
    out = t.fn({
        "op": "jtag_halt",
        "interface": "interface/stlink.cfg",
        "target": "target/stm32f4x.cfg",
    })
    assert len(sb.commands) == 1
    argv = shlex.split(sb.commands[0])
    assert argv[0] == "openocd"
    assert argv[1:5] == ["-f", "interface/stlink.cfg", "-f", "target/stm32f4x.cfg"]
    assert "halt" in argv and "init" in argv and "shutdown" in argv
    assert out == "target halted"


def test_resume_command_line(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    t.fn({"op": "jtag_resume", "target": "target/stm32f4x.cfg"})
    assert "resume" in shlex.split(sb.commands[0])


def test_read_mem_command_bounded(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path, stderr="0x20000000: deadbeef")
    t = embedded_device(sandbox=sb)
    out = t.fn({
        "op": "jtag_read_mem", "target": "target/stm32f4x.cfg",
        "address": "0x20000000", "words": 16,
    })
    assert "mdw 0x20000000 16" in sb.commands[0]
    assert "deadbeef" in out

    out = t.fn({
        "op": "jtag_read_mem", "target": "target/stm32f4x.cfg",
        "address": "0x20000000", "words": 99999,
    })
    assert out.startswith("ERROR") and "out of range" in out
    assert len(sb.commands) == 1  # bound rejected before the shell


def test_read_mem_requires_valid_address(have_openocd, no_config):
    t = embedded_device()
    out = t.fn({"op": "jtag_read_mem", "target": "t.cfg", "address": "lots"})
    assert out.startswith("ERROR") and "address" in out


def test_reset_gated_by_default(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    out = t.fn({"op": "jtag_reset", "target": "target/stm32f4x.cfg"})
    assert out.startswith("ERROR: flashing disabled; set [embedded] allow_flash = true")
    assert sb.commands == []  # never reached the shell


def test_reset_runs_when_enabled(tmp_path, have_openocd, flash_enabled):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    t.fn({"op": "jtag_reset", "target": "target/stm32f4x.cfg", "halt": True})
    assert "reset halt" in sb.commands[0]


def test_flash_write_gated_by_default(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    out = t.fn({
        "op": "jtag_flash_write", "target": "target/stm32f4x.cfg",
        "file": "fw.bin", "address": "0x08000000",
    })
    assert out.startswith("ERROR: flashing disabled; set [embedded] allow_flash = true")
    assert sb.commands == []


def test_flash_write_command_line(tmp_path, have_openocd, flash_enabled):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    out = t.fn({
        "op": "jtag_flash_write", "target": "target/stm32f4x.cfg",
        "file": "fw.bin", "address": "0x08000000",
    })
    cmd = sb.commands[0]
    expected = (tmp_path / "fw.bin").resolve().as_posix()
    assert f"program {expected} verify 0x8000000" in cmd
    assert not out.startswith("ERROR")


def test_flash_path_confined_to_workspace(tmp_path, have_openocd, flash_enabled):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    out = t.fn({
        "op": "jtag_flash_write", "target": "target/stm32f4x.cfg",
        "file": "../../boot/vmlinuz",
    })
    assert out.startswith("ERROR") and "escapes the workspace" in out
    assert sb.commands == []


def test_cfg_rejects_traversal_and_flags(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path)
    t = embedded_device(sandbox=sb)
    for bad in ("../evil.cfg", "/etc/passwd.cfg", "-c shutdown.cfg", "x.cfg; rm -rf"):
        out = t.fn({"op": "jtag_halt", "target": bad})
        assert out.startswith("ERROR"), bad
    assert sb.commands == []


def test_target_required(have_openocd, no_config):
    t = embedded_device()
    out = t.fn({"op": "jtag_halt"})
    assert out.startswith("ERROR") and "target config is required" in out


def test_nonzero_exit_surfaces_stderr(tmp_path, have_openocd, no_config):
    sb = RecordingSandbox(tmp_path, exit_code=1, stderr="Error: open failed (no probe?)")
    t = embedded_device(sandbox=sb)
    out = t.fn({"op": "jtag_halt", "target": "target/stm32f4x.cfg"})
    assert out.startswith("ERROR: openocd exited 1") and "open failed" in out


# ---------- I2C ----------


class FakeBus:
    def __init__(self, response=b""):
        self.calls: list[tuple[int, bytes, int]] = []
        self.response = response

    def __call__(self, addr, write_bytes, read_len):
        self.calls.append((addr, bytes(write_bytes), read_len))
        return self.response[:read_len]


def test_i2c_read_register(no_config):
    bus = FakeBus(response=bytes(range(64)))
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_read", "addr": "0x68", "register": "0x75", "length": 2})
    assert bus.calls == [(0x68, b"\x75", 2)]
    assert out == "read 2 byte(s) from 0x68: 00 01"


def test_i2c_read_no_register(no_config):
    bus = FakeBus(response=b"\xab")
    t = embedded_device(bus=bus)
    t.fn({"op": "i2c_read", "addr": "0x40", "length": 1})
    assert bus.calls == [(0x40, b"", 1)]


def test_i2c_write_builds_transaction(no_config):
    bus = FakeBus()
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_write", "addr": "0x68", "register": "0x6b", "data": "0a ff"})
    assert bus.calls == [(0x68, b"\x6b\x0a\xff", 0)]
    assert out == "wrote 3 byte(s) to 0x68"


def test_i2c_write_rejects_bad_hex(no_config):
    bus = FakeBus()
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_write", "addr": "0x68", "data": "zz"})
    assert out.startswith("ERROR") and "not valid hex" in out
    assert bus.calls == []


def test_i2c_addr_range_enforced(no_config):
    bus = FakeBus()
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_read", "addr": "0xf0", "length": 1})
    assert out.startswith("ERROR") and "out of range" in out


def test_i2c_length_bounded(no_config):
    bus = FakeBus()
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_read", "addr": "0x10", "length": 4096})
    assert out.startswith("ERROR") and "out of range" in out


def test_i2c_dump_renders_table(no_config):
    bus = FakeBus(response=bytes(range(32)))
    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_dump", "addr": "0x50", "length": 32})
    assert bus.calls == [(0x50, b"\x00", 32)]
    assert "00: 00 01 02" in out and "\n10: 10 11 12" in out


def test_i2c_missing_smbus2_is_actionable(no_config, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "smbus2", None)  # forces ImportError
    t = embedded_device()  # no injected bus -> tries the smbus2 adapter
    out = t.fn({"op": "i2c_read", "addr": "0x68", "length": 1})
    assert out.startswith("ERROR") and "smbus2 not installed" in out
    assert "packages/maverick-core[i2c]" in out


def test_i2c_bus_failure_is_error_string(no_config):
    def bus(addr, write_bytes, read_len):
        raise OSError(121, "Remote I/O error")

    t = embedded_device(bus=bus)
    out = t.fn({"op": "i2c_read", "addr": "0x68", "length": 1})
    assert out.startswith("ERROR: embedded request failed: OSError")


def test_parse_dump_roundtrip(no_config):
    text = (
        "     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n"
        "00: 12 34 56 78 XX bc de f0    .4Vx....\n"
        "10: 00 01 02 03\n"
        "ignore this prose line\n"
    )
    assert parse_dump(text) == bytes([0x12, 0x34, 0x56, 0x78, 0xBC, 0xDE, 0xF0, 0, 1, 2, 3])
    t = embedded_device()
    out = t.fn({"op": "i2c_parse_dump", "text": text})
    assert out.startswith("parsed 11 byte(s)") and "12 34 56 78 bc" in out


def test_parse_dump_requires_text(no_config):
    t = embedded_device()
    assert t.fn({"op": "i2c_parse_dump"}).startswith("ERROR")
    assert t.fn({"op": "i2c_parse_dump", "text": "no hex here"}).startswith("ERROR")


# ---------- dispatch ----------


def test_unknown_op_and_missing_op(no_config):
    t = embedded_device()
    assert t.fn({"op": "frobnicate"}).startswith("ERROR: unknown op")
    assert t.fn({}).startswith("ERROR: op is required")


def test_never_raises(no_config, have_openocd):
    t = embedded_device()
    for args in (
        {"op": "jtag_read_mem"},
        {"op": "i2c_read"},
        {"op": "i2c_write", "addr": None, "data": None},
        {"op": "jtag_flash_write"},
    ):
        out = t.fn(args)
        assert isinstance(out, str) and out.startswith("ERROR"), args
