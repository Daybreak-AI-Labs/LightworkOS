"""Embedded-device tool — JTAG (via OpenOCD) and I2C for the OPERATOR'S OWN hardware.

This is dual-use hardware tooling: the same primitives that let an operator
debug their own board would let an agent poke at any board it can reach. The
tool is therefore deliberately narrow and explicit — every operation names its
exact target (config file, address, register); there is no scan, no
autodetect-and-flash, and the destructive operations (``jtag_flash_write``,
``jtag_reset``) are disabled until the operator opts in with
``[embedded] allow_flash = true`` in ``~/.maverick/config.toml``.

JTAG/SWD ops (mediated through the local ``openocd`` binary; the command line
is built here and executed through ``sandbox.exec()`` — never subprocess):
  - jtag_halt / jtag_resume      halt or resume the target core
  - jtag_reset                   reset the target (DESTRUCTIVE — gated)
  - jtag_read_mem                read a bounded memory region (mdw)
  - jtag_flash_write             program a workspace file (DESTRUCTIVE — gated)

I2C ops (a pure protocol layer over an injected bus seam
``bus(addr, write_bytes, read_len) -> bytes``; the default adapter
lazy-imports ``smbus2`` — the ``i2c`` extra — for /dev/i2c-*):
  - i2c_read                     write-then-read transaction (register read)
  - i2c_write                    write transaction (register write)
  - i2c_dump                     read a region and render an i2cdump-style table
  - i2c_parse_dump               parse an i2cdump-style hex table back to bytes

Auth: none. Requires the ``openocd`` binary (JTAG) or an I2C bus adapter.
All ops return strings; failures are "ERROR: ..." strings, never exceptions.
"""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)

# Bounds: a read of N words is bounded so a model can't ask for a gigabyte
# dump in one call; I2C transfers are bounded to one SMBus-ish block.
MAX_READ_WORDS = 1024
MAX_I2C_BYTES = 256

_FLASH_DISABLED = (
    "ERROR: flashing disabled; set [embedded] allow_flash = true "
    "in ~/.maverick/config.toml (destructive ops are opt-in)"
)
_OPENOCD_MISSING = "ERROR: openocd not found — install OpenOCD and connect a probe"

# OpenOCD -f arguments: either a name from OpenOCD's bundled script library
# ("target/stm32f4x.cfg", "interface/stlink.cfg") or a plain relative file in
# the workspace. Reject traversal, absolute paths, leading dashes (option
# injection) and shell/Tcl metacharacters.
_CFG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]*\.cfg$")

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "jtag_halt", "jtag_resume", "jtag_reset",
                "jtag_read_mem", "jtag_flash_write",
                "i2c_read", "i2c_write", "i2c_dump", "i2c_parse_dump",
            ],
        },
        "target": {
            "type": "string",
            "description": "OpenOCD target config, e.g. 'target/stm32f4x.cfg'",
        },
        "interface": {
            "type": "string",
            "description": "OpenOCD probe config, e.g. 'interface/stlink.cfg'",
        },
        "address": {
            "type": "string",
            "description": "memory/flash address, e.g. '0x08000000' (jtag_read_mem / jtag_flash_write)",
        },
        "words": {"type": "integer", "description": "32-bit words to read (jtag_read_mem, <=1024)"},
        "file": {"type": "string", "description": "workspace-relative image to flash (jtag_flash_write)"},
        "halt": {"type": "boolean", "description": "jtag_reset: halt after reset instead of run"},
        "addr": {"type": "string", "description": "7-bit I2C device address, e.g. '0x68'"},
        "register": {"type": "string", "description": "I2C register to address before the transfer"},
        "length": {"type": "integer", "description": "bytes to read (i2c_read / i2c_dump, <=256)"},
        "data": {"type": "string", "description": "hex bytes to write, e.g. '0a ff 01' (i2c_write)"},
        "bus_number": {"type": "integer", "description": "I2C bus number for /dev/i2c-N (default 1)"},
        "text": {"type": "string", "description": "i2cdump-style table to parse (i2c_parse_dump)"},
    },
    "required": ["op"],
}


# ---------- shared guards ----------


def _flash_allowed() -> bool:
    from ..config import load_config
    return bool((load_config() or {}).get("embedded", {}).get("allow_flash", False))


def _safe_path(sandbox, user_path: str) -> str:
    """Confine a model-supplied path to the sandbox workspace (ffmpeg pattern)."""
    if sandbox is None:
        if user_path.startswith("-"):
            raise ValueError(f"path {user_path!r} may not begin with '-'")
        return user_path
    workdir = Path(sandbox.workdir).resolve()
    candidate = (workdir / user_path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(f"path {user_path!r} escapes the workspace") from e
    # OpenOCD's command language treats backslash as an escape. Windows-native
    # paths therefore trip the injection guard below (or can be reinterpreted
    # by Tcl). Forward-slash absolute paths are accepted by Windows/OpenOCD and
    # preserve the already-verified workspace confinement.
    return candidate.as_posix()


def _safe_cfg(name: str, what: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError(f"{what} config is required (e.g. 'target/stm32f4x.cfg')")
    if ".." in name or not _CFG_RE.match(name):
        raise ValueError(f"invalid {what} config {name!r}: must be a relative *.cfg name")
    return name


def _parse_int(raw: Any, what: str, *, lo: int, hi: int) -> int:
    try:
        value = int(str(raw).strip(), 0)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be an integer (decimal or 0x hex), got {raw!r}") from None
    if not lo <= value <= hi:
        raise ValueError(f"{what} {value:#x} out of range [{lo:#x}, {hi:#x}]")
    return value


def _parse_hex_bytes(raw: str) -> bytes:
    tokens = re.split(r"[\s,]+", (raw or "").strip())
    cleaned = "".join(t[2:] if t.lower().startswith("0x") else t for t in tokens if t)
    if not cleaned:
        raise ValueError("data is required (hex bytes, e.g. '0a ff 01')")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"data {raw!r} is not valid hex") from None


# ---------- JTAG via OpenOCD ----------


def _openocd_argv(args: dict, commands: list[str]) -> list[str]:
    """Build the one-shot OpenOCD command line: configs, then -c commands."""
    argv = ["openocd"]
    iface = (args.get("interface") or "").strip()
    if iface:
        argv += ["-f", _safe_cfg(iface, "interface")]
    argv += ["-f", _safe_cfg(args.get("target") or "", "target")]
    for c in commands:
        argv += ["-c", c]
    return argv


def _run_openocd(sandbox, argv: list[str], *, timeout: float = 60.0) -> str:
    if shutil.which("openocd") is None:
        return _OPENOCD_MISSING
    from . import sandbox_run
    try:
        code, out, err = sandbox_run(sandbox, argv, timeout=timeout)
    except FileNotFoundError:
        return _OPENOCD_MISSING
    if code == 127:  # sh -c: command not found (sandbox PATH differs from host)
        return _OPENOCD_MISSING
    # OpenOCD logs to stderr, including successful reads.
    text = "\n".join(s for s in (out.strip(), err.strip()) if s)
    if code != 0:
        return f"ERROR: openocd exited {code}: {text[-800:]}"
    return text[-4000:] or "ok"


def _op_jtag_halt(args: dict, sandbox, bus) -> str:
    argv = _openocd_argv(args, ["init", "halt", "shutdown"])
    return _run_openocd(sandbox, argv)


def _op_jtag_resume(args: dict, sandbox, bus) -> str:
    argv = _openocd_argv(args, ["init", "resume", "shutdown"])
    return _run_openocd(sandbox, argv)


def _op_jtag_reset(args: dict, sandbox, bus) -> str:
    if not _flash_allowed():
        return _FLASH_DISABLED
    mode = "halt" if args.get("halt") else "run"
    argv = _openocd_argv(args, ["init", f"reset {mode}", "shutdown"])
    return _run_openocd(sandbox, argv)


def _op_jtag_read_mem(args: dict, sandbox, bus) -> str:
    # Deliberately does NOT auto-halt: reads must not silently change target
    # state. If the core requires a halt to read, call jtag_halt explicitly.
    address = _parse_int(args.get("address"), "address", lo=0, hi=0xFFFFFFFF)
    words = _parse_int(args.get("words") or 1, "words", lo=1, hi=MAX_READ_WORDS)
    argv = _openocd_argv(args, ["init", f"mdw {address:#x} {words}", "shutdown"])
    return _run_openocd(sandbox, argv)


def _op_jtag_flash_write(args: dict, sandbox, bus) -> str:
    if not _flash_allowed():
        return _FLASH_DISABLED
    raw = (args.get("file") or "").strip()
    if not raw:
        return "ERROR: jtag_flash_write requires file"
    path = _safe_path(sandbox, raw)
    # The path is embedded inside an OpenOCD Tcl command string; refuse
    # characters that would split or re-quote the Tcl word.
    if any(ch in path for ch in " \t\"'{}[]$;\\"):
        return f"ERROR: file path {path!r} contains characters unsafe for an OpenOCD command"
    program = f"program {path} verify"
    if args.get("address") not in (None, ""):
        address = _parse_int(args.get("address"), "address", lo=0, hi=0xFFFFFFFF)
        program += f" {address:#x}"
    argv = _openocd_argv(args, [program, "shutdown"])
    return _run_openocd(sandbox, argv, timeout=300.0)


# ---------- I2C protocol layer ----------


def smbus2_bus(bus_number: int = 1):
    """Real I2C adapter over /dev/i2c-N. Lazy-imports smbus2 (the ``i2c`` extra).

    Returns ``bus(addr, write_bytes, read_len) -> bytes`` doing a combined
    write-then-read transaction (repeated START), the standard register read.
    """
    try:
        from smbus2 import SMBus, i2c_msg
    except ImportError as e:
        raise ImportError(
            "smbus2 not installed — python -m pip install -e './packages/maverick-core[i2c]' "
            "(or pip install smbus2) to talk to /dev/i2c-* on this host"
        ) from e

    def bus(addr: int, write_bytes: bytes, read_len: int) -> bytes:
        msgs = []
        if write_bytes:
            msgs.append(i2c_msg.write(addr, write_bytes))
        read = None
        if read_len:
            read = i2c_msg.read(addr, read_len)
            msgs.append(read)
        if msgs:
            with SMBus(bus_number) as b:
                b.i2c_rdwr(*msgs)
        return bytes(list(read)) if read is not None else b""

    return bus


def _resolve_bus(args: dict, bus):
    if bus is not None:
        return bus
    bus_number = _parse_int(args.get("bus_number") or 1, "bus_number", lo=0, hi=255)
    return smbus2_bus(bus_number)


def _i2c_addr(args: dict) -> int:
    return _parse_int(args.get("addr"), "addr", lo=0x03, hi=0x77)


def _write_prefix(args: dict) -> bytes:
    reg = args.get("register")
    if reg in (None, ""):
        return b""
    return bytes([_parse_int(reg, "register", lo=0, hi=0xFF)])


def _hexdump(data: bytes, *, base: int = 0) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        lines.append(f"{base + off:02x}: " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)


def _op_i2c_read(args: dict, sandbox, bus) -> str:
    addr = _i2c_addr(args)
    length = _parse_int(args.get("length") or 1, "length", lo=1, hi=MAX_I2C_BYTES)
    data = _resolve_bus(args, bus)(addr, _write_prefix(args), length)
    return f"read {len(data)} byte(s) from {addr:#04x}: " + " ".join(f"{b:02x}" for b in data)


def _op_i2c_write(args: dict, sandbox, bus) -> str:
    addr = _i2c_addr(args)
    payload = _write_prefix(args) + _parse_hex_bytes(args.get("data") or "")
    if len(payload) > MAX_I2C_BYTES:
        return f"ERROR: write of {len(payload)} bytes exceeds the {MAX_I2C_BYTES}-byte bound"
    _resolve_bus(args, bus)(addr, payload, 0)
    return f"wrote {len(payload)} byte(s) to {addr:#04x}"


def _op_i2c_dump(args: dict, sandbox, bus) -> str:
    addr = _i2c_addr(args)
    length = _parse_int(args.get("length") or MAX_I2C_BYTES, "length", lo=1, hi=MAX_I2C_BYTES)
    start = 0
    if args.get("register") not in (None, ""):
        start = _parse_int(args.get("register"), "register", lo=0, hi=0xFF)
    data = _resolve_bus(args, bus)(addr, bytes([start]), length)
    return f"dump of {addr:#04x} from register {start:#04x}:\n" + _hexdump(data, base=start)


def parse_dump(text: str) -> bytes:
    """Parse an i2cdump-style hex table ("00: 12 34 ... | ascii") to bytes.

    Tolerates the header row, an ASCII gutter, and i2cdump's ``XX``
    unreadable-byte marker (skipped). Pure function — used by the
    ``i2c_parse_dump`` op and importable on its own.
    """
    out = bytearray()
    for line in (text or "").splitlines():
        body = line.split(":", 1)
        if len(body) != 2 or not re.fullmatch(r"\s*[0-9a-fA-F]{1,4}\s*", body[0]):
            continue  # header / prose line
        for tok in body[1].split():
            if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
                out.append(int(tok, 16))
            elif tok.upper() == "XX":
                continue
            else:
                break  # ASCII gutter reached
    return bytes(out)


def _op_i2c_parse_dump(args: dict, sandbox, bus) -> str:
    text = args.get("text") or ""
    if not text.strip():
        return "ERROR: i2c_parse_dump requires text"
    data = parse_dump(text)
    if not data:
        return "ERROR: no hex bytes found in text (expected i2cdump-style rows like '00: 12 34 ...')"
    return f"parsed {len(data)} byte(s):\n" + _hexdump(data)


# ---------- dispatch ----------

_HANDLERS = {
    "jtag_halt": _op_jtag_halt,
    "jtag_resume": _op_jtag_resume,
    "jtag_reset": _op_jtag_reset,
    "jtag_read_mem": _op_jtag_read_mem,
    "jtag_flash_write": _op_jtag_flash_write,
    "i2c_read": _op_i2c_read,
    "i2c_write": _op_i2c_write,
    "i2c_dump": _op_i2c_dump,
    "i2c_parse_dump": _op_i2c_parse_dump,
}


def _run(args: dict[str, Any], sandbox, bus) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    fn = _HANDLERS.get(op)
    if not fn:
        return f"ERROR: unknown op {op!r}"
    try:
        return fn(args, sandbox, bus)
    except (ValueError, ImportError) as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: embedded request failed: {type(e).__name__}: {e}"


def embedded_device(sandbox=None, bus=None) -> Tool:
    """Build the embedded_device tool.

    ``bus`` is the I2C seam: ``bus(addr, write_bytes, read_len) -> bytes``.
    When None, the smbus2 adapter is built lazily on first I2C op (actionable
    ImportError when the ``i2c`` extra is absent). JTAG ops shell out to
    ``openocd`` strictly through ``sandbox.exec()`` (rule #4).
    """
    return Tool(
        name="embedded_device",
        description=(
            "JTAG/I2C access to the operator's OWN embedded devices. JTAG via "
            "the local openocd binary: jtag_halt, jtag_resume, jtag_reset "
            "(gated), jtag_read_mem (bounded mdw), jtag_flash_write (gated, "
            "workspace file only). I2C transactions: i2c_read, i2c_write, "
            "i2c_dump, i2c_parse_dump. Destructive ops (reset, flash) require "
            "[embedded] allow_flash = true in config. Every op names its "
            "explicit target — there is no device autodetection."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox, bus),
    )
