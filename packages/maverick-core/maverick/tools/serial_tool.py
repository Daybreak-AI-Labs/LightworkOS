"""Embedded-device tool — talk to hardware over a serial port (UART).

The common embedded path: read/write a microcontroller, sensor, or embedded
Linux board over a serial/USB-serial line (``/dev/ttyUSB0``, ``COM3``, …) via
``pyserial`` (the ``[serial]`` extra). Covers the serial leg of
embedded-device access; JTAG/I2C are bus-specific and out of scope here.

Safety: the port is validated to be a real serial device path (``/dev/tty*`` /
``/dev/cu.*`` / ``COM<n>`` / ``/dev/serial/by-id/*``), so this tool can't be
turned into an arbitrary-file opener. It commands hardware, so it is not a
low-risk tool.

ops:
  - list_ports()                                   — discovered serial ports
  - write(port, data, baud?, eol?)                 — send text
  - read(port, baud?, bytes?, timeout?)            — read a chunk
  - query(port, data, baud?, timeout?, eol?)       — write then read the reply
"""
from __future__ import annotations

import math
import re
from typing import Any

from . import Tool

_SERIAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list_ports", "write", "read", "query"]},
        "port": {"type": "string", "description": "e.g. /dev/ttyUSB0 or COM3"},
        "data": {"type": "string"},
        "baud": {"type": "integer", "description": "baud rate (default 115200)"},
        "bytes": {"type": "integer", "description": "max bytes to read (default 256)"},
        "timeout": {"type": "number", "description": "read timeout seconds (default 1.0)"},
        "eol": {"type": "string", "description": "line terminator appended on write (default '\\n')"},
    },
    "required": ["op"],
}

# A real serial device path; rejects anything else so this can't open /etc/passwd
# or a leading-dash option-injection path. The /dev/serial/by-id form is
# intentionally limited to a single device-id filename: accepting extra path
# segments would allow traversal (for example, "../../pts/0") before pyserial
# opens the caller-controlled path.
_PORT_RE = re.compile(r"^(/dev/tty\w+|/dev/cu\.[\w.\-]+|COM\d+)$")
_SERIAL_BY_ID_RE = re.compile(r"^/dev/serial/by-id/[\w.\-]+$")


def _need_serial():
    try:
        import serial  # noqa: F401
        import serial.tools.list_ports  # noqa: F401
        return None
    except ImportError:
        return "ERROR: pyserial not installed. Run: python -m pip install -e './packages/maverick-core[serial]'"


def _valid_port(port: str) -> bool:
    if _PORT_RE.match(port or ""):
        return True
    if not _SERIAL_BY_ID_RE.match(port or ""):
        return False
    name = port.rsplit("/", 1)[-1]
    return name not in {".", ".."}


def _baud(args: dict) -> int:
    try:
        return max(1, int(args.get("baud") or 115200))
    except (TypeError, ValueError):
        return 115200


def _timeout(args: dict) -> float:
    # inf would block a read forever; refuse non-finite and non-positive values.
    timeout = float(args.get("timeout") or 1.0)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive, finite number of seconds")
    return timeout


def _op_list_ports() -> str:
    import serial.tools.list_ports
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        return "no serial ports found"
    return "\n".join(f"  {p.device}  {getattr(p, 'description', '') or ''}".rstrip()
                     for p in ports)


def _op_write(args: dict) -> str:
    import serial
    port = (args.get("port") or "").strip()
    if not _valid_port(port):
        return f"ERROR: invalid serial port {port!r}"
    data = args.get("data")
    if data is None:
        return "ERROR: write requires data"
    eol = args.get("eol", "\n")
    payload = (str(data) + (eol or "")).encode("utf-8", errors="replace")
    timeout = _timeout(args)
    with serial.Serial(port, _baud(args), timeout=timeout) as ser:
        n = ser.write(payload)
    return f"wrote {n} byte(s) to {port}"


def _op_read(args: dict) -> str:
    import serial
    port = (args.get("port") or "").strip()
    if not _valid_port(port):
        return f"ERROR: invalid serial port {port!r}"
    n = max(1, min(int(args.get("bytes") or 256), 65536))
    timeout = _timeout(args)
    with serial.Serial(port, _baud(args), timeout=timeout) as ser:
        raw = ser.read(n)
    return raw.decode("utf-8", errors="replace") if raw else "(no data)"


def _op_query(args: dict) -> str:
    import serial
    port = (args.get("port") or "").strip()
    if not _valid_port(port):
        return f"ERROR: invalid serial port {port!r}"
    if args.get("data") is None:
        return "ERROR: query requires data"
    eol = args.get("eol", "\n")
    payload = (str(args["data"]) + (eol or "")).encode("utf-8", errors="replace")
    n = max(1, min(int(args.get("bytes") or 256), 65536))
    timeout = _timeout(args)
    with serial.Serial(port, _baud(args), timeout=timeout) as ser:
        ser.write(payload)
        raw = ser.read(n)
    return raw.decode("utf-8", errors="replace") if raw else "(no reply)"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    err = _need_serial()
    if err:
        return err
    try:
        if op == "list_ports":
            return _op_list_ports()
        if op == "write":
            return _op_write(args)
        if op == "read":
            return _op_read(args)
        if op == "query":
            return _op_query(args)
    except Exception as e:
        return f"ERROR: serial failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def serial_tool() -> Tool:
    return Tool(
        name="serial",
        description=(
            "Embedded device over serial/UART (pyserial). ops: list_ports, "
            "write (port + data + optional baud/eol), read (port + optional "
            "bytes/timeout), query (write then read reply). Port must be a real "
            "serial device path. Requires the [serial] extra."
        ),
        input_schema=_SERIAL_SCHEMA,
        fn=_run,
    )
