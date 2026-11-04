"""Hardware sensor tool.

Read the HOST's hardware sensors — temperatures, fans, battery — so an agent
can reason about thermal throttling, a dead fan, or whether a long run will
outlast the battery. Sources, in order:

1. an injected ``reader`` (the test seam / a custom telemetry source);
2. ``psutil`` when installed (the ``[sensors]`` extra) — temperatures, fans,
   battery;
3. ``/sys/class/thermal`` on Linux as a no-dependency fallback for
   temperatures.

Read-only by nature, and readings are NEVER fabricated: a category with no
readable sensor reports "unavailable on this host" (with an install hint when
psutil is the missing piece) instead of a guess.

ops: read (all categories), thermal (temperatures only), battery.
Registered in ``base_registry`` only after an explicit operator opt-in.
"""
from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import Tool

# Linux thermal-zone sysfs root; module-level so tests can point it at a tmp dir.
_SYS_THERMAL = Path("/sys/class/thermal")

_PSUTIL_HINT = " (psutil not installed; python -m pip install -e './packages/maverick-core[sensors]')"


def _path_in_cwd(path: str | None) -> bool:
    if not path:
        return False
    try:
        return Path(path).resolve().is_relative_to(Path.cwd().resolve())
    except OSError:
        return False


def _safe_import_path(entry: str) -> bool:
    # Python treats an empty sys.path entry as the current working directory.
    if entry == "":
        return False
    try:
        return not Path(entry).resolve().is_relative_to(Path.cwd().resolve())
    except OSError:
        return True


def _psutil() -> Any | None:
    cached = sys.modules.get("psutil")
    if cached is not None:
        if _path_in_cwd(getattr(cached, "__file__", None)):
            return None
        return cached

    original_path = list(sys.path)
    try:
        sys.path = [entry for entry in original_path if _safe_import_path(entry)]
        psutil = importlib.import_module("psutil")
    except ImportError:
        return None
    finally:
        sys.path = original_path

    if _path_in_cwd(getattr(psutil, "__file__", None)):
        return None
    return psutil


def _temps_psutil(ps: Any) -> list[str]:
    try:
        readings = ps.sensors_temperatures()
    except (AttributeError, OSError):  # platform without the API
        return []
    lines: list[str] = []
    for chip, entries in sorted((readings or {}).items()):
        for e in entries:
            line = f"{chip}/{e.label or 'temp'}: {float(e.current):.1f} C"
            extras = []
            if e.high is not None:
                extras.append(f"high {float(e.high):.1f}")
            if e.critical is not None:
                extras.append(f"critical {float(e.critical):.1f}")
            if extras:
                line += f" ({', '.join(extras)})"
            lines.append(line)
    return lines


def _fans_psutil(ps: Any) -> list[str]:
    try:
        readings = ps.sensors_fans()
    except (AttributeError, OSError):
        return []
    return [
        f"{chip}/{e.label or 'fan'}: {int(e.current)} RPM"
        for chip, entries in sorted((readings or {}).items())
        for e in entries
    ]


def _battery_psutil(ps: Any) -> str | None:
    try:
        b = ps.sensors_battery()
    except (AttributeError, OSError):
        return None
    if b is None:
        return None
    line = f"{float(b.percent):.0f}% ({'plugged in' if b.power_plugged else 'on battery'})"
    secs = getattr(b, "secsleft", None)
    if isinstance(secs, int) and secs > 0:
        line += f", ~{secs // 3600}h{(secs % 3600) // 60:02d}m remaining"
    return line


def _temps_sysfs(base: Path) -> list[str]:
    """Temperatures from /sys/class/thermal — millidegrees C per zone."""
    lines: list[str] = []
    try:
        zones = sorted(base.glob("thermal_zone*"))
    except OSError:
        return []
    for zone in zones:
        try:
            ztype = (zone / "type").read_text(encoding="utf-8").strip() or zone.name
            milli = int((zone / "temp").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            continue  # unreadable zone: skip, never invent a number
        lines.append(f"{ztype}: {milli / 1000:.1f} C")
    return lines


def _read_all() -> dict[str, Any]:
    """Raw readings from the host: list of lines per category, None battery."""
    ps = _psutil()
    temps: list[str] = []
    fans: list[str] = []
    battery: str | None = None
    if ps is not None:
        temps = _temps_psutil(ps)
        fans = _fans_psutil(ps)
        battery = _battery_psutil(ps)
    if not temps:
        temps = _temps_sysfs(_SYS_THERMAL)
    return {"temperatures": temps, "fans": fans, "battery": battery, "psutil": ps is not None}


def _section(name: str, lines: list[str], hint: str) -> str:
    if not lines:
        return f"{name}: unavailable on this host{hint}"
    return f"{name}:\n" + "\n".join(f"  {line}" for line in lines)


def _run(args: dict[str, Any], reader: Callable[[], dict[str, Any]] | None = None) -> str:
    op = args.get("op")
    if op not in ("read", "thermal", "battery"):
        return f"ERROR: unknown op {op!r} (expected read/thermal/battery)"

    raw = reader() if reader is not None else _read_all()
    temps = list(raw.get("temperatures") or [])
    fans = list(raw.get("fans") or [])
    battery = raw.get("battery")
    # The hint only applies when psutil is genuinely the missing piece.
    hint = "" if raw.get("psutil", True) else _PSUTIL_HINT

    battery_line = (
        f"battery: {battery}" if battery else f"battery: unavailable on this host{hint}"
    )
    if op == "thermal":
        # sysfs may have covered temperatures even without psutil.
        return _section("temperatures", temps, hint)
    if op == "battery":
        return battery_line
    return "\n".join([
        _section("temperatures", temps, hint),
        _section("fans", fans, hint),
        battery_line,
    ])


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["read", "thermal", "battery"],
            "description": "read = all categories; thermal = temperatures; battery.",
        },
    },
    "required": ["op"],
}


def hardware_sensors(reader: Callable[[], dict[str, Any]] | None = None) -> Tool:
    """Factory: the host hardware-sensor reader.

    ``reader`` (tests / custom telemetry) replaces the real sources; it returns
    ``{"temperatures": [lines], "fans": [lines], "battery": line|None}``.
    """

    def _fn(args: dict[str, Any]) -> str:
        return _run(args, reader)

    return Tool(
        name="hardware_sensors",
        description=(
            "Read the host machine's hardware sensors. op=read reports "
            "temperatures, fans and battery; op=thermal only temperatures; "
            "op=battery only battery. Categories without a readable sensor "
            "say 'unavailable on this host' — readings are never invented."
        ),
        input_schema=_SCHEMA,
        fn=_fn,
        parallel_safe=True,
    )
