"""Android device / emulator tool via adb.

Drives a physical or emulated Android device for QA / RPA tasks the
agent might want to run: list installed apks, push/pull files, tap
the screen, take a screenshot, install/uninstall apks, run logcat.

Auth: none — uses the local ``adb`` binary. Authorization happens
on the device (developer-mode + USB-debug prompt) once per host;
nothing for Lightwork to manage.

Intentionally host-local: ``adb`` talks to a USB/network-attached
device via the host's adb daemon, which a sandboxed container can't
reach. This tool shells out directly (scrubbed env) rather than through
``sandbox.exec`` — a deliberate exception to the "sandbox-mediate all
shell" rule.

ops:
  - devices()                          — list connected devices
  - shell(cmd)                         — run a shell command (defaults to first device)
  - install(apk_path)                  — install an APK
  - uninstall(package)                 — uninstall a package
  - screenshot(out_path)               — save device screenshot to out_path
  - tap(x, y)                          — synthesize a tap
  - input_text(text)                   — synthesize keyboard input
  - launch(activity)                   — launch an activity (component name)
  - logcat(lines=50)                   — pull last N logcat lines
"""
from __future__ import annotations

import logging
import shlex
import shutil
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_ANDROID_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "devices", "shell", "install", "uninstall", "screenshot",
                "tap", "input_text", "launch", "logcat",
            ],
        },
        "device": {"type": "string", "description": "Target device id (default: first connected)."},
        "cmd": {"type": "string", "description": "Shell command (shell op)."},
        "apk_path": {"type": "string"},
        "package": {"type": "string"},
        "out_path": {"type": "string"},
        "x": {"type": "integer"},
        "y": {"type": "integer"},
        "text": {"type": "string"},
        "activity": {"type": "string", "description": "e.g. 'com.app/.MainActivity'."},
        "lines": {"type": "integer"},
    },
    "required": ["op"],
}


def _adb_present() -> bool:
    return shutil.which("adb") is not None


def _adb(args: list[str], *, device: str = "", timeout: float = 60.0) -> tuple[int, str, str]:
    cmd = ["adb"]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)
    # Host-bound: adb talks to a USB/emulator device on the host, which the
    # sandbox container can't reach — so this is intentionally NOT routed
    # through sandbox.exec (CLAUDE.md rule #4). See tools.host_exec.
    from . import host_exec
    code, out, err = host_exec(cmd, timeout=timeout)
    return code, out or "", err or ""


def _op_devices() -> str:
    code, out, err = _adb(["devices", "-l"])
    if code != 0:
        return f"ERROR: adb devices ({code}): {err.strip()[:200]}"
    lines = [line for line in out.splitlines() if line.strip() and not line.startswith("List of devices")]
    if not lines:
        return "no devices attached"
    return "\n".join(f"  {line}" for line in lines)


def _op_shell(device: str, cmd: str) -> str:
    if not cmd.strip():
        return "ERROR: shell requires cmd"
    code, out, err = _adb(["shell", cmd], device=device)
    body = out or err
    return f"exit={code}\n{body[-4000:]}"


def _op_install(device: str, apk: str, sandbox: Any = None) -> str:
    if not apk:
        return "ERROR: install requires apk_path"
    from .ffmpeg_tool import _safe_path
    try:
        apk = _safe_path(sandbox, apk)
    except ValueError as e:
        return f"ERROR: {e}"
    code, out, err = _adb(["install", "-r", apk], device=device, timeout=180)
    if code != 0:
        return f"ERROR: install ({code}): {(err or out).strip()[:300]}"
    return f"installed: {apk}"


def _op_uninstall(device: str, package: str) -> str:
    if not package:
        return "ERROR: uninstall requires package"
    code, out, err = _adb(["uninstall", package], device=device)
    if code != 0:
        return f"ERROR: uninstall ({code}): {(err or out).strip()[:300]}"
    return f"uninstalled: {package}"


def _op_screenshot(device: str, out_path: str, sandbox: Any = None) -> str:
    if not out_path:
        return "ERROR: screenshot requires out_path"
    from .ffmpeg_tool import _safe_path
    try:
        out_path = _safe_path(sandbox, out_path)
    except ValueError as e:
        return f"ERROR: {e}"
    # adb exec-out screencap streams the png bytes directly.
    cmd = ["adb"]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(["exec-out", "screencap", "-p"])
    # Host-bound (see tools.host_exec): binary png bytes, so text=False.
    from . import host_exec
    code, raw, err = host_exec(cmd, timeout=30, text=False)
    if code == 124:
        return "ERROR: screenshot TIMEOUT"
    if code != 0:
        err_s = (err or b"").decode("utf-8", errors="replace") if isinstance(err, bytes) else str(err)
        return f"ERROR: screencap ({code}): {err_s[:200]}"
    png = raw or b""
    try:
        with open(out_path, "wb") as f:
            f.write(png)
    except OSError as e:
        return f"ERROR: write {out_path}: {e}"
    return f"saved {len(png)} bytes to {out_path}"


def _op_tap(device: str, x: int, y: int) -> str:
    code, out, err = _adb(["shell", "input", "tap", str(x), str(y)], device=device)
    if code != 0:
        return f"ERROR: tap ({code}): {(err or out).strip()[:200]}"
    return f"tapped ({x},{y})"


def _op_input_text(device: str, text: str) -> str:
    if not text:
        return "ERROR: input_text requires text"
    # adb input text doesn't handle spaces well; replace with %s.
    escaped = text.replace(" ", "%s")
    code, out, err = _adb(["shell", "input", "text", shlex.quote(escaped)],
                          device=device)
    if code != 0:
        return f"ERROR: input_text ({code}): {(err or out).strip()[:200]}"
    return f"typed {len(text)} chars"


def _op_launch(device: str, activity: str) -> str:
    if not activity:
        return "ERROR: launch requires activity (e.g. 'com.app/.MainActivity')"
    code, out, err = _adb(
        ["shell", "am", "start", "-n", activity], device=device,
    )
    if code != 0:
        return f"ERROR: launch ({code}): {(err or out).strip()[:200]}"
    return f"launched {activity}"


def _op_logcat(device: str, lines: int) -> str:
    n = max(1, min(int(lines or 50), 1000))
    code, out, err = _adb(
        ["logcat", "-d", "-t", str(n)], device=device, timeout=20,
    )
    if code != 0:
        return f"ERROR: logcat ({code}): {err.strip()[:200]}"
    return out[-8000:]


def _run(args: dict[str, Any], sandbox: Any = None) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not _adb_present():
        return "ERROR: adb not found on PATH. Install Android platform-tools."
    device = (args.get("device") or "").strip()
    try:
        if op == "devices":
            return _op_devices()
        if op == "shell":
            return _op_shell(device, args.get("cmd") or "")
        if op == "install":
            return _op_install(device, args.get("apk_path") or "", sandbox)
        if op == "uninstall":
            return _op_uninstall(device, args.get("package") or "")
        if op == "screenshot":
            return _op_screenshot(device, args.get("out_path") or "", sandbox)
        if op == "tap":
            x = int(args.get("x") or 0)
            y = int(args.get("y") or 0)
            return _op_tap(device, x, y)
        if op == "input_text":
            return _op_input_text(device, args.get("text") or "")
        if op == "launch":
            return _op_launch(device, args.get("activity") or "")
        if op == "logcat":
            return _op_logcat(device, args.get("lines") or 50)
    except Exception as e:
        return f"ERROR: android request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def android(sandbox: Any = None) -> Tool:
    return Tool(
        name="android",
        description=(
            "Drive an Android device / emulator via adb. ops: "
            "devices, shell, install/uninstall, screenshot, tap, "
            "input_text, launch (component name), logcat. Requires "
            "the adb binary on PATH (Android platform-tools)."
        ),
        input_schema=_ANDROID_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
