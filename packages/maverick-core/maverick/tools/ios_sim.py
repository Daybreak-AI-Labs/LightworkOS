"""iOS Simulator tool via xcrun simctl.

Mirrors the android tool: lets the agent drive an iOS Simulator
runtime (booted on the same Mac as Lightwork) for QA / RPA tasks.

Auth: none — uses local Xcode `xcrun simctl`. Mac-only by definition;
the tool fails loudly with an actionable message on Linux / Windows.

Intentionally host-local: the iOS Simulator runs on the host Mac, not
inside any sandbox, so this tool shells out directly (scrubbed env)
rather than through ``sandbox.exec`` — a deliberate exception to the
"sandbox-mediate all shell" rule.

ops:
  - list_devices(state)               — devices (booted/shutdown/all)
  - boot(device_id)
  - shutdown(device_id)
  - install(device_id, app_path)      — .app bundle
  - uninstall(device_id, bundle_id)
  - launch(device_id, bundle_id)
  - terminate(device_id, bundle_id)
  - screenshot(device_id, out_path)
  - open_url(device_id, url)          — deep-link / safari open
"""
from __future__ import annotations

import logging
import platform
import shutil
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_IOS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "list_devices", "boot", "shutdown", "install", "uninstall",
                "launch", "terminate", "screenshot", "open_url",
            ],
        },
        "state": {"type": "string", "enum": ["booted", "shutdown", "all"]},
        "device_id": {
            "type": "string",
            "description": "Simulator UDID or 'booted' for the running one.",
        },
        "app_path": {"type": "string"},
        "bundle_id": {"type": "string", "description": "e.g. com.apple.mobilesafari"},
        "out_path": {"type": "string"},
        "url": {"type": "string"},
    },
    "required": ["op"],
}


def _xcrun_present() -> bool:
    return shutil.which("xcrun") is not None


def _simctl(args: list[str], *, timeout: float = 60.0) -> tuple[int, str, str]:
    cmd = ["xcrun", "simctl", *args]
    # Host-bound: the iOS simulator runs on the host (macOS), not in the
    # sandbox container — so this is intentionally NOT routed through
    # sandbox.exec (CLAUDE.md rule #4). See tools.host_exec.
    from . import host_exec
    code, out, err = host_exec(cmd, timeout=timeout)
    return code, out or "", err or ""


def _op_list(state: str) -> str:
    args = ["list", "devices"]
    if state and state != "all":
        args.append(state)
    code, out, err = _simctl(args)
    if code != 0:
        return f"ERROR: list ({code}): {err.strip()[:200]}"
    return out[-8000:]


def _op_boot(device: str) -> str:
    if not device:
        return "ERROR: boot requires device_id"
    code, out, err = _simctl(["boot", device], timeout=120)
    if code != 0 and "Booted" not in (err or ""):
        return f"ERROR: boot ({code}): {(err or out).strip()[:200]}"
    return f"booted {device}"


def _op_shutdown(device: str) -> str:
    if not device:
        return "ERROR: shutdown requires device_id"
    code, out, err = _simctl(["shutdown", device], timeout=60)
    if code != 0:
        return f"ERROR: shutdown ({code}): {(err or out).strip()[:200]}"
    return f"shutdown {device}"


def _op_install(device: str, app_path: str, sandbox: Any = None) -> str:
    if not device or not app_path:
        return "ERROR: install requires device_id and app_path"
    from .ffmpeg_tool import _safe_path
    try:
        app_path = _safe_path(sandbox, app_path)
    except ValueError as e:
        return f"ERROR: {e}"
    code, out, err = _simctl(["install", device, app_path], timeout=180)
    if code != 0:
        return f"ERROR: install ({code}): {(err or out).strip()[:200]}"
    return f"installed {app_path}"


def _op_uninstall(device: str, bundle_id: str) -> str:
    if not device or not bundle_id:
        return "ERROR: uninstall requires device_id and bundle_id"
    code, out, err = _simctl(["uninstall", device, bundle_id])
    if code != 0:
        return f"ERROR: uninstall ({code}): {(err or out).strip()[:200]}"
    return f"uninstalled {bundle_id}"


def _op_launch(device: str, bundle_id: str) -> str:
    if not device or not bundle_id:
        return "ERROR: launch requires device_id and bundle_id"
    code, out, err = _simctl(["launch", device, bundle_id])
    if code != 0:
        return f"ERROR: launch ({code}): {(err or out).strip()[:200]}"
    return out.strip() or f"launched {bundle_id}"


def _op_terminate(device: str, bundle_id: str) -> str:
    if not device or not bundle_id:
        return "ERROR: terminate requires device_id and bundle_id"
    code, out, err = _simctl(["terminate", device, bundle_id])
    if code != 0:
        return f"ERROR: terminate ({code}): {(err or out).strip()[:200]}"
    return f"terminated {bundle_id}"


def _op_screenshot(device: str, out_path: str, sandbox: Any = None) -> str:
    if not device or not out_path:
        return "ERROR: screenshot requires device_id and out_path"
    from .ffmpeg_tool import _safe_path
    try:
        out_path = _safe_path(sandbox, out_path)
    except ValueError as e:
        return f"ERROR: {e}"
    code, out, err = _simctl(["io", device, "screenshot", out_path])
    if code != 0:
        return f"ERROR: screenshot ({code}): {(err or out).strip()[:200]}"
    return f"saved screenshot to {out_path}"


def _op_open_url(device: str, url: str) -> str:
    if not device or not url:
        return "ERROR: open_url requires device_id and url"
    code, out, err = _simctl(["openurl", device, url])
    if code != 0:
        return f"ERROR: open_url ({code}): {(err or out).strip()[:200]}"
    return f"opened {url}"


def _run(args: dict[str, Any], sandbox: Any = None) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if platform.system() != "Darwin":
        return "ERROR: ios_sim only works on macOS (xcrun simctl)."
    if not _xcrun_present():
        return "ERROR: xcrun not found on PATH. Install Xcode + command-line tools."
    device = (args.get("device_id") or "booted").strip()
    try:
        if op == "list_devices":
            return _op_list(args.get("state") or "all")
        if op == "boot":
            return _op_boot(device)
        if op == "shutdown":
            return _op_shutdown(device)
        if op == "install":
            return _op_install(device, args.get("app_path") or "", sandbox)
        if op == "uninstall":
            return _op_uninstall(device, args.get("bundle_id") or "")
        if op == "launch":
            return _op_launch(device, args.get("bundle_id") or "")
        if op == "terminate":
            return _op_terminate(device, args.get("bundle_id") or "")
        if op == "screenshot":
            return _op_screenshot(device, args.get("out_path") or "", sandbox)
        if op == "open_url":
            return _op_open_url(device, args.get("url") or "")
    except Exception as e:
        return f"ERROR: ios_sim request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def ios_sim(sandbox: Any = None) -> Tool:
    return Tool(
        name="ios_sim",
        description=(
            "Drive an iOS Simulator via xcrun simctl (macOS only). "
            "ops: list_devices, boot/shutdown, install (.app)/uninstall "
            "(bundle id), launch/terminate, screenshot, open_url. "
            "device_id defaults to 'booted'."
        ),
        input_schema=_IOS_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
