"""Computer-use tool. Matches Anthropic's ``computer_20250124`` spec.

Lets the agent see the screen and drive mouse/keyboard. Implemented via
pyautogui for cross-platform input + mss for fast screenshots. Both
ship as the ``[computer-use]`` extra; the tool factory raises an
ImportError with an actionable message if they're not installed.

When this tool is registered, the agent kernel passes it through to
Claude 4.x as a native computer_20250124 tool, which means the model
emits structured actions (action='screenshot', action='mouse_move',
coordinate=[x,y], etc.) and we execute them.

Safety:
  - Each invocation is logged with action + coordinates so users can
    audit what the agent did.
  - The agent kernel runs this through the same Shield checks as other
    tools, so blocked-tool-call rules apply.
  - Coordinates clamped to the active display's bounds.
  - ``MAVERICK_COMPUTER_DISABLE=1`` (or true/yes/on) env var disables the tool entirely
    (kill switch for production deployments where the user wants the
    agent capability but not actual mouse control).
  - Host-safety guard (opt-in): when sandboxing is required --
    ``MAVERICK_COMPUTER_REQUIRE_SANDBOX=1`` or enterprise mode -- the tool
    refuses to drive the display unless ``MAVERICK_COMPUTER_ALLOW_HOST=1`` is
    set or ``DISPLAY`` is explicitly pointed at the same non-host display named
    by ``MAVERICK_COMPUTER_DISPLAY``. Off by default: behavior is unchanged
    unless explicitly required.
"""
from __future__ import annotations

import base64
import copy
import io
import logging
import os
import tempfile
import time
from typing import Any

from ..env_setting import env_or_config as _env_or_config
from ..safety.action_evidence import seal_bracketed
from ..safety.action_gate import (
    ActionPermit,
    computer_action_risk,
    consume_action_permit,
    gate_computer_action,
)
from . import Tool

log = logging.getLogger(__name__)


_COMPUTER_USE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": [
                "key", "type", "mouse_move", "left_click", "left_click_drag",
                "right_click", "middle_click", "double_click", "screenshot",
                "cursor_position", "scroll", "wait",
            ],
            "description": "The action to perform.",
        },
        "coordinate": {
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 2, "maxItems": 2,
            "description": "[x, y] pixel coords. Required for *_click and mouse_move.",
        },
        "text": {
            "type": "string",
            "description": "Text to type (for 'type' action) or key/chord (for 'key').",
        },
        "scroll_direction": {
            "type": "string",
            "enum": ["up", "down", "left", "right"],
        },
        "scroll_amount": {
            "type": "integer",
            "description": "Notch count for 'scroll' (default 3).",
        },
        "duration": {
            "type": "number",
            "description": "Seconds for 'wait' or drag duration.",
        },
        "target": {
            "type": "string",
            "description": (
                "Instead of a coordinate, for *_click and mouse_move: describe the "
                "item, e.g. 'the Save button'. It is found by looking at the screen "
                "and refused when not found with enough certainty."
            ),
        },
    },
    "required": ["action"],
}


def _ensure_pyautogui():
    try:
        import pyautogui  # noqa
    except ImportError as e:
        raise ImportError(
            "pyautogui not installed. Run: python -m pip install -e './packages/maverick-core[computer-use]'"
        ) from e
    return __import__("pyautogui")


def _screenshot_png_b64() -> str:
    """Grab the primary display and return base64-encoded PNG."""
    try:
        import mss
        from PIL import Image
    except ImportError as e:
        raise ImportError(
            "mss + pillow not installed. Run: python -m pip install -e './packages/maverick-core[computer-use]'"
        ) from e
    with mss.mss() as sct:
        monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
        raw = sct.grab(monitor)
        img = Image.frombytes("RGB", raw.size, raw.rgb)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return base64.b64encode(buf.getvalue()).decode("ascii")


def _maybe_seal_capture(b64: str) -> None:
    """Persist + seal a screenshot when a sealing key is configured.

    Captures land under ``data_dir("captures")/<utc-stamp>.png`` and each is
    appended to the directory's tamper-evident ledger
    (:mod:`maverick.screenshot_seal`). Opt-in purely by key presence
    ([safety] screenshot_key / MAVERICK_SCREENSHOT_KEY); best-effort -- a
    sealing problem must never break the screenshot the model is waiting on.
    """
    try:
        from ..screenshot_seal import SealKeyMissing, _key, seal
        try:
            _key(None)  # probe FIRST: no key -> no capture dir, no file
        except SealKeyMissing:
            return  # sealing is off; capture stays in-memory only
        from datetime import datetime, timezone

        from ..paths import data_dir
        captures = data_dir("captures")
        captures.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = captures / f"{stamp}.png"
        path.write_bytes(base64.b64decode(b64))
        seal(path)
    except Exception:  # pragma: no cover -- evidence capture is best-effort
        log.debug("screenshot seal failed", exc_info=True)


def _ocr_enabled() -> bool:
    from ..env_setting import env_or_config

    return (env_or_config("MAVERICK_COMPUTER_OCR", "computer_use", "ocr") or "").lower() in (
        "1", "true", "yes", "on",
    )


def _ocr_png_b64(b64: str) -> str:
    """Best-effort OCR of a base64 PNG via tesseract, run on the host
    (``sandbox_run(None, ...)``: a direct subprocess with a scrubbed
    environment, not a sandbox backend).

    Returns "" on ANY failure (bad base64, tesseract missing, timeout, or
    subprocess error). OCR is a fallback for when the model can't see a DOM /
    accessibility tree, never a hard requirement.
    """
    tmp_path = ""
    try:
        from . import sandbox_run

        png = base64.b64decode(b64)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(png)
            tmp_path = tmp.name

        code, out, stderr = sandbox_run(
            None, ["tesseract", tmp_path, "-", "-l", "eng", "--psm", "3"], timeout=120,
        )
        if code != 0:
            log.debug(
                "computer-use OCR tesseract failed (%s): %s",
                code, (stderr or "").strip()[:300],
            )
            return ""
        return (out or "").strip()
    except Exception as e:  # pragma: no cover - fail-open
        log.debug("computer-use OCR unavailable: %s", e)
        return ""
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _clamp_coordinate(pyautogui, coord: list | None) -> tuple[int, int] | None:
    if not coord:
        return None
    if len(coord) != 2:
        raise ValueError(f"coordinate must be [x, y]; got {coord!r}")
    w, h = pyautogui.size()
    x = max(0, min(int(coord[0]), w - 1))
    y = max(0, min(int(coord[1]), h - 1))
    return (x, y)


_VALID_ACTIONS = frozenset({
    "key", "type", "mouse_move", "left_click", "left_click_drag",
    "right_click", "middle_click", "double_click", "screenshot",
    "cursor_position", "scroll", "wait",
})


def _redact_computer_text(value: Any) -> str:
    """Return model/log-visible computer text with capability tokens removed."""
    try:
        from ..safety.secret_detector import redact

        safe, _matches = redact(str(value or ""))
        return safe
    except Exception:
        return "[computer detail withheld: redaction unavailable]"


def _do_screenshot() -> str:
    """Grab + (optionally) seal + OCR a screenshot. Returns the tool_result
    string or an ``ERROR:`` string if capture deps are missing."""
    try:
        b64 = _screenshot_png_b64()
    except ImportError as e:
        return f"ERROR: {e}"
    log.info("computer.screenshot len=%d", len(b64))
    # Tamper-evident capture (opt-in by key presence): persist the PNG and
    # seal it into the hash-chained ledger so it's usable as evidence.
    # No key configured -> no seal, behavior unchanged.
    _maybe_seal_capture(b64)
    # Claude expects the screenshot as a tool_result image block.
    # The agent kernel translates this string back into a block.
    out = f"<screenshot mime=image/png base64>{b64}</screenshot>"
    # Optional OCR fallback (MAVERICK_COMPUTER_OCR=1): attach recognized
    # text next to the image for models/situations without a DOM. No-op
    # if OCR deps are absent.
    if _ocr_enabled():
        text = _ocr_png_b64(b64)
        if text:
            out += f"\n<ocr>{text}</ocr>"
    return out


def _do_cursor_position(pyautogui, coord, args: dict[str, Any]) -> str:
    x, y = pyautogui.position()
    log.info("computer.cursor_position -> (%d, %d)", x, y)
    return f"({x}, {y})"


def _do_wait(pyautogui, coord, args: dict[str, Any]) -> str:
    duration = float(args.get("duration") or 1.0)
    duration = max(0.0, min(duration, 30.0))  # cap at 30s
    time.sleep(duration)
    log.info("computer.wait %.1fs", duration)
    return f"waited {duration:.1f}s"


def _do_mouse_move(pyautogui, coord, args: dict[str, Any]) -> str:
    if not coord:
        return "ERROR: mouse_move requires coordinate=[x, y]"
    pyautogui.moveTo(coord[0], coord[1], duration=0.05)
    log.info("computer.mouse_move -> %s", coord)
    return f"moved to {coord}"


def _do_left_click(pyautogui, coord, args: dict[str, Any]) -> str:
    if coord:
        pyautogui.click(coord[0], coord[1])
    else:
        pyautogui.click()
    log.info("computer.left_click at %s", coord or pyautogui.position())
    return f"clicked at {coord or pyautogui.position()}"


def _do_right_click(pyautogui, coord, args: dict[str, Any]) -> str:
    if coord:
        pyautogui.rightClick(coord[0], coord[1])
    else:
        pyautogui.rightClick()
    log.info("computer.right_click at %s", coord or pyautogui.position())
    return f"right-clicked at {coord or pyautogui.position()}"


def _do_middle_click(pyautogui, coord, args: dict[str, Any]) -> str:
    if coord:
        pyautogui.middleClick(coord[0], coord[1])
    else:
        pyautogui.middleClick()
    log.info("computer.middle_click at %s", coord or pyautogui.position())
    return f"middle-clicked at {coord or pyautogui.position()}"


def _do_double_click(pyautogui, coord, args: dict[str, Any]) -> str:
    if coord:
        pyautogui.doubleClick(coord[0], coord[1])
    else:
        pyautogui.doubleClick()
    log.info("computer.double_click at %s", coord or pyautogui.position())
    return f"double-clicked at {coord or pyautogui.position()}"


def _do_left_click_drag(pyautogui, coord, args: dict[str, Any]) -> str:
    if not coord:
        return "ERROR: left_click_drag requires coordinate=[x, y] (target)"
    duration = float(args.get("duration") or 0.5)
    pyautogui.dragTo(coord[0], coord[1], duration=duration, button="left")
    log.info("computer.drag -> %s (duration=%.1fs)", coord, duration)
    return f"dragged to {coord}"


def _do_type(pyautogui, coord, args: dict[str, Any]) -> str:
    text = args.get("text") or ""
    if not text:
        return "ERROR: type requires text"
    # ~50 wpm typing -- realistic enough to not trigger paste-detection
    # in apps that have it, while still being fast.
    pyautogui.typewrite(text, interval=0.02)
    log.info("computer.type len=%d", len(text))
    return f"typed {len(text)} chars"


def _do_key(pyautogui, coord, args: dict[str, Any]) -> str:
    text = args.get("text") or ""
    if not text:
        return "ERROR: key requires text (e.g. 'ctrl+c', 'Return', 'shift+tab')"
    # Anthropic spec uses xdotool-style ('ctrl+c'); pyautogui uses
    # hotkey('ctrl', 'c'). Convert here.
    keys = [k.strip().lower() for k in text.replace("-", "+").split("+") if k.strip()]
    # Normalise common synonyms.
    norm_map = {
        "return": "enter", "escape": "esc", "del": "delete",
        "back_space": "backspace", "page_up": "pageup", "page_down": "pagedown",
    }
    keys = [norm_map.get(k, k) for k in keys]
    pyautogui.hotkey(*keys)
    safe_keys = _redact_computer_text("+".join(keys))
    log.info("computer.key %s", safe_keys)
    return f"pressed {safe_keys}"


def _do_scroll(pyautogui, coord, args: dict[str, Any]) -> str:
    direction = args.get("scroll_direction") or "down"
    amount = int(args.get("scroll_amount") or 3)
    # pyautogui.scroll: positive=up, negative=down. Horizontal uses
    # hscroll -- the old map sent delta 0 for left/right, so the scroll was
    # a silent no-op while the tool reported success.
    if coord:
        pyautogui.moveTo(coord[0], coord[1])
    if direction in ("up", "down"):
        pyautogui.scroll(amount if direction == "up" else -amount)
    else:
        pyautogui.hscroll(-amount if direction == "left" else amount)
    log.info("computer.scroll %s %d", direction, amount)
    return f"scrolled {direction} {amount}"


# action -> handler(pyautogui, coord, args) -> str. These run AFTER pyautogui
# is imported and the coordinate is clamped, so each handler can stay flat.
_PYAUTOGUI_ACTIONS = {
    "cursor_position": _do_cursor_position,
    "wait": _do_wait,
    "mouse_move": _do_mouse_move,
    "left_click": _do_left_click,
    "right_click": _do_right_click,
    "middle_click": _do_middle_click,
    "double_click": _do_double_click,
    "left_click_drag": _do_left_click_drag,
    "type": _do_type,
    "key": _do_key,
    "scroll": _do_scroll,
}


def _dispatch_approved_computer_action(
    pyautogui,
    action: str,
    coord,
    args: dict[str, Any],
) -> str:
    """Dispatch only through a driver that binds the exact native target.

    Raw global input has a check/use gap: another window can become foreground
    after observation and receive the click or keystroke. A compliant desktop
    bridge must implement ``dispatch_bound`` and atomically validate its own
    HWND/UIA ticket before sending the frozen input. The pyautogui fallback is
    therefore intentionally unavailable for approved mutations.
    """
    dispatcher = getattr(pyautogui, "dispatch_bound", None)
    if not callable(dispatcher):
        return (
            "ERROR: computer target cannot be bound atomically; no input was "
            "sent; observe it and complete the action manually"
        )
    return str(dispatcher(action, coord, copy.deepcopy(args)))


# X11 :0 is the local console -- the operator's real seat.
_DEFAULT_HOST_DISPLAYS = frozenset({":0", ":0.0"})

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _host_guard_required() -> bool:
    """True when computer-use is REQUIRED to be sandboxed.

    Opt-in only: the explicit ``MAVERICK_COMPUTER_REQUIRE_SANDBOX=1`` flag, or
    enterprise mode. With neither set this is False and the guard is a no-op, so
    default behavior is unchanged (kernel rule 1: fail open).
    """
    from ..env_setting import env_or_config

    if (env_or_config("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "computer_use", "require_sandbox")
            or "").strip().lower() in _TRUTHY:
        return True
    try:
        from ..enterprise import enterprise_enabled
        return enterprise_enabled()
    except Exception:
        # enterprise module absent/broken must never make the tool fail closed.
        return False


def _host_drive_allowed() -> bool:
    """True when it is safe to drive this display.

    Safe means an explicit operator override (``MAVERICK_COMPUTER_ALLOW_HOST=1``)
    or that the process ``DISPLAY`` has actually been pointed at the same
    non-host display named by ``MAVERICK_COMPUTER_DISPLAY``. Merely setting the
    Lightwork-specific variable is not enough because screenshot and input
    backends read the real ``DISPLAY`` environment variable.
    """
    from ..env_setting import env_or_config

    if (env_or_config("MAVERICK_COMPUTER_ALLOW_HOST", "computer_use", "allow_host")
            or "").strip().lower() in _TRUTHY:
        return True
    display = (os.environ.get("DISPLAY") or "").strip()
    configured_display = (os.environ.get("MAVERICK_COMPUTER_DISPLAY") or "").strip()
    return (
        bool(display)
        and display == configured_display
        and display not in _DEFAULT_HOST_DISPLAYS
    )


def _host_safety_error() -> str | None:
    """ERROR string if sandboxing is required but this looks like the host
    display; otherwise None (proceed). No-op unless the guard is required."""
    if not _host_guard_required():
        return None
    if _host_drive_allowed():
        return None
    display = (os.environ.get("DISPLAY") or "").strip() or "(unset)"
    return (
        "ERROR: computer-use refused -- sandboxing is required "
        "(MAVERICK_COMPUTER_REQUIRE_SANDBOX=1 or enterprise mode) and this looks "
        f"like the operator's real display (DISPLAY={display}). Run the agent "
        "against a remote/sandboxed display by setting DISPLAY to the same "
        "non-host value as MAVERICK_COMPUTER_DISPLAY (for example, both :99), "
        "or, only if you intend to "
        "drive this machine, set MAVERICK_COMPUTER_ALLOW_HOST=1."
    )


# Pointer actions that may name a described target instead of a coordinate.
_TARGET_ACTIONS = frozenset({
    "mouse_move", "left_click", "right_click", "middle_click", "double_click",
})

_LOCATE_SYSTEM = (
    "You locate one item on a screenshot. Reply with JSON only, no prose: "
    '{"x": <pixel column of its centre>, "y": <pixel row of its centre>, '
    '"confidence": <0 to 1, how sure you are it is the item described>}. '
    "If the item is not visible, reply with confidence 0."
)


def _vision_locator(budget):
    """``vision(image_bytes, description) -> {"x", "y", "confidence"}`` using
    the vision role's model, charged to the running task's budget."""
    import json
    import re

    def locate(image: bytes, description: str) -> dict[str, Any]:
        from ..llm import LLM, model_for_role

        model = model_for_role("vision")
        resp = LLM(model=model).complete(
            system=_LOCATE_SYSTEM,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {
                    "type": "base64", "media_type": "image/png",
                    "data": base64.b64encode(image).decode("ascii")}},
                {"type": "text", "text": f"Item: {description}"},
            ]}],
            budget=budget, max_tokens=200, model=model,
        )
        found = re.search(r"\{.*\}", getattr(resp, "text", "") or "", re.DOTALL)
        if not found:
            raise ValueError("the vision model gave no location")
        return json.loads(found.group(0))

    return locate


def _resolve_target(args: dict[str, Any]) -> str | None:
    """Fill ``args["coordinate"]`` from ``args["target"]``; an ERROR string
    when the item can't be found surely enough (``[computer_use]
    vision_min_confidence``), else None."""
    target = " ".join(str(args.get("target") or "").split())[:200]
    if not target or args.get("coordinate") or args.get("action") not in _TARGET_ACTIONS:
        return None
    from ..budget import BudgetExceeded
    from ..tenant.provider_admission import current_budget
    from ..vision_click import LowConfidenceError, resolve_click

    budget = current_budget()
    if budget is None:
        return ("ERROR: finding an item on the screen needs a running task; "
                "give coordinate=[x, y] instead")
    try:
        image = base64.b64decode(_screenshot_png_b64())
    except ImportError as e:
        return f"ERROR: {e}"
    try:
        hit = resolve_click(target, app="desktop", screen="primary", image=image,
                            vision=_vision_locator(budget))
    except LowConfidenceError as e:
        return (f"ERROR: {e}. Describe the item more precisely, or give "
                "coordinate=[x, y]")
    except BudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001 -- a failed look is a plain refusal
        return (f"ERROR: could not find {_redact_computer_text(target)!r} on the "
                f"screen ({type(e).__name__}); give coordinate=[x, y] instead")
    args["coordinate"] = [hit.x, hit.y]
    log.info("computer.target -> (%d, %d) confidence=%.2f", hit.x, hit.y, hit.confidence)
    return None


def _foreground_window_identity() -> dict[str, Any]:
    """Observe the current Windows input target; callers persist only its hash."""
    if os.name != "nt":
        return {
            "platform": os.name,
            "display": os.environ.get("DISPLAY") or "local-primary",
        }
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    window = user32.GetForegroundWindow()
    if not window:
        raise RuntimeError("foreground window is unavailable")
    process_id = wintypes.DWORD()
    user32.GetWindowThreadProcessId(window, ctypes.byref(process_id))
    title_length = min(max(0, int(user32.GetWindowTextLengthW(window))), 4096)
    title = ctypes.create_unicode_buffer(title_length + 1)
    user32.GetWindowTextW(window, title, title_length + 1)
    class_name = ctypes.create_unicode_buffer(512)
    user32.GetClassNameW(window, class_name, len(class_name))
    rectangle = wintypes.RECT()
    if not user32.GetWindowRect(window, ctypes.byref(rectangle)):
        raise RuntimeError("foreground window geometry is unavailable")
    return {
        "window": int(window),
        "process_id": int(process_id.value),
        "title": title.value,
        "class": class_name.value,
        "rectangle": [
            rectangle.left, rectangle.top, rectangle.right, rectangle.bottom,
        ],
    }


def _computer_approval_context(args: dict[str, Any] | None = None) -> dict[str, str]:
    """Bind the input seat and foreground target; expose only a redacted label."""
    from ..approval_cards import digest

    material = {
        "display": (os.environ.get("DISPLAY") or "local-primary").strip(),
        "configured_display": (
            os.environ.get("MAVERICK_COMPUTER_DISPLAY") or ""
        ).strip(),
        "host_override": (
            _env_or_config("MAVERICK_COMPUTER_ALLOW_HOST", "computer_use", "allow_host") or ""
        ).strip().lower(),
    }
    identity = _foreground_window_identity()
    raw_summary = str(
        identity.get("title")
        or identity.get("class")
        or identity.get("display")
        or identity.get("platform")
        or "active computer target"
    )
    target_summary = _redact_computer_text(" ".join(raw_summary.split())[:400])
    return {
        "seat_sha256": digest(material),
        "foreground_window_sha256": digest(identity),
        "coordinate_sha256": digest(dict(args or {}).get("coordinate")),
        "credential_version_sha256": "not_applicable:local-input-seat",
        "target_summary": target_summary,
    }


def _run_computer_action(args: dict[str, Any]) -> str:
    # Dispatch from one private copy of the reviewed invocation.  The mutable
    # dictionary supplied by a model/runtime must never be able to change the
    # coordinate, key, or text after the consent boundary validated it.
    try:
        args = copy.deepcopy(dict(args))
    except Exception:
        return "ERROR: computer action input could not be frozen; no input was sent"
    # Same spellings as every other flag in this file (1/true/yes/on): a kill
    # switch that ignores "true" fails open.
    if (os.environ.get("MAVERICK_COMPUTER_DISABLE") or "").strip().lower() in _TRUTHY:
        return "ERROR: computer-use tool disabled by MAVERICK_COMPUTER_DISABLE"
    action = args.get("action")
    if not action:
        return "ERROR: action is required"
    # Reject unknown actions BEFORE trying to import pyautogui so callers
    # validating the schema get a clear error even without optional deps.
    if action not in _VALID_ACTIONS:
        return f"ERROR: unknown action {action!r}"

    # Host-safety guard: when sandboxing is REQUIRED (explicit flag or enterprise
    # mode) refuse to read/drive what looks like the operator's real display
    # unless an override or a remote display is configured. Opt-in -- a no-op by
    # default, so kernel rule 1 (fail open) holds. Sits alongside the
    # MAVERICK_COMPUTER_DISABLE kill switch above.
    host_error = _host_safety_error()
    if host_error is not None:
        return host_error

    # A described target is turned into a coordinate before the approval gate,
    # so the approval shows (and binds) the exact point that will be clicked.
    target_error = _resolve_target(args)
    if target_error is not None:
        return target_error

    # Per-action approval gate for every input mutation, including pointer moves
    # and scrolls. Silent auto approval and standing consent grants are
    # intentionally ineligible. Screenshot/cursor_position/wait remain reads.
    authorization = gate_computer_action(
        action,
        args,
        context_provider=lambda: _computer_approval_context(copy.deepcopy(args)),
    )
    if isinstance(authorization, str):
        return authorization

    # Screenshot is the most common action; handle separately (doesn't
    # need pyautogui, just mss).
    if action == "screenshot":
        return _do_screenshot()

    # Return an error STRING (like the screenshot path above), not a raised
    # ImportError: the tool fn contract is ``-> str``, and a raised exception
    # would crash direct callers and be inconsistent with the browser tool.
    try:
        pyautogui = _ensure_pyautogui()
    except ImportError as e:
        return f"ERROR: {e}"
    pyautogui.FAILSAFE = False  # Don't crash on corner-of-screen mouse moves.

    # cursor_position and wait don't need a coordinate; everything else may.
    coord = None
    if action not in ("cursor_position", "wait"):
        coord = _clamp_coordinate(pyautogui, args.get("coordinate"))

    handler = _PYAUTOGUI_ACTIONS.get(action)
    if handler is not None:
        def dispatch() -> str:
            try:
                if isinstance(authorization, ActionPermit):
                    return consume_action_permit(
                        authorization,
                        effect=lambda: _dispatch_approved_computer_action(
                            pyautogui, action, coord, args,
                        ),
                    )
                return handler(pyautogui, coord, args)
            except Exception as exc:
                # Desktop-driver errors can reflect a key or typed value. The
                # input may already have reached the application, so require a
                # fresh observation before any retry.
                detail = _redact_computer_text(exc)
                return (
                    f"ERROR: computer {action} could not be confirmed "
                    f"({type(exc).__name__}: {detail}); observe current state "
                    "before retrying"
                )

        if computer_action_risk(action, args) == "high":
            # Bracket a high-risk actuation with sealed before/after captures
            # (no-op unless screenshot sealing is configured).
            return seal_bracketed(
                _screenshot_png_b64,
                dispatch,
                action=f"computer.{action}",
            )
        return dispatch()

    # Defense in depth -- _VALID_ACTIONS guard at the top should make
    # this unreachable.
    return f"ERROR: unknown action {action!r}"


def computer() -> Tool:
    """Factory: builds the computer-use tool.

    The tool name matches Anthropic's expected ``computer`` for the
    native ``computer_20250124`` type. The description points the
    agent at what's available.
    """
    return Tool(
        name="computer",
        description=(
            "Drive the computer's display, mouse, and keyboard. "
            "Use screenshot to see the screen; mouse_move + left_click "
            "to interact; type/key to enter text. Coordinates are pixels "
            "from the top-left of the primary display."
        ),
        input_schema=_COMPUTER_USE_INPUT_SCHEMA,
        fn=_run_computer_action,
    )
