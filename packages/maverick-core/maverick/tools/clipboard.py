"""Clipboard tool.

Read from / write to the system clipboard. Useful for bridging between
computer-use / browser / shell flows ("copy this from the page into
the editor").

Intentionally host-local: the clipboard is a host-desktop resource, so
this tool shells out directly (with a scrubbed env) rather than through
``sandbox.exec`` — a sandboxed container has no access to the user's
clipboard. This is a deliberate exception to the "sandbox-mediate all
shell" rule, not an oversight. Because the host path can't be sandboxed,
both read and write are gated through ``safety.consent.require_consent``
(the clipboard holds passwords / 2FA codes / tokens) — that consent gate
is this tool's safety boundary in place of sandbox mediation.

Implementation strategy:
  1. ``pyperclip`` if installed (cross-platform, best UX)
  2. ``pbpaste`` / ``pbcopy`` (macOS)
  3. ``xclip`` / ``xsel`` (Linux X11)
  4. ``wl-paste`` / ``wl-copy`` (Linux Wayland)
  5. fail gracefully with install-hint
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_CLIPBOARD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["read", "write"],
            "description": "Operation.",
        },
        "text": {"type": "string", "description": "Text to write (for write op)."},
    },
    "required": ["op"],
}


def _try_pyperclip_read() -> str | None:
    try:
        import pyperclip  # type: ignore
        return pyperclip.paste()
    except Exception:
        return None


def _try_pyperclip_write(text: str) -> bool:
    try:
        import pyperclip  # type: ignore
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def _try_subprocess(cmd: list[str], stdin: str | None = None) -> str | None:
    """Run cmd; return stdout on success, None on failure.

    Host-bound by nature (CLAUDE.md rule #4): pbcopy/pbpaste/xclip/wl-copy act
    on the *desktop clipboard*, which lives on the host — the sandbox container
    has no clipboard to read/write, so this is intentionally NOT routed through
    sandbox.exec. (It also needs stdin piping, which the argv-only
    ``tools.host_exec`` helper doesn't cover; the rationale is the same.)
    """
    if not shutil.which(cmd[0]):
        return None
    try:
        if stdin is not None:
            proc = subprocess.run(
                cmd, input=stdin.encode("utf-8"),
                capture_output=True, timeout=5,
            )
        else:
            proc = subprocess.run(cmd, capture_output=True, timeout=5)
        if proc.returncode != 0:
            return None
        return (proc.stdout or b"").decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        log.debug("clipboard: %s failed: %s", cmd[0], e)
        return None


def _read_clipboard() -> str | None:
    val = _try_pyperclip_read()
    if val is not None:
        return val
    # macOS
    val = _try_subprocess(["pbpaste"])
    if val is not None:
        return val
    # Wayland
    val = _try_subprocess(["wl-paste"])
    if val is not None:
        return val
    # X11 (xclip)
    val = _try_subprocess(["xclip", "-selection", "clipboard", "-o"])
    if val is not None:
        return val
    # X11 (xsel)
    val = _try_subprocess(["xsel", "--clipboard", "--output"])
    if val is not None:
        return val
    return None


def _write_clipboard(text: str) -> bool:
    if _try_pyperclip_write(text):
        return True
    # macOS
    if shutil.which("pbcopy"):
        if _try_subprocess(["pbcopy"], stdin=text) is not None:
            return True
    # Wayland
    if shutil.which("wl-copy"):
        if _try_subprocess(["wl-copy"], stdin=text) is not None:
            return True
    # X11
    if shutil.which("xclip"):
        if _try_subprocess(["xclip", "-selection", "clipboard"], stdin=text) is not None:
            return True
    if shutil.which("xsel"):
        if _try_subprocess(["xsel", "--clipboard", "--input"], stdin=text) is not None:
            return True
    return False


def _clipboard_target() -> dict[str, object]:
    """Return the live host-surface binding checked again before access."""

    return {
        "surface": "host-desktop-clipboard",
        "disabled": os.environ.get("MAVERICK_CLIPBOARD_DISABLE") == "1",
    }


def _operation_permit(op: str, text: str | None = None):
    """Gate clipboard read/write through an exact one-use approval card.

    The clipboard routinely holds passwords / 2FA codes / tokens, so a
    prompt-injected agent could silently exfiltrate (read) or plant
    (write) content. Both ops therefore require a fresh human decision;
    silent auto-approval and standing grants are ineligible. A denial
    returns a clear tool error instead of crashing.

    This tool stays on the host path -- the desktop clipboard can't be
    sandboxed (see the module docstring) -- so the consent gate is its
    safety boundary, not sandbox.exec.
    """
    from ..safety import require_operation_consent

    parameters = {"operation": op}
    if op == "write":
        parameters["text"] = text
    effects = (
        ["Reads the current host clipboard and returns its contents to the run."]
        if op == "read"
        else ["Replaces the current host clipboard with the exact committed text."]
    )
    before = (
        "The run has not read the current host clipboard."
        if op == "read"
        else "The host clipboard has not been changed by this operation."
    )
    after = (
        "The clipboard contents are available to the current run."
        if op == "read"
        else "The host clipboard contains the reviewed text."
    )
    return require_operation_consent(
        f"clipboard.{op}",
        risk="high",
        scope=f"host clipboard / {op}",
        detail=f"{op.title()} the host clipboard once.",
        provenance="clipboard",
        target=_clipboard_target(),
        parameters=parameters,
        parameter_summary=[
            (
                "Read the clipboard value present at the effect boundary."
                if op == "read"
                else f"Write the exact {len(text or '')}-character value committed by SHA-256."
            )
        ],
        known_effects=effects,
        unresolved_assumptions=[
            "The clipboard may contain sensitive data owned by another application."
        ],
        before=before,
        after=after,
        irreversible=op == "write",
        target_provider=_clipboard_target,
        parameters_provider=lambda: dict(parameters),
        credential_versions_provider=lambda: {
            "state": "not_applicable",
            "surface": "host-desktop-clipboard",
        },
        budget_provider=lambda: {"backend_timeout_seconds": 5},
        allow_auto_approve=False,
        consult_ledger=False,
    )


def _run(args: dict[str, Any]) -> str:
    if os.environ.get("MAVERICK_CLIPBOARD_DISABLE") == "1":
        return "ERROR: clipboard tool disabled by MAVERICK_CLIPBOARD_DISABLE=1"
    op = args.get("op")
    if op == "write" and not isinstance(args.get("text", ""), str):
        return "ERROR: write text must be a string"
    if op not in ("read", "write"):
        return f"ERROR: unknown op {op!r}"
    text = args.get("text", "") if op == "write" else None
    from ..approval_cards import ApprovalCardError
    from ..safety import ConsentDenied, consume_operation_consent

    try:
        permit = _operation_permit(op, text)
    except ConsentDenied:
        return "ERROR: clipboard access was not approved; no clipboard action was sent"
    except ApprovalCardError:
        return (
            "ERROR: the clipboard target or approval authority changed; "
            "review it again"
        )
    if op == "read":
        try:
            with consume_operation_consent(permit):
                val = _read_clipboard()
        except ApprovalCardError:
            return (
                "ERROR: the clipboard target or approval authority changed; "
                "review it again"
            )
        if val is None:
            return (
                "ERROR: no clipboard backend available. Install one of: "
                "pyperclip (pip), xclip / xsel (X11), wl-clipboard (Wayland)."
            )
        return val
    if op == "write":
        try:
            with consume_operation_consent(permit):
                wrote = _write_clipboard(text)
        except ApprovalCardError:
            return (
                "ERROR: the clipboard target or approval authority changed; "
                "review it again"
            )
        if wrote:
            return f"wrote {len(text)} chars to clipboard"
        return (
            "ERROR: no clipboard backend available. Install one of: "
            "pyperclip (pip), xclip / xsel (X11), wl-clipboard (Wayland)."
        )
    raise AssertionError("validated clipboard operation was not handled")


def clipboard() -> Tool:
    return Tool(
        name="clipboard",
        description=(
            "Read or write the system clipboard. ops: read (returns "
            "current clipboard contents), write (sets clipboard to text). "
            "Useful for bridging between the browser/computer-use/shell "
            "tools and the user's editor. MAVERICK_CLIPBOARD_DISABLE=1 "
            "disables. Requires pyperclip OR xclip/xsel/wl-clipboard."
        ),
        input_schema=_CLIPBOARD_SCHEMA,
        fn=_run,
    )
