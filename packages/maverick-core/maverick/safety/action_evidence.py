"""Tamper-evident before/after capture for governed computer/browser actions.

When screenshot sealing is configured (``MAVERICK_SCREENSHOT_KEY`` / ``[safety]
screenshot_key``), a high-risk actuation -- a click on Pay, a Submit keystroke --
brackets its execution with a sealed screenshot: the screen the agent saw
*before* it acted and the result *after*. Each capture is written under
``data_dir("captures")``, sealed into the hash-chained screenshot ledger
(:mod:`maverick.screenshot_seal`), and logged as an ``EVIDENCE_CAPTURE`` audit
event -- correlated to the run via the goal-id context -- so ``/replay`` and the
exported evidence packet carry verifiable visual provenance for the
consequential actions.

Best-effort for capture and sealing failures: no key -> no capture. An explicit
audit policy/custody refusal still propagates, because reporting a governed
action as fully evidenced when the audit subsystem declined its row is a false
success.
"""
from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar

from ..audit import AuditRefused

log = logging.getLogger(__name__)

T = TypeVar("T")


def sealing_enabled() -> bool:
    """True if a screenshot sealing key is configured (the opt-in switch)."""
    try:
        from ..screenshot_seal import SealKeyMissing, _key
        try:
            _key(None)
            return True
        except SealKeyMissing:
            return False
    except Exception:  # pragma: no cover -- never let evidence checks crash
        return False


def seal_evidence(png_b64: str, *, action: str, phase: str) -> None:
    """Persist + seal a base64 PNG and log an ``EVIDENCE_CAPTURE`` audit event.

    ``phase`` is ``"before"`` or ``"after"``. Capture/seal failures are logged
    and swallowed; an explicit :class:`AuditRefused` propagates.
    """
    try:
        from ..paths import data_dir
        from ..screenshot_seal import seal
        captures = data_dir("captures")
        captures.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = captures / f"{stamp}-{phase}.png"
        path.write_bytes(base64.b64decode(png_b64))
        entry = seal(path)
        from ..audit import EventKind, audit_event
        audit_event(
            EventKind.EVIDENCE_CAPTURE,
            action=action, phase=phase, file=path.name, sha256=entry.sha256,
        )
    except AuditRefused:
        raise
    except Exception:  # pragma: no cover -- evidence is best-effort
        log.debug("action evidence seal failed", exc_info=True)


def _try_capture(capture_b64: Callable[[], str], *, action: str, phase: str) -> None:
    try:
        b64 = capture_b64()
    except Exception:  # pragma: no cover -- a flaky screenshot must not break the run
        log.debug("action evidence capture failed", exc_info=True)
        return
    seal_evidence(b64, action=action, phase=phase)


def seal_bracketed(capture_b64: Callable[[], str], run: Callable[[], T], *, action: str) -> T:
    """Run ``run()``; when sealing is on, bracket it with sealed before/after shots.

    ``capture_b64`` is a zero-arg callable returning a base64 PNG of the current
    screen/page. When sealing is off this is exactly ``run()`` with no overhead.
    The "after" capture runs even if ``run()`` raises, so a failed actuation is
    still evidenced.
    """
    if not sealing_enabled():
        return run()
    _try_capture(capture_b64, action=action, phase="before")
    try:
        return run()
    finally:
        _try_capture(capture_b64, action=action, phase="after")


__all__ = ["sealing_enabled", "seal_evidence", "seal_bracketed"]
