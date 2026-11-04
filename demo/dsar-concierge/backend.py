"""The seam between the DSAR Concierge agent and the Lightwork platform.

The agent's record of truth is always the vendored ``dsar_engine`` store —
the same files whether standalone or platform-bundled, so moving to the
platform never migrates data. What the platform ADDS is mirrored through here: the request
also lands in the governed privacy workspace registers, every step hits the
signed audit chain, and fulfillment can use the platform's real
subject-data export machinery. Standalone, those calls are silent no-ops
and email delivers to the in-process capture inbox.
"""
from __future__ import annotations

import os
from typing import Any

from capabilities import CAPS, STANDALONE


def mirror_open(rec: dict) -> str:
    """Best-effort mirror of a new request into the platform's privacy
    workspace. Returns the platform-side id ('' standalone/failure)."""
    if not CAPS["privacy_workspace_sync"]:
        return ""
    try:
        from maverick import privacy_ops
        row = privacy_ops.open_dsar(
            rec["subject_id"], rec["kind"], channel=rec.get("channel", ""),
            opened_by="dsar-concierge")
        return str(row.get("id", ""))
    except Exception as exc:  # pragma: no cover - platform variance
        print(f"[mirror] open failed: {exc}")
        return ""


def mirror_close(rec: dict) -> None:
    if not CAPS["privacy_workspace_sync"] or not rec.get("platform_id"):
        return
    try:
        from maverick import privacy_ops
        privacy_ops.close_dsar(rec["platform_id"],
                               closed_by="dsar-concierge")
    except Exception as exc:  # pragma: no cover - platform variance
        print(f"[mirror] close failed: {exc}")


def audit_record(kind: str, **payload: Any) -> None:
    if not CAPS["signed_audit"]:
        return
    try:
        from maverick.audit import record
        record(kind, agent="dsar-concierge", **payload)
    except Exception as exc:  # pragma: no cover - platform variance
        print(f"[audit] {kind} failed: {exc}")


def send_email(to: str, subject: str, body: str) -> str:
    """Platform routes through the governed email tool; standalone delivers
    straight into the in-process capture inbox."""
    if STANDALONE:
        import mailsink
        sender = os.environ.get("EMAIL_USER", "privacy-office@company.com")
        mailsink.INBOX.insert(0, mailsink.Captured(
            to=to or "subject@example.com", sender=sender,
            subject=subject, body=body))
        return "ok (standalone: delivered to inbox)"
    from maverick.tools.email_tool import email_tool
    return email_tool().fn({"op": "send",
                            "to": to or "subject@example.com",
                            "subject": subject, "body": body})
