"""The catalogue of outbound webhook events for privacy and governance records.

Every event a subscription can ask for is named here, with the record type it
is about and a plain description (the Settings page and ``docs/webhooks.md``
read this table). :func:`emit` builds the shared envelope (see
``webhooks.build_envelope``) and hands it to the dispatcher; it never raises
into the caller, so recording a request or deciding an incident is never
blocked by a webhook.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# event type -> (record type, what it means)
EVENT_CATALOG: dict[str, tuple[str, str]] = {
    "goal_created": ("goal", "A goal was created."),
    "goal_waiting": ("goal", "A task paused while waiting for your answer or more information."),
    "goal_finished": ("goal", "A goal finished (or its gated result is awaiting sign-off)."),
    "episode_finished": ("goal", "One attempt at a goal finished."),
    "final_emitted": ("goal", "A goal produced its final output."),
    "deliverable.approved": ("deliverable", "A person signed off a gated deliverable."),
    "dsar.opened": ("dsar", "A data-subject request was opened."),
    "dsar.verified": ("dsar", "The requester's identity was verified."),
    "dsar.acknowledged": ("dsar", "Receipt of the request was confirmed to the requester."),
    "dsar.due_soon": ("dsar", "A data-subject request is due soon or due today."),
    "dsar.overdue": ("dsar", "A data-subject request passed its deadline."),
    "dsar.extended": ("dsar", "A data-subject request's deadline was extended."),
    "dsar.closed": ("dsar", "A data-subject request was answered or closed."),
    "incident.opened": ("incident", "A privacy incident was opened (the 72-hour clock started)."),
    "incident.notifiable_decided": ("incident", "Someone decided whether the incident must be notified."),
    "incident.due_soon": ("incident", "The 72-hour notification deadline is close or has passed."),
    "incident.closed": ("incident", "A privacy incident was closed."),
    "assessment.assigned": ("assessment", "An assessment was put on someone's desk (or taken off it)."),
    "assessment.decided": ("assessment", "A reviewer approved or rejected an assessment."),
    "assessment.renewal_due": ("assessment", "An assessment's renewal or review date is close or has passed."),
    "vendor.contract_renewal_due": ("vendor", "A vendor contract's renewal date is close or has passed."),
    "vendor.review_due": ("vendor", "A vendor review is due."),
    "approval.created": ("approval", "An action was parked for human approval."),
    "approval.decided": ("approval", "An approval was approved or denied."),
    "approval.undone": ("approval", "A decision was undone within its undo window; the approval is waiting again."),
    "approval.expired": ("approval", "An approval card expired before anyone decided."),
    "policy.published": ("policy", "A policy version was published."),
    "webhook.test": ("webhook_subscription", "A test event sent from the Webhooks settings page."),
}
EVENT_TYPES: frozenset[str] = frozenset(EVENT_CATALOG)


def catalog() -> list[dict[str, str]]:
    """The events as rows for a page: ``[{type, record, description}]``."""
    return [{"type": name, "record": rec, "description": text}
            for name, (rec, text) in EVENT_CATALOG.items()]


def emit(
    event_type: str,
    *,
    record_type: str,
    record_id: str,
    title: str = "",
    summary: dict[str, Any] | None = None,
    link: str = "",
    payload: dict[str, Any] | None = None,
    occurred_at: float | None = None,
    world: Any = None,
) -> int:
    """Fire ``event_type`` about one record. Returns deliveries started (0 when
    nothing is subscribed) and never raises."""
    if event_type not in EVENT_TYPES:
        log.warning("webhook_events: unknown event type %r not sent", event_type)
        return 0
    record = {"type": record_type, "id": str(record_id), "title": str(title or "")[:300]}
    if summary:
        record.update({k: v for k, v in summary.items() if k not in ("type", "id", "title")})
    try:
        from .webhooks import fire
        return fire(event_type, dict(payload or {}), record=record, link=link,
                    occurred_at=occurred_at, world=world)
    except Exception as exc:  # never block the record change
        log.warning("webhook_events: %s not sent: %s", event_type, type(exc).__name__)
        return 0


def record_link(path: str) -> str:
    """An absolute link to a dashboard page when ``[dashboard] public_url`` (or
    ``MAVERICK_PUBLIC_URL``) is set, otherwise the path itself."""
    import os

    base = os.environ.get("MAVERICK_PUBLIC_URL", "").strip()
    if not base:
        try:
            from .config import load_config
            base = str(((load_config() or {}).get("dashboard") or {}).get("public_url") or "").strip()
        except Exception:
            base = ""
    if not base:
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


__all__ = ["EVENT_CATALOG", "EVENT_TYPES", "catalog", "emit", "record_link"]
