"""One plain-language word for where a task's run stands.

The chat page's status badge, its composer (Stop and Send) and the chat list
in the sidebar all describe the same run, so they share one vocabulary. The
orchestrator writes ``active`` while a task works (``running`` and
``in_progress`` are older spellings), ``pending`` while it waits for a worker,
``blocked`` when it pauses for a person or stops on a problem, and one of
``done``/``failed``/``cancelled`` when it is over. The browser copy of this
table is ``static/lightwork-run-status.js``; a test keeps the two in step.
"""
from __future__ import annotations

# Stops whose cause is a broken AI connection or a fault inside Lightwork. The
# run is over until someone fixes the cause and starts it again, so the chat
# says "Stopped" rather than "Paused".
STOPPED_KINDS = frozenset({
    "provider_not_ready", "provider_authentication", "provider_rate_limit",
    "provider_model_not_found", "provider_unavailable", "provider_connection",
    "provider_configuration", "internal_error", "unpriced_model", "process_restart",
})

LABELS = {
    "draft": "Queued",
    "pending": "Queued",
    "active": "Working",
    "running": "Working",
    "in_progress": "Working",
    "blocked": "Paused",
    "done": "Done",
    "completed": "Done",
    "failed": "Failed",
    "error": "Failed",
    "cancelled": "Stopped",
}


def status_label(status: str | None, stop_kind: str | None = None) -> str:
    """The word a person reads for ``status`` ("" for a state with no word)."""
    value = str(status or "").strip().lower()
    if value == "blocked" and stop_kind in {
        "specialist_setup", "specialist_needs_web_search", "specialist_needs_connection"
    }:
        return "Can't start"
    if value == "blocked" and stop_kind in STOPPED_KINDS:
        return "Stopped"
    return LABELS.get(value, "")


__all__ = ["LABELS", "STOPPED_KINDS", "status_label"]
