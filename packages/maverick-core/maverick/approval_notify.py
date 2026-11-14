"""Tell chat channels that a new approval is waiting.

``approval_created`` is called by the world model right after an approval row
is committed -- the one call site for new-approval announcements. It never
blocks or fails the caller: the work happens on a background thread that
carries the caller's tenant context, every error is logged, and nothing
starts at all when no channel could post a card. The posting itself is
:func:`maverick.channel_approvals.announce_new_approval`: Slack is built in,
Microsoft Teams (``[channels.teams] approvals_enabled``) is registered here
through :func:`maverick.channel_approvals.register_approval_announcer`, and
other adapters register the same way.
"""
from __future__ import annotations

import contextvars
import logging
import threading

log = logging.getLogger(__name__)


def teams_approvals_enabled(cfg: dict | None = None) -> bool:
    if cfg is None:
        try:
            from .config import load_config

            cfg = ((load_config() or {}).get("channels") or {}).get("teams") or {}
        except Exception:  # noqa: BLE001 -- config never blocks an approval
            return False
    return bool(isinstance(cfg, dict) and cfg.get("enabled") and cfg.get("approvals_enabled"))


def _teams_announcer(approval, content: dict) -> bool:
    """Post the card to every linked Teams approver (the Teams adapter's poster)."""
    del content  # the Teams card renders from the dashboard's queue projection
    if not teams_approvals_enabled():
        return False
    from maverick_channels.teams import post_approval_to_linked_users

    return bool(post_approval_to_linked_users(int(approval.id)))


def install_announcers() -> None:
    """Register the Teams poster with the shared announcer registry (idempotent)."""
    from .channel_approvals import register_approval_announcer, registered_announcers

    if "teams" not in registered_announcers():
        register_approval_announcer("teams", _teams_announcer)


def announcements_configured() -> bool:
    """Whether any channel could post a new-approval card right now."""
    from .channel_approvals import registered_announcers, slack_announcements_configured

    if teams_approvals_enabled() or slack_announcements_configured():
        return True
    return any(name != "teams" for name in registered_announcers())


def approval_created(approval_id: int, *, provenance: str | None = None, world=None) -> None:
    """Post the approval to every configured chat channel, in the background.

    ``world`` identifies the database that committed the row. The thread opens
    its own connection so the caller may close its world immediately.
    """
    if provenance == "settings_quorum":
        return  # protected-settings changes are decided in the dashboard only
    from . import practice
    if practice.active():  # practice approvals stay in the practice Approvals page
        practice.record("approval card", "Slack or Teams approval card", {"approval": approval_id})
        return
    install_announcers()
    if not announcements_configured():
        return
    context = contextvars.copy_context()
    world_path = getattr(world, "path", None)

    def run() -> None:
        try:
            from .channel_approvals import announce_new_approval
            from .world_model import close_world_if_owned, open_world

            # Preserve explicit CLI/test database paths as well as the tenant
            # context, without retaining the caller's connection lifetime.
            wm = context.run(open_world, world_path) if world_path is not None else context.run(open_world)
            try:
                context.run(announce_new_approval, wm, int(approval_id))
            finally:
                context.run(close_world_if_owned, wm)
        except Exception:  # noqa: BLE001 -- a failed post never blocks the queue
            log.warning("could not announce approval #%s", approval_id, exc_info=True)

    threading.Thread(target=run, name=f"approval-announce-{approval_id}", daemon=True).start()


__all__ = ["announcements_configured", "approval_created", "install_announcers",
           "teams_approvals_enabled"]
