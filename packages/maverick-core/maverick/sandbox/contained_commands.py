"""Commands in a closed container run without asking a person each time.

Every shell command used to wait for a person's approval, even in a Docker or
Podman container with no network: tasks that needed a short script (a chart
image, a spreadsheet edit) stalled on the Approvals page until someone came
back. ``[sandbox] contained_commands_without_approval`` (on by default, off by
default on an enterprise install) lets such commands run at once and records
each one in the audit log. It applies only to a Docker, Podman or gVisor
container whose network is off; a command on the host always asks.

A stricter choice still wins: an explicit consent mode that asks or refuses
(``MAVERICK_CONSENT_MODE`` or ``[safety] consent_mode``), a task's own consent
mode (director mode), and a workspace settings file that turns this off.
"""
from __future__ import annotations

SETTING = "contained_commands_without_approval"


def _default() -> bool:
    try:
        from ..enterprise import enterprise_enabled

        return not enterprise_enabled()
    except Exception:  # noqa: BLE001 -- an unreadable posture keeps asking
        return False


def enabled() -> bool:
    """The setting, read through the workspace-tightened configuration."""
    from .._envparse import coerce_bool
    from ..config import load_config

    try:
        section = load_config().get("sandbox", {}) or {}
    except Exception:  # noqa: BLE001 -- unreadable settings keep asking
        return False
    return coerce_bool(section.get(SETTING), _default())


def closed_container(sandbox) -> bool:
    """A Docker, Podman or gVisor container with its network off."""
    from .docker import DockerBackend
    from .podman import PodmanBackend

    return isinstance(sandbox, (DockerBackend, PodmanBackend)) and getattr(sandbox, "allow_network", True) is False


def runs_without_asking(sandbox) -> bool:
    """Whether a shell command in ``sandbox`` may run without a person's approval."""
    if not closed_container(sandbox) or not enabled():
        return False
    from ..safety.consent import person_must_decide

    return not person_must_decide()


__all__ = ["SETTING", "closed_container", "enabled", "runs_without_asking"]
