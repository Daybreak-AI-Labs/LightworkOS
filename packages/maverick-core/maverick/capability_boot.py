"""Capability negotiation at swarm boot.

When the swarm spawns a child agent, the child today simply *inherits* the
parent's grant attenuated to its principal — it can't ask for a *narrower,
explicit* scope ("I only need read_file + http_fetch, low risk"), and there's
no record of what was agreed. Boot negotiation adds that handshake:

* a child declares a **requested** scope (tools / max_risk / paths / hosts);
* :func:`negotiate_boot` resolves it against the parent grant **narrow-only**
  (via :meth:`Capability.attenuate`, so a child can never gain authority the
  parent lacked), reports anything the parent *couldn't* grant, and fails the
  boot when a **required** capability isn't permitted (a specialist that
  genuinely needs a tool the parent can't grant shouldn't run half-equipped);
* the result carries a serializable **record** for the audit log.

Composes with the existing capability layer (``capability.Capability``) and
the ``capability_negotiation`` tool's set logic; deterministic and offline.
No-op when capability enforcement is off (the parent grant is ``None``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BootNegotiation:
    granted: Any                       # Capability | None (None == unrestricted)
    ok: bool                           # False iff a required cap was denied
    denied_tools: list[str] = field(default_factory=list)
    denied_required: list[str] = field(default_factory=list)
    reason: str = ""

    def record(self) -> dict:
        """A serializable summary for the audit log."""
        return {
            "ok": self.ok,
            "principal": getattr(self.granted, "principal", None),
            "denied_tools": list(self.denied_tools),
            "denied_required": list(self.denied_required),
            "reason": self.reason,
        }


def negotiate_boot(
    parent: Any,
    *,
    principal: str,
    requested_tools: set[str] | None = None,
    max_risk: str | None = None,
    required_tools: set[str] | None = None,
    allow_paths: set[str] | None = None,
    allow_hosts: set[str] | None = None,
) -> BootNegotiation:
    """Negotiate a child's boot capability against ``parent``.

    Returns a :class:`BootNegotiation`. With ``parent is None`` (enforcement
    off) the child is unrestricted and ``ok`` is True — there is nothing to
    negotiate. Otherwise the granted capability is the parent attenuated by the
    requested scope (narrow-only); any ``required_tools`` the granted capability
    does not permit make ``ok`` False so the caller can refuse the spawn.
    """
    if parent is None:
        return BootNegotiation(granted=None, ok=True,
                               reason="enforcement off; child unrestricted")

    granted = parent.attenuate(
        principal=principal,
        allow=requested_tools,
        max_risk=max_risk,
        allow_paths=allow_paths,
        allow_hosts=allow_hosts,
    )

    # What the parent couldn't grant from the request (informational).
    denied_tools: list[str] = []
    if requested_tools:
        denied_tools = sorted(t for t in requested_tools if not granted.permits(t))

    denied_required: list[str] = []
    if required_tools:
        denied_required = sorted(t for t in required_tools if not granted.permits(t))

    ok = not denied_required
    reason = ("ok" if ok else
              f"required capabilities not granted by parent: {denied_required}")
    return BootNegotiation(
        granted=granted, ok=ok,
        denied_tools=denied_tools, denied_required=denied_required, reason=reason,
    )


__all__ = ["BootNegotiation", "negotiate_boot"]
