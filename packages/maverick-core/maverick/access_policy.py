"""Purpose / attribute-based access control (PBAC/ABAC) for agents.

Palantir-style access maturity: an operation is allowed not just by capability
TIER but by PURPOSE and data ATTRIBUTES -- "this agent may touch finance data
ONLY for the quarterly-audit purpose, and only if it holds the finance-cleared
attribute." A resource declares an :class:`AccessPolicy` (which purposes it
serves, which attributes a requester must hold); a run declares its purpose +
granted attributes (a contextvar, or ``MAVERICK_PURPOSE`` / ``_ATTRS``);
:func:`decide` allows iff the purpose is served AND every required attribute is
held.

Default-OPEN and additive (kernel rule 1): a resource with **no** policy is
unrestricted, so shipping this changes nothing out of the box. It composes
*above* capability/risk -- risk says "how dangerous", this says "for what
purpose, on whose data".
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

_PURPOSE: ContextVar[tuple[str, frozenset[str]] | None] = ContextVar(
    "mvk_purpose", default=None)


class AccessDenied(Exception):
    """A resource was accessed without a satisfying purpose/attributes."""


@dataclass(frozen=True)
class AccessPolicy:
    """What a resource requires. Empty ``purposes`` = any purpose; empty
    ``required_attributes`` = none required. Both empty = unrestricted."""
    purposes: frozenset[str] = field(default_factory=frozenset)
    required_attributes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "purposes", frozenset(self.purposes))
        object.__setattr__(self, "required_attributes", frozenset(self.required_attributes))

    @property
    def unrestricted(self) -> bool:
        return not self.purposes and not self.required_attributes


@dataclass(frozen=True)
class AccessRequest:
    """Who/what is asking: the run's declared purpose + granted attributes."""
    purpose: str
    attributes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", frozenset(self.attributes))


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str


def decide(request: AccessRequest, policy: AccessPolicy) -> AccessDecision:
    """Allow iff the request's purpose is served AND it holds every required
    attribute. Pure/deterministic."""
    if policy.purposes and request.purpose not in policy.purposes:
        return AccessDecision(False,
                              f"purpose {request.purpose!r} not in {sorted(policy.purposes)}")
    missing = policy.required_attributes - request.attributes
    if missing:
        return AccessDecision(False, f"missing required attribute(s) {sorted(missing)}")
    return AccessDecision(True, "ok")


def current_request() -> AccessRequest | None:
    """The active purpose/attributes, from the contextvar or the
    ``MAVERICK_PURPOSE`` / ``MAVERICK_PURPOSE_ATTRS`` env (comma-separated).
    ``None`` when no purpose is declared."""
    v = _PURPOSE.get()
    if v is not None:
        return AccessRequest(v[0], v[1])
    env = os.environ.get("MAVERICK_PURPOSE", "").strip()
    if env:
        attrs = frozenset(a.strip() for a in
                          os.environ.get("MAVERICK_PURPOSE_ATTRS", "").split(",") if a.strip())
        return AccessRequest(env, attrs)
    return None


def check(policy: AccessPolicy) -> AccessDecision:
    """Decide against the *active* request. A restricted resource accessed with
    NO declared purpose is denied; an unrestricted resource is always allowed."""
    req = current_request()
    if req is None:
        return (AccessDecision(True, "unrestricted") if policy.unrestricted
                else AccessDecision(False, "no purpose declared for a restricted resource"))
    return decide(req, policy)


def enforce(policy: AccessPolicy) -> None:
    """Raise :class:`AccessDenied` if the active request fails ``policy``."""
    d = check(policy)
    if not d.allowed:
        raise AccessDenied(d.reason)


@contextmanager
def purpose_scope(purpose: str, attributes: object = ()):
    """Run a block under a declared purpose + granted attributes."""
    token = _PURPOSE.set((purpose, frozenset(attributes)))
    try:
        yield
    finally:
        _PURPOSE.reset(token)


__all__ = ["AccessDenied", "AccessPolicy", "AccessRequest", "AccessDecision",
           "decide", "check", "enforce", "current_request", "purpose_scope"]
