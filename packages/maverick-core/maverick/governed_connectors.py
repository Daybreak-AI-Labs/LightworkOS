"""Governed connectors -- act on external systems of record through typed,
audited Actions (NOT a data-integration platform).

Agents must read and write systems of record (CRM, ticketing, ERP) -- but every such operation should be a typed,
risk-classed, lineage-tracked :class:`~maverick.governed_actions.ActionSpec`,
never a raw call. A :class:`Connector` adapts one external system into governed
Actions named ``<connector>.read`` (low risk) and ``<connector>.write`` (high
risk, so it hits the approval floor): each previews its effect before commit and
records a lineage link after.

This ships the FRAMEWORK + a reference in-memory connector; a real connector
(Salesforce, ServiceNow, SAP, ...) implements the same tiny surface against a
live system. Opt-in/additive -- registering a connector is an explicit choice.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .governed_actions import ActionSpec, GovernedActions


class Connector:
    """Adapts an external system of record into governed read/write Actions.

    Subclasses set ``name`` + the typed param schemas and implement ``read`` /
    ``write`` / ``preview_write`` (the simulator -- it must have NO side
    effects)."""
    name: str = "connector"
    read_params: dict[str, type] = {"key": str}
    write_params: dict[str, type] = {"key": str, "value": str}

    def read(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError

    def preview_write(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError

    def write(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError


def register_connector(ga: GovernedActions, conn: Connector) -> tuple[str, str]:
    """Register ``conn``'s read (low risk) + write (high risk) as governed
    Actions. Returns the two action names. Writes preview their effect and hit
    the approval floor; both are lineage-tracked once committed."""
    read_name, write_name = f"{conn.name}.read", f"{conn.name}.write"
    ga.register(ActionSpec(
        name=read_name, params=dict(conn.read_params), risk="low",
        simulate=lambda p, c=conn: f"would read {c.name}: {p}",
        apply=lambda p, c=conn: c.read(p)))
    ga.register(ActionSpec(
        name=write_name, params=dict(conn.write_params), risk="high",
        simulate=lambda p, c=conn: c.preview_write(p),
        apply=lambda p, c=conn: c.write(p)))
    return read_name, write_name


@dataclass
class InMemoryConnector(Connector):
    """Reference connector + test double: a dict standing in for a system of
    record. Real connectors implement the same surface against a live system."""
    name: str = "memory"
    store: dict[str, str] = field(default_factory=dict)
    read_params: dict[str, type] = field(default_factory=lambda: {"key": str})
    write_params: dict[str, type] = field(default_factory=lambda: {"key": str, "value": str})

    def read(self, params: dict) -> str:
        return str(self.store.get(params["key"], "(missing)"))

    def preview_write(self, params: dict) -> str:
        old = self.store.get(params["key"], "(none)")
        return f"{params['key']}: {old!r} -> {params['value']!r}"

    def write(self, params: dict) -> str:
        self.store[params["key"]] = params["value"]
        return f"wrote {params['key']}"


__all__ = ["Connector", "InMemoryConnector", "register_connector"]
