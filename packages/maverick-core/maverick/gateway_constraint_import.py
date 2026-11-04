"""Closed, preview-only imports of restrictive external gateway constraints.

An external AI gateway may expose restrictions that are useful alongside a
Lightwork-compiled regulatory policy.  This module accepts only a small,
digest-only schema of *restrictive* constraints and projects it over the
compiler's JSON verdict table for an operator or auditor to inspect.

It never accepts an allow, exemption, or policy replacement; it never writes
the imported data into runtime configuration; and it never claims that a
gateway assertion, revision digest, transport, or signature has been verified.
An integrating deployment must independently verify authenticity and choose a
separate reviewed configuration path before any gateway constraint is enforced.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import policy_exports

GATEWAY_CONSTRAINT_IMPORT_SCHEMA = "lightwork.gateway-constraint-import.v1"
GATEWAY_CONSTRAINT_PROJECTION_SCHEMA = "lightwork.gateway-constraint-projection.v1"
GATEWAY_CONSTRAINT_IMPORT_NOTICE = (
    "Gateway constraints are a preview-only restrictive overlay. Their source, "
    "revision, transport, and signature are not verified by this import, and the "
    "projection does not change Lightwork runtime enforcement."
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
_ACTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_TOOL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_EFFECTS = frozenset({"deny", "require_human", "attenuate"})
_RISKS = ("low", "medium", "high")
_RISK_RANK = {risk: index for index, risk in enumerate(_RISKS)}


class GatewayConstraintImportError(ValueError):
    """The imported constraint document is not a closed restrictive overlay."""


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise GatewayConstraintImportError("constraint import is not canonical JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise GatewayConstraintImportError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise GatewayConstraintImportError(f"{label} has unsupported or missing fields")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise GatewayConstraintImportError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise GatewayConstraintImportError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _members(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise GatewayConstraintImportError(f"{label} is outside its bound")
    members: list[str] = []
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise GatewayConstraintImportError(f"{label} contains an invalid identifier")
        members.append(item)
    if members != sorted(set(members)):
        raise GatewayConstraintImportError(f"{label} must be unique and sorted")
    return tuple(members)


def _risk(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _RISK_RANK:
        raise GatewayConstraintImportError("min_risk is invalid")
    return value


@dataclass(frozen=True, slots=True)
class GatewayConstraint:
    """One closed, restrictive external gateway assertion."""

    constraint_id: str
    effect: str
    actions: tuple[str, ...]
    min_risk: str | None
    deny_tools: tuple[str, ...]
    source_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.constraint_id,
            "effect": self.effect,
            "actions": list(self.actions),
            "min_risk": self.min_risk,
            "deny_tools": list(self.deny_tools),
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class GatewayConstraintImport:
    """Canonical parsed document with no raw source payload or credentials."""

    gateway_id: str
    revision_sha256: str
    constraints: tuple[GatewayConstraint, ...]
    import_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": GATEWAY_CONSTRAINT_IMPORT_SCHEMA,
            "gateway": {
                "id": self.gateway_id,
                "revision_sha256": self.revision_sha256,
            },
            "constraints": [item.to_dict() for item in self.constraints],
            "import_sha256": self.import_sha256,
        }


def parse_gateway_constraint_import(value: object) -> GatewayConstraintImport:
    """Parse a complete external-gateway constraint document fail closed."""

    root = _mapping(value, "constraint import")
    _exact_keys(root, frozenset({"schema", "gateway", "constraints"}), "constraint import")
    if root.get("schema") != GATEWAY_CONSTRAINT_IMPORT_SCHEMA:
        raise GatewayConstraintImportError("constraint import schema is unsupported")
    gateway = _mapping(root.get("gateway"), "gateway")
    _exact_keys(gateway, frozenset({"id", "revision_sha256"}), "gateway")
    gateway_id = _identifier(gateway.get("id"), "gateway id")
    revision_sha256 = _digest(gateway.get("revision_sha256"), "gateway revision")
    raw_constraints = root.get("constraints")
    if not isinstance(raw_constraints, list) or not 1 <= len(raw_constraints) <= 128:
        raise GatewayConstraintImportError("constraints must contain 1 through 128 items")

    constraints: list[GatewayConstraint] = []
    for raw in raw_constraints:
        item = _mapping(raw, "constraint")
        _exact_keys(
            item,
            frozenset({"id", "effect", "actions", "min_risk", "deny_tools", "source_sha256"}),
            "constraint",
        )
        constraint_id = _identifier(item.get("id"), "constraint id")
        effect = item.get("effect")
        if not isinstance(effect, str) or effect not in _EFFECTS:
            raise GatewayConstraintImportError("constraint effect is not restrictive")
        actions = _members(
            item.get("actions"), label="constraint actions", pattern=_ACTION_RE, maximum=250,
        )
        min_risk = _risk(item.get("min_risk"))
        deny_tools = _members(
            item.get("deny_tools"), label="constraint deny_tools", pattern=_TOOL_RE, maximum=250,
        )
        if not actions and min_risk is None and not deny_tools:
            raise GatewayConstraintImportError("constraint must restrict an action, risk, or tool")
        constraints.append(
            GatewayConstraint(
                constraint_id=constraint_id,
                effect=effect,
                actions=actions,
                min_risk=min_risk,
                deny_tools=deny_tools,
                source_sha256=_digest(item.get("source_sha256"), "constraint source"),
            )
        )
    if [item.constraint_id for item in constraints] != sorted(
        {item.constraint_id for item in constraints}
    ):
        raise GatewayConstraintImportError("constraint ids must be unique and sorted")
    parsed = GatewayConstraintImport(
        gateway_id=gateway_id,
        revision_sha256=revision_sha256,
        constraints=tuple(constraints),
        import_sha256="0" * 64,
    )
    return GatewayConstraintImport(
        gateway_id=parsed.gateway_id,
        revision_sha256=parsed.revision_sha256,
        constraints=parsed.constraints,
        import_sha256=_sha256({
            "schema": GATEWAY_CONSTRAINT_IMPORT_SCHEMA,
            "gateway": {
                "id": parsed.gateway_id,
                "revision_sha256": parsed.revision_sha256,
            },
            "constraints": [item.to_dict() for item in parsed.constraints],
        }),
    )


def _effective_decision(base: str, effects: Sequence[str]) -> str:
    order = {"allow": 0, "require_human": 1, "deny": 2}
    if base not in order:
        raise GatewayConstraintImportError("compiler verdict is invalid")
    selected = order[base]
    for effect in effects:
        if effect == "deny" or effect == "attenuate":
            selected = max(selected, order["deny"])
        elif effect == "require_human":
            selected = max(selected, order["require_human"])
        else:  # defensive: parser rejects this, but never silently widen.
            raise GatewayConstraintImportError("constraint effect is invalid")
    return next(name for name, rank in order.items() if rank == selected)


def project_gateway_constraints(
    value: object,
    *,
    profiles: Sequence[str],
) -> dict[str, Any]:
    """Overlay imported restrictions on a compiled verdict table for inspection.

    The output is complete only when every external selector maps to a currently
    classified Lightwork action.  Unknown selectors are returned explicitly;
    they are never dropped or treated as an allow.  The result is a preview,
    not a runtime policy object.
    """

    parsed = parse_gateway_constraint_import(value)
    table = policy_exports.build_json_verdict_table(profiles)
    verdicts = table.get("verdicts")
    if not isinstance(verdicts, list):
        raise GatewayConstraintImportError("compiler export omitted verdicts")
    by_action: dict[str, Mapping[str, Any]] = {}
    for row in verdicts:
        if not isinstance(row, Mapping):
            raise GatewayConstraintImportError("compiler export verdict is malformed")
        action = row.get("action")
        risk = row.get("risk")
        decision = row.get("decision")
        if (
            not isinstance(action, str)
            or not _ACTION_RE.fullmatch(action)
            or risk not in _RISK_RANK
            or decision not in {"allow", "require_human", "deny"}
        ):
            raise GatewayConstraintImportError("compiler export verdict is invalid")
        by_action[action] = row

    applied: dict[str, list[GatewayConstraint]] = {action: [] for action in by_action}
    coverage: list[dict[str, object]] = []
    incomplete_ids: list[str] = []
    for constraint in parsed.constraints:
        requested = set(constraint.actions).union(constraint.deny_tools)
        matched = {action for action in requested if action in by_action}
        unmatched = requested - matched
        if constraint.min_risk is not None:
            threshold = _RISK_RANK[constraint.min_risk]
            matched.update(
                action for action, row in by_action.items()
                if _RISK_RANK[str(row["risk"])] >= threshold
            )
        if not matched or unmatched:
            incomplete_ids.append(constraint.constraint_id)
        for action in sorted(matched):
            applied[action].append(constraint)
        coverage.append({
            "constraint_id": constraint.constraint_id,
            "mapped_actions": sorted(matched),
            "unmapped_actions": sorted(unmatched),
            "complete": bool(matched) and not unmatched,
        })

    projected_verdicts: list[dict[str, object]] = []
    for action in sorted(by_action):
        base = by_action[action]
        constraints = sorted(applied[action], key=lambda item: item.constraint_id)
        effects = [item.effect for item in constraints]
        projected_verdicts.append({
            "action": action,
            "risk": base["risk"],
            "compiler_decision": base["decision"],
            "effective_decision": _effective_decision(str(base["decision"]), effects),
            "gateway_constraint_ids": [item.constraint_id for item in constraints],
            "attenuated": any(item.effect == "attenuate" for item in constraints),
        })
    return {
        "schema": GATEWAY_CONSTRAINT_PROJECTION_SCHEMA,
        "notice": GATEWAY_CONSTRAINT_IMPORT_NOTICE,
        "runtime_enforcement_changed": False,
        "gateway_source_verified": False,
        "import": parsed.to_dict(),
        "profiles": list(table["profiles"]),
        "compiler_description_sha256": table["compiler_description_sha256"],
        "coverage": coverage,
        "complete": not incomplete_ids,
        "incomplete_constraint_ids": sorted(incomplete_ids),
        "verdicts": projected_verdicts,
    }


__all__ = [
    "GATEWAY_CONSTRAINT_IMPORT_NOTICE",
    "GATEWAY_CONSTRAINT_IMPORT_SCHEMA",
    "GATEWAY_CONSTRAINT_PROJECTION_SCHEMA",
    "GatewayConstraint",
    "GatewayConstraintImport",
    "GatewayConstraintImportError",
    "parse_gateway_constraint_import",
    "project_gateway_constraints",
]
