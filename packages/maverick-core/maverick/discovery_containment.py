"""Reviewed discover-then-contain bridge for non-identifying AI discovery.

Discovery sensor aggregates intentionally do not identify people or agents.
They must therefore never cause an automatic containment action.  This module
requires a human-prepared, four-eyes-reviewed binding from a *current*
aggregate finding to an already-enrolled ``agent:<id>`` principal, then routes
one chosen response through the existing Agent Control Plane (ACP).

Only SHA-256 finding/binding/control digests are retained in this bridge.  Raw
provider records, sensor observations, source application identifiers, user
identities, messages, and arbitrary operator text are never persisted here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .ai_discovery_sensors import DiscoverySensorService, SensorActor, default_service
from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

BINDING_SCHEMA = "lightwork.discovery-containment-binding.v1"
ACTION_SCHEMA = "lightwork.discovery-containment-action.v1"

_BINDINGS = GovernedRecordStore(
    "discovery_containment_bindings", "DCB", "discovery_containment_binding"
)
_ACTION_STORE = GovernedRecordStore(
    "discovery_containment_actions", "DCA", "discovery_containment_action"
)

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_HUMAN_RE = re.compile(r"user:[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_AGENT_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,126}[a-z0-9])?\Z")
_TOKEN_RE = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
_BINDING_ID_RE = re.compile(r"DCB-[0-9a-f]{32}\Z")
_ACTION_ID_RE = re.compile(r"DCA-[0-9a-f]{32}\Z")
_TENANT_REF_RE = re.compile(r"TEN-[0-9a-f]{24}\Z")
_MAX_BINDINGS = 2_000
_MAX_ACTIONS = 10_000
_MAX_LIST = 500
_MAX_JSON_BYTES = 64 * 1024
_CONTROL_ACTIONS = frozenset({"suspend", "contain", "attenuate", "halt"})
_STATUSES = frozenset({"pending_review", "approved"})
_ACTION_STATUSES = frozenset({"prepared", "committed", "failed"})
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_BINDING_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "finding_sha256",
        "agent_principal",
        "prepared_by",
        "prepared_at",
        "approval",
        "status",
        "binding_sha256",
        "state_sha256",
    }
)
_ACTION_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "binding_id",
        "finding_sha256",
        "binding_sha256",
        "agent_principal",
        "action",
        "request_sha256",
        "status",
        "control_sha256",
        "control_ok",
        "control_code",
        "state_sha256",
    }
)


class DiscoveryContainmentError(RuntimeError):
    """Base error for a reviewed discovery-to-control operation."""


class DiscoveryContainmentBindingError(DiscoveryContainmentError):
    """A finding/binding/target is stale, unknown, or not safe to use."""


class DiscoveryContainmentApprovalError(DiscoveryContainmentError):
    """A binding's required human review is absent or invalid."""


class DiscoveryContainmentStateError(DiscoveryContainmentError):
    """The bridge's tenant-scoped governed state is invalid or unavailable."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DiscoveryContainmentStateError("containment data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise DiscoveryContainmentStateError("containment data exceeds the closed bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(text):
        raise DiscoveryContainmentBindingError(f"{label} must be a SHA-256 digest")
    return text


def _actor(value: SensorActor) -> str:
    if not isinstance(value, SensorActor):
        raise TypeError("actor must be a SensorActor")
    principal = value.principal.strip() if isinstance(value.principal, str) else ""
    if not _HUMAN_RE.fullmatch(principal):
        raise DiscoveryContainmentBindingError(
            "binding actor must be an authenticated user principal"
        )
    return principal


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise DiscoveryContainmentStateError(
            "discovery containment operations require an explicit tenant"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _principal(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("agent:"):
        raise DiscoveryContainmentBindingError(
            "discovery containment target must be an agent principal"
        )
    agent_id = value.removeprefix("agent:")
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise DiscoveryContainmentBindingError("discovery containment agent is invalid")
    return f"agent:{agent_id}"


def _token(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _TOKEN_RE.fullmatch(text):
        raise DiscoveryContainmentBindingError(f"{label} is invalid")
    return text


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryContainmentStateError(f"{label} is invalid")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise DiscoveryContainmentStateError(f"{label} is invalid")
    return result


def _closed_record(
    value: object, fields: frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DiscoveryContainmentStateError(f"persisted {label} is invalid")
    unknown = set(value) - fields - _STORE_METADATA
    missing = fields - set(value)
    if unknown or missing:
        raise DiscoveryContainmentStateError(
            f"persisted {label} uses an invalid schema"
        )
    # Keep store metadata (especially ``revision``) for callers performing
    # compare-and-swap. It is excluded from the closed logical state hash.
    return copy.deepcopy(dict(value))


def _binding_state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(row[key]) for key in sorted(_BINDING_FIELDS - {"state_sha256"})}


def _action_state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(row[key]) for key in sorted(_ACTION_FIELDS - {"state_sha256"})}


def _binding_digest(*, tenant_ref: str, finding_sha256: str, agent_principal: str) -> str:
    return _sha256(
        {
            "schema": BINDING_SCHEMA,
            "tenant_ref": tenant_ref,
            "finding_sha256": finding_sha256,
            "agent_principal": agent_principal,
        }
    )


def _validate_binding(value: object, *, tenant_ref: str) -> dict[str, Any]:
    try:
        row = _closed_record(value, _BINDING_FIELDS, "discovery containment binding")
        if row["schema"] != BINDING_SCHEMA or row["tenant_ref"] != tenant_ref:
            raise ValueError("schema or tenant mismatch")
        if not _BINDING_ID_RE.fullmatch(str(row["id"] or "")):
            raise ValueError("binding id invalid")
        finding = _digest(row["finding_sha256"], "finding digest")
        principal = _principal(row["agent_principal"])
        preparer = _actor(SensorActor(str(row["prepared_by"])))
        prepared_at = _timestamp(row["prepared_at"], "prepared_at")
        status = str(row["status"] or "")
        if status not in _STATUSES:
            raise ValueError("binding status invalid")
        expected_binding_digest = _binding_digest(
            tenant_ref=tenant_ref,
            finding_sha256=finding,
            agent_principal=principal,
        )
        if _digest(row["binding_sha256"], "binding digest") != expected_binding_digest:
            raise ValueError("binding digest mismatch")
        approval = row["approval"]
        if approval is None:
            if status != "pending_review":
                raise ValueError("unapproved binding is not pending")
        else:
            if not isinstance(approval, Mapping) or set(approval) != {"approved_by", "approved_at"}:
                raise ValueError("approval invalid")
            approved_by = _actor(SensorActor(str(approval["approved_by"])))
            approved_at = _timestamp(approval["approved_at"], "approved_at")
            if approved_by == preparer or approved_at < prepared_at or status != "approved":
                raise ValueError("approval violates four-eyes")
            approval = {"approved_by": approved_by, "approved_at": approved_at}
        row.update(
            {
                "finding_sha256": finding,
                "agent_principal": principal,
                "prepared_by": preparer,
                "prepared_at": prepared_at,
                "approval": approval,
                "status": status,
                "binding_sha256": expected_binding_digest,
            }
        )
        if _digest(row["state_sha256"], "binding state digest") != _sha256(_binding_state(row)):
            raise ValueError("binding state digest mismatch")
    except (KeyError, TypeError, ValueError, DiscoveryContainmentError) as exc:
        if isinstance(exc, DiscoveryContainmentStateError):
            raise
        raise DiscoveryContainmentStateError(
            "persisted discovery containment binding is invalid"
        ) from exc
    return row


def _validate_action(value: object, *, tenant_ref: str) -> dict[str, Any]:
    try:
        row = _closed_record(value, _ACTION_FIELDS, "discovery containment action")
        if row["schema"] != ACTION_SCHEMA or row["tenant_ref"] != tenant_ref:
            raise ValueError("schema or tenant mismatch")
        if not _ACTION_ID_RE.fullmatch(str(row["id"] or "")):
            raise ValueError("action id invalid")
        if not _BINDING_ID_RE.fullmatch(str(row["binding_id"] or "")):
            raise ValueError("binding id invalid")
        finding = _digest(row["finding_sha256"], "finding digest")
        binding = _digest(row["binding_sha256"], "binding digest")
        principal = _principal(row["agent_principal"])
        action = _token(row["action"], "action")
        if action not in _CONTROL_ACTIONS:
            raise ValueError("action invalid")
        request_digest = _digest(row["request_sha256"], "request digest")
        status = str(row["status"] or "")
        if status not in _ACTION_STATUSES:
            raise ValueError("action status invalid")
        control_sha = row["control_sha256"]
        control_ok = row["control_ok"]
        control_code = row["control_code"]
        if status == "prepared":
            if control_sha is not None or control_ok is not None or control_code is not None:
                raise ValueError("prepared action has a control result")
        else:
            control_sha = _digest(control_sha, "control digest")
            if not isinstance(control_ok, bool):
                raise ValueError("control result is invalid")
            code = _token(control_code or "not_applied", "control code")
            if status == "committed" and control_ok is not True:
                raise ValueError("committed action was not successful")
            if status == "failed" and control_ok is not False:
                raise ValueError("failed action was not unsuccessful")
            control_code = code
        row.update(
            {
                "finding_sha256": finding,
                "binding_sha256": binding,
                "agent_principal": principal,
                "action": action,
                "request_sha256": request_digest,
                "status": status,
                "control_sha256": control_sha,
                "control_ok": control_ok,
                "control_code": control_code,
            }
        )
        if _digest(row["state_sha256"], "action state digest") != _sha256(_action_state(row)):
            raise ValueError("action state digest mismatch")
    except (KeyError, TypeError, ValueError, DiscoveryContainmentError) as exc:
        if isinstance(exc, DiscoveryContainmentStateError):
            raise
        raise DiscoveryContainmentStateError(
            "persisted discovery containment action is invalid"
        ) from exc
    return row


@dataclass(frozen=True)
class _ControlOutcome:
    ok: bool
    code: str


class DiscoveryContainmentService:
    """Store reviewed bindings and apply only explicitly chosen ACP verbs."""

    def __init__(
        self,
        *,
        sensor_service: DiscoverySensorService | None = None,
        bindings: GovernedRecordStore | None = None,
        actions: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._sensors = sensor_service or default_service()
        if not isinstance(self._sensors, DiscoverySensorService):
            raise TypeError("sensor_service must be a DiscoverySensorService")
        self._bindings = bindings or _BINDINGS
        self._actions = actions or _ACTION_STORE
        self._clock = clock

    def _now(self) -> float:
        source = self._clock or self._bindings.authoritative_time
        try:
            return _timestamp(source(), "authority time")
        except DiscoveryContainmentStateError:
            raise
        except Exception as exc:
            raise DiscoveryContainmentStateError("containment clock is unavailable") from exc

    def _require_backends(self) -> str:
        if self._bindings.backend_kind != self._actions.backend_kind:
            raise DiscoveryContainmentStateError(
                "binding and action stores use different backends"
            )
        return _tenant_ref()

    def _current_finding(self, finding_sha256: str) -> Mapping[str, Any] | None:
        try:
            aggregate = self._sensors.aggregate_findings()
        except Exception as exc:
            if isinstance(exc, DiscoveryContainmentError):
                raise
            raise DiscoveryContainmentStateError(
                "discovery aggregate authority is unavailable"
            ) from exc
        findings = aggregate.get("findings") if isinstance(aggregate, Mapping) else None
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes, bytearray)):
            raise DiscoveryContainmentStateError("discovery aggregate is invalid")
        for finding in findings:
            if isinstance(finding, Mapping) and finding.get("finding_sha256") == finding_sha256:
                return finding
        return None

    def _require_current_finding(self, finding_sha256: str) -> None:
        if self._current_finding(finding_sha256) is None:
            raise DiscoveryContainmentBindingError(
                "discovery finding is not currently approved by sensor authority"
            )

    @staticmethod
    def _require_enrolled(principal: str) -> None:
        agent_id = principal.removeprefix("agent:")
        try:
            from .agent_trust import load_registry_strict
            from .external_agents import containment_state

            registry = load_registry_strict()
            if registry.get(agent_id) is None:
                raise DiscoveryContainmentBindingError(
                    "discovery target is not enrolled in the trust registry"
                )
            if containment_state(agent_id) is None:
                raise DiscoveryContainmentBindingError(
                    "discovery target is not enrolled in the external-agent gateway"
                )
        except DiscoveryContainmentBindingError:
            raise
        except Exception as exc:
            raise DiscoveryContainmentStateError(
                "external-agent enrollment authority is unavailable"
            ) from exc

    @staticmethod
    def _binding_id(tenant_ref: str, finding_sha256: str, principal: str) -> str:
        return "DCB-" + _sha256(
            {
                "tenant_ref": tenant_ref,
                "finding_sha256": finding_sha256,
                "agent_principal": principal,
            }
        )[:32]

    def _get_binding(self, binding_id: str, tenant_ref: str) -> dict[str, Any]:
        if not _BINDING_ID_RE.fullmatch(str(binding_id or "")):
            raise ValueError("binding_id is invalid")
        row = self._bindings.get(binding_id)
        if row is None:
            raise DiscoveryContainmentBindingError("discovery containment binding does not exist")
        return _validate_binding(row, tenant_ref=tenant_ref)

    def _binding_public(self, row: Mapping[str, Any]) -> dict[str, Any]:
        current = self._current_finding(str(row["finding_sha256"])) is not None
        return {
            "binding_id": row["id"],
            "finding_sha256": row["finding_sha256"],
            "agent_principal": row["agent_principal"],
            "status": row["status"],
            "current": current,
            "binding_sha256": row["binding_sha256"],
            "revision": row.get("revision"),
        }

    def prepare_binding(
        self,
        finding_sha256: str,
        *,
        agent_principal: str,
        actor: SensorActor,
    ) -> dict[str, Any]:
        """Stage an explicit human binding; it does not take any action."""

        tenant_ref = self._require_backends()
        finding = _digest(finding_sha256, "finding digest")
        principal = _principal(agent_principal)
        preparer = _actor(actor)
        self._require_current_finding(finding)
        self._require_enrolled(principal)
        binding_id = self._binding_id(tenant_ref, finding, principal)
        existing = self._bindings.get(binding_id)
        if existing is not None:
            return self._binding_public(_validate_binding(existing, tenant_ref=tenant_ref))
        row: dict[str, Any] = {
            "id": binding_id,
            "schema": BINDING_SCHEMA,
            "tenant_ref": tenant_ref,
            "finding_sha256": finding,
            "agent_principal": principal,
            "prepared_by": preparer,
            "prepared_at": self._now(),
            "approval": None,
            "status": "pending_review",
            "binding_sha256": _binding_digest(
                tenant_ref=tenant_ref,
                finding_sha256=finding,
                agent_principal=principal,
            ),
        }
        row["state_sha256"] = _sha256(_binding_state(row))
        try:
            saved = self._bindings.create(
                row,
                action="prepare_discovery_containment_binding",
                actor=preparer,
                max_records=_MAX_BINDINGS,
            )
        except RecordConflict:
            concurrent = self._bindings.get(binding_id)
            if concurrent is None:
                raise
            saved = _validate_binding(concurrent, tenant_ref=tenant_ref)
        return self._binding_public(_validate_binding(saved, tenant_ref=tenant_ref))

    def approve_binding(
        self,
        binding_id: str,
        *,
        expected_revision: int,
        actor: SensorActor,
    ) -> dict[str, Any]:
        """Four-eyes approve a current finding-to-enrolled-agent binding."""

        tenant_ref = self._require_backends()
        reviewer = _actor(actor)
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 1:
            raise ValueError("expected_revision is invalid")
        current = self._get_binding(binding_id, tenant_ref)
        if current["status"] == "approved":
            return self._binding_public(current)
        if current["prepared_by"] == reviewer:
            raise DiscoveryContainmentApprovalError(
                "discovery containment approval requires a different human"
            )
        self._require_current_finding(current["finding_sha256"])
        self._require_enrolled(current["agent_principal"])
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["approval"] = {"approved_by": reviewer, "approved_at": now}
            row["status"] = "approved"
            row["state_sha256"] = _sha256(_binding_state(row))

        saved = self._bindings.update(
            binding_id,
            mutate,
            expected_revision=expected_revision,
            action="approve_discovery_containment_binding",
            actor=reviewer,
        )
        if saved is None:
            raise DiscoveryContainmentStateError("discovery containment binding disappeared")
        return self._binding_public(_validate_binding(saved, tenant_ref=tenant_ref))

    def get_binding(self, binding_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_backends()
        if not _BINDING_ID_RE.fullmatch(str(binding_id or "")):
            raise ValueError("binding_id is invalid")
        row = self._bindings.get(binding_id)
        if row is None:
            return None
        return self._binding_public(_validate_binding(row, tenant_ref=tenant_ref))

    @staticmethod
    def _attenuation(
        *,
        deny_tools: Sequence[str] = (),
        max_risk: str | None = None,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
    ) -> dict[str, Any]:
        if isinstance(deny_tools, (str, bytes, bytearray)) or not isinstance(deny_tools, Sequence):
            raise DiscoveryContainmentBindingError("deny_tools is invalid")
        if len(deny_tools) > 64:
            raise DiscoveryContainmentBindingError("deny_tools exceeds the closed bound")
        checked_tools: list[str] = []
        for value in deny_tools:
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > 256
                or not value.strip().isprintable()
            ):
                raise DiscoveryContainmentBindingError("deny_tools is invalid")
            checked_tools.append(value.strip())
        if len(set(checked_tools)) != len(checked_tools):
            raise DiscoveryContainmentBindingError("deny_tools contains duplicates")
        risk = None if max_risk is None else _token(max_risk, "max_risk")
        if risk is not None and risk not in {"low", "medium", "high"}:
            raise DiscoveryContainmentBindingError("max_risk is invalid")

        def _ceiling(value: float | None, label: str) -> float | None:
            if value is None:
                return None
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DiscoveryContainmentBindingError(f"{label} is invalid")
            result = float(value)
            if not math.isfinite(result) or result <= 0:
                raise DiscoveryContainmentBindingError(f"{label} is invalid")
            return result

        return {
            "deny_tools": tuple(sorted(checked_tools)),
            "max_risk": risk,
            "max_dollars": _ceiling(max_dollars, "max_dollars"),
            "max_wall_seconds": _ceiling(max_wall_seconds, "max_wall_seconds"),
        }

    @staticmethod
    def _request_digest(
        *,
        binding: Mapping[str, Any],
        action: str,
        reason_code: str,
        operation_key: str,
        attenuation: Mapping[str, Any],
    ) -> str:
        return _sha256(
            {
                "binding_sha256": binding["binding_sha256"],
                "finding_sha256": binding["finding_sha256"],
                "agent_principal": binding["agent_principal"],
                "action": action,
                "reason_code": reason_code,
                "operation_key": operation_key,
                "attenuation": dict(attenuation),
            }
        )

    @staticmethod
    def _action_id(tenant_ref: str, binding_id: str, request_sha256: str) -> str:
        return "DCA-" + _sha256(
            {
                "tenant_ref": tenant_ref,
                "binding_id": binding_id,
                "request_sha256": request_sha256,
            }
        )[:32]

    @staticmethod
    def _action_public(row: Mapping[str, Any]) -> dict[str, Any]:
        status = str(row["status"])
        return {
            "action_id": row["id"],
            "binding_id": row["binding_id"],
            "finding_sha256": row["finding_sha256"],
            "binding_sha256": row["binding_sha256"],
            "agent_principal": row["agent_principal"],
            "action": row["action"],
            "status": "indeterminate" if status == "prepared" else status,
            "control": (
                None
                if status == "prepared"
                else {"ok": row["control_ok"], "code": row["control_code"]}
            ),
            "control_sha256": row["control_sha256"],
            "revision": row.get("revision"),
        }

    @staticmethod
    def _apply_control(
        *,
        action: str,
        principal: str,
        reason_code: str,
        actor: str,
        attenuation: Mapping[str, Any],
    ) -> _ControlOutcome:
        from . import agent_control_plane as acp

        reason = f"discovery-{reason_code}"
        try:
            if action == "suspend":
                result = acp.suspend(principal, reason=reason, actor=actor)
            elif action == "contain":
                result = acp.contain(principal, reason=reason, actor=actor)
            elif action == "attenuate":
                result = acp.attenuate(principal, actor=actor, **dict(attenuation))
            else:
                result = acp.halt_all(reason, actor=actor)
        except acp.ControlPlaneDisabled:
            return _ControlOutcome(False, "control_plane_disabled")
        except acp.ControlPlaneDependencyError:
            return _ControlOutcome(False, "dependency_unavailable")
        except (LookupError, ValueError):
            return _ControlOutcome(False, "refused")
        except Exception:
            return _ControlOutcome(False, "dependency_unavailable")
        code = _token(getattr(result, "code", None) or ("ok" if result.ok else "not_applied"), "control code")
        return _ControlOutcome(bool(result.ok), code)

    def execute(
        self,
        binding_id: str,
        *,
        action: str,
        reason_code: str,
        operation_key: str,
        actor: SensorActor,
        deny_tools: Sequence[str] = (),
        max_risk: str | None = None,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Prepare, apply, then commit one ACP action without automatic replay.

        A durable PREPARE row is written before invoking ACP.  If the process
        dies after an external control effect but before the terminal update,
        retrying the same operation returns ``indeterminate`` rather than
        guessing that it is safe to perform a second control operation.
        """

        tenant_ref = self._require_backends()
        reviewed_by = _actor(actor)
        chosen_action = _token(action, "action")
        if chosen_action not in _CONTROL_ACTIONS:
            raise DiscoveryContainmentBindingError("action is unsupported")
        safe_reason = _token(reason_code, "reason_code")
        safe_operation_key = _token(operation_key, "operation_key")
        binding = self._get_binding(binding_id, tenant_ref)
        if binding["status"] != "approved":
            raise DiscoveryContainmentApprovalError(
                "discovery containment binding is not human reviewed"
            )
        self._require_current_finding(binding["finding_sha256"])
        self._require_enrolled(binding["agent_principal"])
        attenuation = self._attenuation(
            deny_tools=deny_tools,
            max_risk=max_risk,
            max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds,
        )
        if chosen_action != "attenuate" and any(
            value not in (None, ()) for value in attenuation.values()
        ):
            raise DiscoveryContainmentBindingError(
                "attenuation controls are valid only for an attenuate action"
            )
        request_sha = self._request_digest(
            binding=binding,
            action=chosen_action,
            reason_code=safe_reason,
            operation_key=safe_operation_key,
            attenuation=attenuation,
        )
        action_id = self._action_id(tenant_ref, binding_id, request_sha)
        existing = self._actions.get(action_id)
        if existing is not None:
            row = _validate_action(existing, tenant_ref=tenant_ref)
            if row["request_sha256"] != request_sha:
                raise DiscoveryContainmentStateError("action identity was reused differently")
            return self._action_public(row)
        row: dict[str, Any] = {
            "id": action_id,
            "schema": ACTION_SCHEMA,
            "tenant_ref": tenant_ref,
            "binding_id": binding_id,
            "finding_sha256": binding["finding_sha256"],
            "binding_sha256": binding["binding_sha256"],
            "agent_principal": binding["agent_principal"],
            "action": chosen_action,
            "request_sha256": request_sha,
            "status": "prepared",
            "control_sha256": None,
            "control_ok": None,
            "control_code": None,
        }
        row["state_sha256"] = _sha256(_action_state(row))
        try:
            prepared = self._actions.create(
                row,
                action="prepare_discovery_containment_action",
                actor=reviewed_by,
                max_records=_MAX_ACTIONS,
            )
        except RecordConflict:
            concurrent = self._actions.get(action_id)
            if concurrent is None:
                raise
            return self._action_public(_validate_action(concurrent, tenant_ref=tenant_ref))
        prepared = _validate_action(prepared, tenant_ref=tenant_ref)
        outcome = self._apply_control(
            action=chosen_action,
            principal=binding["agent_principal"],
            reason_code=safe_reason,
            actor=reviewed_by,
            attenuation=attenuation,
        )
        control_sha = _sha256(
            {
                "finding_sha256": binding["finding_sha256"],
                "binding_sha256": binding["binding_sha256"],
                "agent_principal": binding["agent_principal"],
                "action": chosen_action,
                "ok": outcome.ok,
                "code": outcome.code,
            }
        )

        def finish(saved: dict[str, Any]) -> None:
            saved["status"] = "committed" if outcome.ok else "failed"
            saved["control_sha256"] = control_sha
            saved["control_ok"] = outcome.ok
            saved["control_code"] = outcome.code
            saved["state_sha256"] = _sha256(_action_state(saved))

        try:
            completed = self._actions.update(
                action_id,
                finish,
                expected_revision=int(prepared["revision"]),
                action="commit_discovery_containment_action",
                actor=reviewed_by,
            )
        except Exception:
            # The ACP effect may have happened; preserve the PREPARE row and
            # force operator reconciliation rather than re-firing the verb.
            return self._action_public(prepared)
        if completed is None:
            return self._action_public(prepared)
        return self._action_public(_validate_action(completed, tenant_ref=tenant_ref))


def default_containment_service() -> DiscoveryContainmentService:
    """Return the process-default reviewed discovery-to-containment service."""

    return DiscoveryContainmentService()


__all__ = [
    "ACTION_SCHEMA",
    "BINDING_SCHEMA",
    "DiscoveryContainmentApprovalError",
    "DiscoveryContainmentBindingError",
    "DiscoveryContainmentError",
    "DiscoveryContainmentService",
    "DiscoveryContainmentStateError",
    "default_containment_service",
]
