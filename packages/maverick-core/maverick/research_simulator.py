"""Deterministic software-world fixtures for governed research baselines.

This module is deliberately a *simulator*.  It never calls a live connector and
its results can never satisfy business-outcome acceptance.  A controller owns
the complete oracle state while the component process receives only bounded
inputs and a scrubbed environment.  Every mutating proposal still crosses the ordinary
``GovernedActions`` approval boundary, and an optional ``OutcomeAccounting``
adapter records each attempted simulated operation.

The included models are explicit deterministic baselines.  In particular,
``FeaturePrefixBackoffBaseline`` wraps the existing feature-prefix backoff
model; it is not represented as a proven learned world model.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import queue as queue_module
import random
import re
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, ClassVar, Protocol, runtime_checkable

from .counterfactual_rollout import Transition, TransitionModel
from .generative_world_model import BackoffTransitionModel
from .governed_actions import ActionError, ActionSpec, GovernedActions, Preview
from .outcome_accounting import COST_COVERAGE_FAMILIES
from .procedural_memory import Memory, MemoryStore

INTERFACE_VERSION = "maverick.research-component.v1"
SIMULATOR_SCHEMA = "maverick.software-world.v1"
OBSERVATION_SCHEMA = "maverick.software-world-observation.v1"
RESULT_SCHEMA = "maverick.software-world-result.v1"
EVALUATION_SCHEMA = "maverick.software-world-evaluation.v1"
COMPONENT_DESCRIPTOR_SCHEMA = "maverick.research-component-descriptor.v1"
COST_RECEIPT_SCHEMA = "maverick.research-simulation-cost.v1"
APPROVAL_SCHEMA = "maverick.research-human-approval.v1"

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_MAX_JSON_BYTES = 1_048_576
_MAX_FAULTS = 128
_MAX_OPERATIONS = 10_000
_PROCESS_TIMEOUT_SECONDS = 10.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FAULT_ALIASES = {
    "conflict": "conflicting_edit",
    "interruption": "interrupted_execution",
}
FAULT_KINDS = frozenset({
    "partial_commit",
    "stale_read",
    "revoked_credential",
    "conflicting_edit",
    "pagination_change",
    "interrupted_execution",
})
_ACTIONS = frozenset({"read", "upsert", "list"})


class ResearchSimulationError(RuntimeError):
    """A simulated research operation violated its declared contract."""


class SimulatorContaminationError(ResearchSimulationError):
    """Reset did not restore every state surface to its declared baseline."""


class SimulatedOutcomeAcceptanceError(PermissionError):
    """A simulated result was presented as live business evidence."""


class ResearchBudgetExceeded(PermissionError):
    """The fixed operation budget for a research component was exhausted."""


def _canonical(value: object) -> str:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("simulator values must be canonical JSON") from exc
    if len(rendered.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError("simulator values exceed the one-megabyte bound")
    return rendered


def _detached(value: object) -> Any:
    return json.loads(_canonical(value))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _name(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _text(value: object, label: str, *, maximum: int = 4000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = value.strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} must be bounded printable text")
    return text


@dataclass(frozen=True)
class FaultSpec:
    """One deterministic fault injected at an exact one-based operation step."""

    step: int
    kind: str
    operation: str = "*"

    def __post_init__(self) -> None:
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 1:
            raise ValueError("fault step must be a positive integer")
        kind = _FAULT_ALIASES.get(str(self.kind).strip().lower(), str(self.kind).strip().lower())
        if kind not in FAULT_KINDS:
            raise ValueError("fault kind is unsupported")
        operation = str(self.operation or "").strip().lower()
        if operation != "*" and operation not in _ACTIONS:
            raise ValueError("fault operation must be *, read, upsert, or list")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "operation", operation)


@dataclass(frozen=True)
class SoftwareWorldScenario:
    """Public definition plus controller-owned initial oracle state."""

    scenario_id: str
    seed: int
    mechanism_family: str
    application_family: str
    task: Mapping[str, object]
    records: Mapping[str, object] = field(default_factory=dict)
    hidden_state: Mapping[str, object] = field(default_factory=dict)
    external_state: Mapping[str, object] = field(default_factory=dict)
    files: Mapping[str, str] = field(default_factory=dict)
    queue: tuple[object, ...] = ()
    credentials: Mapping[str, bool] = field(
        default_factory=lambda: {"external_write": True}
    )
    memories: tuple[Memory, ...] = ()
    initial_clock: float = 1_700_000_000.0
    page_size: int = 2
    fault_schedule: tuple[FaultSpec, ...] = ()
    schema: str = SIMULATOR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SIMULATOR_SCHEMA:
            raise ValueError("software-world scenario schema is unsupported")
        object.__setattr__(self, "scenario_id", _name(self.scenario_id, "scenario_id"))
        object.__setattr__(
            self, "mechanism_family", _name(self.mechanism_family, "mechanism_family")
        )
        object.__setattr__(
            self, "application_family", _name(self.application_family, "application_family")
        )
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if (
            isinstance(self.initial_clock, bool)
            or not isinstance(self.initial_clock, (int, float))
            or not 0 < float(self.initial_clock) < 10**14
        ):
            raise ValueError("initial_clock must be a bounded positive timestamp")
        if (
            isinstance(self.page_size, bool)
            or not isinstance(self.page_size, int)
            or not 1 <= self.page_size <= 100
        ):
            raise ValueError("page_size must be in [1, 100]")
        task = _detached(dict(self.task))
        task["key"] = _text(task.get("key"), "task key", maximum=256)
        task["value"] = _text(task.get("value"), "task value", maximum=4000)
        mappings = {
            "task": task,
            "records": _detached(dict(self.records)),
            "hidden_state": _detached(dict(self.hidden_state)),
            "external_state": _detached(dict(self.external_state)),
            "files": _detached(dict(self.files)),
            "credentials": _detached(dict(self.credentials)),
        }
        if any(not isinstance(value, bool) for value in mappings["credentials"].values()):
            raise ValueError("credential state values must be booleans")
        for name, value in mappings.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "queue", tuple(_detached(list(self.queue))))
        memories = tuple(self.memories)
        if any(not isinstance(memory, Memory) for memory in memories):
            raise ValueError("memories must contain procedural Memory values")
        object.__setattr__(self, "memories", memories)
        faults = tuple(self.fault_schedule)
        if len(faults) > _MAX_FAULTS or any(not isinstance(fault, FaultSpec) for fault in faults):
            raise ValueError("fault_schedule must be a bounded FaultSpec sequence")
        steps = [fault.step for fault in faults]
        if len(steps) != len(set(steps)):
            raise ValueError("fault_schedule contains an ambiguous duplicate step")
        object.__setattr__(
            self, "fault_schedule", tuple(sorted(faults, key=lambda fault: (fault.step, fault.operation)))
        )


@dataclass(frozen=True)
class ResetReceipt:
    schema: str
    scenario_id: str
    seed: int
    initial_state_sha256: str
    clean: bool
    contamination_removed: tuple[str, ...]


@dataclass(frozen=True)
class ProposalV1:
    """Bounded proposal passed through the version-one execution interface."""

    action: str
    key: str = ""
    value: str = ""
    cursor: str = ""
    limit: int = 2

    def __post_init__(self) -> None:
        action = str(self.action or "").strip().lower()
        if action not in _ACTIONS:
            raise ValueError("proposal action must be read, upsert, or list")
        key = str(self.key or "").strip()
        value = str(self.value or "")
        cursor = str(self.cursor or "").strip()
        if action in {"read", "upsert"} and (not key or len(key) > 256):
            raise ValueError("read and upsert proposals require a bounded key")
        if action == "upsert" and (not value or len(value) > 4000):
            raise ValueError("upsert proposals require a bounded value")
        if cursor and (not cursor.isdigit() or len(cursor) > 8):
            raise ValueError("cursor must be a bounded decimal offset")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= 100:
            raise ValueError("proposal limit must be in [1, 100]")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "cursor", cursor)

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "key": self.key,
            "value": self.value,
            "cursor": self.cursor,
            "limit": self.limit,
        }


@dataclass(frozen=True, slots=True)
class LearnerObservationV1:
    """The complete permitted view.  It never contains oracle-only state."""

    scenario_id: str
    mechanism_family: str
    application_family: str
    step: int
    clock: float
    status: str
    message: str
    task: Mapping[str, object]
    records: Mapping[str, object]
    page: tuple[tuple[str, object], ...] = ()
    next_cursor: str | None = None
    has_more: bool = False
    schema: ClassVar[str] = OBSERVATION_SCHEMA
    interface_version: ClassVar[str] = INTERFACE_VERSION
    evidence_class: ClassVar[str] = "simulated"

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _name(self.scenario_id, "scenario_id"))
        object.__setattr__(
            self, "mechanism_family", _name(self.mechanism_family, "mechanism_family")
        )
        object.__setattr__(
            self, "application_family", _name(self.application_family, "application_family")
        )
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 0:
            raise ValueError("observation step must be a non-negative integer")
        if (
            isinstance(self.clock, bool)
            or not isinstance(self.clock, (int, float))
            or not math.isfinite(float(self.clock))
        ):
            raise ValueError("observation clock must be finite")
        object.__setattr__(self, "status", _text(self.status, "status", maximum=64))
        object.__setattr__(self, "message", _text(self.message, "message"))
        object.__setattr__(self, "task", _detached(dict(self.task)))
        object.__setattr__(self, "records", _detached(dict(self.records)))
        object.__setattr__(
            self,
            "page",
            tuple(
                (_text(key, "page key", maximum=256), _detached(value))
                for key, value in self.page
            ),
        )
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str)
            or not self.next_cursor.isdigit()
            or len(self.next_cursor) > 8
        ):
            raise ValueError("next_cursor must be a bounded decimal offset")
        if not isinstance(self.has_more, bool):
            raise ValueError("has_more must be boolean")

    @property
    def policy_state(self) -> tuple[str, str, str]:
        return (self.mechanism_family, self.application_family, self.status)

    def to_dict(self) -> dict[str, object]:
        return _detached({
            "schema": self.schema,
            "interface_version": self.interface_version,
            "scenario_id": self.scenario_id,
            "mechanism_family": self.mechanism_family,
            "application_family": self.application_family,
            "step": self.step,
            "clock": self.clock,
            "status": self.status,
            "message": self.message,
            "task": dict(self.task),
            "records": dict(self.records),
            "page": [[key, value] for key, value in self.page],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "evidence_class": self.evidence_class,
        })


@dataclass(frozen=True, slots=True)
class SimulationResultV1:
    """A simulated operation result which is ineligible for live acceptance."""

    scenario_id: str
    step: int
    operation_id: str
    status: str
    message: str
    success: bool
    visible_records: Mapping[str, object]
    page: tuple[tuple[str, object], ...] = ()
    next_cursor: str | None = None
    has_more: bool = False
    predicted_external_effect: str = "none"
    fault: str | None = None
    schema: ClassVar[str] = RESULT_SCHEMA
    interface_version: ClassVar[str] = INTERFACE_VERSION
    evidence_class: ClassVar[str] = "simulated"
    result_class: ClassVar[str] = "simulation"
    live_effect: ClassVar[bool] = False
    can_accept_business_outcome: ClassVar[bool] = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _name(self.scenario_id, "scenario_id"))
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 1:
            raise ValueError("result step must be a positive integer")
        object.__setattr__(self, "operation_id", _name(self.operation_id, "operation_id"))
        object.__setattr__(self, "status", _text(self.status, "status", maximum=64))
        object.__setattr__(self, "message", _text(self.message, "message"))
        if not isinstance(self.success, bool):
            raise ValueError("result success must be boolean")
        object.__setattr__(self, "visible_records", _detached(dict(self.visible_records)))
        object.__setattr__(
            self,
            "page",
            tuple(
                (_text(key, "page key", maximum=256), _detached(value))
                for key, value in self.page
            ),
        )
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str)
            or not self.next_cursor.isdigit()
            or len(self.next_cursor) > 8
        ):
            raise ValueError("next_cursor must be a bounded decimal offset")
        if not isinstance(self.has_more, bool):
            raise ValueError("has_more must be boolean")
        effect = _text(
            self.predicted_external_effect,
            "predicted_external_effect",
            maximum=64,
        )
        if effect not in {"none", "uncertain", "succeeded"}:
            raise ValueError("predicted_external_effect is unsupported")
        object.__setattr__(self, "predicted_external_effect", effect)
        if self.fault is not None and self.fault not in FAULT_KINDS:
            raise ValueError("result fault is unsupported")

    @property
    def source_ref(self) -> str:
        """Stable downstream marker for simulation-only evidence rejection."""
        return f"simulator:{self.operation_id}"

    def accept_live_business_outcome(self) -> None:
        raise SimulatedOutcomeAcceptanceError(
            "simulated results cannot accept a live business outcome"
        )

    def to_app_payload(self) -> dict[str, object]:
        return _detached({
            "schema": RESULT_SCHEMA,
            "interface_version": INTERFACE_VERSION,
            "scenario_id": self.scenario_id,
            "step": self.step,
            "operation_id": self.operation_id,
            "source_ref": self.source_ref,
            "status": self.status,
            "message": self.message,
            "success": self.success,
            "predicted_external_effect": self.predicted_external_effect,
            "fault": self.fault,
            "evidence_class": "simulated",
            "result_class": "simulation",
            "live_effect": False,
            "can_accept_business_outcome": False,
            "authoritative_live_evidence_eligible": False,
            "business_outcome_acceptance": "prohibited",
        })

    def to_component_payload(self) -> dict[str, object]:
        """Bounded result projection for the isolated component process."""
        return _detached({
            **self.to_app_payload(),
            "visible_records": dict(self.visible_records),
            "page": [[key, value] for key, value in self.page],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
        })


@dataclass(frozen=True, slots=True)
class ComponentEvaluationV1:
    component_id: str
    passed: bool
    reason: str
    schema: ClassVar[str] = EVALUATION_SCHEMA
    interface_version: ClassVar[str] = INTERFACE_VERSION
    evidence_class: ClassVar[str] = "simulated"

    def __post_init__(self) -> None:
        object.__setattr__(self, "component_id", _name(self.component_id, "component_id"))
        if not isinstance(self.passed, bool):
            raise ValueError("component evaluation passed must be boolean")
        object.__setattr__(self, "reason", _text(self.reason, "reason"))


@dataclass(frozen=True, slots=True)
class OracleAssessment:
    scenario_id: str
    passed: bool
    external_effect: str
    oracle_state_sha256: str
    evidence_class: ClassVar[str] = "simulated"


@dataclass(frozen=True, slots=True)
class AuthenticatedHumanIdentityV1:
    """Controller input proving that a named end-user identity was verified."""

    principal: str
    authentication_context_sha256: str
    schema: ClassVar[str] = "maverick.authenticated-human-identity.v1"

    def __post_init__(self) -> None:
        principal = _text(self.principal, "principal", maximum=4096)
        if not principal.startswith("user:") or not principal.removeprefix("user:").strip():
            raise ValueError("a named user principal is required")
        if not _SHA256.fullmatch(self.authentication_context_sha256):
            raise ValueError("authentication context digest must be SHA-256")
        object.__setattr__(self, "principal", principal)


@dataclass(frozen=True, slots=True)
class AuthenticatedHumanApprovalV1:
    """Named-human approval bound to one exact component proposal."""

    principal: str
    authentication_context_sha256: str
    scenario_id: str
    component_id: str
    proposal_sha256: str
    approval_id: str
    schema: ClassVar[str] = APPROVAL_SCHEMA
    interface_version: ClassVar[str] = INTERFACE_VERSION

    @classmethod
    def bind(
        cls,
        identity: AuthenticatedHumanIdentityV1,
        *,
        scenario_id: str,
        component_id: str,
        proposal: ProposalV1,
    ) -> AuthenticatedHumanApprovalV1:
        if not isinstance(identity, AuthenticatedHumanIdentityV1):
            raise TypeError("identity must be AuthenticatedHumanIdentityV1")
        if not isinstance(proposal, ProposalV1):
            raise TypeError("proposal must be ProposalV1")
        fields = {
            "schema": APPROVAL_SCHEMA,
            "interface_version": INTERFACE_VERSION,
            "principal": identity.principal,
            "authentication_context_sha256": identity.authentication_context_sha256,
            "scenario_id": _name(scenario_id, "scenario_id"),
            "component_id": _name(component_id, "component_id"),
            "proposal_sha256": _digest(proposal.to_dict()),
        }
        return cls(
            principal=identity.principal,
            authentication_context_sha256=identity.authentication_context_sha256,
            scenario_id=str(fields["scenario_id"]),
            component_id=str(fields["component_id"]),
            proposal_sha256=str(fields["proposal_sha256"]),
            approval_id=_digest(fields),
        )

    def __post_init__(self) -> None:
        principal = _text(self.principal, "principal", maximum=4096)
        if not principal.startswith("user:") or not principal.removeprefix("user:").strip():
            raise ValueError("approval requires a named user principal")
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "scenario_id", _name(self.scenario_id, "scenario_id"))
        object.__setattr__(self, "component_id", _name(self.component_id, "component_id"))
        for label, value in (
            ("authentication context", self.authentication_context_sha256),
            ("proposal", self.proposal_sha256),
            ("approval", self.approval_id),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"{label} digest must be SHA-256")
        fields = {
            "schema": APPROVAL_SCHEMA,
            "interface_version": INTERFACE_VERSION,
            "principal": principal,
            "authentication_context_sha256": self.authentication_context_sha256,
            "scenario_id": self.scenario_id,
            "component_id": self.component_id,
            "proposal_sha256": self.proposal_sha256,
        }
        if self.approval_id != _digest(fields):
            raise ValueError("approval binding is invalid")

    def matches(
        self,
        *,
        scenario_id: str,
        component_id: str,
        proposal: ProposalV1,
    ) -> bool:
        return (
            self.scenario_id == scenario_id
            and self.component_id == component_id
            and self.proposal_sha256 == _digest(proposal.to_dict())
        )


@dataclass(frozen=True, slots=True)
class SimulationCostReceiptV1:
    """Controller-issued binding between an effect, lineage, and accounting event."""

    component_id: str
    component_descriptor_sha256: str
    simulation_operation_id: str
    source_ref: str
    action_lineage_sha256: str
    accounting_source_version: str
    accounting_operation_id: str
    accounting_record_id: str
    accounting_event_id: str
    accounting_persisted: bool
    attempt_state: str
    receipt_sha256: str
    schema: ClassVar[str] = COST_RECEIPT_SCHEMA
    evidence_class: ClassVar[str] = "simulated"
    quantity: ClassVar[int] = 1
    unit: ClassVar[str] = "simulated_operation"
    monetary_amount: ClassVar[str] = "0"
    currency: ClassVar[str] = "USD"
    budget_state: ClassVar[str] = "within_limit"

    def __post_init__(self) -> None:
        object.__setattr__(self, "component_id", _name(self.component_id, "component_id"))
        object.__setattr__(
            self,
            "simulation_operation_id",
            _name(self.simulation_operation_id, "simulation_operation_id"),
        )
        if self.source_ref != f"simulator:{self.simulation_operation_id}":
            raise ValueError("cost source_ref does not bind the simulation operation")
        if self.attempt_state not in {"succeeded", "failed"}:
            raise ValueError("cost attempt_state is unsupported")
        if not isinstance(self.accounting_persisted, bool):
            raise ValueError("accounting_persisted must be boolean")
        if self.accounting_persisted and (
            not self.accounting_record_id
            or not self.accounting_event_id
            or not self.accounting_operation_id
        ):
            raise ValueError("persisted cost receipt lacks accounting lineage")
        if not self.accounting_persisted and any((
            self.accounting_record_id,
            self.accounting_event_id,
            self.accounting_operation_id,
        )):
            raise ValueError("unpersisted cost receipt contains accounting lineage")
        for label, value in (
            ("component descriptor", self.component_descriptor_sha256),
            ("action lineage", self.action_lineage_sha256),
            ("accounting source version", self.accounting_source_version),
            ("receipt", self.receipt_sha256),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"{label} digest must be SHA-256")
        if self.receipt_sha256 != _digest(self.binding_payload()):
            raise ValueError("cost receipt digest is invalid")

    def binding_payload(self) -> dict[str, object]:
        return {
            "schema": COST_RECEIPT_SCHEMA,
            "evidence_class": "simulated",
            "component_id": self.component_id,
            "component_descriptor_sha256": self.component_descriptor_sha256,
            "simulation_operation_id": self.simulation_operation_id,
            "source_ref": self.source_ref,
            "action_lineage_sha256": self.action_lineage_sha256,
            "accounting_source_version": self.accounting_source_version,
            "accounting_operation_id": self.accounting_operation_id,
            "accounting_record_id": self.accounting_record_id,
            "accounting_event_id": self.accounting_event_id,
            "accounting_persisted": self.accounting_persisted,
            "attempt_state": self.attempt_state,
            "quantity": 1,
            "unit": "simulated_operation",
            "monetary_amount": "0",
            "currency": "USD",
            "budget_state": "within_limit",
        }


class SoftwareWorldFixture:
    """Controller-owned resettable state and independent oracle.

    The trusted controller receives :class:`ResearchWorkerSession`; the
    component subprocess receives neither object.  The fixture retains records,
    hidden state, fake files/queues/credentials, fake external state, the
    deterministic clock/RNG, and procedural memory.
    """

    def __init__(self, scenario: SoftwareWorldScenario) -> None:
        if not isinstance(scenario, SoftwareWorldScenario):
            raise TypeError("scenario must be SoftwareWorldScenario")
        # Capture a detached definition once.  ``SoftwareWorldScenario`` is
        # frozen, but callers could still mutate a nested input mapping; that
        # must not silently redefine the reset oracle after fixture creation.
        self._scenario_id = scenario.scenario_id
        self._seed = scenario.seed
        self._mechanism_family = scenario.mechanism_family
        self._application_family = scenario.application_family
        self._task = _detached(dict(scenario.task))
        self._initial_records = _detached(dict(scenario.records))
        self._initial_hidden_state = _detached(dict(scenario.hidden_state))
        self._initial_external_state = _detached(dict(scenario.external_state))
        self._initial_files = _detached(dict(scenario.files))
        self._initial_queue = _detached(list(scenario.queue))
        self._initial_credentials = _detached(dict(scenario.credentials))
        self._initial_memories = tuple(scenario.memories)
        self._initial_clock = float(scenario.initial_clock)
        self._initial_page_size = scenario.page_size
        self._fault_schedule = tuple(scenario.fault_schedule)
        self._initialized = False
        self._baseline_sha256 = ""
        self._records: dict[str, object] = {}
        self._hidden_state: dict[str, object] = {}
        self._external_state: dict[str, object] = {}
        self._files: dict[str, str] = {}
        self._queue: list[object] = []
        self._credentials: dict[str, bool] = {}
        self._clock = 0.0
        self._step = 0
        self._page_size = self._initial_page_size
        self._rng = random.Random()
        self._memory = MemoryStore()
        self._generation = 0
        self.reset()

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    def _rng_probe(self) -> str:
        probe = random.Random()
        probe.setstate(self._rng.getstate())
        return f"{probe.getrandbits(256):064x}"

    def _state_surfaces(self) -> dict[str, object]:
        return {
            "records": _detached(self._records),
            "hidden_state": _detached(self._hidden_state),
            "external_state": _detached(self._external_state),
            "files": _detached(self._files),
            "queue": _detached(self._queue),
            "credentials": _detached(self._credentials),
            "clock": self._clock,
            "step": self._step,
            "page_size": self._page_size,
            "rng_probe": self._rng_probe(),
            "procedural_memory": [
                memory.to_dict() for memory in self._memory.recall(top_k=100)
            ],
        }

    def _expected_surfaces(self) -> dict[str, object]:
        rng = random.Random(self._seed)
        probe = random.Random()
        probe.setstate(rng.getstate())
        return {
            "records": _detached(self._initial_records),
            "hidden_state": _detached(self._initial_hidden_state),
            "external_state": _detached(self._initial_external_state),
            "files": _detached(self._initial_files),
            "queue": _detached(self._initial_queue),
            "credentials": _detached(self._initial_credentials),
            "clock": self._initial_clock,
            "step": 0,
            "page_size": self._initial_page_size,
            "rng_probe": f"{probe.getrandbits(256):064x}",
            "procedural_memory": [
                memory.to_dict()
                for memory in sorted(
                    self._initial_memories,
                    key=lambda memory: memory.strength,
                    reverse=True,
                )
            ],
        }

    def reset(self) -> ResetReceipt:
        """Restore every declared state surface and prove the clean fingerprint."""
        expected = self._expected_surfaces()
        previous = self._state_surfaces() if self._initialized else expected
        dirty = tuple(
            name for name in expected if previous.get(name) != expected.get(name)
        )
        self._records = _detached(self._initial_records)
        self._hidden_state = _detached(self._initial_hidden_state)
        self._external_state = _detached(self._initial_external_state)
        self._files = _detached(self._initial_files)
        self._queue = _detached(self._initial_queue)
        self._credentials = _detached(self._initial_credentials)
        self._clock = self._initial_clock
        self._step = 0
        self._page_size = self._initial_page_size
        self._rng = random.Random(self._seed)
        self._memory = MemoryStore()
        self._memory.update(self._initial_memories)
        self._generation += 1
        actual = self._state_surfaces()
        expected_sha256 = _digest(expected)
        if actual != expected or _digest(actual) != expected_sha256:
            raise SimulatorContaminationError(
                "software-world reset left residual state"
            )
        if self._baseline_sha256 and self._baseline_sha256 != expected_sha256:
            raise SimulatorContaminationError("software-world baseline changed")
        self._baseline_sha256 = expected_sha256
        self._initialized = True
        return ResetReceipt(
            schema="maverick.software-world-reset.v1",
            scenario_id=self.scenario_id,
            seed=self._seed,
            initial_state_sha256=expected_sha256,
            clean=True,
            contamination_removed=dirty,
        )

    def reset_status(self) -> dict[str, object]:
        """Controller diagnostic identifying every contaminated state surface."""
        expected = self._expected_surfaces()
        actual = self._state_surfaces()
        changed = tuple(name for name in expected if actual.get(name) != expected.get(name))
        return {
            "clean": not changed,
            "changed_surfaces": changed,
            "expected_sha256": _digest(expected),
            "actual_sha256": _digest(actual),
        }

    def seed_contamination(self) -> None:
        """Controller-only probe used to verify cross-run cleanup coverage."""
        self._records["residual-record"] = "changed"
        self._hidden_state["residual-hidden"] = "changed"
        self._external_state["residual-external"] = "changed"
        self._files["residual.txt"] = "changed"
        self._queue.append({"residual": True})
        self._credentials["external_write"] = False
        self._clock += 99.0
        self._step += 1
        self._page_size = min(100, self._page_size + 1)
        self._rng.random()
        self._memory.update([Memory("residual-action", 1.0, 1.0)])

    def initial_observation(self) -> LearnerObservationV1:
        return self._observation(
            status="ready",
            message="The reset simulated world is ready.",
            visible_records=self._records,
        )

    def open_worker(
        self,
        *,
        accounting: object | None = None,
        accounting_record_id: str = "",
        actor: str = "system:research-simulator",
        max_operations: int = 1,
        actions: GovernedActions | None = None,
    ) -> ResearchWorkerSession:
        return ResearchWorkerSession(
            self,
            accounting=accounting,
            accounting_record_id=accounting_record_id,
            actor=actor,
            max_operations=max_operations,
            actions=actions,
        )

    def oracle_snapshot(self) -> dict[str, object]:
        """Full evaluator-only state; never included in a worker session view."""
        return _detached({
            "schema": "maverick.software-world-oracle.v1",
            "scenario_id": self.scenario_id,
            **self._state_surfaces(),
        })

    def assess(self) -> OracleAssessment:
        key = str(self._task["key"])
        value = self._task["value"]
        passed = self._external_state.get(key) == value
        snapshot = self.oracle_snapshot()
        return OracleAssessment(
            scenario_id=self.scenario_id,
            passed=passed,
            external_effect="succeeded" if passed else "not_succeeded",
            oracle_state_sha256=_digest(snapshot),
        )

    def _fault_for(self, step: int, operation: str) -> str | None:
        for fault in self._fault_schedule:
            if fault.step == step and fault.operation in {"*", operation}:
                return fault.kind
        return None

    def _advance(self) -> tuple[int, str]:
        self._step += 1
        self._clock += 1.0 + self._rng.randrange(1000) / 1000.0
        entropy = f"{self._rng.getrandbits(96):024x}"
        operation = _digest({
            "scenario_id": self.scenario_id,
            "step": self._step,
            "entropy": entropy,
        })[:24]
        return self._step, f"sim-{operation}"

    def _page(self, proposal: ProposalV1) -> tuple[tuple[tuple[str, object], ...], str | None, bool]:
        offset = int(proposal.cursor or "0")
        items = sorted(self._records.items())
        limit = min(proposal.limit, self._page_size)
        selected = tuple((key, _detached(value)) for key, value in items[offset:offset + limit])
        following = offset + len(selected)
        has_more = following < len(items)
        return selected, str(following) if has_more else None, has_more

    def _execute(self, proposal: ProposalV1, *, generation: int) -> SimulationResultV1:
        if generation != self._generation:
            raise ResearchSimulationError(
                "worker session belongs to a previous simulator reset"
            )
        step, operation_id = self._advance()
        fault = self._fault_for(step, proposal.action)
        status = "succeeded"
        message = "The operation succeeded inside the simulated world."
        success = True
        predicted = "none"
        visible = _detached(self._records)
        page: tuple[tuple[str, object], ...] = ()
        next_cursor: str | None = None
        has_more = False

        if fault == "revoked_credential":
            self._credentials["external_write"] = False
            status, success = "credential_revoked", False
            message = "The simulated credential was revoked before the effect."
        elif fault == "interrupted_execution":
            self._queue.append({"operation_id": operation_id, "state": "interrupted"})
            status, success = "interrupted", False
            message = "The simulated operation was interrupted before completion."
        elif fault == "conflicting_edit":
            conflict_value = f"conflict-{self._rng.getrandbits(32):08x}"
            self._external_state[proposal.key or "conflict"] = conflict_value
            self._hidden_state["last_conflict"] = operation_id
            status, success = "conflict", False
            message = "A concurrent simulated edit changed the target."
        elif fault == "partial_commit":
            if proposal.key:
                self._records[proposal.key] = proposal.value
                self._files[f"records/{proposal.key}.json"] = _canonical({"value": proposal.value})
            self._queue.append({"operation_id": operation_id, "state": "partial"})
            self._hidden_state["last_partial_commit"] = operation_id
            status, success = "partial_commit", False
            message = "Only the local simulated commit completed."
            predicted = "uncertain"
        elif fault == "pagination_change":
            self._page_size = 1 if self._page_size != 1 else 2
            status, success = "pagination_changed", False
            message = "The simulated collection pagination changed during the request."
        elif fault == "stale_read":
            visible = _detached(self._initial_records)
            status, success = "stale_read", False
            message = "The simulated read returned the reset-time snapshot."
        elif proposal.action == "upsert":
            if not self._credentials.get("external_write", False):
                status, success = "credential_revoked", False
                message = "The simulated credential is unavailable."
            else:
                self._records[proposal.key] = proposal.value
                self._external_state[proposal.key] = proposal.value
                self._files[f"records/{proposal.key}.json"] = _canonical({"value": proposal.value})
                self._hidden_state["last_successful_operation"] = operation_id
                predicted = "succeeded"
                visible = _detached(self._records)
        elif proposal.action == "read":
            visible = {proposal.key: _detached(self._records.get(proposal.key))}

        if proposal.action == "list" or fault == "pagination_change":
            page, next_cursor, has_more = self._page(proposal)
            visible = {key: value for key, value in page}

        return SimulationResultV1(
            scenario_id=self.scenario_id,
            step=step,
            operation_id=operation_id,
            status=status,
            message=message,
            success=success,
            visible_records=visible,
            page=page,
            next_cursor=next_cursor,
            has_more=has_more,
            predicted_external_effect=predicted,
            fault=fault,
        )

    def _observation(
        self,
        *,
        status: str,
        message: str,
        visible_records: Mapping[str, object],
        page: tuple[tuple[str, object], ...] = (),
        next_cursor: str | None = None,
        has_more: bool = False,
    ) -> LearnerObservationV1:
        return LearnerObservationV1(
            scenario_id=self.scenario_id,
            mechanism_family=self._mechanism_family,
            application_family=self._application_family,
            step=self._step,
            clock=self._clock,
            status=status,
            message=message,
            task=_detached(self._task),
            records=_detached(dict(visible_records)),
            page=tuple((_text(key, "page key", maximum=256), _detached(value)) for key, value in page),
            next_cursor=next_cursor,
            has_more=has_more,
        )

    def _observe(self, result: SimulationResultV1) -> LearnerObservationV1:
        if result.scenario_id != self.scenario_id or result.step != self._step:
            raise ResearchSimulationError("result does not match the current simulated world")
        return self._observation(
            status=result.status,
            message=result.message,
            visible_records=result.visible_records,
            page=result.page,
            next_cursor=result.next_cursor,
            has_more=result.has_more,
        )


class ResearchWorkerSession:
    """Capability-limited worker view with governed execution and a fixed budget."""

    def __init__(
        self,
        world: SoftwareWorldFixture,
        *,
        accounting: object | None,
        accounting_record_id: str,
        actor: str,
        max_operations: int,
        actions: GovernedActions | None,
    ) -> None:
        if (
            isinstance(max_operations, bool)
            or not isinstance(max_operations, int)
            or not 1 <= max_operations <= _MAX_OPERATIONS
        ):
            raise ValueError(f"max_operations must be in [1, {_MAX_OPERATIONS}]")
        if accounting is not None and not accounting_record_id:
            raise ValueError("accounting_record_id is required when accounting is enabled")
        self._world = world
        self._generation = world._generation
        self._accounting = accounting
        self._accounting_record_id = str(accounting_record_id)
        self._actor = _text(actor, "actor", maximum=4096)
        self._max_operations = max_operations
        self._used_operations = 0
        self._actions = actions or GovernedActions()
        self._last_result: SimulationResultV1 | None = None
        self._cost_receipts: list[SimulationCostReceiptV1] = []
        for action, risk in (("read", "low"), ("list", "low"), ("upsert", "high")):
            self._actions.register(ActionSpec(
                name=f"software-world.{action}",
                params={"proposal_json": str},
                risk=risk,
                simulate=lambda params, a=action: (
                    f"would {a} inside the isolated simulated software world: "
                    f"{params['proposal_json']}"
                ),
                apply=lambda params: self._apply(params),
            ))

    @property
    def actions(self) -> GovernedActions:
        return self._actions

    @property
    def max_operations(self) -> int:
        return self._max_operations

    @property
    def used_operations(self) -> int:
        return self._used_operations

    @property
    def cost_receipts(self) -> tuple[SimulationCostReceiptV1, ...]:
        """Immutable controller-issued receipts for completed attempts."""
        return tuple(self._cost_receipts)

    def enumerate_environment(self) -> dict[str, object]:
        """Return the complete worker environment; private/evaluator state is absent."""
        return {
            "schema": "maverick.software-world-worker-environment.v1",
            "interface_version": INTERFACE_VERSION,
            "scenario_id": self._world.scenario_id,
            "mechanism_family": self._world._mechanism_family,
            "application_family": self._world._application_family,
            "allowed_actions": sorted(_ACTIONS),
            "environment": {},
            "credentials": [],
            "oracle_access": False,
        }

    def initial_observation(self) -> LearnerObservationV1:
        return self._world.initial_observation()

    def preview(self, proposal: ProposalV1) -> Preview:
        return self._actions.simulate(
            f"software-world.{proposal.action}",
            {"proposal_json": _canonical(proposal.to_dict())},
        )

    def _apply(self, params: dict[str, object]) -> str:
        raw = json.loads(str(params["proposal_json"]))
        proposal = ProposalV1(**raw)
        result = self._world._execute(proposal, generation=self._generation)
        self._last_result = result
        return _canonical(result.to_app_payload())

    def _record_cost(
        self,
        result: SimulationResultV1,
        component_id: str,
        *,
        component_descriptor_sha256: str,
        action_lineage_sha256: str,
    ) -> None:
        attempt_state = "succeeded" if result.success else "failed"
        accounting_source_version = _digest({
            "interface_version": INTERFACE_VERSION,
            "component_descriptor_sha256": component_descriptor_sha256,
            "action_lineage_sha256": action_lineage_sha256,
        })
        accounting_operation_id = ""
        accounting_event_id = ""
        if self._accounting is not None:
            report = self._accounting.report(self._accounting_record_id)
            operation_binding = {
                "schema": COST_RECEIPT_SCHEMA,
                "interface_version": INTERFACE_VERSION,
                "component_id": component_id,
                "component_descriptor_sha256": component_descriptor_sha256,
                "simulation_operation_id": result.operation_id,
                "source_ref": result.source_ref,
                "action_lineage_sha256": action_lineage_sha256,
                "attempt_state": attempt_state,
                "quantity": 1,
                "unit": "simulated_operation",
                "amount": "0",
                "currency": "USD",
                "budget_state": "within_limit",
            }
            accounting_operation_id = f"research-sim-{_digest(operation_binding)[:32]}"
            self._accounting.record_cost(
                self._accounting_record_id,
                expected_revision=report["revision"],
                operation_id=accounting_operation_id,
                actor=self._actor,
                category="evaluation",
                attempt_state=attempt_state,
                basis="observed",
                amount="0",
                currency="USD",
                quantity="1",
                unit="simulated_operation",
                source_ref=result.source_ref,
                source_version=accounting_source_version,
                budget_state="within_limit",
                source_assurance="application_observation",
                coverage="complete",
                coverage_declarations={
                    family: {
                        "status": (
                            "included"
                            if family == "provider_usage"
                            or (family == "failed_attempts" and attempt_state == "failed")
                            else "zero"
                        ),
                        "note": (
                            "The simulated evaluation operation is included in this "
                            "zero-dollar provider-usage receipt."
                            if family == "provider_usage"
                            else (
                                "The simulated failed attempt is included in this "
                                "zero-dollar receipt."
                                if family == "failed_attempts" and attempt_state == "failed"
                                else "The isolated simulation recorded zero for this cost family."
                            )
                        ),
                    }
                    for family in COST_COVERAGE_FAMILIES
                },
            )
            persisted = self._accounting.report(self._accounting_record_id)
            matching = [
                row
                for row in persisted["costs"]["events"]
                if row.get("source_ref") == result.source_ref
                and row.get("source_version") == accounting_source_version
                and row.get("attempt_state") == attempt_state
            ]
            if len(matching) != 1 or not matching[0].get("id"):
                raise ResearchSimulationError(
                    "simulated cost accounting did not return one bound event"
                )
            accounting_event_id = str(matching[0]["id"])
        receipt_values = {
            "component_id": component_id,
            "component_descriptor_sha256": component_descriptor_sha256,
            "simulation_operation_id": result.operation_id,
            "source_ref": result.source_ref,
            "action_lineage_sha256": action_lineage_sha256,
            "accounting_source_version": accounting_source_version,
            "accounting_operation_id": accounting_operation_id,
            "accounting_record_id": (
                self._accounting_record_id if self._accounting is not None else ""
            ),
            "accounting_event_id": accounting_event_id,
            "accounting_persisted": self._accounting is not None,
            "attempt_state": attempt_state,
        }
        provisional = {
            "schema": COST_RECEIPT_SCHEMA,
            "evidence_class": "simulated",
            **receipt_values,
            "quantity": 1,
            "unit": "simulated_operation",
            "monetary_amount": "0",
            "currency": "USD",
            "budget_state": "within_limit",
        }
        self._cost_receipts.append(SimulationCostReceiptV1(
            **receipt_values,
            receipt_sha256=_digest(provisional),
        ))

    def execute(
        self,
        proposal: ProposalV1,
        *,
        component_id: str,
        component_descriptor_sha256: str,
        approval: AuthenticatedHumanApprovalV1 | None = None,
    ) -> SimulationResultV1:
        if not isinstance(proposal, ProposalV1):
            raise TypeError("proposal must be ProposalV1")
        component = _name(component_id, "component_id")
        if not _SHA256.fullmatch(component_descriptor_sha256):
            raise ValueError("component descriptor digest must be SHA-256")
        if self._used_operations >= self._max_operations:
            raise ResearchBudgetExceeded("research simulation operation budget exhausted")
        preview = self.preview(proposal)
        approver = ""
        if preview.requires_approval:
            if not isinstance(approval, AuthenticatedHumanApprovalV1):
                raise ActionError(
                    "high-risk simulated action requires authenticated named-human approval"
                )
            if not approval.matches(
                scenario_id=self._world.scenario_id,
                component_id=component,
                proposal=proposal,
            ):
                raise ActionError("simulated action approval does not match the proposal")
            approver = approval.principal
        elif approval is not None:
            if not isinstance(approval, AuthenticatedHumanApprovalV1) or not approval.matches(
                scenario_id=self._world.scenario_id,
                component_id=component,
                proposal=proposal,
            ):
                raise ActionError("simulated action approval does not match the proposal")
            approver = approval.principal
        self._last_result = None
        self._actions.commit(
            f"software-world.{proposal.action}",
            {"proposal_json": _canonical(proposal.to_dict())},
            approver=approver,
            sources=(f"simulator:{self._world.scenario_id}",),
            skills=(component,),
        )
        result = self._last_result
        if result is None:
            raise ResearchSimulationError("governed simulator returned no result")
        self._used_operations += 1
        lineage = self._actions.lineage[-1] if self._actions.lineage else None
        if (
            lineage is None
            or lineage.action != f"software-world.{proposal.action}"
            or lineage.skills != (component,)
            or lineage.approver != approver
            or self._actions.verify_lineage().startswith("VALID:") is False
        ):
            raise ResearchSimulationError("governed simulator action lineage is invalid")
        try:
            self._record_cost(
                result,
                component,
                component_descriptor_sha256=component_descriptor_sha256,
                action_lineage_sha256=lineage.hash,
            )
        except Exception as exc:
            raise ResearchSimulationError(
                "simulated operation completed but cost accounting failed; result withheld"
            ) from exc
        return result

    def observe(self, result: SimulationResultV1) -> LearnerObservationV1:
        if self._generation != self._world._generation:
            raise ResearchSimulationError(
                "worker session belongs to a previous simulator reset"
            )
        return self._world._observe(result)


@runtime_checkable
class ResearchComponentV1(Protocol):
    """Versioned pure component contract executed outside the controller.

    ``execute`` produces an execution intent.  It never receives a worker,
    action authority, accounting adapter, or oracle capability.  The controller
    alone commits that intent and sends the bounded result back to ``observe``.
    """

    interface_version: str
    component_id: str
    baseline_label: str

    def propose(self, observation: LearnerObservationV1) -> ProposalV1: ...

    def execute(self, proposal: ProposalV1) -> ProposalV1: ...

    def observe(
        self,
        result: SimulationResultV1,
        observation: LearnerObservationV1,
    ) -> LearnerObservationV1: ...

    def evaluate(
        self,
        observation: LearnerObservationV1,
        result: SimulationResultV1,
    ) -> ComponentEvaluationV1: ...


class _ModelBaseline:
    __slots__ = ("_descriptor_json", "_memory", "_model")

    interface_version = INTERFACE_VERSION
    component_id = "baseline"
    baseline_label = "deterministic research baseline"
    implementation = "baseline"

    def __init__(
        self,
        transitions: Iterable[Transition],
        *,
        memory: MemoryStore | None = None,
    ) -> None:
        material = tuple(transitions)
        if not material or any(not isinstance(row, Transition) for row in material):
            raise ValueError("baseline transitions must be a non-empty Transition sequence")
        if len(material) > _MAX_OPERATIONS:
            raise ValueError("baseline transitions exceed the fixed component bound")
        transition_rows: list[dict[str, object]] = []
        for row in material:
            if not isinstance(row.state, tuple) or len(row.state) > 32:
                raise ValueError("transition state must be a bounded tuple")
            action = str(row.action)
            if action not in _ACTIONS:
                raise ValueError("baseline transition action is unsupported")
            if row.next_state is not None and not isinstance(row.next_state, tuple):
                raise ValueError("transition next_state must be a tuple or None")
            outcome = row.outcome
            if outcome is not None and (
                isinstance(outcome, bool)
                or not isinstance(outcome, (int, float))
                or not math.isfinite(float(outcome))
            ):
                raise ValueError("transition outcome must be finite")
            transition_rows.append({
                "state": _detached(list(row.state)),
                "action": action,
                "next_state": (
                    None if row.next_state is None else _detached(list(row.next_state))
                ),
                "outcome": outcome,
            })
        self._model = self._new_model().fit(material)
        self._memory = memory or MemoryStore()
        memories = self._memory.recall(top_k=1000)
        if any(memory.action not in _ACTIONS for memory in memories):
            raise ValueError("baseline memory action is unsupported")
        self._descriptor_json = _canonical({
            "schema": COMPONENT_DESCRIPTOR_SCHEMA,
            "interface_version": self.interface_version,
            "component_id": self.component_id,
            "baseline_label": self.baseline_label,
            "implementation": self.implementation,
            "transitions": transition_rows,
            "memories": [memory.to_dict() for memory in memories],
        })

    def _new_model(self) -> TransitionModel:
        raise NotImplementedError

    def propose(self, observation: LearnerObservationV1) -> ProposalV1:
        if observation.interface_version != self.interface_version:
            raise ResearchSimulationError("component interface version changed")
        policy = self._model.policy(observation.policy_state)
        remembered = [memory.action for memory in self._memory.recall(top_k=10)]
        candidates = sorted(policy, key=lambda action: (-policy[action], str(action)))
        action = next((action for action in remembered if action in policy), None)
        selected = str(action or (candidates[0] if candidates else "read"))
        if selected not in _ACTIONS:
            raise ResearchSimulationError("baseline proposed an unsupported action")
        task = observation.task
        return ProposalV1(
            action=selected,
            key=str(task.get("key") or ""),
            value=str(task.get("value") or ""),
        )

    def execute(self, proposal: ProposalV1) -> ProposalV1:
        if not isinstance(proposal, ProposalV1):
            raise TypeError("proposal must be ProposalV1")
        return ProposalV1(**proposal.to_dict())

    def observe(
        self,
        result: SimulationResultV1,
        observation: LearnerObservationV1,
    ) -> LearnerObservationV1:
        if (
            not isinstance(result, SimulationResultV1)
            or not isinstance(observation, LearnerObservationV1)
        ):
            raise TypeError("component observation inputs are invalid")
        if result.scenario_id != observation.scenario_id or result.step != observation.step:
            raise ResearchSimulationError("component observation does not match its result")
        return observation

    def evaluate(
        self,
        observation: LearnerObservationV1,
        result: SimulationResultV1,
    ) -> ComponentEvaluationV1:
        key = str(observation.task.get("key") or "")
        expected = observation.task.get("value")
        passed = result.success and observation.records.get(key) == expected
        return ComponentEvaluationV1(
            component_id=self.component_id,
            passed=passed,
            reason=(
                "permitted observation matches the requested simulated value"
                if passed
                else "permitted observation does not establish simulated success"
            ),
        )


class TabularResearchBaseline(_ModelBaseline):
    """Existing deterministic tabular transition model, explicitly a baseline."""

    component_id = "tabular-baseline-v1"
    baseline_label = "deterministic tabular transition baseline"
    implementation = "tabular-v1"
    __slots__ = ()

    def _new_model(self) -> TransitionModel:
        return TransitionModel()


class FeaturePrefixBackoffBaseline(_ModelBaseline):
    """Existing feature-prefix backoff baseline, not a proven learned world model."""

    component_id = "feature-prefix-backoff-baseline-v1"
    baseline_label = (
        "deterministic feature-prefix backoff baseline; "
        "not a proven learned world model"
    )
    implementation = "feature-prefix-backoff-v1"
    __slots__ = ()

    def _new_model(self) -> TransitionModel:
        return BackoffTransitionModel(min_support=1, min_specificity=1)


_REGISTERED_COMPONENT_TYPES = {
    TabularResearchBaseline: "tabular-v1",
    FeaturePrefixBackoffBaseline: "feature-prefix-backoff-v1",
}


def _component_descriptor(component: ResearchComponentV1) -> tuple[dict[str, object], str]:
    expected_implementation = _REGISTERED_COMPONENT_TYPES.get(type(component))
    if expected_implementation is None:
        raise TypeError("component is not a registered isolated research implementation")
    if component.interface_version != INTERFACE_VERSION:
        raise ResearchSimulationError("component declared an unsupported interface version")
    try:
        descriptor = json.loads(component._descriptor_json)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, json.JSONDecodeError) as exc:
        raise ResearchSimulationError("component descriptor is unavailable") from exc
    if (
        descriptor.get("schema") != COMPONENT_DESCRIPTOR_SCHEMA
        or descriptor.get("interface_version") != component.interface_version
        or descriptor.get("component_id") != component.component_id
        or descriptor.get("baseline_label") != component.baseline_label
        or descriptor.get("implementation") != expected_implementation
    ):
        raise ResearchSimulationError("component descriptor does not match its declaration")
    rendered = _canonical(descriptor)
    return json.loads(rendered), hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _isolated_process_environment(temporary: str) -> dict[str, str]:
    environment = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TEMP": temporary,
        "TMP": temporary,
    }
    for name in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _run_component_process(request: Mapping[str, object]) -> tuple[dict[str, object], str]:
    """Run one bounded command in a clean process with no controller capability."""
    body = _canonical(dict(request))
    worker_path = Path(__file__).with_name("research_component_worker.py")
    if not worker_path.is_file():
        raise ResearchSimulationError("isolated component runtime is unavailable")
    runtime_sha256 = hashlib.sha256(worker_path.read_bytes()).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix="lightwork-research-component-") as temporary:
            completed = subprocess.run(
                [sys.executable, "-I", os.fspath(worker_path)],
                input=body,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=_PROCESS_TIMEOUT_SECONDS,
                check=False,
                cwd=temporary,
                env=_isolated_process_environment(temporary),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ResearchSimulationError("isolated component process failed closed") from exc
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout.encode("utf-8")) > _MAX_JSON_BYTES
    ):
        raise ResearchSimulationError("isolated component process refused the request")
    try:
        response = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise ResearchSimulationError("isolated component returned invalid JSON") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise ResearchSimulationError("isolated component returned an invalid response")
    if (
        response.get("process_boundary") is not True
        or response.get("oracle_material_received") is not False
        or response.get("interface_version") != INTERFACE_VERSION
    ):
        raise ResearchSimulationError("isolated component boundary attestation is invalid")
    return _detached(response), runtime_sha256


def _isolated_component_proposal(
    descriptor: Mapping[str, object],
    observation: LearnerObservationV1,
) -> tuple[ProposalV1, str]:
    response, runtime_sha256 = _run_component_process({
        "command": "propose_execute",
        "descriptor": dict(descriptor),
        "observation": observation.to_dict(),
    })
    if (
        response.get("component_id") != descriptor.get("component_id")
        or response.get("method_trace") != ["propose", "execute"]
    ):
        raise ResearchSimulationError("isolated component proposal lineage is invalid")
    try:
        proposal = ProposalV1(**dict(response["proposal"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ResearchSimulationError("isolated component proposal is invalid") from exc
    return proposal, runtime_sha256


def _isolated_component_evaluation(
    descriptor: Mapping[str, object],
    result: SimulationResultV1,
    observation: LearnerObservationV1,
    *,
    runtime_sha256: str,
) -> ComponentEvaluationV1:
    response, second_runtime_sha256 = _run_component_process({
        "command": "observe_evaluate",
        "descriptor": dict(descriptor),
        "result": result.to_component_payload(),
        "observation": observation.to_dict(),
    })
    if (
        second_runtime_sha256 != runtime_sha256
        or response.get("component_id") != descriptor.get("component_id")
        or response.get("method_trace") != ["observe", "evaluate"]
    ):
        raise ResearchSimulationError("isolated component evaluation lineage is invalid")
    try:
        return ComponentEvaluationV1(**dict(response["evaluation"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ResearchSimulationError("isolated component evaluation is invalid") from exc


def _study_evidence_payload(values: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in values.items()
        if key not in {"controller_evidence_sha256", "result_payload"}
    }


@dataclass(frozen=True, slots=True)
class StudyRun:
    component_id: str
    baseline_label: str
    result_status: str
    component_passed: bool
    oracle_passed: bool
    oracle_state_sha256: str
    component_declared_interface_version: str
    component_descriptor_sha256: str
    component_runtime_sha256: str
    component_process_isolated: bool
    authority_risk: str
    authority_requires_approval: bool
    approver_principal: str
    approval_id: str
    action_lineage_sha256: str
    action_lineage_valid: bool
    budget_limit: int
    budget_used: int
    cost_event_count: int
    cost_receipt_sha256: str
    cost_accounting_persisted: bool
    accounting_event_id: str
    source_ref: str
    result_class: str
    live_effect: bool
    can_accept_business_outcome: bool
    result_payload: Mapping[str, object]
    result_payload_sha256: str
    controller_evidence_sha256: str
    interface_version: ClassVar[str] = INTERFACE_VERSION

    def __post_init__(self) -> None:
        if self.component_declared_interface_version != INTERFACE_VERSION:
            raise ValueError("study component interface version is unsupported")
        for label, value in (
            ("component descriptor", self.component_descriptor_sha256),
            ("component runtime", self.component_runtime_sha256),
            ("oracle state", self.oracle_state_sha256),
            ("approval", self.approval_id),
            ("action lineage", self.action_lineage_sha256),
            ("cost receipt", self.cost_receipt_sha256),
            ("result payload", self.result_payload_sha256),
            ("controller evidence", self.controller_evidence_sha256),
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError(f"{label} digest must be SHA-256")
        if not self.approver_principal.startswith("user:"):
            raise ValueError("study approval is not bound to a named user")
        if self.source_ref != str(self.result_payload.get("source_ref") or ""):
            raise ValueError("study source does not match its result")
        if self.result_payload_sha256 != _digest(dict(self.result_payload)):
            raise ValueError("study result payload digest is invalid")
        if (
            self.result_payload.get("evidence_class") != "simulated"
            or self.result_payload.get("result_class") != "simulation"
            or self.result_payload.get("live_effect") is not False
            or self.result_payload.get("can_accept_business_outcome") is not False
            or self.result_payload.get("authoritative_live_evidence_eligible") is not False
            or self.result_payload.get("business_outcome_acceptance") != "prohibited"
        ):
            raise ValueError("study result payload escaped the simulation-only boundary")
        if (
            self.result_class != "simulation"
            or self.live_effect is not False
            or self.can_accept_business_outcome is not False
        ):
            raise ValueError("study result escaped the simulation-only boundary")
        object.__setattr__(self, "result_payload", _detached(dict(self.result_payload)))
        values = {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if item.name not in {"controller_evidence_sha256", "result_payload"}
        }
        if self.controller_evidence_sha256 != _digest(_study_evidence_payload(values)):
            raise ValueError("study controller evidence binding is invalid")

    def to_app_payload(self) -> dict[str, object]:
        return _detached({
            **dict(self.result_payload),
            "study_schema": "maverick.research-study-run.v1",
            "component_id": self.component_id,
            "baseline_label": self.baseline_label,
            "component_declared_interface_version": self.component_declared_interface_version,
            "component_descriptor_sha256": self.component_descriptor_sha256,
            "component_runtime_sha256": self.component_runtime_sha256,
            "component_process_isolated": self.component_process_isolated,
            "component_passed": self.component_passed,
            "oracle_passed": self.oracle_passed,
            "oracle_state_sha256": self.oracle_state_sha256,
            "authority_risk": self.authority_risk,
            "authority_requires_approval": self.authority_requires_approval,
            "approver_principal": self.approver_principal,
            "approval_id": self.approval_id,
            "action_lineage_sha256": self.action_lineage_sha256,
            "action_lineage_valid": self.action_lineage_valid,
            "budget_limit": self.budget_limit,
            "budget_used": self.budget_used,
            "cost_event_count": self.cost_event_count,
            "cost_receipt_sha256": self.cost_receipt_sha256,
            "cost_accounting_persisted": self.cost_accounting_persisted,
            "accounting_event_id": self.accounting_event_id,
            "result_payload_sha256": self.result_payload_sha256,
            "controller_evidence_sha256": self.controller_evidence_sha256,
        })


def run_first_study(
    component: ResearchComponentV1,
    world: SoftwareWorldFixture,
    worker: ResearchWorkerSession,
    *,
    approver_identity: AuthenticatedHumanIdentityV1,
) -> StudyRun:
    """Run one controller path while component code remains in a subprocess."""
    if not isinstance(component, ResearchComponentV1):
        raise TypeError("component does not implement ResearchComponentV1")
    if not isinstance(approver_identity, AuthenticatedHumanIdentityV1):
        raise TypeError("approver_identity must be AuthenticatedHumanIdentityV1")
    descriptor, descriptor_sha256 = _component_descriptor(component)
    before_lineage = len(worker.actions.lineage)
    before_receipts = len(worker.cost_receipts)
    initial = worker.initial_observation()
    proposal, runtime_sha256 = _isolated_component_proposal(descriptor, initial)
    preview = worker.preview(proposal)
    approval = AuthenticatedHumanApprovalV1.bind(
        approver_identity,
        scenario_id=world.scenario_id,
        component_id=component.component_id,
        proposal=proposal,
    )
    result = worker.execute(
        proposal,
        component_id=component.component_id,
        component_descriptor_sha256=descriptor_sha256,
        approval=approval,
    )
    observation = worker.observe(result)
    evaluation = _isolated_component_evaluation(
        descriptor,
        result,
        observation,
        runtime_sha256=runtime_sha256,
    )
    oracle = world.assess()
    if len(worker.actions.lineage) != before_lineage + 1:
        raise ResearchSimulationError("study did not issue exactly one action lineage link")
    if len(worker.cost_receipts) != before_receipts + 1:
        raise ResearchSimulationError("study did not issue exactly one cost receipt")
    lineage = worker.actions.lineage[-1]
    receipt = worker.cost_receipts[-1]
    if (
        receipt.component_id != component.component_id
        or receipt.component_descriptor_sha256 != descriptor_sha256
        or receipt.simulation_operation_id != result.operation_id
        or receipt.action_lineage_sha256 != lineage.hash
        or receipt.source_ref != result.source_ref
    ):
        raise ResearchSimulationError("study controller lineage bindings are inconsistent")
    result_payload = result.to_app_payload()
    values: dict[str, object] = {
        "component_id": component.component_id,
        "baseline_label": component.baseline_label,
        "result_status": result.status,
        "component_passed": evaluation.passed,
        "oracle_passed": oracle.passed,
        "oracle_state_sha256": oracle.oracle_state_sha256,
        "component_declared_interface_version": component.interface_version,
        "component_descriptor_sha256": descriptor_sha256,
        "component_runtime_sha256": runtime_sha256,
        "component_process_isolated": True,
        "authority_risk": preview.risk,
        "authority_requires_approval": preview.requires_approval,
        "approver_principal": approval.principal,
        "approval_id": approval.approval_id,
        "action_lineage_sha256": lineage.hash,
        "action_lineage_valid": worker.actions.verify_lineage().startswith("VALID:"),
        "budget_limit": worker.max_operations,
        "budget_used": worker.used_operations,
        "cost_event_count": len(worker.cost_receipts),
        "cost_receipt_sha256": receipt.receipt_sha256,
        "cost_accounting_persisted": receipt.accounting_persisted,
        "accounting_event_id": receipt.accounting_event_id,
        "source_ref": result.source_ref,
        "result_class": "simulation",
        "live_effect": False,
        "can_accept_business_outcome": False,
        "result_payload_sha256": _digest(result_payload),
    }
    return StudyRun(
        **values,
        result_payload=result_payload,
        controller_evidence_sha256=_digest(_study_evidence_payload(values)),
    )


def compatibility_report(runs: Iterable[StudyRun]) -> dict[str, object]:
    """Compare swappable implementations without hiding gates or cost receipts."""
    rows = tuple(runs)
    if len(rows) < 2 or any(not isinstance(row, StudyRun) for row in rows):
        raise ValueError("compatibility report requires at least two StudyRun values")
    authority = {(row.authority_risk, row.authority_requires_approval) for row in rows}
    budgets = {(row.budget_limit, row.budget_used) for row in rows}
    behaviors = {(row.result_status, row.component_passed, row.oracle_passed) for row in rows}
    versions = {row.component_declared_interface_version for row in rows}
    controller_bindings = all(
        row.component_process_isolated
        and row.action_lineage_valid
        and bool(row.approval_id)
        and bool(row.action_lineage_sha256)
        and bool(row.cost_receipt_sha256)
        and row.source_ref.startswith("simulator:")
        for row in rows
    )
    accounting_active = all(
        row.cost_event_count == row.budget_used > 0
        and row.cost_accounting_persisted
        and bool(row.accounting_event_id)
        for row in rows
    )
    simulated_only = all(
        row.result_class == "simulation"
        and row.live_effect is False
        and row.can_accept_business_outcome is False
        for row in rows
    )
    compatible = (
        versions == {INTERFACE_VERSION}
        and len(authority) == 1
        and len(budgets) == 1
        and len(behaviors) == 1
        and controller_bindings
        and accounting_active
        and simulated_only
    )
    return {
        "schema": "maverick.research-component-compatibility.v1",
        "interface_version": INTERFACE_VERSION,
        "compatible": compatible,
        "authority_policy_equal": len(authority) == 1,
        "budget_equal": len(budgets) == 1,
        "behavior_equal": len(behaviors) == 1,
        "controller_bindings_valid": controller_bindings,
        "cost_accounting_active": accounting_active,
        "simulated_only": simulated_only,
        "components": [
            {
                "component_id": row.component_id,
                "baseline_label": row.baseline_label,
                "authority_risk": row.authority_risk,
                "authority_requires_approval": row.authority_requires_approval,
                "budget_limit": row.budget_limit,
                "budget_used": row.budget_used,
                "cost_event_count": row.cost_event_count,
                "component_descriptor_sha256": row.component_descriptor_sha256,
                "component_runtime_sha256": row.component_runtime_sha256,
                "action_lineage_sha256": row.action_lineage_sha256,
                "cost_receipt_sha256": row.cost_receipt_sha256,
                "accounting_event_id": row.accounting_event_id,
            }
            for row in rows
        ],
    }


@dataclass(frozen=True)
class TaskGeneratorFamily:
    """Evaluator-custody family. Private fields never enter the dev catalog."""

    family_id: str
    mechanism_family: str
    application_family: str
    public_task: Mapping[str, object]
    generator_parameters: Mapping[str, object]
    reference_solution: object

    def __post_init__(self) -> None:
        object.__setattr__(self, "family_id", _name(self.family_id, "family_id"))
        object.__setattr__(
            self, "mechanism_family", _name(self.mechanism_family, "mechanism_family")
        )
        object.__setattr__(
            self, "application_family", _name(self.application_family, "application_family")
        )
        object.__setattr__(self, "public_task", _detached(dict(self.public_task)))
        object.__setattr__(
            self, "generator_parameters", _detached(dict(self.generator_parameters))
        )
        object.__setattr__(self, "reference_solution", _detached(self.reference_solution))


class WithheldFamilyPartition:
    """Whole-family split backed by a separate evaluator-custody process.

    The parent object retains public development rows and the split metadata.
    Private held-out parameters and reference answers are transferred once to a
    scrubbed child process and are never stored on, or returned to, this object.
    """

    __slots__ = (
        "_closed",
        "_custody_sha256",
        "_development",
        "_development_pairs",
        "_evaluator",
        "_lock",
        "_temporary",
        "_withheld",
        "_withheld_pairs",
    )

    def __init__(
        self,
        families: Iterable[TaskGeneratorFamily],
        *,
        withheld_family_ids: Iterable[str],
    ) -> None:
        rows = tuple(families)
        if not rows or any(not isinstance(row, TaskGeneratorFamily) for row in rows):
            raise ValueError("families must be a non-empty TaskGeneratorFamily sequence")
        ids = [row.family_id for row in rows]
        if len(ids) != len(set(ids)):
            raise ValueError("task generator family IDs must be unique")
        withheld = frozenset(_name(value, "withheld family ID") for value in withheld_family_ids)
        if not withheld or not withheld.issubset(ids) or withheld == set(ids):
            raise ValueError("withheld families must be a proper non-empty subset")
        pairs: dict[tuple[str, str], bool] = {}
        for row in rows:
            pair = (row.mechanism_family, row.application_family)
            selected = row.family_id in withheld
            prior = pairs.setdefault(pair, selected)
            if prior != selected:
                raise ValueError(
                    "a mechanism/application family cannot be split across dev and withheld sets"
                )
        development = tuple(
            {
                "family_id": row.family_id,
                "mechanism_family": row.mechanism_family,
                "application_family": row.application_family,
                "public_task": _detached(dict(row.public_task)),
            }
            for row in rows
            if row.family_id not in withheld
        )
        heldout_payload = {
            row.family_id: {
                "generator_parameters": _detached(dict(row.generator_parameters)),
                "reference_solution": _detached(row.reference_solution),
            }
            for row in rows
            if row.family_id in withheld
        }
        self._development = development
        self._development_pairs = tuple(
            (row.mechanism_family, row.application_family)
            for row in rows
            if row.family_id not in withheld
        )
        self._withheld = withheld
        self._withheld_pairs = tuple(
            (row.mechanism_family, row.application_family)
            for row in rows
            if row.family_id in withheld
        )
        self._lock = threading.Lock()
        self._closed = False
        self._custody_sha256 = ""
        self._temporary = tempfile.TemporaryDirectory(
            prefix="lightwork-research-holdout-"
        )
        worker_path = Path(__file__).with_name("research_holdout_worker.py")
        if not worker_path.is_file():
            self._temporary.cleanup()
            raise ResearchSimulationError("held-out evaluator runtime is unavailable")
        try:
            self._evaluator = subprocess.Popen(
                [sys.executable, "-I", os.fspath(worker_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                bufsize=1,
                cwd=self._temporary.name,
                env=_isolated_process_environment(self._temporary.name),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            initialized = self._request({
                "command": "initialize",
                "families": heldout_payload,
            })
            if (
                initialized.get("schema") != "maverick.research-heldout-custody.v1"
                or initialized.get("family_count") != len(heldout_payload)
                or not _SHA256.fullmatch(str(initialized.get("custody_sha256") or ""))
            ):
                raise ResearchSimulationError("held-out evaluator attestation is invalid")
            self._custody_sha256 = str(initialized["custody_sha256"])
        except Exception:
            self.close()
            raise

    def _request(self, payload: Mapping[str, object]) -> dict[str, object]:
        if self._closed or self._evaluator.poll() is not None:
            raise ResearchSimulationError("held-out evaluator is unavailable")
        message = _canonical(dict(payload)) + "\n"
        if self._evaluator.stdin is None or self._evaluator.stdout is None:
            raise ResearchSimulationError("held-out evaluator pipes are unavailable")
        with self._lock:
            try:
                self._evaluator.stdin.write(message)
                self._evaluator.stdin.flush()
                replies: queue_module.Queue[object] = queue_module.Queue(maxsize=1)

                def read_reply() -> None:
                    try:
                        replies.put(self._evaluator.stdout.readline(_MAX_JSON_BYTES + 1))
                    except BaseException as exc:  # process boundary is fail-closed
                        replies.put(exc)

                reader = threading.Thread(target=read_reply, daemon=True)
                reader.start()
                try:
                    received = replies.get(timeout=_PROCESS_TIMEOUT_SECONDS)
                except queue_module.Empty as exc:
                    self._evaluator.kill()
                    raise ResearchSimulationError(
                        "held-out evaluator timed out and was terminated"
                    ) from exc
            except (BrokenPipeError, OSError, UnicodeError) as exc:
                raise ResearchSimulationError("held-out evaluator failed closed") from exc
        if isinstance(received, BaseException):
            raise ResearchSimulationError("held-out evaluator failed closed") from received
        raw = str(received)
        if not raw or len(raw.encode("utf-8")) > _MAX_JSON_BYTES or not raw.endswith("\n"):
            raise ResearchSimulationError("held-out evaluator response is invalid")
        try:
            response = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ResearchSimulationError("held-out evaluator returned invalid JSON") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise ResearchSimulationError(
                str(response.get("error") or "held-out evaluator refused the request")
                if isinstance(response, dict)
                else "held-out evaluator refused the request"
            )
        return _detached(response)

    def development_environment(self) -> dict[str, object]:
        return {
            "schema": "maverick.research-development-environment.v1",
            "interface_version": INTERFACE_VERSION,
            "families": _detached(list(self._development)),
            "environment": {},
            "credentials": [],
            "private_generator_parameters_available": False,
            "reference_solutions_available": False,
            "heldout_evaluator_process_isolated": True,
        }

    def split_report(self) -> dict[str, object]:
        development = list(self._development_pairs)
        withheld = list(self._withheld_pairs)
        return {
            "schema": "maverick.research-family-split.v1",
            "partition_unit": "mechanism_application_family",
            "development_families": development,
            "withheld_families": withheld,
            "disjoint": set(development).isdisjoint(withheld),
            "evaluator_custody_sha256": self._custody_sha256,
            "evaluator_process_isolated": True,
        }

    def evaluate_withheld(self, family_id: str, candidate: object) -> bool:
        selected = _name(family_id, "family_id")
        if selected not in self._withheld:
            raise PermissionError("only withheld families use evaluator custody")
        response = self._request({
            "command": "evaluate",
            "family_id": selected,
            "candidate": _detached(candidate),
        })
        if not isinstance(response.get("passed"), bool):
            raise ResearchSimulationError("held-out evaluator verdict is invalid")
        return bool(response["passed"])

    def close(self) -> None:
        """Release the evaluator without ever retrieving its private material."""
        if self._closed:
            return
        evaluator = getattr(self, "_evaluator", None)
        try:
            if evaluator is not None and evaluator.poll() is None:
                try:
                    self._request({"command": "close"})
                except ResearchSimulationError:
                    pass
                try:
                    evaluator.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    evaluator.kill()
                    evaluator.wait(timeout=2.0)
        finally:
            self._closed = True
            if evaluator is not None:
                for stream in (evaluator.stdin, evaluator.stdout, evaluator.stderr):
                    if stream is not None:
                        stream.close()
            temporary = getattr(self, "_temporary", None)
            if temporary is not None:
                temporary.cleanup()

    def __enter__(self) -> WithheldFamilyPartition:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best-effort interpreter cleanup
        try:
            self.close()
        except Exception:
            pass


__all__ = [
    "APPROVAL_SCHEMA",
    "AuthenticatedHumanApprovalV1",
    "AuthenticatedHumanIdentityV1",
    "COMPONENT_DESCRIPTOR_SCHEMA",
    "ComponentEvaluationV1",
    "COST_RECEIPT_SCHEMA",
    "FAULT_KINDS",
    "FaultSpec",
    "FeaturePrefixBackoffBaseline",
    "INTERFACE_VERSION",
    "LearnerObservationV1",
    "OracleAssessment",
    "ProposalV1",
    "ResearchBudgetExceeded",
    "ResearchComponentV1",
    "ResearchSimulationError",
    "ResearchWorkerSession",
    "ResetReceipt",
    "SIMULATOR_SCHEMA",
    "SimulatedOutcomeAcceptanceError",
    "SimulationCostReceiptV1",
    "SimulationResultV1",
    "SimulatorContaminationError",
    "SoftwareWorldFixture",
    "SoftwareWorldScenario",
    "StudyRun",
    "TabularResearchBaseline",
    "TaskGeneratorFamily",
    "WithheldFamilyPartition",
    "compatibility_report",
    "run_first_study",
]
