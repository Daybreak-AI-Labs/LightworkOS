"""Durable, tenant-scoped research runs over governed registry identities.

The ledger stores content-free commitments and aggregate metrics. Dataset bytes
can reach an execution environment only through an injected adapter while the
same authority fence used by local revocation is held. Distributed deployments
must inject an equivalent shared effect guard; otherwise dispatch fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import Protocol
from urllib.parse import urlsplit

from .governed_records import GovernedRecordStore
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict
from .provider_cost_cap import work_item_scope
from .research_registry import (
    DatasetAdmission,
    ModelAdmission,
    ResearchAssetRef,
    ResearchRegistry,
    TrainingReceiptAuthority,
)

RUN_SCHEMA = "lightwork.research-run.v1"
RUN_EXPORT_SCHEMA = "lightwork.research-run-export.v1"
RUN_AUTHORITY_SCHEMA = "lightwork.research-run-authority.v1"
WORKER_AUTHORITY_SCHEMA = "lightwork.research-worker-authority.v1"
DISPATCH_REQUEST_SCHEMA = "lightwork.research-dispatch-request.v1"
DISPATCH_RECEIPT_SCHEMA = "lightwork.research-dispatch-receipt.v1"
RESOURCE_CAPS_SCHEMA = "lightwork.research-resource-caps.v1"
RESOURCE_COST_SCHEMA = "lightwork.research-resource-cost.v1"
METRIC_SCHEMA = "lightwork.research-metric.v1"
STUDY_CONTEXT_SCHEMA = "lightwork.research-study-context.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z][A-Z0-9]{2,7}\Z")
_UNIT = re.compile(r"[a-z][a-z0-9_.-]{0,31}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})\Z")
_ACTIONS = frozenset({"analyze", "train"})
_TERMINAL = frozenset({"completed", "failed", "cancelled", "interrupted"})
_COST_BASES = frozenset({"estimated", "observed", "settled", "unknown"})
_COST_CATEGORIES = frozenset(
    {
        "compute",
        "evaluation",
        "generation",
        "human",
        "inference",
        "retrieval",
        "storage",
        "training",
        "updates",
    }
)
_MAX_RUNS = 2_048
_MAX_LIST = 256
_MAX_ATTEMPTS = 32
_MAX_EVENTS = 64
_MAX_COST_EVENTS = 128
_MAX_METRICS = 128


class ResearchRunError(RuntimeError):
    """Base run-ledger error."""


class ResearchRunConflict(ResearchRunError):
    """A run, authority, binding, or lifecycle revision changed."""


class ResearchRunNotFound(ResearchRunError, LookupError):
    """A run is not visible in the requested tenant."""


class ResearchMaterializationUnavailable(ResearchRunError):
    """No trusted adapter can keep data materialization inside the boundary."""


class ResearchRunInterrupted(ResearchRunError):
    """A dispatch may have begun and therefore cannot be replayed automatically."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("research run material must be finite JSON") from exc
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("research run material exceeds its size boundary")
    return encoded


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} is not a bounded identifier")
    return value


def _purpose(value: object, label: str = "purpose") -> str:
    if not isinstance(value, str) or not _PURPOSE.fullmatch(value):
        raise ValueError(f"{label} is not a bounded purpose")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _actor(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("user:")
        or not 6 < len(value) <= 512
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(f"{label} must be a named user principal")
    return value


def _text(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    result = value.strip()
    if len(result.encode("utf-8")) > maximum or any(ord(char) < 32 for char in result):
        raise ValueError(f"{label} is not bounded text")
    return result


def _source_ref(value: object, label: str) -> str:
    result = _text(value, label, 512)
    parsed = urlsplit(result)
    if parsed.scheme == "https":
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(f"{label} cannot contain credentials, query, or fragment")
    elif not re.fullmatch(
        r"(?:urn|catalog|artifact):[A-Za-z0-9][A-Za-z0-9._:/-]{0,500}",
        result,
    ):
        raise ValueError(f"{label} must be a safe HTTPS or opaque reference")
    return result


def _decimal(value: object, label: str, *, non_negative: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an exact decimal string")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be an exact decimal string") from exc
    if not number.is_finite() or (non_negative and number < 0):
        requirement = "finite and non-negative" if non_negative else "finite"
        raise ValueError(f"{label} must be {requirement}")
    # Reject huge exponents before normalizing: normalize() raises
    # decimal.Overflow (not ValueError) past the context's exponent limit, and
    # no value this far from 1 fits the 64-character boundary below.
    if number and abs(number.adjusted()) > 64:
        raise ValueError(f"{label} exceeds its precision boundary")
    normalized = format(number.normalize(), "f")
    if normalized == "-0":
        normalized = "0"
    if len(normalized) > 64 or Decimal(normalized) != number:
        raise ValueError(f"{label} exceeds its precision boundary")
    return normalized


def _positive_timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} must be a positive finite timestamp")
    return float(value)


@dataclass(frozen=True)
class ResearchRunAuthority:
    tenant: str
    principal: str
    authorization_sha256: str
    schema: str = RUN_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _actor(self.principal, "run principal")
        _sha(self.authorization_sha256, "run authorization_sha256")
        if self.schema != RUN_AUTHORITY_SCHEMA:
            raise ValueError("run authority schema is unsupported")


@dataclass(frozen=True)
class ResearchWorkerAuthority:
    tenant: str
    principal: str
    authorization_sha256: str
    schema: str = WORKER_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _actor(self.principal, "worker principal")
        _sha(self.authorization_sha256, "worker authorization_sha256")
        if self.schema != WORKER_AUTHORITY_SCHEMA:
            raise ValueError("worker authority schema is unsupported")


@dataclass(frozen=True)
class ResearchResourceCaps:
    max_wall_seconds: int
    max_provider_calls: int
    max_storage_bytes: int
    max_cost: str
    currency: str
    schema: str = RESOURCE_CAPS_SCHEMA

    def __post_init__(self) -> None:
        for value, label, maximum in (
            (self.max_wall_seconds, "max_wall_seconds", 31_536_000),
            (self.max_provider_calls, "max_provider_calls", 10_000_000),
            (self.max_storage_bytes, "max_storage_bytes", 2**60),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"{label} is outside its bounded range")
        object.__setattr__(self, "max_cost", _decimal(self.max_cost, "max_cost"))
        if not isinstance(self.currency, str) or not _CURRENCY.fullmatch(self.currency):
            raise ValueError("currency must be a bounded uppercase currency code")
        if self.schema != RESOURCE_CAPS_SCHEMA:
            raise ValueError("resource caps schema is unsupported")


@dataclass(frozen=True)
class ResearchResourceCost:
    category: str
    basis: str
    quantity: str | None
    unit: str | None
    amount: str | None
    currency: str | None
    evidence_sha256: str
    source_ref: str
    incomplete_reason: str | None = None
    schema: str = RESOURCE_COST_SCHEMA

    def __post_init__(self) -> None:
        if self.category not in _COST_CATEGORIES:
            raise ValueError("resource cost category is unsupported")
        if self.basis not in _COST_BASES:
            raise ValueError("resource cost basis is unsupported")
        if (self.quantity is None) != (self.unit is None):
            raise ValueError("resource quantity and unit must be supplied together")
        if self.quantity is not None:
            object.__setattr__(
                self,
                "quantity",
                _decimal(self.quantity, "resource quantity"),
            )
            if not isinstance(self.unit, str) or not _UNIT.fullmatch(self.unit):
                raise ValueError("resource unit is unsupported")
        if (self.amount is None) != (self.currency is None):
            raise ValueError("resource amount and currency must be supplied together")
        if self.amount is not None:
            object.__setattr__(
                self,
                "amount",
                _decimal(self.amount, "resource amount"),
            )
            if not isinstance(self.currency, str) or not _CURRENCY.fullmatch(self.currency):
                raise ValueError("resource currency is unsupported")
        if self.quantity is None and self.amount is None and self.basis != "unknown":
            raise ValueError("a resource cost needs a quantity or amount")
        if self.basis == "unknown" and self.amount is not None:
            raise ValueError("unknown cost basis cannot claim a known amount")
        if self.amount is None:
            _text(self.incomplete_reason, "incomplete_reason", 512)
        elif self.incomplete_reason is not None:
            raise ValueError("known cost amounts cannot carry an incomplete reason")
        _sha(self.evidence_sha256, "resource cost evidence_sha256")
        object.__setattr__(
            self,
            "source_ref",
            _source_ref(self.source_ref, "resource cost source_ref"),
        )
        if self.schema != RESOURCE_COST_SCHEMA:
            raise ValueError("resource cost schema is unsupported")


@dataclass(frozen=True)
class ResearchMetric:
    name: str
    value: str
    evaluator_id: str
    evaluator_version: str
    source_artifact_sha256: str
    lineage_sha256: str
    schema: str = METRIC_SCHEMA

    def __post_init__(self) -> None:
        _purpose(self.name, "metric name")
        object.__setattr__(
            self,
            "value",
            _decimal(self.value, "metric value", non_negative=False),
        )
        _identifier(self.evaluator_id, "metric evaluator_id")
        _identifier(self.evaluator_version, "metric evaluator_version")
        _sha(self.source_artifact_sha256, "metric source_artifact_sha256")
        _sha(self.lineage_sha256, "metric lineage_sha256")
        if self.schema != METRIC_SCHEMA:
            raise ValueError("research metric schema is unsupported")


@dataclass(frozen=True)
class ResearchStudyContext:
    """Immutable completed-run facts supplied to a trusted study evaluator."""

    tenant: str
    run_id: str
    candidate_principal: str
    run_manifest_sha256: str
    result_sha256: str
    output_artifact_sha256: str
    metric_protocol_sha256: str
    metrics: tuple[ResearchMetric, ...]
    schema: str = STUDY_CONTEXT_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.run_id, "study context run_id")
        _actor(self.candidate_principal, "study context candidate principal")
        _sha(self.run_manifest_sha256, "study context run manifest_sha256")
        _sha(self.result_sha256, "study context result_sha256")
        _sha(self.output_artifact_sha256, "study context output_artifact_sha256")
        _sha(self.metric_protocol_sha256, "study context metric_protocol_sha256")
        if type(self.metrics) is not tuple or len(self.metrics) > _MAX_METRICS:
            raise ValueError("study context metrics are malformed")
        if any(type(item) is not ResearchMetric for item in self.metrics):
            raise ValueError("study context metrics are malformed")
        if self.schema != STUDY_CONTEXT_SCHEMA:
            raise ValueError("study context schema is unsupported")

    @property
    def sha256(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class DatasetMaterializationSpec:
    reference: ResearchAssetRef
    source_ref: str
    content_sha256: str
    license_id: str
    license_evidence_sha256: str
    usage_constraints: tuple[str, ...]
    data_use_authority_sha256: str
    consent_evidence_sha256: str | None


@dataclass(frozen=True)
class ModelExecutionSpec:
    reference: ResearchAssetRef
    source_ref: str
    artifact_sha256: str
    provider_model_identity: str
    immutable_provider_revision: str | None
    observed_from: float | None
    observed_until: float | None
    reproducibility_limitation: str | None


@dataclass(frozen=True)
class ResearchDispatchRequest:
    tenant: str
    run_id: str
    attempt: int
    request_sha256: str
    purpose: str
    action: str
    environment_id: str
    environment_version: str
    environment_sha256: str
    datasets: tuple[DatasetMaterializationSpec, ...]
    model: ModelExecutionSpec | None
    resource_caps: ResearchResourceCaps
    plan: dict | None = None
    schema: str = DISPATCH_REQUEST_SCHEMA


@dataclass(frozen=True)
class ResearchDispatchReceipt:
    tenant: str
    run_id: str
    attempt: int
    request_sha256: str
    dispatch_id: str
    adapter_id: str
    adapter_version: str
    adapter_authority_sha256: str
    materialized_dataset_sha256s: tuple[str, ...]
    dispatched_at: float
    schema: str = DISPATCH_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _identifier(self.run_id, "dispatch run_id")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= _MAX_ATTEMPTS
        ):
            raise ValueError("dispatch attempt is outside its bounded range")
        _sha(self.request_sha256, "dispatch request_sha256")
        _identifier(self.dispatch_id, "dispatch_id")
        _identifier(self.adapter_id, "adapter_id")
        _identifier(self.adapter_version, "adapter_version")
        _sha(self.adapter_authority_sha256, "adapter_authority_sha256")
        if isinstance(self.materialized_dataset_sha256s, str | bytes) or not isinstance(
            self.materialized_dataset_sha256s, Sequence
        ):
            raise ValueError("materialized dataset commitments are invalid")
        commitments = tuple(self.materialized_dataset_sha256s)
        if len(commitments) > 128:
            raise ValueError("materialized dataset commitments are invalid")
        for value in commitments:
            _sha(value, "materialized dataset SHA-256")
        object.__setattr__(self, "materialized_dataset_sha256s", commitments)
        _positive_timestamp(self.dispatched_at, "dispatched_at")
        if self.schema != DISPATCH_RECEIPT_SCHEMA:
            raise ValueError("dispatch receipt schema is unsupported")


class ResearchEffectAdapter(Protocol):
    """Trusted boundary that verifies bytes and begins the research effect.

    Implementations must resolve every source inside the declared execution
    boundary, verify its exact content digest, apply the usage constraints, and
    begin execution before returning the receipt. They must not expose host
    paths or raw rows through the receipt.
    """

    def materialize_and_dispatch(
        self,
        request: ResearchDispatchRequest,
    ) -> ResearchDispatchReceipt: ...


def _event(
    events: list[dict],
    *,
    state: str,
    recorded_at: float,
    actor: str,
    details: Mapping[str, object] | None = None,
) -> dict:
    if len(events) >= _MAX_EVENTS:
        raise ResearchRunConflict("attempt event history reached its bounded limit")
    material = {
        "sequence": len(events) + 1,
        "state": state,
        "recorded_at": recorded_at,
        "actor": actor,
        "details": dict(details or {}),
        "previous_event_sha256": (None if not events else events[-1]["event_sha256"]),
    }
    material["event_sha256"] = _digest(material)
    return material


def _cost_event(
    costs: list[dict],
    *,
    event_key: str,
    cost: ResearchResourceCost,
    recorded_at: float,
    actor: str,
    correction_of: str | None,
) -> dict:
    if len(costs) >= _MAX_COST_EVENTS:
        raise ResearchRunConflict("attempt cost history reached its bounded limit")
    material = {
        "sequence": len(costs) + 1,
        "event_key": _identifier(event_key, "cost event key"),
        "cost": asdict(cost),
        "recorded_at": recorded_at,
        "recorded_by": actor,
        "correction_of": correction_of,
        "previous_event_sha256": (None if not costs else costs[-1]["event_sha256"]),
    }
    material["event_sha256"] = _digest(material)
    return material


def _validate_chain(events: object, *, label: str, maximum: int) -> list[dict]:
    if not isinstance(events, list) or len(events) > maximum:
        raise ResearchRunConflict(f"{label} history is malformed")
    previous = None
    for sequence, item in enumerate(events, start=1):
        if not isinstance(item, dict):
            raise ResearchRunConflict(f"{label} history is malformed")
        if item.get("sequence") != sequence or item.get("previous_event_sha256") != previous:
            raise ResearchRunConflict(f"{label} history chain is broken")
        actual = item.get("event_sha256")
        if not isinstance(actual, str) or not _SHA.fullmatch(actual):
            raise ResearchRunConflict(f"{label} history digest is malformed")
        expected = _digest({key: value for key, value in item.items() if key != "event_sha256"})
        if not hmac.compare_digest(actual, expected):
            raise ResearchRunConflict(f"{label} history digest does not match")
        previous = actual
    return events


class ResearchRuns:
    """Governed run and attempt ledger with pre-effect registry admission."""

    def __init__(
        self,
        *,
        registry: ResearchRegistry,
        authority_resolver: Callable[[str, str], ResearchRunAuthority],
        worker_authority_resolver: Callable[[str, str], ResearchWorkerAuthority],
        effect_adapter: ResearchEffectAdapter | None = None,
        record_store: GovernedRecordStore | None = None,
        effect_fence: Callable[[], AbstractContextManager[object]] | None = None,
        shared_effect_guard: (
            Callable[[str, str, int], AbstractContextManager[object]] | None
        ) = None,
        promotion_study_resolver: Callable[[ResearchStudyContext], object] | None = None,
        review_authority_resolver: Callable[[str, str], ResearchWorkerAuthority] | None = None,
    ) -> None:
        from .authority_effects import authority_effect_fence

        if type(registry) is not ResearchRegistry:
            raise TypeError("an exact ResearchRegistry is required")
        self.registry = registry
        self.authority_resolver = authority_resolver
        self.worker_authority_resolver = worker_authority_resolver
        self.effect_adapter = effect_adapter
        self.store = record_store or GovernedRecordStore(
            "research-runs",
            "research-run",
            "research-run",
        )
        self.effect_fence = effect_fence or authority_effect_fence
        self.shared_effect_guard = shared_effect_guard
        self.promotion_study_resolver = promotion_study_resolver
        self.review_authority_resolver = review_authority_resolver

    def _can_review(self, tenant, principal):
        if self.review_authority_resolver is None:
            return False
        try:
            current = self.review_authority_resolver(tenant, principal)
        except PermissionError:
            return False
        if type(current) is not ResearchWorkerAuthority or current.tenant != tenant or current.principal != principal:
            raise PermissionError("current research reviewer authority is unavailable")
        return True

    @staticmethod
    def _record_id(tenant: str, run_id: str) -> str:
        material = f"{canonical_tenant_id(tenant)}\0{run_id}".encode()
        return f"research-run-{hashlib.sha256(material).hexdigest()[:48]}"

    def _authority(self, tenant: str, principal: str) -> ResearchRunAuthority:
        try:
            result = self.authority_resolver(tenant, principal)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise PermissionError("research run authority is unavailable") from exc
        if (
            type(result) is not ResearchRunAuthority
            or result.tenant != tenant
            or result.principal != principal
        ):
            raise PermissionError("research run authority is unavailable")
        return result

    def _worker_authority(
        self,
        tenant: str,
        principal: str,
    ) -> ResearchWorkerAuthority:
        try:
            result = self.worker_authority_resolver(tenant, principal)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise PermissionError("research worker authority is unavailable") from exc
        if (
            type(result) is not ResearchWorkerAuthority
            or result.tenant != tenant
            or result.principal != principal
        ):
            raise PermissionError("research worker authority is unavailable")
        return result

    def _validate_attempt_record(  # noqa: C901 - validation is deliberately linear
        self,
        attempt: dict,
        manifest: Mapping[str, object],
    ) -> None:
        status = attempt.get("status")
        if status not in {"planned", "queued", "running", *_TERMINAL}:
            raise ResearchRunConflict("research attempt status is malformed")
        if attempt.get("version_binding") != self._version_binding(manifest):
            raise ResearchRunConflict("research attempt version binding changed")
        registry_binding = attempt.get("registry_binding")
        if registry_binding is not None:
            if not isinstance(registry_binding, dict):
                raise ResearchRunConflict("research registry binding is malformed")
            actual = registry_binding.get("binding_sha256")
            expected = _digest(
                {key: value for key, value in registry_binding.items() if key != "binding_sha256"}
            )
            if (
                not isinstance(actual, str)
                or not _SHA.fullmatch(actual)
                or not hmac.compare_digest(actual, expected)
            ):
                raise ResearchRunConflict("research registry binding digest does not match")
        if status not in {"planned", "cancelled"} and registry_binding is None:
            raise ResearchRunConflict("admitted attempt has no registry binding")
        worker = attempt.get("worker_authority")
        if worker is not None:
            try:
                authority = ResearchWorkerAuthority(**worker)
            except (TypeError, ValueError) as exc:
                raise ResearchRunConflict("research worker authority is malformed") from exc
            if asdict(authority) != worker:
                raise ResearchRunConflict("research worker authority changed")
        if status in {"planned", "queued"} and worker is not None:
            raise ResearchRunConflict("pre-dispatch attempt carries unexpected worker authority")
        dispatch = attempt.get("dispatch_receipt")
        if dispatch is not None:
            try:
                receipt = ResearchDispatchReceipt(**dispatch)
            except (TypeError, ValueError) as exc:
                raise ResearchRunConflict("research dispatch receipt is malformed") from exc
            if _canonical(asdict(receipt)) != _canonical(dispatch):
                raise ResearchRunConflict("research dispatch receipt changed")
        if status in {"completed", "failed"} and dispatch is None:
            raise ResearchRunConflict("terminal attempt has no dispatch receipt")
        costs = attempt["costs"]
        event_keys: set[str] = set()
        event_digests: set[str] = set()
        corrected: set[str] = set()
        for event in costs:
            key = event.get("event_key")
            if not isinstance(key, str) or key in event_keys:
                raise ResearchRunConflict("research cost event identity is invalid")
            event_keys.add(key)
            try:
                cost = ResearchResourceCost(**event["cost"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ResearchRunConflict("research cost evidence is malformed") from exc
            if asdict(cost) != event["cost"]:
                raise ResearchRunConflict("research cost evidence changed")
            correction_of = event.get("correction_of")
            if correction_of is None:
                if "request_sha256" in event:
                    raise ResearchRunConflict("original research cost carries correction material")
            else:
                if correction_of not in event_digests or correction_of in corrected:
                    raise ResearchRunConflict("research cost correction history is malformed")
                corrected.add(correction_of)
                expected_request = _digest(
                    {
                        "correction_key": key,
                        "correction_of": correction_of,
                        "replacement": event["cost"],
                    }
                )
                if event.get("request_sha256") != expected_request:
                    raise ResearchRunConflict(
                        "research cost correction request digest does not match"
                    )
            event_digests.add(event["event_sha256"])
        metrics = attempt.get("metrics")
        if not isinstance(metrics, list) or len(metrics) > _MAX_METRICS:
            raise ResearchRunConflict("research metric history is malformed")
        metric_keys = []
        for metric_row in metrics:
            try:
                metric = ResearchMetric(**metric_row)
            except (TypeError, ValueError) as exc:
                raise ResearchRunConflict("research metric evidence is malformed") from exc
            if asdict(metric) != metric_row:
                raise ResearchRunConflict("research metric evidence changed")
            metric_keys.append(
                (
                    metric.name,
                    metric.evaluator_id,
                    metric.evaluator_version,
                    metric.source_artifact_sha256,
                )
            )
        if metric_keys != sorted(set(metric_keys)):
            raise ResearchRunConflict("research metric identities are malformed")
        terminal = attempt.get("terminal")
        if status in _TERMINAL and not isinstance(terminal, dict):
            raise ResearchRunConflict("terminal attempt result is unavailable")
        if status not in _TERMINAL and terminal is not None:
            raise ResearchRunConflict("non-terminal attempt carries a terminal result")
        has_result_digest = isinstance(terminal, dict) and "result_sha256" in terminal
        if has_result_digest:
            result = dict(terminal)
            actual_result = result.pop("result_sha256", None)
            training_authority = result.pop("training_receipt_authority", None)
            if (
                not isinstance(actual_result, str)
                or not _SHA.fullmatch(actual_result)
                or not hmac.compare_digest(actual_result, _digest(result))
                or result.get("outcome") != status
            ):
                raise ResearchRunConflict("terminal result digest does not match")
            result_key = result.get("result_idempotency_key")
            initial_costs = [
                event["cost"]
                for event in costs
                if event.get("event_key", "").startswith(f"finish.{result_key}.")
                and event.get("correction_of") is None
            ]
            if result.get("costs") != initial_costs or result.get("metrics") != metrics:
                raise ResearchRunConflict(
                    "terminal result disagrees with retained cost or metric evidence"
                )
            if training_authority is not None:
                try:
                    authority = TrainingReceiptAuthority(**training_authority)
                except (TypeError, ValueError) as exc:
                    raise ResearchRunConflict(
                        "terminal training receipt authority is malformed"
                    ) from exc
                if asdict(authority) != training_authority:
                    raise ResearchRunConflict("terminal training receipt authority changed")
        elif status in {"completed", "failed"}:
            raise ResearchRunConflict("terminal result digest is unavailable")
        events = attempt["events"]
        if not events:
            raise ResearchRunConflict("research attempt event history is empty")
        final_event = events[-1]
        expected_event_states = {"running", "dispatched"} if status == "running" else {status}
        if final_event.get("state") not in expected_event_states:
            raise ResearchRunConflict("research attempt status disagrees with its event history")
        details = final_event.get("details")
        if not isinstance(details, Mapping):
            raise ResearchRunConflict("research attempt event details are malformed")
        if has_result_digest and details.get("result_sha256") != terminal.get("result_sha256"):
            raise ResearchRunConflict("terminal result disagrees with its event history")

    def _record(self, tenant: str, run_id: str) -> dict:
        record = self.store.get(self._record_id(tenant, run_id))
        if record is None or record.get("tenant") != tenant or record.get("run_id") != run_id:
            raise ResearchRunNotFound("research run was not found in this tenant")
        if record.get("schema") != RUN_SCHEMA:
            raise ResearchRunConflict("research run schema is unsupported")
        submitter = record.get("submit_authority")
        try:
            submit_authority = ResearchRunAuthority(**submitter)
        except (TypeError, ValueError) as exc:
            raise ResearchRunConflict("research submitter authority is malformed") from exc
        if (
            asdict(submit_authority) != submitter
            or submit_authority.tenant != tenant
            or submit_authority.principal != record.get("created_by")
        ):
            raise ResearchRunConflict("research submitter authority changed")
        manifest = record.get("manifest")
        if (
            not isinstance(manifest, dict)
            or not hmac.compare_digest(
                str(record.get("manifest_sha256") or ""),
                _digest(manifest),
            )
            or manifest.get("run_id") != run_id
        ):
            raise ResearchRunConflict("research run manifest digest does not match")
        attempts = record.get("attempts")
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= _MAX_ATTEMPTS:
            raise ResearchRunConflict("research attempt history is malformed")
        for number, attempt in enumerate(attempts, start=1):
            if not isinstance(attempt, dict) or attempt.get("number") != number:
                raise ResearchRunConflict("research attempt history is malformed")
            try:
                _validate_chain(
                    attempt.get("events"),
                    label="attempt event",
                    maximum=_MAX_EVENTS,
                )
                _validate_chain(
                    attempt.get("costs"),
                    label="attempt cost",
                    maximum=_MAX_COST_EVENTS,
                )
                self._validate_attempt_record(attempt, manifest)
            except ResearchRunConflict:
                raise
            except (KeyError, TypeError, ValueError) as exc:
                raise ResearchRunConflict("research attempt history is malformed") from exc
            if number < len(attempts) and attempt.get("status") != "failed":
                raise ResearchRunConflict("only a failed attempt may precede a retained retry")
        if record.get("status") != attempts[-1].get("status"):
            raise ResearchRunConflict("research run status disagrees with its latest attempt")
        return record

    @staticmethod
    def _attempt(record: Mapping[str, object]) -> dict:
        attempts = record["attempts"]
        if not isinstance(attempts, list) or not attempts:
            raise ResearchRunConflict("research attempt history is unavailable")
        attempt = attempts[-1]
        if not isinstance(attempt, dict):
            raise ResearchRunConflict("research attempt history is malformed")
        return attempt

    @staticmethod
    def _version_binding(manifest: Mapping[str, object]) -> dict:
        material = {
            "experiment_id": manifest["experiment_id"],
            "experiment_version": manifest["experiment_version"],
            "run_version": manifest["run_version"],
            "code_revision": manifest["code_revision"],
            "code_sha256": manifest["code_sha256"],
            "environment_id": manifest["environment_id"],
            "environment_version": manifest["environment_version"],
            "environment_sha256": manifest["environment_sha256"],
            "seed": manifest["seed"],
            "dataset_refs": manifest["dataset_refs"],
            "model_ref": manifest["model_ref"],
        }
        if manifest.get("program_id") is not None:
            material["program_id"] = manifest["program_id"]
        material["binding_sha256"] = _digest(material)
        return material

    @staticmethod
    def _dataset_binding(admission: DatasetAdmission) -> dict:
        return {
            "reference": asdict(admission.reference),
            "content_sha256": admission.content_sha256,
            "license_id": admission.license_id,
            "license_evidence_sha256": admission.license_evidence_sha256,
            "allowed_purpose": admission.allowed_purpose,
            "usage_constraints": list(admission.usage_constraints),
            "provenance_kind": admission.provenance_kind,
            "synthetic_provenance": admission.synthetic_provenance,
            "data_use_authority": asdict(admission.data_use_authority),
            "consent_authority": (
                None if admission.consent_authority is None else asdict(admission.consent_authority)
            ),
            "approval_sha256": admission.approval_sha256,
        }

    @staticmethod
    def _model_binding(admission: ModelAdmission) -> dict:
        return {
            "reference": asdict(admission.reference),
            "artifact_sha256": admission.artifact_sha256,
            "license_id": admission.license_id,
            "license_evidence_sha256": admission.license_evidence_sha256,
            "allowed_purpose": admission.allowed_purpose,
            "usage_constraints": list(admission.usage_constraints),
            "provider_model_identity": admission.provider_model_identity,
            "immutable_provider_revision": admission.immutable_provider_revision,
            "observed_from": admission.observed_from,
            "observed_until": admission.observed_until,
            "reproducibility_limitation": admission.reproducibility_limitation,
            "dataset_lineage_purpose": admission.dataset_lineage_purpose,
            "dataset_lineage": [asdict(item) for item in admission.dataset_lineage],
            "model_lineage": [asdict(item) for item in admission.model_lineage],
            "provenance_kind": admission.provenance_kind,
            "training_receipt_authority": (
                None
                if admission.training_receipt_authority is None
                else asdict(admission.training_receipt_authority)
            ),
            "approval_sha256": admission.approval_sha256,
        }

    def _resolve_binding(
        self,
        tenant: str,
        manifest: Mapping[str, object],
    ) -> tuple[dict, tuple[DatasetAdmission, ...], ModelAdmission | None]:
        try:
            dataset_refs = tuple(ResearchAssetRef(**item) for item in manifest["dataset_refs"])
            model_ref = (
                None if manifest["model_ref"] is None else ResearchAssetRef(**manifest["model_ref"])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResearchRunConflict("run registry references are malformed") from exc
        purpose = str(manifest["purpose"])
        action = str(manifest["action"])
        datasets = tuple(
            self.registry.resolve_dataset(
                tenant,
                reference,
                purpose=purpose,
                action=action,
            )
            for reference in dataset_refs
        )
        model = (
            None
            if model_ref is None
            else self.registry.resolve_model(tenant, model_ref, purpose=purpose)
        )
        material = {
            "datasets": [self._dataset_binding(item) for item in datasets],
            "dataset_boundary_sha256": (
                datasets[0].content_sha256
                if len(datasets) == 1
                else _digest(
                    {
                        "schema": "lightwork.research-dataset-boundary.v1",
                        "content_sha256s": [item.content_sha256 for item in datasets],
                    }
                )
            ),
            "model": None if model is None else self._model_binding(model),
            "purpose": purpose,
            "action": action,
        }
        material["binding_sha256"] = _digest(material)
        return material, datasets, model

    @staticmethod
    def _view(record: Mapping[str, object]) -> dict:
        visible = {key: value for key, value in record.items() if key not in {"_audit_pending"}}
        return json.loads(_canonical(visible))

    def plan(
        self,
        tenant: str,
        principal: str,
        *,
        run_id: str,
        run_version: str,
        experiment_id: str,
        experiment_version: str,
        purpose: str,
        action: str,
        code_revision: str,
        code_sha256: str,
        environment_id: str,
        environment_version: str,
        environment_sha256: str,
        seed: int,
        dataset_refs: Sequence[ResearchAssetRef],
        model_ref: ResearchAssetRef | None,
        resource_caps: ResearchResourceCaps,
        metric_protocol_sha256: str,
        program_id: str | None = None,
    ) -> dict:
        """Create an immutable plan without reading or materializing dataset bytes."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        authority = self._authority(canonical, actor)
        exact_run_id = _identifier(run_id, "run_id")
        exact_action = _purpose(action, "action")
        if exact_action not in _ACTIONS:
            raise ValueError("research action must be analyze or train")
        if isinstance(dataset_refs, str | bytes) or not isinstance(dataset_refs, Sequence):
            raise ValueError("dataset_refs must be a bounded list")
        datasets = tuple(dataset_refs)
        if (
            not 0 < len(datasets) <= 128
            or any(type(item) is not ResearchAssetRef for item in datasets)
            or any(item.kind != "dataset" for item in datasets)
        ):
            raise ValueError("run requires one to 128 exact dataset references")
        dataset_keys = [(item.asset_id, item.version, item.manifest_sha256) for item in datasets]
        if dataset_keys != sorted(set(dataset_keys)):
            raise ValueError("dataset_refs must be unique and sorted")
        if model_ref is not None and (
            type(model_ref) is not ResearchAssetRef or model_ref.kind != "model"
        ):
            raise ValueError("model_ref must be an exact model registry reference")
        if type(resource_caps) is not ResearchResourceCaps:
            raise ValueError("exact research resource caps are required")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**63:
            raise ValueError("seed must be between zero and 2^63 - 1")
        if not isinstance(code_revision, str) or not _REVISION.fullmatch(code_revision):
            raise ValueError("code_revision must be an immutable commit digest")
        with tenant_scope(tenant=canonical):
            for reference in datasets:
                self.registry.inspect(canonical, reference)
            if model_ref is not None:
                self.registry.inspect(canonical, model_ref)
            manifest = {
                "run_id": exact_run_id,
                "run_version": _identifier(run_version, "run_version"),
                "experiment_id": _identifier(experiment_id, "experiment_id"),
                "experiment_version": _identifier(
                    experiment_version,
                    "experiment_version",
                ),
                "purpose": _purpose(purpose),
                "action": exact_action,
                "code_revision": code_revision,
                "code_sha256": _sha(code_sha256, "code_sha256"),
                "environment_id": _identifier(environment_id, "environment_id"),
                "environment_version": _identifier(
                    environment_version,
                    "environment_version",
                ),
                "environment_sha256": _sha(
                    environment_sha256,
                    "environment_sha256",
                ),
                "seed": seed,
                "dataset_refs": [asdict(item) for item in datasets],
                "model_ref": None if model_ref is None else asdict(model_ref),
                "resource_caps": asdict(resource_caps),
                "metric_protocol_sha256": _sha(
                    metric_protocol_sha256,
                    "metric_protocol_sha256",
                ),
            }
            if program_id is not None:
                manifest["program_id"] = _identifier(program_id, "program_id")
            manifest_sha256 = _digest(manifest)
            now = self.store.authoritative_time()
            attempt = {
                "number": 1,
                "status": "planned",
                "version_binding": self._version_binding(manifest),
                "registry_binding": None,
                "worker_authority": None,
                "dispatch_receipt": None,
                "terminal": None,
                "events": [],
                "costs": [],
                "metrics": [],
            }
            attempt["events"].append(
                _event(
                    attempt["events"],
                    state="planned",
                    recorded_at=now,
                    actor=actor,
                    details={"manifest_sha256": manifest_sha256},
                )
            )
            value = {
                "id": self._record_id(canonical, exact_run_id),
                "schema": RUN_SCHEMA,
                "tenant": canonical,
                "run_id": exact_run_id,
                "created_by": actor,
                "submit_authority": asdict(authority),
                "manifest": manifest,
                "manifest_sha256": manifest_sha256,
                "status": "planned",
                "attempts": [attempt],
            }
            prior = self.store.get(value["id"])
            if prior is not None:
                current = self._record(canonical, exact_run_id)
                if (
                    current.get("created_by") == actor
                    and current.get("manifest_sha256") == manifest_sha256
                    and current.get("submit_authority") == asdict(authority)
                ):
                    return self._view(current)
                raise ResearchRunConflict(
                    "run identity already belongs to different immutable material"
                )
            try:
                saved = self.store.create(
                    value,
                    actor=actor,
                    action="research.run.plan",
                    max_records=_MAX_RUNS,
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run was planned concurrently") from exc
            return self._view(saved)

    def _current_submitter(
        self, record: Mapping[str, object], actor: str
    ) -> ResearchRunAuthority:
        authority = self._authority(str(record["tenant"]), actor)
        if record.get("created_by") != actor or record.get("submit_authority") != asdict(authority):
            raise ResearchRunConflict("research submitter authority changed; create a new run plan")
        return authority

    def queue(
        self,
        tenant: str,
        principal: str,
        run_id: str,
        *,
        expected_revision: int,
    ) -> dict:
        """Admit one planned attempt only after exact purpose/action checks."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical):
            current = self._record(canonical, exact_run_id)
            self._current_submitter(current, actor)
            attempt = self._attempt(current)
            if current["status"] != "planned" or attempt["status"] != "planned":
                raise ResearchRunConflict("only a planned attempt can be queued")
            binding, _datasets, _model = self._resolve_binding(
                canonical,
                current["manifest"],
            )
            now = self.store.authoritative_time()

            def mutate(record: dict) -> None:
                selected = self._attempt(record)
                if record.get("status") != "planned" or selected.get("status") != "planned":
                    raise ResearchRunConflict("only a planned attempt can be queued")
                selected["status"] = "queued"
                selected["registry_binding"] = binding
                selected["events"].append(
                    _event(
                        selected["events"],
                        state="queued",
                        recorded_at=now,
                        actor=actor,
                        details={"registry_binding_sha256": binding["binding_sha256"]},
                    )
                )
                record["status"] = "queued"

            try:
                saved = self.store.update(
                    current["id"],
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action="research.run.queue",
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run revision changed") from exc
            if saved is None:
                raise ResearchRunNotFound("research run was not found in this tenant")
            return self._view(saved)

    def _effect_context(
        self,
        tenant: str,
        run_id: str,
        attempt: int,
    ) -> AbstractContextManager[object]:
        run_backend = self.store.backend_kind
        registry_backend = self.registry.store.backend_kind
        if run_backend == "local" and registry_backend == "local":
            return self.effect_fence()
        if self.shared_effect_guard is None:
            raise ResearchMaterializationUnavailable(
                "shared research dispatch requires a deployment-shared "
                "transactional authority and materialization guard"
            )
        return self.shared_effect_guard(tenant, run_id, attempt)

    @staticmethod
    def _dispatch_request(
        record: Mapping[str, object],
        attempt: Mapping[str, object],
        datasets: tuple[DatasetAdmission, ...],
        model: ModelAdmission | None,
    ) -> ResearchDispatchRequest:
        manifest = record["manifest"]
        if not isinstance(manifest, Mapping):
            raise ResearchRunConflict("run manifest is malformed")
        dataset_specs = tuple(
            DatasetMaterializationSpec(
                reference=item.reference,
                source_ref=item.source_ref,
                content_sha256=item.content_sha256,
                license_id=item.license_id,
                license_evidence_sha256=item.license_evidence_sha256,
                usage_constraints=item.usage_constraints,
                data_use_authority_sha256=item.data_use_authority.authority_sha256,
                consent_evidence_sha256=(
                    None
                    if item.consent_authority is None
                    else item.consent_authority.evidence_sha256
                ),
            )
            for item in datasets
        )
        model_spec = (
            None
            if model is None
            else ModelExecutionSpec(
                reference=model.reference,
                source_ref=model.source_ref,
                artifact_sha256=model.artifact_sha256,
                provider_model_identity=model.provider_model_identity,
                immutable_provider_revision=model.immutable_provider_revision,
                observed_from=model.observed_from,
                observed_until=model.observed_until,
                reproducibility_limitation=model.reproducibility_limitation,
            )
        )
        material = {
            "tenant": record["tenant"],
            "run_id": record["run_id"],
            "attempt": attempt["number"],
            "purpose": manifest["purpose"],
            "action": manifest["action"],
            "environment_id": manifest["environment_id"],
            "environment_version": manifest["environment_version"],
            "environment_sha256": manifest["environment_sha256"],
            "datasets": [asdict(item) for item in dataset_specs],
            "model": None if model_spec is None else asdict(model_spec),
            "resource_caps": manifest["resource_caps"],
            "plan": dict(manifest),
        }
        return ResearchDispatchRequest(
            tenant=str(record["tenant"]),
            run_id=str(record["run_id"]),
            attempt=int(attempt["number"]),
            request_sha256=_digest(material),
            purpose=str(manifest["purpose"]),
            action=str(manifest["action"]),
            environment_id=str(manifest["environment_id"]),
            environment_version=str(manifest["environment_version"]),
            environment_sha256=str(manifest["environment_sha256"]),
            datasets=dataset_specs,
            model=model_spec,
            resource_caps=ResearchResourceCaps(**manifest["resource_caps"]),
            plan=dict(manifest),
        )

    @staticmethod
    def _validate_dispatch_receipt(
        receipt: object,
        request: ResearchDispatchRequest,
    ) -> ResearchDispatchReceipt:
        if type(receipt) is not ResearchDispatchReceipt:
            raise ResearchRunInterrupted("research adapter returned no exact dispatch receipt")
        expected_datasets = tuple(item.content_sha256 for item in request.datasets)
        if (
            receipt.tenant != request.tenant
            or receipt.run_id != request.run_id
            or receipt.attempt != request.attempt
            or not hmac.compare_digest(
                receipt.request_sha256,
                request.request_sha256,
            )
            or receipt.materialized_dataset_sha256s != expected_datasets
        ):
            raise ResearchRunInterrupted(
                "research dispatch receipt does not bind the admitted material"
            )
        return receipt

    def _mark_interrupted(
        self,
        tenant: str,
        run_id: str,
        actor: str,
        *,
        reason_code: str,
    ) -> None:
        current = self._record(tenant, run_id)
        attempt = self._attempt(current)
        if current.get("status") != "running" or attempt.get("status") != "running":
            return
        now = self.store.authoritative_time()

        def mutate(record: dict) -> None:
            selected = self._attempt(record)
            if record.get("status") != "running" or selected.get("status") != "running":
                return
            selected["status"] = "interrupted"
            selected["terminal"] = {
                "outcome": "interrupted",
                "reason_code": reason_code,
                "external_effect_reversed": False,
            }
            selected["costs"].append(
                _cost_event(
                    selected["costs"],
                    event_key=f"interrupted.{selected['number']}",
                    cost=ResearchResourceCost(
                        category="compute",
                        basis="unknown",
                        quantity=None,
                        unit=None,
                        amount=None,
                        currency=None,
                        evidence_sha256=_digest(
                            {
                                "tenant": tenant,
                                "run_id": run_id,
                                "attempt": selected["number"],
                                "reason_code": reason_code,
                            }
                        ),
                        source_ref=(
                            f"artifact:research-runs/{run_id}/"
                            f"attempt-{selected['number']}/interruption"
                        ),
                        incomplete_reason=(
                            "Dispatch may have begun; authoritative resource usage "
                            "has not been reconciled."
                        ),
                    ),
                    recorded_at=now,
                    actor=actor,
                    correction_of=None,
                )
            )
            selected["events"].append(
                _event(
                    selected["events"],
                    state="interrupted",
                    recorded_at=now,
                    actor=actor,
                    details={
                        "reason_code": reason_code,
                        "external_effect_reversed": False,
                    },
                )
            )
            record["status"] = "interrupted"

        try:
            self.store.update(
                current["id"],
                mutate,
                expected_revision=current["revision"],
                actor=actor,
                action="research.run.interrupt",
            )
        except Exception:
            # A durable running claim is itself the fail-closed recovery state.
            return

    def start(
        self,
        tenant: str,
        worker: str,
        run_id: str,
        *,
        expected_revision: int,
    ) -> dict:
        """Claim, recheck, materialize, and dispatch exactly once."""

        if self.effect_adapter is None or not callable(
            getattr(self.effect_adapter, "materialize_and_dispatch", None)
        ):
            raise ResearchMaterializationUnavailable(
                "no trusted dataset materialization and dispatch adapter is configured"
            )
        canonical = canonical_tenant_id(tenant)
        actor = _actor(worker, "worker")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical), work_item_scope(f"research:{exact_run_id}"):
            current = self._record(canonical, exact_run_id)
            attempt = self._attempt(current)
            worker_authority = self._worker_authority(canonical, actor)
            if current.get("status") != "queued" or attempt.get("status") != "queued":
                raise ResearchRunConflict(
                    "only a queued attempt can start; interrupted work is never replayed"
                )
            attempt_number = int(attempt["number"])
            try:
                with self._effect_context(canonical, exact_run_id, attempt_number):
                    current = self._record(canonical, exact_run_id)
                    attempt = self._attempt(current)
                    preflight = getattr(self.effect_adapter, "validate_start", None)
                    if callable(preflight):
                        preflight(self, current, actor)
                    binding, datasets, model = self._resolve_binding(
                        canonical,
                        current["manifest"],
                    )
                    stored_binding = attempt.get("registry_binding")
                    if not isinstance(stored_binding, dict) or not hmac.compare_digest(
                        str(stored_binding.get("binding_sha256") or ""),
                        binding["binding_sha256"],
                    ):
                        raise ResearchRunConflict(
                            "registry authority changed after queue; review a new run"
                        )
                    claimed_at = self.store.authoritative_time()

                    def claim(record: dict) -> None:
                        selected = self._attempt(record)
                        if record.get("status") != "queued" or selected.get("status") != "queued":
                            raise ResearchRunConflict("research attempt was already claimed")
                        selected["status"] = "running"
                        selected["worker_authority"] = asdict(worker_authority)
                        selected["events"].append(
                            _event(
                                selected["events"],
                                state="running",
                                recorded_at=claimed_at,
                                actor=actor,
                                details={"registry_binding_sha256": binding["binding_sha256"]},
                            )
                        )
                        record["status"] = "running"

                    try:
                        claimed = self.store.update(
                            current["id"],
                            claim,
                            expected_revision=expected_revision,
                            actor=actor,
                            action="research.run.claim",
                        )
                    except RecordConflict as exc:
                        raise ResearchRunConflict(
                            "research run revision changed before claim"
                        ) from exc
                    if claimed is None:
                        raise ResearchRunNotFound("research run was not found in this tenant")
                    # Re-resolve after the durable claim and immediately before
                    # the adapter's first read/materialization/effect.
                    fresh_binding, datasets, model = self._resolve_binding(
                        canonical,
                        claimed["manifest"],
                    )
                    if not hmac.compare_digest(
                        binding["binding_sha256"],
                        fresh_binding["binding_sha256"],
                    ):
                        raise ResearchRunConflict(
                            "registry authority changed before materialization"
                        )
                    request = self._dispatch_request(
                        claimed,
                        self._attempt(claimed),
                        datasets,
                        model,
                    )
                    receipt = self._validate_dispatch_receipt(
                        self.effect_adapter.materialize_and_dispatch(request),
                        request,
                    )
                    dispatched_at = self.store.authoritative_time()
                    dispatched_source = self._record(canonical, exact_run_id)
                    if (dispatched_source["manifest_sha256"] != claimed["manifest_sha256"] or
                            self._attempt(dispatched_source).get("worker_authority") != asdict(worker_authority)):
                        raise ResearchRunConflict("research source changed during execution")

                    def record_dispatch(record: dict) -> None:
                        selected = self._attempt(record)
                        if record.get("status") != "running" or selected.get("status") != "running":
                            raise ResearchRunConflict("research attempt is no longer running")
                        if selected.get("dispatch_receipt") is not None:
                            raise ResearchRunConflict("research dispatch receipt already exists")
                        selected["dispatch_receipt"] = asdict(receipt)
                        selected["events"].append(
                            _event(
                                selected["events"],
                                state="dispatched",
                                recorded_at=dispatched_at,
                                actor=actor,
                                details={
                                    "request_sha256": request.request_sha256,
                                    "dispatch_id": receipt.dispatch_id,
                                    "adapter_authority_sha256": (receipt.adapter_authority_sha256),
                                },
                            )
                        )

                    saved = self.store.update(
                        claimed["id"],
                        record_dispatch,
                        expected_revision=dispatched_source["revision"],
                        actor=actor,
                        action="research.run.dispatch",
                    )
                    if saved is None:
                        raise ResearchRunInterrupted("research run disappeared after dispatch")
                    finish = getattr(self.effect_adapter, "finish", None)
                    return finish(self, saved, actor) if callable(finish) else self._view(saved)
            except (KeyboardInterrupt, SystemExit):
                raise
            except ResearchMaterializationUnavailable:
                raise
            except (ResearchRunConflict, PermissionError):
                # Rights or worker drift before the adapter call is a review
                # conflict. If a durable running claim exists, preserve it as
                # interrupted because process state may already be uncertain.
                self._mark_interrupted(
                    canonical,
                    exact_run_id,
                    actor,
                    reason_code="authority_changed_during_dispatch",
                )
                raise
            except Exception as exc:
                self._mark_interrupted(
                    canonical,
                    exact_run_id,
                    actor,
                    reason_code="dispatch_outcome_uncertain",
                )
                raise ResearchRunInterrupted(
                    "research dispatch outcome is uncertain; automatic retry is blocked"
                ) from exc

    @staticmethod
    def _result_material(
        *,
        outcome: str,
        result_idempotency_key: str,
        costs: tuple[ResearchResourceCost, ...],
        metrics: tuple[ResearchMetric, ...],
        failure_code: str | None,
        failure_evidence_sha256: str | None,
        output_artifact_sha256: str | None,
        training_receipt_id: str | None,
        training_receipt_sha256: str | None,
    ) -> dict:
        material = {
            "outcome": outcome,
            "result_idempotency_key": result_idempotency_key,
            "costs": [asdict(item) for item in costs],
            "metrics": [asdict(item) for item in metrics],
            "failure_code": failure_code,
            "failure_evidence_sha256": failure_evidence_sha256,
            "output_artifact_sha256": output_artifact_sha256,
            "training_receipt_id": training_receipt_id,
            "training_receipt_sha256": training_receipt_sha256,
        }
        material["result_sha256"] = _digest(material)
        return material

    def _validate_training_result(
        self,
        record: Mapping[str, object],
        result: Mapping[str, object],
    ) -> TrainingReceiptAuthority | None:
        manifest = record["manifest"]
        if not isinstance(manifest, Mapping):
            raise ResearchRunConflict("run manifest is malformed")
        values = (
            result.get("training_receipt_id"),
            result.get("training_receipt_sha256"),
        )
        if manifest.get("action") != "train" or result.get("outcome") != "completed":
            if any(value is not None for value in values):
                raise ValueError("only a completed training attempt can carry a training receipt")
            return None
        if any(value is None for value in values):
            raise ValueError("completed training requires an exact signed training receipt")
        artifact_sha256 = _sha(
            result.get("output_artifact_sha256"),
            "output_artifact_sha256",
        )
        authority = self.registry.resolve_training_receipt(
            str(record["tenant"]),
            str(values[0]),
            str(values[1]),
        )
        binding = self._attempt(record).get("registry_binding")
        if not isinstance(binding, Mapping):
            raise ResearchRunConflict("run registry binding is unavailable")
        dataset_boundary_sha256 = binding.get("dataset_boundary_sha256")
        model = binding.get("model")
        expected_base = None if not isinstance(model, Mapping) else model.get("artifact_sha256")
        if (
            authority.run_id != record["run_id"]
            or authority.dataset_sha256 != dataset_boundary_sha256
            or authority.environment_id != manifest["environment_id"]
            or authority.environment_version != manifest["environment_version"]
            or authority.environment_sha256 != manifest["environment_sha256"]
            or authority.training_source_revision != manifest["code_revision"]
            or authority.deterministic_seed != manifest["seed"]
            or authority.output_artifact_sha256 != artifact_sha256
            or (expected_base is not None and authority.base_model_artifact_sha256 != expected_base)
        ):
            raise ResearchRunConflict(
                "signed training receipt does not bind this run, input, environment, and output"
            )
        return authority

    def finish(  # noqa: C901 - validation remains linear and auditable
        self,
        tenant: str,
        worker: str,
        run_id: str,
        *,
        expected_revision: int,
        outcome: str,
        result_idempotency_key: str,
        costs: Sequence[ResearchResourceCost],
        metrics: Sequence[ResearchMetric] = (),
        failure_code: str | None = None,
        failure_evidence_sha256: str | None = None,
        output_artifact_sha256: str | None = None,
        training_receipt_id: str | None = None,
        training_receipt_sha256: str | None = None,
    ) -> dict:
        """Append one terminal result; failed-attempt costs are never discarded."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(worker, "worker")
        exact_run_id = _identifier(run_id, "run_id")
        terminal = _purpose(outcome, "outcome")
        if terminal not in _TERMINAL:
            raise ValueError("attempt outcome is unsupported")
        event_key = _identifier(
            result_idempotency_key,
            "result_idempotency_key",
        )
        if isinstance(costs, str | bytes) or not isinstance(costs, Sequence):
            raise ValueError("costs must be a bounded list")
        exact_costs = tuple(costs)
        if not 1 <= len(exact_costs) <= 64 or any(
            type(item) is not ResearchResourceCost for item in exact_costs
        ):
            raise ValueError("one to 64 exact resource costs are required")
        if isinstance(metrics, str | bytes) or not isinstance(metrics, Sequence):
            raise ValueError("metrics must be a bounded list")
        exact_metrics = tuple(metrics)
        if len(exact_metrics) > _MAX_METRICS or any(
            type(item) is not ResearchMetric for item in exact_metrics
        ):
            raise ValueError("metrics contain invalid research observations")
        metric_keys = [
            (
                item.name,
                item.evaluator_id,
                item.evaluator_version,
                item.source_artifact_sha256,
            )
            for item in exact_metrics
        ]
        if metric_keys != sorted(set(metric_keys)):
            raise ValueError("metrics must be unique and sorted")
        if terminal == "completed":
            if failure_code is not None or failure_evidence_sha256 is not None:
                raise ValueError("completed attempts cannot carry failure evidence")
        else:
            failure_code = _purpose(failure_code, "failure_code")
            failure_evidence_sha256 = _sha(
                failure_evidence_sha256,
                "failure_evidence_sha256",
            )
        if output_artifact_sha256 is not None:
            output_artifact_sha256 = _sha(
                output_artifact_sha256,
                "output_artifact_sha256",
            )
        result = self._result_material(
            outcome=terminal,
            result_idempotency_key=event_key,
            costs=exact_costs,
            metrics=exact_metrics,
            failure_code=failure_code,
            failure_evidence_sha256=failure_evidence_sha256,
            output_artifact_sha256=output_artifact_sha256,
            training_receipt_id=training_receipt_id,
            training_receipt_sha256=training_receipt_sha256,
        )
        with tenant_scope(tenant=canonical):
            current = self._record(canonical, exact_run_id)
            attempt = self._attempt(current)
            worker_authority = self._worker_authority(canonical, actor)
            prior_terminal = attempt.get("terminal")
            if prior_terminal is not None:
                if (
                    isinstance(prior_terminal, Mapping)
                    and prior_terminal.get("result_idempotency_key") == event_key
                    and prior_terminal.get("result_sha256") == result["result_sha256"]
                ):
                    return self._view(current)
                raise ResearchRunConflict("attempt already has a different terminal result")
            if current.get("status") != "running" or attempt.get("status") != "running":
                raise ResearchRunConflict("only a running attempt can finish")
            if attempt.get("dispatch_receipt") is None:
                raise ResearchRunConflict("running attempt has no durable dispatch receipt")
            if attempt.get("worker_authority") != asdict(worker_authority):
                raise ResearchRunConflict(
                    "research worker authority changed before result recording"
                )
            receipt_authority = self._validate_training_result(current, result)
            if receipt_authority is not None:
                result["training_receipt_authority"] = asdict(receipt_authority)
            now = self.store.authoritative_time()

            def mutate(record: dict) -> None:
                selected = self._attempt(record)
                if record.get("status") != "running" or selected.get("status") != "running":
                    raise ResearchRunConflict("attempt is no longer running")
                if selected.get("terminal") is not None:
                    raise ResearchRunConflict("attempt already has a terminal result")
                for index, cost in enumerate(exact_costs, start=1):
                    selected["costs"].append(
                        _cost_event(
                            selected["costs"],
                            event_key=f"finish.{event_key}.{index}",
                            cost=cost,
                            recorded_at=now,
                            actor=actor,
                            correction_of=None,
                        )
                    )
                selected["metrics"] = [asdict(item) for item in exact_metrics]
                selected["terminal"] = result
                selected["status"] = terminal
                selected["events"].append(
                    _event(
                        selected["events"],
                        state=terminal,
                        recorded_at=now,
                        actor=actor,
                        details={
                            "result_sha256": result["result_sha256"],
                            "cost_event_count": len(exact_costs),
                            "metric_count": len(exact_metrics),
                            "external_effect_reversed": False,
                        },
                    )
                )
                record["status"] = terminal

            try:
                saved = self.store.update(
                    current["id"],
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action=f"research.run.{terminal}",
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run revision changed") from exc
            if saved is None:
                raise ResearchRunNotFound("research run was not found in this tenant")
            return self._view(saved)

    def retry(
        self,
        tenant: str,
        principal: str,
        run_id: str,
        *,
        expected_revision: int,
    ) -> dict:
        """Append a new planned attempt only after a known failed result."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical):
            current = self._record(canonical, exact_run_id)
            self._current_submitter(current, actor)
            previous = self._attempt(current)
            if current.get("status") != "failed" or previous.get("status") != "failed":
                raise ResearchRunConflict(
                    "only a known failed attempt can be retried; interrupted work needs reconciliation"
                )
            if len(current["attempts"]) >= _MAX_ATTEMPTS:
                raise ResearchRunConflict("run reached its bounded attempt limit")
            now = self.store.authoritative_time()
            number = len(current["attempts"]) + 1

            def mutate(record: dict) -> None:
                prior = self._attempt(record)
                if record.get("status") != "failed" or prior.get("status") != "failed":
                    raise ResearchRunConflict("run is no longer retryable")
                attempt = {
                    "number": number,
                    "status": "planned",
                    "version_binding": self._version_binding(record["manifest"]),
                    "registry_binding": None,
                    "worker_authority": None,
                    "dispatch_receipt": None,
                    "terminal": None,
                    "events": [],
                    "costs": [],
                    "metrics": [],
                }
                attempt["events"].append(
                    _event(
                        attempt["events"],
                        state="planned",
                        recorded_at=now,
                        actor=actor,
                        details={
                            "retry_of_attempt": prior["number"],
                            "prior_result_sha256": prior["terminal"]["result_sha256"],
                        },
                    )
                )
                record["attempts"].append(attempt)
                record["status"] = "planned"

            try:
                saved = self.store.update(
                    current["id"],
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action="research.run.retry",
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run revision changed") from exc
            if saved is None:
                raise ResearchRunNotFound("research run was not found in this tenant")
            return self._view(saved)

    def approve_execution(self, tenant, principal, run_id, *, expected_revision, review_sha256, review):
        """Retain an independent exact execution review in the existing attempt."""
        canonical, actor = canonical_tenant_id(tenant), _actor(principal, "reviewer")
        _sha(review_sha256, "execution review")
        with tenant_scope(tenant=canonical), self.effect_fence():
            current = self._record(canonical, run_id)
            if current["created_by"] == actor or current["status"] != "queued":
                raise ResearchRunConflict("A different administrator must review a waiting run")
            binding = review(current, actor)
            if not isinstance(binding, dict) or _digest(binding) != review_sha256:
                raise ResearchRunConflict("The complete review changed. Read it again")
            authority = self._worker_authority(canonical, actor)
            approval = {"review_sha256": review_sha256, "binding": binding,
                        "reviewer": actor, "authority": asdict(authority),
                        "expires_at": self.store.authoritative_time()+900}
            def mutate(record):
                if record["status"] != "queued" or record["manifest_sha256"] != current["manifest_sha256"]:
                    raise ResearchRunConflict("The waiting run changed")
                self._attempt(record)["execution_approval"] = approval
                self._attempt(record)["events"].append(_event(self._attempt(record)["events"],
                    state="queued", recorded_at=self.store.authoritative_time(), actor=actor,
                    details={"execution_review_sha256": review_sha256}))
                if review(record, actor) != binding or self._worker_authority(canonical, actor) != authority:
                    raise ResearchRunConflict("Execution review authority changed")
            saved = self.store.update(current["id"], mutate, expected_revision=expected_revision,
                actor=actor, action="research.run.approve_execution")
            return self._view(saved)

    def execution_observation(self, tenant, actor, run_id, evidence):
        """Trusted controller facts only; no synthetic completion or new ledger."""
        current = self._record(tenant, run_id)
        if self._attempt(current).get("worker_authority", {}).get("principal") != actor:
            raise ResearchRunConflict("This execution belongs to another owner")
        def mutate(record):
            selected = self._attempt(record)
            if record["status"] != "running":
                raise ResearchRunConflict("This execution is no longer active")
            selected["execution"] = dict(evidence)
            selected["events"].append(_event(selected["events"], state="running",
                recorded_at=self.store.authoritative_time(), actor=actor,
                details={"execution_state": evidence["state"], "execution_sha256": _digest(evidence)}))
        return self.store.update(current["id"], mutate, expected_revision=current["revision"],
            actor=actor, action="research.run.execution_observation")

    def stop_execution(self, tenant, principal, run_id, *, expected_revision):
        """Request bounded cleanup; the actual execution owner alone may stop it."""
        canonical, actor = canonical_tenant_id(tenant), _actor(principal, "execution owner")
        with tenant_scope(tenant=canonical):
            current = self._record(canonical, run_id)
            authority = self._worker_authority(canonical, actor)
            if current["status"] != "running" or self._attempt(current).get("worker_authority") != asdict(authority):
                raise ResearchRunConflict("Only the current execution owner can stop this running attempt")
            def mutate(record):
                if record["status"] != "running" or self._worker_authority(canonical, actor) != authority:
                    raise ResearchRunConflict("The execution changed before Stop")
                self._attempt(record)["stop_requested"] = True
                self._attempt(record)["events"].append(_event(self._attempt(record)["events"],
                    state="running", recorded_at=self.store.authoritative_time(), actor=actor,
                    details={"stop_requested": True, "cleanup_confirmed": False}))
            return self._view(self.store.update(current["id"], mutate, expected_revision=expected_revision,
                actor=actor, action="research.run.request_stop"))

    def cancel(
        self,
        tenant: str,
        principal: str,
        run_id: str,
        *,
        expected_revision: int,
        reason_code: str,
        evidence_sha256: str,
    ) -> dict:
        """Cancel a plan or queue before dispatch; no reversal claim is made."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        reason = _purpose(reason_code, "reason_code")
        evidence = _sha(evidence_sha256, "evidence_sha256")
        with tenant_scope(tenant=canonical), self.effect_fence():
            current = self._record(canonical, exact_run_id)
            self._current_submitter(current, actor)
            attempt = self._attempt(current)
            if current.get("status") not in {"planned", "queued"} or attempt.get("status") not in {
                "planned",
                "queued",
            }:
                raise ResearchRunConflict("only a pre-dispatch attempt can be cancelled safely")
            now = self.store.authoritative_time()

            def mutate(record: dict) -> None:
                selected = self._attempt(record)
                if record.get("status") not in {"planned", "queued"}:
                    raise ResearchRunConflict("run is no longer cancellable")
                selected["status"] = "cancelled"
                selected["terminal"] = {
                    "outcome": "cancelled",
                    "reason_code": reason,
                    "evidence_sha256": evidence,
                    "external_effect_reversed": False,
                }
                selected["events"].append(
                    _event(
                        selected["events"],
                        state="cancelled",
                        recorded_at=now,
                        actor=actor,
                        details={
                            "reason_code": reason,
                            "evidence_sha256": evidence,
                            "external_effect_reversed": False,
                        },
                    )
                )
                record["status"] = "cancelled"

            try:
                saved = self.store.update(
                    current["id"],
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action="research.run.cancel",
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run revision changed") from exc
            if saved is None:
                raise ResearchRunNotFound("research run was not found in this tenant")
            return self._view(saved)

    def correct_cost(
        self,
        tenant: str,
        principal: str,
        run_id: str,
        *,
        expected_revision: int,
        attempt_number: int,
        correction_key: str,
        correction_of: str,
        replacement: ResearchResourceCost,
    ) -> dict:
        """Append a correction event while retaining the original cost evidence."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        key = _identifier(correction_key, "correction_key")
        _sha(correction_of, "correction_of")
        if type(replacement) is not ResearchResourceCost:
            raise ValueError("an exact replacement resource cost is required")
        if (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or not 1 <= attempt_number <= _MAX_ATTEMPTS
        ):
            raise ValueError("attempt_number is outside its bounded range")
        with tenant_scope(tenant=canonical):
            current = self._record(canonical, exact_run_id)
            self._current_submitter(current, actor)
            if attempt_number > len(current["attempts"]):
                raise ResearchRunNotFound("research attempt was not found")
            attempt = current["attempts"][attempt_number - 1]
            costs = attempt["costs"]
            request_sha256 = _digest(
                {
                    "correction_key": key,
                    "correction_of": correction_of,
                    "replacement": asdict(replacement),
                }
            )
            for event in costs:
                if event.get("event_key") == key:
                    if event.get("request_sha256") == request_sha256:
                        return self._view(current)
                    raise ResearchRunConflict("cost correction key belongs to different material")
            originals = {
                event.get("event_sha256"): event for event in costs if isinstance(event, dict)
            }
            if correction_of not in originals:
                raise ResearchRunNotFound("cost event to correct was not found")
            if any(event.get("correction_of") == correction_of for event in costs):
                raise ResearchRunConflict(
                    "cost event was already corrected; correct the latest event"
                )
            now = self.store.authoritative_time()

            def mutate(record: dict) -> None:
                selected = record["attempts"][attempt_number - 1]
                event = _cost_event(
                    selected["costs"],
                    event_key=key,
                    cost=replacement,
                    recorded_at=now,
                    actor=actor,
                    correction_of=correction_of,
                )
                event["request_sha256"] = request_sha256
                # The request digest is part of the immutable event itself.
                event["event_sha256"] = _digest(
                    {field: value for field, value in event.items() if field != "event_sha256"}
                )
                selected["costs"].append(event)

            try:
                saved = self.store.update(
                    current["id"],
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action="research.run.cost.correct",
                )
            except RecordConflict as exc:
                raise ResearchRunConflict("research run revision changed") from exc
            if saved is None:
                raise ResearchRunNotFound("research run was not found in this tenant")
            return self._view(saved)

    @staticmethod
    def _cost_summary(attempts: Sequence[Mapping[str, object]]) -> dict:
        totals: dict[str, Decimal] = {}
        incomplete = False
        active_events: list[Mapping[str, object]] = []
        for attempt in attempts:
            costs = attempt.get("costs", ())
            if not isinstance(costs, Sequence):
                raise ResearchRunConflict("attempt cost history is malformed")
            if attempt.get("status") == "running":
                incomplete = True
            superseded = {
                event.get("correction_of")
                for event in costs
                if isinstance(event, Mapping) and event.get("correction_of")
            }
            active_events.extend(
                event
                for event in costs
                if isinstance(event, Mapping) and event.get("event_sha256") not in superseded
            )
        for event in active_events:
            cost = event.get("cost")
            if not isinstance(cost, Mapping):
                raise ResearchRunConflict("attempt cost event is malformed")
            amount = cost.get("amount")
            currency = cost.get("currency")
            if amount is None:
                incomplete = True
                continue
            if not isinstance(currency, str):
                raise ResearchRunConflict("attempt cost currency is malformed")
            totals[currency] = totals.get(currency, Decimal(0)) + Decimal(str(amount))
        return {
            "effective_amounts": {
                currency: format(amount, "f") for currency, amount in sorted(totals.items())
            },
            "incomplete": incomplete,
            "effective_event_count": len(active_events),
        }

    def inspect(self, tenant: str, principal: str, run_id: str) -> dict:
        """Inspect retained history without reusing or exporting source material."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical):
            record = self._record(canonical, exact_run_id)
            self._authority(canonical, actor)
            if record.get("created_by") != actor and not self._can_review(canonical, actor):
                raise ResearchRunNotFound("research run was not found in this tenant")
            result = self._view(record)
            result["cost_summary"] = self._cost_summary(record["attempts"])
            self._authority(canonical, actor)
            if record.get("created_by") != actor and not self._can_review(canonical, actor):
                raise PermissionError("current research reviewer authority changed")
            return result

    def list(
        self,
        tenant: str,
        principal: str,
        *,
        limit: int = 100,
    ) -> list[dict]:
        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
        with tenant_scope(tenant=canonical):
            self._authority(canonical, actor)
            reviewer = self._can_review(canonical, actor)
            # The store is tenant-scoped but contains runs from multiple named
            # researchers. Scan the bounded namespace before applying the
            # creator filter so another researcher's newer rows cannot hide the
            # caller's records from a smaller page.
            rows = self.store.list(limit=_MAX_RUNS)
            result = []
            for row in rows:
                if row.get("tenant") != canonical or (row.get("created_by") != actor and not reviewer):
                    continue
                record = self._record(canonical, str(row["run_id"]))
                view = self._view(record)
                view["cost_summary"] = self._cost_summary(record["attempts"])
                result.append(view)
                if len(result) >= limit:
                    break
            self._authority(canonical, actor)
            if reviewer and not self._can_review(canonical, actor):
                raise PermissionError("current research reviewer authority changed")
            return result

    def export(
        self,
        tenant: str,
        principal: str,
        run_id: str,
    ) -> bytes:
        """Return deterministic, raw-data-free metadata after current rights checks."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical):
            record = self._record(canonical, exact_run_id)
            if record.get("created_by") == actor:
                self._current_submitter(record, actor)
            elif not self._can_review(canonical, actor):
                raise ResearchRunNotFound("research run was not found in this tenant")
            latest = self._attempt(record)
            stored = latest.get("registry_binding")
            current, _datasets, _model = self._resolve_binding(
                canonical,
                record["manifest"],
            )
            if not isinstance(stored, Mapping) or not hmac.compare_digest(
                str(stored.get("binding_sha256") or ""),
                current["binding_sha256"],
            ):
                raise ResearchRunConflict(
                    "current rights do not match the admitted run; export is blocked"
                )
            payload = {
                "schema": RUN_EXPORT_SCHEMA,
                "run": self._view(record),
                "cost_summary": self._cost_summary(record["attempts"]),
                "data_statement": {
                    "contains_raw_customer_data": False,
                    "contains_dataset_source_locations": False,
                    "raw_deletion_claims_weight_influence_removed": False,
                    "raw_input_reconstruction": (
                        "excluded; use separately permitted redacted or synthetic sources"
                    ),
                },
            }
            self._authority(canonical, actor)
            if record.get("created_by") != actor and not self._can_review(canonical, actor):
                raise PermissionError("current research reviewer authority changed")
            return _canonical(payload)

    def admit_promotion(
        self,
        tenant: str,
        principal: str,
        run_id: str,
        *,
        trusted_study_resolver: Callable[[ResearchStudyContext], object] | None = None,
    ) -> dict:
        """Recheck current lineage and resolve a server-owned canonical study."""

        canonical = canonical_tenant_id(tenant)
        actor = _actor(principal, "principal")
        exact_run_id = _identifier(run_id, "run_id")
        with tenant_scope(tenant=canonical), self.effect_fence():
            record = self._record(canonical, exact_run_id)
            authority = self._current_submitter(record, actor)
            if record.get("status") != "completed":
                raise ResearchRunConflict("only a completed run can be promoted")
            binding, datasets, model = self._resolve_binding(
                canonical,
                record["manifest"],
            )
            stored = self._attempt(record).get("registry_binding")
            if (
                not isinstance(stored, Mapping)
                or stored.get("binding_sha256") != binding["binding_sha256"]
            ):
                raise ResearchRunConflict(
                    "registry authority changed; artifact promotion is blocked"
                )
            lineage: dict[tuple[str, str, str], dict] = {}
            remediation = (
                "retrain" if record["manifest"].get("action") == "train" else "reevaluate"
            )

            def retain(reference) -> None:
                material = asdict(reference)
                key = (
                    str(material["kind"]),
                    str(material["asset_id"]),
                    str(material["version"]),
                )
                lineage[key] = {
                    "kind": key[0],
                    "asset_id": key[1],
                    "version": key[2],
                    "manifest_sha256": material["manifest_sha256"],
                    "required_action_if_revoked": remediation,
                }

            for dataset in datasets:
                retain(dataset.reference)
            if model is not None:
                retain(model.reference)
                for reference in (*model.dataset_lineage, *model.model_lineage):
                    retain(reference)
            terminal = self._attempt(record).get("terminal")
            if not isinstance(terminal, Mapping):
                raise ResearchRunConflict("completed run result is unavailable")
            worker_authority = self._attempt(record).get("worker_authority")
            if not isinstance(worker_authority, Mapping):
                raise ResearchRunConflict("completed run worker authority is unavailable")
            candidate_principal = _actor(
                worker_authority.get("principal"), "candidate principal"
            )
            try:
                metrics = tuple(
                    ResearchMetric(**item) for item in terminal.get("metrics", ())
                )
                context = ResearchStudyContext(
                    tenant=canonical,
                    run_id=exact_run_id,
                    candidate_principal=candidate_principal,
                    run_manifest_sha256=str(record["manifest_sha256"]),
                    result_sha256=str(terminal.get("result_sha256") or ""),
                    output_artifact_sha256=str(
                        terminal.get("output_artifact_sha256") or ""
                    ),
                    metric_protocol_sha256=str(
                        record["manifest"].get("metric_protocol_sha256") or ""
                    ),
                    metrics=metrics,
                )
            except (TypeError, ValueError) as exc:
                raise ResearchRunConflict(
                    "completed run study context is malformed"
                ) from exc
            resolver = (
                trusted_study_resolver
                if trusted_study_resolver is not None
                else self.promotion_study_resolver
            )
            if not callable(resolver):
                raise ResearchRunConflict(
                    "trusted completed-run study admission is unavailable"
                )
            try:
                study_admission = resolver(context)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise ResearchRunConflict(
                    "trusted completed-run study admission is unavailable"
                ) from exc
            from .candidate_promotion import TrustedStudyAdmission

            if (
                type(study_admission) is not TrustedStudyAdmission
                or study_admission.tenant != context.tenant
                or study_admission.run_id != context.run_id
                or not hmac.compare_digest(
                    study_admission.run_manifest_sha256,
                    context.run_manifest_sha256,
                )
                or not hmac.compare_digest(
                    study_admission.result_sha256, context.result_sha256
                )
                or not hmac.compare_digest(
                    study_admission.output_artifact_sha256,
                    context.output_artifact_sha256,
                )
                or not hmac.compare_digest(
                    study_admission.study.metric_protocol_sha256,
                    context.metric_protocol_sha256,
                )
            ):
                raise ResearchRunConflict(
                    "trusted study admission is not bound to the completed run"
                )
            return {
                "tenant": canonical,
                "principal": actor,
                "candidate_principal": candidate_principal,
                "run_id": exact_run_id,
                "run_manifest_sha256": record["manifest_sha256"],
                # Retain the old name for callers shipped before the full
                # candidate-promotion contract was introduced.
                "manifest_sha256": record["manifest_sha256"],
                "registry_binding_sha256": binding["binding_sha256"],
                "result_sha256": terminal.get("result_sha256"),
                "output_artifact_sha256": terminal.get("output_artifact_sha256"),
                "lineage": [lineage[key] for key in sorted(lineage)],
                "authority_sha256": authority.authorization_sha256,
                "study_context_sha256": context.sha256,
                "study_admission": asdict(study_admission),
            }


__all__ = [
    "DISPATCH_RECEIPT_SCHEMA",
    "DISPATCH_REQUEST_SCHEMA",
    "DatasetMaterializationSpec",
    "METRIC_SCHEMA",
    "ModelExecutionSpec",
    "RESOURCE_CAPS_SCHEMA",
    "RESOURCE_COST_SCHEMA",
    "RUN_AUTHORITY_SCHEMA",
    "RUN_EXPORT_SCHEMA",
    "RUN_SCHEMA",
    "STUDY_CONTEXT_SCHEMA",
    "ResearchDispatchReceipt",
    "ResearchDispatchRequest",
    "ResearchEffectAdapter",
    "ResearchMaterializationUnavailable",
    "ResearchMetric",
    "ResearchResourceCaps",
    "ResearchResourceCost",
    "ResearchRunAuthority",
    "ResearchRunConflict",
    "ResearchRunError",
    "ResearchRunInterrupted",
    "ResearchRunNotFound",
    "ResearchRuns",
    "ResearchStudyContext",
    "ResearchWorkerAuthority",
    "WORKER_AUTHORITY_SCHEMA",
]
