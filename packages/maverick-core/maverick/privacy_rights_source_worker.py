"""Bounded production worker for privacy-rights provider source adapters.

The orchestration store deliberately retains no raw subject or credential
values.  This worker therefore resolves both through deployment-owned,
request-scoped authorities, verifies the subject HMAC against the exact case,
and passes them transiently to a closed provider adapter.  Provider success is
committed with evidence atomically; uncertain mutations are parked in the
orchestration authority's ``ambiguous`` state and are never lease-replayed.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from . import privacy_rights_orchestration as rights

_DIGEST = frozenset("0123456789abcdef")
_SAFE_REF = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
)
_MAX_SECRET_BYTES = 16 * 1024
_MAX_SUBJECT_BYTES = 4 * 1024
_MUTATING_PHASES = frozenset({"delete", "rectify", "restrict", "opt_out"})


class PrivacyRightsSourceWorkerError(RuntimeError):
    """Base worker error."""


class PrivacyRightsSourceWorkerConfigError(PrivacyRightsSourceWorkerError):
    """A deployment-owned authority or binding is absent or inconsistent."""


class PrivacyRightsSourceWorkerProtocolError(PrivacyRightsSourceWorkerError):
    """A provider adapter returned an invalid or over-broad result."""


class ProviderRetryableError(PrivacyRightsSourceWorkerError):
    """A provider read or definitively unsent mutation may be retried."""

    def __init__(self, error_code: str = "provider_temporarily_unavailable") -> None:
        super().__init__(error_code)
        self.error_code = _error_code(error_code)


class ProviderPermanentError(PrivacyRightsSourceWorkerError):
    """A definitive provider or contract refusal should dead-letter work."""

    def __init__(self, error_code: str = "provider_request_rejected") -> None:
        super().__init__(error_code)
        self.error_code = _error_code(error_code)


class ProviderAmbiguousOutcome(PrivacyRightsSourceWorkerError):
    """A mutation may have applied and requires an exact provider probe."""

    def __init__(
        self,
        *,
        operation_sha256: str,
        operation_ref: str,
        error_code: str = "provider_outcome_unknown",
    ) -> None:
        super().__init__(error_code)
        self.operation_sha256 = _digest(operation_sha256, "operation_sha256")
        self.operation_ref = _reference(operation_ref, "operation_ref")
        self.error_code = _error_code(error_code)


def _reference(value: object, label: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str):
        raise PrivacyRightsSourceWorkerProtocolError(f"{label} is invalid")
    selected = unicodedata.normalize("NFC", value).strip()
    if (
        not 1 <= len(selected) <= maximum
        or selected[0] not in _SAFE_REF
        or any(character not in _SAFE_REF for character in selected)
    ):
        raise PrivacyRightsSourceWorkerProtocolError(f"{label} is invalid")
    return selected


def _error_code(value: object) -> str:
    selected = _reference(value, "error_code", maximum=48)
    if not selected[0].islower() or any(
        not (character.islower() or character.isdigit() or character == "_")
        for character in selected
    ):
        raise PrivacyRightsSourceWorkerProtocolError("error_code is invalid")
    return selected


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _DIGEST for character in value)
    ):
        raise PrivacyRightsSourceWorkerProtocolError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyRightsSourceWorkerProtocolError(f"{label} is invalid")
    return value


def _default_subject_digest(tenant_id: str, subject_reference: str) -> str:
    from .secret_provider import get_secret

    raw_key = get_secret("MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY")
    if raw_key is None or len(raw_key.encode("utf-8")) < 32:
        raise PrivacyRightsSourceWorkerConfigError(
            "privacy-rights subject digest authority is unavailable"
        )
    tenant = unicodedata.normalize("NFC", tenant_id).strip()
    subject = unicodedata.normalize("NFC", subject_reference).strip().encode("utf-8")
    if not subject or len(subject) > _MAX_SUBJECT_BYTES:
        raise PrivacyRightsSourceWorkerConfigError(
            "privacy-rights subject binding is unavailable"
        )
    material = (
        tenant.encode("utf-8")
        + b"\x00subject_reference\x00"
        + subject
    )
    return hmac.new(raw_key.encode("utf-8"), material, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SubjectBinding:
    tenant_id: str
    case_id: str
    subject_reference: str
    authority_sha256: str
    expires_at: float


@dataclass(frozen=True)
class ProviderOutcome:
    status: str
    record_count: int
    acknowledgement_sha256: str
    acknowledgement_ref: str
    provider_evidence_sha256: str
    opaque_ref: str
    external_side_effect: bool
    raw_data_returned: bool = False
    live_provider_acceptance_verified: bool = False


@dataclass(frozen=True)
class PreparedProviderMutation:
    """Read-only mutation preparation bound to one immutable provider target."""

    status: str
    target_ref: str | None
    target_binding_sha256: str | None
    acknowledgement_sha256: str
    acknowledgement_ref: str
    provider_evidence_sha256: str
    opaque_ref: str
    record_count: int
    provider_retention_state: str


@dataclass(frozen=True)
class ProviderReconciliationOutcome:
    disposition: str
    provider_evidence_sha256: str
    provider_evidence_ref: str
    record_count: int
    external_side_effect: bool = False
    optimistic_replay_performed: bool = False
    provider_retention_state: str = "unknown"


@dataclass(frozen=True)
class AdapterBinding:
    tenant_id: str
    source_id: str
    adapter_ref: str
    credential_ref: str
    capabilities: tuple[str, ...]
    authority_sha256: str
    adapter: PrivacyRightsProviderAdapter
    provider_contract: str | None = None


@dataclass(frozen=True)
class WorkBatchResult:
    tenant_id: str
    claimed: int
    completed: int
    not_found: int
    retried: int
    dead_lettered: int
    ambiguous: int
    provider_writes_possible: bool
    raw_subject_persisted: bool = False
    credential_values_persisted: bool = False
    estate_completeness_claimed: bool = False
    live_provider_acceptance_verified: bool = False


@dataclass(frozen=True)
class ReconciliationBatchResult:
    tenant_id: str
    inspected: int
    resolved: int
    requeued: int
    still_ambiguous: int
    errors: int
    provider_writes_performed: bool = False
    optimistic_replays_performed: int = 0
    raw_subject_persisted: bool = False
    credential_values_persisted: bool = False
    live_provider_acceptance_verified: bool = False


class PrivacyRightsProviderAdapter(Protocol):
    """One closed source contract; implementations own provider semantics."""

    def execute(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        subject_reference: str,
        credential: str,
        operation_id: str,
        destructive_approved: bool,
    ) -> ProviderOutcome: ...

    def reconcile_delete(
        self,
        *,
        subject_reference: str,
        credential: str,
        operation_id: str,
    ) -> ProviderReconciliationOutcome: ...

    def prepare_mutation(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        subject_reference: str,
        credential: str,
        operation_id: str,
    ) -> PreparedProviderMutation: ...

    def execute_prepared(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        credential: str,
        operation_id: str,
        target_ref: str,
        target_binding_sha256: str,
        destructive_approved: bool,
    ) -> ProviderOutcome: ...

    def reconcile_mutation(
        self,
        *,
        tenant_id: str,
        source_id: str,
        case_id: str,
        phase: str,
        credential: str,
        operation_id: str,
        target_ref: str,
        target_binding_sha256: str,
    ) -> ProviderReconciliationOutcome: ...


StoreFactory = Callable[[str, str], rights.PrivacyRightsOrchestrationStore]
SubjectResolver = Callable[[str, str, str], SubjectBinding]
CredentialResolver = Callable[[str, str, str], str]
AdapterResolver = Callable[[str, str], AdapterBinding]
SubjectDigestResolver = Callable[[str, str], str]


def adapter_authority_sha256(
    *,
    tenant_id: str,
    source_id: str,
    adapter_ref: str,
    credential_ref: str,
    capabilities: tuple[str, ...],
) -> str:
    """Derive the one adapter authority committed by a source enrollment.

    Planning and approval already pin the integrity-protected source fields.
    Requiring ``AdapterBinding.authority_sha256`` to equal this digest makes
    that pin explicit and prevents a resolver from silently substituting a new
    adapter authority behind an approved task.
    """

    selected_capabilities = tuple(
        _reference(value, "capability") for value in capabilities
    )
    if not selected_capabilities or len(set(selected_capabilities)) != len(
        selected_capabilities
    ):
        raise PrivacyRightsSourceWorkerConfigError(
            "privacy-rights adapter capabilities are invalid"
        )
    material = "\x00".join(
        (
            "lightwork.privacy-rights.adapter-authority.v1",
            _reference(tenant_id, "tenant_id"),
            _reference(source_id, "source_id"),
            _reference(adapter_ref, "adapter_ref"),
            _reference(credential_ref, "credential_ref"),
            *selected_capabilities,
        )
    )
    return hashlib.sha256(material.encode("ascii", "strict")).hexdigest()


class PrivacyRightsSourceWorker:
    """Claims and executes bounded provider work for one exact tenant."""

    def __init__(
        self,
        *,
        store_factory: StoreFactory,
        subject_resolver: SubjectResolver,
        credential_resolver: CredentialResolver,
        adapter_resolver: AdapterResolver,
        owned_source_ids: tuple[str, ...],
        subject_digest_resolver: SubjectDigestResolver = _default_subject_digest,
        clock: Callable[[], float] = time.time,
        default_batch_size: int = 10,
        maximum_batch_size: int = 100,
        default_lease_seconds: int = 60,
        minimum_lease_seconds: int = 1,
        maximum_lease_seconds: int = 3_600,
        default_retry_delay_seconds: int = 30,
        maximum_retry_delay_seconds: int = 604_800,
    ) -> None:
        for value, label in (
            (store_factory, "store_factory"),
            (subject_resolver, "subject_resolver"),
            (credential_resolver, "credential_resolver"),
            (adapter_resolver, "adapter_resolver"),
            (subject_digest_resolver, "subject_digest_resolver"),
            (clock, "clock"),
        ):
            if not callable(value):
                raise PrivacyRightsSourceWorkerConfigError(f"{label} is unavailable")
        self._store_factory = store_factory
        self._subject_resolver = subject_resolver
        self._credential_resolver = credential_resolver
        self._adapter_resolver = adapter_resolver
        if (
            not isinstance(owned_source_ids, tuple)
            or not owned_source_ids
            or len(owned_source_ids) > 1_000
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "owned_source_ids is unavailable"
            )
        selected_sources = tuple(
            sorted({_reference(value, "source_id") for value in owned_source_ids})
        )
        if len(selected_sources) != len(owned_source_ids):
            raise PrivacyRightsSourceWorkerConfigError(
                "owned_source_ids contains duplicates"
            )
        self._owned_source_ids = selected_sources
        self._subject_digest_resolver = subject_digest_resolver
        self._clock = clock
        self._maximum_batch_size = _integer(
            maximum_batch_size, "maximum_batch_size", 1, 100
        )
        self._default_batch_size = _integer(
            default_batch_size,
            "default_batch_size",
            1,
            self._maximum_batch_size,
        )
        self._minimum_lease_seconds = _integer(
            minimum_lease_seconds, "minimum_lease_seconds", 1, 3_600
        )
        self._maximum_lease_seconds = _integer(
            maximum_lease_seconds,
            "maximum_lease_seconds",
            self._minimum_lease_seconds,
            3_600,
        )
        self._default_lease_seconds = _integer(
            default_lease_seconds,
            "default_lease_seconds",
            self._minimum_lease_seconds,
            self._maximum_lease_seconds,
        )
        self._maximum_retry_delay_seconds = _integer(
            maximum_retry_delay_seconds,
            "maximum_retry_delay_seconds",
            0,
            604_800,
        )
        self._default_retry_delay_seconds = _integer(
            default_retry_delay_seconds,
            "default_retry_delay_seconds",
            0,
            self._maximum_retry_delay_seconds,
        )

    @staticmethod
    def _operation_id(
        callback: rights.CallbackItem,
        source: rights.SourceEnrollment,
        case: rights.RightsCase,
        task: rights.SourceTask,
    ) -> str:
        digest = hashlib.sha256(
            (
                "lightwork.privacy-rights.provider-operation.v2\x00"
                + callback.tenant_id
                + "\x00"
                + callback.callback_id
                + "\x00"
                + task.task_id
                + "\x00"
                + case.case_id
                + "\x00"
                + source.source_id
                + "\x00"
                + callback.phase
            ).encode("ascii", "strict")
        ).hexdigest()
        return f"prso:{digest[:48]}"

    @staticmethod
    def _idempotency(action: str, callback: rights.CallbackItem) -> str:
        digest = hashlib.sha256(
            (
                "lightwork.privacy-rights.source-worker.v1\x00"
                + action
                + "\x00"
                + callback.callback_id
                + "\x00"
                + str(callback.revision)
            ).encode("ascii")
        ).hexdigest()
        return f"prsw:{action}:{digest[:40]}"

    def _subject(
        self,
        tenant_id: str,
        case: rights.RightsCase,
        source: rights.SourceEnrollment,
    ) -> str:
        try:
            binding = self._subject_resolver(tenant_id, case.case_id, source.source_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ProviderRetryableError:
            raise
        except Exception as exc:
            raise ProviderRetryableError(
                "subject_authority_unavailable"
            ) from exc
        if not isinstance(binding, SubjectBinding):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights subject authority is invalid"
            )
        now = float(self._clock())
        if (
            not math.isfinite(now)
            or binding.tenant_id != tenant_id
            or binding.case_id != case.case_id
            or not math.isfinite(binding.expires_at)
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights subject authority is misbound"
            )
        if binding.expires_at <= now:
            raise ProviderRetryableError("subject_authority_stale")
        authority = _digest(binding.authority_sha256, "subject authority")
        try:
            calculated = self._subject_digest_resolver(
                tenant_id, binding.subject_reference
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ProviderRetryableError(
                "subject_digest_authority_unavailable"
            ) from exc
        if (
            not hmac.compare_digest(calculated, case.subject_sha256)
            or not hmac.compare_digest(authority, case.subject_sha256)
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights subject authority does not match the case"
            )
        raw = unicodedata.normalize("NFC", binding.subject_reference).strip()
        if not raw or len(raw.encode("utf-8")) > _MAX_SUBJECT_BYTES:
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights subject authority is invalid"
            )
        return raw

    def _adapter(
        self, tenant_id: str, source: rights.SourceEnrollment
    ) -> AdapterBinding:
        try:
            binding = self._adapter_resolver(tenant_id, source.source_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ProviderRetryableError:
            raise
        except Exception as exc:
            raise ProviderRetryableError(
                "source_adapter_unavailable"
            ) from exc
        if not isinstance(binding, AdapterBinding) or binding.adapter is None:
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights source adapter is misbound"
            )
        if (
            binding.tenant_id != tenant_id
            or binding.source_id != source.source_id
            or binding.adapter_ref != source.adapter_ref
            or binding.credential_ref != source.credential_ref
            or tuple(binding.capabilities) != tuple(source.capabilities)
        ):
            raise ProviderRetryableError("provider_authority_drift")
        expected_authority = adapter_authority_sha256(
            tenant_id=tenant_id,
            source_id=source.source_id,
            adapter_ref=source.adapter_ref,
            credential_ref=source.credential_ref,
            capabilities=source.capabilities,
        )
        if not hmac.compare_digest(
            _digest(binding.authority_sha256, "adapter authority"),
            expected_authority,
        ):
            raise ProviderRetryableError("provider_authority_drift")
        return binding

    def _credential(
        self, tenant_id: str, source: rights.SourceEnrollment
    ) -> str:
        try:
            value = self._credential_resolver(
                tenant_id, source.source_id, source.credential_ref
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except ProviderRetryableError:
            raise
        except Exception as exc:
            raise ProviderRetryableError(
                "provider_credential_unavailable"
            ) from exc
        if not isinstance(value, str):
            raise ProviderRetryableError("provider_credential_unavailable")
        selected = value.strip()
        if not selected:
            raise ProviderRetryableError("provider_credential_unavailable")
        if len(selected.encode("utf-8")) > _MAX_SECRET_BYTES or any(
            character in selected for character in "\r\n\x00"
        ):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights source credential is invalid"
            )
        return selected

    @staticmethod
    def _validate_outcome(
        outcome: object, *, phase: str
    ) -> ProviderOutcome:
        if not isinstance(outcome, ProviderOutcome):
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider outcome is invalid"
            )
        if outcome.status not in {"complete", "not_found"}:
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider outcome status is invalid"
            )
        _integer(outcome.record_count, "record_count", 0, 1_000_000_000)
        _digest(outcome.acknowledgement_sha256, "acknowledgement_sha256")
        _reference(outcome.acknowledgement_ref, "acknowledgement_ref")
        _digest(outcome.provider_evidence_sha256, "provider_evidence_sha256")
        _reference(outcome.opaque_ref, "opaque_ref")
        expected_side_effect = phase in _MUTATING_PHASES
        if phase in _MUTATING_PHASES and outcome.status == "not_found":
            expected_side_effect = False
        if (
            outcome.external_side_effect is not expected_side_effect
            or outcome.raw_data_returned is not False
            or outcome.live_provider_acceptance_verified is not False
        ):
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider outcome boundary is invalid"
            )
        return outcome

    @staticmethod
    def _validate_prepared_mutation(
        outcome: object,
    ) -> PreparedProviderMutation:
        if not isinstance(outcome, PreparedProviderMutation):
            raise PrivacyRightsSourceWorkerProtocolError(
                "prepared provider mutation is invalid"
            )
        if outcome.status not in {"ready", "not_found"}:
            raise PrivacyRightsSourceWorkerProtocolError(
                "prepared provider mutation status is invalid"
            )
        _integer(outcome.record_count, "record_count", 0, 1_000_000_000)
        _digest(outcome.acknowledgement_sha256, "acknowledgement_sha256")
        _reference(outcome.acknowledgement_ref, "acknowledgement_ref")
        _digest(outcome.provider_evidence_sha256, "provider_evidence_sha256")
        _reference(outcome.opaque_ref, "opaque_ref")
        if outcome.provider_retention_state not in {
            "active",
            "already_absent",
        }:
            raise PrivacyRightsSourceWorkerProtocolError(
                "prepared provider retention state is invalid"
            )
        if outcome.status == "ready":
            _reference(outcome.target_ref, "target_ref", maximum=192)
            _digest(outcome.target_binding_sha256, "target_binding_sha256")
            if outcome.record_count != 1 or outcome.provider_retention_state != "active":
                raise PrivacyRightsSourceWorkerProtocolError(
                    "prepared provider target is invalid"
                )
        elif (
            outcome.target_ref is not None
            or outcome.target_binding_sha256 is not None
            or outcome.record_count != 0
            or outcome.provider_retention_state != "already_absent"
        ):
            raise PrivacyRightsSourceWorkerProtocolError(
                "already-absent provider target is invalid"
            )
        return outcome

    @staticmethod
    def _validate_reconciliation_outcome(
        outcome: object,
    ) -> ProviderReconciliationOutcome:
        if not isinstance(outcome, ProviderReconciliationOutcome):
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider reconciliation outcome is invalid"
            )
        if outcome.disposition not in {"applied", "absent", "unknown"}:
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider reconciliation disposition is invalid"
            )
        _digest(outcome.provider_evidence_sha256, "provider_evidence_sha256")
        _reference(outcome.provider_evidence_ref, "provider_evidence_ref")
        _integer(outcome.record_count, "record_count", 0, 1_000_000_000)
        if (
            outcome.external_side_effect is not False
            or outcome.optimistic_replay_performed is not False
        ):
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider reconciliation must be read-only"
            )
        if outcome.provider_retention_state not in {
            "active",
            "soft_deleted",
            "purged",
            "hard_deleted",
            "retention_unknown",
            "unknown",
        }:
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider reconciliation retention state is invalid"
            )
        if outcome.disposition == "applied" and outcome.provider_retention_state not in {
            "purged",
            "hard_deleted",
        }:
            raise PrivacyRightsSourceWorkerProtocolError(
                "provider absence is not erasure proof"
            )
        return outcome

    @staticmethod
    def _dispatch_digest(
        *,
        callback: rights.CallbackItem,
        operation_id: str,
        adapter_authority_sha256: str,
        source_integrity_sha256: str,
        target_binding_sha256: str | None,
    ) -> str:
        material = "\x00".join(
            (
                "lightwork.privacy-rights.dispatch.v1",
                callback.tenant_id,
                callback.callback_id,
                operation_id,
                adapter_authority_sha256,
                source_integrity_sha256,
                target_binding_sha256 or "no-target",
            )
        )
        return hashlib.sha256(material.encode("ascii", "strict")).hexdigest()

    def run_once(  # noqa: C901
        self,
        tenant_id: str,
        *,
        worker_ref: str,
        run_id: str,
        limit: int | None = None,
        lease_seconds: int | None = None,
        retry_delay_seconds: int | None = None,
    ) -> WorkBatchResult:
        tenant = _reference(tenant_id, "tenant_id")
        worker = _reference(worker_ref, "worker_ref")
        run = _reference(run_id, "run_id", maximum=192)
        bounded_limit = (
            self._default_batch_size
            if limit is None
            else _integer(limit, "limit", 1, self._maximum_batch_size)
        )
        lease = (
            self._default_lease_seconds
            if lease_seconds is None
            else _integer(
                lease_seconds,
                "lease_seconds",
                self._minimum_lease_seconds,
                self._maximum_lease_seconds,
            )
        )
        retry_delay = _integer(
            (
                self._default_retry_delay_seconds
                if retry_delay_seconds is None
                else retry_delay_seconds
            ),
            "retry_delay_seconds",
            0,
            self._maximum_retry_delay_seconds,
        )
        store = self._store_factory(tenant, worker)
        if not isinstance(store, rights.PrivacyRightsOrchestrationStore):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights orchestration store is unavailable"
            )
        claimed = store.claim_callbacks(
            tenant,
            limit=bounded_limit,
            lease_seconds=lease,
            source_ids=self._owned_source_ids,
            idempotency_key=f"prsw:claim:{hashlib.sha256(run.encode()).hexdigest()[:40]}",
        )
        counts = {
            "completed": 0,
            "not_found": 0,
            "retried": 0,
            "dead_lettered": 0,
            "ambiguous": 0,
        }
        for callback in claimed:
            active_callback = callback
            mutation_reserved = False
            try:
                current_callback = store.get_callback(tenant, callback.callback_id)
                dispatch_now = float(self._clock())
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                continue
            if (
                current_callback != callback
                or callback.state != "leased"
                or callback.lease_token is None
                or callback.lease_owner != worker
                or callback.lease_until is None
                or not math.isfinite(dispatch_now)
                or callback.lease_until <= dispatch_now
            ):
                # A replayed claim batch is only a historical response snapshot.
                # Provider work may start solely from the still-current live lease.
                continue
            lease_token = callback.lease_token or ""
            operation_id = f"prso:{hashlib.sha256(callback.integrity_sha256.encode()).hexdigest()[:48]}"
            try:
                source = store.get_source(tenant, callback.source_id)
                case = store.get_case(tenant, callback.case_id)
                task = store.get_task(tenant, callback.task_id)
                if (
                    callback.tenant_id != tenant
                    or source.tenant_id != tenant
                    or case.tenant_id != tenant
                    or task.tenant_id != tenant
                    or task.case_id != case.case_id
                    or task.source_id != source.source_id
                    or task.phase != callback.phase
                    or task.state != "planned"
                    or case.status != "open"
                    or case.identity_status != "verified"
                    or source.state != "active"
                    or callback.phase not in source.capabilities
                    or task.source_revision != source.revision
                    or task.source_integrity_sha256 != source.integrity_sha256
                    or task.adapter_ref != source.adapter_ref
                    or task.credential_ref != source.credential_ref
                    or (
                        callback.phase == "delete"
                        and (
                            task.approved_by is None
                            or case.legal_hold
                            or case.retention_blocks_deletion
                        )
                    )
                ):
                    raise ProviderRetryableError("provider_authority_drift")
                operation_id = self._operation_id(callback, source, case, task)
                binding = self._adapter(tenant, source)
                subject_reference = self._subject(tenant, case, source)
                credential = self._credential(tenant, source)
                provider_contract = _reference(
                    binding.provider_contract or binding.adapter_ref,
                    "provider_contract",
                )
                if callback.phase in _MUTATING_PHASES:
                    prepare = getattr(binding.adapter, "prepare_mutation", None)
                    execute_prepared = getattr(
                        binding.adapter, "execute_prepared", None
                    )
                    if not callable(prepare) or not callable(execute_prepared):
                        raise PrivacyRightsSourceWorkerConfigError(
                            "privacy-rights immutable target custody is unavailable"
                        )
                    prepared = self._validate_prepared_mutation(
                        prepare(
                            tenant_id=tenant,
                            source_id=source.source_id,
                            case_id=case.case_id,
                            phase=callback.phase,
                            subject_reference=subject_reference,
                            credential=credential,
                            operation_id=operation_id,
                        )
                    )
                    dispatch_digest = self._dispatch_digest(
                        callback=callback,
                        operation_id=operation_id,
                        adapter_authority_sha256=binding.authority_sha256,
                        source_integrity_sha256=source.integrity_sha256,
                        target_binding_sha256=prepared.target_binding_sha256,
                    )
                    if prepared.status == "not_found":
                        active_callback = store.authorize_callback_dispatch(
                            tenant,
                            callback.callback_id,
                            lease_token=lease_token,
                            operation_id=operation_id,
                            operation_sha256=dispatch_digest,
                            adapter_authority_sha256=binding.authority_sha256,
                            source_revision=source.revision,
                            source_integrity_sha256=source.integrity_sha256,
                            adapter_ref=source.adapter_ref,
                            credential_ref=source.credential_ref,
                            provider_contract=provider_contract,
                            provider_write=False,
                            target_ref=None,
                            target_binding_sha256=None,
                            expected_revision=callback.revision,
                            idempotency_key=self._idempotency(
                                "authorize_no_change", callback
                            ),
                        )
                        no_change = self._validate_outcome(
                            ProviderOutcome(
                                status="not_found",
                                record_count=0,
                                acknowledgement_sha256=(
                                    prepared.acknowledgement_sha256
                                ),
                                acknowledgement_ref=prepared.acknowledgement_ref,
                                provider_evidence_sha256=(
                                    prepared.provider_evidence_sha256
                                ),
                                opaque_ref=prepared.opaque_ref,
                                external_side_effect=False,
                            ),
                            phase=callback.phase,
                        )
                        store.complete_callback(
                            tenant,
                            callback.callback_id,
                            lease_token=lease_token,
                            acknowledgement_sha256=(
                                no_change.acknowledgement_sha256
                            ),
                            acknowledgement_ref=no_change.acknowledgement_ref,
                            evidence_status=no_change.status,
                            provider_evidence_sha256=(
                                no_change.provider_evidence_sha256
                            ),
                            record_count=no_change.record_count,
                            opaque_ref=no_change.opaque_ref,
                            provider_retention_state="already_absent",
                            expected_revision=active_callback.revision,
                            idempotency_key=self._idempotency(
                                "complete_no_change", active_callback
                            ),
                        )
                        counts["not_found"] += 1
                        continue
                    assert prepared.target_ref is not None
                    assert prepared.target_binding_sha256 is not None
                    active_callback = store.authorize_callback_dispatch(
                        tenant,
                        callback.callback_id,
                        lease_token=lease_token,
                        operation_id=operation_id,
                        operation_sha256=dispatch_digest,
                        adapter_authority_sha256=binding.authority_sha256,
                        source_revision=source.revision,
                        source_integrity_sha256=source.integrity_sha256,
                        adapter_ref=source.adapter_ref,
                        credential_ref=source.credential_ref,
                        provider_contract=provider_contract,
                        provider_write=True,
                        target_ref=prepared.target_ref,
                        target_binding_sha256=prepared.target_binding_sha256,
                        expected_revision=callback.revision,
                        idempotency_key=self._idempotency(
                            "reserve_mutation", callback
                        ),
                    )
                    mutation_reserved = True
                    outcome = self._validate_outcome(
                        execute_prepared(
                            tenant_id=tenant,
                            source_id=source.source_id,
                            case_id=case.case_id,
                            phase=callback.phase,
                            credential=credential,
                            operation_id=operation_id,
                            target_ref=prepared.target_ref,
                            target_binding_sha256=prepared.target_binding_sha256,
                            destructive_approved=(task.approved_by is not None),
                        ),
                        phase=callback.phase,
                    )
                    if outcome.external_side_effect is not True:
                        raise PrivacyRightsSourceWorkerProtocolError(
                            "reserved provider mutation did not execute"
                        )
                    # The durable reservation is intentionally left ambiguous.
                    # Only an exact-target read-only reconciliation can complete it.
                    counts["ambiguous"] += 1
                    continue
                dispatch_digest = self._dispatch_digest(
                    callback=callback,
                    operation_id=operation_id,
                    adapter_authority_sha256=binding.authority_sha256,
                    source_integrity_sha256=source.integrity_sha256,
                    target_binding_sha256=None,
                )
                execute = getattr(binding.adapter, "execute", None)
                if not callable(execute):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "privacy-rights source read adapter is unavailable"
                    )
                active_callback = store.authorize_callback_dispatch(
                    tenant,
                    callback.callback_id,
                    lease_token=lease_token,
                    operation_id=operation_id,
                    operation_sha256=dispatch_digest,
                    adapter_authority_sha256=binding.authority_sha256,
                    source_revision=source.revision,
                    source_integrity_sha256=source.integrity_sha256,
                    adapter_ref=source.adapter_ref,
                    credential_ref=source.credential_ref,
                    provider_contract=provider_contract,
                    provider_write=False,
                    target_ref=None,
                    target_binding_sha256=None,
                    expected_revision=callback.revision,
                    idempotency_key=self._idempotency("authorize_read", callback),
                )
                outcome = self._validate_outcome(
                    execute(
                        tenant_id=tenant,
                        source_id=source.source_id,
                        case_id=case.case_id,
                        phase=callback.phase,
                        subject_reference=subject_reference,
                        credential=credential,
                        operation_id=operation_id,
                        destructive_approved=(
                            not task.destructive and task.approved_by is None
                        )
                        or (task.destructive and task.approved_by is not None),
                    ),
                    phase=callback.phase,
                )
                if (
                    store.get_source(tenant, source.source_id) != source
                    or store.get_case(tenant, case.case_id) != case
                    or store.get_task(tenant, task.task_id) != task
                ):
                    if outcome.external_side_effect:
                        raise ProviderAmbiguousOutcome(
                            operation_sha256=outcome.acknowledgement_sha256,
                            operation_ref=operation_id,
                            error_code="provider_authority_drift",
                        )
                    raise ProviderRetryableError("provider_authority_drift")
                store.complete_callback(
                    tenant,
                    callback.callback_id,
                    lease_token=lease_token,
                    acknowledgement_sha256=outcome.acknowledgement_sha256,
                    acknowledgement_ref=outcome.acknowledgement_ref,
                    evidence_status=outcome.status,
                    provider_evidence_sha256=outcome.provider_evidence_sha256,
                    record_count=outcome.record_count,
                    opaque_ref=outcome.opaque_ref,
                    expected_revision=active_callback.revision,
                    idempotency_key=self._idempotency("complete", active_callback),
                )
                counts["not_found" if outcome.status == "not_found" else "completed"] += 1
            except ProviderAmbiguousOutcome:
                if mutation_reserved:
                    counts["ambiguous"] += 1
                else:
                    store.dead_letter_callback(
                        tenant,
                        callback.callback_id,
                        lease_token=lease_token,
                        error_code="source_adapter_invalid",
                        expected_revision=active_callback.revision,
                        idempotency_key=self._idempotency(
                            "dead_letter", active_callback
                        ),
                    )
                    counts["dead_lettered"] += 1
            except ProviderRetryableError as exc:
                if mutation_reserved:
                    counts["ambiguous"] += 1
                else:
                    store.fail_callback(
                        tenant,
                        callback.callback_id,
                        lease_token=lease_token,
                        error_code=exc.error_code,
                        retry_delay_seconds=retry_delay,
                        expected_revision=active_callback.revision,
                        idempotency_key=self._idempotency("retry", active_callback),
                    )
                    counts["retried"] += 1
            except (
                ProviderPermanentError,
                PrivacyRightsSourceWorkerConfigError,
                PrivacyRightsSourceWorkerProtocolError,
            ) as exc:
                error_code = (
                    exc.error_code
                    if isinstance(exc, ProviderPermanentError)
                    else "source_adapter_invalid"
                )
                if mutation_reserved:
                    counts["ambiguous"] += 1
                else:
                    store.dead_letter_callback(
                        tenant,
                        callback.callback_id,
                        lease_token=lease_token,
                        error_code=error_code,
                        expected_revision=active_callback.revision,
                        idempotency_key=self._idempotency(
                            "dead_letter", active_callback
                        ),
                    )
                    counts["dead_lettered"] += 1
            except rights.PrivacyRightsConflict:
                # Another worker changed the exact callback CAS, including the
                # one-time mutation reservation.  Never infer permission to retry.
                continue
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                if mutation_reserved:
                    counts["ambiguous"] += 1
                else:
                    store.fail_callback(
                        tenant,
                        callback.callback_id,
                        lease_token=lease_token,
                        error_code="provider_temporarily_unavailable",
                        retry_delay_seconds=retry_delay,
                        expected_revision=active_callback.revision,
                        idempotency_key=self._idempotency("retry", active_callback),
                    )
                    counts["retried"] += 1
        return WorkBatchResult(
            tenant_id=tenant,
            claimed=len(claimed),
            provider_writes_possible=any(
                callback.phase in _MUTATING_PHASES for callback in claimed
            ),
            **counts,
        )

    def reconcile_once(
        self,
        tenant_id: str,
        *,
        worker_ref: str,
        run_id: str,
        limit: int | None = None,
        retry_delay_seconds: int | None = None,
    ) -> ReconciliationBatchResult:
        """Probe ambiguous deletes and resolve them without replaying a mutation."""

        tenant = _reference(tenant_id, "tenant_id")
        worker = _reference(worker_ref, "worker_ref")
        _reference(run_id, "run_id", maximum=192)
        bounded_limit = (
            self._default_batch_size
            if limit is None
            else _integer(limit, "limit", 1, self._maximum_batch_size)
        )
        retry_delay = _integer(
            (
                self._default_retry_delay_seconds
                if retry_delay_seconds is None
                else retry_delay_seconds
            ),
            "retry_delay_seconds",
            0,
            self._maximum_retry_delay_seconds,
        )
        store = self._store_factory(tenant, worker)
        if not isinstance(store, rights.PrivacyRightsOrchestrationStore):
            raise PrivacyRightsSourceWorkerConfigError(
                "privacy-rights orchestration store is unavailable"
            )
        callbacks = store.due_reconciliation_callbacks(
            tenant, source_ids=tuple(self._owned_source_ids), limit=bounded_limit,
        )
        counts = {
            "resolved": 0,
            "requeued": 0,
            "still_ambiguous": 0,
            "errors": 0,
        }
        for callback in callbacks:
            try:
                source = store.get_source(tenant, callback.source_id)
                case = store.get_case(tenant, callback.case_id)
                task = store.get_task(tenant, callback.task_id)
                if (
                    callback.phase not in _MUTATING_PHASES
                    or source.state != "active"
                    or task.state != "planned"
                    or task.phase != callback.phase
                    or task.case_id != case.case_id
                    or task.source_id != source.source_id
                    or callback.tenant_id != tenant
                    or task.source_revision != source.revision
                    or task.source_integrity_sha256 != source.integrity_sha256
                    or task.adapter_ref != source.adapter_ref
                    or task.credential_ref != source.credential_ref
                    or callback.source_revision != source.revision
                    or callback.source_integrity_sha256 != source.integrity_sha256
                    or callback.adapter_ref != source.adapter_ref
                    or callback.credential_ref != source.credential_ref
                    or callback.provider_operation_performed is not True
                    or callback.target_ref is None
                    or callback.target_binding_sha256 is None
                ):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "ambiguous provider work authority is misbound"
                    )
                operation_id = callback.provider_operation_id
                if (
                    operation_id is None
                    or callback.ambiguous_operation_ref != operation_id
                    or callback.provider_operation_sha256
                    != callback.ambiguous_operation_sha256
                ):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "ambiguous provider operation identity is unavailable"
                    )
                binding = self._adapter(tenant, source)
                if (
                    binding.authority_sha256 != callback.adapter_authority_sha256
                    or (binding.provider_contract or binding.adapter_ref)
                    != callback.provider_contract
                ):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "privacy-rights reconciliation adapter authority changed"
                    )
                reconcile = getattr(binding.adapter, "reconcile_mutation", None)
                if not callable(reconcile):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "privacy-rights reconciliation adapter is unavailable"
                    )
                credential = self._credential(tenant, source)
                outcome = self._validate_reconciliation_outcome(
                    reconcile(
                        tenant_id=tenant,
                        source_id=source.source_id,
                        case_id=case.case_id,
                        phase=callback.phase,
                        credential=credential,
                        operation_id=operation_id,
                        target_ref=callback.target_ref,
                        target_binding_sha256=callback.target_binding_sha256,
                    )
                )
                if (
                    store.get_source(tenant, source.source_id) != source
                    or store.get_case(tenant, case.case_id) != case
                    or store.get_task(tenant, task.task_id) != task
                    or store.get_callback(tenant, callback.callback_id) != callback
                ):
                    raise PrivacyRightsSourceWorkerConfigError(
                        "privacy-rights reconciliation authority changed"
                    )
                if outcome.disposition == "applied":
                    store.reconcile_ambiguous_callback(
                        tenant,
                        callback.callback_id,
                        disposition="applied",
                        provider_evidence_sha256=outcome.provider_evidence_sha256,
                        provider_evidence_ref=outcome.provider_evidence_ref,
                        evidence_status="complete",
                        record_count=outcome.record_count,
                        opaque_ref=outcome.provider_evidence_ref,
                        provider_retention_state=(
                            outcome.provider_retention_state
                        ),
                        retry_delay_seconds=0,
                        expected_revision=callback.revision,
                        idempotency_key=self._idempotency(
                            "reconcile_applied", callback
                        ),
                    )
                    counts["resolved"] += 1
                elif outcome.disposition == "absent":
                    store.reconcile_ambiguous_callback(
                        tenant,
                        callback.callback_id,
                        disposition="absent",
                        provider_evidence_sha256=outcome.provider_evidence_sha256,
                        provider_evidence_ref=outcome.provider_evidence_ref,
                        provider_retention_state=(
                            outcome.provider_retention_state
                        ),
                        retry_delay_seconds=retry_delay,
                        expected_revision=callback.revision,
                        idempotency_key=self._idempotency(
                            "reconcile_absent", callback
                        ),
                    )
                    counts["still_ambiguous"] += 1
                else:
                    store.reconcile_ambiguous_callback(
                        tenant,
                        callback.callback_id,
                        disposition="unknown",
                        provider_evidence_sha256=outcome.provider_evidence_sha256,
                        provider_evidence_ref=operation_id,
                        provider_retention_state=(
                            outcome.provider_retention_state
                        ),
                        retry_delay_seconds=retry_delay,
                        expected_revision=callback.revision,
                        idempotency_key=self._idempotency(
                            "reconcile_unknown", callback
                        ),
                    )
                    counts["still_ambiguous"] += 1
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                counts["errors"] += 1
                try:
                    store.defer_reconciliation_read(
                        tenant, callback.callback_id, expected_revision=callback.revision,
                        retry_delay_seconds=max(1, retry_delay),
                    )
                except Exception:
                    # A concurrent reconciliation may have advanced this CAS.
                    # Never change its disposition or replay the mutation.
                    pass
        return ReconciliationBatchResult(
            tenant_id=tenant,
            inspected=len(callbacks),
            **counts,
        )


__all__ = [
    "AdapterBinding",
    "PrivacyRightsProviderAdapter",
    "PrivacyRightsSourceWorker",
    "PrivacyRightsSourceWorkerConfigError",
    "PrivacyRightsSourceWorkerError",
    "PrivacyRightsSourceWorkerProtocolError",
    "PreparedProviderMutation",
    "ProviderAmbiguousOutcome",
    "ProviderOutcome",
    "ProviderReconciliationOutcome",
    "ProviderPermanentError",
    "ProviderRetryableError",
    "ReconciliationBatchResult",
    "SubjectBinding",
    "WorkBatchResult",
    "adapter_authority_sha256",
]
