"""Lazy production composition for consent export and mutation bulk jobs.

The stock runtime is local-only: it binds one authenticated principal to one
tenant's private job authority and existing consent preference authority.  A
status probe never opens either SQLite database and never seeds credits.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import consent_bulk_jobs as bulk
from maverick import consent_preferences as preferences
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

_CONFIG_KEYS = frozenset(
    {
        "enable",
        "initial_credits",
        "max_jobs",
        "max_items_per_job",
        "max_artifact_bytes",
        "lease_seconds",
        "retention_seconds",
        "worker_batch_size",
    }
)
_DEFAULT_INITIAL_CREDITS = 10_000
_DEFAULT_WORKER_BATCH_SIZE = 100
_MUTATION_METHODS = {
    "delete_subject": "delete_subject",
    "change_identifier_type": "change_identifier_type",
    "reactivate": "set_receipt_reactivation",
    "clear_expiration": "clear_receipt_expiration",
}


class ConsentBulkJobsCompositionError(bulk.ConsentBulkJobError):
    """A deployment-owned bulk-job dependency is unavailable."""


class ConsentBulkExecutorUnavailable(bulk.ConsentBulkJobError):
    """The exact consent mutation primitive is not installed."""


@dataclass(frozen=True, slots=True)
class ConsentBulkJobsSettings:
    initial_credits: int
    max_jobs: int
    max_items_per_job: int
    max_artifact_bytes: int
    lease_seconds: int
    retention_seconds: int
    worker_batch_size: int

    @property
    def limits(self) -> bulk.ConsentBulkJobLimits:
        return bulk.ConsentBulkJobLimits(
            max_jobs=self.max_jobs,
            max_items_per_job=self.max_items_per_job,
            max_artifact_bytes=self.max_artifact_bytes,
            lease_seconds=self.lease_seconds,
            retention_seconds=self.retention_seconds,
        )


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentBulkJobsCompositionError(f"{label} is outside its bound")
    return value


def consent_bulk_jobs_settings(
    config: Mapping[str, Any],
) -> ConsentBulkJobsSettings | None:
    """Parse the exact nested feature contract; absence and false mean off."""

    if not isinstance(config, Mapping):
        raise ConsentBulkJobsCompositionError("consent bulk-job configuration unavailable")
    parent = config.get("consent_preferences")
    if not isinstance(parent, Mapping) or parent.get("enable") is not True:
        return None
    section = parent.get("bulk_jobs")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise ConsentBulkJobsCompositionError(
            "consent_preferences.bulk_jobs must be a table"
        )
    if any(key not in _CONFIG_KEYS for key in section):
        raise ConsentBulkJobsCompositionError(
            "consent_preferences.bulk_jobs contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise ConsentBulkJobsCompositionError(
            "consent_preferences.bulk_jobs.enable must be true or false"
        )
    if enabled is not True:
        return None
    defaults = bulk.ConsentBulkJobLimits()
    return ConsentBulkJobsSettings(
        initial_credits=_integer(
            section.get("initial_credits", _DEFAULT_INITIAL_CREDITS),
            "consent_preferences.bulk_jobs.initial_credits",
            0,
            1_000_000_000,
        ),
        max_jobs=_integer(
            section.get("max_jobs", defaults.max_jobs),
            "consent_preferences.bulk_jobs.max_jobs",
            1,
            1_000_000,
        ),
        max_items_per_job=_integer(
            section.get("max_items_per_job", defaults.max_items_per_job),
            "consent_preferences.bulk_jobs.max_items_per_job",
            1,
            100_000,
        ),
        max_artifact_bytes=_integer(
            section.get("max_artifact_bytes", defaults.max_artifact_bytes),
            "consent_preferences.bulk_jobs.max_artifact_bytes",
            1_024,
            256 * 1024 * 1024,
        ),
        lease_seconds=_integer(
            section.get("lease_seconds", defaults.lease_seconds),
            "consent_preferences.bulk_jobs.lease_seconds",
            5,
            3_600,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", defaults.retention_seconds),
            "consent_preferences.bulk_jobs.retention_seconds",
            86_400,
            315_360_000,
        ),
        worker_batch_size=_integer(
            section.get("worker_batch_size", _DEFAULT_WORKER_BATCH_SIZE),
            "consent_preferences.bulk_jobs.worker_batch_size",
            1,
            500,
        ),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ConsentBulkJobsCompositionError(
            "consent bulk-job configuration unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise ConsentBulkJobsCompositionError(
            "consent bulk-job configuration unavailable"
        )
    return loaded


def settings_for_tenant(tenant_id: str) -> ConsentBulkJobsSettings:
    settings = consent_bulk_jobs_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise ConsentBulkJobsCompositionError("consent bulk jobs are disabled")
    return settings


def consent_bulk_jobs_enabled(tenant_id: str) -> bool:
    try:
        return consent_bulk_jobs_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _clock_for(app: Any) -> Callable[[], float]:
    selected = getattr(app.state, "consent_bulk_jobs_clock", None) or time.time
    if not callable(selected):
        raise ConsentBulkJobsCompositionError("consent bulk-job clock unavailable")

    def read() -> float:
        try:
            value = selected()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ConsentBulkJobsCompositionError(
                "consent bulk-job clock unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ConsentBulkJobsCompositionError("consent bulk-job clock unavailable")
        return float(value)

    return read


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise ConsentBulkJobsCompositionError("consent bulk-job request unavailable")
    return request


def _subject(request: Request) -> str:
    from .auth import (
        _dashboard_token_authenticated,
        anonymous_local_access_allowed,
        caller_principal,
    )

    principal = caller_principal(request)
    if isinstance(principal, str) and principal and len(principal) <= 512:
        return principal
    if anonymous_local_access_allowed():
        return "local-operator"
    if _dashboard_token_authenticated(request):
        return "static-dashboard-operator"
    raise ConsentBulkJobsCompositionError("consent bulk-job principal unavailable")


def expected_principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.consent-bulk.identity.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()
    return f"consent-bulk-principal-{digest[:32]}"


def _actor_digest(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    return hashlib.sha256(
        f"lightwork.consent-bulk.actor.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()


def _worker_digest(tenant_id: str, instance_nonce: bytes) -> str:
    tenant = canonical_tenant_id(tenant_id)
    if not isinstance(instance_nonce, bytes) or len(instance_nonce) < 32:
        raise ConsentBulkJobsCompositionError("consent bulk-job worker unavailable")
    return hashlib.sha256(
        b"lightwork.consent-bulk.stock-worker.v1\0"
        + tenant.encode()
        + b"\0"
        + instance_nonce
    ).hexdigest()


def _idempotency(operation: str, item_id: object, job_id: str = "") -> str:
    identity = f"{job_id}:{operation}:{item_id}" if job_id else f"{operation}:{item_id}"
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return f"bulk-item-{digest}"


class ConsentBulkExecutor:
    """Closed adapter from job operations to explicit preference primitives."""

    def __init__(
        self,
        *,
        tenant_id: str,
        actor_sha256: str,
        preference_store: Any,
    ) -> None:
        self.tenant_id = canonical_tenant_id(tenant_id)
        self.actor_sha256 = actor_sha256
        self.preference_store = preference_store

    def capabilities(self) -> dict[str, bool]:
        store = self.preference_store
        return {
            "export_receipts": callable(getattr(store, "export_profile", None)),
            "export_after_sequence": callable(
                getattr(store, "export_receipts", None)
            ),
            "edit_preferences": callable(
                getattr(store, "record_preferences", None)
            ),
            **{
                operation: callable(getattr(store, method, None))
                for operation, method in _MUTATION_METHODS.items()
            },
        }

    @staticmethod
    def _context(value: object) -> preferences.ConsentContext:
        if not isinstance(value, Mapping):
            raise preferences.ConsentValidationError("context is invalid")
        return preferences.ConsentContext(**dict(value))

    @staticmethod
    def _choices(value: object) -> list[preferences.PreferenceChoice]:
        if not isinstance(value, list):
            raise preferences.ConsentValidationError("choices are invalid")
        choices: list[preferences.PreferenceChoice] = []
        for item in value:
            if not isinstance(item, Mapping):
                raise preferences.ConsentValidationError("choices are invalid")
            choices.append(preferences.PreferenceChoice(**dict(item)))
        return choices

    def _required(self, method_name: str) -> Callable[..., Mapping[str, Any]]:
        method = getattr(self.preference_store, method_name, None)
        if not callable(method):
            raise ConsentBulkExecutorUnavailable(
                "consent bulk-job mutation primitive unavailable"
            )
        return method

    def __call__(
        self,
        operation: str,
        item: Mapping[str, Any],
        *, job_id: str = "",
    ) -> Mapping[str, Any]:
        tenant = self.tenant_id
        profile = str(item["profile_id"])
        key = _idempotency(operation, item["item_id"], job_id)
        if operation == "export_receipts":
            if "after_sequence" in item:
                return self._required("export_receipts")(
                    tenant,
                    profile,
                    after_sequence=item["after_sequence"],
                    receipt_limit=item.get("receipt_limit", 100),
                    actor_sha256=self.actor_sha256,
                    access_purpose="bulk_export_receipts",
                )
            return self._required("export_profile")(
                tenant,
                profile,
                actor_sha256=self.actor_sha256,
                access_purpose="bulk_export_receipts",
                receipt_limit=item.get("receipt_limit", 100),
            )
        if operation == "edit_preferences":
            return self._required("record_preferences")(
                tenant,
                profile,
                item["policy_id"],
                item["policy_version"],
                self._context(item["context"]),
                self._choices(item["choices"]),
                expected_revision=item["expected_revision"],
                idempotency_key=key,
                actor_sha256=self.actor_sha256,
                retention_until=item.get("retention_until"),
            )
        if operation == "delete_subject":
            return self._required("delete_subject")(
                tenant,
                profile,
                expected_revision=item["expected_revision"],
                reason_code=item["reason_code"],
                actor_sha256=self.actor_sha256,
                idempotency_key=key,
            )
        if operation == "change_identifier_type":
            return self._required("change_identifier_type")(
                tenant,
                profile,
                expected_revision=item["expected_revision"],
                identity_kind=item["identity_kind"],
                subject_sha256=item["subject_sha256"],
                actor_sha256=self.actor_sha256,
                idempotency_key=key,
            )
        if operation == "reactivate":
            return self._required("set_receipt_reactivation")(
                tenant,
                profile,
                item["receipt_id"],
                item["reactivation_at"],
                expected_revision=item["expected_revision"],
                actor_sha256=self.actor_sha256,
                idempotency_key=key,
            )
        if operation == "clear_expiration":
            return self._required("clear_receipt_expiration")(
                tenant,
                profile,
                expected_revision=item["expected_revision"],
                receipt_id=item["receipt_id"],
                actor_sha256=self.actor_sha256,
                idempotency_key=key,
            )
        raise bulk.ConsentBulkJobValidationError("bulk-job operation is invalid")


@dataclass(slots=True)
class ConsentBulkJobsRuntime:
    tenant_id: str
    principal_ref: str
    actor_sha256: str
    store: bulk.ConsentBulkJobStore
    executor: ConsentBulkExecutor
    worker_sha256: str
    worker_batch_size: int
    clock: Callable[[], float]

    def operation_capabilities(self) -> dict[str, bool]:
        return self.executor.capabilities()

    def run_job(self, job_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
        scope = self.store.job_executor_scope(self.tenant_id, job_id)

        def execute(operation: str, item: Mapping[str, Any]) -> Mapping[str, Any]:
            if scope == "job" and operation in {"reactivate", "clear_expiration"}:
                item = self.store.receipt_execution_item(self.tenant_id, job_id, item)
            return self.executor(operation, item, job_id=job_id if scope == "job" else "")

        return self.store.run_job(
            self.tenant_id,
            job_id,
            worker_sha256=self.worker_sha256,
            executor=execute,
            batch_size=self.worker_batch_size,
            **({"expected_revision": expected_revision} if expected_revision is not None else {}),
        )

    def run_next(self) -> dict[str, Any]:
        running = self.store.list_jobs(self.tenant_id, state="running", limit=500)
        skipped = 0
        for selected in sorted(
            running["jobs"],
            key=lambda job: (float(job["started_at"]), str(job["job_id"])),
        ):
            try:
                return {"ran": True, "job": self.run_job(str(selected["job_id"]))}
            except bulk.ConsentBulkJobConflict:
                # Another process owns an unexpired lease. Do not steal it or
                # prevent this worker from looking for an unleased due job.
                skipped += 1
        queued = self.store.list_jobs(self.tenant_id, state="queued", limit=500)
        now = self.clock()
        due = [job for job in queued["jobs"] if float(job["scheduled_for"]) <= now]
        if not due:
            return {"ran": False, "job": None, "leased_jobs_skipped": skipped}
        selected = min(
            due,
            key=lambda job: (
                float(job["scheduled_for"]),
                float(job["created_at"]),
                str(job["job_id"]),
            ),
        )
        return {"ran": True, "job": self.run_job(str(selected["job_id"]))}


def _default_job_store_path(*, tenant_id: str, request: object) -> Path:
    del request
    return data_dir(
        "consent_preferences",
        "bulk-jobs.sqlite3",
        tenant=canonical_tenant_id(tenant_id),
    )


def _default_preference_store(*, tenant_id: str, request: object) -> Any:
    del request
    tenant = canonical_tenant_id(tenant_id)
    return preferences.ConsentPreferenceStore(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant,
        )
    )


def build_consent_bulk_jobs_runtime(
    *,
    tenant_id: str,
    principal_ref: str,
    request: Request,
    config: Mapping[str, Any],
    job_store_path: str | Path,
    preference_store: Any,
    worker_sha256: str,
    clock: Callable[[], float] = time.time,
) -> ConsentBulkJobsRuntime:
    tenant = canonical_tenant_id(tenant_id)
    settings = consent_bulk_jobs_settings(config)
    if settings is None:
        raise ConsentBulkJobsCompositionError("consent bulk jobs are disabled")
    if principal_ref != expected_principal_ref(request, tenant):
        raise ConsentBulkJobsCompositionError("consent bulk-job principal unavailable")
    if (
        not isinstance(worker_sha256, str)
        or len(worker_sha256) != 64
        or any(character not in "0123456789abcdef" for character in worker_sha256)
    ):
        raise ConsentBulkJobsCompositionError("consent bulk-job worker unavailable")
    actor = _actor_digest(request, tenant)
    store = bulk.ConsentBulkJobStore(Path(job_store_path), limits=settings.limits, clock=clock)
    store.ensure_credit_account(tenant, initial_credits=settings.initial_credits)
    executor = ConsentBulkExecutor(
        tenant_id=tenant,
        actor_sha256=actor,
        preference_store=preference_store,
    )
    return ConsentBulkJobsRuntime(
        tenant_id=tenant,
        principal_ref=principal_ref,
        actor_sha256=actor,
        store=store,
        executor=executor,
        worker_sha256=worker_sha256,
        worker_batch_size=settings.worker_batch_size,
        clock=clock,
    )


def _class_capabilities() -> dict[str, bool]:
    return {
        "export_receipts": callable(getattr(preferences.ConsentPreferenceStore, "export_profile", None)),
        "export_after_sequence": callable(
            getattr(preferences.ConsentPreferenceStore, "export_receipts", None)
        ),
        "edit_preferences": callable(
            getattr(preferences.ConsentPreferenceStore, "record_preferences", None)
        ),
        **{
            operation: callable(
                getattr(preferences.ConsentPreferenceStore, method, None)
            )
            for operation, method in _MUTATION_METHODS.items()
        },
    }


def install_consent_bulk_jobs_composition(app: Any) -> None:
    """Install lazy feature, readiness and runtime factories on app state."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    defaults: dict[str, Callable[..., Any]] = {
        "consent_bulk_jobs_enabled_probe": consent_bulk_jobs_enabled,
        "consent_bulk_jobs_job_store_path_factory": _default_job_store_path,
        "consent_bulk_jobs_preference_store_factory": _default_preference_store,
    }
    for name, default in defaults.items():
        existing = getattr(state, name, None)
        if existing is not None and not callable(existing):
            raise TypeError(f"{name} must be callable")
        if existing is None:
            setattr(state, name, default)

    readiness = getattr(state, "consent_bulk_jobs_readiness_probe", None)
    if readiness is not None and not callable(readiness):
        raise TypeError("consent_bulk_jobs_readiness_probe must be callable")
    if readiness is None:

        def readiness_probe(tenant_id: str) -> Mapping[str, Any]:
            enabled = consent_bulk_jobs_enabled(tenant_id)
            capabilities = _class_capabilities()
            configured = all(
                callable(getattr(state, name, None))
                for name in (
                    "consent_bulk_jobs_job_store_path_factory",
                    "consent_bulk_jobs_preference_store_factory",
                )
            )
            return {
                "enabled": enabled,
                "configured": configured,
                "ready": enabled
                and configured
                and capabilities["export_receipts"]
                and capabilities["edit_preferences"],
                "operations": capabilities,
                "status_probe_opened_store": False,
                "status_probe_seeded_credits": False,
                "status_probe_invoked_provider": False,
            }

        state.consent_bulk_jobs_readiness_probe = readiness_probe

    runtime_factory = getattr(state, "consent_bulk_jobs_runtime_factory", None)
    if runtime_factory is not None and not callable(runtime_factory):
        raise TypeError("consent_bulk_jobs_runtime_factory must be callable")
    if runtime_factory is None:
        # One unexported nonce per process gives every worker a distinct lease
        # owner while keeping the identity stable across request-scoped runtimes.
        worker_instance_nonce = secrets.token_bytes(32)

        def factory(
            *,
            tenant_id: str,
            principal_ref: str,
            request: object,
        ) -> ConsentBulkJobsRuntime:
            tenant = canonical_tenant_id(tenant_id)
            selected = _request_for(app, request)
            config = _load_tenant_config(tenant)
            # Admission precedes path resolution, SQLite, and credit seeding.
            if consent_bulk_jobs_settings(config) is None:
                raise ConsentBulkJobsCompositionError("consent bulk jobs are disabled")
            path_factory = state.consent_bulk_jobs_job_store_path_factory
            preference_factory = state.consent_bulk_jobs_preference_store_factory
            try:
                path = path_factory(tenant_id=tenant, request=selected)
                preference_store = preference_factory(
                    tenant_id=tenant,
                    request=selected,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise ConsentBulkJobsCompositionError(
                    "consent bulk-job dependency unavailable"
                ) from exc
            if not isinstance(path, (str, Path)):
                raise ConsentBulkJobsCompositionError(
                    "consent bulk-job storage unavailable"
                )
            return build_consent_bulk_jobs_runtime(
                tenant_id=tenant,
                principal_ref=principal_ref,
                request=selected,
                config=config,
                job_store_path=path,
                preference_store=preference_store,
                worker_sha256=_worker_digest(tenant, worker_instance_nonce),
                clock=_clock_for(app),
            )

        state.consent_bulk_jobs_runtime_factory = factory

    state.consent_bulk_jobs_composition_installed = True


__all__ = [
    "ConsentBulkExecutor",
    "ConsentBulkExecutorUnavailable",
    "ConsentBulkJobsCompositionError",
    "ConsentBulkJobsRuntime",
    "ConsentBulkJobsSettings",
    "build_consent_bulk_jobs_runtime",
    "consent_bulk_jobs_enabled",
    "consent_bulk_jobs_settings",
    "expected_principal_ref",
    "install_consent_bulk_jobs_composition",
    "settings_for_tenant",
]
