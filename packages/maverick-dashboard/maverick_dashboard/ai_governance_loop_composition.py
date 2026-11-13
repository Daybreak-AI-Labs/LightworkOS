"""Fail-closed dashboard composition for the AI-governance control loop.

The core coordinator deliberately knows nothing about dashboard identity,
tenant discovery, HTTP requests, or deployment configuration.  This module
binds those concerns without creating a second authority.  Inventory, risk,
policy, enforcement, and evidence remain source-owned and can be read only
through a deployment-injected ``GovernanceAuthorityReader`` factory.

Trigger ingestion is intentionally a server-only callback.  The dashboard API
never accepts triggers, authority snapshots, telemetry, provider selectors, or
credentials.  Human operations are committed to the authenticated server
principal before being passed to the digest-only core store.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from maverick import ai_governance_loop as loop
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

_SECTION_KEYS = frozenset(
    {
        "enable",
        "poll_seconds",
        "batch_size",
        "lease_seconds",
        "max_attempts",
        "retry_base_seconds",
        "max_lag_seconds",
    }
)
_DEPENDENCIES = (
    "ai_inventory",
    "ai_dynamic_risk",
    "ai_policy_management",
    "ai_runtime_guardrails",
)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class AIGovernanceLoopCompositionError(loop.AIGovernanceLoopError, ValueError):
    """The deployment cannot construct a safe tenant-bound runtime."""


@dataclass(frozen=True, slots=True)
class AIGovernanceLoopSettings:
    """Closed, bounded settings admitted from ``[ai_governance_loop]``."""

    poll_seconds: int = 300
    batch_size: int = 100
    lease_seconds: int = 120
    max_attempts: int = 5
    retry_base_seconds: int = 30
    max_lag_seconds: int = 900


@dataclass(frozen=True, slots=True)
class AIGovernanceLoopBatchResult:
    """Digest-safe bounded worker outcome used by the tenant scheduler."""

    processed: int
    failed: int
    no_change: int
    idle: bool


@runtime_checkable
class UnifiedAuditProjectionSink(Protocol):
    """Optional deployment seam for the source-owned unified-audit chain."""

    def __call__(
        self,
        *,
        tenant_id: str,
        source_id: str,  # noqa: F841 - protocol keyword is part of the seam
        events: tuple[loop.UnifiedAuditProjectionEvent, ...],  # noqa: F841
    ) -> None: ...


@runtime_checkable
class GovernanceAuthorityReaderFactory(Protocol):
    """Deployment-owned resolver for the six authoritative source projections."""

    def __call__(
        self,
        *,
        tenant_id: str,
        principal_ref: str,
        request: Any | None,
    ) -> loop.GovernanceAuthorityReader: ...


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AIGovernanceLoopCompositionError(f"{label} is outside its bound")
    return value


def _enabled(table: Mapping[str, Any], label: str) -> bool:
    value = table.get("enable", False)
    if type(value) is not bool:
        raise AIGovernanceLoopCompositionError(f"{label}.enable must be boolean")
    return value


def _table(config: Mapping[str, Any], key: str, label: str) -> Mapping[str, Any] | None:
    value = config.get(key)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise AIGovernanceLoopCompositionError(f"{label} must be a table")
    return value


def governance_loop_settings(config: object) -> AIGovernanceLoopSettings | None:
    """Parse the exact opt-in gate and its bounded runtime settings.

    Missing configuration is disabled.  An explicitly enabled loop requires
    all four source capabilities to be explicitly enabled as well; malformed
    or unknown material fails closed instead of falling back to truthiness.
    """

    if not isinstance(config, Mapping):
        raise AIGovernanceLoopCompositionError("configuration must be a table")
    section = _table(config, "ai_governance_loop", "ai_governance_loop")
    if section is None:
        return None
    unknown = set(section) - _SECTION_KEYS
    if unknown:
        raise AIGovernanceLoopCompositionError("ai_governance_loop key is unsupported")
    if not _enabled(section, "ai_governance_loop"):
        return None
    for dependency in _DEPENDENCIES:
        dependency_table = _table(config, dependency, dependency)
        if dependency_table is None or not _enabled(dependency_table, dependency):
            raise AIGovernanceLoopCompositionError(
                f"ai_governance_loop requires enabled {dependency}"
            )
    return AIGovernanceLoopSettings(
        poll_seconds=_integer(
            section.get("poll_seconds", 300),
            "ai_governance_loop.poll_seconds",
            5,
            3_600,
        ),
        batch_size=_integer(
            section.get("batch_size", 100),
            "ai_governance_loop.batch_size",
            1,
            500,
        ),
        # The core's fenced lease contract caps a lease at one hour.  Config
        # that exceeds the implemented safety bound is rejected here even if a
        # more permissive generic linter admitted it.
        lease_seconds=_integer(
            section.get("lease_seconds", 120),
            "ai_governance_loop.lease_seconds",
            30,
            3_600,
        ),
        max_attempts=_integer(
            section.get("max_attempts", 5),
            "ai_governance_loop.max_attempts",
            1,
            20,
        ),
        retry_base_seconds=_integer(
            section.get("retry_base_seconds", 30),
            "ai_governance_loop.retry_base_seconds",
            1,
            86_400,
        ),
        max_lag_seconds=_integer(
            section.get("max_lag_seconds", 900),
            "ai_governance_loop.max_lag_seconds",
            1,
            31_536_000,
        ),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    """Load one tenant snapshot and reject any ambiguous source state."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIGovernanceLoopCompositionError(
            "ai-governance-loop configuration is unavailable"
        ) from exc
    if source_errors:
        raise AIGovernanceLoopCompositionError("ai-governance-loop configuration source is invalid")
    if not isinstance(config, Mapping):
        raise AIGovernanceLoopCompositionError("ai-governance-loop configuration is unavailable")
    return config


def ai_governance_loop_capability_enabled(tenant_id: str) -> bool:
    """Side-effect-free gate probe used by the disabled API status path."""

    try:
        return governance_loop_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AIGovernanceLoopCompositionError(
            "ai-governance-loop commitment is not canonical"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise loop.AIGovernanceLoopValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise loop.AIGovernanceLoopValidationError(f"{label} must be a bounded opaque identifier")
    return value


class DashboardAIGovernanceLoopRuntime:
    """Principal-bound operations over one tenant's core coordinator/store."""

    __slots__ = (
        "coordinator",
        "principal_ref",
        "settings",
        "store",
        "tenant_id",
        "_projection_sink",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        principal_ref: str,
        store: loop.AIGovernanceLoopStore,
        coordinator: loop.AIGovernanceLoopCoordinator,
        settings: AIGovernanceLoopSettings,
        projection_sink: UnifiedAuditProjectionSink | None = None,
    ) -> None:
        tenant = canonical_tenant_id(tenant_id)
        principal = _ref(principal_ref, "principal_ref")
        if not isinstance(store, loop.AIGovernanceLoopStore) or store.tenant_id != tenant:
            raise AIGovernanceLoopCompositionError(
                "ai-governance-loop store tenant binding is invalid"
            )
        if (
            not isinstance(coordinator, loop.AIGovernanceLoopCoordinator)
            or coordinator.store is not store
        ):
            raise AIGovernanceLoopCompositionError(
                "ai-governance-loop coordinator binding is invalid"
            )
        if not isinstance(settings, AIGovernanceLoopSettings):
            raise AIGovernanceLoopCompositionError("ai-governance-loop settings are unavailable")
        if projection_sink is not None and not isinstance(
            projection_sink, UnifiedAuditProjectionSink
        ):
            raise AIGovernanceLoopCompositionError("unified-audit projection sink is invalid")
        self.tenant_id = tenant
        self.principal_ref = principal
        self.store = store
        self.coordinator = coordinator
        self.settings = settings
        self._projection_sink = projection_sink

    def _principal_commitment(
        self,
        action: str,
        asset_id: str,
        reason_sha256: str,
        **fields: object,
    ) -> str:
        return _canonical_sha256(
            {
                "schema": "lightwork.ai-governance-loop-human-control.v1",
                "tenant_id": self.tenant_id,
                "principal_ref": self.principal_ref,
                "action": _ref(action, "action"),
                "asset_id": _ref(asset_id, "asset_id"),
                "reason_sha256": _digest(reason_sha256, "reason_sha256"),
                **fields,
            }
        )

    def _operation_key(self, operation_id: str, action: str) -> str:
        operation = _ref(operation_id, "operation_id")
        digest = _canonical_sha256(
            {
                "schema": "lightwork.ai-governance-loop-operation-key.v1",
                "tenant_id": self.tenant_id,
                "principal_ref": self.principal_ref,
                "action": action,
                "operation_id": operation,
            }
        )
        return f"dashboard-{digest}"

    def _project(self) -> None:
        if self._projection_sink is None:
            return
        self._projection_sink(
            tenant_id=self.tenant_id,
            source_id=loop.SOURCE_ID,
            events=self.store.unified_audit_events(),
        )

    def status(self) -> dict[str, object]:
        return {
            "schema": "lightwork.ai-governance-loop-runtime-status.v1",
            "enabled": True,
            "tenant_bound": True,
            "principal_bound": True,
            "authority_reader_injected": True,
            "server_trigger_callback_available": True,
            "http_trigger_ingestion_available": False,
            "raw_telemetry_accepted": False,
            "provider_selector_accepted": False,
            "provider_mutation_performed": False,
            "unified_audit_projection_available": self._projection_sink is not None,
            "live_provider_acceptance_verified": False,
            "live_customer_acceptance_verified": False,
            "settings": asdict(self.settings),
        }

    def get_case(self, asset_id: str) -> dict[str, object]:
        result = self.store.get_case(_ref(asset_id, "asset_id"))
        if result is None:
            raise loop.AIGovernanceLoopNotFound("case does not exist")
        return result

    def history(self, asset_id: str, *, limit: int) -> tuple[dict[str, object], ...]:
        bounded = _integer(limit, "history limit", 1, 1_000)
        self.get_case(asset_id)
        return self.store.history(asset_id, limit=bounded)

    def verify_integrity(self, asset_id: str) -> dict[str, object]:
        return self.store.verify_integrity(_ref(asset_id, "asset_id"))

    def ingest_server_trigger(
        self,
        trigger: loop.GovernanceTrigger,
        *,
        operation_id: str,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        """Accept one already-normalized source callback; never exposed by HTTP."""

        if type(trigger) is not loop.GovernanceTrigger:
            raise loop.AIGovernanceLoopValidationError(
                "server trigger must use the closed GovernanceTrigger contract"
            )
        result = self.store.enqueue(
            trigger,
            idempotency_key=self._operation_key(operation_id, "server-trigger"),
            expected_revision=expected_revision,
        )
        self._project()
        return result

    def discover_sources(self, *, limit: int, after: str = "") -> str:
        from .ai_governance_native_sources import NativeAuthorityReader, produce

        if not isinstance(self.coordinator.authority_reader, NativeAuthorityReader):
            return after
        return produce(self, limit=limit, after=after)

    def run_batch(self, *, worker_id: str, limit: int) -> AIGovernanceLoopBatchResult:
        bounded = _integer(limit, "worker batch limit", 1, 500)
        processed = 0
        failed = 0
        no_change = 0
        idle = False
        for _ in range(bounded):
            try:
                result = self.coordinator.run_once(worker_id=_ref(worker_id, "worker_id"))
            except (
                loop.AIGovernanceLoopAuthorityDrift,
                loop.AIGovernanceLoopConflict,
                loop.AIGovernanceLoopLeaseLost,
                loop.AIGovernanceLoopValidationError,
            ):
                failed += 1
                continue
            if result is None:
                idle = True
                break
            processed += 1
            if result.get("no_change") is True:
                no_change += 1
            self._project()
        return AIGovernanceLoopBatchResult(
            processed=processed,
            failed=failed,
            no_change=no_change,
            idle=idle,
        )

    def authorize_control(
        self,
        asset_id: str,
        *,
        decision: str,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        authorization = self._principal_commitment(
            "authorize-control",
            asset_id,
            reason_sha256,
            decision=decision,
            expected_revision=expected_revision,
        )
        result = self.store.authorize_control(
            asset_id,
            decision=decision,
            authorization_sha256=authorization,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "authorize-control"),
        )
        self._project()
        return result

    def revoke_control_authorization(
        self,
        asset_id: str,
        *,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        revocation = self._principal_commitment(
            "revoke-control-authorization",
            asset_id,
            reason_sha256,
            expected_revision=expected_revision,
        )
        result = self.store.revoke_control_authorization(
            asset_id,
            revocation_sha256=revocation,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "revoke-control-authorization"),
        )
        self._project()
        return result

    def replay(
        self,
        asset_id: str,
        *,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        authorization = self._principal_commitment(
            "replay",
            asset_id,
            reason_sha256,
            expected_revision=expected_revision,
        )
        result = self.store.replay(
            asset_id,
            authorization_sha256=authorization,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "replay"),
        )
        self._project()
        return result

    def authorize_rollback(
        self,
        asset_id: str,
        *,
        target_revision: int,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        authorization = self._principal_commitment(
            "authorize-rollback",
            asset_id,
            reason_sha256,
            expected_revision=expected_revision,
            target_revision=target_revision,
        )
        result = self.store.authorize_rollback(
            asset_id,
            target_revision=target_revision,
            authorization_sha256=authorization,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "authorize-rollback"),
        )
        self._project()
        return result

    def revoke_rollback_authorization(
        self,
        asset_id: str,
        *,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        revocation = self._principal_commitment(
            "revoke-rollback-authorization",
            asset_id,
            reason_sha256,
            expected_revision=expected_revision,
        )
        result = self.store.revoke_rollback_authorization(
            asset_id,
            revocation_sha256=revocation,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "revoke-rollback-authorization"),
        )
        self._project()
        return result

    def apply_authorized_rollback(
        self,
        asset_id: str,
        *,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        current = self.get_case(asset_id)
        authorization = current.get("rollback_authorization_sha256")
        if not isinstance(authorization, str):
            raise loop.AIGovernanceLoopConflict("rollback authorization is not active")
        result = self.store.apply_authorized_rollback(
            asset_id,
            authorization_sha256=authorization,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "apply-rollback"),
        )
        self._project()
        return result

    def revoke_case(
        self,
        asset_id: str,
        *,
        reason_sha256: str,
        expected_revision: int,
        operation_id: str,
    ) -> dict[str, object]:
        revocation = self._principal_commitment(
            "revoke-case",
            asset_id,
            reason_sha256,
            expected_revision=expected_revision,
        )
        result = self.store.revoke_case(
            asset_id,
            revocation_sha256=revocation,
            expected_revision=expected_revision,
            idempotency_key=self._operation_key(operation_id, "revoke-case"),
        )
        self._project()
        return result


def build_ai_governance_loop_runtime(
    *,
    tenant_id: str,
    principal_ref: str,
    authority_reader_factory: GovernanceAuthorityReaderFactory,
    config: Mapping[str, Any],
    request: Any | None = None,
    store_path: str | Path | None = None,
    projection_sink: UnifiedAuditProjectionSink | None = None,
    clock: Callable[[], float] = time.time,
) -> DashboardAIGovernanceLoopRuntime:
    """Construct a runtime only from explicit config and injected authority."""

    settings = governance_loop_settings(config)
    if settings is None:
        raise AIGovernanceLoopCompositionError("ai_governance_loop_disabled")
    tenant = canonical_tenant_id(tenant_id)
    principal = _ref(principal_ref, "principal_ref")
    if not isinstance(authority_reader_factory, GovernanceAuthorityReaderFactory):
        raise AIGovernanceLoopCompositionError(
            "ai-governance-loop authority-reader factory is unavailable"
        )
    try:
        reader = authority_reader_factory(
            tenant_id=tenant,
            principal_ref=principal,
            request=request,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIGovernanceLoopCompositionError(
            "ai-governance-loop authority reader is unavailable"
        ) from exc
    if not isinstance(reader, loop.GovernanceAuthorityReader):
        raise AIGovernanceLoopCompositionError("ai-governance-loop authority reader is unavailable")
    selected_path = (
        Path(store_path)
        if store_path is not None
        else data_dir(
            "ai_governance",
            "governance-loop.sqlite3",
            tenant=tenant,
        )
    )
    # The exact tenant config was independently admitted above.  Bypass only
    # the core's ambient config lookup so this immutable snapshot cannot race
    # a second read during construction.
    store = loop.AIGovernanceLoopStore(
        selected_path,
        tenant_id=tenant,
        config_gate=lambda: None,
        clock=clock,
    )
    coordinator = loop.AIGovernanceLoopCoordinator(
        store=store,
        authority_reader=reader,
        lease_seconds=settings.lease_seconds,
        max_attempts=settings.max_attempts,
        backoff_base_seconds=settings.retry_base_seconds,
    )
    return DashboardAIGovernanceLoopRuntime(
        tenant_id=tenant,
        principal_ref=principal,
        store=store,
        coordinator=coordinator,
        settings=settings,
        projection_sink=projection_sink,
    )


def _runtime_from_app(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: Any | None,
) -> DashboardAIGovernanceLoopRuntime:
    state = getattr(app, "state", None)
    if state is None:
        raise AIGovernanceLoopCompositionError("dashboard app state is unavailable")
    reader_factory = getattr(
        state,
        "ai_governance_loop_authority_reader_factory",
        None,
    )
    if not isinstance(reader_factory, GovernanceAuthorityReaderFactory):
        raise AIGovernanceLoopCompositionError(
            "ai-governance-loop authority-reader factory is unavailable"
        )
    projection_sink = getattr(state, "ai_governance_loop_audit_projection_sink", None)
    if projection_sink is not None and not isinstance(projection_sink, UnifiedAuditProjectionSink):
        raise AIGovernanceLoopCompositionError("unified-audit projection sink is invalid")
    return build_ai_governance_loop_runtime(
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        authority_reader_factory=reader_factory,
        config=_load_tenant_config(tenant_id),
        request=request,
        projection_sink=projection_sink,
    )


def install_ai_governance_loop_composition(app: Any) -> None:
    """Install lazy API/scheduler/server-trigger factories on an ASGI app.

    No store is opened and no authority is read at install time.  A deployment
    may replace ``ai_governance_loop_authority_reader_factory`` with its own
    validated source adapter; the default reads the native retained authorities.
    The enabled probe and the runtime, worker and trigger-callback factories
    are likewise kept when a deployment set them before this runs.
    """

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "ai_governance_loop_composition_installed"
    if getattr(state, marker, False):
        return

    def runtime_factory(tenant_id: str, principal_ref: str, request: Any):
        return _runtime_from_app(
            app,
            tenant_id=tenant_id,
            principal_ref=principal_ref,
            request=request,
        )

    def worker_factory(tenant_id: str, principal_ref: str):
        return _runtime_from_app(
            app,
            tenant_id=tenant_id,
            principal_ref=principal_ref,
            request=None,
        )

    def trigger_callback_factory(source_ref: str):
        source = _ref(source_ref, "source_ref")
        principal = f"governance-source-{_canonical_sha256(source)[:32]}"

        def callback(
            trigger: loop.GovernanceTrigger,
            *,
            operation_id: str,
            expected_revision: int | None = None,
        ) -> dict[str, object]:
            runtime = _runtime_from_app(
                app,
                tenant_id=trigger.tenant_id,
                principal_ref=principal,
                request=None,
            )
            return runtime.ingest_server_trigger(
                trigger,
                operation_id=operation_id,
                expected_revision=expected_revision,
            )

        return callback

    if getattr(state, "ai_governance_loop_authority_reader_factory", None) is None:
        from .ai_governance_native_sources import factory

        state.ai_governance_loop_authority_reader_factory = factory

    for name, default in (
        ("ai_governance_loop_enabled_probe", ai_governance_loop_capability_enabled),
        ("ai_governance_loop_runtime_factory", runtime_factory),
        ("ai_governance_loop_worker_factory", worker_factory),
        ("ai_governance_loop_trigger_callback_factory", trigger_callback_factory),
    ):
        if getattr(state, name, None) is None:
            setattr(state, name, default)
    setattr(state, marker, True)


__all__ = [
    "AIGovernanceLoopBatchResult",
    "AIGovernanceLoopCompositionError",
    "AIGovernanceLoopSettings",
    "DashboardAIGovernanceLoopRuntime",
    "GovernanceAuthorityReaderFactory",
    "UnifiedAuditProjectionSink",
    "ai_governance_loop_capability_enabled",
    "build_ai_governance_loop_runtime",
    "governance_loop_settings",
    "install_ai_governance_loop_composition",
]
