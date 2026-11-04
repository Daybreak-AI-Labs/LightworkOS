"""Stock production composition for governed AI-entity tasks.

The strict HTTP API accepts an inventory asset id and exact revision, but it
does not accept tenant, actor, or entity authority.  This module supplies those
server-owned authorities from the tenant's persisted AI inventory and opens a
tenant-local durable task store only after all feature, identity, and readiness
checks have succeeded.

Installation is intentionally lazy and default-off.  It neither opens SQLite
nor reads inventory records.  The stock composition performs no provider
network I/O; live inventory discovery remains the responsibility of the
configured inventory scheduler and connectors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import ai_entity_tasks as tasks
from maverick import ai_inventory as inventory
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .auth import has_global_permission

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TASKS = 1_000_000
_MIN_RETENTION_SECONDS = 3_600
_MAX_RETENTION_SECONDS = 315_360_000
_MIN_AUTHORITY_MAX_AGE_SECONDS = 60
_MAX_AUTHORITY_MAX_AGE_SECONDS = 31_536_000
_DEFAULT_MAX_TASKS = 100_000
_DEFAULT_RETENTION_SECONDS = 31_536_000
_DEFAULT_AUTHORITY_MAX_AGE_SECONDS = 604_800
_CONFIG_KEYS = frozenset(
    {
        "enable",
        "max_tasks",
        "retention_seconds",
        "authority_max_age_seconds",
    }
)


class AIEntityTasksCompositionError(tasks.AIEntityTaskConfigError):
    """A deployment-owned AI-entity task authority is unavailable."""


@dataclass(frozen=True)
class AIEntityTasksCompositionSettings:
    """Validated, exact limits for one admitted tenant configuration."""

    max_tasks: int
    retention_seconds: int
    authority_max_age_seconds: int


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise AIEntityTasksCompositionError(f"{label} is outside its bound")
    return value


def ai_entity_tasks_settings(
    config: Mapping[str, Any],
) -> AIEntityTasksCompositionSettings | None:
    """Return exact settings, ``None`` only for a literal disabled gate."""

    if not isinstance(config, Mapping):
        raise AIEntityTasksCompositionError(
            "AI-entity task configuration is unavailable"
        )
    inventory_section = config.get("ai_inventory")
    if not isinstance(inventory_section, Mapping):
        inventory_section = {}
    section = config.get("ai_entity_tasks")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise AIEntityTasksCompositionError("ai_entity_tasks must be a table")
    unknown = sorted(str(key) for key in section if key not in _CONFIG_KEYS)
    if unknown:
        raise AIEntityTasksCompositionError(
            "ai_entity_tasks contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise AIEntityTasksCompositionError(
            "ai_entity_tasks.enable must be true or false"
        )
    if enabled is not True:
        return None
    if inventory_section.get("enable") is not True:
        raise AIEntityTasksCompositionError(
            "AI-entity tasks require ai_inventory.enable = true"
        )
    return AIEntityTasksCompositionSettings(
        max_tasks=_integer(
            section.get("max_tasks", _DEFAULT_MAX_TASKS),
            "ai_entity_tasks.max_tasks",
            1,
            _MAX_TASKS,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "ai_entity_tasks.retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        ),
        authority_max_age_seconds=_integer(
            section.get(
                "authority_max_age_seconds",
                _DEFAULT_AUTHORITY_MAX_AGE_SECONDS,
            ),
            "ai_entity_tasks.authority_max_age_seconds",
            _MIN_AUTHORITY_MAX_AGE_SECONDS,
            _MAX_AUTHORITY_MAX_AGE_SECONDS,
        ),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIEntityTasksCompositionError(
            "AI-entity task configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise AIEntityTasksCompositionError(
            "AI-entity task configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> AIEntityTasksCompositionSettings:
    settings = ai_entity_tasks_settings(_load_tenant_config(tenant_id))
    if settings is None:
        raise AIEntityTasksCompositionError("AI-entity tasks are disabled")
    return settings


def ai_entity_tasks_enabled(tenant_id: str) -> bool:
    """Side-effect-free tenant gate used by the API's disabled status path."""

    try:
        return ai_entity_tasks_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _clock_for(app: Any) -> Callable[[], float]:
    configured = getattr(app.state, "ai_entity_tasks_clock", None)
    if configured is None:
        configured = time.time
    if not callable(configured):
        raise AIEntityTasksCompositionError("AI-entity task clock is unavailable")

    def read() -> float:
        try:
            value = configured()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIEntityTasksCompositionError(
                "AI-entity task clock is unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise AIEntityTasksCompositionError(
                "AI-entity task clock is unavailable"
            )
        return float(value)

    return read


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request):
        raise AIEntityTasksCompositionError(
            "AI-entity task request authority is unavailable"
        )
    try:
        owner = request.app
    except Exception as exc:
        raise AIEntityTasksCompositionError(
            "AI-entity task request authority is unavailable"
        ) from exc
    if owner is not app:
        raise AIEntityTasksCompositionError(
            "AI-entity task request authority is unavailable"
        )
    return request


def _principal_ref_from_request(request: Request, tenant_id: str) -> str:
    """Independently reproduce the API's opaque tenant-bound principal ref."""

    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if (
        not isinstance(subject, str)
        or not subject.strip()
        or len(subject) > 512
    ):
        raise tasks.AIEntityTaskPermissionDenied(
            "authenticated principal authority is unavailable"
        )
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.ai-entity-task.identity.v1:{tenant}:{subject.strip()}".encode()
    ).hexdigest()
    return f"ai-task-principal-{digest[:32]}"


def _default_principal_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> Callable[[], str]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    if not isinstance(principal_ref, str) or not principal_ref:
        raise tasks.AIEntityTaskPermissionDenied(
            "authenticated principal authority is unavailable"
        )
    expected = _principal_ref_from_request(selected_request, tenant)
    if not hmac.compare_digest(principal_ref, expected):
        raise tasks.AIEntityTaskPermissionDenied(
            "authenticated principal authority is unavailable"
        )

    def resolve() -> str:
        current = _principal_ref_from_request(selected_request, tenant)
        if not hmac.compare_digest(current, expected):
            raise tasks.AIEntityTaskPermissionDenied(
                "authenticated principal authority changed"
            )
        return expected

    return resolve


def _default_maintenance_authorizer_factory(
    app: Any,
    *,
    tenant_id: str,
    request: object,
) -> Callable[[], bool]:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)

    def authorize() -> bool:
        # Revalidate both the request owner and the tenant identity at the
        # destructive operation, rather than freezing an earlier role result.
        _request_for(app, selected_request)
        canonical_tenant_id(tenant)
        try:
            return has_global_permission(selected_request, "admin") is True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise tasks.AIEntityTaskPermissionDenied(
                "maintenance authority is unavailable"
            ) from exc

    return authorize


def _canonical_sha256(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise tasks.AIEntityTaskConflict(
            "AI inventory entity authority is unavailable"
        ) from exc
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _text(
    projection: Mapping[str, Any],
    key: str,
    *,
    maximum: int,
) -> str:
    value = projection.get(key)
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise tasks.AIEntityTaskConflict(
            "AI inventory entity authority is unavailable"
        )
    return value


def _digest(projection: Mapping[str, Any], key: str) -> str:
    value = _text(projection, key, maximum=64)
    if _HEX_DIGEST.fullmatch(value) is None:
        raise tasks.AIEntityTaskConflict(
            "AI inventory entity authority is unavailable"
        )
    return value


def _positive_integer(
    projection: Mapping[str, Any],
    key: str,
    *,
    maximum: int = 2_147_483_647,
) -> int:
    value = projection.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise tasks.AIEntityTaskConflict(
            "AI inventory entity authority is unavailable"
        )
    return value


def _positive_time(projection: Mapping[str, Any], key: str) -> float:
    value = projection.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise tasks.AIEntityTaskConflict(
            "AI inventory entity authority is unavailable"
        )
    return float(value)


class InventoryEntityAuthorityResolver:
    """Resolve one exact, current persisted inventory asset authority."""

    def __init__(
        self,
        app: Any,
        *,
        tenant_id: str,
        settings: AIEntityTasksCompositionSettings,
        request: object,
        clock: Callable[[], float],
    ) -> None:
        self._app = app
        self._tenant_id = canonical_tenant_id(tenant_id)
        self._settings = settings
        self._request = _request_for(app, request)
        self._clock = clock

    def _revoked(self, projection: Mapping[str, Any]) -> bool:
        probe = getattr(
            self._app.state,
            "ai_entity_tasks_entity_revocation_probe",
            None,
        )
        if probe is None:
            return False
        if not callable(probe):
            raise AIEntityTasksCompositionError(
                "AI inventory revocation authority is unavailable"
            )
        try:
            result = probe(
                tenant_id=self._tenant_id,
                entity=dict(projection),
                request=self._request,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIEntityTasksCompositionError(
                "AI inventory revocation authority is unavailable"
            ) from exc
        if type(result) is not bool:
            raise AIEntityTasksCompositionError(
                "AI inventory revocation authority is unavailable"
            )
        return result

    def __call__(
        self,
        tenant_id: str,
        entity_id: str,
        entity_revision: int,
    ) -> tasks.AIEntityAuthority:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self._tenant_id:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            )
        if not isinstance(entity_id, str) or not entity_id:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            )
        if (
            isinstance(entity_revision, bool)
            or not isinstance(entity_revision, int)
            or entity_revision < 1
        ):
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            )
        try:
            with tenant_scope(tenant=tenant):
                rows = inventory.list_discovered_assets()
        except tasks.AIEntityTaskError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            ) from exc
        if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            )
        selected = [
            row
            for row in rows
            if isinstance(row, Mapping) and row.get("asset_id") == entity_id
        ]
        if len(selected) != 1:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is unavailable"
            )
        projection = selected[0]
        revision = _positive_integer(projection, "revision")
        if revision != entity_revision:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity revision changed"
            )
        status = _text(projection, "status", maximum=16)
        if status != "present" or self._revoked(projection):
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is revoked"
            )
        entity_type = _text(projection, "asset_type", maximum=64)
        connector = _text(projection, "connector", maximum=64)
        source = _text(projection, "source", maximum=64)
        source_id = _text(projection, "source_id", maximum=256)
        version_digest = _digest(projection, "version_digest")
        observation_revision = _positive_integer(
            projection,
            "observation_revision",
        )
        observation_snapshot_sha256 = _digest(
            projection,
            "observation_snapshot_sha256",
        )
        issued_at = _positive_time(projection, "updated_at")
        now = self._clock()
        valid_until = issued_at + self._settings.authority_max_age_seconds
        if issued_at > now or now >= valid_until:
            raise tasks.AIEntityTaskConflict(
                "AI inventory entity authority is stale"
            )
        issuer_digest = _canonical_sha256(
            {
                "schema": "lightwork.ai-entity-task.inventory-issuer.v1",
                "tenant_id": tenant,
                "asset_id": entity_id,
                "asset_revision": revision,
                "asset_type": entity_type,
                "connector": connector,
                "source": source,
                "source_id": source_id,
                "version_digest": version_digest,
                "observation_revision": observation_revision,
                "observation_snapshot_sha256": observation_snapshot_sha256,
                "issued_at": issued_at,
            }
        )
        return tasks.issue_entity_authority(
            tenant_id=tenant,
            entity_id=entity_id,
            entity_revision=revision,
            entity_type=entity_type,
            issuer_ref=f"ai-inventory:{issuer_digest}",
            issued_at=issued_at,
            valid_until=valid_until,
            revoked=False,
        )


def _default_authority_resolver_factory(
    app: Any,
    *,
    tenant_id: str,
    settings: AIEntityTasksCompositionSettings,
    request: object,
) -> InventoryEntityAuthorityResolver:
    return InventoryEntityAuthorityResolver(
        app,
        tenant_id=tenant_id,
        settings=settings,
        request=request,
        clock=_clock_for(app),
    )


def _default_store_path_factory(
    *,
    tenant_id: str,
    request: object,
) -> Path:
    del request
    tenant = canonical_tenant_id(tenant_id)
    return data_dir(
        "ai_entity_tasks",
        "ai-entity-tasks.sqlite3",
        tenant=tenant,
    )


def _factory_result(
    app: Any,
    *,
    state_name: str,
    unavailable: str,
    kwargs: Mapping[str, Any],
) -> object:
    factory = getattr(app.state, state_name, None)
    if not callable(factory):
        raise AIEntityTasksCompositionError(unavailable)
    try:
        return factory(**dict(kwargs))
    except tasks.AIEntityTaskError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIEntityTasksCompositionError(unavailable) from exc


def _build_store(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> tasks.AIEntityTaskStore:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    common = {
        "tenant_id": tenant,
        "request": selected_request,
    }
    principal_resolver = _factory_result(
        app,
        state_name="ai_entity_tasks_principal_resolver_factory",
        unavailable="AI-entity task principal authority is unavailable",
        kwargs={**common, "principal_ref": principal_ref},
    )
    maintenance_authorizer = _factory_result(
        app,
        state_name="ai_entity_tasks_maintenance_authorizer_factory",
        unavailable="AI-entity task maintenance authority is unavailable",
        kwargs=common,
    )
    authority_resolver = _factory_result(
        app,
        state_name="ai_entity_tasks_entity_authority_resolver_factory",
        unavailable="AI inventory entity authority is unavailable",
        kwargs={**common, "settings": settings},
    )
    path = _factory_result(
        app,
        state_name="ai_entity_tasks_store_path_factory",
        unavailable="AI-entity task storage path is unavailable",
        kwargs=common,
    )
    if not all(
        callable(value)
        for value in (principal_resolver, maintenance_authorizer, authority_resolver)
    ):
        raise AIEntityTasksCompositionError(
            "AI-entity task runtime authorities are unavailable"
        )
    if not isinstance(path, (str, Path)):
        raise AIEntityTasksCompositionError(
            "AI-entity task storage path is unavailable"
        )

    def config_gate() -> None:
        current = settings_for_tenant(tenant)
        if current != settings:
            raise AIEntityTasksCompositionError(
                "AI-entity task configuration changed during admission"
            )

    return tasks.AIEntityTaskStore(
        Path(path),
        tenant_id=tenant,
        entity_authority_resolver=authority_resolver,  # type: ignore[arg-type]
        principal_resolver=principal_resolver,  # type: ignore[arg-type]
        maintenance_authorizer=maintenance_authorizer,  # type: ignore[arg-type]
        config_gate=config_gate,
        retention_seconds=settings.retention_seconds,
        max_tasks=settings.max_tasks,
        clock=_clock_for(app),
    )


def install_ai_entity_tasks_composition(  # noqa: C901 - one closed seam installation
    app: Any,
) -> None:
    """Install every strict API seam without opening tenant state."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "ai_entity_tasks_composition_installed"
    if getattr(state, marker, False):
        return

    deployment_enabled_probe = getattr(state, "ai_entity_tasks_enabled_probe", None)
    deployment_readiness_probe = getattr(
        state,
        "ai_entity_tasks_readiness_probe",
        None,
    )
    if deployment_enabled_probe is not None and not callable(deployment_enabled_probe):
        raise TypeError("AI-entity task enabled probe must be callable")
    if deployment_readiness_probe is not None and not callable(
        deployment_readiness_probe
    ):
        raise TypeError("AI-entity task readiness probe must be callable")

    defaults = {
        "ai_entity_tasks_principal_resolver_factory": (
            lambda **kwargs: _default_principal_resolver_factory(app, **kwargs)
        ),
        "ai_entity_tasks_maintenance_authorizer_factory": (
            lambda **kwargs: _default_maintenance_authorizer_factory(app, **kwargs)
        ),
        "ai_entity_tasks_entity_authority_resolver_factory": (
            lambda **kwargs: _default_authority_resolver_factory(app, **kwargs)
        ),
        "ai_entity_tasks_store_path_factory": _default_store_path_factory,
    }
    for name, value in defaults.items():
        existing = getattr(state, name, None)
        if existing is not None and not callable(existing):
            raise TypeError(f"{name} must be callable")
        if existing is None:
            setattr(state, name, value)

    if getattr(state, "ai_entity_tasks_store_factory", None) is None:

        def store_factory(
            *,
            tenant_id: str,
            principal_ref: str,
            request: object,
        ) -> tasks.AIEntityTaskStore:
            return _build_store(
                app,
                tenant_id=tenant_id,
                principal_ref=principal_ref,
                request=request,
            )

        state.ai_entity_tasks_store_factory = store_factory
    elif not callable(state.ai_entity_tasks_store_factory):
        raise TypeError("AI-entity task store factory must be callable")

    def enabled_probe(tenant_id: str) -> bool:
        try:
            base = ai_entity_tasks_enabled(tenant_id)
            if base is not True:
                return False
            if callable(deployment_enabled_probe):
                return deployment_enabled_probe(tenant_id) is True
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    def readiness_probe(tenant_id: str) -> bool:
        try:
            tenant = canonical_tenant_id(tenant_id)
            if enabled_probe(tenant) is not True:
                return False
            settings_for_tenant(tenant)
            with tenant_scope(tenant=tenant):
                inventory_ready = inventory.enabled()
            required = (
                "ai_entity_tasks_store_factory",
                "ai_entity_tasks_principal_resolver_factory",
                "ai_entity_tasks_maintenance_authorizer_factory",
                "ai_entity_tasks_entity_authority_resolver_factory",
                "ai_entity_tasks_store_path_factory",
            )
            if inventory_ready is not True or not all(
                callable(getattr(state, name, None)) for name in required
            ):
                return False
            _clock_for(app)()
            if callable(deployment_readiness_probe):
                return deployment_readiness_probe(tenant) is True
            return True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    state.ai_entity_tasks_enabled_probe = enabled_probe
    state.ai_entity_tasks_readiness_probe = readiness_probe
    setattr(state, marker, True)


__all__ = [
    "AIEntityTasksCompositionError",
    "AIEntityTasksCompositionSettings",
    "InventoryEntityAuthorityResolver",
    "ai_entity_tasks_enabled",
    "ai_entity_tasks_settings",
    "install_ai_entity_tasks_composition",
    "settings_for_tenant",
]
