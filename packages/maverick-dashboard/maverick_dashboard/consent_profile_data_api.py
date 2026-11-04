"""Governed dashboard integration for custom profile data and prompt journeys.

The operator router is tenant-scoped and derives every durable actor from the
authenticated request.  Public helpers in this module derive opaque catalog
and journey identifiers from an exact published consent configuration; no
public caller chooses those authorities.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from maverick import consent_storage
from maverick.file_lock import ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id
from maverick.sqlite_closing import ClosingConnection
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_ID_RE = re.compile(_ID_PATTERN.removeprefix("^").removesuffix("$"))
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DAY = 24 * 60 * 60
_MAX_JSON_BYTES = 512 * 1024
_ASSIGNMENT_SCHEMA = 1
_ASSIGNMENT_KEY_CAPABILITY = "lightwork.consent-profile-assignments.v1"


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("profile-data material must be canonical JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise ValueError("profile-data material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a bounded opaque identifier")
    return value


def _strict_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def public_profile_data_ids(
    *,
    tenant_id: str,
    property_id: str,
    publication_sha256: str,
    bundle_sha256: str,
    configuration_sha256: str,
    policy_id: str,
    policy_version: int,
    policy_sha256: str,
) -> tuple[str, str]:
    """Derive non-selectable v1 catalog/journey IDs for one exact contract."""

    tenant = canonical_tenant_id(tenant_id)
    if tenant != tenant_id:
        raise ValueError("tenant_id must already be canonical")
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise ValueError("policy_version is invalid")
    if not 1 <= policy_version <= 1_000_000:
        raise ValueError("policy_version is invalid")
    binding = {
        "tenant_id": tenant,
        "property_id": _strict_id(property_id, "property_id"),
        "publication_sha256": _strict_digest(publication_sha256, "publication_sha256"),
        "bundle_sha256": _strict_digest(bundle_sha256, "bundle_sha256"),
        "configuration_sha256": _strict_digest(configuration_sha256, "configuration_sha256"),
        "policy_id": _strict_id(policy_id, "policy_id"),
        "policy_version": policy_version,
        "policy_sha256": _strict_digest(policy_sha256, "policy_sha256"),
    }
    digest = _sha256(binding)
    return f"profile-catalog-{digest[:40]}", f"profile-journey-{digest[:40]}"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class OptionIn(_StrictModel):
    value_id: str = Field(pattern=_ID_PATTERN)
    label_ref: str = Field(pattern=_ID_PATTERN)


class DefinitionIn(_StrictModel):
    preference_id: str = Field(pattern=_ID_PATTERN)
    definition_version: int = Field(ge=1, le=1_000_000)
    label_ref: str = Field(pattern=_ID_PATTERN)
    value_type: Literal["boolean", "single_select", "multi_select"]
    options: list[OptionIn] = Field(default_factory=list, max_length=64)
    required: bool
    expires_after_seconds: int | None = Field(default=None, ge=60, le=2 * 365 * _DAY)
    retention_seconds: int = Field(ge=_DAY, le=5 * 365 * _DAY)


class CatalogCreateIn(_StrictModel):
    catalog_id: str = Field(pattern=_ID_PATTERN)
    property_id: str = Field(pattern=_ID_PATTERN)
    publication_sha256: str = Field(pattern=_DIGEST_PATTERN)
    bundle_sha256: str = Field(pattern=_DIGEST_PATTERN)
    configuration_sha256: str = Field(pattern=_DIGEST_PATTERN)
    policy_id: str = Field(pattern=_ID_PATTERN)
    policy_version: int = Field(ge=1, le=1_000_000)
    policy_sha256: str = Field(pattern=_DIGEST_PATTERN)
    definitions: list[DefinitionIn] = Field(min_length=1, max_length=256)
    retention_seconds: int = Field(ge=_DAY, le=5 * 365 * _DAY)
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: str = Field(pattern=_OP_PATTERN)


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: str = Field(pattern=_OP_PATTERN)


class ConditionIn(_StrictModel):
    source: Literal["preference", "purpose"]
    key: str = Field(pattern=_ID_PATTERN)
    operator: Literal["equals", "contains"]
    value: bool | str | list[str]


class StageIn(_StrictModel):
    stage_id: str = Field(pattern=_ID_PATTERN)
    priority: int = Field(ge=0, le=10_000)
    prompt_label_ref: str = Field(pattern=_ID_PATTERN)
    preference_ids: list[str] = Field(min_length=1, max_length=64)
    condition: ConditionIn | None = None


class JourneyCreateIn(_StrictModel):
    journey_id: str = Field(pattern=_ID_PATTERN)
    catalog_id: str = Field(pattern=_ID_PATTERN)
    catalog_version: int = Field(ge=1, le=1_000_000)
    stages: list[StageIn] = Field(min_length=1, max_length=64)
    max_prompts: int = Field(ge=1, le=10)
    cooldown_seconds: int = Field(ge=60, le=30 * _DAY)
    frequency_cap: int = Field(ge=1, le=100)
    frequency_window_seconds: int = Field(ge=60, le=90 * _DAY)
    retention_seconds: int = Field(ge=_DAY, le=5 * 365 * _DAY)
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: str = Field(pattern=_OP_PATTERN)


class PurgeIn(_StrictModel):
    before: float = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: str = Field(pattern=_OP_PATTERN)


@dataclass(frozen=True)
class ConsentProfileDataAdminDependencies:
    gate: Callable[[], bool] | None = None
    store_for: Callable[[str, str], Any] | None = None
    principal_for: Callable[[Request, str], str] | None = None


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent profile data",
        )
    return tenant


def _default_gate() -> bool:
    try:
        from maverick.consent_profile_data import profile_data_enabled

        return profile_data_enabled()
    except Exception:
        return False


def profile_data_enabled_for_page() -> bool:
    return _default_gate()


def _principal_ref(request: Request, tenant_id: str) -> str:
    from .request_identity import request_actor as _request_actor

    actor = _request_actor(request)
    return (
        "admin-"
        + hashlib.sha256(f"consent-profile-data\0{tenant_id}\0{actor}".encode()).hexdigest()[:48]
    )


def _default_store(tenant_id: str, principal_ref: str) -> Any:
    from maverick.consent_profile_data import ConsentProfileDataStore
    from maverick.paths import data_dir

    return ConsentProfileDataStore(
        data_dir(
            "consent_preferences",
            "consent-profile-data.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
    )


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


async def _call(ops: Any, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ops.ConsentProfileDataConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentProfileDataNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.ConsentProfileDataPermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ops.ConsentProfileDataValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentProfileDataConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ops.ConsentProfileDataIntegrityError as exc:
        raise HTTPException(
            status_code=503,
            detail="consent profile-data authority unavailable",
        ) from exc
    except ops.ConsentProfileDataError as exc:
        raise HTTPException(
            status_code=503,
            detail="consent profile-data authority unavailable",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="consent profile-data authority unavailable",
        ) from exc


def published_contract_for_key(
    tenant_id: str,
    credential_id: str,
    *,
    jurisdiction: str,
    country_code: str,
    locale: str,
) -> dict[str, Any]:
    """Resolve what one website key currently publishes for one audience.

    Read-only: the same exact-contract facts the public endpoint derives, so a
    person picks a key, region and language instead of typing digests.
    Raises ``LookupError`` when the key is unknown and ``ValueError`` when the
    published banner and the key's consent policy no longer agree.
    """
    from . import consent_public_admin_api as admin

    listed = admin._registry().list_clients(tenant_id, limit=500)
    binding = next(
        (item for item in listed["items"] if item.get("credential_id") == credential_id),
        None,
    )
    if binding is None or binding.get("status") != "active":
        raise LookupError("website key not found")
    configuration = admin._publishing_store(tenant_id).resolve_public_configuration(
        tenant_id,
        binding["property_id"],
        server_origin=binding.get("target_origin") or binding.get("browser_origin"),
        server_bundle_id=binding.get("target_bundle_id"),
        server_platform=binding.get("target_platform"),
        jurisdiction=jurisdiction,
        country_code=country_code,
        region_code="",
        requested_locale=locale,
    )
    if not isinstance(configuration, dict) or configuration.get("allowed") is not True:
        raise ValueError("nothing is published for this audience")
    publication = configuration["publication"]
    if publication.get("bundle_sha256") != binding.get("bundle_sha256"):
        raise ValueError("the key no longer matches the published banner")
    policy = admin._preference_store(tenant_id).get_active_policy(
        tenant_id,
        binding["policy_id"],
        at=time.time(),
    )
    if (
        not isinstance(policy, dict)
        or policy.get("version") != binding.get("policy_version")
        or policy.get("policy_sha256") != binding.get("policy_sha256")
    ):
        raise ValueError("the key's consent policy is no longer current")
    catalog_id, journey_id = public_profile_data_ids(
        tenant_id=tenant_id,
        property_id=binding["property_id"],
        publication_sha256=publication["publication_sha256"],
        bundle_sha256=publication["bundle_sha256"],
        configuration_sha256=configuration["configuration_sha256"],
        policy_id=binding["policy_id"],
        policy_version=int(binding["policy_version"]),
        policy_sha256=binding["policy_sha256"],
    )
    content = configuration.get("configuration") or {}
    questions = [
        {
            "preference_id": item["id"],
            "version": item["version"],
            "title": item.get("title", item["id"]),
            "value_type": item["value_type"],
            "required": item["required"],
            "option_ids": list(item.get("option_ids", [])),
        }
        for item in content.get("custom_preferences", [])
        if isinstance(item, Mapping)
    ]
    return {
        "catalog_id": catalog_id,
        "journey_id": journey_id,
        "property_id": binding["property_id"],
        "publication_sha256": publication["publication_sha256"],
        "bundle_sha256": publication["bundle_sha256"],
        "configuration_sha256": configuration["configuration_sha256"],
        "policy_id": binding["policy_id"],
        "policy_version": int(binding["policy_version"]),
        "policy_sha256": binding["policy_sha256"],
        "purposes": [
            {"id": item.get("id"), "title": item.get("title", item.get("id"))}
            for item in content.get("purposes", [])
            if isinstance(item, Mapping)
        ],
        "questions": questions,
    }


def create_consent_profile_data_router(  # noqa: C901 - explicit route assembly
    dependencies: ConsentProfileDataAdminDependencies | None = None,
) -> APIRouter:
    """Create the operator API without mutating global application state."""

    deps = dependencies or ConsentProfileDataAdminDependencies()
    router = APIRouter(prefix="/consent/profile-data", tags=["consent-profile-data"])

    def authority(request: Request) -> tuple[Any, str, Any]:
        from maverick import consent_profile_data as ops

        gate = deps.gate or _default_gate
        try:
            enabled = gate() is True
        except Exception:
            enabled = False
        if not enabled:
            raise HTTPException(
                status_code=403,
                detail=(
                    "consent profile data is disabled ([consent_preferences.profile_data] enable)"
                ),
            )
        tenant = _tenant_id()
        principal = (
            deps.principal_for(request, tenant)
            if deps.principal_for is not None
            else _principal_ref(request, tenant)
        )
        principal = _strict_id(principal, "derived principal")
        if deps.store_for is not None:
            store = deps.store_for(tenant, principal)
        else:
            factory = getattr(
                request.app.state,
                "consent_profile_data_store_factory",
                None,
            )
            if callable(factory):
                store = factory(
                    tenant_id=tenant,
                    principal_resolver=lambda: principal,
                    request=request,
                )
            else:
                store = _default_store(tenant, principal)
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="consent profile-data authority unavailable",
            )
        return ops, tenant, store

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        integrity = await _call(ops, store.verify_integrity, tenant)
        return {
            "enabled": True,
            "tenant_id": tenant,
            "integrity": _jsonable(integrity),
            "product_boundaries": dict(ops.product_boundaries()),
            "public_binding": {
                "catalog_version": 1,
                "journey_version": 1,
                "identifiers": "server-derived from the exact published contract",
            },
        }

    @router.get("/catalogs")
    async def list_catalogs(request: Request, limit: int = Query(100, ge=1, le=500)) -> dict:
        """Read-only list of the active workspace's catalog versions."""
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.list_catalogs, tenant, limit=limit))

    @router.get("/journeys")
    async def list_journeys(request: Request, limit: int = Query(100, ge=1, le=500)) -> dict:
        """Read-only list of the active workspace's journey versions."""
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.list_journeys, tenant, limit=limit))

    @router.get("/contract")
    async def contract(
        request: Request,
        credential_id: str = Query(..., pattern=_ID_PATTERN),
        jurisdiction: str = Query("global", pattern=r"^[a-z0-9][a-z0-9-]{0,63}$"),
        country_code: str = Query("US", pattern=r"^[A-Z]{2}$"),
        locale: str = Query("en-US", pattern=r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$"),
    ) -> dict:
        """Read-only: the published facts a new catalog or journey must bind to."""
        require_permission(request, "operate")
        authority(request)
        from .consent_public_admin_api import _require_enabled

        _require_enabled()
        tenant = _tenant_id()
        try:
            return await run_in_threadpool(
                published_contract_for_key,
                tenant,
                credential_id,
                jurisdiction=jurisdiction,
                country_code=country_code,
                locale=locale,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="website key not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/catalogs", status_code=201)
    async def create_catalog(request: Request, body: CatalogCreateIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        payload = body.model_dump()
        payload["definitions"] = [item.model_dump() for item in body.definitions]
        return _jsonable(await _call(ops, store.create_catalog_version, tenant, **payload))

    @router.get("/catalogs/{catalog_id}/versions/{version}")
    async def get_catalog(request: Request, catalog_id: str, version: int) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.get_catalog_version, tenant, catalog_id, version))

    @router.post("/catalogs/{catalog_id}/versions/{version}/approve")
    async def approve_catalog(
        request: Request,
        catalog_id: str,
        version: int,
        body: RevisionIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await _call(
                ops,
                store.approve_catalog_version,
                tenant,
                catalog_id,
                version,
                **body.model_dump(),
            )
        )

    @router.post("/journeys", status_code=201)
    async def create_journey(request: Request, body: JourneyCreateIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        payload = body.model_dump()
        payload["stages"] = [item.model_dump() for item in body.stages]
        return _jsonable(await _call(ops, store.create_journey_version, tenant, **payload))

    @router.get("/journeys/{journey_id}/versions/{version}")
    async def get_journey(request: Request, journey_id: str, version: int) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.get_journey_version, tenant, journey_id, version))

    async def lifecycle(
        request: Request,
        journey_id: str,
        version: int,
        body: RevisionIn,
        action: str,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        function = (
            store.approve_journey_version
            if action == "approve"
            else getattr(store, f"{action}_journey")
        )
        return _jsonable(
            await _call(
                ops,
                function,
                tenant,
                journey_id,
                version,
                **body.model_dump(),
            )
        )

    @router.post("/journeys/{journey_id}/versions/{version}/approve")
    async def approve_journey(
        request: Request, journey_id: str, version: int, body: RevisionIn
    ) -> dict[str, Any]:
        return await lifecycle(request, journey_id, version, body, "approve")

    @router.post("/journeys/{journey_id}/versions/{version}/activate")
    async def activate_journey(
        request: Request, journey_id: str, version: int, body: RevisionIn
    ) -> dict[str, Any]:
        return await lifecycle(request, journey_id, version, body, "activate")

    @router.post("/journeys/{journey_id}/versions/{version}/pause")
    async def pause_journey(
        request: Request, journey_id: str, version: int, body: RevisionIn
    ) -> dict[str, Any]:
        return await lifecycle(request, journey_id, version, body, "pause")

    @router.post("/journeys/{journey_id}/versions/{version}/kill")
    async def kill_journey(
        request: Request, journey_id: str, version: int, body: RevisionIn
    ) -> dict[str, Any]:
        return await lifecycle(request, journey_id, version, body, "kill")

    @router.post("/journeys/{journey_id}/versions/{version}/rollback")
    async def rollback_journey(
        request: Request, journey_id: str, version: int, body: RevisionIn
    ) -> dict[str, Any]:
        return await lifecycle(request, journey_id, version, body, "rollback")

    @router.get("/integrity")
    async def integrity(request: Request) -> dict[str, Any]:
        require_global_permission(request, "audit")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.verify_integrity, tenant))

    @router.post("/retention/purge")
    async def purge(request: Request, body: PurgeIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(await _call(ops, store.purge_expired, tenant, **body.model_dump()))

    return router


router = create_consent_profile_data_router()


class PublicPromptAssignmentError(RuntimeError):
    """A retained public assignment is absent, mismatched, or already terminal."""


class PublicPromptAssignmentConflict(PublicPromptAssignmentError):
    pass


class PublicPromptAssignmentStore:
    """Private keyed store for server-issued prompt assignments and outcomes."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        key_authority: Any,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.tenant_id = canonical_tenant_id(tenant_id)
        if self.tenant_id != tenant_id:
            raise ValueError("tenant_id must already be canonical")
        key = key_authority.key_for(self.tenant_id, _ASSIGNMENT_KEY_CAPABILITY)
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("prompt assignment key authority is invalid")
        self._key = key
        self._clock = clock
        ensure_private_directory(self.path.parent)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS public_profile_assignments(
                    assignment_id TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_hmac TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO metadata(key,value)
                    VALUES('schema_version','1');
                COMMIT;
                """
            )
        if not consent_storage.shared():
            ensure_private_file(self.path)

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30.0)
        else:
            connection = sqlite3.connect(
                self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _mac(self, payload: Mapping[str, object]) -> str:
        return hmac.new(self._key, _canonical(dict(payload)), hashlib.sha256).hexdigest()

    def _payload(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PublicPromptAssignmentError("retained prompt assignment is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("assignment_id") != row["assignment_id"]
            or payload.get("expires_at") != row["expires_at"]
            or not hmac.compare_digest(self._mac(payload), row["integrity_hmac"])
        ):
            raise PublicPromptAssignmentError("retained prompt assignment is invalid")
        return payload

    @staticmethod
    def _assignment_json(assignment: Any) -> dict[str, Any]:
        from maverick.consent_profile_data import PromptAssignment

        if type(assignment) is not PromptAssignment:
            raise ValueError("server-issued PromptAssignment is required")
        return asdict(assignment)

    @staticmethod
    def _assignment(value: Mapping[str, Any]) -> Any:
        from maverick.consent_profile_data import PromptAssignment, PromptItem

        prompts = tuple(
            PromptItem(
                stage_id=str(item["stage_id"]),
                preference_id=str(item["preference_id"]),
                definition_version=int(item["definition_version"]),
                label_ref=str(item["label_ref"]),
                value_type=str(item["value_type"]),
                required=bool(item["required"]),
                options=tuple(dict(option) for option in item["options"]),
            )
            for item in value["prompts"]
        )
        return PromptAssignment(
            assignment_id=str(value["assignment_id"]),
            binding_sha256=str(value["binding_sha256"]),
            profile_token=str(value["profile_token"]),
            journey_id=str(value["journey_id"]),
            journey_version=int(value["journey_version"]),
            journey_sha256=str(value["journey_sha256"]),
            stage_ids=tuple(str(item) for item in value["stage_ids"]),
            prompts=prompts,
            eligible=bool(value["eligible"]),
            reason=str(value["reason"]),
            assigned_at=float(value["assigned_at"]),
        )

    def save(
        self,
        binding_sha256: str,
        assignment: Any,
        *,
        retention_seconds: int = _DAY,
    ) -> None:
        binding = _strict_digest(binding_sha256, "binding_sha256")
        if not isinstance(retention_seconds, int) or not _DAY <= retention_seconds <= 7 * _DAY:
            raise ValueError("assignment retention_seconds is invalid")
        material = self._assignment_json(assignment)
        assignment_id = _strict_id(material["assignment_id"], "assignment_id")
        now = float(self._clock())
        if not math.isfinite(now) or now <= 0:
            raise ValueError("current time is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM public_profile_assignments WHERE assignment_id=?",
                (assignment_id,),
            ).fetchone()
            if row is not None:
                payload = self._payload(row)
                if (
                    payload["tenant_id"] != self.tenant_id
                    or payload["binding_sha256"] != binding
                    or payload["assignment"] != material
                ):
                    raise PublicPromptAssignmentConflict(
                        "prompt assignment identifier is already bound"
                    )
                return
            payload = {
                "schema_version": _ASSIGNMENT_SCHEMA,
                "tenant_id": self.tenant_id,
                "assignment_id": assignment_id,
                "binding_sha256": binding,
                "assignment": material,
                "state": "assigned",
                "inserted_operation_sha256": None,
                "terminal_operation_sha256": None,
                "terminal_outcome": None,
                "created_at": now,
                "expires_at": now + retention_seconds,
            }
            connection.execute(
                "INSERT INTO public_profile_assignments VALUES(?,?,?,?)",
                (
                    assignment_id,
                    payload["expires_at"],
                    _canonical(payload).decode("ascii"),
                    self._mac(payload),
                ),
            )

    def _load(
        self,
        connection: sqlite3.Connection,
        assignment_id: str,
        binding_sha256: str,
    ) -> dict[str, Any]:
        assignment = _strict_id(assignment_id, "assignment_id")
        binding = _strict_digest(binding_sha256, "binding_sha256")
        row = connection.execute(
            "SELECT * FROM public_profile_assignments WHERE assignment_id=?",
            (assignment,),
        ).fetchone()
        if row is None:
            raise PublicPromptAssignmentError("prompt assignment is unavailable")
        payload = self._payload(row)
        if (
            payload["tenant_id"] != self.tenant_id
            or payload["binding_sha256"] != binding
            or float(payload["expires_at"]) <= float(self._clock())
        ):
            raise PublicPromptAssignmentError("prompt assignment is unavailable")
        return payload

    def get(self, assignment_id: str, binding_sha256: str) -> Any:
        with self._connect() as connection:
            payload = self._load(connection, assignment_id, binding_sha256)
            return self._assignment(payload["assignment"])

    def mark_inserted(
        self,
        assignment_id: str,
        binding_sha256: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        operation = hashlib.sha256(
            _strict_id(idempotency_key, "idempotency_key").encode()
        ).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            payload = self._load(connection, assignment_id, binding_sha256)
            if payload["inserted_operation_sha256"] == operation:
                return {
                    "assignment_id": assignment_id,
                    "outcome": "inserted",
                    "recorded": True,
                }
            if payload["state"] != "assigned":
                raise PublicPromptAssignmentConflict(
                    "prompt assignment is already inserted or terminal"
                )
            payload["state"] = "inserted"
            payload["inserted_operation_sha256"] = operation
            connection.execute(
                "UPDATE public_profile_assignments SET payload_json=?,integrity_hmac=? "
                "WHERE assignment_id=?",
                (
                    _canonical(payload).decode("ascii"),
                    self._mac(payload),
                    assignment_id,
                ),
            )
            return {
                "assignment_id": assignment_id,
                "outcome": "inserted",
                "recorded": True,
            }

    def load_for_terminal(
        self,
        assignment_id: str,
        binding_sha256: str,
        outcome: str,
        idempotency_key: str,
    ) -> tuple[Any, bool]:
        if outcome not in {"completed", "dismissed"}:
            raise ValueError("terminal outcome is invalid")
        operation = hashlib.sha256(
            _strict_id(idempotency_key, "idempotency_key").encode()
        ).hexdigest()
        with self._connect() as connection:
            payload = self._load(connection, assignment_id, binding_sha256)
            if payload["state"] == "terminal":
                if (
                    payload["terminal_operation_sha256"] == operation
                    and payload["terminal_outcome"] == outcome
                ):
                    return self._assignment(payload["assignment"]), True
                raise PublicPromptAssignmentConflict(
                    "prompt assignment already has a terminal interaction"
                )
            if payload["state"] != "inserted":
                raise PublicPromptAssignmentConflict(
                    "prompt assignment must be inserted before completion or dismissal"
                )
            return self._assignment(payload["assignment"]), False

    def mark_terminal(
        self,
        assignment_id: str,
        binding_sha256: str,
        outcome: str,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        assignment, replay = self.load_for_terminal(
            assignment_id,
            binding_sha256,
            outcome,
            idempotency_key,
        )
        if replay:
            return {
                "assignment_id": assignment.assignment_id,
                "outcome": outcome,
                "recorded": True,
            }
        operation = hashlib.sha256(
            _strict_id(idempotency_key, "idempotency_key").encode()
        ).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            payload = self._load(connection, assignment_id, binding_sha256)
            if payload["state"] != "inserted":
                raise PublicPromptAssignmentConflict(
                    "prompt assignment already has a terminal interaction"
                )
            payload["state"] = "terminal"
            payload["terminal_operation_sha256"] = operation
            payload["terminal_outcome"] = outcome
            connection.execute(
                "UPDATE public_profile_assignments SET payload_json=?,integrity_hmac=? "
                "WHERE assignment_id=?",
                (
                    _canonical(payload).decode("ascii"),
                    self._mac(payload),
                    assignment_id,
                ),
            )
        return {
            "assignment_id": assignment.assignment_id,
            "outcome": outcome,
            "recorded": True,
        }

    def purge_expired(self, *, before: float | None = None) -> int:
        cutoff = float(self._clock() if before is None else before)
        if not math.isfinite(cutoff) or cutoff <= 0:
            raise ValueError("purge cutoff is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return connection.execute(
                "DELETE FROM public_profile_assignments WHERE expires_at<=?",
                (cutoff,),
            ).rowcount


__all__ = [
    "CatalogCreateIn",
    "ConsentProfileDataAdminDependencies",
    "JourneyCreateIn",
    "PublicPromptAssignmentConflict",
    "PublicPromptAssignmentError",
    "PublicPromptAssignmentStore",
    "create_consent_profile_data_router",
    "profile_data_enabled_for_page",
    "public_profile_data_ids",
    "router",
]
