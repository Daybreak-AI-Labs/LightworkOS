"""Asset-bound identity-change outcomes for dynamic risk and alerts.

The identity-governance scheduler deliberately retains only normalized digests.
This module is the next trust boundary: an operator provisions an exact mapping
from a provider or normalized observation digest to a current Model Risk asset
revision.  A scheduler change can then produce a durable dynamic-risk signal and
score, or a durable internal alert, instead of stopping at a request intent.

No raw provider identifier, display name, email address, token, prompt, output,
or arbitrary provider payload is accepted or retained here.  Local completion
is not represented as provider, customer, regulator, or auditor acceptance.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal, Protocol

from .ai_identity_governance_controls import (
    CHANGE_DELIVERY_ACK_SCHEMA,
    ChangeDeliveryAck,
    IdentityGovernanceBindingError,
    IdentityGovernanceDeliveryError,
    IdentityGovernanceIdempotencyConflict,
    IdentityGovernanceStaleBinding,
    IdentityGovernanceStateError,
)
from .privacy_ops import RecordConflict

Provider = Literal["entra", "okta", "purview"]
SelectorKind = Literal[
    "provider",
    "identities",
    "grants",
    "data_classifications",
]
OutcomeSink = Literal["dynamic_risk", "alert"]

ASSET_BINDING_SCHEMA = "lightwork.identity_governance.ai-asset-binding.v1"
ASSET_MANIFEST_SCHEMA = "lightwork.identity_governance.ai-asset-manifest.v1"
ASSET_EVENT_SCHEMA = "lightwork.identity_governance.asset-change-event.v1"
OUTCOME_RECORD_SCHEMA = "lightwork.identity_governance.asset-outcome.v1"
OUTCOME_RECEIPT_SCHEMA = "lightwork.identity_governance.asset-outcome-receipt.v1"
DECISION_RECORD_SCHEMA = (
    "lightwork.identity_governance.conditional-access-decision-record.v1"
)

_PROVIDERS = frozenset({"entra", "okta", "purview"})
_SELECTORS = frozenset(
    {"provider", "identities", "grants", "data_classifications"}
)
_SINKS = frozenset({"dynamic_risk", "alert"})
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_EVENT_RE = re.compile(r"IGCE-[0-9a-f]{32}\Z")
_RECORD_RE = re.compile(r"IGAO-[0-9a-f]{32}\Z")
_CODE_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_MAX_BINDINGS = 10_000
_MAX_EVENT_BINDINGS = 256
_MAX_CHANGED_ITEMS = 1_000_000


class IdentityAssetOutcomeError(RuntimeError):
    """Base error for exact identity-change asset outcomes."""


class IdentityAssetOutcomeConfigError(IdentityAssetOutcomeError):
    """The outcome runtime cannot preserve its configured authority."""


class IdentityAssetOutcomeCoverageError(IdentityAssetOutcomeError):
    """The normalized change is not fully covered by enrolled bindings."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a SHA-256 digest")
    selected = value.strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(selected):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return selected


def _provider(value: object) -> str:
    selected = str(value or "").strip().lower()
    if selected not in _PROVIDERS:
        raise ValueError("identity provider is unsupported")
    return selected


def _selector(value: object) -> str:
    selected = str(value or "").strip().lower()
    if selected not in _SELECTORS:
        raise ValueError("identity asset selector is unsupported")
    return selected


def _asset(value: object) -> str:
    if not isinstance(value, str) or not _ASSET_RE.fullmatch(value.strip()):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return value.strip()


def _revision(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be a valid revision")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    selected = float(value)
    if not math.isfinite(selected) or selected < 0:
        raise ValueError(f"{label} must be a timestamp")
    return selected


def _actor(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("actor is invalid")
    selected = value.strip()
    if (
        not selected
        or len(selected) > 512
        or not selected.startswith(("user:", "system:"))
        or any(ord(character) < 32 for character in selected)
    ):
        raise ValueError("actor is invalid")
    return selected


def _code(value: object, label: str) -> str:
    selected = str(value or "").strip().lower()
    if not _CODE_RE.fullmatch(selected):
        raise ValueError(f"{label} is invalid")
    return selected


def _safe_error_type(exc: BaseException) -> str:
    selected = type(exc).__name__
    return selected if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", selected) else "Exception"


def _record_revision(record: Mapping[str, Any]) -> int:
    return _revision(record.get("revision"), "record revision")


@dataclass(frozen=True)
class IdentityChangeAssetBinding:
    """Exact governed link from a provider/digest selector to an AI asset."""

    tenant_sha256: str
    provider: Provider | str
    selector_kind: SelectorKind | str
    selector_sha256: str
    asset_id: str
    asset_revision: int
    asset_version_digest: str
    binding_revision: int
    asset_criticality: Literal["low", "medium", "high", "critical"] | str
    eu_risk_tier: Literal["minimal", "limited", "high", "unacceptable"] | str
    sensitive_data: Literal["none", "internal", "personal", "special_category"] | str
    external_exposure: Literal["internal", "restricted", "partner", "public"] | str
    binding_sha256: str

    def __post_init__(self) -> None:
        material = self.material()
        expected = _sha256(material)
        if _digest(self.binding_sha256, "binding_sha256") != expected:
            raise ValueError("identity asset binding digest does not match")
        for key, choices in {
            "asset_criticality": {"low", "medium", "high", "critical"},
            "eu_risk_tier": {"minimal", "limited", "high", "unacceptable"},
            "sensitive_data": {"none", "internal", "personal", "special_category"},
            "external_exposure": {"internal", "restricted", "partner", "public"},
        }.items():
            selected = _code(getattr(self, key), key)
            if selected not in choices:
                raise ValueError(f"{key} is unsupported")
            object.__setattr__(self, key, selected)
        object.__setattr__(self, "tenant_sha256", material["tenant_sha256"])
        object.__setattr__(self, "provider", material["provider"])
        object.__setattr__(self, "selector_kind", material["selector_kind"])
        object.__setattr__(self, "selector_sha256", material["selector_sha256"])
        object.__setattr__(self, "asset_id", material["asset_id"])
        object.__setattr__(self, "asset_revision", material["asset_revision"])
        object.__setattr__(
            self, "asset_version_digest", material["asset_version_digest"]
        )
        object.__setattr__(self, "binding_revision", material["binding_revision"])
        object.__setattr__(self, "binding_sha256", expected)

    def material(self) -> dict[str, Any]:
        return {
            "schema": ASSET_BINDING_SCHEMA,
            "tenant_sha256": _digest(self.tenant_sha256, "tenant_sha256"),
            "provider": _provider(self.provider),
            "selector_kind": _selector(self.selector_kind),
            "selector_sha256": _digest(self.selector_sha256, "selector_sha256"),
            "asset_id": _asset(self.asset_id),
            "asset_revision": _revision(self.asset_revision, "asset_revision"),
            "asset_version_digest": _digest(
                self.asset_version_digest, "asset_version_digest"
            ),
            "binding_revision": _revision(self.binding_revision, "binding_revision"),
            "asset_criticality": _code(self.asset_criticality, "asset_criticality"),
            "eu_risk_tier": _code(self.eu_risk_tier, "eu_risk_tier"),
            "sensitive_data": _code(self.sensitive_data, "sensitive_data"),
            "external_exposure": _code(self.external_exposure, "external_exposure"),
        }

    @classmethod
    def bind(cls, **kwargs: Any) -> IdentityChangeAssetBinding:
        return make_identity_change_asset_binding(**kwargs)


def make_identity_change_asset_binding(
    *,
    tenant_sha256: str,
    provider: Provider,
    selector_kind: SelectorKind,
    selector_sha256: str,
    asset_id: str,
    asset_revision: int,
    asset_version_digest: str,
    binding_revision: int,
    asset_criticality: str,
    eu_risk_tier: str,
    sensitive_data: str,
    external_exposure: str,
) -> IdentityChangeAssetBinding:
    """Create a binding after normalizing every digest and closed risk fact."""

    material = {
        "schema": ASSET_BINDING_SCHEMA,
        "tenant_sha256": _digest(tenant_sha256, "tenant_sha256"),
        "provider": _provider(provider),
        "selector_kind": _selector(selector_kind),
        "selector_sha256": _digest(selector_sha256, "selector_sha256"),
        "asset_id": _asset(asset_id),
        "asset_revision": _revision(asset_revision, "asset_revision"),
        "asset_version_digest": _digest(
            asset_version_digest, "asset_version_digest"
        ),
        "binding_revision": _revision(binding_revision, "binding_revision"),
        "asset_criticality": _code(asset_criticality, "asset_criticality"),
        "eu_risk_tier": _code(eu_risk_tier, "eu_risk_tier"),
        "sensitive_data": _code(sensitive_data, "sensitive_data"),
        "external_exposure": _code(external_exposure, "external_exposure"),
    }
    return IdentityChangeAssetBinding(
        **{key: value for key, value in material.items() if key != "schema"},
        binding_sha256=_sha256(material),
    )


class OutcomeRecordStore(Protocol):
    def authoritative_time(self) -> float: ...

    def get(self, record_id: str) -> dict[str, Any] | None: ...

    def list(self, *, limit: int | None = None) -> list[dict[str, Any]]: ...

    def create(
        self,
        record: dict[str, Any],
        *,
        action: str,
        actor: str,
        max_records: int | None = None,
    ) -> dict[str, Any]: ...

    def update(
        self,
        record_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        expected_revision: int,
        action: str,
        actor: str,
    ) -> dict[str, Any] | None: ...


def _default_binding_store() -> OutcomeRecordStore:
    from .governed_records import GovernedRecordStore

    return GovernedRecordStore(
        "identity_governance_ai_asset_bindings",
        "IGAB",
        "identity_governance_ai_asset_binding",
    )


def _default_outcome_store(sink: OutcomeSink) -> OutcomeRecordStore:
    from .governed_records import GovernedRecordStore

    return GovernedRecordStore(
        f"identity_governance_{sink}_outcomes",
        "IGAO",
        f"identity_governance_{sink}_outcome",
    )


def _default_decision_store() -> OutcomeRecordStore:
    from .governed_records import GovernedRecordStore

    return GovernedRecordStore(
        "identity_governance_conditional_access_decisions",
        "IGCD",
        "identity_governance_conditional_access_decision",
    )


def _binding_key(binding: IdentityChangeAssetBinding) -> dict[str, Any]:
    return {
        "tenant_sha256": binding.tenant_sha256,
        "provider": binding.provider,
        "selector_kind": binding.selector_kind,
        "selector_sha256": binding.selector_sha256,
        "asset_id": binding.asset_id,
    }


def _binding_record_id(binding: IdentityChangeAssetBinding) -> str:
    return "IGAB-" + _sha256(_binding_key(binding))[:32]


class IdentityChangeAssetRegistry:
    """CAS-governed binding authority for scheduler change fan-out."""

    def __init__(
        self,
        *,
        tenant_sha256: str,
        store: OutcomeRecordStore | None = None,
        max_records: int = _MAX_BINDINGS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tenant_sha256 = _digest(tenant_sha256, "tenant_sha256")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 1 <= max_records <= _MAX_BINDINGS
        ):
            raise ValueError("identity asset binding capacity is invalid")
        if not callable(clock):
            raise TypeError("identity asset binding clock must be callable")
        selected = store or _default_binding_store()
        for method in ("get", "list", "create", "update"):
            if not callable(getattr(selected, method, None)):
                raise TypeError("identity asset binding store is invalid")
        self._store = selected
        self._max_records = max_records
        self._clock = clock

    def _now(self) -> float:
        return _timestamp(self._clock(), "authority time")

    def _validate_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if (
            not isinstance(record, Mapping)
            or record.get("schema") != ASSET_BINDING_SCHEMA
            or record.get("tenant_sha256") != self.tenant_sha256
            or record.get("status") not in {"active", "revoked"}
            or not isinstance(record.get("binding"), Mapping)
        ):
            raise IdentityGovernanceStateError("identity_asset_binding_record_invalid")
        binding = IdentityChangeAssetBinding(**dict(record["binding"]))
        if (
            binding.tenant_sha256 != self.tenant_sha256
            or record.get("binding_sha256") != binding.binding_sha256
            or record.get("record_sha256")
            != _sha256(
                {
                    "binding": asdict(binding),
                    "status": record.get("status"),
                    "revocation": record.get("revocation"),
                }
            )
        ):
            raise IdentityGovernanceStateError("identity_asset_binding_integrity_failed")
        _record_revision(record)
        return dict(record)

    def enroll(
        self,
        binding: IdentityChangeAssetBinding,
        *,
        actor: str,
        expected_record_revision: int | None = None,
    ) -> dict[str, Any]:
        if not isinstance(binding, IdentityChangeAssetBinding):
            raise TypeError("binding must be an IdentityChangeAssetBinding")
        if binding.tenant_sha256 != self.tenant_sha256:
            raise IdentityGovernanceBindingError("identity_asset_binding_tenant_mismatch")
        operator = _actor(actor)
        record_id = _binding_record_id(binding)
        existing = self._store.get(record_id)
        if existing is not None:
            current = self._validate_record(existing)
            if (
                current["status"] == "active"
                and current["binding_sha256"] == binding.binding_sha256
            ):
                return self._public(current)
            if expected_record_revision != _record_revision(current):
                raise IdentityGovernanceStaleBinding(
                    "identity_asset_binding_revision_stale"
                )

            def replace(row: dict[str, Any]) -> None:
                row["status"] = "active"
                row["binding"] = asdict(binding)
                row["binding_sha256"] = binding.binding_sha256
                row["revocation"] = None
                row["record_sha256"] = _sha256(
                    {
                        "binding": row["binding"],
                        "status": row["status"],
                        "revocation": None,
                    }
                )

            try:
                saved = self._store.update(
                    record_id,
                    replace,
                    expected_revision=_record_revision(current),
                    action="replace_identity_change_asset_binding",
                    actor=operator,
                )
            except RecordConflict as exc:
                raise IdentityGovernanceStaleBinding(
                    "identity_asset_binding_revision_stale"
                ) from exc
            if saved is None:
                raise IdentityGovernanceStateError("identity_asset_binding_missing")
            return self._public(self._validate_record(saved))
        if expected_record_revision not in (None, 0):
            raise IdentityGovernanceStaleBinding(
                "identity_asset_binding_revision_stale"
            )
        record = {
            "id": record_id,
            "schema": ASSET_BINDING_SCHEMA,
            "tenant_sha256": self.tenant_sha256,
            "status": "active",
            "binding": asdict(binding),
            "binding_sha256": binding.binding_sha256,
            "revocation": None,
            "live_acceptance_verified": False,
        }
        record["record_sha256"] = _sha256(
            {
                "binding": record["binding"],
                "status": "active",
                "revocation": None,
            }
        )
        try:
            saved = self._store.create(
                record,
                action="enroll_identity_change_asset_binding",
                actor=operator,
                max_records=self._max_records,
            )
        except RecordConflict as exc:
            concurrent = self._store.get(record_id)
            if concurrent is None:
                raise IdentityGovernanceStateError(
                    "identity_asset_binding_admission_failed"
                ) from exc
            current = self._validate_record(concurrent)
            if current.get("binding_sha256") != binding.binding_sha256:
                raise IdentityGovernanceIdempotencyConflict(
                    "identity_asset_binding_conflict"
                ) from exc
            saved = current
        return self._public(self._validate_record(saved))

    def revoke(
        self,
        binding_id: str,
        *,
        expected_revision: int,
        evidence_sha256: str,
        actor: str,
    ) -> dict[str, Any]:
        if not isinstance(binding_id, str) or not re.fullmatch(
            r"IGAB-[0-9a-f]{32}", binding_id
        ):
            raise ValueError("identity asset binding id is invalid")
        current_raw = self._store.get(binding_id)
        if current_raw is None:
            raise IdentityGovernanceStateError("identity_asset_binding_missing")
        current = self._validate_record(current_raw)
        expected = _revision(expected_revision, "expected_revision")
        if _record_revision(current) != expected:
            raise IdentityGovernanceStaleBinding(
                "identity_asset_binding_revision_stale"
            )
        proof = _digest(evidence_sha256, "evidence_sha256")
        operator = _actor(actor)
        if current["status"] == "revoked":
            revocation = current.get("revocation")
            if not isinstance(revocation, Mapping) or revocation.get(
                "evidence_sha256"
            ) != proof:
                raise IdentityGovernanceIdempotencyConflict(
                    "identity_asset_binding_revocation_conflict"
                )
            return self._public(current)

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "revoked"
            row["revocation"] = {
                "evidence_sha256": proof,
                "revoked_at": self._now(),
                "actor_sha256": _sha256(operator),
            }
            row["record_sha256"] = _sha256(
                {
                    "binding": row["binding"],
                    "status": "revoked",
                    "revocation": row["revocation"],
                }
            )

        try:
            saved = self._store.update(
                binding_id,
                mutate,
                expected_revision=expected,
                action="revoke_identity_change_asset_binding",
                actor=operator,
            )
        except RecordConflict as exc:
            raise IdentityGovernanceStaleBinding(
                "identity_asset_binding_revision_stale"
            ) from exc
        if saved is None:
            raise IdentityGovernanceStateError("identity_asset_binding_missing")
        return self._public(self._validate_record(saved))

    @staticmethod
    def _public(record: Mapping[str, Any]) -> dict[str, Any]:
        binding = dict(record["binding"])
        return {
            "binding_id": record["id"],
            "revision": record["revision"],
            "status": record["status"],
            "binding": binding,
            "binding_sha256": record["binding_sha256"],
            "revocation": (
                dict(record["revocation"])
                if isinstance(record.get("revocation"), Mapping)
                else None
            ),
            "live_acceptance_verified": False,
        }

    def list_bindings(self, *, provider: str | None = None) -> list[dict[str, Any]]:
        selected_provider = _provider(provider) if provider is not None else None
        rows = self._store.list(limit=self._max_records + 1)
        if len(rows) > self._max_records:
            raise IdentityGovernanceStateError("identity_asset_binding_capacity_exceeded")
        result = []
        for row in rows:
            current = self._validate_record(row)
            binding = current["binding"]
            if selected_provider is None or binding.get("provider") == selected_provider:
                result.append(self._public(current))
        return sorted(result, key=lambda item: item["binding_id"])

    def resolve_change(self, change: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve a validated coupler change into a bounded exact manifest."""

        expected = {
            "tenant_sha256",
            "provider",
            "slot",
            "collected_at",
            "change_sha256",
            "change_kind",
            "previous_snapshot_sha256",
            "current_snapshot_sha256",
            "configuration_changed",
            "provider_tenant_changed",
            "categories",
        }
        if not isinstance(change, Mapping) or set(change) != expected:
            raise ValueError("identity asset change resolver input is unsupported")
        tenant = _digest(change.get("tenant_sha256"), "tenant_sha256")
        if tenant != self.tenant_sha256:
            raise IdentityGovernanceBindingError("identity_asset_change_tenant_mismatch")
        provider = _provider(change.get("provider"))
        categories = change.get("categories")
        if not isinstance(categories, Mapping):
            raise ValueError("identity asset change categories are invalid")
        changed_by_category: dict[str, set[str]] = {}
        total_changes = int(bool(change.get("configuration_changed"))) + int(
            bool(change.get("provider_tenant_changed"))
        )
        truncated = False
        for name in ("identities", "grants", "data_classifications"):
            category = categories.get(name)
            if not isinstance(category, Mapping):
                raise ValueError("identity asset change category is invalid")
            added_count = category.get("added_count")
            removed_count = category.get("removed_count")
            if (
                isinstance(added_count, bool)
                or not isinstance(added_count, int)
                or isinstance(removed_count, bool)
                or not isinstance(removed_count, int)
                or not 0 <= added_count <= _MAX_CHANGED_ITEMS
                or not 0 <= removed_count <= _MAX_CHANGED_ITEMS
            ):
                raise ValueError("identity asset change count is invalid")
            total_changes += added_count + removed_count
            digests = {
                _digest(value, "changed_item_sha256")
                for field in ("added_sha256", "removed_sha256")
                for value in category.get(field, ())
            }
            changed_by_category[name] = digests
            truncated = truncated or category.get("digests_truncated") is True

        rows = self.list_bindings(provider=provider)
        provider_scope = any(
            row["status"] == "active"
            and row["binding"]["selector_kind"] == "provider"
            for row in rows
        )
        matched_digests: set[tuple[str, str]] = set()
        selected: list[dict[str, Any]] = []
        for row in rows:
            if row["status"] != "active":
                continue
            binding = IdentityChangeAssetBinding(**row["binding"])
            triggers: list[dict[str, str]] = []
            if binding.selector_kind == "provider":
                if total_changes > 0:
                    triggers.append(
                        {
                            "category": "provider",
                            "selector_sha256": binding.selector_sha256,
                        }
                    )
            elif binding.selector_sha256 in changed_by_category[binding.selector_kind]:
                matched_digests.add(
                    (binding.selector_kind, binding.selector_sha256)
                )
                triggers.append(
                    {
                        "category": binding.selector_kind,
                        "selector_sha256": binding.selector_sha256,
                    }
                )
            if triggers:
                selected.append(
                    {
                        "binding": asdict(binding),
                        "binding_record_id": row["binding_id"],
                        "binding_record_revision": row["revision"],
                        "triggers": triggers,
                    }
                )
        if len(selected) > _MAX_EVENT_BINDINGS:
            raise IdentityAssetOutcomeCoverageError(
                "identity_change_asset_binding_limit_exceeded"
            )
        unmapped = 0 if provider_scope else max(0, total_changes - len(matched_digests))
        coverage_complete = provider_scope or (not truncated and unmapped == 0)
        material = {
            "schema": ASSET_MANIFEST_SCHEMA,
            "tenant_sha256": tenant,
            "provider": provider,
            "change_sha256": _digest(change.get("change_sha256"), "change_sha256"),
            "bindings": selected,
            "normalized_change": {
                **dict(change),
                "categories": {
                    name: dict(value)
                    for name, value in categories.items()
                },
            },
            "changed_item_count": total_changes,
            "mapped_item_count": total_changes if provider_scope else len(matched_digests),
            "unmapped_item_count": unmapped,
            "digests_truncated": truncated,
            "coverage_complete": coverage_complete,
            "source_complete": False,
            "live_acceptance_verified": False,
        }
        return {**material, "manifest_sha256": _sha256(material)}

    __call__ = resolve_change

    def status(self) -> dict[str, Any]:
        rows = self.list_bindings()
        return {
            "schema": "lightwork.identity_governance.ai-asset-binding-status.v1",
            "tenant_sha256": self.tenant_sha256,
            "active_binding_count": sum(row["status"] == "active" for row in rows),
            "revoked_binding_count": sum(row["status"] == "revoked" for row in rows),
            "cas_enforced": True,
            "exact_asset_revision_required": True,
            "exact_asset_digest_required": True,
            "raw_identity_retained": False,
            "live_acceptance_verified": False,
        }


def validate_asset_event(  # noqa: C901 - explicit closed-schema trust boundary
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the closed asset-bound event admitted by an outcome consumer."""

    expected = {
        "schema",
        "event_id",
        "tenant_sha256",
        "provider",
        "change_sha256",
        "slot",
        "observed_at",
        "change_kind",
        "previous_snapshot_sha256",
        "current_snapshot_sha256",
        "counts",
        "configuration_changed",
        "provider_tenant_changed",
        "digests_truncated",
        "risk_assessment_required",
        "alert_candidate",
        "source_complete",
        "live_acceptance_verified",
        "asset_manifest",
    }
    if not isinstance(event, Mapping) or set(event) != expected:
        raise ValueError("asset-bound identity change event shape is unsupported")
    if event.get("schema") != ASSET_EVENT_SCHEMA:
        raise ValueError("asset-bound identity change event schema is unsupported")
    event_id = str(event.get("event_id") or "")
    if not _EVENT_RE.fullmatch(event_id):
        raise ValueError("asset-bound identity change event id is invalid")
    tenant = _digest(event.get("tenant_sha256"), "tenant_sha256")
    provider = _provider(event.get("provider"))
    change_sha = _digest(event.get("change_sha256"), "change_sha256")
    manifest = event.get("asset_manifest")
    if not isinstance(manifest, Mapping):
        raise ValueError("identity asset manifest is invalid")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if (
        manifest.get("schema") != ASSET_MANIFEST_SCHEMA
        or manifest.get("tenant_sha256") != tenant
        or manifest.get("provider") != provider
        or manifest.get("change_sha256") != change_sha
        or _digest(manifest.get("manifest_sha256"), "manifest_sha256")
        != _sha256(material)
        or manifest.get("source_complete") is not False
        or manifest.get("live_acceptance_verified") is not False
        or not isinstance(manifest.get("coverage_complete"), bool)
    ):
        raise ValueError("identity asset manifest binding is invalid")
    source_change = manifest.get("normalized_change")
    if (
        not isinstance(source_change, Mapping)
        or source_change.get("tenant_sha256") != tenant
        or source_change.get("provider") != provider
        or source_change.get("change_sha256") != change_sha
    ):
        raise ValueError("identity asset manifest source change is invalid")
    bindings = manifest.get("bindings")
    if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
        raise ValueError("identity asset manifest bindings are invalid")
    if len(bindings) > _MAX_EVENT_BINDINGS:
        raise ValueError("identity asset manifest exceeds its binding bound")
    normalized_bindings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in bindings:
        if not isinstance(item, Mapping) or set(item) != {
            "binding",
            "binding_record_id",
            "binding_record_revision",
            "triggers",
        }:
            raise ValueError("identity asset manifest binding is invalid")
        binding_raw = item.get("binding")
        if not isinstance(binding_raw, Mapping):
            raise ValueError("identity asset manifest binding is invalid")
        binding = IdentityChangeAssetBinding(**dict(binding_raw))
        if binding.tenant_sha256 != tenant or binding.provider != provider:
            raise IdentityGovernanceBindingError("identity_asset_manifest_mismatch")
        if binding.binding_sha256 in seen:
            raise ValueError("identity asset manifest contains duplicate bindings")
        seen.add(binding.binding_sha256)
        record_id = item.get("binding_record_id")
        if not isinstance(record_id, str) or not re.fullmatch(
            r"IGAB-[0-9a-f]{32}", record_id
        ):
            raise ValueError("identity asset manifest record id is invalid")
        record_revision = _revision(
            item.get("binding_record_revision"), "binding_record_revision"
        )
        triggers = item.get("triggers")
        if not isinstance(triggers, Sequence) or isinstance(triggers, (str, bytes)):
            raise ValueError("identity asset manifest triggers are invalid")
        normalized_bindings.append(
            {
                "binding": asdict(binding),
                "binding_record_id": record_id,
                "binding_record_revision": record_revision,
                "triggers": [dict(value) for value in triggers],
            }
        )
    counts = event.get("counts")
    if not isinstance(counts, Mapping) or set(counts) != {"added", "removed"}:
        raise ValueError("identity change counts are invalid")
    for value in counts.values():
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= _MAX_CHANGED_ITEMS
        ):
            raise ValueError("identity change count is invalid")
    for flag in (
        "configuration_changed",
        "provider_tenant_changed",
        "digests_truncated",
    ):
        if not isinstance(event.get(flag), bool):
            raise ValueError("identity change flag is invalid")
    if (
        event.get("risk_assessment_required") is not True
        or event.get("alert_candidate") is not True
        or event.get("source_complete") is not False
        or event.get("live_acceptance_verified") is not False
    ):
        raise ValueError("asset-bound identity change event contains unsupported claims")
    return {
        **dict(event),
        "tenant_sha256": tenant,
        "provider": provider,
        "change_sha256": change_sha,
        "asset_manifest": {**dict(manifest), "bindings": normalized_bindings},
    }


def asset_event_from_change_event(
    event: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Upgrade a validated v1 coupler event with an exact asset manifest."""

    selected = dict(event)
    selected["schema"] = ASSET_EVENT_SCHEMA
    selected["asset_manifest"] = dict(manifest)
    return validate_asset_event(selected)


class DynamicRiskService(Protocol):
    def ingest_signal(self, signal: object, *, actor: object) -> Mapping[str, Any]: ...

    def current_score(self, asset_id: str) -> Mapping[str, Any] | None: ...

    def score_asset(
        self,
        asset_id: str,
        *,
        context: object,
        expected_revision: int,
        actor: object,
    ) -> Mapping[str, Any]: ...


class IdentityChangeOutcomeConsumer:
    """Durable idempotent worker for risk scores or internal alerts."""

    def __init__(
        self,
        *,
        tenant_sha256: str,
        sink: OutcomeSink,
        asset_lookup: Callable[[str], Mapping[str, Any] | None],
        risk_service: DynamicRiskService | None = None,
        manifest_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]]
        | None = None,
        store: OutcomeRecordStore | None = None,
        max_records: int = 10_000,
        max_attempts: int = 5,
        retry_base_seconds: float = 30.0,
        retry_max_seconds: float = 3_600.0,
        lease_seconds: float = 60.0,
        signal_validity_seconds: int = 86_400,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._tenant_sha256 = _digest(tenant_sha256, "tenant_sha256")
        selected_sink = str(sink or "").strip().lower()
        if selected_sink not in _SINKS:
            raise ValueError("identity outcome sink is unsupported")
        if not callable(asset_lookup):
            raise TypeError("identity outcome asset lookup must be callable")
        if selected_sink == "dynamic_risk" and risk_service is None:
            raise IdentityAssetOutcomeConfigError(
                "dynamic risk outcome service is required"
            )
        if risk_service is not None:
            for method in ("ingest_signal", "current_score", "score_asset"):
                if not callable(getattr(risk_service, method, None)):
                    raise TypeError("dynamic risk outcome service is invalid")
        if manifest_resolver is not None and not callable(manifest_resolver):
            raise TypeError("identity outcome manifest resolver is invalid")
        for value, label, lower, upper in (
            (max_records, "max_records", 1, 10_000),
            (max_attempts, "max_attempts", 1, 20),
            (signal_validity_seconds, "signal_validity_seconds", 60, 31_622_400),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise ValueError(f"identity outcome {label} is invalid")
        for value, label, lower, upper in (
            (retry_base_seconds, "retry_base_seconds", 0.1, 86_400.0),
            (retry_max_seconds, "retry_max_seconds", 0.1, 604_800.0),
            (lease_seconds, "lease_seconds", 1.0, 3_600.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not lower <= float(value) <= upper
            ):
                raise ValueError(f"identity outcome {label} is invalid")
        if float(retry_max_seconds) < float(retry_base_seconds):
            raise ValueError("identity outcome retry maximum is invalid")
        if not callable(clock):
            raise TypeError("identity outcome clock must be callable")
        selected_store = store or _default_outcome_store(selected_sink)  # type: ignore[arg-type]
        for method in ("get", "list", "create", "update"):
            if not callable(getattr(selected_store, method, None)):
                raise TypeError("identity outcome store is invalid")
        self._sink: OutcomeSink = selected_sink  # type: ignore[assignment]
        self._asset_lookup = asset_lookup
        self._risk_service = risk_service
        self._manifest_resolver = manifest_resolver
        self._store = selected_store
        self._max_records = max_records
        self._max_attempts = max_attempts
        self._retry_base_seconds = float(retry_base_seconds)
        self._retry_max_seconds = float(retry_max_seconds)
        self._lease_seconds = float(lease_seconds)
        self._signal_validity_seconds = signal_validity_seconds
        self._clock = clock

    def _now(self) -> float:
        return _timestamp(self._clock(), "outcome authority time")

    @staticmethod
    def _record_id(event_id: str, sink: str) -> str:
        return "IGAO-" + _sha256({"event_id": event_id, "sink": sink})[:32]

    def _event_receipt(self, record: Mapping[str, Any]) -> str:
        outcomes = []
        for item in record.get("items", ()):
            if not isinstance(item, Mapping):
                continue
            outcome = item.get("outcome")
            outcomes.append(
                {
                    "binding_sha256": item.get("binding_sha256"),
                    "status": item.get("status"),
                    "outcome_sha256": (
                        outcome.get("outcome_sha256")
                        if isinstance(outcome, Mapping)
                        else None
                    ),
                }
            )
        return _sha256(
            {
                "schema": OUTCOME_RECEIPT_SCHEMA,
                "tenant_sha256": self._tenant_sha256,
                "sink": self._sink,
                "event_id": record.get("event_id"),
                "event_sha256": record.get("event_sha256"),
                "status": record.get("status"),
                "outcomes": outcomes,
                "dead_letter_reason": record.get("dead_letter_reason"),
                "revocation_sha256": (
                    record.get("revocation", {}).get("evidence_sha256")
                    if isinstance(record.get("revocation"), Mapping)
                    else None
                ),
            }
        )

    def _ack(self, record: Mapping[str, Any]) -> ChangeDeliveryAck:
        receipt = record.get("receipt_sha256") or self._event_receipt(record)
        return ChangeDeliveryAck(
            schema=CHANGE_DELIVERY_ACK_SCHEMA,
            sink=self._sink,
            event_id=str(record["event_id"]),
            idempotency_sha256=str(record["idempotency_sha256"]),
            receipt_sha256=_digest(receipt, "receipt_sha256"),
            accepted=True,
            live_acceptance_verified=False,
        )

    def _admit(self, event: Mapping[str, Any]) -> dict[str, Any]:
        validated = validate_asset_event(event)
        if validated["tenant_sha256"] != self._tenant_sha256:
            raise IdentityGovernanceBindingError("identity_outcome_tenant_mismatch")
        event_sha = _sha256(validated)
        event_id = validated["event_id"]
        record_id = self._record_id(event_id, self._sink)
        idempotency_sha = _sha256({"event_id": event_id, "sink": self._sink})
        existing = self._store.get(record_id)
        if existing is not None:
            if (
                existing.get("schema") != OUTCOME_RECORD_SCHEMA
                or existing.get("tenant_sha256") != self._tenant_sha256
                or existing.get("sink") != self._sink
                or existing.get("event_sha256") != event_sha
                or existing.get("idempotency_sha256") != idempotency_sha
            ):
                raise IdentityGovernanceIdempotencyConflict(
                    "identity_outcome_idempotency_conflict"
                )
            _record_revision(existing)
            return dict(existing)
        manifest = validated["asset_manifest"]
        items = [
            {
                "binding": dict(item["binding"]),
                "binding_sha256": item["binding"]["binding_sha256"],
                "binding_record_id": item["binding_record_id"],
                "binding_record_revision": item["binding_record_revision"],
                "triggers_sha256": _sha256(item["triggers"]),
                "status": "pending",
                "attempts": 0,
                "last_error_type": None,
                "outcome": None,
            }
            for item in manifest["bindings"]
        ]
        no_change = (
            manifest["changed_item_count"] == 0
            and validated["counts"] == {"added": 0, "removed": 0}
            and validated["configuration_changed"] is False
            and validated["provider_tenant_changed"] is False
        )
        if no_change:
            initial_status = "no_change"
            dead_reason = None
        elif manifest["coverage_complete"] is not True or manifest[
            "unmapped_item_count"
        ]:
            initial_status = "dead_letter"
            dead_reason = "asset_binding_coverage_incomplete"
        elif not items:
            initial_status = "dead_letter"
            dead_reason = "asset_binding_unavailable"
        else:
            initial_status = "pending"
            dead_reason = None
        record = {
            "id": record_id,
            "schema": OUTCOME_RECORD_SCHEMA,
            "tenant_sha256": self._tenant_sha256,
            "sink": self._sink,
            "event_id": event_id,
            "event_sha256": event_sha,
            "change_sha256": validated["change_sha256"],
            "provider": validated["provider"],
            "manifest_sha256": manifest["manifest_sha256"],
            "idempotency_sha256": idempotency_sha,
            "event": dict(validated),
            "status": initial_status,
            "health": "degraded" if initial_status == "dead_letter" else "healthy",
            "attempts": 0,
            "next_attempt_at": 0.0,
            "lease": None,
            "last_error_type": None,
            "dead_letter_reason": dead_reason,
            "items": items,
            "revocation": None,
            "receipt_sha256": None,
            "provider_write_performed": False,
            "live_acceptance_verified": False,
        }
        if initial_status in {"no_change", "dead_letter"}:
            record["receipt_sha256"] = self._event_receipt(record)
        try:
            return self._store.create(
                record,
                action=f"admit_identity_{self._sink}_outcome",
                actor="system:identity-governance-outcome-consumer",
                max_records=self._max_records,
            )
        except RecordConflict as exc:
            concurrent = self._store.get(record_id)
            if concurrent is None or concurrent.get("event_sha256") != event_sha:
                raise IdentityGovernanceIdempotencyConflict(
                    "identity_outcome_idempotency_conflict"
                ) from exc
            return dict(concurrent)

    def _update(
        self,
        record: Mapping[str, Any],
        mutate: Callable[[dict[str, Any]], None],
        *,
        action: str,
        actor: str = "system:identity-governance-outcome-consumer",
    ) -> dict[str, Any]:
        try:
            saved = self._store.update(
                str(record["id"]),
                mutate,
                expected_revision=_record_revision(record),
                action=action,
                actor=actor,
            )
        except RecordConflict as exc:
            raise IdentityGovernanceStaleBinding("identity_outcome_revision_stale") from exc
        if saved is None:
            raise IdentityGovernanceStateError("identity_outcome_missing")
        return saved

    def _current_asset(self, binding: IdentityChangeAssetBinding) -> Mapping[str, Any]:
        try:
            current = self._asset_lookup(binding.asset_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceDeliveryError(
                "identity_outcome_asset_authority_unavailable"
            ) from None
        if not isinstance(current, Mapping):
            raise IdentityGovernanceStaleBinding("identity_outcome_asset_missing")
        try:
            asset_id = _asset(current.get("asset_id"))
            revision = _revision(current.get("revision"), "asset_revision")
            digest = _digest(current.get("version_digest"), "asset_version_digest")
        except (TypeError, ValueError) as exc:
            raise IdentityGovernanceStateError(
                "identity_outcome_asset_authority_invalid"
            ) from exc
        if (
            asset_id != binding.asset_id
            or revision != binding.asset_revision
            or digest != binding.asset_version_digest
        ):
            raise IdentityGovernanceStaleBinding("identity_outcome_asset_binding_stale")
        return current

    @staticmethod
    def _severity(event: Mapping[str, Any]) -> float:
        counts = event["counts"]
        total = int(counts["added"]) + int(counts["removed"])
        score = min(75.0, 20.0 + math.log2(total + 1) * 10.0)
        if event["configuration_changed"]:
            score = max(score, 80.0)
        if event["provider_tenant_changed"]:
            score = 100.0
        return round(score, 6)

    def _dynamic_risk_outcome(
        self,
        *,
        event: Mapping[str, Any],
        binding: IdentityChangeAssetBinding,
    ) -> dict[str, Any]:
        from . import ai_dynamic_risk as risk

        assert self._risk_service is not None
        evidence_sha = _sha256(
            {
                "event_sha256": _sha256(event),
                "binding_sha256": binding.binding_sha256,
                "asset_revision": binding.asset_revision,
                "asset_version_digest": binding.asset_version_digest,
            }
        )
        source_id = f"identity-change:{event['event_id']}:{binding.asset_id}"
        idempotency = f"identity-governance:{event['event_id']}:{binding.binding_sha256}"
        current = self._risk_service.current_score(binding.asset_id)
        if isinstance(current, Mapping):
            for contribution in current.get("contributions", ()):
                if (
                    isinstance(contribution, Mapping)
                    and contribution.get("source_id") == source_id
                    and contribution.get("source_digest") == evidence_sha
                    and current.get("asset_revision") == binding.asset_revision
                    and current.get("asset_version_digest")
                    == binding.asset_version_digest
                ):
                    material = {
                        "sink": "dynamic_risk",
                        "asset_id": binding.asset_id,
                        "asset_revision": binding.asset_revision,
                        "asset_version_digest": binding.asset_version_digest,
                        "binding_sha256": binding.binding_sha256,
                        "signal_id": contribution.get("signal_id"),
                        "snapshot_id": current.get("snapshot_id"),
                        "snapshot_revision": current.get("snapshot_revision"),
                        "score": current.get("score"),
                        "risk_tier": current.get("risk_tier"),
                        "evidence_sha256": evidence_sha,
                        "ambiguity_recovered": True,
                    }
                    return {**material, "outcome_sha256": _sha256(material)}
        observed_at = _timestamp(event["observed_at"], "observed_at")
        signal = risk.RiskSignal(
            asset_id=binding.asset_id,
            category=risk.RiskCategory.SECURITY,
            severity=self._severity(event),
            confidence=0.9,
            observed_at=observed_at,
            expires_at=observed_at + self._signal_validity_seconds,
            source_type=risk.SignalSourceType.EVIDENCE,
            source_id=source_id,
            source_digest=evidence_sha,
            signal_code="identity_governance_change",
            idempotency_key=idempotency,
        )
        actor = risk.RiskActor(
            risk.ActorKind.SYSTEM,
            "system:identity-governance-outcome-consumer",
        )
        admitted = self._risk_service.ingest_signal(signal, actor=actor)
        current = self._risk_service.current_score(binding.asset_id)
        expected_revision = (
            _revision(current.get("snapshot_revision"), "snapshot_revision")
            if isinstance(current, Mapping)
            else 0
        )
        scored = self._risk_service.score_asset(
            binding.asset_id,
            context=risk.RiskContext(
                asset_criticality=binding.asset_criticality,
                eu_risk_tier=binding.eu_risk_tier,
                sensitive_data=binding.sensitive_data,
                external_exposure=binding.external_exposure,
            ),
            expected_revision=expected_revision,
            actor=actor,
        )
        material = {
            "sink": "dynamic_risk",
            "asset_id": binding.asset_id,
            "asset_revision": binding.asset_revision,
            "asset_version_digest": binding.asset_version_digest,
            "binding_sha256": binding.binding_sha256,
            "signal_id": admitted.get("signal_id"),
            "snapshot_id": scored.get("snapshot_id"),
            "snapshot_revision": scored.get("snapshot_revision"),
            "score": scored.get("score"),
            "risk_tier": scored.get("risk_tier"),
            "evidence_sha256": evidence_sha,
            "ambiguity_recovered": False,
        }
        return {**material, "outcome_sha256": _sha256(material)}

    def _alert_outcome(
        self,
        *,
        event: Mapping[str, Any],
        binding: IdentityChangeAssetBinding,
    ) -> dict[str, Any]:
        evidence_sha = _sha256(
            {
                "event_sha256": _sha256(event),
                "binding_sha256": binding.binding_sha256,
                "asset_revision": binding.asset_revision,
                "asset_version_digest": binding.asset_version_digest,
            }
        )
        severity = self._severity(event)
        material = {
            "sink": "alert",
            "alert_id": "IGA-"
            + _sha256(
                {
                    "event_id": event["event_id"],
                    "binding_sha256": binding.binding_sha256,
                }
            )[:32],
            "asset_id": binding.asset_id,
            "asset_revision": binding.asset_revision,
            "asset_version_digest": binding.asset_version_digest,
            "binding_sha256": binding.binding_sha256,
            "severity": severity,
            "severity_band": (
                "critical" if severity >= 75 else "high" if severity >= 50 else "medium"
            ),
            "alert_state": "open",
            "evidence_sha256": evidence_sha,
            "provider_write_performed": False,
            "live_acceptance_verified": False,
        }
        return {**material, "outcome_sha256": _sha256(material)}

    def _process(  # noqa: C901 - explicit durable state transition boundary
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._now()
        status = record.get("status")
        if status in {"completed", "no_change", "dead_letter", "revoked"}:
            return dict(record)
        next_at = _timestamp(record.get("next_attempt_at", 0.0), "next_attempt_at")
        if next_at > now:
            raise IdentityGovernanceDeliveryError("identity_outcome_backoff_active")
        lease = record.get("lease")
        if isinstance(lease, Mapping) and _timestamp(
            lease.get("expires_at"), "lease_expires_at"
        ) > now:
            raise IdentityGovernanceDeliveryError("identity_outcome_in_progress")
        attempts = record.get("attempts")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
            raise IdentityGovernanceStateError("identity_outcome_attempts_invalid")
        token = _sha256(uuid.uuid4().hex)

        def claim(row: dict[str, Any]) -> None:
            row["status"] = "processing"
            row["attempts"] = attempts + 1
            row["lease"] = {"token_sha256": token, "expires_at": now + self._lease_seconds}
            row["last_error_type"] = None

        current = self._update(
            record,
            claim,
            action=f"claim_identity_{self._sink}_outcome",
        )
        event = current.get("event")
        if not isinstance(event, Mapping):
            raise IdentityGovernanceStateError("identity_outcome_event_invalid")
        try:
            for index, raw_item in enumerate(list(current.get("items") or [])):
                if not isinstance(raw_item, Mapping):
                    raise IdentityGovernanceStateError("identity_outcome_item_invalid")
                if raw_item.get("status") == "completed":
                    continue
                binding_raw = raw_item.get("binding")
                if not isinstance(binding_raw, Mapping):
                    raise IdentityGovernanceStateError("identity_outcome_binding_invalid")
                binding = IdentityChangeAssetBinding(**dict(binding_raw))
                self._current_asset(binding)
                outcome = (
                    self._dynamic_risk_outcome(event=event, binding=binding)
                    if self._sink == "dynamic_risk"
                    else self._alert_outcome(event=event, binding=binding)
                )

                def complete_item(row: dict[str, Any], selected=outcome, item_index=index) -> None:
                    active = row.get("lease")
                    if not isinstance(active, Mapping) or active.get("token_sha256") != token:
                        raise IdentityGovernanceStateError("identity_outcome_lease_lost")
                    item = row["items"][item_index]
                    item["status"] = "completed"
                    item["attempts"] = int(item.get("attempts") or 0) + 1
                    item["last_error_type"] = None
                    item["outcome"] = selected

                current = self._update(
                    current,
                    complete_item,
                    action=f"record_identity_{self._sink}_asset_outcome",
                )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            error_type = _safe_error_type(exc)
            final_attempt = attempts + 1 >= self._max_attempts
            backoff = min(
                self._retry_base_seconds * (2 ** min(attempts, 20)),
                self._retry_max_seconds,
            )

            def fail(row: dict[str, Any]) -> None:
                active = row.get("lease")
                if not isinstance(active, Mapping) or active.get("token_sha256") != token:
                    raise IdentityGovernanceStateError("identity_outcome_lease_lost")
                row["lease"] = None
                row["status"] = "dead_letter" if final_attempt else "failed"
                row["health"] = "degraded"
                row["last_error_type"] = error_type
                row["next_attempt_at"] = 0.0 if final_attempt else now + backoff
                row["dead_letter_reason"] = (
                    "attempts_exhausted" if final_attempt else None
                )
                if final_attempt:
                    row["receipt_sha256"] = self._event_receipt(row)

            failed = self._update(
                current,
                fail,
                action=f"record_identity_{self._sink}_outcome_failure",
            )
            if final_attempt:
                return failed
            raise IdentityGovernanceDeliveryError("identity_outcome_degraded") from None

        def finish(row: dict[str, Any]) -> None:
            active = row.get("lease")
            if not isinstance(active, Mapping) or active.get("token_sha256") != token:
                raise IdentityGovernanceStateError("identity_outcome_lease_lost")
            if any(item.get("status") != "completed" for item in row["items"]):
                raise IdentityGovernanceStateError("identity_outcome_incomplete")
            row["lease"] = None
            row["status"] = "completed"
            row["health"] = "healthy"
            row["next_attempt_at"] = 0.0
            row["last_error_type"] = None
            row["dead_letter_reason"] = None
            row["receipt_sha256"] = self._event_receipt(row)

        return self._update(
            current,
            finish,
            action=f"complete_identity_{self._sink}_outcome",
        )

    def __call__(self, event: Mapping[str, Any]) -> ChangeDeliveryAck:
        record = self._admit(event)
        record = self._process(record)
        return self._ack(record)

    def get(self, record_id: str) -> dict[str, Any] | None:
        if not isinstance(record_id, str) or not _RECORD_RE.fullmatch(record_id):
            raise ValueError("identity outcome record id is invalid")
        record = self._store.get(record_id)
        if record is None:
            return None
        if (
            record.get("schema") != OUTCOME_RECORD_SCHEMA
            or record.get("tenant_sha256") != self._tenant_sha256
            or record.get("sink") != self._sink
        ):
            raise IdentityGovernanceStateError("identity_outcome_record_invalid")
        return self._public(record)

    @staticmethod
    def _public(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "outcome_id": record["id"],
            "revision": record["revision"],
            "sink": record["sink"],
            "event_id": record["event_id"],
            "change_sha256": record["change_sha256"],
            "provider": record["provider"],
            "manifest_sha256": record["manifest_sha256"],
            "status": record["status"],
            "health": record["health"],
            "attempts": record["attempts"],
            "next_attempt_at": record["next_attempt_at"],
            "last_error_type": record["last_error_type"],
            "dead_letter_reason": record["dead_letter_reason"],
            "items": [
                {
                    "binding_sha256": item["binding_sha256"],
                    "asset_id": item["binding"]["asset_id"],
                    "asset_revision": item["binding"]["asset_revision"],
                    "asset_version_digest": item["binding"]["asset_version_digest"],
                    "status": item["status"],
                    "attempts": item["attempts"],
                    "last_error_type": item["last_error_type"],
                    "outcome": (
                        dict(item["outcome"])
                        if isinstance(item.get("outcome"), Mapping)
                        else None
                    ),
                }
                for item in record.get("items", ())
            ],
            "revocation": (
                dict(record["revocation"])
                if isinstance(record.get("revocation"), Mapping)
                else None
            ),
            "receipt_sha256": record.get("receipt_sha256"),
            "provider_write_performed": False,
            "live_acceptance_verified": False,
        }


    def list(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self._max_records
        ):
            raise ValueError("identity outcome list limit is invalid")
        allowed = {"pending", "processing", "failed", "completed", "no_change", "dead_letter", "revoked"}
        if status is not None and status not in allowed:
            raise ValueError("identity outcome status filter is invalid")
        rows = self._store.list(limit=self._max_records + 1)
        if len(rows) > self._max_records:
            raise IdentityGovernanceStateError("identity_outcome_capacity_exceeded")
        selected = [
            self._public(row)
            for row in rows
            if row.get("tenant_sha256") == self._tenant_sha256
            and row.get("sink") == self._sink
            and (status is None or row.get("status") == status)
        ]
        return sorted(selected, key=lambda item: item["outcome_id"])[:limit]

    def run_due(self, *, limit: int = 25) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("identity outcome worker limit is invalid")
        now = self._now()
        processed = completed = failed = dead_lettered = 0
        for public in self.list(limit=self._max_records):
            if processed >= limit:
                break
            if public["status"] not in {"pending", "failed", "processing"}:
                continue
            if float(public["next_attempt_at"]) > now:
                continue
            record = self._store.get(public["outcome_id"])
            if record is None:
                continue
            processed += 1
            try:
                saved = self._process(record)
            except IdentityGovernanceDeliveryError:
                failed += 1
                continue
            if saved.get("status") == "completed":
                completed += 1
            elif saved.get("status") == "dead_letter":
                dead_lettered += 1
        return {
            "schema": "lightwork.identity_governance.asset-outcome-worker.v1",
            "sink": self._sink,
            "processed": processed,
            "completed": completed,
            "failed": failed,
            "dead_lettered": dead_lettered,
            "provider_writes": False,
            "live_acceptance_verified": False,
        }

    def replay(
        self,
        record_id: str,
        *,
        expected_revision: int,
        replacement_event: Mapping[str, Any],
        evidence_sha256: str,
        actor: str,
    ) -> dict[str, Any]:
        current_raw = self._store.get(record_id)
        if current_raw is None:
            raise IdentityGovernanceStateError("identity_outcome_missing")
        current = dict(current_raw)
        if current.get("status") not in {"failed", "dead_letter", "revoked"}:
            raise IdentityGovernanceStateError("identity_outcome_not_replayable")
        if _record_revision(current) != _revision(expected_revision, "expected_revision"):
            raise IdentityGovernanceStaleBinding("identity_outcome_revision_stale")
        selected_replacement: Mapping[str, Any] = replacement_event
        if not replacement_event:
            resolver = self._manifest_resolver
            retained_event = current.get("event")
            retained_manifest = (
                retained_event.get("asset_manifest")
                if isinstance(retained_event, Mapping)
                else None
            )
            source_change = (
                retained_manifest.get("normalized_change")
                if isinstance(retained_manifest, Mapping)
                else None
            )
            if resolver is None or not isinstance(source_change, Mapping):
                raise IdentityAssetOutcomeConfigError(
                    "identity outcome manifest refresh is unavailable"
                )
            refreshed = resolver(source_change)
            if not isinstance(refreshed, Mapping):
                raise IdentityGovernanceStateError(
                    "identity outcome manifest refresh is invalid"
                )
            base = dict(retained_event)
            base.pop("asset_manifest", None)
            base["schema"] = "lightwork.identity_governance.change-event.v1"
            selected_replacement = asset_event_from_change_event(base, refreshed)
        event = validate_asset_event(selected_replacement)
        if (
            event["tenant_sha256"] != self._tenant_sha256
            or event["event_id"] != current.get("event_id")
            or event["change_sha256"] != current.get("change_sha256")
            or event["provider"] != current.get("provider")
        ):
            raise IdentityGovernanceBindingError("identity_outcome_replay_binding_mismatch")
        if (
            event["asset_manifest"]["coverage_complete"] is not True
            or event["asset_manifest"]["unmapped_item_count"]
            or not event["asset_manifest"]["bindings"]
        ):
            raise IdentityAssetOutcomeCoverageError(
                "identity_outcome_replay_coverage_incomplete"
            )
        proof = _digest(evidence_sha256, "evidence_sha256")
        operator = _actor(actor)
        event_sha = _sha256(event)
        items = [
            {
                "binding": dict(item["binding"]),
                "binding_sha256": item["binding"]["binding_sha256"],
                "binding_record_id": item["binding_record_id"],
                "binding_record_revision": item["binding_record_revision"],
                "triggers_sha256": _sha256(item["triggers"]),
                "status": "pending",
                "attempts": 0,
                "last_error_type": None,
                "outcome": None,
            }
            for item in event["asset_manifest"]["bindings"]
        ]

        def mutate(row: dict[str, Any]) -> None:
            row["event"] = dict(event)
            row["event_sha256"] = event_sha
            row["manifest_sha256"] = event["asset_manifest"]["manifest_sha256"]
            row["status"] = "pending"
            row["health"] = "healthy"
            row["attempts"] = 0
            row["next_attempt_at"] = 0.0
            row["lease"] = None
            row["last_error_type"] = None
            row["dead_letter_reason"] = None
            row["items"] = items
            row["revocation"] = {
                "replay_evidence_sha256": proof,
                "replayed_at": self._now(),
                "actor_sha256": _sha256(operator),
            }
            row["receipt_sha256"] = None

        saved = self._update(
            current,
            mutate,
            action=f"replay_identity_{self._sink}_outcome",
            actor=operator,
        )
        return self._public(saved)

    def revoke(
        self,
        record_id: str,
        *,
        expected_revision: int,
        evidence_sha256: str,
        actor: str,
    ) -> dict[str, Any]:
        current_raw = self._store.get(record_id)
        if current_raw is None:
            raise IdentityGovernanceStateError("identity_outcome_missing")
        current = dict(current_raw)
        if _record_revision(current) != _revision(expected_revision, "expected_revision"):
            raise IdentityGovernanceStaleBinding("identity_outcome_revision_stale")
        proof = _digest(evidence_sha256, "evidence_sha256")
        operator = _actor(actor)
        if current.get("status") == "revoked":
            existing = current.get("revocation")
            if not isinstance(existing, Mapping) or existing.get("evidence_sha256") != proof:
                raise IdentityGovernanceIdempotencyConflict(
                    "identity_outcome_revocation_conflict"
                )
            return self._public(current)

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "revoked"
            row["health"] = "healthy"
            row["lease"] = None
            row["next_attempt_at"] = 0.0
            row["revocation"] = {
                "evidence_sha256": proof,
                "revoked_at": self._now(),
                "actor_sha256": _sha256(operator),
                "prior_outcomes_preserved": True,
            }
            row["receipt_sha256"] = self._event_receipt(row)

        saved = self._update(
            current,
            mutate,
            action=f"revoke_identity_{self._sink}_outcome",
            actor=operator,
        )
        return self._public(saved)

    def status(
        self,
    ) -> dict[str, Any]:
        rows = self.list(limit=self._max_records)
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return {
            "schema": "lightwork.identity_governance.asset-outcome-status.v1",
            "sink": self._sink,
            "runtime_available": True,
            "downstream_consumer_attached": True,
            "outcome_mode": (
                "dynamic_risk_signal_and_score"
                if self._sink == "dynamic_risk"
                else "durable_internal_alert"
            ),
            "counts": counts,
            "max_attempts": self._max_attempts,
            "retry_base_seconds": self._retry_base_seconds,
            "retry_max_seconds": self._retry_max_seconds,
            "dead_letter_supported": True,
            "replay_supported": True,
            "revocation_supported": True,
            "no_change_supported": True,
            "exact_asset_revision_required": True,
            "exact_asset_digest_required": True,
            "provider_writes": False,
            "live_acceptance_verified": False,
        }


class GovernedConditionalAccessDecisionLedger:
    """Durable, evidence-bound authority for conditional-access decisions."""

    def __init__(
        self,
        *,
        tenant_sha256: str,
        store: OutcomeRecordStore | None = None,
        max_records: int = 10_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._tenant_sha256 = _digest(tenant_sha256, "tenant_sha256")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 1 <= max_records <= 10_000
        ):
            raise ValueError("conditional-access decision capacity is invalid")
        if not callable(clock):
            raise TypeError("conditional-access decision clock must be callable")
        selected = store or _default_decision_store()
        for method in ("get", "list", "create", "update"):
            if not callable(getattr(selected, method, None)):
                raise TypeError("conditional-access decision store is invalid")
        self._store = selected
        self._max_records = max_records
        self._clock = clock

    def _now(self) -> float:
        return _timestamp(self._clock(), "conditional-access authority time")

    def _validate(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if (
            not isinstance(record, Mapping)
            or record.get("schema") != DECISION_RECORD_SCHEMA
            or record.get("tenant_sha256") != self._tenant_sha256
            or record.get("status") not in {"active", "revoked"}
            or not isinstance(record.get("decision"), Mapping)
            or not isinstance(record.get("evidence"), Mapping)
        ):
            raise IdentityGovernanceStateError(
                "conditional_access_decision_record_invalid"
            )
        material = {
            "decision": record["decision"],
            "evidence": record["evidence"],
            "status": record["status"],
            "revocation": record.get("revocation"),
        }
        if record.get("record_sha256") != _sha256(material):
            raise IdentityGovernanceStateError(
                "conditional_access_decision_integrity_failed"
            )
        _record_revision(record)
        return dict(record)

    @staticmethod
    def _public(record: Mapping[str, Any]) -> dict[str, Any]:
        decision = record["decision"]
        evidence = record["evidence"]
        return {
            "decision_record_id": record["id"],
            "revision": record["revision"],
            "status": record["status"],
            "provider": decision["provider"],
            "principal_ref": decision["principal_ref"],
            "binding_sha256": decision["binding_sha256"],
            "binding_revision": decision["binding_revision"],
            "required_capability": decision["required_capability"],
            "action": decision["action"],
            "reason_code": decision["reason_code"],
            "decision_sha256": decision["decision_sha256"],
            "mapping_sha256": evidence["mapping_sha256"],
            "policy_sha256": evidence["policy_sha256"],
            "source_sha256": evidence["source_sha256"],
            "evidence_sha256": evidence["evidence_sha256"],
            "receipt_sha256": record["receipt_sha256"],
            "revocation": (
                dict(record["revocation"])
                if isinstance(record.get("revocation"), Mapping)
                else None
            ),
            "provider_policy_mutated": False,
            "live_acceptance_verified": False,
        }

    def record(
        self,
        decision: object,
        observation: object,
        mapping: object,
        *,
        actor: str,
    ) -> dict[str, Any]:
        from .ai_identity_governance_controls import (
            ConditionalAccessDecision,
            ConditionalAccessObservation,
            IdentityCapabilityMapping,
        )

        if not isinstance(decision, ConditionalAccessDecision):
            raise TypeError("decision must be a ConditionalAccessDecision")
        if not isinstance(observation, ConditionalAccessObservation):
            raise TypeError("observation must be a ConditionalAccessObservation")
        if not isinstance(mapping, IdentityCapabilityMapping):
            raise TypeError("mapping must be an IdentityCapabilityMapping")
        expected = (
            self._tenant_sha256,
            decision.provider,
            decision.principal_ref,
            decision.binding_sha256,
            decision.binding_revision,
        )
        observation_binding = (
            observation.tenant_sha256,
            observation.provider,
            observation.principal_ref,
            observation.binding_sha256,
            observation.binding_revision,
        )
        mapping_binding = (
            mapping.tenant_sha256,
            mapping.provider,
            mapping.principal_ref,
            mapping.federation_binding_sha256,
            mapping.authority_revision,
        )
        if expected != observation_binding or expected != mapping_binding:
            raise IdentityGovernanceBindingError(
                "conditional_access_decision_evidence_mismatch"
            )
        operator = _actor(actor)
        decision_value = asdict(decision)
        evidence = {
            "mapping_sha256": mapping.mapping_sha256,
            "mapping_revision": mapping.mapping_revision,
            "mapping_rules_sha256": mapping.rules_sha256,
            "policy_sha256": observation.policy_sha256,
            "source_sha256": observation.source_sha256,
            "observed_at": observation.observed_at,
        }
        evidence["evidence_sha256"] = _sha256(
            {
                "decision_sha256": decision.decision_sha256,
                **evidence,
            }
        )
        record_id = "IGCD-" + _sha256(
            {
                "tenant_sha256": self._tenant_sha256,
                "idempotency_sha256": decision.idempotency_sha256,
            }
        )[:32]
        receipt = _sha256(
            {
                "schema": DECISION_RECORD_SCHEMA,
                "decision_sha256": decision.decision_sha256,
                "evidence_sha256": evidence["evidence_sha256"],
                "idempotency_sha256": decision.idempotency_sha256,
            }
        )
        existing = self._store.get(record_id)
        if existing is not None:
            current = self._validate(existing)
            if (
                current["decision"] != decision_value
                or current["evidence"] != evidence
                or current["receipt_sha256"] != receipt
            ):
                raise IdentityGovernanceIdempotencyConflict(
                    "conditional_access_decision_idempotency_conflict"
                )
            return self._public(current)
        record = {
            "id": record_id,
            "schema": DECISION_RECORD_SCHEMA,
            "tenant_sha256": self._tenant_sha256,
            "status": "active",
            "decision": decision_value,
            "evidence": evidence,
            "receipt_sha256": receipt,
            "revocation": None,
            "recorded_at": self._now(),
            "actor_sha256": _sha256(operator),
            "provider_policy_mutated": False,
            "live_acceptance_verified": False,
        }
        record["record_sha256"] = _sha256(
            {
                "decision": decision_value,
                "evidence": evidence,
                "status": "active",
                "revocation": None,
            }
        )
        try:
            saved = self._store.create(
                record,
                action="record_conditional_access_decision",
                actor=operator,
                max_records=self._max_records,
            )
        except RecordConflict as exc:
            concurrent = self._store.get(record_id)
            if concurrent is None:
                raise IdentityGovernanceStateError(
                    "conditional_access_decision_admission_failed"
                ) from exc
            current = self._validate(concurrent)
            if current.get("receipt_sha256") != receipt:
                raise IdentityGovernanceIdempotencyConflict(
                    "conditional_access_decision_idempotency_conflict"
                ) from exc
            saved = current
        return self._public(self._validate(saved))

    def get(self, record_id: str) -> dict[str, Any] | None:
        if not isinstance(record_id, str) or not re.fullmatch(
            r"IGCD-[0-9a-f]{32}", record_id
        ):
            raise ValueError("conditional-access decision record id is invalid")
        value = self._store.get(record_id)
        return None if value is None else self._public(self._validate(value))

    def list(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= min(self._max_records, 1_000)
        ):
            raise ValueError("conditional-access decision list limit is invalid")
        rows = self._store.list(limit=self._max_records + 1)
        if len(rows) > self._max_records:
            raise IdentityGovernanceStateError(
                "conditional_access_decision_capacity_exceeded"
            )
        selected = [
            self._public(self._validate(row))
            for row in rows
            if row.get("tenant_sha256") == self._tenant_sha256
        ]
        return sorted(selected, key=lambda item: item["decision_record_id"])[:limit]

    def revoke(
        self,
        record_id: str,
        *,
        expected_revision: int,
        evidence_sha256: str,
        actor: str,
    ) -> dict[str, Any]:
        current_raw = self._store.get(record_id)
        if current_raw is None:
            raise IdentityGovernanceStateError(
                "conditional_access_decision_missing"
            )
        current = self._validate(current_raw)
        if _record_revision(current) != _revision(expected_revision, "expected_revision"):
            raise IdentityGovernanceStaleBinding(
                "conditional_access_decision_revision_stale"
            )
        proof = _digest(evidence_sha256, "evidence_sha256")
        operator = _actor(actor)
        if current["status"] == "revoked":
            revocation = current.get("revocation")
            if not isinstance(revocation, Mapping) or revocation.get(
                "evidence_sha256"
            ) != proof:
                raise IdentityGovernanceIdempotencyConflict(
                    "conditional_access_decision_revocation_conflict"
                )
            return self._public(current)

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "revoked"
            row["revocation"] = {
                "evidence_sha256": proof,
                "revoked_at": self._now(),
                "actor_sha256": _sha256(operator),
            }
            row["record_sha256"] = _sha256(
                {
                    "decision": row["decision"],
                    "evidence": row["evidence"],
                    "status": "revoked",
                    "revocation": row["revocation"],
                }
            )

        try:
            saved = self._store.update(
                record_id,
                mutate,
                expected_revision=_record_revision(current),
                action="revoke_conditional_access_decision",
                actor=operator,
            )
        except RecordConflict as exc:
            raise IdentityGovernanceStaleBinding(
                "conditional_access_decision_revision_stale"
            ) from exc
        if saved is None:
            raise IdentityGovernanceStateError(
                "conditional_access_decision_missing"
            )
        return self._public(self._validate(saved))

    def status(self) -> dict[str, Any]:
        rows = self.list(limit=min(self._max_records, 1_000))
        return {
            "schema": "lightwork.identity_governance.conditional-access-decision-ledger-status.v1",
            "active_decisions": sum(row["status"] == "active" for row in rows),
            "revoked_decisions": sum(row["status"] == "revoked" for row in rows),
            "evidence_bound": True,
            "cas_enforced": True,
            "provider_policy_mutated": False,
            "live_acceptance_verified": False,
        }


__all__ = [
    "ASSET_BINDING_SCHEMA",
    "ASSET_EVENT_SCHEMA",
    "ASSET_MANIFEST_SCHEMA",
    "IdentityAssetOutcomeConfigError",
    "IdentityAssetOutcomeCoverageError",
    "IdentityAssetOutcomeError",
    "IdentityChangeAssetBinding",
    "IdentityChangeAssetRegistry",
    "IdentityChangeOutcomeConsumer",
    "GovernedConditionalAccessDecisionLedger",
    "asset_event_from_change_event",
    "make_identity_change_asset_binding",
    "validate_asset_event",
]
