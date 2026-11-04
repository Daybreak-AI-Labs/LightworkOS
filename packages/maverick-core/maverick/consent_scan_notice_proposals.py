"""Governed reviewed-scan proposals for cookie and privacy disclosures.

This module is intentionally a local proposal authority, not a publisher.  A
trusted resolver chooses the tenant, property, and exact reviewed scan snapshot;
public/request data cannot provide report content, a publication target, legal
copy, credentials, or site configuration.  The authority stores only closed
metadata, digests, revisions, and hashed actors.  It performs no network I/O and
cannot mutate a provider, SDK, privacy notice, cookie banner, or web site.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import consent_storage
from .consent_scan_inventory import ConsentScanInventory, ConsentScanInventoryError
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

NOTICE_PROPOSAL_SCHEMA = "lightwork.consent-scan-notice-proposal.v1"
NOTICE_PROPOSAL_EXPORT_SCHEMA = "lightwork.consent-scan-notice-proposal-export.v1"

LIVE_NETWORK_IO = False
LIVE_PROVIDER_WRITES = False
LIVE_SITE_MUTATION = False
LIVE_NOTICE_PUBLICATION = False
LIVE_ACCEPTANCE_VERIFIED = False

_MAX_JSON_BYTES = 512 * 1024
_MAX_DISCLOSURES = 10_000
_INVENTORY_DISCOVERY_PAGE_SIZE = 500
_MAX_APPROVAL_TTL = 366 * 86_400
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CLASSIFICATIONS = frozenset(
    {"essential", "functional", "analytics", "advertising", "other", "not_a_tracker"}
)
_DISCLOSURE_CLASSES = _CLASSIFICATIONS - {"not_a_tracker"}
_KINDS = frozenset({"network", "cookie", "storage"})
_RESOURCE_TYPES = frozenset(
    {"script", "image", "xhr", "fetch", "media", "font", "websocket", "other"}
)
_ACTIONS = frozenset({"desired", "no_change", "reconcile", "rollback"})
_STATES = frozenset({"proposed", "approved", "locally_accepted"})


class ConsentScanNoticeProposalError(RuntimeError):
    """Base failure for the reviewed-scan proposal authority."""


class NoticeProposalDisabled(ConsentScanNoticeProposalError):
    """The exact default-off feature gate is not enabled."""


class NoticeProposalValidationError(ConsentScanNoticeProposalError, ValueError):
    """Input or trusted resolver output is outside the closed contract."""


class NoticeProposalConflict(ConsentScanNoticeProposalError):
    """A CAS, idempotency, approval, or freshness precondition changed."""


class NoticeProposalNotFound(ConsentScanNoticeProposalError):
    """A tenant/property-scoped proposal is unavailable."""


class NoticeProposalIntegrityError(ConsentScanNoticeProposalError):
    """Stored or injected authority metadata failed exact integrity validation."""


@dataclass(frozen=True)
class ReviewedScanDiscovery:
    """Closed, non-content metadata for one independently reviewed discovery."""

    tracker_key: str
    classification: str
    kind: str
    first_party: bool
    resource_type: str | None
    review_version: int
    review_sha256: str
    evidence_sha256: str
    valid_until: float
    revoked: bool = False
    finding_evidence_sha256: str | None = None


@dataclass(frozen=True)
class ReviewedScanSnapshot:
    """Server-resolved exact report/review authority for one property.

    ``classification_sha256`` is independently recomputed from the normalized
    discoveries.  It prevents a resolver from changing a classification while
    retaining an older aggregate binding.
    """

    tenant_id: str
    property_id: str
    report_id: str
    report_sha256: str
    property_revision: int
    property_sha256: str
    inventory_revision: int
    classification_sha256: str
    completed_at: float
    valid_until: float
    complete: bool
    truncated: bool
    revoked: bool
    discoveries: tuple[ReviewedScanDiscovery, ...]
    scanner_report_sha256: str | None = None
    inventory_sha256: str | None = None


@dataclass(frozen=True)
class IncompleteScanApproval:
    """Constructor-bound, independently reviewed exception for one exact report."""

    policy_ref: str
    tenant_sha256: str
    property_sha256: str
    report_sha256: str
    reviewer_sha256: str
    second_reviewer_sha256: str
    valid_until: float
    policy_sha256: str
    revoked: bool = False


@dataclass(frozen=True)
class InventoryNoticeProposalBinding:
    """Server-side selection of one inventory authority scope.

    ``inventory_revision`` is the revision of this enrolled binding.  The
    adapter also derives an exact aggregate digest from public inventory reads;
    it never invents a global inventory revision the inventory does not expose.
    """

    tenant_id: str
    property_id: str
    report_id: str
    inventory_revision: int
    allow_incomplete: IncompleteScanApproval | None = None


def notice_proposals_enabled() -> bool:
    """Return the exact, default-off consent/scanner/proposal gate."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        loaded = load_config()
    except Exception:
        return False
    if not isinstance(loaded, Mapping):
        return False
    consent = loaded.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    scanner = consent.get("scanner")
    if not isinstance(scanner, Mapping) or scanner.get("enable") is not True:
        return False
    proposals = scanner.get("notice_proposals")
    return isinstance(proposals, Mapping) and proposals.get("enable") is True


def require_notice_proposals_enabled() -> None:
    if not notice_proposals_enabled():
        raise NoticeProposalDisabled(
            "consent_preferences.scanner.notice_proposals is not explicitly enabled"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise NoticeProposalValidationError("proposal metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise NoticeProposalValidationError("proposal metadata exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except UnicodeEncodeError:
        return False


def _loads(value: object, label: str) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= _MAX_JSON_BYTES:
        raise NoticeProposalIntegrityError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise NoticeProposalIntegrityError(f"stored {label} is invalid") from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise NoticeProposalValidationError(f"{label} must be an opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise NoticeProposalValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _revision(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**31 - 1:
        raise NoticeProposalValidationError(f"{label} is outside its revision bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NoticeProposalValidationError(f"{label} must be a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise NoticeProposalValidationError(f"{label} must be a finite timestamp")
    return normalized


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise NoticeProposalValidationError("resolved tenant_id is invalid") from exc


def _idempotency(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise NoticeProposalValidationError("idempotency_key is invalid")
    return value, _text_sha256(value)


def _actor_hash(value: object) -> str:
    return _text_sha256(_ref(value, "resolved actor"))


class ConsentScanInventorySnapshotAdapter:
    """Optimistically read one exact reviewed snapshot through public APIs only.

    The binding and revocation resolvers are installed server-side and accept no
    request input.  The adapter double-reads every selected public record and
    rejects drift.  The inventory has no public global-revision API, so the
    binding supplies its own enrolled revision while the adapter derives an
    exact digest over the selected property's report, discoveries, and reviews.
    Public cursor pagination is followed up to the proposal authority's explicit
    10,000-discovery ceiling; no SQLite fallback is used.
    """

    def __init__(
        self,
        inventory: ConsentScanInventory,
        *,
        binding_resolver: Callable[[], InventoryNoticeProposalBinding],
        revoked_review_resolver: Callable[[], Sequence[str]],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(inventory, ConsentScanInventory):
            raise NoticeProposalValidationError(
                "inventory must be the local ConsentScanInventory authority"
            )
        if not all(callable(item) for item in (binding_resolver, revoked_review_resolver, clock)):
            raise NoticeProposalValidationError("inventory adapter resolvers must be callable")
        self._inventory = inventory
        self._binding_resolver = binding_resolver
        self._revoked_review_resolver = revoked_review_resolver
        self._clock = clock

    @staticmethod
    def product_boundaries() -> dict[str, bool | int]:
        return {
            "public_inventory_api_only": True,
            "optimistic_double_read": True,
            "global_inventory_revision_available": False,
            "binding_revision_required": True,
            "inventory_cursor_pagination": True,
            "maximum_exact_discoveries": _MAX_DISCLOSURES,
            "network_io": False,
            "provider_write": False,
            "site_mutation": False,
            "publication": False,
            "live_acceptance_verified": False,
        }

    @staticmethod
    def incomplete_policy_sha256(policy: IncompleteScanApproval) -> str:
        if not isinstance(policy, IncompleteScanApproval):
            raise NoticeProposalValidationError("incomplete policy uses an invalid type")
        return _sha256(
            {
                "policy_ref": _ref(policy.policy_ref, "policy_ref"),
                "tenant_sha256": _digest(policy.tenant_sha256, "tenant_sha256"),
                "property_sha256": _digest(policy.property_sha256, "property_sha256"),
                "report_sha256": _digest(policy.report_sha256, "report_sha256"),
                "reviewer_sha256": _digest(policy.reviewer_sha256, "reviewer_sha256"),
                "second_reviewer_sha256": _digest(
                    policy.second_reviewer_sha256, "second_reviewer_sha256"
                ),
                "valid_until": _timestamp(policy.valid_until, "policy valid_until"),
            }
        )

    @staticmethod
    def _binding(value: object) -> InventoryNoticeProposalBinding:
        if not isinstance(value, InventoryNoticeProposalBinding):
            raise NoticeProposalIntegrityError("binding resolver returned an invalid type")
        tenant = _tenant(value.tenant_id)
        property_id = _ref(value.property_id, "bound property_id")
        report_id = _ref(value.report_id, "bound report_id")
        revision = _revision(value.inventory_revision, "binding inventory_revision", positive=True)
        return InventoryNoticeProposalBinding(
            tenant_id=tenant,
            property_id=property_id,
            report_id=report_id,
            inventory_revision=revision,
            allow_incomplete=value.allow_incomplete,
        )

    def _revocations(self) -> frozenset[str]:
        try:
            values = self._revoked_review_resolver()
        except Exception as exc:
            raise NoticeProposalIntegrityError("review revocation resolver failed") from exc
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise NoticeProposalIntegrityError("review revocations must be a bounded sequence")
        if len(values) > _MAX_DISCLOSURES:
            raise NoticeProposalIntegrityError("review revocations exceed their bound")
        try:
            normalized = [_digest(value, "revoked review_sha256") for value in values]
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError("review revocations are invalid") from exc
        if len(normalized) != len(set(normalized)):
            raise NoticeProposalIntegrityError("review revocations contain duplicates")
        return frozenset(normalized)

    @classmethod
    def _allow_incomplete(
        cls,
        policy: object,
        *,
        tenant: str,
        property_sha256: str,
        report_sha256: str,
        now: float,
    ) -> float:
        if not isinstance(policy, IncompleteScanApproval):
            raise NoticeProposalConflict(
                "incomplete or truncated reports require an exact reviewed policy"
            )
        try:
            supplied_sha = _digest(policy.policy_sha256, "policy_sha256")
            expected_sha = cls.incomplete_policy_sha256(policy)
            reviewer = _digest(policy.reviewer_sha256, "reviewer_sha256")
            second = _digest(policy.second_reviewer_sha256, "second_reviewer_sha256")
            valid_until = _timestamp(policy.valid_until, "policy valid_until")
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError("incomplete policy metadata is invalid") from exc
        if not isinstance(policy.revoked, bool):
            raise NoticeProposalIntegrityError("incomplete policy revocation is invalid")
        if (
            policy.revoked
            or valid_until <= now
            or not _same(supplied_sha, expected_sha)
            or not _same(policy.tenant_sha256, _text_sha256(tenant))
            or not _same(policy.property_sha256, property_sha256)
            or not _same(policy.report_sha256, report_sha256)
            or _same(reviewer, second)
        ):
            raise NoticeProposalConflict(
                "incomplete report policy is stale, revoked, mismatched, or not independent"
            )
        return valid_until

    def _reviewed_finding(
        self,
        binding: InventoryNoticeProposalBinding,
        finding: object,
        discovery_by_key: Mapping[str, Mapping[str, Any]],
        revoked_reviews: frozenset[str],
        now: float,
    ) -> tuple[ReviewedScanDiscovery, dict[str, Any]]:
        if not isinstance(finding, Mapping):
            raise NoticeProposalIntegrityError("inventory report finding is invalid")
        try:
            tracker_key = _digest(finding.get("tracker_key"), "finding tracker_key")
            finding_evidence = _digest(finding.get("evidence_sha256"), "finding evidence_sha256")
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError("inventory finding pins are invalid") from exc
        discovery = discovery_by_key.get(tracker_key)
        if discovery is None:
            raise NoticeProposalConflict("report finding has no exact inventory discovery")
        review = discovery.get("review")
        if not isinstance(review, Mapping):
            raise NoticeProposalConflict("report finding is unknown or unreviewed")
        try:
            review_page = self._inventory.list_reviews(
                binding.tenant_id, binding.property_id, tracker_key, limit=2
            )
        except ConsentScanInventoryError as exc:
            raise NoticeProposalConflict("current tracker review is unavailable") from exc
        review_items = review_page.get("items")
        if not isinstance(review_items, list) or not review_items:
            raise NoticeProposalConflict("report finding has no current review")
        current_review = review_items[0]
        if not isinstance(current_review, Mapping) or current_review != review:
            raise NoticeProposalConflict("tracker review head drifted during the inventory read")
        try:
            review_sha = _digest(review.get("record_sha256"), "review_sha256")
            review_evidence = _digest(review.get("evidence_sha256"), "review evidence_sha256")
            reviewer = _digest(review.get("reviewer_sha256"), "reviewer_sha256")
            second_reviewer = _digest(
                review.get("second_reviewer_sha256"), "second_reviewer_sha256"
            )
            review_version = _revision(review.get("version"), "review version", positive=True)
            review_valid_until = _timestamp(review.get("valid_until"), "review valid_until")
            discovery_revision = _revision(
                discovery.get("revision"), "discovery revision", positive=True
            )
            discovery_sha = _digest(discovery.get("record_sha256"), "discovery record_sha256")
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError("inventory review pins are invalid") from exc
        classification = review.get("classification")
        kind = finding.get("kind")
        first_party = finding.get("first_party")
        resource_type = finding.get("resource_type")
        if (
            classification not in _CLASSIFICATIONS
            or kind not in _KINDS
            or not isinstance(first_party, bool)
            or (resource_type is not None and resource_type not in _RESOURCE_TYPES)
        ):
            raise NoticeProposalIntegrityError("inventory reviewed finding is not closed")
        if (
            review.get("report_id") != binding.report_id
            or review_valid_until <= now
            or review_sha in revoked_reviews
            or _same(reviewer, second_reviewer)
        ):
            raise NoticeProposalConflict(
                "review is stale, revoked, not report-bound, or not independently approved"
            )
        reviewed = ReviewedScanDiscovery(
            tracker_key=tracker_key,
            classification=str(classification),
            kind=str(kind),
            first_party=first_party,
            resource_type=str(resource_type) if resource_type is not None else None,
            review_version=review_version,
            review_sha256=review_sha,
            evidence_sha256=review_evidence,
            valid_until=review_valid_until,
            finding_evidence_sha256=finding_evidence,
        )
        aggregate = {
            "tracker_key": tracker_key,
            "finding_evidence_sha256": finding_evidence,
            "discovery_revision": discovery_revision,
            "discovery_sha256": discovery_sha,
            "review_version": review_version,
            "review_sha256": review_sha,
            "review_evidence_sha256": review_evidence,
        }
        return reviewed, aggregate

    def _list_all_discoveries(
        self,
        binding: InventoryNoticeProposalBinding,
    ) -> dict[str, object]:
        items: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        after: str | None = None
        while True:
            remaining = _MAX_DISCLOSURES - len(items)
            if remaining <= 0:
                raise NoticeProposalConflict(
                    "inventory discoveries exceed the proposal authority limit"
                )
            page_size = min(_INVENTORY_DISCOVERY_PAGE_SIZE, remaining)
            page = self._inventory.list_discoveries(
                binding.tenant_id,
                binding.property_id,
                after_tracker_key=after,
                limit=page_size,
            )
            if not isinstance(page, Mapping):
                raise NoticeProposalIntegrityError("inventory discovery page is invalid")
            page_items = page.get("items")
            truncated = page.get("truncated")
            if (
                not isinstance(page_items, list)
                or not isinstance(truncated, bool)
                or page.get("after_tracker_key") != after
                or len(page_items) > page_size
            ):
                raise NoticeProposalIntegrityError("inventory discovery page is invalid")
            page_keys: list[str] = []
            for item in page_items:
                if not isinstance(item, Mapping):
                    raise NoticeProposalIntegrityError("inventory discovery is invalid")
                try:
                    key = _digest(item.get("tracker_key"), "discovery tracker_key")
                except NoticeProposalValidationError as exc:
                    raise NoticeProposalIntegrityError(
                        "inventory discovery key is invalid"
                    ) from exc
                if (
                    key in seen
                    or (after is not None and key <= after)
                    or (page_keys and key <= page_keys[-1])
                ):
                    raise NoticeProposalIntegrityError(
                        "inventory discovery cursor order is invalid"
                    )
                seen.add(key)
                page_keys.append(key)
                items.append(item)
            next_after = page.get("next_after_tracker_key")
            if not truncated:
                if next_after is not None:
                    raise NoticeProposalIntegrityError(
                        "inventory discovery terminal cursor is invalid"
                    )
                break
            if not page_keys or len(items) >= _MAX_DISCLOSURES:
                raise NoticeProposalConflict(
                    "inventory discoveries exceed the proposal authority limit"
                )
            try:
                cursor = _digest(next_after, "next_after_tracker_key")
            except NoticeProposalValidationError as exc:
                raise NoticeProposalIntegrityError(
                    "inventory discovery continuation cursor is invalid"
                ) from exc
            if cursor != page_keys[-1] or cursor == after:
                raise NoticeProposalIntegrityError(
                    "inventory discovery continuation cursor is invalid"
                )
            after = cursor
        return {
            "items": items,
            "after_tracker_key": None,
            "truncated": False,
            "next_after_tracker_key": None,
        }

    def _read_once(
        self,
        binding: InventoryNoticeProposalBinding,
        revoked_reviews: frozenset[str],
        now: float,
    ) -> ReviewedScanSnapshot:
        try:
            property_result = self._inventory.get_property(binding.tenant_id, binding.property_id)
            report = self._inventory.get_report(binding.tenant_id, binding.report_id)
            report_job_id = _ref(report.get("job_id"), "report job_id")
            job = self._inventory.get_job(binding.tenant_id, report_job_id)
            discovery_page = self._list_all_discoveries(binding)
        except (ConsentScanInventoryError, NoticeProposalValidationError) as exc:
            raise NoticeProposalConflict("bound inventory authority is unavailable") from exc
        if report.get("property_id") != binding.property_id:
            raise NoticeProposalConflict("bound report belongs to a different property")
        try:
            property_revision = _revision(
                property_result.get("revision"), "property revision", positive=True
            )
            property_sha = _digest(property_result.get("record_sha256"), "property_sha256")
            report_record_sha = _digest(report.get("record_sha256"), "report record_sha256")
            scanner_report_sha = _digest(
                report.get("scanner_report_sha256"), "scanner_report_sha256"
            )
            job_revision = _revision(job.get("revision"), "report job revision", positive=True)
            job_sha = _digest(job.get("record_sha256"), "report job record_sha256")
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError(
                "inventory property or report pins are invalid"
            ) from exc
        if (
            job.get("status") != "succeeded"
            or job.get("report_id") != binding.report_id
            or job.get("property_id") != binding.property_id
            or job.get("property_revision") != property_revision
            or not _same(job.get("property_sha256"), property_sha)
        ):
            raise NoticeProposalConflict(
                "bound report job is stale or does not match the enrolled property"
            )
        complete = report.get("complete")
        truncated = report.get("truncated")
        if not isinstance(complete, bool) or not isinstance(truncated, bool):
            raise NoticeProposalIntegrityError("inventory report completeness is invalid")
        policy_valid_until: float | None = None
        if not complete or truncated:
            policy_valid_until = self._allow_incomplete(
                binding.allow_incomplete,
                tenant=binding.tenant_id,
                property_sha256=property_sha,
                report_sha256=report_record_sha,
                now=now,
            )

        items = discovery_page.get("items")
        if not isinstance(items, list):
            raise NoticeProposalIntegrityError("inventory discoveries are invalid")
        discovery_by_key: dict[str, Mapping[str, Any]] = {}
        for item in items:
            if not isinstance(item, Mapping):
                raise NoticeProposalIntegrityError("inventory discovery is invalid")
            try:
                key = _digest(item.get("tracker_key"), "discovery tracker_key")
            except NoticeProposalValidationError as exc:
                raise NoticeProposalIntegrityError("inventory discovery key is invalid") from exc
            if key in discovery_by_key:
                raise NoticeProposalIntegrityError("inventory discoveries contain duplicates")
            discovery_by_key[key] = item

        scanner_report = report.get("scanner_report")
        findings = scanner_report.get("findings") if isinstance(scanner_report, Mapping) else None
        if not isinstance(findings, list) or len(findings) > _MAX_DISCLOSURES:
            raise NoticeProposalIntegrityError("inventory report findings are invalid or oversized")
        reviewed: list[ReviewedScanDiscovery] = []
        aggregate: list[dict[str, Any]] = []
        seen: set[str] = set()
        valid_until_values: list[float] = []
        for finding in findings:
            reviewed_item, aggregate_item = self._reviewed_finding(
                binding, finding, discovery_by_key, revoked_reviews, now
            )
            if reviewed_item.tracker_key in seen:
                raise NoticeProposalIntegrityError(
                    "inventory report contains duplicate tracker keys"
                )
            seen.add(reviewed_item.tracker_key)
            valid_until_values.append(reviewed_item.valid_until)
            reviewed.append(reviewed_item)
            aggregate.append(aggregate_item)
        aggregate.sort(key=lambda value: value["tracker_key"])
        inventory_sha = _sha256(
            {
                "binding_revision": binding.inventory_revision,
                "property_id": binding.property_id,
                "property_revision": property_revision,
                "property_sha256": property_sha,
                "report_id": binding.report_id,
                "report_record_sha256": report_record_sha,
                "scanner_report_sha256": scanner_report_sha,
                "report_job_revision": job_revision,
                "report_job_sha256": job_sha,
                "reviewed_discoveries": aggregate,
                "incomplete_policy_sha256": (
                    binding.allow_incomplete.policy_sha256
                    if policy_valid_until is not None and binding.allow_incomplete is not None
                    else None
                ),
            }
        )
        validity = valid_until_values + (
            [policy_valid_until] if policy_valid_until is not None else []
        )
        if not validity:
            raise NoticeProposalConflict("selected report has no independently reviewed findings")
        reviewed_tuple = tuple(sorted(reviewed, key=lambda value: value.tracker_key))
        return ReviewedScanSnapshot(
            tenant_id=binding.tenant_id,
            property_id=binding.property_id,
            report_id=binding.report_id,
            report_sha256=report_record_sha,
            property_revision=property_revision,
            property_sha256=property_sha,
            inventory_revision=binding.inventory_revision,
            classification_sha256=ConsentScanNoticeProposalStore.classification_sha256(
                reviewed_tuple
            ),
            completed_at=_timestamp(report.get("completed_at"), "report completed_at"),
            valid_until=min(validity),
            complete=complete,
            truncated=truncated,
            revoked=False,
            discoveries=reviewed_tuple,
            scanner_report_sha256=scanner_report_sha,
            inventory_sha256=inventory_sha,
        )

    def __call__(self) -> ReviewedScanSnapshot:
        now = _timestamp(self._clock(), "adapter clock")
        try:
            first_binding = self._binding_resolver()
        except Exception as exc:
            raise NoticeProposalIntegrityError("inventory binding resolver failed") from exc
        first_binding = self._binding(first_binding)
        first = self._read_once(first_binding, self._revocations(), now)
        try:
            second_binding = self._binding_resolver()
        except Exception as exc:
            raise NoticeProposalIntegrityError("inventory binding resolver failed") from exc
        second_binding = self._binding(second_binding)
        second = self._read_once(second_binding, self._revocations(), now)
        if first_binding != second_binding or asdict(first) != asdict(second):
            raise NoticeProposalConflict("inventory authority drifted during snapshot resolution")
        return second


class ConsentScanNoticeProposalStore:
    """Durable local authority for review, approval, and metadata acceptance."""

    def __init__(
        self,
        path: Path,
        *,
        snapshot_resolver: Callable[[], ReviewedScanSnapshot],
        actor_resolver: Callable[[], str],
        signing_key_resolver: Callable[[str], bytes],
        signing_key_ref: str = "local-notice-proposals-v1",
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        gate: Callable[[], None] = require_notice_proposals_enabled,
        approval_ttl_seconds: int = 86_400,
    ) -> None:
        if not isinstance(path, Path):
            raise NoticeProposalValidationError("path must be a pathlib.Path")
        if not all(
            callable(item)
            for item in (snapshot_resolver, actor_resolver, signing_key_resolver, clock, gate)
        ):
            raise NoticeProposalValidationError("proposal authority dependencies must be callable")
        if (
            isinstance(approval_ttl_seconds, bool)
            or not isinstance(approval_ttl_seconds, int)
            or not 1 <= approval_ttl_seconds <= _MAX_APPROVAL_TTL
        ):
            raise NoticeProposalValidationError("approval_ttl_seconds is outside its bound")
        self._path = path
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        self._snapshot_resolver = snapshot_resolver
        self._actor_resolver = actor_resolver
        self._signing_key_resolver = signing_key_resolver
        self._signing_key_ref = _ref(signing_key_ref, "signing_key_ref")
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_hex(12)}")
        self._gate = gate
        self._approval_ttl = approval_ttl_seconds
        ensure_private_directory(path.parent)
        self._initialize()
        if not consent_storage.shared():
            ensure_private_file(path)

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        return {
            "local_reviewed_scan_proposals": True,
            "structured_metadata_only": True,
            "independent_approval": True,
            "legal_prose_generation": False,
            "automatic_publication": False,
            "network_io": LIVE_NETWORK_IO,
            "provider_write": LIVE_PROVIDER_WRITES,
            "site_mutation": LIVE_SITE_MUTATION,
            "notice_publication": LIVE_NOTICE_PUBLICATION,
            "live_acceptance_verified": LIVE_ACCEPTANCE_VERIFIED,
        }

    def _require(self) -> None:
        self._gate()

    def _now(self) -> float:
        return _timestamp(self._clock(), "clock")

    def _new_id(self, prefix: str) -> str:
        return _ref(self._id_factory(prefix), "generated identifier")

    @contextlib.contextmanager
    def _connect(self):
        with cross_process_lock(self._lock_path):
            if consent_storage.shared():
                connection = consent_storage.connect(self._path, timeout=30.0, implicit_transactions=True)
            else:
                connection = sqlite3.connect(self._path, timeout=30.0)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
            except BaseException:
                if isinstance(connection, sqlite3.Connection):
                    connection.close()
                raise
            try:
                yield connection
            finally:
                connection.close()

    def _initialize(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS scan_notice_heads (
                tenant TEXT NOT NULL, property_id TEXT NOT NULL, revision INTEGER NOT NULL,
                current_proposal_id TEXT NOT NULL, effective_proposal_id TEXT,
                effective_metadata_sha256 TEXT, updated_at REAL NOT NULL,
                record_sha256 TEXT NOT NULL, PRIMARY KEY (tenant, property_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_notice_proposals (
                tenant TEXT NOT NULL, property_id TEXT NOT NULL, proposal_id TEXT NOT NULL,
                version INTEGER NOT NULL, action TEXT NOT NULL, definition_json TEXT NOT NULL,
                definition_sha256 TEXT NOT NULL, state_json TEXT NOT NULL,
                state_sha256 TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
                PRIMARY KEY (tenant, property_id, proposal_id),
                UNIQUE (tenant, property_id, version)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_notice_approvals (
                tenant TEXT NOT NULL, property_id TEXT NOT NULL, proposal_id TEXT NOT NULL,
                approval_json TEXT NOT NULL, integrity_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant, property_id, proposal_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_notice_idempotency (
                tenant TEXT NOT NULL, property_id TEXT NOT NULL, namespace TEXT NOT NULL,
                key_sha256 TEXT NOT NULL, request_sha256 TEXT NOT NULL, result_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (tenant, property_id, namespace, key_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_notice_exports (
                tenant TEXT NOT NULL, property_id TEXT NOT NULL, export_id TEXT NOT NULL,
                payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                signature_sha256 TEXT NOT NULL, created_at REAL NOT NULL,
                PRIMARY KEY (tenant, property_id, export_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_notice_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
                property_id TEXT NOT NULL, event_id TEXT NOT NULL, event_type TEXT NOT NULL,
                object_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                previous_event_sha256 TEXT, event_sha256 TEXT NOT NULL, created_at REAL NOT NULL,
                UNIQUE (tenant, property_id, event_id)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_definitions_no_update
            BEFORE UPDATE OF definition_json, definition_sha256, version, action
            ON scan_notice_proposals
            BEGIN SELECT RAISE(ABORT, 'proposal definitions are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_proposals_no_delete
            BEFORE DELETE ON scan_notice_proposals
            BEGIN SELECT RAISE(ABORT, 'proposals are immutable records'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_idempotency_no_update
            BEFORE UPDATE ON scan_notice_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_idempotency_no_delete
            BEFORE DELETE ON scan_notice_idempotency
            BEGIN SELECT RAISE(ABORT, 'idempotency records are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_audit_no_update
            BEFORE UPDATE ON scan_notice_audit
            BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS scan_notice_audit_no_delete
            BEFORE DELETE ON scan_notice_audit
            BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END
            """,
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)
            connection.commit()

    @staticmethod
    def _normalized_snapshot(snapshot: object, now: float) -> dict[str, Any]:
        if not isinstance(snapshot, ReviewedScanSnapshot):
            raise NoticeProposalIntegrityError("snapshot resolver returned an invalid type")
        tenant = _tenant(snapshot.tenant_id)
        property_id = _ref(snapshot.property_id, "resolved property_id")
        report_id = _ref(snapshot.report_id, "resolved report_id")
        report_sha = _digest(snapshot.report_sha256, "report_sha256")
        scanner_report_sha = (
            _digest(snapshot.scanner_report_sha256, "scanner_report_sha256")
            if snapshot.scanner_report_sha256 is not None
            else report_sha
        )
        property_revision = _revision(
            snapshot.property_revision, "property_revision", positive=True
        )
        property_sha = _digest(snapshot.property_sha256, "property_sha256")
        inventory_revision = _revision(
            snapshot.inventory_revision, "inventory_revision", positive=True
        )
        completed_at = _timestamp(snapshot.completed_at, "completed_at")
        valid_until = _timestamp(snapshot.valid_until, "valid_until")
        if not isinstance(snapshot.complete, bool) or not isinstance(snapshot.truncated, bool):
            raise NoticeProposalIntegrityError("snapshot completeness fields are invalid")
        if not isinstance(snapshot.revoked, bool):
            raise NoticeProposalIntegrityError("snapshot revocation field is invalid")
        if snapshot.revoked or valid_until <= now:
            raise NoticeProposalConflict("reviewed scan snapshot is expired or revoked")
        if completed_at > now:
            raise NoticeProposalIntegrityError("reviewed scan snapshot is future-dated")
        if (
            not isinstance(snapshot.discoveries, tuple)
            or len(snapshot.discoveries) > _MAX_DISCLOSURES
        ):
            raise NoticeProposalIntegrityError("reviewed discoveries exceed their closed bound")

        normalized: list[dict[str, Any]] = []
        all_reviews: list[dict[str, Any]] = []
        seen: set[str] = set()
        minimum_valid_until = valid_until
        for discovery in snapshot.discoveries:
            if not isinstance(discovery, ReviewedScanDiscovery):
                raise NoticeProposalIntegrityError("reviewed discovery has an invalid type")
            tracker_key = _digest(discovery.tracker_key, "tracker_key")
            if tracker_key in seen:
                raise NoticeProposalIntegrityError("reviewed discoveries contain a duplicate")
            seen.add(tracker_key)
            if discovery.classification not in _CLASSIFICATIONS:
                raise NoticeProposalIntegrityError("reviewed classification is not closed")
            if discovery.kind not in _KINDS:
                raise NoticeProposalIntegrityError("reviewed discovery kind is not closed")
            if not isinstance(discovery.first_party, bool):
                raise NoticeProposalIntegrityError("first_party must be explicit")
            if (
                discovery.resource_type is not None
                and discovery.resource_type not in _RESOURCE_TYPES
            ):
                raise NoticeProposalIntegrityError("resource_type is not closed")
            review_version = _revision(discovery.review_version, "review_version", positive=True)
            review_sha = _digest(discovery.review_sha256, "review_sha256")
            evidence_sha = _digest(discovery.evidence_sha256, "evidence_sha256")
            finding_evidence_sha = (
                _digest(discovery.finding_evidence_sha256, "finding_evidence_sha256")
                if discovery.finding_evidence_sha256 is not None
                else evidence_sha
            )
            review_valid_until = _timestamp(discovery.valid_until, "review valid_until")
            if not isinstance(discovery.revoked, bool):
                raise NoticeProposalIntegrityError("review revocation field is invalid")
            if discovery.revoked or review_valid_until <= now:
                raise NoticeProposalConflict("a reviewed classification is expired or revoked")
            minimum_valid_until = min(minimum_valid_until, review_valid_until)
            review_pin = {
                "tracker_key": tracker_key,
                "classification": discovery.classification,
                "kind": discovery.kind,
                "first_party": discovery.first_party,
                "resource_type": discovery.resource_type,
                "review_version": review_version,
                "review_sha256": review_sha,
                "evidence_sha256": evidence_sha,
                "finding_evidence_sha256": finding_evidence_sha,
                "valid_until": review_valid_until,
            }
            all_reviews.append(review_pin)
            if discovery.classification in _DISCLOSURE_CLASSES:
                normalized.append(review_pin)
        all_reviews.sort(key=lambda item: item["tracker_key"])
        classification_sha = _sha256(all_reviews)
        supplied_classification_sha = _digest(
            snapshot.classification_sha256, "classification_sha256"
        )
        if not _same(classification_sha, supplied_classification_sha):
            raise NoticeProposalIntegrityError("classification digest does not match reviews")
        normalized.sort(key=lambda item: item["tracker_key"])
        inventory_sha = (
            _digest(snapshot.inventory_sha256, "inventory_sha256")
            if snapshot.inventory_sha256 is not None
            else _sha256(
                {
                    "property_revision": property_revision,
                    "property_sha256": property_sha,
                    "report_sha256": report_sha,
                    "scanner_report_sha256": scanner_report_sha,
                    "inventory_revision": inventory_revision,
                    "classification_sha256": classification_sha,
                }
            )
        )
        return {
            "tenant_id": tenant,
            "property_id": property_id,
            "report_id": report_id,
            "report_sha256": report_sha,
            "scanner_report_sha256": scanner_report_sha,
            "property_revision": property_revision,
            "property_sha256": property_sha,
            "inventory_revision": inventory_revision,
            "inventory_sha256": inventory_sha,
            "classification_sha256": classification_sha,
            "completed_at": completed_at,
            "valid_until": minimum_valid_until,
            "complete": snapshot.complete,
            "truncated": snapshot.truncated,
            "disclosures": normalized,
        }

    def _context(self) -> tuple[dict[str, Any], str, float]:
        self._require()
        now = self._now()
        try:
            raw_snapshot = self._snapshot_resolver()
            actor = self._actor_resolver()
        except ConsentScanNoticeProposalError:
            raise
        except Exception as exc:
            raise NoticeProposalIntegrityError("trusted proposal resolver failed") from exc
        try:
            normalized = self._normalized_snapshot(raw_snapshot, now)
        except NoticeProposalValidationError as exc:
            raise NoticeProposalIntegrityError(
                "trusted snapshot contains invalid authority metadata"
            ) from exc
        return normalized, _actor_hash(actor), now

    @staticmethod
    def classification_sha256(discoveries: Sequence[ReviewedScanDiscovery]) -> str:
        """Compute the resolver binding without accepting unstructured content."""

        pins = []
        for item in discoveries:
            if not isinstance(item, ReviewedScanDiscovery):
                raise NoticeProposalValidationError("discoveries must use the closed dataclass")
            pins.append(
                {
                    "tracker_key": _digest(item.tracker_key, "tracker_key"),
                    "classification": item.classification,
                    "kind": item.kind,
                    "first_party": item.first_party,
                    "resource_type": item.resource_type,
                    "review_version": _revision(
                        item.review_version, "review_version", positive=True
                    ),
                    "review_sha256": _digest(item.review_sha256, "review_sha256"),
                    "evidence_sha256": _digest(item.evidence_sha256, "evidence_sha256"),
                    "finding_evidence_sha256": (
                        _digest(item.finding_evidence_sha256, "finding_evidence_sha256")
                        if item.finding_evidence_sha256 is not None
                        else _digest(item.evidence_sha256, "evidence_sha256")
                    ),
                    "valid_until": _timestamp(item.valid_until, "valid_until"),
                }
            )
        return _sha256(sorted(pins, key=lambda value: value["tracker_key"]))

    @staticmethod
    def _metadata(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        counts = dict.fromkeys(sorted(_DISCLOSURE_CLASSES), 0)
        first_party = 0
        for item in snapshot["disclosures"]:
            counts[item["classification"]] += 1
            first_party += int(item["first_party"])
        disclosures = [
            {
                "tracker_key": item["tracker_key"],
                "classification": item["classification"],
                "kind": item["kind"],
                "first_party": item["first_party"],
                "resource_type": item["resource_type"],
                "review_version": item["review_version"],
                "review_sha256": item["review_sha256"],
                "evidence_sha256": item["evidence_sha256"],
                "finding_evidence_sha256": item["finding_evidence_sha256"],
            }
            for item in snapshot["disclosures"]
        ]
        return {
            "schema": NOTICE_PROPOSAL_SCHEMA,
            "disclosures": disclosures,
            "classification_counts": counts,
            "disclosure_count": len(disclosures),
            "first_party_count": first_party,
            "third_party_count": len(disclosures) - first_party,
            "scan_complete": snapshot["complete"],
            "scan_truncated": snapshot["truncated"],
            "legal_prose_included": False,
        }

    @staticmethod
    def _head_result(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "property_id": str(row["property_id"]),
            "revision": int(row["revision"]),
            "current_proposal_id": str(row["current_proposal_id"]),
            "effective_proposal_id": row["effective_proposal_id"],
            "effective_metadata_sha256": row["effective_metadata_sha256"],
            "updated_at": float(row["updated_at"]),
        }
        expected = _sha256(body)
        if not _same(expected, str(row["record_sha256"])):
            raise NoticeProposalIntegrityError("stored proposal head failed integrity")
        return {**body, "record_sha256": expected}

    @staticmethod
    def _proposal_result(row: sqlite3.Row) -> dict[str, Any]:
        definition = _loads(row["definition_json"], "proposal definition")
        state = _loads(row["state_json"], "proposal state")
        if not isinstance(definition, dict) or not isinstance(state, dict):
            raise NoticeProposalIntegrityError("stored proposal payload is invalid")
        definition_sha = _sha256(definition)
        state_sha = _sha256(state)
        if (
            not _same(definition_sha, str(row["definition_sha256"]))
            or not _same(state_sha, str(row["state_sha256"]))
            or definition.get("proposal_id") != row["proposal_id"]
            or definition.get("property_id") != row["property_id"]
            or definition.get("version") != row["version"]
            or definition.get("action") != row["action"]
            or state.get("proposal_id") != row["proposal_id"]
            or state.get("state") not in _STATES
        ):
            raise NoticeProposalIntegrityError("stored proposal failed integrity")
        return {
            **definition,
            **state,
            "definition_sha256": definition_sha,
            "state_sha256": state_sha,
        }

    def _proposal_row(
        self, connection: sqlite3.Connection, tenant: str, property_id: str, proposal_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM scan_notice_proposals WHERE tenant=? AND property_id=? "
            "AND proposal_id=?",
            (tenant, property_id, proposal_id),
        ).fetchone()
        if row is None:
            raise NoticeProposalNotFound("proposal is unavailable")
        self._proposal_result(row)
        return row

    @staticmethod
    def _approval_result(row: sqlite3.Row) -> dict[str, Any]:
        payload = _loads(row["approval_json"], "proposal approval")
        if not isinstance(payload, dict):
            raise NoticeProposalIntegrityError("stored proposal approval is invalid")
        expected = _sha256(payload)
        if not _same(expected, str(row["integrity_sha256"])):
            raise NoticeProposalIntegrityError("stored proposal approval failed integrity")
        return {**payload, "integrity_sha256": expected}

    @staticmethod
    def _idempotent(
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
        namespace: str,
        key_sha: str,
        request_sha: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256,result_json FROM scan_notice_idempotency WHERE "
            "tenant=? AND property_id=? AND namespace=? AND key_sha256=?",
            (tenant, property_id, namespace, key_sha),
        ).fetchone()
        if row is None:
            return None
        if not _same(str(row["request_sha256"]), request_sha):
            raise NoticeProposalConflict("idempotency key was rebound to different content")
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise NoticeProposalIntegrityError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_idempotency(
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
        namespace: str,
        key_sha: str,
        request_sha: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO scan_notice_idempotency(tenant,property_id,namespace,key_sha256,"
            "request_sha256,result_json,created_at) VALUES (?,?,?,?,?,?,?)",
            (
                tenant,
                property_id,
                namespace,
                key_sha,
                request_sha,
                _canonical(result).decode("ascii"),
                now,
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
        event_type: str,
        object_id: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM scan_notice_audit WHERE tenant=? AND property_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant, property_id),
        ).fetchone()
        previous_sha = str(previous["event_sha256"]) if previous else None
        body = {
            "event_id": self._new_id("CSNP-AUD"),
            "event_type": _ref(event_type, "event_type"),
            "object_id": _ref(object_id, "object_id"),
            "payload_sha256": _sha256(payload),
            "previous_event_sha256": previous_sha,
            "created_at": now,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO scan_notice_audit(tenant,property_id,event_id,event_type,object_id,"
            "payload_sha256,previous_event_sha256,event_sha256,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                property_id,
                body["event_id"],
                body["event_type"],
                body["object_id"],
                body["payload_sha256"],
                previous_sha,
                event_sha,
                now,
            ),
        )

    @staticmethod
    def _source_pins(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "report_id": snapshot["report_id"],
            "report_sha256": snapshot["report_sha256"],
            "scanner_report_sha256": snapshot["scanner_report_sha256"],
            "property_revision": snapshot["property_revision"],
            "property_sha256": snapshot["property_sha256"],
            "inventory_revision": snapshot["inventory_revision"],
            "inventory_sha256": snapshot["inventory_sha256"],
            "classification_sha256": snapshot["classification_sha256"],
            "completed_at": snapshot["completed_at"],
            "valid_until": snapshot["valid_until"],
        }

    def propose(self, *, expected_revision: int, idempotency_key: str) -> dict[str, Any]:
        """Create a deterministic desired/no-change/reconcile proposal."""

        snapshot, actor_sha, now = self._context()
        expected = _revision(expected_revision, "expected_revision")
        _raw_key, key_sha = _idempotency(idempotency_key)
        metadata = self._metadata(snapshot)
        metadata_sha = _sha256(metadata)
        request = {
            "operation": "propose",
            "source_pins": self._source_pins(snapshot),
            "metadata_sha256": metadata_sha,
            "expected_revision": expected,
            "actor_sha256": actor_sha,
        }
        request_sha = _sha256(request)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.create", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                head_row = connection.execute(
                    "SELECT * FROM scan_notice_heads WHERE tenant=? AND property_id=?",
                    (tenant, property_id),
                ).fetchone()
                current = self._head_result(head_row) if head_row else None
                current_revision = current["revision"] if current else 0
                if current_revision != expected:
                    raise NoticeProposalConflict(
                        f"proposal head revision is {current_revision}, expected {expected}"
                    )
                effective_sha = current["effective_metadata_sha256"] if current else None
                action = (
                    "desired"
                    if effective_sha is None
                    else "no_change"
                    if _same(effective_sha, metadata_sha)
                    else "reconcile"
                )
                proposal_id = self._new_id("CSNP")
                latest_version = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(version),0) FROM scan_notice_proposals "
                        "WHERE tenant=? AND property_id=?",
                        (tenant, property_id),
                    ).fetchone()[0]
                )
                definition = {
                    "schema": NOTICE_PROPOSAL_SCHEMA,
                    "proposal_id": proposal_id,
                    "property_id": property_id,
                    "version": latest_version + 1,
                    "action": action,
                    "source_pins": self._source_pins(snapshot),
                    "metadata": metadata,
                    "metadata_sha256": metadata_sha,
                    "rollback_target_proposal_id": None,
                    "created_by_sha256": actor_sha,
                    "created_at": now,
                    "expires_at": min(snapshot["valid_until"], now + self._approval_ttl),
                }
                state = {
                    "proposal_id": proposal_id,
                    "state": "proposed",
                    "revision": 1,
                    "accepted_at": None,
                    "updated_at": now,
                }
                definition_sha = _sha256(definition)
                state_sha = _sha256(state)
                connection.execute(
                    "INSERT INTO scan_notice_proposals(tenant,property_id,proposal_id,version,"
                    "action,definition_json,definition_sha256,state_json,state_sha256,created_at,"
                    "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        property_id,
                        proposal_id,
                        definition["version"],
                        action,
                        _canonical(definition).decode("ascii"),
                        definition_sha,
                        _canonical(state).decode("ascii"),
                        state_sha,
                        now,
                        now,
                    ),
                )
                head = {
                    "property_id": property_id,
                    "revision": current_revision + 1,
                    "current_proposal_id": proposal_id,
                    "effective_proposal_id": current["effective_proposal_id"] if current else None,
                    "effective_metadata_sha256": effective_sha,
                    "updated_at": now,
                }
                head_sha = _sha256(head)
                if current is None:
                    connection.execute(
                        "INSERT INTO scan_notice_heads VALUES (?,?,?,?,?,?,?,?)",
                        (
                            tenant,
                            property_id,
                            head["revision"],
                            proposal_id,
                            None,
                            None,
                            now,
                            head_sha,
                        ),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE scan_notice_heads SET revision=?,current_proposal_id=?,"
                        "updated_at=?,record_sha256=? WHERE tenant=? AND property_id=? "
                        "AND revision=?",
                        (
                            head["revision"],
                            proposal_id,
                            now,
                            head_sha,
                            tenant,
                            property_id,
                            current_revision,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise NoticeProposalConflict("proposal head changed concurrently")
                result = {
                    **definition,
                    **state,
                    "definition_sha256": definition_sha,
                    "state_sha256": state_sha,
                    "head_revision": head["revision"],
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.created",
                    proposal_id,
                    {"action": action, "definition_sha256": definition_sha},
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.create",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def propose_rollback(
        self,
        target_proposal_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Propose restoring prior accepted metadata; never perform a site rollback."""

        snapshot, actor_sha, now = self._context()
        target_id = _ref(target_proposal_id, "target_proposal_id")
        expected = _revision(expected_revision, "expected_revision", positive=True)
        _raw_key, key_sha = _idempotency(idempotency_key)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                target = self._proposal_result(
                    self._proposal_row(connection, tenant, property_id, target_id)
                )
                if target["state"] != "locally_accepted":
                    raise NoticeProposalConflict("rollback target was not locally accepted")
                request = {
                    "operation": "rollback",
                    "source_pins": self._source_pins(snapshot),
                    "target_proposal_id": target_id,
                    "target_definition_sha256": target["definition_sha256"],
                    "expected_revision": expected,
                    "actor_sha256": actor_sha,
                }
                request_sha = _sha256(request)
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.rollback", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                head_row = connection.execute(
                    "SELECT * FROM scan_notice_heads WHERE tenant=? AND property_id=?",
                    (tenant, property_id),
                ).fetchone()
                if head_row is None:
                    raise NoticeProposalConflict("proposal head is unavailable")
                current = self._head_result(head_row)
                if current["revision"] != expected:
                    raise NoticeProposalConflict(
                        f"proposal head revision is {current['revision']}, expected {expected}"
                    )
                if current["effective_proposal_id"] == target_id:
                    raise NoticeProposalConflict("rollback target is already effective")
                proposal_id = self._new_id("CSNP")
                latest_version = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(version),0) FROM scan_notice_proposals "
                        "WHERE tenant=? AND property_id=?",
                        (tenant, property_id),
                    ).fetchone()[0]
                )
                definition = {
                    "schema": NOTICE_PROPOSAL_SCHEMA,
                    "proposal_id": proposal_id,
                    "property_id": property_id,
                    "version": latest_version + 1,
                    "action": "rollback",
                    "source_pins": self._source_pins(snapshot),
                    "metadata": target["metadata"],
                    "metadata_sha256": target["metadata_sha256"],
                    "rollback_target_proposal_id": target_id,
                    "created_by_sha256": actor_sha,
                    "created_at": now,
                    "expires_at": min(snapshot["valid_until"], now + self._approval_ttl),
                }
                state = {
                    "proposal_id": proposal_id,
                    "state": "proposed",
                    "revision": 1,
                    "accepted_at": None,
                    "updated_at": now,
                }
                definition_sha = _sha256(definition)
                state_sha = _sha256(state)
                connection.execute(
                    "INSERT INTO scan_notice_proposals VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        property_id,
                        proposal_id,
                        definition["version"],
                        "rollback",
                        _canonical(definition).decode("ascii"),
                        definition_sha,
                        _canonical(state).decode("ascii"),
                        state_sha,
                        now,
                        now,
                    ),
                )
                head = {
                    "property_id": property_id,
                    "revision": expected + 1,
                    "current_proposal_id": proposal_id,
                    "effective_proposal_id": current["effective_proposal_id"],
                    "effective_metadata_sha256": current["effective_metadata_sha256"],
                    "updated_at": now,
                }
                updated = connection.execute(
                    "UPDATE scan_notice_heads SET revision=?,current_proposal_id=?,updated_at=?,"
                    "record_sha256=? WHERE tenant=? AND property_id=? AND revision=?",
                    (
                        head["revision"],
                        proposal_id,
                        now,
                        _sha256(head),
                        tenant,
                        property_id,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise NoticeProposalConflict("proposal head changed concurrently")
                result = {
                    **definition,
                    **state,
                    "definition_sha256": definition_sha,
                    "state_sha256": state_sha,
                    "head_revision": head["revision"],
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.rollback_created",
                    proposal_id,
                    {"target_definition_sha256": target["definition_sha256"]},
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.rollback",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _assert_source_current(
        self, proposal: Mapping[str, Any], snapshot: Mapping[str, Any], now: float
    ) -> None:
        pins = proposal.get("source_pins")
        if not isinstance(pins, Mapping) or pins != self._source_pins(snapshot):
            raise NoticeProposalConflict("proposal source pins are stale")
        if proposal["expires_at"] <= now:
            raise NoticeProposalConflict("proposal approval window expired")

    def approve(
        self,
        proposal_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Record one independent maker-checker approval over exact pins."""

        snapshot, actor_sha, now = self._context()
        proposal_ref = _ref(proposal_id, "proposal_id")
        expected = _revision(expected_revision, "expected_revision", positive=True)
        _raw_key, key_sha = _idempotency(idempotency_key)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._proposal_row(connection, tenant, property_id, proposal_ref)
                proposal = self._proposal_result(row)
                self._assert_source_current(proposal, snapshot, now)
                request = {
                    "operation": "approve",
                    "proposal_id": proposal_ref,
                    "definition_sha256": proposal["definition_sha256"],
                    "expected_revision": expected,
                    "actor_sha256": actor_sha,
                }
                request_sha = _sha256(request)
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.approve", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                if proposal["revision"] != expected or proposal["state"] != "proposed":
                    raise NoticeProposalConflict("proposal approval state or revision changed")
                if _same(proposal["created_by_sha256"], actor_sha):
                    raise NoticeProposalConflict(
                        "proposal creator cannot approve their own proposal"
                    )
                if connection.execute(
                    "SELECT 1 FROM scan_notice_approvals WHERE tenant=? AND property_id=? "
                    "AND proposal_id=?",
                    (tenant, property_id, proposal_ref),
                ).fetchone():
                    raise NoticeProposalConflict("proposal already has an approval")
                approval = {
                    "proposal_id": proposal_ref,
                    "definition_sha256": proposal["definition_sha256"],
                    "actor_sha256": actor_sha,
                    "revision": 1,
                    "approved_at": now,
                    "expires_at": min(proposal["expires_at"], now + self._approval_ttl),
                    "revoked_at": None,
                }
                approval_sha = _sha256(approval)
                connection.execute(
                    "INSERT INTO scan_notice_approvals VALUES (?,?,?,?,?)",
                    (
                        tenant,
                        property_id,
                        proposal_ref,
                        _canonical(approval).decode("ascii"),
                        approval_sha,
                    ),
                )
                state = {
                    "proposal_id": proposal_ref,
                    "state": "approved",
                    "revision": expected + 1,
                    "accepted_at": None,
                    "updated_at": now,
                }
                updated = connection.execute(
                    "UPDATE scan_notice_proposals SET state_json=?,state_sha256=?,updated_at=? "
                    "WHERE tenant=? AND property_id=? AND proposal_id=? AND state_sha256=?",
                    (
                        _canonical(state).decode("ascii"),
                        _sha256(state),
                        now,
                        tenant,
                        property_id,
                        proposal_ref,
                        proposal["state_sha256"],
                    ),
                )
                if updated.rowcount != 1:
                    raise NoticeProposalConflict("proposal changed concurrently")
                result = {
                    **approval,
                    "integrity_sha256": approval_sha,
                    "proposal_state": "approved",
                    "proposal_revision": expected + 1,
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.approved",
                    proposal_ref,
                    {"approval_sha256": approval_sha},
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.approve",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def revoke_approval(
        self,
        proposal_id: str,
        *,
        expected_proposal_revision: int,
        expected_approval_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Let only the approving identity revoke before local acceptance."""

        snapshot, actor_sha, now = self._context()
        proposal_ref = _ref(proposal_id, "proposal_id")
        expected_proposal = _revision(
            expected_proposal_revision, "expected_proposal_revision", positive=True
        )
        expected_approval = _revision(
            expected_approval_revision, "expected_approval_revision", positive=True
        )
        _raw_key, key_sha = _idempotency(idempotency_key)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        request = {
            "operation": "revoke",
            "proposal_id": proposal_ref,
            "expected_proposal_revision": expected_proposal,
            "expected_approval_revision": expected_approval,
            "actor_sha256": actor_sha,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.revoke", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                proposal_row = self._proposal_row(connection, tenant, property_id, proposal_ref)
                proposal = self._proposal_result(proposal_row)
                approval_row = connection.execute(
                    "SELECT * FROM scan_notice_approvals WHERE tenant=? AND property_id=? "
                    "AND proposal_id=?",
                    (tenant, property_id, proposal_ref),
                ).fetchone()
                if approval_row is None:
                    raise NoticeProposalNotFound("proposal approval is unavailable")
                approval = self._approval_result(approval_row)
                if (
                    proposal["state"] != "approved"
                    or proposal["revision"] != expected_proposal
                    or approval["revision"] != expected_approval
                    or approval["revoked_at"] is not None
                ):
                    raise NoticeProposalConflict("approval revocation state or revision changed")
                if not _same(approval["actor_sha256"], actor_sha):
                    raise NoticeProposalConflict("only the approver can revoke this approval")
                new_approval = {
                    **{key: value for key, value in approval.items() if key != "integrity_sha256"},
                    "revision": expected_approval + 1,
                    "revoked_at": now,
                }
                approval_sha = _sha256(new_approval)
                updated_approval = connection.execute(
                    "UPDATE scan_notice_approvals SET approval_json=?,integrity_sha256=? WHERE "
                    "tenant=? AND property_id=? AND proposal_id=? AND integrity_sha256=?",
                    (
                        _canonical(new_approval).decode("ascii"),
                        approval_sha,
                        tenant,
                        property_id,
                        proposal_ref,
                        approval["integrity_sha256"],
                    ),
                )
                state = {
                    "proposal_id": proposal_ref,
                    "state": "proposed",
                    "revision": expected_proposal + 1,
                    "accepted_at": None,
                    "updated_at": now,
                }
                updated_proposal = connection.execute(
                    "UPDATE scan_notice_proposals SET state_json=?,state_sha256=?,updated_at=? "
                    "WHERE tenant=? AND property_id=? AND proposal_id=? AND state_sha256=?",
                    (
                        _canonical(state).decode("ascii"),
                        _sha256(state),
                        now,
                        tenant,
                        property_id,
                        proposal_ref,
                        proposal["state_sha256"],
                    ),
                )
                if updated_approval.rowcount != 1 or updated_proposal.rowcount != 1:
                    raise NoticeProposalConflict("approval or proposal changed concurrently")
                result = {
                    **new_approval,
                    "integrity_sha256": approval_sha,
                    "proposal_state": "proposed",
                    "proposal_revision": expected_proposal + 1,
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.approval_revoked",
                    proposal_ref,
                    {"approval_sha256": approval_sha},
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.revoke",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def accept_local(
        self,
        proposal_id: str,
        *,
        expected_revision: int,
        expected_head_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Accept metadata as the local desired baseline; never publish it."""

        snapshot, actor_sha, now = self._context()
        proposal_ref = _ref(proposal_id, "proposal_id")
        expected = _revision(expected_revision, "expected_revision", positive=True)
        expected_head = _revision(expected_head_revision, "expected_head_revision", positive=True)
        _raw_key, key_sha = _idempotency(idempotency_key)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._proposal_result(
                    self._proposal_row(connection, tenant, property_id, proposal_ref)
                )
                self._assert_source_current(proposal, snapshot, now)
                request = {
                    "operation": "accept_local",
                    "proposal_id": proposal_ref,
                    "definition_sha256": proposal["definition_sha256"],
                    "expected_revision": expected,
                    "expected_head_revision": expected_head,
                    "actor_sha256": actor_sha,
                }
                request_sha = _sha256(request)
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.accept", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                if proposal["state"] != "approved" or proposal["revision"] != expected:
                    raise NoticeProposalConflict(
                        "proposal is not approved at the expected revision"
                    )
                if _same(proposal["created_by_sha256"], actor_sha):
                    raise NoticeProposalConflict(
                        "proposal creator cannot accept their own proposal"
                    )
                approval_row = connection.execute(
                    "SELECT * FROM scan_notice_approvals WHERE tenant=? AND property_id=? "
                    "AND proposal_id=?",
                    (tenant, property_id, proposal_ref),
                ).fetchone()
                if approval_row is None:
                    raise NoticeProposalConflict("proposal approval is unavailable")
                approval = self._approval_result(approval_row)
                if (
                    approval["revoked_at"] is not None
                    or approval["expires_at"] <= now
                    or not _same(approval["definition_sha256"], proposal["definition_sha256"])
                ):
                    raise NoticeProposalConflict("proposal approval is expired, revoked, or stale")
                if _same(approval["actor_sha256"], actor_sha):
                    raise NoticeProposalConflict(
                        "proposal approver cannot accept the local baseline"
                    )
                head_row = connection.execute(
                    "SELECT * FROM scan_notice_heads WHERE tenant=? AND property_id=?",
                    (tenant, property_id),
                ).fetchone()
                if head_row is None:
                    raise NoticeProposalConflict("proposal head is unavailable")
                head = self._head_result(head_row)
                if head["revision"] != expected_head or head["current_proposal_id"] != proposal_ref:
                    raise NoticeProposalConflict("proposal head is stale or points elsewhere")
                state = {
                    "proposal_id": proposal_ref,
                    "state": "locally_accepted",
                    "revision": expected + 1,
                    "accepted_at": now,
                    "updated_at": now,
                }
                updated_proposal = connection.execute(
                    "UPDATE scan_notice_proposals SET state_json=?,state_sha256=?,updated_at=? "
                    "WHERE tenant=? AND property_id=? AND proposal_id=? AND state_sha256=?",
                    (
                        _canonical(state).decode("ascii"),
                        _sha256(state),
                        now,
                        tenant,
                        property_id,
                        proposal_ref,
                        proposal["state_sha256"],
                    ),
                )
                new_head = {
                    "property_id": property_id,
                    "revision": expected_head + 1,
                    "current_proposal_id": proposal_ref,
                    "effective_proposal_id": proposal_ref,
                    "effective_metadata_sha256": proposal["metadata_sha256"],
                    "updated_at": now,
                }
                updated_head = connection.execute(
                    "UPDATE scan_notice_heads SET revision=?,effective_proposal_id=?,"
                    "effective_metadata_sha256=?,updated_at=?,record_sha256=? WHERE tenant=? "
                    "AND property_id=? AND revision=? AND current_proposal_id=?",
                    (
                        new_head["revision"],
                        proposal_ref,
                        proposal["metadata_sha256"],
                        now,
                        _sha256(new_head),
                        tenant,
                        property_id,
                        expected_head,
                        proposal_ref,
                    ),
                )
                if updated_proposal.rowcount != 1 or updated_head.rowcount != 1:
                    raise NoticeProposalConflict("proposal or head changed concurrently")
                result = {
                    "proposal_id": proposal_ref,
                    "action": proposal["action"],
                    "state": "locally_accepted",
                    "proposal_revision": expected + 1,
                    "head_revision": expected_head + 1,
                    "metadata_sha256": proposal["metadata_sha256"],
                    "local_baseline_only": True,
                    "published": False,
                    "site_mutated": False,
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.locally_accepted",
                    proposal_ref,
                    result,
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.accept",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def get(self, proposal_id: str) -> dict[str, Any]:
        snapshot, _actor_sha, _now = self._context()
        proposal_ref = _ref(proposal_id, "proposal_id")
        with self._connect() as connection:
            return self._proposal_result(
                self._proposal_row(
                    connection, snapshot["tenant_id"], snapshot["property_id"], proposal_ref
                )
            )

    def list_proposals(self, *, limit: int = 100) -> dict[str, Any]:
        """Newest-first proposals of the bound property with the current head.

        Read-only. Each row says whether the signed-in person created or
        approved it (booleans only; no person digest leaves the store), so a
        page can offer only the steps that person may take.
        """

        snapshot, actor_sha, _now = self._context()
        bound = _revision(limit, "limit", positive=True)
        if bound > 500:
            raise NoticeProposalValidationError("limit is outside its bound")
        tenant, property_id = snapshot["tenant_id"], snapshot["property_id"]
        with self._connect() as connection:
            head_row = connection.execute(
                "SELECT * FROM scan_notice_heads WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM scan_notice_proposals WHERE tenant=? AND property_id=? "
                "ORDER BY version DESC LIMIT ?",
                (tenant, property_id, bound + 1),
            ).fetchall()
            approvals = {
                str(row["proposal_id"]): self._approval_result(row)
                for row in connection.execute(
                    "SELECT * FROM scan_notice_approvals WHERE tenant=? AND property_id=?",
                    (tenant, property_id),
                ).fetchall()
            }
        head = self._head_result(head_row) if head_row is not None else None
        items: list[dict[str, Any]] = []
        for row in rows[:bound]:
            proposal = self._proposal_result(row)
            metadata = proposal.get("metadata") if isinstance(proposal.get("metadata"), Mapping) else {}
            approval = approvals.get(str(proposal["proposal_id"]))
            items.append(
                {
                    "proposal_id": proposal["proposal_id"],
                    "version": proposal["version"],
                    "action": proposal["action"],
                    "state": proposal["state"],
                    "revision": proposal["revision"],
                    "created_at": proposal.get("created_at"),
                    "expires_at": proposal.get("expires_at"),
                    "accepted_at": proposal.get("accepted_at"),
                    "rollback_target_proposal_id": proposal.get("rollback_target_proposal_id"),
                    "classification_counts": dict(metadata.get("classification_counts") or {}),
                    "disclosure_count": metadata.get("disclosure_count"),
                    "first_party_count": metadata.get("first_party_count"),
                    "third_party_count": metadata.get("third_party_count"),
                    "scan_complete": metadata.get("scan_complete"),
                    "created_by_me": _same(proposal.get("created_by_sha256"), actor_sha),
                    "approval": (
                        None
                        if approval is None
                        else {
                            "revision": approval["revision"],
                            "approved_at": approval.get("approved_at"),
                            "expires_at": approval.get("expires_at"),
                            "revoked": approval.get("revoked_at") is not None,
                            "approved_by_me": _same(approval.get("actor_sha256"), actor_sha),
                        }
                    ),
                    "is_current": head is not None
                    and head["current_proposal_id"] == proposal["proposal_id"],
                    "is_effective": head is not None
                    and head["effective_proposal_id"] == proposal["proposal_id"],
                }
            )
        return {
            "head_revision": head["revision"] if head is not None else 0,
            "items": items,
            "truncated": len(rows) > bound,
        }

    def export_signed_metadata(self, proposal_id: str, *, idempotency_key: str) -> dict[str, Any]:
        """Export signed structured metadata; never export copy, secrets, or URLs."""

        snapshot, actor_sha, now = self._context()
        proposal_ref = _ref(proposal_id, "proposal_id")
        _raw_key, key_sha = _idempotency(idempotency_key)
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        try:
            key = self._signing_key_resolver(tenant)
        except Exception as exc:
            raise NoticeProposalIntegrityError("signing key resolver failed") from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise NoticeProposalIntegrityError("signing key must be at least 32 bytes")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                proposal = self._proposal_result(
                    self._proposal_row(connection, tenant, property_id, proposal_ref)
                )
                request = {
                    "operation": "export",
                    "proposal_id": proposal_ref,
                    "definition_sha256": proposal["definition_sha256"],
                    "state_sha256": proposal["state_sha256"],
                    "actor_sha256": actor_sha,
                }
                request_sha = _sha256(request)
                replay = self._idempotent(
                    connection, tenant, property_id, "proposal.export", key_sha, request_sha
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                if proposal["state"] not in {"approved", "locally_accepted"}:
                    raise NoticeProposalConflict("only approved metadata can be exported")
                export_id = self._new_id("CSNP-EXP")
                payload = {
                    "schema": NOTICE_PROPOSAL_EXPORT_SCHEMA,
                    "export_id": export_id,
                    "tenant_sha256": _text_sha256(tenant),
                    "property_id": property_id,
                    "proposal_id": proposal_ref,
                    "proposal_version": proposal["version"],
                    "action": proposal["action"],
                    "state": proposal["state"],
                    "definition_sha256": proposal["definition_sha256"],
                    "state_sha256": proposal["state_sha256"],
                    "source_pins": proposal["source_pins"],
                    "metadata": proposal["metadata"],
                    "metadata_sha256": proposal["metadata_sha256"],
                    "signing_key_ref": self._signing_key_ref,
                    "created_at": now,
                    "boundaries": self.product_boundaries(),
                }
                payload_bytes = _canonical(payload)
                payload_sha = hashlib.sha256(payload_bytes).hexdigest()
                signature = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
                connection.execute(
                    "INSERT INTO scan_notice_exports VALUES (?,?,?,?,?,?,?)",
                    (
                        tenant,
                        property_id,
                        export_id,
                        payload_bytes.decode("ascii"),
                        payload_sha,
                        signature,
                        now,
                    ),
                )
                result = {
                    "payload": payload,
                    "payload_sha256": payload_sha,
                    "signature_sha256": signature,
                }
                self._audit(
                    connection,
                    tenant,
                    property_id,
                    "proposal.metadata_exported",
                    proposal_ref,
                    {"export_id": export_id, "payload_sha256": payload_sha},
                    now,
                )
                self._save_idempotency(
                    connection,
                    tenant,
                    property_id,
                    "proposal.export",
                    key_sha,
                    request_sha,
                    result,
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def verify_export(self, export: Mapping[str, Any]) -> bool:
        """Verify a returned export using the server-selected tenant/key."""

        snapshot, _actor_sha, _now = self._context()
        if not isinstance(export, Mapping) or set(export) != {
            "payload",
            "payload_sha256",
            "signature_sha256",
        }:
            return False
        payload = export.get("payload")
        if not isinstance(payload, Mapping):
            return False
        try:
            encoded = _canonical(payload)
            supplied_payload_sha = _digest(export.get("payload_sha256"), "payload_sha256")
            supplied_signature = _digest(export.get("signature_sha256"), "signature_sha256")
            key = self._signing_key_resolver(snapshot["tenant_id"])
        except (ConsentScanNoticeProposalError, Exception):
            return False
        if not isinstance(key, bytes) or len(key) < 32:
            return False
        expected_sha = hashlib.sha256(encoded).hexdigest()
        expected_signature = hmac.new(key, encoded, hashlib.sha256).hexdigest()
        return (
            payload.get("tenant_sha256") == _text_sha256(snapshot["tenant_id"])
            and payload.get("property_id") == snapshot["property_id"]
            and payload.get("schema") == NOTICE_PROPOSAL_EXPORT_SCHEMA
            and _same(expected_sha, supplied_payload_sha)
            and _same(expected_signature, supplied_signature)
        )

    def verify_integrity(self) -> dict[str, int]:
        """Verify scoped records, idempotency bindings, export signatures, and audit chain."""

        snapshot, _actor_sha, _now = self._context()
        tenant = snapshot["tenant_id"]
        property_id = snapshot["property_id"]
        counts = {
            "heads": 0,
            "proposals": 0,
            "approvals": 0,
            "idempotency": 0,
            "exports": 0,
            "audit_events": 0,
        }
        try:
            key = self._signing_key_resolver(tenant)
        except Exception as exc:
            raise NoticeProposalIntegrityError("signing key resolver failed") from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise NoticeProposalIntegrityError("signing key must be at least 32 bytes")
        with self._connect() as connection:
            for row in connection.execute(
                "SELECT * FROM scan_notice_heads WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ):
                self._head_result(row)
                counts["heads"] += 1
            for row in connection.execute(
                "SELECT * FROM scan_notice_proposals WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ):
                self._proposal_result(row)
                counts["proposals"] += 1
            for row in connection.execute(
                "SELECT * FROM scan_notice_approvals WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ):
                self._approval_result(row)
                counts["approvals"] += 1
            for row in connection.execute(
                "SELECT * FROM scan_notice_idempotency WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ):
                if not _DIGEST_RE.fullmatch(str(row["key_sha256"])) or not _DIGEST_RE.fullmatch(
                    str(row["request_sha256"])
                ):
                    raise NoticeProposalIntegrityError("stored idempotency binding is invalid")
                result = _loads(row["result_json"], "idempotency result")
                if not isinstance(result, dict):
                    raise NoticeProposalIntegrityError("stored idempotency result is invalid")
                counts["idempotency"] += 1
            for row in connection.execute(
                "SELECT * FROM scan_notice_exports WHERE tenant=? AND property_id=?",
                (tenant, property_id),
            ):
                payload = _loads(row["payload_json"], "metadata export")
                encoded = _canonical(payload)
                expected_sha = hashlib.sha256(encoded).hexdigest()
                expected_signature = hmac.new(key, encoded, hashlib.sha256).hexdigest()
                if not _same(expected_sha, str(row["payload_sha256"])) or not _same(
                    expected_signature, str(row["signature_sha256"])
                ):
                    raise NoticeProposalIntegrityError("stored metadata export failed integrity")
                counts["exports"] += 1
            previous = None
            for row in connection.execute(
                "SELECT * FROM scan_notice_audit WHERE tenant=? AND property_id=? "
                "ORDER BY sequence",
                (tenant, property_id),
            ):
                body = {
                    "event_id": str(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "object_id": str(row["object_id"]),
                    "payload_sha256": str(row["payload_sha256"]),
                    "previous_event_sha256": row["previous_event_sha256"],
                    "created_at": float(row["created_at"]),
                }
                expected = _sha256(body)
                if row["previous_event_sha256"] != previous or not _same(
                    expected, str(row["event_sha256"])
                ):
                    raise NoticeProposalIntegrityError("stored audit chain failed integrity")
                previous = expected
                counts["audit_events"] += 1
        return counts
