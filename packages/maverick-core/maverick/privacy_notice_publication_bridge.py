"""Governed local bridge from notice intents to consent publications.

The bridge is deliberately a worker, not a public mutation API.  ``process_next``
accepts no tenant, actor, content, credential, or publication target.  A trusted
tenant resolver and a trusted target resolver are installed when the worker is
constructed.  Every resolved target is then certified against the leased notice
intent, the independently re-read notice release, and an exact consent preview.

The digest contract is intentionally strict:

* a notice release ``policy_sha256`` is the pinned consent rule-group digest;
* ``content_sha256`` is the exact pinned consent notice document digest; and
* ``configuration_sha256`` is the exact consent preview bundle digest.

Only the local :class:`~maverick.consent_publishing.ConsentPublishingStore` is
mutated.  There is no network I/O, provider write, SDK deployment, executable
content, or site mutation here.  Withdrawal replaces the active consent head
with a locally constructed immutable tombstone; the prior bundle remains only
in history and cannot be publicly resolved.  The two SQLite authorities cannot
share one transaction.  A mutation followed by an uncertain notice
acknowledgement is therefore returned as ``ambiguous`` and left under its lease
for idempotent recovery; it is never converted to a normal failure that could
conceal a completed consent write.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .consent_publishing import (
    PREVIEW_SCHEMA,
    PUBLICATION_SCHEMA,
    ConsentPublishingError,
    ConsentPublishingStore,
    PublishingConflict,
)
from .paths import canonical_tenant_id
from .privacy_notice_governance import (
    NoticeRelease,
    PrivacyNoticeGovernanceError,
    PrivacyNoticeGovernanceStore,
    PublicationIntent,
)

ACKNOWLEDGEMENT_SCHEMA = "lightwork.privacy-notice-publication-ack.v1"
LIVE_PROVIDER_WRITES = False
LIVE_SITE_MUTATION = False
LIVE_ACCEPTANCE_VERIFIED = False

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ACTIONS = frozenset({"publish", "rollback", "withdraw"})
_MAX_EVIDENCE_BYTES = 32 * 1024
_MAX_PREVIEW_BYTES = 512 * 1024


class PrivacyNoticePublicationBridgeError(RuntimeError):
    """Base error for bridge construction or an unrecordable worker outcome."""


class BridgeValidationError(PrivacyNoticePublicationBridgeError, ValueError):
    """Trusted worker configuration is outside the closed bridge contract."""


class BridgeAuthorityError(PrivacyNoticePublicationBridgeError):
    """A pre-mutation rejection could not be durably recorded."""


class BridgeAmbiguousOutcome(PrivacyNoticePublicationBridgeError):
    """Reserved for callers that choose to raise an ambiguous run result."""


@dataclass(frozen=True)
class ConsentPublicationTarget:
    """Server-resolved, fully pinned target for exactly one leased intent.

    The resolver must obtain this record from trusted server-side configuration
    or durable bindings.  It must never translate request parameters directly.
    ``selected_release_*`` describes the release whose consent bundle is desired:
    the intent release for publish, and the target release for rollback.
    """

    tenant_id: str
    intent_id: str
    action: str
    intent_release_sha256: str
    notice_id: str
    selected_release_version: int
    selected_release_sha256: str
    consent_publication_ref: str
    property_id: str
    rule_group_id: str
    rule_group_version: int
    notice_resource_id: str
    notice_resource_version: int
    expected_property_revision: int
    expected_publication_revision: int
    target_publication_id: str | None = None


@dataclass(frozen=True)
class BridgeRunResult:
    """Bounded worker result that never exposes the notice lease token."""

    status: str
    tenant_sha256: str | None
    intent_id: str | None
    action: str | None
    release_sha256: str | None
    publication_id: str | None
    publication_revision: int | None
    error_code: str | None
    acknowledgement_sha256: str | None
    evidence: Mapping[str, Any] | None


class _Rejected(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object, *, maximum: int = _MAX_EVIDENCE_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise BridgeValidationError("bridge evidence must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise BridgeValidationError("bridge evidence exceeds its byte bound")
    return encoded


def _sha256(value: object, *, maximum: int = _MAX_EVIDENCE_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise _Rejected("stale_binding", f"{label} is not a bounded identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise _Rejected("digest_mismatch", f"{label} is not a SHA-256 digest")
    return value


def _revision(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**31 - 1:
        raise _Rejected("stale_binding", f"{label} is outside its revision bound")
    return value


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


class PrivacyNoticePublicationBridge:
    """Lease, certify, locally apply, verify, and acknowledge one intent."""

    def __init__(
        self,
        *,
        notice_store: PrivacyNoticeGovernanceStore,
        consent_store: ConsentPublishingStore,
        tenant_resolver: Callable[[], str],
        target_resolver: Callable[
            [PublicationIntent, NoticeRelease, NoticeRelease | None],
            ConsentPublicationTarget,
        ],
        lease_seconds: int = 60,
        retry_delay_seconds: int = 60,
    ) -> None:
        if not isinstance(notice_store, PrivacyNoticeGovernanceStore):
            raise BridgeValidationError("notice_store must be the local notice authority")
        if not isinstance(consent_store, ConsentPublishingStore):
            raise BridgeValidationError("consent_store must be the local consent authority")
        if not callable(tenant_resolver) or not callable(target_resolver):
            raise BridgeValidationError("bridge resolvers must be callable")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 1 <= lease_seconds <= 3_600
        ):
            raise BridgeValidationError("lease_seconds must be between 1 and 3600")
        if (
            isinstance(retry_delay_seconds, bool)
            or not isinstance(retry_delay_seconds, int)
            or not 0 <= retry_delay_seconds <= 7 * 24 * 3_600
        ):
            raise BridgeValidationError("retry_delay_seconds is outside its bound")
        self._notice = notice_store
        self._consent = consent_store
        self._tenant_resolver = tenant_resolver
        self._target_resolver = target_resolver
        self._lease_seconds = lease_seconds
        self._retry_delay_seconds = retry_delay_seconds

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        """Return explicit proof boundaries for this local worker."""

        return {
            "local_notice_intent_consumer": True,
            "local_consent_publish": True,
            "local_consent_rollback": True,
            "local_consent_withdraw": True,
            "local_no_change_acceptance": True,
            "consent_withdrawal_supported": True,
            "cross_store_atomicity": False,
            "network_io": False,
            "provider_write": LIVE_PROVIDER_WRITES,
            "site_mutation": LIVE_SITE_MUTATION,
            "sdk_deployment": False,
            "live_acceptance_verified": LIVE_ACCEPTANCE_VERIFIED,
        }

    def process_next(self) -> BridgeRunResult:
        """Process at most one intent for the server-resolved tenant.

        No request-derived input is accepted.  ``idle`` is returned when no
        intent is currently both ready and claimable.
        """

        try:
            tenant = canonical_tenant_id(self._tenant_resolver())
        except (TypeError, ValueError) as exc:
            raise BridgeValidationError("tenant_resolver returned an invalid tenant") from exc
        claimed = self._notice.claim_publication_intents(
            tenant,
            limit=1,
            lease_seconds=self._lease_seconds,
        )
        tenant_sha = hashlib.sha256(tenant.encode("utf-8")).hexdigest()
        if not claimed:
            return BridgeRunResult(
                status="idle",
                tenant_sha256=tenant_sha,
                intent_id=None,
                action=None,
                release_sha256=None,
                publication_id=None,
                publication_revision=None,
                error_code=None,
                acknowledgement_sha256=None,
                evidence=None,
            )
        intent = claimed[0]
        if type(intent) is not PublicationIntent:
            raise BridgeAuthorityError("notice authority returned an invalid claimed intent")
        try:
            return self._process_claim(tenant, tenant_sha, intent)
        except _Rejected as exc:
            return self._record_failure(tenant, tenant_sha, intent, exc.code)

    def _process_claim(
        self,
        tenant: str,
        tenant_sha: str,
        intent: PublicationIntent,
    ) -> BridgeRunResult:
        self._validate_claim(tenant, intent)
        release = self._read_intent_release(tenant, intent)
        selected = release
        if intent.action == "rollback":
            if intent.target_version is None:
                raise _Rejected("stale_binding", "rollback intent has no target version")
            try:
                selected = self._notice.get_release(
                    tenant,
                    intent.notice_id,
                    intent.target_version,
                )
            except PrivacyNoticeGovernanceError as exc:
                raise _Rejected(
                    "target_unavailable", "rollback target release is unavailable"
                ) from exc
            self._validate_rollback_release(tenant, release, selected)
        try:
            target = self._target_resolver(
                intent,
                release,
                selected if intent.action == "rollback" else None,
            )
        except Exception as exc:
            raise _Rejected("target_unavailable", "target resolution failed") from exc
        if type(target) is not ConsentPublicationTarget:
            raise _Rejected("stale_binding", "target resolver returned an invalid record")
        self._validate_target(tenant, intent, release, selected, target)
        preview = self._certify_preview(tenant, selected, target)
        history = self._history(tenant, target.property_id)
        head = history[0] if history else None
        withdrawal_source_id: str | None = None
        if intent.action == "rollback":
            rollback_targets = [
                item
                for item in history
                if item.get("publication_id") == target.target_publication_id
            ]
            if len(rollback_targets) != 1:
                raise _Rejected(
                    "target_unavailable",
                    "rollback publication is absent from bounded verified history",
                )
            rollback_target = rollback_targets[0]
            if (
                rollback_target.get("property_id") != target.property_id
                or rollback_target.get("property_revision") != target.expected_property_revision
                or not _same(
                    str(rollback_target.get("bundle_sha256")),
                    str(preview["bundle_sha256"]),
                )
            ):
                raise _Rejected(
                    "digest_mismatch", "rollback publication does not bind target release"
                )
        current_revision = int(head["publication_revision"]) if head else 0
        if intent.action == "withdraw":
            recovery_candidate, no_change, withdrawal_source_id = self._validate_withdrawal_head(
                target,
                history,
                current_revision,
                str(preview["bundle_sha256"]),
            )
        else:
            recovery_candidate = self._validate_head(
                target,
                head,
                current_revision,
                str(preview["bundle_sha256"]),
            )
            no_change = (
                head is not None
                and current_revision == target.expected_publication_revision
                and _same(str(head["bundle_sha256"]), str(preview["bundle_sha256"]))
            )

        if no_change and head is not None:
            try:
                return self._acknowledge(
                    tenant,
                    tenant_sha,
                    intent,
                    release,
                    selected,
                    target,
                    head,
                    outcome="no_change",
                )
            except Exception:
                return self._ambiguous(
                    tenant_sha,
                    intent,
                    "acknowledgement_ambiguous",
                    publication=head,
                )

        mutation_key = self._mutation_key(tenant_sha, intent, selected)
        try:
            if intent.action == "publish":
                publication = self._consent.publish(
                    tenant,
                    target.property_id,
                    target.rule_group_id,
                    target.rule_group_version,
                    expected_property_revision=target.expected_property_revision,
                    expected_publication_revision=target.expected_publication_revision,
                    idempotency_key=mutation_key,
                )
            elif intent.action == "rollback":
                publication = self._consent.rollback(
                    tenant,
                    target.property_id,
                    target.target_publication_id or "",
                    expected_property_revision=target.expected_property_revision,
                    expected_publication_revision=target.expected_publication_revision,
                    idempotency_key=mutation_key,
                )
            else:
                publication = self._consent.withdraw(
                    tenant,
                    target.property_id,
                    expected_property_revision=target.expected_property_revision,
                    expected_publication_revision=target.expected_publication_revision,
                    idempotency_key=mutation_key,
                )
        except PublishingConflict as exc:
            code = "stale_binding" if recovery_candidate else "publication_conflict"
            raise _Rejected(code, "consent publication CAS failed") from exc
        except ConsentPublishingError as exc:
            raise _Rejected("publication_rejected", "consent mutation was rejected") from exc
        except Exception:
            return self._ambiguous(tenant_sha, intent, "mutation_outcome_unknown")

        try:
            certified = self._certify_publication(
                tenant,
                intent,
                target,
                publication,
                (None if intent.action == "withdraw" else str(preview["bundle_sha256"])),
                withdrawal_source_id=withdrawal_source_id,
            )
            verified_history = self._history(tenant, target.property_id)
            if not verified_history or not self._publication_matches(
                certified, verified_history[0]
            ):
                return self._ambiguous(tenant_sha, intent, "verification_ambiguous")
        except Exception:
            return self._ambiguous(tenant_sha, intent, "verification_ambiguous")
        try:
            return self._acknowledge(
                tenant,
                tenant_sha,
                intent,
                release,
                selected,
                target,
                certified,
                outcome="recovered" if recovery_candidate else "applied",
            )
        except Exception:
            return self._ambiguous(
                tenant_sha,
                intent,
                "acknowledgement_ambiguous",
                publication=certified,
            )

    @staticmethod
    def _validate_claim(tenant: str, intent: PublicationIntent) -> None:
        if intent.tenant_id != tenant:
            raise _Rejected("stale_binding", "claimed intent tenant changed")
        if intent.action not in _ACTIONS:
            raise _Rejected("stale_binding", "claimed intent action is unsupported")
        if intent.state != "leased" or not intent.lease_token:
            raise _Rejected("stale_binding", "claimed intent has no valid lease")
        _ref(intent.intent_id, "intent_id")
        _digest(intent.release_sha256, "release_sha256")
        _ref(intent.consent_publication_ref, "consent_publication_ref")
        _revision(intent.revision, "intent revision", positive=True)

    def _read_intent_release(
        self,
        tenant: str,
        intent: PublicationIntent,
    ) -> NoticeRelease:
        try:
            release = self._notice.get_release(
                tenant,
                intent.notice_id,
                intent.release_version,
            )
        except PrivacyNoticeGovernanceError as exc:
            raise _Rejected("target_unavailable", "intent release is unavailable") from exc
        if type(release) is not NoticeRelease:
            raise _Rejected("stale_binding", "notice authority returned an invalid release")
        expected_state = {
            "publish": "scheduled",
            "rollback": "rolled_back",
            "withdraw": "withdrawn",
        }[intent.action]
        if (
            release.tenant_id != tenant
            or release.notice_id != intent.notice_id
            or release.version != intent.release_version
            or release.state != expected_state
            or not _same(release.definition_sha256, intent.release_sha256)
            or not _same(
                release.consent_publication_ref,
                intent.consent_publication_ref,
            )
        ):
            raise _Rejected("stale_binding", "intent and release binding is stale")
        return release

    def _validate_rollback_release(
        self,
        tenant: str,
        source: NoticeRelease,
        selected: NoticeRelease,
    ) -> None:
        if (
            selected.tenant_id != tenant
            or selected.notice_id != source.notice_id
            or selected.version != source.rollback_target_version
            or selected.version >= source.version
            or selected.property_id != source.property_id
            or selected.state != "published"
        ):
            raise _Rejected("stale_binding", "rollback release binding is stale")
        # This public authority call is the only current API that revalidates
        # active approvals and the effective window for an already-published
        # release.  Certify every bounded jurisdiction/locale selection.
        for jurisdiction in selected.jurisdictions:
            for locale in selected.locales:
                try:
                    current = self._notice.current_effective_release(
                        tenant,
                        selected.property_id,
                        jurisdiction,
                        locale,
                    )
                except PrivacyNoticeGovernanceError as exc:
                    raise _Rejected(
                        "approval_not_current",
                        "rollback target approval or effective window is not current",
                    ) from exc
                if not _same(current.definition_sha256, selected.definition_sha256):
                    raise _Rejected(
                        "approval_not_current", "rollback target is not the current release"
                    )

    @staticmethod
    def _validate_target(
        tenant: str,
        intent: PublicationIntent,
        release: NoticeRelease,
        selected: NoticeRelease,
        target: ConsentPublicationTarget,
    ) -> None:
        for value, label in (
            (target.intent_id, "target.intent_id"),
            (target.notice_id, "target.notice_id"),
            (target.consent_publication_ref, "target.consent_publication_ref"),
            (target.property_id, "target.property_id"),
            (target.rule_group_id, "target.rule_group_id"),
            (target.notice_resource_id, "target.notice_resource_id"),
        ):
            _ref(value, label)
        _digest(target.intent_release_sha256, "target.intent_release_sha256")
        _digest(target.selected_release_sha256, "target.selected_release_sha256")
        _revision(target.selected_release_version, "selected release version", positive=True)
        _revision(target.rule_group_version, "rule group version", positive=True)
        _revision(target.notice_resource_version, "notice resource version", positive=True)
        _revision(target.expected_property_revision, "property revision", positive=True)
        _revision(target.expected_publication_revision, "publication revision")
        expected_target_publication = target.target_publication_id
        if intent.action == "rollback":
            _ref(expected_target_publication, "target_publication_id")
        elif expected_target_publication is not None:
            raise _Rejected("stale_binding", "publish target cannot include rollback state")
        if (
            target.tenant_id != tenant
            or target.intent_id != intent.intent_id
            or target.action != intent.action
            or target.notice_id != intent.notice_id
            or not _same(target.intent_release_sha256, release.definition_sha256)
            or target.selected_release_version != selected.version
            or not _same(target.selected_release_sha256, selected.definition_sha256)
            or not _same(
                target.consent_publication_ref,
                selected.consent_publication_ref,
            )
            or target.property_id != selected.property_id
        ):
            raise _Rejected("stale_binding", "resolved publication target is stale")

    def _certify_preview(
        self,
        tenant: str,
        selected: NoticeRelease,
        target: ConsentPublicationTarget,
    ) -> dict[str, Any]:
        try:
            preview = self._consent.preview(
                tenant,
                target.property_id,
                target.rule_group_id,
                target.rule_group_version,
            )
        except ConsentPublishingError as exc:
            raise _Rejected("target_unavailable", "exact consent preview is unavailable") from exc
        if not isinstance(preview, dict) or set(preview) != {
            "schema",
            "bundle",
            "bundle_sha256",
        }:
            raise _Rejected("digest_mismatch", "consent preview shape is invalid")
        bundle = preview.get("bundle")
        if (
            preview.get("schema") != PREVIEW_SCHEMA
            or not isinstance(bundle, dict)
            or set(bundle) != {"schema", "property", "rule_group", "resources"}
            or bundle.get("schema") != PREVIEW_SCHEMA
        ):
            raise _Rejected("digest_mismatch", "consent preview schema is invalid")
        bundle_sha = _digest(preview.get("bundle_sha256"), "bundle_sha256")
        if not _same(bundle_sha, _sha256(bundle, maximum=_MAX_PREVIEW_BYTES)):
            raise _Rejected("digest_mismatch", "consent bundle digest is invalid")
        property_value = bundle.get("property")
        rule_group = bundle.get("rule_group")
        resources = bundle.get("resources")
        if (
            not isinstance(property_value, dict)
            or property_value.get("property_id") != target.property_id
            or property_value.get("revision") != target.expected_property_revision
            or not isinstance(rule_group, dict)
            or rule_group.get("resource_kind") != "rule_group"
            or rule_group.get("resource_id") != target.rule_group_id
            or rule_group.get("version") != target.rule_group_version
            or not isinstance(resources, list)
        ):
            raise _Rejected("stale_binding", "consent preview target is stale")
        rule_sha = _digest(rule_group.get("resource_sha256"), "rule group digest")
        if not _same(rule_sha, selected.policy_sha256):
            raise _Rejected("digest_mismatch", "notice policy digest does not bind the rule group")
        if not _same(bundle_sha, selected.configuration_sha256):
            raise _Rejected(
                "digest_mismatch", "notice configuration digest does not bind the bundle"
            )
        matches = [
            resource
            for resource in resources
            if isinstance(resource, dict)
            and resource.get("resource_kind") == "notice"
            and resource.get("resource_id") == target.notice_resource_id
            and resource.get("locale") == ""
            and resource.get("version") == target.notice_resource_version
        ]
        if len(matches) != 1:
            raise _Rejected("stale_binding", "exact consent notice resource is not unique")
        payload = matches[0].get("payload")
        if not isinstance(payload, dict):
            raise _Rejected("digest_mismatch", "consent notice payload is invalid")
        document_sha = _digest(payload.get("document_sha256"), "notice document digest")
        if not _same(document_sha, selected.content_sha256):
            raise _Rejected("digest_mismatch", "notice content digest does not bind the document")
        return preview

    def _history(self, tenant: str, property_id: str) -> list[dict[str, Any]]:
        try:
            history = self._consent.publication_history(tenant, property_id, limit=500)
        except ConsentPublishingError as exc:
            raise _Rejected("target_unavailable", "publication history is unavailable") from exc
        if (
            not isinstance(history, dict)
            or set(history) != {"items", "truncated"}
            or not isinstance(history.get("items"), list)
            or not isinstance(history.get("truncated"), bool)
        ):
            raise _Rejected("digest_mismatch", "publication history shape is invalid")
        items = history["items"]
        if any(not isinstance(item, dict) for item in items):
            raise _Rejected("digest_mismatch", "publication history item is invalid")
        return items

    @staticmethod
    def _validate_head(
        target: ConsentPublicationTarget,
        head: dict[str, Any] | None,
        current_revision: int,
        expected_bundle_sha256: str,
    ) -> bool:
        expected = target.expected_publication_revision
        if current_revision == expected:
            return False
        if (
            current_revision == expected + 1
            and head is not None
            and _same(str(head.get("bundle_sha256")), expected_bundle_sha256)
        ):
            # Only an exact replay with the bridge's deterministic key can pass
            # the subsequent old-revision mutation call.  Otherwise CAS fails.
            return True
        raise _Rejected("stale_binding", "consent publication head changed")

    @staticmethod
    def _validate_withdrawal_head(
        target: ConsentPublicationTarget,
        history: list[dict[str, Any]],
        current_revision: int,
        expected_bundle_sha256: str,
    ) -> tuple[bool, bool, str]:
        """Certify the active source or one exact recovered tombstone."""

        if not history:
            raise _Rejected(
                "target_unavailable", "there is no active consent publication to withdraw"
            )
        head = history[0]
        expected = target.expected_publication_revision
        if (
            head.get("property_id") != target.property_id
            or head.get("property_revision") != target.expected_property_revision
        ):
            raise _Rejected("stale_binding", "withdrawal publication head is stale")
        if current_revision == expected and head.get("action") in {"publish", "rollback"}:
            if not _same(str(head.get("bundle_sha256")), expected_bundle_sha256):
                raise _Rejected(
                    "digest_mismatch", "active publication does not bind withdrawn release"
                )
            return False, False, _ref(head.get("publication_id"), "publication_id")
        if not (head.get("action") == "withdraw" and current_revision in {expected, expected + 1}):
            raise _Rejected("stale_binding", "consent publication head changed")
        source_id = _ref(head.get("source_publication_id"), "source_publication_id")
        sources = [item for item in history if item.get("publication_id") == source_id]
        if len(sources) != 1:
            raise _Rejected(
                "target_unavailable",
                "withdrawal source is absent from bounded verified history",
            )
        source = sources[0]
        if (
            source.get("action") not in {"publish", "rollback"}
            or source.get("property_id") != target.property_id
            or source.get("property_revision") != target.expected_property_revision
            or not _same(str(source.get("bundle_sha256")), expected_bundle_sha256)
        ):
            raise _Rejected(
                "digest_mismatch", "withdrawal tombstone does not bind withdrawn release"
            )
        return current_revision == expected + 1, current_revision == expected, source_id

    @staticmethod
    def _publication_matches(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        keys = (
            "schema",
            "tenant_sha256",
            "publication_id",
            "property_id",
            "publication_revision",
            "action",
            "source_publication_id",
            "property_revision",
            "bundle_sha256",
            "created_at",
            "publication_sha256",
        )
        return all(left.get(key) == right.get(key) for key in keys)

    @staticmethod
    def _mutation_key(
        tenant_sha: str,
        intent: PublicationIntent,
        selected: NoticeRelease,
    ) -> str:
        digest_value = _sha256(
            {
                "tenant_sha256": tenant_sha,
                "intent_id": intent.intent_id,
                "action": intent.action,
                "intent_release_sha256": intent.release_sha256,
                "selected_release_sha256": selected.definition_sha256,
            }
        )
        return f"notice-bridge:{digest_value}"

    def _certify_publication(
        self,
        tenant: str,
        intent: PublicationIntent,
        target: ConsentPublicationTarget,
        publication: object,
        expected_bundle_sha256: str | None,
        *,
        withdrawal_source_id: str | None,
    ) -> dict[str, Any]:
        if not isinstance(publication, dict):
            raise BridgeAmbiguousOutcome("consent mutation returned an invalid result")
        required = {
            "schema",
            "tenant_sha256",
            "publication_id",
            "property_id",
            "publication_revision",
            "action",
            "source_publication_id",
            "property_revision",
            "bundle_sha256",
            "created_at",
            "publication_sha256",
        }
        if set(publication) != required:
            raise BridgeAmbiguousOutcome("consent mutation result shape is invalid")
        expected_source = {
            "publish": None,
            "rollback": target.target_publication_id,
            "withdraw": withdrawal_source_id,
        }[intent.action]
        bundle_sha = publication.get("bundle_sha256")
        bundle_matches = (
            isinstance(bundle_sha, str)
            and _DIGEST_RE.fullmatch(bundle_sha) is not None
            and (expected_bundle_sha256 is None or _same(bundle_sha, expected_bundle_sha256))
        )
        if (
            publication.get("schema") != PUBLICATION_SCHEMA
            or publication.get("tenant_sha256")
            != hashlib.sha256(tenant.encode("utf-8")).hexdigest()
            or publication.get("property_id") != target.property_id
            or publication.get("publication_revision") != target.expected_publication_revision + 1
            or publication.get("action") != intent.action
            or publication.get("source_publication_id") != expected_source
            or publication.get("property_revision") != target.expected_property_revision
            or not bundle_matches
            or not isinstance(publication.get("publication_id"), str)
        ):
            raise BridgeAmbiguousOutcome("consent mutation result failed certification")
        body = {key: publication[key] for key in required - {"publication_sha256"}}
        if not _same(str(publication["publication_sha256"]), _sha256(body)):
            raise BridgeAmbiguousOutcome("consent publication digest is invalid")
        return publication

    def _acknowledge(
        self,
        tenant: str,
        tenant_sha: str,
        intent: PublicationIntent,
        release: NoticeRelease,
        selected: NoticeRelease,
        target: ConsentPublicationTarget,
        publication: Mapping[str, Any],
        *,
        outcome: str,
    ) -> BridgeRunResult:
        publication_id = _ref(publication.get("publication_id"), "publication_id")
        publication_revision = _revision(
            publication.get("publication_revision"),
            "publication revision",
            positive=True,
        )
        evidence: dict[str, Any] = {
            "schema": ACKNOWLEDGEMENT_SCHEMA,
            "tenant_sha256": tenant_sha,
            "intent_id": intent.intent_id,
            "action": intent.action,
            "outcome": outcome,
            "intent_release_sha256": release.definition_sha256,
            "selected_release_sha256": selected.definition_sha256,
            "consent_publication_ref_sha256": hashlib.sha256(
                selected.consent_publication_ref.encode("utf-8")
            ).hexdigest(),
            "property_id": target.property_id,
            "publication_id": publication_id,
            "publication_revision": publication_revision,
            "publication_sha256": _digest(
                publication.get("publication_sha256"), "publication_sha256"
            ),
            "bundle_sha256": _digest(publication.get("bundle_sha256"), "bundle_sha256"),
            "network_io": False,
            "provider_write": False,
            "site_mutation": False,
        }
        acknowledgement_sha = _sha256(evidence)
        acknowledgement_ref = f"consent-publication:{publication['publication_sha256']}"
        try:
            acked = self._notice.ack_publication_intent(
                tenant,
                intent.intent_id,
                lease_token=intent.lease_token or "",
                acknowledgement_sha256=acknowledgement_sha,
                acknowledgement_ref=acknowledgement_ref,
                expected_revision=intent.revision,
                idempotency_key=f"notice-bridge-ack:{acknowledgement_sha}",
            )
        except PrivacyNoticeGovernanceError:
            return self._ambiguous(
                tenant_sha,
                intent,
                "acknowledgement_ambiguous",
                publication=publication,
                evidence=evidence,
            )
        if (
            type(acked) is not PublicationIntent
            or acked.state != "acked"
            or not _same(acked.acknowledgement_sha256 or "", acknowledgement_sha)
            or acked.acknowledgement_ref != acknowledgement_ref
        ):
            return self._ambiguous(
                tenant_sha,
                intent,
                "acknowledgement_ambiguous",
                publication=publication,
                evidence=evidence,
            )
        return BridgeRunResult(
            status=outcome,
            tenant_sha256=tenant_sha,
            intent_id=intent.intent_id,
            action=intent.action,
            release_sha256=release.definition_sha256,
            publication_id=publication_id,
            publication_revision=publication_revision,
            error_code=None,
            acknowledgement_sha256=acknowledgement_sha,
            evidence=evidence,
        )

    def _record_failure(
        self,
        tenant: str,
        tenant_sha: str,
        intent: PublicationIntent,
        error_code: str,
    ) -> BridgeRunResult:
        digest_value = _sha256(
            {
                "tenant_sha256": tenant_sha,
                "intent_id": intent.intent_id,
                "revision": intent.revision,
                "error_code": error_code,
            }
        )
        try:
            failed = self._notice.fail_publication_intent(
                tenant,
                intent.intent_id,
                lease_token=intent.lease_token or "",
                error_code=error_code,
                retry_delay_seconds=self._retry_delay_seconds,
                expected_revision=intent.revision,
                idempotency_key=f"notice-bridge-fail:{digest_value}",
            )
        except PrivacyNoticeGovernanceError as exc:
            raise BridgeAuthorityError("bridge rejection could not be durably recorded") from exc
        return BridgeRunResult(
            status="failed",
            tenant_sha256=tenant_sha,
            intent_id=intent.intent_id,
            action=intent.action,
            release_sha256=intent.release_sha256,
            publication_id=None,
            publication_revision=None,
            error_code=error_code,
            acknowledgement_sha256=None,
            evidence={
                "schema": ACKNOWLEDGEMENT_SCHEMA,
                "tenant_sha256": tenant_sha,
                "intent_id": intent.intent_id,
                "action": intent.action,
                "outcome": "failed",
                "error_code": error_code,
                "intent_state": failed.state,
                "attempts": failed.attempts,
                "network_io": False,
                "provider_write": False,
                "site_mutation": False,
            },
        )

    @staticmethod
    def _ambiguous(
        tenant_sha: str,
        intent: PublicationIntent,
        error_code: str,
        *,
        publication: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> BridgeRunResult:
        return BridgeRunResult(
            status="ambiguous",
            tenant_sha256=tenant_sha,
            intent_id=intent.intent_id,
            action=intent.action,
            release_sha256=intent.release_sha256,
            publication_id=(
                str(publication["publication_id"])
                if publication is not None and "publication_id" in publication
                else None
            ),
            publication_revision=(
                int(publication["publication_revision"])
                if publication is not None and "publication_revision" in publication
                else None
            ),
            error_code=error_code,
            acknowledgement_sha256=None,
            evidence=evidence,
        )
