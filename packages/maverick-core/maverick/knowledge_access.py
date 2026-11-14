"""Current-rights knowledge access over the governed research registry.

This module is deliberately an access layer, not another search index.  Exact
dataset versions remain owned by :mod:`maverick.research_registry`; callers may
inject a content projector for an already-existing knowledge store.  Every
direct read, cache hit, export, and queued-job materialization re-resolves the
registry version and its current data-use, consent, freshness, and lineage
authority before any projected content leaves the process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass

from .constant_time import text_equals
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore
from .knowledge_retrieval import LexicalProjection, SearchCursor, digest, rank, retrieval_passage
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict
from .research_registry import (
    DatasetAdmission,
    ResearchAssetRef,
    ResearchRegistry,
    ResearchRegistryConflict,
    ResearchRegistryDenied,
    ResearchRegistryNotFound,
)

KNOWLEDGE_DOCUMENT_SCHEMA = "lightwork.knowledge-document.v1"
KNOWLEDGE_DETAIL_SCHEMA = "lightwork.knowledge-detail.v1"
KNOWLEDGE_SEARCH_SCHEMA = "lightwork.knowledge-search.v1"
KNOWLEDGE_EXPORT_SCHEMA = "lightwork.knowledge-export.v1"
KNOWLEDGE_JOB_MATERIALIZATION_SCHEMA = "lightwork.knowledge-job-materialization.v1"
KNOWLEDGE_RIGHTS_REQUEST_SCHEMA = "lightwork.knowledge-rights-request.v1"
KNOWLEDGE_ACTOR_AUTHORITY_SCHEMA = "lightwork.knowledge-actor-authority.v1"
KNOWLEDGE_RETENTION_HOLD_SCHEMA = "lightwork.knowledge-retention-hold.v1"
KNOWLEDGE_REQUEST_ARCHIVE_SCHEMA = "lightwork.knowledge-rights-archive.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PURPOSE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_TYPES = frozenset({"correction", "deletion", "exclusion"})
_DECISIONS = frozenset({"approve", "deny"})
_ACTIONS = frozenset({"analyze", "export", "read", "train"})
_CLAIM_STATES = frozenset({"inferred", "verified"})
_MAX_CACHE = 256
_MAX_RESULTS = 50
_MAX_EXPORT = 100
_MAX_SCAN = 250
_MAX_REQUESTS = 2_048
_MAX_SOURCE_SELECTORS = 64

_ACTION_DENIAL_CONSTRAINTS = {
    "read": frozenset(
        {
            "machine_only",
            "machine_use_only",
            "no_display",
            "no_human_display",
            "no_read",
            "no_retrieval",
            "not_for_human_display",
            "training_only",
        }
    ),
    "analyze": frozenset(
        {"export_only", "no_analysis", "not_for_analysis", "read_only", "training_only"}
    ),
    "export": frozenset(
        {
            "analysis_only",
            "no_export",
            "no_redistribution",
            "not_for_export",
            "read_only",
            "training_only",
        }
    ),
    "train": frozenset(
        {
            "analysis_only",
            "export_only",
            "no_training",
            "no_ai_training",
            "no_machine_learning",
            "no_model_training",
            "no_training_without_separate_permission",
            "not_for_training",
            "read_only",
            "separate_training_permission_required",
            "training_prohibited",
        }
    ),
}

WEIGHT_INFLUENCE_NOTICE = (
    "Deleting or excluding a raw source does not erase its influence from learned weights. "
    "Affected models require a documented retirement or retraining assessment."
)
TRAINING_PERMISSION_NOTICE = (
    "Access to search, deploy, or export a source does not grant permission to train on it."
)


class KnowledgeAccessError(RuntimeError):
    """Base failure for the governed knowledge surface."""


class KnowledgeAccessDenied(KnowledgeAccessError, PermissionError):
    """Current source authority does not allow the requested use."""


class KnowledgeContentUnavailable(KnowledgeAccessDenied):
    """Authority may be valid, but its content could not be checked."""


class KnowledgeRequestNotFound(KnowledgeAccessError, LookupError):
    """A rights request is absent from the selected tenant."""


class KnowledgeRequestConflict(KnowledgeAccessError):
    """A rights request or its source changed during review."""


class KnowledgeRequestCapacity(KnowledgeRequestConflict):
    """The live rights ledger requires administrator archival of finished work."""


class KnowledgeArchiveUnavailable(KnowledgeRequestConflict):
    """A shared backend cannot safely move a request between record stores."""


@dataclass(frozen=True)
class KnowledgeActorAuthority:
    """A trusted composition result for one current knowledge operation.

    The registry owns source rights.  This independent authority binds the
    authenticated caller to the tenant, purpose, and operation so a worker or
    HTTP adapter cannot turn valid source rights into access for an arbitrary
    principal.
    """

    tenant: str
    principal: str
    action: str
    purpose: str
    authorization_sha256: str
    schema: str = KNOWLEDGE_ACTOR_AUTHORITY_SCHEMA
    # The signed-in person's address as their identity provider asserted it for this sign-in.
    # Empty for keys, agents and workers, so the permission filter fails closed for them.
    verified_email: str = ""

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        principal = _text(self.principal, "knowledge principal", 512)
        if not principal.startswith(("user:", "worker:", "agent:")):
            raise ValueError("knowledge authority requires a named principal")
        if self.action not in _ACTIONS:
            raise ValueError("knowledge authority action is unsupported")
        _purpose(self.purpose)
        if not isinstance(self.authorization_sha256, str) or not _SHA.fullmatch(
            self.authorization_sha256
        ):
            raise ValueError("knowledge authorization_sha256 must be a lowercase SHA-256")
        if self.schema != KNOWLEDGE_ACTOR_AUTHORITY_SCHEMA:
            raise ValueError("knowledge actor authority schema is unsupported")
        if self.verified_email:
            if (not principal.startswith("user:") or not isinstance(self.verified_email, str)
                    or len(self.verified_email) > 254 or self.verified_email != self.verified_email.strip().lower()
                    or self.verified_email.count("@") != 1 or any(c.isspace() for c in self.verified_email)):
                raise ValueError("knowledge verified email must be a normalized address of a named user")


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("knowledge material must be finite JSON") from exc
    if len(encoded) > 256 * 1024:
        raise ValueError("knowledge material exceeds its size boundary")
    return encoded


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} is not a bounded identifier")
    return value


def _purpose(value: object) -> str:
    if not isinstance(value, str) or not _PURPOSE.fullmatch(value):
        raise ValueError("purpose is not a bounded purpose code")
    return value


def _text(
    value: object,
    label: str,
    maximum: int,
    *,
    required: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{label} is required")
    if len(result.encode("utf-8")) > maximum:
        raise ValueError(f"{label} exceeds its size boundary")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in result):
        raise ValueError(f"{label} contains unsupported control characters")
    return result


def _positive_time(value: object, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{label} must be a positive finite timestamp")
    return float(value)


def _reference_key(reference: ResearchAssetRef) -> tuple[str, str, str, str]:
    if type(reference) is not ResearchAssetRef:
        raise ValueError("an exact ResearchAssetRef is required")
    if reference.kind != "dataset":
        raise ValueError("knowledge access requires an exact dataset version")
    return (
        reference.kind,
        reference.asset_id,
        reference.version,
        reference.manifest_sha256,
    )


@dataclass(frozen=True)
class KnowledgeDocument:
    """A bounded projection from an existing content authority.

    Searchable chunks are bounded to 2048 chunks and 256 KiB for every store.
    A projector with more text (a large saved remote source) keeps the leading
    chunks and sets ``search_coverage_complete`` to False.
    The owning store is reread on every access. The exact tenant, registry ref,
    and content digest stop a buggy adapter from crossing a tenant or version
    boundary.
    """

    tenant: str
    reference: ResearchAssetRef
    content_sha256: str
    title: str
    summary: str
    claim_state: str
    observed_at: float | None = None
    verified_at: float | None = None
    schema: str = KNOWLEDGE_DOCUMENT_SCHEMA
    retrieval_chunks: tuple[str, ...] = ()
    search_coverage_complete: bool = True
    summary_truncated: bool = False
    # Items of a saved remote source this reader may not see under its permission filter. Counted only.
    permissions_withheld: int = 0

    def __post_init__(self) -> None:
        canonical_tenant_id(self.tenant)
        _reference_key(self.reference)
        if not isinstance(self.content_sha256, str) or not _SHA.fullmatch(
            self.content_sha256
        ):
            raise ValueError("knowledge content_sha256 must be a lowercase SHA-256 digest")
        _text(self.title, "knowledge title", 240)
        _text(self.summary, "knowledge summary", 8_192, required=False)
        if (not isinstance(self.retrieval_chunks, tuple) or len(self.retrieval_chunks) > 2048
            or any(not isinstance(chunk, str) for chunk in self.retrieval_chunks)
            or sum(len(chunk.encode("utf-8")) for chunk in self.retrieval_chunks) > 256 * 1024
            or type(self.search_coverage_complete) is not bool
            or type(self.summary_truncated) is not bool
            or type(self.permissions_withheld) is not int or self.permissions_withheld < 0):
            raise ValueError("knowledge retrieval chunks or coverage are malformed")
        if self.claim_state not in _CLAIM_STATES:
            raise ValueError("knowledge claim_state must be inferred or verified")
        _positive_time(self.observed_at, "knowledge observed_at", optional=True)
        _positive_time(self.verified_at, "knowledge verified_at", optional=True)
        if self.schema != KNOWLEDGE_DOCUMENT_SCHEMA:
            raise ValueError("knowledge document schema is unsupported")


ContentResolver = Callable[
    [str, ResearchAssetRef, DatasetAdmission],
    KnowledgeDocument | None,
]
ActorAuthorityResolver = Callable[
    [str, str, str, str],
    KnowledgeActorAuthority,
]


class KnowledgeAccessService:
    """Tenant-safe current-rights access and derivative-rights requests."""

    def __init__(
        self,
        *,
        registry: ResearchRegistry,
        content_resolver: ContentResolver | None = None,
        actor_authority_resolver: ActorAuthorityResolver | None = None,
        request_store: GovernedRecordStore | None = None,
        archive_store: GovernedRecordStore | None = None,
        correction_store: GovernedRecordStore | None = None,
        after_source_revoked: Callable[[dict], None] | None = None,
        cache_capacity: int = _MAX_CACHE,
    ) -> None:
        if not isinstance(registry, ResearchRegistry):
            raise TypeError("knowledge access requires the governed research registry")
        if content_resolver is not None and not callable(content_resolver):
            raise TypeError("knowledge content resolver must be callable")
        if actor_authority_resolver is not None and not callable(actor_authority_resolver):
            raise TypeError("knowledge actor authority resolver must be callable")
        if (
            isinstance(cache_capacity, bool)
            or not isinstance(cache_capacity, int)
            or not 1 <= cache_capacity <= _MAX_CACHE
        ):
            raise ValueError(f"cache_capacity must be between 1 and {_MAX_CACHE}")
        self.registry = registry
        self.content_resolver = content_resolver
        self.actor_authority_resolver = actor_authority_resolver
        self.request_store = request_store or GovernedRecordStore(
            "knowledge-rights-requests",
            "knowledge-req",
            "knowledge-rights-request",
        )
        self.archive_store = archive_store or GovernedRecordStore(
            "knowledge-rights-archive",
            "knowledge-req",
            "knowledge-rights-archive",
        )
        self.correction_store = correction_store or GovernedRecordStore(
            "knowledge-correction-sources",
            "knowledge-fix",
            "knowledge-correction-source",
        )
        self.after_source_revoked = after_source_revoked
        self.cache_capacity = cache_capacity
        self._cache: OrderedDict[
            tuple[str, str, str, str, str], KnowledgeDocument
        ] = OrderedDict()
        self._cache_lock = threading.RLock()
        self._lexical: OrderedDict[str, LexicalProjection] = OrderedDict()
        # Which source each projection was derived from, so revoking one source
        # evicts only its derived terms instead of every tenant's cache.
        self._lexical_owner: dict[str, tuple] = {}

    def bind_actor_authority(
        self,
        resolver: ActorAuthorityResolver,
    ) -> KnowledgeAccessService:
        """Return a process-local view with the same stores and a new actor gate."""

        if not callable(resolver):
            raise TypeError("knowledge actor authority resolver must be callable")
        return KnowledgeAccessService(
            registry=self.registry,
            content_resolver=self.content_resolver,
            actor_authority_resolver=resolver,
            request_store=self.request_store,
            archive_store=self.archive_store,
            correction_store=self.correction_store,
            after_source_revoked=self.after_source_revoked,
            cache_capacity=self.cache_capacity,
        )

    def _actor_authority(
        self,
        tenant: str,
        actor: str,
        *,
        action: str,
        purpose: str,
        human_display: bool,
    ) -> KnowledgeActorAuthority:
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "knowledge actor", 512)
        exact_purpose = _purpose(purpose)
        if action not in _ACTIONS:
            raise ValueError("knowledge action is unsupported")
        if human_display and not principal.startswith("user:"):
            raise KnowledgeAccessDenied("human-readable knowledge requires a named user")
        if self.actor_authority_resolver is None:
            raise KnowledgeAccessDenied("knowledge actor authority is unavailable")
        try:
            authority = self.actor_authority_resolver(
                canonical,
                principal,
                action,
                exact_purpose,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise KnowledgeAccessDenied("current actor authority is unavailable") from exc
        if type(authority) is not KnowledgeActorAuthority or (
            authority.tenant != canonical
            or authority.principal != principal
            or authority.action != action
            or authority.purpose != exact_purpose
        ):
            raise KnowledgeAccessDenied("actor authority crossed its exact boundary")
        return authority

    @staticmethod
    def _cache_key(
        tenant: str,
        reference: ResearchAssetRef,
    ) -> tuple[str, str, str, str, str]:
        return (canonical_tenant_id(tenant), *_reference_key(reference))

    def _evict(self, tenant: str, reference: ResearchAssetRef) -> None:
        key = self._cache_key(tenant, reference)
        with self._cache_lock:
            self._cache.pop(key, None)
            # Derived lexical terms can contain source words too. Revocation
            # evicts them along with the rendering, never just its permission.
            if any(identity not in self._lexical_owner for identity in self._lexical):
                self._lexical.clear()  # an untracked projection: fail safe
                self._lexical_owner.clear()
                return
            for identity in [i for i, owner in self._lexical_owner.items() if owner == key]:
                self._lexical.pop(identity, None)
                self._lexical_owner.pop(identity, None)

    def _deny_applying_retirement(
        self,
        tenant: str,
        reference: ResearchAssetRef,
    ) -> None:
        """Withhold a source once an approved retirement starts applying.

        The request record is made durable before the registry revocation so a
        stopped process can recover exactly.  That recovery window must itself
        revoke read authority; otherwise the still-approved registry row would
        let direct, cached, export, or queued-job reads escape after approval.
        Callers hold the registry effect fence while this bounded request scan
        and the following registry resolution run.
        """

        expected = asdict(reference)
        with tenant_scope(tenant=tenant):
            rows = self.request_store.list(limit=_MAX_REQUESTS)
        if len(rows) >= _MAX_REQUESTS and self.request_store.count(
            maximum=_MAX_REQUESTS + 1
        ) > len(rows):
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied(
                "knowledge retirement authority cannot be resolved within its request boundary"
            )
        if any(
            row.get("tenant") == tenant
            and row.get("source_reference") == expected
            and row.get("status") == "applying"
            and row.get("decision") == "approve"
            for row in rows
        ):
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied("knowledge source retirement is in progress")

    def _admission(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        *,
        purpose: str,
        action: str | None,
    ) -> DatasetAdmission:
        canonical = canonical_tenant_id(tenant)
        _reference_key(reference)
        self._deny_applying_retirement(canonical, reference)
        exact_purpose = _purpose(purpose)
        exact_action = None
        if action is not None:
            if not isinstance(action, str) or action not in _ACTIONS:
                raise ValueError("knowledge action is unsupported")
            exact_action = action
        try:
            admission = self.registry.resolve_dataset(
                canonical,
                reference,
                purpose=exact_purpose,
                action=exact_action,
            )
        except (ResearchRegistryDenied, ResearchRegistryConflict, ResearchRegistryNotFound):
            self._evict(canonical, reference)
            raise
        if admission.tenant != canonical or admission.reference != reference:
            self._evict(canonical, reference)
            raise KnowledgeAccessDenied("current source authority crossed its exact boundary")
        if exact_action is not None:
            normalized = {
                re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
                for value in admission.usage_constraints
            }
            denied = sorted(normalized & _ACTION_DENIAL_CONSTRAINTS[exact_action])
            if denied:
                self._evict(canonical, reference)
                raise KnowledgeAccessDenied(
                    "current source constraints do not permit the requested action"
                )
        return admission

    def _document(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        admission: DatasetAdmission,
        *,
        actor_authority: KnowledgeActorAuthority,
        use_cache: bool,
    ) -> tuple[KnowledgeDocument, bool]:
        key = self._cache_key(tenant, reference)
        cached: KnowledgeDocument | None = None
        if use_cache:
            with self._cache_lock:
                cached = self._cache.get(key)
                if cached is not None:
                    self._cache.move_to_end(key)
                    if not hmac.compare_digest(cached.content_sha256, admission.content_sha256):
                        self._cache.pop(key, None)
                        raise KnowledgeAccessDenied(
                            "cached knowledge no longer matches the current source version"
                        )
        # A cache entry is only a bounded rendering optimization.  Re-read the
        # owning store on every access so an exact source that was removed,
        # retired, or changed cannot remain readable merely because the
        # registry commitment itself has not yet been corrected.
        try:
            contextual = getattr(self.content_resolver, "resolve_for_context", None)
            resolved = (
                None
                if self.content_resolver is None
                else contextual(tenant, reference, admission, actor_authority)
                if callable(contextual)
                else self.content_resolver(tenant, reference, admission)
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            self._evict(tenant, reference)
            raise KnowledgeContentUnavailable("current knowledge content is unavailable") from exc
        if resolved is None:
            self._evict(tenant, reference)
            raise KnowledgeContentUnavailable(
                "registered source content is not available through a governed projector"
            )
        document = resolved
        if type(document) is not KnowledgeDocument:
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied("knowledge content authority returned malformed material")
        if (
            document.tenant != tenant
            or document.reference != reference
            or not hmac.compare_digest(document.content_sha256, admission.content_sha256)
        ):
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied("knowledge content crossed its tenant or version boundary")
        cache_hit = cached == document
        with self._cache_lock:
            self._cache[key] = document
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_capacity:
                self._cache.popitem(last=False)
        return cached if cache_hit and cached is not None else document, cache_hit

    def _requests_for_reference(
        self,
        tenant: str,
        reference: ResearchAssetRef,
    ) -> list[dict]:
        canonical = canonical_tenant_id(tenant)
        expected = asdict(reference)
        with tenant_scope(tenant=canonical):
            rows = self.request_store.list(limit=_MAX_REQUESTS)
        matched = [
            self._fresh_request_projection(canonical, row)
            for row in rows
            if row.get("tenant") == canonical and row.get("source_reference") == expected
        ]
        matched.sort(
            key=lambda row: (float(row.get("created_at", 0)), str(row.get("id", ""))),
            reverse=True,
        )
        return matched[:50]

    def _revalidate_return_set(
        self,
        tenant: str,
        actor_authority: KnowledgeActorAuthority,
        references: Sequence[ResearchAssetRef],
        items: Sequence[Mapping[str, object]],
        *,
        purpose: str,
        action: str,
    ) -> None:
        """Recheck the complete assembled result immediately before release.

        Per-item checks stop a revocation that happens during that item's
        projector.  They are not enough for a catalogue: projecting a later
        source can race with revocation of an earlier one.  This final fence
        re-walks the actor and every exact source after all projectors and
        request-history reads have completed.  Any change withholds the whole
        assembled response so no stale item can survive beside a newer one.
        The caller holds ``registry.effect_fence`` through this sweep and
        response assembly, excluding normal registry and shared-authority
        mutations until the release value has been built.
        """

        if len(references) != len(items):
            raise KnowledgeAccessDenied("knowledge result assembly is incomplete")
        current_authority = self._actor_authority(
            tenant,
            actor_authority.principal,
            action=action,
            purpose=purpose,
            human_display=False,
        )
        if current_authority != actor_authority:
            for reference in references:
                self._evict(tenant, reference)
            raise KnowledgeAccessDenied("actor authority changed during knowledge access")
        for reference, item in zip(references, items, strict=True):
            current = self._admission(
                tenant,
                reference,
                purpose=purpose,
                action=action,
            )
            source = item.get("source")
            eligibility = item.get("eligibility")
            if not isinstance(source, Mapping) or not isinstance(eligibility, Mapping):
                self._evict(tenant, reference)
                raise KnowledgeAccessDenied("knowledge result authority is malformed")
            consent_until = (
                None
                if current.consent_authority is None
                else current.consent_authority.valid_until
            )
            if (
                item.get("reference") != asdict(reference)
                or source.get("source_ref") != current.source_ref
                or source.get("version") != reference.version
                or source.get("content_sha256") != current.content_sha256
                or source.get("license_id") != current.license_id
                or source.get("provenance_kind") != current.provenance_kind
                or source.get("usage_constraints") != list(current.usage_constraints)
                or eligibility.get("purpose") != current.allowed_purpose
                or eligibility.get("permitted_action")
                != current.data_use_authority.action
                or eligibility.get("fresh_until")
                != current.data_use_authority.expires_at
                or eligibility.get("consent_until") != consent_until
                or eligibility.get("approval_sha256") != current.approval_sha256
                or eligibility.get("requested_action") != action
                or eligibility.get("actor") != actor_authority.principal
                or eligibility.get("actor_authorization_sha256")
                != actor_authority.authorization_sha256
            ):
                self._evict(tenant, reference)
                raise KnowledgeAccessDenied("source authority changed during knowledge access")
        # A shared role/capability may be revoked while the source set is being
        # re-walked.  Make the actor check the last authority read before the
        # caller receives content.
        if (
            self._actor_authority(
                tenant,
                actor_authority.principal,
                action=action,
                purpose=purpose,
                human_display=False,
            )
            != actor_authority
        ):
            for reference in references:
                self._evict(tenant, reference)
            raise KnowledgeAccessDenied("actor authority changed during knowledge access")
        # Authority resolvers are composition boundaries and can execute code.
        # A same-thread resolver that performs a re-entrant registry mutation
        # would legitimately hold the fence and could otherwise revoke an
        # earlier source during the later source's final admission read. End
        # with direct registry-state reads, which invoke no external authority
        # resolver, while the shared mutation fence is still held.
        for reference, item in zip(references, items, strict=True):
            row = self.registry.inspect(tenant, reference)
            approval = row.get("approval")
            if (
                row.get("state") != "approved"
                or row.get("reference") != asdict(reference)
                or not isinstance(approval, Mapping)
                or approval.get("approval_sha256")
                != item["eligibility"]["approval_sha256"]
            ):
                self._evict(tenant, reference)
                raise KnowledgeAccessDenied(
                    "source registry state changed during knowledge access"
                )
        final_time = self.registry.store.authoritative_time()
        for reference, item in zip(references, items, strict=True):
            eligibility = item["eligibility"]
            fresh_until = eligibility["fresh_until"]
            consent_until = eligibility["consent_until"]
            if fresh_until <= final_time or (
                consent_until is not None and consent_until <= final_time
            ):
                self._evict(tenant, reference)
                raise KnowledgeAccessDenied(
                    "source authority expired during knowledge access"
                )

    def _item(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        *,
        purpose: str,
        action: str,
        actor_authority: KnowledgeActorAuthority,
        use_cache: bool,
        include_retrieval_chunks: bool = False,
    ) -> dict:
        admission = self._admission(
            tenant,
            reference,
            purpose=purpose,
            action=action,
        )
        document, cache_hit = self._document(
            tenant,
            reference,
            admission,
            actor_authority=actor_authority,
            use_cache=use_cache,
        )
        # The projector may cross a process or storage boundary. Re-read both
        # authorities after it returns so a revocation or role change during
        # that read cannot escape in the response assembled below.
        current_authority = self._actor_authority(
            tenant,
            actor_authority.principal,
            action=action,
            purpose=purpose,
            human_display=False,
        )
        if current_authority != actor_authority:
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied("actor authority changed during knowledge access")
        current_admission = self._admission(
            tenant,
            reference,
            purpose=purpose,
            action=action,
        )
        if current_admission != admission:
            self._evict(tenant, reference)
            raise KnowledgeAccessDenied("source authority changed during knowledge access")
        history = self._requests_for_reference(tenant, reference)
        checked_at = self.registry.store.authoritative_time()
        consent = admission.consent_authority
        item = {
            "schema": KNOWLEDGE_DETAIL_SCHEMA,
            "reference": asdict(reference),
            "title": document.title,
            "summary": document.summary,
            "summary_truncated": document.summary_truncated,
            "search_coverage_complete": document.search_coverage_complete,
            "permissions_withheld": document.permissions_withheld,
            "content_available": bool(document.summary),
            "claim_state": document.claim_state,
            "observed_at": document.observed_at,
            "verified_at": document.verified_at,
            "source": {
                "authority_owner": "research_registry",
                "source_ref": admission.source_ref,
                "version": reference.version,
                "content_sha256": admission.content_sha256,
                "provenance_kind": admission.provenance_kind,
                "license_id": admission.license_id,
                "usage_constraints": list(admission.usage_constraints),
            },
            "eligibility": {
                "state": "eligible",
                "checked_at": checked_at,
                "purpose": admission.allowed_purpose,
                "permitted_action": admission.data_use_authority.action,
                "fresh_until": admission.data_use_authority.expires_at,
                "consent_until": None if consent is None else consent.valid_until,
                "approval_sha256": admission.approval_sha256,
                "requested_action": action,
                "actor": actor_authority.principal,
                "actor_authorization_sha256": actor_authority.authorization_sha256,
            },
            "cache": {
                "owner": "knowledge_access_process_projection",
                "hit": cache_hit,
                "content_revalidated_before_return": True,
            },
            "correction_history": history,
            "training_permission_notice": TRAINING_PERMISSION_NOTICE,
        }
        if include_retrieval_chunks:
            item["_retrieval_chunks"] = document.retrieval_chunks
        # Request-history projection performs additional registry/store I/O.
        # Revalidate after it so a revocation during that work cannot release
        # the content assembled above.
        with self.registry.effect_fence():
            self._revalidate_return_set(
                tenant,
                actor_authority,
                (reference,),
                (item,),
                purpose=purpose,
                action=action,
            )
            return item

    def detail(
        self,
        tenant: str,
        actor: str,
        reference: ResearchAssetRef,
        *,
        purpose: str,
        use_cache: bool = True,
    ) -> dict:
        """Return one exact version after live source-authority validation."""

        if not isinstance(use_cache, bool):
            raise ValueError("use_cache must be boolean")
        canonical = canonical_tenant_id(tenant)
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            authority = self._actor_authority(
                canonical,
                actor,
                action="read",
                purpose=purpose,
                human_display=True,
            )
            return self._item(
                canonical,
                reference,
                purpose=purpose,
                action="read",
                actor_authority=authority,
                use_cache=use_cache,
            )

    def _search_page(
        self,
        tenant: str,
        authority: KnowledgeActorAuthority,
        *,
        query: str,
        purpose: str,
        action: str,
        selectors: tuple[str, ...] | None,
        limit: int,
        cursor: str | None,
    ) -> tuple[list[dict], dict]:
        binding = digest({
            "tenant": tenant, "actor": authority.principal,
            "actor_authorization_sha256": authority.authorization_sha256,
            "query": query, "purpose": purpose, "action": action,
            "selectors": selectors, "limit": limit,
        })
        continuation = SearchCursor.decode(cursor, binding)
        page = self.registry.knowledge_candidate_page(
            tenant, source_selectors=selectors, limit=_MAX_SCAN,
            after=continuation.after, snapshot=continuation.snapshot,
        )
        items: list[dict] = []
        projections: list[LexicalProjection] = []
        unavailable = partial = withheld = 0
        for row in page["items"]:
            try:
                item = self._item(
                    tenant, ResearchAssetRef(**row["reference"]), purpose=purpose,
                    action=action, actor_authority=authority, use_cache=True,
                    include_retrieval_chunks=True,
                )
            except KnowledgeContentUnavailable:
                unavailable += 1
                continue
            except (ResearchRegistryDenied, KnowledgeAccessDenied):
                continue
            # This projection contains no cached authority. _item has already
            # reread the owning content store and current source/actor rights.
            partial += not item["search_coverage_complete"]
            withheld += item["permissions_withheld"]
            identity = LexicalProjection.key(tenant, item)
            with self._cache_lock:
                projection = self._lexical.get(identity)
                if projection is None:
                    projection = LexicalProjection.from_item(identity, item)
                    self._lexical[identity] = projection
                    ref = item["reference"]
                    self._lexical_owner[identity] = (canonical_tenant_id(tenant), *(
                        ref[field] for field in ("kind", "asset_id", "version", "manifest_sha256")))
                self._lexical.move_to_end(projection.identity)
                while len(self._lexical) > self.cache_capacity:
                    evicted, _ = self._lexical.popitem(last=False)
                    self._lexical_owner.pop(evicted, None)
            projections.append(projection)
            items.append(item)
        ranked = rank(query, projections)
        ranking_digest = digest([
            projections[index].identity for index, _score in ranked
        ])
        if continuation.ranking is not None and continuation.ranking != ranking_digest:
            raise ValueError("knowledge candidates changed; restart the search")
        if continuation.offset > len(ranked):
            raise ValueError("knowledge cursor exceeds the candidate page; restart the search")
        end = min(len(ranked), continuation.offset + limit)
        selected = [retrieval_passage(items[index], query)
                    for index, _score in ranked[continuation.offset:end]]
        more_matches = end < len(ranked)
        next_cursor = None
        if more_matches:
            next_cursor = SearchCursor(
                binding, continuation.after, page["snapshot"], end, ranking_digest,
                continuation.unavailable_before,
                continuation.partial_before or bool(partial),
            ).encode()
        elif page["has_more"]:
            next_cursor = SearchCursor(
                binding, page["last"], page["snapshot"],
                unavailable_before=continuation.unavailable_before or bool(unavailable),
                partial_before=continuation.partial_before or bool(partial),
            ).encode()
        reasons = []
        if more_matches:
            reasons.append("more_matches")
        if page["has_more"]:
            reasons.append("more_candidates")
        if unavailable or continuation.unavailable_before:
            reasons.append("content_unavailable")
        if partial or continuation.partial_before:
            reasons.append("partial_source_coverage")
        complete = not reasons
        status = (
            "unavailable" if "content_unavailable" in reasons and not selected and next_cursor is None
            else "incomplete" if not complete
            else "matched" if selected else "no_match"
        )
        return selected, {
            "status": status, "complete": complete, "incomplete_reasons": reasons,
            "next_cursor": next_cursor, "truncated": not complete,
            "matched": len(ranked), "matched_scope": "candidate_page",
            # Keep the transport field for existing clients without disclosing
            # how many inaccessible records exist in the registry.
            "omitted_ineligible": 0, "unavailable_sources": unavailable,
            "permissions_withheld": withheld,
            "candidates_examined": len(items),
            "ranking": "lexical_bm25_v1_within_candidate_page",
        }

    def available_purposes(self, tenant: str, actor: str) -> list[str]:
        """All current purposes backed by at least one source this actor may read.

        Registry pages are candidate metadata only. Never release a purpose
        until the same live source, consent, lineage and principal checks used
        for detail succeed. A source whose content is unavailable (a storage or
        projection failure) is treated like a denied source: it backs no
        purpose, so the purpose is omitted rather than reported as an error.
        """
        canonical = canonical_tenant_id(tenant)
        found: set[str] = set()
        after = snapshot = None
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            while True:
                page = self.registry.knowledge_candidate_page(
                    canonical, source_selectors=None, limit=_MAX_SCAN,
                    after=after, snapshot=snapshot,
                )
                for row in page["items"]:
                    if row.get("state") != "approved":
                        continue
                    for purpose in row.get("manifest", {}).get("allowed_purposes", ()):
                        try:
                            self.detail(canonical, actor, ResearchAssetRef(**row["reference"]),
                                        purpose=purpose)
                        except (ResearchRegistryDenied, KnowledgeAccessDenied, PermissionError):
                            continue
                        found.add(purpose)
                if not page["has_more"]:
                    break
                after, snapshot = page["last"], page["snapshot"]
        return sorted(found)

    def search(
        self,
        tenant: str,
        actor: str,
        *,
        query: str,
        purpose: str,
        limit: int = 20,
        source_selectors: Sequence[str] | None = None,
        cursor: str | None = None,
    ) -> dict:
        """Search eligible registry-backed projections without duplicating an index.

        Optional source selectors constrain registry metadata before content is
        projected.  This lets a caller search one governed collection without
        fetching unrelated eligible sources or allowing them to consume the
        result limit.
        """

        canonical = canonical_tenant_id(tenant)
        needle = _text(query, "knowledge query", 512, required=False).casefold()
        exact_purpose = _purpose(purpose)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_RESULTS:
            raise ValueError(f"limit must be between 1 and {_MAX_RESULTS}")
        selectors = (
            None if source_selectors is None else self._source_selectors(source_selectors)
        )
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            authority = self._actor_authority(
                canonical,
                actor,
                action="read",
                purpose=exact_purpose,
                human_display=True,
            )
            results, retrieval = self._search_page(
                canonical, authority, query=needle, purpose=exact_purpose,
                action="read", selectors=selectors, limit=limit, cursor=cursor,
            )
            result_references = tuple(
                ResearchAssetRef(**item["reference"]) for item in results
            )
            with self.registry.effect_fence():
                self._revalidate_return_set(
                    canonical,
                    authority,
                    result_references,
                    results,
                    purpose=exact_purpose,
                    action="read",
                )
                return {
                    "schema": KNOWLEDGE_SEARCH_SCHEMA,
                    "tenant": canonical,
                    "actor": authority.principal,
                    "actor_authorization_sha256": authority.authorization_sha256,
                    "query": query.strip(),
                    "purpose": exact_purpose,
                    "items": results,
                    "count": len(results),
                    **retrieval,
                    "authority_checks": (
                        "Current registry version, approval, data-use authority, freshness, consent, "
                        "and parent lineage are revalidated before every result."
                    ),
                    "training_permission_notice": TRAINING_PERMISSION_NOTICE,
                }

    @staticmethod
    def _exact_references(values: Sequence[ResearchAssetRef], maximum: int) -> tuple:
        if isinstance(values, str | bytes) or not isinstance(values, Sequence):
            raise ValueError("knowledge references must be a bounded list")
        references = tuple(values)
        if not 1 <= len(references) <= maximum:
            raise ValueError(f"knowledge references must contain one to {maximum} versions")
        keys = [_reference_key(item) for item in references]
        if len(set(keys)) != len(keys):
            raise ValueError("knowledge references must be unique")
        return references

    def export(
        self,
        tenant: str,
        actor: str,
        references: Sequence[ResearchAssetRef],
        *,
        purpose: str,
    ) -> dict:
        """Build an all-or-nothing export after exact current export checks."""

        canonical = canonical_tenant_id(tenant)
        exact = self._exact_references(references, _MAX_EXPORT)
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            authority = self._actor_authority(
                canonical,
                actor,
                action="export",
                purpose=purpose,
                human_display=True,
            )
            items = [
                self._item(
                    canonical,
                    reference,
                    purpose=purpose,
                    action="export",
                    actor_authority=authority,
                    use_cache=True,
                )
                for reference in exact
            ]
            with self.registry.effect_fence():
                self._revalidate_return_set(
                    canonical,
                    authority,
                    exact,
                    items,
                    purpose=purpose,
                    action="export",
                )
                evidence = {
                    "schema": "lightwork.knowledge-export-authority-evidence.v1",
                    "tenant": canonical,
                    "actor": authority.principal,
                    "actor_authorization_sha256": authority.authorization_sha256,
                    "purpose": _purpose(purpose),
                    "action": "export",
                    "sources": [
                        {
                            "reference": item["reference"],
                            "content_sha256": item["source"]["content_sha256"],
                            "approval_sha256": item["eligibility"]["approval_sha256"],
                        }
                        for item in items
                    ],
                }
                return {
                    "schema": KNOWLEDGE_EXPORT_SCHEMA,
                    "tenant": canonical,
                    "actor": authority.principal,
                    "actor_authorization_sha256": authority.authorization_sha256,
                    "purpose": _purpose(purpose),
                    "items": items,
                    "count": len(items),
                    "complete": True,
                    "authority_evidence": {
                        **evidence,
                        "binding_sha256": _digest(evidence),
                    },
                    "qualification": {
                        "local_control_validation": "passed_at_request_time",
                        "external_store_and_customer_qualification": "qualification_pending",
                    },
                    "training_permission_notice": TRAINING_PERMISSION_NOTICE,
                }

    def materialize_at_job_start(
        self,
        tenant: str,
        actor: str,
        references: Sequence[ResearchAssetRef],
        *,
        purpose: str,
        action: str,
        job_id: str,
        retrieval_query: str | None = None,
    ) -> dict:
        """Revalidate and materialize an exact catalogue inside a queued worker.

        Call this after a job is claimed, immediately before the worker may use
        source material.  The method returns no partial catalogue if any source
        changed while the job waited.
        """

        canonical = canonical_tenant_id(tenant)
        exact = self._exact_references(references, _MAX_EXPORT)
        exact_job = _identifier(job_id, "job_id")
        if retrieval_query is not None:
            retrieval_query = _text(retrieval_query, "knowledge query", 512, required=False)
        if action not in _ACTIONS:
            raise ValueError("knowledge job action is unsupported")
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            authority = self._actor_authority(
                canonical,
                actor,
                action=action,
                purpose=purpose,
                human_display=False,
            )
            items = [
                self._item(
                    canonical,
                    reference,
                    purpose=purpose,
                    action=action,
                    actor_authority=authority,
                    use_cache=True,
                    include_retrieval_chunks=retrieval_query is not None,
                )
                for reference in exact
            ]
            with self.registry.effect_fence():
                self._revalidate_return_set(
                    canonical,
                    authority,
                    exact,
                    items,
                    purpose=purpose,
                    action=action,
                )
                if retrieval_query is not None:
                    items = [retrieval_passage(item, retrieval_query) for item in items]
                binding = {
                    "schema": KNOWLEDGE_JOB_MATERIALIZATION_SCHEMA,
                    "tenant": canonical,
                    "actor": authority.principal,
                    "actor_authorization_sha256": authority.authorization_sha256,
                    "job_id": exact_job,
                    "purpose": _purpose(purpose),
                    "action": action,
                    "references": [asdict(item) for item in exact],
                }
                return {
                    **binding,
                    "binding_sha256": _digest(binding),
                    "items": items,
                    "count": len(items),
                    "complete": True,
                    "revalidated_at_job_start": True,
                    "training_permission_notice": TRAINING_PERMISSION_NOTICE,
                }

    @staticmethod
    def _source_selectors(values: Sequence[str]) -> tuple[str, ...]:
        if isinstance(values, str | bytes) or not isinstance(values, Sequence):
            raise ValueError("knowledge source selectors must be a bounded list")
        selectors = tuple(
            _text(value, "knowledge source selector", 2_048) for value in values
        )
        if not 1 <= len(selectors) <= _MAX_SOURCE_SELECTORS:
            raise ValueError(
                f"knowledge source selectors must contain one to {_MAX_SOURCE_SELECTORS} values"
            )
        if len(set(selectors)) != len(selectors):
            raise ValueError("knowledge source selectors must be unique")
        return selectors

    def search_at_job_start(
        self,
        tenant: str,
        actor: str,
        *,
        query: str,
        purpose: str,
        source_selectors: Sequence[str],
        limit: int,
        job_id: str,
        cursor: str | None = None,
    ) -> dict:
        """Search only configured sources and rematerialize them for agent use.

        The result is intentionally built through ``materialize_at_job_start``:
        the agent tool cannot reuse the legacy vector-search shortcut or a
        catalogue assembled before the worker began.  Selector matching uses
        registry metadata only, before any source content is projected.
        """

        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "knowledge actor", 512)
        needle = _text(query, "knowledge query", 512, required=False).casefold()
        exact_purpose = _purpose(purpose)
        selectors = self._source_selectors(source_selectors)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_RESULTS:
            raise ValueError(f"limit must be between 1 and {_MAX_RESULTS}")
        exact_job = _identifier(job_id, "job_id")
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            authority = self._actor_authority(
                canonical,
                principal,
                action="analyze",
                purpose=exact_purpose,
                human_display=False,
            )
            selected, retrieval = self._search_page(
                canonical, authority, query=needle, purpose=exact_purpose,
                action="analyze", selectors=selectors, limit=limit, cursor=cursor,
            )
            matched_references = [ResearchAssetRef(**item["reference"]) for item in selected]
            if not matched_references:
                self._revalidate_return_set(
                    canonical,
                    authority,
                    (),
                    (),
                    purpose=exact_purpose,
                    action="analyze",
                )
                items: list[dict] = []
                materialization = None
            else:
                materialization = self.materialize_at_job_start(
                    canonical,
                    principal,
                    tuple(matched_references),
                    purpose=exact_purpose,
                    action="analyze",
                    job_id=exact_job,
                    retrieval_query=needle,
                )
                if (
                    materialization.get("actor") != authority.principal
                    or materialization.get("actor_authorization_sha256")
                    != authority.authorization_sha256
                ):
                    for reference in matched_references:
                        self._evict(canonical, reference)
                    raise KnowledgeAccessDenied(
                        "actor authority changed before job materialization"
                    )
                items = materialization["items"]
            return {
                "schema": KNOWLEDGE_SEARCH_SCHEMA,
                "tenant": canonical,
                "actor": authority.principal,
                "actor_authorization_sha256": authority.authorization_sha256,
                "query": query.strip(),
                "purpose": exact_purpose,
                "requested_action": "analyze",
                "source_selectors": list(selectors),
                "items": items,
                "count": len(items),
                **retrieval,
                "job_materialization": (
                    None
                    if materialization is None
                    else {
                        "schema": materialization["schema"],
                        "job_id": materialization["job_id"],
                        "binding_sha256": materialization["binding_sha256"],
                        "revalidated_at_job_start": materialization[
                            "revalidated_at_job_start"
                        ],
                    }
                ),
                "training_permission_notice": TRAINING_PERMISSION_NOTICE,
            }

    @staticmethod
    def _request_id(tenant: str, actor: str, request_key: str) -> str:
        material = f"{tenant}\0{actor}\0{request_key}".encode()
        return "knowledge-req-" + hashlib.sha256(material).hexdigest()[:40]

    @staticmethod
    def _derivatives(impact: Mapping[str, object], *, request_status: str) -> list[dict]:
        raw = impact.get("derivatives", ())
        if not isinstance(raw, list):
            raise KnowledgeRequestConflict("registry derivative lineage is malformed")
        result = []
        for item in raw:
            if not isinstance(item, Mapping) or not isinstance(item.get("reference"), Mapping):
                raise KnowledgeRequestConflict("registry derivative lineage is malformed")
            reference = ResearchAssetRef(**dict(item["reference"]))
            required = str(item.get("required_action") or "")
            if required not in {"invalidate_dataset", "retire_or_retrain_model"}:
                raise KnowledgeRequestConflict("registry derivative action is malformed")
            state = str(item.get("state") or "unknown")
            if state == "revoked":
                workflow_state = (
                    "dataset_invalidation_confirmed"
                    if required == "invalidate_dataset"
                    else "model_retirement_confirmed_retraining_unverified"
                )
            elif request_status == "denied":
                workflow_state = "no_action_after_denial"
            elif request_status in {"applying", "approved"}:
                workflow_state = required + "_required"
            else:
                workflow_state = "pending_source_review"
            result.append(
                {
                    "reference": asdict(reference),
                    "current_state": state,
                    "required_action": required,
                    "authority_owner": "research_registry_lineage",
                    "workflow_state": workflow_state,
                }
            )
        return result

    @staticmethod
    def _retention_hold_projection(record: Mapping[str, object], *, now: float) -> dict:
        hold = record.get("retention_hold")
        if not isinstance(hold, Mapping):
            raise KnowledgeRequestConflict("knowledge retention hold is malformed")
        required = {
            "schema",
            "hold_id",
            "basis",
            "evidence_sha256",
            "placed_by",
            "placed_at",
            "expires_at",
            "status",
            "released_by",
            "released_at",
            "release_reason",
            "release_evidence_sha256",
        }
        if set(hold) != required or hold.get("schema") != KNOWLEDGE_RETENTION_HOLD_SCHEMA:
            raise KnowledgeRequestConflict("knowledge retention hold is malformed")
        try:
            hold_id = _identifier(hold.get("hold_id"), "retention hold_id")
            basis = _text(hold.get("basis"), "retention hold basis", 2_000)
            evidence_sha256 = str(hold.get("evidence_sha256") or "")
            if not _SHA.fullmatch(evidence_sha256):
                raise ValueError("retention hold evidence is malformed")
            placed_by = _text(hold.get("placed_by"), "retention hold actor", 512)
            if not placed_by.startswith("user:"):
                raise ValueError("retention hold actor is malformed")
            placed_at = _positive_time(hold.get("placed_at"), "retention hold placement")
            expires_at = _positive_time(hold.get("expires_at"), "retention hold expiry")
            assert placed_at is not None and expires_at is not None
            if expires_at <= placed_at:
                raise ValueError("retention hold expiry is malformed")
            status = str(hold.get("status") or "")
            if status not in {"active", "released"}:
                raise ValueError("retention hold state is malformed")
            released = (
                hold.get("released_by"),
                hold.get("released_at"),
                hold.get("release_reason"),
                hold.get("release_evidence_sha256"),
            )
            if status == "active":
                if any(value is not None for value in released):
                    raise ValueError("active retention hold carries release material")
                released_by = released_at = release_reason = release_evidence = None
            else:
                released_by = _text(released[0], "retention release actor", 512)
                if not released_by.startswith("user:"):
                    raise ValueError("retention release actor is malformed")
                released_at = _positive_time(
                    released[1],
                    "retention release time",
                )
                assert released_at is not None
                if released_at < placed_at:
                    raise ValueError("retention release time is malformed")
                release_reason = _text(
                    released[2],
                    "retention release reason",
                    2_000,
                )
                release_evidence = str(released[3] or "")
                if not _SHA.fullmatch(release_evidence):
                    raise ValueError("retention release evidence is malformed")
        except (TypeError, ValueError) as exc:
            raise KnowledgeRequestConflict("knowledge retention hold is malformed") from exc
        effective = "expired" if status == "active" and expires_at <= now else status
        return {
            "schema": KNOWLEDGE_RETENTION_HOLD_SCHEMA,
            "hold_id": hold_id,
            "basis": basis,
            "evidence_sha256": evidence_sha256,
            "placed_by": placed_by,
            "placed_at": placed_at,
            "expires_at": expires_at,
            "status": status,
            "released_by": released_by,
            "released_at": released_at,
            "release_reason": release_reason,
            "release_evidence_sha256": release_evidence,
            "effective_status": effective,
        }

    @staticmethod
    def _request_projection(record: Mapping[str, object]) -> dict:
        reference = ResearchAssetRef(**dict(record["source_reference"]))
        derivatives = record.get("derivatives", ())
        if not isinstance(derivatives, list):
            raise KnowledgeRequestConflict("knowledge request derivative state is malformed")
        recorded_derivatives = record.get("derivatives_at_request", derivatives)
        if not isinstance(recorded_derivatives, list):
            raise KnowledgeRequestConflict(
                "knowledge request recorded derivative state is malformed"
            )
        retention_hold = (
            None
            if record.get("retention_hold") is None
            else KnowledgeAccessService._retention_hold_projection(
                record,
                now=float(record.get("projection_time") or 0) or float(record["updated_at"]),
            )
        )
        replacement = record.get("replacement_reference")
        if replacement is not None:
            replacement = asdict(ResearchAssetRef(**dict(replacement)))
        raw_record_status = str(record["raw_record_status"])
        retention_review_status = str(record["retention_review_status"])
        if (
            str(record.get("request_type")) == "deletion"
            and str(record.get("status")) == "approved"
            and retention_hold is not None
            and retention_hold["effective_status"] == "expired"
        ):
            raw_record_status = (
                "external_source_deletion_unverified_after_hold_expiry"
            )
            retention_review_status = "retention_hold_expired"
        return {
            "schema": KNOWLEDGE_RIGHTS_REQUEST_SCHEMA,
            "id": str(record["id"]),
            "revision": int(record["revision"]),
            "request_type": str(record["request_type"]),
            "status": str(record["status"]),
            "source_reference": asdict(reference),
            "requested_by": str(record["requested_by"]),
            "reason": str(record["reason"]),
            "proposed_correction": record.get("proposed_correction"),
            "source_use_status": str(record["source_use_status"]),
            "raw_record_status": raw_record_status,
            "retention_review_status": retention_review_status,
            "retention_hold": retention_hold,
            "replacement_reference": replacement,
            "replacement_status": record.get("replacement_status"),
            "decision": record.get("decision"),
            "decided_by": record.get("decided_by"),
            "decision_evidence_sha256": record.get("decision_evidence_sha256"),
            "derivatives": [dict(item) for item in derivatives],
            "derivatives_at_request": [
                dict(item)
                for item in recorded_derivatives
            ],
            "weight_influence_notice": WEIGHT_INFLUENCE_NOTICE,
            "training_permission_notice": TRAINING_PERMISSION_NOTICE,
            "created_at": float(record["created_at"]),
            "updated_at": float(record["updated_at"]),
        }

    def _fresh_request_projection(
        self,
        tenant: str,
        record: Mapping[str, object],
        *,
        archived_at: float | None = None,
    ) -> dict:
        """Project immutable request history with current derivative states.

        The stored derivative list remains evidence of what the requester and
        reviewer saw.  The display/export projection re-walks the registry so a
        later invalidation or retirement cannot leave the workflow card stale.
        """

        canonical = canonical_tenant_id(tenant)
        reference = ResearchAssetRef(**dict(record["source_reference"]))
        impact = self.registry.derivative_impact(canonical, reference)
        material = dict(record)
        material["projection_time"] = self.request_store.authoritative_time()
        projection = self._request_projection(material)
        projection["derivatives"] = self._derivatives(
            impact,
            request_status=str(record.get("status")),
        )
        projection["lineage_revalidated_before_return"] = True
        projection["archived_at"] = archived_at
        projection["archive_ready"] = (
            archived_at is None and self._archive_ready(canonical, record)
        )
        return projection

    @staticmethod
    def _archive_digest(record: Mapping[str, object]) -> str:
        encoded = json.dumps(
            record, allow_nan=False, ensure_ascii=False,
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _archived_request(self, tenant: str, archive: Mapping[str, object]) -> dict:
        """Verify a retained snapshot before it can be shown or replayed."""
        record = archive.get("request")
        if (
            archive.get("schema") != KNOWLEDGE_REQUEST_ARCHIVE_SCHEMA
            or archive.get("tenant") != tenant
            or not isinstance(record, dict)
            or record.get("tenant") != tenant
            or record.get("id") != archive.get("id")
            or record.get("status") not in {"approved", "denied"}
            or not hmac.compare_digest(
                str(archive.get("request_sha256") or ""),
                self._archive_digest(record),
            )
        ):
            raise KnowledgeRequestConflict("retained knowledge request could not be verified")
        return record

    def _archive_ready(self, tenant: str, record: Mapping[str, object]) -> bool:
        if not self._archive_available(tenant):
            return False
        if record.get("status") not in {"approved", "denied"}:
            return False
        hold = record.get("retention_hold")
        if hold is not None and (
            not isinstance(hold, Mapping) or hold.get("status") != "released"
        ):
            return False
        if record.get("decision") != ("approve" if record["status"] == "approved" else "deny"):
            return False
        if record.get("status") == "denied":
            return True
        try:
            reference = ResearchAssetRef(**dict(record["source_reference"]))
            source = self.registry.inspect(tenant, reference)
            revocation = source.get("revocation")
            if (
                source.get("state") != "revoked"
                or not isinstance(revocation, Mapping)
                or revocation.get("revoked_by") != record.get("decided_by")
                or revocation.get("reason_code") != "knowledge_" + str(record["request_type"])
                or not hmac.compare_digest(
                    str(revocation.get("evidence_sha256") or ""),
                    str(record.get("decision_evidence_sha256") or ""),
                )
            ):
                return False
            if record.get("request_type") == "correction":
                replacement = record.get("replacement_reference")
                if not isinstance(replacement, Mapping) or record.get(
                    "replacement_status"
                ) != "approved":
                    return False
                state = self.registry.inspect(tenant, ResearchAssetRef(**dict(replacement)))
                return state.get("state") == "approved"
            return True
        except (
            KeyError, TypeError, ValueError,
            ResearchRegistryNotFound, ResearchRegistryConflict, ResearchRegistryDenied,
        ):
            return False

    def _archive_available(self, tenant: str) -> bool:
        """The two-store retirement protocol is safe only under one local fence."""
        with tenant_scope(tenant=tenant):
            return (
                self.request_store.backend_kind == "local"
                and self.archive_store.backend_kind == "local"
            )

    def _full_request_message(self, tenant: str) -> str:
        if self._archive_available(tenant):
            return (
                "The active knowledge request list is full. Ask an administrator to archive "
                "finished requests in Knowledge. Requests and evidence are retained."
            )
        return (
            "The active knowledge request list is full. Ask an administrator to review "
            "capacity. Archiving is unavailable on shared storage until transactional "
            "retirement is supported; requests and evidence remain in place."
        )

    def request_capacity(self, tenant: str) -> dict:
        canonical = canonical_tenant_id(tenant)
        with tenant_scope(tenant=canonical):
            count = self.request_store.count(maximum=_MAX_REQUESTS + 1)
            archive_available = self._archive_available(canonical)
        return {
            "active_count": count,
            "active_limit": _MAX_REQUESTS,
            "archive_available": archive_available,
        }

    def recovery_candidates(
        self, tenant: str, *, cursor: str = "", limit: int = 100,
    ) -> dict:
        """Find archivable requests in one bounded ID window of an overfilled ledger.

        The ordinary list is deliberately capped at ``_MAX_REQUESTS``. A
        legacy import can put a finished request beyond that window, so an
        administrator needs a cursor over IDs without loading every body.
        This only discovers candidates; ``archive_request`` still performs
        the revision, source, hold, audit, and local-backend checks.
        """
        canonical = canonical_tenant_id(tenant)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 250:
            raise ValueError("recovery scan limit must be between 1 and 250")
        if not isinstance(cursor, str) or len(cursor) > 128:
            raise ValueError("recovery cursor is invalid")
        with tenant_scope(tenant=canonical):
            if not self._archive_available(canonical):
                raise KnowledgeArchiveUnavailable(
                    "Finished-request archiving is unavailable on this installation. "
                    "The request and source restrictions remain in place."
                )
            window = list(self.request_store.iter_record_ids(start_after=cursor, limit=limit))
            items: list[dict] = []
            next_cursor = None
            complete = len(window) < limit
            for position, request_id in window:
                # Backends rotate to the beginning after the final ID. Never
                # show that wrapped prefix twice or call it a later page.
                if cursor and position <= cursor:
                    complete = True
                    break
                next_cursor = position
                record = self.request_store.get(request_id)
                if record is not None and record.get("tenant") == canonical and self._archive_ready(canonical, record):
                    items.append(self._fresh_request_projection(canonical, record))
        return {"items": items, "next_cursor": None if complete else next_cursor}

    def archive_request(
        self, tenant: str, actor: str, request_id: str, *, expected_revision: int,
    ) -> dict:
        """Retain a final request before removing its live ledger row.

        A concurrent revision change or undelivered archive audit leaves the
        live row intact. The registry continues to enforce approved retirements.
        """
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "archive reviewer", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named administrator is required")
        _text(request_id, "knowledge request_id", 128)
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            if not self._archive_available(canonical):
                raise KnowledgeArchiveUnavailable(
                    "Finished-request archiving is unavailable on this installation. "
                    "The request and source restrictions remain in place."
                )
            current = self.request_store.get(request_id)
            if current is None:
                archive = self.archive_store.get(request_id)
                if archive is None:
                    raise KnowledgeRequestNotFound("knowledge rights request was not found")
                record = self._archived_request(canonical, archive)
                if int(record["revision"]) != expected_revision:
                    raise KnowledgeRequestConflict("knowledge request changed before archiving")
                return self._fresh_request_projection(
                    canonical, record, archived_at=float(archive["created_at"]),
                )
            if current.get("tenant") != canonical:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            if int(current["revision"]) != expected_revision:
                raise KnowledgeRequestConflict("knowledge request changed before archiving")
            if not self._archive_ready(canonical, current):
                raise KnowledgeRequestConflict(
                    "Only finished requests with confirmed source changes and released legal holds can be archived"
                )
            if current.get("_audit_pending"):
                current = self.request_store._flush(current)
            if current.get("_audit_pending"):
                raise KnowledgeRequestConflict(
                    "The request's audit record is still syncing. Refresh and try again."
                )
            snapshot = {key: value for key, value in current.items() if key != "_audit_pending"}
            material = {
                "schema": KNOWLEDGE_REQUEST_ARCHIVE_SCHEMA,
                "id": request_id,
                "tenant": canonical,
                "request": snapshot,
                "request_sha256": self._archive_digest(snapshot),
                "archived_by": principal,
            }
            archive = self.archive_store.get(request_id)
            if archive is None:
                archive = self.archive_store.create(
                    material, actor=principal, action="knowledge.rights_request.archive",
                )
            else:
                self._archived_request(canonical, archive)
                if archive.get("request_sha256") != material["request_sha256"]:
                    def refresh(record: dict) -> None:
                        record.update(material)
                    archive = self.archive_store.update(
                        request_id, refresh, expected_revision=int(archive["revision"]),
                        actor=principal, action="knowledge.rights_request.archive.refresh",
                    )
                    if archive is None:
                        raise KnowledgeRequestConflict("retained request changed before archiving")
            if archive.get("_audit_pending"):
                archive = self.archive_store._flush(archive)
            if archive.get("_audit_pending"):
                raise KnowledgeRequestConflict(
                    "The retained audit record is still syncing. Refresh and try again."
                )
            if not self.request_store.delete(request_id, expected_revision=expected_revision):
                raise KnowledgeRequestConflict("knowledge request changed before archiving")
            return self._fresh_request_projection(
                canonical, snapshot, archived_at=float(archive["created_at"]),
            )

    def _prepare_correction_source(
        self,
        *,
        tenant: str,
        actor: str,
        request_id: str,
        request_sha256: str,
        reference: ResearchAssetRef,
        prior_content_sha256: str,
        correction: str,
    ) -> tuple[str, str]:
        from .knowledge_content_projection import (
            correction_source_payload,
            correction_source_record_id,
            correction_source_ref,
        )

        artifact = {
            "schema": "lightwork.knowledge-correction-source.v1",
            "id": correction_source_record_id(request_id),
            "tenant": tenant,
            "request_id": request_id,
            "requested_by": actor,
            "prior_reference": asdict(reference),
            "prior_content_sha256": prior_content_sha256,
            "correction": correction,
            "request_sha256": request_sha256,
        }
        content_sha256 = _digest(correction_source_payload(artifact))
        current = self.correction_store.get(artifact["id"])
        if current is None:
            try:
                self.correction_store.create(
                    artifact,
                    actor=actor,
                    action="knowledge.correction_source.create",
                    # Approved corrections remain live registered source content.
                    # Their source artifacts cannot be retired with request cards.
                )
            except RecordConflict as exc:
                current = self.correction_store.get(artifact["id"])
                if current is None:
                    raise KnowledgeRequestConflict(
                        "knowledge correction source could not be prepared"
                    ) from exc
        if current is not None and not hmac.compare_digest(
            _digest(correction_source_payload(current)),
            content_sha256,
        ):
            raise KnowledgeRequestConflict(
                "knowledge correction source identity was reused"
            )
        return correction_source_ref(request_id), content_sha256

    def submit_request(
        self,
        tenant: str,
        actor: str,
        reference: ResearchAssetRef,
        *,
        request_type: str,
        reason: str,
        request_key: str,
        proposed_correction: str | None = None,
    ) -> dict:
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "request actor", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named user is required for a knowledge rights request")
        _reference_key(reference)
        kind = str(request_type or "")
        if kind not in _REQUEST_TYPES:
            raise ValueError("knowledge request_type is unsupported")
        exact_reason = _text(reason, "knowledge request reason", 2_000)
        key = _identifier(request_key, "request_key")
        correction = None
        if proposed_correction is not None:
            correction = _text(
                proposed_correction,
                "proposed correction",
                8_192,
                required=False,
            )
            if not correction:
                correction = None
        if kind == "correction" and correction is None:
            raise ValueError("a correction request requires the corrected information")
        material = {
            "schema": KNOWLEDGE_RIGHTS_REQUEST_SCHEMA,
            "tenant": canonical,
            "requested_by": principal,
            "request_key": key,
            "request_type": kind,
            "source_reference": asdict(reference),
            "reason": exact_reason,
            "proposed_correction": correction,
        }
        material_sha256 = _digest(material)
        record_id = self._request_id(canonical, principal, key)
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            current = self.registry.inspect(canonical, reference)
            impact = self.registry.derivative_impact(canonical, reference)
            existing = self.request_store.get(record_id)
            archived_at = None
            if existing is None:
                archived = self.archive_store.get(record_id)
                if archived is not None:
                    existing = self._archived_request(canonical, archived)
                    archived_at = float(archived["created_at"])
            if existing is not None:
                if existing.get("request_sha256") != material_sha256:
                    raise KnowledgeRequestConflict(
                        "knowledge request key was already used for different material"
                    )
                return self._fresh_request_projection(
                    canonical, existing, archived_at=archived_at,
                )
            if self.request_store.count(maximum=_MAX_REQUESTS) >= _MAX_REQUESTS:
                raise KnowledgeRequestCapacity(self._full_request_message(canonical))
            correction_source = None
            correction_sha256 = None
            if kind == "correction":
                assert correction is not None
                correction_source, correction_sha256 = self._prepare_correction_source(
                    tenant=canonical,
                    actor=principal,
                    request_id=record_id,
                    request_sha256=material_sha256,
                    reference=reference,
                    prior_content_sha256=str(current["manifest"]["content_sha256"]),
                    correction=correction,
                )
            record = {
                **material,
                "id": record_id,
                "request_sha256": material_sha256,
                "status": "submitted",
                "source_revision_at_request": current["revision"],
                "source_state_at_request": current["state"],
                "source_use_status": "unchanged_pending_review",
                "raw_record_status": "pending_source_review",
                "retention_review_status": "required",
                "retention_hold": None,
                "correction_source_ref": correction_source,
                "correction_content_sha256": correction_sha256,
                "replacement_reference": None,
                "replacement_status": (
                    "source_prepared" if kind == "correction" else None
                ),
                "decision": None,
                "decided_by": None,
                "decision_evidence_sha256": None,
                "derivatives": self._derivatives(impact, request_status="submitted"),
                "derivatives_at_request": self._derivatives(
                    impact,
                    request_status="submitted",
                ),
            }
            try:
                saved = self.request_store.create(
                    record,
                    actor=principal,
                    action="knowledge.rights_request.submit",
                    max_records=_MAX_REQUESTS,
                )
            except RecordConflict as exc:
                replay = self.request_store.get(record_id)
                if replay is not None and replay.get("request_sha256") == material_sha256:
                    return self._fresh_request_projection(canonical, replay)
                raise KnowledgeRequestConflict(
                    "knowledge request was created concurrently with different material"
                ) from exc
            except GovernedRecordCapacityError as exc:
                raise KnowledgeRequestCapacity(self._full_request_message(canonical)) from exc
            return self._fresh_request_projection(canonical, saved)

    @staticmethod
    def _feedback_projection(record: dict) -> dict:
        """Employee receipt: own submission/status, never derivative or hold details."""
        fields = ("id", "request_type", "status", "reason", "proposed_correction",
                  "created_at", "updated_at", "source_use_status", "raw_record_status",
                  "retention_review_status", "archived_at")
        return {"schema": "lightwork.knowledge-feedback.v1",
                **{field: record.get(field) for field in fields},
                "notice": "An independent administrator reviews source changes, dependencies and legal holds. Submitting grants no deletion or training rights."}

    def submit_feedback(self, tenant: str, actor: str, reference: ResearchAssetRef,
                        *, purpose: str, **kwargs) -> dict:
        canonical = canonical_tenant_id(tenant)
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            # Exact source/version must still be visible, not merely a guessed
            # registry identity. The review and apply paths retain admin gates.
            self.detail(canonical, actor, reference, purpose=purpose)
            existing_id = self._request_id(canonical, actor, kwargs["request_key"])
            if self.request_store.get(existing_id) is None:
                pending = sum(row.get("tenant") == canonical
                              and row.get("requested_by") == actor
                              and row.get("status") in {"submitted", "applying"}
                              for row in self.request_store.list(limit=_MAX_REQUESTS))
                if pending >= 100:
                    raise ValueError("Review pending feedback before submitting more requests")
            result = self.submit_request(canonical, actor, reference, **kwargs)
            return self._feedback_projection(result)

    def feedback_requests(self, tenant: str, actor: str, *, limit: int = 100,
                          request_id: str | None = None,
                          archived: bool = False) -> list[dict]:
        canonical = canonical_tenant_id(tenant)
        if not actor.startswith("user:"):
            raise PermissionError("A named user is required")
        with tenant_scope(tenant=canonical):
            archive_times: dict[str, float] = {}
            if request_id is not None:
                hot = self.request_store.get(request_id)
                cold = None if hot is not None else self.archive_store.get(request_id)
                rows = [hot] if hot is not None else (
                    [self._archived_request(canonical, cold)] if cold is not None else []
                )
                if cold is not None:
                    archive_times[request_id] = float(cold["created_at"])
            elif archived:
                rows = []
                for item in self.archive_store.list(limit=_MAX_REQUESTS):
                    if (item.get("tenant") == canonical
                            and self.request_store.get(str(item["id"])) is None):
                        rows.append(self._archived_request(canonical, item))
                        archive_times[str(item["id"])] = float(item["created_at"])
            else:
                rows = self.request_store.list(limit=_MAX_REQUESTS)
            rows = [row for row in rows if row.get("tenant") == canonical
                    and row.get("requested_by") == actor]
        rows.sort(key=lambda row: (row.get("created_at", 0), row.get("id", "")), reverse=True)
        return [self._feedback_projection({**row, "archived_at": archive_times.get(str(row["id"]))})
                for row in rows[:max(1, min(limit, 250))]]

    def get_request(self, tenant: str, request_id: str) -> dict:
        canonical = canonical_tenant_id(tenant)
        exact_id = _text(request_id, "knowledge request_id", 128)
        if not exact_id.startswith("knowledge-req-"):
            raise ValueError("knowledge request_id is malformed")
        with tenant_scope(tenant=canonical):
            record = self.request_store.get(exact_id)
            archived_at = None
            if record is None:
                archive = self.archive_store.get(exact_id)
                if archive is not None:
                    record = self._archived_request(canonical, archive)
                    archived_at = float(archive["created_at"])
        if record is None or record.get("tenant") != canonical:
            raise KnowledgeRequestNotFound("knowledge rights request was not found")
        return self._fresh_request_projection(
            canonical, record, archived_at=archived_at,
        )

    def list_requests(self, tenant: str, *, limit: int = 100,
                      archived: bool = False,
                      ready_to_archive: bool = False) -> list[dict]:
        canonical = canonical_tenant_id(tenant)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 250:
            raise ValueError("request limit must be between 1 and 250")
        if archived and ready_to_archive:
            raise ValueError("choose one knowledge request view")
        with tenant_scope(tenant=canonical):
            if archived:
                archives = [item for item in self.archive_store.list(limit=_MAX_REQUESTS)
                            if item.get("tenant") == canonical
                            and self.request_store.get(str(item["id"])) is None]
                rows = [self._archived_request(canonical, item) for item in archives]
                archive_times = {str(item["id"]): float(item["created_at"])
                                 for item in archives}
            else:
                rows = [row for row in self.request_store.list(limit=_MAX_REQUESTS)
                        if row.get("tenant") == canonical]
                if ready_to_archive:
                    rows = [row for row in rows if self._archive_ready(canonical, row)]
                archive_times = {}
        rows.sort(
            key=lambda row: (float(row.get("created_at", 0)), str(row.get("id", ""))),
            reverse=True,
        )
        return [self._fresh_request_projection(
            canonical, row, archived_at=archive_times.get(str(row["id"])),
        ) for row in rows[:limit]]

    def browse_requests(self, tenant: str, *, view: str = "active",
                        cursor: str = "", limit: int = 100,
                        actor: str | None = None) -> dict:
        """Hydrate one bounded forward window, never the rotating prefix twice.

        Positions are private persistence metadata. Dashboard callers must bind
        them to their current administrator, workspace and selected view.
        This is a current index walk, not a frozen or creation-time snapshot.
        """
        canonical = canonical_tenant_id(tenant)
        if (view not in {"active", "archive", "ready"}
                or not isinstance(cursor, str) or len(cursor) > 128
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 250):
            raise ValueError("knowledge request batch is malformed")
        if actor is not None and (not isinstance(actor, str) or not actor.startswith("user:")):
            raise PermissionError("A named user is required")
        if actor is not None and view == "ready":
            raise PermissionError("Administrator access is required for this view")
        with tenant_scope(tenant=canonical):
            store = self.archive_store if view == "archive" else self.request_store
            # One identity-only lookahead distinguishes an exact final window.
            identities = list(store.iter_record_ids(start_after=cursor, limit=limit + 1))
            forward = [(position, record_id) for position, record_id in identities
                       if not cursor or position > cursor]
            window = forward[:limit]
            more = len(forward) > limit
            items = []
            for _position, record_id in window:
                row = store.get(record_id)
                if row is None or row.get("tenant") != canonical:
                    continue
                archived_at = None
                if view == "archive":
                    # A partially completed archive move still has one live
                    # authority. Do not display its cold copy as a second item.
                    if self.request_store.get(record_id) is not None:
                        continue
                    archived_at = float(row["created_at"])
                    row = self._archived_request(canonical, row)
                if actor is not None and row.get("requested_by") != actor:
                    continue
                if view == "ready" and not self._archive_ready(canonical, row):
                    continue
                items.append(self._feedback_projection({**row, "archived_at": archived_at})
                             if actor is not None else self._fresh_request_projection(
                                 canonical, row, archived_at=archived_at))
            return {"items": items,
                    "next_cursor": window[-1][0] if more else None,
                    "scanned": len(window), "complete": not more}

    def place_retention_hold(
        self,
        tenant: str,
        actor: str,
        request_id: str,
        *,
        expected_revision: int,
        hold_id: str,
        basis: str,
        expires_at: float,
        evidence_sha256: str,
    ) -> dict:
        """Place one evidence-bound legal/preservation hold on a deletion request."""
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "retention hold actor", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named user is required for a retention hold")
        exact_hold = _identifier(hold_id, "retention hold_id")
        exact_basis = _text(basis, "retention hold basis", 2_000)
        expiry = _positive_time(expires_at, "retention hold expiry")
        assert expiry is not None
        if not isinstance(evidence_sha256, str) or not _SHA.fullmatch(evidence_sha256):
            raise ValueError("retention hold evidence must be a lowercase SHA-256")
        now = self.request_store.authoritative_time()
        if expiry <= now:
            raise ValueError("retention hold expiry must be in the future")
        with tenant_scope(tenant=canonical):
            current = self.request_store.get(request_id)
            if current is None or current.get("tenant") != canonical:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            if current.get("request_type") != "deletion":
                raise KnowledgeRequestConflict(
                    "retention holds apply only to source-deletion requests"
                )
            if int(current.get("revision", 0)) != expected_revision:
                raise KnowledgeRequestConflict("knowledge request changed before hold placement")
            existing = current.get("retention_hold")
            material = {
                "schema": KNOWLEDGE_RETENTION_HOLD_SCHEMA,
                "hold_id": exact_hold,
                "basis": exact_basis,
                "evidence_sha256": evidence_sha256,
                "placed_by": principal,
                "placed_at": now,
                "expires_at": expiry,
                "status": "active",
                "released_by": None,
                "released_at": None,
                "release_reason": None,
                "release_evidence_sha256": None,
            }
            if existing is not None:
                if existing == material:
                    return self._fresh_request_projection(canonical, current)
                raise KnowledgeRequestConflict("knowledge request already has a retention hold")
            if current.get("status") not in {"submitted", "approved"}:
                raise KnowledgeRequestConflict(
                    "knowledge request cannot receive a retention hold in this state"
                )

            def place(record: dict) -> None:
                if record.get("retention_hold") is not None:
                    raise KnowledgeRequestConflict(
                        "knowledge request already has a retention hold"
                    )
                record["retention_hold"] = material
                record["retention_review_status"] = "retention_hold_active"
                if record.get("status") == "approved":
                    record["raw_record_status"] = (
                        "retention_hold_active_external_preservation_unverified"
                    )

            saved = self.request_store.update(
                request_id,
                place,
                expected_revision=expected_revision,
                actor=principal,
                action="knowledge.rights_request.retention_hold.place",
            )
            if saved is None:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            return self._fresh_request_projection(canonical, saved)

    def release_retention_hold(
        self,
        tenant: str,
        actor: str,
        request_id: str,
        *,
        expected_revision: int,
        reason: str,
        evidence_sha256: str,
    ) -> dict:
        """Release the exact recorded hold while retaining its audit history."""
        canonical = canonical_tenant_id(tenant)
        principal = _text(actor, "retention release actor", 512)
        if not principal.startswith("user:"):
            raise ValueError("a named user is required to release a retention hold")
        exact_reason = _text(reason, "retention release reason", 2_000)
        if not isinstance(evidence_sha256, str) or not _SHA.fullmatch(evidence_sha256):
            raise ValueError("retention release evidence must be a lowercase SHA-256")
        now = self.request_store.authoritative_time()
        with tenant_scope(tenant=canonical):
            current = self.request_store.get(request_id)
            if current is None or current.get("tenant") != canonical:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            if int(current.get("revision", 0)) != expected_revision:
                raise KnowledgeRequestConflict("knowledge request changed before hold release")
            hold = current.get("retention_hold")
            if not isinstance(hold, Mapping):
                raise KnowledgeRequestConflict("knowledge request has no retention hold")
            projected_hold = self._retention_hold_projection(current, now=now)
            if projected_hold["status"] == "released":
                if (
                    projected_hold["released_by"] == principal
                    and projected_hold["release_reason"] == exact_reason
                    and projected_hold["release_evidence_sha256"] == evidence_sha256
                ):
                    return self._fresh_request_projection(canonical, current)
                raise KnowledgeRequestConflict("retention hold was already released")

            def release(record: dict) -> None:
                active = record.get("retention_hold")
                if not isinstance(active, dict) or active.get("status") != "active":
                    raise KnowledgeRequestConflict("retention hold is not active")
                active.update(
                    status="released",
                    released_by=principal,
                    released_at=now,
                    release_reason=exact_reason,
                    release_evidence_sha256=evidence_sha256,
                )
                record["retention_review_status"] = "retention_hold_released"
                if record.get("status") == "approved":
                    record["raw_record_status"] = (
                        "external_source_deletion_unverified_after_hold_release"
                    )

            saved = self.request_store.update(
                request_id,
                release,
                expected_revision=expected_revision,
                actor=principal,
                action="knowledge.rights_request.retention_hold.release",
            )
            if saved is None:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            return self._fresh_request_projection(canonical, saved)

    def _ensure_correction_replacement(  # noqa: C901 - explicit recoverable lifecycle
        self, canonical: str, record: dict,
    ) -> dict:
        """Create and approve the exact corrected registry version, idempotently."""
        if record.get("request_type") != "correction":
            return record
        reviewer = str(record.get("decided_by") or "")
        requester = str(record.get("requested_by") or "")
        if not reviewer or text_equals(reviewer, requester):
            raise KnowledgeRequestConflict(
                "correction approval requires a different named reviewer"
            )
        old_reference = ResearchAssetRef(**dict(record["source_reference"]))
        old = self.registry.inspect(canonical, old_reference)
        manifest = old.get("manifest")
        if not isinstance(manifest, Mapping):
            raise KnowledgeRequestConflict("prior source manifest is unavailable")
        source_ref = str(record.get("correction_source_ref") or "")
        content_sha256 = str(record.get("correction_content_sha256") or "")
        from .knowledge_content_projection import inspect_existing_source

        inspected = inspect_existing_source(
            canonical,
            source_ref,
            correction_store=self.correction_store,
        )
        if not hmac.compare_digest(
            str(inspected.get("content_sha256") or ""), content_sha256
        ):
            raise KnowledgeRequestConflict(
                "corrected source no longer matches its prepared commitment"
            )
        version = "corrected-" + str(record["id"]).removeprefix("knowledge-req-")[:20]
        parents = [dict(item) for item in manifest.get("parent_datasets", ())]
        provenance = "derived" if parents else "source"
        replacement_manifest = {
            "kind": "dataset",
            "asset_id": old_reference.asset_id,
            "version": version,
            "source_ref": source_ref,
            "content_sha256": content_sha256,
            "license_id": str(manifest["license_id"]),
            "license_evidence_sha256": str(manifest["license_evidence_sha256"]),
            "allowed_purposes": list(manifest["allowed_purposes"]),
            "usage_constraints": list(manifest["usage_constraints"]),
            "data_use_action": str(manifest["data_use_action"]),
            "data_use_decision_id": str(manifest["data_use_decision_id"]),
            "data_use_decision_sha256": str(manifest["data_use_decision_sha256"]),
            "consent_record_id": manifest.get("consent_record_id"),
            "consent_evidence_sha256": manifest.get("consent_evidence_sha256"),
            "parent_datasets": parents,
            "provenance_kind": provenance,
            "synthetic_provenance": None,
        }
        expected_replacement = ResearchAssetRef(
            "dataset",
            old_reference.asset_id,
            version,
            _digest(replacement_manifest),
        )
        recorded = record.get("replacement_reference")
        if recorded is not None and dict(recorded) != asdict(expected_replacement):
            raise KnowledgeRequestConflict(
                "knowledge request is bound to another corrected replacement"
            )
        replacement = expected_replacement
        try:
            replacement_state = self.registry.inspect(canonical, replacement)
        except ResearchRegistryNotFound:
            replacement_state = None
        if replacement_state is None:
            try:
                replacement = self.registry.register_dataset(
                    canonical,
                    requester,
                    dataset_id=old_reference.asset_id,
                    version=version,
                    source_ref=source_ref,
                    content_sha256=content_sha256,
                    license_id=replacement_manifest["license_id"],
                    license_evidence_sha256=replacement_manifest[
                        "license_evidence_sha256"
                    ],
                    allowed_purposes=tuple(replacement_manifest["allowed_purposes"]),
                    usage_constraints=tuple(replacement_manifest["usage_constraints"]),
                    data_use_action=replacement_manifest["data_use_action"],
                    data_use_decision_id=replacement_manifest["data_use_decision_id"],
                    data_use_decision_sha256=replacement_manifest[
                        "data_use_decision_sha256"
                    ],
                    consent_record_id=manifest.get("consent_record_id"),
                    consent_evidence_sha256=manifest.get("consent_evidence_sha256"),
                    parent_datasets=tuple(
                        ResearchAssetRef(**dict(item))
                        for item in parents
                    ),
                    provenance_kind=provenance,
                )
            except (ResearchRegistryConflict, ResearchRegistryDenied) as exc:
                raise KnowledgeRequestConflict(
                    "corrected replacement could not be registered"
                ) from exc
            if replacement != expected_replacement:
                raise KnowledgeRequestConflict(
                    "corrected replacement manifest was not deterministic"
                )
            replacement_state = self.registry.inspect(canonical, replacement)
        if replacement_state.get("manifest") != replacement_manifest:
            raise KnowledgeRequestConflict(
                "corrected replacement identity already has different material"
            )
        if recorded is None or record.get("replacement_status") == "source_prepared":

            def bind_draft(current: dict) -> None:
                if current.get("status") != "applying":
                    raise KnowledgeRequestConflict(
                        "knowledge request is not applying its correction"
                    )
                current.update(
                    replacement_reference=asdict(replacement),
                    replacement_status="draft_registered",
                )

            updated = self.request_store.update(
                record["id"],
                bind_draft,
                expected_revision=int(record["revision"]),
                actor=reviewer,
                action="knowledge.rights_request.correction.register",
            )
            if updated is None:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            record = updated

        if replacement_state.get("state") == "draft":
            try:
                self.registry.approve(
                    canonical,
                    reviewer,
                    replacement,
                    expected_revision=int(replacement_state["revision"]),
                )
            except (ResearchRegistryConflict, ResearchRegistryDenied) as exc:
                raise KnowledgeRequestConflict(
                    "corrected replacement could not be approved"
                ) from exc
            replacement_state = self.registry.inspect(canonical, replacement)
        approval = replacement_state.get("approval")
        if (
            replacement_state.get("state") != "approved"
            or not isinstance(approval, Mapping)
            or approval.get("approved_by") != reviewer
        ):
            raise KnowledgeRequestConflict(
                "corrected replacement approval is uncertain"
            )
        if record.get("replacement_status") != "approved":

            def bind_approval(current: dict) -> None:
                if current.get("status") != "applying":
                    raise KnowledgeRequestConflict(
                        "knowledge request is not applying its correction"
                    )
                if current.get("replacement_reference") != asdict(replacement):
                    raise KnowledgeRequestConflict(
                        "corrected replacement binding changed before approval"
                    )
                current["replacement_status"] = "approved"

            updated = self.request_store.update(
                record["id"],
                bind_approval,
                expected_revision=int(record["revision"]),
                actor=reviewer,
                action="knowledge.rights_request.correction.approve",
            )
            if updated is None:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            record = updated
        return record

    def _finish_approved_request(self, canonical: str, record: dict) -> dict:
        reference = ResearchAssetRef(**record["source_reference"])
        impact = self.registry.derivative_impact(canonical, reference)
        request_type = str(record.get("request_type"))
        hold = record.get("retention_hold")
        active_hold = False
        if hold is not None:
            hold_projection = self._retention_hold_projection(
                record,
                now=self.request_store.authoritative_time(),
            )
            active_hold = hold_projection["effective_status"] == "active"
        if request_type == "correction" and record.get("replacement_status") != "approved":
            raise KnowledgeRequestConflict(
                "corrected replacement is not approved"
            )

        def finish(current: dict) -> None:
            if current.get("status") != "applying":
                raise KnowledgeRequestConflict("knowledge request is not awaiting completion")
            current.update(
                status="approved",
                source_use_status=(
                    "prior_version_revoked_replacement_approved"
                    if request_type == "correction"
                    else "revoked_for_new_use"
                ),
                raw_record_status=(
                    "retention_hold_active_external_preservation_unverified"
                    if request_type == "deletion" and active_hold
                    else "external_source_deletion_unverified"
                    if request_type == "deletion"
                    else "prior_source_version_retired"
                    if request_type == "correction"
                    else "source_version_retired"
                ),
                retention_review_status=(
                    "retention_hold_active"
                    if request_type == "deletion" and active_hold
                    else "external_retention_and_deletion_unverified"
                    if request_type == "deletion"
                    else "raw_source_retained_use_excluded"
                    if request_type == "exclusion"
                    else "corrected_replacement_approved_raw_prior_retained"
                ),
                derivatives=self._derivatives(impact, request_status="approved"),
            )

        saved = self.request_store.update(
            record["id"],
            finish,
            expected_revision=int(record["revision"]),
            actor=str(record["decided_by"]),
            action="knowledge.rights_request.complete",
        )
        if saved is None:
            raise KnowledgeRequestNotFound("knowledge rights request was not found")
        self._evict(canonical, reference)
        return self._fresh_request_projection(canonical, saved)

    def decide_request(  # noqa: C901 - explicit recoverable review state machine
        self,
        tenant: str,
        actor: str,
        request_id: str,
        *,
        expected_revision: int,
        decision: str,
        evidence_sha256: str,
    ) -> dict:
        """Review a request and retire the exact registry version when approved.

        The durable ``applying`` state makes the registry-revocation boundary
        recoverable.  If a process stops after revocation, an exact retry first
        verifies the matching revocation evidence and then completes the request.
        """

        canonical = canonical_tenant_id(tenant)
        reviewer = _text(actor, "request reviewer", 512)
        if not reviewer.startswith("user:"):
            raise ValueError("a named reviewer is required")
        exact_decision = str(decision or "")
        if exact_decision not in _DECISIONS:
            raise ValueError("knowledge request decision is unsupported")
        if not isinstance(evidence_sha256, str) or not _SHA.fullmatch(evidence_sha256):
            raise ValueError("decision evidence must be a lowercase SHA-256 digest")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")
        with tenant_scope(tenant=canonical), self.registry.effect_fence():
            current = self.request_store.get(request_id)
            if current is None or current.get("tenant") != canonical:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            status = current.get("status")
            if (
                exact_decision == "approve"
                and current.get("request_type") == "correction"
                and status not in {"approved", "denied"}
                and text_equals(str(current.get("requested_by") or ""), reviewer)
            ):
                raise KnowledgeRequestConflict(
                    "correction approval requires a different named reviewer"
                )
            if status in {"approved", "denied"}:
                if (
                    current.get("decision") == exact_decision
                    and current.get("decided_by") == reviewer
                    and current.get("decision_evidence_sha256") == evidence_sha256
                ):
                    return self._fresh_request_projection(canonical, current)
                raise KnowledgeRequestConflict("knowledge request already has a final decision")
            reference = ResearchAssetRef(**current["source_reference"])
            reason_code = "knowledge_" + str(current["request_type"])
            if status == "applying":
                if (
                    current.get("decision") != exact_decision
                    or current.get("decided_by") != reviewer
                    or current.get("decision_evidence_sha256") != evidence_sha256
                    or exact_decision != "approve"
                    or int(current["revision"]) != expected_revision
                ):
                    raise KnowledgeRequestConflict(
                        "knowledge request recovery must exactly match the applying decision"
                    )
                current = self._ensure_correction_replacement(canonical, current)
                source = self.registry.inspect(canonical, reference)
                revocation = source.get("revocation")
                if source.get("state") == "approved" and source.get("revision") == current.get(
                    "source_revision_at_request"
                ):
                    try:
                        self.registry.revoke(
                            canonical,
                            reviewer,
                            reference,
                            expected_revision=int(current["source_revision_at_request"]),
                            reason_code=reason_code,
                            evidence_sha256=evidence_sha256,
                        )
                    except ResearchRegistryConflict as exc:
                        raise KnowledgeRequestConflict(
                            "source version changed during retirement; inspect the exact version"
                        ) from exc
                    self._evict(canonical, reference)
                elif not (
                    source.get("state") == "revoked"
                    and isinstance(revocation, Mapping)
                    and revocation.get("revoked_by") == reviewer
                    and revocation.get("reason_code") == reason_code
                    and hmac.compare_digest(
                        str(revocation.get("evidence_sha256") or ""), evidence_sha256
                    )
                ):
                    raise KnowledgeRequestConflict(
                        "source retirement outcome is uncertain; inspect the exact registry version"
                    )
                return self._finish_approved_request(canonical, current)
            if status != "submitted":
                raise KnowledgeRequestConflict("knowledge request cannot be reviewed in this state")
            if int(current["revision"]) != expected_revision:
                raise KnowledgeRequestConflict("knowledge request changed before review")
            source = self.registry.inspect(canonical, reference)
            if source.get("state") != "approved" or source.get("revision") != current.get(
                "source_revision_at_request"
            ):
                raise KnowledgeRequestConflict(
                    "source version changed after the request; submit a new exact review"
                )
            if exact_decision == "deny":

                def deny(record: dict) -> None:
                    if record.get("status") != "submitted":
                        raise KnowledgeRequestConflict("knowledge request changed before review")
                    record.update(
                        status="denied",
                        decision="deny",
                        decided_by=reviewer,
                        decision_evidence_sha256=evidence_sha256,
                        source_use_status="unchanged_after_denial",
                        raw_record_status="request_denied",
                        retention_review_status="not_applied_after_denial",
                    )

                saved = self.request_store.update(
                    request_id,
                    deny,
                    expected_revision=expected_revision,
                    actor=reviewer,
                    action="knowledge.rights_request.deny",
                )
                if saved is None:
                    raise KnowledgeRequestNotFound("knowledge rights request was not found")
                return self._fresh_request_projection(canonical, saved)

            def begin(record: dict) -> None:
                if record.get("status") != "submitted":
                    raise KnowledgeRequestConflict("knowledge request changed before review")
                record.update(
                    status="applying",
                    decision="approve",
                    decided_by=reviewer,
                    decision_evidence_sha256=evidence_sha256,
                    source_use_status="retirement_in_progress",
                    raw_record_status="source_review_approved",
                )

            applying = self.request_store.update(
                request_id,
                begin,
                expected_revision=expected_revision,
                actor=reviewer,
                action="knowledge.rights_request.apply",
            )
            if applying is None:
                raise KnowledgeRequestNotFound("knowledge rights request was not found")
            applying = self._ensure_correction_replacement(canonical, applying)
            try:
                self.registry.revoke(
                    canonical,
                    reviewer,
                    reference,
                    expected_revision=int(current["source_revision_at_request"]),
                    reason_code=reason_code,
                    evidence_sha256=evidence_sha256,
                )
            except ResearchRegistryConflict as exc:
                raise KnowledgeRequestConflict(
                    "source version changed during retirement; inspect the exact version"
                ) from exc
            self._evict(canonical, reference)
            if self.after_source_revoked is not None:
                self.after_source_revoked(dict(applying))
            return self._finish_approved_request(canonical, applying)


__all__ = [
    "KNOWLEDGE_ACTOR_AUTHORITY_SCHEMA",
    "KNOWLEDGE_DETAIL_SCHEMA",
    "KNOWLEDGE_DOCUMENT_SCHEMA",
    "KNOWLEDGE_EXPORT_SCHEMA",
    "KNOWLEDGE_JOB_MATERIALIZATION_SCHEMA",
    "KNOWLEDGE_RETENTION_HOLD_SCHEMA",
    "KNOWLEDGE_RIGHTS_REQUEST_SCHEMA",
    "KNOWLEDGE_REQUEST_ARCHIVE_SCHEMA",
    "KNOWLEDGE_SEARCH_SCHEMA",
    "KnowledgeAccessDenied",
    "KnowledgeAccessError",
    "KnowledgeAccessService",
    "KnowledgeActorAuthority",
    "KnowledgeArchiveUnavailable",
    "KnowledgeDocument",
    "KnowledgeRequestConflict",
    "KnowledgeRequestCapacity",
    "KnowledgeRequestNotFound",
    "TRAINING_PERMISSION_NOTICE",
    "WEIGHT_INFLUENCE_NOTICE",
]
