"""Exact, checksum-bound projections from existing Lightwork knowledge stores.

The APP10 access layer does not search an ungoverned store by label.  A
registry ``source_ref`` names one immutable record in a supported store, this
adapter reads that exact record in the active tenant, and a canonical
projection must match the registry's content commitment before any text is
returned.

Supported references:

``catalog:evidence-graph/<node-id>``
    One current, approved evidence-graph node.

``catalog:fleet-memory/<immutable-json-file>``
    One Shield-screened immutable fleet inbox record.

``catalog:vector-knowledge/<collection>/<document-sha256>``
    One complete position-stamped document. Legacy or ambiguous chunks fail closed.

``catalog:work-discovery/<owner-base64url>/<device>/candidates``
    Content-free candidates under the exact owner's live Ekko consent barriers.

``catalog:knowledge-correction/<request-id>``
    One immutable corrected source prepared by the rights-request workflow.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from .constant_time import text_equals
from .governed_records import GovernedRecordStore
from .knowledge_access import KnowledgeActorAuthority, KnowledgeDocument
from .paths import canonical_tenant_id, tenant_scope
from .research_registry import DatasetAdmission, ResearchAssetRef

_NODE_REF = re.compile(r"catalog:evidence-graph/([A-Za-z0-9][A-Za-z0-9_.:-]{0,127})\Z")
_FLEET_REF = re.compile(
    r"catalog:fleet-memory/([A-Za-z0-9][A-Za-z0-9_.-]{0,239}\.json)\Z"
)
_VECTOR_REF = re.compile(
    r"catalog:vector-knowledge/([A-Za-z0-9][A-Za-z0-9_.:-]{0,127})/([0-9a-f]{64})\Z"
)
_WORK_REF = re.compile(
    r"catalog:work-discovery/([A-Za-z0-9_-]{2,684})/"
    r"([A-Za-z0-9][A-Za-z0-9_.:-]{0,63})/candidates\Z"
)
_CORRECTION_REF = re.compile(r"catalog:knowledge-correction/(knowledge-req-[0-9a-f]{40})\Z")
_REMOTE_REF = re.compile(r"catalog:remote-knowledge/(KNS-[a-f0-9]{32})/([a-f0-9]{32})\Z")
_MAX_SOURCE_BYTES = 256 * 1024
# A saved remote source's record carries every chunk of its text, and the chunker
# overlaps neighbouring chunks: measured with the default chunker, its canonical
# JSON is about 1.43 times its text bytes. The bound is twice the text, plus
# room for each item's manifest and extraction map (up to 256 regions).
_REMOTE_TEXT_FACTOR = 2
_REMOTE_ITEM_BYTES = 64 * 1024
_PROJECTION_SCHEMA = "lightwork.knowledge-source-projection.v1"
_CORRECTION_SCHEMA = "lightwork.knowledge-correction-source.v1"


class KnowledgeProjectionUnavailable(RuntimeError):
    """An exact source cannot be safely projected from its owning store."""


def _canonical(value: object, *, limit: int = _MAX_SOURCE_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KnowledgeProjectionUnavailable("source record is not finite JSON") from exc
    if len(encoded) > limit:
        raise KnowledgeProjectionUnavailable("source record exceeds its projection boundary")
    return encoded


def _remote_source_limit(record: Mapping[str, object]) -> int:
    """The canonical bound for a retained remote source, from the text it holds.

    exact_source_snapshot has already held that text to the source's current
    max_text_kib, so the bound scales with the text the source actually holds.
    """
    text_bytes = int(record["text_bytes"])
    items = len(record["items"])
    return max(_MAX_SOURCE_BYTES, _REMOTE_TEXT_FACTOR * text_bytes + _REMOTE_ITEM_BYTES * items)


def _payload(store: str, source_id: str, record: Mapping[str, object]) -> dict:
    return {
        "schema": _PROJECTION_SCHEMA,
        "store": store,
        "source_id": source_id,
        "record": dict(record),
    }


def _commitment(payload: Mapping[str, object], *, limit: int = _MAX_SOURCE_BYTES) -> str:
    return hashlib.sha256(_canonical(payload, limit=limit)).hexdigest()


def _bounded_summary(value: object) -> str:
    summary = str(value or "").strip()
    encoded = summary.encode("utf-8")
    if len(encoded) <= 8_192:
        return summary
    return encoded[:8_192].decode("utf-8", errors="ignore").rstrip()


def _bounded_title(value: object) -> str:
    title = str(value or "").strip()
    encoded = title.encode("utf-8")
    if len(encoded) <= 240:
        return title
    return encoded[:240].decode("utf-8", errors="ignore").rstrip()


def _stable_evidence_record(record: Mapping[str, object]) -> dict:
    # ``freshness`` and inherited-authority validation are live projections
    # added by evidence_graph.get().  Registry freshness is independently
    # rechecked; only persisted node material belongs in this commitment.
    return {
        str(key): value
        for key, value in record.items()
        if key not in {"authority_validation", "freshness"}
    }


def _evidence_projection(node_id: str) -> tuple[dict, str, str, float | None, float | None]:
    from . import evidence_graph

    if not evidence_graph.enabled():
        raise KnowledgeProjectionUnavailable("evidence graph is disabled or unavailable")
    record = evidence_graph.get(node_id)
    if not isinstance(record, Mapping):
        raise KnowledgeProjectionUnavailable("evidence graph source was not found")
    if record.get("status") != "approved" or record.get("freshness") != "current":
        raise KnowledgeProjectionUnavailable("evidence graph source is not current and approved")
    stable = _stable_evidence_record(record)
    title = str(
        record.get("title")
        or record.get("evidence_type")
        or record.get("kind")
        or node_id
    )
    summary = _bounded_summary(record.get("summary"))
    review = record.get("review")
    verified_at = (
        float(review["reviewed_at"])
        if isinstance(review, Mapping) and isinstance(review.get("reviewed_at"), int | float)
        else None
    )
    observed = record.get("observed_at", record.get("created_at"))
    observed_at = float(observed) if isinstance(observed, int | float) else None
    return _payload("evidence_graph", node_id, stable), title, summary, observed_at, verified_at


def _fleet_projection(filename: str) -> tuple[dict, str, str, float | None, None]:
    from . import fleet_memory
    from .file_lock import atomic_read_text, ensure_private_file

    if not fleet_memory.enabled():
        raise KnowledgeProjectionUnavailable("fleet memory is disabled or unavailable")
    root = fleet_memory.inbox_dir().resolve()
    path = (root / filename).resolve()
    if path.parent != root or not path.is_file():
        raise KnowledgeProjectionUnavailable("fleet memory source was not found")
    try:
        if path.stat().st_size > _MAX_SOURCE_BYTES:
            raise KnowledgeProjectionUnavailable("fleet memory source exceeds its boundary")
        ensure_private_file(path)
        raw = atomic_read_text(path)
        if len(raw.encode("utf-8")) > _MAX_SOURCE_BYTES:
            raise KnowledgeProjectionUnavailable("fleet memory source exceeds its boundary")
        record = json.loads(raw)
    except KnowledgeProjectionUnavailable:
        raise
    except (OSError, ValueError) as exc:
        raise KnowledgeProjectionUnavailable("fleet memory source is unreadable") from exc
    if not isinstance(record, Mapping):
        raise KnowledgeProjectionUnavailable("fleet memory source is malformed")
    title = str(record.get("task_brief_text") or filename)
    summary = _bounded_summary(
        "\n\n".join(
            value
            for value in (
                str(record.get("task_brief_text") or "").strip(),
                str(record.get("verifier_critique") or "").strip(),
            )
            if value
        )
    )
    observed = record.get("ts")
    observed_at = float(observed) if isinstance(observed, int | float) else None
    return _payload("fleet_memory", filename, record), title, summary, observed_at, None


def vector_knowledge_source_ref(collection: str, doc_sha256: str) -> str:
    """Build the only supported exact reference to an ingested vector document."""
    candidate = f"catalog:vector-knowledge/{collection}/{doc_sha256}"
    if not _VECTOR_REF.fullmatch(candidate):
        raise ValueError("vector knowledge source identity is malformed")
    return candidate


def _encode_owner(owner: str) -> str:
    raw = str(owner or "").encode("utf-8")
    if not raw or len(raw) > 512:
        raise ValueError("work-discovery owner is malformed")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_owner(value: str) -> str:
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
        owner = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise KnowledgeProjectionUnavailable(
            "work-discovery owner binding is malformed"
        ) from exc
    if _encode_owner(owner) != value:
        raise KnowledgeProjectionUnavailable(
            "work-discovery owner binding is not canonical"
        )
    return owner


def work_discovery_source_ref(owner: str, device_id: str) -> str:
    """Build an owner- and device-bound Ekko candidate reference."""
    candidate = f"catalog:work-discovery/{_encode_owner(owner)}/{device_id}/candidates"
    if not _WORK_REF.fullmatch(candidate):
        raise ValueError("work-discovery source identity is malformed")
    return candidate


def correction_source_store() -> GovernedRecordStore:
    return GovernedRecordStore(
        "knowledge-correction-sources",
        "knowledge-fix",
        "knowledge-correction-source",
    )


def correction_source_ref(request_id: str) -> str:
    candidate = f"catalog:knowledge-correction/{request_id}"
    if not _CORRECTION_REF.fullmatch(candidate):
        raise ValueError("knowledge correction source identity is malformed")
    return candidate


def correction_source_record_id(request_id: str) -> str:
    correction_source_ref(request_id)
    return "knowledge-fix-" + request_id.removeprefix("knowledge-req-")


def correction_source_payload(record: Mapping[str, object]) -> dict:
    expected = {
        "schema",
        "id",
        "tenant",
        "request_id",
        "requested_by",
        "prior_reference",
        "prior_content_sha256",
        "correction",
        "request_sha256",
    }
    if set(record) & expected != expected or record.get("schema") != _CORRECTION_SCHEMA:
        raise KnowledgeProjectionUnavailable("knowledge correction source is malformed")
    stable = {key: record[key] for key in sorted(expected)}
    return _payload("knowledge_correction", str(record["request_id"]), stable)


def _vector_projection(
    collection: str,
    digest: str,
    knowledge_base: Any,
) -> tuple[dict, str, str, float | None, None]:
    if knowledge_base is None or not callable(getattr(knowledge_base, "exact_document", None)):
        raise KnowledgeProjectionUnavailable("vector knowledge store is unavailable")
    try:
        record = knowledge_base.exact_document(collection, digest)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise KnowledgeProjectionUnavailable(
            "vector knowledge document cannot be read exactly"
        ) from exc
    if not isinstance(record, Mapping):
        raise KnowledgeProjectionUnavailable("vector knowledge document is malformed")
    chunks = record.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise KnowledgeProjectionUnavailable("vector knowledge document is incomplete")
    reconstructed = record.get("text")
    if not isinstance(reconstructed, str) or not reconstructed:
        raise KnowledgeProjectionUnavailable("vector knowledge document is incomplete")
    if not hmac.compare_digest(
        hashlib.sha256(reconstructed.encode("utf-8")).hexdigest(),
        digest,
    ):
        raise KnowledgeProjectionUnavailable(
            "vector knowledge document does not match its source identity"
        )
    summary = _bounded_summary(reconstructed)
    committed_record = dict(record)
    # The verified text is deterministically reconstructed from the committed
    # chunks and offsets. Do not duplicate it in the bounded projection payload.
    committed_record.pop("text", None)
    # Vector-space migration does not change the admitted source document.
    # Keep operational index identity outside its immutable content commitment.
    if isinstance(committed_record.get("metadata"), Mapping):
        committed_record["metadata"] = {
            key: value for key, value in committed_record["metadata"].items()
            if key not in {"embedding_identity", "embedding_fingerprint"}
        }
    title = str(record.get("source") or f"{collection} knowledge document")
    observed = record.get("ingested_at")
    observed_at = float(observed) if isinstance(observed, int | float) else None
    return (
        _payload("vector_knowledge", f"{collection}/{digest}", committed_record),
        title,
        summary,
        observed_at,
        None,
    )


def _work_projection(
    tenant: str,
    owner: str,
    device_id: str,
    factory: Callable[[str, str, str], Any] | None,
) -> tuple[dict, str, str, float | None, None]:
    if factory is None:
        from .work_discovery_store import WorkDiscoveryStore

        store = WorkDiscoveryStore(owner, device_id, tenant=tenant)
    else:
        store = factory(tenant, owner, device_id)
    projector = getattr(store, "governed_candidate_projection", None)
    if not callable(projector):
        raise KnowledgeProjectionUnavailable("work-discovery projector is unavailable")
    try:
        record = projector()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise KnowledgeProjectionUnavailable(
            "work-discovery authority or content is unavailable"
        ) from exc
    if not isinstance(record, Mapping):
        raise KnowledgeProjectionUnavailable("work-discovery projection is malformed")
    candidates = record.get("candidates")
    consent = record.get("consent")
    if not isinstance(candidates, list) or not isinstance(consent, Mapping):
        raise KnowledgeProjectionUnavailable("work-discovery projection is incomplete")
    summary = _bounded_summary(
        "\n".join(
            f"{item.get('title')} ({item.get('occurrences')} occurrences)"
            for item in candidates
            if isinstance(item, Mapping)
        )
    )
    observed = consent.get("enrolled_at")
    observed_at = float(observed) if isinstance(observed, int | float) else None
    source_id = f"{_encode_owner(owner)}/{device_id}/candidates"
    return (
        _payload("work_discovery", source_id, record),
        "Ekko work opportunities",
        summary,
        observed_at,
        None,
    )


def _correction_projection(
    request_id: str,
    store: GovernedRecordStore | None,
) -> tuple[dict, str, str, float | None, float | None]:
    source_store = store or correction_source_store()
    record = source_store.get(correction_source_record_id(request_id))
    if not isinstance(record, Mapping):
        raise KnowledgeProjectionUnavailable("knowledge correction source was not found")
    payload = correction_source_payload(record)
    created = record.get("created_at")
    updated = record.get("updated_at")
    return (
        payload,
        f"Corrected version of {dict(record['prior_reference'])['asset_id']}",
        _bounded_summary(record.get("correction")),
        float(created) if isinstance(created, int | float) else None,
        float(updated) if isinstance(updated, int | float) else None,
    )


def inspect_existing_source(
    tenant: str,
    source_ref: str,
    *,
    knowledge_base: Any | None = None,
    knowledge_base_factory: Callable[[str], Any | None] | None = None,
    work_discovery_factory: Callable[[str, str, str], Any] | None = None,
    correction_store: GovernedRecordStore | None = None,
    include_retrieval_chunks: bool = False,
    remote_authority: KnowledgeActorAuthority | None = None,
) -> dict:
    """Return the exact content commitment and safe preview for registration."""

    canonical = canonical_tenant_id(tenant)
    if not isinstance(source_ref, str):
        raise KnowledgeProjectionUnavailable("source reference must be text")
    with tenant_scope(tenant=canonical):
        remote = _REMOTE_REF.fullmatch(source_ref)
        if remote:
            from .knowledge_sources import exact_source_snapshot
            opened = None
            base = knowledge_base
            if base is None:
                if knowledge_base_factory is not None:
                    base = knowledge_base_factory(canonical)
                else:
                    from .knowledge_admin import open_knowledge_base
                    base = open_knowledge_base(tenant=canonical, require_existing=True)
                opened = base
            if base is None:
                raise KnowledgeProjectionUnavailable("remote Knowledge content is unavailable")
            try:
                record = exact_source_snapshot(canonical, remote[1], remote[2], knowledge_base=base, authority=remote_authority)
            except Exception as exc:
                raise KnowledgeProjectionUnavailable("the exact remote source or its current account rights are unavailable") from exc
            finally:
                if opened is not None:
                    opened.close()
            # Only the items this authority may see are projected; the commitment above covers all of them.
            visible = record["visible_items"]
            summary = _bounded_summary("\n\n".join(chunk["text"] for item in visible for chunk in item["document"]["chunks"]))
            # The commitment covers the retained snapshot only; the per-reader view is not part of it.
            committed_record = {key: value for key, value in record.items() if key not in {"visible_items", "withheld_for_permissions"}}
            payload = _payload("remote_knowledge", f"{remote[1]}/{remote[2]}", committed_record)
            inspected = {"source_ref": source_ref, "content_sha256": _commitment(payload, limit=_remote_source_limit(committed_record)),
                         "title": _bounded_title(record["name"]),
                         "summary": summary, "claim_state": "inferred", "observed_at": record["observed_at"], "verified_at": None,
                         "projection_schema": _PROJECTION_SCHEMA, "summary_truncated": len(summary.encode()) < record["text_bytes"],
                         "permissions_withheld": record["withheld_for_permissions"]}
            if include_retrieval_chunks:
                inspected["retrieval_chunks"] = tuple(chunk["text"] for item in visible for chunk in item["document"]["chunks"])
            inspected["permissions_withheld"] = record["withheld_for_permissions"]
            return inspected
        match = _NODE_REF.fullmatch(source_ref)
        claim_state = "verified"
        if match:
            payload, title, summary, observed_at, verified_at = _evidence_projection(match[1])
        else:
            match = _FLEET_REF.fullmatch(source_ref)
            if match:
                payload, title, summary, observed_at, verified_at = _fleet_projection(match[1])
                claim_state = "inferred"
            else:
                match = _VECTOR_REF.fullmatch(source_ref)
                if match:
                    opened = None
                    base = knowledge_base
                    if base is None:
                        if knowledge_base_factory is not None:
                            base = knowledge_base_factory(canonical)
                        else:
                            from .knowledge_admin import open_knowledge_base

                            base = open_knowledge_base(
                                tenant=canonical,
                                require_existing=True,
                            )
                        opened = base
                    try:
                        payload, title, summary, observed_at, verified_at = (
                            _vector_projection(match[1], match[2], base)
                        )
                    finally:
                        if opened is not None:
                            closer = getattr(opened, "close", None)
                            if callable(closer):
                                closer()
                    claim_state = "inferred"
                else:
                    match = _WORK_REF.fullmatch(source_ref)
                    if match:
                        owner = _decode_owner(match[1])
                        payload, title, summary, observed_at, verified_at = (
                            _work_projection(
                                canonical,
                                owner,
                                match[2],
                                work_discovery_factory,
                            )
                        )
                        claim_state = "inferred"
                    else:
                        match = _CORRECTION_REF.fullmatch(source_ref)
                        if not match:
                            raise KnowledgeProjectionUnavailable(
                                "source reference has no installed exact content projector"
                            )
                        payload, title, summary, observed_at, verified_at = (
                            _correction_projection(match[1], correction_store)
                        )
                        claim_state = "verified"
    inspected = {
        "source_ref": source_ref,
        "content_sha256": _commitment(payload),
        "title": _bounded_title(title),
        "summary": summary,
        "claim_state": claim_state,
        "observed_at": observed_at,
        "verified_at": verified_at,
        "projection_schema": _PROJECTION_SCHEMA,
    }
    chunks, truncated = _retrieval_chunks(payload, summary)
    inspected["summary_truncated"] = truncated
    if include_retrieval_chunks:
        inspected["retrieval_chunks"] = chunks
    return inspected


def _retrieval_chunks(payload: Mapping, summary: str) -> tuple[tuple[str, ...], bool]:
    """Return bounded source text from the SAME checksum-verified snapshot."""
    record = payload["record"]
    store = payload["store"]
    if store == "vector_knowledge":
        return (tuple(chunk["text"] for chunk in record["chunks"]),
                record["document_length"] > len(summary))
    if store == "evidence_graph":
        text = str(record.get("summary") or "")
    elif store == "fleet_memory":
        text = "\n\n".join(str(record.get(key) or "").strip()
                           for key in ("task_brief_text", "verifier_critique"))
    elif store == "knowledge_correction":
        text = str(record.get("correction") or "")
    elif store == "work_discovery":
        text = "\n".join(f"{item.get('title')} ({item.get('occurrences')} occurrences)"
                         for item in record["candidates"] if isinstance(item, Mapping))
    else:
        text = summary
    return (tuple(text[start:start + 1000] for start in range(0, len(text), 900)),
            text.strip() != summary)


class ExistingKnowledgeContentProjector:
    """Production resolver for exact references in supported existing stores."""

    def __init__(
        self,
        *,
        knowledge_base: Any | None = None,
        knowledge_base_factory: Callable[[str], Any | None] | None = None,
        work_discovery_factory: Callable[[str, str, str], Any] | None = None,
        correction_store: GovernedRecordStore | None = None,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.knowledge_base_factory = knowledge_base_factory
        self.work_discovery_factory = work_discovery_factory
        self.correction_store = correction_store

    def _resolve(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        admission: DatasetAdmission,
        authority: KnowledgeActorAuthority | None = None,
    ) -> KnowledgeDocument:
        inspected = inspect_existing_source(
            tenant,
            admission.source_ref,
            knowledge_base=self.knowledge_base,
            knowledge_base_factory=self.knowledge_base_factory,
            work_discovery_factory=self.work_discovery_factory,
            correction_store=self.correction_store,
            include_retrieval_chunks=True,
            remote_authority=authority,
        )
        if not hmac.compare_digest(inspected["content_sha256"], admission.content_sha256):
            raise KnowledgeProjectionUnavailable(
                "source content no longer matches the registered version commitment"
            )
        return KnowledgeDocument(
            tenant=canonical_tenant_id(tenant),
            reference=reference,
            content_sha256=inspected["content_sha256"],
            title=inspected["title"],
            summary=inspected["summary"],
            claim_state=inspected["claim_state"],
            observed_at=inspected["observed_at"],
            verified_at=inspected["verified_at"],
            retrieval_chunks=inspected["retrieval_chunks"],
            summary_truncated=inspected["summary_truncated"],
            permissions_withheld=inspected.get("permissions_withheld", 0),
        )

    def __call__(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        admission: DatasetAdmission,
    ) -> KnowledgeDocument | None:
        if admission.source_ref.startswith(
            ("catalog:vector-knowledge/", "catalog:work-discovery/", "catalog:remote-knowledge/")
        ):
            raise KnowledgeProjectionUnavailable(
                "this source requires exact actor, action, and purpose context"
            )
        return self._resolve(tenant, reference, admission)

    def resolve_for_context(
        self,
        tenant: str,
        reference: ResearchAssetRef,
        admission: DatasetAdmission,
        authority: KnowledgeActorAuthority,
    ) -> KnowledgeDocument:
        """Resolve a new projector only under its exact authorized context."""
        canonical = canonical_tenant_id(tenant)
        if (
            type(authority) is not KnowledgeActorAuthority
            or authority.tenant != canonical
            or authority.action not in {"analyze", "export", "read", "train"}
            or authority.purpose != admission.allowed_purpose
        ):
            raise KnowledgeProjectionUnavailable(
                "knowledge projection context crossed its exact boundary"
            )
        match = _WORK_REF.fullmatch(admission.source_ref)
        if match:
            owner = _decode_owner(match[1])
            if not text_equals(authority.principal, owner):
                raise KnowledgeProjectionUnavailable(
                    "work-discovery source belongs to another actor"
                )
            if authority.action not in {"analyze", "export", "read"}:
                raise KnowledgeProjectionUnavailable(
                    "work-discovery consent does not grant training use"
                )
        vector = _VECTOR_REF.fullmatch(admission.source_ref)
        if vector and vector[1].startswith("remote-"):
            from .knowledge_sources import require_remote_document_authority
            try:
                require_remote_document_authority(canonical, vector[1], vector[2], authority)
            except Exception as exc:
                raise KnowledgeProjectionUnavailable("current remote source account and snapshot rights are required") from exc
        return self._resolve(canonical, reference, admission, authority)


__all__ = [
    "ExistingKnowledgeContentProjector",
    "KnowledgeProjectionUnavailable",
    "correction_source_payload",
    "correction_source_record_id",
    "correction_source_ref",
    "correction_source_store",
    "inspect_existing_source",
    "vector_knowledge_source_ref",
    "work_discovery_source_ref",
]
