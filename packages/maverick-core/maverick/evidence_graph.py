"""Continuous, review-gated evidence graph for controls and governed assets.

The graph stores bounded evidence *metadata* and cryptographic bindings, not raw
telemetry or credentials.  Nodes are content-addressed, edges are explicit, and
only current human-approved nodes satisfy control coverage.  That makes a
readiness report reproducible while preventing stale or merely collected data
from silently becoming compliance proof.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any

from .governed_records import GovernedRecordStore

_STORE = GovernedRecordStore("evidence_graph", "EGN", "evidence_graph_node")
_SCHEMA = "lightwork.evidence-graph-node.v1"
_PACK_SCHEMA = "lightwork.evidence-graph-pack.v1"
_DECISIONS = frozenset({"approved", "rejected", "revoked"})
_MAX_MODEL_RISK_PROJECTIONS = 2048
_MAX_GRAPH_NODES = 10_000
_SAFE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|passwd|credential|authorization|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _PersistedReviewBinding:
    review: dict[str, Any]


class _InheritedAuthorityError(RuntimeError):
    """A projected approval no longer resolves to its exact source authority."""

    def __init__(self, reason: str, *, current_revision: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.current_revision = current_revision


def enabled() -> bool:
    """Deployment-global feature gate; malformed policy fails closed."""
    try:
        from .config import config_source_errors, load_global_config

        cfg = load_global_config()
        if config_source_errors(include_tenant=False):
            return False
        if "evidence_graph" not in cfg:
            return False
        section = cfg.get("evidence_graph")
        return isinstance(section, dict) and section.get("enable") is True
    except Exception:  # pragma: no cover - authority reads fail closed
        return False


def _required(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    _reject_secret_text(text, label)
    return text[:limit]


def _reject_secret_text(value: str, label: str) -> None:
    """Reject credential-shaped data before any truncation or persistence."""

    try:
        from .safety.secret_detector import scan

        matches = scan(str(value))
    except Exception as exc:  # failure-policy: evidence persistence fails closed
        raise ValueError("secret detection is unavailable") from exc
    if matches:
        kinds = ", ".join(sorted({match.name for match in matches}))
        raise ValueError(f"{label} contains secret material ({kinds})")


def _bounded_text(value: object, label: str, limit: int) -> str:
    text = str(value)
    _reject_secret_text(text, label)
    return text[:limit]


def _sha256_digest(value: object, label: str) -> str:
    digest = _required(value, label, 64).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"{label} must be a SHA-256 hex digest")
    return digest


def _timestamp(value: float | None, label: str) -> float:
    out = time.time() if value is None else float(value)
    if not math.isfinite(out) or out <= 0:
        raise ValueError(f"{label} must be a positive timestamp")
    return out


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _controls(values) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise ValueError("controls must be a list")
    out = {
        _required(value, "control id", 128)
        for value in list(values)[:512]
    }
    return sorted(out)


def _attributes(values: dict[str, Any] | None) -> dict[str, Any]:
    if values is None:
        return {}
    if not isinstance(values, dict):
        raise ValueError("attributes must be an object")
    if len(values) > 128:
        raise ValueError("attributes exceed the 128-field limit")
    out: dict[str, Any] = {}
    for raw_key, raw_value in values.items():
        key = str(raw_key or "").strip()
        if not _SAFE_KEY.fullmatch(key):
            raise ValueError("attribute key is invalid")
        if _SENSITIVE_KEY.search(key):
            raise ValueError(f"sensitive attribute {key!r} is not permitted")
        if isinstance(raw_value, bool) or raw_value is None:
            value: Any = raw_value
        elif isinstance(raw_value, int):
            value = raw_value
        elif isinstance(raw_value, float):
            if not math.isfinite(raw_value):
                raise ValueError(f"attribute {key!r} must be finite")
            value = raw_value
        elif isinstance(raw_value, str):
            value = _bounded_text(raw_value, f"attribute {key!r}", 2000)
        elif isinstance(raw_value, (list, tuple)):
            value = [
                _bounded_text(item, f"attribute {key!r} item", 500)
                for item in list(raw_value)[:64]
            ]
        else:
            raise ValueError(f"attribute {key!r} has an unsupported value")
        out[key] = value
    return {key: out[key] for key in sorted(out)}


def _links(values) -> list[dict[str, str]]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise ValueError("links must be a list")
    dedup: dict[tuple[str, str, str], dict[str, str]] = {}
    for raw in list(values)[:512]:
        if not isinstance(raw, dict):
            raise ValueError("each evidence link must be an object")
        relation = _required(raw.get("relation"), "link relation", 64)
        target_type = _required(raw.get("target_type"), "link target_type", 64)
        target_id = _required(raw.get("target_id"), "link target_id", 256)
        key = (relation, target_type, target_id)
        dedup[key] = {
            "relation": relation,
            "target_type": target_type,
            "target_id": target_id,
        }
    return [dedup[key] for key in sorted(dedup)]


def _persisted_review(
    authority_record: dict[str, Any],
    *,
    decision: dict[str, Any],
    reviewer: object,
    rationale: object,
    reviewed_at: float,
    authority_schema: str = "",
) -> _PersistedReviewBinding:
    """Bind inherited approval to a freshly loaded governed source record."""

    record_id = _required(authority_record.get("id"), "inherited_from", 256)
    revision = authority_record.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("persisted review authority has no valid revision")
    schema = _required(
        authority_record.get("schema") or authority_schema,
        "authority schema",
        128,
    )
    return _PersistedReviewBinding({
        "status": "approved",
        "reviewer": _required(reviewer, "inherited reviewer", 256),
        "rationale": _required(rationale, "inherited rationale", 4000),
        "reviewed_at": _timestamp(reviewed_at, "reviewed_at"),
        "inherited_from": record_id,
        "authority_schema": schema,
        "authority_revision": revision,
        "authority_sha256": _authority_sha256(
            record_id=record_id,
            revision=revision,
            schema=schema,
            decision=decision,
        ),
    })


def _authority_sha256(
    *,
    record_id: str,
    revision: int,
    schema: str,
    decision: dict[str, Any],
) -> str:
    return hashlib.sha256(_canonical({
        "record_id": record_id,
        "revision": revision,
        "schema": schema,
        "decision": decision,
    })).hexdigest()


def _security_evidence_authority(record_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    from . import security_ops

    authority = security_ops.get_evidence(record_id)
    if not isinstance(authority, dict):
        raise _InheritedAuthorityError("source_not_found")
    decision = authority.get("decision")
    if (
        authority.get("status") != "approved"
        or not isinstance(decision, dict)
        or decision.get("decision") != "approved"
    ):
        raise _InheritedAuthorityError(
            "source_not_approved",
            current_revision=_valid_authority_revision(authority.get("revision")),
        )
    return authority, decision, "maverick.security_ops.evidence.v1"


def _model_risk_evidence_authority(
    record_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Load one exact, current human approval from Model Risk authority."""

    # Keep this import local: model-risk recording projects raw observations to
    # the graph, while approved reviews call back into the trusted projector.
    from . import model_risk_assurance

    authority = model_risk_assurance.get_evidence(record_id)
    if not isinstance(authority, dict):
        raise _InheritedAuthorityError("source_not_found")
    revision = _valid_authority_revision(authority.get("revision"))
    expected_schema = model_risk_assurance.EVIDENCE_SCHEMA
    if authority.get("schema") != expected_schema:
        raise _InheritedAuthorityError(
            "source_identity_changed",
            current_revision=revision,
        )
    decision = authority.get("review")
    if (
        authority.get("status") != "approved"
        or not isinstance(decision, dict)
        or decision.get("decision") != "approved"
    ):
        raise _InheritedAuthorityError(
            "source_not_approved",
            current_revision=revision,
        )
    if decision.get("payload_sha256") != authority.get("payload_sha256"):
        raise _InheritedAuthorityError(
            "source_authority_invalid",
            current_revision=revision,
        )
    if authority.get("evidence_kind") == "red_team":
        producer = authority.get("producer_actor")
        reviewer = decision.get("reviewer")
        if (
            not isinstance(producer, str)
            or not producer.strip()
            or not isinstance(reviewer, str)
            or not reviewer.strip()
            or producer.strip().casefold() == reviewer.strip().casefold()
        ):
            raise _InheritedAuthorityError(
                "source_review_separation_invalid",
                current_revision=revision,
            )
    asset = model_risk_assurance.get_observation(str(authority.get("asset_id") or ""))
    if (
        not isinstance(asset, dict)
        or asset.get("version_digest") != authority.get("artifact_digest")
    ):
        raise _InheritedAuthorityError(
            "source_artifact_authority_stale",
            current_revision=revision,
        )
    evaluator_asset_id = authority.get("evaluator_asset_id")
    if evaluator_asset_id is not None:
        evaluator = model_risk_assurance.get_observation(str(evaluator_asset_id))
        binding = authority.get("evaluator_binding")
        if (
            not isinstance(evaluator, dict)
            or not isinstance(binding, dict)
            or not model_risk_assurance.citation_is_current(binding, evaluator)
            or evaluator.get("version_digest") != authority.get("evaluator_digest")
        ):
            raise _InheritedAuthorityError(
                "source_evaluator_authority_stale",
                current_revision=revision,
            )
    try:
        valid_until = float(authority.get("valid_until"))
    except (TypeError, ValueError) as exc:
        raise _InheritedAuthorityError(
            "source_expired",
            current_revision=revision,
        ) from exc
    if (
        not math.isfinite(valid_until)
        or valid_until <= time.time()
        or authority.get("freshness") != "current"
    ):
        raise _InheritedAuthorityError(
            "source_expired",
            current_revision=revision,
        )
    return authority, decision, expected_schema


def _valid_authority_revision(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return None


def _load_inherited_authority(
    node: dict[str, Any],
    record_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    source = str(node.get("source") or "")
    evidence_type = str(node.get("evidence_type") or "")
    if source == "security_ops" and evidence_type == "reviewed_control_evidence":
        return _security_evidence_authority(record_id)
    if (
        source == "model_risk_assurance"
        and evidence_type.startswith("approved_ai_assurance_")
    ):
        return _model_risk_evidence_authority(record_id)
    raise _InheritedAuthorityError("unsupported_inherited_source")


def _inherited_authority_validation(
    node: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve inherited approval to its exact current governed source.

    The returned state is a read-time projection only.  The content-addressed
    graph record and its historical review remain immutable, while callers get
    an effective status that fails closed when the source is unavailable,
    rejected, invalid, or at a different revision.
    """

    review = node.get("review")
    if not isinstance(review, dict):
        return None
    record_id = str(review.get("inherited_from") or "").strip()
    if not record_id:
        return None
    bound_revision = _valid_authority_revision(review.get("authority_revision"))
    source = str(node.get("source") or "")
    state: dict[str, Any] = {
        "status": "stale",
        "source": source,
        "record_id": record_id,
        "bound_revision": bound_revision,
    }
    if review.get("status") != "approved" or bound_revision is None:
        state["reason"] = "binding_invalid"
        return state
    try:
        authority, decision, expected_schema = _load_inherited_authority(
            node,
            record_id,
        )
        current_revision = _valid_authority_revision(authority.get("revision"))
        if current_revision is None:
            raise _InheritedAuthorityError("source_revision_invalid")
        if current_revision != bound_revision:
            raise _InheritedAuthorityError(
                "source_revision_changed",
                current_revision=current_revision,
            )
        current_id = str(authority.get("id") or "")
        current_schema = str(authority.get("schema") or expected_schema)
        if (
            current_id != record_id
            or current_schema != expected_schema
            or review.get("authority_schema") != expected_schema
        ):
            raise _InheritedAuthorityError(
                "source_identity_changed",
                current_revision=current_revision,
            )
        current_sha256 = _authority_sha256(
            record_id=current_id,
            revision=current_revision,
            schema=current_schema,
            decision=decision,
        )
        if review.get("authority_sha256") != current_sha256:
            raise _InheritedAuthorityError(
                "source_decision_changed",
                current_revision=current_revision,
            )
    except _InheritedAuthorityError as exc:
        state["reason"] = exc.reason
        if exc.current_revision is not None:
            state["current_revision"] = exc.current_revision
        return state
    except Exception:
        state["reason"] = "source_unavailable"
        return state
    return {
        **state,
        "status": "current",
        "current_revision": bound_revision,
    }


def _ingest(
    *,
    source: str,
    source_id: str,
    evidence_type: str,
    title: str,
    summary: str,
    controls,
    attributes: dict[str, Any] | None,
    links=None,
    actor: str,
    observed_at: float | None = None,
    valid_until: float | None = None,
    persisted_review: _PersistedReviewBinding | None = None,
) -> dict[str, Any]:
    source_name = _required(source, "source", 80)
    source_record = _required(source_id, "source_id", 256)
    kind = _required(evidence_type, "evidence_type", 80)
    ingest_actor = _required(actor, "actor", 4096)
    observed = _timestamp(observed_at, "observed_at")
    expiry = None if valid_until is None else _timestamp(valid_until, "valid_until")
    if expiry is not None and expiry <= observed:
        # Historical imports may already be stale, but their recorded
        # observation still has to predate the expiry it claims.
        raise ValueError("valid_until must be after observed_at")
    if persisted_review is not None and not isinstance(
        persisted_review,
        _PersistedReviewBinding,
    ):
        raise ValueError("persisted review binding is invalid")
    review = None if persisted_review is None else dict(persisted_review.review)
    payload = {
        "source": source_name,
        "source_id": source_record,
        "evidence_type": kind,
        "title": _required(title, "title", 300),
        "summary": _required(summary, "summary", 8000),
        "controls": _controls(controls),
        "attributes": _attributes(attributes),
        "links": _links(links),
        "valid_until": expiry,
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    identity_digest = hashlib.sha256(
        _canonical({"source": source_name, "source_id": source_record})
    ).hexdigest()
    record_id = f"EGN-{identity_digest[:24]}"
    existing = _STORE.get(record_id)
    if existing is not None:
        if existing.get("payload_sha256") != digest:
            raise RuntimeError("evidence graph content-address collision")
        return existing
    record: dict[str, Any] = {
        "id": record_id,
        "schema": _SCHEMA,
        **payload,
        "observed_at": observed,
        "payload_sha256": digest,
        "status": "approved" if review else "pending_review",
        "review": review,
    }
    return _STORE.create(record, action="ingest", actor=ingest_actor)


def ingest(
    *,
    source: str,
    source_id: str,
    evidence_type: str,
    title: str,
    summary: str,
    controls,
    attributes: dict[str, Any] | None,
    links=None,
    actor: str,
    observed_at: float | None = None,
    valid_until: float | None = None,
) -> dict[str, Any]:
    """Ingest one bounded observation; public ingestion always awaits review."""

    return _ingest(
        source=source,
        source_id=source_id,
        evidence_type=evidence_type,
        title=title,
        summary=summary,
        controls=controls,
        attributes=attributes,
        links=links,
        actor=actor,
        observed_at=observed_at,
        valid_until=valid_until,
    )


def decide(
    node_id: str,
    *,
    decision: str,
    rationale: str,
    reviewer: str,
    expected_revision: int,
) -> dict[str, Any] | None:
    choice = str(decision or "").strip().lower()
    if choice not in _DECISIONS:
        raise ValueError(f"decision must be one of {sorted(_DECISIONS)}")
    why = _required(rationale, "rationale", 4000)
    human = _required(reviewer, "reviewer", 4096)

    def _mutate(record: dict[str, Any]) -> None:
        inherited_from = str(
            (record.get("review") or {}).get("inherited_from") or ""
        ).strip()
        if inherited_from:
            raise ValueError(
                "inherited evidence is reviewed by its governed source authority"
            )
        if record.get("status") == "revoked":
            raise ValueError("revoked evidence cannot be re-approved")
        record["status"] = choice
        record["review"] = {
            "status": choice,
            "reviewer": human[:256],
            "rationale": why,
            "reviewed_at": time.time(),
            "inherited_from": "",
        }

    return _STORE.update(
        node_id,
        _mutate,
        expected_revision=expected_revision,
        action=f"review_{choice}",
        actor=human,
    )


def _present(record: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    row = dict(record)
    current = time.time() if now is None else float(now)
    expiry = row.get("valid_until")
    row["freshness"] = (
        "stale"
        if expiry is not None and float(expiry) <= current
        else "current"
    )
    authority = _inherited_authority_validation(row)
    if authority is not None:
        row["authority_validation"] = authority
        if authority.get("status") != "current":
            # Preserve the persisted review as historical provenance, but make
            # the projected status unusable to every existing status/freshness
            # consumer.  No graph mutation is needed to revoke inherited power.
            row["status"] = "authority_stale"
            row["freshness"] = "stale"
    return row


def get(node_id: str) -> dict[str, Any] | None:
    row = _STORE.get(node_id)
    return None if row is None else _present(row)


def list_nodes() -> list[dict[str, Any]]:
    rows = _STORE.list(limit=_MAX_GRAPH_NODES + 1)
    if len(rows) > _MAX_GRAPH_NODES:
        raise ValueError(
            f"evidence graph exceeds the {_MAX_GRAPH_NODES}-node operational limit"
        )
    return [_present(row) for row in rows]


def _coverage_report(
    required_controls,
    nodes: list[dict[str, Any]],
) -> dict[str, Any]:
    required = _controls(required_controls)
    usable = [
        node
        for node in nodes
        if node.get("status") == "approved" and node.get("freshness") == "current"
    ]
    covered = sorted({control for node in usable for control in node.get("controls", [])})
    covered_required = [control for control in required if control in covered]
    missing = [control for control in required if control not in covered]
    return {
        "required_controls": required,
        "covered_controls": covered_required,
        "missing_controls": missing,
        "coverage_percent": (
            round(100.0 * len(covered_required) / len(required), 1)
            if required else 100.0
        ),
        "approved_current_nodes": len(usable),
        "pending_review_nodes": sum(
            1 for node in nodes if node.get("status") == "pending_review"
        ),
        "stale_nodes": sum(1 for node in nodes if node.get("freshness") == "stale"),
    }


def coverage_report(required_controls) -> dict[str, Any]:
    return _coverage_report(required_controls, list_nodes())


def collect_security_evidence(*, actor: str) -> list[dict[str, Any]]:
    """Project approved GRC evidence into the continuous graph."""
    from . import security_ops

    imported: list[dict[str, Any]] = []
    for listed in security_ops.list_evidence():
        # Re-read by governed id instead of trusting a caller/list projection to
        # carry approval.  The persisted revision and exact decision are bound
        # into the graph review provenance below.
        evidence = security_ops.get_evidence(str(listed.get("id") or ""))
        if not isinstance(evidence, dict) or evidence.get("status") != "approved":
            continue
        verdicts = list(evidence.get("verdicts") or [])
        controls = sorted({
            str(verdict.get("control_id") or "")
            for verdict in verdicts
            if verdict.get("status") in {"present", "partial"}
            and str(verdict.get("control_id") or "")
        })
        decision = dict(evidence.get("decision") or {})
        if decision.get("decision") != "approved":
            continue
        review = _persisted_review(
            evidence,
            decision=decision,
            reviewer=decision.get("decided_by"),
            rationale=decision.get("rationale"),
            reviewed_at=decision.get("decided_at"),
            authority_schema="maverick.security_ops.evidence.v1",
        )
        imported.append(_ingest(
            source="security_ops",
            source_id=(
                f"{evidence.get('id')}:review:{evidence.get('revision')}"
            ),
            evidence_type="reviewed_control_evidence",
            title=str(evidence.get("title") or "Security evidence"),
            summary=(
                "Human-approved deterministic control mapping; raw source content "
                "remains in the governed Security/GRC evidence store."
            ),
            controls=controls,
            attributes={
                "source_sha256": str(evidence.get("source_sha256") or ""),
                "mapping_method": str(evidence.get("mapping_method") or ""),
                "present": int((evidence.get("counts") or {}).get("present") or 0),
                "partial": int((evidence.get("counts") or {}).get("partial") or 0),
            },
            links=[{
                "relation": "projects",
                "target_type": "security_evidence",
                "target_id": str(evidence.get("id") or ""),
            }],
            actor=actor,
            observed_at=float(evidence.get("created_at") or time.time()),
            persisted_review=review,
        ))
    return imported


def project_model_risk_evidence(
    evidence_id: str,
    *,
    actor: str,
) -> dict[str, Any]:
    """Project one freshly loaded, approved Model Risk evidence record.

    Callers provide only an id.  Approval, freshness, content identity, and
    reviewer provenance are always re-read from the governed Model Risk store;
    a caller-supplied graph observation can never manufacture this binding.
    """

    record_id = _required(evidence_id, "model-risk evidence id", 64)
    try:
        evidence, decision, authority_schema = _model_risk_evidence_authority(
            record_id,
        )
    except _InheritedAuthorityError as exc:
        raise ValueError(
            "model-risk evidence has no current approved governed authority "
            f"({exc.reason})"
        ) from exc
    review = _persisted_review(
        evidence,
        decision=decision,
        reviewer=decision.get("reviewer"),
        rationale=decision.get("rationale"),
        reviewed_at=decision.get("reviewed_at"),
        authority_schema=authority_schema,
    )
    kind = _required(evidence.get("evidence_kind"), "evidence kind", 80)
    result = _required(evidence.get("result"), "evidence result", 80)
    asset_id = _required(evidence.get("asset_id"), "asset id", 128)
    payload_sha256 = _sha256_digest(
        evidence.get("payload_sha256"),
        "evidence payload digest",
    )
    attributes: dict[str, Any] = {
        "artifact_digest": _sha256_digest(
            evidence.get("artifact_digest"),
            "artifact digest",
        ),
        "asset_id": asset_id,
        "evidence_kind": kind,
        "evidence_payload_sha256": payload_sha256,
        "evidence_revision": int(evidence["revision"]),
        "result": result,
        "scope_digest": _sha256_digest(
            evidence.get("scope_digest"),
            "scope digest",
        ),
    }
    evaluator_digest = evidence.get("evaluator_digest")
    if evaluator_digest is not None:
        attributes["evaluator_digest"] = _sha256_digest(
            evaluator_digest,
            "evaluator digest",
        )
    evaluator_asset_id = evidence.get("evaluator_asset_id")
    if evaluator_asset_id is not None:
        attributes["evaluator_asset_id"] = _required(
            evaluator_asset_id,
            "evaluator asset id",
            128,
        )
    return _ingest(
        source="model_risk_assurance",
        source_id=(
            f"{record_id}:{payload_sha256}:review:{evidence['revision']}"
        ),
        evidence_type=f"approved_ai_assurance_{kind}",
        title=f"Approved AI assurance {kind.replace('_', ' ')}",
        summary=(
            f"Human-approved, expiring {kind.replace('_', ' ')} evidence; "
            f"the governed result is {result}."
        ),
        controls=["AI-RMF:MEASURE", "ISO42001:performance_evaluation"],
        attributes=attributes,
        links=[
            {
                "relation": "supports",
                "target_type": "ai_asset",
                "target_id": asset_id,
            },
            {
                "relation": "projects",
                "target_type": "model_risk_evidence",
                "target_id": record_id,
            },
        ],
        actor=actor,
        observed_at=float(evidence["observed_at"]),
        valid_until=float(evidence["valid_until"]),
        persisted_review=review,
    )


def collect_model_risk_evidence(*, actor: str) -> list[dict[str, Any]]:
    """Project a bounded snapshot of current approved Model Risk evidence."""

    from . import model_risk_assurance

    listed = model_risk_assurance.list_evidence()
    if not isinstance(listed, list):
        raise ValueError("model-risk evidence inventory must be a list")
    if len(listed) > _MAX_MODEL_RISK_PROJECTIONS:
        raise ValueError(
            "model-risk evidence inventory exceeds the 2048-record projection limit"
        )
    imported: list[dict[str, Any]] = []
    for summary in listed:
        if not isinstance(summary, dict):
            raise ValueError("model-risk evidence inventory contains an invalid record")
        review = summary.get("review")
        if (
            summary.get("status") != "approved"
            or summary.get("freshness") != "current"
            or not isinstance(review, dict)
            or review.get("decision") != "approved"
        ):
            continue
        imported.append(project_model_risk_evidence(
            str(summary.get("id") or ""),
            actor=actor,
        ))
    return imported


def render_pack(*, required_controls=None) -> dict[str, Any]:
    nodes = sorted(
        (
            {key: value for key, value in row.items() if key != "_audit_pending"}
            for row in list_nodes()
        ),
        key=lambda row: str(row.get("id") or ""),
    )
    controls = required_controls if required_controls is not None else sorted({
        control for node in nodes for control in node.get("controls", [])
    })
    # Derive coverage from the exact authority-revalidated node snapshot being
    # signed.  A second graph/source read here could otherwise produce a pack
    # whose nodes and coverage describe different authority moments.
    coverage = _coverage_report(controls, nodes)
    bound = {
        "schema": _PACK_SCHEMA,
        "nodes": nodes,
        "coverage": coverage,
    }
    pack = {
        **bound,
        "generated_at": time.time(),
        "graph_sha256": hashlib.sha256(_canonical(bound)).hexdigest(),
        "note": (
            "Coverage includes only current human-approved evidence; this pack "
            "is not a certification or legal determination."
        ),
    }
    from .proof_pack import sign

    return sign(pack)


def verify_pack(
    pack: dict[str, Any],
    *,
    trusted_pubkey_hex: str,
) -> tuple[bool, str]:
    """Verify graph content and the trusted-anchor Ed25519 signature."""
    if not isinstance(pack, dict):
        return False, "evidence graph pack must be an object"
    bound = {
        "schema": pack.get("schema"),
        "nodes": pack.get("nodes"),
        "coverage": pack.get("coverage"),
    }
    expected = hashlib.sha256(_canonical(bound)).hexdigest()
    if pack.get("graph_sha256") != expected:
        return False, "evidence graph content digest does not verify"
    from .proof_pack import verify

    return verify(pack, trusted_pubkey_hex=trusted_pubkey_hex)


__all__ = [
    "collect_model_risk_evidence",
    "collect_security_evidence",
    "coverage_report",
    "decide",
    "enabled",
    "get",
    "ingest",
    "list_nodes",
    "project_model_risk_evidence",
    "render_pack",
    "verify_pack",
]
