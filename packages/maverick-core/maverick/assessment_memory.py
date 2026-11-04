"""Assessment memory: the assessment flow learns from every one before it.

Every completed assessment is already persisted (:func:`maverick.assessment.
save_session` -> the tenant's assessments dir). This module turns that record
into working memory:

  * :func:`similar` -- past assessments of subjects like this one, with their
    risk ratings, so an intake can say "you've assessed systems like this
    before; the last CRM vendor came out MEDIUM".
  * :func:`suggest_answers` -- per-question suggested answers with confidence
    and provenance, distilled from the top-k similar past sessions of the SAME
    template (a majority vote -- explainable, deterministic, no LLM), so a
    respondent confirms instead of re-typing what the org already knows.
  * :func:`record_session` -- the write hook ``save_session`` calls: besides
    the canonical JSON record, it distills the assessment into the governed
    knowledge plane (collection ``assessments``) when knowledge RAG is
    enabled, so agents and future assessments can recall lessons
    semantically. Retrieval still requires a caller-supplied governed reader.

Similarity is transparent token overlap (Jaccard over subject words, with a
same-template bonus) -- the goal is recall of the org's OWN precedents, not
open-ended semantics; the knowledge plane adds the semantic layer when it's
on. Suggestions are advisory only: nothing here auto-answers an assessment,
and the human reviewer gate is untouched. Gated by ``[assessments] learn``
(default on -- it only reads the org's own records).
"""
from __future__ import annotations

import logging
import time
from collections import Counter
from typing import Any

log = logging.getLogger(__name__)

KNOWLEDGE_COLLECTION = "assessments"


def enabled() -> bool:
    try:
        from .config import get_assessments
        return bool(get_assessments()["learn"])
    except Exception:  # pragma: no cover -- config never crashes a read
        return True


def _tokens(text: str) -> set[str]:
    return {t for t in (text or "").lower().replace("/", " ").split()
            if len(t) > 2}


def _similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def similar(subject: str, *, assessment_type: str | None = None,
            k: int = 3, exclude_id: str | None = None, allowed_types: set[str] | None = None) -> list[dict]:
    """Past assessments most like ``subject``, best first.

    Each entry: id/type/subject/risk_rating/findings/created_at/similarity.
    Empty when learning is off or there is no history -- never raises."""
    if not enabled():
        return []
    try:
        from .assessment import list_saved
        rows = list_saved()
    except Exception:  # pragma: no cover -- a read miss is just "no history"
        return []
    scored = []
    for r in rows:
        if allowed_types is not None and r.get("type") not in allowed_types:
            continue
        if exclude_id and r.get("id") == exclude_id:
            continue
        sim = _similarity(subject, str(r.get("subject", "")))
        if assessment_type and r.get("type") == assessment_type:
            sim += 0.15
        if sim > 0:
            scored.append({**r, "similarity": round(min(sim, 1.0), 3),
                           "evidence_state": "stale_precedent" if r.get("review_due") else "approved_precedent" if r.get("status") == "approved" else "unreviewed_precedent"})
    scored.sort(key=lambda r: (r["similarity"], r.get("created_at", 0)),
                reverse=True)
    return scored[:k]


def source_evidence(data: dict, question_id: str) -> dict:
    """Exact saved answer provenance; an agreement ratio is not truth confidence."""
    from .assessment import template_for_saved_record, template_state
    policy = template_state(data["type"])
    template = template_for_saved_record(data)
    question = next((q for q in template.questions if q.id == question_id), None) if template else None
    answer = (data.get("answers") or {}).get(question_id) or {}
    now = time.time()
    expiry = [data.get("next_review_at"), data.get("renewal_at"), (data.get("risk_acceptance") or {}).get("expires_at")]
    reasons = []
    if not data.get("template_digest") or policy["digest"] != data.get("template_digest"):
        reasons.append("The current questionnaire differs from this source's pinned version.")
    if data.get("review_forced_at") or any(value and float(value) <= now for value in expiry):
        reasons.append("This precedent is due for renewed review.")
    approved = data.get("status") == "approved" and bool(data.get("decided_by")) and bool(data.get("decided_at"))
    state = "stale_precedent" if reasons else "current_approved" if approved else "unreviewed_precedent"
    if not approved:
        reasons.append("A current named approval is not recorded; this is prior opinion, not verified evidence.")
    return {"assessment_id": data["id"], "source_revision": data.get("revision", 0),
            "question_id": question_id, "question": question.text if question else "Question unavailable",
            "answer": str(answer.get("answer", "")), "note": str(answer.get("note", "")),
            "subject": data.get("subject", ""), "source_date": data.get("created_at"),
            "policy_version": data.get("template_revision"), "policy_digest": data.get("template_digest", ""),
            "current_policy_version": policy["revision"], "current_policy_digest": policy["digest"],
            "approval_owner": data.get("decided_by") or None, "approved_at": data.get("decided_at"),
            "state": state, "reasons": reasons}


def suggest_answers(assessment_type: str, subject: str, *, k: int = 3,
                    min_confidence: float = 0.6, exclude_id: str | None = None,
                    allowed_types: set[str] | None = None) -> dict[str, dict]:
    """Advisory majority with exact provenance for supporting and conflicting votes."""
    if not enabled() or (allowed_types is not None and assessment_type not in allowed_types):
        return {}
    from .assessment import load_saved
    picks = similar(subject, assessment_type=assessment_type, k=k, exclude_id=exclude_id, allowed_types=allowed_types)
    evidence: dict[str, list[dict]] = {}
    for pick in picks:
        data = load_saved(str(pick.get("id", "")))
        if not data or data.get("type") != assessment_type:
            continue
        for qid, record in (data.get("answers") or {}).items():
            answer = str((record or {}).get("answer", "")).strip().lower()
            if answer not in {"yes", "no", "na"}:
                continue
            evidence.setdefault(qid, []).append(source_evidence(data, qid))
    out = {}
    for qid, sources in evidence.items():
        votes = Counter(source["answer"].strip().lower() for source in sources)
        answer, count = votes.most_common(1)[0]
        confidence = count / len(sources)
        if confidence < min_confidence:
            continue
        supporting = [source for source in sources if source["answer"].strip().lower() == answer]
        out[qid] = {"answer": answer,
            "note": next((source["note"] for source in supporting if source["note"]), ""),
            "confidence": round(confidence, 2), "confidence_meaning": "Agreement among selected precedents, not factual certainty.",
            "based_on": [source["assessment_id"] for source in supporting], "sources": supporting,
            "conflicts": [source for source in sources if source not in supporting],
            "state": "current_approved" if all(source["state"] == "current_approved" for source in supporting) else "stale_precedent" if any(source["state"] == "stale_precedent" for source in supporting) else "unreviewed_precedent",
            "why_reused": "Similar subject and the same questionnaire; the most common saved answer is offered for your independent review."}
    return out


def lessons(subject: str, *, k: int = 3, reader=None) -> list[str]:
    """Semantic recall from the knowledge plane's ``assessments`` collection
    (past findings/ratings distilled at record time).

    The caller must supply an APP10-governed reader bound to the current
    tenant, actor, purpose, and source versions.  Missing or malformed readers
    return no semantic lessons; this legacy helper never falls back to raw
    vector-store access.  The deterministic :func:`similar` path remains
    available under its assessment-record controls.
    """
    if not enabled() or not callable(reader):
        return []
    try:
        values = reader(subject, k)
        if (
            not isinstance(values, (tuple, list))
            or len(values) > k
            or any(not isinstance(value, str) for value in values)
        ):
            return []
        return [value.strip()[:8_192] for value in values if value.strip()]
    except Exception as e:  # noqa: BLE001 -- recall never breaks the caller
        log.debug("assessment_memory: lessons recall failed: %s", e)
        return []


def _distill(payload: dict[str, Any]) -> str:
    """One compact, human-readable record for semantic recall."""
    res = payload.get("result") or {}
    findings = res.get("findings") or []
    inherent = res.get("inherent_risk", res.get("risk_rating", "?"))
    residual = res.get("residual_risk", res.get("risk_rating", "?"))
    lines = [
        f"Assessment {payload.get('id', '?')} ({payload.get('type', '?')}) "
        f"of {payload.get('subject', '?')}: risk {res.get('risk_rating', '?')} "
        f"(inherent {inherent} -> residual {residual}), "
        f"{res.get('answered', 0)}/{res.get('total', 0)} answered, "
        f"{len(findings)} finding(s).",
    ]
    for f in findings[:12]:
        sev = f.get("severity", "?")
        lines.append(f"- [{sev}] {f.get('section', '')}: "
                     f"{f.get('question', f.get('text', ''))} "
                     f"(answer: {f.get('answer', '?')})")
    return "\n".join(lines)


def record_session(payload: dict[str, Any]) -> bool:
    """Distill a saved assessment into the knowledge plane (fail-open).

    Called by ``save_session`` with the same payload it wrote to disk. The
    JSON record stays canonical; this adds the semantic index. Returns True
    only when a knowledge ingest actually happened."""
    if not enabled():
        return False
    try:
        from .knowledge_admin import open_knowledge_base
        kb = open_knowledge_base()
        if kb is None:
            return False
        kb.ingest_text(
            KNOWLEDGE_COLLECTION,
            _distill(payload),
            source=f"assessment:{payload.get('id', '')}",
            subject=str(payload.get("subject", "")),
        )
        return True
    except Exception as e:  # noqa: BLE001 -- memory must never break a save
        log.debug("assessment_memory: knowledge ingest skipped: %s", e)
        return False


__all__ = ["KNOWLEDGE_COLLECTION", "enabled", "lessons", "record_session",
           "similar", "suggest_answers"]
