"""Machine-readable assessment exports: OSCAL results and the 42001 SoA.

Two projections over one saved assessment record:

* :func:`render_oscal_assessment_results` — the answers and findings as an
  OSCAL ``assessment-results`` JSON document (the NIST format FedRAMP
  automation and GRC pipelines standardized on), one observation per
  answered question and one finding per question with a satisfied /
  not-satisfied target status.
* :func:`render_statement_of_applicability` — the ISO-style Statement of
  Applicability an AIMS/ISMS certification audit starts from: one row per
  control with applicability (``na`` answers are exclusions, justified by
  the recorded note), implementation status, and the assessor's note.

Both are faithful projections of the governed record — nothing is
re-scored and nothing is invented. The OSCAL rendering targets the 1.1.2
JSON shape at a minimal, self-assessment profile; it is not a full-schema
validation service, and neither export is a certification.
"""
from __future__ import annotations

import uuid
from typing import Any

from .assessment import load_saved

OSCAL_VERSION = "1.1.2"


class AssessmentExportError(RuntimeError):
    """Base failure for assessment exports."""


def _rfc3339(stamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(
        float(stamp or 0.0), tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid_for(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "lightwork-oscal:" + ":".join(parts)))


def _record_or_raise(assessment_id: str) -> dict[str, Any]:
    record = load_saved(str(assessment_id or "").strip())
    if record is None:
        raise KeyError(f"no such assessment: {assessment_id}")
    return record


def _questions(record: dict[str, Any]) -> list[dict[str, Any]]:
    snapshot = record.get("template_snapshot") or {}
    return [dict(question) for question in snapshot.get("questions") or []]


def render_oscal_assessment_results(assessment_id: str) -> dict[str, Any]:
    """One saved assessment as an OSCAL ``assessment-results`` document."""

    record = _record_or_raise(assessment_id)
    session_id = str(record.get("id"))
    questions = _questions(record)
    answers = record.get("answers") or {}
    result = record.get("result") or {}
    findings_by_qid = {
        str(finding.get("question_id")): finding
        for finding in result.get("findings") or []
    }
    created = float(record.get("created_at") or 0.0)

    observations = []
    findings = []
    for question in questions:
        qid = str(question.get("id"))
        answer = answers.get(qid) or {}
        if not answer:
            continue
        note = str(answer.get("note") or "").strip()
        observations.append(
            {
                "uuid": _uuid_for(session_id, "observation", qid),
                "title": qid,
                "description": str(question.get("text") or ""),
                "methods": ["INTERVIEW"],
                "collected": _rfc3339(created),
                "remarks": (
                    f"answer: {answer.get('answer')}"
                    + (f"; note: {note}" if note else "")
                ),
            }
        )
        finding = findings_by_qid.get(qid)
        satisfied = finding is None and str(answer.get("answer")) != "na"
        if str(answer.get("answer")) == "na":
            continue
        findings.append(
            {
                "uuid": _uuid_for(session_id, "finding", qid),
                "title": f"{qid} ({question.get('severity')})",
                "description": (
                    str(finding.get("recommendation") or "")
                    if finding is not None
                    else "Control outcome attested by the recorded answer."
                ),
                "target": {
                    "type": "objective-id",
                    "target-id": qid,
                    "status": {
                        "state": "satisfied" if satisfied else "not-satisfied"
                    },
                },
                "related-observations": [
                    {"observation-uuid": _uuid_for(session_id, "observation", qid)}
                ],
            }
        )

    snapshot = record.get("template_snapshot") or {}
    return {
        "assessment-results": {
            "uuid": _uuid_for(session_id, "assessment-results"),
            "metadata": {
                "title": (
                    f"{snapshot.get('title') or record.get('type')} — "
                    f"{record.get('subject')}"
                ),
                "last-modified": _rfc3339(created),
                "version": str(record.get("revision") or 1),
                "oscal-version": OSCAL_VERSION,
                "remarks": (
                    "Self-assessment exported from Lightwork governed "
                    f"record {session_id}; residual risk rating: "
                    f"{result.get('risk_rating')}."
                ),
            },
            "import-ap": {"href": f"#lightwork-template-{record.get('template_digest')}"},
            "results": [
                {
                    "uuid": _uuid_for(session_id, "result"),
                    "title": str(snapshot.get("title") or record.get("type")),
                    "description": (
                        f"Assessment of {record.get('subject')} against "
                        f"{snapshot.get('framework') or record.get('type')}."
                    ),
                    "start": _rfc3339(created),
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "include-controls": [
                                    {"control-id": str(question.get("id"))}
                                    for question in questions
                                ]
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }


def render_statement_of_applicability(assessment_id: str) -> dict[str, Any]:
    """One control-style assessment as a Statement of Applicability.

    ``na`` answers become exclusions (their recorded note is the
    justification an auditor asks for); risky/unverified answers surface
    as not-yet-implemented.
    """

    record = _record_or_raise(assessment_id)
    questions = _questions(record)
    answers = record.get("answers") or {}
    rows = []
    counts = {"implemented": 0, "not_implemented": 0,
              "excluded": 0, "unanswered": 0}
    for question in questions:
        qid = str(question.get("id"))
        answer = answers.get(qid) or {}
        given = str(answer.get("answer") or "")
        note = str(answer.get("note") or "").strip()
        risky = str(question.get("risk_answer") or "").strip().lower()
        if not given:
            state = "unanswered"
        elif given == "na":
            state = "excluded"
        elif given == risky or given == "unknown":
            state = "not_implemented"
        else:
            state = "implemented"
        counts[state] += 1
        rows.append(
            {
                "control": qid,
                "section": str(question.get("section") or ""),
                "outcome": str(question.get("text") or ""),
                "applicable": given != "na",
                "status": state,
                "justification": note,
            }
        )
    snapshot = record.get("template_snapshot") or {}
    return {
        "framework": str(snapshot.get("framework") or record.get("type")),
        "subject": str(record.get("subject") or ""),
        "generated_from": str(record.get("id")),
        "template_digest": str(record.get("template_digest") or ""),
        "rows": rows,
        "counts": counts,
        "notice": (
            "A projection of the operator's own self-assessment — not a "
            "certification audit or an auditor's statement."
        ),
    }


def soa_markdown(soa: dict[str, Any]) -> str:
    """The SoA as a filing-ready markdown table."""

    lines = [
        f"# Statement of Applicability — {soa.get('framework')}",
        "",
        f"Subject: {soa.get('subject')}  ",
        f"Source record: {soa.get('generated_from')}  ",
        f"Template digest: {soa.get('template_digest')}",
        "",
        "| Control | Section | Applicable | Status | Justification / note |",
        "|---|---|---|---|---|",
    ]
    for row in soa.get("rows") or []:
        justification = str(row.get("justification") or "").replace("|", "\\|")
        lines.append(
            f"| {row['control']} | {row['section']} | "
            f"{'yes' if row['applicable'] else 'no'} | {row['status']} | "
            f"{justification} |"
        )
    counts = soa.get("counts") or {}
    lines += [
        "",
        f"Implemented: {counts.get('implemented', 0)} · "
        f"Not implemented: {counts.get('not_implemented', 0)} · "
        f"Excluded: {counts.get('excluded', 0)} · "
        f"Unanswered: {counts.get('unanswered', 0)}",
        "",
        str(soa.get("notice") or ""),
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "AssessmentExportError",
    "OSCAL_VERSION",
    "render_oscal_assessment_results",
    "render_statement_of_applicability",
    "soa_markdown",
]
