"""Authority-preserving backend seam for the GRC Concierge SKU.

Auto mode can reuse Lightwork's built-in questionnaire declarations and scoring
algorithm. It deliberately never calls platform persistence, connectors, or
audit: every record and mock review decision remains unsigned local demo state.
Set ``GRC_STANDALONE=1`` to force the smaller bundled catalog and scorer.
"""
from __future__ import annotations

import re

import grc_engine as local
from capabilities import (
    CAPABILITY_LABELS,
    CAPS,
    FORCED_STANDALONE,
    PLATFORM_ENGINE,
    STANDALONE,
)
from capabilities import (
    caps_summary as _caps_summary,
)

if PLATFORM_ENGINE:
    from maverick import assessment as _assessment
else:
    _assessment = None


STORE = local.LocalStore()


def _binding(implementation: str, authority: str, active: bool = True) -> dict:
    return {
        "implementation": implementation,
        "authority": authority,
        "active": active,
    }


def _integrated_only(path: str) -> dict:
    return _binding(
        f"Not available in this standalone app; use integrated Lightwork {path}",
        "integrated-lightwork-only",
        False,
    )


_QUESTIONNAIRE_ENGINE = (
    "maverick.assessment adapter (analysis only)"
    if PLATFORM_ENGINE
    else "grc_engine vendored catalog and scorer"
)

# This is the executable capability contract for the web app.  Every advertised
# capability is resolved here, including explicit integrated-only gaps, and the
# routes call this module without branching on runtime mode.
CAPABILITY_BINDINGS = {
    "starter_catalog": _binding(_QUESTIONNAIRE_ENGINE, "unsigned-local"),
    "questionnaire_scoring": _binding(_QUESTIONNAIRE_ENGINE, "unsigned-local"),
    "evidence_quotes": _binding(
        "grc_engine.evaluate_controls", "unsigned-local-human-review-required"
    ),
    "guided_browser_intake": _binding(
        "app routes and templates/index.html", "unsigned-local"
    ),
    "local_risk_register": _binding(
        "grc_engine.create_risk and LocalStore", "unsigned-local"
    ),
    "local_poam": _binding(
        "grc_engine.create_poam and LocalStore", "unsigned-local"
    ),
    "mock_grc_handoff": _binding(
        "grc_engine.create_mock_handoff and LocalStore", "local-mock-only"
    ),
    "mock_tenant_review": _binding(
        "grc_engine.decide_mock_handoff and LocalStore", "local-mock-only"
    ),
    "vendor_carry_forward": _binding(
        "grc_engine.create_vendor_assessment and LocalStore", "unsigned-local"
    ),
    "workflow_speed_metrics": _binding(
        "grc_engine.speed_story over LocalStore", "unsigned-local-observation"
    ),
    "platform_assessment_adapter": _binding(
        (
            "maverick.assessment adapter (analysis only)"
            if PLATFORM_ENGINE
            else "Not bound: Lightwork core analysis is unavailable or forced off"
        ),
        "analysis-only-no-platform-authority",
        PLATFORM_ENGINE,
    ),
    "expanded_security_catalog": _binding(
        (
            "maverick.assessment security templates"
            if PLATFORM_ENGINE
            else "Not bound: Lightwork core analysis is unavailable or forced off"
        ),
        "analysis-only-no-platform-authority",
        PLATFORM_ENGINE,
    ),
    "full_framework_catalog": _integrated_only("/security"),
    "cross_framework_crosswalk": _integrated_only("/security"),
    "connected_evidence_sources": _integrated_only("/security"),
    "signed_audit": _integrated_only("/security"),
    "governed_approval": _integrated_only("/security"),
    "program_workspace": _integrated_only("/security"),
    "cross_run_learning": _integrated_only("/security"),
}


def _validate_capability_bindings() -> None:
    if set(CAPABILITY_BINDINGS) != set(CAPS):
        raise RuntimeError("GRC capability bindings do not match CAPS")
    for capability, enabled in CAPS.items():
        binding = CAPABILITY_BINDINGS[capability]
        if binding.get("active") is not enabled:
            raise RuntimeError(f"GRC capability binding drift: {capability}")
        if not binding.get("implementation") or not binding.get("authority"):
            raise RuntimeError(f"GRC capability binding is incomplete: {capability}")


_validate_capability_bindings()


def caps_summary() -> dict:
    summary = _caps_summary()
    summary["capabilities"] = [
        {
            "id": capability,
            "label": CAPABILITY_LABELS[capability],
            **CAPABILITY_BINDINGS[capability],
        }
        for capability in CAPS
    ]
    return summary

_PLATFORM_SECURITY_TYPES = (
    ("soc2", "soc2"),
    ("iso27001", "iso27001"),
    ("nist-csf", "nist_csf"),
    ("nist_800_53", "nist_800_53"),
    ("cis_v8", "cis_v8"),
    ("pci_dss", "pci_dss"),
    ("hipaa", "hipaa"),
    ("cmmc_l2", "cmmc_l2"),
    ("fedramp_moderate", "fedramp_moderate"),
)
_EVIDENCE_STOPWORDS = {
    "about",
    "according",
    "against",
    "appropriate",
    "controls",
    "ensure",
    "from",
    "have",
    "information",
    "must",
    "organization",
    "relevant",
    "requirements",
    "security",
    "that",
    "their",
    "these",
    "this",
    "with",
}


def _platform_templates() -> list[tuple[str, object]]:
    if _assessment is None:
        return []
    return [
        (public_id, _assessment.TEMPLATES[core_id])
        for public_id, core_id in _PLATFORM_SECURITY_TYPES
        if core_id in _assessment.TEMPLATES
    ]


def _evidence_terms(text: str) -> tuple[str, ...]:
    terms: list[str] = []
    for token in re.findall(r"[a-z0-9][a-z0-9_-]{3,}", text.lower()):
        if token not in _EVIDENCE_STOPWORDS and token not in terms:
            terms.append(token)
        if len(terms) == 8:
            break
    return tuple(terms)


def _adapt_template(public_id: str, template) -> dict:
    return {
        "id": public_id,
        "name": template.title,
        "version": template.framework,
        "description": template.description,
        "controls": [
            {
                "id": question.id,
                "family": question.section,
                "requirement": question.text,
                "severity": question.severity,
                "evidence_terms": _evidence_terms(
                    f"{question.text} {question.guidance}"
                ),
                "remediation": question.guidance,
            }
            for question in template.questions
        ],
        "engine": "lightwork_assessment",
        "authority": "unsigned_local_demo",
    }


def list_frameworks():
    if _assessment is None:
        return local.list_frameworks()
    return [
        {
            "id": public_id,
            "name": template.title,
            "version": template.framework,
            "controls": len(template.questions),
        }
        for public_id, template in _platform_templates()
    ]


def get_framework(framework: str):
    if _assessment is None:
        return local.get_framework(framework)
    if not isinstance(framework, str):
        raise ValueError("framework must be a string")
    match = next(
        (item for item in _platform_templates() if item[0] == framework), None
    )
    if match is None:
        raise ValueError(f"unknown framework: {framework}")
    return _adapt_template(*match)


def _platform_score(framework: str, answers: dict, subject: str) -> dict:
    if not isinstance(answers, dict):
        raise ValueError("answers must be an object keyed by control id")
    bounded_subject = str(subject or "").strip()
    if not bounded_subject or len(bounded_subject) > 300:
        raise ValueError("subject must contain 1 to 300 characters")
    match = next(
        (item for item in _platform_templates() if item[0] == framework), None
    )
    if match is None:
        raise ValueError(f"unknown framework: {framework}")
    _, template = match
    known_ids = {question.id for question in template.questions}
    unexpected = set(answers).difference(known_ids)
    if unexpected:
        raise ValueError(f"unknown control answers: {sorted(unexpected)}")

    class _PinnedSession(_assessment.AssessmentSession):
        def template(self):
            return template

    session = _PinnedSession(type=template.type, subject=bounded_subject)
    for question in template.questions:
        answer = answers.get(question.id, "unknown")
        if not isinstance(answer, str):
            raise ValueError(f"invalid answer for {question.id}")
        session.record(question.id, answer)
    result = session.evaluate()
    weights = {"high": 3, "medium": 2, "low": 1}
    possible = sum(weights[question.severity] for question in template.questions)
    gap_score = sum(weights[finding.severity] for finding in result.findings)
    return {
        "id": session.id,
        "type": "assessment",
        "framework": framework,
        "subject": bounded_subject,
        "posture": f"{result.risk_rating} risk",
        "score": round((1 - gap_score / possible) * 100) if possible else 100,
        "answered": result.answered,
        "total": result.total,
        "inherent_risk": result.inherent_risk,
        "residual_risk": result.residual_risk,
        "controls_in_place": result.controls_in_place,
        "findings": [
            {
                "control_id": finding.question_id,
                "severity": finding.severity,
                "answer": finding.answer,
                "kind": finding.kind,
                "requirement": finding.question,
                "remediation": finding.recommendation,
            }
            for finding in result.findings
        ],
        "engine": "lightwork_assessment",
        "authority": "unsigned_local_demo",
    }


def score_questionnaire(framework: str, answers: dict, subject: str = ""):
    if _assessment is not None:
        return _platform_score(framework, answers, subject)
    return local.score_questionnaire(framework, answers, subject)


def evaluate_evidence(framework: str, text: str, source: str = "pasted evidence"):
    if _assessment is None:
        return local.evaluate_evidence(framework, text, source)
    return local.evaluate_controls(get_framework(framework)["controls"], text, source)


def create_risk(*args, **kwargs):
    return local.create_risk(*args, **kwargs)


def create_poam(*args, **kwargs):
    return local.create_poam(*args, **kwargs)


def create_vendor_assessment(*args, **kwargs):
    return local.create_vendor_assessment(*args, **kwargs)


def create_mock_handoff(*args, **kwargs):
    return local.create_mock_handoff(*args, **kwargs)


def decide_mock_handoff(*args, **kwargs):
    return local.decide_mock_handoff(*args, **kwargs)


def save_record(record: dict, expected_revision: int):
    return STORE.save(record, expected_revision)


def replace_record(record_id: str, record: dict, expected_revision: int):
    return STORE.replace(record_id, record, expected_revision)


def list_records(kind: str | None = None):
    return STORE.list_records(kind)


def get_record(record_id: str):
    return STORE.get_record(record_id)


def current_revision() -> int:
    return STORE.current_revision()


def speed_story() -> dict:
    return local.speed_story(STORE.list_records())


__all__ = [
    "CAPS",
    "CAPABILITY_BINDINGS",
    "FORCED_STANDALONE",
    "PLATFORM_ENGINE",
    "STANDALONE",
    "caps_summary",
    "list_frameworks",
    "get_framework",
    "score_questionnaire",
    "evaluate_evidence",
    "create_risk",
    "create_poam",
    "create_vendor_assessment",
    "create_mock_handoff",
    "decide_mock_handoff",
    "save_record",
    "replace_record",
    "list_records",
    "get_record",
    "current_revision",
    "speed_story",
]
