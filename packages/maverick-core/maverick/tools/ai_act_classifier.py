"""EU AI Act risk classification helper.

A deterministic, keyword-driven *triage* aid: describe an AI system/use-case
and it returns the EU AI Act risk tier it most likely falls under —
**prohibited** (Art. 5), **high-risk** (Annex III), **limited-risk**
(transparency obligations), or **minimal** — with the matched category and the
headline obligations. It is a screening helper for the regulated-enterprise
audience Lightwork targets, NOT legal advice; the output says so.

ops:
  - classify(description)  — tier + matched categories + obligations.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# (category label, [keyword/phrase regexes]). Tiers checked most-severe first.
_PROHIBITED: list[tuple[str, list[str]]] = [
    ("social scoring", [r"social scor", r"social credit"]),
    ("subliminal / manipulative techniques", [r"subliminal", r"manipulat\w* behaviou?r", r"exploit\w* vulnerab"]),
    ("untargeted facial scraping", [r"scrap\w* (?:facial|face)", r"facial recognition database", r"untargeted facial"]),
    ("emotion recognition at work/school", [r"emotion recognition.*(?:workplace|employ|school|education)", r"(?:workplace|school).*emotion recognition"]),
    ("real-time remote biometric ID in public", [r"real[- ]time.*biometric", r"live facial recognition.*public"]),
]
_HIGH_RISK: list[tuple[str, list[str]]] = [
    ("biometric identification", [r"biometric", r"facial recognition", r"fingerprint", r"iris scan"]),
    ("critical infrastructure", [r"critical infrastructure", r"power grid", r"water supply", r"traffic control"]),
    ("education / vocational training", [r"\bexam\b", r"student assessment", r"admission", r"grading", r"proctor"]),
    ("employment / worker management", [r"recruit", r"hiring", r"\bcv\b|resume screening", r"employee monitoring", r"promotion decision"]),
    ("essential services & creditworthiness", [r"credit scor", r"creditworth", r"loan approval", r"insurance pricing", r"benefits eligibility", r"welfare"]),
    ("law enforcement", [r"law enforcement", r"\bpolice\b", r"crime predict", r"recidivism", r"predictive policing"]),
    ("migration / border control", [r"\bborder\b", r"asylum", r"\bvisa\b", r"migration"]),
    ("administration of justice", [r"judicial", r"\bcourt\b", r"legal decision", r"sentencing"]),
]
_LIMITED: list[tuple[str, list[str]]] = [
    ("AI interacting with people (chatbot)", [r"chatbot", r"conversational agent", r"virtual assistant", r"customer support bot"]),
    ("synthetic/manipulated media (deepfake)", [r"deepfake", r"synthetic media", r"face swap", r"voice clon"]),
    ("emotion recognition (disclosure)", [r"emotion recognition", r"sentiment analysis"]),
]

_OBLIGATIONS = {
    "prohibited": "Prohibited under Article 5 — must not be placed on the market or used in the EU.",
    "high-risk": ("High-risk (Annex III): conformity assessment, risk-management system, "
                  "data governance, technical documentation, logging, human oversight, "
                  "accuracy/robustness, and EU-database registration."),
    "limited-risk": "Limited-risk: transparency obligations (disclose AI interaction / label synthetic content).",
    "minimal": "Minimal-risk: no mandatory obligations under the Act; voluntary codes of conduct apply.",
}


def _matches(desc: str, groups: list[tuple[str, list[str]]]) -> list[str]:
    hits = []
    for label, patterns in groups:
        if any(re.search(p, desc) for p in patterns):
            hits.append(label)
    return hits


def _classify(description: str) -> str:
    desc = description.lower()
    for tier, groups in (("prohibited", _PROHIBITED), ("high-risk", _HIGH_RISK), ("limited-risk", _LIMITED)):
        cats = _matches(desc, groups)
        if cats:
            return (
                f"tier: {tier.upper()}\n"
                f"matched: {', '.join(cats)}\n"
                f"obligations: {_OBLIGATIONS[tier]}\n"
                "— heuristic screening only, not legal advice; confirm against the Act's text."
            )
    return (
        "tier: MINIMAL\n"
        f"obligations: {_OBLIGATIONS['minimal']}\n"
        "— heuristic screening only, not legal advice; confirm against the Act's text."
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "classify"):
        return f"ERROR: unknown op {args.get('op')!r}"
    description = args.get("description")
    if not isinstance(description, str) or not description.strip():
        return "ERROR: description (string) is required"
    return _classify(description)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["classify"]},
        "description": {"type": "string", "description": "the AI system / use-case to classify"},
    },
    "required": ["description"],
}


def ai_act_classifier() -> Tool:
    return Tool(
        name="ai_act_classifier",
        description=(
            "EU AI Act risk-tier screening for a described AI use-case: returns "
            "prohibited (Art. 5) / high-risk (Annex III) / limited-risk "
            "(transparency) / minimal, with the matched category and headline "
            "obligations. op=classify with 'description'. Deterministic keyword "
            "heuristic — a triage aid, explicitly not legal advice."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
