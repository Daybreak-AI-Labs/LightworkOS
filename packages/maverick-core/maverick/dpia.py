"""GDPR Article 35 — Data Protection Impact Assessment (DPIA) generator.

A DPIA is required when processing is "likely to result in a high risk to the
rights and freedoms of natural persons" (Art. 35(1)) — and running an autonomous
agent over personal data usually qualifies. Art. 35(7) fixes the contents: a
description of the processing (a), an assessment of necessity/proportionality
(b), an assessment of the risks (c), and the measures envisaged to address them
(d).

Lightwork can pre-fill the parts it knows. The differentiated half is the **risk
register**: the risks specific to running an AI agent on personal data — data
egress to an LLM, unsupervised automated action, audit tampering, indefinite
retention — each mapped to the Lightwork control that mitigates it and whether
that control is *active right now* (read live from the compliance report). The
necessity/proportionality judgement and the residual-risk sign-off are left to
the controller.

Like :mod:`maverick.ropa` and :mod:`maverick.soc2`, this is fail-soft and
import-light — it never raises. Surfaced as ``maverick dpia``.
"""
from __future__ import annotations

import time
from typing import Any

from .ropa import FILL_IN

DPIA_DISCLAIMER = (
    "Pre-filled Art. 35 scaffold derived from this deployment's configuration -- "
    "not a completed DPIA or a legal attestation. The controller must complete the "
    "necessity/proportionality assessment, judge residual risk, and (where high "
    "risk remains) consult the supervisory authority (Art. 36); a DPO / qualified "
    "counsel must review it."
)

# Each agent-on-personal-data risk, keyed by the compliance control that mitigates
# it. The live status of that control (active / action_needed) is joined in at
# generation time, so an unmitigated risk shows up as OPEN automatically.
_RISK_FRAMING: dict[str, str] = {
    "Data-egress control":
        "Personal data is transmitted to a third-party LLM provider -- loss of "
        "confidentiality and an international transfer without safeguards.",
    "Encryption at rest":
        "Personal data on disk is readable by anyone with host / file access.",
    "Human oversight (consent gating)":
        "The agent takes unsupervised, irreversible actions affecting data subjects "
        "(cf. Art. 22 automated decision-making).",
    "Tamper-evident audit":
        "The audit trail is altered or forged, defeating accountability (Art. 5(2)).",
    "Storage limitation (retention)":
        "Personal data is retained indefinitely, beyond what is necessary "
        "(Art. 5(1)(e)).",
    "Secret/PII redaction in logs":
        "Secrets or personal data leak into operational logs.",
}

# Map a compliance status to the DPIA risk-treatment vocabulary.
_TREATMENT = {
    "active": "mitigated",
    "available": "available (invoke on demand)",
    "action_needed": "OPEN -- mitigation available but not enabled",
}


def _safe(fn, default):
    try:
        return fn()
    except BaseException:  # noqa: BLE001 -- a DPIA snapshot must never crash
        return default


def _risk_register() -> list[dict[str, str]]:
    from .compliance import compliance_report

    by_control = {c.control: c for c in compliance_report()}
    register: list[dict[str, str]] = []
    for control, risk in _RISK_FRAMING.items():
        c = by_control.get(control)
        if c is None:
            continue
        register.append({
            "risk": risk,
            "mitigation": f"{control}: {c.detail}",
            "treatment": _TREATMENT.get(c.status, c.status),
        })
    return register


def _description_of_processing() -> dict[str, Any]:
    """Art. 35(7)(a): reuse the ROPA so the DPIA and the Art. 30 record agree."""
    from .ropa import generate_ropa

    ropa = generate_ropa()
    proc = ropa.get("processing", {})
    return {
        "purposes": proc.get("purposes", FILL_IN),
        "data_subjects": proc.get("data_subjects", []),
        "personal_data_categories": proc.get("personal_data_categories", []),
        "recipients": ropa.get("recipients", []),
        "international_transfers": ropa.get("international_transfers", FILL_IN),
        "retention": ropa.get("retention", FILL_IN),
    }


def generate_dpia() -> dict[str, Any]:
    """Assemble a pre-filled Art. 35 DPIA from this deployment. Never raises."""
    register = _safe(_risk_register, [])
    open_risks = sum(1 for r in register if r["treatment"].startswith("OPEN"))
    return {
        "assessment_type": "GDPR Article 35 data protection impact assessment",
        "generated_at": time.time(),
        "description_of_processing": _safe(_description_of_processing, {}),
        "necessity_and_proportionality": (
            f"{FILL_IN} (Art. 35(7)(b) -- justify that the processing is necessary "
            "and proportionate to the purposes)"
        ),
        "risk_register": register,
        "open_risk_count": open_risks,
        "residual_risk_assessment": (
            f"{FILL_IN} (Art. 35(7)(c)/(d) -- after the measures above, judge the "
            "residual risk; if it stays high, consult the supervisory authority "
            "under Art. 36)"
        ),
        "disclaimer": DPIA_DISCLAIMER,
    }


def render_dpia_json(dpia: dict[str, Any]) -> str:
    import json
    return json.dumps(dpia, indent=2, default=str)


def render_dpia_text(dpia: dict[str, Any]) -> str:
    head = "GDPR Art. 35 — Data Protection Impact Assessment (scaffold)"
    lines = [head, "=" * len(head), ""]

    desc = dpia["description_of_processing"]
    lines += [
        "1. Description of the processing (Art. 35(7)(a))",
        f"   Purposes:      {desc.get('purposes', '')}",
        f"   Data subjects: {', '.join(desc.get('data_subjects', []))}",
        f"   Recipients:    {'; '.join(desc.get('recipients', []))}",
        f"   Transfers:     {desc.get('international_transfers', '')}",
        f"   Retention:     {desc.get('retention', '')}",
        "   Personal-data categories:",
    ]
    for c in desc.get("personal_data_categories", []):
        lines.append(f"     - {c['category']} ({c['store']})")
    lines += [
        "",
        "2. Necessity and proportionality (Art. 35(7)(b))",
        f"   {dpia['necessity_and_proportionality']}",
        "",
        "3. Risks to data subjects and measures (Art. 35(7)(c)/(d))",
    ]
    for r in dpia["risk_register"]:
        lines += [
            f"   [{r['treatment']}]",
            f"     risk:     {r['risk']}",
            f"     measure:  {r['mitigation']}",
        ]
    lines += [
        "",
        f"   Open risks (mitigation available but off): {dpia['open_risk_count']}",
        "",
        "4. Residual risk",
        f"   {dpia['residual_risk_assessment']}",
        "",
        dpia["disclaimer"],
    ]
    return "\n".join(lines)


__all__ = [
    "DPIA_DISCLAIMER",
    "generate_dpia",
    "render_dpia_json",
    "render_dpia_text",
]
