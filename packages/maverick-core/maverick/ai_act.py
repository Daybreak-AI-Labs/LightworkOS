"""EU AI Act risk-classification helper.

The EU AI Act (Regulation 2024/1689; transparency duties enforceable Aug 2 2026)
sorts AI systems into risk tiers: **prohibited** (Art. 5), **high-risk**
(Annex III), **limited-risk** (Art. 50 transparency), and minimal. The tier
determines the obligations — and the tier depends on the *use case*, which only
the operator knows.

So this helper does the honest thing: it reports what Lightwork *can* determine —
the deployment's live Art. 50 transparency posture — and hands the operator a
self-assessment checklist of the prohibited and high-risk categories plus the
obligations each tier triggers. A conversational agent that discloses it is AI is
**limited-risk by default**, but the operator must rule out the prohibited and
high-risk lists for their own deployment.

Fail-soft and import-light like :mod:`maverick.ropa`. Surfaced as
``maverick ai-act``.
"""
from __future__ import annotations

import time
from typing import Any

AI_ACT_DISCLAIMER = (
    "Self-assessment aid, not a legal classification or attestation. The AI Act "
    "tier depends on your use case; rule out the prohibited and high-risk lists "
    "below for your deployment and have qualified counsel confirm the result."
)

# Art. 5 — prohibited practices (abridged for self-assessment).
_PROHIBITED: tuple[str, ...] = (
    "Subliminal / manipulative techniques that distort behaviour and cause harm",
    "Exploiting vulnerabilities of age, disability, or socio-economic situation",
    "Social scoring leading to detrimental or disproportionate treatment",
    "Predicting criminal offences from profiling / personality alone",
    "Untargeted scraping of facial images to build recognition databases",
    "Emotion inference in the workplace or education (save medical/safety)",
    "Biometric categorisation inferring race, politics, religion, sexual orientation",
    "Real-time remote biometric identification in public for law enforcement",
)

# Annex III — high-risk domains (abridged for self-assessment).
_HIGH_RISK: tuple[str, ...] = (
    "Biometric identification / categorisation",
    "Critical infrastructure (safety components)",
    "Education and vocational training (access, scoring, proctoring)",
    "Employment (recruitment, screening, task allocation, monitoring)",
    "Access to essential private/public services (credit, benefits, insurance)",
    "Law enforcement",
    "Migration, asylum, and border control",
    "Administration of justice and democratic processes",
)


def _safe(fn, default):
    try:
        return fn()
    except BaseException:  # noqa: BLE001 -- never crash on a posture probe
        return default


def _transparency_posture() -> dict[str, Any]:
    """Live Art. 50 status, read from the compliance report."""
    from .compliance import compliance_report

    for c in compliance_report():
        if c.regulation.startswith("EU AI Act Art. 50"):
            return {"disclosure_active": c.status == "active", "detail": c.detail}
    return {"disclosure_active": False, "detail": "transparency disclosure not found"}


def assess_ai_act() -> dict[str, Any]:
    """Report the deployment's AI Act posture + a classification checklist."""
    posture = _safe(_transparency_posture, {"disclosure_active": False, "detail": ""})
    return {
        "framework": "EU AI Act (Reg. 2024/1689) risk classification — self-assessment",
        "generated_at": time.time(),
        "default_classification": (
            "Limited risk (Art. 50). A conversational AI agent that discloses it is "
            "AI is limited-risk by default — provided it is NOT in any prohibited "
            "(Art. 5) or high-risk (Annex III) category below."
        ),
        "transparency_obligation_art50": posture,
        "self_assessment": {
            "prohibited_art5": list(_PROHIBITED),
            "high_risk_annex_iii": list(_HIGH_RISK),
            "instruction": (
                "Confirm NONE of the prohibited practices apply (else the system is "
                "banned), then check whether your use falls in any high-risk domain."
            ),
        },
        "obligations_by_tier": {
            "limited_risk_art50": (
                "Inform users they are interacting with AI (Lightwork does this via "
                "the first-turn disclosure) and mark AI-generated content."
            ),
            "high_risk_annex_iii": (
                "Risk management, data governance, technical documentation, "
                "record-keeping, human oversight, accuracy/robustness, and a "
                "conformity assessment before deployment."
            ),
            "prohibited_art5": "Not permitted to be placed on the market or used.",
        },
        "disclaimer": AI_ACT_DISCLAIMER,
    }


def render_ai_act_json(report: dict[str, Any]) -> str:
    import json
    return json.dumps(report, indent=2, default=str)


def render_ai_act_text(report: dict[str, Any]) -> str:
    head = "EU AI Act — risk classification (self-assessment)"
    lines = [head, "=" * len(head), ""]

    p = report["transparency_obligation_art50"]
    status = "MET" if p.get("disclosure_active") else "NOT MET"
    lines += [
        f"Default classification: {report['default_classification']}",
        "",
        f"Art. 50 transparency (AI disclosure): [{status}] {p.get('detail', '')}",
        "",
        "Self-assessment — confirm NONE of these PROHIBITED practices (Art. 5) apply:",
    ]
    lines += (f"  [ ] {x}" for x in report["self_assessment"]["prohibited_art5"])
    lines += ["", "Then check whether your use is HIGH-RISK (Annex III):"]
    lines += (f"  [ ] {x}" for x in report["self_assessment"]["high_risk_annex_iii"])

    obl = report["obligations_by_tier"]
    lines += [
        "",
        "Obligations by tier:",
        f"  - Limited risk (Art. 50): {obl['limited_risk_art50']}",
        f"  - High risk (Annex III):  {obl['high_risk_annex_iii']}",
        f"  - Prohibited (Art. 5):    {obl['prohibited_art5']}",
        "",
        report["disclaimer"],
    ]
    return "\n".join(lines)


__all__ = [
    "AI_ACT_DISCLAIMER",
    "assess_ai_act",
    "render_ai_act_json",
    "render_ai_act_text",
]
