"""Privacy & security control catalog -- "find the control for this risk".

A privacy/security analyst's core move is mapping a risk to the specific control
that closes it and citing the authoritative framework reference. This module is
that catalog: each :class:`Control` states the control and its references across
GDPR, the EU AI Act, ISO/IEC 27001:2022, SOC 2 (Trust Services Criteria), the
NIST Cybersecurity Framework, and HIPAA. :func:`find_controls` looks one up by
keyword.

It grounds the analyst agent's recommendations in a consistent, citable catalog
instead of model recall, and the same catalog backs the assessment remediations
and (later) the security assessor. Surfaced to agents as the ``find_controls``
tool and to people via ``maverick controls``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    id: str
    title: str                      # the control statement
    theme: str                      # risk area
    frameworks: dict[str, str]      # framework -> reference (article/clause/criterion)
    keywords: tuple[str, ...] = ()

    def search_text(self) -> str:
        return " ".join((
            self.id, self.title, self.theme,
            " ".join(self.frameworks), " ".join(self.frameworks.values()),
            " ".join(self.keywords),
        )).lower()


def _c(cid, title, theme, frameworks, keywords):
    return Control(cid, title, theme, frameworks, tuple(keywords))


CONTROLS: tuple[Control, ...] = (
    _c("AC-1", "Enforce least-privilege access and multi-factor authentication",
       "access control",
       {"GDPR": "Art. 32", "ISO 27001": "A.5.15 / A.8.5", "SOC 2": "CC6.1",
        "NIST CSF": "PR.AC-1", "HIPAA": "§164.312(a)"},
       ["access", "mfa", "authentication", "least privilege", "rbac", "login"]),
    _c("CR-1", "Encrypt personal data at rest (AES-256)", "encryption",
       {"GDPR": "Art. 32", "ISO 27001": "A.8.24", "SOC 2": "CC6.1",
        "NIST CSF": "PR.DS-1", "HIPAA": "§164.312(a)(2)(iv)"},
       ["encryption", "at rest", "aes", "storage", "disk"]),
    _c("CR-2", "Encrypt data in transit (TLS 1.2+)", "encryption",
       {"GDPR": "Art. 32", "ISO 27001": "A.8.24", "SOC 2": "CC6.7",
        "NIST CSF": "PR.DS-2"},
       ["encryption", "transit", "tls", "https", "network"]),
    _c("VN-1", "Bind processors with a data-processing agreement (DPA)",
       "vendor management",
       {"GDPR": "Art. 28", "ISO 27001": "A.5.19", "SOC 2": "CC9.2"},
       ["dpa", "processor", "vendor", "contract", "third party", "subprocessor"]),
    _c("VN-2", "Maintain and monitor a disclosed subprocessor list",
       "vendor management",
       {"GDPR": "Art. 28(2)", "ISO 27001": "A.5.21", "SOC 2": "CC9.2"},
       ["subprocessor", "vendor", "supply chain", "fourth party"]),
    _c("RT-1", "Define and enforce a retention schedule with secure disposal",
       "retention",
       {"GDPR": "Art. 5(1)(e) / Art. 17", "ISO 27001": "A.8.10",
        "NIST CSF": "PR.IP-6"},
       ["retention", "deletion", "disposal", "storage limitation", "purge"]),
    _c("LM-1", "Keep tamper-evident audit logs of access and processing",
       "logging & monitoring",
       {"GDPR": "Art. 5(2) / Art. 30", "ISO 27001": "A.8.15", "SOC 2": "CC7.2",
        "NIST CSF": "DE.CM", "HIPAA": "§164.312(b)"},
       ["logging", "audit", "monitoring", "accountability", "traceability"]),
    _c("IR-1", "Maintain an incident-response plan with breach notification",
       "incident response",
       {"GDPR": "Art. 33 / Art. 34", "ISO 27001": "A.5.24-A.5.26",
        "SOC 2": "CC7.3", "NIST CSF": "RS.RP", "HIPAA": "§164.410"},
       ["incident", "breach", "notification", "72 hours", "response", "sla"]),
    _c("DM-1", "Collect only the personal data necessary for the purpose",
       "data minimization",
       {"GDPR": "Art. 5(1)(c)", "ISO 27001": "A.8.10"},
       ["minimization", "necessity", "purpose limitation", "over-collection"]),
    _c("LB-1", "Establish a documented lawful basis (and valid consent)",
       "lawful basis",
       {"GDPR": "Art. 6 / Art. 7"},
       ["lawful basis", "consent", "legitimate interest", "legal basis"]),
    _c("DR-1", "Provide data-subject access, erasure, and portability (DSAR)",
       "data-subject rights",
       {"GDPR": "Art. 15-20"},
       ["dsar", "access", "erasure", "portability", "rights", "deletion request"]),
    _c("IT-1", "Safeguard international transfers (adequacy / SCCs)",
       "international transfers",
       {"GDPR": "Art. 44-49 (Chapter V)"},
       ["transfer", "international", "scc", "adequacy", "cross-border", "eu"]),
    _c("RA-1", "Run a DPIA for high-risk processing", "risk assessment",
       {"GDPR": "Art. 35", "ISO 27001": "A.5.8", "NIST CSF": "ID.RA"},
       ["dpia", "risk assessment", "impact assessment", "high risk"]),
    _c("AI-1", "Provide meaningful human oversight of AI decisions",
       "ai governance",
       {"EU AI Act": "Art. 14", "NIST AI RMF": "GOVERN/MANAGE"},
       ["human oversight", "human in the loop", "ai", "automated decision"]),
    _c("AI-2", "Disclose AI interaction and AI-generated content",
       "ai transparency",
       {"EU AI Act": "Art. 50"},
       ["transparency", "disclosure", "ai", "chatbot", "deepfake"]),
    _c("AI-3", "Evaluate AI systems for bias and accuracy", "ai fairness",
       {"EU AI Act": "Art. 10 / Art. 15", "NIST AI RMF": "MEASURE"},
       ["bias", "fairness", "accuracy", "robustness", "drift", "ai"]),
    _c("BC-1", "Maintain tested backups and a business-continuity / DR plan",
       "resilience",
       {"ISO 27001": "A.8.13 / A.5.29-A.5.30", "SOC 2": "A1.2",
        "NIST CSF": "RC.RP"},
       ["backup", "business continuity", "disaster recovery", "dr", "resilience"]),
)


def find_controls(query: str, *, limit: int = 5) -> list[Control]:
    """Return the controls best matching ``query`` (a risk / topic), best first.

    Scored by how many of the query's words appear in each control's searchable
    text; ties keep catalog order. Returns up to ``limit`` controls with a
    non-zero match, or [] when nothing matches.
    """
    words = [w for w in (query or "").lower().split() if len(w) > 2]
    if not words:
        return []
    scored: list[tuple[int, int, Control]] = []
    for i, c in enumerate(CONTROLS):
        text = c.search_text()
        score = sum(1 for w in words if w in text)
        if score:
            scored.append((score, -i, c))
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [c for _, _, c in scored[:limit]]


def render_control(c: Control) -> str:
    refs = "; ".join(f"{fw} {ref}" for fw, ref in c.frameworks.items())
    return f"{c.id}: {c.title}\n   theme: {c.theme}\n   references: {refs}"


__all__ = ["Control", "CONTROLS", "find_controls", "render_control"]
