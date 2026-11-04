"""Curated regulatory starter corpora for the knowledge plane.

Ships a small, licensing-clean grounding corpus so a privacy/GRC/AI-security
specialist can cite the governing regulation out of the box instead of
retrieving nothing until a customer uploads documents. Every entry is an
ORIGINAL plain-language summary of a PUBLIC-DOMAIN framework (EU/US law and a
US-government framework), each anchored to the article/section it summarizes —
not a reproduction of copyrighted standard text. Redistributable standards
(e.g. ISO) are deliberately excluded; a customer layers their licensed copies
on top.

The documents are ingested into the suite collections the shipped packs already
point at (``itgrc`` for IT-GRC/privacy/security, ``legal`` for legal). Ingestion
runs through the normal :meth:`KnowledgeBase.ingest_text` path, so each chunk is
provenance-stamped (``source``, ``sensitivity="public"``, ``trust_tier=3``) and
content-hashed — re-seeding is idempotent per document.
"""
from __future__ import annotations

from typing import Any

# Each corpus: (collection, title, [(source, text), ...]). ``source`` is the
# citation shown to the model; ``text`` is the summary body.
_CORPORA: list[dict[str, Any]] = [
    {
        "collection": "itgrc",
        "title": "EU GDPR — core obligations (summary)",
        "documents": [
            (
                "GDPR Art. 5 — Principles",
                "GDPR Article 5 sets the principles for processing personal data: "
                "lawfulness, fairness and transparency; purpose limitation (collect "
                "for specified, explicit, legitimate purposes only); data "
                "minimisation (adequate, relevant and limited to what is necessary); "
                "accuracy; storage limitation (keep no longer than necessary); "
                "integrity and confidentiality (appropriate security); and "
                "accountability — the controller must be able to demonstrate "
                "compliance with all of the above.",
            ),
            (
                "GDPR Art. 6 — Lawful basis",
                "GDPR Article 6 requires a lawful basis for every processing "
                "activity: consent, performance of a contract, a legal obligation, "
                "vital interests, a public-interest task, or legitimate interests "
                "(balanced against the data subject's rights). Without a documented "
                "lawful basis the processing is unlawful.",
            ),
            (
                "GDPR Art. 9 — Special-category data",
                "GDPR Article 9 prohibits processing special-category data (health, "
                "biometrics, genetics, race/ethnicity, political/religious beliefs, "
                "trade-union membership, sex life/orientation) unless a specific "
                "condition applies — e.g. explicit consent, a substantial public "
                "interest with a legal basis, or medical/employment-law grounds.",
            ),
            (
                "GDPR Arts. 12-14 — Transparency",
                "GDPR Articles 12-14 require controllers to inform data subjects, in "
                "concise and plain language, about the identity of the controller, "
                "the purposes and lawful basis of processing, recipients, retention "
                "periods, international transfers, and their rights — at collection "
                "(Art. 13) or within a reasonable period when data is obtained "
                "indirectly (Art. 14).",
            ),
            (
                "GDPR Arts. 15-22 — Data-subject rights",
                "GDPR Chapter III grants data subjects the rights of access (Art. "
                "15), rectification (Art. 16), erasure / 'right to be forgotten' "
                "(Art. 17), restriction (Art. 18), data portability (Art. 20), "
                "objection (Art. 21), and not to be subject to solely automated "
                "decisions with legal or similarly significant effects (Art. 22). "
                "Requests must generally be answered within one month.",
            ),
            (
                "GDPR Art. 30 — Records of processing (ROPA)",
                "GDPR Article 30 requires controllers and processors to maintain a "
                "record of processing activities: purposes, categories of data "
                "subjects and personal data, recipients, international transfers, "
                "retention periods, and a general description of security measures. "
                "This ROPA is a primary artefact requested in a supervisory-authority "
                "audit.",
            ),
            (
                "GDPR Arts. 33-34 — Breach notification",
                "GDPR Article 33 requires notifying the supervisory authority of a "
                "personal-data breach without undue delay and, where feasible, within "
                "72 hours of becoming aware, unless the breach is unlikely to risk "
                "individuals' rights. Article 34 requires notifying affected data "
                "subjects without undue delay when the breach is likely to result in "
                "a high risk to them.",
            ),
            (
                "GDPR Art. 35 — Data Protection Impact Assessment",
                "GDPR Article 35 requires a Data Protection Impact Assessment (DPIA) "
                "before processing that is likely to result in a high risk to "
                "individuals — notably large-scale processing of special-category "
                "data, systematic monitoring of a public area, or systematic and "
                "extensive profiling with legal/significant effects. The DPIA "
                "describes the processing, assesses necessity and proportionality, "
                "and identifies measures to mitigate the risks.",
            ),
            (
                "GDPR Arts. 44-49 — International transfers",
                "GDPR Chapter V restricts transfers of personal data outside the "
                "EU/EEA. A transfer needs an adequacy decision (Art. 45), appropriate "
                "safeguards such as Standard Contractual Clauses or Binding Corporate "
                "Rules (Art. 46), or a specific derogation (Art. 49). Absent one of "
                "these, the transfer is unlawful.",
            ),
        ],
    },
    {
        "collection": "itgrc",
        "title": "EU AI Act — risk tiers (summary)",
        "documents": [
            (
                "EU AI Act — risk-based tiers",
                "The EU AI Act classifies AI systems by risk. Unacceptable-risk "
                "practices (e.g. social scoring by public authorities, manipulative "
                "or exploitative systems) are prohibited (Art. 5). High-risk systems "
                "(Annex III use cases such as employment, credit, biometric "
                "identification, and critical infrastructure) face conformity "
                "obligations. Limited-risk systems face transparency duties, and "
                "minimal-risk systems are largely unregulated.",
            ),
            (
                "EU AI Act — high-risk obligations",
                "Providers of high-risk AI systems must implement a risk-management "
                "system, data governance for training/validation data, technical "
                "documentation, record-keeping/logging, transparency and human "
                "oversight, and appropriate accuracy, robustness and cybersecurity, "
                "and register the system before placing it on the market. Deployers "
                "have their own use, monitoring and human-oversight duties.",
            ),
            (
                "EU AI Act — transparency (Art. 50)",
                "The EU AI Act requires transparency for certain systems: users must "
                "be told when they are interacting with an AI system, AI-generated or "
                "manipulated media (including deepfakes) must be disclosed, and "
                "emotion-recognition or biometric-categorisation use must be "
                "communicated to affected persons.",
            ),
            (
                "EU AI Act — general-purpose AI (GPAI)",
                "Providers of general-purpose AI models must maintain technical "
                "documentation, publish a summary of training-data content, and "
                "respect EU copyright law. Models presenting systemic risk carry "
                "additional obligations: model evaluation, adversarial testing, "
                "systemic-risk assessment and mitigation, incident reporting and "
                "cybersecurity protection.",
            ),
        ],
    },
    {
        "collection": "itgrc",
        "title": "NIST AI Risk Management Framework (summary)",
        "documents": [
            (
                "NIST AI RMF — core functions",
                "The NIST AI Risk Management Framework (AI RMF 1.0) organises AI "
                "risk management into four functions. GOVERN establishes a culture "
                "of risk management and accountability across the AI lifecycle. MAP "
                "establishes context and identifies risks. MEASURE analyses, "
                "assesses and tracks the identified risks. MANAGE prioritises and "
                "acts on risks, allocating resources to the highest-priority ones. "
                "The functions are iterative, not sequential.",
            ),
            (
                "NIST AI RMF — trustworthiness characteristics",
                "NIST characterises trustworthy AI as valid and reliable; safe; "
                "secure and resilient; accountable and transparent; explainable and "
                "interpretable; privacy-enhanced; and fair with harmful bias "
                "managed. These characteristics are balanced against one another in "
                "context rather than maximised independently.",
            ),
            (
                "NIST — AI agents as an attack surface",
                "Emerging NIST and Treasury guidance treats AI agents as an active "
                "attack surface: prompt injection (direct and indirect), training- "
                "and retrieval-data poisoning, model extraction, and the use of "
                "agents themselves as attack surrogates. Recommended controls include "
                "auditable pipelines, least-privilege tool access, continuous "
                "monitoring, and human oversight of high-impact decisions.",
            ),
        ],
    },
    {
        "collection": "itgrc",
        "title": "US CCPA/CPRA — core rights (summary)",
        "documents": [
            (
                "CCPA/CPRA — consumer rights",
                "The California Consumer Privacy Act, as amended by the CPRA, grants "
                "consumers the rights to know what personal information is collected "
                "and how it is used and shared, to delete personal information, to "
                "correct inaccurate information, to opt out of the sale or sharing of "
                "personal information, and to limit the use of sensitive personal "
                "information. Businesses must honour these requests, generally within "
                "45 days, and cannot discriminate against consumers who exercise "
                "them.",
            ),
            (
                "CCPA/CPRA — sensitive personal information",
                "The CPRA created a category of sensitive personal information "
                "(government IDs, financial account access, precise geolocation, "
                "race/ethnicity, health, sex life/orientation, and contents of "
                "certain communications) and gave consumers the right to limit its "
                "use and disclosure to what is necessary to provide the requested "
                "service.",
            ),
        ],
    },
]


def available_corpora() -> list[dict[str, Any]]:
    """Summaries of the shipped starter corpora for `knowledge seed --list`."""
    return [
        {"collection": c["collection"], "title": c["title"],
         "documents": len(c["documents"])}
        for c in _CORPORA
    ]


def seed_corpora(kb, *, only: str | None = None,
                 ingested_by: str = "system:knowledge-seed") -> dict[str, int]:
    """Ingest the curated corpora into ``kb``. Returns ``{collection: chunks}``.

    ``only`` restricts to one collection. Each document is ingested as public,
    first-party reference material (``sensitivity="public"``, ``trust_tier=3``,
    no ``subject`` — reference corpora are never touched by subject erasure).
    Matching content reuses its admitted rows. Revised content replaces the
    prior source atomically only after embedding and provenance checks succeed.
    """
    report: dict[str, int] = {}
    for corpus in _CORPORA:
        collection = corpus["collection"]
        if only and collection != only:
            continue
        for source, text in corpus["documents"]:
            n = kb.ingest_text(
                collection, text, source=source,
                sensitivity="public", trust_tier=3, ingested_by=ingested_by,
                extra_meta={"corpus": corpus["title"]},
                replace_source=True,
            )
            report[collection] = report.get(collection, 0) + n
    return report
