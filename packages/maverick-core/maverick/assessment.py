"""Compliance assessment engine -- conduct PIAs, AIRAs, Vendor Risk Assessments.

This is the OneTrust-style assessment core: a structured questionnaire is run
against a *subject* (a processing activity, an AI system, a vendor), each answer
is scored, and the result is a completed assessment with **findings** and an
overall **risk rating**. Distinct from ``maverick ropa`` / ``dpia`` / ``ai-act``,
which generate a scaffold from Lightwork's *own* deployment config -- this assesses
an arbitrary third-party subject.

A template is plain data (:class:`AssessmentTemplate` -> :class:`Question`), so
new assessment types are added by appending to :data:`TEMPLATES`, not by writing
code. The frameworks built in here:

  - ``pia``         -- Privacy Impact Assessment (ISO 29134 / GDPR Art. 35 flavour)
  - ``aira``        -- AI Risk Assessment (NIST AI RMF / EU AI Act flavour)
  - ``vendor_risk`` -- Third-party / vendor risk assessment (TPRM flavour)
  - ``hipaa``       -- HIPAA Security Rule safeguards (45 CFR Part 164)
  - ``soc2``        -- SOC 2 Trust Services Criteria readiness (AICPA)
  - ``pci_dss``     -- PCI DSS v4.0 cardholder-data controls

The scoring is a transparent max-severity rollup: a question's *risk answer*
raises a finding at its severity; ``unknown`` raises an "unverified" finding
(diligence gap); ``na`` / the safe answer clear it. Overall rating = the highest
finding severity present.

The conversational assessor agent (``build_assessment_agent``) and its tools are
a thin layer on top of this engine, exactly as the intake agent sits on
:mod:`maverick.intake`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from .security_framework_catalog import (
    CIS_V81_SAFEGUARDS,
    CMMC_L2_PRACTICES,
    FEDRAMP_CLASS_C_CONTROLS,
    NIST_800_53_MODERATE,
    NIST_CSF_2_SUBCATEGORIES,
    SECURITY_CATALOG_PROVENANCE,
    SecurityPractice,
)

_log = logging.getLogger(__name__)

# Answer vocabulary. ``na`` = not applicable (clears the question); ``unknown`` =
# the assessor could not confirm it (a diligence gap, scored as "unverified").
ANSWERS = ("yes", "no", "na", "unknown")
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _new_session_id() -> str:
    return f"{int(time.time())}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class Question:
    id: str
    section: str
    text: str
    risk_answer: str  # the answer that indicates risk: "yes" or "no"
    severity: str  # "low" | "medium" | "high"
    guidance: str = ""  # how to remediate if this is a finding


@dataclass(frozen=True)
class AssessmentTemplate:
    type: str
    title: str
    framework: str
    description: str
    questions: tuple[Question, ...]
    # Governance identity of the exact questionnaire release. Built-in
    # declarations leave these empty; :func:`get_template` returns a copy with
    # the current monotonic pointer revision and content digest attached.
    revision: int = 0
    digest: str = ""
    custom: bool = False

    def question(self, qid: str) -> Question | None:
        return next((q for q in self.questions if q.id == qid), None)


@dataclass(frozen=True)
class Finding:
    question_id: str
    section: str
    question: str
    severity: str
    answer: str
    kind: str  # "risk" (gave the risky answer) | "unverified" (unknown)
    recommendation: str


@dataclass
class AssessmentResult:
    type: str
    subject: str
    risk_rating: str  # "high" | "medium" | "low" | "minimal" (= residual)
    findings: list[Finding]
    answered: int
    total: int
    # The GRC pair. INHERENT = the exposure the subject carries before
    # crediting any control: the rollup of every risk area that applies (any
    # in-scope answer, i.e. not "na"). RESIDUAL = what's left after the
    # controls the answers attest to: the findings rollup (risky answers +
    # unverified). ``risk_rating`` keeps carrying the residual value so every
    # existing consumer (demo, OneTrust filing, memory) is unchanged.
    inherent_risk: str = "minimal"
    residual_risk: str = "minimal"
    risks_in_scope: int = 0  # applicable risk areas (answered, not "na")
    controls_in_place: int = 0  # of those, mitigated by the safe answer


def _q(qid, section, text, risk_answer, severity, guidance=""):
    return Question(qid, section, text, risk_answer, severity, guidance)


# --- Built-in assessment templates ----------------------------------------

_PIA = AssessmentTemplate(
    type="pia",
    title="Privacy Impact Assessment",
    framework="ISO 29134 / GDPR Art. 35",
    description="Assess the privacy risk of a processing activity.",
    questions=(
        _q(
            "pia_necessity",
            "Necessity",
            "Is the personal data collected strictly necessary for the stated purpose?",
            "no",
            "high",
            "Minimize collection to what the purpose requires (Art. 5(1)(c)).",
        ),
        _q(
            "pia_lawful_basis",
            "Lawful basis",
            "Is there a documented lawful basis for the processing (Art. 6)?",
            "no",
            "high",
            "Identify and record a lawful basis before processing.",
        ),
        _q(
            "pia_special_category",
            "Lawful basis",
            "Does it process special-category data (health, biometrics, etc.) without an Art. 9 condition?",
            "yes",
            "high",
            "Establish an Art. 9 condition or stop processing special-category data.",
        ),
        _q(
            "pia_transparency",
            "Transparency",
            "Are data subjects informed of the processing (privacy notice, Art. 13/14)?",
            "no",
            "medium",
            "Provide a clear privacy notice at or before collection.",
        ),
        _q(
            "pia_rights",
            "Data-subject rights",
            "Can data subjects exercise access / erasure / portability rights?",
            "no",
            "medium",
            "Wire up DSAR handling (access, erasure, portability).",
        ),
        _q(
            "pia_retention",
            "Storage limitation",
            "Is there a defined retention period after which the data is deleted?",
            "no",
            "medium",
            "Set and enforce a retention schedule (Art. 5(1)(e)).",
        ),
        _q(
            "pia_security",
            "Security",
            "Is the personal data encrypted in transit and at rest?",
            "no",
            "high",
            "Encrypt in transit (TLS) and at rest (Art. 32).",
        ),
        _q(
            "pia_transfers",
            "International transfers",
            "Is personal data transferred outside the EU/EEA without a Chapter V safeguard?",
            "yes",
            "high",
            "Put an adequacy decision or SCCs in place before transferring.",
        ),
        _q(
            "pia_processors",
            "Processors",
            "Is every processor bound by a data-processing agreement (Art. 28)?",
            "no",
            "medium",
            "Execute an Art. 28 DPA with each processor.",
        ),
        _q(
            "pia_automated",
            "Automated decisions",
            "Does it make solely-automated decisions with legal/significant effects (Art. 22)?",
            "yes",
            "medium",
            "Add human review or an Art. 22 exception/safeguard.",
        ),
    ),
)

_AIRA = AssessmentTemplate(
    type="aira",
    title="AI Risk Assessment",
    framework="NIST AI RMF / EU AI Act",
    description="Assess the risk of an AI system.",
    questions=(
        _q(
            "aira_purpose",
            "Governance",
            "Is the AI system's purpose and intended use documented?",
            "no",
            "medium",
            "Document intended purpose, scope, and out-of-scope uses.",
        ),
        _q(
            "aira_prohibited",
            "Governance",
            "Could the system fall under an EU AI Act prohibited practice (Art. 5)?",
            "yes",
            "high",
            "Stop -- prohibited uses cannot be placed on the market.",
        ),
        _q(
            "aira_high_risk",
            "Governance",
            "Is the use case in a high-risk domain (Annex III) without a conformity assessment?",
            "yes",
            "high",
            "Run an Annex III conformity assessment before deployment.",
        ),
        _q(
            "aira_transparency",
            "Transparency",
            "Are users informed they are interacting with / subject to AI (Art. 50)?",
            "no",
            "medium",
            "Disclose AI use to affected users.",
        ),
        _q(
            "aira_oversight",
            "Human oversight",
            "Is there meaningful human oversight of the system's decisions (Art. 14)?",
            "no",
            "high",
            "Add a human-in-the-loop / override mechanism.",
        ),
        _q(
            "aira_bias",
            "Fairness",
            "Has the system been evaluated for bias across affected groups?",
            "no",
            "high",
            "Run a bias/fairness evaluation on representative data.",
        ),
        _q(
            "aira_accuracy",
            "Robustness",
            "Are accuracy / robustness metrics measured and monitored in production?",
            "no",
            "medium",
            "Define accuracy thresholds and monitor for drift.",
        ),
        _q(
            "aira_data_governance",
            "Data governance",
            "Is the training/operating data of known provenance and lawful to use?",
            "no",
            "high",
            "Establish data provenance and processing lawfulness.",
        ),
        _q(
            "aira_security",
            "Security",
            "Is the system protected against adversarial / prompt-injection attacks?",
            "no",
            "medium",
            "Add input validation and adversarial testing.",
        ),
        _q(
            "aira_logging",
            "Accountability",
            "Are the system's decisions logged for traceability (Art. 12)?",
            "no",
            "medium",
            "Enable tamper-evident decision logging.",
        ),
    ),
)

_VENDOR_RISK = AssessmentTemplate(
    type="vendor_risk",
    title="Vendor Risk Assessment",
    framework="Third-party risk management (TPRM)",
    description="Assess the security and privacy risk of a third-party vendor.",
    questions=(
        _q(
            "vr_soc2",
            "Certifications",
            "Does the vendor hold a current SOC 2 Type II (or ISO 27001) report?",
            "no",
            "high",
            "Request the report; treat absence as elevated risk.",
        ),
        _q(
            "vr_dpa",
            "Contractual",
            "Is a data-processing agreement (DPA) in place with the vendor?",
            "no",
            "high",
            "Execute a DPA before sharing personal data (Art. 28).",
        ),
        _q(
            "vr_encryption",
            "Security",
            "Does the vendor encrypt your data in transit and at rest?",
            "no",
            "high",
            "Require TLS in transit and encryption at rest.",
        ),
        _q(
            "vr_access_control",
            "Security",
            "Does the vendor enforce MFA and least-privilege access to your data?",
            "no",
            "medium",
            "Require MFA and role-based access controls.",
        ),
        _q(
            "vr_breach_history",
            "History",
            "Has the vendor had a reported data breach in the last 24 months?",
            "yes",
            "medium",
            "Review the breach, root cause, and remediation.",
        ),
        _q(
            "vr_subprocessors",
            "Subprocessors",
            "Does the vendor disclose its subprocessors and notify of changes?",
            "no",
            "medium",
            "Require a subprocessor list and change notification.",
        ),
        _q(
            "vr_data_location",
            "Data residency",
            "Is your data stored or processed outside the EU/EEA without safeguards?",
            "yes",
            "high",
            "Confirm data location and Chapter V transfer safeguards.",
        ),
        _q(
            "vr_incident_sla",
            "Incident response",
            "Does the contract commit the vendor to a breach-notification timeline?",
            "no",
            "medium",
            "Require a defined breach-notification SLA (e.g. 72h).",
        ),
        _q(
            "vr_deletion",
            "Offboarding",
            "Will the vendor return or delete your data on contract termination?",
            "no",
            "medium",
            "Require data return/deletion terms at offboarding.",
        ),
        _q(
            "vr_business_continuity",
            "Resilience",
            "Does the vendor have a tested business-continuity / DR plan?",
            "no",
            "low",
            "Request BC/DR evidence proportional to criticality.",
        ),
    ),
)

# --- Finance assessment templates (finance-agent-suite §6) -----------------

_SOX_CONTROL = AssessmentTemplate(
    type="sox_control",
    title="SOX Control Assessment",
    framework="SOX §404 / COSO",
    description="Test the design + operating effectiveness of an ICFR control.",
    questions=(
        _q(
            "sox_evidence",
            "Operating effectiveness",
            "Is the control's operating effectiveness evidenced for the period?",
            "no",
            "high",
            "Obtain and retain sampled evidence of each execution.",
        ),
        _q(
            "sox_sod",
            "Segregation of duties",
            "Is there an SoD conflict in the roles responsible for this control?",
            "yes",
            "high",
            "Separate the incompatible duties (record/authorize/custody/reconcile).",
        ),
        _q(
            "sox_design",
            "Control design",
            "Does the control's design address the risk/assertion it is mapped to?",
            "no",
            "high",
            "Redesign the control to cover the assertion (existence/completeness/...).",
        ),
        _q(
            "sox_frequency",
            "Operation",
            "Did the control operate at its defined frequency throughout the period?",
            "no",
            "medium",
            "Remediate gaps; assess whether a deficiency must be reported.",
        ),
        _q(
            "sox_review",
            "Review",
            "Is the control's execution independently reviewed and signed off?",
            "no",
            "medium",
            "Add an independent reviewer with evidenced sign-off.",
        ),
        _q(
            "sox_itdependency",
            "IT dependency",
            "Does the control rely on a report/system whose ITGCs are untested?",
            "yes",
            "medium",
            "Test the supporting ITGCs (access, change, completeness).",
        ),
    ),
)

_FRAUD_RISK = AssessmentTemplate(
    type="fraud_risk",
    title="Fraud Risk Assessment",
    framework="ACFE / SAS 99",
    description="Assess fraud exposure in a financial process.",
    questions=(
        _q(
            "fraud_vendor_create_approve",
            "Segregation",
            "Can one person both create and approve a vendor?",
            "yes",
            "high",
            "Split vendor creation from approval (SoD).",
        ),
        _q(
            "fraud_bank_change",
            "Master data",
            "Are vendor/employee bank-detail changes independently reviewed?",
            "no",
            "high",
            "Require out-of-band verification for every bank-detail change.",
        ),
        _q(
            "fraud_dup_payment",
            "Payments",
            "Are duplicate and split payments detected before release?",
            "no",
            "high",
            "Run duplicate/split detection on every payment batch.",
        ),
        _q(
            "fraud_ghost",
            "Master data",
            "Is the vendor/employee master periodically checked for ghost entries?",
            "no",
            "medium",
            "Reconcile master data to active relationships regularly.",
        ),
        _q(
            "fraud_override",
            "Management override",
            "Are manual journal entries and management overrides independently reviewed?",
            "no",
            "high",
            "Review all top-side/manual JEs for business rationale.",
        ),
        _q(
            "fraud_whistleblower",
            "Detection",
            "Is there a confidential channel to report suspected fraud?",
            "no",
            "medium",
            "Provide an anonymous reporting hotline.",
        ),
    ),
)

_ITGC = AssessmentTemplate(
    type="itgc",
    title="IT General Controls Assessment",
    framework="COBIT / SOX ITGC",
    description="Assess access, change, and operations controls over a financial system.",
    questions=(
        _q(
            "itgc_access_least_priv",
            "Access",
            "Is access to the posting/payment tool least-privileged and logged?",
            "no",
            "high",
            "Restrict to least privilege and log every use (capability + audit).",
        ),
        _q(
            "itgc_access_review",
            "Access",
            "Is system access reviewed periodically and revoked on role change?",
            "no",
            "medium",
            "Run periodic access recertification with evidenced removal.",
        ),
        _q(
            "itgc_change_mgmt",
            "Change",
            "Are changes to the financial system tested and approved before release?",
            "no",
            "high",
            "Require tested, approved, segregated change management.",
        ),
        _q(
            "itgc_audit_trail",
            "Operations",
            "Is there a complete, tamper-evident audit trail of transactions?",
            "no",
            "high",
            "Enable the signed append-only audit log and verify it.",
        ),
        _q(
            "itgc_backup",
            "Operations",
            "Are backups taken and restoration periodically tested?",
            "no",
            "medium",
            "Schedule backups and test restores on a cadence.",
        ),
        _q(
            "itgc_segregation",
            "Access",
            "Does any one identity hold incompatible system duties?",
            "yes",
            "high",
            "Separate incompatible system roles (SoD).",
        ),
    ),
)

_CREDIT_RISK = AssessmentTemplate(
    type="credit_risk",
    title="Customer Credit Risk Assessment",
    framework="CECL / internal credit policy",
    description="Assess the credit risk of a customer / receivable.",
    questions=(
        _q(
            "credit_past_due",
            "Aging",
            "Is the customer past terms by more than 90 days?",
            "yes",
            "high",
            "Escalate to collections; reassess the credit limit.",
        ),
        _q(
            "credit_limit_breach",
            "Exposure",
            "Does current exposure exceed the approved credit limit?",
            "yes",
            "high",
            "Hold new orders pending a credit review.",
        ),
        _q(
            "credit_deteriorating",
            "Monitoring",
            "Has the customer's payment behaviour deteriorated recently?",
            "yes",
            "medium",
            "Tighten terms and increase the allowance estimate.",
        ),
        _q(
            "credit_concentration",
            "Concentration",
            "Does this customer represent a concentration risk (>10% of AR)?",
            "yes",
            "medium",
            "Diversify or secure the exposure (guarantee/insurance).",
        ),
        _q(
            "credit_secured",
            "Mitigation",
            "Is the exposure unsecured with no guarantee or insurance?",
            "yes",
            "low",
            "Consider credit insurance or collateral for large balances.",
        ),
    ),
)

_CLOSE_READINESS = AssessmentTemplate(
    type="close_readiness",
    title="Period-Close Readiness Assessment",
    framework="internal close policy",
    description="Assess whether the books are ready to close for the period.",
    questions=(
        _q(
            "close_bs_recon",
            "Reconciliation",
            "Are all balance-sheet accounts reconciled for the period?",
            "no",
            "high",
            "Complete and review all balance-sheet reconciliations.",
        ),
        _q(
            "close_bank_rec",
            "Reconciliation",
            "Is every bank account reconciled to the ledger?",
            "no",
            "high",
            "Reconcile each bank account and clear stale items.",
        ),
        _q(
            "close_accruals",
            "Completeness",
            "Are all known accruals and prepaids recorded?",
            "no",
            "medium",
            "Record outstanding accruals/prepaids before close.",
        ),
        _q(
            "close_intercompany",
            "Intercompany",
            "Do intercompany balances net to zero across entities?",
            "no",
            "high",
            "Resolve intercompany mismatches before consolidation.",
        ),
        _q(
            "close_flux",
            "Review",
            "Has flux/variance analysis been performed and explained?",
            "no",
            "medium",
            "Complete flux analysis with documented explanations.",
        ),
        _q(
            "close_checklist",
            "Governance",
            "Is the close checklist complete with sign-offs?",
            "no",
            "medium",
            "Finish the checklist with evidenced approvals.",
        ),
    ),
)

_HIPAA = AssessmentTemplate(
    type="hipaa",
    title="HIPAA Security Rule Assessment",
    framework="HIPAA Security Rule (45 CFR Part 164)",
    description="Assess safeguards for electronic protected health information (ePHI).",
    questions=(
        _q(
            "hipaa_risk_analysis",
            "Administrative safeguards",
            "Has a security risk analysis of ePHI been conducted and documented?",
            "no",
            "high",
            "Conduct + document a risk analysis (164.308(a)(1)(ii)(A)).",
        ),
        _q(
            "hipaa_access_control",
            "Technical safeguards",
            "Is access to ePHI restricted by unique user IDs and role-based controls?",
            "no",
            "high",
            "Enforce unique user IDs + least-privilege access (164.312(a)).",
        ),
        _q(
            "hipaa_encryption",
            "Technical safeguards",
            "Is ePHI encrypted in transit and at rest?",
            "no",
            "high",
            "Encrypt ePHI at rest and in transit, or document the "
            "addressable rationale (164.312(a)(2)(iv)/(e)).",
        ),
        _q(
            "hipaa_audit_controls",
            "Technical safeguards",
            "Are audit controls in place to record and examine ePHI access?",
            "no",
            "high",
            "Enable audit logging of ePHI access + review (164.312(b)).",
        ),
        _q(
            "hipaa_baa",
            "Administrative safeguards",
            "Is a Business Associate Agreement in place with every vendor that handles ePHI?",
            "no",
            "high",
            "Execute a BAA before a business associate touches ePHI (164.308(b)).",
        ),
        _q(
            "hipaa_training",
            "Administrative safeguards",
            "Does the workforce receive periodic HIPAA security awareness training?",
            "no",
            "medium",
            "Provide + document security training (164.308(a)(5)).",
        ),
        _q(
            "hipaa_contingency",
            "Administrative safeguards",
            "Is there a tested data-backup and disaster-recovery / contingency plan?",
            "no",
            "medium",
            "Maintain + test backup/contingency plans (164.308(a)(7)).",
        ),
        _q(
            "hipaa_breach_notification",
            "Breach Notification Rule",
            "Is there a documented breach-notification process meeting the 60-day rule?",
            "no",
            "high",
            "Document breach assessment + notification (164.404, 60 days).",
        ),
        _q(
            "hipaa_minimum_necessary",
            "Privacy Rule",
            "Is the 'minimum necessary' standard applied to ePHI use and disclosure?",
            "no",
            "medium",
            "Limit ePHI use/disclosure to minimum necessary (164.502(b)).",
        ),
        _q(
            "hipaa_integrity",
            "Technical safeguards",
            "Are mechanisms in place to ensure ePHI is not improperly altered or destroyed?",
            "no",
            "medium",
            "Implement integrity controls for ePHI (164.312(c)).",
        ),
    ),
)

_SOC2 = AssessmentTemplate(
    type="soc2",
    title="SOC 2 Readiness Assessment",
    framework="SOC 2 Trust Services Criteria (AICPA)",
    description="Assess readiness against the SOC 2 common/security criteria.",
    questions=(
        _q(
            "soc2_access",
            "CC6 Logical access",
            "Are logical access controls (unique IDs, MFA, least privilege) enforced?",
            "no",
            "high",
            "Enforce MFA, RBAC, and unique IDs for all access (CC6.1).",
        ),
        _q(
            "soc2_change_mgmt",
            "CC8 Change management",
            "Are changes to production reviewed, tested, and approved before release?",
            "no",
            "high",
            "Adopt a documented change-management process (CC8.1).",
        ),
        _q(
            "soc2_risk",
            "CC3 Risk assessment",
            "Is a formal risk assessment performed and documented at least annually?",
            "no",
            "medium",
            "Run + document an annual risk assessment (CC3.1).",
        ),
        _q(
            "soc2_monitoring",
            "CC7 System operations",
            "Are systems monitored for security events with alerting?",
            "no",
            "high",
            "Deploy monitoring + alerting for anomalies (CC7.2).",
        ),
        _q(
            "soc2_incident",
            "CC7 System operations",
            "Is there a documented and tested incident-response plan?",
            "no",
            "high",
            "Document + test an incident-response plan (CC7.4).",
        ),
        _q(
            "soc2_vendor",
            "CC9 Risk mitigation",
            "Are vendors risk-assessed before onboarding and monitored over time?",
            "no",
            "medium",
            "Run vendor due diligence + ongoing monitoring (CC9.2).",
        ),
        _q(
            "soc2_encryption",
            "CC6 Logical access",
            "Is data encrypted in transit and at rest?",
            "no",
            "high",
            "Encrypt data in transit (TLS) and at rest (CC6.7).",
        ),
        _q(
            "soc2_backup",
            "A1 Availability",
            "Are backups performed and recovery periodically tested?",
            "no",
            "medium",
            "Perform backups + test restores periodically (A1.2).",
        ),
        _q(
            "soc2_policies",
            "CC1/CC2 Control environment",
            "Are information-security policies documented, approved, and communicated?",
            "no",
            "medium",
            "Maintain approved, communicated security policies (CC1.1/CC2.2).",
        ),
        _q(
            "soc2_deprovision",
            "CC6 Logical access",
            "Is access revoked promptly when personnel are terminated?",
            "no",
            "medium",
            "Automate timely deprovisioning on termination (CC6.2/6.3).",
        ),
    ),
)

_PCI_DSS = AssessmentTemplate(
    type="pci_dss",
    title="PCI DSS Assessment",
    framework="PCI DSS v4.0",
    description="Assess controls protecting cardholder data (the CDE).",
    questions=(
        _q(
            "pci_segmentation",
            "Req 1 Network security",
            "Is the cardholder data environment (CDE) segmented from other networks?",
            "no",
            "high",
            "Segment + firewall the CDE from untrusted networks (Req 1).",
        ),
        _q(
            "pci_defaults",
            "Req 2 Secure configuration",
            "Have vendor-default passwords and settings been changed on CDE systems?",
            "no",
            "high",
            "Remove/replace all vendor defaults before deployment (Req 2).",
        ),
        _q(
            "pci_stored_pan",
            "Req 3 Protect stored data",
            "Is stored cardholder data (PAN) rendered unreadable "
            "(encryption / truncation / tokenization)?",
            "no",
            "high",
            "Encrypt or tokenize stored PAN; never store sensitive authentication data (Req 3).",
        ),
        _q(
            "pci_transit",
            "Req 4 Protect data in transit",
            "Is cardholder data encrypted with strong cryptography over open networks?",
            "no",
            "high",
            "Use TLS 1.2+ for cardholder data in transit (Req 4).",
        ),
        _q(
            "pci_malware",
            "Req 5 Malware protection",
            "Is anti-malware deployed and kept current on applicable CDE systems?",
            "no",
            "medium",
            "Deploy + update anti-malware on applicable systems (Req 5).",
        ),
        _q(
            "pci_secure_dev",
            "Req 6 Secure systems",
            "Are systems patched promptly and software developed securely?",
            "no",
            "high",
            "Patch promptly + follow a secure SDLC (Req 6).",
        ),
        _q(
            "pci_need_to_know",
            "Req 7 Restrict access",
            "Is access to cardholder data restricted by business need-to-know?",
            "no",
            "high",
            "Enforce least-privilege need-to-know access to CHD (Req 7).",
        ),
        _q(
            "pci_auth",
            "Req 8 Authenticate access",
            "Is MFA with unique IDs enforced for all access to the CDE?",
            "no",
            "high",
            "Require MFA + unique credentials for all CDE access (Req 8).",
        ),
        _q(
            "pci_logging",
            "Req 10 Log and monitor",
            "Is all access to cardholder data and CDE systems logged and reviewed?",
            "no",
            "high",
            "Log + review access to cardholder data (Req 10).",
        ),
        _q(
            "pci_testing",
            "Req 11 Test security",
            "Are vulnerability scans and penetration tests performed regularly?",
            "no",
            "medium",
            "Run quarterly ASV scans + annual penetration tests (Req 11).",
        ),
    ),
)


# --- Security & GRC control-framework catalog ------------------------------
#
# Framework identifiers are useful interoperability keys, but several source
# standards are licensed works.  The questions below are original, compact
# paraphrases of control outcomes; they do not reproduce restricted control
# text.  ``FRAMEWORK_SOURCES`` records the exact release and primary publisher
# page from which an operator should obtain the authoritative material.

FRAMEWORK_SOURCES: dict[str, dict[str, str]] = {
    "soc2": {
        "title": "AICPA Trust Services Criteria",
        "version": "2017 criteria; revised points of focus 2022",
        "source_url": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
        "access_note": "Licensed AICPA text is not reproduced; questions are original paraphrases.",
    },
    "iso27001": {
        "title": "ISO/IEC 27001 Information security management systems",
        "version": "ISO/IEC 27001:2022, Edition 3; Amendment 1:2024 noted",
        "source_url": "https://www.iso.org/standard/27001",
        "access_note": "Licensed ISO text is not reproduced; Annex A identifiers and original paraphrases only.",
    },
    "nist_csf": {
        "title": "NIST Cybersecurity Framework",
        "version": "CSF 2.0 (NIST CSWP 29), 2024-02-26",
        "source_url": "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
        "access_note": "Primary public-domain NIST source.",
    },
    "nist_800_53": {
        "title": "NIST SP 800-53 and SP 800-53B",
        "version": "Revision 5; 800-53B Release 5.2.0 (baseline unchanged), 2025-08-27",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final",
        "access_note": "Resolved Moderate baseline identifiers and evidence prompts; tailoring remains system-specific.",
    },
    "cis_v8": {
        "title": "CIS Critical Security Controls",
        "version": "v8.1",
        "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
        "access_note": "Identifiers and minimum IG assignments only; use an authorized CIS copy for normative text.",
    },
    "pci_dss": {
        "title": "PCI Data Security Standard",
        "version": "PCI DSS v4.0.1, June 2024",
        "source_url": "https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss",
        "access_note": "Licensed PCI text is not reproduced; requirement-level paraphrases only.",
    },
    "hipaa": {
        "title": "HIPAA Security Rule",
        "version": "Current 45 CFR Part 164, Subpart C; 2025 NPRM is not treated as final",
        "source_url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
        "access_note": "Current HHS rule summary and eCFR references.",
    },
    "cmmc_l2": {
        "title": "Cybersecurity Maturity Model Certification Program",
        "version": "CMMC 2.0 Level 2; 32 CFR Part 170",
        "source_url": "https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-170",
        "access_note": "All 110 NIST SP 800-171r2 practices; contract scope and assessment type require human determination.",
    },
    "fedramp_moderate": {
        "title": "FedRAMP Rev. 5 Class C (Moderate transition)",
        "version": "FedRAMP Consolidated Rules for 2026 transition; current Moderate maps to Rev. 5 Class C",
        "source_url": "https://www.fedramp.gov/2026/",
        "access_note": "Current Class C identifiers; the rules, transition timeline, parameters, and agency scope remain authoritative.",
    },
    "iso42001": {
        "title": "ISO/IEC 42001 Artificial intelligence management system",
        "version": "ISO/IEC 42001:2023, Edition 1",
        "source_url": "https://www.iso.org/standard/42001",
        "access_note": "Licensed ISO text is not reproduced; clause/control identifiers and original outcome paraphrases only.",
    },
}

# The generated, static catalog module pins exact artifacts and hashes.  Merge
# that provenance into the human-facing metadata without discarding the
# compatibility notes above.
for _framework_key, _provenance in SECURITY_CATALOG_PROVENANCE.items():
    FRAMEWORK_SOURCES[_framework_key].update(_provenance)


def _control_questions(prefix: str, entries: tuple[tuple[str, str, str, str], ...]):
    """Compile original control-outcome paraphrases into assessment questions."""
    questions = []
    for reference, section, objective, severity in entries:
        slug = re.sub(r"[^a-z0-9]+", "_", reference.lower()).strip("_")
        questions.append(
            _q(
                f"{prefix}_{slug}",
                section,
                f"Is there current, reviewable evidence that the organization {objective}?",
                "no",
                severity,
                f"Define an owner, implement and test the outcome, and retain evidence ({reference}).",
            )
        )
    return tuple(questions)


def _practice_questions(
    prefix: str,
    entries: tuple[SecurityPractice, ...],
    *,
    scope: str,
) -> tuple[Question, ...]:
    """Compile a pinned practice catalog while preserving legacy group IDs.

    The former shallow templates exposed one question per category, family, or
    CIS Control.  The first practice in each such group keeps that identifier;
    subsequent practices use their full authoritative reference.  Existing
    answer files therefore retain a meaningful anchor while the template gains
    complete practice-level coverage.
    """

    def group_key(reference: str, section: str) -> str:
        if scope == "category":
            return reference.rsplit("-", 1)[0]
        if scope == "family":
            return section.split(" /", 1)[0]
        if scope == "control":
            return reference.split(".", 1)[0]
        raise ValueError(f"unsupported practice scope: {scope}")

    questions = []
    seen_groups: set[str] = set()
    for reference, section, objective, severity, minimum_ig in entries:
        group = group_key(reference, section)
        token = group if group not in seen_groups else reference
        seen_groups.add(group)
        slug = re.sub(r"[^a-z0-9]+", "_", token.lower()).strip("_")
        display_section = section
        guidance = (
            f"Define an owner, implement and test the outcome, and retain evidence ({reference})."
        )
        if minimum_ig is not None:
            applicable_groups = ", ".join(f"IG{value}" for value in range(minimum_ig, 4))
            display_section = f"{section} / minimum IG{minimum_ig} ({applicable_groups})"
            guidance = (
                "Use an authorized CIS Controls v8.1 copy for the normative safeguard; "
                f"retain owned, tested evidence for {reference} at {applicable_groups} scope."
            )
        questions.append(
            _q(
                f"{prefix}_{slug}",
                display_section,
                f"For {reference}, is there current, reviewable evidence that the organization {objective}?",
                "no",
                severity,
                guidance,
            )
        )
    return tuple(questions)


_SOC2_ENTRIES = (
    (
        "CC1.1",
        "CC1 Control environment",
        "sets and demonstrates integrity and ethical expectations",
        "high",
    ),
    (
        "CC1.2",
        "CC1 Control environment",
        "maintains independent oversight of internal control",
        "high",
    ),
    (
        "CC1.3",
        "CC1 Control environment",
        "defines accountable structures, reporting lines, and authority",
        "medium",
    ),
    (
        "CC1.4",
        "CC1 Control environment",
        "recruits, develops, and retains competent personnel",
        "medium",
    ),
    (
        "CC1.5",
        "CC1 Control environment",
        "holds control owners accountable for assigned duties",
        "high",
    ),
    (
        "CC2.1",
        "CC2 Information and communication",
        "uses reliable information to operate controls",
        "medium",
    ),
    (
        "CC2.2",
        "CC2 Information and communication",
        "communicates security objectives and responsibilities internally",
        "medium",
    ),
    (
        "CC2.3",
        "CC2 Information and communication",
        "communicates relevant commitments and incidents externally",
        "medium",
    ),
    (
        "CC3.1",
        "CC3 Risk assessment",
        "sets sufficiently clear objectives for risk assessment",
        "medium",
    ),
    (
        "CC3.2",
        "CC3 Risk assessment",
        "identifies and analyzes risks to service commitments",
        "high",
    ),
    ("CC3.3", "CC3 Risk assessment", "includes fraud scenarios in risk analysis", "medium"),
    (
        "CC3.4",
        "CC3 Risk assessment",
        "reassesses risks after material internal or external change",
        "high",
    ),
    ("CC4.1", "CC4 Monitoring", "performs ongoing or separate evaluations of controls", "high"),
    ("CC4.2", "CC4 Monitoring", "reports deficiencies and tracks timely correction", "high"),
    (
        "CC5.1",
        "CC5 Control activities",
        "selects control activities that reduce identified risks",
        "high",
    ),
    (
        "CC5.2",
        "CC5 Control activities",
        "implements technology controls supporting business controls",
        "high",
    ),
    (
        "CC5.3",
        "CC5 Control activities",
        "turns control expectations into operated policies and procedures",
        "medium",
    ),
    (
        "CC6.1",
        "CC6 Logical and physical access",
        "maintains logical access architecture and protective mechanisms",
        "high",
    ),
    (
        "CC6.2",
        "CC6 Logical and physical access",
        "authorizes and provisions new identities before access",
        "high",
    ),
    (
        "CC6.3",
        "CC6 Logical and physical access",
        "modifies and removes access promptly when conditions change",
        "high",
    ),
    (
        "CC6.4",
        "CC6 Logical and physical access",
        "restricts physical entry to protected assets",
        "high",
    ),
    (
        "CC6.5",
        "CC6 Logical and physical access",
        "retires assets and data using controlled disposal",
        "medium",
    ),
    (
        "CC6.6",
        "CC6 Logical and physical access",
        "protects system boundaries from unauthorized traffic",
        "high",
    ),
    (
        "CC6.7",
        "CC6 Logical and physical access",
        "protects information during transmission and movement",
        "high",
    ),
    (
        "CC6.8",
        "CC6 Logical and physical access",
        "prevents or detects unauthorized and malicious software",
        "high",
    ),
    (
        "CC7.1",
        "CC7 System operations",
        "detects configuration changes and new vulnerabilities",
        "high",
    ),
    (
        "CC7.2",
        "CC7 System operations",
        "monitors system components for anomalous security events",
        "high",
    ),
    (
        "CC7.3",
        "CC7 System operations",
        "evaluates security events to determine appropriate handling",
        "high",
    ),
    (
        "CC7.4",
        "CC7 System operations",
        "responds to security incidents under an assigned plan",
        "high",
    ),
    (
        "CC7.5",
        "CC7 System operations",
        "restores operations and improves controls after incidents",
        "high",
    ),
    (
        "CC8.1",
        "CC8 Change management",
        "authorizes, tests, and controls infrastructure and software changes",
        "high",
    ),
    (
        "CC9.1",
        "CC9 Risk mitigation",
        "selects and operates treatments for business disruption risks",
        "medium",
    ),
    (
        "CC9.2",
        "CC9 Risk mitigation",
        "assesses and monitors vendor and business-partner risk",
        "high",
    ),
    (
        "A1.1",
        "Availability",
        "plans capacity and availability around service commitments",
        "medium",
    ),
    ("A1.2", "Availability", "operates recovery and environmental protections", "high"),
    ("A1.3", "Availability", "tests recovery procedures and corrects observed gaps", "high"),
    (
        "C1.1",
        "Confidentiality",
        "identifies and protects confidential information throughout its lifecycle",
        "high",
    ),
    (
        "C1.2",
        "Confidentiality",
        "disposes of confidential information when retention ends",
        "medium",
    ),
    (
        "PI1.1",
        "Processing integrity",
        "defines processing objectives and validates accurate, complete output",
        "high",
    ),
    ("PI1.2", "Processing integrity", "validates authorized and complete input", "high"),
    (
        "PI1.3",
        "Processing integrity",
        "detects processing errors and unauthorized manipulation",
        "high",
    ),
    ("PI1.4", "Processing integrity", "preserves outputs and resolves delivery failures", "medium"),
    (
        "PI1.5",
        "Processing integrity",
        "stores processing records sufficient to investigate exceptions",
        "medium",
    ),
    (
        "P1-P8",
        "Privacy",
        "operates notice, choice, collection, use, retention, access, disclosure, and quality controls",
        "high",
    ),
)

_SOC2 = AssessmentTemplate(
    type="soc2",
    title="SOC 2 Readiness Assessment",
    framework="AICPA Trust Services Criteria (2017; revised points of focus 2022)",
    description="Readiness screen across CC1-CC9 and the availability, confidentiality, processing-integrity, and privacy categories; not an audit opinion.",
    questions=_control_questions("soc2", _SOC2_ENTRIES),
)


_ISO27001_ENTRIES = (
    (
        "A.5.1",
        "Organizational",
        "keeps approved information-security policies current and available",
        "medium",
    ),
    ("A.5.2", "Organizational", "assigns and communicates information-security roles", "high"),
    (
        "A.5.3",
        "Organizational",
        "separates conflicting duties or documents compensating safeguards",
        "high",
    ),
    ("A.5.4", "Organizational", "requires managers to enforce security responsibilities", "medium"),
    ("A.5.5", "Organizational", "maintains appropriate contacts with public authorities", "low"),
    (
        "A.5.6",
        "Organizational",
        "participates in relevant security communities and expert groups",
        "low",
    ),
    ("A.5.7", "Organizational", "collects and applies threat intelligence", "high"),
    ("A.5.8", "Organizational", "integrates security into project governance", "medium"),
    (
        "A.5.9",
        "Organizational",
        "maintains an owned inventory of information and related assets",
        "high",
    ),
    (
        "A.5.10",
        "Organizational",
        "defines acceptable use and handling for information assets",
        "medium",
    ),
    (
        "A.5.11",
        "Organizational",
        "recovers organizational assets when roles or relationships end",
        "medium",
    ),
    ("A.5.12", "Organizational", "classifies information according to risk and obligation", "high"),
    (
        "A.5.13",
        "Organizational",
        "labels information consistently with its classification",
        "medium",
    ),
    (
        "A.5.14",
        "Organizational",
        "protects information transferred inside and outside the organization",
        "high",
    ),
    (
        "A.5.15",
        "Organizational",
        "defines access-control rules from business and security needs",
        "high",
    ),
    ("A.5.16", "Organizational", "governs identities across their full lifecycle", "high"),
    ("A.5.17", "Organizational", "protects authentication secrets and their issuance", "high"),
    ("A.5.18", "Organizational", "reviews, changes, and revokes access rights", "high"),
    ("A.5.19", "Organizational", "manages security risk in supplier relationships", "high"),
    (
        "A.5.20",
        "Organizational",
        "places appropriate security duties in supplier agreements",
        "high",
    ),
    ("A.5.21", "Organizational", "manages ICT supply-chain risk", "high"),
    (
        "A.5.22",
        "Organizational",
        "monitors and changes supplier services under governance",
        "medium",
    ),
    ("A.5.23", "Organizational", "governs acquisition, use, and exit of cloud services", "high"),
    ("A.5.24", "Organizational", "prepares roles and procedures for security incidents", "high"),
    (
        "A.5.25",
        "Organizational",
        "assesses security events and determines incident handling",
        "high",
    ),
    ("A.5.26", "Organizational", "responds to information-security incidents", "high"),
    ("A.5.27", "Organizational", "uses incident lessons to improve safeguards", "medium"),
    (
        "A.5.28",
        "Organizational",
        "collects and preserves evidence using defensible procedures",
        "high",
    ),
    ("A.5.29", "Organizational", "maintains appropriate security during disruption", "high"),
    ("A.5.30", "Organizational", "tests ICT readiness for continuity objectives", "high"),
    (
        "A.5.31",
        "Organizational",
        "tracks security-related legal, regulatory, and contractual duties",
        "high",
    ),
    ("A.5.32", "Organizational", "protects intellectual-property rights", "medium"),
    (
        "A.5.33",
        "Organizational",
        "protects records for integrity, availability, and retention",
        "medium",
    ),
    (
        "A.5.34",
        "Organizational",
        "protects privacy and personally identifiable information",
        "high",
    ),
    ("A.5.35", "Organizational", "obtains independent review of security governance", "medium"),
    ("A.5.36", "Organizational", "checks compliance with security policies and standards", "high"),
    (
        "A.5.37",
        "Organizational",
        "documents operating procedures needed for secure, consistent work",
        "medium",
    ),
    ("A.6.1", "People", "screens personnel proportionately before sensitive access", "medium"),
    ("A.6.2", "People", "sets security obligations in employment terms", "medium"),
    ("A.6.3", "People", "provides role-appropriate security awareness and training", "high"),
    ("A.6.4", "People", "operates a fair, documented disciplinary process for violations", "low"),
    ("A.6.5", "People", "changes or ends access and duties after role termination", "high"),
    ("A.6.6", "People", "uses confidentiality agreements where risk requires them", "medium"),
    ("A.6.7", "People", "protects information during remote work", "high"),
    ("A.6.8", "People", "gives personnel a clear path to report security events", "medium"),
    ("A.7.1", "Physical", "defines and protects physical security boundaries", "high"),
    ("A.7.2", "Physical", "authorizes and records entry into protected areas", "high"),
    ("A.7.3", "Physical", "secures offices, rooms, and facilities", "high"),
    ("A.7.4", "Physical", "monitors physical premises for unauthorized access", "medium"),
    ("A.7.5", "Physical", "protects sites against environmental and physical threats", "high"),
    ("A.7.6", "Physical", "sets working rules for secure areas", "medium"),
    ("A.7.7", "Physical", "keeps sensitive information clear from unattended work areas", "low"),
    (
        "A.7.8",
        "Physical",
        "positions and protects equipment against damage and observation",
        "medium",
    ),
    ("A.7.9", "Physical", "protects assets used away from organizational premises", "high"),
    ("A.7.10", "Physical", "governs removable and other storage media", "high"),
    ("A.7.11", "Physical", "protects processing facilities from utility failures", "medium"),
    ("A.7.12", "Physical", "protects power and data cabling", "medium"),
    ("A.7.13", "Physical", "maintains equipment without compromising information", "medium"),
    ("A.7.14", "Physical", "sanitizes or destroys equipment before disposal or reuse", "high"),
    ("A.8.1", "Technological", "manages and protects user endpoint devices", "high"),
    ("A.8.2", "Technological", "restricts and reviews privileged access", "high"),
    ("A.8.3", "Technological", "restricts access to information by approved need", "high"),
    ("A.8.4", "Technological", "limits access to source code and development assets", "high"),
    ("A.8.5", "Technological", "uses secure authentication suited to access risk", "high"),
    ("A.8.6", "Technological", "monitors capacity and plans for future demand", "medium"),
    ("A.8.7", "Technological", "prevents, detects, and recovers from malware", "high"),
    ("A.8.8", "Technological", "identifies and remediates technical vulnerabilities", "high"),
    ("A.8.9", "Technological", "maintains approved, monitored configuration baselines", "high"),
    ("A.8.10", "Technological", "deletes information when retention and legal needs end", "medium"),
    ("A.8.11", "Technological", "masks sensitive data where exposure should be reduced", "medium"),
    ("A.8.12", "Technological", "detects and limits unauthorized data leakage", "high"),
    ("A.8.13", "Technological", "takes protected backups and verifies restoration", "high"),
    ("A.8.14", "Technological", "provides redundancy consistent with availability needs", "medium"),
    ("A.8.15", "Technological", "records and protects security-relevant logs", "high"),
    ("A.8.16", "Technological", "monitors systems and acts on anomalous events", "high"),
    ("A.8.17", "Technological", "synchronizes system clocks to trusted sources", "medium"),
    ("A.8.18", "Technological", "restricts powerful utility programs", "high"),
    ("A.8.19", "Technological", "controls software installation on operational systems", "high"),
    ("A.8.20", "Technological", "secures and manages networks", "high"),
    ("A.8.21", "Technological", "defines security expectations for network services", "high"),
    ("A.8.22", "Technological", "separates networks according to trust and risk", "high"),
    (
        "A.8.23",
        "Technological",
        "filters access to malicious or inappropriate web resources",
        "medium",
    ),
    ("A.8.24", "Technological", "governs cryptography and key management", "high"),
    ("A.8.25", "Technological", "uses a secure development lifecycle", "high"),
    (
        "A.8.26",
        "Technological",
        "defines security requirements before acquiring or building applications",
        "high",
    ),
    ("A.8.27", "Technological", "uses secure architecture and engineering principles", "high"),
    ("A.8.28", "Technological", "applies secure coding practices", "high"),
    ("A.8.29", "Technological", "tests security during development and acceptance", "high"),
    ("A.8.30", "Technological", "governs security in outsourced development", "high"),
    ("A.8.31", "Technological", "separates development, test, and production environments", "high"),
    ("A.8.32", "Technological", "authorizes, tests, and records changes", "high"),
    ("A.8.33", "Technological", "protects operational data used for testing", "medium"),
    ("A.8.34", "Technological", "protects systems and data during assurance testing", "medium"),
)

_ISO27001 = AssessmentTemplate(
    type="iso27001",
    title="ISO/IEC 27001:2022 Annex A Readiness",
    framework="ISO/IEC 27001:2022 Annex A (93-control identifier screen)",
    description="Original readiness questions covering every Annex A identifier across organizational, people, physical, and technological themes; not certification.",
    questions=_control_questions("iso", _ISO27001_ENTRIES),
)


_NIST_CSF = AssessmentTemplate(
    type="nist_csf",
    title="NIST Cybersecurity Framework 2.0 Assessment",
    framework="NIST CSF 2.0 (NIST CSWP 29)",
    description="All 106 non-withdrawn CSF 2.0 Core subcategories across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER.",
    questions=_practice_questions("csf", NIST_CSF_2_SUBCATEGORIES, scope="category"),
)


_NIST_800_53 = AssessmentTemplate(
    type="nist_800_53",
    title="NIST SP 800-53 Rev. 5 Moderate Baseline Assessment",
    framework="NIST SP 800-53 Rev. 5 / SP 800-53B moderate baseline",
    description="All 287 controls and enhancements selected by the official OSCAL-resolved SP 800-53B Moderate baseline; system-specific tailoring remains authoritative.",
    questions=_practice_questions("n53", NIST_800_53_MODERATE, scope="family"),
)


_CIS_V8 = AssessmentTemplate(
    type="cis_v8",
    title="CIS Controls v8.1 Assessment",
    framework="CIS Critical Security Controls v8.1 (IG1/IG2/IG3 scoping)",
    description="All 153 safeguard identifiers with minimum IG1, IG2, or IG3 assignment. Licensed safeguard titles and text are deliberately omitted; use an authorized CIS copy.",
    questions=_practice_questions("cis", CIS_V81_SAFEGUARDS, scope="control"),
)


_PCI_ENTRIES = tuple(
    (f"Req {number}", f"Requirement {number}", objective, severity)
    for number, objective, severity in (
        (
            1,
            "installs and maintains network security controls around the cardholder-data environment",
            "high",
        ),
        (2, "applies secure configurations and removes unsafe defaults", "high"),
        (3, "protects stored account data and cryptographic keys", "high"),
        (4, "protects cardholder data over open public networks", "high"),
        (5, "protects systems and users from malicious software", "high"),
        (6, "develops and maintains secure systems and software", "high"),
        (7, "restricts access by business need to know", "high"),
        (8, "identifies users and authenticates access strongly", "high"),
        (9, "restricts physical access to cardholder data", "high"),
        (10, "logs and monitors access to systems and cardholder data", "high"),
        (11, "tests systems, networks, and defenses regularly", "high"),
        (12, "supports information security with governed policies and programs", "high"),
    )
)

_PCI_DSS = AssessmentTemplate(
    type="pci_dss",
    title="PCI DSS v4.0.1 Readiness Assessment",
    framework="PCI DSS v4.0.1 (June 2024)",
    description="Requirement-level readiness screen for the cardholder-data environment; not an SAQ, ROC, or compliance validation.",
    questions=_control_questions("pci", _PCI_ENTRIES),
)


_HIPAA_ENTRIES = (
    (
        "164.308(a)(1)",
        "Administrative safeguards",
        "performs accurate ePHI risk analysis and manages identified risk",
        "high",
    ),
    (
        "164.308(a)(2)",
        "Administrative safeguards",
        "assigns a responsible security official",
        "high",
    ),
    (
        "164.308(a)(3)",
        "Administrative safeguards",
        "authorizes, supervises, and clears workforce access",
        "high",
    ),
    (
        "164.308(a)(4)",
        "Administrative safeguards",
        "limits information access according to role and need",
        "high",
    ),
    (
        "164.308(a)(5)",
        "Administrative safeguards",
        "trains the workforce and responds to malicious software and login risk",
        "high",
    ),
    (
        "164.308(a)(6)",
        "Administrative safeguards",
        "identifies, responds to, mitigates, and documents security incidents",
        "high",
    ),
    (
        "164.308(a)(7)",
        "Administrative safeguards",
        "maintains data backup, disaster recovery, and emergency operations",
        "high",
    ),
    (
        "164.308(a)(8)",
        "Administrative safeguards",
        "periodically evaluates safeguards after environmental or operational change",
        "medium",
    ),
    (
        "164.308(b)",
        "Organizational requirements",
        "uses compliant written arrangements with business associates",
        "high",
    ),
    (
        "164.310(a)",
        "Physical safeguards",
        "controls and validates physical facility access",
        "high",
    ),
    (
        "164.310(b)",
        "Physical safeguards",
        "defines appropriate workstation functions and surroundings",
        "medium",
    ),
    (
        "164.310(c)",
        "Physical safeguards",
        "physically protects workstations that access ePHI",
        "medium",
    ),
    (
        "164.310(d)",
        "Physical safeguards",
        "governs receipt, movement, reuse, and disposal of devices and media",
        "high",
    ),
    (
        "164.312(a)",
        "Technical safeguards",
        "uses unique identities and access controls for ePHI",
        "high",
    ),
    (
        "164.312(b)",
        "Technical safeguards",
        "records and examines activity in systems containing ePHI",
        "high",
    ),
    (
        "164.312(c)",
        "Technical safeguards",
        "protects ePHI from improper alteration or destruction",
        "high",
    ),
    ("164.312(d)", "Technical safeguards", "verifies identities seeking ePHI access", "high"),
    (
        "164.312(e)",
        "Technical safeguards",
        "protects ePHI against unauthorized access during transmission",
        "high",
    ),
    (
        "164.314",
        "Organizational requirements",
        "flows required safeguards into group and business-associate arrangements",
        "high",
    ),
    (
        "164.316",
        "Policies and documentation",
        "maintains required policies, records, retention, and change documentation",
        "medium",
    ),
)

_HIPAA = AssessmentTemplate(
    type="hipaa",
    title="HIPAA Security Rule Readiness Assessment",
    framework="HIPAA Security Rule, current 45 CFR Part 164 Subpart C",
    description="Standard-level screen across administrative, physical, technical, organizational, and documentation safeguards; the 2025 proposed rule is not scored as current law.",
    questions=_control_questions("hipaa", _HIPAA_ENTRIES),
)


_CMMC_L2 = AssessmentTemplate(
    type="cmmc_l2",
    title="CMMC 2.0 Level 2 Practice Readiness",
    framework="CMMC 2.0 Level 2 / NIST SP 800-171 Rev. 2",
    description="All 110 NIST SP 800-171r2 practices used by CMMC Level 2. It does not calculate an SPRS score or assert certification.",
    questions=_practice_questions("cmmc", CMMC_L2_PRACTICES, scope="family"),
)


_FEDRAMP_MODERATE = AssessmentTemplate(
    type="fedramp_moderate",
    title="FedRAMP Rev. 5 Class C Control Readiness",
    framework="FedRAMP Consolidated Rules for 2026 transition; legacy Moderate maps to Rev. 5 Class C",
    description="Practice-level readiness screen for all 322 controls and enhancements marked Class C in the official 2026 reference snapshot. Current rules, agency scope, parameters, and assessment procedures remain authoritative.",
    questions=_practice_questions("fedramp", FEDRAMP_CLASS_C_CONTROLS, scope="family"),
)

_TIA = AssessmentTemplate(
    type="tia",
    title="Transfer Impact Assessment",
    framework="Schrems II / EDPB Recommendations 01/2020",
    description="Assess a cross-border transfer of personal data: the "
    "destination's legal regime and the supplementary measures "
    "that make the safeguard hold in practice.",
    questions=(
        _q(
            "tia_mechanism",
            "Transfer mechanism",
            "Is a valid Chapter V transfer mechanism in place (adequacy, SCCs, BCRs)?",
            "no",
            "high",
            "Put SCCs/BCRs in place or rely on an adequacy "
            "decision before transferring (Art. 44-49).",
        ),
        _q(
            "tia_mapping",
            "Transfer mapping",
            "Are the destination countries, recipients, and onward transfers mapped for this flow?",
            "no",
            "high",
            "Map the full transfer chain including sub-processors' locations (EDPB step 1).",
        ),
        _q(
            "tia_local_law",
            "Destination legal regime",
            "Has the destination's surveillance/access law been assessed "
            "against the mechanism (e.g. FISA 702, national security access)?",
            "no",
            "high",
            "Assess problematic legislation in practice; document the analysis (EDPB step 3).",
        ),
        _q(
            "tia_gov_requests",
            "Government access",
            "Has the importer disclosed its history of government access "
            "requests (transparency report or attestation)?",
            "no",
            "medium",
            "Obtain the importer's disclosure history and warrant-canary posture.",
        ),
        _q(
            "tia_encryption_transit",
            "Supplementary measures",
            "Is the data encrypted in transit with keys held outside the "
            "destination's jurisdiction where feasible?",
            "no",
            "high",
            "Apply transport encryption with exporter-side key custody (EDPB technical measure).",
        ),
        _q(
            "tia_encryption_rest",
            "Supplementary measures",
            "Is the data encrypted or pseudonymised at rest such that the "
            "importer alone cannot re-identify subjects?",
            "no",
            "high",
            "Encrypt/pseudonymise at rest with keys retained "
            "by the exporter where the use case allows.",
        ),
        _q(
            "tia_contract_measures",
            "Contractual measures",
            "Do the contracts add measures beyond the SCC baseline "
            "(challenge obligations, notification duties, audits)?",
            "no",
            "medium",
            "Add contractual supplementary measures: "
            "challenge government requests, notify the exporter, permit "
            "audits.",
        ),
        _q(
            "tia_necessity",
            "Data minimisation",
            "Is the transferred data limited to what the purpose strictly requires?",
            "no",
            "medium",
            "Minimise fields and subjects in scope before transferring (Art. 5(1)(c)).",
        ),
        _q(
            "tia_reassessment",
            "Ongoing review",
            "Is there a trigger to re-assess when the destination's law or the transfer changes?",
            "no",
            "medium",
            "Set a review cadence and legal-change trigger (EDPB step 6).",
        ),
        _q(
            "tia_suspension",
            "Exit path",
            "Can the transfer be suspended or the data repatriated if the safeguard fails?",
            "no",
            "high",
            "Define the suspension/repatriation path before relying on the transfer.",
        ),
    ),
)

_DPIA = AssessmentTemplate(
    type="dpia",
    title="Data Protection Impact Assessment",
    framework="GDPR Art. 35",
    description="The formal Art. 35 assessment triggered by high-risk "
    "processing: the systematic description, necessity and "
    "proportionality test, risks to rights and freedoms, and the "
    "mitigating measures — with the Art. 36 prior-consultation "
    "trigger. Deeper than the lightweight PIA screen.",
    questions=(
        _q(
            "dpia_description",
            "Art. 35(7)(a)",
            "Is there a systematic description of the processing operations, "
            "purposes, and (where relevant) the controller's legitimate "
            "interest?",
            "no",
            "medium",
            "Document the processing end to end: data flows, "
            "purposes, recipients, retention (Art. 35(7)(a)).",
        ),
        _q(
            "dpia_necessity",
            "Art. 35(7)(b)",
            "Is the processing necessary and proportionate in relation to the purposes?",
            "no",
            "high",
            "Justify necessity and proportionality; minimise data and purposes (Art. 35(7)(b)).",
        ),
        _q(
            "dpia_risk_assessment",
            "Art. 35(7)(c)",
            "Have the risks to the rights and freedoms of data subjects been assessed?",
            "no",
            "high",
            "Assess likelihood and severity of harm to individuals (Art. 35(7)(c)).",
        ),
        _q(
            "dpia_measures",
            "Art. 35(7)(d)",
            "Are measures to address the risks identified (safeguards, "
            "security, mechanisms to demonstrate compliance)?",
            "no",
            "high",
            "Define mitigating measures and residual-risk treatment (Art. 35(7)(d)).",
        ),
        _q(
            "dpia_dpo",
            "Consultation",
            "Has the Data Protection Officer been consulted and their advice "
            "recorded (Art. 35(2))?",
            "no",
            "medium",
            "Seek and document the DPO's advice on the DPIA.",
        ),
        _q(
            "dpia_subject_views",
            "Consultation",
            "Where appropriate, have the views of data subjects or their "
            "representatives been sought (Art. 35(9))?",
            "no",
            "low",
            "Seek data-subject views where proportionate, or record why it was not appropriate.",
        ),
        _q(
            "dpia_residual_high",
            "Prior consultation",
            "After mitigation, does a high residual risk remain that requires "
            "prior consultation with the supervisory authority (Art. 36)?",
            "yes",
            "high",
            "Consult the supervisory authority before "
            "processing where high residual risk remains (Art. 36).",
        ),
        _q(
            "dpia_monitoring",
            "High-risk triggers",
            "Does it involve systematic monitoring of a publicly accessible area on a large scale?",
            "yes",
            "medium",
            "Systematic large-scale monitoring is a "
            "high-risk trigger — ensure the DPIA and safeguards are complete.",
        ),
        _q(
            "dpia_automated",
            "High-risk triggers",
            "Does it involve automated decision-making, including profiling, "
            "with legal or similarly significant effects?",
            "yes",
            "medium",
            "Add human oversight and an Art. 22 "
            "safeguard/exception for significant automated decisions.",
        ),
        _q(
            "dpia_review",
            "Ongoing review",
            "Is the DPIA reviewed when the risk posed by the processing changes (Art. 35(11))?",
            "no",
            "low",
            "Set a review trigger for material changes to the processing.",
        ),
    ),
)

_LIA = AssessmentTemplate(
    type="lia",
    title="Legitimate Interest Assessment",
    framework="GDPR Art. 6(1)(f)",
    description="The three-part test for relying on legitimate interests: the "
    "purpose test (is there a real interest?), the necessity test "
    "(is processing needed for it?), and the balancing test (do "
    "the individual's rights override it?).",
    questions=(
        _q(
            "lia_interest",
            "Purpose test",
            "Is a specific legitimate interest clearly identified and "
            "articulated (yours or a third party's)?",
            "no",
            "high",
            "State the legitimate interest precisely; a vague "
            "or generic interest cannot be balanced.",
        ),
        _q(
            "lia_lawful_interest",
            "Purpose test",
            "Is that interest lawful, real, and present rather than "
            "speculative or contrary to law?",
            "no",
            "medium",
            "Confirm the interest is lawful and current, not hypothetical.",
        ),
        _q(
            "lia_necessity",
            "Necessity test",
            "Is the processing necessary to achieve that interest, with no "
            "reasonable less-intrusive means?",
            "no",
            "high",
            "Show the processing is necessary — if a less "
            "intrusive route exists, legitimate interests does not apply.",
        ),
        _q(
            "lia_alternative",
            "Necessity test",
            "Could the purpose reasonably be achieved with less data or a "
            "different, more appropriate lawful basis?",
            "yes",
            "medium",
            "If consent or another basis fits better, or "
            "less data would do, reconsider relying on legitimate interests.",
        ),
        _q(
            "lia_expectation",
            "Balancing test",
            "Would data subjects reasonably expect this processing at the "
            "time and in the context the data was collected?",
            "no",
            "high",
            "If the processing is unexpected, the balance tips "
            "against you — add transparency or reconsider the basis.",
        ),
        _q(
            "lia_impact",
            "Balancing test",
            "Is the processing likely to have an unjustified adverse impact "
            "on the individual's interests, rights, or freedoms?",
            "yes",
            "high",
            "Where adverse impact is likely and unjustified, "
            "legitimate interests fails the balancing test.",
        ),
        _q(
            "lia_vulnerable",
            "Balancing test",
            "Does it involve children's data or vulnerable individuals "
            "without additional safeguards?",
            "yes",
            "high",
            "Give special weight to children/vulnerable "
            "groups; add safeguards or do not rely on this basis.",
        ),
        _q(
            "lia_safeguards",
            "Balancing test",
            "Are safeguards in place (data minimisation, transparency, "
            "opt-out) that tip the balance in your favour?",
            "no",
            "medium",
            "Add safeguards that reduce the impact on individuals and strengthen the balance.",
        ),
        _q(
            "lia_objection",
            "Right to object",
            "Is an easy, effective mechanism to object to the processing provided (Art. 21)?",
            "no",
            "medium",
            "Provide a simple right-to-object route and honour objections.",
        ),
        _q(
            "lia_documented",
            "Accountability",
            "Is the LIA outcome documented, dated, and available for review?",
            "no",
            "low",
            "Record the LIA and its conclusion so the basis can be demonstrated (Art. 5(2)).",
        ),
    ),
)

_CCPA = AssessmentTemplate(
    type="ccpa",
    title="CCPA / CPRA Assessment",
    framework="CCPA / CPRA (California)",
    description="Assess a processing activity against the California Consumer "
    "Privacy Act as amended by the CPRA: consumer notices, rights, "
    "opt-outs, sensitive-PI limits, purpose limitation, and "
    "service-provider contracts.",
    questions=(
        _q(
            "ccpa_notice",
            "Notices",
            "Are consumers given notice at or before collection of the "
            "categories of personal information and the purposes (§1798.100)?",
            "no",
            "high",
            "Publish a notice at collection listing categories and purposes before collecting.",
        ),
        _q(
            "ccpa_do_not_sell",
            "Opt-out",
            'If personal information is sold or shared, is a "Do Not Sell or '
            'Share My Personal Information" opt-out provided (§1798.135)?',
            "no",
            "high",
            "Add the Do-Not-Sell/Share link and honour opt-out preference signals.",
        ),
        _q(
            "ccpa_sensitive_pi",
            "Sensitive PI",
            "Where sensitive personal information is used beyond permitted "
            'purposes, is a "Limit the Use of My Sensitive Personal '
            'Information" control offered (§1798.121)?',
            "no",
            "medium",
            "Offer the sensitive-PI limitation right where required.",
        ),
        _q(
            "ccpa_rights",
            "Consumer rights",
            "Can consumers exercise the rights to know, delete, correct, and "
            "opt out (§1798.105-.130)?",
            "no",
            "high",
            "Wire up know / delete / correct / opt-out request "
            "handling within statutory timelines.",
        ),
        _q(
            "ccpa_methods",
            "Consumer rights",
            "Are at least two designated methods offered for submitting "
            "requests (e.g. toll-free number and web form)?",
            "no",
            "low",
            "Provide the required request submission methods for your business type.",
        ),
        _q(
            "ccpa_purpose_limit",
            "Purpose limitation",
            "Is the use of personal information limited to the disclosed, "
            "compatible purposes (CPRA data minimisation)?",
            "no",
            "medium",
            "Limit use to disclosed purposes and minimise to what is reasonably necessary.",
        ),
        _q(
            "ccpa_retention",
            "Retention",
            "Are retention periods (or the criteria for them) disclosed and "
            "enforced per category (§1798.100(a)(3))?",
            "no",
            "medium",
            "Disclose and enforce retention per category of personal information.",
        ),
        _q(
            "ccpa_service_providers",
            "Contracts",
            "Are CCPA-compliant contracts in place with service providers, "
            "contractors, and third parties (§1798.140)?",
            "no",
            "high",
            "Execute service-provider / contractor agreements with the required CCPA terms.",
        ),
        _q(
            "ccpa_non_discrimination",
            "Non-discrimination",
            "Are consumers protected from discrimination for exercising their "
            "privacy rights (§1798.125)?",
            "no",
            "medium",
            "Ensure price/service parity for consumers who "
            "exercise rights, within the statute's financial-incentive rules.",
        ),
        _q(
            "ccpa_minors",
            "Minors",
            "Is opt-in consent obtained before selling or sharing the data of "
            "consumers under 16 (§1798.120(c))?",
            "no",
            "high",
            "Obtain opt-in (13-15) or parental consent (under "
            "13) before selling/sharing minors' data.",
        ),
        _q(
            "ccpa_risk_assessment",
            "Accountability",
            "For processing that presents significant risk, is a CPRA risk "
            "assessment / cybersecurity audit performed (§1798.185)?",
            "no",
            "medium",
            "Perform and retain the CPRA risk assessment / audit for high-risk processing.",
        ),
    ),
)

_LGPD = AssessmentTemplate(
    type="lgpd",
    title="LGPD Assessment",
    framework="LGPD (Brazil, Lei 13.709/2018)",
    description="Assess a processing activity against Brazil's Lei Geral de "
    "Proteção de Dados: legal bases, sensitive data, data-subject "
    "rights, the encarregado, transfers, security, and ANPD "
    "incident notification.",
    questions=(
        _q(
            "lgpd_legal_basis",
            "Legal basis",
            "Is each processing purpose grounded in one of the Art. 7 legal "
            "bases, recorded per activity?",
            "no",
            "high",
            "Document the Art. 7 basis for every purpose before processing.",
        ),
        _q(
            "lgpd_sensitive",
            "Sensitive data",
            "Where sensitive personal data is processed, is an Art. 11 "
            "condition (specific consent or a listed necessity) satisfied?",
            "no",
            "high",
            "Stop or re-base sensitive-data processing on an Art. 11 condition.",
        ),
        _q(
            "lgpd_rights",
            "Data-subject rights",
            "Can data subjects exercise the Art. 18 rights (confirmation, "
            "access, correction, anonymization, portability, deletion, "
            "information, revocation) through a working channel?",
            "no",
            "high",
            "Stand up and test the rights channel end to end.",
        ),
        _q(
            "lgpd_encarregado",
            "Accountability",
            "Is an encarregado (data protection officer, Art. 41) appointed "
            "and publicly identified with contact information?",
            "no",
            "medium",
            "Appoint and publish the encarregado's identity and contact.",
        ),
        _q(
            "lgpd_transfers",
            "International transfers",
            "Do international transfers rest on an Art. 33 mechanism "
            "(adequacy, contractual clauses, ANPD-approved safeguards)?",
            "no",
            "high",
            "Put an Art. 33 mechanism in place before transferring abroad.",
        ),
        _q(
            "lgpd_security",
            "Security",
            "Are the Art. 46 technical and administrative security measures "
            "implemented and reviewed for this processing?",
            "no",
            "medium",
            "Implement and evidence the Art. 46 measures.",
        ),
        _q(
            "lgpd_ripd",
            "Impact report",
            "Where processing may create relevant risk, is the Art. 38 "
            "impact report (RIPD) prepared and available to the ANPD?",
            "unknown",
            "medium",
            "Prepare the RIPD for high-risk processing and keep it current.",
        ),
        _q(
            "lgpd_incidents",
            "Incidents",
            "Will a security incident with relevant risk be reported to the "
            "ANPD and affected data subjects per Art. 48?",
            "no",
            "high",
            "Wire incident handling to the Art. 48 notification path.",
        ),
    ),
)

_PIPEDA = AssessmentTemplate(
    type="pipeda",
    title="PIPEDA Assessment",
    framework="PIPEDA (Canada)",
    description="Assess a processing activity against Canada's Personal "
    "Information Protection and Electronic Documents Act: the "
    "fair-information principles, valid consent, safeguards, "
    "access, and OPC breach reporting.",
    questions=(
        _q(
            "pipeda_purposes",
            "Purposes",
            "Are the purposes for collection identified at or before the time "
            "of collection (Principle 2)?",
            "no",
            "high",
            "Identify and record purposes before collecting.",
        ),
        _q(
            "pipeda_consent",
            "Consent",
            "Is consent valid under s. 6.1 — could the individual reasonably "
            "understand the nature, purpose and consequences of what they "
            "agreed to?",
            "no",
            "high",
            "Rework the consent flow until s. 6.1 understanding is plausible.",
        ),
        _q(
            "pipeda_limiting",
            "Limiting collection",
            "Is collection limited to what is necessary for the identified "
            "purposes (Principle 4)?",
            "no",
            "medium",
            "Trim collection to the identified purposes.",
        ),
        _q(
            "pipeda_safeguards",
            "Safeguards",
            "Are safeguards appropriate to the sensitivity of the information "
            "in place (Principle 7)?",
            "no",
            "high",
            "Match safeguards to sensitivity and evidence them.",
        ),
        _q(
            "pipeda_access",
            "Individual access",
            "Can individuals obtain access to their personal information and "
            "challenge its accuracy (Principle 9)?",
            "no",
            "medium",
            "Stand up the access-and-correction channel.",
        ),
        _q(
            "pipeda_accountability",
            "Accountability",
            "Is an individual designated as accountable for compliance, "
            "including for information transferred for processing "
            "(Principle 1)?",
            "no",
            "medium",
            "Designate the accountable individual and cover transfers by contract.",
        ),
        _q(
            "pipeda_breach",
            "Breach reporting",
            "Will a breach creating a real risk of significant harm be "
            "reported to the OPC and affected individuals, with records kept "
            "(s. 10.1-10.3)?",
            "no",
            "high",
            "Wire breach handling to the s. 10.1 report-and-record path.",
        ),
    ),
)

_US_STATE_PRIVACY = AssessmentTemplate(
    type="us_state_privacy",
    title="US State Privacy Applicability & Readiness",
    framework="US state comprehensive privacy laws (20 states, 2026)",
    description="Applicability and readiness across the US state "
    "comprehensive privacy laws in effect in 2026 (California, Virginia, "
    "Colorado, Connecticut, Utah, Texas, Oregon, Montana, Florida, "
    "Delaware, Iowa, Nebraska, New Hampshire, New Jersey, Tennessee, "
    "Minnesota, Maryland, Indiana, Kentucky, Rhode Island). A structured "
    "self-assessment of the common obligations — never a state-by-state "
    "legal opinion.",
    questions=(
        _q(
            "ussp_applicability",
            "Applicability",
            "Has the organization determined which state laws apply to it, "
            "against each law's residency and processing thresholds?",
            "no",
            "high",
            "Map consumer counts and revenue per state against each "
            "statute's applicability thresholds; record the analysis.",
        ),
        _q(
            "ussp_rights_intake",
            "Consumer rights",
            "Can consumers exercise access, deletion, correction, and "
            "portability through a documented intake with statutory "
            "deadlines tracked?",
            "no",
            "high",
            "Stand up one intake covering the strictest deadline; track "
            "due dates per request.",
        ),
        _q(
            "ussp_appeals",
            "Consumer rights",
            "Is there a documented appeal process for refused requests, "
            "with the state-required appeal disclosures?",
            "no",
            "medium",
            "Most 2026 state laws require an appeal path; document it in "
            "the privacy notice.",
        ),
        _q(
            "ussp_opt_outs",
            "Opt-outs",
            "Are opt-outs of sale, targeted advertising, and significant "
            "profiling honored across every applicable state?",
            "no",
            "high",
            "Wire the opt-out signal into the ad/analytics stack; keep "
            "evidence of suppression.",
        ),
        _q(
            "ussp_universal_signal",
            "Opt-outs",
            "Are universal opt-out signals (e.g. Global Privacy Control) "
            "recognized where required (California, Colorado, Connecticut, "
            "Texas, and others)?",
            "no",
            "high",
            "Honor GPC as a valid opt-out where a statute or rule "
            "requires it.",
        ),
        _q(
            "ussp_sensitive_consent",
            "Sensitive data",
            "Is consent obtained before processing sensitive data where "
            "required, and is the Maryland-style restriction (no sale of "
            "sensitive data) respected?",
            "no",
            "high",
            "Inventory sensitive-data flows; Maryland's MODPA is the "
            "strictest floor — no sensitive-data sale, strict necessity.",
        ),
        _q(
            "ussp_assessments",
            "Assessments",
            "Are data protection assessments performed and retained for "
            "targeted advertising, sale, sensitive data, and profiling "
            "with significant effects?",
            "no",
            "medium",
            "Several states can demand these assessments; retain them.",
        ),
        _q(
            "ussp_contracts",
            "Processors",
            "Do processor contracts carry the state-required clauses "
            "(purpose limits, confidentiality, deletion, audit, "
            "subcontractor flow-down)?",
            "no",
            "medium",
            "One processor addendum can satisfy the state common core; "
            "review against the strictest applicable law.",
        ),
        _q(
            "ussp_minors",
            "Minors",
            "Are heightened minor-data duties met where applicable (no "
            "targeted advertising or sale for known minors in several "
            "states)?",
            "no",
            "high",
            "Suppress targeted advertising and sale for known minors; "
            "verify age-knowledge handling.",
        ),
        _q(
            "ussp_notice",
            "Notices",
            "Does the privacy notice disclose categories, purposes, "
            "sharing, rights, and opt-out methods as the applicable "
            "states require?",
            "no",
            "medium",
            "Keep one notice covering the union of state disclosure "
            "requirements; version it.",
        ),
    ),
)

_COLORADO_ADMT = AssessmentTemplate(
    type="colorado_admt",
    title="Colorado ADMT Act Readiness",
    framework="Colorado SB 26-189 (C.R.S. § 6-1-1701 ff., eff. 2027-01-01)",
    description="Readiness for Colorado's automated-decision-making "
    "technology act (the 2026 replacement of SB 24-205), covering ADMT "
    "used in consequential decisions: developer documentation, "
    "pre-decision and adverse-decision disclosures, correction and human "
    "review rights, and three-year record-keeping. Never legal advice.",
    questions=(
        _q(
            "coadmt_inventory",
            "Scope",
            "Is every ADMT used in consequential decisions (housing, "
            "employment, education, financial, government services, "
            "healthcare, insurance, legal) inventoried for Colorado "
            "consumers?",
            "no",
            "high",
            "Inventory ADMT against the consequential-decision list; the "
            "act's duties attach per system (§ 6-1-1701).",
        ),
        _q(
            "coadmt_developer_docs",
            "Documentation",
            "Is the developer's statement in hand (intended and harmful or "
            "inappropriate uses, data categories, known limitations and "
            "risks, instructions for use, monitoring, meaningful human "
            "review)?",
            "no",
            "high",
            "Obtain (or as developer, provide) the § 6-1-1702 statement; "
            "track material updates.",
        ),
        _q(
            "coadmt_pre_notice",
            "Disclosures",
            "Is a clear and conspicuous pre-decision notice given that "
            "ADMT is or will be used, with instructions for accessing "
            "more information?",
            "no",
            "high",
            "A prominent public notice at consumer touchpoints satisfies "
            "§ 6-1-1704(1)-(2).",
        ),
        _q(
            "coadmt_adverse_notice",
            "Disclosures",
            "After an adverse decision, does the consumer receive within "
            "30 days a plain-language description of the decision and the "
            "ADMT's role, plus a path to request system name, version, "
            "developer, and data types?",
            "no",
            "high",
            "Wire the § 6-1-1704(3) adverse-outcome disclosure into the "
            "decision workflow.",
        ),
        _q(
            "coadmt_correction",
            "Consumer rights",
            "Can consumers correct factually incorrect or materially "
            "inaccurate personal data used in the decision, on request?",
            "no",
            "high",
            "§ 6-1-1705(1): provide access and correction after an "
            "adverse outcome.",
        ),
        _q(
            "coadmt_human_review",
            "Consumer rights",
            "Is meaningful human review and reconsideration of the "
            "decision offered to the extent commercially reasonable?",
            "no",
            "high",
            "Name the reviewers and document the reconsideration path.",
        ),
        _q(
            "coadmt_records",
            "Records",
            "Are compliance records kept for at least three years, "
            "including ADMT version identifiers, changelogs, and material "
            "mitigation changes?",
            "no",
            "medium",
            "§ 6-1-1703: retain versioned records demonstrating "
            "compliance for three years.",
        ),
    ),
)

_NYC_LL144 = AssessmentTemplate(
    type="nyc_ll144",
    title="NYC Local Law 144 AEDT Readiness",
    framework="NYC Local Law 144 (AEDT; DCWP-enforced since 2023-07-05)",
    description="Readiness for New York City's automated employment "
    "decision tool law: the annual independent bias audit, the published "
    "results summary, and the candidate notices. A readiness check of the "
    "employer's own program — never a bias audit itself.",
    questions=(
        _q(
            "ll144_inventory",
            "Scope",
            "Is every AEDT used to substantially assist employment "
            "decisions for NYC candidates or employees inventoried?",
            "no",
            "high",
            "The duties attach per tool; include vendor tools used in "
            "screening and promotion.",
        ),
        _q(
            "ll144_audit_current",
            "Bias audit",
            "Has each AEDT had a bias audit within the last year, "
            "computing impact ratios across the required "
            "sex/race-ethnicity categories?",
            "no",
            "high",
            "No audit within one year means the tool may not be used; "
            "schedule the annual audit.",
        ),
        _q(
            "ll144_auditor_independent",
            "Bias audit",
            "Was the auditor independent — not involved in using, "
            "developing, or distributing the AEDT, and free of "
            "compromising employment or financial ties?",
            "no",
            "high",
            "Independence is definitional; an internal team that uses "
            "the tool does not qualify.",
        ),
        _q(
            "ll144_published_summary",
            "Publication",
            "Is a summary of the most recent audit public on the careers "
            "site — audit date, tool first-use date, and the impact "
            "ratios for every category tested?",
            "no",
            "high",
            "Post the summary in a clear and conspicuous location before "
            "continued use.",
        ),
        _q(
            "ll144_advance_notice",
            "Notices",
            "Do NYC candidates and employees receive notice at least 10 "
            "business days before the AEDT is used on them?",
            "no",
            "high",
            "Notice may be on the careers page or sent directly; keep "
            "evidence of timing.",
        ),
        _q(
            "ll144_notice_content",
            "Notices",
            "Does the notice state the job qualifications and "
            "characteristics the AEDT uses, and how to request an "
            "alternative selection process or accommodation?",
            "no",
            "medium",
            "Include data categories, sources, and the retention policy "
            "or where to request them.",
        ),
    ),
)

_TEXAS_TRAIGA = AssessmentTemplate(
    type="texas_traiga",
    title="Texas TRAIGA Attestation",
    framework="Texas TRAIGA (HB 149, eff. 2026-01-01)",
    description="Attestation against the Texas Responsible AI Governance "
    "Act's intent-based prohibited practices, plus the government-context "
    "disclosure duties. Questions where 'yes' flags risk are deliberate: "
    "they name the prohibited conduct. Never legal advice.",
    questions=(
        _q(
            "traiga_manipulation",
            "Prohibited practices",
            "Could any AI system be found to intentionally incite or "
            "encourage self-harm, violence, or criminal activity through "
            "behavioral manipulation?",
            "yes",
            "critical",
            "TRAIGA prohibits AI developed or deployed with that intent; "
            "document intended use and safeguards.",
        ),
        _q(
            "traiga_discrimination",
            "Prohibited practices",
            "Could any AI system be found to have been developed or "
            "deployed with the intent to unlawfully discriminate against "
            "a protected class?",
            "yes",
            "critical",
            "Intent is the trigger; retain design intent and testing "
            "records that evidence lawful purpose.",
        ),
        _q(
            "traiga_social_scoring",
            "Prohibited practices",
            "Is any AI system used for social scoring of natural persons "
            "by or for a government entity?",
            "yes",
            "critical",
            "Social scoring is prohibited; withdraw or re-scope any such "
            "use.",
        ),
        _q(
            "traiga_biometrics",
            "Prohibited practices",
            "Does any system capture or use biometric identifiers of "
            "individuals without consent where TRAIGA requires it?",
            "yes",
            "high",
            "Review the biometric provisions with counsel and record the "
            "consent basis.",
        ),
        _q(
            "traiga_explicit_content",
            "Prohibited practices",
            "Could any system be used to produce or distribute unlawful "
            "sexually explicit content, including deepfakes or CSAM?",
            "yes",
            "critical",
            "Prohibited outright; enforce generation and distribution "
            "safeguards and takedown paths.",
        ),
        _q(
            "traiga_gov_disclosure",
            "Disclosures",
            "Where the organization acts for a Texas government agency, "
            "are individuals told when they are interacting with an AI "
            "system?",
            "no",
            "high",
            "Government-context interactions carry disclosure duties; "
            "confirm scope with counsel.",
        ),
        _q(
            "traiga_intent_records",
            "Records",
            "Are intended-purpose and design-intent records retained for "
            "each system, given TRAIGA's intent-based liability framing?",
            "no",
            "medium",
            "Intent records are the practical defense; keep purpose "
            "statements and testing evidence.",
        ),
    ),
)

_ILLINOIS_HB3773 = AssessmentTemplate(
    type="illinois_hb3773",
    title="Illinois AI Employment (HB 3773) Readiness",
    framework="Illinois HB 3773 / IHRA (eff. 2026-01-01)",
    description="Readiness for the Illinois Human Rights Act amendments on "
    "AI in employment: discriminatory-effect testing across covered "
    "decisions, the zip-code proxy prohibition, and employee and "
    "applicant notice. Never legal advice.",
    questions=(
        _q(
            "ilhb_inventory",
            "Scope",
            "Is every use of AI in covered employment decisions "
            "(recruitment, hiring, promotion, renewal, training or "
            "apprenticeship selection, discharge, discipline, tenure, "
            "terms and privileges) inventoried for Illinois employees "
            "and applicants?",
            "no",
            "high",
            "The IHRA amendment covers the full employment lifecycle; "
            "include vendor tools.",
        ),
        _q(
            "ilhb_effect_testing",
            "Discrimination",
            "Is each system tested for discriminatory effect on IHRA "
            "protected classes, with results and remediation recorded?",
            "no",
            "high",
            "Liability attaches to discriminatory EFFECT, not intent — "
            "test outcomes, not intentions.",
        ),
        _q(
            "ilhb_zip_proxy",
            "Discrimination",
            "Is zip code excluded from use as a proxy for protected "
            "classes in any employment decision model?",
            "no",
            "high",
            "HB 3773 prohibits zip-code proxying explicitly; verify "
            "features and correlated inputs.",
        ),
        _q(
            "ilhb_notice",
            "Notices",
            "Are employees and applicants notified that AI is used in "
            "covered employment decisions, per the IDHR notice rules?",
            "no",
            "high",
            "Failure to notify is itself a violation; follow the IDHR "
            "rules on timing and means.",
        ),
        _q(
            "ilhb_remediation",
            "Remediation",
            "When testing finds disparity, is there a documented "
            "remediation path (model change, human review, or "
            "discontinuation)?",
            "no",
            "medium",
            "Record what was found, what changed, and when it was "
            "re-tested.",
        ),
        _q(
            "ilhb_vendor_diligence",
            "Vendors",
            "For vendor-supplied employment AI, has the vendor's own "
            "bias testing been obtained and reviewed?",
            "no",
            "medium",
            "Employer liability does not transfer to the vendor; review "
            "their evidence yourself.",
        ),
    ),
)

_ISO42001_ENTRIES = (
    ("4.1", "Context", "understands its role as an AI provider, deployer, or "
     "user and the internal and external issues bearing on the AIMS", "medium"),
    ("4.4", "Context", "has established and continually improves an AI "
     "management system with the needed processes", "high"),
    ("5.2", "Leadership", "maintains a top-management-approved AI policy "
     "aligned with organizational objectives", "high"),
    ("5.3", "Leadership", "assigns and communicates AI governance roles, "
     "responsibilities, and authorities", "high"),
    ("6.1", "Planning", "assesses AI risks against defined criteria and "
     "treats the risks it identifies", "high"),
    ("6.1.4", "Planning", "assesses the potential impacts of its AI systems "
     "on individuals, groups, and society", "high"),
    ("7.2", "Support", "ensures the people doing AIMS work are competent, "
     "with evidence retained", "medium"),
    ("7.5", "Support", "creates and controls the documented information the "
     "AIMS requires", "medium"),
    ("8.1", "Operation", "plans and controls the AI life-cycle processes "
     "needed to meet AIMS requirements", "high"),
    ("9.1", "Evaluation", "monitors, measures, analyses, and evaluates the "
     "AIMS's performance and effectiveness", "medium"),
    ("9.2", "Evaluation", "conducts internal AIMS audits at planned "
     "intervals", "medium"),
    ("9.3", "Evaluation", "reviews the AIMS at top-management level at "
     "planned intervals", "medium"),
    ("10.1", "Improvement", "corrects nonconformities and continually "
     "improves the AIMS", "medium"),
    ("A.2", "Annex A", "keeps management-approved AI policies current and "
     "consistent with other organizational policies", "medium"),
    ("A.3", "Annex A", "defines the internal organization for AI, including "
     "roles and the reporting of AI concerns", "medium"),
    ("A.4", "Annex A", "manages the resources AI systems need — data, "
     "tooling, human, and computing", "medium"),
    ("A.5", "Annex A", "performs and documents AI system impact assessments "
     "for affected individuals and societies", "high"),
    ("A.6", "Annex A", "governs the AI system life cycle from requirements "
     "through operation and retirement", "high"),
    ("A.7", "Annex A", "manages data for AI systems, including provenance, "
     "quality, and preparation", "high"),
    ("A.8", "Annex A", "provides interested parties the information they "
     "need about its AI systems", "medium"),
    ("A.9", "Annex A", "governs the responsible use of AI systems within "
     "intended-purpose limits", "medium"),
    ("A.10", "Annex A", "manages third-party and customer relationships "
     "across the AI supply chain", "medium"),
)

_CPPA_ADMT = AssessmentTemplate(
    type="cppa_admt",
    title="California ADMT & Risk Assessment Readiness",
    framework="CPPA CCPA regulations (OAL-approved 2025-09-23)",
    description="Readiness for California's finalized ADMT, risk-assessment, "
    "and cybersecurity-audit regulations: risk assessments required since "
    "2026-01-01 (CPPA submission by 2028-04-01), ADMT opt-out and notice "
    "duties by 2027-01-01, audit certifications staggered from 2028. "
    "Structured self-assessment, never legal advice.",
    questions=(
        _q(
            "cppadmt_inventory",
            "Scope",
            "Is every ADMT used for significant decisions (financial or "
            "lending services, housing, education, employment or "
            "compensation, healthcare) inventoried for California "
            "consumers?",
            "no",
            "high",
            "The duties attach per technology; include vendor tools that "
            "replace or substantially replace human judgment.",
        ),
        _q(
            "cppadmt_pre_notice",
            "ADMT notices",
            "Does the pre-use notice cover the ADMT's purpose, the opt-out "
            "and how to exercise it, the access right, how the ADMT works "
            "and what data affects outputs, the alternative process, and "
            "the anti-retaliation statement?",
            "no",
            "high",
            "All elements are enumerated in the regulation; a generic "
            "privacy-policy mention does not satisfy them.",
        ),
        _q(
            "cppadmt_opt_out",
            "ADMT rights",
            "Can consumers opt out of ADMT for significant decisions — or "
            "does the business properly fit an exception (human-review "
            "appeal with overturn authority, or the narrow "
            "hiring/admissions assessment exception with demonstrated "
            "non-discrimination)?",
            "no",
            "high",
            "Document which path each ADMT relies on; the exceptions have "
            "conditions that must be evidenced.",
        ),
        _q(
            "cppadmt_access",
            "ADMT rights",
            "On request, can the business explain in plain language the "
            "ADMT's purpose, its logic and parameters, the decision "
            "outcome, and how it will be used going forward?",
            "no",
            "medium",
            "Wire the access response into the DSAR intake; the "
            "explanation must be decision-specific.",
        ),
        _q(
            "cppadmt_risk_assessments",
            "Risk assessments",
            "Are risk assessments performed for every triggering activity "
            "— selling/sharing, sensitive personal information, ADMT "
            "significant decisions, automated trait inference, and "
            "TRAINING ADMT or facial-recognition/biometric technologies?",
            "no",
            "high",
            "Required since 2026-01-01. The training trigger catches AI "
            "development, not just deployment.",
        ),
        _q(
            "cppadmt_assessment_content",
            "Risk assessments",
            "Does each assessment record purpose, data categories, "
            "operational elements, benefits, consumer privacy impacts, "
            "safeguards, the go/no-go decision, and who participated and "
            "approved?",
            "no",
            "medium",
            "The content list is prescriptive; retain for the processing "
            "duration or five years.",
        ),
        _q(
            "cppadmt_submission",
            "Risk assessments",
            "Is the annual CPPA submission (by April 1, first due "
            "2028-04-01) calendared with an owner?",
            "no",
            "medium",
            "Submission is to the agency, not just a file: assign the "
            "April 1 obligation now.",
        ),
        _q(
            "cppadmt_cyber_audit",
            "Cybersecurity audits",
            "If the thresholds apply (50%+ revenue from selling/sharing, "
            "or $25M+ revenue with 250K+ consumers or 50K+ sensitive "
            "records), is the independent annual audit scheduled against "
            "the staggered certification deadlines (2028/2029/2030 by "
            "revenue)?",
            "no",
            "medium",
            "The auditor must be independent and sign a qualification "
            "and independence certification.",
        ),
    ),
)

_ISO42001 = AssessmentTemplate(
    type="iso42001",
    title="ISO/IEC 42001 AIMS Readiness",
    framework="ISO/IEC 42001:2023",
    description="Readiness against the AI management system standard: the "
    "clause 4-10 management loop and the Annex A control themes, as "
    "original outcome paraphrases. A readiness self-assessment — never a "
    "certification audit, and no standards text is reproduced.",
    questions=_control_questions("iso42001", _ISO42001_ENTRIES),
)

_ISO27701 = AssessmentTemplate(
    type="iso27701",
    title="ISO/IEC 27701 PIMS Readiness",
    framework="ISO/IEC 27701 (Privacy Information Management System)",
    description="Readiness self-assessment for a privacy information "
    "management system extending an ISO 27001 ISMS: scope and roles, PII "
    "inventory, legal-basis and consent records, data-subject requests, "
    "processor contracts, transfers, breach response, retention, and the "
    "management-system loop. Original paraphrases; no standards text is "
    "reproduced, and completing this is not certification.",
    questions=(
        _q(
            "p27701_scope",
            "PIMS scope",
            "Is the PIMS scope defined on top of an operating ISO 27001 "
            "ISMS, stating whether the organization acts as PII "
            "controller, PII processor, or both?",
            "no",
            "high",
            "Define the PIMS scope and controller/processor roles before "
            "anything else; every other control inherits it.",
        ),
        _q(
            "p27701_inventory",
            "PII inventory",
            "Is there a maintained inventory of PII categories, processing "
            "purposes, storage locations, and flows in scope?",
            "no",
            "high",
            "Build the PII inventory (the data map) and keep it current.",
        ),
        _q(
            "p27701_legal_basis",
            "Legal basis & consent",
            "Is the legal basis for each processing purpose recorded, with "
            "consent captured and withdrawable where consent is the basis?",
            "no",
            "high",
            "Record a basis per purpose and operate a durable consent "
            "record with withdrawal.",
        ),
        _q(
            "p27701_rights",
            "Data-subject requests",
            "Is there a working, tested process to receive, verify, and "
            "fulfill PII principals' requests (access, correction, "
            "deletion) within applicable deadlines?",
            "no",
            "high",
            "Stand up the request pipeline with identity verification and "
            "deadline tracking.",
        ),
        _q(
            "p27701_processors",
            "Processor contracts",
            "Do written contracts with PII processors and subprocessors "
            "cover processing instructions, confidentiality, breach "
            "notice, and return-or-deletion at termination?",
            "no",
            "medium",
            "Close DPA gaps with every processor; track renewals.",
        ),
        _q(
            "p27701_transfers",
            "Transfers",
            "Are cross-border PII transfers identified, with their "
            "safeguards and destinations documented and available to "
            "principals on request?",
            "no",
            "medium",
            "Map transfers and document the safeguard behind each.",
        ),
        _q(
            "p27701_privacy_by_design",
            "Privacy by design",
            "Do new products and changes in scope run a documented privacy "
            "impact review (necessity, minimization, defaults) before "
            "release?",
            "no",
            "medium",
            "Gate releases on a recorded privacy review.",
        ),
        _q(
            "p27701_breach",
            "Breach response",
            "Is there a tested PII breach response process with roles, "
            "regulator/principal notification criteria, and records of "
            "every incident, notified or not?",
            "no",
            "high",
            "Adopt a breach runbook with jurisdiction deadlines and a "
            "complete incident record.",
        ),
        _q(
            "p27701_retention",
            "Retention & deletion",
            "Are retention periods defined per PII category and enforced "
            "with actual deletion or anonymization at end of life?",
            "no",
            "medium",
            "Define and enforce retention schedules; prove deletion.",
        ),
        _q(
            "p27701_awareness",
            "Awareness",
            "Have staff who touch PII received privacy training relevant "
            "to their roles, with completion recorded?",
            "no",
            "low",
            "Run role-based privacy training and record completion.",
        ),
        _q(
            "p27701_audit",
            "Audit & review",
            "Does the PIMS run the management-system loop — internal "
            "audits, management review, and corrective actions — on a "
            "schedule?",
            "no",
            "medium",
            "Schedule internal PIMS audits and management reviews; track "
            "findings to closure.",
        ),
        _q(
            "p27701_applicability",
            "Control applicability",
            "Is there a statement of applicability for the privacy "
            "control set, with justified exclusions?",
            "no",
            "medium",
            "Produce the SoA for the privacy controls; justify every "
            "exclusion in writing.",
        ),
    ),
)

TEMPLATES: dict[str, AssessmentTemplate] = {
    t.type: t
    for t in (
        _PIA,
        _DPIA,
        _LIA,
        _CCPA,
        _LGPD,
        _PIPEDA,
        _US_STATE_PRIVACY,
        _ISO27701,
        _CPPA_ADMT,
        _COLORADO_ADMT,
        _NYC_LL144,
        _TEXAS_TRAIGA,
        _ILLINOIS_HB3773,
        _AIRA,
        _VENDOR_RISK,
        _TIA,
        _SOX_CONTROL,
        _FRAUD_RISK,
        _ITGC,
        _CREDIT_RISK,
        _CLOSE_READINESS,
        _HIPAA,
        _SOC2,
        _ISO27001,
        _ISO42001,
        _NIST_CSF,
        _NIST_800_53,
        _CIS_V8,
        _PCI_DSS,
        _CMMC_L2,
        _FEDRAMP_MODERATE,
    )
}


# --- Governed questionnaire releases ---------------------------------------
#
# Questionnaire policy is executable governance data: it determines which
# risks are asked about and therefore what can be approved.  Treating one
# mutable ``<type>.json`` file as the policy let an operator silently weaken a
# built-in questionnaire, changed the meaning of in-flight assessments, and
# made concurrent edits last-writer-wins.  The store below uses:
#
# * immutable, content-addressed release artifacts;
# * one monotonic per-type pointer/tombstone with compare-and-swap;
# * stable question ids carried by the editor; and
# * a durable at-least-once audit receipt embedded in the pointer.
#
# The old single-file format is read as revision 0 and migrated on the next
# governed publication.  It is never silently discarded or treated as an
# absent override when it is malformed.

TEMPLATE_DEPARTMENTS = ("privacy", "finance", "security")
_TYPE_RE = r"^[a-z0-9_]{2,40}$"
_SEVERITIES = ("low", "medium", "high")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TEMPLATE_STATE_SCHEMA = 2
_AUDIT_READ_RETRY_LIMIT = 8
_AUDIT_OUTBOX_LIMIT = 128
_MAX_TEMPLATE_QUESTIONS = 500


class AssessmentConflict(RuntimeError):
    """A governed record no longer matches the revision the caller reviewed."""


class AssessmentStateError(RuntimeError):
    """Persisted assessment governance state is present but cannot be trusted."""


class AssessmentAuditBackpressure(AssessmentStateError):
    """A governed write was refused because its durable audit outbox is full."""


class AssessmentTransitionError(AssessmentStateError):
    """A requested valid-state transition is not currently permitted."""


def _validated_revision_value(value, *, label: str) -> int:
    """Require an exact non-boolean monotonic revision integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AssessmentStateError(f"{label} revision is invalid")
    return value


def _record_revision(
    record: dict | None,
    *,
    label: str,
    key: str = "revision",
    required: bool = False,
) -> int:
    if record is None or key not in record:
        if required:
            raise AssessmentStateError(f"{label} revision is invalid")
        return 0
    return _validated_revision_value(record.get(key), label=label)


def _validated_audit_pending(value, *, label: str) -> list[dict]:
    pending = [] if value is None else value
    if (
        not isinstance(pending, list)
        or any(not isinstance(receipt, dict) for receipt in pending)
        or len(pending) > _AUDIT_OUTBOX_LIMIT
    ):
        raise AssessmentStateError(f"{label} audit outbox is invalid")
    event_ids: set[str] = set()
    for receipt in pending:
        event_id = receipt.get("event_id")
        if (
            not isinstance(event_id, str)
            or not 1 <= len(event_id) <= 128
            or event_id in event_ids
            or not isinstance(receipt.get("kind"), str)
            or not isinstance(receipt.get("actor"), str)
            or not isinstance(receipt.get("payload"), dict)
        ):
            raise AssessmentStateError(f"{label} audit outbox is invalid")
        event_ids.add(event_id)
    return list(pending)


def _reserve_audit_slot(pending: list[dict], *, label: str) -> None:
    if len(pending) >= _AUDIT_OUTBOX_LIMIT:
        raise AssessmentAuditBackpressure(
            f"{label} audit outbox is full; retry audit delivery before writing"
        )


def _custom_templates_dir() -> Path:
    from .paths import data_dir

    return data_dir("custom_templates")


def _canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _template_policy_record(record: dict) -> dict:
    """Fields whose exact bytes define questionnaire semantics."""
    return {
        "type": str(record.get("type", "")),
        "title": str(record.get("title", "")),
        "framework": str(record.get("framework", "")),
        "department": str(record.get("department", "privacy")),
        "description": str(record.get("description", "")),
        "questions": [dict(q) for q in (record.get("questions") or [])],
    }


def _template_digest(record: dict) -> str:
    return hashlib.sha256(
        _canonical_json(_template_policy_record(record)).encode("utf-8")
    ).hexdigest()


def _template_record(tpl: AssessmentTemplate, *, department: str) -> dict:
    return {
        "type": tpl.type,
        "title": tpl.title,
        "framework": tpl.framework,
        "department": department,
        "description": tpl.description,
        "questions": [asdict(q) for q in tpl.questions],
    }


def _builtin_record(assessment_type: str) -> dict | None:
    tpl = TEMPLATES.get(assessment_type)
    if tpl is None:
        return None
    if assessment_type in {
        "sox_control",
        "fraud_risk",
        "itgc",
        "credit_risk",
        "close_readiness",
    }:
        department = "finance"
    elif assessment_type in {
        "soc2",
        "iso27001",
        "iso42001",
        "nist_csf",
        "nist_800_53",
        "cis_v8",
        "pci_dss",
        "hipaa",
        "cmmc_l2",
        "fedramp_moderate",
    }:
        department = "security"
    else:
        department = "privacy"
    return _template_record(tpl, department=department)


def _state_path(assessment_type: str) -> Path:
    return _custom_templates_dir() / f"{assessment_type}.json"


def _release_path(assessment_type: str, digest: str) -> Path:
    if not _DIGEST_RE.fullmatch(digest):
        raise AssessmentStateError("questionnaire release digest is invalid")
    return _custom_templates_dir() / "releases" / assessment_type / f"{digest}.json"


def _read_json(path: Path) -> dict | None:
    from .file_lock import atomic_read_text, ensure_private_file

    if not path.exists():
        return None
    try:
        ensure_private_file(path)
        value = json.loads(atomic_read_text(path, encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AssessmentStateError(
            f"questionnaire state is unreadable or corrupt: {path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise AssessmentStateError(f"questionnaire state is not an object: {path.name}")
    return value


def _validated_release(record: dict, assessment_type: str, expected_digest: str) -> dict:
    policy = _template_policy_record(record)
    if policy["type"] != assessment_type:
        raise AssessmentStateError("questionnaire release type does not match its path")
    actual = _template_digest(policy)
    claimed = str(record.get("digest") or actual)
    if claimed != expected_digest or actual != expected_digest:
        raise AssessmentStateError("questionnaire release digest does not verify")
    # Re-run the full semantic validator on data loaded from disk.  A valid
    # digest only proves consistency, not that malicious/tampered data is safe.
    _normalise_template(policy)
    return policy


def _load_state_unlocked(assessment_type: str) -> dict | None:
    raw = _read_json(_state_path(assessment_type))
    if raw is None:
        return None
    # Legacy v1: the state file was the mutable policy artifact itself.
    if "questions" in raw and "active_digest" not in raw:
        policy = _normalise_template(raw)
        if policy["type"] != assessment_type:
            raise AssessmentStateError("legacy questionnaire type does not match its path")
        digest = _template_digest(policy)
        legacy_revision = _record_revision(raw, label="legacy questionnaire")
        return {
            "schema_version": 1,
            "type": assessment_type,
            "revision": legacy_revision,
            "active_digest": digest,
            "_legacy_release": policy,
            "_audit_pending": [],
        }
    schema = raw.get("schema_version")
    _record_revision(raw, label="questionnaire pointer", required=True)
    if (
        not isinstance(schema, int)
        or isinstance(schema, bool)
        or schema != _TEMPLATE_STATE_SCHEMA
        or raw.get("type") != assessment_type
    ):
        raise AssessmentStateError("questionnaire pointer identity is invalid")
    active = raw.get("active_digest")
    if not isinstance(active, str):
        raise AssessmentStateError("questionnaire pointer digest is invalid")
    if active and not _DIGEST_RE.fullmatch(active):
        raise AssessmentStateError("questionnaire pointer digest is invalid")
    _validated_audit_pending(
        raw.get("_audit_pending"),
        label="questionnaire",
    )
    return dict(raw)


def _active_release_unlocked(assessment_type: str, state: dict) -> dict | None:
    digest = str(state.get("active_digest") or "")
    if not digest:
        return None
    legacy = state.get("_legacy_release")
    if isinstance(legacy, dict):
        return _validated_release(legacy, assessment_type, digest)
    release = _read_json(_release_path(assessment_type, digest))
    if release is None:
        raise AssessmentStateError("active questionnaire release is missing")
    return _validated_release(release, assessment_type, digest)


def _write_release_unlocked(assessment_type: str, policy: dict, digest: str) -> None:
    from .file_lock import atomic_write_text, ensure_private_directory

    path = _release_path(assessment_type, digest)
    ensure_private_directory(path.parent)
    release = {"schema_version": 1, "digest": digest, **policy}
    existing = _read_json(path)
    if existing is not None:
        _validated_release(existing, assessment_type, digest)
        if _canonical_json(existing) != _canonical_json(release):
            raise AssessmentStateError("immutable questionnaire release was replaced")
        return
    atomic_write_text(path, json.dumps(release, indent=2, ensure_ascii=False), mode=0o600)


def _write_state_unlocked(assessment_type: str, state: dict) -> None:
    from .file_lock import atomic_write_text, ensure_private_directory

    path = _state_path(assessment_type)
    ensure_private_directory(path.parent)
    atomic_write_text(path, json.dumps(state, indent=2, ensure_ascii=False), mode=0o600)


def _audit_receipt(kind: str, actor: str, **payload) -> dict:
    return {
        "event_id": uuid.uuid4().hex,
        "kind": kind,
        "actor": str(actor or "system")[:256],
        "payload": payload,
        "created_at": time.time(),
    }


def _deliver_audit(receipt: dict) -> bool:
    try:
        from .audit import record as audit_record

        return bool(
            audit_record(
                str(receipt.get("kind") or "assessment_governance"),
                agent=str(receipt.get("actor") or "system"),
                event_id=str(receipt.get("event_id") or ""),
                **dict(receipt.get("payload") or {}),
            )
        )
    except Exception:  # noqa: BLE001 -- durable receipt remains for retry
        return False


def _flush_template_audit(assessment_type: str) -> None:
    """Best-effort delivery; the pointer retains undelivered stable event ids."""
    from .file_lock import cross_process_lock

    path = _state_path(assessment_type)
    with cross_process_lock(path, strict=True):
        state = _load_state_unlocked(assessment_type)
        pending = list((state or {}).get("_audit_pending") or [])
    delivered = {str(item.get("event_id")) for item in pending if _deliver_audit(item)}
    if not delivered:
        return
    with cross_process_lock(path, strict=True):
        state = _load_state_unlocked(assessment_type)
        if state is None:
            return
        current = list(state.get("_audit_pending") or [])
        state["_audit_pending"] = [
            item for item in current if str(item.get("event_id")) not in delivered
        ]
        _write_state_unlocked(assessment_type, state)


def _load_state_with_audit_retry(assessment_type: str, *, retry: bool) -> dict | None:
    state = _load_state_unlocked(assessment_type)
    if retry and state and state.get("_audit_pending"):
        _flush_template_audit(assessment_type)
        state = _load_state_unlocked(assessment_type)
    return state


def _normalise_template(
    payload: dict,
    *,
    historical_ids: set[str] | None = None,
    reusable_ids: set[str] | None = None,
) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("template must be an object")
    t = str(payload.get("type", "")).strip().lower()
    if not re.fullmatch(_TYPE_RE, t):
        raise ValueError("type must be a slug: lowercase letters, digits, _")
    title = str(payload.get("title", "")).strip()[:120]
    framework = str(payload.get("framework", "")).strip()[:200]
    if not title or not framework:
        raise ValueError("title and framework are required")
    department = str(payload.get("department", "privacy")).strip().lower()
    if department not in TEMPLATE_DEPARTMENTS:
        raise ValueError(f"department must be one of {TEMPLATE_DEPARTMENTS}")
    raw_qs = payload.get("questions") or []
    if not 1 <= len(raw_qs) <= _MAX_TEMPLATE_QUESTIONS:
        raise ValueError(f"a template needs 1-{_MAX_TEMPLATE_QUESTIONS} questions")
    questions = []
    seen_ids: set[str] = set()
    explicit_ids: dict[int, str] = {}
    historical = set(historical_ids or ())
    reusable = set(reusable_ids or ())
    # Reserve every existing id before allocating ids for newly-inserted blank
    # rows. Otherwise inserting a blank row before ``type_q1`` would steal q1
    # and either renumber or reject the unchanged existing question.
    for i, q in enumerate(raw_qs, start=1):
        if not isinstance(q, dict):
            raise ValueError(f"question {i}: must be an object")
        raw_qid = str(q.get("id", ""))
        qid = raw_qid.strip().lower()
        if not qid:
            continue
        if raw_qid != qid:
            raise ValueError(f"question {i}: id must already be lowercase with no padding")
        if not re.fullmatch(r"^[a-z0-9_]{1,60}$", qid) or qid in seen_ids:
            raise ValueError(f"question {i}: bad or duplicate id {qid!r}")
        if qid in historical and qid not in reusable:
            raise ValueError(f"question {i}: id {qid!r} belongs to a retired question")
        explicit_ids[i] = qid
        seen_ids.add(qid)
    next_id = 1
    for i, q in enumerate(raw_qs, start=1):
        text = str(q.get("text", "")).strip()[:500]
        if len(text) < 3:
            raise ValueError(f"question {i}: text is required")
        qid = explicit_ids.get(i, "")
        if not qid:
            while f"{t}_q{next_id}" in seen_ids or f"{t}_q{next_id}" in historical:
                next_id += 1
            qid = f"{t}_q{next_id}"
            seen_ids.add(qid)
            next_id += 1
        risk_answer = str(q.get("risk_answer", "no")).strip().lower()
        if risk_answer not in ("yes", "no"):
            raise ValueError(f"question {i}: risk_answer must be yes or no")
        severity = str(q.get("severity", "medium")).strip().lower()
        if severity not in _SEVERITIES:
            raise ValueError(f"question {i}: severity must be low|medium|high")
        questions.append(
            {
                "id": qid,
                "section": str(q.get("section", "")).strip()[:80] or "General",
                "text": text,
                "risk_answer": risk_answer,
                "severity": severity,
                "guidance": str(q.get("guidance", "")).strip()[:500],
            }
        )
    return {
        "type": t,
        "title": title,
        "framework": framework,
        "department": department,
        "description": str(payload.get("description", "")).strip()[:500],
        "questions": questions,
    }


def _historical_question_ids(assessment_type: str) -> set[str]:
    """Every question id ever published for one immutable template type."""
    identifiers: set[str] = set()
    builtin = _builtin_record(assessment_type)
    if builtin is not None:
        identifiers.update(str(q.get("id") or "") for q in builtin["questions"])
    root = _custom_templates_dir() / "releases" / assessment_type
    if not root.exists():
        return {item for item in identifiers if item}
    releases = sorted(root.glob("*.json"))
    if len(releases) > 4096:
        raise AssessmentStateError("questionnaire release history exceeds limit")
    for path in releases:
        if not _DIGEST_RE.fullmatch(path.stem):
            raise AssessmentStateError("questionnaire release identity is invalid")
        record = _read_json(path)
        if record is None:  # pragma: no cover -- path came from glob
            raise AssessmentStateError("questionnaire release disappeared")
        policy = _validated_release(record, assessment_type, path.stem)
        identifiers.update(str(q.get("id") or "") for q in policy["questions"])
    return {item for item in identifiers if item}


def _effective_digest_unlocked(assessment_type: str, state: dict | None) -> str:
    if state and state.get("active_digest"):
        return str(state["active_digest"])
    builtin = _builtin_record(assessment_type)
    return _template_digest(builtin) if builtin else ""


def save_custom_template(
    payload: dict,
    *,
    expected_revision: int | None = None,
    expected_digest: str | None = None,
    actor: str = "system",
) -> AssessmentTemplate:
    """Publish an immutable questionnaire release and CAS its active pointer.

    Core callers may omit CAS for legacy/bootstrap compatibility; dashboard
    publication always supplies both values.  Writes are still serialized and
    atomic in the compatibility path.
    """
    from .file_lock import cross_process_lock, ensure_private_directory

    preflight = _normalise_template(payload)
    t = preflight["type"]
    path = _state_path(t)
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        state = _load_state_unlocked(t)
        active_policy = None
        if state and state.get("active_digest"):
            active_policy = _active_release_unlocked(t, state)
        if active_policy is None:
            active_policy = _builtin_record(t)
        reusable_ids = {
            str(question.get("id") or "")
            for question in (active_policy or {}).get("questions", [])
            if str(question.get("id") or "")
        }
        historical_ids = _historical_question_ids(t)
        # The first governed write over a legacy mutable policy has no release
        # artifact yet. Include that active policy so any removed legacy ids
        # become retired instead of silently reusable after migration.
        historical_ids.update(reusable_ids)
        policy = _normalise_template(
            payload,
            historical_ids=historical_ids,
            reusable_ids=reusable_ids,
        )
        revision = _record_revision(state, label="questionnaire pointer")
        current_digest = _effective_digest_unlocked(t, state)
        if expected_revision is not None and revision != _validated_revision_value(
            expected_revision,
            label="expected questionnaire",
        ):
            raise AssessmentConflict(
                f"questionnaire changed (expected revision {expected_revision}, found {revision})"
            )
        if expected_digest is not None and current_digest != str(expected_digest):
            raise AssessmentConflict("questionnaire changed (digest mismatch)")
        pending = _validated_audit_pending(
            (state or {}).get("_audit_pending"),
            label="questionnaire",
        )
        _reserve_audit_slot(pending, label="questionnaire")
        digest = _template_digest(policy)
        _write_release_unlocked(t, policy, digest)
        receipt = _audit_receipt(
            "QUESTIONNAIRE_RELEASE_PUBLISHED",
            actor,
            template=t,
            before_digest=current_digest,
            digest=digest,
            before_revision=revision,
            revision=revision + 1,
            questions=len(policy["questions"]),
        )
        pending.append(receipt)
        new_state = {
            "schema_version": _TEMPLATE_STATE_SCHEMA,
            "type": t,
            "revision": revision + 1,
            "active_digest": digest,
            "published_at": time.time(),
            "published_by": str(actor or "system")[:256],
            "_audit_pending": pending,
        }
        _write_state_unlocked(t, new_state)
    _flush_template_audit(t)
    return replace(_template_from_record(policy), revision=revision + 1, digest=digest, custom=True)


def delete_custom_template(
    assessment_type: str,
    *,
    expected_revision: int | None = None,
    expected_digest: str | None = None,
    actor: str = "system",
) -> bool:
    """CAS-unpublish a custom release; immutable history remains available."""
    from .file_lock import cross_process_lock, ensure_private_directory

    t = (assessment_type or "").strip().lower()
    if not re.fullmatch(_TYPE_RE, t):
        return False
    path = _state_path(t)
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        state = _load_state_unlocked(t)
        if state is None or not state.get("active_digest"):
            return False
        _active_release_unlocked(t, state)
        revision = _record_revision(state, label="questionnaire pointer", required=True)
        current_digest = str(state["active_digest"])
        if expected_revision is not None and revision != _validated_revision_value(
            expected_revision,
            label="expected questionnaire",
        ):
            raise AssessmentConflict(
                f"questionnaire changed (expected revision {expected_revision}, found {revision})"
            )
        if expected_digest is not None and current_digest != str(expected_digest):
            raise AssessmentConflict("questionnaire changed (digest mismatch)")
        effective_after = _builtin_record(t)
        after_digest = _template_digest(effective_after) if effective_after else ""
        receipt = _audit_receipt(
            "QUESTIONNAIRE_RELEASE_UNPUBLISHED",
            actor,
            template=t,
            before_digest=current_digest,
            digest=after_digest,
            before_revision=revision,
            revision=revision + 1,
        )
        pending = _validated_audit_pending(
            state.get("_audit_pending"),
            label="questionnaire",
        )
        _reserve_audit_slot(pending, label="questionnaire")
        pending.append(receipt)
        new_state = {
            "schema_version": _TEMPLATE_STATE_SCHEMA,
            "type": t,
            "revision": revision + 1,
            "active_digest": "",
            "deleted_at": time.time(),
            "deleted_by": str(actor or "system")[:256],
            "_audit_pending": pending,
        }
        _write_state_unlocked(t, new_state)
    _flush_template_audit(t)
    return True


def _template_from_record(record: dict) -> AssessmentTemplate:
    return AssessmentTemplate(
        type=record["type"],
        title=record["title"],
        framework=record["framework"],
        description=record.get("description", ""),
        questions=tuple(
            _q(
                q["id"],
                q["section"],
                q["text"],
                q["risk_answer"],
                q["severity"],
                q.get("guidance", ""),
            )
            for q in record.get("questions", [])
        ),
    )


def template_state(assessment_type: str) -> dict:
    """CAS identity for the currently effective release (including tombstones)."""
    t = (assessment_type or "").strip().lower()
    if not re.fullmatch(_TYPE_RE, t):
        raise ValueError("invalid assessment type")
    state = _load_state_with_audit_retry(t, retry=True)
    active = bool(state and state.get("active_digest"))
    builtin = _builtin_record(t)
    digest = _effective_digest_unlocked(t, state)
    return {
        "type": t,
        "revision": _record_revision(state, label="questionnaire pointer"),
        "digest": digest,
        "custom": active,
        "builtin": builtin is not None,
        "exists": active or builtin is not None,
    }


def custom_template_records() -> dict[str, dict]:
    """Active immutable custom releases by type (carries governance identity)."""
    d = _custom_templates_dir()
    if not d.exists():
        return {}
    out: dict[str, dict] = {}
    for p in sorted(d.glob("*.json")):
        t = p.stem
        if not re.fullmatch(_TYPE_RE, t):
            continue
        state = _load_state_unlocked(t)
        if state is None or not state.get("active_digest"):
            continue
        rec = _active_release_unlocked(t, state)
        if rec is None:  # pragma: no cover -- active pointer is checked above
            raise AssessmentStateError("active questionnaire release is missing")
        out[t] = {
            **rec,
            "revision": _record_revision(state, label="questionnaire pointer", required=True),
            "digest": str(state.get("active_digest") or ""),
        }
    return out


def template_department(assessment_type: str) -> str:
    """Which department workspace a template belongs to."""
    rec = custom_template_records().get((assessment_type or "").lower())
    if rec:
        return rec.get("department", "privacy")
    if assessment_type in ("sox_control", "fraud_risk", "itgc", "credit_risk", "close_readiness"):
        return "finance"
    if assessment_type in {
        "soc2",
        "iso27001",
        "iso42001",
        "nist_csf",
        "nist_800_53",
        "cis_v8",
        "pci_dss",
        "hipaa",
        "cmmc_l2",
        "fedramp_moderate",
    }:
        return "security"
    return "privacy"


def list_templates() -> list[AssessmentTemplate]:
    types = set(TEMPLATES)
    d = _custom_templates_dir()
    if d.exists():
        types.update(p.stem for p in d.glob("*.json") if re.fullmatch(_TYPE_RE, p.stem))
    out: list[AssessmentTemplate] = []
    retries = 0
    for t in sorted(types):
        state = _load_state_unlocked(t)
        retry = bool(state and state.get("_audit_pending") and retries < _AUDIT_READ_RETRY_LIMIT)
        if retry:
            retries += 1
        tpl = get_template(t, _retry_audit=retry)
        if tpl is not None:
            out.append(tpl)
    return out


def get_template(assessment_type: str, *, _retry_audit: bool = True) -> AssessmentTemplate | None:
    t = (assessment_type or "").strip().lower()
    if not re.fullmatch(_TYPE_RE, t):
        return None
    state = _load_state_with_audit_retry(t, retry=_retry_audit)
    revision = _record_revision(state, label="questionnaire pointer")
    if state and state.get("active_digest"):
        rec = _active_release_unlocked(t, state)
        if rec is None:  # pragma: no cover
            raise AssessmentStateError("active questionnaire release is missing")
        return replace(
            _template_from_record(rec),
            revision=revision,
            digest=str(state["active_digest"]),
            custom=True,
        )
    builtin = TEMPLATES.get(t)
    builtin_record = _builtin_record(t)
    if builtin is None or builtin_record is None:
        return None
    return replace(
        builtin, revision=revision, digest=_template_digest(builtin_record), custom=False
    )


# --- A running assessment --------------------------------------------------


@dataclass
class AssessmentSession:
    """An in-progress assessment of ``subject`` against a template. Answers are
    recorded by id; :meth:`evaluate` scores them into findings + a risk rating."""

    type: str = ""
    subject: str = ""
    answers: dict[str, dict] = field(default_factory=dict)
    id: str = field(default_factory=_new_session_id)
    created_at: float = field(default_factory=time.time)
    template_revision: int = -1
    template_digest: str = ""
    template_snapshot: dict = field(default_factory=dict, repr=False)

    def restart(self, assessment_type: str, subject: str) -> None:
        """Start a new assessment draft in this reusable conversation session."""
        self.type = assessment_type
        self.subject = subject
        self.answers.clear()
        self.id = _new_session_id()
        self.created_at = time.time()
        self.template_revision = -1
        self.template_digest = ""
        self.template_snapshot.clear()
        # Pin now, before an admin can publish another release between start
        # and the first answer.
        self.template()

    def template(self) -> AssessmentTemplate:
        if self.template_snapshot:
            policy = _normalise_template(self.template_snapshot)
            digest = _template_digest(policy)
            if (
                policy["type"] != self.type
                or not self.template_digest
                or digest != self.template_digest
                or self.template_revision < 0
            ):
                raise AssessmentStateError("pinned assessment questionnaire does not verify")
            return replace(
                _template_from_record(policy),
                revision=self.template_revision,
                digest=self.template_digest,
                custom=bool(self.template_snapshot.get("custom", False)),
            )
        tpl = get_template(self.type)
        if tpl is None:
            raise KeyError(f"unknown assessment type {self.type!r}")
        policy = _template_record(
            tpl,
            department=template_department(tpl.type),
        )
        self.template_revision = tpl.revision
        self.template_digest = tpl.digest or _template_digest(policy)
        self.template_snapshot = {**policy, "custom": tpl.custom}
        return tpl

    def record(self, question_id: str, answer: str, note: str = "") -> None:
        answer = (answer or "").strip().lower()
        if answer not in ANSWERS:
            raise ValueError(f"answer must be one of {ANSWERS}, got {answer!r}")
        if self.template().question(question_id) is None:
            raise KeyError(f"no question {question_id!r} in {self.type!r}")
        self.answers[question_id] = {"answer": answer, "note": note}

    def evaluate(self) -> AssessmentResult:
        tpl = self.template()
        findings: list[Finding] = []
        answered = 0
        in_scope: list[str] = []  # severities of every applicable risk area
        controls_in_place = 0
        for q in tpl.questions:
            rec = self.answers.get(q.id)
            if not rec:
                continue
            ans = rec["answer"]
            if ans in {"yes", "no", "na"}:
                answered += 1
            if ans != "na":
                # The risk area applies to this subject, so it counts toward
                # the INHERENT exposure whether or not a control covers it.
                in_scope.append(q.severity)
            if ans == q.risk_answer:
                findings.append(
                    Finding(
                        q.id,
                        q.section,
                        q.text,
                        q.severity,
                        ans,
                        "risk",
                        q.guidance,
                    )
                )
            elif ans == "unknown":
                findings.append(
                    Finding(
                        q.id,
                        q.section,
                        q.text,
                        q.severity,
                        ans,
                        "unverified",
                        q.guidance,
                    )
                )
            elif ans != "na":
                controls_in_place += 1  # in scope AND the safe answer
        residual = _rollup([f.severity for f in findings])
        return AssessmentResult(
            type=self.type,
            subject=self.subject,
            risk_rating=residual,
            findings=findings,
            answered=answered,
            total=len(tpl.questions),
            inherent_risk=_rollup(in_scope),
            residual_risk=residual,
            risks_in_scope=len(in_scope),
            controls_in_place=controls_in_place,
        )


def template_for_saved_record(record: dict) -> AssessmentTemplate | None:
    """Resolve the exact release pinned into a saved assessment.

    Pre-governance records lack a snapshot and retain the historical fallback
    to the current template. New records never consult a mutable live pointer.
    """
    snapshot = record.get("template_snapshot")
    if isinstance(snapshot, dict) and snapshot:
        policy = _normalise_template(snapshot)
        digest = _template_digest(policy)
        expected = str(record.get("template_digest") or "")
        if not expected or digest != expected:
            raise AssessmentStateError("saved assessment questionnaire snapshot does not verify")
        revision = _record_revision(
            record,
            key="template_revision",
            label="saved assessment questionnaire",
            required=True,
        )
        if policy["type"] != str(record.get("type") or ""):
            raise AssessmentStateError("saved assessment questionnaire identity is invalid")
        return replace(
            _template_from_record(policy),
            revision=revision,
            digest=digest,
            custom=bool(snapshot.get("custom", False)),
        )
    return get_template(str(record.get("type") or ""))


def _rollup(severities: list[str]) -> str:
    if not severities:
        return "minimal"
    top = max(_SEVERITY_RANK.get(s, 1) for s in severities)
    return {3: "high", 2: "medium", 1: "low"}[top]


# --- Persistence -----------------------------------------------------------


def _assessments_dir() -> Path:
    from .paths import data_dir

    return data_dir("assessments")


_ASSESSMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ASSESSMENT_COMMENT_IDEMPOTENCY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
)
_ASSESSMENT_COMMENT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_AI_ANSWER_FLAGS = frozenset(
    {
        "human_review_required",
        "low_confidence",
        "source_incomplete",
        "source_stale",
        "source_conflict",
        "human_edited",
    }
)
_AI_ANSWER_SOURCE_KINDS = frozenset(
    {"assessment_memory", "document_evidence", "agent_draft", "imported_record"}
)
_MAX_ASSESSMENT_COMMENTS = 1_000
_MAX_ASSESSMENT_COMMENT_CHARS = 4_000
_MAX_ASSESSMENT_COMMENTS_BYTES = 8 * 1024 * 1024


def _assessment_comment_operation(value: object) -> str:
    if not isinstance(value, str) or not _ASSESSMENT_COMMENT_IDEMPOTENCY_RE.fullmatch(value):
        raise ValueError("idempotency_key is invalid")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def assessment_comment_id(assessment_id: str, idempotency_key: str) -> str:
    """Return the opaque stable comment id for an idempotent create request."""

    operation_sha = _assessment_comment_operation(idempotency_key)
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"lightwork:assessment-comment:{assessment_id}:{operation_sha}",
        )
    )


def _assessment_comment_semantic_sha256(
    *,
    section_id: str,
    question_id: str,
    comment: str,
    commented_by: str,
) -> str:
    payload = {
        "comment": comment,
        "commented_by": commented_by,
        "question_id": question_id,
        "section_id": section_id,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _validated_assessment_comments(value: object) -> list[dict]:
    comments = [] if value is None else value
    if not isinstance(comments, list) or len(comments) > _MAX_ASSESSMENT_COMMENTS:
        raise AssessmentStateError("assessment comments are invalid")
    validated: list[dict] = []
    identifiers: set[str] = set()
    operations: set[str] = set()
    total_bytes = 0
    for raw in comments:
        if not isinstance(raw, dict):
            raise AssessmentStateError("assessment comments are invalid")
        item = dict(raw)
        identifier = item.get("id")
        section = item.get("section_id")
        question = item.get("question_id")
        text = item.get("comment")
        actor = item.get("commented_by")
        created_at = item.get("commented_at")
        if (
            not isinstance(identifier, str)
            or not _ASSESSMENT_COMMENT_ID_RE.fullmatch(identifier)
            or identifier in identifiers
            or not isinstance(section, str)
            or not 1 <= len(section) <= 80
            or not isinstance(question, str)
            or not 1 <= len(question) <= 60
            or not isinstance(text, str)
            or not 1 <= len(text) <= _MAX_ASSESSMENT_COMMENT_CHARS
            or not isinstance(actor, str)
            or not 1 <= len(actor) <= 256
            or isinstance(created_at, bool)
            or not isinstance(created_at, (int, float))
            or not math.isfinite(float(created_at))
            or float(created_at) < 0
        ):
            raise AssessmentStateError("assessment comments are invalid")
        identifiers.add(identifier)
        operation_sha = item.get("_idempotency_sha256")
        semantic_sha = item.get("_semantic_sha256")
        if operation_sha is not None or semantic_sha is not None:
            if (
                not isinstance(operation_sha, str)
                or not _DIGEST_RE.fullmatch(operation_sha)
                or operation_sha in operations
                or not isinstance(semantic_sha, str)
                or not _DIGEST_RE.fullmatch(semantic_sha)
                or semantic_sha
                != _assessment_comment_semantic_sha256(
                    section_id=section,
                    question_id=question,
                    comment=text,
                    commented_by=actor,
                )
            ):
                raise AssessmentStateError("assessment comments are invalid")
            operations.add(operation_sha)
        try:
            total_bytes += len(_canonical_json(item).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise AssessmentStateError("assessment comments are invalid") from exc
        if total_bytes > _MAX_ASSESSMENT_COMMENTS_BYTES:
            raise AssessmentStateError("assessment comment storage limit reached")
        validated.append(item)
    return validated


def _validated_record_comments(record: dict) -> list[dict]:
    comments = _validated_assessment_comments(record.get("comments"))
    if not comments:
        return comments
    snapshot = record.get("template_snapshot")
    if not isinstance(snapshot, dict) or not snapshot:
        raise AssessmentStateError(
            "assessment comments require a pinned questionnaire snapshot"
        )
    template = template_for_saved_record(record)
    for item in comments:
        pinned = template.question(str(item["question_id"])) if template is not None else None
        if pinned is None or pinned.section != item["section_id"]:
            raise AssessmentStateError(
                "assessment comment is not bound to the pinned questionnaire"
            )
    return comments


def _assessment_path(assessment_id: str) -> Path | None:
    value = str(assessment_id or "")
    if not _ASSESSMENT_ID_RE.fullmatch(value):
        return None
    return _assessments_dir() / f"{value}.json"


def _read_saved_path_unlocked(path: Path) -> dict | None:
    from .file_lock import atomic_read_text, ensure_private_file

    if not path.exists():
        return None
    try:
        ensure_private_file(path)
        record = json.loads(atomic_read_text(path, encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AssessmentStateError(
            f"assessment record is unreadable or corrupt: {path.name}"
        ) from exc
    if not isinstance(record, dict) or record.get("id") != path.stem:
        raise AssessmentStateError("assessment record identity is invalid")
    _validated_audit_pending(
        record.get("_audit_pending"),
        label="assessment",
    )
    _record_revision(record, label="assessment")
    if "comments" in record:
        _validated_record_comments(record)
    return record


def _write_saved_path_unlocked(path: Path, record: dict) -> None:
    from .file_lock import atomic_write_text

    atomic_write_text(
        path,
        json.dumps(record, indent=2, default=str, ensure_ascii=False),
        mode=0o600,
    )
    # Keep the cross-platform stat postcondition that the previous O_CREAT
    # writer exposed, in addition to atomic_write_text's Windows DACL hardening.
    os.chmod(path, 0o600)


def _public_assessment_record(record: dict) -> dict:
    public = {key: value for key, value in record.items() if key != "_audit_pending"}
    comments = public.get("comments")
    if isinstance(comments, list):
        public["comments"] = [
            {
                key: value
                for key, value in item.items()
                if key not in {"_idempotency_sha256", "_semantic_sha256"}
            }
            if isinstance(item, dict)
            else item
            for item in comments
        ]
    return public


def save_session(session: AssessmentSession) -> Path:
    """Atomically create a pinned assessment draft. Returns its path."""
    from .file_lock import cross_process_lock, ensure_private_directory

    d = _assessments_dir()
    ensure_private_directory(d)
    result = session.evaluate()
    # evaluate() pins the current release before we serialize it.
    if not session.template_snapshot or not session.template_digest:
        raise AssessmentStateError("assessment questionnaire was not pinned")
    path = _assessment_path(session.id)
    if path is None:
        raise ValueError("invalid assessment id")
    record = {
        "id": session.id,
        "type": session.type,
        "subject": session.subject,
        "created_at": session.created_at,
        "status": "pending_review",
        "revision": 1,
        "template_revision": session.template_revision,
        "template_digest": session.template_digest,
        "template_snapshot": session.template_snapshot,
        "answers": session.answers,
        "result": asdict(result),
    }
    with cross_process_lock(path, strict=True):
        if _read_saved_path_unlocked(path) is not None:
            raise AssessmentConflict("assessment id already exists")
        _write_saved_path_unlocked(path, record)
    # Assessment memory: distill into the knowledge plane so future
    # assessments recall this one. Fail-open -- the JSON above is canonical.
    try:
        from .assessment_memory import record_session

        record_session(record)
    except Exception:  # noqa: BLE001 -- memory must never break a save
        pass
    return path


def _flush_assessment_audit(assessment_id: str) -> None:
    """Deliver embedded audit receipts and remove only confirmed event ids.

    Delivery is at-least-once: a crash after append and before receipt removal
    may retry the same stable ``event_id``, which downstream sinks can dedupe.
    """
    from .file_lock import cross_process_lock

    path = _assessment_path(assessment_id)
    if path is None:
        return
    with cross_process_lock(path, strict=True):
        record = _read_saved_path_unlocked(path)
        pending = list((record or {}).get("_audit_pending") or [])
    delivered = {
        str(item.get("event_id"))
        for item in pending
        if isinstance(item, dict) and _deliver_audit(item)
    }
    if not delivered:
        return
    with cross_process_lock(path, strict=True):
        record = _read_saved_path_unlocked(path)
        if record is None:
            return
        current = _validated_audit_pending(
            record.get("_audit_pending"),
            label="assessment",
        )
        record["_audit_pending"] = [
            item for item in current if str(item.get("event_id")) not in delivered
        ]
        _write_saved_path_unlocked(path, record)


def _rewrite_saved(
    assessment_id: str,
    mutate,
    *,
    expected_revision: int | None = None,
    audit_receipt: dict | None = None,
) -> dict | None:
    """Locked read-modify-atomic-replace, optionally guarded by revision CAS.

    ``expected_revision=None`` remains a safe serialized compatibility path for
    the demo seeder and old internal callers. Security-sensitive dashboard
    mutations always pass the revision fetched by the reviewer.
    """
    from .file_lock import cross_process_lock, ensure_private_directory

    path = _assessment_path(assessment_id)
    if path is None:
        return None
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        record = _read_saved_path_unlocked(path)
        if record is None:
            return None
        revision = _record_revision(record, label="assessment")
        if expected_revision is not None and revision != _validated_revision_value(
            expected_revision,
            label="expected assessment",
        ):
            raise AssessmentConflict(
                f"assessment changed (expected revision {expected_revision}, found {revision})"
            )
        # Deep-copy through JSON so nested follow-up edits do not mutate the
        # object used for validation before the atomic commit.
        updated = json.loads(json.dumps(record, default=str))
        mutate(updated)
        if updated == record:
            return _public_assessment_record(record)
        updated["revision"] = revision + 1
        pending = _validated_audit_pending(
            updated.get("_audit_pending"),
            label="assessment",
        )
        if audit_receipt is not None:
            _reserve_audit_slot(pending, label="assessment")
            pending.append(audit_receipt)
        updated["_audit_pending"] = pending
        _write_saved_path_unlocked(path, updated)
    _flush_assessment_audit(assessment_id)
    refreshed = _load_saved_raw(assessment_id)
    return _public_assessment_record(refreshed) if refreshed is not None else None


def answer_saved_question(
    assessment_id: str,
    question_id: str,
    answer: str,
    *,
    note: str = "",
    answered_by: str,
    expected_revision: int,
) -> dict | None:
    """Record a human answer against a saved, pinned questionnaire draft.

    Recompute the ordinary deterministic score without approving the record.
    Prior answers (including their evidence metadata) remain in its history.
    """
    question = str(question_id or "").strip()
    actor = str(answered_by or "").strip()
    text = str(note or "").strip()
    if not question or len(question) > 60 or not actor or len(actor) > 256:
        raise ValueError("question and answer attribution are required")
    if len(text) > 4000:
        raise ValueError("answer note cannot exceed 4000 characters")
    normalized_answer = str(answer or "").strip().lower()
    if normalized_answer not in ANSWERS:
        raise ValueError("answer must be yes, no, na, or unknown")

    def _mutate(record: dict) -> None:
        if record.get("status") not in ("pending_review", "needs_more"):
            raise AssessmentTransitionError("Start a new assessment or reopen review before changing a decided assessment.")
        if not record.get("template_snapshot"):
            raise AssessmentTransitionError("Start a new assessment to use a pinned questionnaire.")
        template = template_for_saved_record(record)
        if template is None or template.question(question) is None:
            raise ValueError("question is not part of this assessment’s pinned questionnaire")
        answers = record.get("answers")
        if not isinstance(answers, dict):
            raise AssessmentStateError("saved assessment answers are invalid")
        previous = answers.get(question)
        if previous is not None and not isinstance(previous, dict):
            raise AssessmentStateError("saved assessment answer is invalid")
        if previous and previous.get("answer") == normalized_answer and previous.get("note", "") == text:
            return
        history = record.setdefault("answer_history", [])
        if not isinstance(history, list) or len(history) >= 1000:
            raise AssessmentTransitionError("Answer history is full; start a new assessment.")
        change = {"question_id": question, "previous_answer": previous,
                  "replaced_at_revision": record["revision"], "changed_by": actor,
                  "changed_at": time.time()}
        if record.get("risk_acceptance"):
            change["superseded_risk_acceptance"] = record.pop("risk_acceptance")
        history.append(change)
        session = AssessmentSession(
            id=record["id"], type=record["type"], subject=record["subject"],
            answers=answers, template_snapshot=record["template_snapshot"],
            template_revision=record["template_revision"], template_digest=record["template_digest"],
        )
        session.record(question, normalized_answer, text)
        answers[question].update({"by": actor, "answered_at": time.time()})
        record["result"] = asdict(session.evaluate())
        record["status"] = "needs_more" if any(not f.get("answer") for f in record.get("followups", [])) else "pending_review"

    return _rewrite_saved(
        assessment_id, _mutate, expected_revision=expected_revision,
        audit_receipt=_audit_receipt("ASSESSMENT_ANSWER_RECORDED", actor,
                                    assessment=assessment_id, question_id=question),
    )


def add_followups(
    assessment_id: str,
    questions: list[str],
    asked_by: str = "",
    *,
    expected_revision: int | None = None,
) -> dict | None:
    """Attach reviewer follow-up questions to a saved assessment.

    The reviewer working the assessment (dashboard pop-out) sends these back
    to the respondent; the record's ``status`` flips to ``needs_more`` until
    every follow-up carries an answer. Returns the updated record, or None
    for an unknown id / no usable questions."""
    cleaned = [q.strip()[:2000] for q in questions if q and q.strip()]
    if not cleaned:
        return None

    def _mutate(record: dict) -> None:
        fups = record.setdefault("followups", [])
        base = len(fups)
        for i, q in enumerate(cleaned, start=1):
            fups.append(
                {
                    "id": f"fu-{base + i}",
                    "question": q,
                    "asked_by": asked_by,
                    "asked_at": time.time(),
                    "answer": "",
                    "answered_by": "",
                    "answered_at": None,
                }
            )
        record["status"] = "needs_more"

    receipt = _audit_receipt(
        "ASSESSMENT_FOLLOWUP",
        asked_by,
        assessment=assessment_id,
        questions=len(cleaned),
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )


def add_assessment_comment(
    assessment_id: str,
    *,
    section_id: str,
    question_id: str,
    comment: str,
    commented_by: str,
    expected_revision: int,
    idempotency_key: str,
) -> dict | None:
    """Create an audited comment bound to one pinned assessment question.

    Comments are discussion records, not follow-up tasks and therefore do not
    change the assessment workflow state. The section/question pair is
    resolved against the immutable questionnaire snapshot saved with the
    assessment so a caller cannot attach a comment to an invented or newly
    repointed question.
    """

    if not isinstance(section_id, str):
        raise ValueError("section_id must be a string")
    if not isinstance(question_id, str):
        raise ValueError("question_id must be a string")
    if not isinstance(comment, str):
        raise ValueError("comment must be a string")
    if not isinstance(commented_by, str):
        raise ValueError("commented_by must be a string")
    section = section_id.strip()
    question = question_id.strip()
    text = comment.strip()
    actor = commented_by.strip()
    if not section or len(section) > 80:
        raise ValueError("section_id must be between 1 and 80 characters")
    if not question or len(question) > 60:
        raise ValueError("question_id must be between 1 and 60 characters")
    if not text or len(text) > _MAX_ASSESSMENT_COMMENT_CHARS:
        raise ValueError("comment must be between 1 and 4000 characters")
    if not actor or len(actor) > 256:
        raise ValueError("commented_by must be between 1 and 256 characters")
    expected = _validated_revision_value(expected_revision, label="expected assessment")
    operation_sha = _assessment_comment_operation(idempotency_key)
    comment_id = assessment_comment_id(assessment_id, idempotency_key)
    semantic_sha = _assessment_comment_semantic_sha256(
        section_id=section,
        question_id=question,
        comment=text,
        commented_by=actor,
    )

    created_at = time.time()

    def _mutate(record: dict) -> None:
        # Comments promise a binding to the immutable questionnaire reviewed by
        # the respondent. Legacy records without a snapshot cannot satisfy that
        # promise and must be upgraded/re-run instead of consulting a live
        # mutable template pointer.
        snapshot = record.get("template_snapshot")
        if not isinstance(snapshot, dict) or not snapshot:
            raise AssessmentTransitionError(
                "assessment comments require a pinned questionnaire snapshot"
            )
        template = template_for_saved_record(record)
        item = template.question(question) if template is not None else None
        if item is None or item.section != section:
            raise AssessmentTransitionError(
                "assessment section/question does not exist in the pinned questionnaire"
            )
        comments = _validated_record_comments(record)
        for existing in comments:
            if existing.get("_idempotency_sha256") != operation_sha:
                continue
            if (
                existing.get("id") != comment_id
                or existing.get("_semantic_sha256") != semantic_sha
            ):
                raise AssessmentConflict(
                    "idempotency_key was already used for a different assessment comment"
                )
            return
        revision = _record_revision(record, label="assessment")
        if revision != expected:
            raise AssessmentConflict(
                f"assessment changed (expected revision {expected}, found {revision})"
            )
        if len(comments) >= _MAX_ASSESSMENT_COMMENTS:
            raise AssessmentStateError("assessment comment limit reached")
        created = {
            "id": comment_id,
            "section_id": section,
            "question_id": question,
            "comment": text,
            "commented_by": actor,
            "commented_at": created_at,
            "_idempotency_sha256": operation_sha,
            "_semantic_sha256": semantic_sha,
        }
        _validated_assessment_comments([*comments, created])
        record["comments"] = [*comments, created]

    receipt = _audit_receipt(
        "ASSESSMENT_COMMENT_CREATED",
        actor,
        assessment=assessment_id,
        comment_id=comment_id,
        section_id=section,
        question_id=question,
        comment_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        semantic_sha256=semantic_sha,
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        # CAS is enforced inside the locked mutation after replay detection so
        # an exact retry remains successful even if later writes advanced the
        # assessment revision.
        expected_revision=None,
        audit_receipt=receipt,
    )


def assessment_comments(
    assessment_id: str,
    *,
    offset: int = 0,
    limit: int = 100,
    expected_revision: int | None = None,
) -> dict | None:
    """Return a bounded, deterministic page of question comments."""

    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    record = load_saved(assessment_id)
    if record is None:
        return None
    revision = _record_revision(record, label="assessment")
    if expected_revision is not None and revision != _validated_revision_value(
        expected_revision,
        label="expected assessment",
    ):
        raise AssessmentConflict(
            f"assessment changed (expected revision {expected_revision}, found {revision})"
        )
    template = template_for_saved_record(record)
    questions = tuple(template.questions) if template is not None else ()
    section_order: dict[str, int] = {}
    question_order: dict[str, int] = {}
    for index, item in enumerate(questions):
        section_order.setdefault(item.section, len(section_order))
        question_order[item.id] = index
    comments = _validated_record_comments(record)
    comments.sort(
        key=lambda item: (
            section_order.get(str(item["section_id"]), len(section_order)),
            question_order.get(str(item["question_id"]), len(question_order)),
            float(item["commented_at"]),
            str(item["id"]),
        )
    )
    total = len(comments)
    return {
        "assessment_id": assessment_id,
        "assessment_revision": revision,
        "offset": offset,
        "limit": limit,
        "total": total,
        "comments": comments[offset : offset + limit],
    }


def answer_followup(
    assessment_id: str,
    followup_id: str,
    answer: str,
    answered_by: str = "",
    *,
    expected_revision: int | None = None,
) -> dict | None:
    """Record the respondent's answer to one follow-up. When the last open
    follow-up is answered the record's ``status`` returns to
    ``pending_review``. Returns the updated record, or None for an unknown
    assessment or follow-up id."""
    answer = (answer or "").strip()[:4000]
    if not answer:
        return None
    hit = {"found": False}

    def _mutate(record: dict) -> None:
        if record.get("status") not in ("pending_review", "needs_more"):
            raise AssessmentTransitionError(
                "Reopen review before changing a decided assessment."
            )
        fups = record.get("followups") or []
        for f in fups:
            if f.get("id") == followup_id:
                hit["found"] = True
                if f.get("answer") == answer:
                    return
                if f.get("answer") or record.get("risk_acceptance"):
                    history = record.setdefault("followup_answer_history", [])
                    if not isinstance(history, list) or len(history) >= 1000:
                        raise AssessmentTransitionError("Follow-up history is full; start a new assessment.")
                    change = {
                        "followup_id": followup_id,
                        "previous_answer": {key: f.get(key) for key in ("answer", "answered_by", "answered_at")},
                        "replaced_at_revision": record["revision"],
                        "changed_by": answered_by,
                        "changed_at": time.time(),
                    }
                    if record.get("risk_acceptance"):
                        change["superseded_risk_acceptance"] = record.pop("risk_acceptance")
                    history.append(change)
                f["answer"] = answer
                f["answered_by"] = answered_by
                f["answered_at"] = time.time()
        if hit["found"] and all(f.get("answer") for f in fups):
            record["status"] = "pending_review"

    receipt = _audit_receipt(
        "ASSESSMENT_FOLLOWUP_ANSWERED",
        answered_by,
        assessment=assessment_id,
        followup_id=followup_id[:64],
    )
    record = _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )
    return record if (record is not None and hit["found"]) else None


DECISIONS = ("approved", "rejected")


def _emit_assessment_event(event: str, record: dict | None, payload: dict) -> None:
    """Tell webhook subscribers; never raises, nothing sent without subscribers."""
    if not isinstance(record, dict) or not record.get("id"):
        return
    try:
        from .webhook_events import emit, record_link

        rid = str(record.get("id"))
        emit(event, record_type="assessment", record_id=rid,
             title=f"{record.get('subject') or 'assessment'} ({record.get('type') or 'assessment'})",
             summary={"status": record.get("status"), "assignee": record.get("assignee", ""),
                      "next_review_at": record.get("next_review_at"),
                      "renewal_at": record.get("renewal_at")},
             link=record_link(f"/assessments#{rid}"), payload=payload)
    except Exception:  # pragma: no cover - webhooks never block a record change
        pass


def assign_assessment(
    assessment_id: str,
    assignee: str,
    *,
    assigned_by: str = "",
    expected_revision: int | None = None,
) -> dict | None:
    """Put a saved assessment on a named reviewer's desk (or clear it).

    Everything else on an assessment record is *post-hoc* attribution -- who
    decided, who answered, who accepted the risk. Nothing said whose job it is
    NEXT, so a reviewer could not ask "what is mine?" and a queue could only be
    eyeballed. ``assignee=""`` unassigns and returns the record to the pool.

    Assignment is deliberately not a permission: it routes work, it does not
    gate who may decide. The approval gate stays where it already is."""
    who = (assignee or "").strip()[:200]

    def _mutate(record: dict) -> None:
        if who:
            record["assignee"] = who
            record["assigned_at"] = time.time()
            record["assigned_by"] = str(assigned_by or "")[:256]
        else:
            record.pop("assignee", None)
            record.pop("assigned_at", None)
            record.pop("assigned_by", None)

    receipt = _audit_receipt(
        "ASSESSMENT_ASSIGNED",
        assigned_by,
        assessment=assessment_id,
        assignee=who,
    )
    saved = _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )
    _emit_assessment_event("assessment.assigned", saved, {"assignee": who})
    return saved


def set_assessment_answer_ai_metadata(
    assessment_id: str,
    question_id: str,
    *,
    confidence: float,
    flags: Sequence[str],
    source_kind: str,
    source_ref: str,
    source_sha256: str,
    recorded_by: str,
    expected_revision: int,
) -> dict | None:
    """Persist bounded, cited AI-assistance metadata on one saved answer.

    This never changes the answer or score.  The caller must separately review
    and mutate an answer through the assessment workflow; the metadata only
    makes AI assistance, confidence, flags, and its exact source discoverable.
    """

    question = str(question_id or "").strip()
    if not question or len(question) > 60:
        raise ValueError("question_id is invalid")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("confidence must be a number between 0 and 1")
    normalized_confidence = float(confidence)
    if not math.isfinite(normalized_confidence) or not 0 <= normalized_confidence <= 1:
        raise ValueError("confidence must be a number between 0 and 1")
    if isinstance(flags, (str, bytes)) or not isinstance(flags, Sequence) or len(flags) > 16:
        raise ValueError("AI answer flags are invalid")
    normalized_flags = tuple(sorted(set(flags)))
    if len(normalized_flags) != len(flags) or any(
        not isinstance(flag, str) or flag not in _AI_ANSWER_FLAGS
        for flag in normalized_flags
    ):
        raise ValueError("AI answer flags are invalid")
    kind = str(source_kind or "").strip()
    if kind not in _AI_ANSWER_SOURCE_KINDS:
        raise ValueError("AI answer source kind is invalid")
    reference = str(source_ref or "").strip()
    if not reference or len(reference) > 256:
        raise ValueError("AI answer source reference is invalid")
    digest = str(source_sha256 or "")
    if not _DIGEST_RE.fullmatch(digest):
        raise ValueError("AI answer source digest is invalid")
    actor = str(recorded_by or "").strip()
    if not actor or len(actor) > 256:
        raise ValueError("AI answer recorder is invalid")

    def _mutate(record: dict) -> None:
        template = template_for_saved_record(record)
        if template is None or template.question(question) is None:
            raise AssessmentStateError(
                "AI answer metadata is not bound to the pinned questionnaire"
            )
        answers = record.get("answers")
        if not isinstance(answers, dict) or not isinstance(answers.get(question), dict):
            raise AssessmentStateError("AI answer metadata requires a saved answer")
        answers[question]["ai_metadata"] = {
            "schema": "lightwork.assessment-answer-ai-metadata.v1",
            "confidence": round(normalized_confidence, 6),
            "flags": list(normalized_flags),
            "source": {
                "kind": kind,
                "ref": reference,
                "sha256": digest,
            },
            "recorded_by": actor,
            "recorded_at": time.time(),
            "answer_at_recording": answers[question].get("answer"),
        }

    receipt = _audit_receipt(
        "ASSESSMENT_ANSWER_AI_METADATA_RECORDED",
        actor,
        assessment=assessment_id,
        question_id=question,
        source_kind=kind,
        source_sha256=digest,
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )


def decide_assessment(
    assessment_id: str,
    decision: str,
    *,
    decided_by: str = "",
    note: str = "",
    cadence_days: int | None = 365,
    expected_revision: int | None = None,
) -> dict | None:
    """Record the reviewer's decision on a saved assessment.

    ``approved`` closes the loop and (with a cadence) schedules the next
    review -- the record becomes a living one that comes due instead of a
    PDF that dies in a folder. ``rejected`` closes it with no re-review
    date. Either decision is re-openable: sending new follow-ups flips the
    record back to ``needs_more`` and the cycle runs again."""
    decision = (decision or "").strip().lower()
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")

    def _mutate(record: dict) -> None:
        if decision == "approved" and any(
            not str(f.get("answer") or "").strip() for f in (record.get("followups") or [])
        ):
            raise AssessmentTransitionError(
                "assessment cannot be approved with unanswered follow-ups"
            )
        record["status"] = decision
        record["decided_at"] = time.time()
        record["decided_by"] = decided_by
        record["decision_note"] = (note or "").strip()[:4000]
        # A fresh decision supersedes the ad-hoc "due now" flags AND any prior
        # risk acceptance: the reviewer just looked at the record, so a stale
        # (possibly expired) acceptance must not keep it flagged due after
        # approval. If the reviewer still wants to accept the residual risk,
        # that is a fresh accept_risk with a new expiry.
        record.pop("review_forced_at", None)
        record.pop("review_trigger_reason", None)
        record.pop("risk_acceptance", None)
        if decision == "approved" and cadence_days:
            record["cadence_days"] = int(cadence_days)
            record["next_review_at"] = record["decided_at"] + int(cadence_days) * 86400
        else:
            record["cadence_days"] = None
            record["next_review_at"] = None

    receipt = _audit_receipt(
        "ASSESSMENT_DECIDED",
        decided_by,
        assessment=assessment_id,
        decision=decision,
        cadence_days=int(cadence_days or 0),
    )
    saved = _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )
    _emit_assessment_event("assessment.decided", saved, {"decision": decision})
    return saved


def accept_risk(
    assessment_id: str,
    *,
    accepted_by: str = "",
    rationale: str = "",
    expires_days: int = 365,
    expected_revision: int | None = None,
) -> dict | None:
    """Formally accept the residual risk on an assessment with a named owner,
    a rationale, and an expiry. A risk acceptance is a dated decision, not a
    permanent waiver: when it expires the record comes due again."""
    rationale = (rationale or "").strip()
    if not rationale:
        raise ValueError("a rationale is required to accept risk")
    days = int(expires_days or 0)
    if days <= 0:
        raise ValueError("risk acceptance must have a positive expiry (days)")

    def _mutate(record: dict) -> None:
        if record.get("status") not in ("approved", "pending_review"):
            raise AssessmentTransitionError(
                "only an approved or pending assessment can carry a risk acceptance"
            )
        now = time.time()
        record["risk_acceptance"] = {
            "accepted_by": accepted_by,
            "rationale": rationale[:4000],
            "accepted_at": now,
            "expires_at": now + days * 86400,
        }

    receipt = _audit_receipt(
        "RISK_ACCEPTED",
        accepted_by,
        assessment=assessment_id,
        expires_days=days,
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )


def trigger_review(
    assessment_id: str, *, reason: str = "", by: str = "", expected_revision: int | None = None
) -> dict | None:
    """Force an assessment due for re-review now, ahead of its cadence -- the
    hook for external events: a contract renewal, a new sub-processor, or any
    material change to the processing."""
    reason = (reason or "").strip() or "external trigger"

    def _mutate(record: dict) -> None:
        record["review_forced_at"] = time.time()
        record["review_trigger_reason"] = reason[:400]

    receipt = _audit_receipt(
        "REVIEW_TRIGGERED",
        by,
        assessment=assessment_id,
        reason=reason[:120],
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )


def set_renewal(
    assessment_id: str,
    *,
    renewal_at: float | None,
    by: str = "",
    expected_revision: int | None = None,
) -> dict | None:
    """Record a contract-renewal (or review-by) date. When it passes, the
    record automatically flips due for re-review -- no manual trigger needed."""
    ts = float(renewal_at) if renewal_at else 0.0

    def _mutate(record: dict) -> None:
        record["renewal_at"] = ts or None

    receipt = _audit_receipt(
        "RENEWAL_SET",
        by,
        assessment=assessment_id,
        renewal_at=ts,
    )
    return _rewrite_saved(
        assessment_id,
        _mutate,
        expected_revision=expected_revision,
        audit_receipt=receipt,
    )


def list_saved() -> list[dict]:
    """Summaries of saved assessments, newest first."""
    d = _assessments_dir()
    if not d.exists():
        return []
    out: list[dict] = []
    audit_retries = 0
    for p in d.glob("*.json"):
        if not _ASSESSMENT_ID_RE.fullmatch(p.stem):
            continue
        try:
            data = _load_saved_raw(p.stem)
        except AssessmentStateError:
            # A file that passes the permissive filename check but isn't a
            # genuine per-assessment record (e.g. another module's own
            # register living in this same data directory) fails the
            # identity check in _read_saved_path_unlocked. That's not this
            # listing's record to fail on -- skip it like a missing file.
            continue
        if data is None:
            continue
        if data.get("_audit_pending") and audit_retries < _AUDIT_READ_RETRY_LIMIT:
            audit_retries += 1
            _flush_assessment_audit(p.stem)
            try:
                data = _load_saved_raw(p.stem)
            except AssessmentStateError:
                continue
            if data is None:  # pragma: no cover -- immutable id cannot vanish here
                continue
        revision = _record_revision(data, label="assessment")
        res = data.get("result", {})
        fups = data.get("followups") or []
        now = time.time()
        acceptance = data.get("risk_acceptance") or {}
        acc_expires = acceptance.get("expires_at")
        acc_expired = bool(acc_expires and now >= float(acc_expires))
        forced = data.get("review_forced_at")
        renewal = data.get("renewal_at")
        renewal_due = bool(renewal and now >= float(renewal))
        cadence_due = (
            data.get("status") == "approved"
            and bool(data.get("next_review_at"))
            and now >= float(data.get("next_review_at") or 0)
        )
        # Why the record is due -- most specific reason first.
        if forced:
            due_reason = data.get("review_trigger_reason") or "external trigger"
        elif acc_expired:
            due_reason = "risk acceptance expired"
        elif renewal_due:
            due_reason = "renewal date reached"
        elif cadence_due:
            due_reason = "review cadence elapsed"
        else:
            due_reason = ""
        out.append(
            {
                "id": data.get("id", p.stem),
                "type": data.get("type", "?"),
                "subject": data.get("subject", "?"),
                "risk_rating": res.get("risk_rating", "?"),
                # Pre-pair records fall back to the single rating for both.
                "inherent_risk": res.get("inherent_risk", res.get("risk_rating", "?")),
                "residual_risk": res.get("residual_risk", res.get("risk_rating", "?")),
                "findings": len(res.get("findings", [])),
                "answered": res.get("answered", 0),
                "total": res.get("total", 0),
                "created_at": data.get("created_at", 0),
                "revision": revision,
                "template_revision": data.get("template_revision"),
                "template_digest": data.get("template_digest", ""),
                "status": data.get("status", "pending_review"),
                "assignee": data.get("assignee", ""),
                "assigned_at": data.get("assigned_at"),
                "open_followups": sum(1 for f in fups if not f.get("answer")),
                "decided_at": data.get("decided_at"),
                "next_review_at": data.get("next_review_at"),
                "review_due": bool(cadence_due or forced or renewal_due or acc_expired),
                "review_due_reason": due_reason,
                "renewal_at": renewal or None,
                "risk_accepted": bool(acceptance),
                "acceptance_expires_at": acc_expires,
                "acceptance_expired": acc_expired,
            }
        )
    # Filesystem enumeration order is undefined.  A timestamp can legitimately
    # tie (notably on Windows), so use the persisted record identity as a
    # canonical secondary key.  This cannot reconstruct unknowable causal
    # order for legacy ties, but it keeps trend direction and limit membership
    # stable across processes and filesystems.
    return sorted(
        out,
        key=lambda r: (r["created_at"], r["id"]),
        reverse=True,
    )


def risk_trend(subject: str, assessment_type: str = "", *, limit: int = 12) -> list[dict]:
    """The residual-risk history for a subject (optionally one type), oldest
    first. Powers the re-review delta -- a vendor's risk moving up or down
    across successive assessments instead of a single point in time."""
    subj = (subject or "").strip().lower()
    if not subj:
        return []
    rows = [
        r
        for r in list_saved()
        if str(r["subject"]).strip().lower() == subj
        and (not assessment_type or r["type"] == assessment_type)
    ]
    rows.sort(key=lambda r: (r["created_at"], r["id"]))
    return [
        {
            "id": r["id"],
            "created_at": r["created_at"],
            "residual_risk": r["residual_risk"],
            "inherent_risk": r["inherent_risk"],
        }
        for r in rows
    ][-limit:]


def _iter_saved_raw():
    d = _assessments_dir()
    if not d.exists():
        return
    for p in d.glob("*.json"):
        if not _ASSESSMENT_ID_RE.fullmatch(p.stem):
            continue
        try:
            data = _load_saved_raw(p.stem)
        except AssessmentStateError as exc:
            # Same tolerance as list_saved(): a file whose name passes the
            # id pattern but which is not a genuine per-assessment record
            # (the capability-review register.json shares this directory)
            # must not take down the metrics, the audit binder or the
            # finance board that read this iterator. Say so in the log.
            _log.warning(
                "skipping %s in the assessments directory: %s", p.name, exc,
            )
            continue
        if data is not None:
            yield data


def acceptance_metrics(
    *,
    types: frozenset[str] | set[str] | None = None,
    months: int = 12,
    since: float | None = None,
    until: float | None = None,
) -> dict:
    """Reviewer-acceptance KPIs over decided assessments -- the measurable
    learning loop. FIRST-PASS means approved with no follow-up thread: the
    reviewer accepted the agent's draft as-is. QUALIFIED is approved after
    follow-ups. The monthly trend (by decision date) is the chart that shows
    the agent getting better -- or not -- with evidence, not vibes."""
    now = time.time()
    t = time.gmtime(now)
    y, m = t.tm_year, t.tm_mon
    keys: list[str] = []
    for _ in range(max(1, months)):
        keys.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    keys.reverse()
    trend = {k: {"month": k, "decided": 0, "first_pass": 0} for k in keys}
    decided = first_pass = qualified = rejected = 0
    latencies: list[float] = []
    for data in _iter_saved_raw():
        if types is not None and data.get("type") not in types:
            continue
        status = data.get("status")
        if status not in ("approved", "rejected") \
                or not data.get("decided_at"):
            continue
        at = float(data["decided_at"])
        if since is not None and at < float(since):
            continue
        if until is not None and at > float(until):
            continue
        decided += 1
        fups = data.get("followups") or []
        if status == "rejected":
            rejected += 1
        elif fups:
            qualified += 1
        else:
            first_pass += 1
        created = float(data.get("created_at") or 0)
        if created and at >= created:
            latencies.append((at - created) / 86400.0)
        row = trend.get(time.strftime("%Y-%m", time.gmtime(at)))
        if row is not None:
            row["decided"] += 1
            if status == "approved" and not fups:
                row["first_pass"] += 1
    for row in trend.values():
        row["rate"] = (round(100.0 * row["first_pass"] / row["decided"], 1)
                       if row["decided"] else None)
    latencies.sort()
    return {
        "decided": decided, "first_pass": first_pass,
        "qualified": qualified, "rejected": rejected,
        "first_pass_rate": (round(100.0 * first_pass / decided, 1)
                            if decided else None),
        "median_days_to_decision": (round(latencies[len(latencies) // 2], 1)
                                    if latencies else None),
        "trend": [trend[k] for k in keys],
    }


# A question needs this many askings with zero findings before the evidence
# says "inert" -- below it the verdict stays "unproven", never "prune".
_ROI_MIN_ASKED = 5


def question_roi(assessment_type: str) -> dict:
    """Which questions earn their place, with evidence: per-question stats
    across every saved assessment of this type. LOAD-BEARING = removing its
    finding would lower at least one assessment's residual rating on the
    same rollup the scorer uses. INFORMATIVE = has produced findings without
    ever being decisive alone. INERT = asked >= _ROI_MIN_ASKED times without
    a single finding -- the evidence-based prune list."""
    tpl = get_template(assessment_type)
    if tpl is None:
        return {"type": assessment_type, "assessed": 0, "questions": [],
                "inert": 0, "load_bearing": 0}
    stats = {q.id: {"question_id": q.id, "text": q.text,
                    "section": q.section, "severity": q.severity,
                    "asked": 0, "fired": 0, "rating_impact": 0}
             for q in tpl.questions}
    assessed = 0
    for data in _iter_saved_raw():
        if data.get("type") != assessment_type:
            continue
        assessed += 1
        answers = data.get("answers") or {}
        findings = (data.get("result") or {}).get("findings") or []
        sev_by_q: dict[str, list[str]] = {}
        for f in findings:
            qid = f.get("question_id")
            if qid:
                sev_by_q.setdefault(qid, []).append(
                    str(f.get("severity", "low")))
        all_sevs = [str(f.get("severity", "low")) for f in findings]
        baseline = _rollup(all_sevs)
        for qid, row in stats.items():
            if qid in answers:
                row["asked"] += 1
            fired = sev_by_q.get(qid)
            if not fired:
                continue
            row["fired"] += 1
            rest = list(all_sevs)
            for s in fired:
                rest.remove(s)
            if _rollup(rest) != baseline:
                row["rating_impact"] += 1
    rows = []
    for row in stats.values():
        row["fire_rate"] = (round(100.0 * row["fired"] / row["asked"], 1)
                            if row["asked"] else None)
        row["verdict"] = ("load-bearing" if row["rating_impact"]
                          else "informative" if row["fired"]
                          else "inert" if row["asked"] >= _ROI_MIN_ASKED
                          else "unproven")
        rows.append(row)
    rows.sort(key=lambda r: (-r["rating_impact"], -r["fired"],
                             r["question_id"]))
    return {"type": assessment_type, "assessed": assessed,
            "questions": rows,
            "inert": sum(1 for r in rows if r["verdict"] == "inert"),
            "load_bearing": sum(1 for r in rows
                                if r["verdict"] == "load-bearing")}


def _load_saved_raw(assessment_id: str) -> dict | None:
    from .file_lock import cross_process_lock

    path = _assessment_path(assessment_id)
    if path is None:
        return None
    with cross_process_lock(path, strict=True):
        return _read_saved_path_unlocked(path)


def load_saved(assessment_id: str) -> dict | None:
    record = _load_saved_raw(assessment_id)
    if record is not None and record.get("_audit_pending"):
        _flush_assessment_audit(assessment_id)
        record = _load_saved_raw(assessment_id)
    return _public_assessment_record(record) if record is not None else None


def list_saved_heads(
    *,
    limit: int = 100,
) -> tuple[tuple[dict, ...], int]:
    """Read a bounded deterministic set of current assessment heads.

    Unlike :func:`list_saved`, this projection helper does not retry the audit
    outbox or write any record.  It is intended for read-only cross-suite
    consumers that must never turn a context read into a mutation.  The total
    valid filename count is returned so callers can disclose truncation.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
        raise ValueError("assessment head limit is outside its bound")
    directory = _assessments_dir()
    if not directory.exists():
        return (), 0
    identifiers = tuple(
        sorted(
            path.stem
            for path in directory.glob("*.json")
            if _ASSESSMENT_ID_RE.fullmatch(path.stem)
        )
    )
    records: list[dict] = []
    for assessment_id in identifiers[:limit]:
        try:
            record = _load_saved_raw(assessment_id)
        except AssessmentStateError:
            # Same tolerance as list_saved(): a filename that passes the
            # permissive ID pattern but isn't a genuine per-assessment
            # record (e.g. a sibling module's own register file in this
            # directory) is skipped rather than failing the whole read.
            continue
        if record is not None:
            records.append(_public_assessment_record(record))
    return tuple(records), len(identifiers)


def history_heads(*, offset=0, after=None, before=None, oldest=False, allowed_types=None):
    """Bounded current metadata, authorized by type before matching/counts.

    Native file windows can be empty after authorization. Their private scan
    positions must remain in sealed cursors; they are never accessible counts.
    No answers/notes leave the adapter and no audit outbox is drained.
    """
    import time

    from .metadata_history import WINDOW, HistoryChanged, Window, check_scan, digest
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("Invalid history position")
    directory = _assessments_dir()
    started = time.monotonic()

    def heads():
        result = []
        for count, path in enumerate(directory.glob("*.json"), 1):
            check_scan(count, started)
            if not _ASSESSMENT_ID_RE.fullmatch(path.stem):
                continue
            stat = path.stat()
            if (after is not None and stat.st_mtime < after) or (before is not None and stat.st_mtime >= before):
                continue
            result.append((path.stem, stat.st_mtime_ns, stat.st_size))
        return sorted(result, key=lambda row: (row[1] if oldest else -row[1], row[0]))

    selected = heads()
    snapshot = digest(selected)
    rows = []
    for identifier, modified, _ in selected[offset:offset + WINDOW]:
        check_scan(len(selected), started)
        raw = _load_saved_raw(identifier)
        if raw is not None and (allowed_types is None or raw.get("type") in allowed_types):
            rows.append({**{key: raw.get(key) for key in ("id", "type", "subject", "status", "revision")},
                         "date": modified / 1_000_000_000})
    if snapshot != digest(heads()):
        raise HistoryChanged("Questionnaires changed during search. Start a fresh search.")
    return Window(rows, snapshot, offset + WINDOW if offset + WINDOW < len(selected) else None)



def assessment_score_profile(record: dict) -> dict:
    """Return a deterministic question-level score explanation.

    The projection is derived only from the immutable questionnaire snapshot
    and saved answers.  It does not rescore from a mutable live template and it
    does not use a model.  ``contribution_bps`` is an explanatory severity
    weight; the authoritative overall result remains the existing transparent
    max-severity rollup.
    """

    if not isinstance(record, dict):
        raise AssessmentStateError("assessment record is invalid")
    assessment_id = str(record.get("id") or "")
    if _assessment_path(assessment_id) is None:
        raise AssessmentStateError("assessment identity is invalid")
    template = template_for_saved_record(record)
    if template is None:
        raise AssessmentStateError("assessment questionnaire is unavailable")
    answers = record.get("answers")
    if not isinstance(answers, dict):
        raise AssessmentStateError("assessment answers are invalid")
    result = record.get("result")
    if not isinstance(result, dict):
        raise AssessmentStateError("assessment result is invalid")
    findings = result.get("findings")
    if not isinstance(findings, list):
        raise AssessmentStateError("assessment findings are invalid")
    finding_kinds = {
        str(item.get("question_id")): str(item.get("kind"))
        for item in findings
        if isinstance(item, dict)
        and isinstance(item.get("question_id"), str)
        and item.get("kind") in {"risk", "unverified"}
    }
    severity_bps = {"low": 2_500, "medium": 5_000, "high": 10_000}
    rows: list[dict] = []
    for position, question in enumerate(template.questions, start=1):
        answer_record = answers.get(question.id)
        if answer_record is None:
            answer = None
        elif isinstance(answer_record, dict) and answer_record.get("answer") in ANSWERS:
            answer = str(answer_record["answer"])
        else:
            raise AssessmentStateError("assessment answer contract is invalid")
        finding_kind = finding_kinds.get(question.id)
        if answer is None:
            contribution_kind = "unanswered"
        elif answer == "na":
            contribution_kind = "not_applicable"
        elif finding_kind == "risk":
            contribution_kind = "risk_finding"
        elif finding_kind == "unverified":
            contribution_kind = "unverified_finding"
        else:
            contribution_kind = "control_in_place"
        rows.append(
            {
                "position": position,
                "question_id": question.id,
                "section": question.section,
                "severity": question.severity,
                "risk_answer": question.risk_answer,
                "answer": answer,
                "applicable": answer not in {None, "na"},
                "finding_kind": finding_kind,
                "contribution_kind": contribution_kind,
                "contribution_bps": (
                    severity_bps[question.severity] if finding_kind is not None else 0
                ),
            }
        )
    return {
        "schema": "lightwork.assessment-score-profile.v1",
        "assessment_id": assessment_id,
        "assessment_revision": _record_revision(record, label="assessment"),
        "template_revision": record.get("template_revision"),
        "template_digest": str(record.get("template_digest") or ""),
        "scoring_method": "transparent_max_severity",
        "risk_rating": result.get("risk_rating"),
        "inherent_risk": result.get("inherent_risk", result.get("risk_rating")),
        "residual_risk": result.get("residual_risk", result.get("risk_rating")),
        "answered": result.get("answered"),
        "total": result.get("total"),
        "questions": rows,
    }


def assessment_record_projection(record: dict, *, show_all_details: bool) -> dict:
    """Return a stable lightweight or full assessment wire projection."""

    if type(show_all_details) is not bool:
        raise ValueError("show_all_details must be boolean")
    score_profile = assessment_score_profile(record)
    direct_path = f"/assessments?assessment_id={score_profile['assessment_id']}"
    administrator = (
        None
        if not record.get("assignee")
        else {
            "principal_ref": record.get("assignee"),
            "assigned_by_ref": record.get("assigned_by") or None,
            "assigned_at": record.get("assigned_at"),
        }
    )
    completed_by = (
        None
        if not record.get("decided_by")
        else {
            "principal_ref": record.get("decided_by"),
            "completed_at": record.get("decided_at"),
            "decision": record.get("status"),
        }
    )
    if show_all_details:
        return {
            **_public_assessment_record(record),
            "score_profile": score_profile,
            "show_all_details": True,
            "direct_path": direct_path,
            "record_administrator": administrator,
            "completed_by": completed_by,
        }
    result = record.get("result")
    if not isinstance(result, dict):
        raise AssessmentStateError("assessment result is invalid")
    return {
        "schema": "lightwork.assessment-record-summary.v1",
        "id": score_profile["assessment_id"],
        "type": record.get("type"),
        "subject": record.get("subject"),
        "status": record.get("status"),
        "revision": score_profile["assessment_revision"],
        "template_revision": score_profile["template_revision"],
        "template_digest": score_profile["template_digest"],
        "risk_rating": result.get("risk_rating"),
        "inherent_risk": result.get("inherent_risk", result.get("risk_rating")),
        "residual_risk": result.get("residual_risk", result.get("risk_rating")),
        "findings": len(result.get("findings") or []),
        "assignee": record.get("assignee", ""),
        "created_at": record.get("created_at"),
        "updated_at": record.get("decided_at") or record.get("assigned_at") or record.get(
            "created_at"
        ),
        "show_all_details": False,
        "direct_path": direct_path,
        "record_administrator": administrator,
        "completed_by": completed_by,
    }


# --- Rendering -------------------------------------------------------------


def render_questions_text(tpl: AssessmentTemplate) -> str:
    head = f"{tpl.title} ({tpl.framework}) -- {len(tpl.questions)} questions"
    lines = [head, "=" * len(head), ""]
    section = None
    for q in tpl.questions:
        if q.section != section:
            section = q.section
            lines.append(f"[{section}]")
        lines.append(f"  {q.id}  ({q.severity}; risk if {q.risk_answer})")
        lines.append(f"     {q.text}")
    return "\n".join(lines)


def render_questions_json(tpl: AssessmentTemplate) -> str:
    return json.dumps(
        {
            "type": tpl.type,
            "title": tpl.title,
            "framework": tpl.framework,
            "questions": [asdict(q) for q in tpl.questions],
        },
        indent=2,
    )


def render_result_text(result: AssessmentResult) -> str:
    tpl = get_template(result.type)
    title = tpl.title if tpl else result.type
    head = f"{title}: {result.subject}"
    lines = [
        head,
        "=" * len(head),
        "",
        f"Inherent risk: {result.inherent_risk.upper()} -> "
        f"Residual risk: {result.residual_risk.upper()} "
        f"({result.controls_in_place} of {result.risks_in_scope} in-scope "
        "risk areas controlled)",
        f"Completeness: {result.answered}/{result.total} answered, "
        f"{len(result.findings)} finding(s)",
        "",
    ]
    if not result.findings:
        lines.append("No findings recorded.")
    else:
        lines.append("Findings (highest severity first):")
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(result.findings, key=lambda f: order.get(f.severity, 3)):
            flag = "UNVERIFIED" if f.kind == "unverified" else f.severity.upper()
            lines.append(f"  [{flag}] {f.section}: {f.question}")
            lines.append(f"      -> {f.recommendation}")
    return "\n".join(lines)


def render_result_json(result: AssessmentResult) -> str:
    return json.dumps(asdict(result), indent=2, default=str)


# --- The conversational assessor agent -------------------------------------

ASSESSMENT_PERSONA = (
    "You are Lightwork's compliance assessor. You conduct structured assessments "
    "(privacy impact, AI risk, vendor risk). First call list_assessments to see "
    "the types, then start_assessment with the type and the subject being "
    "assessed. Answer each question from the documents and facts you were given, "
    "one at a time, with answer_question -- yes/no/na, or 'unknown' when you "
    "genuinely cannot verify it from the evidence. NEVER guess: 'unknown' is the "
    "honest answer when the evidence is silent. When every question is answered, "
    "call finalize_assessment to produce the scored findings. You produce a DRAFT "
    "for a human reviewer (DPO / risk owner) to sign off; you never approve it "
    "yourself."
)


def build_assessment_agent(ctx, session: AssessmentSession | None = None):
    """Construct the compliance-assessor agent: an Agent with the assessor persona
    and the assessment tools bound to a shared :class:`AssessmentSession`. Returns
    ``(agent, session)``. Mirrors :func:`maverick.intake.build_intake_agent` -- the
    live chat loop reuses the normal agent surface; this assembles the assessor."""
    from .agent import Agent
    from .tools import ToolRegistry
    from .tools.assessment_tools import assessment_tools

    session = session or AssessmentSession()
    agent = Agent(
        ctx=ctx,
        role="assessment",
        brief="Conduct a compliance assessment and produce scored findings.",
        persona=ASSESSMENT_PERSONA,
    )
    # The assessor only needs its own tools; replace the full base registry
    # (shell, filesystem, MCP, ...) with an assessment-only one.
    agent.tools = ToolRegistry()
    for tool in assessment_tools(session):
        agent.tools.register(tool)
    return agent, session


# --- The first-round privacy analyst ---------------------------------------

PRIVACY_ANALYST_PERSONA = (
    "You are Lightwork's privacy & security analyst -- the first-round analyst. "
    "Given a subject (a vendor, an AI system, or a processing activity) you "
    "conduct the assessment end to end:\n"
    "1. RESEARCH the subject from the documents/context you are given (read_file, "
    "knowledge_search) and the web (web_search), gathering the evidence each "
    "question needs.\n"
    "2. start_assessment for the right framework (call list_assessments for the set "
    "-- privacy: vendor_risk/aira/pia; security: hipaa/soc2/pci_dss), then answer "
    "each question from that evidence with answer_question -- yes/no/na, or "
    "'unknown' when the evidence is genuinely silent. NEVER guess.\n"
    "3. For each risk, call find_controls to cite the specific control and framework "
    "reference (GDPR / EU AI Act / ISO 27001 / SOC 2 / NIST / HIPAA) that closes it.\n"
    "4. finalize_assessment to produce the scored findings.\n"
    "You produce a DRAFT with cited controls for a human reviewer (DPO / risk owner) "
    "to sign off. You never approve or certify compliance yourself."
)

# The analyst's safe envelope: read-only research + the control catalog. Mutating
# tools (shell, write_file, ...) are excluded -- and so is ``http_fetch``: it can
# POST an arbitrary body to any URL, which a prompt-injected analyst (it ingests
# untrusted subject material) could use to exfiltrate what it read. ``web_search``
# stays as the research channel (a query, not an arbitrary request body).
_ANALYST_RESEARCH_TOOLS = (
    "read_file",
    "web_search",
    "knowledge_search",
    "find_controls",
)


def _privacy_analyst_tools(base_registry, session: AssessmentSession):
    """Curate the analyst's registry: keep the read-only research + control tools
    from ``base_registry`` and add the assessment tools bound to ``session``."""
    from .tools import ToolRegistry
    from .tools.assessment_tools import assessment_tools

    reg = ToolRegistry()
    for name in _ANALYST_RESEARCH_TOOLS:
        try:
            reg.register(base_registry.get(name))
        except KeyError:
            continue  # tool not present in this build (e.g. web_search disabled)
    for tool in assessment_tools(session):
        reg.register(tool)
    return reg


def build_privacy_analyst_agent(ctx, session: AssessmentSession | None = None):
    """Construct the first-round privacy analyst: an Agent that researches a subject
    (read-only research tools), conducts the structured assessment, and cites the
    control for each finding. Returns ``(agent, session)``. The agent's registry is
    curated to the read-only research/control tools plus the assessment tools, so it
    can gather evidence and score it but cannot take mutating/outward actions."""
    from .agent import Agent

    session = session or AssessmentSession()
    agent = Agent(
        ctx=ctx,
        role="privacy_analyst",
        brief="Research the subject and conduct a scored compliance assessment.",
        persona=PRIVACY_ANALYST_PERSONA,
    )
    agent.tools = _privacy_analyst_tools(agent.tools, session)
    return agent, session


COMPLIANCE_AUDITOR_PERSONA = (
    "You are Lightwork's compliance auditor. Given a framework (hipaa / soc2 / "
    "pci_dss, or another from list_assessments) and a subject -- usually THIS "
    "deployment, sometimes a vendor -- you produce an audit-readiness report a "
    "human compliance officer signs off.\n"
    "1. list_assessments, then start_assessment for the framework.\n"
    "2. Gather EVIDENCE before answering: deployment_posture for this system's live "
    "control state, read_file / knowledge_search for policies and documents, "
    "web_search for the framework's requirements. Answer each control with "
    "answer_question -- yes/na when the evidence shows it is met, no when it is not, "
    "'unknown' when there is NO evidence (an honest gap, never a guessed pass).\n"
    "3. For each gap, find_controls to cite the control and its remediation.\n"
    "4. finalize_assessment for the scored gaps, then frame it as audit readiness: "
    "what is in place, what is missing (ranked by severity), and the remediation "
    "roadmap. You DRAFT the readiness report -- the compliance officer signs off. "
    "You never declare the system 'compliant', 'certified', or 'audit-passed'."
)


def _compliance_auditor_tools(base_registry, session: AssessmentSession):
    """The auditor's envelope: the analyst's read-only research + control +
    assessment tools, plus ``deployment_posture`` for live control-state evidence."""
    from .tools.posture_tools import posture_tools

    reg = _privacy_analyst_tools(base_registry, session)
    for tool in posture_tools():
        reg.register(tool)
    return reg


def build_compliance_auditor_agent(ctx, session: AssessmentSession | None = None):
    """Construct the compliance auditor: an Agent that audits a subject (usually this
    deployment) against a framework -- gathering evidence from the live control
    posture + documents, scoring the gaps, and drafting an audit-readiness report
    for a human to sign off. Returns ``(agent, session)``. Read-only research +
    control + assessment tools plus deployment_posture; no mutating/outward tools."""
    from .agent import Agent

    session = session or AssessmentSession()
    agent = Agent(
        ctx=ctx,
        role="compliance_auditor",
        brief="Audit the subject against a framework and draft an audit-readiness "
        "report for a human to sign off.",
        persona=COMPLIANCE_AUDITOR_PERSONA,
    )
    agent.tools = _compliance_auditor_tools(agent.tools, session)
    return agent, session


__all__ = [
    "COMPLIANCE_AUDITOR_PERSONA",
    "build_compliance_auditor_agent",
    "ANSWERS",
    "ASSESSMENT_PERSONA",
    "build_assessment_agent",
    "PRIVACY_ANALYST_PERSONA",
    "build_privacy_analyst_agent",
    "Question",
    "AssessmentTemplate",
    "Finding",
    "AssessmentResult",
    "AssessmentSession",
    "AssessmentConflict",
    "AssessmentStateError",
    "AssessmentAuditBackpressure",
    "AssessmentTransitionError",
    "FRAMEWORK_SOURCES",
    "TEMPLATES",
    "list_templates",
    "get_template",
    "template_state",
    "template_department",
    "template_for_saved_record",
    "custom_template_records",
    "save_custom_template",
    "delete_custom_template",
    "save_session",
    "add_assessment_comment",
    "assessment_comment_id",
    "assessment_comments",
    "set_assessment_answer_ai_metadata",
    "list_saved",
    "list_saved_heads",
    "load_saved",
    "assessment_score_profile",
    "assessment_record_projection",
    "decide_assessment",
    "accept_risk",
    "trigger_review",
    "set_renewal",
    "risk_trend",
    "acceptance_metrics",
    "question_roi",
    "render_questions_text",
    "render_questions_json",
    "render_result_text",
    "render_result_json",
]
