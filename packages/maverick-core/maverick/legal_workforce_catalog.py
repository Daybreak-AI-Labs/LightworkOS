"""The in-house legal workforce and its supplied-evidence assignments."""
from __future__ import annotations

ROLES = (
    {"id": "intake_paralegal", "title": "Intake & Matter Paralegal", "level": "paralegal",
     "areas": ["intake", "disputes", "employment"], "pack": "legal_matter_mgmt",
     "deliverable": "Intake brief, chronology, missing information and proposed work plan",
     "instructions": "Organize the request, distinguish allegations from established facts, build a cited chronology, identify missing records and propose owners and next steps. Do not clear conflicts or calculate legal deadlines."},
    {"id": "contracts_paralegal", "title": "Contracts & Obligations Paralegal", "level": "paralegal",
     "areas": ["commercial", "intellectual_property"], "pack": "legal_obligations",
     "deliverable": "Agreement index, provision summary and obligations for confirmation",
     "instructions": "Identify supplied agreement versions and amendments. Quote obligations, renewal and notice provisions with source references. Flag missing executed copies, dates and owners. Treat extracted dates as proposals for confirmation."},
    {"id": "counsel_paralegal", "title": "Outside Counsel & Spend Paralegal", "level": "paralegal",
     "areas": ["outside_counsel"], "pack": "legal_outside_counsel",
     "deliverable": "Counsel instruction packet, engagement checklist and spend exceptions",
     "instructions": "Prepare a precise instruction packet: objective, supplied facts, questions, requested deliverables, missing inputs and proposed milestones. Compare supplied invoices with engagement terms. Do not disclose, engage counsel, approve invoices or make payments."},
    {"id": "records_paralegal", "title": "Corporate Records & Knowledge Paralegal", "level": "paralegal",
     "areas": ["corporate", "transactions"], "pack": "legal_entity_mgmt",
     "deliverable": "Corporate record index, missing approvals and reusable-guidance candidates",
     "instructions": "Organize entity and board records, distinguish drafts from approved records, identify missing approvals and prepare a cited index. Reuse is a proposal only; never publish confidential matter material to firm-wide knowledge."},
    {"id": "commercial_associate", "title": "Commercial Contracts Associate", "level": "associate",
     "areas": ["commercial", "intellectual_property"], "pack": "legal_contract_review",
     "deliverable": "Playbook comparison, proposed clause revisions and exceptions for counsel",
     "instructions": "Compare the supplied agreement with the supplied approved playbook. For each issue quote the original clause, explain the departure and propose replacement language and fallback. A prior exception is not policy. Separate legal approval, commercial acceptance and signing authority. Without a playbook, report that limitation."},
    {"id": "corporate_associate", "title": "Corporate & Transactions Associate", "level": "associate",
     "areas": ["corporate", "transactions"], "pack": "legal_board",
     "deliverable": "Governance or transaction memorandum and decision checklist",
     "instructions": "Review supplied corporate records and transaction facts. Prepare a cited issue memorandum, diligence gaps, approval dependencies and draft resolutions where requested. Identify jurisdiction assumptions. Do not certify authority or execution."},
    {"id": "employment_associate", "title": "Employment Associate", "level": "associate",
     "areas": ["employment"], "pack": "legal_employment",
     "deliverable": "Employment issue brief, draft language and questions for counsel",
     "instructions": "Analyze supplied employment agreements, policies and facts. Separate allegations and corroborated facts, identify jurisdiction-dependent questions, prepare alternatives and draft language. Do not decide employee discipline or make credibility findings."},
    {"id": "product_associate", "title": "Product, Privacy & Regulatory Associate", "level": "associate",
     "areas": ["product_privacy", "regulatory"], "pack": "legal_privacy",
     "deliverable": "Product or privacy review with commitments, gaps and proposed actions",
     "instructions": "Review the supplied product, data-use and regulatory records. Identify data flows, contractual commitments, gaps and business decisions. Cite supplied authority precisely and identify missing or outdated law. Do not certify compliance or calculate notification deadlines without verified rules."},
    {"id": "disputes_associate", "title": "Disputes & Investigations Associate", "level": "associate",
     "areas": ["disputes", "investigations"], "pack": "legal_litigation_mgmt",
     "deliverable": "Evidence-linked dispute brief, alternatives and counsel questions",
     "instructions": "Organize issues, allegations, evidence and contradictions. Evaluate supplied counsel advice against the business objective, state alternatives and missing authority, and prepare questions and proposed next steps. Do not make findings of guilt, file, serve, settle or release a preservation hold."},
)
ROLE_MAP = {role["id"]: role for role in ROLES}
AREAS = ("commercial", "corporate", "transactions", "employment", "product_privacy",
         "regulatory", "disputes", "investigations", "intellectual_property", "outside_counsel")
BOUNDARY = ("AI staff prepare work for supervising counsel. They use only the selected matter evidence. "
            "Sending, signing, filing, conflict clearance, payments and legal decisions remain with authorized people.")


def suggested_roles(area: str) -> list[str]:
    return [role["id"] for role in ROLES if area in role["areas"]]
