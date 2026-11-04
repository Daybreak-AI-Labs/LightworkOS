"""EU AI Act conformity workflows: FRIA (Art. 27), Annex IV, Art. 43 route.

Three human-gated registers over governed CAS records:

* **FRIA** — the Art. 27(1) fundamental-rights impact assessment as six named
  assertions ((a) processes, (b) period/frequency, (c) affected categories,
  (d) risks of harm, (e) oversight implementation, (f) materialisation
  measures). Completion requires every element and a named assessor; the
  Art. 27(2) update obligation is a ``mark_outdated`` transition that reopens
  the record; the Art. 27(3) notification to the market surveillance
  authority is recorded as a human submission — the platform never transmits.
* **Annex IV** — the technical documentation of Art. 11(1) as a nine-item
  checklist. Each item is asserted by a named human with a reference to
  where the documentation lives; the module renders a bounded skeleton with
  citations, never fabricated content.
* **Art. 43 route** — the conformity-assessment route as a validated human
  decision: Annex III point 1 may use internal control (Annex VI) only when
  harmonised standards (Art. 40) or common specifications (Art. 41) were
  applied, and otherwise requires a notified body (Annex VII); points 2-8
  use internal control; Annex I products follow their sectoral acts. A
  substantial modification reopens the assessment (Art. 43(4)); provider
  pre-determined changes documented in the technical documentation do not.

Everything here is decision support and drafting assistance for the
provider's or deployer's own obligations. It is not a conformity assessment,
a CE marking, a notified-body opinion, or legal advice.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from typing import Any

from .governed_records import GovernedRecordStore

REGULATION_METADATA = {
    "regulation": "Regulation (EU) 2024/1689",
    "consolidated": "2026-07-27",
}
NON_CERTIFICATION_NOTICE = (
    "Drafting and tracking assistance for the operator's own EU AI Act "
    "obligations; not a conformity assessment, CE marking, notified-body "
    "opinion, or legal advice."
)
FRIA_SCHEMA = "lightwork.eu-fria.v1"
ANNEX_IV_SCHEMA = "lightwork.eu-annex-iv.v1"
ROUTE_SCHEMA = "lightwork.eu-art43-route.v1"

FRIA_ELEMENTS = {
    "process_description": {
        "citation": "Art. 27(1)(a)",
        "prompt": "The deployer's processes in which the high-risk AI system "
                  "will be used, in line with its intended purpose.",
    },
    "period_frequency": {
        "citation": "Art. 27(1)(b)",
        "prompt": "The period of time within which, and the frequency with "
                  "which, the system is intended to be used.",
    },
    "affected_categories": {
        "citation": "Art. 27(1)(c)",
        "prompt": "The categories of natural persons and groups likely to be "
                  "affected by its use in the specific context.",
    },
    "risks_of_harm": {
        "citation": "Art. 27(1)(d)",
        "prompt": "The specific risks of harm likely to impact the identified "
                  "categories, taking the provider's instructions into account.",
    },
    "oversight_measures": {
        "citation": "Art. 27(1)(e)",
        "prompt": "The implementation of human oversight measures, according "
                  "to the instructions for use.",
    },
    "materialisation_measures": {
        "citation": "Art. 27(1)(f)",
        "prompt": "The measures to be taken where those risks materialise, "
                  "including internal governance and complaint mechanisms.",
    },
}

ANNEX_IV_ITEMS = {
    "general_description": ("Annex IV(1)", "A general description of the AI system."),
    "development_process": (
        "Annex IV(2)",
        "A detailed description of the elements of the AI system and of the "
        "process for its development.",
    ),
    "monitoring_control": (
        "Annex IV(3)",
        "Detailed information about the monitoring, functioning and control "
        "of the AI system.",
    ),
    "performance_metrics": (
        "Annex IV(4)",
        "A description of the appropriateness of the performance metrics.",
    ),
    "risk_management": (
        "Annex IV(5)",
        "A detailed description of the risk management system in accordance "
        "with Article 9.",
    ),
    "lifecycle_changes": (
        "Annex IV(6)",
        "A description of relevant changes made by the provider through the "
        "system's lifecycle.",
    ),
    "standards_applied": (
        "Annex IV(7)",
        "A list of the harmonised standards applied in full or in part, or "
        "the alternative solutions adopted.",
    ),
    "declaration_of_conformity": (
        "Annex IV(8)",
        "A copy of the EU declaration of conformity referred to in Article 47.",
    ),
    "post_market_plan": (
        "Annex IV(9)",
        "A detailed description of the post-market performance evaluation "
        "system, including the Article 72 monitoring plan.",
    ),
}

ROUTES = ("internal_control_annex_vi", "notified_body_annex_vii", "sectoral_annex_i")

PMM_SCHEMA = "lightwork.eu-pmm-plan.v1"
REGISTRATION_SCHEMA = "lightwork.eu-registration.v1"
IFU_SCHEMA = "lightwork.eu-ifu.v1"

#: Art. 49 registration bases -> (citation, the registry that basis belongs in).
#: Points 49(1)-(3) register in the Commission's EU database; Annex III point 2
#: systems register at national level instead (Art. 49(5)).
REGISTRATION_BASES = {
    "provider_high_risk": ("Art. 49(1)", "eu_database"),
    "provider_not_high_risk": ("Art. 49(2)", "eu_database"),
    "public_authority_deployer": ("Art. 49(3)", "eu_database"),
    "annex_iii_point_2_national": ("Art. 49(5)", "national"),
}
REGISTRIES = ("eu_database", "national")

#: Art. 13(3) instructions-for-use content items, mirrored from the Annex IV
#: checklist pattern: the register records WHERE each item is documented.
IFU_ITEMS = {
    "provider_identity": (
        "Art. 13(3)(a)",
        "The identity and contact details of the provider and, where "
        "applicable, its authorised representative.",
    ),
    "system_characteristics": (
        "Art. 13(3)(b)",
        "The characteristics, capabilities and limitations of performance: "
        "intended purpose, accuracy, robustness and cybersecurity, known "
        "foreseeable risks, input-data specifications, and how to interpret "
        "the system's output.",
    ),
    "predetermined_changes": (
        "Art. 13(3)(c)",
        "The changes to the system and its performance pre-determined by the "
        "provider at the moment of the initial conformity assessment.",
    ),
    "human_oversight_measures": (
        "Art. 13(3)(d)",
        "The human oversight measures, including the technical measures put "
        "in place to facilitate the interpretation of the outputs.",
    ),
    "resources_and_maintenance": (
        "Art. 13(3)(e)",
        "The computational and hardware resources needed, the expected "
        "lifetime, and the necessary maintenance and care measures, "
        "including software updates.",
    ),
    "log_collection": (
        "Art. 13(3)(f)",
        "Where relevant, the mechanisms allowing deployers to properly "
        "collect, store and interpret the logs (Art. 12).",
    ),
}

GPAI_SCHEMA = "lightwork.eu-gpai-register.v1"

#: Art. 53(1) obligations for every general-purpose AI model provider.
GPAI_OBLIGATIONS = {
    "technical_documentation": (
        "Art. 53(1)(a)",
        "Up-to-date technical documentation of the model, including training "
        "and testing process and evaluation results (Annex XI minimum), for "
        "the AI Office and national authorities on request.",
    ),
    "downstream_information": (
        "Art. 53(1)(b)",
        "Information and documentation for downstream AI system providers to "
        "understand the model's capabilities and limitations (Annex XII "
        "minimum).",
    ),
    "copyright_policy": (
        "Art. 53(1)(c)",
        "A policy to comply with Union copyright law, identifying and "
        "respecting rights reservations under Art. 4(3) of Directive (EU) "
        "2019/790.",
    ),
    "training_content_summary": (
        "Art. 53(1)(d)",
        "A sufficiently detailed public summary of the content used for "
        "training, per the AI Office template.",
    ),
}

#: Art. 55(1) additions for general-purpose AI models with systemic risk.
GPAI_SYSTEMIC_OBLIGATIONS = {
    "model_evaluation": (
        "Art. 55(1)(a)",
        "State-of-the-art model evaluation, including conducted and "
        "documented adversarial testing to identify and mitigate systemic "
        "risks.",
    ),
    "systemic_risk_mitigation": (
        "Art. 55(1)(b)",
        "Assessment and mitigation of possible Union-level systemic risks, "
        "including their sources, from development, placing on the market, "
        "or use.",
    ),
    "incident_reporting": (
        "Art. 55(1)(c)",
        "Tracking, documenting, and reporting relevant serious-incident "
        "information to the AI Office and national authorities without "
        "undue delay.",
    ),
    "cybersecurity_protection": (
        "Art. 55(1)(d)",
        "An adequate level of cybersecurity protection for the model and "
        "its physical infrastructure.",
    ),
}

#: Art. 53(2): the free and open-source exemption covers only (a) and (b),
#: and never applies to a model with systemic risk.
GPAI_OPEN_SOURCE_EXEMPT = ("technical_documentation", "downstream_information")

DEPLOYER_SCHEMA = "lightwork.eu-deployer-register.v1"

#: Art. 26 deployer obligations for high-risk AI systems. Always-applicable
#: duties; the conditional ones below join the register only when the
#: deployment's flags say the condition holds. Art. 26(3) is a savings
#: clause, not a duty, and the Art. 26(10) post-remote-biometric
#: law-enforcement regime is out of scope for this register and stated so.
DEPLOYER_OBLIGATIONS = {
    "use_per_instructions": (
        "Art. 26(1)",
        "The system is used in accordance with the provider's instructions "
        "for use, under appropriate technical and organisational measures.",
    ),
    "operation_monitoring": (
        "Art. 26(5)",
        "Operation is monitored on the basis of the instructions for use; "
        "the provider (and, where required, authorities) are informed "
        "without undue delay of Art. 79(1) risks and serious incidents, "
        "and use is suspended where required.",
    ),
    "log_retention": (
        "Art. 26(6)",
        "Automatically generated logs under the deployer's control are "
        "kept for a period appropriate to the intended purpose — at least "
        "six months, unless Union or national law provides otherwise.",
    ),
    "affected_person_information": (
        "Art. 26(11)",
        "Natural persons subject to the use of the high-risk AI system "
        "are informed that they are subject to its use, where required.",
    ),
    "authority_cooperation": (
        "Art. 26(12)",
        "The deployer cooperates with the competent authorities in any "
        "action those authorities take in relation to the system.",
    ),
}

#: Conditional Art. 26 duties, included when the matching flag is set at open.
DEPLOYER_CONDITIONAL_OBLIGATIONS = {
    "input_data_control": (
        "Art. 26(4)",
        "To the extent the deployer exercises control over input data, "
        "that data is relevant and sufficiently representative in view of "
        "the system's intended purpose.",
        "controls_input_data",
    ),
    "worker_information": (
        "Art. 26(7)",
        "Before putting the system into service or use at the workplace, "
        "affected workers and their representatives are informed, per "
        "applicable Union/national law and practice.",
        "workplace_use",
    ),
    "registration_check": (
        "Art. 26(8)",
        "As a public authority (or Union body), the system's registration "
        "in the EU database under Art. 49 has been verified; an "
        "unregistered system is not used and the provider or distributor "
        "is informed.",
        "public_authority",
    ),
    "dpia_information": (
        "Art. 26(9)",
        "The information under Art. 13 is used to carry out the data "
        "protection impact assessment where GDPR Art. 35 / Directive (EU) "
        "2016/680 Art. 27 requires one.",
        "requires_dpia",
    ),
}

#: Art. 26(2): the one obligation that must name natural persons.
DEPLOYER_OVERSIGHT_KEY = "human_oversight_assignment"
DEPLOYER_OVERSIGHT_CITATION = "Art. 26(2)"
_MAX_OVERSIGHT_PERSONS = 20

_FRIA = GovernedRecordStore("eu_fria", "ECF", "eu_fria_assessment")
_ANNEX_IV = GovernedRecordStore("eu_annex_iv", "ECD", "eu_annex_iv_checklist")
_ROUTES = GovernedRecordStore("eu_art43_routes", "ECA", "eu_art43_route")
_GPAI = GovernedRecordStore("eu_gpai", "ECG", "eu_gpai_register")
_DEPLOYER = GovernedRecordStore("eu_deployer", "ECY", "eu_deployer_register")
_PMM = GovernedRecordStore("eu_pmm_plans", "ECP", "eu_pmm_plan")
_REGISTRATIONS = GovernedRecordStore("eu_registrations", "ECR", "eu_registration")
_IFU = GovernedRecordStore("eu_ifu", "ECI", "eu_ifu_checklist")

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}\Z")
_MAX_LIST = 500


class EUConformityError(RuntimeError):
    """Base error for the conformity workflows."""


class EUConformityConfigError(EUConformityError):
    """The [eu_conformity] configuration is missing, malformed, or disabled."""


def _sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value.strip()):
        raise ValueError(f"{label} must be a bounded identifier token")
    return value.strip()


def _text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    out = value.strip()
    if len(out) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    return out


def get_eu_conformity_config() -> dict[str, bool]:
    try:
        from .config import config_source_errors, load_global_config

        errors = config_source_errors(include_tenant=False)
        root = load_global_config()
    except Exception as exc:
        raise EUConformityConfigError(
            "EU conformity configuration is unavailable"
        ) from exc
    if errors or not isinstance(root, Mapping):
        raise EUConformityConfigError("EU conformity configuration is unreadable")
    raw = root.get("eu_conformity") or {}
    if not isinstance(raw, Mapping):
        raise EUConformityConfigError("eu_conformity must be a table")
    unknown = sorted(set(raw) - {"enable"})
    if unknown:
        raise EUConformityConfigError(
            f"unknown eu_conformity keys: {', '.join(unknown)}"
        )
    flag = raw.get("enable", False)
    if not isinstance(flag, bool):
        raise EUConformityConfigError("eu_conformity.enable must be a boolean")
    return {"enable": flag}


def enabled() -> bool:
    try:
        return get_eu_conformity_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise EUConformityConfigError(
            "EU conformity workflows require [eu_conformity] enable = true"
        )


# --------------------------------------------------------------------------
# FRIA (Art. 27)
# --------------------------------------------------------------------------
def _fria_id(asset_id: str, context: str) -> str:
    return f"ECF-{_sha256([asset_id, context])[:24]}"


def open_fria(asset_id: str, *, context: str, actor: str) -> dict[str, Any]:
    """Open (or return) the FRIA record for one asset in one use context."""

    _require_enabled()
    asset = _text(asset_id, "asset_id", 64)
    context_key = _token(context, "context")
    operator = _text(actor, "actor", 256)
    record_id = _fria_id(asset, context_key)
    current = _FRIA.get(record_id)
    if current is not None:
        return dict(current)
    record = {
        "id": record_id,
        "schema": FRIA_SCHEMA,
        "asset_id": asset,
        "context": context_key,
        "status": "draft",
        "elements": dict.fromkeys(FRIA_ELEMENTS),
        "assessor": None,
        "completed_at": None,
        "notification": None,
        "opened_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_FRIA.create(record, action="open_fria", actor=operator))


def assert_fria_element(
    record_id: str,
    element: str,
    *,
    content: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """One named human asserts one Art. 27(1) element."""

    _require_enabled()
    if element not in FRIA_ELEMENTS:
        raise ValueError(
            f"element must be one of: {', '.join(sorted(FRIA_ELEMENTS))}"
        )
    operator = _text(actor, "actor", 256)
    body = _text(content, "content", 8000)

    def mutate(value: dict[str, Any]) -> None:
        if value.get("status") not in {"draft", "outdated"}:
            raise EUConformityError(
                "a completed FRIA must be marked outdated before it changes"
            )
        elements = dict(value.get("elements") or {})
        elements[element] = {
            "content": body,
            "citation": FRIA_ELEMENTS[element]["citation"],
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["elements"] = elements

    saved = _FRIA.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assert_fria_element",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    return dict(saved)


def complete_fria(
    record_id: str, *, assessor: str, expected_revision: int,
) -> dict[str, Any]:
    """Completion requires every Art. 27(1) element and a named assessor."""

    _require_enabled()
    operator = _text(assessor, "assessor", 256)

    def mutate(value: dict[str, Any]) -> None:
        if value.get("status") not in {"draft", "outdated"}:
            raise EUConformityError("only a draft or outdated FRIA can complete")
        elements = value.get("elements") or {}
        missing = sorted(
            key for key in FRIA_ELEMENTS if not isinstance(elements.get(key), Mapping)
        )
        if missing:
            raise EUConformityError(
                f"FRIA elements are not asserted: {', '.join(missing)}"
            )
        value["status"] = "completed"
        value["assessor"] = operator
        value["completed_at"] = time.time()

    saved = _FRIA.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="complete_fria",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    return dict(saved)


def mark_fria_outdated(
    record_id: str, *, reason: str, actor: str, expected_revision: int,
) -> dict[str, Any]:
    """Art. 27(2): a changed or outdated element reopens the assessment."""

    _require_enabled()
    operator = _text(actor, "actor", 256)
    rationale = _text(reason, "reason", 2000)

    def mutate(value: dict[str, Any]) -> None:
        if value.get("status") != "completed":
            raise EUConformityError("only a completed FRIA can become outdated")
        value["status"] = "outdated"
        value["outdated"] = {
            "reason": rationale,
            "marked_by": operator,
            "marked_at": time.time(),
        }

    saved = _FRIA.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="mark_fria_outdated",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    return dict(saved)


def record_fria_notification(
    record_id: str,
    *,
    authority: str,
    submitted_by: str,
    submitted_at: float,
    reference: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Art. 27(3): a human filed the results template; nothing is transmitted."""

    _require_enabled()
    operator = _text(submitted_by, "submitted_by", 256)
    target = _text(authority, "authority", 512)
    filing = _text(reference, "reference", 512)
    if isinstance(submitted_at, bool) or not isinstance(submitted_at, (int, float)):
        raise ValueError("submitted_at must be a Unix timestamp")

    def mutate(value: dict[str, Any]) -> None:
        if value.get("status") != "completed":
            raise EUConformityError(
                "the Art. 27(3) notification follows a completed assessment"
            )
        value["notification"] = {
            "citation": "Art. 27(3)",
            "authority": target,
            "submitted_by": operator,
            "submitted_at": float(submitted_at),
            "reference": filing,
        }

    saved = _FRIA.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="record_fria_notification",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    return dict(saved)


def render_fria(record_id: str) -> str:
    """A bounded markdown draft of the assessment, citations included."""

    _require_enabled()
    record = _FRIA.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    lines = [
        "# Fundamental rights impact assessment (Art. 27)",
        "",
        f"Asset: {record.get('asset_id')}  |  Context: {record.get('context')}",
        f"Status: {record.get('status')}  |  Assessor: {record.get('assessor') or 'unassigned'}",
        f"Basis: {REGULATION_METADATA['regulation']} "
        f"(consolidated {REGULATION_METADATA['consolidated']})",
        "",
    ]
    elements = record.get("elements") or {}
    for key, meta in FRIA_ELEMENTS.items():
        entry = elements.get(key)
        lines.append(f"## {meta['citation']} — {meta['prompt']}")
        if isinstance(entry, Mapping):
            lines.append(str(entry.get("content")))
            lines.append(f"*Asserted by {entry.get('asserted_by')}.*")
        else:
            lines.append("*Not yet asserted.*")
        lines.append("")
    notification = record.get("notification")
    if isinstance(notification, Mapping):
        lines.append(
            f"Notified to {notification.get('authority')} "
            f"(reference {notification.get('reference')}, Art. 27(3))."
        )
    lines.append("")
    lines.append(NON_CERTIFICATION_NOTICE)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Annex IV checklist (Art. 11(1))
# --------------------------------------------------------------------------
def _annex_id(asset_id: str) -> str:
    return f"ECD-{_sha256(asset_id)[:24]}"


def open_annex_iv(asset_id: str, *, actor: str) -> dict[str, Any]:
    _require_enabled()
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    record_id = _annex_id(asset)
    current = _ANNEX_IV.get(record_id)
    if current is not None:
        return dict(current)
    record = {
        "id": record_id,
        "schema": ANNEX_IV_SCHEMA,
        "asset_id": asset,
        "items": dict.fromkeys(ANNEX_IV_ITEMS),
        "opened_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_ANNEX_IV.create(record, action="open_annex_iv", actor=operator))


def assert_annex_iv_item(
    record_id: str,
    item: str,
    *,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """A named human asserts where one Annex IV item's documentation lives."""

    _require_enabled()
    if item not in ANNEX_IV_ITEMS:
        raise ValueError(f"item must be one of: {', '.join(sorted(ANNEX_IV_ITEMS))}")
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        items = dict(value.get("items") or {})
        items[item] = {
            "citation": ANNEX_IV_ITEMS[item][0],
            "reference": where,
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["items"] = items

    saved = _ANNEX_IV.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assert_annex_iv_item",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"Annex IV checklist is not recorded: {record_id}")
    return dict(saved)


def get_annex_iv(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _ANNEX_IV.get(_annex_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def annex_iv_status(record_id: str) -> dict[str, Any]:
    _require_enabled()
    record = _ANNEX_IV.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"Annex IV checklist is not recorded: {record_id}")
    items = record.get("items") or {}
    missing = sorted(
        key for key in ANNEX_IV_ITEMS if not isinstance(items.get(key), Mapping)
    )
    return {
        "id": record.get("id"),
        "asset_id": record.get("asset_id"),
        "asserted": len(ANNEX_IV_ITEMS) - len(missing),
        "total": len(ANNEX_IV_ITEMS),
        "missing": missing,
        "complete": not missing,
        "revision": record.get("revision"),
    }


def render_annex_iv(record_id: str) -> str:
    """A bounded skeleton naming every Annex IV item and its assertion."""

    _require_enabled()
    record = _ANNEX_IV.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"Annex IV checklist is not recorded: {record_id}")
    lines = [
        "# Technical documentation checklist (Art. 11(1), Annex IV)",
        "",
        f"Asset: {record.get('asset_id')}",
        f"Basis: {REGULATION_METADATA['regulation']} "
        f"(consolidated {REGULATION_METADATA['consolidated']})",
        "",
    ]
    items = record.get("items") or {}
    for key, (citation, heading) in ANNEX_IV_ITEMS.items():
        entry = items.get(key)
        lines.append(f"## {citation} — {heading}")
        if isinstance(entry, Mapping):
            lines.append(
                f"Documented at: {entry.get('reference')} "
                f"(asserted by {entry.get('asserted_by')})"
            )
        else:
            lines.append("*Not yet asserted.*")
        lines.append("")
    lines.append(NON_CERTIFICATION_NOTICE)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Art. 43 conformity-assessment route
# --------------------------------------------------------------------------
def _route_id(asset_id: str) -> str:
    return f"ECA-{_sha256(asset_id)[:24]}"


def record_assessment_route(
    asset_id: str,
    *,
    route: str,
    annex_iii_point: int | None,
    harmonised_standards_applied: bool,
    common_specifications_applied: bool,
    rationale: str,
    actor: str,
) -> dict[str, Any]:
    """Record the human route decision, refusing combinations Art. 43 forbids."""

    _require_enabled()
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    reason = _text(rationale, "rationale", 2000)
    if route not in ROUTES:
        raise ValueError(f"route must be one of: {', '.join(ROUTES)}")
    if not isinstance(harmonised_standards_applied, bool) or not isinstance(
        common_specifications_applied, bool,
    ):
        raise ValueError("standards flags must be booleans")
    if route == "sectoral_annex_i":
        if annex_iii_point is not None:
            raise ValueError("a sectoral Annex I route carries no Annex III point")
    else:
        if (
            isinstance(annex_iii_point, bool)
            or not isinstance(annex_iii_point, int)
            or not 1 <= annex_iii_point <= 8
        ):
            raise ValueError("annex_iii_point must be an integer between 1 and 8")
        covered = harmonised_standards_applied or common_specifications_applied
        if annex_iii_point == 1:
            if route == "internal_control_annex_vi" and not covered:
                raise EUConformityError(
                    "Art. 43(1): an Annex III point 1 system may use internal "
                    "control (Annex VI) only where harmonised standards "
                    "(Art. 40) or common specifications (Art. 41) were applied; "
                    "otherwise the Annex VII notified-body procedure applies"
                )
        else:
            if route != "internal_control_annex_vi":
                raise EUConformityError(
                    "Art. 43(2): Annex III points 2-8 follow the internal-"
                    "control procedure of Annex VI, without a notified body"
                )
    record_id = _route_id(asset)
    record = {
        "id": record_id,
        "schema": ROUTE_SCHEMA,
        "asset_id": asset,
        "route": route,
        "annex_iii_point": annex_iii_point,
        "harmonised_standards_applied": harmonised_standards_applied,
        "common_specifications_applied": common_specifications_applied,
        "rationale": reason,
        "status": "recorded",
        "decided_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_ROUTES.create(record, action="record_assessment_route", actor=operator))


def mark_substantial_modification(
    asset_id: str, *, reason: str, actor: str, expected_revision: int,
    predetermined: bool = False,
) -> dict[str, Any]:
    """Art. 43(4): a substantial modification requires a new assessment.

    A change pre-determined by the provider and documented in the technical
    documentation is not a substantial modification; passing
    ``predetermined=True`` records the change without reopening the route.
    """

    _require_enabled()
    operator = _text(actor, "actor", 256)
    rationale = _text(reason, "reason", 2000)
    if not isinstance(predetermined, bool):
        raise ValueError("predetermined must be a boolean")

    def mutate(value: dict[str, Any]) -> None:
        changes = list(value.get("modifications") or [])
        changes.append(
            {
                "reason": rationale,
                "predetermined": predetermined,
                "marked_by": operator,
                "marked_at": time.time(),
            }
        )
        value["modifications"] = changes[-50:]
        if not predetermined:
            value["status"] = "reassessment_required"

    saved = _ROUTES.update(
        _route_id(_text(asset_id, "asset_id", 64)),
        mutate,
        expected_revision=int(expected_revision),
        action="mark_substantial_modification",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"assessment route is not recorded for asset: {asset_id}")
    return dict(saved)


def record_fria_review(
    record_id: str,
    *,
    outcome: str,
    reviewer: str,
    expected_revision: int,
    notes: str = "",
) -> dict[str, Any]:
    """Independent second-person review of a completed FRIA (four-eyes).

    The reviewer must not be the assessor; a review never edits the
    assessment — objections are recorded and the Art. 27(2) reopen path
    stays the only way content changes.
    """

    _require_enabled()
    if outcome not in {"concur", "objections"}:
        raise ValueError("outcome must be concur or objections")
    person = _text(reviewer, "reviewer", 256)
    remark = str(notes or "").strip()[:2000]

    def mutate(value: dict[str, Any]) -> None:
        if value.get("status") != "completed":
            raise EUConformityError(
                "independent review applies to a completed FRIA only"
            )
        if str(value.get("assessor") or "").strip().lower() == person.lower():
            raise EUConformityError(
                "independent review requires a reviewer other than the assessor"
            )
        reviews = list(value.get("reviews") or [])
        reviews.append(
            {
                "reviewer": person,
                "outcome": outcome,
                "notes": remark,
                "reviewed_at": time.time(),
            }
        )
        value["reviews"] = reviews[-20:]

    saved = _FRIA.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="record_fria_review",
        actor=person,
    )
    if saved is None:
        raise KeyError(f"FRIA record is not recorded: {record_id}")
    return dict(saved)


def get_assessment_route(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _ROUTES.get(_route_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def list_assessment_routes(*, status: str | None = None) -> list[dict[str, Any]]:
    _require_enabled()
    if status is not None and status not in {"recorded", "reassessment_required"}:
        raise ValueError("status must be recorded or reassessment_required")
    rows = _ROUTES.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: (str(row.get("asset_id") or ""), str(row.get("id") or "")))
    return [
        dict(row) for row in rows
        if status is None or row.get("status") == status
    ]


# --------------------------------------------------------------------------
# GPAI provider obligations (Art. 53 / Art. 55)
# --------------------------------------------------------------------------
def _gpai_id(asset_id: str) -> str:
    return f"ECG-{_sha256(asset_id)[:24]}"


def _gpai_obligation_keys(record: Mapping[str, Any]) -> dict[str, tuple[str, str]]:
    keys = dict(GPAI_OBLIGATIONS)
    if record.get("systemic_risk"):
        keys.update(GPAI_SYSTEMIC_OBLIGATIONS)
    return keys


def open_gpai(
    asset_id: str,
    *,
    systemic_risk: bool,
    open_source_exempt: bool = False,
    actor: str,
) -> dict[str, Any]:
    """Open (or return) the provider-obligation register for one GPAI model.

    A systemic-risk model carries the Art. 55(1) additions and can never use
    the Art. 53(2) open-source exemption; an exempt non-systemic model still
    tracks the copyright policy and the public training-content summary.
    """

    _require_enabled()
    if not isinstance(systemic_risk, bool) or not isinstance(open_source_exempt, bool):
        raise ValueError("systemic_risk and open_source_exempt must be booleans")
    if systemic_risk and open_source_exempt:
        raise EUConformityError(
            "Art. 53(2): the open-source exemption does not apply to a "
            "general-purpose AI model with systemic risk"
        )
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    record_id = _gpai_id(asset)
    current = _GPAI.get(record_id)
    if current is not None:
        return dict(current)
    obligations: dict[str, Any] = dict.fromkeys(GPAI_OBLIGATIONS)
    if systemic_risk:
        obligations.update(dict.fromkeys(GPAI_SYSTEMIC_OBLIGATIONS))
    elif open_source_exempt:
        for key in GPAI_OPEN_SOURCE_EXEMPT:
            obligations[key] = {"exempt": True, "citation": "Art. 53(2)"}
    record = {
        "id": record_id,
        "schema": GPAI_SCHEMA,
        "asset_id": asset,
        "systemic_risk": systemic_risk,
        "open_source_exempt": open_source_exempt,
        "obligations": obligations,
        "opened_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_GPAI.create(record, action="open_gpai", actor=operator))


def assert_gpai_obligation(
    record_id: str,
    obligation: str,
    *,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """A named human asserts where one obligation's evidence lives."""

    _require_enabled()
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        keys = _gpai_obligation_keys(value)
        if obligation not in keys:
            raise ValueError(
                f"obligation must be one of: {', '.join(sorted(keys))}"
            )
        obligations = dict(value.get("obligations") or {})
        obligations[obligation] = {
            "citation": keys[obligation][0],
            "reference": where,
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["obligations"] = obligations

    saved = _GPAI.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assert_gpai_obligation",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"GPAI register is not recorded: {record_id}")
    return dict(saved)


def gpai_status(record_id: str) -> dict[str, Any]:
    _require_enabled()
    record = _GPAI.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"GPAI register is not recorded: {record_id}")
    return gpai_status_from_record(record)


def gpai_status_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """The obligation posture of one already-loaded GPAI register row.

    Pure projection — list consumers call this with the rows they already
    hold instead of re-reading each record from the store."""

    keys = _gpai_obligation_keys(record)
    obligations = record.get("obligations") or {}
    missing = sorted(
        key
        for key in keys
        if not isinstance(obligations.get(key), Mapping)
    )
    exempt = sorted(
        key
        for key, value in obligations.items()
        if isinstance(value, Mapping) and value.get("exempt") is True
    )
    return {
        "id": record.get("id"),
        "asset_id": record.get("asset_id"),
        "systemic_risk": bool(record.get("systemic_risk")),
        "asserted": len(keys) - len(missing),
        "total": len(keys),
        "missing": missing,
        "exempt": exempt,
        "complete": not missing,
        "revision": record.get("revision"),
    }


def get_gpai(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _GPAI.get(_gpai_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def list_gpai_registers() -> list[dict[str, Any]]:
    _require_enabled()
    rows = _GPAI.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: str(row.get("asset_id") or ""))
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Art. 26 deployer obligations register
# --------------------------------------------------------------------------
def _deployer_id(asset_id: str) -> str:
    return f"ECY-{_sha256(asset_id)[:24]}"


def _deployer_obligation_keys(record: Mapping[str, Any]) -> dict[str, Any]:
    keys: dict[str, Any] = dict(DEPLOYER_OBLIGATIONS)
    keys[DEPLOYER_OVERSIGHT_KEY] = (
        DEPLOYER_OVERSIGHT_CITATION,
        "Human oversight is assigned to named natural persons with the "
        "necessary competence, training, authority, and support.",
    )
    flags = record.get("flags") or {}
    for key, (citation, text, flag) in DEPLOYER_CONDITIONAL_OBLIGATIONS.items():
        if flags.get(flag) is True:
            keys[key] = (citation, text)
    return keys


def open_deployer_register(
    asset_id: str,
    *,
    workplace_use: bool = False,
    public_authority: bool = False,
    controls_input_data: bool = False,
    requires_dpia: bool = False,
    actor: str,
) -> dict[str, Any]:
    """Open (or return) the Art. 26 deployer-obligations register for one
    high-risk system.

    The always-applicable duties (26(1), (2), (5), (6), (11), (12)) are
    tracked for every deployment; the conditional duties join only when the
    matching flag is set — input-data control (26(4)), workplace use
    (26(7)), public-authority registration (26(8)), and the DPIA
    information duty (26(9)). The Art. 26(10) law-enforcement biometric
    regime is out of this register's scope and stated so. A record of the
    deployer's own compliance work — never legal advice.
    """

    _require_enabled()
    for name, value in (
        ("workplace_use", workplace_use),
        ("public_authority", public_authority),
        ("controls_input_data", controls_input_data),
        ("requires_dpia", requires_dpia),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean")
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    record_id = _deployer_id(asset)
    current = _DEPLOYER.get(record_id)
    if current is not None:
        return dict(current)
    flags = {
        "workplace_use": workplace_use,
        "public_authority": public_authority,
        "controls_input_data": controls_input_data,
        "requires_dpia": requires_dpia,
    }
    obligations: dict[str, Any] = dict.fromkeys(DEPLOYER_OBLIGATIONS)
    obligations[DEPLOYER_OVERSIGHT_KEY] = None
    for key, (_citation, _unused, flag) in DEPLOYER_CONDITIONAL_OBLIGATIONS.items():
        if flags[flag]:
            obligations[key] = None
    record = {
        "id": record_id,
        "schema": DEPLOYER_SCHEMA,
        "asset_id": asset,
        "flags": flags,
        "obligations": obligations,
        "opened_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(
        _DEPLOYER.create(record, action="open_deployer_register", actor=operator)
    )


def assert_deployer_obligation(
    record_id: str,
    obligation: str,
    *,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """A named human asserts where one Art. 26 duty's evidence lives.

    The Art. 26(2) oversight duty is deliberately NOT assertable here — it
    must name natural persons, via :func:`assign_deployer_oversight`.
    """

    _require_enabled()
    if obligation == DEPLOYER_OVERSIGHT_KEY:
        raise EUConformityError(
            "Art. 26(2) human oversight must name natural persons — use "
            "assign_deployer_oversight"
        )
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        keys = _deployer_obligation_keys(value)
        keys.pop(DEPLOYER_OVERSIGHT_KEY, None)
        if obligation not in keys:
            raise ValueError(
                f"obligation must be one of: {', '.join(sorted(keys))}"
            )
        obligations = dict(value.get("obligations") or {})
        obligations[obligation] = {
            "citation": keys[obligation][0],
            "reference": where,
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["obligations"] = obligations

    saved = _DEPLOYER.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assert_deployer_obligation",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"deployer register is not recorded: {record_id}")
    return dict(saved)


def assign_deployer_oversight(
    record_id: str,
    *,
    persons: list[str],
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Assign Art. 26(2) human oversight to named natural persons.

    At least one named person; the reference records where their
    competence, training, authority, and support are evidenced.
    """

    _require_enabled()
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)
    named = [
        _text(person, "person", 256)
        for person in list(persons or [])[:_MAX_OVERSIGHT_PERSONS]
    ]
    if not named:
        raise ValueError(
            "Art. 26(2) oversight needs at least one named natural person"
        )
    if len(set(name.lower() for name in named)) != len(named):
        raise ValueError("oversight persons must be distinct")

    def mutate(value: dict[str, Any]) -> None:
        obligations = dict(value.get("obligations") or {})
        obligations[DEPLOYER_OVERSIGHT_KEY] = {
            "citation": DEPLOYER_OVERSIGHT_CITATION,
            "persons": named,
            "reference": where,
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["obligations"] = obligations

    saved = _DEPLOYER.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assign_deployer_oversight",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"deployer register is not recorded: {record_id}")
    return dict(saved)


def deployer_status(record_id: str) -> dict[str, Any]:
    _require_enabled()
    record = _DEPLOYER.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"deployer register is not recorded: {record_id}")
    return deployer_status_from_record(record)


def deployer_status_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """The obligation posture of one already-loaded deployer register row.

    Pure projection — list consumers call this with the rows they already
    hold instead of re-reading each record from the store."""

    keys = _deployer_obligation_keys(record)
    obligations = record.get("obligations") or {}
    missing = sorted(
        key for key in keys if not isinstance(obligations.get(key), Mapping)
    )
    oversight = obligations.get(DEPLOYER_OVERSIGHT_KEY)
    persons = (
        list(oversight.get("persons") or [])
        if isinstance(oversight, Mapping)
        else []
    )
    return {
        "id": record.get("id"),
        "asset_id": record.get("asset_id"),
        "flags": dict(record.get("flags") or {}),
        "asserted": len(keys) - len(missing),
        "total": len(keys),
        "missing": missing,
        "oversight_persons": persons,
        "complete": not missing,
        "revision": record.get("revision"),
    }


def list_deployer_registers() -> list[dict[str, Any]]:
    _require_enabled()
    rows = _DEPLOYER.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: str(row.get("asset_id") or ""))
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Art. 72 post-market monitoring plan
# --------------------------------------------------------------------------
def _pmm_id(asset_id: str) -> str:
    return f"ECP-{_sha256(asset_id)[:24]}"


def record_pmm_plan(
    asset_id: str, *, plan_reference: str, actor: str,
) -> dict[str, Any]:
    """Record that a documented Art. 72 post-market monitoring plan exists.

    The register records WHERE the plan lives; it never authors the plan.
    """

    _require_enabled()
    asset = _text(asset_id, "asset_id", 64)
    where = _text(plan_reference, "plan_reference", 512)
    operator = _text(actor, "actor", 256)
    record = {
        "id": _pmm_id(asset),
        "schema": PMM_SCHEMA,
        "asset_id": asset,
        "plan_reference": where,
        "reviews": [],
        "established_by": operator,
        "established_at": time.time(),
        "citation": "Art. 72(1)",
        "template_note": (
            "The plan shall be based on the Commission's post-market "
            "monitoring plan template (Art. 72(3), implementing act due "
            "2026-02-02)."
        ),
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_PMM.create(record, action="record_pmm_plan", actor=operator))


def record_pmm_review(
    asset_id: str,
    *,
    outcome: str,
    actor: str,
    expected_revision: int,
    plan_reference: str | None = None,
) -> dict[str, Any]:
    """Append one monitoring-plan review; ``plan_updated`` may move the plan."""

    _require_enabled()
    if outcome not in {"no_change", "plan_updated"}:
        raise ValueError("outcome must be no_change or plan_updated")
    operator = _text(actor, "actor", 256)
    moved = (
        None if plan_reference is None
        else _text(plan_reference, "plan_reference", 512)
    )
    if outcome == "no_change" and moved is not None:
        raise ValueError("a no_change review cannot move the plan reference")

    def mutate(value: dict[str, Any]) -> None:
        reviews = list(value.get("reviews") or [])
        reviews.append(
            {
                "outcome": outcome,
                "reviewed_by": operator,
                "reviewed_at": time.time(),
            }
        )
        value["reviews"] = reviews[-50:]
        if moved is not None:
            value["plan_reference"] = moved

    saved = _PMM.update(
        _pmm_id(_text(asset_id, "asset_id", 64)),
        mutate,
        expected_revision=int(expected_revision),
        action="record_pmm_review",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"monitoring plan is not recorded for asset: {asset_id}")
    return dict(saved)


def get_pmm_plan(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _PMM.get(_pmm_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def list_pmm_plans() -> list[dict[str, Any]]:
    _require_enabled()
    rows = _PMM.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: str(row.get("asset_id") or ""))
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Art. 49 registration
# --------------------------------------------------------------------------
def _registration_id(asset_id: str) -> str:
    return f"ECR-{_sha256(asset_id)[:24]}"


def record_registration(
    asset_id: str,
    *,
    basis: str,
    registry: str,
    reference: str,
    actor: str,
) -> dict[str, Any]:
    """Record a completed Art. 49 registration, refusing the wrong registry."""

    _require_enabled()
    if basis not in REGISTRATION_BASES:
        raise ValueError(
            f"basis must be one of: {', '.join(sorted(REGISTRATION_BASES))}"
        )
    if registry not in REGISTRIES:
        raise ValueError(f"registry must be one of: {', '.join(REGISTRIES)}")
    citation, expected_registry = REGISTRATION_BASES[basis]
    if registry != expected_registry:
        raise EUConformityError(
            f"{citation}: a {basis} registration belongs in the "
            f"{expected_registry} registry"
        )
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    record = {
        "id": _registration_id(asset),
        "schema": REGISTRATION_SCHEMA,
        "asset_id": asset,
        "basis": basis,
        "citation": citation,
        "registry": registry,
        "reference": _text(reference, "reference", 512),
        "registered_by": operator,
        "recorded_at": time.time(),
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(
        _REGISTRATIONS.create(record, action="record_registration", actor=operator)
    )


def get_registration(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _REGISTRATIONS.get(_registration_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def list_registrations() -> list[dict[str, Any]]:
    _require_enabled()
    rows = _REGISTRATIONS.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: str(row.get("asset_id") or ""))
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Art. 13(3) instructions-for-use checklist
# --------------------------------------------------------------------------
def _ifu_id(asset_id: str) -> str:
    return f"ECI-{_sha256(asset_id)[:24]}"


def open_ifu(asset_id: str, *, actor: str) -> dict[str, Any]:
    _require_enabled()
    asset = _text(asset_id, "asset_id", 64)
    operator = _text(actor, "actor", 256)
    record_id = _ifu_id(asset)
    current = _IFU.get(record_id)
    if current is not None:
        return dict(current)
    record = {
        "id": record_id,
        "schema": IFU_SCHEMA,
        "asset_id": asset,
        "items": dict.fromkeys(IFU_ITEMS),
        "opened_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return dict(_IFU.create(record, action="open_ifu", actor=operator))


def assert_ifu_item(
    record_id: str,
    item: str,
    *,
    reference: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """A named human asserts where one Art. 13(3) item is documented."""

    _require_enabled()
    if item not in IFU_ITEMS:
        raise ValueError(f"item must be one of: {', '.join(sorted(IFU_ITEMS))}")
    operator = _text(actor, "actor", 256)
    where = _text(reference, "reference", 512)

    def mutate(value: dict[str, Any]) -> None:
        items = dict(value.get("items") or {})
        items[item] = {
            "citation": IFU_ITEMS[item][0],
            "reference": where,
            "asserted_by": operator,
            "asserted_at": time.time(),
        }
        value["items"] = items

    saved = _IFU.update(
        _text(record_id, "record_id", 64),
        mutate,
        expected_revision=int(expected_revision),
        action="assert_ifu_item",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"instructions-for-use checklist is not recorded: {record_id}")
    return dict(saved)


def ifu_status(record_id: str) -> dict[str, Any]:
    _require_enabled()
    record = _IFU.get(_text(record_id, "record_id", 64))
    if record is None:
        raise KeyError(f"instructions-for-use checklist is not recorded: {record_id}")
    items = record.get("items") or {}
    missing = sorted(
        key for key in IFU_ITEMS if not isinstance(items.get(key), Mapping)
    )
    return {
        "id": record.get("id"),
        "asset_id": record.get("asset_id"),
        "asserted": len(IFU_ITEMS) - len(missing),
        "total": len(IFU_ITEMS),
        "missing": missing,
        "complete": not missing,
        "revision": record.get("revision"),
    }


def get_ifu(asset_id: str) -> dict[str, Any] | None:
    _require_enabled()
    record = _IFU.get(_ifu_id(_text(asset_id, "asset_id", 64)))
    return None if record is None else dict(record)


def list_ifu_checklists() -> list[dict[str, Any]]:
    _require_enabled()
    rows = _IFU.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: str(row.get("asset_id") or ""))
    return [dict(row) for row in rows]


def list_frias(*, status: str | None = None) -> list[dict[str, Any]]:
    _require_enabled()
    if status is not None and status not in {"draft", "completed", "outdated"}:
        raise ValueError("status must be draft, completed, or outdated")
    rows = _FRIA.list(limit=_MAX_LIST)
    rows.sort(key=lambda row: (str(row.get("asset_id") or ""), str(row.get("id") or "")))
    return [
        dict(row) for row in rows
        if status is None or row.get("status") == status
    ]


__all__ = [
    "ANNEX_IV_ITEMS",
    "DEPLOYER_CONDITIONAL_OBLIGATIONS",
    "DEPLOYER_OBLIGATIONS",
    "DEPLOYER_OVERSIGHT_KEY",
    "EUConformityConfigError",
    "EUConformityError",
    "FRIA_ELEMENTS",
    "GPAI_OBLIGATIONS",
    "GPAI_OPEN_SOURCE_EXEMPT",
    "GPAI_SYSTEMIC_OBLIGATIONS",
    "IFU_ITEMS",
    "NON_CERTIFICATION_NOTICE",
    "REGISTRATION_BASES",
    "REGISTRIES",
    "REGULATION_METADATA",
    "ROUTES",
    "annex_iv_status",
    "assert_annex_iv_item",
    "assert_deployer_obligation",
    "assert_fria_element",
    "assert_gpai_obligation",
    "assert_ifu_item",
    "assign_deployer_oversight",
    "complete_fria",
    "deployer_status",
    "deployer_status_from_record",
    "enabled",
    "get_annex_iv",
    "get_assessment_route",
    "get_eu_conformity_config",
    "get_gpai",
    "get_ifu",
    "get_pmm_plan",
    "get_registration",
    "gpai_status",
    "gpai_status_from_record",
    "ifu_status",
    "list_assessment_routes",
    "list_deployer_registers",
    "list_frias",
    "list_gpai_registers",
    "list_ifu_checklists",
    "list_pmm_plans",
    "list_registrations",
    "mark_fria_outdated",
    "mark_substantial_modification",
    "open_annex_iv",
    "open_deployer_register",
    "open_fria",
    "open_gpai",
    "open_ifu",
    "record_assessment_route",
    "record_fria_notification",
    "record_fria_review",
    "record_pmm_plan",
    "record_pmm_review",
    "record_registration",
    "render_annex_iv",
    "render_fria",
]
