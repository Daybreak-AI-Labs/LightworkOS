"""Read-only choice lists for the /security/assurance page.

The page lets people pick existing records instead of typing identifiers,
version numbers, or fingerprints.  Every route here only reads; the write
routes the page calls keep their own permission, workspace, and freshness
checks unchanged.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from . import product_operations_policy_exceptions as policy_exceptions
from .auth import require_global_permission, require_permission
from .model_risk_api import (
    _call,
    _configured_conformity_workflow,
    _configured_media_provenance,
    _human_principal,
    _identity_control_runtime,
    _identity_governance_section,
    _module,
    _require_active_tenant,
)

router = APIRouter(prefix="/assurance/pickers", tags=["model-risk-assurance"])

_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})


@router.get("/policy-exceptions")
async def policy_exception_choices(request: Request) -> dict[str, Any]:
    return await run_in_threadpool(policy_exceptions.catalog, request)


@router.post("/policy-exceptions/original")
async def policy_exception_original(
    request: Request, body: policy_exceptions.OriginalInput,
) -> dict[str, Any]:
    return await run_in_threadpool(policy_exceptions.original, request, body)


def _record_digest(record: Mapping[str, Any]) -> str:
    """Fingerprint one stored record's content, excluding store bookkeeping."""

    content = {
        str(key): value
        for key, value in record.items()
        if str(key) not in _STORE_METADATA
    }
    encoded = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _revision(record: Mapping[str, Any]) -> int:
    value = record.get("revision")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HTTPException(status_code=503, detail="an assurance record is malformed")
    return value


@router.get("/package-forms")
async def package_form_definitions(request: Request) -> dict[str, Any]:
    """Field lists the guided evidence-package forms are built from."""

    require_permission(request, "operate")
    from maverick import (
        ai_bank_mrm,
        ai_conformity_workflow,
        ai_insurability,
        ai_regulated_verticals,
    )

    bank_sections = [
        {
            "key": section,
            "fields": [
                {
                    "key": field,
                    "kind": kind,
                    "choices": sorted(allowed) if allowed is not None else None,
                }
                for field, (kind, allowed) in specs.items()
            ],
        }
        for section, specs in ai_bank_mrm._FIELD_SPECS.items()
    ]
    return {
        "insurability": {
            "measurement_schema": ai_insurability.MEASUREMENT_SCHEMA,
            "measurements": list(ai_insurability._MEASUREMENT_NAMES),
            "measurement_states": sorted(ai_insurability._MEASUREMENT_STATES),
            "measurement_units": sorted(ai_insurability._MEASUREMENT_UNITS),
            "framework_postures": sorted(ai_insurability._FRAMEWORK_POSTURES),
            "safeguard_states": sorted(ai_insurability._SAFEGUARD_STATES),
            "severities": sorted(ai_insurability._SEVERITIES),
        },
        "regulated": {
            "nyc_checks": list(ai_regulated_verticals.NYC_LL144_CHECKS),
            "naic_checks": list(ai_regulated_verticals.NAIC_CHECKS),
        },
        "bank_mrm": {
            "section_schema": ai_bank_mrm.SECTION_SCHEMA,
            "sections": bank_sections,
        },
        "conformity": {
            "checklist_sections": {
                domain: list(sections)
                for domain, sections in ai_conformity_workflow.CHECKLIST_SECTIONS.items()
            },
        },
    }


@router.get("/conformity-evidence")
async def conformity_case_evidence(
    request: Request,
    case_id: str = Query(..., min_length=1, max_length=36),
) -> dict[str, Any]:
    """Evidence already added to one readiness case, for the checklist form."""

    require_permission(request, "view")
    _require_active_tenant()
    _conformity, service = await _configured_conformity_workflow()
    items = await _call(service.list_case_evidence, case_id)
    return {
        "case_id": case_id,
        "evidence": [
            {
                "binding_id": item["binding_id"],
                "evidence_type": item["evidence_type"],
                "source_ref": item["source_ref"],
            }
            for item in items
        ],
    }


_AI_ACT = "EU AI Act"
_GDPR = "GDPR"
_MAX_PROVISIONS = 500
_REGISTRIES = {"eu_database": "in the EU database", "national": "at national level"}


def _provision_order(row: Mapping[str, Any]) -> tuple:
    regulation = 0 if row["regulation"] == _AI_ACT else 1
    text = str(row["provision"])
    parts = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.lower())
        for part in re.findall(r"\d+|[^\d]+", text)
    )
    return (regulation, 0 if text.startswith("Art") else 1, parts)


@lru_cache(maxsize=1)
def _provision_catalog() -> tuple[dict[str, str], ...]:
    """Provisions the kernel's regulatory catalogs already cite.

    Only entries the readiness workflow itself accepts as an official citation
    are offered, so choosing one can never be refused for its wording.
    """

    from maverick import (
        ai_act,
        ai_conformity_workflow,
        ai_literacy,
        controls,
        eu_conformity,
        regulatory_compiler,
    )

    ai_act_url = ai_conformity_workflow.CONSOLIDATED_REGULATION_URL
    gdpr_url = next(item.source_url for item in regulatory_compiler.REGULATIONS["gdpr"])
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def add(regulation: str, provision: str, title: str, url: str) -> None:
        entry = rows.setdefault(
            (regulation, provision),
            {"regulation": regulation, "provision": provision, "official_url": url, "titles": []},
        )
        text = " ".join(str(title or "").split())
        if text and text not in entry["titles"]:
            entry["titles"].append(text)

    literacy = ai_literacy.REGULATION_METADATA
    add(_AI_ACT, literacy["article"], literacy["obligation"], ai_act_url)
    # The self-assessment lists follow the Regulation's own order: Art. 5(1)
    # points (a)-(h) and Annex III points 1-8.
    for index, text in enumerate(ai_act._PROHIBITED):
        add(_AI_ACT, f"Art. 5(1)({chr(ord('a') + index)})", f"Prohibited practice: {text}", ai_act_url)
    for index, text in enumerate(ai_act._HIGH_RISK, start=1):
        add(_AI_ACT, f"Annex III point {index}", f"High-risk area: {text}", ai_act_url)
    for element in eu_conformity.FRIA_ELEMENTS.values():
        add(_AI_ACT, element["citation"], element["prompt"], ai_act_url)
    for table in (
        eu_conformity.ANNEX_IV_ITEMS,
        eu_conformity.IFU_ITEMS,
        eu_conformity.GPAI_OBLIGATIONS,
        eu_conformity.GPAI_SYSTEMIC_OBLIGATIONS,
        eu_conformity.DEPLOYER_OBLIGATIONS,
    ):
        for citation, text in table.values():
            add(_AI_ACT, citation, text, ai_act_url)
    for citation, text, _flag in eu_conformity.DEPLOYER_CONDITIONAL_OBLIGATIONS.values():
        add(_AI_ACT, citation, text, ai_act_url)
    add(
        _AI_ACT,
        eu_conformity.DEPLOYER_OVERSIGHT_CITATION,
        eu_conformity.DEPLOYER_OVERSIGHT_KEY.replace("_", " ").capitalize(),
        ai_act_url,
    )
    for basis, (citation, registry) in eu_conformity.REGISTRATION_BASES.items():
        where = _REGISTRIES.get(registry, "")
        basis_words = basis.replace("_", " ").replace("annex iii", "Annex III")
        add(_AI_ACT, citation, f"Registration {where}: {basis_words}", ai_act_url)
    for obligation in regulatory_compiler.REGULATIONS["eu_ai_act"]:
        add(_AI_ACT, obligation.article, obligation.title, ai_act_url)
    for obligation in regulatory_compiler.REGULATIONS["gdpr"]:
        add(_GDPR, obligation.article, obligation.title, obligation.source_url)
    for control in controls.CONTROLS:
        for framework, reference in control.frameworks.items():
            if framework == _AI_ACT:
                add(_AI_ACT, reference, control.title, ai_act_url)
            elif framework == _GDPR:
                add(_GDPR, reference, control.title, gdpr_url)

    accepted = []
    for entry in rows.values():
        try:
            ai_conformity_workflow._citation(
                ai_conformity_workflow.LegalCitation(entry["provision"], entry["official_url"])
            )
        except (TypeError, ValueError):
            continue
        accepted.append(
            {
                "regulation": entry["regulation"],
                "provision": entry["provision"],
                "title": "; ".join(entry["titles"])[:400],
                "official_url": entry["official_url"],
            }
        )
    return tuple(sorted(accepted, key=_provision_order)[:_MAX_PROVISIONS])


@router.get("/legal-provisions")
async def legal_provisions(request: Request) -> dict[str, Any]:
    """Provisions to cite on the launch-readiness forms, from the kernel's catalogs."""

    require_permission(request, "operate")
    from maverick import ai_conformity_workflow

    provisions = [dict(row) for row in _provision_catalog()]
    return {
        "provisions": provisions,
        "count": len(provisions),
        "default_official_url": ai_conformity_workflow.CONSOLIDATED_REGULATION_URL,
    }


@router.get("/media-release-references")
async def media_release_references(request: Request) -> dict[str, Any]:
    """Release references this workspace's media checks already used."""

    require_permission(request, "view")
    _require_active_tenant()
    _provenance, service = await _configured_media_provenance()
    rows = await _call(service.release_references, limit=200)
    return {"references": rows, "count": len(rows)}


def _grc_source_choices(officer: Any, kind: str) -> list[dict[str, Any]]:
    if kind == "ai_incident":
        records = [(record, record.get("summary") or "AI incident") for record in officer.list_incidents()]
    else:
        records = []
        for finding in officer.findings():
            record = finding if kind == "finding" else officer.current_risk_acceptance(finding)
            if record is not None:
                records.append((record, finding.get("summary") or "Finding"))
    return [{"label": str(label), "asset_id": record["asset_id"], "severity": record["severity"],
             "source": {"source_kind": kind, "source_id": record["id"]}}
            for record, label in records]


@router.get("/grc-sources")
async def grc_outbound_sources(
    request: Request,
    source_kind: Literal["finding", "risk_acceptance", "ai_incident"] = Query(...),
) -> dict[str, Any]:
    """Records that can be previewed or sent to ServiceNow or Archer."""

    require_permission(request, "operate")
    _require_active_tenant()
    officer = _module("model_risk_assurance", "model_risk_assurance")
    sources = await _call(_grc_source_choices, officer, source_kind)
    return {"source_kind": source_kind, "sources": sources[:500], "count": len(sources)}


_NO_REGISTRY: dict[str, Any] = {
    "available": False,
    "capabilities": [],
    "federation_bindings": [],
    "purview_assets": [],
}


def _registry_choices(request: Request, tenant: str) -> dict[str, Any]:
    factory = getattr(
        request.app.state,
        "identity_governance_authority_registry_factory",
        None,
    )
    if not callable(factory):
        return dict(_NO_REGISTRY)
    try:
        registry = factory(tenant)
        bindings = registry.active_payloads("federation_binding")
        assets = registry.active_payloads("purview_asset_binding")
        rules = registry.active_payloads("capability_rule")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return dict(_NO_REGISTRY)
    capabilities = sorted(
        {
            str(capability)
            for rule in rules
            for capability in (rule.get("capabilities") or ())
        }
    )
    return {
        "available": True,
        "capabilities": capabilities,
        "federation_bindings": [
            {
                "provider": row.get("provider"),
                "principal_ref": row.get("principal_ref"),
                "provider_subject_id": row.get("provider_subject_id"),
                "binding_sha256": row.get("binding_sha256"),
                "authority_revision": row.get("authority_revision"),
            }
            for row in bindings
        ],
        "purview_assets": [
            {
                "asset_id": row.get("asset_id"),
                "binding_sha256": row.get("binding_sha256"),
                "revision": row.get("revision"),
                "classification_codes": list(row.get("classification_codes") or ()),
            }
            for row in assets
        ],
    }


@router.get("/identity-controls")
async def identity_control_choices(request: Request) -> dict[str, Any]:
    """Enrolled agent identities, data assets, and prepared label changes."""

    require_global_permission(request, "admin")
    tenant = _require_active_tenant()
    _human_principal(request)
    result = await _call(_registry_choices, request, tenant)
    intents: list[dict[str, Any]] = []
    intents_available = False
    try:
        section = _identity_governance_section()
        runtime = _identity_control_runtime(request, section, "purview_writeback")
        service = runtime.require_purview_writeback()
        intents = await _call(service.list_intents, limit=100)
        intents_available = True
    except HTTPException:
        intents = []
    result["purview_intents"] = intents
    result["purview_intents_available"] = intents_available
    result["purview_labels"] = _purview_labels(result["purview_assets"], intents)
    result["purview_connected"] = await _call(_purview_connected)
    return result


_LABEL_CODE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_MAX_LABELS = 512


def _purview_labels(*sources: list[Mapping[str, Any]]) -> list[str]:
    """Labels already on enrolled Purview data or in prepared label changes.

    The Purview connector reads the labels on data; it has no call that lists
    a label catalog, so these are the labels this workspace has seen.
    """

    labels = {
        code
        for rows in sources
        for row in rows
        if isinstance(row, Mapping)
        for code in (row.get("classification_codes") or ())
        if isinstance(code, str) and _LABEL_CODE.fullmatch(code)
    }
    return sorted(labels)[:_MAX_LABELS]


def _purview_connected() -> bool:
    from . import identity_governance_runtime

    try:
        section = _identity_governance_section()
        status = identity_governance_runtime.connector_status(section)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
    return "purview" in (status.get("configured_providers") or ())
