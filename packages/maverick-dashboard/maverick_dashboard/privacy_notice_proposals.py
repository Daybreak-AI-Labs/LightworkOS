"""Ordinary proposed notice changes, using native approved sources and receipts."""
from __future__ import annotations

import contextlib
import hmac
import json
import re
import secrets
import time
from contextvars import ContextVar
from dataclasses import asdict
from datetime import date

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import consent_publishing_api as consent
from . import privacy_notice_governance_api as native
from . import privacy_regulatory_intelligence_api as regulatory
from .draft_api import context_for
from .product_operations import StrictInput

PAGE = "/privacy/notice-governance"
PURPOSE = "lightwork.privacy-notice-proposal-review.v1"
TTL = 600
REASONS = {"regulatory_change": "A requirement changed", "content_update": "Notice wording changed", "policy_update": "Our privacy policy changed", "configuration_update": "The website or app changed", "review_findings": "A review identified changes"}
_active_corpus = ContextVar("notice_proposal_authorized_corpus", default=None)


class FileChoice(StrictInput):
    name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0, le=67_108_864)


class Choices(StrictInput):
    notice: str = Field(min_length=3, max_length=140)
    publication: str = Field(pattern=r"^[a-f0-9]{64}$")
    references: list[str] = Field(min_length=1, max_length=64)
    reasons: list[str] = Field(min_length=1, max_length=5)
    retained_until: int = Field(gt=0, lt=100_000_000_000)
    content: FileChoice
    policy: FileChoice
    configuration: FileChoice


def human(value, fallback="Privacy notice"):
    if re.search(r"[a-f0-9]{24,}", str(value), re.IGNORECASE):
        return fallback
    return re.sub(r"[-_:]+", " ", str(value)).strip().capitalize() or fallback


def authority(request, *, write=False):
    auth.require_permission(request, "operate" if write else "view")
    return native.authority(request)


def corpus(tenant):
    active = _active_corpus.get()
    if active is not None and active[0] == tenant:
        return active[1]
    regulatory._ops()
    return regulatory._default_store_for(tenant)


def reference(tenant, identity, store):
    document = store.get_document(tenant, identity)
    source = store.get_source(tenant, document.source_id)
    today = date.today().isoformat()
    if (source.state != "active" or not source.approved_by or source.approved_by == source.enrolled_by
            or "research" not in source.allowed_uses or document.retain_until <= time.time()
            or document.publication_date > today or document.superseded_date and document.superseded_date <= today
            or document.jurisdiction not in source.jurisdictions or document.authority not in source.authorities
            or document.document_type not in source.document_types or document.language not in source.languages):
        raise HTTPException(409, "This reference is no longer available from a currently approved research source. Choose a current reference; your draft is kept.")
    binding = digest({"purpose": "notice-update-reference", "tenant": tenant, "document": asdict(document), "source": asdict(source), "use": "research"})
    return {"value": digest([document.document_id, binding]), "document_ref": document.document_id, "source_ref": source.source_id,
            "evidence_sha256": binding, "label": document.title, "source_name": source.name, "version": document.version,
            "citation_labels": [item.title + " · " + item.pinpoint for item in document.citations], "jurisdiction": document.jurisdiction,
            "source_notice": "Material from a source independently approved for research; applicability is a human decision."}


def reference_allowed(tenant, identity, source, evidence):
    try:
        value = reference(tenant, identity, corpus(tenant))
        return value["source_ref"] == source and hmac.compare_digest(value["evidence_sha256"], evidence)
    except Exception:
        # The native writer refuses unavailable or unverifiable references.
        return False


def publications(tenant, store):
    rows, offset = [], 0
    while True:
        page = store.catalog(tenant, kind="property", offset=offset, limit=50)
        for prop in page["items"]:
            history = store.publication_history(tenant, prop["property_id"], limit=1)["items"]
            if not history or history[0]["action"] == "withdraw":
                continue
            pub = history[0]
            if pub["publication_revision"] != prop["publication_revision"]:
                raise HTTPException(409, "Consent publishing changed while it was being read. Refresh current choices.")
            rows.append({"value": digest([prop, pub]), "label": human(prop["property_id"], "Website or app") + " · release " + str(pub["publication_revision"]),
                         "property_id": prop["property_id"], "publication_id": pub["publication_id"], "binding": digest([prop, pub])})
        offset += len(page["items"])
        if offset >= page["total"]:
            return rows
        if offset >= 1000:
            raise HTTPException(409, "More than 1,000 consent properties need a paged selection. No publication was silently omitted.")


def latest_version(connection, tenant, identity):
    value = connection.execute("SELECT MAX(version) FROM notice_release_definitions WHERE tenant_id=? AND notice_id=?", (tenant, identity)).fetchone()[0]
    return int(value or 0)


def notices(tenant, store):
    rows = store.list_records(tenant, limit=200)["releases"]
    result = []
    with store._connect() as connection:
        for row in rows:
            if row.version != latest_version(connection, tenant, row.notice_id) or row.retained_until <= time.time():
                continue
            result.append({"value": row.notice_id + "/" + str(row.version), "label": human(row.notice_id) + " · version " + str(row.version),
                           "binding": digest(asdict(row)), "item": row})
    return result


def references(tenant, pri):
    result = []
    for document in pri.list_records(tenant)["documents"]:
        try:
            result.append(reference(tenant, document.document_id, pri))
        except HTTPException:
            continue
    return result


def check_read(request, context):
    auth.require_permission(request, "view")
    native._notice()
    if context_for(request) != context:
        raise HTTPException(409, "Your account, access or workspace changed during this read. Private results were not released.")


def catalog(request):
    initial_context = context_for(request)
    _module, tenant, store = authority(request)
    pri = corpus(tenant)
    refs = references(tenant, pri)
    ops = consent._ops()
    pubs = publications(tenant, consent._store(ops, tenant))
    selected = notices(tenant, store)
    check_read(request, initial_context)
    context = initial_context
    revision = digest([context, [{k:v for k,v in row.items() if k != "item"} for row in selected], refs, pubs])
    return {"context": context, "revision": revision,
            "notices": [{"value": row["value"], "label": row["label"]} for row in selected],
            "references": [{key:row[key] for key in ("value", "label", "source_name", "version", "jurisdiction", "source_notice")} for row in refs],
            "publications": [{"value": row["value"], "label": row["label"]} for row in pubs],
            "reasons": REASONS, "notice": "This proposes a recorded change for independent review. It neither writes notice text nor publishes, sends, or certifies anything.",
            "listing_notice": "Up to 200 retained notice versions and 1,000 current regulatory documents are considered. References require an independently approved source with research permission."}


def selection(request, choices, *, pri=None, publishing=None):
    _module, tenant, store = authority(request, write=True)
    parts = choices.notice.rsplit("/", 1)
    if len(parts) != 2 or not re.fullmatch(native._ID_PATTERN, parts[0]) or not parts[1].isdigit():
        raise HTTPException(422, "Choose a named current notice version.")
    base = store.get_release(tenant, parts[0], int(parts[1]))
    with store._connect() as connection:
        if base.version != latest_version(connection, tenant, base.notice_id) or base.retained_until <= time.time():
            raise HTTPException(409, "A newer notice is available or its record expired. Your draft is kept; select the current notice before a new review.")
    pri = pri or corpus(tenant)
    available = {row["value"]: row for row in references(tenant, pri)}
    if len(set(choices.references)) != len(choices.references) or any(value not in available for value in choices.references):
        raise HTTPException(409, "A selected regulatory reference changed. Your draft is kept; choose current references.")
    refs = [available[value] for value in choices.references]
    publishing = publishing or consent._store(consent._ops(), tenant)
    pub = next((row for row in publications(tenant, publishing) if row["value"] == choices.publication), None)
    if pub is None or pub["property_id"] != base.property_id:
        raise HTTPException(409, "Choose the current consent publication for this notice's website or app. Your draft is kept.")
    if len(set(choices.reasons)) != len(choices.reasons) or any(reason not in REASONS for reason in choices.reasons):
        raise HTTPException(422, "Choose the reasons for the change.")
    native._notice()._retained_until(choices.retained_until, time.time())
    for file in (choices.content, choices.policy, choices.configuration):
        if any(ord(char) < 32 for char in file.name):
            raise HTTPException(422, "Choose files with ordinary readable names.")
    body = {"notice_id": base.notice_id, "base_version": base.version, "content_sha256": choices.content.sha256,
            "policy_sha256": choices.policy.sha256, "configuration_sha256": choices.configuration.sha256,
            "consent_publication_ref": pub["publication_id"],
            "regulatory_citations": [{key:row[key] for key in ("document_ref", "source_ref", "evidence_sha256")} for row in refs],
            "reason_codes": sorted(choices.reasons), "retained_until": float(choices.retained_until)}
    binding = digest([asdict(base), refs, pub])
    details = {"notice": human(base.notice_id), "base_version": base.version, "publication": pub["label"],
               "references": [{key:row[key] for key in ("label", "source_name", "version", "citation_labels", "source_notice")} for row in refs],
               "files": [{"purpose": label, "name": file.name, "size": file.size} for label,file in (("Notice", choices.content), ("Privacy policy", choices.policy), ("Website or app configuration", choices.configuration))],
               "reasons": [REASONS[reason] for reason in choices.reasons], "retained_until": choices.retained_until}
    return tenant, store, base, body, binding, details


def review(request, choices, revision):
    current = catalog(request)
    if current["revision"] != revision:
        raise HTTPException(409, "The available records changed. Your draft is kept; refresh choices and review again.")
    tenant, _store, base, body, binding, details = selection(request, choices)
    material = {"purpose": PURPOSE, "context": context_for(request), "owner": native._principal(request, tenant), "expires": time.time()+TTL,
                "operation": secrets.token_hex(16), "proposal": "proposal-"+secrets.token_hex(16), "choices": choices.model_dump(),
                "body": body, "binding": binding, "base": digest(asdict(base)), "details": {"notice": details["notice"]}}
    token = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "This review could not be protected. Nothing was saved.")
    return {"context": material["context"], "token": token, "details": details, "message": "Save this exact proposal for another administrator to review. This records file fingerprints and source references, not their contents or legal applicability. Nothing is published."}


def open_review(request, token, *, current=True):
    _module, tenant, _store = authority(request)
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or value["context"] != context_for(request) or value["owner"] != native._principal(request, tenant) or not isinstance(value["expires"], (int, float)) or value["expires"] > time.time()+TTL or current and value["expires"] <= time.time():
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or your account or workspace changed. Return to the original account to check saved proposals; your current draft is kept.") from exc


def receipt(request, token):
    value = open_review(request, token, current=False)
    _module, tenant, store = authority(request)
    request_material = {"action": "create_update_proposal", "proposal_id": value["proposal"], **value["body"], "actor_ref": value["owner"]}
    with store._connect() as connection:
        _sha, accepted = store._operation(connection, tenant, "guided-"+value["operation"], request_material)
    if accepted is None:
        check_read(request, value["context"])
        return {"status": "not_found", "message": "No accepted original request was found. Nothing was repeated. Check saved proposals before explicitly continuing this exact review."}
    item = store.get_update_proposal(tenant, value["proposal"])
    if accepted["result_kind"] != "proposal" or accepted["result_id"] != item.proposal_id or item.created_by != value["owner"]:
        raise HTTPException(409, "The saved proposal cannot be attributed to this original request. Nothing was repeated.")
    check_read(request, value["context"])
    return {"status": "confirmed", "message": "The exact original proposal is saved. No save was repeated. Its current review status is shown in the proposal list.",
            "proposal": item.proposal_id, "details": {"notice": value["details"]["notice"], "base_version": item.base_version, "status": "Approved" if item.status == "approved" else "Rejected" if item.status == "rejected" else "Waiting for another administrator"}}


def apply(request, token, *, confirmed):
    if confirmed is not True:
        raise HTTPException(422, "Review the full proposal and confirm before saving it.")
    with authority_effect_fence():
        value = open_review(request, token)
        authority(request, write=True)
        saved = receipt(request, token)
        if saved["status"] != "not_found":
            return saved
        tenant = native._tenant_id()
        pri = corpus(tenant)
        publishing = consent._store(consent._ops(), tenant)
        # Native PRI and consent writers use these same database reservations.
        # Instantiate stores before reserving, so initialization cannot recurse.
        with contextlib.ExitStack() as stack:
            pri_connection = stack.enter_context(pri._connect())
            pri._begin(pri_connection)
            pub_connection = stack.enter_context(publishing._connect())
            pub_connection.execute("BEGIN IMMEDIATE")
            marker = _active_corpus.set((tenant, pri))
            try:
                _tenant, store, base, body, binding, _details = selection(request, Choices.model_validate(value["choices"]), pri=pri, publishing=publishing)
                if binding != value["binding"] or body != value["body"] or context_for(request) != value["context"]:
                    raise HTTPException(409, "A reviewed notice, source approval, document or consent publication changed. Your draft is kept; review current choices. Nothing was saved.")
                def guard(connection, current):
                    auth.require_permission(request, "operate")
                    native._notice()
                    regulatory._ops()
                    consent._ops()
                    if (digest(asdict(current)) != value["base"] or latest_version(connection, tenant, current.notice_id) != current.version
                            or current.retained_until <= time.time() or value["expires"] <= time.time()
                            or not all(reference_allowed(tenant, row["document_ref"], row["source_ref"], row["evidence_sha256"]) for row in body["regulatory_citations"])
                            or context_for(request) != value["context"]):
                        raise HTTPException(409, "The notice version or your access changed before saving. Your draft is kept; review the current notice.")
                store.create_update_proposal(tenant, value["proposal"], **body, idempotency_key="guided-"+value["operation"], before_write=guard)
            finally:
                _active_corpus.reset(marker)
                if pub_connection.in_transaction:
                    pub_connection.execute("ROLLBACK")
                if pri_connection.in_transaction:
                    pri_connection.execute("ROLLBACK")
        return receipt(request, token)


def create_version(request, store, tenant, notice_id, body):
    body = dict(body)
    expected = body.pop("expected_context", None)
    with authority_effect_fence():
        auth.require_permission(request, "operate")
        if expected is not None and context_for(request) != expected:
            raise HTTPException(409, "The account or workspace changed since this version was reviewed. Nothing was saved.")
        if body["update_proposal_ref"] is not None:
            return approved_version(request, store, tenant, notice_id, body, expected or context_for(request))
        def guard(_connection, _proposal):
            auth.require_permission(request, "operate")
            native._notice()
            if context_for(request) != expected:
                raise HTTPException(409, "Your access changed before saving. Nothing was saved.")
        return store.create_release(tenant, notice_id, **body, before_write=guard if expected is not None else None)


def approved_version(request, store, tenant, notice_id, body, expected_context):
    """A proposal-backed draft still uses current native sources and admission."""
    with authority_effect_fence():
        auth.require_permission(request, "operate")
        pri = corpus(tenant)
        publishing = consent._store(consent._ops(), tenant)
        with contextlib.ExitStack() as stack:
            research = stack.enter_context(pri._connect())
            pri._begin(research)
            connection = stack.enter_context(publishing._connect())
            connection.execute("BEGIN IMMEDIATE")
            marker = _active_corpus.set((tenant, pri))
            try:
                proposal = store.get_update_proposal(tenant, body["update_proposal_ref"])
                base = store.get_release(tenant, notice_id, proposal.base_version)
                current = publications(tenant, publishing)
                if (proposal.status != "approved" or proposal.notice_id != notice_id
                        or proposal.retained_until <= time.time() or base.property_id != body["property_id"]
                        or proposal.base_version != body["expected_latest_version"]
                        or not all(reference_allowed(tenant, row["document_ref"], row["source_ref"], row["evidence_sha256"]) for row in proposal.regulatory_citations)
                        or not any(row["property_id"] == base.property_id and row["publication_id"] == proposal.consent_publication_ref for row in current)):
                    raise HTTPException(409, "The accepted update, its research references or current consent publication changed. Keep your files and review the current records. Nothing was saved.")
                def guard(current_connection, current_proposal):
                    auth.require_permission(request, "operate")
                    native._notice()
                    regulatory._ops()
                    consent._ops()
                    current_base = store._get_release(current_connection, tenant, notice_id, proposal.base_version)
                    if (current_proposal is None or digest(asdict(current_proposal)) != digest(asdict(proposal))
                            or current_proposal.retained_until <= time.time() or current_base.retained_until <= time.time()
                            or digest(asdict(current_base)) != digest(asdict(base)) or context_for(request) != expected_context
                            or not all(reference_allowed(tenant, row["document_ref"], row["source_ref"], row["evidence_sha256"]) for row in current_proposal.regulatory_citations)):
                        raise HTTPException(409, "A reviewed record expired or changed before saving. Keep your files and review the current records. Nothing was saved.")
                return store.create_release(tenant, notice_id, **body, before_write=guard)
            finally:
                _active_corpus.reset(marker)
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                if research.in_transaction:
                    research.execute("ROLLBACK")


def version_receipt(request, notice_id, body):
    initial_context = context_for(request)
    module, tenant, store = authority(request)
    data = body.model_dump(exclude={"context", "notice_id", "expected_context"})
    key = data.pop("idempotency_key")
    material = {"action": "create_release", "notice_id": notice_id, **data, "actor_ref": native._principal(request, tenant)}
    material["jurisdictions"] = list(module._selection(data["jurisdictions"], "jurisdictions", module._JURISDICTION_RE))
    material["locales"] = list(module._selection(data["locales"], "locales", module._LOCALE_RE))
    for field in ("effective_from", "effective_until", "retained_until"):
        material[field] = float(data[field])
    with store._connect() as connection:
        _sha, accepted = store._operation(connection, tenant, key, material)
        if accepted is None:
            check_read(request, initial_context)
            return {"status": "not_found", "message": "No accepted original version save was found. Nothing was repeated. Keep the original files and review current records before another save."}
        item = store._get_release(connection, tenant, notice_id, data["expected_latest_version"]+1)
    if accepted["result_kind"] != "release" or accepted["result_id"] != f"{notice_id}:{item.version}" or item.created_by != material["actor_ref"]:
        raise HTTPException(409, "This version cannot be attributed to your original save. Nothing was repeated.")
    check_read(request, initial_context)
    return {"status": "confirmed", "message": "Your exact original version save was accepted. No save was repeated. The version is still subject to its separate approval and publishing steps.", "version": item.version}


def proposal_view(request, identity):
    initial_context = context_for(request)
    _module, tenant, store = authority(request)
    item = store.get_update_proposal(tenant, identity)
    base = store.get_release(tenant, item.notice_id, item.base_version)
    refs = []
    for citation in item.regulatory_citations:
        try:
            current = reference(tenant, citation["document_ref"], corpus(tenant))
            if current["source_ref"] != citation["source_ref"] or current["evidence_sha256"] != citation["evidence_sha256"]:
                raise HTTPException(409, "changed")
            refs.append({key: current[key] for key in ("label", "source_name", "version", "citation_labels")})
        except Exception:
            refs.append({"label": "A recorded reference is no longer available under its original research approval", "source_name": "Current source details were not verified", "version": None, "citation_labels": []})
    check_read(request, initial_context)
    return {"context": initial_context, "revision": item.revision, "status": item.status, "notice_id": item.notice_id,
            "notice": human(item.notice_id), "base_version": item.base_version, "property_id": base.property_id,
            "content_sha256": item.content_sha256, "policy_sha256": item.policy_sha256, "configuration_sha256": item.configuration_sha256,
            "publication": item.consent_publication_ref, "reasons": [REASONS.get(reason, human(reason)) for reason in item.reason_codes],
            "references": refs, "notice_scope": "This decision accepts or rejects recorded file fingerprints and references. Original file contents are not retained or shown here; this is not proof that they were examined, a legal applicability decision, or publication."}


def legacy_proposal(request, store, tenant, identity, body):
    """Keep the existing closed input, with the installed current-source fence."""
    with authority_effect_fence():
        auth.require_permission(request, "operate")
        expected_context = context_for(request)
        pri = corpus(tenant)
        publishing = consent._store(consent._ops(), tenant)
        with contextlib.ExitStack() as stack:
            research = stack.enter_context(pri._connect())
            pri._begin(research)
            publication = stack.enter_context(publishing._connect())
            publication.execute("BEGIN IMMEDIATE")
            marker = _active_corpus.set((tenant, pri))
            try:
                base = store.get_release(tenant, body["notice_id"], body["base_version"])
                if not any(row["property_id"] == base.property_id and row["publication_id"] == body["consent_publication_ref"] for row in publications(tenant, publishing)):
                    raise HTTPException(409, "Choose this notice's current consent publication. Nothing was saved.")
                def guard(connection, current):
                    auth.require_permission(request, "operate")
                    native._notice()
                    regulatory._ops()
                    consent._ops()
                    if (context_for(request) != expected_context or digest(asdict(current)) != digest(asdict(base))
                            or current.retained_until <= time.time() or latest_version(connection, tenant, current.notice_id) != current.version
                            or not all(reference_allowed(tenant, row["document_ref"], row["source_ref"], row["evidence_sha256"]) for row in body["regulatory_citations"])):
                        raise HTTPException(409, "The notice or its approved research references changed before saving. Nothing was saved.")
                return store.create_update_proposal(tenant, identity, **body, before_write=guard)
            finally:
                _active_corpus.reset(marker)
                if publication.in_transaction:
                    publication.execute("ROLLBACK")
                if research.in_transaction:
                    research.execute("ROLLBACK")
