"""The policy documents a suggested edit can change, each through its own flow (NOT-4).

Every document type answers the same questions for ``policy_suggestions_api``:
who may read and change it (the same permission its own pages and routes
use), what its current wording is part by part, how a suggested value is
checked, and how an accepted suggestion is saved. Saving always goes through
the document's own save path and only ever creates the next draft:

* ``ai-policy`` (AI use rules): the next version, through the same version
  route as editing by hand. It is used only once someone turns it on.
* ``data-use-rule``: the next draft policy version, through the same route.
  It takes effect only after a different administrator activates it.
* ``privacy-notice``: the next notice version, through the same store call
  as the version route. It still needs submitting, the approval rule's
  quorum and scheduling before publication, and signed records as usual.
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from . import auth


def _canonical(document: dict) -> str:
    return json.dumps(document, sort_keys=True, indent=1)


class AIPolicy:
    kind = "ai-policy"
    noun = "AI use rules"
    ai_drafting = True

    def can_read(self, request: Request) -> None:
        auth.require_permission(request, "view")

    def can_write(self, request: Request) -> None:
        auth.require_permission(request, "operate")

    def may_write(self, request: Request) -> bool:
        return auth.has_permission(request, "operate")

    def _service(self):
        from maverick import ai_policy_management
        from maverick.paths import current_tenant_id_strict

        if not ai_policy_management.enabled():
            raise HTTPException(404, "AI use rules are turned off.")
        if current_tenant_id_strict() is None:
            raise HTTPException(409, "Choose a workspace before suggesting changes to its rules.")
        return ai_policy_management.configured_policy_management()

    @staticmethod
    def _label(field: str) -> str:
        if field in ("title", "description"):
            return field.capitalize()
        return "Rule: " + field.split(":", 1)[1].replace("-", " ").replace("_", " ")

    def _snapshot(self, policy: dict) -> dict:
        versions = policy.get("versions") or []
        latest = versions[-1] if versions else {}
        values = {"title": str(latest.get("title") or ""), "description": str(latest.get("description") or "")}
        for statement in latest.get("statements") or []:
            values[f"statement:{statement['statement_id']}"] = str(statement.get("text") or "")
        return {"id": policy["policy_id"], "title": values["title"] or policy["policy_id"],
                "version": latest.get("version"), "values": values,
                "labels": {f: self._label(f) for f in values}, "raw": policy}

    def snapshots(self, request: Request) -> dict[str, dict]:
        return {p["policy_id"]: self._snapshot(p) for p in self._service().list_policies()}

    def snapshot(self, request: Request, document_id: str) -> dict:
        policy = self._service().get_policy(document_id)
        if policy is None or not policy.get("versions"):
            raise HTTPException(404, "Those rules no longer exist.")
        return self._snapshot(policy)

    def parse(self, field: str, text: str, document: dict | None) -> str:
        return (text or "").strip()

    def display(self, text: str) -> str:
        return text

    async def save(self, request: Request, snap: dict, field: str, after: str, suggestion_id: int) -> dict:
        from .model_risk_api import add_operational_ai_policy_version
        from .model_risk_schemas import AIPolicyVersionIn

        policy = snap["raw"]
        latest = policy["versions"][-1]
        title, description = latest.get("title") or "", latest.get("description") or ""
        statements = [dict(s) for s in latest.get("statements") or []]
        if field == "title":
            title = after
        elif field == "description":
            description = after
        else:
            wanted = field.split(":", 1)[1]
            for statement in statements:
                if statement.get("statement_id") == wanted:
                    statement["text"] = after
        body = AIPolicyVersionIn.model_validate({"title": title, "description": description, "statements": statements,
                                                 "expected_revision": int(policy["revision"])})
        saved = await add_operational_ai_policy_version(request, snap["id"], body)
        version = int(saved["versions"][-1]["version"])
        return {"applied_version": version,
                "next_step": f"Saved as version {version}. Turn it on above when you are ready."}


_EFFECTS = {"allow": "allow it", "deny": "block it", "mask": "hide part of each value",
            "row_filter": "show only some rows", "review": "send it to a person to review"}
_CONDITIONS = {"business_purpose_any": "the business purpose is", "regulatory_any": "the law that applies is",
               "consent_any": "the consent given is", "observed_classification_any": "the data is classed as",
               "label_any": "the data is labelled"}


class DataUseRule:
    kind = "data-use-rule"
    noun = "data use rule"
    ai_drafting = False

    def can_read(self, request: Request) -> None:
        auth.require_permission(request, "operate")

    def can_write(self, request: Request) -> None:
        # The same check as saving a policy version on the data use page.
        auth.require_global_permission(request, "admin")

    def may_write(self, request: Request) -> bool:
        return auth.has_global_permission(request, "admin")

    def _store(self):
        from .data_use_governance_api import _authority

        return _authority()

    def _snapshot(self, store, tenant: str, pointer: dict) -> dict | None:
        current = pointer.get("current_version")
        if not current:
            return None
        version = store.get_record(tenant, "policy_version", f"{pointer['policy_id']}:{current}")
        if version is None:
            return None
        return {"id": pointer["policy_id"], "title": pointer["policy_id"].replace("-", " ").replace("_", " "),
                "version": int(current), "values": {"document": _canonical(version["document"])},
                "labels": {"document": "Rule"}, "raw": pointer}

    def snapshots(self, request: Request) -> dict[str, dict]:
        _ops, tenant, store = self._store()
        out = {}
        for pointer in store.list_records(tenant, "policy", limit=200):
            snap = self._snapshot(store, tenant, pointer)
            if snap is not None:
                out[snap["id"]] = snap
        return out

    def snapshot(self, request: Request, document_id: str) -> dict:
        _ops, tenant, store = self._store()
        pointer = store.get_record(tenant, "policy", document_id)
        snap = self._snapshot(store, tenant, pointer) if pointer else None
        if snap is None:
            raise HTTPException(404, "That data use rule no longer exists.")
        return snap

    def parse(self, field: str, text: str, document: dict | None) -> str:
        from maverick.data_use_governance import DataUseValidationError, normalize_policy_document

        if document is None:
            try:
                document = json.loads(text or "")
            except ValueError as exc:
                raise HTTPException(422, "Send the suggested rule as a complete rule document.") from exc
        try:
            return _canonical(normalize_policy_document(document))
        except DataUseValidationError as exc:
            raise HTTPException(422, f"The suggested rule cannot be used: {exc}.") from exc

    def display(self, text: str) -> str:
        """The rule in plain lines, so the change reads as words, not code."""
        try:
            document = json.loads(text)
        except ValueError:
            return text
        scope = document.get("scope") or {}
        lines = []
        for key, words in (("asset_ids", "Data sets"), ("field_ids", "Fields"), ("project_ids", "Projects"),
                           ("actions", "Uses")):
            lines.append(f"{words}: {', '.join(scope.get(key) or []) or 'any'}.")
        for key, words in _CONDITIONS.items():
            values = (document.get("conditions") or {}).get(key) or []
            if values:
                lines.append(f"Only when {words} {', '.join(values)}.")
        for control in document.get("controls") or []:
            effect = _EFFECTS.get(control.get("effect"), str(control.get("effect")))
            extra = f" for {', '.join(control['field_ids'])}" if control.get("field_ids") else ""
            method = f" by {control['mask_method'].replace('_', ' ')}" if control.get("mask_method") else ""
            lines.append(f"Step {control.get('control_id')}: {effect}{extra}{method}.")
        return "\n".join(lines)

    async def save(self, request: Request, snap: dict, field: str, after: str, suggestion_id: int) -> dict:
        from .data_use_governance_api import PolicyVersionIn, put_policy_version

        pointer = snap["raw"]
        body = PolicyVersionIn(version=snap["version"] + 1, document=json.loads(after),
                               expected_current_version=snap["version"], expected_revision=int(pointer["revision"]),
                               idempotency_key=f"policy-suggestion-{suggestion_id}")
        saved = await put_policy_version(request, snap["id"], body)
        version = int(saved["current_version"])
        return {"applied_version": version,
                "next_step": f"Saved as draft version {version}. It takes effect only after another "
                             "administrator reviews and activates it."}


class PrivacyNotice:
    kind = "privacy-notice"
    noun = "privacy notice"
    ai_drafting = False
    # The same patterns the notice store checks.
    _LISTS = {"jurisdictions": ("Places it covers", re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")),
              "locales": ("Languages", re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}\Z"))}

    def can_read(self, request: Request) -> None:
        from . import privacy_notice_governance_api as native

        native.require_permission(request, "view")

    def can_write(self, request: Request) -> None:
        from . import privacy_notice_governance_api as native

        # The same check as the notice version route.
        native.require_permission(request, "operate")

    def may_write(self, request: Request) -> bool:
        return auth.has_permission(request, "operate")

    def _releases(self, request: Request) -> tuple[Any, str, Any, dict[str, Any]]:
        from . import privacy_notice_governance_api as native

        notice, tenant, store = native.authority(request)
        try:
            listed = store.list_records(tenant)
        except notice.PrivacyNoticeGovernanceError as exc:
            raise HTTPException(503, "Privacy notices can't be read right now. Try again in a minute.") from exc
        latest: dict[str, Any] = {}
        for release in listed["releases"]:
            if release.notice_id not in latest or release.version > latest[release.notice_id].version:
                latest[release.notice_id] = release
        return notice, tenant, store, latest

    def _snapshot(self, release) -> dict:
        values = {"jurisdictions": ", ".join(release.jurisdictions), "locales": ", ".join(release.locales)}
        return {"id": release.notice_id, "title": release.notice_id.replace("-", " ").replace("_", " "),
                "version": release.version, "values": values,
                "labels": {key: label for key, (label, _pattern) in self._LISTS.items()}, "raw": release}

    def snapshots(self, request: Request) -> dict[str, dict]:
        return {nid: self._snapshot(r) for nid, r in self._releases(request)[3].items()}

    def snapshot(self, request: Request, document_id: str) -> dict:
        release = self._releases(request)[3].get(document_id)
        if release is None:
            raise HTTPException(404, "That privacy notice no longer exists.")
        return self._snapshot(release)

    def parse(self, field: str, text: str, document: dict | None) -> str:
        label, pattern = self._LISTS[field]
        values = [v.strip() for v in (text or "").split(",") if v.strip()]
        if not values or any(not pattern.fullmatch(v) for v in values) or len(values) > 64:
            raise HTTPException(422, f"List the {label.lower()} as short codes separated by commas, like eu, us-ca.")
        return ", ".join(dict.fromkeys(values))

    def display(self, text: str) -> str:
        return text

    async def save(self, request: Request, snap: dict, field: str, after: str, suggestion_id: int) -> dict:
        from . import privacy_notice_governance_api as native

        self.can_write(request)
        notice, tenant, store, latest = await run_in_threadpool(self._releases, request)
        release = latest.get(snap["id"])
        if release is None or release.version != snap["version"]:
            raise HTTPException(409, "This notice changed since this was suggested. Reject it, or suggest again.")
        fields = {"property_id": release.property_id, "jurisdictions": list(release.jurisdictions),
                  "locales": list(release.locales), "policy_sha256": release.policy_sha256,
                  "content_sha256": release.content_sha256, "configuration_sha256": release.configuration_sha256,
                  "consent_publication_ref": release.consent_publication_ref,
                  "approval_policy_id": release.approval_policy_id, "effective_from": release.effective_from,
                  "effective_until": release.effective_until, "retained_until": release.retained_until,
                  "expected_latest_version": release.version,
                  "idempotency_key": f"policy-suggestion-{suggestion_id}"}
        fields[field] = after.split(", ")
        body = native.ReleaseCreateIn.model_validate(fields)
        try:
            saved = await run_in_threadpool(store.create_release, tenant, snap["id"],
                                            **body.model_dump(exclude={"expected_context"}))
        except notice.PrivacyNoticeConflict as exc:
            raise HTTPException(409, "This notice changed since this was suggested. Reject it, or suggest again.") from exc
        except notice.PrivacyNoticeGovernanceError as exc:
            raise HTTPException(422, "The notice could not take this change. Check the notice's dates and approval rule.") from exc
        return {"applied_version": int(saved.version),
                "next_step": f"Saved as notice version {saved.version}. It still needs submitting, the approvals "
                             "its approval rule asks for and scheduling before anyone sees it."}


DOCUMENTS = {d.kind: d for d in (AIPolicy(), DataUseRule(), PrivacyNotice())}


def document(kind: str):
    found = DOCUMENTS.get(kind)
    if found is None:
        raise HTTPException(404, "Suggestions work on AI use rules, data use rules and privacy notices.")
    return found
