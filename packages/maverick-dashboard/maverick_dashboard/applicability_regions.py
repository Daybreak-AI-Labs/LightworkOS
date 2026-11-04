"""Owner-scoped, source-bound finite answer routing and original custody."""
from __future__ import annotations

import json
import re
import secrets
import time
from contextlib import ExitStack
from typing import Literal

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import BudgetExceeded
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
)
from maverick.flow import applicability_regions as engine
from maverick.flow import store
from maverick.governed_records import (
    GovernedRecordCapacityError,
    GovernedRecordStore,
    RecordConflict,
)
from pydantic import BaseModel, ConfigDict, Field

from . import flow_requalification as source
from . import local_flow_comparisons as comparisons
from . import local_flow_promotions as release
from . import work_restructuring as evidence
from .plain_labels import datetime_text
from .scalar_wire import whole_number

PAGE = "/learning/applicability"
API = "/api/v1/learning/applicability"
NOTICE = ("Find exactly where your current or proposed local answers match the answers you reviewed. "
          "Every displayed starting combination is checked. Missing or conflicting expected answers remain unresolved. "
          "When both versions are correct, keep the current version. No AI, connected work or publication runs.")
SOURCE_ERRORS = (HTTPException, ValueError, KeyError, RecordConflict, CandidatePromotionConflict,
                 CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError)


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: str = Field(pattern=r"^(qualify|label|withdraw|run)$")
    flow: str = Field(default="", max_length=128)
    comparisons: list[str] = Field(default_factory=list, max_length=20)
    original: str = Field(default="", pattern=r"^(APR-[a-f0-9]{32})?$")
    expected: str | int | bool | None = None
    inputs: dict = Field(default_factory=dict)
    seconds: Literal[30, 60, 120] | None = None


def records():
    release._records()
    return GovernedRecordStore("local-rule-applicability", "APR", "applicability_regions", required_backend="local")


def authority(request, context=None, *, write=False):
    return source.authority(request, context, write=write)


def available(request):
    release._learning_allowed()
    if config.get_features().get("applicability_regions") is not True:
        raise HTTPException(409, "Checked answer routing is off. An administrator can enable it in Settings. Original history remains available.")
    return source._policy(request)


def _rows():
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, "The complete original collection exceeds its supported limit. Nothing was silently hidden.")
    return rows


def opened(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if engine.digest(value["prepared"]) != row["binding"]:
        raise HTTPException(409, "The original reviewed request cannot be verified.")
    if row["state"] == "done" and type(value.get("result")) is not dict:
        raise HTTPException(409, "The complete original result cannot be verified.")
    return value


def seal(value):
    result = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(result):
        raise HTTPException(503, "Private reviews need Encrypt stored data. An administrator can enable it in All settings.")
    if len(result) > 2 * 1024 * 1024:
        raise HTTPException(413, "The complete private review is too large to retain safely. Nothing will repeat automatically.")
    return result


def owned(request, identifier):
    tenant, owner, context = authority(request)
    if re.fullmatch(r"APR-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(422, "Choose an original answer-routing request.")
    row = records().get(identifier)
    if row and (row["tenant"], row["owner"]) != (tenant, owner):
        raise HTTPException(404, "This original request is unavailable to your account.")
    authority(request, context)
    return row


def _withdrawn(rows):
    result = set()
    for row in rows:
        if row["kind"] == "withdraw" and row["state"] == "done":
            payload = opened(row)
            if payload["result"] != {"withdrawn": True}:
                raise HTTPException(409, "A retained answer withdrawal cannot be verified. No further answer reuse starts.")
            value = payload["prepared"]
            result.add((value["target"], value["target_binding"]))
    return result


def _pair(request, flow, identifiers):
    if not 1 <= len(identifiers) <= 20 or len(set(identifiers)) != len(identifiers):
        raise HTTPException(422, "Choose one to twenty distinct complete comparisons.")
    tenant, owner, context, candidate, baseline, publication, root, _bundle = comparisons._current(request, flow)
    flows = [baseline, candidate]
    spec, points = engine.definitions(flows)
    if publication.get("subflow_digests"):
        raise HTTPException(409, "Choose one taught answer step without included workflows.")
    pair = engine.digest([publication, root, spec["inputs"], spec["output_type"]])
    grants = source.records().list(limit=1001)
    if len(grants) > 1000:
        raise HTTPException(409, "The complete case-use collection exceeds its supported limit. Nothing was omitted.")
    selected, labels, runs = [], [], set()
    for identifier in sorted(identifiers):
        comparisons.view(request, identifier)
        row = comparisons.records().get(identifier)
        if (row is None or row["state"] != "done" or row.get("_audit_pending")
                or (row["tenant"], row["owner"], row["flow_id"]) != (tenant, owner, flow)
                or row["root"] != root or row["baseline"] != publication or row.get("candidate_manifest")):
            raise HTTPException(409, "Choose complete comparisons of these exact current and proposed versions.")
        comparisons._check(row)
        selected.append({"id": identifier, "revision": row["revision"], "binding": row["binding"]})
        for case in row["cases"]:
            matching = [grant for grant in grants if (grant.get("tenant"), grant.get("owner"), grant.get("flow_id"), grant.get("kind"))
                        == (tenant, owner, flow, "retain") and grant.get("case", {}).get("run_id") == case["run_id"] and grant.get("baseline") == publication]
            valid = None
            for grant in matching:
                try:
                    checked = evidence._receipt(request, grant["id"])
                except SOURCE_ERRORS:
                    continue
                if checked["case"]["version"] == case["version"]:
                    valid = checked
                    break
            if valid is None:
                raise HTTPException(409, "A selected real case needs current separately retained reuse permission in Recheck local rules. A comparison alone does not grant reuse.")
            values = {name: case["inputs"].get(name) for name in spec["inputs"]}
            engine.scalar._inputs(spec, values, exact=True)
            if values not in points:
                raise HTTPException(409, "A selected case lies outside these exact displayed starting limits.")
            labels.append({"inputs": values, "expected": case["expected"], "type": "real_case",
                           "comparison": identifier, "run": case["run_id"], "source_version": publication["definition_version"], "source_binding": case["version"],
                           "grant": valid["id"], "grant_revision": valid["revision"], "grant_binding": valid["binding"],
                           "original_inputs": case["inputs"]})
            runs.add(case["run_id"])
    return {"flow": flow, "name": candidate.name, "pair": pair, "publication": publication, "root": root,
            "version": candidate.version, "baseline_version": baseline.version, "flow_revision": candidate.revision, "selected": selected,
            "real_labels": labels, "runs": sorted(runs), "inputs": spec["inputs"], "output_kind": spec["output_type"],
            "points": len(points)}


def _labels(request, pair, *, omit=""):
    tenant, owner, context = authority(request)
    policy = source._policy(request)
    rows = [row for row in _rows() if (row["tenant"], row["owner"]) == (tenant, owner)]
    withdrawn = _withdrawn(rows)
    labels = []
    for row in rows:
        if row["id"] == omit or row["kind"] != "label" or row["state"] != "done" or row.get("_audit_pending") or (row["id"], row["binding"]) in withdrawn:
            continue
        value = opened(row)["prepared"]
        if value["pair"] == pair and value["context"] == context and value["policy"] == policy:
            labels.append({"id": row["id"], "binding": row["binding"], "inputs": value["question"]["inputs"],
                           "expected": value["expected"], "type": "hypothetical", "when": row["created_at"]})
    return sorted(labels, key=lambda row: row["id"])


def _saved_sources(request, row, payload):
    """Validate retained source bindings without recursively replaying parents."""
    value = payload["prepared"]
    authority(request, value["context"])
    pair = _pair(request, value["flow"], [item["id"] for item in value["selected"]])
    if any(value[key] != item for key, item in pair.items()) or available(request) != value["policy"]:
        raise HTTPException(409, "A retained version, original case or reuse permission changed. Check current regions again.")
    active = _labels(request, value["pair"])
    bindings = {(item["id"], item["binding"]) for item in active}
    required = {(item["id"], item["binding"]) for item in value["labels"]}
    if row["kind"] == "label":
        required.add((row["id"], row["binding"]))
    if not required <= bindings:
        raise HTTPException(409, "A separately reviewed answer was withdrawn. Check current regions again.")
    return active, required


def material(request, arguments, *, omit=""):
    body = Choices.model_validate(arguments)
    tenant, owner, context = authority(request)
    value = {"arguments": body.model_dump(exclude={"seconds"} if body.seconds is None else set()),
             "kind": body.kind, "tenant": tenant, "owner": owner, "context": context}
    if body.kind == "qualify":
        if body.original or body.expected is not None or body.inputs:
            raise HTTPException(422, "Use only the named comparisons for this complete region check.")
        value.update(_pair(request, body.flow, body.comparisons), policy=available(request))
        value["labels"] = _labels(request, value["pair"], omit=omit)
        return value
    if body.flow or body.comparisons:
        raise HTTPException(422, "Use the selected original result for this action.")
    row = owned(request, body.original)
    if row is None or row["state"] != "done" or row.get("_audit_pending"):
        raise HTTPException(409, "Choose a confirmed original complete request first.")
    prior = opened(row)
    if body.kind == "withdraw":
        if body.expected is not None or body.inputs or row["kind"] != "label":
            raise HTTPException(422, "Choose one separately reviewed hypothetical answer to stop reusing.")
        if (row["id"], row["binding"]) in _withdrawn(item for item in _rows() if (item["tenant"], item["owner"]) == (tenant, owner)):
            raise HTTPException(409, "This expected answer already has a recorded withdrawal. Read its original history; nothing needs to run again.")
        value.update(target=row["id"], target_binding=row["binding"], name="Withdraw reviewed test answer", target_when=row["created_at"])
        return value
    if row["kind"] not in {"qualify", "label"}:
        raise HTTPException(409, "Choose a complete checked routing result.")
    active, required = _saved_sources(request, row, prior)
    prepared = prior["prepared"]
    value.update(_pair(request, prepared["flow"], [item["id"] for item in prepared["selected"]]), policy=available(request),
                 labels=_labels(request, prepared["pair"], omit=omit), original_binding=row["binding"])
    if body.kind == "label":
        question = prior["result"].get("next_question")
        if question is None or body.inputs:
            raise HTTPException(409, "This result has no unreviewed starting situation to answer.")
        if any(engine.digest(item["inputs"]) == engine.digest(question["inputs"]) for item in active):
            raise HTTPException(409, "Another reviewed answer already covers this situation. Check current regions before answering another question.")
        expected = whole_number(body.expected) if value["output_kind"] == "integer" else body.expected
        engine.scalar._scalar(expected, value["output_kind"], output=True)
        value.update(question=question, expected=expected)
    else:
        if body.expected is not None:
            raise HTTPException(422, "Use only the displayed starting values to try the checked routing.")
        engine.scalar._inputs({"inputs": value["inputs"]}, body.inputs, exact=True)
        if {(item["id"], item["binding"]) for item in active} != required:
            raise HTTPException(409, "The reviewed answers changed after this routing check. Check current regions before trying it.")
        value.update(checked=prior["result"], entered=body.inputs)
    return value


def guard(request, value, *, deadline=True, omit=""):
    authority(request, value["context"])
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "This complete review expired. Read the original request without repeating work.")
    if material(request, value["arguments"], omit=omit) != {key: item for key, item in value.items() if key != "expires"}:
        raise HTTPException(409, "A version, original case, expected answer, permission or policy changed. Review current sources again.")
    authority(request, value["context"])
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "The review expired while current sources were checked. No further work starts.")


def prepare(request, arguments, *, context=None):
    authority(request, context)
    with authority_effect_fence(), store._definitions_lock():
        value = material(request, arguments)
        value["expires"] = time.time() + 600
        changes = [{"label": "Action", "after": {"qualify": "Check the complete starting range and learn answer regions", "label": "Record a reviewed hypothetical answer and recheck regions", "withdraw": "Stop reusing this reviewed hypothetical answer", "run": "Try the checked answer routing"}[value["kind"]]}]
        if value["kind"] != "withdraw":
            flows = [store.load_flow_snapshot(value["publication"]["definition_digest"]), store.load_flow_snapshot(value["root"])]
            for title, flow in zip(("Current retained version", "Proposed retained version"), flows, strict=True):
                changes.extend(source._source_review(flow, {}, title))
            changes.extend([{"label": "Complete starting range", "after": source._display(value["inputs"])},
                {"label": "Full local work and independent comparison", "after": "Check all " + str(value["points"]) + " starting combinations, both immutable answers, minimum supported split boundaries and fresh separate routing checks. One " + str(value["arguments"].get("seconds", 30)) + "-second total allowance includes writer wait and all source checks; at most 100,000 split-search steps and 1,024 native calculation boundaries. The independent full-information table uses its own fresh rule executions. No faster or better business result is claimed."}])
            for index, label in enumerate(value["real_labels"]):
                changes.extend([{"label": "Real case " + str(index + 1) + " / complete original starting values", "after": source._display(label["original_inputs"])},
                    {"label": "Real case " + str(index + 1) + " / reviewed expected answer", "after": source._display(label["expected"])},
                    {"label": "Real case " + str(index + 1) + " / current source and reuse", "after": "Original version " + str(label["source_version"]) + "; separately retained current permission allows this exact case to be reused. Complete paired results and source versions are checked again before reuse."}])
            for index, label in enumerate(value["labels"]):
                changes.append({"label": "Reviewed hypothetical answer " + str(index + 1) + " / " + datetime_text(label["when"], seconds=True),
                                "after": source._display({"Starting values": label["inputs"], "Expected answer": label["expected"]})})
            if value["kind"] == "label":
                changes.extend([{"label": "Hypothetical starting situation", "after": source._display(value["question"]["inputs"])},
                    {"label": "Current version / actual local test answer", "after": source._display(value["question"]["arms"][0]["value"]) if value["question"]["arms"][0]["complete"] else "No complete answer"},
                    {"label": "Proposed version / actual local test answer", "after": source._display(value["question"]["arms"][1]["value"]) if value["question"]["arms"][1]["complete"] else "No complete answer"},
                    {"label": "Your full expected answer", "after": source._display(value["expected"])},
                    {"label": "Separate reuse permission", "after": "I authorize retaining and reusing this expected answer for these exact local rule versions while my access and the sources remain current. This is a reviewed hypothetical test, not a measured real customer outcome. I can withdraw it separately."}])
                if value["output_kind"] == "string":
                    changes.append({"label": "Expected text length", "after": str(len(value["expected"])) + " characters; all spaces and line breaks are retained exactly"})
            if value["kind"] == "run":
                changes.append({"label": "Complete entered starting values", "after": source._display(value["entered"])})
        else:
            changes.append({"label": "Selected separately reviewed hypothetical answer", "after": datetime_text(value["target_when"], seconds=True)})
            changes.append({"label": "Withdrawal and retained original", "after": "Stop future reuse of the selected separately reviewed test answer. Keep its original receipt. Derived routing becomes unavailable; no workflow or real customer record is deleted."})
        changes.append({"label": "Scope and decision", "after": NOTICE + " Unknown or conflicting cases ask for review. When both versions are correct, use the current version. Known answers do not prove future accuracy, customer savings or business improvement."})
        if len(changes) > 512 or len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "The complete review is too large. Choose fewer bounded cases.")
        authority(request, value["context"])
        return value, changes


def _admit_current(request, value, work, current):
    authority(request, value["context"], write=True)
    work.budget.check()
    guard(request, value)
    if current["state"] != "prepared" or current["binding"] != engine.digest(value) or current.get("_audit_pending"):
        raise HTTPException(409, "The original admission is unconfirmed. Read its saved outcome without repeating work.")
    work.budget.check()
    current["state"] = "running"


def _create_claim(service, value, identifier):
    try:
        return service.create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "kind": value["kind"],
            "context": value["context"], "binding": engine.digest(value), "state": "prepared", "payload": seal({"prepared": value, "observations": []})},
            action="applicability.start", actor=value["owner"], max_records=1000 if value["kind"] == "withdraw" else 500)
    except GovernedRecordCapacityError:
        raise HTTPException(409, "This collection has reached its supported request limit. Original outcomes and reserved answer withdrawals remain available; no new work started.") from None


def apply(request, value, operation):
    try:
        return _apply(request, value, operation)
    except BudgetExceeded as exc:
        raise HTTPException(409, "The reviewed total time was used up. Any saved observations remain available in the original request; the complete result is unconfirmed. Nothing resumes or repeats automatically. A separate check needs a new review, which can allow more time.") from exc


def _apply(request, value, operation):
    identifier, service = "APR-" + operation, records()
    if re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "This original request is invalid.")

    def boundary():
        authority(request, value["context"])
        if time.time() >= value["expires"] or available(request) != value["policy"]:
            raise HTTPException(409, "The review time or current permission changed. Further work stopped; the original will not resume.")

    work = engine.Work(boundary, identifier, seconds=value["arguments"].get("seconds", 30))
    with authority_effect_fence(), ExitStack() as locks:
        for run in value.get("runs", []):
            locks.enter_context(store.run_lock(run))
        locks.enter_context(store._definitions_lock())
        prior = owned(request, identifier)
        if prior:
            if prior["binding"] != engine.digest(value):
                raise HTTPException(409, "This original request belongs to another complete review.")
            return original(request, identifier)
        authority(request, value["context"], write=True)
        work.budget.check()
        guard(request, value)
        try:
            row = _create_claim(service, value, identifier)
        except RecordConflict:
            prior = owned(request, identifier)
            if prior is None or prior["binding"] != engine.digest(value):
                raise HTTPException(409, "This original request belongs to another complete review.") from None
            return original(request, identifier)
        if row.get("_audit_pending"):
            return original(request, identifier)

        row = service.update(identifier, lambda current: _admit_current(request, value, work, current),
                             expected_revision=row["revision"], action="applicability.admit", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)

        def save_cell(cell):
            nonlocal row
            def save(current):
                authority(request, value["context"], write=True)
                boundary()
                work.budget.check()
                if current["state"] != "running" or current.get("_audit_pending"):
                    raise HTTPException(409, "The original partial outcome is uncertain. Further work stopped.")
                payload = opened(current)
                payload["observations"].append(cell)
                current["payload"] = seal(payload)
                boundary()
            row = service.update(identifier, save, expected_revision=row["revision"], action="applicability.observation", actor=value["owner"])
            if row.get("_audit_pending"):
                raise HTTPException(409, "An original local result is unconfirmed. Further work stopped.")

        if value["kind"] == "withdraw":
            result = {"withdrawn": True}
        else:
            flows = [store.load_flow_snapshot(value["publication"]["definition_digest"]), store.load_flow_snapshot(value["root"])]
            if value["kind"] == "run":
                result = engine.run(flows, value["checked"], value["entered"], work=work)
            else:
                labels = [*value["real_labels"], *value["labels"]]
                if value["kind"] == "label":
                    labels.append({"inputs": value["question"]["inputs"], "expected": value["expected"], "type": "hypothetical"})
                result = engine.qualify(flows, labels, work=work, save_cell=save_cell)
        def finish(current):
            authority(request, value["context"], write=True)
            work.budget.check()
            guard(request, value, omit=identifier)
            if current["state"] != "running" or current.get("_audit_pending"):
                raise HTTPException(409, "The original complete result is unconfirmed. Read it without repeating work.")
            payload = opened(current)
            payload["result"] = result
            retained = seal(payload)
            guard(request, value, omit=identifier)
            work.budget.check()
            current.update(state="done", payload=retained)
        service.update(identifier, finish, expected_revision=row["revision"], action="applicability.complete", actor=value["owner"])
    return original(request, identifier)


def original(request, identifier):
    _tenant, _owner, context = authority(request)
    row = owned(request, identifier)
    result = {"id": identifier, "confirmed": False, "current": False, "message": "The original request has no confirmed complete result. Missing or interrupted work never resumes automatically."}
    if row:
        result["kind"] = row["kind"]
        try:
            payload = opened(row)
            result["confirmed"] = row["state"] == "done" and not row.get("_audit_pending")
            if result["confirmed"]:
                result["message"] = "The exact original complete result is retained. Nothing ran again."
            if row["kind"] == "withdraw":
                if result["confirmed"] and payload["result"] == {"withdrawn": True}:
                    result["result"] = {"withdrawn": True}
                elif result["confirmed"]:
                    result.update(confirmed=False, message="The original withdrawal outcome cannot be verified. It will not run again automatically.")
            elif row["kind"] in {"qualify", "label"} and result["confirmed"]:
                active, required = _saved_sources(request, row, payload)
                if {(item["id"], item["binding"]) for item in active} != required:
                    raise HTTPException(409, "The currently reviewed answers changed; the retained routing cannot be reused.")
            else:
                guard(request, payload["prepared"], deadline=False, omit=identifier)
            if row["kind"] != "withdraw":
                result.update(current=True, context=authority(request)[2], name=payload["prepared"]["name"],
                              flow=payload["prepared"]["flow"], versions={"current": payload["prepared"]["baseline_version"], "proposed": payload["prepared"]["version"]},
                              observations=payload["observations"])
                if result["confirmed"]:
                    result["result"] = payload["result"]
        except SOURCE_ERRORS:
            result["message"] += " Current source details are unavailable; no private answers are returned or reused."
    authority(request, context)
    return result


def listing(request, flow=""):
    tenant, owner, context = authority(request)
    enabled = config.get_features().get("applicability_regions") is True
    value = {"context": context, "enabled": enabled, "flows": [], "comparisons": [], "notice": NOTICE}
    if enabled:
        for item in source.listing(request)["flows"]:
            try:
                current = comparisons._current(request, item["value"])
                engine.definitions([current[4], current[3]])
            except SOURCE_ERRORS:
                continue
            value["flows"].append(item)
        if flow:
            rows = comparisons.records().list(limit=1001)
            if len(rows) > 1000:
                raise HTTPException(409, "The complete comparison collection exceeds its supported limit. Nothing was hidden.")
            for row in rows:
                if (row.get("tenant"), row.get("owner"), row.get("flow_id"), row.get("state")) != (tenant, owner, flow, "done"):
                    continue
                try:
                    _pair(request, flow, [row["id"]])
                except SOURCE_ERRORS:
                    continue
                value["comparisons"].append({"value": row["id"], "label": "Known-case comparison / " + datetime_text(row["created_at"], seconds=True)})
    authority(request, context)
    value["revision"] = engine.digest(value)
    return value


def history(request):
    tenant, owner, context = authority(request)
    rows = [{"value": row["id"], "label": {"qualify": "Complete region check", "label": "Reviewed hypothetical answer", "withdraw": "Expected-answer withdrawal", "run": "Checked routing attempt"}[row["kind"]]
             + " / " + datetime_text(row["created_at"], seconds=True), "kind": row["kind"]}
            for row in _rows() if (row["tenant"], row["owner"]) == (tenant, owner)]
    authority(request, context)
    return {"context": context, "choices": rows}


def operation():
    return secrets.token_hex(16)
