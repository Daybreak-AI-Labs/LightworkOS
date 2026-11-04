"""Native work-value controls and the shared authorized Copilot read contract."""
from __future__ import annotations

import copy
import functools
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from maverick.intent_value import calculation, opportunities, service, settings, taxonomy
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import auth

router = APIRouter(prefix="/intent-value", tags=["intent-value"])


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RevisionIn(StrictInput):
    revision: int = Field(ge=0)


class CorrectionIn(RevisionIn):
    intents: list[str] = Field(max_length=4)
    size: Literal["standard", "large"] = "standard"
    reason: str = Field(min_length=1, max_length=1000)
    units: dict[str, Annotated[int, Field(strict=True, ge=1, le=50)]] | None = Field(default=None, max_length=4)


class SettingsIn(RevisionIn):
    hourly_rate: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    currency: Literal["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "INR"]
    completion_confirmation: bool = False


class BenchmarkIn(RevisionIn):
    minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    low_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    high_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    attributable_share: float = Field(ge=0, le=1, allow_inf_nan=False)
    review_minutes: float = Field(ge=0, le=100_000, allow_inf_nan=False)
    reason: str = Field(min_length=1, max_length=1000)


class DecisionIn(RevisionIn):
    decision: Literal["defer", "decline", "keep", "adjust", "reopen"]
    manual_steps: list[Literal["inputs", "prepare", "review"]] = Field(default_factory=lambda: ["inputs", "review"])


def _call(call):
    try:
        return call()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(409, "This record changed. Refresh and review its current version.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Work value records could not be read completely. Refresh to retry; this is not zero activity.") from exc


def authority(request, *, write=False, company=False, admin=False):
    auth.require_permission(request, "admin" if admin else "operate" if write else "view")
    if company:
        auth.require_unscoped_board(request)
    if not settings.policy()["enabled"]:
        raise HTTPException(403, "Work value intelligence is turned off. An administrator can enable it in All settings.")


def _world():
    from ._shared import _world as shared
    return shared()


def period(start="", end="", *, now=None):
    if any(value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) for value in (start, end)):
        raise ValueError("Use UTC calendar dates in YYYY-MM-DD format.")
    now = datetime.fromtimestamp(now or time.time(), timezone.utc)
    left = datetime.fromisoformat(start).replace(tzinfo=timezone.utc) if start else now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    right = datetime.fromisoformat(end).replace(tzinfo=timezone.utc) + timedelta(days=1) if end else now
    if left >= right or (right - left).days > 730:
        raise ValueError("Choose a reporting period of at most two years, with the end after the start.")
    return left.timestamp(), right.timestamp()


def _gone_sources(rows, world):
    """Ids of the rows whose recorded flow run, task or conversation turn no longer exists.

    A read cannot re-derive the ledger without writing, so a row whose source was
    deleted since the last sync is withheld until the sync retires or re-derives
    it. Each source kind costs one bounded lookup, not one per row."""
    from maverick.flow import store

    named = {"flow": set(), "goal": set(), "turn": set()}
    for row in rows:
        for source in row["source"]["sources"]:
            if source["kind"] in named:
                named[source["kind"]].add(str(source["id"]))
    if not any(named.values()):
        return set()
    present = {kind: set() for kind in named}
    if named["flow"]:
        present["flow"] = {run.run_id for run in store.iter_run_metadata()}
    for kind, table in (("goal", "goals"), ("turn", "turns")):
        ids = sorted(int(value) for value in named[kind] if value.isdigit())
        for index in range(0, len(ids), 500):
            chunk = ids[index:index + 500]
            found = world.query(f"SELECT id FROM {table} WHERE id IN ({','.join('?' * len(chunk))})", tuple(chunk))
            present[kind].update(str(row[0]) for row in found)
    return {row["id"] for row in rows if any(
        source["kind"] in named and str(source["id"]) not in present[source["kind"]]
        for source in row["source"]["sources"])}


def records(request, *, scope="own", refresh=True):
    """Work rows for ``request``. ``refresh=True`` records newly observed work
    (a write); ``refresh=False`` is a read of the recorded ledger only, which
    still withholds a row whose recorded source has since been deleted."""
    authority(request, company=scope == "company")
    world = _world()
    rows = service.refresh(world) if refresh else opportunities.conversions(service.WORKS.list(limit=10_001), pin=False)
    if len(rows) > 10_000:
        raise ValueError("Work value history exceeds the supported reporting population.")
    owner = auth.goal_owner_filter(request)
    if scope != "company":
        # One batched read supplies every candidate's source goals; each goal still
        # passes the same per-goal access check, and a missing goal is refused.
        candidates = [row for row in rows if row["owner"] == owner]
        goals = world.get_goals({gid for row in candidates for gid in row["source"]["goal_ids"]})
        rows = [row for row in candidates if all(
            auth.can_access_goal(request, goals.get(gid)) for gid in row["source"]["goal_ids"])]
    authority(request, company=scope == "company")
    rows = [row for row in rows if not row.get("deleted")]
    withheld = _gone_sources(rows, world)
    return [row for row in rows if row["id"] not in withheld]


def read_report(request, *, start="", end="", scope="own", intent="", entity_kind="", entity_id="", refresh=True):
    left, right = period(start, end)
    rows = records(request, scope=scope, refresh=refresh)
    result = calculation.report(rows, start=left, end=right, intent=intent, entity_kind=entity_kind, entity_id=entity_id)
    from maverick.intent_value.reconciliation import bridge
    result["legacy_bridge"] = bridge(_world(), rows, result)
    _label_entities(request, result["by_entity"])
    # The newest recorded change, not the read time: a read reports the ledger as it was recorded.
    stamps = [row["updated_at"] for row in rows if isinstance(row.get("updated_at"), (int, float))]
    result.update(scope=scope, recorded_as_of=max(stamps, default=None), incomplete=any(row.get("_audit_pending") for row in rows))
    # Deprecated alias for clients that still read checked_at. It carries the same value as recorded_as_of.
    from maverick.deprecations import warn_once
    result["checked_at"] = result["recorded_as_of"]
    warn_once("intent_value.checked_at")
    return result


def _label_entities(request, entities):
    from maverick.domain import available_domains
    from maverick.flow import store

    from .flows_api import _can_access_flow

    names = {flow.id: flow.name for flow in store.list_flows() if _can_access_flow(request, flow)}
    domains = available_domains()
    for row in entities:
        kind, identifier = row["kind"], row["id"]
        if kind == "processes":
            row["label"] = names.get(identifier, "Related task contribution" if identifier.startswith("goal:") else "Workflow contribution")
        elif kind == "specialists" and identifier in domains and auth.domain_suites_allowed(request, identifier):
            row["label"] = domains[identifier].description.split(":")[0][:100]
        else:
            row["label"] = identifier.replace("_", " ").capitalize()


def synced_report(request, **kwargs):
    """A report for an authorized write-capable flow: records new work first."""
    def run():
        settings.retry_pending()
        return read_report(request, **kwargs)
    return _call(run)


@router.get("")
def report_endpoint(request: Request, start: str = "", end: str = "", scope: Literal["own", "company"] = "own",
                    intent: str = "", entity_kind: Literal["", "specialists", "agents", "processes"] = "", entity_id: str = ""):
    """The work-value report. ``recorded_as_of`` is when the recorded work last changed. ``checked_at`` is a
    deprecated alias with the same value, kept for existing clients until its removal in 0.3.0."""
    return _call(lambda: read_report(request, start=start, end=end, scope=scope, intent=intent, entity_kind=entity_kind,
                                     entity_id=entity_id, refresh=False))


@router.post("/sync")
def sync_endpoint(request: Request, device_id: str = "local-device"):
    """Record newly observed work and suggestions, and delete the expired Ekko observations of ``device_id``
    (none when the name is not a device name). Reads do not record them; the page calls this before it reads."""
    return _call(lambda: _record(request, device_id))


def _record(request, device_id="local-device"):
    authority(request)
    settings.retry_pending()
    if auth.has_permission(request, "operate"):
        # Expired Ekko observations are deleted by this explicit write; a page read does not delete them.
        from .ekko_routes import _purge_expired_for_device
        _purge_expired_for_device(request, device_id)
    rows = records(request)
    enabled = settings.policy()["recommendations"]
    if enabled:
        opportunities.evaluate(rows, owner=auth.goal_owner_filter(request), capabilities=capabilities(request))
    return {"state": "recorded", "recommendations_enabled": enabled, "checked_at": time.time()}


def work(request, identifier, *, write=False, company=False):
    authority(request, write=write, company=company)
    row = service.WORKS.get(identifier)
    if row is None or row.get("deleted"):
        raise HTTPException(404, "This work item is unavailable.")
    owner = auth.goal_owner_filter(request)
    if row["owner"] != owner and (write or not company):
        raise HTTPException(404, "This work item is unavailable.")
    if row.get("_audit_pending"):
        raise HTTPException(503, "This work item's audit record is pending. Refresh the report to retry before inspecting or changing it.")
    world = _world()
    if not company and any(not auth.can_access_goal(request, world.get_goal(gid)) for gid in row["source"]["goal_ids"]):
        raise HTTPException(404, "This work item's source is no longer accessible.")
    if row["id"] in _gone_sources([row], world):
        raise HTTPException(404, "This work item is unavailable.")
    return row


@router.get("/work/{identifier}")
def work_endpoint(request: Request, identifier: str, scope: Literal["own", "company"] = "own"):
    def read():
        # Reads withhold work whose recorded source was deleted and whose access
        # changed, before any explanation is released, even for an old bookmarked
        # work ID. A deletion is retired durably only by the explicit sync.
        current_rows = records(request, scope=scope, refresh=False)
        row = work(request, identifier, company=scope == "company")
        converted = next((item.get("converted_to") for item in current_rows if item["id"] == identifier), None)
        own = row["owner"] == auth.goal_owner_filter(request)
        result = {key: copy.deepcopy(row[key]) for key in ("id", "label", "revision", "intents", "classification", "estimates")}
        result["corrections"] = row["corrections"] if own else [{"at": item["at"], "before": item["before"], "after": item["after"]} for item in row["corrections"]]
        if not own:
            for estimate in result["estimates"]:
                estimate.pop("actor", None)
                estimate["reason"] = "Original estimate" if estimate["version"] == 1 else "Evidence update or authorized recalculation"
        result.update(converted_to=converted, evidence=row["source"]["evidence"], costs=row["source"]["costs"],
                      provider_evidence=row["source"].get("provider_evidence", []),
                      grouping=row["source"]["grouping"], observed_intents=row["source"]["observed_intents"],
                      cost_limitations=row["source"]["cost_limitations"], can_correct=own and auth.has_permission(request, "operate"),
                      confirmation_enabled=settings.settings()["completion_confirmation"],
                      confirmation_count=len(row["confirmations"]), sources=[])
        if own:
            for source in row["source"]["sources"]:
                if source["kind"] == "goal" and auth.can_access_goal(request, _world().get_goal(int(source["id"]))):
                    result["sources"].append({"label": "Open original task", "href": "/chat/goal/" + source["id"]})
                elif source["kind"] == "flow":
                    result["sources"].append({"label": "Inspect workflow execution", "href": f"/flows/{quote(source['flow_id'], safe='')}/runs/{quote(source['id'], safe='')}"})
        return result
    return _call(read)


@router.post("/work/{identifier}/correct")
def correct_endpoint(request: Request, identifier: str, body: CorrectionIn):
    def run():
        work(request, identifier, write=True)
        return service.correct(identifier, intents=body.intents, size=body.size, units=body.units, expected_revision=body.revision,
            reason=body.reason, actor=auth.caller_principal(request) or "local", guard=lambda: work(request, identifier, write=True))
    return _mutation(_call(run))


def _mutation(row):
    if row is None:
        raise HTTPException(404, "This record is unavailable.")
    return {"id": row["id"], "revision": row["revision"], "state": "audit_pending" if row.get("_audit_pending") else "saved"}


@router.post("/work/{identifier}/recalculate")
def recalculate_endpoint(request: Request, identifier: str, body: RevisionIn):
    def run():
        work(request, identifier, write=True)
        return service.recalculate(identifier, expected_revision=body.revision, actor=auth.caller_principal(request) or "local",
                                   guard=lambda: work(request, identifier, write=True))
    return _mutation(_call(run))


@router.post("/work/{identifier}/confirm")
def confirm_endpoint(request: Request, identifier: str, body: RevisionIn):
    def run():
        work(request, identifier, write=True)
        return service.confirm(identifier, expected_revision=body.revision, actor=auth.caller_principal(request) or "local",
                               guard=lambda: work(request, identifier, write=True))
    return _mutation(_call(run))


@router.get("/settings")
def settings_endpoint(request: Request):
    authority(request)
    return _call(lambda: {**settings.settings(), "can_edit": auth.has_permission(request, "admin"),
                         "can_company": auth.caller_suites(request) is None})


@router.put("/settings")
def save_settings_endpoint(request: Request, body: SettingsIn):
    authority(request, admin=True)
    _call(lambda: _record_before_assumptions(request))
    return _mutation(_call(lambda: settings.save_settings(**body.model_dump(exclude={"revision"}),
        expected_revision=body.revision, actor=auth.caller_principal(request) or "local", guard=lambda: authority(request, admin=True))))


@router.get("/benchmarks")
def benchmarks_endpoint(request: Request):
    authority(request)
    def read():
        rows = []
        for item in taxonomy.catalog():
            override = settings.BENCHMARKS.get("IVB-" + item["id"].replace(".", "-"))
            rows.append({**item, "benchmark": settings.benchmark(item["id"]), "revision": override["revision"] if override else 0})
        return {"benchmarks": rows, "can_edit": auth.has_permission(request, "admin")}
    return _call(read)


@router.put("/benchmarks/{identifier}")
def benchmark_endpoint(request: Request, identifier: str, body: BenchmarkIn):
    authority(request, admin=True)
    _call(lambda: _record_before_assumptions(request))
    return _mutation(_call(lambda: settings.save_benchmark(identifier, **body.model_dump(exclude={"revision"}),
        expected_revision=body.revision, actor=auth.caller_principal(request) or "local", guard=lambda: authority(request, admin=True))))


def capabilities(request):
    from maverick.domain import available_domains
    from maverick.flow import store

    from .flows_api import _can_access_flow

    out = []
    for flow in store.list_flows():
        if _can_access_flow(request, flow):
            from maverick.flow.evolve import maybe_propose

            classified = taxonomy.classify(" and ".join(node.brief for node in flow.nodes.values() if node.kind == "agent") or flow.name)
            out.append({"id": flow.id, "kind": "process", "label": flow.name,
                        "version": flow.version, "revision": flow.revision,
                        "intents": classified["intents"], "href": "/flows/designer/" + quote(flow.id, safe=""),
                        "learning_evidence": [{"node_id": item.node_id, "reason": item.reason,
                            "support": item.n, "applicable": item.applicable,
                            "blocking_reason": item.blocking_reason} for item in maybe_propose(flow)]})
    allowed = auth.domain_suites_checker(request)  # The caller's grants are read once for the whole catalogue.
    for name, profile in available_domains().items():
        if not allowed(name):
            continue
        intents = _domain_intents(profile.description)
        if intents:
            out.append({"id": name, "kind": "specialist", "label": profile.description.split(":")[0][:100],
                        "intents": list(intents), "href": "/chat?specialist=" + quote(name, safe="")})
    return out


@functools.lru_cache(maxsize=4096)
def _domain_intents(description):
    """The business activities a specialist's description names: a pure function
    of its text, so the catalogue's 2,000-odd descriptions are parsed once per process."""
    return tuple(taxonomy.classify(description)["intents"])


def synced_opportunities(request, *, include_decided=False, device_id="local-device"):
    """Suggestions for an authorized write-capable flow: records them first."""
    return _call(lambda: _opportunities(request, include_decided=include_decided, device_id=device_id, persist=True))


@router.get("/opportunities")
def opportunities_endpoint(request: Request, include_decided: bool = False, device_id: str = "local-device"):
    return _call(lambda: _opportunities(request, include_decided=include_decided, device_id=device_id, persist=False))


def _record_before_assumptions(request):
    """Records observed work, and retries pending receipts, before assumptions change.

    Work recorded before the save keeps the assumptions in force when it was seen.
    Work that finishes while the save runs is recorded afterwards under the new
    assumptions; this is not a lock across the two steps."""
    settings.retry_pending()
    records(request)


def _opportunities(request, *, include_decided, device_id, persist):
    authority(request)
    if persist:
        settings.retry_pending()
    enabled = settings.policy()["recommendations"]
    rows = records(request, refresh=persist) if enabled else []
    proposals = opportunities.evaluate(rows, owner=auth.goal_owner_filter(request), capabilities=capabilities(request),
                                       persist=persist) if enabled else []
    visible = []
    for proposal in proposals:
        if proposal.get("_audit_pending") or (not include_decided and proposal["status"] in {"declined", "deferred"}):
            continue
        outcome = opportunities.outcome(proposal, rows, pin=persist)
        proposal = {key: value for key, value in proposal.items() if key not in {"owner", "_audit_pending"}}
        proposal["outcome"] = outcome
        visible.append(proposal)
    from .intent_value_discovery import read as discovery
    external = discovery(request, device_id) if settings.policy()["recommendations"] else None
    # Discovery can overlap an administrator changing the policy. Release
    # neither native nor external suggestions after that revocation.
    enabled = settings.policy()["recommendations"]
    if not enabled or external is None:
        external = {"state": "off", "patterns": [],
                    "notice": "Reusable-work recommendations are turned off. An administrator can review this setting."}
    return {"opportunities": visible if enabled else [], "external_observations": external,
            "recommendations_enabled": enabled,
            "notice": "Potential value and forecasts are separate from executed work. You choose whether to use, draft, defer or keep your current process." if enabled else
                "Reusable-work recommendations are turned off. An administrator can review this setting."}


def recommendation(request, identifier, *, write=False):
    authority(request, write=write)
    if write and not settings.policy()["recommendations"]:
        raise HTTPException(403, "Reusable-work recommendations are turned off. An administrator can review this setting.")
    row = opportunities.RECOMMENDATIONS.get(identifier)
    if row is None or row["owner"] != auth.goal_owner_filter(request):
        raise HTTPException(404, "This recommendation is unavailable.")
    if row.get("_audit_pending"):
        opportunities.RECOMMENDATIONS.retry_pending(limit=100)
        row = opportunities.RECOMMENDATIONS.get(identifier)
        if row.get("_audit_pending"):
            raise HTTPException(503, "This recommendation is waiting for its audit record. Refresh before acting.")
    return row


@router.post("/opportunities/{identifier}/decision")
def decision_endpoint(request: Request, identifier: str, body: DecisionIn):
    recommendation(request, identifier, write=True)
    return _mutation(_call(lambda: opportunities.decide(identifier, decision=body.decision, expected_revision=body.revision,
        actor=auth.caller_principal(request) or "local", manual_steps=body.manual_steps,
        guard=lambda: recommendation(request, identifier, write=True))))


@router.post("/opportunities/{identifier}/build")
def build_endpoint(request: Request, identifier: str, body: RevisionIn):
    from .intent_value_builder import build
    return _call(lambda: build(request, identifier, body.revision))


@router.post("/opportunities/{identifier}/use")
def use_endpoint(request: Request, identifier: str, body: RevisionIn):
    from .intent_value_handoff import select
    return _call(lambda: select(request, identifier, body.revision))
