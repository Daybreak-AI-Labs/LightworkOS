"""Read-only current acceptance and pricing from authorized business records."""
from __future__ import annotations

import math
from dataclasses import asdict

from .auth import (
    caller_principal,
    can_access_goal,
    domain_suites_allowed,
    goal_owner_filter,
    suite_allowed,
)
from .outcome_pilots import digest

PREPARED = "Prepared for a workflow pilot. Start this task after the pilot plan is frozen."
_MAX_PROVIDER_RECEIPTS = 2000


def _is_prepared(goal, episodes):
    return not episodes and ((goal.status == "pending" and not goal.result)
                             or (goal.status == "blocked" and goal.result == PREPARED))


def _provider_receipts(work_item_id: str) -> tuple[list[dict], str]:
    from maverick.provider_cost_cap import reservation_catalogue_for_work_item

    catalogue = reservation_catalogue_for_work_item(
        work_item_id,
        limit=_MAX_PROVIDER_RECEIPTS,
    )
    return [asdict(receipt) for receipt in catalogue.receipts], catalogue.version


def _can_read_source(request, goal, *, independent_review=False):
    if can_access_goal(request, goal):
        return True
    if not independent_review or getattr(request.state, "paired_device_id", None):
        return False
    # An independent decision mutates the pilot, not its underlying task.
    # Its read-only resolver still requires the same exact expiring content
    # grant and confirmed per-read audit receipt as a GET. Never change the
    # request method or grant the reviewer task mutation/publication authority.
    from .auth import has_global_permission
    from .content_access import may_read_employee_content

    if not has_global_permission(request, "admin"):
        return False
    return may_read_employee_content(request, goal.owner or "",
                                     resource_kind="goal", resource_id=str(goal.id))


def goal_source(request, reference, *, independent_review=False):
    from .app import _world

    world = _world()
    goal = world.get_goal(int(reference))
    if goal is None or not _can_read_source(request, goal, independent_review=independent_review) or not domain_suites_allowed(request, goal.domain):
        raise LookupError("Task unavailable.")
    episodes = world.list_episodes(goal_id=goal.id, limit=2001)
    if len(episodes) > 2000:
        raise ValueError("Task history exceeds the measurement limit.")
    signoff = world.signoff_for(goal.id) or {}
    reviewer = str(signoff.get("decided_by") or "")
    human = reviewer.startswith("user:") or (caller_principal(request) is None and reviewer == "operator")
    values = [e.cost_dollars for e in episodes]
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("Task pricing history is unavailable.")
    provider_receipt_error = None
    provider_catalog_version = None
    try:
        provider_receipts, provider_catalog_version = _provider_receipts(
            f"goal:{goal.id}",
        )
    except Exception as exc:
        provider_receipts = []
        provider_receipt_error = type(exc).__name__
    source = {"title": goal.title, "href": f"/chat/goal/{goal.id}", "status": goal.status,
        "input_version": digest([goal.id, goal.title, goal.description, goal.domain]),
        "unstarted": _is_prepared(goal, episodes),
        "first_started_at": min((e.started_at for e in episodes), default=None),
        "finished": not _is_prepared(goal, episodes) and goal.status in {"done", "blocked", "cancelled", "failed"},
        "accepted": goal.status == "done" and signoff.get("decision") == "approved" and human,
        "reviewer": reviewer if human else None,
        "runtime_cost_usd": sum(values) if episodes else None,
        "runtime_cost_basis": "recorded episode prices; provider invoice unverified",
        "provider_cost_receipts": provider_receipts,
        "provider_cost_receipts_complete": (
            provider_receipt_error is None and (bool(provider_receipts) or not episodes)
        ),
        "provider_cost_receipts_catalog_version": provider_catalog_version,
        "provider_cost_receipts_error": provider_receipt_error,
        "sample": False}
    # Provider reservations are an independently versioned accounting stream.
    # Settling, claiming, or pruning one must not make the task's technical
    # outcome observation stale; the bridge advances those receipts by their
    # own opaque reference and ledger state.
    version_source = {
        key: value for key, value in source.items()
        if key not in {
            "provider_cost_receipts",
            "provider_cost_receipts_complete",
            "provider_cost_receipts_catalog_version",
            "provider_cost_receipts_error",
        }
    }
    source["version"] = digest([
        version_source, goal.result, signoff, [vars(e) for e in episodes],
    ])
    return source


def vendor_source(request, reference):
    from .vendor_onboarding_api import _binding, _call

    row = _call(_binding(request), "get", reference)
    outcome, metrics = row.get("outcome") or {}, row.get("metrics") or {}
    sample = (row.get("integration_mode") or {}).get("tickets") != "live_unverified"
    reviewer = str(outcome.get("reviewer") or "")
    provider_receipt_error = None
    provider_catalog_version = None
    try:
        provider_receipts, provider_catalog_version = _provider_receipts(
            f"vendor:{row['id']}",
        )
    except Exception as exc:
        provider_receipts = []
        provider_receipt_error = type(exc).__name__
    source = {"title": row["vendor_name"], "href": "/third-party/vendor-onboarding", "status": row["stage"],
        "input_version": digest({k: row.get(k) for k in
            ("id", "vendor_name", "purpose", "project", "document_ids", "uploads", "freshness_days")}),
        "unstarted": row["stage"] == "intake" and not row.get("evidence") and not metrics.get("document_reads") and not row.get("review_history"),
        "first_started_at": (row.get("evidence") or {}).get("collected_at"),
        "finished": row["stage"] in {"accepted", "customer_rejected"},
        "accepted": not sample and row["stage"] == "accepted" and outcome.get("accepted") is True
            and outcome.get("execution_completed") is True and outcome.get("validation") == "verified_external_record"
            and reviewer.startswith("user:"),
        "reviewer": reviewer or None, "runtime_cost_usd": metrics.get("execution_cost_usd"),
        "runtime_cost_basis": metrics.get("cost_basis"), "sample": sample,
        "provider_cost_receipts": provider_receipts,
        "provider_cost_receipts_complete": (
            provider_receipt_error is None and bool(provider_receipts)
        ),
        "provider_cost_receipts_catalog_version": provider_catalog_version,
        "provider_cost_receipts_error": provider_receipt_error}
    version_source = {key: value for key, value in source.items() if key not in {
        "provider_cost_receipts", "provider_cost_receipts_complete",
        "provider_cost_receipts_catalog_version",
        "provider_cost_receipts_error",
    }}
    source["version"] = digest([version_source, row["revision"], outcome])
    return source


def resolve(request, kind, reference, *, independent_review=False):
    if kind == "goal":
        return goal_source(request, reference, independent_review=independent_review)
    if kind == "vendor":
        return vendor_source(request, reference)
    raise ValueError("Choose a task or vendor case.")


def choices(request):
    from .app import _deliverable_specs, _world
    from .vendor_onboarding_api import _binding, _call

    items, coverage = [], []
    try:
        from maverick.world_model import episodes_by_goal_batch

        world = _world()
        goals = world.list_goals(owner=goal_owner_filter(request), limit=201, order="desc")
        visible = [goal for goal in goals[:200]
                   if can_access_goal(request, goal) and domain_suites_allowed(request, goal.domain)]
        # One batched read of each visible goal's newest run, not one query each.
        latest = episodes_by_goal_batch(world, [goal.id for goal in visible], per_goal=1)
        for goal in visible:
            episodes = (latest[goal.id] if latest is not None and goal.id in latest
                        else world.list_episodes(goal_id=goal.id, limit=1))
            if _is_prepared(goal, episodes):
                items.append({"kind": "goal", "reference": str(goal.id), "label": goal.title})
        coverage.append({"kind": "goal", "status": "partial" if len(goals) > 200 else "current"})
    except Exception:
        coverage.append({"kind": "goal", "status": "unavailable"})
    try:
        rows = _call(_binding(request), "list")
        for row in rows[:200]:
            if row["stage"] == "intake" and not row.get("evidence") and not (row.get("metrics") or {}).get("document_reads"):
                items.append({"kind": "vendor", "reference": row["id"], "label": row["vendor_name"]})
        coverage.append({"kind": "vendor", "status": "partial" if len(rows) > 200 else "current"})
    except Exception:
        coverage.append({"kind": "vendor", "status": "unavailable"})
    specialists = [{"domain": s["domain"], "label": s.get("name") or s["domain"].replace("_", " ").title()}
                   for s in _deliverable_specs() if s.get("gate") and domain_suites_allowed(request, s["domain"])]
    return {"items": items, "coverage": coverage, "specialists": specialists}


def prepare_task(request, body, context, *, before_write=None):
    from maverick.domain import enabled_domains, suites_for_domain

    from .app import _deliverable_specs, _world

    domain = body["domain"]
    profile = enabled_domains().get(domain)
    if profile is None or any(
        not suite_allowed(request, suite) for suite in suites_for_domain(domain, profile)
    ):
        raise PermissionError("Choose an agent or specialist that is turned on in your permitted departments.")
    if not any(s["domain"] == domain and s.get("gate") for s in _deliverable_specs()):
        raise ValueError("Choose an agent or specialist whose result requires approval.")
    world, actor = _world(), caller_principal(request) or ""
    channel, key = "outcome-pilot-preparation", digest([context, body["operation_id"]])

    def previous(identifier):
        goal = world.get_goal(identifier)
        if goal is None or not can_access_goal(request, goal):
            raise ValueError("The prepared task is unavailable. No new task was started.")
        if (goal.title, goal.description, goal.domain, goal.owner) != (body["title"], body["description"], domain, actor):
            raise ValueError("This preparation reference belongs to different task inputs.")
        return {"id": goal.id, "title": goal.title, "href": f"/chat/goal/{goal.id}"}

    identifier = world.lookup_processed_message(channel, key)
    if identifier is not None:
        return previous(identifier)
    if before_write is not None:
        from maverick.attachment_submissions import SubmissionStore

        # The existing admission writer retains goal, blocked state, original
        # marker and receipt in one native SQLite/PostgreSQL transaction.
        receipt = SubmissionStore(world).create(
            token="outcome-pilot-preparation:" + key,
            fingerprint=digest([context, actor, body]), owner=actor,
            title=body["title"], description=body["description"], domain=domain,
            manifest=[], kind="outcome-pilot-preparation",
            initial_status="blocked", initial_result=PREPARED,
            processed_message={"channel": channel, "key": key},
            before_create=lambda _connection: before_write())
        return previous(receipt["goal_id"])
    identifier = world.create_goal(body["title"], body["description"], owner=actor, domain=domain)
    world.set_goal_status(identifier, "blocked", result=PREPARED)
    if not world.mark_message_processed(channel, key, goal_id=identifier):
        world.set_goal_status(identifier, "cancelled", result="Duplicate preparation; use the original task.")
        winner = world.lookup_processed_message(channel, key)
        if winner is None:
            raise ValueError("Task preparation is indeterminate. Refresh before retrying.")
        return previous(winner)
    return previous(identifier)
