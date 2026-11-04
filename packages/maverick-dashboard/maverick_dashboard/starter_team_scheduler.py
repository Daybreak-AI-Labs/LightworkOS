"""Request-free worker for exact approved starter-team inbox items.

No request object, bearer token or ambient administrator is retained. Every
boundary resolves the saved person's current permissions and workspace. Merely
starting the application grants no team permission to run or spend.
"""
from __future__ import annotations

import logging
import threading
import time

from maverick import config, shoring
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import current_tenant_id_strict, tenant_scope

from . import auth, workspace_tenants
from .vendor_onboarding_composition import _budget_authority, _role_authority

log = logging.getLogger(__name__)
_lock = threading.Lock()
_stop = None
_thread = None
_stopping = False
_cursor = ""
_runtime_cursors = {}
_POLL_SECONDS = 30


def _workspace_current(context):
    from .trc_stock_evidence_composition import source_workspace_authorized

    actor, tenant = context.actor, context.tenant
    for source in ("principal_selection", "principal_isolation", "operator_floor"):
        if not source_workspace_authorized(tenant, actor, source):
            continue
        generation = 0
        if source == "principal_selection":
            selected, generation = workspace_tenants.get_selection_binding(actor)
            if selected != tenant:
                continue
        pin = "sha256:" + digest({"schema": "lightwork.workspace-authority.v1",
            "principal": actor, "tenant": tenant, "source": source, "generation": generation})
        if pin == context.workspace_authority:
            return True
    return False


def authorize_worker(context, operation, team):
    """Current owner authority; False on stale policy, membership or selection."""
    from maverick.departments import department_entitled
    from maverick.domain import suites_for_domain
    from maverick.tenant.registry import assert_tenant_active

    from . import ui_visibility

    if operation not in {"read", "run", "runtime_read", "runtime_start"} or context.human:
        return False
    if _stopping and operation in {"run", "runtime_start"}:
        return False
    try:
        if (current_tenant_id_strict() != context.tenant or not shoring.enabled()
                or config.config_source_errors(include_tenant=True)):
            return False
        assert_tenant_active(context.tenant)
        owner, _user, suites = auth.stored_automation_identity(context.actor)
        role = auth.role_for_principal(owner)
        if (not owner or owner != context.resource_owner or owner != context.credential_authority
                or role != context.authorization_role
                or _role_authority(role) != context.authorization_policy
                or _budget_authority(context.tenant) != context.budget_authority
                or not _workspace_current(context)):
            return False
        if not ui_visibility.is_visible(ui_visibility.page_for("/starter-teams"), role):
            return False
        required = {suite for name in team["specialists"] for suite in suites_for_domain(name)}
        allowed = all((suites is None or suite in suites) and department_entitled(suite, tenant=context.tenant)
                      for suite in required)
        # This callback also runs inside the durable effect guard. A stop that
        # arrived during the current-authority reads must close that admission.
        return allowed and not (_stopping and operation in {"run", "runtime_start"})
    except Exception:
        return False


def runtime_cycle(tenant, *, runtime_factory=None):
    """Continue at most five explicitly started direct workflows, one stage each."""
    from maverick.starter_team_runtime import StarterTeamRuntime, worker_runtimes
    from maverick.starter_teams import StarterTeamService, get_team

    register_runtime_authorizer()
    if _stopping or current_tenant_id_strict() != tenant or not shoring.enabled():
        return 0
    advanced = attempted = 0
    rows = sorted(worker_runtimes(), key=lambda row: row["id"])
    cursor = _runtime_cursors.get(tenant, "")
    rotation = [row for row in rows if row["id"] > cursor] + [row for row in rows if row["id"] <= cursor]
    for row in rotation:
        if _stopping or attempted >= 5:
            break
        review = row["review"]
        # A scheduled occurrence belongs exclusively to its scheduler, including
        # its pause, due-time and aggregate-budget boundaries.
        if row.get("schedule_id") is not None or review.get("schedule_id") is not None:
            continue
        context = ServiceContext(**review["context"], human=False)
        team = get_team(row["team_id"])
        if not authorize_worker(context, "runtime_start", team):
            continue
        service = StarterTeamService(context, authorize_worker, workspace_id=row["workspace"])
        runtime = (runtime_factory or StarterTeamRuntime)(service)
        if _stopping:
            break
        attempted += 1
        _runtime_cursors[tenant] = row["id"]
        try:
            runtime.start_runtime(review, confirmed=False)
            advanced += 1
        except Exception as exc:
            log.warning("Starter team workflow held for review (%s)", type(exc).__name__)
    return advanced


def workspace_cycle(tenant, *, schedule_factory=None, now=None):
    """Advance at most five schedules in one tenant, one runtime stage each."""
    from maverick.starter_team_schedule import StarterTeamScheduleService, worker_schedules

    register_runtime_authorizer()
    if _stopping or current_tenant_id_strict() != tenant or not shoring.enabled():
        return 0
    current = time.time() if now is None else now
    advanced = attempted = 0
    # The store's administrative enumerator is only called within the trusted
    # tenant loop. Each row is independently reauthorized before any execution.
    rows = worker_schedules()
    rows.sort(key=lambda row: (row.get("next_due", 0), row["id"]))
    for row in rows:
        if _stopping or attempted >= 5:
            break
        definition = row["definition"]
        if (row["paused"] or row["status"] == "awaiting_confirmation"
                or current < definition["start_at"] or current >= definition["end_at"]
                or (not row.get("active_item_id") and current < row["next_due"])):
            continue
        context = ServiceContext(**definition["context"], human=False)
        from maverick.starter_teams import get_team
        if not authorize_worker(context, "run", get_team(row["team_id"])):
            continue
        factory = schedule_factory or StarterTeamScheduleService
        service = factory(context, authorize_worker, workspace_id=row["workspace"])
        if not row.get("active_item_id") and not any(item["status"] == "approved" for item in service.list_items(row["id"])):
            continue
        if _stopping:
            break
        key = "worker:" + digest({"schedule": row["id"], "poll": int(current // _POLL_SECONDS)})
        attempted += 1
        try:
            service.tick(row["id"], idempotency_key=key)
            advanced += 1
        except Exception as exc:
            # The durable case/runtime owns recovery. The next poll re-reads it;
            # no exception here is interpreted as permission to retry a goal.
            log.warning("Starter team schedule held for review (%s)", type(exc).__name__)
    return advanced


def cycle():
    global _cursor
    from maverick.tenant.registry import list_tenants

    from .automation_queue import _configured_tenant_floor

    if _stopping or config.config_source_errors(include_tenant=False) or not shoring.enabled():
        return 0
    tenants = {row.id for row in list_tenants() if row.active}
    floor = _configured_tenant_floor()
    if floor:
        tenants.add(floor)
    ordered = sorted(tenants)
    rotation = [value for value in ordered if value > _cursor] + [value for value in ordered if value <= _cursor]
    advanced = 0
    for tenant in rotation[:10]:
        if _stopping:
            break
        with tenant_scope(tenant=tenant):
            for advance in (workspace_cycle, runtime_cycle):
                if _stopping:
                    break
                try:
                    advanced += advance(tenant)
                except Exception as exc:
                    log.warning("Starter team workspace check unavailable (%s)", type(exc).__name__)
        _cursor = tenant
    return advanced


def _loop(stop):
    while not stop.wait(_POLL_SECONDS):
        try:
            cycle()
        except Exception as exc:
            log.warning("Starter team worker held (%s)", type(exc).__name__)


def start_starter_team_scheduler():
    global _stop, _thread, _stopping
    register_runtime_authorizer()
    with _lock:
        if _thread is not None and _thread.is_alive():
            return not _stopping
        if not shoring.enabled():
            return False
        _stopping = False
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop,), name="starter-team-schedules", daemon=True)
        _thread.start()
        return True


def stop_starter_team_scheduler(timeout=5.0, wait=True):
    global _stop, _thread, _stopping
    with _lock:
        # Signalling must not wait for an effect fence or provider. The current
        # authority callback observes this flag at the existing guarded write.
        _stopping = True
        thread = _thread
        if _stop is not None:
            _stop.set()
    if wait and thread is not None:
        thread.join(timeout=max(0.0, min(float(timeout), 30.0)))
    with _lock:
        if thread is _thread and (thread is None or not thread.is_alive()):
            _thread = _stop = None


def worker_status():
    return {"running": bool(_thread and _thread.is_alive()),
            "meaning": "Continues started specialist workflows and exact approved schedule inputs while Lightwork is running; outside actions remain unavailable."}


def register_runtime_authorizer():
    """Bind queued native goals to fresh authority, even with scheduling off."""
    from maverick.starter_team_runtime import register_worker_authorizer

    register_worker_authorizer(authorize_worker)
