"""Request-less poll-and-fire for event triggers.

Shared by the HTTP endpoint (``POST /api/v1/event-triggers/poll``) and the
background automation scheduler (app lifespan). Each polls its sources, fires
the bound template per new event -- the event's fields filling the template's
declared params -- and advances the cursor at most once. ``fire(goal_id)``
schedules the actual run through the same durable, idempotent queue in both
the request path and the scheduler. Observed event batches remain durable until
delivery and cursor disposition complete.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from typing import Any


class EventSourceAdmissionError(RuntimeError):
    """A stored event-source configuration crossed a host-resource boundary."""


def event_source_authority(source: str, config: dict) -> str:
    """Return the request authority required to admit one event source.

    This classification is request-independent so the HTTP create/manual-poll
    paths and request-less scheduler cannot disagree about which sources touch
    process credentials or the local filesystem.
    """
    cfg = dict(config or {})
    uses_tenant_oauth = bool(str(cfg.get("provider") or "").strip())
    uses_process_github_token = source == "github_issues" and not uses_tenant_oauth
    if source == "imap_email" or source == "file_dir" or uses_process_github_token:
        return "global_admin"
    from maverick.automation_connected_events import SOURCES
    if uses_tenant_oauth or source in SOURCES:
        return "tenant_admin"
    return "operate"


def admit_event_source_config(source: str, config: dict) -> dict:
    """Return a poll-safe copy of ``config`` or fail closed.

    Relative ``file_dir`` paths are rooted in the active tenant's dedicated
    ``event-input`` directory. Existing symlinks/junctions are resolved on every
    admission, so a legacy row, a post-save edit, or a reparse point that now
    escapes that root is refused before the source can enumerate host files.
    The returned path is canonical, ensuring the poll uses exactly the path
    that was checked.
    """
    cfg = dict(config or {})
    if source != "file_dir":
        return cfg

    import os
    from pathlib import Path

    from maverick.paths import data_dir

    raw_path = str(cfg.get("path") or "").strip()
    if not raw_path:
        raise EventSourceAdmissionError("file_dir source needs a 'path'")
    glob = str(cfg.get("glob") or "*")
    glob_path = Path(glob)
    if glob_path.is_absolute() or ".." in glob_path.parts:
        raise EventSourceAdmissionError(
            "file_dir glob must be relative and cannot traverse parent directories"
        )

    try:
        configured_root = data_dir("event-input")
        is_junction = getattr(configured_root, "is_junction", lambda: False)
        if configured_root.exists() and (
            configured_root.is_symlink() or is_junction()
        ):
            raise EventSourceAdmissionError(
                "tenant event-input root must not be a symlink or reparse point"
            )
        root = configured_root.resolve(strict=False)
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve(strict=False)
    except EventSourceAdmissionError:
        raise
    except (OSError, RuntimeError) as exc:
        raise EventSourceAdmissionError(
            "file_dir path could not be resolved safely"
        ) from exc
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EventSourceAdmissionError(
            f"file_dir path must stay under the tenant event-input root: {root}"
        ) from exc
    cfg["path"] = os.fspath(candidate)
    return cfg


def _require_stored_event_source_authority(owner: str, authority: str) -> None:
    """Revalidate host-resource authority for request-less polling.

    ``stored_automation_identity`` proves ordinary operate authority. Sources
    that consume a tenant OAuth credential or a deployment-wide process/file
    resource retain their stronger admin requirement on every scheduled poll;
    durable trigger possession is not a perpetual privilege grant.
    """
    if authority == "operate":
        return


    from maverick_dashboard import rbac
    from maverick_dashboard.auth import (
        AutomationAuthorizationError,
        anonymous_local_access_allowed,
        global_role_for_principal,
        role_for_principal,
    )

    if anonymous_local_access_allowed():
        return
    # Static-token requests deliberately persist this reserved execution owner;
    # the token itself is the deployment-global operator credential.
    from ._shared import dashboard_token

    if owner == "user:local" and dashboard_token():
        return
    role = (
        global_role_for_principal(owner)
        if authority == "global_admin"
        else role_for_principal(owner)
    )
    if "admin" not in rbac.permissions_for(role):
        raise AutomationAuthorizationError("trigger authorization unavailable")


def _safe_error(exc: BaseException, *, fallback: str = "operation failed") -> str:
    """Return a bounded, secret-scrubbed error safe for API notes/history."""
    from maverick.secrets import scrub

    message = scrub(str(exc)).strip()[:500]
    return message or fallback


def _trigger_key(trig: dict, *, legacy_mail: bool = False) -> str:
    import hashlib
    import json
    # Include creation identity AND approved binding. Recreating/editing a
    # trigger is a new admission namespace, while cursor/cadence updates are not.
    fields = ("name", "created", "tenant", "owner", "source", "config", "params",
              "template", "template_revision", "flow", "flow_owner", "flow_revision")
    identity = {k: trig.get(k) for k in fields}
    # Pre-gate IMAP admissions and batches have no authenticated-sender proof.
    # A new namespace prevents an old UID/goal receipt from being reused after
    # an owner configures sender checks for the same inbox.
    if trig.get("source") == "imap_email" and not legacy_mail:
        identity["mail_auth_protocol"] = "trusted_dmarc_v1"
    encoded = json.dumps(identity, sort_keys=True,
                         separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _verified_mail_batch(batch: dict | None) -> bool:
    return bool(batch and isinstance(batch.get("events"), list)
                and isinstance(batch.get("event_ids"), list)
                and len(batch["events"]) == len(batch["event_ids"])
                and batch["events"] and all(
        isinstance(event, dict)
        and event.get("_sender_auth") == "trusted_dmarc_pass"
        for event in batch["events"]
    ))


def _publish_cursor(trig, cursor, cursor_format=1):
    from maverick_dashboard import event_triggers_store
    if not event_triggers_store.set_cursor(
        trig["name"], cursor, tenant=str(trig.get("tenant") or ""),
        expected_cursor=trig["cursor"], expected_generation=_trigger_key(trig),
        cursor_format=cursor_format,
        accept_peer_progress=True,
    ):
        raise RuntimeError("trigger changed during polling; cursor publication refused")
    trig["_cursor_publication_completed"] = True


def _dispatch_admission(world, key, goal_id, state, fire, summary, durable):
    from maverick import event_admission
    if state in {"delivered", "retired"}:
        return
    if world.get_goal(goal_id) is None:
        # Erasure is authoritative. Keep a terminal tombstone, rather than
        # recreating erased work or starving every future event on the trigger.
        event_admission.transition(world, key, state, "retired")
        summary["notes"].append(f"retired delivery for removed goal {goal_id}")
        return
    if state == "dispatching":
        raise event_admission.EventDispatchUncertain(
            "event dispatch outcome is unconfirmed; reconcile the existing goal")
    if not durable and not event_admission.transition(world, key, "pending", "dispatching"):
        raise event_admission.EventDispatchUncertain("event dispatch is already claimed")
    # Production dispatch is a permanent, transactional queue admission keyed by
    # tenant+goal. It can safely retry even when acknowledgement was lost. Other
    # callbacks remain held on an exception; never infer safety from an error.
    fire(goal_id)
    event_admission.transition(world, key, "pending" if durable else "dispatching", "delivered")
    if goal_id not in summary["fired"]:
        summary["fired"].append(goal_id)


def _fire_template(world, trig, tpl, events, owner, fire, summary, durable=False,
                   event_ids=None) -> None:
    """Render the bound template per event (event fields fill DECLARED params)
    and fire a goal. Mutates ``summary``."""
    from maverick_dashboard import trigger_events_store
    name = trig["name"]
    declared = set(tpl.params) - {key for key, spec in tpl.parameter_schema.get("fields", {}).items() if spec["type"] == "connection"}
    trigger_key = _trigger_key(trig)
    entries = []
    for index, event in enumerate(events):
        if trig.get("source") == "imap_email" and (
            event_ids is None or event.get("_sender_auth") != "trusted_dmarc_pass"
        ):
            raise RuntimeError("Email sender verification is required before work can start")
        if trig.get("source") == "form":
            from .form_inputs import (
                FormInputError,
                public_form_fields,
                validate_public_form_fields,
            )

            try:
                allowed = public_form_fields(tpl, trig.get("params") or {}, is_flow=False)
                validate_public_form_fields(
                    event, allowed, trusted_keys=frozenset({"_seq", "_ts"}),
                )
            except FormInputError as exc:
                raise RuntimeError(f"form submission needs attention: {exc}") from exc
        params = dict(trig.get("params") or {})
        for k, v in event.items():      # event fields fill DECLARED params only
            if k in declared and not (trig.get("source") == "imap_email" and k == "_sender_auth"):
                params[str(k)] = str(v)[:2000]
        try:
            from maverick.template_connections import parameters as connection_parameters
            _, refs = connection_parameters(tpl, owner, params)
            title, description = tpl.render_for(owner, **params)
        except ValueError as e:         # a required param the event didn't supply
            detail = _safe_error(e, fallback="template parameters are invalid")
            if trig.get("source") == "form":
                # A public caller was already told this submission was accepted.
                # Keep its row pending rather than silently retire it.
                raise RuntimeError(f"form submission needs attention: {detail}") from e
            summary["notes"].append(f"skipped an event: {detail}")
            trigger_events_store.record(
                name,
                owner,
                trigger_events_store.EVENT_SKIPPED,
                note=detail,
            )
            continue
        key = _event_key(trigger_key, event, event_ids[index] if event_ids is not None else None)
        entries.append((key, title[:200], description[:8000], refs))
    from maverick import event_admission
    admissions = event_admission.admit_batch(
        world, entries, owner=owner, origin=name, trigger_key=trigger_key,
        origin_kind="event_v2")
    for key, goal_id, state in admissions:
        _dispatch_admission(world, key, goal_id, state, fire, summary, durable)


def _event_key(name: str, event: dict, event_id: str | None = None) -> str:
    """A stable idempotency key for an event: the trigger name + the event's own
    id (or a hash of its fields), so a re-delivered event doesn't fire twice."""
    import hashlib
    import json as _json
    eid = event_id
    if eid is None:
        eid = event.get("id", event.get("guid", event.get("uid")))
    if eid is None:
        eid = _json.dumps(event, sort_keys=True, default=str)
    encoded = _json.dumps([name, eid], separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _fire_flow(trig, events, owner, fire_flow, summary, event_ids=None, durable=False,
               bound_flow=None) -> None:
    """Start a flow run per event, with the event's fields as the run's data
    (the trigger's ``params`` are defaults). Each fire carries an idempotency key
    so a re-delivered event is deduplicated. Mutates ``summary``; run ids land in
    ``summary['fired_flows']``."""
    flow_id = trig["flow"]
    for index, event in enumerate(events):
        if trig.get("source") == "imap_email" and (
            event_ids is None or event.get("_sender_auth") != "trusted_dmarc_pass"
        ):
            raise RuntimeError("Email sender verification is required before a workflow can start")
        if trig.get("source") == "form":
            from .form_inputs import (
                FormInputError,
                public_form_fields,
                validate_public_form_fields,
            )

            try:
                allowed = public_form_fields(
                    bound_flow, trig.get("params") or {}, is_flow=True,
                )
                validate_public_form_fields(
                    event, allowed, trusted_keys=frozenset({"_seq", "_ts"}),
                )
            except FormInputError as exc:
                raise RuntimeError(f"form submission needs attention: {exc}") from exc
        data = dict(trig.get("params") or {})
        for k, v in event.items():   # a flow takes ALL event fields as data (no declared set)
            if trig.get("source") == "imap_email" and k == "_sender_auth":
                continue
            data[str(k)] = v if isinstance(v, (int, float, bool)) else str(v)[:2000]
        if trig.get("source") == "form":
            from .form_inputs import FormInputError, coerce_flow_form

            try:
                data = coerce_flow_form(bound_flow, data)
            except FormInputError as exc:
                # Keep the accepted row behind the unchanged cursor; an
                # operator must repair or explicitly dispose of it.
                raise RuntimeError(f"form submission needs attention: {exc}") from exc
        # Preserve already released flow idempotency keys. Flow admission has
        # its own owner/release scope; changing its key format during this
        # template repair would make a pre-upgrade flow retry executable again.
        import hashlib
        import json
        legacy_id = event.get("id") or event.get("guid") or event.get("uid")
        if legacy_id is None:
            legacy_id = hashlib.sha1(json.dumps(event, sort_keys=True, default=str).encode(),
                                     usedforsecurity=False).hexdigest()[:16]
        legacy_key = f"{trig['name']}:{legacy_id}"
        key = legacy_key
        options = {}
        if event_ids is not None:
            key = _event_key(_trigger_key(trig), event, event_ids[index])
            if durable and not trig.get("cursor_format"):
                source = trig.get("source")
                field = ("number" if source == "github_issues" else "_seq" if source == "form"
                         else "uid" if source == "imap_email" else
                         str((trig.get("config") or {}).get("id_field") or "id"))
                fields = ("path", "mtime", "size") if source == "file_dir" else (field,)
                identity = {k: str(event[k]) for k in fields if k in event}
                complete = len(identity) == len(fields) and all(len(v) < 2000 for v in identity.values())
                if source not in {"file_dir", "imap_email"}:
                    complete = complete and identity.get(field) == event_ids[index]
                options["legacy_event"] = {"key": legacy_key, "identity": identity if complete else None}
        # The worker can distinguish this reservation from pre-sender-check
        # event runs, including those already queued before an upgrade.
        origin = f"event:v2:{trig['source']}:{_trigger_key(trig)}:{trig['name']}"
        run_id = fire_flow(flow_id, data, owner, key,
                           origin,
                           expected_revision=str(trig.get("flow_revision") or ""), **options)
        if run_id:
            if durable:
                from maverick.flow import store as flow_store

                from .automation_queue import _event_flow_start_problem

                saved = flow_store.load_run(run_id, owner=owner, flow_id=flow_id)
                if (saved is None
                        or saved.origin not in {origin, f"event:{trig['name']}"}
                        or saved.status in {"failed", "indeterminate", "skipped_concurrency"}
                        or _event_flow_start_problem(saved)):
                    # An idempotency claim from a pre-upgrade event run may be
                    # returned even though that run is now held by the worker.
                    # Keep the source cursor so an owner can reconcile it;
                    # never report the old unverified run as newly fired.
                    raise RuntimeError(
                        "An earlier automation run needs review before this item can start"
                    )
            summary["fired_flows"].append(run_id)


def _deliver(world, trig, res, owner, fire, fire_flow, summary, durable=False) -> bool:
    """Dispatch a trigger's new events to its target (bound flow, else template).
    Returns False when nothing was delivered and the caller must NOT advance the
    cursor past these events (missing target, or no flow dispatcher wired);
    otherwise True. The missing-target cases advance the cursor themselves so a
    permanent backlog can't wedge the trigger."""
    from maverick_dashboard import trigger_events_store
    name = trig["name"]
    event_ids = getattr(res, "event_ids", None)
    if event_ids is not None and (len(event_ids) != len(res.events)
                                 or any(not isinstance(eid, str) or not eid for eid in event_ids)
                                 or len(set(event_ids)) != len(event_ids)):
        raise ValueError("event source returned invalid delivery identities")
    if trig.get("flow"):
        from maverick.flow import store as flow_store

        from maverick_dashboard.auth import auth_genuinely_off

        try:
            published = flow_store.load_published_bundle(trig["flow"])
        except flow_store.FlowSnapshotError:
            published = None
        flow = published[0] if published is not None else None
        release = published[1] if published is not None else None
        expected_owner = str(trig.get("flow_owner") or "")
        expected_revision = str(trig.get("flow_revision") or "")
        stale = flow is None or (
            not expected_revision and not auth_genuinely_off()
        )
        if flow is not None and expected_revision:
            stale = stale or (
                flow.owner != expected_owner
                or release is None
                or str(release.get("release_id") or "") != expected_revision
            )
        if stale:
            summary["notes"].append("flow unavailable: binding is stale")
            if trig.get("source") == "form":
                # An accepted public submission must remain attached to this
                # generation until a durable delivery or explicit disposition.
                # Rebind/delete guard sees the unchanged cursor and blocks.
                trigger_events_store.record(
                    name, owner, trigger_events_store.TEMPLATE_UNAVAILABLE,
                    note="form submissions are waiting for their original flow",
                )
                return False
            # A deleted/recreated target is not the target that was approved at
            # trigger creation. Advance past this batch so an ABA replacement
            # cannot accumulate an unbounded replay backlog.
            _publish_cursor(trig, res.cursor, res.cursor_format)
            trigger_events_store.record(
                name,
                owner,
                trigger_events_store.TEMPLATE_UNAVAILABLE,
                note="flow binding is unavailable",
            )
            return False
        if fire_flow is None:
            # No flow dispatcher in this context (e.g. a caller that only wires
            # template fires). Leave the cursor so these events retry once a
            # dispatcher is available rather than silently advancing past them.
            summary["notes"].append("flow firing unavailable in this context")
            return False
        _fire_flow(trig, res.events, owner, fire_flow, summary, event_ids, durable,
                   bound_flow=flow)
        return True
    try:
        from maverick_dashboard.triggers_store import bound_template

        tpl = bound_template(trig)
    except ValueError as e:
        detail = _safe_error(e, fallback="template unavailable")
        summary["notes"].append(f"template unavailable: {detail}")
        if trig.get("source") == "form":
            trigger_events_store.record(
                name, owner, trigger_events_store.TEMPLATE_UNAVAILABLE,
                note="form submissions are waiting for their original workflow",
            )
            return False
        _publish_cursor(trig, res.cursor, res.cursor_format)
        trigger_events_store.record(
            name,
            owner,
            trigger_events_store.TEMPLATE_UNAVAILABLE,
            note=detail,
        )
        return False
    _fire_template(world, trig, tpl, res.events, owner, fire, summary, durable, event_ids)
    return True


def _complete_trigger_batch(world, trig, res, batch, owner, fire, fire_flow,
                            summary, durable) -> bool:
    """Serialize form decisions with delivery and cursor publication."""
    from maverick import event_admission
    from maverick.automation_events import PollResult

    from maverick_dashboard import trigger_events_store

    generation = _trigger_key(trig)
    if trig.get("source") == "form":
        from maverick_dashboard import form_recovery

        form_token = str((trig.get("config") or {}).get("token") or "")
        decision_lock = form_recovery.locked(form_token)
    else:
        decision_lock = nullcontext()
    # A poll already delivering this batch finishes before the owner can
    # decide; a prior decision is applied even to a retained batch.
    with decision_lock:
        skipped = 0
        if trig.get("source") == "form":
            events, event_ids, skipped = form_recovery.without_abandoned(
                form_token, generation, res.events, res.event_ids,
            )
            res = PollResult(events=events, event_ids=event_ids,
                             cursor=res.cursor, cursor_format=res.cursor_format)
            if skipped:
                summary["abandoned_submissions"] = skipped
                summary["notes"].append(
                    f"{skipped} submission(s) did not run after an owner's recorded decision"
                )
        delivered = skipped > 0 and not res.events
        if not delivered:
            delivered = _deliver(world, trig, res, owner, fire, fire_flow, summary, durable)
        if not delivered:
            if batch is not None and trig.get("_cursor_publication_completed"):
                event_admission.complete_poll_batch(world, generation, batch["batch_digest"])
            return False
        # Publish only after delivery or a witnessed disposition.
        if res.cursor != trig["cursor"] or res.cursor_format != trig.get("cursor_format", 0):
            _publish_cursor(trig, res.cursor, res.cursor_format)
        if batch is not None:
            event_admission.complete_poll_batch(world, generation, batch["batch_digest"])
        if summary["fired"] or summary["fired_flows"]:
            trigger_events_store.record(trig["name"], owner, trigger_events_store.FIRED,
                                        new_events=summary["new_events"],
                                        fired=summary["fired"],
                                        fired_flows=summary["fired_flows"])
    return True


def _quarantine_legacy_imap(world, trig) -> None:
    """Prevent pre-sender-check receipts from starting work after an upgrade."""
    from maverick import event_admission
    from maverick.automation_events import EventSourceError

    old_key = _trigger_key(trig, legacy_mail=True)
    current_key = _trigger_key(trig)
    while event_admission.quarantine_legacy_mail_goals(
        world, trig["name"], current_key,
    ):
        pass
    for key, goal_id, state in event_admission.pending(world, old_key):
        goal = world.get_goal(goal_id)
        if goal is not None and goal.status == "pending":
            if not world.block_goal_admission(
                goal_id, result="Email request held: sender identity was not verified"
            ):
                raise EventSourceError("An earlier email request needs review")
        elif goal is not None and goal.status not in {
            "blocked", "done", "completed", "failed", "cancelled", "error"
        }:
            raise EventSourceError("An earlier email request may have started; review it")
        if not event_admission.transition(world, key, state, "retired"):
            raise EventSourceError("An earlier email request needs review")
    if event_admission.poll_batch(world, old_key) is not None:
        raise EventSourceError(
            "Email received before sender checks is held for review; update this automation before starting new work"
        )


def _dispatch_verified_imap_pending(world, trig, batch, fire, summary, durable) -> None:
    """Only recover admissions belonging to this exact authenticated batch."""
    from maverick import event_admission
    from maverick.automation_events import EventSourceError

    generation = _trigger_key(trig)
    pending = event_admission.pending(world, generation) if not trig.get("flow") else []
    if batch is not None and not _verified_mail_batch(batch):
        raise EventSourceError("An earlier email batch lacks sender verification; review it")
    if not pending:
        return
    if not _verified_mail_batch(batch):
        raise EventSourceError("An earlier email request lacks sender verification; review it")
    allowed_keys = {
        _event_key(generation, event, event_id)
        for event, event_id in zip(batch["events"], batch["event_ids"], strict=True)
    }
    if any(key not in allowed_keys for key, _, _ in pending):
        raise EventSourceError("An earlier email request does not match the verified batch")
    for key, goal_id, state in pending:
        _dispatch_admission(world, key, goal_id, state, fire, summary, durable)


def poll_and_fire(world: Any, triggers: list[dict], *, principal: str = "",
                  fire: Callable[[int], None],
                  fire_flow: Callable[..., Any] | None = None,
                  fire_is_durable: bool = False) -> list[dict]:
    """Poll each trigger and fire its target (template->goal, or flow) per new
    event. Returns a summary per trigger: ``{name, new_events, fired: [goal_id...],
    fired_flows: [run_id...], notes, poll_error}``. Never raises for a single bad
    trigger -- it's recorded in that trigger's notes + ``poll_error`` and the batch
    continues. ``fire_flow(flow_id, data, owner) -> run_id`` starts a flow run."""
    from maverick import event_admission
    from maverick.automation_events import EventSourceError, PollResult, poll_source
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant.registry import assert_tenant_active

    from maverick_dashboard import trigger_events_store
    from maverick_dashboard.auth import (
        AutomationAuthorizationError,
        auth_genuinely_off,
        stored_automation_identity,
    )

    results: list[dict] = []
    for trig in triggers:
        # Attribute the fired goal to the trigger's OWN owner -- so the
        # background tick (which has no request principal and drains every
        # owner's triggers) doesn't create unowned goals. On the on-demand path
        # the trigger's owner is the caller, so this matches ``principal``.
        owner = str(trig.get("owner") or "").strip()
        if not owner and auth_genuinely_off():
            owner = principal
        name = trig["name"]
        summary: dict = {"name": name, "new_events": 0, "fired": [], "fired_flows": [],
                         "notes": [], "poll_error": False}
        results.append(summary)   # append the ref now; it's mutated in place below
        # Bind the poll (incl. any OAuth vault read) to the tenant that created
        # the trigger, so a polled source never reads a cross-tenant token.
        # Single-tenant deployments store "" and run under the active tenant.
        tenant = str(trig.get("tenant") or "")
        tok = set_tenant(tenant) if tenant else None
        try:
            try:
                if tenant:
                    assert_tenant_active(tenant)
                stored_automation_identity(owner)
                authority = event_source_authority(
                    str(trig.get("source") or ""), trig.get("config") or {}
                )
                _require_stored_event_source_authority(owner, authority)
                admitted_config = admit_event_source_config(
                    str(trig.get("source") or ""), trig.get("config") or {}
                )
                # A world/model store is tenant-scoped. Resolve a factory only
                # after the durable trigger tenant has been restored.
                active_world = world() if callable(world) else world
                if trig.get("source") == "imap_email":
                    _quarantine_legacy_imap(active_world, trig)
                if not trig.get("flow") and trig.get("source") != "imap_email":
                    for key, goal_id, state in event_admission.pending(active_world, _trigger_key(trig)):
                        _dispatch_admission(active_world, key, goal_id, state,
                                            fire, summary, fire_is_durable)
                generation = _trigger_key(trig)
                batch = event_admission.poll_batch(active_world, generation)
                if batch is None:
                    admitted_config["_lightwork_cursor_format"] = int(trig.get("cursor_format") or 0)
                    from maverick import connections
                    with connections.bind_principal(owner):
                        if trig["source"] in {"sharepoint_files", "salesforce_records", "servicenow_tickets", "teams_messages"}:
                            admitted_config["_lightwork_authority_check"] = lambda current_owner=owner, current_authority=authority: (
                                stored_automation_identity(current_owner),
                                _require_stored_event_source_authority(current_owner, current_authority),
                            )
                        res = poll_source(trig["source"], admitted_config, trig["cursor"])
                    if res.events:
                        batch = event_admission.poll_batch(active_world, generation, {
                            "events": res.events, "event_ids": getattr(res, "event_ids", None),
                            "cursor": res.cursor, "cursor_format": getattr(res, "cursor_format", 0),
                            "before_cursor": trig["cursor"], "before_format": trig.get("cursor_format", 0),
                        })
                if trig.get("source") == "imap_email":
                    _dispatch_verified_imap_pending(
                        active_world, trig, batch, fire, summary, fire_is_durable
                    )
                if batch is not None:
                    res = PollResult(events=batch["events"], cursor=batch["cursor"],
                                     event_ids=batch["event_ids"], cursor_format=batch["cursor_format"])
                    trig = {**trig, "cursor": batch["before_cursor"], "cursor_format": batch["before_format"]}
            except (EventSourceAdmissionError, EventSourceError) as e:
                detail = _safe_error(e, fallback="event source unavailable")
                summary["poll_error"] = True
                summary["notes"].append(f"poll failed: {detail}")
                trigger_events_store.record(
                    name,
                    owner,
                    trigger_events_store.POLL_ERROR,
                    note=detail,
                )
                continue
            except AutomationAuthorizationError:
                summary["poll_error"] = True
                summary["notes"].append("trigger authorization unavailable")
                trigger_events_store.record(
                    name,
                    owner,
                    trigger_events_store.POLL_ERROR,
                    note="trigger authorization unavailable",
                )
                continue
            summary["new_events"] = len(res.events)
            if not _complete_trigger_batch(
                active_world, trig, res, batch, owner, fire, fire_flow,
                summary, fire_is_durable,
            ):
                continue
        except Exception as e:  # one trigger's unexpected error must not abort the batch
            detail = _safe_error(e)
            summary["poll_error"] = True
            summary["notes"].append(
                f"trigger error: {type(e).__name__}: {detail}"
            )
            trigger_events_store.record(
                name,
                owner,
                trigger_events_store.POLL_ERROR,
                note=f"{type(e).__name__}: {detail}"[:500],
            )
        finally:
            if tok is not None:
                reset_tenant(tok)
    return results
