"""Read-only state for the dashboard's first-run checklist."""

from __future__ import annotations

from typing import Any


def selected_model_route_state() -> dict[str, Any]:
    """Return bounded evidence for the selected swarm model routes.

    This deliberately uses the same deterministic route resolver as goal
    preflight.  A credential for an unrelated provider (including an existing
    Codex CLI login) must not complete onboarding when the selected role models
    still route to Anthropic, OpenAI, or another unconfigured provider.

    ``configured`` proves only offline prerequisites.  It never claims that a
    provider accepted a credential or a live request; that belongs to
    ``maverick doctor`` and provider-specific readiness receipts.
    """

    try:
        from maverick.config import config_source_errors, load_config
        from maverick.operator_preflight import _routed_configuration_missing

        loaded = load_config()
        if config_source_errors(include_tenant=True):
            raise RuntimeError("active configuration sources are invalid")
        routed = _routed_configuration_missing(loaded)
        if not isinstance(routed, dict) or not routed:
            raise TypeError("selected model-route result is not a mapping")
        missing: dict[str, tuple[str, ...]] = {}
        for route, fields in routed.items():
            if isinstance(fields, (str, bytes)) or not isinstance(
                fields, (list, tuple, set, frozenset)
            ):
                raise TypeError("selected model-route fields are malformed")
            if fields:
                missing[str(route)] = tuple(str(field) for field in fields)
    except Exception as exc:
        return {
            "status": "failed",
            "configured": False,
            "detail": "Selected model-route configuration could not be evaluated safely.",
            "evidence": {
                "kind": "offline_configuration",
                "error_type": type(exc).__name__,
                "live_provider_verified": False,
            },
        }

    if missing:
        return {
            "status": "incomplete",
            "configured": False,
            "detail": (
                f"{len(missing)} selected model route(s) still have missing "
                "offline prerequisites."
            ),
            "evidence": {
                "kind": "offline_configuration",
                "routes_evaluated": len(routed),
                "routes_incomplete": len(missing),
                "live_provider_verified": False,
            },
        }
    return {
        "status": "configured",
        "configured": True,
        "detail": (
            "Every selected model route has its offline prerequisites. "
            "Live provider acceptance has not been inferred."
        ),
        "evidence": {
            "kind": "offline_configuration",
            "routes_evaluated": len(routed),
            "routes_incomplete": 0,
            "live_provider_verified": False,
        },
    }


def workspace_readiness() -> dict[str, Any]:
    """The one truth about whether an AI service is connected (see
    :mod:`maverick_dashboard.provider_readiness`). Patch this in tests."""
    from .provider_readiness import workspace_readiness as _workspace_readiness

    return _workspace_readiness()


def selected_model_routes_ready() -> bool:
    """Whether AI work may start: the workspace verdict is not ``not_ready``.

    A saved-but-untested key (``needs_test``) still admits work, exactly as
    goal submission does; only a missing, blocked or failed provider blocks."""

    return workspace_readiness()["verdict"] != "not_ready"


def _has_user_template() -> bool:
    try:
        from maverick.templates import user_templates_dir

        return any(user_templates_dir().glob("*.md"))
    except OSError:
        return False


def _has_user_agent() -> bool:
    try:
        from maverick.domain import _load_raw_domains, user_dir
        from maverick.domain_edit import list_agents

        # The editor roster resolves every bundled specialist. An empty or
        # malformed-only override directory cannot contain a customized agent,
        # so avoid hydrating that catalog just to render the setup checklist.
        # Use the same bounded, no-follow parser and re-read the active workspace
        # on every request; existing overrides still use the full resolver.
        if not _load_raw_domains(user_dir()):
            return False
        return any(agent.get("is_override") for agent in list_agents())
    except Exception:
        return False


def _has_run(world: Any, owner: str | None = None) -> bool:
    try:
        return bool(world.list_goals(limit=1, owner=owner))
    except Exception:
        return False


def _has_automation() -> bool:
    try:
        from maverick.job_queue import JobQueue

        if any(
            (job.payload or {}).get("__cron__")
            for job in JobQueue().list(status="pending")
        ):
            return True
    except Exception:
        pass
    try:
        from . import triggers_store

        return bool(triggers_store.list_triggers())
    except Exception:
        return False


# What each installation check means, and the page that fixes it. The raw
# check detail and the terminal remediation stay available to administrators
# under "Technical details"; people see these words and a button.
_CHECK_WORDS: dict[str, tuple[str, str, str]] = {
    "config": ("Lightwork's settings", "Settings", "/settings#settings-maintenance"),
    "provider": ("AI service", "Add an AI provider key", "/settings#settings-integrations"),
    "model_routes": ("Models", "Choose models", "/settings#settings-models"),
    "provider_dependencies": ("Software the AI service needs", "Run the health check", "/settings#settings-maintenance"),
    "storage": ("Saved data", "Run the health check", "/settings#settings-maintenance"),
    "dashboard": ("This dashboard", "Run the health check", "/settings#settings-maintenance"),
    "tenant_scope": ("Workspace", "Choose a workspace", "/workspace/tenant"),
}
_STATUS_WORDS = {"ready": "Ready", "blocked": "Needs fixing", "attention": "Could be improved"}
# What fixing a check gets you, in the words of the outcome rather than the
# feature's internal name ("Fix next: Evidence graph" told nobody anything).
# id -> (title, what to do, what it is for). The provider checks keep their
# own wording (they belong to the provider readiness work).
_CHECK_OUTCOMES: dict[str, tuple[str, str, str]] = {
    "evidence_graph": ("Evidence linking", "Turn on evidence linking",
                       "so reviews can cite the sources behind each result"),
    "evidence_gateway": ("Signed evidence records", "Turn on signed evidence records",
                         "so auditors can verify that results were not changed"),
    "model_risk_assurance": ("Model assurance checks", "Turn on model assurance checks",
                             "so AI models are reviewed before their work is relied on"),
    "tenant_scope": ("Workspace", "Choose a workspace",
                     "so records are kept for the right client or team"),
    "storage": ("Saved data", "Repair saved data",
                "so tasks and results are kept between restarts"),
    "dashboard": ("This dashboard", "Run the health check",
                  "so the dashboard can show what is happening"),
    "config": ("Lightwork's settings", "Save or repair the settings",
               "so every page reads the same setup"),
    "gateway_key_custody": ("Evidence signing key", "Store the signing key safely",
                            "so signed records cannot be forged"),
    "gateway_signing": ("Evidence signing", "Turn on evidence signing",
                        "so each evidence record carries a signature"),
    "gateway_trust_registry": ("Trusted signers", "Register the trusted signers",
                               "so signatures can be checked against known keys"),
    "gateway_ledgers": ("Signed evidence ledgers", "Set up the signed ledgers",
                        "so evidence records are kept in order"),
}


def _plain_check(check: dict[str, Any], switchable: frozenset[str]) -> dict[str, Any]:
    check_id = str(check.get("id") or "")
    status = str(check.get("status") or "attention")
    title, fix_label, fix_href = _CHECK_WORDS.get(check_id, (str(check.get("label") or "Setup"), "", ""))
    module = ""
    if check_id.startswith("gateway_"):
        title = str(check.get("label") or "Assurance setup").replace("Gateway", "Evidence gateway")
        fix_label, fix_href = "Open assurance setup", "/security/assurance"
    elif not check_id:
        fix_label, fix_href = "Run the health check", "/settings#settings-maintenance"
    elif not fix_label:
        module = check_id if check_id in switchable else ""
        fix_label, fix_href = ("", "") if module else ("Open assurance setup", "/security/assurance")
    outcome = ""
    if check_id in _CHECK_OUTCOMES:
        title, action, purpose = _CHECK_OUTCOMES[check_id]
        outcome = f"{action} {purpose}"
        if module:
            fix_label = action
    if status == "ready":
        summary = "Ready."
    elif outcome:
        summary = outcome[0].upper() + outcome[1:] + "."
    elif check_id == "config":
        summary = "Lightwork's settings need to be saved or repaired."
    elif module or check_id not in _CHECK_WORDS:
        summary = "Turned off, or waiting on something else to be set up first."
    else:
        summary = "Waiting on setup. Use the button to fix it."
    return {**check, "title": title, "state_label": _STATUS_WORDS.get(status, "Could be improved"),
            "summary": summary, "fix_label": "" if status == "ready" else fix_label,
            "fix_href": "" if status == "ready" else fix_href,
            "module": "" if status == "ready" else module,
            "outcome": "" if status == "ready" else outcome}


def _with_plain_checks(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        from .module_activation import _MODULE_SWITCHES
        switchable = frozenset(_MODULE_SWITCHES)
    except Exception:  # pragma: no cover -- fall back to links only
        switchable = frozenset()
    checks = [_plain_check(check, switchable) for check in payload.get("checks") or []]
    payload["checks"] = checks
    first = next((c for c in checks if c.get("status") == "blocked"), None) or next(
        (c for c in checks if c.get("status") == "attention"), None)
    payload["next_fix"] = first
    return payload


def _preflight_state(profile: str, readiness: dict[str, Any] | None = None) -> dict[str, Any]:
    from maverick.operator_preflight import collect

    try:
        payload = collect(profile).to_dict()
        if not isinstance(payload, dict) or not isinstance(payload.get("checks"), list):
            raise TypeError("preflight report contract is invalid")
    except Exception as exc:
        label = "Runtime" if profile == "run" else "Assurance"
        return _with_plain_checks({
            "ready": False,
            "status": "failed",
            "checks": [
                {
                    "status": "blocked",
                    "label": f"{label} checks",
                    "detail": "Readiness evidence could not be evaluated safely.",
                    "remediation": "maverick preflight --json",
                }
            ],
            "next_action": "maverick preflight --json",
            "error_type": type(exc).__name__,
        })
    payload["ready"] = payload.get("ready") is True
    payload["status"] = "ready" if payload["ready"] else "incomplete"
    return _with_provider_verdict(_with_plain_checks(payload), readiness)


def _with_provider_verdict(payload: dict[str, Any], readiness: dict[str, Any] | None = None) -> dict[str, Any]:
    """Make the offline "provider" check tell the same truth as every other
    page: a saved key that never passed a connection test is not "Ready", and
    a failed test blocks. The kernel preflight stays network-free; the test
    receipt comes from the dashboard's own readiness module."""
    checks = payload.get("checks") or []
    check = next((c for c in checks if c.get("id") == "provider"), None)
    if check is None:
        return payload
    if readiness is None:
        readiness = workspace_readiness()
    verdict = readiness["verdict"]
    if verdict == "ready":
        check.update(status="ready", state_label=_STATUS_WORDS["ready"], summary="Ready.",
                     detail=readiness["reason"], fix_label="", fix_href="", module="")
    else:
        status = "attention" if verdict == "needs_test" else "blocked"
        action = readiness["next_action"] or {"label": "Open providers", "href": "/providers"}
        check.update(status=status, state_label=_STATUS_WORDS[status], summary=readiness["reason"],
                     detail=readiness["reason"], fix_label=action["label"], fix_href=action["href"],
                     module="")
        payload["ready"] = False
        payload["status"] = "incomplete"
    first = next((c for c in checks if c.get("status") == "blocked"), None) or next(
        (c for c in checks if c.get("status") == "attention"), None)
    payload["next_fix"] = first
    return payload


def build(
    world: Any,
    *,
    can_configure: bool = True,
    can_operate: bool = True,
    owner: str | None = None,
    reviewed_outcome: dict | None = None,
) -> dict[str, Any]:
    """Build the activation checklist and deterministic install preflight."""

    model_route_state = selected_model_route_state()
    readiness = workspace_readiness()
    provider_ok = readiness["verdict"] == "ready"
    provider_action = readiness["next_action"] or {"label": "Open providers", "href": "/providers"}
    activated = _has_run(world, owner)
    built = activated or _has_user_template() or _has_user_agent()
    if reviewed_outcome is None:
        from .guided_outcome import reviewed_goal

        reviewed_outcome = reviewed_goal(world, owner=owner)
    steps = [
        {
            "key": "connect",
            "title": "Connect your AI service",
            "done": provider_ok,
            "body": readiness["reason"],
            "status": readiness["verdict"],
            "cta": provider_action["href"],
            "cta_label": provider_action["label"],
            "allowed": bool(can_configure),
            "readonly_label": "Ask your administrator to connect an AI service.",
            "command": "maverick preflight",
        },
        {
            "key": "build",
            "title": "Choose a workflow or agent",
            "done": built,
            "body": (
                "Choose an existing agent, specialist or workflow, or create one in the builder. "
                "Using an existing agent or specialist also completes this step."
            ),
            "status": "complete" if built else "incomplete",
            "cta": "/agents",
            "cta_label": "Choose an agent or specialist",
            "allowed": bool(can_operate),
            "readonly_label": "An operator can choose or build the first workflow or agent.",
            "command": "",
        },
        {
            "key": "run",
            "title": "Start your first task",
            "done": activated,
            "body": (
                "Describe what you need in Chat. You can also schedule a "
                "saved workflow from Automations."
            ),
            "status": "complete" if activated else "incomplete",
            "cta": "/chat",
            "cta_label": "Start a task",
            "allowed": bool(can_operate),
            "readonly_label": "An operator can start or automate the first task.",
            "command": "",
        },
    ]
    steps.append({
        "key": "review",
        "title": "Review and accept your first result", "done": reviewed_outcome.get("complete") is True,
        "body": reviewed_outcome["detail"], "status": reviewed_outcome["status"],
        "cta": reviewed_outcome.get("href", "/deliverables"), "cta_label": "Review the result",
        "allowed": bool(can_operate), "readonly_label": "An operator can review and accept the first result.",
        "command": "",
    })
    done_count = sum(step["done"] for step in steps)
    next_step = next((step for step in steps if not step["done"]), None)
    # Both reports describe this request's provider inventory. Reuse its
    # snapshot instead of resolving every provider and model route twice more.
    runtime_preflight = _preflight_state("run", readiness=readiness)
    assurance_preflight = _preflight_state("cockpit", readiness=readiness)
    from maverick.config import config_path

    return {
        "steps": steps,
        "done_count": done_count,
        "total": len(steps),
        "next_step": next_step,
        # Get started leads with this one step and its one primary action.
        "next_index": steps.index(next_step) if next_step is not None else None,
        "model_route_state": model_route_state,
        "workspace": readiness,
        "can_operate": bool(can_operate),
        "can_configure": bool(can_configure),
        "needs_initial_settings": not config_path().exists(),
        # Compatibility alias for existing template and API consumers.
        "preflight": runtime_preflight,
        "runtime_preflight": runtime_preflight,
        "assurance_preflight": assurance_preflight,
        "runtime_ready": runtime_preflight["ready"] is True,
        "assurance_ready": assurance_preflight["ready"] is True,
        "runtime_all_set": (
            done_count == len(steps) and runtime_preflight["ready"] is True
        ),
    }


__all__ = ["build", "selected_model_route_state", "selected_model_routes_ready", "workspace_readiness"]
