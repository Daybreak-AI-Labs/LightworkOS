"""Admin pages router: /settings and /users (pages + form handlers).

The first slice of decomposing ``app.py`` by nav group: everything on this
router is the site admin's control surface (RBAC "admin" permission via
``auth.require_permission`` for tenant-scoped administration and
``auth.require_global_permission`` for global control-plane writes),
same-origin-checked on every mutation, and rendered with the shared app
templates.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from . import _shared, auth, step_up
from .notification_health import router as notification_health_router

router = APIRouter()
router.include_router(notification_health_router)


def _admin_audit(request: Request, action: str, **payload) -> None:
    """One activity-log row per administrator change made from these pages
    (invites, department access, settings saves). A configured custody refusal
    stops the change from looking recorded; ordinary writer trouble is logged
    by the audit subsystem and never blocks the page."""
    from .audit_actions_api import _audit_event

    _audit_event(request, action, **payload)


def _setting_write(request: Request, section: str, key: str, project,
                   *, confirmed: bool = False, changed_fields=None):
    from .settings_audit import bind_setting_write

    return bind_setting_write(request, section=section, key=key,
                              project=project, confirmed=confirmed,
                              changed_fields=changed_fields)


def _provider_audit_value(data: dict, name: str) -> dict[str, str]:
    """Record only credential presence; never put a key or endpoint in Activity."""
    providers = data.get("providers") or {}
    value = providers.get(name) if isinstance(providers, dict) else None
    value = value if isinstance(value, dict) else {}
    setup = {field: value.get(field) for field in
             ("auth_mode", "deployment", "api_version", "endpoint", "region", "model_id", "project_id")
             if value.get(field)}
    return {
        "api_key": "set" if value.get("api_key") else "not set",  # pragma: allowlist secret
        "base_url": "set" if value.get("base_url") else "not set",
        "setup_sha256": hashlib.sha256(json.dumps(setup, sort_keys=True).encode()).hexdigest(),
    }


def _provider_changed_fields(old: dict, new: dict, name: str) -> list[str]:
    """Name changed connection fields without recording their values or hashes."""
    def provider(data: dict) -> dict:
        providers = data.get("providers") or {}
        value = providers.get(name) if isinstance(providers, dict) else None
        return value if isinstance(value, dict) else {}

    before, after = provider(old), provider(new)
    labels = {
        "api_key": "access key", "base_url": "service address",  # pragma: allowlist secret
        "auth_mode": "sign-in method", "deployment": "deployment",
        "api_version": "service version", "endpoint": "endpoint",
        "region": "region", "model_id": "model", "project_id": "project",
    }
    return [label for field, label in labels.items() if before.get(field) != after.get(field)]


def _rate_audit_value(data: dict, spec: str) -> dict[str, object]:
    """Prove the exact rate changed without publishing contract references."""
    row = (data.get("model_rates") or {}).get(spec)
    if row is None:
        return {"configured": False}
    fingerprint = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    return {"configured": True, "sha256": fingerprint}


def _app():
    """The dashboard app module, resolved lazily.

    This router is included while ``maverick_dashboard.app`` is still
    executing, so a top-level ``from .app import templates`` would race that
    module's initialization; by request time it is fully loaded.
    """
    from . import app as app_module
    return app_module


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: str = "") -> HTMLResponse:
    """Operator settings: appearance (theme/density/font/language) + which model
    Lightwork uses by default. Appearance is applied via the existing
    persist_theme middleware (the form GETs back here with the params); the
    model choice is saved to the dashboard-owned runtime overlay."""
    return _settings_response(request, saved)


def _api_keys_enabled() -> bool:
    try:
        from . import api_keys

        return api_keys.enabled()
    except Exception:
        return False


def _settings_response(request: Request, saved: str = "", *, notice: str = "",
                       status_code: int = 200) -> HTMLResponse:
    """The settings page; ``notice`` is a message shown instead of "Saved"
    (a change waiting for other administrators' approval)."""
    # Every form on this page changes deployment-wide process configuration.
    # A tenant-local admin must not see an apparently actionable console whose
    # POSTs all fail the correct global gate.
    auth.require_global_permission(request, "admin")
    import re as _re

    from maverick.llm import catalog_specs, model_for_role
    from maverick.runner import DEFAULT_MAX_DOLLARS
    from maverick.runtime_overrides import (
        allowed_models,
        budget_override,
        default_model_override,
        model_rate_overrides,
        role_model_override,
        task_limits_override,
    )
    roles = [
        ("Orchestrator", "orchestrator"), ("Coder", "coder"),
        ("Researcher", "researcher"), ("Writer", "writer"),
        ("Analyst", "analyst"), ("Verifier", "verifier"),
        ("Summarizer", "summarizer"),
    ]
    role_models = [
        (label, role, model_for_role(role), role_model_override(role))
        for label, role in roles
    ]
    from maverick.budget import UnpricedModelError, _lookup_price_quote

    route_prices = []
    for label, spec in [("Default", model_for_role("default"))] + [
        (label, effective) for label, _, effective, _ in role_models
    ]:
        try:
            quote = _lookup_price_quote(spec)
        except UnpricedModelError:
            quote = None
        route_prices.append({
            "label": label, "spec": spec,
            "status": ("Will stop before a paid request" if quote is None else
                       "Administrator ceiling" if quote.rate_card_version == "operator-ceiling-v1" else
                       "Tracked price" if quote.verified else "Estimate only"),
            "ready": quote is not None,
        })
    today = datetime.now(timezone.utc).date()
    operator_rates = [
        {"spec": spec, **rate, "active": rate["valid_until"] >= today.isoformat()}
        for spec, rate in sorted(model_rate_overrides().items())
    ]
    model_options = list(catalog_specs())
    seen = {s for s, _ in model_options}
    try:  # admins extend the picker via [models] catalog in config.toml
        from maverick.config import load_config
        for spec in (load_config().get("models", {}) or {}).get("catalog") or []:
            s = str(spec).strip()
            if s and s not in seen and _re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", s):
                model_options.append((s, "Custom (config)"))
                seen.add(s)
    except Exception:  # pragma: no cover -- config read fails soft
        pass
    # Admin allow-list: when set, every model picker is capped to it (and the
    # resolver enforces it as a hard cap). Empty = no restriction. The checkbox
    # section lets the admin pick which catalogue models everyone may use; the
    # default/per-role pickers then offer only those.
    allow = allowed_models()
    label_by_spec = dict(model_options)
    allow_options = [(s, label_by_spec.get(s, "Allowed")) for s in sorted(allow)]
    picker_options = allow_options if allow else model_options
    from maverick_dashboard import settings_store
    from maverick_dashboard.integration_readiness import (
        IntegrationConfigurationUnavailable,
        require_readable_config,
    )

    try:
        require_readable_config()
        cfg_state = settings_store.state()
        if any(provider.get("source_errors") for provider in cfg_state["providers"]):
            raise IntegrationConfigurationUnavailable(
                "provider configuration source changed while it was read"
            )
    except IntegrationConfigurationUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="integration configuration is unavailable",
        ) from exc

    # The one truth about whether an AI service is connected: the header,
    # each provider row and every other page read the same verdict.
    from maverick_dashboard.provider_readiness import (
        apply_to_rows,
        attention_provider,
        workspace_readiness,
    )

    workspace = workspace_readiness()
    present = {row["name"] for row in workspace.get("providers") or []}
    if any(provider["name"] not in present for provider in cfg_state["providers"]):
        raise HTTPException(status_code=503, detail="provider readiness is unavailable")
    apply_to_rows(cfg_state["providers"], workspace)
    # Grouped pickers: every model the configured keys can reach (cached live
    # discovery) plus the shipped catalog, capped by the allow-list.
    from maverick_dashboard import model_pickers
    pickers = model_pickers.build(cfg_state["providers"], allow)
    groups_by_name = {g["name"]: g for g in pickers["model_groups"]}
    from maverick_dashboard import plain_labels
    for provider in cfg_state["providers"]:
        provider["discovery"] = groups_by_name.get(provider["name"])
        provider["key_help"] = plain_labels.PROVIDER_KEY_HELP.get(provider["name"], "")
    for feature in cfg_state["features"]:
        feature["info"] = plain_labels.feature_help(feature["name"], feature.get("info") or "")
    saved_msg = {
        "appearance": "Appearance updated.",
        "models": "Default model updated.",
        "roles": "Role models updated.",
        "budget": "Task spending limit updated.",
        "allowed": "Approved models updated.",
        "model_rate": "Model spending ceiling updated.",
        "model_rate_removed": "Model spending ceiling removed.",
        "discover": "Model lists refreshed from your provider keys.",
        "providers": "Provider keys updated.",
        "provider_test": "Connection test finished. The result is shown next to the provider.",
        "webhooks": "Secret for other apps updated.",
        "discovery": "Automatic model lists updated.",
        "capabilities": "Capabilities updated.",
        "features": "Features updated.",
        "visibility": "Page visibility updated.",
        "visibility_reset": "Page visibility reset to defaults.",
    }.get(saved, "")
    saved_section = {
        "appearance": "general",
        "budget": "general",
        "models": "models",
        "roles": "models",
        "allowed": "models",
        "model_rate": "models",
        "model_rate_removed": "models",
        "discover": "models",
        "discovery": "models",
        "providers": "integrations",
        "provider_test": "integrations",
        "webhooks": "integrations",
        "capabilities": "controls",
        "features": "controls",
        "visibility": "access",
        "visibility_reset": "access",
    }.get(saved, "")
    from maverick_dashboard import rbac, ui_visibility

    from .webhook_settings import WebhookSettingsConflict, WebhookSettingsUnavailable
    from .webhook_settings import state as webhook_state

    # Render only the safe current state; the browser obtains a fresh reviewed
    # generation before it can submit any change.
    try:
        webhook_configured = webhook_state(
            principal=auth.caller_principal(request) or "local-operator",
            authorize=lambda: auth.require_global_permission(request, "admin"),
        )["configured"]
    except (WebhookSettingsConflict, WebhookSettingsUnavailable):
        webhook_configured = None
    return _app().templates.TemplateResponse(request, "settings.html", {
        "visibility_matrix": ui_visibility.matrix(),
        "visibility_roles": list(rbac.known_roles()),
        "role_models": role_models,
        "route_prices": route_prices,
        "operator_rates": operator_rates,
        "price_today": today.isoformat(),
        "price_review_until": (today + timedelta(days=30)).isoformat(),
        "model_options": model_options,
        "picker_options": picker_options,
        "allowed_models": sorted(allow),
        "pinned_model": default_model_override(),
        **pickers,
        "providers": cfg_state["providers"],
        "workspace": workspace,
        # The row "Open AI provider keys" (?focus=ai-provider) lands on.
        "ai_focus_provider": attention_provider(workspace),
        "capabilities": cfg_state["capabilities"],
        "features": cfg_state["features"],
        "budget": budget_override(),
        "default_budget": DEFAULT_MAX_DOLLARS,
        "task_limits_enabled": (task_limits_override() if task_limits_override() is not None
                                else (load_config().get("budget") or {}).get("task_limits_enabled", True)),
        "discovery_locked": bool(__import__("os").environ.get("MAVERICK_MODEL_DISCOVERY", "").strip()),
        "webhook_configured": webhook_configured,
        # The static server token is the break-glass credential: it has no
        # person behind it and no scopes, so Settings says so while it is set.
        "static_token_set": bool(_shared.dashboard_token()),
        "api_keys_enabled": _api_keys_enabled(),
        "saved": saved_msg,
        "saved_section": saved_section,
        "notice": notice,
    }, status_code=status_code)


@router.post("/settings/models")
async def settings_set_model(request: Request) -> RedirectResponse:
    """Pin (or clear) the dashboard's default model via the runtime overlay.

    ``model`` is the picker value; when it is the custom marker the typed
    ``model_custom`` id is used instead. An empty value clears the pin,
    reverting to config.toml / built-in defaults. config.toml is never
    written."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.runtime_overrides import (
        RuntimeOverridesSecurityError,
        allowed_models,
        clear_default_model,
        set_default_model,
    )

    from maverick_dashboard.model_pickers import chosen
    model = chosen(await request.form(), "model")
    allow = await run_in_threadpool(allowed_models)
    if model and allow and model not in allow:
        raise HTTPException(status_code=400, detail="model not in the allowed list")
    from maverick.runtime_overrides import default_model_override
    previous = await run_in_threadpool(default_model_override)
    try:
        with _setting_write(request, "models", "default", lambda d:
                            (d.get("models") or {}).get("default")):
            if model:
                await run_in_threadpool(set_default_model, model)
            else:
                await run_in_threadpool(clear_default_model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid model id") from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "Model settings could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_models")
    from . import agent_changelog
    agent_changelog.record(agent_changelog.EVERY_AGENT,
                           agent_changelog.describe_default_model(previous, model or None),
                           by=auth.caller_principal(request) or "")
    return RedirectResponse("/settings?saved=models", status_code=303)


@router.post("/settings/models/rate")
async def settings_set_model_rate(request: Request) -> RedirectResponse:
    """Admin-attested ceiling for one exact provider route; never an invoice rate."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.budget import UnpricedModelError, _lookup_price_quote
    from maverick.llm import _parse_spec
    from maverick.runtime_overrides import (
        RuntimeOverridesSecurityError,
        model_rate_overrides,
        set_model_rate,
    )

    from .model_pickers import chosen

    form = await request.form()
    spec = chosen(form, "rate_model")
    if form.get("confirm") != "on":
        raise HTTPException(status_code=400, detail="Confirm the source and ceiling before saving.")
    try:
        provider, model_id = _parse_spec(spec)
        spec = f"{provider}:{model_id}"
        try:
            current_quote = _lookup_price_quote(spec)
        except UnpricedModelError:
            current_quote = None
        if current_quote is not None and current_quote.verified:
            raise HTTPException(status_code=409, detail=(
                "This model already has a tracked price. Review its current rate in Models."
            ))
        actor = auth.caller_principal(request) or "local administrator"
        with _setting_write(request, "model_rates", spec, lambda d:
                            _rate_audit_value(d, spec)):
            recorded = await run_in_threadpool(
                set_model_rate, spec,
                input_per_mtok=float(form.get("input_per_mtok", "")),
                output_per_mtok=float(form.get("output_per_mtok", "")),
                source=str(form.get("source", "")),
                as_of=str(form.get("as_of", "")),
                valid_until=str(form.get("valid_until", "")),
                approved_by=actor,
            )
        if (await run_in_threadpool(model_rate_overrides)).get(spec) != recorded:
            raise RuntimeOverridesSecurityError("model rate readback differs")
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Review the model, USD amounts, source and dates.") from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "The model price could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_model_rate", model=spec)
    return RedirectResponse("/settings?saved=model_rate#settings-model-prices", status_code=303)


@router.post("/settings/models/rate/remove")
async def settings_remove_model_rate(request: Request, model: str = Form("")) -> RedirectResponse:
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.runtime_overrides import (
        RuntimeOverridesSecurityError,
        clear_model_rate,
        model_rate_overrides,
    )

    try:
        with _setting_write(request, "model_rates", model, lambda d:
                            _rate_audit_value(d, model)):
            await run_in_threadpool(clear_model_rate, model)
        if model in await run_in_threadpool(model_rate_overrides):
            raise RuntimeOverridesSecurityError("model rate removal readback differs")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Choose a saved model rate to remove.") from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "The change could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_model_rate_removed", model=model)
    return RedirectResponse("/settings?saved=model_rate_removed#settings-model-prices", status_code=303)


@router.post("/settings/budget")
def settings_set_budget(request: Request, max_dollars: str = Form(""),
                        mode: str = Form("configured")) -> Response:
    """Set (or clear) the dashboard's per-goal spend cap via the runtime
    overlay. An empty value clears it, reverting to config.toml / defaults.
    config.toml is never written."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.runtime_overrides import (
        RuntimeOverridesSecurityError,
        clear_budget,
        set_budget,
        set_task_limits,
    )
    val = (max_dollars or "").strip()
    try:
        wanted = _budget_choice(mode, val)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="spend cap must be a positive number",
        ) from exc
    # [safety] quorum_required: the per-task spending limit is a protected
    # setting by default, so a change waits for other administrators'
    # approval exactly as on All settings (settings_quorum).
    approved = None
    current = _budget_now()
    if wanted != current:
        from . import settings_quorum

        actor = auth.caller_principal(request) or "local administrator"
        change = [{"setting": _BUDGET_SETTING, "old": current, "new": wanted}]
        hold, approved = settings_quorum.review(change, actor, lambda _s, value: value)
        if hold is not None:
            return _held(request, hold)
    try:
        with _setting_write(request, "budget", "task_limit", lambda d:
                            d.get("budget") or {}, confirmed=approved is not None):
            if mode == "disabled":
                set_task_limits(False)
            elif mode == "configured" and val:
                set_budget(float(val))
            else:
                # Drop the Settings amount and keep task limits on.
                clear_budget()
                set_task_limits(True)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="spend cap must be a positive number",
        ) from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "Spending settings could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    if approved is not None:
        from . import settings_quorum

        settings_quorum.settle(approved)
    _admin_audit(request, "settings_budget")
    return RedirectResponse("/settings?saved=budget", status_code=303)


# The per-task spending limit as the quorum sees it: one protected setting
# (``budget.max_dollars`` in [safety] quorum_protected_keys), whatever the
# form's mode, so switching limits off is protected too.
_BUDGET_SETTING = SimpleNamespace(id="budget.max_dollars", label="Spending limit per task")


def _budget_choice(mode: str, amount: str) -> str:
    """What the form asks for, in the words approvers see."""
    if mode == "disabled":
        return "No limit for each task"
    if mode == "configured" and amount:
        value = float(amount)
        if not 0 < value < float("inf"):
            raise ValueError("spend cap must be positive")
        return f"Stop a task after ${value:,.2f}"
    if mode in ("configured", "default"):
        return "Your installation's standard limits"
    raise ValueError("unknown task limit policy")


def _budget_now() -> str:
    from maverick.config import load_config
    from maverick.runtime_overrides import budget_override, task_limits_override

    enabled = task_limits_override()
    if enabled is None:
        enabled = (load_config().get("budget") or {}).get("task_limits_enabled", True)
    if not enabled:
        return "No limit for each task"
    amount = budget_override()
    return (f"Stop a task after ${amount:,.2f}" if amount is not None
            else "Your installation's standard limits")


def _held(request: Request, hold: dict):
    """202: the change waits for approval. JSON for scripts, the settings
    page with the message for the browser form."""
    from fastapi.responses import JSONResponse

    if "application/json" in (request.headers.get("accept") or ""):
        return JSONResponse({"changed": [], "quorum": hold, "message": hold["message"]},
                            status_code=202, headers={"Cache-Control": "no-store"})
    return _settings_response(request, notice=hold["message"], status_code=202)


@router.post("/settings/models/roles")
async def settings_set_role_models(request: Request) -> RedirectResponse:
    """Set/clear per-role model pins from the settings page in one write. Each
    form field is named for a role; an empty value clears that role's pin."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.runtime_overrides import (
        RuntimeOverridesSecurityError,
        allowed_models,
        set_role_models,
    )
    roles = ("orchestrator", "coder", "researcher", "writer",
             "analyst", "verifier", "summarizer")
    from maverick_dashboard.model_pickers import chosen
    form = await request.form()
    updates = {r: chosen(form, r) for r in roles}
    allow = await run_in_threadpool(allowed_models)
    if allow:
        for spec in updates.values():
            if spec and spec not in allow:
                raise HTTPException(
                    status_code=400, detail="model not in the allowed list")
    from maverick.runtime_overrides import role_model_override
    previous = {r: await run_in_threadpool(role_model_override, r) for r in roles}
    try:
        with _setting_write(request, "models", "roles", lambda d:
                            {k: v for k, v in (d.get("models") or {}).items()
                             if k != "default"}):
            await run_in_threadpool(set_role_models, updates)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid model id") from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "Role models could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_roles")
    from . import agent_changelog
    agent_changelog.record(agent_changelog.EVERY_AGENT,
                           agent_changelog.describe_role_models(
                               previous, {r: (spec or None) for r, spec in updates.items()}),
                           by=auth.caller_principal(request) or "")
    return RedirectResponse("/settings?saved=roles", status_code=303)

@router.post("/settings/models/allowed")
async def settings_set_allowed_models(request: Request) -> RedirectResponse:
    """Set the admin model allow-list from the settings page. Each checked
    ``models`` field is an allowed spec; none checked clears the restriction
    (every model allowed again). Saved to the dashboard overlay, never
    config.toml; ``llm.model_for_role`` then caps every role to this set."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick.runtime_overrides import RuntimeOverridesSecurityError, set_allowed_models
    form = await request.form()
    try:
        with _setting_write(request, "models", "allowed", lambda d:
                            (d.get("access") or {}).get("allowed_models", [])):
            await run_in_threadpool(set_allowed_models, form.getlist("models"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid model id") from exc
    except (OSError, RuntimeOverridesSecurityError) as exc:
        raise HTTPException(status_code=503, detail=(
            "Allowed models could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_allowed")
    return RedirectResponse("/settings?saved=allowed", status_code=303)


@router.post("/settings/models/discover")
async def settings_discover_models(request: Request, provider: str = Form("")) -> RedirectResponse:
    """Ask every configured provider (or one) which models its key can reach and
    cache the answer for the pickers. Bounded live requests; nothing is pinned."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick import model_discovery
    from maverick.providers import KNOWN_PROVIDERS, _canonical
    name = _canonical(provider.strip()) if provider.strip() else ""
    if name and name not in KNOWN_PROVIDERS:
        raise HTTPException(status_code=400, detail="unknown provider")
    await run_in_threadpool(model_discovery.refresh, [name] if name else None)
    _admin_audit(request, "settings_discover")
    return RedirectResponse("/settings?saved=discover", status_code=303)


def _refresh_models_quietly(provider: str) -> None:
    """Refresh one provider's reachable-model list after its key changed; a
    discovery failure is recorded in the cache, never surfaced as a save error."""
    try:
        from maverick import model_discovery
        model_discovery.refresh([provider])
    except Exception:  # pragma: no cover -- best effort by design
        pass


def _webhook_operation(request: Request, operation):
    from .webhook_settings import WebhookSettingsConflict, WebhookSettingsUnavailable

    auth.require_global_permission(request, "admin")
    principal = auth.caller_principal(request) or "local-operator"
    try:
        return operation(principal, lambda: auth.require_global_permission(request, "admin"))
    except WebhookSettingsConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except WebhookSettingsUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/settings/webhooks")
def settings_get_webhooks(request: Request) -> dict:
    """Current effective ownership and an opaque, caller-bound review token."""
    from .webhook_settings import state
    return _webhook_operation(request, lambda principal, authorize:
        state(principal=principal, authorize=authorize))


@router.post("/settings/webhooks")
def settings_set_webhooks(
    request: Request,
    secret: str = Form(""),
    expected_generation: str = Form(""),
    action: str = Form("set"),
) -> dict:
    """Confirm a reviewed rotation against the actual runtime secret resolver."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import settings_store
    return _webhook_operation(request, lambda principal, authorize:
        settings_store.set_webhooks_secret(secret, action=action,
            expected_generation=expected_generation, principal=principal, authorize=authorize))


@router.post("/settings/models/discovery")
def settings_set_model_discovery(request: Request, enabled: str = Form("on")) -> RedirectResponse:
    """Turn automatic model lists on or off from the Models section (admin)."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    import os as _os

    from maverick_dashboard import settings_store
    if _os.environ.get("MAVERICK_MODEL_DISCOVERY", "").strip():
        raise HTTPException(
            status_code=409,
            detail="Automatic model lists are controlled by your installation, so this can't be changed here.",
        )
    try:
        with _setting_write(request, "models", "discovery", lambda d:
                            (d.get("models") or {}).get("discovery")):
            settings_store.set_model_discovery(enabled == "on")
    except (OSError, settings_store.SecuritySuiteConfigUnavailable) as exc:
        raise HTTPException(
            status_code=503,
            detail="Settings could not be confirmed. Refresh Settings and Activity before retrying.",
        ) from exc
    try:
        from maverick import config as _config
        _config.reset_config_cache()
    except Exception:  # pragma: no cover -- cache reset is best effort
        pass
    _admin_audit(request, "settings_discovery")
    return RedirectResponse("/settings?saved=discovery", status_code=303)


@router.post("/settings/providers")
async def settings_set_provider(
    request: Request,
    provider: str = Form(...),
    api_key: str = Form(""),
    base_url: str = Form(""),
    auth_mode: str = Form(""),
    deployment: str = Form(""),
    api_version: str = Form(""),
    endpoint: str = Form(""),
    region: str = Form(""),
    model_id: str = Form(""),
    project_id: str = Form(""),
) -> RedirectResponse:
    """Rotate only provider fields this dashboard can make effective.

    Tenant and operator overlays outrank the dashboard overlay. Refuse those
    rotations with the exact controlling source, then verify the effective
    credential generation before reporting success.
    """
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import settings_store
    provider_name = provider.strip()
    key_value = api_key.strip()
    base_value = base_url.strip()
    setup = ({"auth_mode": auth_mode, "deployment": deployment, "api_version": api_version}
             if provider_name == "azure" else
             {"auth_mode": auth_mode, "endpoint": endpoint, "region": region, "model_id": model_id}
             if provider_name == "bedrock" else
             {"project_id": project_id, "region": region, "model_id": model_id}
             if provider_name == "vertex" else None)
    try:
        with _setting_write(request, "providers", provider_name, lambda d:
                            _provider_audit_value(d, provider_name), changed_fields=lambda old, new:
                            _provider_changed_fields(old, new, provider_name)):
            values = {"api_key": key_value, "base_url": base_value}
            if setup is not None:
                values["details"] = setup
            await run_in_threadpool(settings_store.rotate_provider, provider_name, **values)
    except settings_store.ProviderConfigurationUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except settings_store.SecuritySuiteConfigUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except settings_store.ProviderRotationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await run_in_threadpool(_refresh_models_quietly, provider_name)
    _admin_audit(request, "settings_providers")
    return RedirectResponse("/settings?saved=providers", status_code=303)


@router.post("/settings/providers/clear")
def settings_clear_provider(request: Request, provider: str = Form(...)) -> RedirectResponse:
    """Remove a provider's dashboard-set key (config.toml / env unaffected)."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import settings_store
    try:
        name = provider.strip()
        with _setting_write(request, "providers", name, lambda d:
                            _provider_audit_value(d, name), changed_fields=lambda old, new:
                            _provider_changed_fields(old, new, name)):
            settings_store.clear_provider(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="unknown provider") from exc
    _admin_audit(request, "settings_providers")
    return RedirectResponse("/settings?saved=providers", status_code=303)


@router.post("/settings/providers/test")
async def settings_test_provider(
    request: Request, provider: str = Form(...), next_page: str = Form("", alias="next")
) -> RedirectResponse:
    """Run a bounded live provider probe and bind its receipt to this config."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard.integration_readiness import test_provider
    from maverick_dashboard.provider_readiness import workspace_readiness

    name = provider.strip().lower()
    rows = (await run_in_threadpool(workspace_readiness))["providers"]
    row = next((item for item in rows if item["name"] == name), None)
    if row is None:
        raise HTTPException(status_code=400, detail="unknown provider")
    if not row["configured"]:
        raise HTTPException(status_code=409, detail="finish the provider setup before testing")
    await run_in_threadpool(test_provider, name)
    await run_in_threadpool(_refresh_models_quietly, name)
    _admin_audit(request, "settings_provider_test")
    if next_page == "providers":  # the Providers page's own Test connection button
        return RedirectResponse("/providers?tested=1", status_code=303)
    return RedirectResponse("/settings?saved=provider_test", status_code=303)


@router.post("/settings/capabilities")
async def settings_set_capabilities(request: Request) -> RedirectResponse:
    """Activate/deactivate capabilities via the dashboard config overlay."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import settings_store
    form = await request.form()
    try:
        with _setting_write(request, "capabilities", "all", lambda d:
                            d.get("capabilities") or {}):
            await run_in_threadpool(settings_store.set_toggles, "capabilities", {
                name: name in form for name in settings_store.CAPABILITY_DEFAULTS
            })
    except (OSError, settings_store.SecuritySuiteConfigUnavailable) as exc:
        raise HTTPException(
            status_code=503,
            detail="Settings could not be confirmed. Refresh Settings and Activity before retrying.",
        ) from exc
    _admin_audit(request, "settings_capabilities")
    return RedirectResponse("/settings?saved=capabilities", status_code=303)


@router.post("/settings/features")
async def settings_set_features(request: Request) -> RedirectResponse:
    """Old whole-form submissions cannot overwrite current feature choices."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    raise HTTPException(409, "This older feature form was not saved. Your draft is kept. "
                        "Open Settings, then All settings and Product features to review "
                        "only the switches you want to change.")


@router.post("/settings/ui-visibility")
async def settings_set_ui_visibility(request: Request) -> RedirectResponse:
    """Save the page-visibility matrix (admin). Every eligible, unlocked
    page x role checkbox is submitted as ``cell=role:path``; an absent cell is
    hidden. Only differences from the defaults are stored (0600 JSON, never
    config.toml); a role can never be shown a page its permissions don't reach,
    and admins always keep Settings + Users."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import ui_visibility
    form = await request.form()
    try:
        with _setting_write(request, "ui_visibility", "matrix", lambda d: d):
            await run_in_threadpool(ui_visibility.apply_selection, set(form.getlist("cell")))
    except OSError as exc:
        raise HTTPException(status_code=503, detail=(
            "Page visibility could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_visibility")
    return RedirectResponse("/settings?saved=visibility#ui-visibility", status_code=303)


@router.post("/settings/ui-visibility/reset")
def settings_reset_ui_visibility(request: Request) -> RedirectResponse:
    """Reset every page x role cell to its default visibility (admin)."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from maverick_dashboard import ui_visibility
    try:
        with _setting_write(request, "ui_visibility", "matrix", lambda d: d):
            ui_visibility.clear_overrides()
    except OSError as exc:
        raise HTTPException(status_code=503, detail=(
            "Page visibility could not be confirmed. Refresh Settings and Activity before retrying."
        )) from exc
    _admin_audit(request, "settings_visibility_reset")
    return RedirectResponse("/settings?saved=visibility_reset#ui-visibility", status_code=303)


def _invite_labels(all_invites) -> dict[str, str]:
    """Email per sign-in id for people who arrived through an accepted invite.

    An accepted invite is the one record that ties the address the owner typed
    to the federated subject the person actually signed in with, so the roster
    can read as people instead of provider id fragments."""
    labels: dict[str, str] = {}
    for inv in all_invites:
        if inv.used_by and inv.email:
            labels.setdefault(inv.used_by, inv.email)
    return labels


def _workspace_options(request: Request) -> tuple[list[dict], str]:
    """Active workspaces the caller may assign members to, and the one the
    Members section should start on (the caller's current selection when it is
    among them, else the first). Global admins see every active workspace;
    anyone else only the workspaces they hold a membership in."""
    principal = auth.caller_principal(request)
    options: list[dict] = []
    try:
        from maverick.tenant.registry import list_tenants

        from . import workspace_tenants
        visible = None
        if principal and not auth.has_global_permission(request, "admin"):
            visible = workspace_tenants.accessible_tenant_ids(principal)
            from . import rbac
            visible = {tenant for tenant in (visible or ())
                       if "admin" in rbac.permissions_for(rbac.get_tenant_role(tenant, principal))}
        options = [
            {"id": rec.id, "name": (getattr(rec, "display_name", "") or rec.id)}
            for rec in list_tenants()
            if rec.active and (visible is None or rec.id in visible)
        ]
        from .workspace_display import duplicate_workspace_ids

        duplicates = duplicate_workspace_ids((row["id"], row["name"]) for row in options)
        for row in options:
            if row["id"] in duplicates:
                row["name"] += f" (Reference: {row['id']})"
    except Exception:
        options = []
    try:
        from maverick.paths import current_tenant_id
        current = current_tenant_id() or ""
    except Exception:
        current = ""
    ids = [w["id"] for w in options]
    start = current if current in ids else (ids[0] if ids else "")
    return options, start


def _signed_in_principals(limit: int = 200) -> list[str]:
    """People who have signed in with company sign-in, most recent first."""
    try:
        from . import subject_directory
        index = subject_directory.load_index()
    except Exception:
        return []
    latest: dict[str, float] = {}
    for entry in index.values():
        sub = str(entry.get("sub") or "").strip()
        if sub:
            latest[sub] = max(latest.get(sub, 0.0), float(entry.get("ts") or 0.0))
    ordered = sorted(latest, key=lambda sub: latest[sub], reverse=True)[:limit]
    return [sub if sub.startswith("user:") else f"user:{sub}" for sub in ordered]


def _people(users: dict, labels: dict, extra) -> list[dict]:
    """Everyone the roster knows about, as choices for the people pickers.

    Sources: explicit role holders, accepted invites, department grants,
    installation administrators and people who have signed in. Each entry
    carries a readable label; the exact sign-in identity is only the value."""
    from .identity_format import humanize_principal
    seen: dict[str, dict] = {}
    for principal in [*users, *labels, *extra]:
        principal = str(principal or "").strip()
        if not principal.startswith("user:") or principal in seen:
            continue
        ident = humanize_principal(principal)
        name = labels.get(principal) or ident.name
        detail = "" if labels.get(principal) else ident.detail
        seen[principal] = {"principal": principal,
                           "label": f"{name} ({detail})" if detail and detail != "Email" else name,
                           "role": users.get(principal)}
    return sorted(seen.values(), key=lambda p: p["label"].lower())


def known_people(role_map: dict, all_invites, verified: dict | None = None) -> tuple[list[dict], dict[str, str]]:
    """The installation's people for every picker, and the readable label per sign-in id.

    One source for the Users page and Departures: explicit role holders, people
    who joined by an accepted invitation (installation-wide or into a
    workspace), department grants, installation administrators and people who
    have signed in. ``verified`` adds labels from company sign-in checks.
    ``all_invites`` is passed in so each caller chooses how an unreadable
    invitation store is handled."""
    from . import suite_grants

    labels = _invite_labels(all_invites)
    labels.update(verified or {})
    extra = [*suite_grants.list_grants(), *suite_grants.admin_principals(), *_signed_in_principals()]
    return _people(role_map, labels, extra), labels


def _users_context(request: Request) -> dict:
    """Template context for the /users page (shared with the invite handler)."""
    import os as _os

    from maverick.oidc import oidc_enabled
    from maverick.proxy_auth import proxy_auth_enabled

    from . import rbac
    from .draft_api import context_for
    people_context = context_for(request)
    global_admin = auth.has_global_permission(request, "admin")
    workspace_options, wm_tenant = _workspace_options(request)
    workspace_names = {option["id"]: option["name"] for option in workspace_options}
    if not global_admin:
        # Never expose the installation roster, global invitations or department
        # grants to a workspace administrator. Invitation labels and pending
        # links are limited to workspaces they currently administer.
        from . import invites
        from .access_explanations import role_descriptions
        from .identity_format import role_label

        try:
            workspace_invites = [inv for inv in invites.list_invites()
                                 if inv.tenant in workspace_names]
        except invites.InviteStoreError:
            workspace_invites = []
        member_rosters = {
            option["id"]: rbac.list_tenant_roles(option["id"])
            for option in workspace_options
        }
        members = {principal: role for roster in member_rosters.values()
                   for principal, role in roster.items()}
        labels = {principal: label for principal, label in _invite_labels(workspace_invites).items()
                  if principal in members}
        people = _people(members, labels, [])
        role_permissions = {r: sorted(rbac.permissions_for(r)) for r in rbac.known_roles()}
        workspace_role_options = {}
        for option in workspace_options:
            actor_role = member_rosters[option["id"]].get(auth.caller_principal(request))
            actor_permissions = rbac.permissions_for(actor_role)
            workspace_role_options[option["id"]] = [
                role for role in rbac.known_roles()
                if rbac.permissions_for(role).issubset(actor_permissions)
            ]
        return {
            "workspace_people_context": people_context,
            "global_admin": False, "people": people,
            "people_labels": {p["principal"]: p["label"] for p in people},
            "role_labels": {r: role_label(r) for r in rbac.known_roles()},
            "roles": rbac.known_roles(), "users": [], "invite_labels": labels,
            "role_permissions": role_permissions,
            "workspace_role_options": workspace_role_options,
            "workspace_roles": workspace_role_options.get(wm_tenant, []),
            "workspace_member_count": len(member_rosters.get(wm_tenant, {})),
            "role_descriptions": role_descriptions(),
            "bootstrap_admins": [], "auth_on": True, "default_role": rbac.default_role(), "workspace_roles_initialized": rbac.tenant_role_scope_initialized(),
            "you": auth.caller_principal(request),
            "saved": ("Workspace invitation revoked."
                      if request.query_params.get("saved") == "workspace_invite_revoked" else ""),
            "workspace_options": workspace_options, "wm_tenant": wm_tenant,
            "workspace_names": workspace_names,
            "invites_on": invites.invites_enabled(),
            "invite_sso_on": invites.invites_enabled() and not invites.local_login_mode(),
            "workspace_pending_invites": [inv for inv in workspace_invites if inv.pending],
            "workspace_recent_invites": [inv for inv in workspace_invites if inv.used_at is not None][:20],
        }
    auth_on = (auth.caller_principal(request) is not None
               or oidc_enabled() or proxy_auth_enabled())
    env = (_os.environ.get("MAVERICK_DASHBOARD_ADMINS") or "").strip()
    if env:
        bootstrap = [a.strip() for a in env.split(",") if a.strip()]
    else:
        try:
            from maverick.config import load_config
            raw = (load_config().get("dashboard", {}) or {}).get("admins", []) or []
            seq = raw if isinstance(raw, (list, tuple)) else [raw]
            bootstrap = [str(a).strip() for a in seq if str(a).strip()]
        except Exception:
            bootstrap = []
    saved = {"set": "Role updated.", "removed": (
                 "Explicit installation role cleared. Current group or standard-role rules now apply; "
                 "this person's access has not been removed. Workspace memberships remain in effect."),
             "suites": "Department access updated.",
             "first_login": "The effective installation fallback is now Viewer with no departments. Explicit roles, verified group mappings and workspace memberships remain in effect.",
             "suites_removed": "Department access removed.",
             "invite_revoked": "Invitation revoked.",
             "role_saved": "Custom role saved.",
             "role_deleted": "Custom role deleted.",
             "roster_reset": ("A new, empty role list was started. Earlier assignments are gone; "
                              "assign roles again before relying on them."),
             "channel_linked": "Chat account linked.",
             "channel_unlinked": "Chat account unlinked."}.get(
        request.query_params.get("saved", ""), "")
    if request.query_params.get("saved") == "removed" and request.query_params.get("reset_person"):
        from .access_explanations import standard_role
        effective = standard_role(request.query_params["reset_person"])
        saved = (f"Explicit installation role cleared. {effective['label']} from {effective['source'].lower()} "
                 f"now applies, with powers: {', '.join(effective['permissions']) or 'none'}. "
                 "Access was not removed. Workspace memberships remain in effect.")
    from maverick.departments import department_title

    from . import invites, suite_grants
    default_suites = suite_grants.default_suites()
    try:
        custom_roles = sorted(rbac.list_custom_roles().items())
    except rbac.RbacStoreError:
        custom_roles = []
    try:
        all_invites = invites.list_invites()
    except Exception:
        all_invites = []
    workspace_options, wm_tenant = _workspace_options(request)
    role_map = rbac.list_users()
    from .company_signin_tests import verified_people
    people, labels = known_people(role_map, all_invites, verified_people(request))
    grants = suite_grants.list_grants()
    from .access_explanations import role_descriptions, standard_role
    from .first_login_defaults import preview as first_login_preview
    from .identity_format import role_label
    defaults = set(default_suites) if default_suites is not None else None
    try:
        from maverick import channel_identities
        channel_links = sorted(channel_identities.all_links().items())
    except Exception:  # noqa: BLE001 -- an unreadable store must not hide the roster
        channel_links = []
    return {
        "global_admin": True,
        "workspace_people_context": people_context,
        "first_login": first_login_preview(),
        "role_permissions": {r: sorted(rbac.permissions_for(r)) for r in rbac.known_roles()},
        "role_descriptions": role_descriptions(),
        "channel_links": channel_links,
        "people": people,
        "people_labels": {p["principal"]: p["label"] for p in people},
        "role_labels": {r: role_label(r) for r in rbac.known_roles()},
        "grant_can_use_default": {
            principal: defaults is not None and defaults.issubset(set(suites))
            for principal, suites in grants.items()
        },
        "users": sorted(role_map.items()),
        **_people_filter(request, role_map, labels),
        "standard_roles": {principal: standard_role(principal) for principal in role_map},
        "roles": rbac.known_roles(),
        "workspace_roles": rbac.known_roles(),
        "workspace_role_options": {},
        "workspace_member_count": len(rbac.list_tenant_roles(wm_tenant)) if wm_tenant else 0,
        "builtin_roles": rbac.ROLES,
        "custom_roles": custom_roles,
        "permission_atoms": rbac.PERMISSION_ATOMS,
        "bootstrap_admins": sorted(bootstrap),
        "default_role": rbac.default_role(), "workspace_roles_initialized": rbac.tenant_role_scope_initialized(),
        "auth_on": auth_on,
        "you": auth.caller_principal(request),
        "saved": saved,
        "suite_grants": sorted(grants.items()),
        "all_suites": sorted(((k, department_title(k))
                              for k in suite_grants.known_suites()),
                             key=lambda kv: kv[1]),
        "default_suites": (sorted(default_suites)
                           if default_suites is not None else None),
        "invites_on": invites.invites_enabled(),
        "invite_sso_on": invites.invites_enabled() and not invites.local_login_mode(),
        "pending_invites": [i for i in all_invites if i.pending and not i.tenant],
        "workspace_pending_invites": [i for i in all_invites
                                      if i.pending and i.tenant in workspace_names],
        "workspace_recent_invites": [i for i in all_invites
                                     if i.used_at is not None and i.tenant in workspace_names][:20],
        "invite_labels": labels,
        "workspace_options": workspace_options,
        "wm_tenant": wm_tenant,
        "workspace_names": workspace_names,
        "passphrase_resets": _passphrase_resets(request),
    }


def _passphrase_resets(request: Request) -> dict | None:
    """Colleagues whose passphrase this caller may reset, or None when the
    caller may not reset any (only the installation owner)."""
    from . import passphrase_resets
    caller = passphrase_resets.can_reset(request)
    if caller is None:
        return None
    try:
        return {"accounts": passphrase_resets.accounts(caller), "unavailable": False}
    except HTTPException:
        return {"accounts": [], "unavailable": True}


def _people_filter(request: Request, role_map: dict, labels: dict) -> dict:
    """The People list's filter (``?q=`` text, ``?has_role=``) and the rows it shows."""
    from .users_bulk import matching
    query = str(request.query_params.get("q", ""))[:200]
    role_filter = str(request.query_params.get("has_role", ""))[:100]
    shown = set(matching(role_map, labels, query, role_filter))
    return {"users_filter": {"q": query, "role": role_filter, "active": bool(query.strip() or role_filter)},
            "users_shown": [(p, r) for p, r in sorted(role_map.items()) if p in shown]}


def _bulk_page(request: Request, **extra) -> HTMLResponse:
    """The Users page with a bulk confirmation, change report or problem."""
    context = _users_context(request)
    context.update(extra)
    return _app().templates.TemplateResponse(request, "users.html", context,
                                             headers={"Cache-Control": "private, no-store"})


@router.post("/users/bulk", response_class=HTMLResponse)
def users_bulk_role(
    request: Request, role: str = Form(""), scope: str = Form("selected"),
    principals: list[str] = Form(default=[]), q: str = Form(""), role_filter: str = Form(""),
    confirmed: str = Form(""), expected_count: int = Form(0),
) -> HTMLResponse:
    """Change the role of several people: first a confirmation that states the
    count, then (``confirmed=yes``) the change and a report that can be undone."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import invites, rbac, users_bulk
    try:
        labels = _invite_labels(invites.list_invites())
    except Exception:  # noqa: BLE001 -- labels only help the text filter
        labels = {}
    people = users_bulk.targets(rbac.list_users(), labels, scope=scope, chosen=principals,
                                query=q, role_filter=role_filter)
    problem = ""
    if not rbac.is_known_role(role.strip()):
        problem = "Choose the new role."
    elif not people:
        problem = "Select at least one person, or choose everyone matching the filter."
    elif len(people) > users_bulk.MAX_PEOPLE:
        problem = f"Change at most {users_bulk.MAX_PEOPLE} people at once. Narrow the filter first."
    if problem:
        return _bulk_page(request, bulk_problem=problem)
    role = role.strip()
    if confirmed != "yes" or expected_count != len(people):
        changed_since = confirmed == "yes"
        return _bulk_page(request, bulk_confirm={
            "people": people, "role": role, "count": len(people), "changed_since": changed_since,
            "current": rbac.list_users()})
    step_up.require_recent_mfa(request, "change_role")
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        auth.require_global_permission(request, "admin")
        report = users_bulk.apply(people, role, actor=auth.caller_principal(request) or "local")
    return _bulk_page(request, bulk_report={"rows": report, "undo": users_bulk.undo_tokens(report),
                                            "undone": False})


@router.post("/users/bulk/undo", response_class=HTMLResponse)
def users_bulk_undo(request: Request, restore: list[str] = Form(default=[])) -> HTMLResponse:
    """Put the people from a bulk change back on the roles they had before."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    step_up.require_recent_mfa(request, "change_role")
    from maverick.authority_effects import authority_effect_fence

    from . import users_bulk
    with authority_effect_fence():
        auth.require_global_permission(request, "admin")
        report = users_bulk.undo(restore, actor=auth.caller_principal(request) or "local")
    return _bulk_page(request, bulk_report={"rows": report, "undo": [], "undone": True})


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request) -> HTMLResponse:
    """Admin: manage dashboard user roles (admin / operator / auditor / viewer)."""
    auth.require_permission(request, "admin")
    from . import rbac
    try:
        context = _users_context(request)
    except rbac.RosterMissingError:
        # Only an installation administrator (a configured bootstrap admin
        # while roles are unreadable) may see or start the recovery.
        auth.require_global_permission(request, "admin")
        return _app().templates.TemplateResponse(request, "error.html", {
            "status": 503, "title": "The role list is missing",
            "message": ("Lightwork recorded a role list on this installation, but it is missing, so "
                        "nobody's stored role is used and no access is granted from it. Restore "
                        "dashboard-users.json (and dashboard-tenant-roles.json) from a backup, or "
                        "start a new, empty role list and assign roles again."),
            "path": request.url.path, "gate": "roster_missing", "reauthenticate": "", "feature": {},
        }, status_code=503, headers={"Cache-Control": "private, no-store"})
    return _app().templates.TemplateResponse(request, "users.html", context)


@router.post("/users/roster/reset")
def users_roster_reset(request: Request, confirm: str = Form("")) -> RedirectResponse:
    """Explicitly start new, empty role lists where recorded ones are missing.

    Recovery for an installation administrator when no backup can be
    restored. Present rosters, including corrupt ones, are never replaced.
    """
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    if confirm != "reset":
        raise HTTPException(status_code=422, detail="Confirm that earlier role assignments are gone before starting a new role list.")
    step_up.require_recent_mfa(request, "change_role")
    from . import rbac
    if not rbac.reset_missing_rosters(actor=auth.caller_principal(request) or "local"):
        raise HTTPException(status_code=409, detail="No missing role list was found. Nothing was changed.")
    return RedirectResponse("/users?saved=roster_reset", status_code=303)


@router.post("/users/passphrase-reset", response_class=HTMLResponse)
def users_passphrase_reset(request: Request, email: str = Form(...), confirm: str = Form("")) -> HTMLResponse:
    """Reset a colleague's forgotten passphrase, or give a person with access but no
    passphrase a first link, and show its one-time link ONCE.

    Only the installation owner; never a workspace administrator or an
    administrator named in configuration (see :mod:`passphrase_resets`)."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import local_passphrases, passphrase_resets
    if not local_passphrases.available():
        raise HTTPException(status_code=404, detail="Passphrase sign-in is not used in this workspace.")
    passphrase_resets.actor(request)
    if confirm != "reset":
        raise HTTPException(status_code=422, detail=(
            "Confirm the reset: it removes this person's passphrase and signs them out everywhere."))
    step_up.require_recent_mfa(request, "reset_passphrase")
    token, record = passphrase_resets.issue(request, email)
    link = str(request.base_url).rstrip("/") + f"/auth/invite/reset/{token}"
    return _app().templates.TemplateResponse(request, "users.html", {
        **_users_context(request), "passphrase_reset_link": link,
        "passphrase_reset_email": record["email"], "passphrase_reset_expires_at": record["expires_at"],
        "passphrase_reset_first": record["first"],
    }, headers={"Cache-Control": "private, no-store"})


@router.get("/users/access", response_class=HTMLResponse)
def users_access_page(request: Request, person: str = "") -> HTMLResponse:
    """Admin: what one person can do and which rule allows each thing.

    Read-only. Global administrators only: the answer reads the installation
    roster, every workspace membership and the department grants."""
    auth.require_global_permission(request, "admin")
    principal = person.strip()
    if not principal.startswith("user:") or len(principal) > 1024:
        raise HTTPException(status_code=404, detail="Choose a person on the Users page to check their access.")
    from . import effective_access, invites, rbac, suite_grants
    try:
        labels = _invite_labels(invites.list_invites())
    except Exception:  # noqa: BLE001 -- an unreadable invite store only loses the email label
        labels = {}
    try:
        known = (principal in rbac.list_users() or principal in labels
                 or suite_grants.get_grant(principal) is not None
                 or auth.is_dashboard_admin(principal)
                 or principal in _signed_in_principals(limit=10_000))
    except Exception:  # noqa: BLE001 -- the roster note is advisory
        known = True
    from maverick.oidc import oidc_enabled
    from maverick.proxy_auth import proxy_auth_enabled
    auth_on = auth.caller_principal(request) is not None or oidc_enabled() or proxy_auth_enabled()
    return _app().templates.TemplateResponse(request, "user_access.html", {
        "report": effective_access.person(principal), "name": labels.get(principal, ""),
        "known": known, "auth_on": auth_on,
    }, headers={"Cache-Control": "private, no-store"})


@router.post("/users/set")
def users_set_role(
    request: Request, principal: str = Form(...), role: str = Form(...),
) -> RedirectResponse:
    """Assign a dashboard role to a user principal (admin only)."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    step_up.require_recent_mfa(request, "change_role")
    from . import rbac
    try:
        rbac.set_role(principal.strip(), role.strip(),
                      actor=auth.caller_principal(request) or "local")
    except rbac.RecoveryAuthorityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        from .product_errors import background_save, product_error
        if background_save(request):
            message = "Choose a person and a role from the lists."
            raise product_error(422, "role_invalid", message, field_errors={"role": message}) from exc
        raise HTTPException(status_code=400, detail="invalid principal or role") from exc
    return RedirectResponse("/users?saved=set", status_code=303)


@router.post("/users/remove")
def users_remove(request: Request, principal: str = Form(...), expected_standard: str = Form(...)) -> RedirectResponse:
    """Remove a user's explicit role assignment (admin only). A bootstrap admin
    pinned in config is unaffected — it can't be removed here."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick.authority_effects import authority_effect_fence

    step_up.require_recent_mfa(request, "change_role")
    from . import rbac
    from .access_explanations import standard_role
    try:
        with authority_effect_fence():
            auth.require_global_permission(request, "admin")
            if standard_role(principal.strip())["revision"] != expected_standard:
                raise HTTPException(409, "The fallback role or its powers changed. Reload and review before resetting.")
            rbac.remove_user(principal.strip(), actor=auth.caller_principal(request) or "local")
    except rbac.RecoveryAuthorityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    from urllib.parse import urlencode
    return RedirectResponse("/users?" + urlencode({"saved": "removed", "reset_person": principal.strip()}), status_code=303)


@router.post("/users/first-login-baseline")
def users_first_login_baseline(request: Request, expected_revision: str = Form(...), confirm: str = Form(...)):
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    step_up.require_recent_mfa(request, "change_role")
    if confirm != "existing-unassigned":
        raise HTTPException(422, "Review how existing unassigned accounts will change.")
    from .first_login_defaults import apply_conservative
    apply_conservative(request, expected_revision)
    return RedirectResponse("/users?saved=first_login", status_code=303)


@router.post("/users/roles/save")
def users_save_custom_role(
    request: Request,
    name: str = Form(...),
    permissions: list[str] = Form([]),
    description: str = Form(""),
) -> RedirectResponse:
    """Create or update a custom role (admin only). Permission checkboxes come
    in as repeated form fields; "view" is always granted (rbac enforces it),
    so the form only offers the operate/audit/admin atoms on top."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import rbac
    atoms = {str(p).strip() for p in permissions if str(p).strip()}
    atoms.add("view")
    # People type a role name ("Privacy officer"); the stored key is derived
    # from it (privacy-officer), so saving the same name again updates it.
    from .plain_labels import slugify
    key = slugify(name, max_len=32)
    if key and not key[0].isalpha():
        key = ("role-" + key)[:32]
    if len(key) < 2:
        raise HTTPException(status_code=400, detail="Give the role a name of at least two letters.")
    try:
        rbac.set_custom_role(
            key,
            sorted(atoms),
            description.strip(),
            actor=auth.caller_principal(request) or "local",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/users?saved=role_saved", status_code=303)


@router.post("/users/roles/delete")
def users_delete_custom_role(
    request: Request, name: str = Form(...)
) -> RedirectResponse:
    """Delete a custom role (admin only). Refused while anyone still holds it."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import rbac
    try:
        rbac.delete_custom_role(
            name.strip(), actor=auth.caller_principal(request) or "local"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/users?saved=role_deleted", status_code=303)


def _existing_account_refusal(request: Request, email: str, *, scoped: bool = False,
                              **payload) -> HTTPException:
    """An invitation for someone who can already sign in: recorded and refused.

    An installation administrator can already see every account, so they are told
    why. A workspace administrator is told only that the invitation could not be
    made: the same words whichever store matched and whether the person belongs
    to another workspace, so the refusal cannot be used to look people up.
    """
    from .local_passphrases import ACCOUNT_EXISTS, NOT_INVITABLE
    from .product_errors import background_save, product_error

    _admin_audit(request, "invite_refused", email=(email or "").strip().lower(),
                 reason="existing_local_account", **payload)
    message = NOT_INVITABLE if scoped else ACCOUNT_EXISTS
    if background_save(request):
        return product_error(409, "invite_not_created" if scoped else "invite_existing_account",
                             message, field_errors={"email": message})
    return HTTPException(status_code=409, detail=message)


def _invite_rate_refusal(request: Request, exc: Exception) -> HTTPException:
    from .product_errors import background_save, product_error

    if background_save(request):
        return product_error(429, "invite_rate_limited", str(exc))
    return HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "600"})


def _invite_refusal(reason: str) -> HTTPException:
    """An invite the store refused, in words for the person who typed it."""
    from .product_errors import product_error
    if "expiry" in reason:
        message = "Choose when the invitation link should expire."
        return product_error(422, "invite_expiry", message, field_errors={"expiry": message})
    if "email" in reason:
        message = "Enter a full email address. For example: name@company.com."
        return product_error(422, "invite_email", message, field_errors={"email": message})
    if "role" in reason:
        message = "Choose a role from the list."
        return product_error(422, "invite_role", message, field_errors={"role": message})
    if "too many" in reason:
        return product_error(409, "invite_full", "There are too many invitations waiting. "
                             "Cancel some you no longer need, then try again.")
    return product_error(422, "invite_invalid", "The invitation could not be created. Check the details and try again.")


@router.post("/users/invite", response_class=HTMLResponse)
def users_invite(request: Request, email: str = Form(...),
                 role: str = Form(...), expiry: str = Form("7_days"),
                 expected_context: str | None = Form(default=None)) -> HTMLResponse:
    """Mint a single-use invite link (admin only) and show it ONCE.

    The token is never stored (only its hash), so this response is the only
    place the link exists — the admin copies it into an email/chat to the
    invitee. Renders the users page directly instead of redirecting, because a
    redirect would drop the one-time link."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick.authority_effects import authority_effect_fence

    from . import invites
    from .invite_routes import require_people_context
    if not invites.invites_enabled():
        raise HTTPException(status_code=404, detail="invites are not enabled")
    invited_by = auth.caller_principal(request) or "local-admin"
    def guard() -> None:
        auth.require_global_permission(request, "admin")
        require_people_context(request, expected_context)
        if not invites.invites_enabled():
            raise HTTPException(404, "Invitations are not enabled.")
    try:
        ttl = invites.expiry_hours(expiry)
        with authority_effect_fence():
            guard()
            inv, token = invites.create_invite(email, role, created_by=invited_by,
                                              ttl_hours=ttl, before_effect=guard)
    except invites.ExistingAccountError as exc:
        raise _existing_account_refusal(request, email) from exc
    except ValueError as exc:
        from .product_errors import background_save
        if background_save(request):
            raise _invite_refusal(str(exc)) from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    link = str(request.base_url).rstrip("/") + f"/auth/invite/{token}"
    _admin_audit(request, "invite_created", email=inv.email, role=getattr(inv, "role", role),
                 expires_at=inv.expires_at, expiry=expiry, ttl_hours=ttl)
    # Best-effort email (fail-soft): the copyable link below is always the
    # fallback, so a broken SMTP account can never strand an invite.
    sent, send_note = invites.send_invite_email(inv, link, invited_by=invited_by)
    return _app().templates.TemplateResponse(request, "users.html", {
        **_users_context(request), "invite_link": link, "invite_email": inv.email,
        "invite_sent": sent, "invite_send_note": send_note, "invite_expires_at": inv.expires_at,
    })


@router.post("/users/invite/revoke")
def users_invite_revoke(request: Request,
                       invite_id: str = Form(...)) -> RedirectResponse:
    """Revoke a pending invite link (admin only)."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import invites
    invites.revoke_invite(invite_id.strip())
    _admin_audit(request, "invite_revoked", invite_id=invite_id.strip())
    return RedirectResponse("/users?saved=invite_revoked", status_code=303)


def _workspace_invite_authority(request: Request, tenant: str, role: str | None = None) -> bool:
    """Authorize a workspace invitation against its exact workspace.

    Return whether the caller is an installation administrator. Scoped callers
    may offer only a role no more powerful than their current direct role.
    """
    from . import api, rbac

    installation_admin = api._require_tenant_roles_admin(request, tenant)
    if not api._get_tenant_or_404(tenant).active:
        raise HTTPException(403, "This workspace is not active.")
    if role is not None:
        if not rbac.is_known_role(role):
            raise HTTPException(400, "Choose an available role.")
        if not installation_admin:
            actor_role = rbac.get_tenant_role(tenant, auth.caller_principal(request))
            if not rbac.permissions_for(role).issubset(rbac.permissions_for(actor_role)):
                raise HTTPException(409, "Your workspace role cannot invite this level of access.")
    return installation_admin


@router.post("/users/workspace-invite", response_class=HTMLResponse)
def users_workspace_invite(
    request: Request, tenant: str = Form(...), email: str = Form(...), role: str = Form(...),
    expected_context: str | None = Form(default=None), expiry: str = Form("7_days"),
) -> HTMLResponse:
    """Create a single-use invitation for one existing workspace only."""
    _app()._require_same_origin(request)
    from maverick.authority_effects import authority_effect_fence

    from . import api, invites

    if not invites.invites_enabled():
        raise HTTPException(404, "Invitations are not enabled.")
    api._reject_tenant_role_assignment_under_per_user_tenancy()
    _workspace_invite_authority(request, tenant, role)
    step_up.require_recent_mfa(request, "change_role")
    invited_by = auth.caller_principal(request) or "local-admin"
    from .invite_routes import require_people_context

    def guard() -> None:
        require_people_context(request, expected_context)
        _workspace_invite_authority(request, tenant, role)
        step_up.require_recent_mfa(request, "change_role")
        if not invites.invites_enabled():
            raise HTTPException(404, "Invitations are not enabled.")
    with authority_effect_fence():
        guard()
        installation_admin = _workspace_invite_authority(request, tenant, role)
        try:
            ttl = invites.expiry_hours(expiry)
            inv, token = invites.create_invite(
                email, role, created_by=invited_by, tenant=tenant,
                workspace_admin_invite=not installation_admin,
                ttl_hours=ttl, before_effect=guard,
            )
        except invites.ExistingAccountError as exc:
            raise _existing_account_refusal(request, email, scoped=not installation_admin,
                                            workspace=tenant) from exc
        except invites.InviteRateLimited as exc:
            raise _invite_rate_refusal(request, exc) from exc
        except ValueError as exc:
            from .product_errors import background_save
            if background_save(request):
                raise _invite_refusal(str(exc)) from exc
            raise HTTPException(400, str(exc)) from exc
    link = str(request.base_url).rstrip("/") + f"/auth/invite/{token}"
    _admin_audit(request, "workspace_invite_created", workspace=tenant,
                 email=inv.email, role=inv.role, expires_at=inv.expires_at,
                 expiry=expiry, ttl_hours=ttl)
    sent, send_note = invites.send_invite_email(inv, link, invited_by=invited_by)
    return _app().templates.TemplateResponse(request, "users.html", {
        **_users_context(request), "workspace_invite_link": link,
        "workspace_invite_email": inv.email, "workspace_invite_tenant": tenant,
        "workspace_invite_sent": sent, "workspace_invite_send_note": send_note,
        "workspace_invite_expires_at": inv.expires_at,
    })


@router.post("/users/workspace-invite/revoke")
def users_workspace_invite_revoke(
    request: Request, invite_id: str = Form(...),
    expected_context: str | None = Form(default=None),
) -> RedirectResponse:
    """Cancel a pending invite only when the caller administers its workspace."""
    _app()._require_same_origin(request)
    from maverick.authority_effects import authority_effect_fence

    from . import invites

    if not invites.invites_enabled():
        raise HTTPException(404, "Invitations are not enabled.")
    with authority_effect_fence():
        from .invite_routes import require_people_context
        require_people_context(request, expected_context)
        invite = next((item for item in invites.list_invites()
                       if item.id == invite_id.strip() and item.tenant and item.pending), None)
        if invite is None:
            raise HTTPException(404, "Invitation not found.")
        _workspace_invite_authority(request, invite.tenant)
        if not invites.revoke_invite(invite.id):
            raise HTTPException(404, "Invitation not found.")
    _admin_audit(request, "workspace_invite_revoked", workspace=invite.tenant,
                 invite_id=invite.id)
    return RedirectResponse("/users?saved=workspace_invite_revoked", status_code=303)


@router.post("/users/invite/bulk-revoke", response_class=HTMLResponse)
def users_invite_bulk_revoke(
    request: Request, scope: str = Form("selected"), invite_ids: list[str] = Form(default=[]),
    confirmed: str = Form(""), expected_count: int = Form(0),
) -> HTMLResponse:
    """Cancel several pending invitations: confirm the count, then a report."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import invites
    pending = [i for i in invites.list_invites() if i.pending]
    chosen = {i.strip() for i in invite_ids if i and i.strip()}
    picked = pending if scope == "all" else [i for i in pending if i.id in chosen]
    if not picked:
        return _bulk_page(request, bulk_problem="Select at least one waiting invitation.")
    if confirmed != "yes" or expected_count != len(picked):
        return _bulk_page(request, invite_confirm={"invites": picked, "changed_since": confirmed == "yes"})
    report = []
    for inv in picked:
        cancelled = invites.revoke_invite(inv.id)
        if cancelled:
            _admin_audit(request, "invite_revoked", invite_id=inv.id)
        report.append({"email": inv.email, "cancelled": cancelled})
    return _bulk_page(request, invite_report=report)


@router.post("/users/suites/set")
async def users_set_suites(request: Request) -> RedirectResponse:
    """Scope a user to a set of departments (global admin only).

    The grant store is GLOBAL control-plane data (like the role roster), so
    this requires the global admin role — a tenant-local admin may not scope
    users across the deployment. An empty selection is a valid grant meaning
    "no departments". Removing an override is allowed only when the configured
    default is no broader than the current grant."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import suite_grants
    form = await request.form()
    principal = str(form.get("principal", "")).strip()
    suites = [str(s) for s in form.getlist("suites")]
    try:
        await run_in_threadpool(
            suite_grants.set_suites, principal, suites,
            actor=auth.caller_principal(request) or "local",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid principal or department") from exc
    _admin_audit(request, "department_access_set", principal=principal, suites=sorted(suites))
    return RedirectResponse("/users?saved=suites", status_code=303)


@router.post("/users/suites/remove")
def users_remove_suites(
    request: Request, principal: str = Form(...),
) -> RedirectResponse:
    """Remove a department override without broadening access."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from . import suite_grants
    try:
        suite_grants.remove_grant(
            principal.strip(), actor=auth.caller_principal(request) or "local"
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _admin_audit(request, "department_access_removed", principal=principal.strip())
    return RedirectResponse("/users?saved=suites_removed", status_code=303)



# -- Spending limits ---------------------------------------------------------

_LIMIT_SAVED = {
    "workspace": "Workspace limit saved.",
    "workspace_cleared": "The workspace no longer has a spending limit.",
    "default": "Limit for everyone saved.",
    "default_cleared": "People without their own limit can now spend without a limit.",
    "person": "Personal limit saved.",
    "person_cleared": "Personal limit removed.",
}
_LIMIT_ERRORS = {
    "amount": "Enter the limit as an amount in dollars, more than $0.",
    "period": "Choose how often the limit resets.",
    "person": "Choose a person.",
    "full": "There are too many personal limits to add another.",
    "unreadable": "The saved spending limits could not be read. Try again.",
}


@router.get("/spending-limits", response_class=HTMLResponse)
def spending_limits_page(request: Request, saved: str = "", error: str = "",
                         preview: str = "", amount: str = "", period: str = "",
                         principal: str = "") -> HTMLResponse:
    """Admin: workspace and per-person spending limits (none by default).

    ``?preview=workspace|default|person`` with an amount and period replays
    the last 30 days of finished tasks against that limit, report-only:
    nothing is saved until the administrator presses Save."""
    auth.require_permission(request, "admin")
    from maverick import spending_limits
    from maverick.paths import current_tenant_id, current_tenant_id_strict
    from maverick.quotas import UsageLedger

    from . import rbac
    if auth.has_global_permission(request, "admin"):
        people = set(rbac.list_users())
    else:
        try:
            tenant = current_tenant_id_strict()
            if not tenant:
                raise ValueError("workspace is unavailable")
            people = set(rbac.list_tenant_roles(tenant))
        except Exception as exc:
            raise HTTPException(503, "Workspace membership is unavailable.") from exc
    try:
        people |= set(UsageLedger()._load())
    except Exception:  # noqa: BLE001 -- spend history is a convenience here
        pass
    people.discard("")
    load_error = ""
    try:
        view = spending_limits.overview(sorted(people))
    except Exception:  # noqa: BLE001 -- show a plain message, never a trace
        load_error = ("The saved spending limits could not be read, so paid work is "
                      "paused. Save the limits below again to repair them.")
        view = {"workspace": None, "default": None, "people": [],
                "workspace_today": 0.0, "workspace_month": 0.0}
    organization_cap = 0.0
    try:
        from maverick.tenant.registry import get_tenant
        record = get_tenant(current_tenant_id() or "")
        organization_cap = float(record.max_daily_dollars) if record else 0.0
    except Exception:  # noqa: BLE001 -- the organization cap is informational here
        pass
    replay, replay_error = _limit_preview(preview, amount, period, principal)
    return _app().templates.TemplateResponse(request, "spending_limits.html", {
        "view": view,
        "alert_at": _alert_points(),
        "preview": replay, "preview_error": replay_error,
        "draft": {"scope": preview, "amount": amount, "period": period, "principal": principal},
        "periods": [(p, spending_limits.PERIOD_LABELS[p]) for p in spending_limits.PERIODS],
        "workspace_periods": [(p, spending_limits.PERIOD_LABELS[p])
                              for p in spending_limits.WORKSPACE_PERIODS],
        "period_labels": spending_limits.PERIOD_LABELS,
        "organization_cap": organization_cap,
        "saved": _LIMIT_SAVED.get(saved, ""),
        "error": _LIMIT_ERRORS.get(error, ""),
        "load_error": load_error,
    })


def _limit_preview(scope: str, amount: str, period: str, principal: str) -> tuple[dict | None, str]:
    """The report-only replay for a proposed limit, or a plain error."""
    if scope not in ("workspace", "default", "person"):
        return None, ""
    from maverick import spending_limits
    from maverick.spending_limit_preview import preview
    try:
        return preview(scope, amount, period, principal=principal, world=_app()._world()), ""
    except spending_limits.SpendingLimitError as exc:
        return None, _LIMIT_ERRORS.get(exc.code, _LIMIT_ERRORS["amount"])
    except Exception:  # noqa: BLE001 -- the preview is advice; say it is unavailable
        return None, "The task history could not be read, so there is no preview. Saving still works."


def _alert_points() -> str:
    """The spending-alert percentages in words ("50%, 75% and 100%"), or ""."""
    from maverick.spending_alerts import alert_at
    try:
        points = [f"{p}%" for p in alert_at()]
    except Exception:  # noqa: BLE001 -- unreadable settings keep the default points
        points = ["50%", "75%", "100%"]
    if len(points) < 2:
        return "".join(points)
    return ", ".join(points[:-1]) + " and " + points[-1]


def _limit_redirect(saved: str = "", error: str = "") -> RedirectResponse:
    from urllib.parse import urlencode
    query = urlencode({"saved": saved} if saved else {"error": error})
    return RedirectResponse(f"/spending-limits?{query}", status_code=303)


# The form field each refusal is about, for a save made in the background.
_LIMIT_ERROR_FIELDS = {"amount": "amount", "period": "period", "person": "principal"}


def _limit_error(request: Request, code: str) -> RedirectResponse:
    """A refused limit: the page with its message, or, for a background save,
    the same message tied to its field (nothing typed is lost)."""
    from .product_errors import background_save, product_error
    if not background_save(request):
        return _limit_redirect(error=code)
    message = _LIMIT_ERRORS.get(code, _LIMIT_ERRORS["amount"])
    field = _LIMIT_ERROR_FIELDS.get(code)
    raise product_error(422, f"spending_limit_{code}", message,
                        field_errors={field: message} if field else None)


@router.post("/spending-limits/workspace")
def spending_limits_workspace(request: Request, choice: str = Form("none"),
                              amount: str = Form(""), period: str = Form("month")) -> RedirectResponse:
    auth.require_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import spending_limits
    actor = auth.caller_principal(request) or "local"
    try:
        if choice == "none":
            step_up.require_recent_mfa(request, "remove_spending_limit")
            spending_limits.clear_workspace_limit(actor=actor)
            return _limit_redirect("workspace_cleared")
        spending_limits.set_workspace_limit(amount, period, actor=actor)
    except spending_limits.SpendingLimitError as exc:
        return _limit_error(request, exc.code)
    return _limit_redirect("workspace")


@router.post("/spending-limits/default")
def spending_limits_default(request: Request, choice: str = Form("none"),
                            amount: str = Form(""), period: str = Form("month")) -> RedirectResponse:
    auth.require_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import spending_limits
    actor = auth.caller_principal(request) or "local"
    try:
        if choice == "none":
            step_up.require_recent_mfa(request, "remove_spending_limit")
            spending_limits.clear_default_limit(actor=actor)
            return _limit_redirect("default_cleared")
        spending_limits.set_default_limit(amount, period, actor=actor)
    except spending_limits.SpendingLimitError as exc:
        return _limit_error(request, exc.code)
    return _limit_redirect("default")


@router.post("/spending-limits/person")
def spending_limits_person(request: Request, principal: str = Form(""),
                           amount: str = Form(""), period: str = Form("month"),
                           action: str = Form("save")) -> RedirectResponse:
    auth.require_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import spending_limits
    actor = auth.caller_principal(request) or "local"
    try:
        if action == "remove":
            step_up.require_recent_mfa(request, "remove_spending_limit")
            spending_limits.clear_user_limit(principal, actor=actor)
            return _limit_redirect("person_cleared")
        spending_limits.set_user_limit(principal, amount, period, actor=actor)
    except spending_limits.SpendingLimitError as exc:
        return _limit_error(request, exc.code)
    return _limit_redirect("person")
