"""Safe account preferences with explicit scope, inheritance, and review versions."""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from maverick import experience_preferences as preferences
from pydantic import BaseModel, Field

from . import auth
from .draft_api import context_for

router = APIRouter()
PROFILE_FIELDS = frozenset({'tone', 'language', 'interface_language', 'verbosity', 'output_style', 'custom_style_name',
                            'custom_style', 'theme', 'font', 'density', 'text_size', 'glass'})


def _app():
    from . import app
    return app


def _principal(request: Request) -> str:
    with auth.fresh_configuration():
        return _fresh_principal(request)


def _fresh_principal(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
               "proxy": auth._proxy_principal}.get((getattr(principal, "claims", None) or {}).get("via"))
    if refresh is not None:
        fresh = refresh(request)
        if fresh is None or fresh.principal != principal.principal:
            raise HTTPException(401, "Sign in again to use your private preferences.")
        request.state.principal = principal = fresh
    if principal is not None:
        auth._enforce_scim_active(principal)
        auth._enforce_workspace_policies(request, principal)
    auth.require_permission(request, "view")
    principal = auth.caller_principal(request)
    if not principal:
        raise HTTPException(403, "Sign in to save preferences to your account. Display preferences can still be saved on this device.")
    if not preferences.enabled():
        raise HTTPException(403, "Personal preferences are turned off in Settings.")
    return principal


def _destinations(request: Request) -> dict[str, str]:
    groups = _app()._nav_context(request)["finder_pages"]
    return {link["href"]: link["label"] for group in groups for link in group["links"]}


def _thread(request: Request, thread: int | None) -> int | None:
    if thread is not None:
        goal = _app()._world().get_goal(thread)
        if goal is None or goal.owner != auth.caller_principal(request):
            raise HTTPException(403, "Choose a conversation that belongs to your account.")
        from maverick.chat_threads import ChatThreads
        binding = ChatThreads(_app()._world()).binding(thread)
        if binding is not None:
            return binding.root_id
    return thread


def _state(request: Request, thread: int | None = None) -> dict:
    with auth.fresh_configuration():
        return _current_state(request, thread)


def _current_state(request: Request, thread: int | None = None) -> dict:
    principal = _principal(request)
    state = preferences.state(principal, thread=_thread(request, thread))
    destinations = _destinations(request)
    # The one pin list (the sidebar's Pinned pages): the person's own, or their
    # role's starting set until they choose; only pages they may open now.
    from .navigation_api import pin_hrefs
    state["values"]["favorites"], _preset = pin_hrefs(state, destinations, _app()._page_role(request))
    if state["values"]["start_page"] not in destinations:
        state["values"]["start_page"] = "/chat"
    ai_models, specialists = [], []
    if thread is None and auth.has_permission(request, "operate"):
        from .task_model_selection_api import choices
        ai_models = choices(request)
        from .product_operations_task_launch import published_specialists
        specialists = published_specialists(request)["choices"]
    return {**state, "context": context_for(request), "destinations": destinations, "chat_models": ai_models, "chat_specialists": specialists,
            "scopes": ["personal"] + (["workspace"] if auth.has_permission(request, "admin") else []) +
                      (["organization"] if auth.has_global_permission(request, "admin") else [])}


def personal_specialist_default(request) -> str:
    """Only the person's saved name; publication and execution remain separate."""
    from .task_model_selection_api import current_authority
    with auth.fresh_configuration():
        current_authority(request)
        context, principal = context_for(request), auth.caller_principal(request)
        name = preferences.state(principal)["values"]["chat_specialist"] if principal and preferences.enabled() else ""
        current_authority(request)
        if context != context_for(request):
            raise HTTPException(409, "Your account or workspace changed while your Chat default was read.")
        return name


@router.get('/preferences')
def preferences_page(request: Request, thread: int | None = None):
    from maverick.persona import load_persona, style_choices
    from maverick.styles import BUILTIN_STYLES

    from .navigation_api import navigation_settings
    from .preference_memory import describe

    state = _state(request, thread)
    return _app().templates.TemplateResponse(request, 'preferences.html', {
        "preference_state": state, "preference_thread": thread, "tones": style_choices(),
        "preference_can_operate": auth.has_permission(request, "operate"),
        "memory_preferences": describe(request) if thread is None else None,
        "navigation_choice": navigation_settings()[1],
        "output_styles": BUILTIN_STYLES, "preference_themes": [("system", "Follow system")] + [(name, {"light": "Light", "dark": "Dark", "solarized": "Solarized", "hicontrast": "High contrast"}.get(name, name)) for name in sorted(_app()._valid_theme_names())], "legacy_name": load_persona().get("user_name", "") if auth.has_global_permission(request, "admin") else "",
    }, headers={"Cache-Control": "private, no-store"})


@router.get('/api/v1/preferences')
def current_preferences(request: Request, thread: int | None = None):
    return JSONResponse(_state(request, thread), headers={"Cache-Control": "private, no-store"})


class PreferenceUpdate(BaseModel):
    expected_revision: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    context: str
    scope: str = "personal"
    thread: int | None = None
    changes: dict[str, Any]
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    specialist_revision: str | None = Field(default=None, pattern=r"^(?:|[a-f0-9]{64})$")


def _check_display(key: str, value: str) -> None:
    from .i18n import LANGS

    allowed = {"theme": {*_app()._valid_theme_names(), "system"},
               "font": _app()._VALID_FONTS, "density": _app()._VALID_DENSITIES,
               "language": set(LANGS), "interface_language": {"", *LANGS}, "text_size": {"standard", "large", "larger"},
               "glass": {"off", "on"}}
    if key not in allowed or not isinstance(value, str) or value not in allowed[key]:
        raise HTTPException(422, "Choose an available display preference.")


@router.post('/api/v1/preferences')
def update_preferences(request: Request, body: PreferenceUpdate) -> JSONResponse:
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        return _update_preferences(request, body)


def _update_preferences(request: Request, body: PreferenceUpdate) -> JSONResponse:
    _app()._require_same_origin(request)
    auth.require_personal_write(request)
    principal = _principal(request)
    if body.thread is not None and body.scope != "personal":
        raise HTTPException(422, "Conversation styles belong to one person; choose Personal scope.")
    if not auth.constant_time_equals(body.context, context_for(request)):
        raise HTTPException(409, "The account or workspace changed. Reload before saving preferences.")
    if body.scope == "organization":
        auth.require_global_permission(request, "admin")
    elif body.scope == "workspace":
        auth.require_permission(request, "admin")
    elif body.scope != "personal":
        raise HTTPException(422, "Choose Personal, Workspace, or Organization.")
    destinations = _destinations(request)
    for key, value in body.changes.items():
        if value is None:
            continue
        if key in {"theme", "font", "density", "language", "interface_language", "text_size", "glass"}:
            _check_display(key, value)
        if key == "start_page" and (not isinstance(value, str) or value not in destinations):
            raise HTTPException(403, "That starting page is not available to your account. Choose another starting page.")
        if key == "favorites" and (not isinstance(value, list) or any(not isinstance(item, str) or item not in destinations for item in value)):
            raise HTTPException(403, "Only currently available pages can be pinned.")
        if key == "today_cards" and (not isinstance(value, list) or any(not isinstance(item, str) or item not in {"tasks", "decisions", "recent", "schedules", "templates"} for item in value)):
            raise HTTPException(422, "Choose an available Today card.")
        if key == "template_favorites":
            from .today_projection import template_choices
            choices = template_choices(request)
            if not isinstance(value, list) or any(not isinstance(item, str) or item not in choices for item in value):
                raise HTTPException(403, "Only currently accessible templates can be pinned.")
    _validate_chat_defaults(request, body)
    try:
        preferences.save(principal, scope=body.scope, changes=body.changes,
                         expected_revision=body.expected_revision, thread=_thread(request, body.thread), operation_id=body.operation_id,
                         before_effect=_effect_guard(request, body, principal), specialist_revision=body.specialist_revision)
    except preferences.PreferenceConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    response = JSONResponse(_state(request, body.thread), headers={"Cache-Control": "private, no-store"})
    if body.scope == 'personal' and body.thread is None:
        for key in set(body.changes) & {'theme', 'font', 'density', 'text_size', 'glass', 'interface_language'}:
            response.delete_cookie('mvk_lang' if key == 'interface_language' else 'mvk_' + key)
    return response


def _effect_guard(request, body, principal):
    def guard():
        with auth.fresh_configuration():
            if _principal(request) != principal or not auth.constant_time_equals(body.context, context_for(request)):
                raise HTTPException(409, "Your account, workspace or access changed. Review your retained choices again.")
            if body.scope == "organization":
                auth.require_global_permission(request, "admin")
            elif body.scope == "workspace":
                auth.require_permission(request, "admin")
            _thread(request, body.thread)
            _validate_chat_defaults(request, body)
    return guard


def _validate_chat_defaults(request, body):
    changed = set(body.changes) & {"chat_model", "chat_effort", "chat_specialist"}
    if not changed:
        return
    if body.scope != "personal" or body.thread is not None:
        raise HTTPException(422, "Chat AI defaults belong to your account in this workspace. Choose Personal scope.")
    from .task_model_selection_api import choices, current_authority
    current_authority(request)
    if "chat_specialist" in changed:
        from .product_operations_task_launch import published_selection
        try:
            name = preferences._validate("chat_specialist", body.changes["chat_specialist"] or "")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        current = published_selection(request, name)["revision"]
        if body.specialist_revision is None or not hmac.compare_digest(body.specialist_revision, current):
            raise HTTPException(409, "This published specialist changed. Read its current choice and review your retained preference again.")
    if not changed & {"chat_model", "chat_effort"}:
        return
    values = preferences.state(_principal(request))["values"]
    picked = {key: body.changes.get(key, values[key]) or "" for key in ("chat_model", "chat_effort")}
    if not picked["chat_model"]:
        if picked["chat_effort"]:
            raise HTTPException(422, "Choose a Chat model before choosing its thinking depth.")
        return
    row = next((row for row in choices(request) if row["value"] == picked["chat_model"]), None)
    if row is None or picked["chat_effort"] and picked["chat_effort"] not in {item["value"] for item in row["efforts"]}:
        raise HTTPException(409, "This Chat model or thinking depth is no longer available. Your draft is kept; choose current options.")


@router.post('/api/v1/preferences/original')
def original_preferences(request: Request, body: PreferenceUpdate):
    _app()._require_same_origin(request)
    auth.require_personal_write(request)
    principal = _principal(request)
    if not body.operation_id or not auth.constant_time_equals(body.context, context_for(request)):
        raise HTTPException(409, "The account or workspace changed. This original save cannot be read here.")
    if body.scope == "organization":
        auth.require_global_permission(request, "admin")
    elif body.scope == "workspace":
        auth.require_permission(request, "admin")
    elif body.scope != "personal":
        raise HTTPException(422, "Choose a supported preference scope.")
    confirmed = preferences.operation_confirmed(principal, scope=body.scope, changes=body.changes,
        expected_revision=body.expected_revision, operation_id=body.operation_id, thread=_thread(request, body.thread),
        specialist_revision=body.specialist_revision)
    current = _state(request, body.thread)
    if _principal(request) != principal or not auth.constant_time_equals(body.context, context_for(request)):
        raise HTTPException(409, "Your account, workspace or access changed. Private preferences cannot be released.")
    with auth.fresh_configuration():
        if body.scope == "organization":
            auth.require_global_permission(request, "admin")
        elif body.scope == "workspace":
            auth.require_permission(request, "admin")
    return JSONResponse({"confirmed": confirmed, "state": current,
        "message": "The original preference save is confirmed. Nothing was repeated." if confirmed else
                   "This original save is unconfirmed or is older than the latest saved change. Matching current values are not proof. Nothing was repeated."},
        headers={"Cache-Control":"private, no-store"})


class DisplayUpdate(BaseModel):
    key: str
    value: str
    context: str
    expected_revision: str | None = None
    device_only: bool = False


@router.post('/api/v1/preferences/display')
def display_preference(request: Request, body: DisplayUpdate) -> JSONResponse:
    _app()._require_same_origin(request)
    auth.require_personal_write(request)
    # The legacy header key meant interface language, never response language.
    if body.key == "language":
        body = body.model_copy(update={"key": "interface_language"})
    _check_display(body.key, body.value)
    context = context_for(request)
    if not auth.constant_time_equals(body.context, context):
        raise HTTPException(409, "Your account or workspace changed. Reload before changing preferences.")
    principal = auth.caller_principal(request)
    if principal and preferences.enabled() and body.key in preferences.state(principal)["locked"]:
        raise HTTPException(403, "This display preference is set by organization policy.")
    result = {"value": body.value}
    if principal and not body.device_only:
        if not body.expected_revision:
            raise HTTPException(409, "Refresh your preferences before saving.")
        try:
            result.update(preferences.save(principal, scope="personal", changes={body.key: body.value},
                                           expected_revision=body.expected_revision))
        except preferences.PreferenceConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    response = JSONResponse(result, headers={"Cache-Control": "private, no-store"})
    cookie = "mvk_lang" if body.key == "interface_language" else "mvk_" + body.key
    if body.device_only or not principal:
        response.set_cookie(cookie, body.value, max_age=365*24*3600, samesite="lax")
        response.set_cookie('mvk_pref_context', context, max_age=365*24*3600, samesite="lax")
    else:
        response.delete_cookie(cookie)
    return response


def _profiles_allowed(request: Request) -> None:
    from maverick.config import get_features, load_global_config
    _principal(request)
    if load_global_config().get('features', {}).get('configuration_profiles', True) is not True or not get_features().get('configuration_profiles'):
        raise HTTPException(403, 'Portable profiles are turned off by your administrator.')


@router.get('/api/v1/preferences/profile')
def export_personal_profile(request: Request):
    _profiles_allowed(request)
    from .draft_store import validate_payload
    current = _state(request)
    values, excluded = {}, []
    for key in sorted(PROFILE_FIELDS):
        value = current['values'][key]
        try:
            validate_payload({key: value})
        except ValueError:
            excluded.append(key)
        else:
            values[key] = value
    if values.get('output_style') == 'custom' and 'custom_style' not in values:
        values.pop('output_style', None)
        values.pop('custom_style_name', None)
        excluded.extend(['output_style', 'custom_style_name'])
    return JSONResponse({'format': 'lightwork-personal-style-profile', 'version': 1,
                         'scope': 'personal', 'settings': values, 'excluded': excluded},
                        headers={'Cache-Control': 'private, no-store'})


class PersonalProfileImport(BaseModel):
    profile: dict[str, Any]


@router.post('/api/v1/preferences/profile/import')
def import_personal_profile(request: Request, body: PersonalProfileImport):
    _app()._require_same_origin(request)
    auth.require_personal_write(request)
    _profiles_allowed(request)
    from .draft_store import validate_payload
    data = body.profile
    if data.get('format') != 'lightwork-personal-style-profile' or data.get('version') != 1 or data.get('scope') != 'personal':
        raise HTTPException(422, 'Use a version 1 personal style profile. Re-export older profiles from their original installation.')
    values = data.get('settings')
    if not isinstance(values, dict) or not values or set(values) - PROFILE_FIELDS:
        raise HTTPException(422, 'This file contains unknown or non-portable fields. Keep writing and display preferences only; permissions, names, tools and memory policy cannot be imported.')
    current = _state(request)
    locked = set(values) & set(current['locked'])
    if locked:
        raise HTTPException(409, 'Organization policy owns these preferences: ' + ', '.join(sorted(locked)) + '. Remove them from this profile before importing.')
    try:
        validate_payload(values)
        changes = {key: preferences._validate(key, value) for key, value in values.items()}
        for key, value in changes.items():
            if key in {'theme', 'font', 'density', 'language', 'interface_language', 'text_size', 'glass'}:
                _check_display(key, value)
    except ValueError as exc:
        raise HTTPException(422, 'The profile includes an unsupported value or credential-like data. Review the file; nothing was changed.') from exc
    if changes.get('output_style') == 'custom' and not changes.get('custom_style'):
        raise HTTPException(422, 'A named custom style must include its guidance. Export the complete style again.')
    return JSONResponse({'changes': changes, 'state': current,
                         'message': 'Loaded for review only. Nothing was saved.'},
                        headers={'Cache-Control': 'private, no-store'})


def _display_context_for(request: Request) -> str:
    """Display chrome must not turn an unverified error request into a 500.

    No binding means account-scoped cookies cannot be reused. Authorization
    checks on actual preference reads/writes still use ``context_for`` directly.
    """
    try:
        return context_for(request)
    except HTTPException:
        return ""


def display_context(request: Request) -> dict:
    principal = auth.caller_principal(request)
    state = None
    if principal and preferences.enabled():
        try:
            state = preferences.state(principal)
        except Exception:
            state = None
    return {"display_preference_context": _display_context_for(request),
            "display_preference_revision": state["revision"] if state else "",
            "display_text_size": resolved_display(request, "text_size", "standard"),
            "display_interface_language": resolved_display(request, "interface_language", ""),
            "display_signed_in": bool(principal and preferences.enabled())}


def resolved_display(request: Request, key: str, fallback: str | None = None):
    principal = auth.caller_principal(request)
    cookie = "mvk_lang" if key == "interface_language" else "mvk_" + key
    cached = None
    if principal and preferences.enabled():
        try:
            cached = getattr(request.state, "experience_preferences", None)
            if cached is None:
                cached = preferences.state(principal)
                request.state.experience_preferences = cached
            if key in cached["locked"]:
                return cached["values"].get(key, fallback)
        except Exception:
            return fallback
    cookie_context = request.cookies.get('mvk_pref_context')
    if cookie_context and cookie_context == _display_context_for(request) and request.cookies.get(cookie):
        return request.cookies[cookie]
    if cached is not None:
        return cached["values"].get(key, fallback)
    if not principal and not request.cookies.get('mvk_pref_context'):
        return request.cookies.get(cookie, fallback)
    return fallback


@router.get('/today')
def today_page(request: Request):
    from .navigation_api import areas_redirect
    from .today_projection import project

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    model = _state(request)
    return _app().templates.TemplateResponse(request, 'today.html', {
        'today_preferences': model, 'today': project(request, _app()._world(), model),
        'today_decisions_allowed': auth.has_permission(request, 'operate'),
    }, headers={'Cache-Control': 'private, no-store'})


# Home's sections in the job-named navigation: each shows one old page in
# full, at the old page's own access check. The area's page tabs (Today, My
# work, Overview) switch between them, so Home stays a set of short views.
HOME_SECTIONS = {"": "/today", "my-work": "/me", "overview": "/overview"}


@router.get('/home')
def home_page(request: Request, section: str = "", saved: str = ""):
    """Home in the job-named navigation: today's work, decisions, results and
    pins (the Today page); ``?section=my-work`` is My work (questions,
    spending, chat accounts and the daily summary) and ``?section=overview``
    the Overview (activity and statistics). The address exists only in areas
    mode."""
    from .navigation_api import areas_on

    if not areas_on(request) or section not in HOME_SECTIONS:
        raise HTTPException(404, "Not Found")
    _app().require_page_visible(request, HOME_SECTIONS[section])
    if section == "my-work":
        from .me_api import me_page

        return me_page(request, saved=saved)
    if section == "overview":
        return _app().overview(request)
    try:
        return today_page(request)
    except HTTPException as exc:
        # Today needs a named account with personal preferences on (the
        # local owner has neither). Home is the start page, so it opens on
        # the next view this person may open rather than on a refusal.
        if exc.status_code != 403:
            raise
        for fallback in ("my-work", "overview"):
            if _app().page_visible(request, HOME_SECTIONS[fallback]):
                return RedirectResponse(f"/home?section={fallback}", status_code=303)
        raise
