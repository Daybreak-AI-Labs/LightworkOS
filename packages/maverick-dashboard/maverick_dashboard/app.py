"""FastAPI dashboard for Lightwork.

Goals run through the shared BackgroundTask runner in ``maverick.runner``,
which the REST API and the MCP server use too.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import sys
import threading
import time
import weakref
from collections import deque
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketException,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from maverick import a2a
from maverick.flow.payloads import FlowPayloadError
from maverick.oidc import VerifiedPrincipal
from maverick.runner import TaskLimitConfigError
from maverick.runtime_overrides import RuntimeOverridesSecurityError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__ as _dashboard_version
from . import auth_metrics as _auth_metrics
from . import (
    capability_assessment_controls_api,
    learning_acquisition_api,
    page_handoff,
    request_spans,
    runtime_policy_recovery_api,
)
from . import health_routes as _health_routes
from ._shared import (
    _any_provider_key_set,
    _get_sse_semaphore,
    _world,
    require_provider_or_400,
)
from ._shared import _world_cache as _world_cache  # re-export: tests clear app._world_cache
from ._shared import dashboard_token as _dashboard_token
from .action_center_api import router as action_center_router
from .api import router as api_router
from .api_documentation import router as api_documentation_router
from .api_schemas import GOAL_DESCRIPTION_MAX_LENGTH, GOAL_TITLE_MAX_LENGTH
from .auth import (
    BOARD_SCOPE_DETAIL,
    PUBLIC_STATIC_PATHS,
    SELF_AUTH_SIGNIN_RECOVERY_PATHS,
    SELF_AUTH_WEBHOOK_PATHS,
    AutomationAuthorizationError,
    assert_goal_access,
    assert_template_access,
    auth_genuinely_off,
    caller_principal,
    caller_role,
    caller_suites,
    can_access_goal,
    can_access_goal_principal,
    constant_time_equals,
    execution_user_id_from_request,
    goal_owner_filter,
    has_global_permission,
    has_permission,
    non_static_auth_configured,
    require_global_permission,
    require_permission,
    require_principal_in_request_context,
    require_suite,
    require_unscoped_board,
    require_websocket_principal_in_context,
    route_path,
    stored_automation_identity,
    websocket_caller_principal,
)
from .budget_guidance_api import router as budget_guidance_router
from .chat_message_actions_api import router as chat_message_actions_router
from .commitment_viability_api import router as commitment_viability_router
from .conversation_inbox_api import router as conversation_inbox_router
from .conversation_organization import present_title as _conversation_title
from .conversation_organization import router as conversation_organization_router
from .cost_reconciliation_api import router as cost_reconciliation_router
from .deliverable_bundles_api import router as deliverable_bundles_router
from .draft_api import context_for as _conversation_context
from .draft_api import page_context as _draft_page_context
from .draft_api import router as draft_router
from .employee_activation import router as employee_activation_router
from .flow_dependencies import _services as _flow_services
from .health_routes import (
    health_response as _health_response,
)
from .health_routes import (
    metrics_response as _metrics_response,
)
from .health_routes import (
    readiness_response as _readiness_response,
)
from .i18n_journeys import region as _journey_region
from .i18n_journeys import text as _journey_text
from .model_tests_api import router as model_tests_router
from .my_work_api import router as my_work_router
from .navigation_api import GO_TO_KEYS, area_context, command_list, personal_view
from .navigation_api import router as navigation_router
from .oidc_login import router as oidc_login_router
from .outcome_accounting_api import router as outcome_accounting_router
from .outcome_pilot_costs_api import router as outcome_pilot_costs_router
from .outcome_pilots_api import router as outcome_pilots_router
from .preferences_api import display_context as _display_preference_context
from .preferences_api import router as preferences_router
from .product_operations import router as product_operations_router
from .project_reviews_api import router as project_reviews_router
from .project_workspaces_api import router as project_workspaces_router
from .record_search_api import page_context as _record_search_page_context
from .record_search_api import router as record_search_router
from .route_identity import (
    stabilize_effective_route_names as _stabilize_effective_route_names,
)
from .settings_experience import router as settings_experience_router
from .settings_runtime_status import router as settings_runtime_router
from .specialist_drafts_api import router as specialist_drafts_router
from .static_asset_versioning import AssetVersionExtension, AssetVersions, StaticCacheMiddleware
from .task_diagnostics import router as task_diagnostics_router
from .task_handoffs_api import router as task_handoffs_router
from .template_runtime import (
    _format_datetime as _format_datetime,
)
from .template_runtime import (
    _template_bytecode_cache as _template_bytecode_cache,
)
from .template_runtime import (
    _Templates as _Templates,
)
from .template_runtime import (
    _templates_auto_reload as _templates_auto_reload,
)
from .workspace_erasure_api import router as workspace_erasure_router

_MAX_USER_SPEND_METRIC_SERIES = _health_routes.MAX_USER_SPEND_METRIC_SERIES
_USER_SPEND_OVERFLOW_LABEL = _health_routes.USER_SPEND_OVERFLOW_LABEL

log = logging.getLogger(__name__)


class _CallbackAccessLogFilter(logging.Filter):
    """Remove callback queries before Uvicorn handlers or formatters see them."""

    _lightwork_callback_redaction = True

    def filter(self, record):
        args = record.args
        # Both Uvicorn HTTP implementations emit this structured access record.
        # Keep method, route and status useful without changing the ASGI request:
        # the authorization handler still needs the original one-time values.
        if isinstance(args, tuple) and len(args) == 5 and isinstance(args[2], str):
            path, separator, _query = args[2].partition("?")
            # Suffix matching also covers an application mounted under a prefix.
            # Login can carry a nested callback query in its return_to parameter.
            if separator and unquote(path).rstrip("/").endswith(
                ("/connections", "/auth/login", "/auth/callback", "/flow/approve")
            ):
                record.args = (*args[:2], f"{path}?[redacted]", *args[3:])
        return True


# Logger filters survive Uvicorn's default dictConfig. Installing at app import
# covers CLI/desktop (app imported first), direct Uvicorn import strings (logging
# configured first), and JSON logging with propagation to the configured root.
_access_logger = logging.getLogger("uvicorn.access")
if not any(getattr(item, "_lightwork_callback_redaction", False) for item in _access_logger.filters):
    _access_logger.addFilter(_CallbackAccessLogFilter())

TEMPLATES_DIR = Path(__file__).parent / "templates"


templates = _Templates(directory=str(TEMPLATES_DIR))
# Starlette builds the Environment itself; both are plain Environment
# attributes read at get_template time.
templates.env.auto_reload = _templates_auto_reload()
templates.env.bytecode_cache = _template_bytecode_cache()


templates.env.filters["datetime"] = _format_datetime
# Human-friendly identities and roles: never show a raw OIDC sub or a lowercase
# role slug in the UI. `identity` returns an object with .name/.detail/.raw/.kind.
from . import identity_format as _idfmt  # noqa: E402

templates.env.filters["identity"] = _idfmt.humanize_principal
templates.env.filters["role_label"] = _idfmt.role_label
templates.env.filters["permission_label"] = _idfmt.permission_label
templates.env.filters["humanize"] = _idfmt.humanize
from .approval_labels import action_label as _approval_action_label  # noqa: E402

templates.env.globals["approval_action_label"] = _approval_action_label
# One run-status vocabulary for the chat badge, composer and recents.
from maverick.channel_approvals import spending_text as _approval_spending  # noqa: E402

from .run_status import status_label as _run_status_label  # noqa: E402

# The spending line every approval surface shares: a sentence, never a mapping.
templates.env.filters["approval_spending"] = _approval_spending

templates.env.globals["run_status_label"] = _run_status_label
# The optional reasons a thumbs-down offers (shared by the page and its live refresh).
from .goal_feedback_store import REASONS as _FEEDBACK_REASONS  # noqa: E402

templates.env.globals["feedback_reasons"] = list(_FEEDBACK_REASONS.items())
# Plain labels for model ids, setting sources and sizes (administration pages).
from . import plain_labels as _plain_labels  # noqa: E402

_plain_labels.register(templates.env)
# Make `theme` available unconditionally so templates rendered without
# a Request object (rare; legacy paths) still resolve `theme or 'dark'`.
templates.env.globals.setdefault("theme", "dark")
templates.env.globals.setdefault("font", "default")
templates.env.globals.setdefault("lang", "en")
templates.env.globals.setdefault("page_lang", "en")
templates.env.globals.setdefault("density", "comfortable")
templates.env.globals.setdefault("glass", "off")
templates.env.globals.setdefault("custom_theme_css", "")
templates.env.globals.setdefault("custom_theme_names", [])
templates.env.globals.setdefault("dir", "ltr")

# Content-versioned static URLs refresh when bundled file metadata changes.
# Matching public versions may be cached for a year; canonical/stale script
# and stylesheet URLs revalidate. Missing files are checked again next time.
_asset_versions = AssetVersions(Path(__file__).parent / "static")
STATIC_IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
STATIC_SHORT_CACHE = "public, max-age=300"


def static_version(name: str) -> str:
    """Return the current content hash for a bundled public asset."""
    return _asset_versions.version(name)


def static_url(name: str) -> str:
    """``/static/<name>?v=<hash>`` for a bundled asset (plain path if unknown)."""
    version = static_version(name)
    return f"/static/{name}?v={version}" if version else f"/static/{name}"


templates.env.globals["static_url"] = static_url
templates.env.add_extension(AssetVersionExtension)


def _comments_enabled() -> bool:
    """Whether comment threads show on tasks, runs, approvals and policies."""
    try:
        from maverick.comments import enabled

        return enabled()
    except Exception:  # noqa: BLE001 -- an unreadable setting shows no thread
        return False


templates.env.globals["comments_enabled"] = _comments_enabled


def _suggestions_enabled() -> bool:
    """Whether suggested edits show on AI use rules."""
    try:
        from maverick.policy_suggestions import enabled

        return enabled()
    except Exception:  # noqa: BLE001 -- an unreadable setting shows no suggestions
        return False


templates.env.globals["suggestions_enabled"] = _suggestions_enabled


from .i18n import t as _i18n_t  # noqa: E402
from .themes import custom_themes, theme_color, theme_css  # noqa: E402

templates.env.globals.setdefault("t", lambda key: _i18n_t(key, "en"))

templates.env.globals.setdefault("ui", _journey_region)
templates.env.globals.setdefault("ut", _journey_text)
templates.env.globals.setdefault("ul", lambda source: "en")

_VALID_THEMES = {"dark", "light", "solarized", "hicontrast"}
_VALID_FONTS = {"default", "dyslexic"}
_VALID_DENSITIES = {"comfortable", "compact"}
_VALID_GLASS = {"off", "on"}


def _valid_theme_names() -> set[str]:
    """Built-in themes plus the operator's validated ``[dashboard] themes``."""
    return _VALID_THEMES | set(custom_themes())


def _resolve_pref(
    request: Request,
    *,
    param: str,
    cookie: str,
    valid,
    default: str,
    config_key: str | None = None,
) -> str:
    """Resolve a UI preference via the shared query-param → cookie →
    [dashboard] config → default ladder, accepting only values in ``valid``.
    ``config_key=None`` skips the config step (cookie-only prefs)."""
    q = (request.query_params.get(param) or "").strip().lower()
    if q in valid and not caller_principal(request):
        return q
    from .preferences_api import resolved_display

    preferred = resolved_display(request, param)
    if preferred in valid or (param == "theme" and preferred == "system"):
        return preferred
    if config_key is not None:
        try:
            from maverick.config import load_config

            cfg = (load_config() or {}).get("dashboard") or {}
            v = (cfg.get(config_key) or "").strip().lower()
            if v in valid:
                return v
        except Exception:
            pass
    return default


def _resolve_theme(request: Request) -> str:
    """Pick the theme from ``?theme=`` query param, cookie, config, then dark."""
    return _resolve_pref(
        request,
        param="theme",
        cookie="mvk_theme",
        valid=_valid_theme_names(),
        config_key="theme",
        default="dark",
    )


def resolve_density(request: Request) -> str:
    """UI density: ``?density=`` → ``mvk_density`` cookie → ``[dashboard]
    density`` config → comfortable. Default-off: ``comfortable`` is the
    existing layout; ``compact`` opts in to the denser one."""
    return _resolve_pref(
        request,
        param="density",
        cookie="mvk_density",
        valid=_VALID_DENSITIES,
        config_key="density",
        default="comfortable",
    )


def resolve_glass(request: Request) -> str:
    """Glass effects: ``?glass=`` → ``mvk_glass`` cookie (or the account's
    saved choice) → ``[dashboard] glass`` config → off. Default-off: solid
    panes repaint fast; ``on`` brings back the translucent, blurred look."""
    return _resolve_pref(
        request,
        param="glass",
        cookie="mvk_glass",
        valid=_VALID_GLASS,
        config_key="glass",
        default="off",
    )


def _resolve_font(request: Request) -> str:
    """Font preference: ``?font=`` → cookie → default. Independent axis from
    the theme so high-contrast + dyslexia-friendly compose."""
    return _resolve_pref(
        request,
        param="font",
        cookie="mvk_font",
        valid=_VALID_FONTS,
        default="default",
    )


# Context processor: every template gets the `theme` variable for the
# body class + the theme switcher links, the `font` accessibility axis,
# and the chrome-i18n helpers (`lang`, `t`).
def _theme_context(request: Request) -> dict:
    from .i18n import content_lang, dir_for, resolve_lang
    from .i18n import t as _t
    from .i18n_journeys import context as journey_context

    lang = resolve_lang(request)
    custom = custom_themes()
    theme = _resolve_theme(request)
    return {
        "theme": theme,
        "theme_color": theme_color(theme, custom),
        "font": _resolve_font(request),
        "density": resolve_density(request),
        "glass": resolve_glass(request),
        "custom_theme_css": theme_css(custom),
        "custom_theme_names": sorted(custom),
        # ``lang`` is the selected UI language (drives ``t()``); ``page_lang``
        # is what the page body is actually written in and is what
        # ``<html lang>`` and ``dir`` declare. They differ
        # until the templates are translated, so an English body is never
        # mirrored because a few chrome strings are Arabic.
        "lang": lang,
        "page_lang": content_lang(lang),
        "dir": dir_for(content_lang(lang)),
        "t": lambda key: _t(key, lang),
        **journey_context(request, lang),
    }


# Register the per-request context processor with Starlette so every
# TemplateResponse picks up the resolved theme automatically.
templates.context_processors.append(_theme_context)


# Context processor: every page template gets this response's CSP script nonce
# (drawn per request by security_headers) for its inline <script> tags.
def _csp_nonce_context(request: Request) -> dict:
    return {"csp_script_nonce": getattr(request.state, "csp_script_nonce", "")}


templates.context_processors.append(_csp_nonce_context)

templates.context_processors.append(_draft_page_context)
templates.context_processors.append(_record_search_page_context)


# Context processor: every template gets `nav_groups` -- the sidebar filtered
# to the pages the caller's RBAC role may see (defaults + the admin's Settings
# overrides; see maverick_dashboard.ui_visibility). Auth off -> full nav,
# exactly as before.
def _page_role(request: Request, *, global_scope: bool = False) -> str | None:
    """Reserve None/full navigation for a verified principal-less grant.

    Role resolution also returns None when a signed-in user's policy cannot
    be read. That case has no permissions, unlike the local/static-token
    compatibility grant which caller_role validates before returning.
    """
    from . import auth

    try:
        principal = auth.caller_principal(request)
        role = (
            auth.global_role_for_principal(principal)
            if global_scope and principal is not None else caller_role(request)
        )
        if role is None and principal is not None:
            return ""
        return role
    except Exception:
        return ""


def _switched_off_pages() -> frozenset[str]:
    """Registry pages whose in-app module switch is off right now: the same
    effective gate chain as each page's banner (module_activation._module_switch_enabled),
    with every enable gate read once per render."""
    from . import ui_visibility
    from .module_activation import _MODULE_SWITCHES, _load_module_config, _module_path_enabled

    try:
        loaded = _load_module_config()
    except Exception:  # unreadable configuration: navigation stays as it is
        return frozenset()
    gates: dict[str, bool] = {}

    def gate(path: str) -> bool:
        if path not in gates:
            gates[path] = _module_path_enabled(loaded, path)
        return gates[path]

    return ui_visibility.switched_off_paths(
        lambda section: all(gate(path) for path in (*_MODULE_SWITCHES[section]["requires"], section))
    )

def _account_pages_unavailable(request: Request) -> set[str]:
    """Registered pages whose route also needs a named account (employee
    activation also needs its switch). Like the companion pages, navigation
    offers each one only when that route's own check admits the caller."""
    from . import (
        device_pairing_api,
        employee_activation,
        human_conversation_handoffs,
        permission_requests_api,
        personal_notifications_api,
    )

    unavailable = set()
    for path, admit in (("/access-requests", permission_requests_api.authority),
                        ("/devices", device_pairing_api._principal),
                        ("/get-started/employee", employee_activation.actor),
                        ("/notifications", personal_notifications_api.page_authority),
                        ("/human-conversations", human_conversation_handoffs.authority)):
        try:
            admit(request)
        except Exception:  # a refused or unreadable check hides the link
            unavailable.add(path)
    return unavailable


def _nav_context(request: Request) -> dict:
    """The navigation's permission and role checks share one current read
    (``single_read(fresh=True)``), even inside the page render's own read."""
    from maverick.config import single_read

    with single_read(fresh=True):
        return _nav_context_now(request)


def _nav_context_now(request: Request) -> dict:
    from . import ui_visibility
    from .auth import api_key_permissions, api_key_scopes
    from .halt_policy import shared_halt_backend as _shared_halt_backend

    role = _page_role(request)
    scope_roles = {"global": _page_role(request, global_scope=True)}
    groups = ui_visibility.nav_groups(role, scope_roles=scope_roles)
    # The Ctrl+K page finder: same role resolution, but it also indexes pages
    # folded out of the rail (in_nav: False) -- reachable must mean searchable.
    finder = ui_visibility.finder_pages(role, scope_roles=scope_roles)
    from .employee_companion_api import navigation_available

    unavailable = {path for path, admin in (("/companion", False), ("/companion/admin", True))
                   if not navigation_available(request, admin=admin)}
    key_permissions = api_key_permissions(request)
    key_scopes = api_key_scopes(request)

    def key_can_open(link: dict) -> bool:
        if key_permissions is None:
            return True
        page = ui_visibility.page_for(link["href"])
        if page is None:
            return False
        permission = ui_visibility._permission(page, "floor")
        if permission not in key_permissions:
            return False
        if permission == "operate":
            scope = "approvals:decide" if page["path"] in {"/approvals", "/oversight"} else "tasks:write"
            return key_scopes is not None and ("admin" in key_scopes or scope in key_scopes)
        return True
    unavailable |= _account_pages_unavailable(request)
    for collection in (groups, finder):
        for group in collection:
            group["links"] = [link for link in group["links"]
                              if link["href"] not in unavailable and key_can_open(link)]
        collection[:] = [group for group in collection if group["links"]]
    finder_hrefs = {link["href"] for group in finder for link in group["links"]}

    def can_open_page(path: str) -> bool:
        """In-page links to another screen use the finder's own answer, so a
        link appears only for people that screen admits."""
        page = ui_visibility.page_for(path.split("#")[0].split("?")[0])
        return page is not None and page["path"] in finder_hrefs
    # The topbar's Settings gear follows the same policy as the sidebar entry.
    show_settings = any(link["href"] == "/settings" for g in groups for link in g["links"])
    # A deployment-wide halt backend is a global control even when the caller
    # is an administrator inside one tenant.  Keep the shell's affordance in
    # lock-step with the API rather than discovering this only after a 403.
    try:
        can_halt = (
            has_global_permission(request, "admin")
            if _shared_halt_backend()
            else has_global_permission(request, "operate")
        )
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        can_halt = False
    # Guarded like caller_role/can_halt above: with a browser login provider
    # (OIDC) configured, an unauthenticated render raises 401 here, which would
    # turn every branded error page (and the login redirect) into a 500. The
    # shell affordance is fail-closed -- no principal means no create button.
    try:
        can_create_goal = has_permission(request, "operate")
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        can_create_goal = False
    # Use the logout route's own browser-session policy, including local owner
    # and invited accounts. Static-token / auth-off users have no session to end.
    try:
        from .oidc_login import browser_session_enabled

        show_logout = browser_session_enabled()
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft
        show_logout = False
    try:
        viewer_global_admin = has_global_permission(request, "admin")
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        viewer_global_admin = False
    # A page whose module is switched off only says "...is turned off". Global
    # administrators, who can turn it on, keep the link marked Off; nobody else
    # gets a sidebar link into that dead end. Same switch state as the banner.
    switched_off = _switched_off_pages()
    ui_visibility.mark_switched_off(groups, switched_off, can_turn_on=viewer_global_admin)
    try:
        from maverick import config as core_config
        from maverick import experience_preferences
        from maverick.personal_notifications import personal_alerts_on

        show_personal_notifications = bool(caller_principal(request)) and has_permission(request, "view")
        personal_notifications_enabled = (
            show_personal_notifications and experience_preferences.enabled()
            and not core_config.config_source_errors(include_tenant=True)
            and personal_alerts_on(core_config.load_config().get("notifications"))
        )
    except Exception:  # pragma: no cover -- shell rendering stays fail-closed
        show_personal_notifications = personal_notifications_enabled = False
    personal = personal_view(request, role, finder, switched_off, viewer_global_admin)
    return {
        "viewer_global_admin": viewer_global_admin,
        "nav_groups": groups,
        "finder_pages": finder,
        "can_open_page": can_open_page,
        "show_settings_link": show_settings,
        "can_create_goal": can_create_goal,
        "can_halt": can_halt,
        "show_logout": show_logout,
        "show_personal_notifications": show_personal_notifications,
        "personal_notifications_enabled": personal_notifications_enabled,
        # Pinned and recent pages, and the command menu's commands: computed
        # only when a template asks.
        "nav_personal": personal,
        "nav_commands": command_list(can_create_goal=can_create_goal, can_halt=can_halt,
                                     can_open_page=can_open_page, global_admin=viewer_global_admin,
                                     personal=personal),
        "nav_go_to_keys": GO_TO_KEYS,
        # Where a page kept out of the sidebar sits: its highlighted parent in
        # the sidebar and the breadcrumb (ui_visibility.where).
        "nav_where": _nav_where(request, groups, finder),
        # The navigation style ("classic" or "areas") and, in areas mode, the
        # areas and where this page sits in them.
        **area_context(request, role, finder, switched_off, viewer_global_admin),
    }


def _nav_where(request, groups, finder):
    from . import ui_visibility
    try:
        return ui_visibility.where(request.url.path, groups, finder)
    except Exception:  # pragma: no cover -- shell rendering never fails on it
        return None


templates.context_processors.append(_nav_context)


def _workspace_context(request: Request) -> dict:
    """Expose the request-bound tenant to the shell's stale-tab guard."""
    try:
        from maverick.paths import current_tenant_id

        tenant_id = current_tenant_id() or ""
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft
        tenant_id = ""
    source = str(getattr(request.state, "workspace_tenant_source", "") or "")
    workspace_name = "Main workspace"
    if tenant_id:
        from maverick.tenant.registry import get_tenant
        record = get_tenant(tenant_id)
        workspace_name = ((record.display_name or "").strip()
                          or ("Main workspace" if record.id == "default" else "Unnamed workspace")) if record else "Selected workspace"
    return {
        "workspace_tenant_name": workspace_name,
        "workspace_tenant_id": tenant_id,
        "workspace_tenant_selection": tenant_id
        if source in {"local_selection", "principal_selection"}
        else "",
    }


templates.context_processors.append(_workspace_context)


def _docs_context(request: Request) -> dict:
    """The Docs link in the top bar and the per-page Learn more link."""
    from .docs_links import DOCS_HOME, learn_more_for

    try:
        path = request.url.path
    except Exception:  # pragma: no cover -- shell rendering stays fail-soft
        path = ""
    return {"docs_home": DOCS_HOME, "docs_learn_more": learn_more_for(path)}


templates.context_processors.append(_docs_context)
templates.env.globals.setdefault("docs_home", "https://daybreak-ai-labs.github.io/LightworkOS/")
templates.env.globals.setdefault("docs_learn_more", None)
# A page's tab bar (templates/_tabs.html) and a hosted page's header: absent
# unless the page's handler passes them.
for _tab_value in ("tab_host", "builder_modes", "map_views", "replay_tabs", "outside_agent_tabs",
                   "permission_tabs", "compliance_tabs", "knowledge_tabs"):
    templates.env.globals.setdefault(_tab_value, None)


def _help_context(request: Request) -> dict:
    """The Help menu (page topic, status page) and the AI service banner."""
    from .help_menu import context

    return context(request)


templates.context_processors.append(_help_context)
templates.env.globals.setdefault("help_topic", None)
templates.env.globals.setdefault("support_status_page_url", "")
templates.env.globals.setdefault("help_menu_text", False)
templates.env.globals.setdefault("service_status", None)
templates.env.globals.setdefault("service_notices", [])
# Requestless renders cannot prove authority; the request processor supplies
# permitted destinations, including full navigation in verified local mode.
templates.env.globals.setdefault("nav_groups", [])
templates.env.globals.setdefault("finder_pages", [])
templates.env.globals.setdefault("can_open_page", lambda path: False)
templates.env.globals.setdefault("nav_mode", "classic")
templates.env.globals.setdefault("nav_areas", None)


def _set_theme_cookie(response, theme: str) -> None:
    """Persist the theme choice as a cookie so it sticks across page loads."""
    if theme in _valid_theme_names():
        response.set_cookie(
            "mvk_theme",
            theme,
            max_age=30 * 24 * 3600,  # 30 days
            samesite="lax",
            httponly=False,  # the switcher links are visible to JS anyway
        )


def _require_auth_enabled() -> bool:
    """Opt-in guard: refuse to serve the dashboard with no auth configured.
    ``MAVERICK_DASHBOARD_REQUIRE_AUTH`` env wins over ``[dashboard] require_auth``;
    off by default so the single-tenant local flow is unchanged."""
    env = os.environ.get("MAVERICK_DASHBOARD_REQUIRE_AUTH", "").strip().lower()
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        # A malformed/unreadable config may conceal ``require_auth = true``.
        # Treat ambiguity as required so startup cannot silently enable local
        # administrator access.
        return True
    if not isinstance(config, dict):
        return True
    if env:
        if env in {"1", "true", "yes", "on"}:
            return True
        if env in {"0", "false", "no", "off"}:
            return False
        return True
    if "dashboard" not in config:
        dashboard = {}
    else:
        dashboard = config["dashboard"]
    if not isinstance(dashboard, dict):
        return True
    configured = dashboard.get("require_auth", False)
    return configured if isinstance(configured, bool) else True


def _assert_dashboard_auth_configured() -> None:
    """When ``require_auth`` is set, refuse to boot if NO auth mechanism is
    configured (token, OIDC, proxy SSO, invites, or complete SAML), so an operator
    who asked for auth can never accidentally serve the (loopback) control
    surface unauthenticated. No-op unless ``require_auth`` is explicitly on, so
    a fresh single-tenant install is never locked out."""
    if not _require_auth_enabled():
        return
    if _dashboard_token():
        return
    try:
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        from maverick.proxy_auth import proxy_auth_enabled

        if proxy_auth_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        # Email-invite local sessions count as a configured mechanism: with
        # require_auth on, only a verified invite-minted session (or one of the
        # modes above) passes the middleware — everything else 401s.
        from .invites import invites_enabled

        if invites_enabled():
            return
    except Exception:  # pragma: no cover
        pass
    try:
        # SAML uses the same signed browser session as OIDC, so a complete SAML
        # configuration is a first-class authentication mechanism too.
        from .saml import _session_secret, saml_enabled

        if saml_enabled() and _session_secret():
            return
    except Exception:  # pragma: no cover
        pass
    raise RuntimeError(
        "[dashboard] require_auth is set, but no auth mechanism is configured. "
        "Set MAVERICK_DASHBOARD_TOKEN, enable OIDC ([auth.oidc]), enable "
        "reverse-proxy SSO ([auth.proxy]), enable SAML ([auth.saml]), or enable "
        "email invites ([dashboard] invites) -- refusing to serve the dashboard "
        "unauthenticated."
    )


# ---- background automation (event polling + scheduled dreaming) -------------
# Runs in the dashboard lifespan, NOT the core worker: event triggers are a
# dashboard-owned store the core worker (a separate process) can't reach. Driven
# by maverick-core's JobQueue/Worker -- durable and retrying. A claim is atomic
# (one worker per job), but delivery is at-least-once: a job whose worker dies
# after its effect and before completion runs again once its lease expires, so
# handlers must be idempotent. The flock is gone -- via
# maverick_dashboard.automation_queue. Per-trigger polling
# cadence + scheduled dreaming are recurring cron jobs; fired goals are durable
# run_goal jobs with retry + dead-letter. TestClient skips the lifespan, so this
# never runs under tests; both halves are OFF by default (their own enabled()).


async def _install_automation_scheduler() -> None:
    """Start the JobQueue-backed automation worker when event triggers OR
    dreaming is enabled. No-op under TestClient and when both are off."""
    try:
        from maverick_dashboard import automation_queue

        await run_in_threadpool(automation_queue.start)
    except Exception:  # pragma: no cover - never block startup
        log.exception("automation worker not started")


async def _start_privacy_discovery_remediation_scheduler() -> None:
    try:
        from maverick_dashboard.privacy_data_discovery_scheduler import (
            start_privacy_data_discovery_scheduler,
        )

        await run_in_threadpool(start_privacy_data_discovery_scheduler, app)
    except Exception:  # pragma: no cover - never block startup
        log.exception("privacy-discovery remediation scheduler not started")


async def _start_privacy_notice_publication_scheduler() -> None:
    try:
        from maverick_dashboard.privacy_notice_publication_scheduler import (
            start_privacy_notice_publication_scheduler,
        )

        await run_in_threadpool(start_privacy_notice_publication_scheduler, app)
    except Exception:  # pragma: no cover - never block startup
        log.exception("privacy-notice publication scheduler not started")


#: Templates every session renders early: the shell, the page finder, the
#: landing pages and the main tabs. Compiling them, and every shared partial
#: (:func:`_warm_template_names`), here moves the Jinja compile cost off the
#: first visits: after an install or upgrade (an empty or stale bytecode
#: cache) that was about 1.15 s, 50-170 ms on each main tab's first click.
_WARM_TEMPLATES = ("base.html", "_navfinder.html", "index.html", "goals.html",
                   "chat.html", "approvals.html", "agents.html", "audit.html",
                   "billing.html", "chat_base.html", "compliance.html",
                   "connections.html", "learning.html", "me.html",
                   "permissions.html", "privacy.html", "security.html",
                   "settings.html", "store.html", "tools.html", "users.html",
                   "workflows_index.html", "workforce.html")


def _warm_template_names() -> list[str]:
    """The pages above, then every shared partial (``_*.html``) they include."""
    partials = [name for name in templates.env.list_templates()
                if name.startswith("_") and name.endswith(".html")]
    return list(dict.fromkeys((*_WARM_TEMPLATES, *partials)))


def _warm_dashboard_caches(stop: threading.Event | None = None) -> dict[str, float]:
    """Pay the dashboard's once-per-process first-hit costs now.

    Measured cold on a 4 vCPU box: first ``GET /`` 1.25 s (Jinja compile),
    every included route's context about 2.5 s (FastAPI 0.141 builds them
    on the first request that routes past them), ``builtin_domains()``
    0.78 s (2,031 pack files), ``_build_shield()`` 37 ms. Each step is
    independent and fail-open; the returned timings are for logs and tests.
    The OpenAPI schema (about 4.3 s, needed only by /openapi.json and the
    guided API forms) is not built here: :func:`_build_openapi_when_idle`.
    """
    timings: dict[str, float] = {}

    def _step(name: str, fn) -> None:
        if stop is not None and stop.is_set():
            return
        started = time.perf_counter()
        try:
            fn()
        except Exception:  # pragma: no cover - warm-up is best-effort
            log.debug("dashboard warm-up step %s skipped", name, exc_info=True)
        timings[name] = time.perf_counter() - started

    def _templates() -> None:
        for name in _warm_template_names():
            try:
                templates.env.get_template(name)
            except Exception:  # pragma: no cover - a renamed page is not fatal
                log.debug("template warm-up skipped %s", name, exc_info=True)

    def _domains() -> None:
        from maverick.domain import builtin_domains

        builtin_domains()

    def _agents() -> None:
        # The agent roster's tool inventory (about 0.6 s cold), cached per
        # installation configuration. Ctrl+K's first agent lookup needs it;
        # nothing in it is about a person.
        from maverick.domain_edit import list_agents

        list_agents()

    def _routes() -> None:
        # Request routing needs these contexts; materialising them here avoids
        # paying for the full schema build (seconds of extra CPU). The route
        # memory's check walks them too; run here, the first request skips it.
        from .route_dispatch import validate
        from .route_identity import iter_compatible_route_contexts

        for _context in iter_compatible_route_contexts(app.routes):
            pass
        validate(app.router)

    def _shield() -> None:
        from maverick.orchestrator import _build_shield

        _build_shield()

    # The pack catalogue first: the first Ctrl+K search after start needs it,
    # and the OpenAPI build after it is the slowest step.
    _step("domains", _domains)
    _step("agents", _agents)
    _step("routes", _routes)
    _step("templates", _templates)
    _step("shield", _shield)
    return timings


_SCHEMA_BUILD_SWITCH_INTERVAL = 0.0001


def _build_openapi_when_idle(quiet: float = 10.0, sleep=time.sleep, limit: float = 1800.0,
                             stop: threading.Event | None = None) -> bool:
    """Build the OpenAPI schema once the dashboard has been quiet for
    ``quiet`` seconds, so its seconds of CPU do not land on someone's first
    searches. Ten seconds, not one or two: a person opening the dashboard
    pauses that long only rarely while working, but often while a browser
    starts. A request for /openapi.json before then builds it on demand, as
    FastAPI always did. Gives up after ``limit`` seconds of steady traffic,
    or as soon as ``stop`` is set (the dashboard is shutting down)."""
    if not _wait_for_quiet(quiet, sleep, limit, stop):
        return False
    # The build is about six seconds of pure-Python CPU. At the default 5 ms
    # switch interval, a request arriving meanwhile waited for the GIL after
    # each of its I/O calls: the clicks after someone's first pause took about
    # a second each. A short interval for the build hands it back at once.
    switch = sys.getswitchinterval()
    sys.setswitchinterval(_SCHEMA_BUILD_SWITCH_INTERVAL)
    try:
        app.openapi()
    except Exception:  # pragma: no cover - the schema still builds on demand
        log.debug("OpenAPI warm-up skipped", exc_info=True)
        return False
    finally:
        sys.setswitchinterval(switch)
    return True


def _wait_for_quiet(quiet: float, sleep, limit: float, stop: threading.Event | None) -> bool:
    """Whether ``quiet`` seconds without a request arrived before ``limit``
    seconds of traffic passed and before ``stop`` was set.

    The quiet must also last ``quiet`` seconds from the start of the wait: a
    dashboard that has just started has served nothing yet, and starting its
    schema build at once would land seconds of CPU on the first pages someone
    opens."""
    from . import request_activity

    waited = 0.0
    while waited < quiet or not request_activity.quiet_for(quiet):
        if waited >= limit or (stop is not None and stop.is_set()):
            return False
        sleep(0.5)
        waited += 0.5
    return not (stop is not None and stop.is_set())


_GC_ROUND_SECONDS = 3600.0


def _freeze_long_lived_objects() -> None:
    """One full collection, then keep its survivors out of later ones.

    After warm-up the process tracks about 700,000 long-lived objects (the
    pack catalogue, templates, routes, modules, the OpenAPI schema). A full
    collection walked all of them, 350-450 ms, on whichever request triggered
    it. ``gc.freeze()`` leaves them out of every automatic collection. Each
    round first unfreezes, so warmed structures replaced since the last round
    (a rebuilt catalogue, a cleared cache) are reclaimed rather than kept.
    """
    try:
        gc.unfreeze()
        gc.collect()
        gc.freeze()
    except Exception:  # pragma: no cover - a tuning step never breaks the dashboard
        log.debug("garbage-collector freeze skipped", exc_info=True)


def _collect_when_idle(stop: threading.Event, quiet: float = 10.0, sleep=time.sleep,
                       wait=None, every: float = _GC_ROUND_SECONDS, limit: float = 1800.0) -> None:
    """Run :func:`_freeze_long_lived_objects` in quiet moments until shutdown.

    Each round waits for ``quiet`` seconds without a request in flight or
    started (open event streams and sockets do not count), so its own full
    collection lands on none. When ``limit`` seconds of traffic pass first,
    the round only unfreezes: automatic collections then reclaim garbage as
    they did without a freeze, so nothing frozen is kept indefinitely. Rounds
    are ``every`` seconds apart.
    """
    wait = wait or stop.wait
    while not stop.is_set():
        if _wait_for_quiet(quiet, sleep, limit, stop):
            _freeze_long_lived_objects()
        elif not stop.is_set():
            gc.unfreeze()
        if wait(every):
            return


# How long startup waits for the request-path caches before it serves anyway
# (the desktop splash gives the whole start 60 s; this is about 5 s normally).
_WARM_BEFORE_SERVING_SECONDS = 15.0


def _warm_goal_runtime(thread_factory=threading.Thread,
                       ready: threading.Event | None = None) -> threading.Event:
    """Pay the dashboard's first-hit costs (:func:`_warm_dashboard_caches`)
    and the kernel's once-per-process start-up cost (hook discovery across
    installed distributions, about 1.5 s cold) in a background thread,
    instead of on the first request or chat turn after start.

    ``ready`` is set once the request-path caches are warm (or their warm-up
    failed): the lifespan waits for it before serving, because a first page
    opened while they were still cold took 4 to 9 seconds. Fail-open.
    Returns the event the lifespan sets on shutdown, so a stopped dashboard
    does not keep warming (or build its schema) in the background."""
    stop = threading.Event()

    def _warm() -> None:
        try:
            timings = _warm_dashboard_caches(stop)
            if not stop.is_set():
                # Freeze what warm-up built while startup still waits: the
                # first garbage round needs ten quiet seconds, and until then
                # every full collection walked it, 0.4-0.6 s on a request.
                started = time.perf_counter()
                _freeze_long_lived_objects()
                timings["freeze"] = time.perf_counter() - started
            log.info("dashboard warm-up done: %s",
                     ", ".join(f"{k} {v * 1000:.0f} ms" for k, v in timings.items()))
        finally:
            if ready is not None:
                ready.set()
        if stop.is_set():
            return
        try:
            import asyncio as _asyncio

            from maverick import hooks

            _asyncio.run(hooks.ensure_loaded())
        except Exception:  # pragma: no cover - warm-up is best-effort
            log.debug("goal runtime warm-up skipped", exc_info=True)
        if stop.is_set():
            return
        _build_openapi_when_idle(stop=stop)
        _collect_when_idle(stop)

    thread_factory(target=_warm, name="lightwork-warm-hooks", daemon=True).start()
    return stop


def repair_default_workspace() -> None:
    """Keep the deployment's default workspace admitted once named ones exist.

    An install that created its first workspace before the default-tenant rule
    has a roster without its own bound tenant, so every task was refused as an
    unknown tenant. Registering it (active, audited) is a no-op otherwise and
    never blocks startup.
    """
    try:
        from maverick.tenant.registry import ensure_default_tenant_registered

        ensure_default_tenant_registered(actor="dashboard-startup")
    except Exception:  # pragma: no cover -- a repair must never block startup
        log.exception("default workspace repair skipped")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Application lifespan: run startup tasks, then yield to serve.

    Replaces the deprecated ``@app.on_event("startup")`` handlers. The two
    startup steps (orphan-goal reclaim, queue-dispatcher install) run in their
    original registration order; their bodies each guard with try/except so a
    failure never blocks startup.

    All owned and composed schedulers share a shutdown supervisor: close goal
    admission, signal every component, then join/drain against one deadline.
    Partial startup and exceptional lifespan exit run the same cleanup.

    One exception to "never blocks startup": when the deployment has opted into
    a mandatory enterprise boundary (MAVERICK_REQUIRE_ENTERPRISE=1 /
    ``[enterprise] require = true``), the preflight is allowed to raise and abort
    startup -- that is the point of a deploy gate. It is a silent no-op
    otherwise, so the default fail-open posture is unchanged (kernel rule 1).
    """
    from maverick.installation_recovery import assert_normal_start_allowed

    assert_normal_start_allowed()
    # Moves an administrator scheduled for "while Lightwork is stopped" run
    # here, before this process takes ownership of the data folder. Never raises.
    from .offline_maintenance import run_scheduled as _run_offline_maintenance

    await run_in_threadpool(_run_offline_maintenance)
    from maverick.deployment import require_enterprise_or_die

    require_enterprise_or_die()
    from maverick.residency import require_residency_or_die

    require_residency_or_die()  # strict region pin; no-op unless opted in
    from maverick.supply_chain import startup_check

    startup_check()  # dependency pin check; no-op unless [safety] supply_chain_pinning
    # Exactly one control plane may write a data root. A `helm template` guard
    # alone is not enough: a raw kubectl apply, `compose up --scale`, or a
    # second local `maverick dashboard` walks past it
    # -- and the failure is silent: two writers interleave valid records into
    # hash-chained ledgers that assume one author. This raises, deliberately:
    # a replica that refuses to start is a visible outage, while a corrupted
    # audit chain is discovered months later by whoever needs it most.
    from maverick.control_plane_lease import acquire as _acquire_control_plane
    from maverick.control_plane_lease import current
    from maverick.postgres_transactions import open_postgres_pools
    from maverick.runner import open_goal_admission

    from ._lifecycle import ShutdownSupervisor, register_main_components, shutdown_seconds

    runtime_receipt = None
    warm_stop: threading.Event | None = None
    previous = getattr(app.state, "lifecycle_supervisor", None)
    if previous is not None:
        previous.assert_restart_allowed()
    supervisor = ShutdownSupervisor(shutdown_seconds())
    app.state.lifecycle_supervisor = supervisor
    register_main_components(app, supervisor)
    try:
        supervisor.release_control_plane = current() is None
        _acquire_control_plane(role="dashboard")
        _assert_dashboard_auth_configured()
        open_postgres_pools()
        open_goal_admission()
        # Loud warning if reverse-proxy SSO is on but no upstream is trusted
        # (neither trusted_proxies pinned nor trust_loopback explicitly set) --
        # the forwarded identity header is then refused from every peer.
        try:
            from maverick.proxy_auth import warn_if_untrusted_proxy_config

            warn_if_untrusted_proxy_config()
        except Exception:  # pragma: no cover -- a warning must never block startup
            pass
        await run_in_threadpool(repair_default_workspace)
        await _reclaim_orphans()
        await _install_queue_dispatcher()
        try:
            from .personal_notification_scheduler import start_personal_notification_scheduler
            await run_in_threadpool(start_personal_notification_scheduler)
        except Exception as exc:
            log.warning("Personal notification observer did not start (%s)", type(exc).__name__)
        from .conversation_inbox_scheduler import start_conversation_inbox_scheduler
        await run_in_threadpool(start_conversation_inbox_scheduler)
        from .knowledge_sources_scheduler import start_knowledge_sources_scheduler
        await run_in_threadpool(start_knowledge_sources_scheduler)
        from .consent_delivery_scheduler import start_consent_delivery_scheduler
        await run_in_threadpool(start_consent_delivery_scheduler)
        from .starter_team_scheduler import start_starter_team_scheduler
        await run_in_threadpool(start_starter_team_scheduler)
        warm_ready = threading.Event()
        warm_stop = _warm_goal_runtime(ready=warm_ready)
        try:
            from maverick_dashboard.security_api import start_hunter_scheduler

            await run_in_threadpool(start_hunter_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("security hunter scheduler not started")
        try:
            from maverick_dashboard.finance_scheduler import start_finance_scheduler

            await run_in_threadpool(start_finance_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("finance operations scheduler not started")
        try:
            from maverick_dashboard.red_team_scheduler import start_red_team_scheduler

            await run_in_threadpool(start_red_team_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("red-team schedule dispatcher not started")
        try:
            from maverick_dashboard.shield_update_scheduler import (
                start_shield_update_scheduler,
            )

            await run_in_threadpool(start_shield_update_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("shared threat rules check not started")
        try:
            from maverick_dashboard.ai_inventory_scheduler import (
                start_ai_inventory_scheduler,
            )

            await run_in_threadpool(start_ai_inventory_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("AI inventory scheduler not started")
        try:
            from maverick_dashboard.ai_cost_scheduler import start_ai_cost_scheduler

            await run_in_threadpool(start_ai_cost_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("AI cost scheduler not started")
        try:
            from maverick_dashboard.daily_digest_scheduler import (
                start_daily_digest_scheduler,
            )

            await run_in_threadpool(start_daily_digest_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("daily summary scheduler not started")
        try:
            from maverick_dashboard.identity_governance_scheduler import (
                start_identity_governance_scheduler,
            )

            await run_in_threadpool(start_identity_governance_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("identity-governance scheduler not started")
        try:
            from maverick_dashboard.data_use_scheduler import start_data_use_scheduler

            await run_in_threadpool(start_data_use_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("data-use checks not started")
        try:
            # Deadline alerts (requests, incidents, assessments, vendor contracts,
            # approvals) and the webhook retry pump; stopped at shutdown.
            from maverick_dashboard.deadline_alerts_scheduler import (
                start_deadline_alerts_scheduler,
            )

            await run_in_threadpool(start_deadline_alerts_scheduler)
        except Exception:  # pragma: no cover - never block startup
            log.exception("deadline alerts scheduler not started")
        try:
            # Contact-centre handoffs still waiting when the server stopped continue; a send
            # that was in flight is shown as not confirmed and is never sent again.
            from maverick.contact_centre import resume_all_workspaces

            await run_in_threadpool(resume_all_workspaces)
        except Exception:  # pragma: no cover - never block startup
            log.exception("contact centre deliveries not resumed")
        try:
            # Profiling, the kernel activity monitor and the model proxy, each
            # only when its setting is on (All settings); stopped at shutdown.
            from maverick_dashboard.background_programs import start_enabled

            await run_in_threadpool(start_enabled)
        except Exception:  # pragma: no cover - never block startup
            log.exception("background programs not started")
        await _start_privacy_discovery_remediation_scheduler()
        await _start_privacy_notice_publication_scheduler()
        # Load installed voice weights without delaying startup. Downloads require
        # explicit persisted opt-in, or the separately reviewed Settings action.
        try:
            from .voice_setup_api import start_warmup

            start_warmup(app)
        except Exception:  # pragma: no cover - never block startup
            log.exception("voice STT warm-up not started")
        # Serve only once the first page will not pay the cold caches (it
        # waits, never fails: past the limit the warm-up simply continues).
        await run_in_threadpool(warm_ready.wait, _WARM_BEFORE_SERVING_SECONDS)
        # After the warm-up: a dream cycle that came due while the dashboard
        # was stopped is claimed at once, and run beside the warm-up it
        # stretched from about 0.3 s to 3 s and delayed serving by as much.
        await _install_automation_scheduler()
        supervisor.phase = "running"
        from maverick.runtime_configuration import start as start_runtime_receipt
        runtime_receipt = start_runtime_receipt("dashboard")
        yield
    finally:
        if warm_stop is not None:
            warm_stop.set()
        if runtime_receipt is not None:
            runtime_receipt.close()
        from .local_runtime_service import shutdown as stop_local_ai

        try:
            # Close goal admission and drain in-flight goals first: a goal still
            # running against the managed local server would otherwise lose it
            # mid-call, and new goals could still be admitted while it stops.
            await supervisor.stop()
        finally:
            await run_in_threadpool(stop_local_ai)


def enforce_page_visibility(
    request: Request = None,  # type: ignore[assignment]
) -> None:
    """App-level dependency: 403 a UI page hidden for the caller's RBAC role.

    Runs AFTER ``require_principal`` (dependency order), so the verified
    principal is already on ``request.state``. Visibility (defaults + the
    admin's Settings overrides) governs registered page paths and their
    subpaths only -- /api, webhooks, share links, auth and probe endpoints are
    unregistered and untouched. Auth off (no principal -> role None) is a
    no-op, preserving single-user local mode; hiding the nav entry alone would
    be cosmetic, this makes the hidden page unreachable too.
    """
    if request is None:  # WebSocket connection -- page policy doesn't apply
        return
    from . import auth as auth_boundary

    # A route that carries its own credential (the signed consent webhook) has
    # no dashboard role to compare against the page policy of its parent page.
    if auth_boundary._self_authenticated_path(route_path(request)):
        return
    if route_path(request) == "/workspace/tenant":
        # The picker is the recovery path for authenticated workspace members
        # who intentionally have no authority in the unbound namespace.
        auth_boundary.require_workspace_picker_access(request)
        return
    require_page_visible(request, route_path(request))


def page_visible(request: Request, path: str) -> bool:
    """Whether the page governing ``path`` admits the caller: the same rule
    :func:`enforce_page_visibility` applies to every request for it."""
    from . import ui_visibility

    page = ui_visibility.page_for(path)
    if page is None:
        return True
    role = _page_role(request, global_scope=page.get("scope") == "global")
    return ui_visibility.is_visible(page, role)


def require_page_visible(request: Request, path: str) -> None:
    """403 unless the page governing ``path`` admits the caller. A page that
    shows another page's content at a new address checks the old page here,
    so a merged view never admits more (or fewer) people than before."""
    if not page_visible(request, path):
        raise HTTPException(status_code=403, detail="this page is not enabled for your role")


async def enforce_expected_workspace_tenant(
    request: Request = None,  # type: ignore[assignment]
) -> None:
    """Reject a stale browser mutation after the selected workspace changed.

    Each rendered page carries the tenant it was rendered under. The shared UI
    client adds that value to fetches and native forms. Comparing it after
    authentication has established the request's current principal-scoped
    selection prevents an old tab from silently writing into a newly selected
    tenant. Bearer/API clients and public cross-origin contracts remain on their
    explicit authority paths and are not made dependent on browser state.
    """
    if request is None or request.method in _CSRF_SAFE_METHODS:
        return
    expected = str(
        getattr(request.state, "workspace_expected_tenant", "") or ""
    )
    if not expected or not _is_same_origin(request):
        return
    supplied = request.headers.get("x-lightwork-expected-tenant", "").strip()
    content_type = request.headers.get("content-type", "").lower()
    if not supplied and (
        content_type.startswith("application/x-www-form-urlencoded")
        or content_type.startswith("multipart/form-data")
    ):
        form = await request.form()
        supplied = str(form.get("_expected_tenant") or "").strip()
    if not constant_time_equals(supplied, expected):
        raise HTTPException(
            status_code=409,
            detail=(
                "the active workspace changed after this page loaded; reload "
                "the page and review the action before trying again"
            ),
        )


app = FastAPI(
    title="Lightwork Dashboard + REST API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    description="Local browser UI plus REST API for programmatic access.",
    # The installed maverick-dashboard release (see maverick_dashboard.__version__).
    version=_dashboard_version,
    # Global authentication dependency, applied to every route. It composes
    # proxy/OIDC/SAML/invite sessions and the static dashboard bearer, while
    # preserving same-origin loopback mode only when authentication is genuinely
    # off. `enforce_page_visibility` runs second so role-based page policy sees
    # the established principal.
    dependencies=[
        Depends(require_principal_in_request_context),
        Depends(enforce_expected_workspace_tenant),
        Depends(enforce_page_visibility),
    ],
    lifespan=_lifespan,
    # The request span (below) is the server span; see request_spans.
    **request_spans.fastapi_telemetry_kwargs(),
)
app.state.flow_dependencies = _flow_services()
from .administration_document_access_composition import (  # noqa: E402
    attach_administration_document_access_composition,
)
from .ai_entity_tasks_composition import (  # noqa: E402
    install_ai_entity_tasks_composition,
)
from .ai_evidence_analysis_composition import (  # noqa: E402
    install_ai_evidence_analysis_composition,
)
from .ai_governance_loop_composition import (  # noqa: E402
    install_ai_governance_loop_composition,
)


@app.middleware("http")
async def _shutdown_admission(request: Request, call_next):
    supervisor = getattr(request.app.state, "lifecycle_supervisor", None)
    if (supervisor is not None and supervisor.phase in {"stopping", "draining", "degraded"}
            and route_path(request) != "/livez"):
        return JSONResponse({"detail": "dashboard is shutting down"}, status_code=503,
                            headers={"Retry-After": "5"})
    return await call_next(request)


from .ai_governance_loop_scheduler import (  # noqa: E402
    attach_ai_governance_loop_scheduler,
)
from .assessment_evidence_autopopulation_composition import (  # noqa: E402
    install_assessment_evidence_autopopulation_composition,
)
from .candidate_promotion_composition import (  # noqa: E402
    install_candidate_promotion_composition,
)
from .consent_application_scanner_composition import (  # noqa: E402
    attach_consent_application_scanner_composition,
)
from .consent_bulk_jobs_composition import (  # noqa: E402
    install_consent_bulk_jobs_composition,
)
from .consent_custom_index_composition import (  # noqa: E402
    install_consent_custom_index_composition,
)
from .consent_delivery_destinations_composition import (  # noqa: E402
    attach_consent_delivery_destinations,
)
from .consent_global_opt_out_composition import (  # noqa: E402
    attach_consent_global_opt_out_composition,
)
from .consent_scan_scheduler import attach_consent_scan_scheduler  # noqa: E402
from .consent_web_publish_settings_composition import (  # noqa: E402
    attach_consent_web_publish_settings_composition,
)
from .consumer_trust_center_authority_composition import (  # noqa: E402
    attach_consumer_trust_center_authority_composition,
)
from .customer_sandbox_composition import (  # noqa: E402
    attach_customer_sandbox_composition,
)
from .data_use_provider_audit_composition import (  # noqa: E402
    attach_data_use_provider_audit_composition,
)
from .governance_agent_cross_suite_context import (  # noqa: E402
    install_governance_agent_cross_suite_context,
)
from .governance_agents_composition import (  # noqa: E402
    install_governance_agents_composition,
)
from .governed_document_vault_composition import (  # noqa: E402
    attach_governed_document_vault_composition,
)
from .identity_governance_composition import (  # noqa: E402
    attach_identity_governance_composition,
)
from .incident_attachment_metadata_composition import (  # noqa: E402
    attach_incident_attachment_metadata_composition,
)
from .no_code_grc_studio_composition import (  # noqa: E402
    install_no_code_grc_studio_composition,
)
from .privacy_data_discovery_adapters_composition import (  # noqa: E402
    attach_privacy_data_discovery_adapters,
)
from .privacy_data_discovery_scheduler import (  # noqa: E402
    install_privacy_data_discovery_scheduler,
)
from .privacy_drop_management_composition import (  # noqa: E402
    attach_privacy_drop_management_composition,
)
from .privacy_notice_publication_composition import (  # noqa: E402
    attach_privacy_notice_publication_composition,
)
from .privacy_notice_publication_scheduler import (  # noqa: E402
    install_privacy_notice_publication_scheduler,
)
from .privacy_rights_consumer_delivery_composition import (  # noqa: E402
    attach_privacy_rights_consumer_delivery_composition,
)
from .privacy_rights_intake_composition import (  # noqa: E402
    attach_privacy_rights_intake_composition,
)
from .privacy_rights_source_composition import (  # noqa: E402
    attach_privacy_rights_source_composition,
)
from .shared_governance_inventory_composition import (  # noqa: E402
    install_shared_governance_inventory_composition,
)
from .third_party_collaboration_composition import (  # noqa: E402
    attach_third_party_collaboration_composition,
)
from .third_party_contracts_composition import (  # noqa: E402
    install_third_party_contracts_composition,
)
from .third_party_executive_reports_composition import (  # noqa: E402
    install_third_party_executive_reports_composition,
)
from .third_party_intelligence_provider_composition import (  # noqa: E402
    attach_third_party_intelligence_provider_composition,
)
from .trc_continuous_evidence_scheduler import (  # noqa: E402
    attach_trc_continuous_evidence_scheduler,
)
from .trc_stock_evidence_composition import (  # noqa: E402
    install_trc_stock_evidence_composition,
)
from .trust_center_branding_composition import (  # noqa: E402
    attach_trust_center_branding_composition,
)
from .unified_audit_composition import (  # noqa: E402
    attach_unified_audit_composition,
)
from .unified_audit_scheduler import (  # noqa: E402
    attach_unified_audit_scheduler,
)

install_ai_governance_loop_composition(app)
attach_ai_governance_loop_scheduler(app)
install_ai_entity_tasks_composition(app)
install_ai_evidence_analysis_composition(app)
install_assessment_evidence_autopopulation_composition(app)
install_candidate_promotion_composition(app)
install_governance_agents_composition(app)
attach_administration_document_access_composition(app)
attach_governed_document_vault_composition(app)
attach_identity_governance_composition(app)
attach_incident_attachment_metadata_composition(app)
install_no_code_grc_studio_composition(app)
install_consent_custom_index_composition(app)
install_consent_bulk_jobs_composition(app)
attach_consent_delivery_destinations(app)
attach_consent_application_scanner_composition(app)
attach_consent_scan_scheduler(app)
attach_consent_web_publish_settings_composition(app)
install_trc_stock_evidence_composition(app)
attach_trc_continuous_evidence_scheduler(app)
attach_data_use_provider_audit_composition(app)
attach_customer_sandbox_composition(app)
attach_consumer_trust_center_authority_composition(app)
attach_trust_center_branding_composition(app)
attach_privacy_rights_intake_composition(app)
attach_privacy_rights_source_composition(app)
attach_privacy_rights_consumer_delivery_composition(app)
attach_consent_global_opt_out_composition(app)
attach_privacy_drop_management_composition(app)
attach_privacy_notice_publication_composition(app)
install_privacy_notice_publication_scheduler(app)
attach_privacy_data_discovery_adapters(app)
install_privacy_data_discovery_scheduler(app)
attach_third_party_collaboration_composition(app)
attach_third_party_intelligence_provider_composition(app)
install_third_party_contracts_composition(app)
install_third_party_executive_reports_composition(app)
install_governance_agent_cross_suite_context(app)
attach_unified_audit_composition(app)
install_shared_governance_inventory_composition(app)
attach_unified_audit_scheduler(app)
app.include_router(api_router)
app.include_router(api_documentation_router)
app.include_router(capability_assessment_controls_api.router, prefix="/api/v1")
app.include_router(runtime_policy_recovery_api.router, prefix="/api/v1")
app.include_router(learning_acquisition_api.router, prefix="/api/v1")
app.include_router(draft_router)

app.include_router(preferences_router)
app.include_router(navigation_router)
app.include_router(budget_guidance_router)
app.include_router(model_tests_router)
app.include_router(cost_reconciliation_router)
app.include_router(task_diagnostics_router)
app.include_router(employee_activation_router)
app.include_router(product_operations_router)

app.include_router(settings_experience_router)
app.include_router(settings_runtime_router)
templates.context_processors.append(_display_preference_context)
app.include_router(record_search_router)
app.include_router(conversation_inbox_router)
app.include_router(chat_message_actions_router, prefix="/api/v1")
app.include_router(workspace_erasure_router)
app.include_router(specialist_drafts_router)
app.include_router(action_center_router)
app.include_router(outcome_accounting_router)
app.include_router(outcome_pilots_router)
app.include_router(commitment_viability_router)
app.include_router(outcome_pilot_costs_router)
app.include_router(project_reviews_router)
app.include_router(deliverable_bundles_router)
app.include_router(project_workspaces_router)
app.include_router(task_handoffs_router)

app.include_router(my_work_router)
from .approval_waits import router as approval_waits_router  # noqa: E402
from .usability_survey_api import router as usability_survey_router  # noqa: E402
from .usability_survey_api import survey_context as _usability_survey_context  # noqa: E402

app.include_router(approval_waits_router)
app.include_router(usability_survey_router)
templates.context_processors.append(_usability_survey_context)
from .web_vitals_api import router as web_vitals_router  # noqa: E402
from .web_vitals_api import vitals_context as _web_vitals_context  # noqa: E402

app.include_router(web_vitals_router)
templates.context_processors.append(_web_vitals_context)

from . import usage_measures_api as _usage_measures_api  # noqa: E402

# Usage research measures: off unless [analytics] usage_measures.
app.include_router(_usage_measures_api.router)
templates.context_processors.append(_usage_measures_api.context)
app.include_router(conversation_organization_router)
from .first_outcome_api import router as first_outcome_router  # noqa: E402
from .in_app_routes import router as in_app_router  # noqa: E402

app.include_router(in_app_router)
app.include_router(first_outcome_router)
from . import practice_mode  # noqa: E402

# A person's practice session runs in the separate practice workspace,
# with a marker on every screen and live changes refused until Back to live.
app.include_router(practice_mode.router)
app.middleware("http")(practice_mode.middleware)
templates.context_processors.append(practice_mode.context)
from .billing_invoice_api import router as billing_invoice_router  # noqa: E402
from .channel_check_api import router as channel_check_router  # noqa: E402
from .comments_api import router as comments_router  # noqa: E402
from .dsar_export_handoff_api import router as dsar_export_handoff_router  # noqa: E402
from .feature_actions_api import page_router as feature_actions_page_router  # noqa: E402
from .feature_actions_api import router as feature_actions_router  # noqa: E402
from .flow_action_fields import router as flow_action_fields_router  # noqa: E402
from .mcp_presets import router as mcp_presets_router  # noqa: E402
from .page_assets import router as page_assets_router  # noqa: E402
from .policy_preview_api import router as policy_preview_router  # noqa: E402
from .policy_suggestions_api import router as policy_suggestions_router  # noqa: E402
from .provider_spending_api import router as provider_spending_router  # noqa: E402
from .recovery_api import router as recovery_router  # noqa: E402
from .recovery_mode import RecoveryOnlyMiddleware  # noqa: E402
from .store_catalogs import router as store_catalogs_router  # noqa: E402
from .support_api import router as support_router  # noqa: E402
from .system_checks_api import router as system_checks_router  # noqa: E402
from .tax_actions_api import router as tax_actions_router  # noqa: E402
from .teams_links_api import router as teams_links_router  # noqa: E402
from .tools_ops_api import build_router as build_tools_ops_router  # noqa: E402
from .voice_setup_api import VoiceSetup  # noqa: E402
from .voice_setup_api import router as voice_setup_router  # noqa: E402
from .voice_unlock_api import router as voice_unlock_router  # noqa: E402

app.include_router(recovery_router)
app.include_router(provider_spending_router)
app.include_router(support_router)
app.include_router(comments_router)
app.include_router(policy_suggestions_router)
app.include_router(policy_preview_router)
app.include_router(system_checks_router)
app.include_router(feature_actions_router)
app.include_router(feature_actions_page_router)
app.include_router(tax_actions_router)
app.include_router(channel_check_router)
app.include_router(dsar_export_handoff_router)
app.include_router(flow_action_fields_router)
app.include_router(teams_links_router)
app.include_router(page_assets_router)
app.include_router(mcp_presets_router)
app.include_router(store_catalogs_router)
app.include_router(billing_invoice_router)
app.include_router(voice_setup_router)
app.include_router(voice_unlock_router)
app.include_router(build_tools_ops_router())
# Installation operations that were terminal-only (Settings > Maintenance,
# Workspaces, Billing, Help, Savings, Performance and the full setup guide).
from . import (  # noqa: E402
    billing_ops_api,
    insights_ops_api,
    installation_ops_api,
    process_ops_api,
    setup_guide,
    support_ops_api,
    tenant_ops_api,
)

for _ops_module in (billing_ops_api, insights_ops_api, installation_ops_api, support_ops_api, tenant_ops_api):
    app.include_router(_ops_module.router)
    app.include_router(_ops_module.asset_router)
app.include_router(process_ops_api.router)
app.include_router(setup_guide.router)
from .workflow_explanation import asset_router as workflow_explanation_assets  # noqa: E402

app.include_router(workflow_explanation_assets)
from . import local_flow_promotions  # noqa: E402

app.include_router(local_flow_promotions.router)
app.include_router(local_flow_promotions.asset_router)
from . import local_flow_comparisons  # noqa: E402

app.include_router(local_flow_comparisons.router)
from . import instruction_capture_api  # noqa: E402

app.include_router(instruction_capture_api.router)
app.include_router(instruction_capture_api.page_router)
from . import approval_challenges_api  # noqa: E402

app.include_router(approval_challenges_api.router)
app.include_router(approval_challenges_api.page_router)

from . import installation_security_api  # noqa: E402

app.include_router(installation_security_api.router)
app.include_router(installation_security_api.page_router)

from . import local_runtime_api  # noqa: E402

app.include_router(local_runtime_api.router)

from . import compliance_mapping_builder_api  # noqa: E402

app.include_router(compliance_mapping_builder_api.router)
app.include_router(compliance_mapping_builder_api.page_router)

from . import webhook_settings_recovery_api  # noqa: E402

app.include_router(webhook_settings_recovery_api.router)
app.include_router(webhook_settings_recovery_api.asset_router)
app.state.voice_setup = VoiceSetup()
app.add_middleware(RecoveryOnlyMiddleware, dashboard_app=app)


def _compress_enabled() -> bool:
    """``[dashboard] compress`` (default on), overridden by
    ``MAVERICK_DASHBOARD_COMPRESS``. Response compression for a self-hosted
    dashboard behind a bare uvicorn or a default ingress; turn it off
    when a proxy in front already compresses."""
    env = os.environ.get("MAVERICK_DASHBOARD_COMPRESS", "").strip().lower()
    if env:
        return env in {"1", "true", "yes", "on"}
    try:
        from maverick.config import load_config

        value = ((load_config() or {}).get("dashboard") or {}).get("compress")
    except Exception:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return True


# Versioned static assets get the long cache; then gzip (outermost, so it
# compresses every response including the static bundles). Starlette's
# middleware skips text/event-stream and already-compressed media types.
# Level 6 (zlib's default) instead of Starlette's 9: on the rendered pages
# it halves the per-response CPU cost for a 1-3% larger body.
app.add_middleware(StaticCacheMiddleware, version_for=static_version)
if _compress_enabled():
    from starlette.middleware.gzip import GZipMiddleware

    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)
# Outermost: refuse an over-size request before any parser (the multipart
# form parser spools uploads to disk) reads it.
from .request_size import RequestSizeLimitMiddleware  # noqa: E402

app.add_middleware(RequestSizeLimitMiddleware)
from .agent_control_plane_page import (  # noqa: E402
    create_agent_control_plane_page_router,
)
from .ai_entity_tasks_page import create_ai_entity_tasks_page_router  # noqa: E402
from .ai_evidence_analysis_page import (  # noqa: E402
    create_ai_evidence_analysis_page_router,
)
from .assessment_evidence_autopopulation_page import (  # noqa: E402
    create_assessment_evidence_autopopulation_page_router,
)
from .autonomous_compliance_page import (  # noqa: E402
    create_autonomous_compliance_page_router,
)
from .consent_application_scanner_page import (  # noqa: E402
    create_consent_application_scanner_page_router,
)
from .consent_bulk_jobs_page import (  # noqa: E402
    create_consent_bulk_jobs_page_router,
)
from .consent_custom_index_page import (  # noqa: E402
    create_consent_custom_index_page_router,
)
from .consent_global_opt_out_page import (  # noqa: E402
    create_consent_global_opt_out_page_router,
)
from .consent_native_page import create_consent_native_page_router  # noqa: E402
from .consent_web_publish_settings_page import (  # noqa: E402
    create_consent_web_publish_settings_page_router,
)
from .cortex_page import create_cortex_page_router  # noqa: E402
from .evolution_ledger_page import (  # noqa: E402
    create_evolution_ledger_page_router,
)
from .governed_document_vault_page import (  # noqa: E402
    create_governed_document_vault_page_router,
)
from .immune_console import create_immune_console_page_router  # noqa: E402
from .no_code_grc_studio_page import create_no_code_grc_studio_page_router  # noqa: E402
from .privacy_drop_management_page import (  # noqa: E402
    create_privacy_drop_management_page_router,
)
from .regulatory_obligations_page import (  # noqa: E402
    create_regulatory_obligations_page_router,
)
from .shared_governance_inventory_page import (  # noqa: E402
    create_shared_governance_inventory_page_router,
)
from .shoring_page import create_shoring_page_router  # noqa: E402
from .tenant_select_page import create_tenant_select_page_router  # noqa: E402
from .third_party_contracts_page import (  # noqa: E402
    create_third_party_contracts_page_router,
)
from .third_party_executive_reports_page import (  # noqa: E402
    create_third_party_executive_reports_page_router,
)
from .trust_receipts_page import (  # noqa: E402
    create_trust_receipts_page_router,
)

app.include_router(create_tenant_select_page_router(templates))
app.include_router(create_ai_evidence_analysis_page_router(templates))
app.include_router(create_assessment_evidence_autopopulation_page_router(templates))
app.include_router(create_ai_entity_tasks_page_router(templates))
app.include_router(create_consent_custom_index_page_router(templates))
app.include_router(create_consent_application_scanner_page_router(templates))
app.include_router(create_consent_global_opt_out_page_router(templates))
app.include_router(create_consent_native_page_router(templates))
app.include_router(create_consent_web_publish_settings_page_router(templates))
app.include_router(create_consent_bulk_jobs_page_router(templates))
app.include_router(create_governed_document_vault_page_router(templates))
app.include_router(create_no_code_grc_studio_page_router(templates))
app.include_router(create_privacy_drop_management_page_router(templates))
app.include_router(create_shared_governance_inventory_page_router(templates))
app.include_router(create_agent_control_plane_page_router(templates))
app.include_router(create_regulatory_obligations_page_router(templates))
app.include_router(create_trust_receipts_page_router(templates))
app.include_router(create_cortex_page_router(templates))
app.include_router(create_autonomous_compliance_page_router(templates))
from .compliance_controls_api import router as _compliance_controls_router  # noqa: E402

app.include_router(_compliance_controls_router)
from .privacy_actions_api import router as _privacy_actions_router  # noqa: E402

app.include_router(_privacy_actions_router)
from .ui_choices_api import router as _ui_choices_router  # noqa: E402

app.include_router(_ui_choices_router)
from .trust_page_api import router as _trust_page_router  # noqa: E402

app.include_router(_trust_page_router)
from .third_party_page_assets import router as _third_party_page_assets  # noqa: E402

app.include_router(_third_party_page_assets)
from .trc_setup_api import router as _trc_setup_router  # noqa: E402

app.include_router(_trc_setup_router)
from .audit_ops_api import router as _audit_ops_router  # noqa: E402
from .governance_ops_api import router as _governance_ops_router  # noqa: E402
from .immune_ops_api import router as _immune_ops_router  # noqa: E402
from .privacy_ops_api import router as _privacy_ops_router  # noqa: E402
from .security_ops_api import router as _security_ops_router  # noqa: E402
from .webhooks_api import create_webhooks_page_router  # noqa: E402
from .webhooks_api import router as _webhooks_router  # noqa: E402

for _ops_router in (_audit_ops_router, _governance_ops_router, _immune_ops_router,
                    _privacy_ops_router, _security_ops_router):
    app.include_router(_ops_router)
app.include_router(_webhooks_router)
app.include_router(create_webhooks_page_router(templates))
app.include_router(create_shoring_page_router(templates))
app.include_router(create_evolution_ledger_page_router(templates))
app.include_router(create_immune_console_page_router(templates))
app.include_router(create_third_party_contracts_page_router(templates))
app.include_router(create_third_party_executive_reports_page_router(templates))
from .vendor_onboarding_api import router as vendor_onboarding_router  # noqa: E402
from .vendor_onboarding_composition import attach_vendor_onboarding_composition  # noqa: E402
from .vendor_onboarding_page import create_vendor_onboarding_page_router  # noqa: E402

attach_vendor_onboarding_composition(app)
app.include_router(vendor_onboarding_router, prefix="/api/v1")
from .portal_routing_key_api import router as portal_routing_key_router  # noqa: E402
from .task_changes_api import router as task_changes_router  # noqa: E402
from .task_file_recovery_api import router as task_file_recovery_router  # noqa: E402
from .vendor_setup_api import router as vendor_setup_router  # noqa: E402
from .viewpoints_api import router as viewpoints_router  # noqa: E402

app.include_router(vendor_setup_router)
app.include_router(portal_routing_key_router)
app.include_router(task_file_recovery_router)
app.include_router(task_changes_router)
app.include_router(viewpoints_router)
from .cli_ops_api import router as cli_ops_router  # noqa: E402

app.include_router(cli_ops_router)
from .connection_setup_api import router as connection_setup_router  # noqa: E402

app.include_router(connection_setup_router)
from .knowledge_access_api import page_router as knowledge_access_page_router  # noqa: E402
from .knowledge_access_api import router as knowledge_access_router  # noqa: E402
from .research_api import page_router as research_page_router  # noqa: E402
from .research_api import router as research_router  # noqa: E402

app.include_router(research_router)
app.include_router(research_page_router)
app.include_router(knowledge_access_router)
from .knowledge_sources_api import router as knowledge_sources_router  # noqa: E402

app.include_router(knowledge_sources_router, prefix="/api/v1")
from .vendor_profile_api import router as vendor_profile_router  # noqa: E402

app.include_router(vendor_profile_router, prefix="/api/v1")
from .channel_test_requests_api import router as channel_test_requests_router  # noqa: E402

app.include_router(channel_test_requests_router)
from .answer_feedback_operations import router as answer_feedback_router  # noqa: E402
from .department_team_updates_api import router as department_team_updates_router  # noqa: E402
from .starter_team_schedule_api import router as starter_team_schedule_router  # noqa: E402
from .starter_teams_api import create_page_router as create_starter_teams_page_router  # noqa: E402
from .starter_teams_api import router as starter_teams_router  # noqa: E402

app.include_router(department_team_updates_router)
app.include_router(starter_teams_router)
app.include_router(starter_team_schedule_router)
app.include_router(create_starter_teams_page_router(templates))
app.include_router(answer_feedback_router)
from .flow_run_feedback import router as flow_run_feedback_router  # noqa: E402

app.include_router(flow_run_feedback_router)
from .compliance_questionnaire_builder_api import (  # noqa: E402
    router as compliance_questionnaire_builder_router,
)

app.include_router(compliance_questionnaire_builder_router, prefix="/api/v1")

from .manual_skill_removal_api import router as manual_skill_removal_router  # noqa: E402

app.include_router(manual_skill_removal_router, prefix="/api/v1")

from .learning_example_decisions_api import (  # noqa: E402
    router as learning_example_decisions_router,
)

app.include_router(learning_example_decisions_router, prefix="/api/v1")

from . import (  # noqa: E402
    access_key_requests_api,
    agent_override_changes_api,
    applicability_regions_api,
    automation_imports_api,
    commitment_capability_api,
    commitment_economic_alternatives_api,
    competence_transport_api,
    consent_publication_withdrawal_api,
    flow_requalification_api,
    generated_tool_removal_api,
    governed_rule_evolution_api,
    grc_draft_changes_api,
    learning_calibration_api,
    learning_distinctions_api,
    learning_transfers_api,
    operator_acquisition_api,
    private_task_computation_api,
    procedure_interactions_api,
    recovery_visibility_api,
    report_downloads_api,
    request_program_api,
    settings_catalog_requests_api,
    shared_decision_evidence_api,
    work_restructuring_api,
    workflow_step_checks,
)

app.include_router(shared_decision_evidence_api.router)
app.include_router(flow_requalification_api.router)
app.include_router(learning_distinctions_api.router)
app.include_router(learning_calibration_api.router)
app.include_router(learning_transfers_api.router)
app.include_router(commitment_capability_api.router)
app.include_router(commitment_economic_alternatives_api.router)
app.include_router(competence_transport_api.router)
app.include_router(grc_draft_changes_api.router, prefix="/api/v1")
app.include_router(work_restructuring_api.router)
app.include_router(private_task_computation_api.router)
app.include_router(recovery_visibility_api.router)
app.include_router(procedure_interactions_api.router)
app.include_router(request_program_api.router)
app.include_router(operator_acquisition_api.router)
app.include_router(governed_rule_evolution_api.router)
app.include_router(applicability_regions_api.router)
app.include_router(agent_override_changes_api.router, prefix="/api/v1")
app.include_router(automation_imports_api.router)
app.include_router(report_downloads_api.router)
from .chat_answer_exports_api import router as chat_answer_exports_router  # noqa: E402

app.include_router(chat_answer_exports_router)
from .product_operations_chat_code_controls import router as chat_code_controls_router  # noqa: E402

app.include_router(chat_code_controls_router)
from .learning_question_checks_api import router as learning_question_checks_router  # noqa: E402

app.include_router(learning_question_checks_router)
from .task_model_selection_api import router as task_model_selection_router  # noqa: E402

app.include_router(task_model_selection_router)
from .privacy_discovery_data_use_api import (  # noqa: E402
    router as privacy_discovery_data_use_router,
)

app.include_router(privacy_discovery_data_use_router, prefix="/api/v1")
from .agent_activity_api import router as agent_activity_router  # noqa: E402
from .audit_checkpoint_custody_api import router as audit_checkpoint_custody_router  # noqa: E402
from .consent_delivery_managed_api import router as consent_delivery_managed_router  # noqa: E402
from .dsar_handling_api import router as dsar_handling_router  # noqa: E402
from .executive_report_schedules_api import (  # noqa: E402
    router as executive_report_schedules_router,
)
from .personal_push_devices_api import router as personal_push_devices_router  # noqa: E402
from .product_tour import router as product_tour_router  # noqa: E402
from .runtime_enforcement_api import router as runtime_enforcement_router  # noqa: E402
from .voice_receiver_api import router as voice_receiver_router  # noqa: E402
from .work_record_details_api import router as work_record_details_router  # noqa: E402

app.include_router(dsar_handling_router)
app.include_router(runtime_enforcement_router, prefix="/api/v1")
app.include_router(consent_delivery_managed_router, prefix="/api/v1")
app.include_router(voice_receiver_router)
app.include_router(personal_push_devices_router)
app.include_router(product_tour_router)
app.include_router(audit_checkpoint_custody_router)
app.include_router(agent_activity_router)
app.include_router(executive_report_schedules_router)
app.include_router(work_record_details_router)
app.include_router(generated_tool_removal_api.router)
app.include_router(access_key_requests_api.router, prefix="/api/v1")
app.include_router(consent_publication_withdrawal_api.router, prefix="/api/v1")
app.include_router(workflow_step_checks.router)
app.include_router(settings_catalog_requests_api.router, prefix="/api/v1")
from .plugin_practice_forms_api import router as plugin_practice_forms_router  # noqa: E402

app.include_router(plugin_practice_forms_router)
app.include_router(knowledge_access_page_router)
app.include_router(create_vendor_onboarding_page_router(templates))
from .agent_control_plane_api import router as agent_control_plane_router  # noqa: E402
from .cortex_api import router as cortex_router  # noqa: E402
from .customer_sandbox_api import router as customer_sandbox_router  # noqa: E402
from .evolution_ledger_api import router as evolution_ledger_router  # noqa: E402
from .immune_console import router as immune_console_router  # noqa: E402
from .regulatory_obligations_api import router as regulatory_obligations_router  # noqa: E402
from .shared_governance_inventory_api import (  # noqa: E402
    router as shared_governance_inventory_router,
)
from .shoring_api import router as shoring_router  # noqa: E402
from .trust_receipts_api import router as trust_receipts_router  # noqa: E402
from .unified_audit_api import router as unified_audit_router  # noqa: E402

app.include_router(customer_sandbox_router, prefix="/api/v1")
app.include_router(unified_audit_router, prefix="/api/v1")
app.include_router(shared_governance_inventory_router, prefix="/api/v1")
app.include_router(agent_control_plane_router, prefix="/api/v1")
app.include_router(regulatory_obligations_router, prefix="/api/v1")
app.include_router(trust_receipts_router, prefix="/api/v1")
app.include_router(cortex_router, prefix="/api/v1")
app.include_router(shoring_router, prefix="/api/v1")
app.include_router(evolution_ledger_router, prefix="/api/v1")
app.include_router(immune_console_router, prefix="/api/v1")
from .operations_actions import api_router as operations_actions_router  # noqa: E402
from .operations_actions import asset_router as operations_assets_router  # noqa: E402

app.include_router(operations_actions_router, prefix="/api/v1")
app.include_router(operations_assets_router)
# Public consent collection uses a separate opaque client credential and
# profile capability.  It is mounted directly because its router already owns
# the complete /api/v1/public/consent prefix and must not inherit /api/v1 twice.
# The feature gate is fail-closed, so including it is inert until consent,
# publishing, and the public API are all explicitly enabled.
from .consent_public_api import (  # noqa: E402
    create_consent_public_router,
    default_public_consent_dependencies,
    public_consent_error_origin,
)

_public_consent_dependencies = default_public_consent_dependencies()
app.state.privacy_rights_intake_public_dependencies_factory = lambda *, request: (
    _public_consent_dependencies
)
app.state.public_consent_error_origin_resolver = lambda request: public_consent_error_origin(
    request, _public_consent_dependencies
)
app.include_router(create_consent_public_router(_public_consent_dependencies))
# Public website chat: the visitor router is self-authenticated (publishable key
# plus origin) and the admin router sits under dashboard auth. Both answer 404
# while [public_chat] enabled is false, and store nothing until then.
from .public_chat_api import (  # noqa: E402
    create_public_chat_admin_router,
    create_public_chat_router,
)

app.include_router(create_public_chat_router())
app.include_router(create_public_chat_admin_router())
# The public rights-request form: JSON API under /api/v1/public/rights and
# the hosted pages under /rights/. Fail-closed on its module gate.
from .public_rights_api import pages as _public_rights_pages  # noqa: E402
from .public_rights_api import router as _public_rights_router  # noqa: E402

app.include_router(_public_rights_router)
app.include_router(_public_rights_pages)
from .consent_native_admin_api import (  # noqa: E402
    create_consent_native_public_metadata_router,
)
from .consent_native_admin_api import router as consent_native_admin_router  # noqa: E402
from .consent_native_composition import attach_consent_native_composition  # noqa: E402
from .consent_native_sdk_api import create_consent_native_sdk_router  # noqa: E402

_native_consent_dependencies = attach_consent_native_composition(
    app,
    public_dependencies=_public_consent_dependencies,
)
app.include_router(create_consent_native_sdk_router(_native_consent_dependencies))
app.include_router(create_consent_native_public_metadata_router())
app.include_router(consent_native_admin_router, prefix="/api/v1")
from .consent_web_publish_settings_api import (  # noqa: E402
    create_consent_web_publish_settings_public_router,
)

app.include_router(
    create_consent_web_publish_settings_public_router(),
    prefix="/api/v1/public",
)
from .consent_identity_federation_api import (  # noqa: E402
    create_consent_identity_federation_router,
)

app.include_router(create_consent_identity_federation_router())
from .privacy_rights_ott_ctv_api import (  # noqa: E402
    create_ott_ctv_privacy_rights_router,
)

app.include_router(create_ott_ctv_privacy_rights_router())
# Admin pages (/settings + /users): their own router module -- the first
# slice of decomposing this file by nav group. See maverick_dashboard.admin_pages.
from .admin_pages import router as admin_pages_router  # noqa: E402
from .me_api import api as me_api_router  # noqa: E402
from .me_api import router as me_router  # noqa: E402
from .sessions_page import router as sessions_router  # noqa: E402

app.include_router(admin_pages_router)
app.include_router(sessions_router)
app.include_router(me_router)
app.include_router(me_api_router)
# Settings > All settings (/settings/all + its catalog save/reset API).
from .privacy_notice_publication_targets_api import (  # noqa: E402
    router as privacy_notice_targets_router,
)
from .settings_all_page import router as settings_all_router  # noqa: E402

app.include_router(settings_all_router)
from .employee_companion_api import router as employee_companion_router  # noqa: E402

app.include_router(employee_companion_router)
from .content_access_api import router as content_access_router  # noqa: E402
from .employee_departures_api import router as employee_departures_router  # noqa: E402
from .personal_data_api import router as personal_data_router  # noqa: E402

app.include_router(content_access_router)
app.include_router(employee_departures_router)
from .permission_requests_api import router as permission_requests_router  # noqa: E402

app.include_router(permission_requests_router)
app.include_router(personal_data_router)
# Finance operations that were terminal-only (the separation-of-duties check).
from .finance_ops_api import router as finance_ops_router  # noqa: E402

app.include_router(finance_ops_router)
app.include_router(privacy_notice_targets_router)
# Settings > Maintenance: copying consent records into the shared consent database.
from .consent_storage_api import router as consent_storage_router  # noqa: E402

app.include_router(consent_storage_router)
# Ekko Work Discovery: a human review/control surface only.  Endpoint
# collectors do not enter through HTTP; they write through the local core
# daemon's owner/device/tenant-scoped store.
from .ekko_routes import router as ekko_router  # noqa: E402

app.include_router(ekko_router)
# Built-in OIDC browser-login routes (/auth/login, /auth/callback, /auth/logout).
# Each route self-gates on maverick.oidc.login_enabled() and 404s when the login
# flow isn't fully configured, so including the router unconditionally is inert
# off by default. See maverick_dashboard.oidc_login.
app.include_router(oidc_login_router)
from .company_signin_tests import router as company_signin_tests_router  # noqa: E402
from .connected_event_sources_api import router as connected_event_sources_router  # noqa: E402

app.include_router(company_signin_tests_router)
from .company_signin_migration_api import router as company_signin_migration_router  # noqa: E402

app.include_router(company_signin_migration_router)
from .company_saml_setup_api import recovery_router as company_saml_recovery_router  # noqa: E402
from .company_saml_setup_api import router as company_saml_setup_router  # noqa: E402

app.include_router(company_saml_setup_router)
app.include_router(company_saml_recovery_router)


@app.get("/auth/company-signin-recovery", response_class=HTMLResponse)
def company_signin_recovery_page(request: Request):
    from .company_signin_migration import recovery_page_allowed

    recovery_page_allowed(request)
    response = templates.TemplateResponse(request, "company_signin_recovery.html", {})
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.get("/auth/company-saml-recovery", response_class=HTMLResponse)
def company_saml_recovery_page(request: Request):
    from .company_signin_migration import recovery_page_allowed

    recovery_page_allowed(request)
    return templates.TemplateResponse(request, "company_saml_recovery.html", {},
                                      headers={"Cache-Control": "private, no-store", "Referrer-Policy": "same-origin"})


app.include_router(connected_event_sources_router, prefix="/api/v1")
from .personal_alert_tests import router as personal_alert_tests_router  # noqa: E402

app.include_router(personal_alert_tests_router)
from .human_conversation_handoffs_api import (  # noqa: E402
    router as human_conversation_handoffs_router,
)

app.include_router(human_conversation_handoffs_router)


@app.get("/human-conversations", response_class=HTMLResponse)
def human_conversations_page(request: Request):
    from .human_conversation_handoffs import authority

    _actor, context = authority(request)
    return templates.TemplateResponse(request, "human_conversation_handoffs.html", {"human_conversation_context": context},
                                      headers={"Cache-Control": "private, no-store"})


# Email invite links (/auth/invite/{token}): single-use onboarding links an
# admin mints on /users. Self-gates on [dashboard] invites (default off), so
# including it unconditionally is inert. See maverick_dashboard.invite_routes.
from .api_keys_api import router as api_keys_router  # noqa: E402
from .invite_routes import router as invite_router  # noqa: E402

# Personal / service-account API keys: page + JSON routes. Self-gates on
# [dashboard] api_keys (404 when off).
app.include_router(api_keys_router)
from .local_owner_mfa_routes import router as local_owner_mfa_router  # noqa: E402
from .local_owner_routes import router as local_owner_router  # noqa: E402
from .session_expiry import page_session as _page_session  # noqa: E402
from .session_expiry import router as session_expiry_router  # noqa: E402

app.include_router(local_owner_router)
app.include_router(local_owner_mfa_router)
app.include_router(session_expiry_router)
# The page shell's sign-in timer (lightwork-session.js): when this browser's
# sign-in ends and how to stay signed in. None when nobody is signed in.
templates.env.globals["page_session"] = _page_session

app.include_router(invite_router)
# One-time passphrase reset links (/auth/invite/reset/{token}) that the owner
# makes on /users. Same token-is-the-credential shape as invite links; inert
# unless colleagues sign in with passphrases. See passphrase_resets.
from .passphrase_resets import router as passphrase_reset_router  # noqa: E402

app.include_router(passphrase_reset_router)
# SCIM 2.0 user provisioning (/scim/v2). Self-gates on MAVERICK_SCIM_TOKEN and
# 404s when unset, so including it is inert off by default. It carries its own
# static IdP bearer, so the /scim/ prefix is exempted from the dashboard-token
# middleware and the OIDC gate below.
from .scim import router as scim_router  # noqa: E402

app.include_router(scim_router)
# SAML 2.0 SP browser SSO (/saml/...). 404s until [auth.saml] is configured, so
# including it is inert off by default. The IdP POSTs the assertion to the ACS
# with no dashboard bearer, so the /saml/ prefix is exempted from the
# dashboard-token middleware and the OIDC gate (it's how a browser gets a session).
from .saml import router as saml_router  # noqa: E402

app.include_router(saml_router)
# Self-authenticating external integrations (/api/v1/external/...): agents on
# other platforms, signed discovery sensors, and invited vendor respondents use
# route-specific credentials instead of a dashboard session. Individual route
# families self-gate on their own configuration. The prefix is
# self-authenticating (see _AUTH_EXEMPT rationale for /a2a/v1).
from .external_gateway import router as external_gateway_router  # noqa: E402
from .third_party_collaboration_api import (  # noqa: E402
    external_router as third_party_collaboration_external_router,
)
from .third_party_collaboration_portal import (  # noqa: E402
    router as third_party_collaboration_portal_router,
)

app.include_router(external_gateway_router)
app.include_router(third_party_collaboration_external_router)
app.include_router(third_party_collaboration_portal_router)
a2a.mount(app)

_DOCS_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "script-src 'self' 'nonce-{script_nonce}' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)

# {script_nonce} is filled per response by security_headers.
_DEFAULT_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'nonce-{script_nonce}'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)

def _persist_pref_cookie(request, response, *, param, cookie, valid, max_age) -> None:
    """Set a preference cookie when ``?param=`` is a valid value. Shared by the
    font/density/lang persistence (the theme uses its own _set_theme_cookie)."""
    v = request.query_params.get(param)
    if v and v.lower() in valid:
        response.set_cookie(cookie, v.lower(), max_age=max_age, samesite="lax", httponly=False)


@app.middleware("http")
async def persist_theme(request: Request, call_next):
    """If ?theme= / ?font= / ?density= / ?glass= / ?lang= is in the URL, set a cookie so it sticks."""
    response = await call_next(request)
    q = request.query_params.get("theme")
    if q and q.lower() in _valid_theme_names():
        _set_theme_cookie(response, q.lower())
    from .i18n import LANGS

    _persist_pref_cookie(
        request,
        response,
        param="font",
        cookie="mvk_font",
        valid=_VALID_FONTS,
        max_age=30 * 24 * 3600,
    )
    _persist_pref_cookie(
        request,
        response,
        param="density",
        cookie="mvk_density",
        valid=_VALID_DENSITIES,
        max_age=30 * 24 * 3600,
    )
    _persist_pref_cookie(
        request,
        response,
        param="glass",
        cookie="mvk_glass",
        valid=_VALID_GLASS,
        max_age=30 * 24 * 3600,
    )
    _persist_pref_cookie(
        request, response, param="lang", cookie="mvk_lang", valid=LANGS, max_age=365 * 24 * 3600
    )
    return response


async def _reclaim_orphans() -> None:
    """Mark stale goals as blocked after a crash in each configured world.

    Without this, SIGKILL/OOM mid-run strands rows in 'active' forever
    and `active_goal()` returns a ghost. SQLite retains its established
    active/pending startup policy for the default world and visits registered
    workspace worlds in bounded batches. PostgreSQL leaves pending to dispatchers.
    """
    try:
        from maverick.world_model_backends import is_postgres_configured

        if is_postgres_configured():
            from maverick.paths import current_tenant_id_strict
            from maverick.world_model import reclaim_window_seconds

            from .orphan_sweeper import MIN_WINDOW_SECONDS, reclaim_registered_postgres

            window = reclaim_window_seconds()
            if not math.isfinite(window) or window < MIN_WINDOW_SECONDS:
                log.warning("orphan reclaim skipped: unsafe PostgreSQL stale window")
                n = 0
            elif current_tenant_id_strict() is not None:
                # A process-bound single-tenant deployment already has its
                # authority; preserve that path without requiring a roster.
                n = _world().reclaim_orphan_goals(
                    statuses=("active",), resolved_window_seconds=window,
                    exact_tenant=True,
                )
            else:
                # Shared PostgreSQL has no request tenant at startup. One
                # bounded roster batch runs now; the periodic sweeper resumes
                # the cursor. Missing/corrupt roster leaves rows untouched.
                n = reclaim_registered_postgres(
                    _world, resolved_window_seconds=window,
                )
        else:
            n = _world().reclaim_orphan_goals()
            from maverick.paths import current_tenant_id_strict
            if current_tenant_id_strict() is None:
                from .orphan_sweeper import reclaim_registered_sqlite
                n += reclaim_registered_sqlite(_world)
        if n:
            log.warning("reclaimed %d orphan goal(s) from prior crash", n)
    except Exception:
        log.exception("orphan reclaim failed on startup")
    # A quick restart can leave a dead goal younger than the stale window.
    # The supervised sweep revisits it after the window, while live runs
    # continue to refresh their own liveness timestamp.
    try:
        from .orphan_sweeper import start_orphan_sweeper

        start_orphan_sweeper()
    except Exception:
        log.exception("stopped-task sweep not started")


async def _install_queue_dispatcher() -> None:
    """Install an out-of-process goal dispatcher if one is configured.

    ``[queue] backend`` selects the arq/Redis QueueDispatcher; ``[grpc_dispatch]
    target`` selects the gRPC remote-worker dispatcher. Both make this (producer)
    process hand goals to a worker pool instead of running them in-process. The
    queue takes precedence when both are set (they share the single dispatcher
    slot); the gRPC dispatcher is only attempted when the queue didn't install.
    No-op for the default in-process install."""
    try:
        from maverick.queue_dispatcher import install_from_config

        if install_from_config():
            log.info("queue dispatcher installed: goals run out-of-process")
            return
    except Exception:
        # The queue installer pins a rejecting dispatcher before raising. Keep
        # that fail-closed state; a gRPC fallback would silently overwrite it.
        log.exception("queue dispatcher install failed; dispatch remains fail-closed")
        return
    # gRPC dispatch had a complete install_from_config() that nothing called, so
    # [grpc_dispatch] target was silently ignored and goals kept running
    # in-process. Wire it in as the fallback out-of-process path.
    try:
        from maverick.grpc_dispatcher import install_from_config as install_grpc

        if install_grpc():
            log.info("gRPC dispatcher installed: goals run on a remote worker")
    except Exception:
        log.exception("gRPC dispatcher install failed (running in-process)")


_AUTH_EXEMPT = {
    "/healthz",
    "/livez",
    "/readyz",
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    # The A2A task endpoint enforces its own shared/per-agent bearer and trust
    # plane. Requiring the unrelated dashboard bearer here would either block
    # valid A2A identities or pressure operators to reuse one credential across
    # two trust domains.
    "/a2a/v1",
    # /webhook/start authenticates with its own HMAC signature instead of
    # the dashboard bearer / same-origin checks (external senders have
    # neither), so it must bypass the centralized middleware.
    *SELF_AUTH_WEBHOOK_PATHS,
    *SELF_AUTH_SIGNIN_RECOVERY_PATHS,
    # The exact HMAC webhook paths are shared with the global dependency. A
    # future /webhook/* route is authenticated by default until explicitly
    # added to that reviewed set.
    # Built-in OIDC browser-login endpoints: they bootstrap a session and carry
    # their own flow-level security (state/PKCE/signed cookies). They must be
    # reachable by a browser that has no dashboard token yet; each self-gates on
    # login_enabled() and 404s when the login flow is off.
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/auth/error",
    "/auth/local-owner",
    "/auth/local-login",
    "/auth/owner-second-factor",
    # The stylesheet, brand images, fonts and share-page renderer the
    # signed-out pages (sign-in, invitation, public rights form, shared
    # result) load before any session exists. One reviewed set of exact files,
    # shared with the global dependency (auth.PUBLIC_STATIC_PATHS).
    *PUBLIC_STATIC_PATHS,
    # The LLM gateway authenticates every call with its OWN bearer inside
    # maverick.llm_gateway (same rationale as /a2a/v1): callers are foreign
    # agents that hold the gateway credential, never the dashboard bearer.
    # Self-gates on [llm_gateway] enable and 403s when off.
    "/gateway/v1/chat/completions",
    "/gateway/v1/messages",
    "/gateway/v1/otel",
    # The consent webhook authenticates every delivery with its OWN HMAC
    # signature inside maverick.consent_registry (external CMPs hold the
    # webhook secret, never the dashboard bearer). Self-gates on
    # [consent_registry] webhook_enable and 403s when off.
    "/consent/webhook",
}


# Inbound webhook bodies are intentionally small JSON payloads.  Enforce
# this before HMAC verification so unauthenticated callers cannot force the
# dashboard to buffer or hash arbitrarily large request bodies.
_MAX_WEBHOOK_BODY_BYTES = 256 * 1024
_MAX_SKILL_VALIDATE_BODY_BYTES = 256 * 1024
_MAX_SAVED_VIEW_BODY_BYTES = 32 * 1024
_MAX_SECURITY_HUNTER_HTTP_BODY_BYTES = 17 * 1024 * 1024
_MAX_FINANCE_DEFAULT_BODY_BYTES = 256 * 1024
_MAX_FINANCE_REGULATORY_BODY_BYTES = 7 * 1024 * 1024
_MAX_FINANCE_AML_LIST_BODY_BYTES = 20 * 1024 * 1024
_MAX_FINANCE_ANOMALY_BODY_BYTES = 32 * 1024 * 1024
_MAX_EVIDENCE_GATEWAY_BODY_BYTES = 3 * 1024 * 1024
_MAX_EVIDENCE_GATEWAY_DELIVERY_BODY_BYTES = 34 * 1024 * 1024
_MAX_PUBLIC_CONSENT_BODY_BYTES = 64 * 1024
_MAX_NATIVE_CONSENT_BODY_BYTES = 256 * 1024
_MAX_THIRD_PARTY_COLLABORATION_BODY_BYTES = 2 * 1024 * 1024
_EXTERNAL_BODY_SLOTS = 32
_EXTERNAL_BODY_TIMEOUT_SECONDS = 10.0
_external_body_limiters: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_external_body_limiter_lock = threading.Lock()


def _external_body_limiter() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    with _external_body_limiter_lock:
        limiter = _external_body_limiters.get(loop)
        if limiter is None:
            limiter = asyncio.Semaphore(_EXTERNAL_BODY_SLOTS)
            _external_body_limiters[loop] = limiter
        return limiter
_EVIDENCE_GATEWAY_PREFIX = "/api/v1/security/assurance/gateway/"
# Owner passphrase and authenticator-code steps: their bodies hold both secrets, so a 422 names
# the field and never echoes the value.
_OWNER_SECRET_PREFIXES = (
    "/auth/company-signin-recovery/",
    "/auth/company-saml-recovery/",
    "/api/v1/settings/sign-in-migration/review",
    "/api/v1/settings/single-sign-on/activation-review",
)
_SECURITY_HUNTER_BODY_PATHS = {
    "/api/v1/security/threats/scan",
    "/api/v1/security/soc/ingest",
}
_FINANCE_LARGE_BODY_LIMITS = {
    "/api/v1/finance-operations/regulatory/feeds/ingest": (_MAX_FINANCE_REGULATORY_BODY_BYTES),
    "/api/v1/finance-operations/aml/lists/ingest": _MAX_FINANCE_AML_LIST_BODY_BYTES,
    "/api/v1/finance-operations/anomalies/scan": _MAX_FINANCE_ANOMALY_BODY_BYTES,
}


async def _read_limited_request_body(
    request: Request,
    *,
    max_bytes: int,
    too_large_detail: str,
) -> bytes:
    """Read a request body with a hard size cap.

    ``Content-Length`` lets us reject obviously oversized requests before
    reading any body bytes.  For chunked or otherwise lengthless requests,
    stream incrementally and abort as soon as the cap is exceeded instead of
    using ``request.body()``, which buffers the entire body before returning.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > max_bytes:
            raise HTTPException(status_code=413, detail=too_large_detail)

    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > max_bytes - len(body):
            raise HTTPException(status_code=413, detail=too_large_detail)
        body.extend(chunk)
    return bytes(body)


def _external_body_max(path: str) -> int:
    from .external_gateway import (
        _MAX_DISCOVERY_SENSOR_HTTP_BODY_BYTES,
        _MAX_RED_TEAM_HTTP_BODY_BYTES,
        _MAX_RUNTIME_HTTP_BODY_BYTES,
        _MAX_VENDOR_PORTAL_HTTP_BODY_BYTES,
    )

    route = path.rstrip("/")
    if route == "/api/v1/external/runtime/evaluate":
        return _MAX_RUNTIME_HTTP_BODY_BYTES
    if route.startswith("/api/v1/external/discovery-sensors/"):
        return _MAX_DISCOVERY_SENSOR_HTTP_BODY_BYTES
    if route.startswith("/api/v1/external/ai-vendor/"):
        return _MAX_VENDOR_PORTAL_HTTP_BODY_BYTES
    if re.fullmatch(r"/api/v1/external/red-team/[^/]+/results", route):
        return _MAX_RED_TEAM_HTTP_BODY_BYTES
    return 256 * 1024


@app.middleware("http")
async def bound_public_governance_body(request: Request, call_next):
    """Cap self-authenticating public JSON before FastAPI model parsing."""

    path = route_path(request)
    if request.method not in {"POST", "PUT", "PATCH"} and not path.startswith("/api/v1/external/"):
        return await call_next(request)
    if path.startswith("/api/v1/public/consent/native/"):
        maximum = _MAX_NATIVE_CONSENT_BODY_BYTES
        detail = "native consent request body too large"
    elif path.startswith("/api/v1/public/consent/"):
        # The installation's public request cap (Settings > All settings),
        # else 64 KiB; the router applies the same cap again.
        from .consent_public_api import configured_request_byte_limit

        maximum = configured_request_byte_limit() or _MAX_PUBLIC_CONSENT_BODY_BYTES
        detail = "public consent request body too large"
    elif path.startswith("/api/v1/public/rights/"):
        from .public_rights_api import MAX_BODY_BYTES as _rights_max

        maximum = _rights_max
        detail = "rights request body too large"
    elif path.startswith("/api/v1/external/third-party-collaboration/"):
        if request.method == "POST" and path.endswith("/evidence"):
            # Evidence files are not buffered here: the route authenticates the
            # invitation first, then streams at most that invitation's own
            # byte bound (and requires an exact Content-Length).
            return await call_next(request)
        maximum = _MAX_THIRD_PARTY_COLLABORATION_BODY_BYTES
        detail = "third-party collaboration request body too large"
    elif path.startswith("/api/v1/external/"):
        maximum = _external_body_max(path)
        detail = "external request body too large"
    else:
        return await call_next(request)
    limiter = _external_body_limiter() if path.startswith("/api/v1/external/") else None
    acquired = False
    try:
        if limiter is not None:
            try:
                await asyncio.wait_for(limiter.acquire(), timeout=1.0)
            except TimeoutError:
                return JSONResponse({"detail": "external request capacity is busy"}, status_code=503)
            acquired = True
        reader = _read_limited_request_body(request, max_bytes=maximum, too_large_detail=detail)
        try:
            body = await asyncio.wait_for(reader, timeout=_EXTERNAL_BODY_TIMEOUT_SECONDS) if limiter else await reader
        except TimeoutError:
            if acquired:
                limiter.release()
            return JSONResponse({"detail": "external request body timed out"}, status_code=408)
    except HTTPException as exc:
        if acquired:
            limiter.release()
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    except BaseException:
        if acquired:
            limiter.release()
        raise

    delivered = False

    async def replay_receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._body = body  # noqa: SLF001 - bounded ASGI body replay
    request._receive = replay_receive  # noqa: SLF001 - bounded ASGI body replay
    try:
        return await call_next(request)
    finally:
        if acquired:
            limiter.release()


@app.middleware("http")
async def protect_public_consent_error_responses(request: Request, call_next):
    """Keep public errors private and expose them only to an enrolled origin."""

    response = await call_next(request)
    if response.status_code < 400 or not route_path(request).startswith("/api/v1/public/consent/"):
        return response
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    origin = getattr(request.state, "public_consent_allowed_origin", None)
    if not isinstance(origin, str):
        resolver = getattr(
            request.app.state,
            "public_consent_error_origin_resolver",
            None,
        )
        if callable(resolver):
            try:
                origin = await run_in_threadpool(resolver, request)
            except Exception:
                origin = None
    if isinstance(origin, str):
        response.headers["Access-Control-Allow-Origin"] = origin
        vary = {
            item.strip() for item in response.headers.get("Vary", "").split(",") if item.strip()
        }
        vary.add("Origin")
        response.headers["Vary"] = ", ".join(sorted(vary))
    return response


@app.middleware("http")
async def bound_security_hunter_body(request: Request, call_next):
    """Cap hunter JSON before FastAPI/Pydantic parses nested telemetry."""
    if request.method != "POST" or route_path(request) not in _SECURITY_HUNTER_BODY_PATHS:
        return await call_next(request)
    try:
        body = await _read_limited_request_body(
            request,
            max_bytes=_MAX_SECURITY_HUNTER_HTTP_BODY_BYTES,
            too_large_detail="security hunter request body too large",
        )
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    delivered = False

    async def replay_receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    # BaseHTTPMiddleware wraps this Request and consults its cached-body marker;
    # setting only ``_receive`` after consuming the stream makes that wrapper
    # emit an empty body. Populate both seams so downstream validation receives
    # the exact bounded bytes once.
    request._body = body  # noqa: SLF001 - bounded ASGI body replay
    request._receive = replay_receive  # noqa: SLF001 - bounded ASGI body replay
    return await call_next(request)


@app.middleware("http")
async def bound_finance_operations_body(request: Request, call_next):
    """Cap finance JSON before Starlette/Pydantic buffers nested records."""
    path = route_path(request)
    if request.method != "POST" or not path.startswith("/api/v1/finance-operations/"):
        return await call_next(request)
    maximum = _FINANCE_LARGE_BODY_LIMITS.get(path, _MAX_FINANCE_DEFAULT_BODY_BYTES)
    try:
        body = await _read_limited_request_body(
            request,
            max_bytes=maximum,
            too_large_detail="finance operations request body too large",
        )
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    delivered = False

    async def replay_receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._body = body  # noqa: SLF001 - bounded ASGI body replay
    request._receive = replay_receive  # noqa: SLF001 - bounded ASGI body replay
    return await call_next(request)


@app.middleware("http")
async def bound_evidence_gateway_body(request: Request, call_next):
    """Bound gateway JSON before Starlette/Pydantic buffers evidence inputs."""

    path = route_path(request)
    if request.method not in {"POST", "PUT"} or not path.startswith(_EVIDENCE_GATEWAY_PREFIX):
        return await call_next(request)
    maximum = (
        _MAX_EVIDENCE_GATEWAY_DELIVERY_BODY_BYTES
        if path == f"{_EVIDENCE_GATEWAY_PREFIX}deliver"
        else _MAX_EVIDENCE_GATEWAY_BODY_BYTES
    )
    try:
        body = await _read_limited_request_body(
            request,
            max_bytes=maximum,
            too_large_detail="AI evidence gateway request body too large",
        )
    except HTTPException as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    delivered = False

    async def replay_receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    request._body = body  # noqa: SLF001 - bounded ASGI body replay
    request._receive = replay_receive  # noqa: SLF001 - bounded ASGI body replay
    return await call_next(request)


async def _read_limited_webhook_body(request: Request) -> bytes:
    """Read a webhook request body with a hard size cap."""
    return await _read_limited_request_body(
        request,
        max_bytes=_MAX_WEBHOOK_BODY_BYTES,
        too_large_detail="webhook body too large",
    )


async def _read_limited_skill_validator_body(request: Request) -> bytes:
    """Read a skill-validator request body with a hard size cap."""
    return await _read_limited_request_body(
        request,
        max_bytes=_MAX_SKILL_VALIDATE_BODY_BYTES,
        too_large_detail="skill too large (max 256 KiB)",
    )


async def _verify_maverick_webhook(request: Request) -> dict:
    """Verify a Lightwork-format inbound webhook (HMAC over body+timestamp) and
    return the parsed JSON object. Shared by /webhook/start and /webhook/run,
    which had byte-identical preambles. Raises HTTPException (401 unconfigured,
    403 bad signature, 400 bad body) and enforces a configured LLM provider."""
    from maverick.webhooks import (
        inbound_secret,
        read_signature_headers,
        separate_webhook_credential,
        verify_signature,
    )

    secret = inbound_secret()
    if not separate_webhook_credential(secret, "control"):
        secret = None
    if not secret:
        raise HTTPException(
            status_code=401,
            detail=(
                "Inbound webhooks aren't set up yet — an administrator must "
                "configure a distinct MAVERICK_INBOUND_WEBHOOK_SECRET."
            ),
        )
    try:
        signature, timestamp = read_signature_headers(request.headers)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Conflicting webhook authentication headers.") from exc
    if not signature or not timestamp:
        raise HTTPException(status_code=403, detail="bad webhook signature")
    body = await _read_limited_webhook_body(request)
    if not verify_signature(body, signature, secret, timestamp=timestamp):
        raise HTTPException(status_code=403, detail="bad webhook signature")

    # NOTE: replay beyond a single byte-identical capture is bounded by the
    # freshness window (verify_signature enforces max_age on the signed
    # timestamp). We deliberately do NOT add signature-level dedup here: an HMAC
    # over (timestamp, body) can't distinguish an attacker's byte replay from a
    # legitimate rapid identical fire (same trigger, same second, no `data`), so
    # dedup would drop valid duplicate fires. Tightening this further needs a
    # client-supplied delivery id to dedup on (as the GitHub/GitLab routes do),
    # which is a webhook-format change, not a drop-in here.
    require_provider_or_400()
    try:
        payload = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    return payload


def _webhook_duplicate_delivery(route: str, payload: dict) -> bool:
    """True if this signed webhook carries a delivery ``id`` we've already
    processed within the freshness window (an at-most-once guard the caller
    opts into by stamping ``{"id": "..."}``). Returns False when no id is
    given, so id-less callers keep the current at-least-once behaviour. The id
    is namespaced per ``route`` so a /webhook/start id can't mask a /webhook/run
    one. Never raises -- a degraded dedup store must not drop a webhook."""
    delivery_id = str(payload.get("id") or "").strip()[:200]
    if not delivery_id:
        return False
    from maverick.webhooks import _default_max_age

    return _issue_webhook_replay_seen(f"webhook-{route}:{delivery_id}", _default_max_age())


# Safe methods skip the CSRF check (browsers send Origin/Referer
# inconsistently on GETs from address bars and bookmarks).
_CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _is_same_origin(request: Request) -> bool:
    """Allow only same-origin browser submissions for mutating form POSTs.

    Fails closed when no Origin or Referer is present on a mutating
    request. The previous fail-open branch ("Non-browser/API clients
    commonly omit both headers") was a soft-CSRF: any tab on the same
    machine could fire a no-cors fetch with both headers stripped and
    have it accepted. Real API clients send Authorization headers and
    are exempted by the bearer-auth middleware before they reach here.
    """
    if request.method in _CSRF_SAFE_METHODS:
        return True
    expected = request.url.netloc
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.netloc == expected:
            return True
        return False
    return False


def _require_same_origin(request: Request) -> None:
    """Reject a cross-site mutating form POST (403). Shared CSRF guard inlined by
    ~20 form handlers."""
    if not _is_same_origin(request):
        raise HTTPException(
            status_code=403,
            detail="cross-site form post blocked — for your security, changes "
            "must be made from the Lightwork page itself. Reload the "
            "dashboard and try again.",
        )


def _is_loopback_client(host: str) -> bool:
    """True for in-process/loopback callers (safe to serve without a token)."""
    if not host:
        return False
    # Starlette's in-process TestClient reports host="testclient"; a real
    # network peer can never present that (request.client.host is the
    # socket peer, set by the server, not user-controllable).
    if host in ("localhost", "testclient"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_loopback_request_host(request: Request) -> bool:
    """True when the user-controlled Host header names a loopback host.

    No-token mode is intentionally limited to local dashboards.  Checking only
    the socket peer is not enough for browser requests: a DNS-rebinding page can
    connect to 127.0.0.1 while preserving an attacker-controlled Host/Origin
    pair, which would otherwise satisfy Host-derived same-origin checks.
    """
    host = (request.url.hostname or "").rstrip(".").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Standard headers a reverse proxy adds when forwarding a request.
_PROXY_FORWARD_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded")


def _is_proxied(request: Request) -> bool:
    """True if a reverse proxy forwarded this request.

    In no-token mode the dashboard trusts the loopback peer
    (``request.client.host``). A reverse proxy on the same host connects over
    loopback, so a deploy that fronts the app with a public proxy but forgets
    to set ``MAVERICK_DASHBOARD_TOKEN`` on the app process would serve the
    control surface unauthenticated to the internet — the loopback peer is the
    proxy, not the real remote client. Treat any standard forwarding header as
    proof a proxy is in front and fall through to the token requirement (fail
    closed). Reading these headers only ever makes auth STRICTER, so a forged
    header cannot grant access — at worst a direct caller locks itself out by
    sending one.
    """
    return any(request.headers.get(h) for h in _PROXY_FORWARD_HEADERS)


def _configured_oidc_bearer_present(request: Request) -> bool:
    """Whether this request explicitly presents a bearer to enabled OIDC.

    Such API credentials do not use ambient browser authority, so they do not
    need an Origin/Referer. The global auth dependency remains authoritative:
    it verifies the token (and rejects an invalid one) before any cookie/proxy
    identity can be selected.
    """
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        return False
    try:
        from . import auth as auth_boundary

        return auth_boundary.oidc_enabled()
    except Exception:
        return False


def _api_key_bearer_present(request: Request) -> bool:
    """Whether this request presents a personal / service-account API key.

    Like an OIDC bearer it is explicit, non-ambient authority: no Origin check
    applies, and the global auth dependency verifies it (and 401s a bad,
    expired, revoked or out-of-scope one) before any cookie identity could be
    selected. Cheap shape check only -- no store read here.
    """
    try:
        from . import auth as auth_boundary

        return bool(auth_boundary._api_key_bearer(request))
    except Exception:
        return False


@app.middleware("http")
async def http_metrics(request: Request, call_next):
    """Count every request into the always-on runtime metrics registry.

    Route TEMPLATES, never raw paths, keep label cardinality bounded;
    a request that matches no route counts under "unmatched"."""
    import time as _time

    from maverick import runtime_metrics

    started = _time.monotonic()
    response = await call_next(request)
    route = request.scope.get("route")
    template = getattr(route, "path", None) or "unmatched"
    runtime_metrics.increment(
        "lightwork_http_requests_total", method=request.method,
        route=template, status=str(response.status_code),
        help_text="Dashboard HTTP requests by route template",
    )
    runtime_metrics.increment(
        "lightwork_http_request_seconds_total", route=template,
        amount=_time.monotonic() - started,
        help_text="Total request wall time by route template",
    )
    return response


@app.middleware("http")
async def bearer_auth(request: Request, call_next):
    expected = _dashboard_token() or None
    path = route_path(request)
    if (
        path in _AUTH_EXEMPT
        or path.startswith("/share/")
        or path.startswith("/scim/")
        or path.startswith("/form/")
        # DSAR response links are addressed by their unguessable token,
        # exactly like /form/ — the requester has no dashboard bearer.
        or path.startswith("/dsar/response/")
        # One-action mute links in notification messages: the signed link is
        # the credential and only quiets that one person's own notifications.
        or path.startswith("/unsubscribe/")
        or path.startswith("/saml/")
        or path.startswith("/auth/invite/")
        # External integrations authenticate inside their route family
        # using agent, signed-sensor, or vendor-invitation credentials. The
        # trailing slash keeps /api/v1/external-agents under dashboard auth.
        or path.startswith("/api/v1/external/")
        # Public consent uses its own client and profile capabilities. Keep
        # the exact administration prefix under dashboard authentication.
        or path.startswith("/api/v1/public/consent/")
        # Public policy links resolve an opaque stable link and optionally
        # a private bearer. The admin policy-publication prefix remains
        # under normal dashboard authentication.
        or path.startswith("/api/v1/public/policies/")
        # Pairing bootstrap authenticates its own opaque, expiring device proof.
        # Browser approval and device administration remain under normal auth.
        or path.startswith("/api/v1/devices/pairing/")
        # The public rights-request form (pages + JSON). Anonymous by
        # design; gated, origin-checked and token-addressed in its router.
        or path.startswith("/rights/")
        or path.startswith("/api/v1/public/rights/")
        # Public website chat (its own publishable key, origin and visitor
        # session). The admin prefix /api/v1/public-chat stays authenticated.
        or path.startswith("/public/chat/v1/")
    ):
        # /share/<token> self-authenticates with its signed, revocable token
        # (verified in the route, which 404s an invalid/expired/revoked one) --
        # an external recipient has no dashboard bearer, like the webhook paths.
        # /auth/invite/<token> is the same shape: the invitee has no credential
        # yet; the single-use token IS the auth, verified (and same-origin-
        # gated on the consuming POST) in the route, which 404s when invites
        # are disabled.
        return await call_next(request)
    if not expected:
        # Any configured identity mechanism disables legacy loopback-as-admin,
        # even when the separate startup assertion ``dashboard.require_auth``
        # is unset. The global dependency verifies proxy, OIDC, SAML, or invite
        # identity and fails closed on unreadable auth configuration.
        # Resolve through the module so identity-policy changes made by a
        # deployment/test harness cannot leave this long-lived middleware with
        # a stale function binding.
        from . import auth as auth_boundary

        if not auth_boundary.auth_genuinely_off():
            explicit_oidc_bearer = (_configured_oidc_bearer_present(request)
                                    or _api_key_bearer_present(request))
            if (
                not explicit_oidc_bearer
                and not _is_same_origin(request)
                and _allowed_extension_origin(request) is None
            ):
                return JSONResponse(
                    {
                        "detail": "cross-site request blocked - for your security, "
                        "changes must be made from the Lightwork page "
                        "itself. Reload the dashboard and try again."
                    },
                    status_code=403,
                )
            return await call_next(request)
        # Client-bound / enterprise: loopback-trust (no-token) mode is DISABLED.
        # In a hosted/regulated deployment any process sharing the loopback
        # namespace (a sidecar, a co-located container, an SSRF pivot to
        # 127.0.0.1) must never become an unauthenticated admin — require a
        # token (or OIDC) explicitly.
        try:
            from maverick.client import client_binding_enforced

            if client_binding_enforced():
                _auth_metrics.record_auth_failure("client_binding")
                return JSONResponse(
                    {
                        "detail": "Sign-in is required on this deployment — an "
                        "administrator must configure dashboard "
                        "authentication for enterprise / client-binding "
                        "mode (set MAVERICK_DASHBOARD_TOKEN, or enable "
                        "OIDC)."
                    },
                    status_code=401,
                )
        except Exception:  # pragma: no cover - never break auth on a read error
            pass
        # A personal / service-account API key is an explicit credential the
        # local operator minted on this computer: let the global dependency
        # verify it (it fails closed), so a script can reach Lightwork from
        # another computer without a shared static token.
        if _api_key_bearer_present(request):
            return await call_next(request)
        # No token configured: serve loopback only. An operator who binds
        # --host 0.0.0.0 without setting a token must NOT silently expose
        # run history, spend, and the control surface unauthenticated to
        # the network. Set MAVERICK_DASHBOARD_TOKEN to allow remote access.
        client_host = request.client.host if request.client else ""
        if (
            _is_loopback_client(client_host)
            and _is_loopback_request_host(request)
            and not _is_proxied(request)
        ):
            # Loopback is served without a bearer, so a malicious page open in
            # the user's browser could otherwise drive mutating endpoints via an
            # ambient cross-site request (CSRF): cancel/resume goals, disable
            # safety tools, arm the killswitch, purge caches. Gate unsafe methods
            # behind the same-origin check centrally (the one /chat/send already
            # enforces per-route) so every current and future /api/v1 mutation is
            # covered. Token mode needs no such check — a cross-site page cannot
            # attach the Authorization header.
            # The bundled WebExtension is the one sanctioned cross-origin
            # caller: its Origin is chrome-extension://… and it is accepted
            # only behind the operator's explicit opt-in (see extension_cors).
            if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
                script_without_origin = (
                    path.startswith("/api/")
                    and not request.headers.get("origin")
                    and not request.headers.get("referer")
                )
                return JSONResponse(
                    {
                        "detail": (
                            "Local API writes need an Origin header matching this Lightwork "
                            "address, or an API key created in Account > API keys and sent as "
                            "Authorization: Bearer <key>. See the REST API guide."
                            if script_without_origin else
                            "cross-site request blocked — for your security, changes must "
                            "be made from the Lightwork page itself. Reload the dashboard "
                            "and try again."
                        )
                    },
                    status_code=403,
                )
            return await call_next(request)
        # A VERIFIED invite-minted session is a real credential: accept it for
        # remote access in no-token mode (same-origin-gated like every other
        # cookie mode), so an invites-only deployment works over the network
        # without extra config. Anonymous remote requests still 401 below.
        try:
            from .invites import invites_enabled, local_session_principal

            if invites_enabled() and local_session_principal(request) is not None:
                if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
                    return JSONResponse(
                        {
                            "detail": "cross-site request blocked — for your "
                            "security, changes must be made from the "
                            "Lightwork page itself. Reload the "
                            "dashboard and try again."
                        },
                        status_code=403,
                    )
                return await call_next(request)
        except Exception:  # pragma: no cover - invites must never open access
            pass
        _auth_metrics.record_auth_failure("remote_no_token")
        return JSONResponse(
            {
                "detail": "Remote access to this dashboard requires an access "
                "token — an administrator must configure one for "
                "non-loopback or proxied access (set "
                "MAVERICK_DASHBOARD_TOKEN)."
            },
            status_code=401,
        )
    auth = request.headers.get("authorization", "")
    header_token = auth[7:] if auth.startswith("Bearer ") else ""
    # ``?token=`` query auth was removed: it leaks the bearer through
    # browser history, Referer headers on outbound link clicks, uvicorn
    # access logs, and any logging proxy in front. Require the
    # ``Authorization: Bearer`` header.
    if header_token and hmac.compare_digest(header_token.encode(), expected.encode()):
        return await call_next(request)
    if auth:
        # A non-static bearer may be an OIDC token in a mixed deployment. Let
        # the global dependency verify it; malformed/invalid credentials never
        # fall back to proxy or cookie identity there.
        if (header_token.startswith("lwdev1_") or _configured_oidc_bearer_present(request)
                or _api_key_bearer_present(request)):
            return await call_next(request)
        _auth_metrics.record_auth_failure("bad_token")
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    if non_static_auth_configured():
        # The static operator token composes with proxy/OIDC/SAML/invite browser
        # identities. Ambient authority remains CSRF-gated; the dependency then
        # verifies the actual identity and rejects a missing/invalid session.
        if not _is_same_origin(request) and _allowed_extension_origin(request) is None:
            return JSONResponse(
                {
                    "detail": "cross-site request blocked - for your security, "
                    "changes must be made from the Lightwork page "
                    "itself. Reload the dashboard and try again."
                },
                status_code=403,
            )
        return await call_next(request)
    # The bad/missing-bearer case — the credential-stuffing signal an alert
    # rule watches (a flood here means someone is probing the token).
    _auth_metrics.record_auth_failure("bad_token")
    return JSONResponse({"detail": "unauthorized"}, status_code=401)


_IP_ALLOWLIST_EXEMPT = frozenset({"/healthz", "/livez", "/readyz"})


@app.middleware("http")
async def ip_allowlist_gate(request: Request, call_next):
    """Refuse every request from an address outside ``[auth.ip_allowlist]``.

    Registered after ``bearer_auth`` so it wraps it and runs first: an address
    that is not allowed never reaches sign-in. Only the liveness/readiness
    probes pass (a load balancer's address is not a person's). The workspace
    list is checked later, in the authentication dependency, once the
    caller's workspace is known. Empty list: nothing changes."""
    if route_path(request) in _IP_ALLOWLIST_EXEMPT:
        return await call_next(request)
    from . import ip_allowlist

    if await run_in_threadpool(ip_allowlist.installation_allows, request):
        return await call_next(request)
    _auth_metrics.record_auth_failure("ip_allowlist")
    if _wants_html(request):
        return templates.TemplateResponse(
            request, "error.html",
            {"status": 403, "title": "This address isn't allowed",
             "message": ip_allowlist.BLOCKED_MESSAGE, "path": request.url.path,
             "gate": "ip"},
            status_code=403,
        )
    return JSONResponse({"detail": ip_allowlist.BLOCKED_MESSAGE}, status_code=403)


def _wants_html(request: Request) -> bool:
    """True when the client prefers HTML (browser nav) over JSON (API)."""
    accept = (request.headers.get("accept") or "").lower()
    if route_path(request).startswith(
        ("/api/", "/openapi", "/healthz", "/livez", "/readyz", "/metrics")
    ):
        return False
    # Browser navigations explicitly advertise text/html. Generic HTTP clients
    # commonly send only */* and must retain the machine-readable JSON error
    # contract even when they call a non-/api form compatibility route.
    return "text/html" in accept


def _not_found_page(request: Request):
    """The browser 404: a plain public page for dead share links, else the app's."""
    if route_path(request).startswith("/share/"):
        # A shared-result recipient has no account: an unknown, expired or
        # revoked link gets a plain public page (no detail), never the app shell.
        return templates.TemplateResponse(
            request, "share_unavailable.html", {}, status_code=404,
            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"},
        )
    return templates.TemplateResponse(
        request,
        "404.html",
        {"path": request.url.path},
        status_code=404,
    )


def _task_limit_error(status, detail, headers, title, message):
    if status == 400 and (headers or {}).get("X-Lightwork-Task-Settings") == "agent.max_steps":
        return "Review the task limit", detail, "task_steps"
    if status == 409 and isinstance(detail, dict) and detail.get("retryable") is True:
        # Still changing (a task that has just started): the page reloads
        # itself in a moment instead of asking the person to try again.
        return ("Still getting this ready",
                "This page is still being set up. It refreshes by itself in a moment.", "retry")
    return title, message, ""


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Branded, actionable HTML for browser failures; JSON for API callers."""
    from . import feature_gate

    headers = exc.headers
    if exc.status_code == 403 and feature_gate.REASON_HEADER not in (headers or {}):
        # A feature that is turned off is not a missing permission: say which.
        headers = {**(headers or {}), **feature_gate.refusal_headers(exc.detail)} or headers
    feature_off = (headers or {}).get(feature_gate.REASON_HEADER) == feature_gate.FEATURE_OFF
    if exc.status_code == 404 and _wants_html(request):
        return _not_found_page(request)
    if (
        exc.status_code == 409
        and _wants_html(request)
        and str(exc.detail or "").startswith("select an active tenant")
    ):
        # Every tenant-scoped workbench raises this same gate. A browser user
        # gets the picker, not a JSON dead end that sends them to a config
        # file; API callers keep the machine-readable 409 below.
        from .tenant_select_page import tenant_select_response

        return tenant_select_response(request, templates, detail=str(exc.detail))
    if (
        exc.status_code == 401
        and _wants_html(request)
        and request.method == "GET"
    ):
        # A browser navigating to a protected page with no valid session should
        # land on the sign-in flow, not a static "sign in required" page. Only
        # when a browser login provider is actually configured (OIDC); otherwise
        # fall through to the branded page below (there is nowhere to send them).
        try:
            from maverick.oidc import login_enabled as _login_enabled

            login_on = _login_enabled()
        except Exception:  # pragma: no cover - never turn an auth error into a 500
            login_on = False
        if login_on:
            from urllib.parse import quote

            return_to = request.url.path
            if request.url.query:
                return_to = f"{return_to}?{request.url.query}"
            return RedirectResponse(
                f"/auth/login?return_to={quote(return_to, safe='')}",
                status_code=302,
            )
        from .local_owner import claimed as local_owner_claimed
        from .local_passphrases import available as passphrase_sign_in

        # The owner and invited colleagues both sign in on that page.
        if ((local_owner_claimed() or passphrase_sign_in())
                and request.url.path not in {"/auth/local-owner", "/auth/local-login", "/auth/owner-second-factor"}):
            # Back to this page after signing in again (the sign-in keeps
            # only a local path; see local_owner_routes).
            from urllib.parse import quote

            return_to = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/auth/local-login?return_to={quote(return_to, safe='')}", status_code=302)
    if _wants_html(request):
        status = int(exc.status_code)
        title, message = {
            400: (
                "Check this request",
                "Lightwork could not use the submitted value. Review the fields and try again.",
            ),
            401: (
                "Sign in required",
                "Your sign-in has expired. Sign in again.",
            ),
            403: (
                "Permission required",
                "Your current role cannot use this page or action. Switch to an authorized workspace or ask an administrator for access.",
            ),
            409: (
                "Refresh before continuing",
                "The workspace or record changed after this page loaded. Reload it to see the current state before retrying.",
            ),
            429: (
                "Too many requests",
                "Lightwork is protecting this service from overload. Wait briefly, then retry.",
            ),
            503: (
                "Temporarily unavailable",
                "A required service or control is unavailable. Your action was not confirmed; retry after service is restored.",
            ),
        }.get(
            status,
            (
                "Request could not be completed",
                "Lightwork stopped before confirming this action. Return to the page and try again.",
            ),
        )
        if status == 400 and str(exc.detail or "").startswith("Invalid audit day"):
            message = "That date isn’t valid. Pick a day from the calendar, then try again."
        if status == 403 and exc.detail == BOARD_SCOPE_DETAIL:
            message = BOARD_SCOPE_DETAIL
        title, message, gate = _task_limit_error(status, exc.detail, headers, title, message)
        reauthenticate = ""
        feature = {}
        if status == 403 and feature_off:
            from urllib.parse import unquote

            gate = "off"
            label = unquote(headers.get(feature_gate.LABEL_HEADER, ""))
            title = f"{label} is turned off" if label else "This page is turned off"
            message = (
                "This feature is turned off for your workspace, or its settings "
                "could not be read. An administrator can turn it on in Settings."
            )
            if label and headers.get(feature_gate.SWITCH_HEADER) == "module":
                feature = {"section": headers[feature_gate.FEATURE_HEADER], "label": label}
        elif status == 403 and isinstance(exc.detail, str):
            # Feature switches and named sign-in gates raise 403 with these
            # fixed server phrases; show the real reason instead of the
            # generic role message. The check itself is unchanged.
            from .ip_allowlist import BLOCKED_MESSAGE as _ip_blocked
            from .mfa_policy import MFA_MISSING_MESSAGE as _mfa_missing
            from .step_up import StepUpRequired as _StepUpRequired

            if isinstance(exc, _StepUpRequired):
                gate = "step_up"
                title = "Sign in again to continue"
                message = exc.detail
                reauthenticate = exc.reauthenticate
            elif exc.detail == _mfa_missing:
                gate = "step_up"
                title = "Sign in again with your authenticator"
                message = exc.detail
                from .step_up import reauthenticate_url

                reauthenticate = reauthenticate_url(request)
            elif exc.detail == _ip_blocked:
                gate = "ip"
                title = "This address isn't allowed"
                message = exc.detail
            elif exc.detail.startswith("Sign in with a named account"):
                gate = "sign_in"
                title = "Sign in with your own account"
                message = (
                    "This page works only when you sign in with your own account "
                    "and choose a workspace. Sign in, then choose a workspace."
                )
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "status": status,
                "title": title,
                "message": message,
                "path": request.url.path,
                "gate": gate,
                "reauthenticate": reauthenticate,
                "feature": feature,
            },
            status_code=status,
            headers=headers,
        )
    body: dict = {"detail": exc.detail}
    reauthenticate = getattr(exc, "reauthenticate", "")
    if reauthenticate:
        # Step-up: the API caller (a page script or a program) gets the plain
        # sentence and the link that signs the person in again.
        body["reauthenticate"] = reauthenticate
    return JSONResponse(
        body,
        status_code=exc.status_code,
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """422 for browser nav becomes 400 with the branded error page."""
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "500.html",
            {"path": request.url.path},
            status_code=400,
        )
    if route_path(request) == "/api/v1/connection-setup" or route_path(request).startswith(
        "/api/v1/connection-setup/"
    ):
        # Pydantic may place submitted secrets in input, msg, ctx, or even loc
        # (for unsupported object keys). Rebuild from fixed field labels before
        # encoding: malformed binary input must remain a safe 422, not a 500.
        messages = {
            "confirm": "Review and confirm the account connection action.",
            "context": "Refresh Connections before continuing.",
            "provider": "Select a supported account provider.",
            "client_id": "Enter a valid application client ID.",
            "client_secret": "Enter a valid application client secret.",  # pragma: allowlist secret
            "expected_revision": "Refresh Connections before changing this connection.",
            "profile": "Select a supported connection profile.",
            "name": "Use a connection name with lowercase letters, numbers, hyphens or underscores.",
            "site_url": "Enter a valid workspace site address.",
            "state": "Start a new authorization from Connections.",
            "code": "Start a new authorization from Connections.",
            "return_profile": "Choose the supported account return mode.",
            "desktop_return": "Review the provider's registered desktop return address.",
        }
        errors = []
        for error in exc.errors()[:32]:
            loc = error.get("loc", ())
            field = loc[1] if isinstance(loc, (list, tuple)) and len(loc) == 2 and loc[0] == "body" else None
            field = field if isinstance(field, str) and field in messages else None
            errors.append({
                "type": "value_error",
                "loc": ["body", field] if field else ["body"],
                "msg": messages[field] if field else "Check the connection fields and remove unsupported fields.",
            })
        return JSONResponse({"detail": errors}, status_code=422, headers={"Cache-Control": "no-store"})
    # exc.errors() can embed the raw request body (bytes) in 'input' when the
    # client sent a wrong/garbage Content-Type; json.dumps can't serialize bytes,
    # so a 422 turned into an opaque 500. jsonable_encoder coerces bytes -> str.
    from fastapi.encoders import jsonable_encoder

    errors = jsonable_encoder(exc.errors())
    if route_path(request).startswith(_EVIDENCE_GATEWAY_PREFIX) or route_path(request).startswith(
        _OWNER_SECRET_PREFIXES
    ):
        for error in errors:
            if isinstance(error, dict) and "input" in error:
                error["input"] = "[redacted]"
    try:
        return JSONResponse({"detail": errors}, status_code=422)
    except UnicodeEncodeError:
        # The error echoes the rejected input, and a lone surrogate in a JSON
        # string cannot be written as UTF-8: escape it instead of answering 500.
        return Response(json.dumps({"detail": errors}), status_code=422, media_type="application/json")


@app.exception_handler(TaskLimitConfigError)
async def task_limit_config_handler(request: Request, exc: TaskLimitConfigError):
    """Malformed task-limit configuration is an operator fix, not a server
    crash: refuse new work with the reason instead of an opaque 500."""
    return JSONResponse(
        {"detail": f"task limit configuration is invalid ({exc}); fix [budget] "
                   "in config.toml or MAVERICK_BUDGET_DOLLARS"},
        status_code=503)


@app.exception_handler(OverflowError)
async def overflow_exception_handler(request: Request, exc: OverflowError):
    """An out-of-range integer path param (e.g. goal_id > 2**63-1) can't be a real
    row -- SQLite raises OverflowError binding it. Treat it as not-found rather
    than letting it fall through to a 500."""
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "404.html",
            {"path": request.url.path},
            status_code=404,
        )
    return JSONResponse({"detail": "not found"}, status_code=404)


from .rbac import RbacStoreError as _RbacStoreError  # noqa: E402


@app.exception_handler(_RbacStoreError)
async def rbac_store_exception_handler(request: Request, exc: _RbacStoreError):
    """Unreadable or missing role policy is a plain refusal, never a grant or 500."""
    from .rbac import ROSTER_RECOVERY, RosterMissingError, RosterRollbackError

    log.error("dashboard role policy is unavailable on %s: %s", request.url.path, exc)
    if isinstance(exc, RosterRollbackError):
        # The change was refused but could not be taken back: do not claim
        # that nothing changed.
        detail = ("The role change was refused by the activity log, but the role list could not be put back "
                  "and may now include it. Ask an administrator to check the role list.")
    else:
        detail = ("Access roles cannot be read, so nothing was changed and no access was granted. "
                  + (f"The role list is missing. {ROSTER_RECOVERY}"
                     if isinstance(exc, RosterMissingError)
                     else "Ask an administrator to restore or repair the role list."))
    if _wants_html(request):
        return templates.TemplateResponse(request, "error.html", {
            "status": 503, "title": "Access roles unavailable", "message": detail,
            "path": request.url.path, "gate": "", "reauthenticate": "", "feature": {},
        }, status_code=503)
    return JSONResponse({"detail": detail, "code": "access_roles_unavailable"}, status_code=503)


@app.exception_handler(RuntimeOverridesSecurityError)
async def runtime_policy_exception_handler(
    request: Request,
    exc: RuntimeOverridesSecurityError,
):
    """Make a fail-closed operator-policy stop actionable without leaking paths."""
    log.error(
        "operator runtime policy is unavailable on %s: %s",
        request.url.path,
        exc,
    )
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "500.html",
            {"path": request.url.path, "policy_error": True},
            status_code=503,
        )
    return JSONResponse(
        {
            "detail": (
                "operator policy is unavailable; restore or repair "
                "runtime-overrides.toml before retrying"
            ),
            "code": "operator_policy_unavailable",
        },
        status_code=503,
    )


@app.exception_handler(FlowPayloadError)
async def flow_payload_exception_handler(request: Request, exc: FlowPayloadError):
    """Expose a recovery action without leaking private payload or key details."""
    message = (
        "We couldn't open this workflow's saved progress. Ask your administrator "
        "to restore it, or start the workflow again after checking what it already "
        "did in other apps."
    )
    headers = {"Cache-Control": "no-store"}
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"path": request.url.path, "status": 409,
             "title": "Workflow data needs recovery", "message": message},
            status_code=409,
            headers=headers,
        )
    return JSONResponse(
        {"detail": message, "code": "flow_data_unavailable"},
        status_code=409,
        headers=headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all so we never serve the default white "Internal Server Error"."""
    from datetime import datetime, timezone
    from secrets import token_hex

    reference = "lw-failure-" + token_hex(16)
    occurred_at = datetime.now(timezone.utc).isoformat()
    route = getattr(request.scope.get("route"), "path", "unmatched route")
    log.error("dashboard failure reference=%s time=%s action=%s route=%s",
              reference, occurred_at, request.method, route,
              exc_info=(type(exc), exc, exc.__traceback__))
    headers = {"Cache-Control": "private, no-store", "X-Lightwork-Failure-Reference": reference}
    from maverick.service_status import READ_ONLY_REFUSAL, is_read_only_error

    # A write refused by a read-only database says what broke, that
    # saved work is safe and what to do, never the database error itself.
    read_only = is_read_only_error(exc)
    status = 503 if read_only else 500
    if _wants_html(request):
        try:
            return templates.TemplateResponse(
                request, "500.html", {"failure_reference": reference, "failure_time": occurred_at,
                                      "uncertain_mutation": request.method not in {"GET", "HEAD"},
                                      "read_only_error": read_only},
                status_code=status, headers=headers,
            )
        except Exception:
            # Deliberately independent of the normal layout and its data reads.
            return HTMLResponse(
                '<!doctype html><html lang="en"><meta charset="utf-8"><title>Lightwork needs attention</title>'
                '<h1>Something went wrong</h1><p>Check the current state before repeating a change.</p>'
                f'<p>Support reference: {reference}</p><p>Time: {occurred_at}</p>'
                f'<a href="/help?failure={reference}">Open Help</a></html>',
                status_code=500, headers=headers,
            )
    detail = READ_ONLY_REFUSAL if read_only else (
        "The request could not be completed. Check its current state before retrying a change.")
    return JSONResponse({"detail": detail, "failure_reference": reference, "occurred_at": occurred_at},
                        status_code=status, headers=headers)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Apply baseline browser-security headers to every response.

    These are cheap, well-supported, and close a class of attacks
    (clickjacking, MIME sniffing, Referer leakage, cross-origin
    exfiltration) the dashboard had no defense against before.
    """
    # One script nonce per response, for the inline <script> tags the templates
    # render (csp_script_nonce, see _csp_nonce_context).
    script_nonce = secrets.token_urlsafe(16)
    request.state.csp_script_nonce = script_nonce
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    # "same-origin", NOT "no-referrer": under no-referrer the Fetch spec makes
    # browsers send "Origin: null" on same-origin form POST navigations, which
    # the CSRF guard (_is_same_origin) must reject — so every native form save
    # in the dashboard 403'd in a real browser ("cross-site request blocked")
    # while fetch()-based saves (mode "cors" keeps the real Origin) and tests
    # (explicit Origin header) still passed. same-origin keeps the privacy win
    # (no Referer leaks to external sites) and restores Origin/Referer on
    # first-party requests.
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Cross-Origin-Opener-Policy",
        "same-origin",
    )
    # Drop the ambient-capability attack surface. microphone=(self) because
    # the chat pages capture voice in-browser (getUserMedia); camera,
    # geolocation, and payment are never used, so deny them outright.
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), camera=(), payment=(), microphone=(self)",
    )
    # no-store on everything by default so authenticated HTML and sensitive
    # JSON aren't left in the browser's back/forward cache or a shared proxy
    # after logout. setdefault preserves the explicit caching the static-asset
    # and SSE routes already set (public max-age / no-cache).
    response.headers.setdefault("Cache-Control", "no-store")
    # HSTS only when the request actually arrived over TLS (directly or via a
    # terminating proxy) — never on plain-HTTP loopback dev, which HSTS would
    # otherwise pin to https and break.
    if (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
    ):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    # Content-Security-Policy. Inline <script> tags carry this response's
    # nonce, so script-src admits no 'unsafe-inline' and an injected inline
    # script cannot run. The templates' first-party inline <style> and
    # style="" attributes still need 'unsafe-inline' in style-src (out of
    # scope for this change). The value still hardens the dashboard meaningfully:
    #   - default/connect/script/style 'self' → injected JS can't fetch()
    #     to an external exfil endpoint or pull a remote script
    #   - frame-ancestors 'none' → reinforces X-Frame-Options (clickjack)
    #   - form-action 'self' → an injected <form> can't POST off-origin
    #   - object-src 'none', base-uri 'none' → kill plugin + <base> tricks
    # This matters because the dashboard renders agent-produced text;
    # if any of it ever reaches an HTML sink, CSP is the backstop.
    path = route_path(request)
    if path == "/redoc":
        csp = _DOCS_CSP.format(script_nonce=script_nonce)
    else:
        csp = _DEFAULT_CSP.format(script_nonce=script_nonce)
    if path == "/connections" and str(request.base_url).rstrip("/") == "http://127.0.0.1:8765":
        from maverick.connection_oauth import desktop_return_enabled

        if desktop_return_enabled():
            # Only IPC to this desktop's scoped native account-return commands.
            # Rust separately pins the main window and exact Connections URL.
            csp = csp.replace("connect-src 'self';", "connect-src 'self' ipc: http://ipc.localhost;")
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


@app.middleware("http")
async def bind_active_tenant(request: Request, call_next):
    """Scope local-operator requests to the shared dashboard selection.

    The tenant-scoped workbenches (consent, privacy discovery, third-party,
    ...) refuse to run unbound. Before this middleware the only ways to bind
    were the MAVERICK_TENANT env var or an enterprise client binding -- a
    config-file/environment step, which the dashboard promises not to need.
    The operator-wide Settings selection remains valid only in genuine local
    auth-off mode or for the authenticated static dashboard token. End-user
    selections are principal-scoped and are bound later by the authentication
    dependency, after membership can be verified. An explicit env/context
    binding still wins in every mode. A selection naming a tenant that was
    suspended or deleted is ignored rather than trusted, so the registry stays
    authoritative for who may do work.
    """
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant

    def _stored_selection() -> str | None:
        # current_tenant_id covers all three existing bindings -- request
        # context, MAVERICK_TENANT, and the enterprise client binding (the
        # tenant FLOOR for one-client deployments) -- and each outranks the
        # dashboard selection, which must never widen an existing scope.
        if current_tenant_id() is not None:
            return None
        from maverick_dashboard.auth import (
            _dashboard_token_authenticated,
            anonymous_local_access_allowed,
        )

        if not (
            anonymous_local_access_allowed()
            or _dashboard_token_authenticated(request)
        ):
            return None
        from maverick_dashboard import settings_store

        selected = settings_store.active_tenant()
        if not selected:
            return None
        from maverick.tenant.registry import is_active

        return selected if is_active(selected) else None

    selected = await run_in_threadpool(_stored_selection)
    if not selected:
        return await call_next(request)
    request.state.workspace_tenant_source = "local_selection"
    request.state.workspace_expected_tenant = selected
    token = set_tenant(selected)
    try:
        return await call_next(request)
    finally:
        reset_tenant(token)


# ----- browser-extension CORS gate (extensions/browser) -----
# The bundled WebExtension is a cross-origin caller: its popup/service-worker
# fetches arrive with an Origin of chrome-extension://<id> (moz-extension://
# <uuid> on Firefox). Browsers need CORS approval for it to read responses,
# and the no-token CSRF gate in bearer_auth would otherwise 403 its POSTs.
# This allowance is OPT-IN and fail-closed: until the operator sets
# `[dashboard] allow_extension = true` (or MAVERICK_DASHBOARD_ALLOW_EXTENSION=1)
# AND configures MAVERICK_DASHBOARD_TOKEN, no CORS header is ever emitted and
# extension origins stay blocked. Requiring a bearer token keeps extension
# support from turning no-token loopback mode into an ambient trust boundary for
# any installed browser extension. The allowance is scoped to extension origins
# only — a web origin (https://…) never matches, so the same-origin posture for
# ordinary sites is unchanged.
_EXTENSION_ORIGIN_RE = re.compile(r"^(?:chrome|moz)-extension://[a-zA-Z0-9-]+$")


def _extension_cors_enabled() -> bool:
    """Operator opt-in for the bundled WebExtension. Fail-closed default."""
    if os.environ.get("MAVERICK_DASHBOARD_ALLOW_EXTENSION") == "1":
        return True
    try:
        from maverick.config import load_config

        return bool(((load_config() or {}).get("dashboard") or {}).get("allow_extension"))
    except Exception:
        return False


def _allowed_extension_origin(request: Request) -> str | None:
    """The request's Origin, iff extension CORS is enabled and token-gated."""
    origin = request.headers.get("origin") or ""
    if (
        _dashboard_token()
        and _EXTENSION_ORIGIN_RE.match(origin)
        and _extension_cors_enabled()
    ):
        return origin
    return None


@app.middleware("http")
async def extension_cors(request: Request, call_next):
    """CORS for the bundled WebExtension only (opt-in; see above).

    Registered after the other middlewares, so it is OUTERMOST: preflights
    are answered before bearer_auth (a preflight carries no Authorization
    header by design and grants nothing by itself), and the CORS header is
    added to every response for an allowed origin — including 401s, so the
    popup can read the error instead of a blocked-by-CORS blank.
    """
    origin = _allowed_extension_origin(request)
    if origin is None:
        return await call_next(request)
    if request.method == "OPTIONS" and request.headers.get("access-control-request-method"):
        allow_headers = "Authorization, Content-Type"
        if route_path(request) in {"/api/v1/goals", "/api/v1/goal-submissions/receipt"}:
            allow_headers += ", Idempotency-Key"
        return PlainTextResponse(
            "",
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": allow_headers,
                "Access-Control-Max-Age": "600",
                "Vary": "Origin",
            },
        )
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = origin
    vary = response.headers.get("Vary")
    if not vary:
        response.headers["Vary"] = "Origin"
    elif "origin" not in vary.lower():
        response.headers["Vary"] = f"{vary}, Origin"
    return response


@app.middleware("http")
async def tenant_pinning(request: Request, call_next):
    """Reset any per-request tenant pin established by authentication.

    The actual pin is set inside ``require_principal`` after FastAPI has resolved
    the verified caller but before route handlers run. This outer middleware owns
    cleanup so the ContextVar token never leaks across requests/tasks.
    """
    try:
        return await call_next(request)
    finally:
        token = getattr(request.state, "tenant_pin_token", None)
        if token is not None:
            try:
                from maverick.paths import reset_tenant

                reset_tenant(token)
            except Exception:  # pragma: no cover
                pass


# ----- goal-creation rate limit -----
# Nothing throttled /chat/send or
# POST /api/v1/goals. A runaway loop or a flood of same-origin posts
# could spawn unbounded goals, each costing real money. This is an
# in-process sliding-window limiter (no new dependency) shared by all
# goal-creating routes. Caps are generous and configurable.
#
# Exposed-deployment hardening: one process-wide deque shared across every
# caller AND the HMAC webhooks would let a single noisy client (or a webhook
# flood) 429 everyone. Key the per-client
# window per principal/source (client IP, or a webhook source label) and
# keep a separate global ceiling so the process still can't be driven to
# spawn unbounded paid goals in aggregate.
_goal_times: dict[str, deque[float]] = {}
_goal_times_global: deque[float] = deque()
_goal_rl_lock = threading.Lock()
_dsar_response_times: dict[str, deque[float]] = {}
_dsar_response_lock = threading.Lock()


def _check_dsar_response_rate(request: Request) -> None:
    """Limit anonymous response links per client without consuming goal quota."""
    from .ip_allowlist import client_ip

    key = str(client_ip(request) or "unknown")
    now = time.monotonic()
    with _dsar_response_lock:
        if key not in _dsar_response_times and len(_dsar_response_times) >= 10_000:
            for old_key, events in list(_dsar_response_times.items()):
                if not events or events[-1] <= now - 60:
                    del _dsar_response_times[old_key]
            if len(_dsar_response_times) >= 10_000:
                raise HTTPException(status_code=429, detail="response request limit reached")
        events = _dsar_response_times.setdefault(key, deque())
        while events and events[0] <= now - 60:
            events.popleft()
        if len(events) >= 30:
            raise HTTPException(status_code=429, detail="response request limit reached",
                                headers={"Retry-After": "60"})
        events.append(now)


def _max_goals_per_min() -> int:
    from ._shared import dashboard_setting

    try:
        return max(1, int(dashboard_setting(
            "MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "max_goals_per_min", 30)))
    except (TypeError, ValueError):
        return 30


def _max_goals_global_per_min() -> int:
    # Process-wide ceiling across all clients; defaults to 10x the per-client
    # cap so one client can't starve others yet a distributed flood is still
    # bounded.
    from ._shared import dashboard_setting

    try:
        return max(1, int(dashboard_setting(
            "MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "max_goals_global_per_min",
            _max_goals_per_min() * 10)))
    except (TypeError, ValueError):
        return _max_goals_per_min() * 10


def _rate_limit_key(request: Request | None, source: str | None = None) -> str:
    """Identify the principal/source for rate-limiting.

    Prefer the authenticated principal when one is established (so a reverse
    proxy that collapses every user onto one client IP doesn't lump them into
    a single bucket), falling back to the client IP otherwise. HMAC webhooks
    pass an explicit ``source`` label since their callers share no useful
    client identity.
    """
    if source:
        return f"source:{source}"
    principal = caller_principal(request) if request else None
    if principal:
        return f"principal:{principal}"
    host = request.client.host if (request and request.client) else "unknown"
    return f"ip:{host}"


# Synthetic bucket for the process-wide ceiling in the shared store.
_RL_GLOBAL_KEY = "__rl_goal_global__"


def _shared_rate_limit_check(key: str, cap: int, global_cap: int) -> bool:
    """Cross-replica goal-creation rate check, backed by the shared world store.

    The in-process windows below only bound ONE replica, so N replicas admit N x
    the cap. When Postgres (the HA backend) is configured, count admitted events
    in the shared ``rate_events`` table across a 60s wall-clock window (shared
    across replicas, unlike the in-process monotonic clock) and record this one.
    Returns True when it admitted the request, raises ``HTTPException(429)`` when
    a cap is exceeded, and returns False when there is no shared backend / it is
    unavailable (the caller then applies the in-process limiter). A small
    over-admission race is acceptable for a spend backstop -- it is not a hard
    security boundary."""
    try:
        from maverick.world_model_backends import is_postgres_configured

        if not is_postgres_configured():
            return False
        w = _world()
        result = w.reserve_rate_events(key, cap, _RL_GLOBAL_KEY, global_cap, time.time())
        if result == "global":
            raise HTTPException(
                status_code=429,
                detail=f"goal rate limit reached ({global_cap}/min total). Try again shortly.",
                headers={"Retry-After": "60"},
            )
        if result == "key":
            raise HTTPException(
                status_code=429,
                detail=f"goal rate limit reached ({cap}/min). Try again shortly.",
                headers={"Retry-After": "60"},
            )
        return True
    except HTTPException:
        raise
    except Exception:  # pragma: no cover - never fail the request closed on a store blip
        log.warning("shared rate limiter unavailable, using in-process window")
        return False


def check_goal_rate_limit(request: Request | None = None, *, source: str | None = None) -> None:
    """Raise HTTPException(429) if the goal-creation rate exceeds a cap.

    Two 60-second sliding windows are enforced: a per-client window keyed
    by principal/source (so one noisy client can't 429 everyone) and a
    process-wide global ceiling (so a distributed flood still can't spawn
    unbounded paid goals). On the Postgres (HA) backend these windows are
    shared across replicas (see :func:`_shared_rate_limit_check`); otherwise
    they are the per-process windows below.
    """
    key = _rate_limit_key(request, source)
    cap = _max_goals_per_min()
    global_cap = _max_goals_global_per_min()
    if _shared_rate_limit_check(key, cap, global_cap):
        return
    now = time.monotonic()
    cutoff = now - 60.0
    with _goal_rl_lock:
        # Global ceiling first.
        while _goal_times_global and _goal_times_global[0] < cutoff:
            _goal_times_global.popleft()
        if len(_goal_times_global) >= global_cap:
            retry = int(60 - (now - _goal_times_global[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"goal rate limit reached ({global_cap}/min total). Try again in {retry}s.",
                headers={"Retry-After": str(max(1, retry))},
            )

        window = _goal_times.get(key)
        if window is None:
            window = _goal_times[key] = deque()
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= cap:
            retry = int(60 - (now - window[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"goal rate limit reached ({cap}/min). Try again in {retry}s.",
                headers={"Retry-After": str(max(1, retry))},
            )

        # Sweep EVERY other key's window of expired entries, then drop the ones
        # that became empty. Collecting only ALREADY-empty deques would never
        # prune a key whose lone entry expired and whose IP/principal never
        # recurs (its deque keeps len 1, so `not w` stays False) -- so a stream
        # of distinct one-shot keys (many principals / direct client IPs) would
        # grow the dict without bound. The dict stays bounded by the number of
        # keys active within the window.
        for stale_key in list(_goal_times):
            if stale_key == key:
                continue
            w = _goal_times[stale_key]
            while w and w[0] < cutoff:
                w.popleft()
            if not w:
                del _goal_times[stale_key]

        window.append(now)
        _goal_times_global.append(now)


# ----- SSE stream concurrency cap -----
# Exposed-deployment hardening: each open SSE
# stream spawns a 300s task polling SQLite every 0.5s. Thousands of
# EventSource opens exhaust file descriptors and the event loop. The cap
# lives in _shared so app and api share ONE process-wide semaphore rather
# than two independent caps. Imported above.


def _load_skills():
    from maverick.skills import load_skills

    return load_skills()


@app.get("/demo", response_class=HTMLResponse)
def public_demo(request: Request) -> HTMLResponse:
    """Redacted public-demo page for the reference demo-cluster proxy.

    The demo proxy exposes this route to the internet. Keep it intentionally
    narrow: render only goals owned by the seeded ``demo`` principal and never
    include facts, spend, audit logs, tool configuration, or other operator
    state that authenticated dashboard GET endpoints may expose.
    """
    from html import escape

    goals = _world().list_goals(owner="demo", limit=50, order="desc")
    cards = []
    for goal in goals:
        status = escape(str(getattr(goal, "status", "")))
        title = escape(str(getattr(goal, "title", "")))
        description = escape(str(getattr(goal, "description", "") or ""))
        result = escape(str(getattr(goal, "result", "") or ""))
        cards.append(
            "<article class='card'>"
            f"<p class='status'>{status}</p>"
            f"<h2>{title}</h2>"
            f"<p>{description}</p>"
            f"<p><strong>Result:</strong> {result}</p>"
            "</article>"
        )
    body = "".join(cards) or "<p class='empty'>No seeded demo goals are available yet.</p>"
    # The public proxy serves only this path, so the page cannot load
    # lightwork.css; it repeats the shared --font-sans token (a test keeps the
    # two identical).
    return HTMLResponse(
        "<!doctype html>"
        "<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Lightwork public demo</title>"
        "<style>"
        ":root{color-scheme:dark;"
        "--font-sans:'Manrope',-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;"
        "font-family:var(--font-sans);"
        "background:#0d1117;color:#e6edf3}"
        "body{margin:0;padding:2rem;max-width:1100px;margin-inline:auto}"
        "header{margin-bottom:2rem}.eyebrow,.status{color:#2ea043;"
        "text-transform:uppercase;letter-spacing:.08em;font-size:.8rem}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}"
        ".card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:1rem}"
        ".empty{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:1rem}"
        "a{color:#58a6ff}"
        "</style></head><body>"
        "<header><p class='eyebrow'>read-only public snapshot</p>"
        "<h1>Lightwork demo</h1>"
        "<p>This page intentionally shows only seeded demo-owned finished tasks. "
        "Operator state, audit logs, spend, facts, plugins, permissions, and "
        "the rest of the authenticated dashboard are not proxied publicly.</p>"
        "</header><main class='grid'>"
        f"{body}"
        "</main></body></html>"
    )


@app.get("/overview", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    from . import department_boards
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Home's Overview section
    if moved is not None:
        return moved
    if department_boards.scoped(request):
        return department_boards.page(request, "overview")
    require_unscoped_board(request)
    from .value_views import value_scope

    w = _world()
    # Use SQL aggregation instead of pulling every goal into Python. Count the
    # caller's own goals; a read-only role counts the whole workspace (totals
    # only -- see value_views).
    value_view = value_scope(request)
    owner = value_view["owner"]
    by_status = w.goal_status_counts(owner=owner)
    counts = {
        "total": sum(by_status.values()),
        "active": by_status.get("active", 0),
        "done": by_status.get("done", 0),
        "blocked": by_status.get("blocked", 0),
    }
    # The executive board (charts, KPI deltas, recent list) renders client-side
    # from GET /api/v1/dashboards/overview; the page only needs the hero counts.
    # Reserved task/user memory is private; the overview is shared business context.
    facts = {key: value for key, value in w.get_facts().items()
             if not str(key).startswith(("goal:", "user:"))}
    skills = _load_skills()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"counts": counts, "facts": facts, "skills": skills[:10], "value_view": value_view},
    )


@app.get("/redact", response_class=HTMLResponse)
async def redact_page(request: Request) -> HTMLResponse:
    """Granular redaction UI (preview/select/scrub via /api/v1/redact/preview)."""
    return templates.TemplateResponse(request, "redact.html", {})


@app.get("/workforce", response_class=HTMLResponse)
def workforce_page(request: Request) -> HTMLResponse:
    """The workforce: specialist packs as departments, with delivery outcomes.

    Presents the 1,000+ packs as buyable teams (charter + headcount), a
    firm-wide delivery rollup from the Operating Record, and the catalog counts.
    Per-department governed reviews load from /api/v1/departments/{key}/review.
    """
    from . import department_boards
    if department_boards.scoped(request):
        return department_boards.page(request, "workforce")
    require_unscoped_board(request)
    from maverick.departments import department_entitlements, list_departments
    from maverick.fleet import list_fleets
    from maverick.marketplace.storefront import connector_marketplace
    from maverick.operating_record import assemble
    from maverick.outcomes import firm_totals

    from .auth import scope_to_suites

    w = _world()
    # Job-function scoping: mirror GET /api/v1/departments — a caller with a
    # department grant sees only their departments.
    depts = scope_to_suites(request, list_departments(), suite_of=lambda d: d.key, keep_none=False)
    owner = goal_owner_filter(request)
    firm = firm_totals(assemble(w, owner=owner)).to_dict()
    # Catalog capacity is not deployment state.  Count only persisted fleet
    # agents that belong to one of the departments visible to this caller.
    visible_department_keys = {d.key for d in depts}
    try:
        deployed_fleets = list_fleets()
    except Exception:
        deployed_fleets = []
    if owner is not None:
        deployed_fleets = [fleet for fleet in deployed_fleets if fleet.owner == owner]
    deployed_specialists = sum(
        1
        for fleet in deployed_fleets
        for agent in fleet.agents
        if agent.domain in visible_department_keys
    )

    # A saved connection is configured, but it is not necessarily reachable.
    # Keep this count separate from the much larger connector catalog.
    try:
        from maverick.connections import list_connections

        configured_connectors = len(
            {
                str(connection.get("connector") or "").strip().lower()
                for connection in list_connections(owner=owner)
                if str(connection.get("connector") or "").strip()
            }
        )
    except Exception:
        configured_connectors = 0
    # The delivery/spend/leader charts render client-side from
    # GET /api/v1/dashboards/workforce.
    return templates.TemplateResponse(
        request,
        "workforce.html",
        {
            "departments": depts,
            "entitlements": department_entitlements(d.key for d in depts),
            "firm": firm,
            "pack_total": sum(d.headcount for d in depts),
            "deployed_specialists": deployed_specialists,
            "connector_total": connector_marketplace()["total"],
            "configured_connectors": configured_connectors,
        },
    )


@app.get("/learning", response_class=HTMLResponse)
async def learning_page(request: Request) -> HTMLResponse:
    """Accumulated learning: which learning systems are on, and the durable,
    per-tenant judgement the workforce has accumulated (Operating Record +
    grounded outcomes + self-taught capabilities). Read-only; same numbers as
    /api/v1/learning."""
    from . import auth
    from .learning_snapshot import learning_snapshot

    snap = learning_snapshot(
        request, world_factory=_world, owner_filter=goal_owner_filter,
        permission_check=auth.has_global_permission,
    )
    return templates.TemplateResponse(
        request,
        "learning.html",
        {
            "snap": snap,
            "learning_can_manage": has_global_permission(request, "admin"),
            "agent_feedback": _agent_feedback_summary(),
            "flow_feedback": _flow_feedback_summary(),
            "learning_can_operate": has_permission(request, "operate"),
        },
    )


def _agent_feedback_summary() -> list[dict]:
    """Ratings and picked reasons per agent for the administrator's Learning page."""
    try:
        from . import goal_feedback_store
        from .agent_changelog import agent_title

        rows = goal_feedback_store.summary_by_agent(world=_world())
        for row in rows:
            row["title"] = agent_title(row["agent"])
        return rows
    except Exception:  # pragma: no cover -- the page renders without the summary
        return []


def _flow_feedback_summary() -> list[dict]:
    """Useful / not useful per flow for the Learning page (flow_run_feedback.py)."""
    try:
        from maverick.flow import store as flow_store

        from . import flow_run_feedback

        rows = flow_run_feedback.summary_by_flow()
        for row in rows:
            try:
                flow = flow_store.load_flow(row["flow_id"])
            except Exception:  # noqa: BLE001 -- a removed or unreadable flow keeps its id
                flow = None
            row["title"] = (getattr(flow, "name", "") or row["flow_id"]) if flow else row["flow_id"]
        return rows
    except Exception:  # pragma: no cover -- the page renders without the summary
        return []


@app.get("/perf", response_class=HTMLResponse)
async def perf_page(request: Request) -> HTMLResponse:
    """Admin diagnostics: SLA + benchmark history (data via /api/v1/perf)."""
    return templates.TemplateResponse(request, "perf.html", {})


@app.get("/static/lightwork-task-views.js")
def task_views_script():
    return FileResponse(Path(__file__).parent / "static" / "lightwork-task-views.js", media_type="application/javascript",
                        headers={"Cache-Control": STATIC_SHORT_CACHE})
@app.get("/nav/finder", response_class=HTMLResponse, include_in_schema=False)
def nav_finder_items(request: Request) -> HTMLResponse:
    """The page finder's destinations for the caller, as the ``<li>`` items of
    its listbox (``_navfinder_items.html``), fetched on the finder's first open.

    Every page embedded this list (81 KB, 125 groups) in its HTML; now it is
    one small request per session, privately cacheable and revalidated by
    ETag. It renders through the same context processor as the shell, so the
    role, overrides and lockout policy are exactly the sidebar's.
    """
    rendered = templates.TemplateResponse(request, "_navfinder_items.html", {})
    body = bytes(rendered.body)
    etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
    headers = {
        "Cache-Control": "private, max-age=60",
        "ETag": etag,
        "Vary": "Cookie, Authorization",
    }
    candidates = {t.strip().removeprefix("W/") for t in request.headers.get("if-none-match", "").split(",")}
    if etag in candidates:
        return HTMLResponse(status_code=304, headers=headers)
    return HTMLResponse(body, headers=headers)


#: Rows the Tasks page renders before "Show more" (the API's default page).
GOALS_PAGE_SIZE = 50


@app.get("/goals", response_class=HTMLResponse)
def goals_page(request: Request, owner: str = "", include: str = "") -> HTMLResponse:
    """The Tasks page: the newest page of goals; the rest load on demand from
    ``/api/v1/goals`` (rendering all 200 was 104 KB of rows per visit).

    ``?owner=me`` names the list for what it is -- every account lists its own
    tasks (``goal_owner_filter``), so it never widens or narrows the rows.
    ``&include=background`` adds My background work (schedules, workflow runs
    and connections) under the same check as its old page, /my-work."""
    from .draft_api import context_for
    from .task_search import initial as initial_tasks

    background = include == "background"
    if background:
        require_page_visible(request, "/my-work")
        require_permission(request, "view")
    task_page = initial_tasks(request, limit=GOALS_PAGE_SIZE)
    goals = task_page["goals"]
    has_more = not task_page["complete"]
    from .preferences_api import _principal
    try:
        _principal(request)
        task_views_available = True
    except HTTPException:
        task_views_available = False
    return templates.TemplateResponse(request, "goals.html", {
        "goals": goals[:GOALS_PAGE_SIZE],
        "task_search_context": task_page["context"],
        "task_search_continuation": task_page["continuation"],
        "task_views_available": task_views_available,
        "work_details_available": page_visible(request, "/work-details") and has_permission(request, "operate"),
        "page_size": GOALS_PAGE_SIZE,
        "has_more": has_more,
        "next_offset": GOALS_PAGE_SIZE if has_more else 0,
        "goals_owner": "me" if owner == "me" or background else "",
        "goals_background": background,
        "work_context": context_for(request) if background else "",
    })


@app.get("/work-details", response_class=HTMLResponse)
def work_record_details_page(request: Request) -> HTMLResponse:
    """Ordinary business fields and stages for currently readable native work."""
    from .work_record_details_api import page_context

    require_permission(request, "operate")
    require_page_visible(request, "/work-details")
    return templates.TemplateResponse(request, "work_record_details.html", page_context(request))


@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request) -> HTMLResponse:
    """Projects ("matters") -- workspaces grouping related goals. In the
    job-named navigation it also lists the project plans (the Project
    workspaces page), for exactly the people that page admits."""
    from .draft_api import context_for
    from .navigation_api import areas_on

    projects = _world().list_projects(owner=goal_owner_filter(request))
    plans = areas_on(request) and page_visible(request, "/project-workspaces") and has_permission(request, "view")
    return templates.TemplateResponse(request, "projects.html", {
        "projects": projects, "project_plans": plans,
        "project_context": context_for(request) if plans else "",
    })


@app.post("/projects")
def projects_create(
    request: Request, name: str = Form(...), description: str = Form(""), domain: str = Form("")
) -> RedirectResponse:
    """Create a project, then redirect to it. Same-origin; owned by the caller."""
    _require_same_origin(request)
    require_permission(request, "operate")
    if not name.strip():
        raise HTTPException(status_code=422, detail="a project needs a name")
    pid = _world().create_project(
        name.strip(),
        description=description.strip(),
        owner=caller_principal(request) or "",
        domain=domain.strip(),
    )
    return RedirectResponse(f"/projects/{pid}", status_code=303)


def _project_plan_tab(request: Request, project_id: int, project) -> HTMLResponse:
    """A project's Plan tab: the Project workspace page for this project,
    under that page's own check (its page policy and ``view``). The
    workspace's API decides what the person may read, as before -- a planning
    member who cannot open the project's task list still sees the plan."""
    from .draft_api import context_for

    require_page_visible(request, "/project-workspaces")
    require_permission(request, "view")
    tabs = [("plan", "Plan", f"/projects/{project_id}?tab=plan")]
    if project is not None:
        tabs.insert(0, ("tasks", "Tasks", f"/projects/{project_id}"))
    return templates.TemplateResponse(
        request, "project_workspaces.html",
        {"project_id": project_id, "project_context": context_for(request), "project_tabs": tabs},
        headers={"Cache-Control": "private, no-store"},
    )


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int, tab: str = "") -> HTMLResponse:
    w = _world()
    project = w.get_project(project_id)
    # Owner-scoped like goals: a project you don't own 404s rather than leaks.
    owner = goal_owner_filter(request)
    if project is not None and owner is not None and project["owner"] != owner:
        project = None
    if tab == "plan":
        return _project_plan_tab(request, project_id, project)
    if project is None:
        raise HTTPException(status_code=404, detail="no such project")
    goals = w.list_goals(project_id=project_id, owner=owner, order="desc")
    counts: dict[str, int] = {}
    for goal in goals:
        counts[goal.status] = counts.get(goal.status, 0) + 1
    return templates.TemplateResponse(
        request,
        "project_detail.html",
        {"project": project, "goals": goals, "counts": counts,
         "project_plan_available": page_visible(request, "/project-workspaces")},
    )


@app.post("/chat/goal/{goal_id}/project")
def goal_set_project(
    request: Request, goal_id: int, project_id: str = Form("")
) -> RedirectResponse:
    """File a goal under a project (empty value clears it). Same-origin; the
    caller must be able to access the goal."""
    _require_same_origin(request)
    require_permission(request, "operate")
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    try:
        pid = int(project_id) if project_id.strip() else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Choose a valid project.") from exc
    if pid is not None:
        project = w.get_project(pid)
        owner = goal_owner_filter(request)
        if project is None or (owner is not None and project["owner"] != owner):
            raise HTTPException(status_code=404, detail="no such project")
    w.set_goal_project(goal_id, pid)
    return RedirectResponse(f"/chat/goal/{goal_id}", status_code=303)


@app.get("/styles", response_class=HTMLResponse)
async def styles_page(request: Request) -> HTMLResponse:
    """Output styles -- the response style applied to every run."""
    require_global_permission(request, "operate")
    from maverick.styles import active_style_name, all_styles

    items = [{"name": n, "guidance": g} for n, g in sorted(all_styles().items())]
    return templates.TemplateResponse(
        request, "output_styles.html", {"styles": items, "active": active_style_name()}
    )


@app.post("/styles/set")
async def styles_set(request: Request, name: str = Form("")) -> RedirectResponse:
    """Set the active output style (empty value clears it). Same-origin; the
    operator role (it changes how every agent responds)."""
    _require_same_origin(request)
    require_global_permission(request, "operate")
    from maverick import runtime_overrides

    n = (name or "").strip()
    try:
        runtime_overrides.set_style(n) if n else runtime_overrides.clear_style()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/styles", status_code=303)


def _deliverable_specs() -> list[dict]:
    """The packs that declare a deliverable -- the rows of the persona inbox.

    A pack earns a spec once its output contract names a deliverable or its
    consumers; packs that only emit prose stay out of the inbox (they're plain
    runs on ``/goals``). Fail-soft to an empty list so the page never 500s if
    the factory layer is unavailable."""
    try:
        from maverick.domain import available_domains, enforced_gate, suite_for, suites_for_domain
    except Exception:  # pragma: no cover -- factory layer unavailable
        return []
    specs: list[dict] = []
    for name, prof in sorted(available_domains().items()):
        out = prof.output
        if not (out.deliverable or out.consumers):
            continue
        specs.append(
            {
                "domain": name,
                "deliverable": out.deliverable or name,
                "shape": out.shape,
                "consumers": list(out.consumers),
                "cadence": out.cadence,
                "gate": enforced_gate(prof),
                "suite": suite_for(name),
                "suites": sorted(suites_for_domain(name, prof)),
            }
        )
    return specs


@app.get("/deliverables", response_class=HTMLResponse)
def deliverables_page(request: Request, role: str = "") -> HTMLResponse:
    """Show the caller's completed work; explicit role links browse pack output."""
    from . import auth as _auth
    from .auth import caller_suites
    from .deliverables import PAGE_SIZE, build_inbox, persona_roles_for, recent_runs_by_domain

    owner = goal_owner_filter(request)
    if not role:
        try:
            page = max(1, min(int(request.query_params.get("page", "1")), 10_000))
        except ValueError:
            page = 1
        rows = _world().list_goal_results(
            owner=owner, limit=PAGE_SIZE + 1, offset=(page - 1) * PAGE_SIZE,
        )
        shown = rows[:PAGE_SIZE]
        shown_domains = {g.domain for g in shown}
        gates = {s["domain"]: s for s in (_deliverable_specs() if shown_domains else [])
                 if s["domain"] in shown_domains}
        try:
            signoffs = _world().signoffs_for_goals([g.id for g in shown])
        except Exception:  # pragma: no cover -- sign-off lookup never hides finished work
            signoffs = {}
        awaiting = [
            {"id": g.id, "title": g.title, "updated_at": g.updated_at,
             "deliverable": gates[g.domain]["deliverable"], "gate": gates[g.domain]["gate"]}
            for g in shown if g.domain in gates and gates[g.domain]["gate"]
            and not signoffs.get(g.id)
        ]
        return templates.TemplateResponse(request, "deliverables.html", {
            "browse": False, "recent_results": shown, "awaiting": awaiting,
            "result_labels": {domain: spec["deliverable"] for domain, spec in gates.items()},
            "results_page": page, "results_more": len(rows) > PAGE_SIZE,
            # Only the task owner may rate a result (answer_feedback_operations).
            "feedback_owner": _auth.caller_principal(request) or "", "can_rate": has_permission(request, "operate"),
        })

    # Job-function scoping: a scoped caller's inbox lists only their
    # departments' deliverable specs (plus generic packs), matching /agents.
    allowed = caller_suites(request)
    specs = [
        spec for spec in _deliverable_specs()
        if allowed is None or set(spec["suites"]) <= allowed
    ]
    # One grouped read for every pack's latest runs, not one query per pack.
    runs_by_domain = recent_runs_by_domain(_world(), [s["domain"] for s in specs], owner=owner)
    ids = [g.id for runs in runs_by_domain.values() for g in runs]
    try:
        signoffs = _world().signoffs_for_goals(ids)
    except Exception:  # pragma: no cover -- never break the page on the sign-off lookup
        signoffs = {}
    # Explicit chip wins; "all" forces the full view; otherwise default to mine.
    selected = role if role and role != "all" else None
    mine = set(persona_roles_for(caller_principal(request)))
    default_mine = mine if (not selected and role != "all") else None
    model = build_inbox(specs, runs_by_domain, selected, signoffs, mine=default_mine)
    # ?role=all is the explicit request to browse the whole catalogue even
    # before any result exists; the plain page shows a real empty state.
    model["showing_all"] = role == "all"
    model["browse"] = True
    return templates.TemplateResponse(request, "deliverables.html", model)


@app.get("/action-center", response_class=HTMLResponse)
async def action_center_page(request: Request) -> HTMLResponse:
    from .action_center_api import require_enabled
    from .draft_api import context_for
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Approvals' "All decisions"
    if moved is not None:
        return moved
    require_enabled(request)
    return templates.TemplateResponse(
        request, "action_center.html",
        {"action_context": context_for(request), "can_admin": has_permission(request, "admin")},
    )


@app.get("/workflow-readiness", response_class=HTMLResponse)
async def workflow_readiness_page(request: Request) -> HTMLResponse:
    from maverick import config

    from .workflow_readiness import for_request

    require_permission(request, "view")
    unavailable = bool(config.config_source_errors(include_tenant=True))
    if unavailable or config.get_features().get("workflow_readiness") is not True:
        # Friendly turned-off page (still 403) instead of a bare error.
        return templates.TemplateResponse(
            request, "workflow_readiness.html",
            {"capabilities": [], "disabled": True, "unavailable": unavailable,
             "can_turn_on": has_permission(request, "admin")},
            status_code=403, headers={"Cache-Control": "private, no-store"})
    return templates.TemplateResponse(request, "workflow_readiness.html", {"capabilities": for_request(request)},
                                      headers={"Cache-Control": "private, no-store"})


@app.get("/workspaces", include_in_schema=False)
def workspaces_alias() -> RedirectResponse:
    """The product calls the tenant roster "Workspaces"; links use that name."""
    return RedirectResponse("/tenants", status_code=303)


@app.get("/tenants", response_class=HTMLResponse)
async def tenants_page(request: Request) -> HTMLResponse:
    """Operator console: the provisioned-tenant roster (status / plan / quota).

    Cross-tenant control-plane data, so it is admin-only: the RBAC "admin"
    permission gates the route outright (matching the page's visibility floor),
    and a store-assigned admin role counts the same as a config-pinned
    bootstrap admin. Fail-soft to an empty roster so a missing registry never
    500s the console.
    """
    require_global_permission(request, "admin")
    try:
        from maverick.tenant.registry import list_tenants

        tenants = list_tenants()
    except Exception:  # pragma: no cover -- never 500 the console
        tenants = []
    try:
        from maverick.tenant.registry import list_removed_tenants

        removed_tenants = list_removed_tenants()
        removed_error = ""
    except Exception:
        removed_tenants = []
        removed_error = "Removed workspace history is unavailable. Ask an administrator to check the installation."
    from .workspace_display import duplicate_workspace_ids

    duplicate_ids = duplicate_workspace_ids((t.id, t.display_name or t.id) for t in tenants)
    # Plans (Free / Pro / Enterprise) only mean something when platform billing
    # collects for them; a self-hosted administrator never sees them otherwise.
    try:
        from maverick import billing_stripe

        billing_on = bool(billing_stripe.enabled())
    except Exception:  # pragma: no cover -- billing is optional
        billing_on = False
    return templates.TemplateResponse(
        request,
        "tenants.html",
        {"tenants": tenants, "removed_tenants": removed_tenants, "removed_error": removed_error,
         "duplicate_ids": duplicate_ids, "is_admin": True, "billing_on": billing_on},
    )


def _tenant_overview_rows() -> list[dict]:
    """Per-tenant rollup for the multi-tenant view: goals by status (from the
    tenant's configured world backend), today's spend, suspended flag.

    Fail-soft per tenant: an unreadable world DB or spend ledger yields zero
    counts/spend, never a 500. On SQLite a tenant whose world.db doesn't exist
    yet reports empty counts rather than materializing the DB. Postgres has no
    local sentinel file, so it is always queried under an explicit tenant
    scope through the canonical backend selector.
    """
    from maverick.tenant.registry import list_tenants, tenant_spend_today
    from maverick.world_model_backends import is_postgres_configured

    postgres = is_postgres_configured()
    rows: list[dict] = []
    for t in list_tenants():
        counts: dict[str, int] = {}
        try:
            from maverick.workspace import Workspace

            db = Workspace(t.id).db_path
            if postgres or db.exists():
                from maverick.paths import tenant_scope
                from maverick.world_model import close_world_if_owned, open_world

                with tenant_scope(tenant=t.id):
                    wm = open_world()
                    try:
                        # Aggregate in the selected backend. Do not decrypt and
                        # materialize every goal just to render a histogram.
                        counts = wm.goal_status_counts()
                    finally:
                        close_world_if_owned(wm)
        except Exception:  # pragma: no cover -- one bad tenant DB never 500s
            counts = {}
        try:
            spend = float(tenant_spend_today(t.id))
        except Exception:  # pragma: no cover -- spend read never blocks the view
            spend = 0.0
        rows.append(
            {
                "id": t.id,
                "display_name": t.display_name,
                "plan": t.plan,
                "status": t.status,
                "suspended": not t.active,
                "goals": counts,
                "total_goals": sum(counts.values()),
                "spend_today": round(spend, 4),
                "max_daily_dollars": t.max_daily_dollars,
            }
        )
    return rows


@app.get("/tenants/overview", response_class=HTMLResponse)
async def tenants_overview_page(request: Request) -> HTMLResponse:
    """Multi-tenant view: per-tenant goal/spend rollup for the operator.

    Admin-only exactly like ``/tenants`` (cross-tenant control-plane data):
    the RBAC "admin" permission gates the route outright. Fail-soft to an
    empty roster so a missing registry never 500s the console.
    """
    require_global_permission(request, "admin")
    try:
        rows = _tenant_overview_rows()
    except Exception:  # pragma: no cover -- never 500 the console
        rows = []
    from .workspace_display import duplicate_workspace_ids

    duplicate_ids = duplicate_workspace_ids((row["id"], row["display_name"] or row["id"]) for row in rows)
    return templates.TemplateResponse(
        request,
        "tenants_overview.html",
        {"rows": rows, "duplicate_ids": duplicate_ids, "is_admin": True},
    )


@app.get("/api/v1/tenants/overview")
async def tenants_overview_api(request: Request) -> JSONResponse:
    """JSON face of the multi-tenant view. Admin-only like ``/tenants`` (the
    RBAC "admin" permission, so store-assigned admins count too)."""
    require_global_permission(request, "admin")
    try:
        rows = _tenant_overview_rows()
    except Exception:  # pragma: no cover -- never 500 the console
        rows = []
    return JSONResponse({"tenants": rows})


def _feature_label(feature: str) -> str:
    """A human-facing label for a catalog feature key. Departments read as
    their business-suite title; the cross-cutting flags get short names."""
    if feature.startswith("department:"):
        from maverick.departments import department_title
        return department_title(feature.split(":", 1)[1]) + " department"
    return {
        "core": "Core features",
        "channels": "Chat apps (Slack, Teams, email and more)",
        "audit_export": "Download the activity history",
        "grpc": "Connections for other software (advanced)",
    }.get(feature, feature.replace("_", " ").capitalize())


@app.get("/tenants/{tenant_id}/features", response_class=HTMLResponse)
async def tenant_features_page(request: Request, tenant_id: str) -> HTMLResponse:
    """Per-tenant feature overrides: toggle individual capabilities on/off on
    top of the tenant's plan (tier).

    Cross-tenant control-plane data, so admin-only exactly like ``/tenants``.
    A checked box is a feature the tenant effectively has; each row shows whether
    it comes from the plan or from an override. Saving posts the derived
    ``add``/``remove`` overrides to ``PUT /api/v1/admin/tenants/{id}/features``.
    """
    require_global_permission(request, "admin")
    from maverick import billing
    from maverick.tenant.registry import get_tenant

    rec = get_tenant(tenant_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no such tenant")
    # The diff basis MUST be the effective baseline overrides apply on top of
    # (downgraded when past-due), not the subscribed plan -- otherwise saving a
    # past-due tenant's page would record a spurious remove for every downgraded
    # feature (and those persist past payment recovery).
    plan_features = set(billing.plan_features_for_tenant(tenant_id))
    effective = set(billing.effective_features(tenant_id))
    caps: list[dict] = []
    depts: list[dict] = []
    on_count = 0
    for feature in billing.gateable_features():
        in_plan = feature in plan_features
        is_on = feature in effective
        if is_on:
            on_count += 1
        if in_plan and is_on:
            source = "plan"
        elif in_plan and not is_on:
            source = "removed"
        elif is_on:
            source = "added"
        else:
            source = "off"
        row = {
            "feature": feature,
            "label": _feature_label(feature),
            "in_plan": in_plan,
            "on": is_on,
            "source": source,
        }
        (depts if feature.startswith("department:") else caps).append(row)
    return templates.TemplateResponse(
        request,
        "tenant_features.html",
        {
            "tenant": rec,
            "caps": caps,
            "depts": depts,
            "on_count": on_count,
            "is_admin": True,
        },
    )


@app.get("/skills", response_class=HTMLResponse)
async def skills_page(request: Request) -> HTMLResponse:
    # Same opt-in the create/install API enforces; the page only reads it so
    # it can say "switched off" instead of offering forms that would fail.
    from maverick.skills import url_install_allowed

    install_allowed = url_install_allowed()
    return templates.TemplateResponse(request, "skills.html", {
        "skills": sorted(_load_skills(), key=lambda s: s.name),
        "is_admin": has_permission(request, "admin"),
        "install_allowed": install_allowed,
    })


@app.get("/learned", response_class=HTMLResponse)
async def learned_page(request: Request) -> HTMLResponse:
    """Self-learning observability: the learned-capability ledger + the
    on-disk generated tools, with a remove action per generated tool."""
    from .api import _learned_snapshot

    can_manage = has_global_permission(request, "admin")
    return templates.TemplateResponse(
        request,
        "learned.html",
        {
            **_learned_snapshot(include_pending_items=can_manage, request=request),
            "can_manage": can_manage,
            "can_remove_tools": has_permission(request, "admin"),
        },
    )


@app.get("/facts", response_class=HTMLResponse)
def facts_page(request: Request) -> HTMLResponse:
    from .draft_api import context_for
    return templates.TemplateResponse(request, "facts.html", {
        "fact_records": _world().fact_records(limit=51, shared_only=True), "fact_context": context_for(request),
    })


def _newest_cost_at(w, owner) -> float | None:
    """When the newest task cost in this view was recorded, for the Spend
    page's "Spending updated" label (None when there is none)."""
    try:
        newest = w.list_episodes(limit=1, owner=owner)
    except Exception:  # noqa: BLE001 -- no label beats a made-up one
        return None
    if not newest:
        return None
    return newest[0].ended_at or newest[0].started_at


@app.get("/spend", response_class=HTMLResponse)
def spend_page(request: Request) -> HTMLResponse:
    from . import department_boards

    if department_boards.scoped(request):
        return department_boards.page(request, "spend")
    require_unscoped_board(request)
    # The burn/outcome/top-goal charts render client-side from
    # GET /api/v1/dashboards/spend; the page keeps the episode table + hero.
    # Scope both reads to the caller (matches /api/v1/spend and the on-page
    # charts) so a non-admin never sees the whole tenant's spend/episodes.
    # goal_owner_filter returns None for admins / auth-off, preserving that view.
    from .value_views import value_scope

    owner = goal_owner_filter(request)
    # The heading total follows the value view (a read-only role sees the
    # workspace total); the task table always stays the caller's own rows.
    value_view = value_scope(request)
    w = _world()
    episodes = w.list_episodes(limit=50, owner=owner)
    from maverick.cost_provenance import for_goal, runtime_basis
    episode_provenance = {e.id: {"runtime_basis": runtime_basis(e.cost_dollars), **for_goal(e.goal_id)} for e in episodes}
    # Task titles for the table (the episodes are already scoped to the caller).
    goal_titles: dict[int, str] = {}
    try:
        from maverick.world_model import goals_by_id

        goal_titles = {gid: g.title for gid, g in goals_by_id(w, [e.goal_id for e in episodes if e.goal_id]).items()
                       if getattr(g, "title", "")}
    except Exception:  # noqa: BLE001 - a missing title falls back to "Task"
        for gid in {e.goal_id for e in episodes if e.goal_id}:
            try:
                g = w.get_goal(gid)
                if g is not None and getattr(g, "title", ""):
                    goal_titles[gid] = g.title
            except Exception:  # noqa: BLE001
                continue
    import datetime as _dt
    today = _dt.date.today().replace(day=1)
    months = []
    for back in range(12):
        year, month = divmod(today.month - 1 - back, 12)
        first = _dt.date(today.year + year, month + 1, 1)
        months.append({"value": first.strftime("%Y-%m"), "label": first.strftime("%B %Y")})
    return templates.TemplateResponse(
        request,
        "spend.html",
        {"episodes": episodes, "total": w.total_spend(owner=value_view["owner"]),
         "goal_titles": goal_titles, "csv_months": months, "episode_provenance": episode_provenance,
         "value_view": value_view, "spend_recorded_at": _newest_cost_at(w, value_view["owner"]),
         "practice_cost": _practice_cost_text(value_view["owner"], when="across all time")},
    )


def _practice_cost_text(owner, *, when: str, since: float | None = None) -> str:
    """The labelled practice line for a cost view (maverick.practice_costs), or ""."""
    from maverick import practice_costs

    line = practice_costs.summary(owner, since=since)
    return practice_costs.label(line, when) if line else ""


# One assessment engine, one workspace chassis per department: each
# department page filters the same records/templates to its own types.
PRIVACY_ASSESSMENT_TYPES = frozenset(
    {
        "pia", "dpia", "lia", "ccpa", "lgpd", "pipeda",
        "us_state_privacy", "cppa_admt", "colorado_admt", "nyc_ll144",
        "texas_traiga", "illinois_hb3773", "aira", "vendor_risk", "tia",
    }
)
FINANCE_ASSESSMENT_TYPES = frozenset(
    {"sox_control", "fraud_risk", "itgc", "credit_risk", "close_readiness"}
)
SECURITY_ASSESSMENT_TYPES = frozenset(
    {
        "soc2",
        "iso27001",
        "iso42001",
        "nist_csf",
        "nist_800_53",
        "cis_v8",
        "pci_dss",
        "hipaa",
        "cmmc_l2",
        "fedramp_moderate",
    }
)


def _workspace_ctx(department: str, viewer: str = "") -> dict:
    """Chassis context for a department workspace: the worklist (risk pair,
    aging, follow-ups), hero stats, precedent memory, and catalog — filtered
    to the department's assessment types (built-ins plus any custom
    templates authored for this department).

    ``viewer`` is the signed-in principal; rows they own are flagged ``mine``
    so the worklist can answer "what is on my desk?" rather than only "what is
    outstanding?"."""
    import time as _time

    from maverick.assessment import (
        custom_template_records,
        list_saved,
        list_templates,
    )

    base = {
        "finance": FINANCE_ASSESSMENT_TYPES,
        "privacy": PRIVACY_ASSESSMENT_TYPES,
        "security": SECURITY_ASSESSMENT_TYPES,
    }.get(department, frozenset())
    customs = custom_template_records()
    types = set(base) | {
        t for t, rec in customs.items() if rec.get("department", "privacy") == department
    }

    sessions = [s for s in list_saved() if s.get("type") in types]
    now = _time.time()
    me = (viewer or "").strip()
    for s in sessions:
        created = float(s.get("created_at") or 0)
        s["age_days"] = int((now - created) // 86400) if created else None
        nra = s.get("next_review_at")
        # Days until the scheduled re-review (negative = overdue).
        s["review_in_days"] = int((float(nra) - now) // 86400) if nra else None
        # Only a real signed-in principal owns rows. In auth-off single-user
        # mode `me` is empty, and an empty assignee must NOT then read as
        # "mine" -- that would make every unassigned record look owned.
        s["mine"] = bool(me) and s.get("assignee") == me
    open_rows = [s for s in sessions if s.get("status") in ("pending_review", "needs_more")]
    stats = {
        "total": len(sessions),
        "pending": sum(1 for s in sessions if s.get("status") == "pending_review"),
        "needs_more": sum(1 for s in sessions if s.get("status") == "needs_more"),
        "high_residual": sum(1 for s in sessions if s.get("residual_risk") == "high"),
        "review_due": sum(1 for s in sessions if s.get("review_due")),
        "mine": sum(1 for s in sessions if s.get("mine")),
        "unassigned": sum(1 for s in sessions if not s.get("assignee")),
        "oldest_open_days": (max((s["age_days"] or 0) for s in open_rows) if open_rows else None),
    }

    # At program volume (hundreds of records a year) the worklist stays
    # sharp: actionable rows first (open work + anything due for
    # re-review), then settled records by recency, capped — the hero stats
    # always count everything.
    def _rank(s: dict) -> tuple:
        actionable = s.get("status") in ("pending_review", "needs_more") or s.get("review_due")
        return (0 if actionable else 1, -(s.get("created_at") or 0))

    worklist = sorted(sessions, key=_rank)[:250]
    return {
        "sessions": sessions,
        "worklist": worklist,
        "stats": stats,
        "department": department,
        # Precedents: what the memory recalls from — recent completions.
        "precedents": sessions[:8],
        "templates": [
            {
                "type": t.type,
                "title": t.title,
                "framework": t.framework,
                "questions": len(t.questions),
                "custom": t.type in customs,
            }
            for t in list_templates()
            if t.type in types
        ],
    }


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request) -> HTMLResponse:
    """The Privacy workspace: the module view over the privacy team's
    assessment records — worklist with the inherent→residual pair, aging,
    open follow-ups, the precedent memory, the framework catalog, and the
    privacy ops record types (DPA reviews, AI registry, RoPA, DSARs).

    Operate-gated like /approvals: assessment records carry answer bodies and
    reviewer threads, a tier above viewer summaries.
    """
    require_permission(request, "operate")
    ctx = _workspace_ctx("privacy", viewer=caller_principal(request) or "")
    # Every register scan below is synchronous disk I/O; keep it off the
    # event loop in one threadpool hop.
    records, estate = await run_in_threadpool(_privacy_page_data)
    ctx["records"] = records
    ctx["estate"] = estate
    if records.get("dsar"):
        from . import people_directory

        # Who a request can be assigned to: people who may work privacy requests.
        ctx["dsar_assignees"] = await run_in_threadpool(people_directory.candidates, "operate")
    return templates.TemplateResponse(request, "privacy.html", ctx)


def _privacy_page_data() -> tuple[dict, dict]:
    """The Privacy workspace's data plane: privacy-ops records plus the
    estate registers (vendors, consent, data map), each its own opt-in."""

    from maverick import privacy_ops

    records = {
        "enabled": privacy_ops.enabled(),
        "kind": "privacy",
        "dpa": [],
        "ai": [],
        "ropa": [],
        "dsar": [],
        "incidents": [],
        "paper": [],
    }
    if records["enabled"]:
        records["dpa"] = privacy_ops.list_dpa_reviews()
        records["ai"] = privacy_ops.list_ai_systems()
        records["ropa"] = privacy_ops.list_ropa()
        records["dsar"] = privacy_ops.list_dsars()
        for row in records["dsar"]:
            row["answer"] = privacy_ops.dsar_answer(row)
        records["incidents"] = privacy_ops.list_incidents()
        records["paper"] = privacy_ops.list_paper_reviews()
        for rows in (
            records["dpa"],
            records["ai"],
            records["ropa"],
            records["dsar"],
            records["incidents"],
            records["paper"],
        ):
            for r in rows:
                created = float(r.get("created_at") or 0)
                r["created"] = _plain_labels.datetime_text(created, date_only=True) if created else "—"
        records["dsar_open"] = sum(
            1 for r in records["dsar"] if r.get("status") in ("open", "awaiting_erasure")
        )
        records["dsar_overdue"] = sum(1 for r in records["dsar"] if r.get("overdue"))
        records["incidents_open"] = sum(
            1 for r in records["incidents"] if r.get("status") in ("open", "notify")
        )
        records["incidents_breached"] = sum(
            1 for r in records["incidents"] if r.get("clock_breached"))
    from maverick import consent_registry, data_map, vendor_management
    estate = {
        "vendors_enabled": vendor_management.enabled(),
        "consent_enabled": consent_registry.enabled(),
        "data_map_enabled": data_map.enabled(),
        "vendors": [], "vendor_posture": {},
        "consent_posture": {},
        "assets": [], "data_map_posture": {},
        # The forms' vocab comes from the modules that enforce it, so a
        # new kind/status/channel never needs a template edit. "import"
        # is the importer's channel, not a manual-entry choice.
        "contract_kinds": vendor_management.CONTRACT_KINDS,
        "consent_statuses": consent_registry.STATUSES,
        "consent_channels": tuple(
            c for c in consent_registry.CHANNELS if c != "import"),
    }
    estate["renewals"] = {"overdue": [], "due_soon": []}
    estate["notices"] = []
    estate["notice_coverage"] = {}
    if estate["vendors_enabled"]:
        estate["vendors"] = vendor_management.list_vendors()
        estate["vendor_posture"] = vendor_management.vendor_posture()
        try:
            estate["renewals"] = vendor_management.contract_renewals()
        except Exception:
            pass
    if estate["consent_enabled"]:
        estate["consent_posture"] = consent_registry.consent_posture()
        try:
            estate["notices"] = consent_registry.list_notices()[:20]
            for notice in estate["notices"]:
                notice["published_date"] = _date(notice.get("published_at"))
            estate["notice_coverage"] = consent_registry.notice_coverage()
        except Exception:
            pass
    if estate["data_map_enabled"]:
        estate["assets"] = data_map.list_data_assets()
        estate["data_map_posture"] = data_map.data_map_posture()
    return records, estate


def _date(stamp) -> str:
    try:
        value = float(stamp or 0)
    except (TypeError, ValueError):
        return "—"
    return _plain_labels.datetime_text(value, date_only=True) if value else "—"


def _day(stamp) -> str:
    """The UTC calendar day of a deadline stamp ("2026-10-04"; "" when unset)."""
    try:
        value = float(stamp or 0)
    except (TypeError, ValueError):
        return ""
    return time.strftime("%Y-%m-%d", time.gmtime(value)) if value > 0 else ""


@app.get("/privacy/vendors/{vendor_id}", response_class=HTMLResponse)
async def vendor_detail_page(request: Request, vendor_id: str) -> HTMLResponse:
    """One vendor's full governed record: lifecycle, contracts and their
    renewal state, questionnaires (never their live form tokens), linked
    specialist records, and monitoring notes."""
    require_permission(request, "operate")
    import time as _time

    from maverick import vendor_management
    if not vendor_management.enabled():
        raise HTTPException(status_code=403,
                            detail="Vendor management is turned off. An administrator can turn it on from the Privacy workspace.")
    record = vendor_management.get_vendor(vendor_id[:64])
    if record is None:
        raise HTTPException(status_code=404, detail="That vendor could not be found.")
    questionnaire_unavailable = False
    questionnaire_statuses = {}
    if record.get("questionnaires"):
        try:
            checked = await run_in_threadpool(
                vendor_management.questionnaire_responses, vendor_id[:64]
            )
            questionnaire_statuses = {
                row["request_id"]: row
                for row in checked
            }
        except vendor_management.QuestionnaireResponsesUnavailable:
            questionnaire_unavailable = True
    record["registered_at_date"] = _date(record.get("registered_at"))
    now = _time.time()
    for c in record.get("contracts") or []:
        c["renews_date"] = _date(c.get("renews_at"))
        c["overdue"] = float(c.get("renews_at") or 0) < now
    for q in record.get("questionnaires") or []:
        # Core returns a non-authorizing request id; no live form address is
        # available on a read, even to this server-rendered page.
        status = questionnaire_statuses.get(q["request_id"])
        if status is None:
            questionnaire_unavailable = True
            q["status"] = "unavailable"
        else:
            q["status"] = status["status"]
            q["current_replies"] = status["reply_count"]
            q["past_replies"] = sum(old["reply_count"] for old in status["previous_links"])
            q["previous_count"] = len(status["previous_links"])
        q.pop("previous_links", None)  # never render earlier addresses either
        q["requested_at_date"] = _date(q.get("requested_at"))
    for n in record.get("monitoring_notes") or []:
        n["recorded_at_date"] = _date(n.get("recorded_at"))
    # Choices for the page's buttons: questionnaire templates and saved
    # assessments a person can link, so nothing is typed as an ID.
    from maverick.assessment import list_saved, list_templates

    try:
        questionnaire_types = [{"value": t.type, "label": t.title} for t in list_templates()]
    except Exception:
        questionnaire_types = []
    try:
        assessments = [
            {"value": s["id"], "label": f"{s.get('subject') or 'Assessment'} · {_idfmt.humanize(s.get('type'))} · {_date(s.get('created_at'))}"}
            for s in list_saved()[:200]
        ]
    except Exception:
        assessments = []
    titles = {t["value"]: t["label"] for t in questionnaire_types}
    for q in record.get("questionnaires") or []:
        q["title"] = titles.get(q.get("assessment_type")) or _idfmt.humanize(q.get("assessment_type"))
    labels = {a["value"]: a["label"] for a in assessments}
    for link in record.get("links") or []:
        link["label"] = labels.get(link.get("reference")) or link.get("reference")
    from .webhooks_api import record_alerts

    alerts: list[dict] = []
    for c in record.get("contracts") or []:
        alerts.extend(record_alerts("vendor_contract", f"{record.get('id')}:{c.get('kind')}"))
    alerts.sort(key=lambda a: float(a.get("sent_at") or 0), reverse=True)
    return templates.TemplateResponse(
        request, "vendor_detail.html",
        {"vendor": record, "questionnaire_types": questionnaire_types, "assessments": assessments,
         "questionnaire_unavailable": questionnaire_unavailable,
         "can_replace_questionnaire": has_permission(request, "admin"),
         "record_alerts": alerts})


@app.get("/privacy/dsar/{request_id}", response_class=HTMLResponse)
async def dsar_detail_page(request: Request, request_id: str) -> HTMLResponse:
    """One DSAR with its fulfillment trail: the SLA clock, identity
    verification, collection sources, and the response link's delivery
    state (reads used against the cap; never the token itself)."""
    require_permission(request, "operate")
    import time as _time

    from maverick import dsar_fulfillment, privacy_ops

    from .feature_gate import feature_off

    if not privacy_ops.enabled():
        raise feature_off("privacy_ops", "The privacy register")
    record = privacy_ops.get_dsar(request_id[:64])
    if record is None or "status" not in record:
        raise HTTPException(status_code=404, detail="no such DSAR")
    record = dict(record)
    now = _time.time()
    record.update(privacy_ops.dsar_clock(record, now=now))
    record["received_date"] = _date(record.get("received_at") or record.get("created_at"))
    # Deadlines are calendar days: the page shows that same day in each
    # reader's own style (|datetime('date')), never shifted by a time zone.
    record["due_day"] = _day(record.get("effective_due_at"))
    record["acknowledge_day"] = _day(record.get("acknowledge_by"))
    record["extended_day"] = _day(record.get("extended_until"))
    from maverick import rights_deadlines

    regime = rights_deadlines.REGIMES.get(str(record.get("jurisdiction") or ""))
    record["jurisdiction_name"] = regime["name"] if regime else ""
    record["citation"] = regime["citation"] if regime else ""
    fulfillment = None
    fulfillment_enabled = dsar_fulfillment.enabled()
    if fulfillment_enabled:
        fulfillment = dsar_fulfillment.get_fulfillment(record["id"])
    # Which secure-link step the "Completed" notice can point to.
    fulfillment_state = (
        "off" if not fulfillment_enabled else "not_started" if not fulfillment
        else "ready" if (fulfillment.get("identity") or {}).get("status") == "verified"
        else "unverified")
    from maverick import public_rights_form

    from .webhooks_api import record_alerts

    return templates.TemplateResponse(
        request, "dsar_detail.html",
        {"dsar": record, "fulfillment": fulfillment,
         "fulfillment_enabled": fulfillment_enabled,
         "fulfillment_state": fulfillment_state,
         "record_alerts": record_alerts("dsar", record["id"]),
         "can_admin": has_permission(request, "admin"),
         "can_manage_email": has_global_permission(request, "admin"),
         "can_record_package_handoff": has_permission(request, "operate") and has_permission(request, "audit"),
         "notices": public_rights_form.notice_log(record),
         "answer": privacy_ops.dsar_answer(record)})


@app.get("/consent", response_class=HTMLResponse)
async def consent_preferences_page(request: Request) -> HTMLResponse:
    """Consumer consent operations, separate from agent-action approvals."""
    require_permission(request, "operate")
    from maverick import consent_analytics, consent_preferences, consent_registry

    return templates.TemplateResponse(
        request,
        "consent_preferences.html",
        {
            "consent_preferences_enabled": consent_preferences.enabled(),
            "consent_analytics_enabled": consent_analytics.enabled(),
            "consent_registry_enabled": consent_registry.enabled(),
            "consent_can_admin": has_global_permission(request, "admin"),
        },
    )


@app.get("/consent/publishing", response_class=HTMLResponse)
async def consent_publishing_page(request: Request) -> HTMLResponse:
    """Versioned public experience configuration, promotion, and rollback."""
    require_permission(request, "operate")
    from collections.abc import Mapping

    from maverick import config

    try:
        product = config.load_config().get("consent_preferences", {})
    except Exception:
        product = {}
    publishing = product.get("publishing") if isinstance(product, Mapping) else None
    enabled = (
        isinstance(product, Mapping)
        and product.get("enable") is True
        and isinstance(publishing, Mapping)
        and publishing.get("enable") is True
    )
    return templates.TemplateResponse(
        request,
        "consent_publishing.html",
        {
            "consent_publishing_enabled": enabled,
            "report_download_context": _conversation_context(request),
            "consent_can_admin": has_global_permission(request, "admin"),
        },
    )


@app.get("/consent/experiments", response_class=HTMLResponse)
async def consent_experiments_page(request: Request) -> HTMLResponse:
    """Governed consent presentation experiments and bounded analytics."""

    require_permission(request, "operate")
    from .consent_experiments_api import experiments_enabled_for_page

    return templates.TemplateResponse(
        request,
        "consent_experiments.html",
        {
            "consent_experiments_enabled": experiments_enabled_for_page(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/consent/delivery", response_class=HTMLResponse)
async def consent_delivery_page(request: Request) -> HTMLResponse:
    """Durable signed preference-delivery operations and recovery."""
    require_permission(request, "operate")
    from maverick import consent_delivery

    return templates.TemplateResponse(
        request,
        "consent_delivery.html",
        {
            "consent_delivery_enabled": consent_delivery.enabled(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
            "consent_can_operate": has_global_permission(request, "operate"),
        },
    )


@app.get("/consent/public-clients", response_class=HTMLResponse)
async def consent_public_clients_page(request: Request) -> HTMLResponse:
    """Origin-bound public SDK enrollment and capability revocation."""
    require_permission(request, "operate")
    from .consent_public_admin_api import _enabled

    return templates.TemplateResponse(
        request,
        "consent_public_clients.html",
        {
            "consent_public_clients_enabled": _enabled(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/consent/profile-data", response_class=HTMLResponse)
async def consent_profile_data_page(request: Request) -> HTMLResponse:
    """Governed profile-data catalogs and progressive prompt journeys."""

    require_permission(request, "operate")
    from .consent_profile_data_api import profile_data_enabled_for_page

    return templates.TemplateResponse(
        request,
        "consent_profile_data.html",
        {
            "consent_profile_data_enabled": profile_data_enabled_for_page(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/consent/scan-inventory", response_class=HTMLResponse)
async def consent_scan_inventory_page(request: Request) -> HTMLResponse:
    """Scheduled, reviewed-only browser tracker discovery operations."""

    require_permission(request, "operate")
    from .consent_scan_inventory_api import _enabled

    return templates.TemplateResponse(
        request,
        "consent_scan_inventory.html",
        {
            "consent_scan_inventory_enabled": _enabled(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/consent/scan-notice-proposals", response_class=HTMLResponse)
async def consent_scan_notice_proposals_page(request: Request) -> HTMLResponse:
    """Reviewed scan-to-structured-disclosure proposal workbench."""

    require_permission(request, "operate")
    from .consent_scan_notice_proposals_api import (
        scan_notice_proposals_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "consent_scan_notice_proposals.html",
        {
            "consent_scan_notice_proposals_enabled": (scan_notice_proposals_enabled_for_page()),
            "consent_can_admin": has_global_permission(request, "admin"),
        },
    )


def _trust_center_branding_enabled() -> bool:
    try:
        from .trust_center_branding_api import trust_center_branding_enabled

        return trust_center_branding_enabled() is True
    except Exception:
        return False


@app.get("/consent/trust-center-authority", response_class=HTMLResponse)
async def consumer_trust_center_authority_page(request: Request) -> HTMLResponse:
    """Digest-only Trust Center context and four-eyes authority workbench."""

    require_permission(request, "operate")
    from .consumer_trust_center_authority_api import (
        consumer_trust_center_authority_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "consumer_trust_center_authority.html",
        {
            "consumer_trust_center_authority_enabled": (
                consumer_trust_center_authority_enabled_for_page()
            ),
            "trust_center_branding_enabled": _trust_center_branding_enabled(),
            "consent_can_admin": has_global_permission(request, "admin"),
            "consent_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/data-use", response_class=HTMLResponse)
def data_use_governance_page(request: Request) -> HTMLResponse:
    """Provider-neutral data-use policy authority and compiler workspace."""
    require_permission(request, "operate")
    from collections.abc import Mapping

    from maverick import config

    try:
        loaded = config.load_config()
        section = loaded.get("data_use_governance", {})
    except Exception:
        loaded, section = {}, {}
    compiler = section.get("compiler") if isinstance(section, Mapping) else None
    from maverick.compliance_catalog import module_status

    try:
        # Requests pick a project from the person's own projects.
        projects = [
            {"value": f"project-{item['id']}", "label": str(item.get("name") or "")}
            for item in _world().list_projects(owner=goal_owner_filter(request))
        ]
    except Exception:
        projects = []
    return templates.TemplateResponse(
        request,
        "data_use_governance.html",
        {
            "data_use_enabled": config.data_use_governance_enabled(loaded),
            "data_use_compiler_enabled": (
                isinstance(compiler, Mapping) and compiler.get("enable") is True
            ),
            "acm_module_status": module_status("/data-use"),
            "data_use_projects": projects,
            "data_use_can_admin": has_global_permission(request, "admin"),
        },
    )


@app.get("/data-use/providers", response_class=HTMLResponse)
async def data_use_providers_page(request: Request) -> HTMLResponse:
    """Controlled Snowflake and Databricks enrollment/execution workspace."""

    require_permission(request, "operate")
    from collections.abc import Mapping

    from maverick import config

    try:
        loaded = config.load_config()
        section = loaded.get("data_use_governance", {})
    except Exception:
        section = {}
    enforcement = section.get("enforcement") if isinstance(section, Mapping) else None

    def provider_enabled(name: str) -> bool:
        selected = section.get(name) if isinstance(section, Mapping) else None
        return bool(isinstance(selected, Mapping) and selected.get("enable") is True)

    return templates.TemplateResponse(
        request,
        "data_use_providers.html",
        {
            "data_use_enforcement_enabled": bool(
                isinstance(enforcement, Mapping) and enforcement.get("enable") is True
            ),
            "data_use_snowflake_enabled": provider_enabled("snowflake"),
            "data_use_databricks_enabled": provider_enabled("databricks"),
            "data_use_can_admin": has_global_permission(request, "admin"),
        },
    )


@app.get("/privacy/data-discovery", response_class=HTMLResponse)
async def privacy_data_discovery_page(request: Request) -> HTMLResponse:
    """Bounded personal-data discovery, review, and RoPA delivery workspace."""

    require_permission(request, "view")
    from maverick import privacy_data_discovery
    from maverick.compliance_catalog import module_status
    from maverick.paths import current_tenant_id_strict

    from .auth import has_global_permission

    if current_tenant_id_strict() is None:
        # Browsers get the workspace picker from the shared handler (which also
        # sets up a first workspace for a signed-in administrator).
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using privacy data discovery",
        )
    if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
        raise HTTPException(
            status_code=404,
            detail="privacy data discovery workbench unavailable",
        )
    nonce = secrets.token_urlsafe(18)
    response = templates.TemplateResponse(
        request,
        "privacy_data_discovery.html",
        {
            "privacy_data_discovery_enabled": privacy_data_discovery.enabled(),
            "privacy_data_discovery_api_base": "/api/v1/privacy/data-discovery",
            "privacy_data_discovery_page_path": "/privacy/data-discovery",
            "privacy_data_discovery_can_operate": has_permission(request, "operate"),
            "privacy_data_discovery_can_audit": has_permission(request, "audit"),
            "privacy_data_discovery_can_admin": has_global_permission(request, "admin"),
            "csp_style_nonce": nonce,
            "acm_module_status": module_status("/privacy/data-discovery"),
        },
    )
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self'; object-src 'none'; script-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; worker-src 'none'"
    )
    return response


@app.get("/privacy/regulatory-intelligence", response_class=HTMLResponse)
async def privacy_regulatory_intelligence_page(request: Request) -> HTMLResponse:
    """Licensed-source privacy research, trackers, alerts, and reports."""

    require_permission(request, "operate")
    from maverick import privacy_regulatory_intelligence

    return templates.TemplateResponse(
        request,
        "privacy_regulatory_intelligence.html",
        {
            "privacy_regulatory_intelligence_enabled": (privacy_regulatory_intelligence.enabled()),
            "can_admin": has_global_permission(request, "admin"),
        },
    )


@app.get("/privacy/rights-orchestration", response_class=HTMLResponse)
async def privacy_rights_orchestration_page(request: Request) -> HTMLResponse:
    """Provider-neutral privacy-rights case orchestration workbench."""

    require_permission(request, "operate")
    from .privacy_rights_orchestration_api import (
        privacy_rights_orchestration_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "privacy_rights_orchestration.html",
        {
            "privacy_rights_orchestration_enabled": (
                privacy_rights_orchestration_enabled_for_page()
            ),
            "can_admin": has_global_permission(request, "admin"),
            "can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/privacy/rights-consumer-delivery", response_class=HTMLResponse)
async def privacy_rights_consumer_delivery_page(request: Request) -> HTMLResponse:
    """One-time, digest-only privacy-rights delivery workbench."""

    require_permission(request, "operate")
    from .privacy_rights_consumer_delivery_api import (
        privacy_rights_consumer_delivery_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "privacy_rights_consumer_delivery.html",
        {
            "privacy_rights_consumer_delivery_enabled": (
                privacy_rights_consumer_delivery_enabled_for_page()
            ),
            "can_admin": has_global_permission(request, "admin"),
            "can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/privacy/rights-form", response_class=HTMLResponse)
async def privacy_rights_form_page(request: Request) -> HTMLResponse:
    """Administration of the public rights-request form: properties, the
    public link and embed snippet, and the email templates."""
    require_permission(request, "operate")
    from maverick import public_rights_form

    return templates.TemplateResponse(
        request, "privacy_rights_form.html",
        {"enabled": public_rights_form.enabled(),
         "can_admin": has_global_permission(request, "admin")},
    )


@app.get("/privacy/notice-governance", response_class=HTMLResponse)
async def privacy_notice_governance_page(request: Request) -> HTMLResponse:
    """Approval-gated privacy-notice publication-intent workbench."""

    require_permission(request, "operate")
    from .privacy_notice_governance_api import (
        privacy_notice_governance_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "privacy_notice_governance.html",
        {
            "privacy_notice_governance_enabled": (privacy_notice_governance_enabled_for_page()),
            "can_admin": has_global_permission(request, "admin"),
            "can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/privacy/board", response_class=HTMLResponse)
async def privacy_board_page(request: Request) -> HTMLResponse:
    """The privacy command center: the whole program on one live board --
    KPI tiles with deltas, the risk mix and burn-down, 12 months of
    throughput, DSAR SLA runway, transfer safeguards, AI Act tiers, and
    posture gauges, with click-to-cross-filter. Same operate floor as the
    workspace; the numbers arrive from GET /api/v1/privacy/board."""
    require_permission(request, "operate")
    return templates.TemplateResponse(request, "privacy_board.html", {})


@app.get("/privacy/report", response_class=HTMLResponse)
async def privacy_report_page(request: Request) -> HTMLResponse:
    """The privacy program report: a print-friendly board pack over every
    register. Same operate floor as the workspace it summarizes."""
    require_permission(request, "operate")

    from maverick import privacy_ops

    if not privacy_ops.enabled():
        raise HTTPException(status_code=404, detail="privacy ops are disabled")
    report = privacy_ops.program_report()
    report["generated"] = _plain_labels.datetime_text(report["generated_at"])
    return templates.TemplateResponse(request, "privacy_report.html", {"r": report})


@app.get("/third-party/intelligence", response_class=HTMLResponse)
async def third_party_intelligence_page(request: Request) -> HTMLResponse:
    """Governed screening, EDD, monitoring, delivery, and risk exchange."""

    require_permission(request, "operate")
    from .third_party_intelligence_api import (
        third_party_intelligence_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "third_party_intelligence.html",
        {
            "third_party_intelligence_enabled": (third_party_intelligence_enabled_for_page()),
            "intelligence_can_admin": has_global_permission(request, "admin"),
            "intelligence_can_audit": has_permission(request, "audit"),
        },
    )


@app.get("/governance-agents", response_class=HTMLResponse)
async def governance_agents_page(request: Request) -> HTMLResponse:
    """Closed packaged agents over server-resolved governance evidence."""

    require_permission(request, "view")
    from .auth import has_global_permission
    from .governance_agents_api import governance_agents_enabled_for_page

    response = templates.TemplateResponse(
        request,
        "governance_agents.html",
        {
            "governance_agents_enabled": governance_agents_enabled_for_page(),
            "governance_can_operate": has_permission(request, "operate"),
            "governance_can_admin": has_global_permission(request, "admin"),
            "governance_can_audit": has_global_permission(request, "audit"),
        },
    )
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@app.get("/third-party/lifecycle", response_class=HTMLResponse)
async def third_party_lifecycle_page(request: Request) -> HTMLResponse:
    """Conditional assessments, lifecycle changes, and governed offboarding."""

    require_permission(request, "operate")
    from .third_party_lifecycle_api import third_party_lifecycle_enabled_for_page

    return templates.TemplateResponse(
        request,
        "third_party_lifecycle.html",
        {
            "third_party_lifecycle_enabled": (third_party_lifecycle_enabled_for_page()),
            "lifecycle_can_admin": has_global_permission(request, "admin"),
            "lifecycle_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/third-party/collaboration", response_class=HTMLResponse)
async def third_party_collaboration_page(request: Request) -> HTMLResponse:
    """Internal control plane for governed external-vendor collaboration."""

    require_permission(request, "operate")
    from .third_party_collaboration_api import (
        third_party_collaboration_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "third_party_collaboration.html",
        {
            "third_party_collaboration_enabled": (third_party_collaboration_enabled_for_page()),
            "collaboration_can_admin": has_permission(request, "admin"),
            "collaboration_can_audit": has_permission(request, "audit"),
        },
    )


@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request) -> HTMLResponse:
    """Security & GRC department workspace over assessments and durable
    control-program records. Record contents are operate-tier data."""
    require_permission(request, "operate")
    from maverick import security_ops

    ctx = _workspace_ctx("security", viewer=caller_principal(request) or "")
    records = {
        "enabled": security_ops.enabled(),
        "kind": "security",
        "controls": [],
        "evidence": [],
        "risks": [],
        "poams": [],
        "vendors": [],
        "policies": [],
        "incidents": [],
        "audits": [],
    }
    report: dict = {}
    framework_labels = (
        ("soc2", "SOC 2"),
        ("iso27001", "ISO 27001"),
        ("nist_csf", "NIST CSF 2.0"),
        ("nist_800_53", "NIST 800-53"),
        ("cis_v8", "CIS v8.1"),
        ("pci_dss", "PCI DSS 4.0.1"),
        ("hipaa", "HIPAA"),
        ("cmmc_l2", "CMMC L2"),
        ("fedramp_moderate", "FedRAMP Class C"),
    )
    insights = {
        "coverage_percent": 0.0,
        "framework_coverage": [],
        "control_status": {},
        "open_poams": [],
        "exceptions_due": [],
        "crosswalk_links": 0,
        "crosswalk_frameworks": [{"key": key, "label": label} for key, label in framework_labels],
        "crosswalk_matrix": [],
    }
    if records["enabled"]:
        records.update(
            {
                "controls": security_ops.list_controls(),
                "evidence": security_ops.list_evidence(),
                "risks": security_ops.list_risks(),
                "poams": security_ops.list_poams(),
                "vendors": security_ops.list_vendor_assessments(),
                "policies": security_ops.list_policies(),
                "incidents": security_ops.list_incidents(),
                "audits": security_ops.list_audit_engagements(),
            }
        )
        report = security_ops.program_report()
        for control in records["controls"]:
            status = str(control.get("implementation_status") or "unknown")
            insights["control_status"][status] = insights["control_status"].get(status, 0) + 1
            mappings = control.get("crosswalk") or control.get("mappings") or []
            insights["crosswalk_links"] += (
                len(mappings) if isinstance(mappings, (list, tuple, dict)) else 0
            )
        overall_readiness = security_ops.readiness_report()
        insights["coverage_percent"] = overall_readiness["coverage_percent"]
        insights["framework_coverage"] = [
            {
                **security_ops.readiness_report(key),
                "label": label,
            }
            for key, label in framework_labels
        ]
        insights["crosswalk_matrix"] = security_ops.control_crosswalk()
        insights["open_poams"] = [
            row
            for row in records["poams"]
            if row.get("status") not in {"closed", "complete", "accepted"}
        ][:10]
        insights["exceptions_due"] = [
            row
            for row in records["risks"]
            if row.get("exception_due") or row.get("exception_expired")
        ][:10]
    ctx.update({"records": records, "program": report, "insights": insights})
    ctx["security_can_manage_hunters"] = has_global_permission(request, "admin")
    from .immune_actions_api import people_choices
    from .security_page_helpers import attack_choices

    ctx["people"] = people_choices()
    ctx["attack_techniques"] = attack_choices()
    try:
        ctx["clocks"] = [
            {"value": c["key"], "label": f"{c.get('title') or c['key']} ({c.get('jurisdiction', '')})".replace(" ()", "")}
            for c in security_ops.list_regulatory_clock_packs()
        ] if records["enabled"] else []
    except Exception:  # pragma: no cover - the incident form still opens without clocks
        ctx["clocks"] = []
    return templates.TemplateResponse(request, "security.html", ctx)


@app.get("/security/report", response_class=HTMLResponse)
async def security_report_page(request: Request) -> HTMLResponse:
    """Print-friendly security readiness and board report."""
    require_permission(request, "operate")
    from maverick import security_ops

    if not security_ops.enabled():
        raise HTTPException(status_code=404, detail="security ops are disabled")
    report = security_ops.program_report()
    generated_at = report.get("generated_at")
    if isinstance(generated_at, (int, float)):
        report["generated"] = _plain_labels.datetime_text(generated_at)
    else:
        report["generated"] = "unknown"
    # The click-through must carry substance: each control with what it does,
    # its governed status, scope decision, owner, and the reviewed evidence
    # cited behind that status (joined here so the template stays dumb).
    evidence_index = {str(row.get("id")): row for row in security_ops.list_evidence()}
    control_rows = []
    for row in sorted(
        security_ops.list_controls(),
        key=lambda item: (
            str(item.get("framework") or ""),
            str(item.get("control_id") or item.get("id") or ""),
        ),
    ):
        cited = []
        for evidence_id in row.get("evidence_ids") or []:
            evidence = evidence_index.get(str(evidence_id)) or {}
            cited.append(
                {
                    "id": evidence_id,
                    "title": evidence.get("title") or evidence_id,
                    "status": evidence.get("status") or "unknown",
                    "source": evidence.get("source") or "",
                }
            )
        control_rows.append({**row, "cited_evidence": cited})
    from .security_page_helpers import FRAMEWORK_LABELS

    return templates.TemplateResponse(
        request,
        "security_report.html",
        {"r": report, "controls": control_rows, "framework_labels": FRAMEWORK_LABELS},
    )


async def _model_risk_page_data(module: Any) -> dict[str, Any]:
    enabled = module.enabled()
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    if enabled:
        results = await asyncio.gather(
            run_in_threadpool(module.list_inventory),
            run_in_threadpool(module.list_evidence),
            run_in_threadpool(module.findings),
            return_exceptions=True,
        )
        for label, result in zip(
            ("assets", "evidence", "findings"),
            results,
            strict=True,
        ):
            if isinstance(result, Exception):
                errors[label] = f"Model-risk {label} are temporarily unavailable."
            elif label == "assets":
                assets = result
            elif label == "evidence":
                evidence = result
            else:
                findings = result
    return {
        "enabled": enabled,
        "assets": assets,
        "evidence": evidence,
        "findings": findings,
        "errors": errors,
    }


async def _governance_extensions_page_data(
    vendor: Any,
    drift: Any,
    topology: Any,
    officer: Any,
) -> dict[str, Any]:
    """Bounded status for additive assurance workflows.

    The page does not load vendor document text, raw drift samples, or topology
    configuration.  Detailed records are reachable only through their
    authenticated API routes.
    """

    data: dict[str, Any] = {
        "vendor_items": [],
        "vendor_error": "",
        "drift_items": [],
        "drift_enabled": False,
        "drift_error": "",
        "topology_enabled": False,
        "topology_error": "",
    }
    try:
        listing = await run_in_threadpool(vendor.list_vendor_assessments, limit=20)
        data["vendor_items"] = list(listing.get("items") or [])[:20]
    except Exception as exc:
        data["vendor_error"] = (
            "Choose a workspace first to see supplier reviews."
            if "tenant" in str(exc).lower()
            else "AI vendor assessments are temporarily unavailable."
        )
    data["drift_enabled"] = drift.enabled()
    if data["drift_enabled"]:
        try:
            evidence = await run_in_threadpool(officer.list_evidence)
            data["drift_items"] = [
                row for row in evidence
                if row.get("evidence_kind") == "drift_monitoring"
            ][:20]
        except Exception:
            data["drift_error"] = "Drift evidence is temporarily unavailable."
    data["topology_enabled"] = topology.enabled()
    if not data["topology_enabled"]:
        data["topology_error"] = "Agent topology is disabled."
    return data


async def _ai_incident_page_data(module: Any) -> dict[str, Any]:
    """Bounded Art. 73 clock status; report drafts stay behind the API."""

    enabled = module.enabled()
    rows: list[dict[str, Any]] = []
    overdue = 0
    error = ""
    if enabled:
        try:
            declarations = await run_in_threadpool(module.list_declarations)
        except Exception:
            error = "Serious-incident declarations are temporarily unavailable."
        else:
            for record in declarations[:20]:
                clock = record.get("clock") or {}
                is_overdue = bool(clock.get("overdue"))
                remaining = float(clock.get("seconds_remaining") or 0.0)
                rows.append(
                    {
                        "id": record.get("id"),
                        "category": record.get("category"),
                        "member_state": record.get("member_state"),
                        "status": record.get("status"),
                        "deadline_citation": record.get("deadline_citation"),
                        "clock_label": (
                            {"initial_reported": "First report filed; full report to follow",
                             "complete_reported": "Full report filed", "withdrawn": "Withdrawn"}
                            .get(record.get("status"))
                            or ("OVERDUE" if is_overdue else f"{remaining / 86_400:.1f}d left")
                        ),
                        "overdue": is_overdue,
                        "revision": record.get("revision"),
                    }
                )
            overdue = sum(1 for row in rows if row["overdue"])
    return {
        "enabled": enabled,
        "declarations": rows,
        "overdue": overdue,
        "error": error,
    }


async def _portfolio_risk_page_data(module: Any) -> dict[str, Any]:
    enabled = module.enabled()
    report: dict[str, Any] = {}
    snapshots: list[dict[str, Any]] = []
    error = ""
    if enabled:
        report_result, snapshots_result = await asyncio.gather(
            run_in_threadpool(module.current_report),
            run_in_threadpool(module.list_snapshots),
            return_exceptions=True,
        )
        if isinstance(report_result, Exception):
            error = (
                "Portfolio risk could not be calculated from a stable governed "
                "source snapshot. No score is shown."
            )
        else:
            report = report_result
        if isinstance(snapshots_result, Exception):
            error = error or "Quarterly portfolio snapshots are temporarily unavailable."
        else:
            snapshots = snapshots_result
    return {
        "enabled": enabled,
        "report": report,
        "snapshots": snapshots,
        "error": error,
    }


async def _red_team_page_data(module: Any, external_agents: Any) -> dict[str, Any]:
    enabled = module.enabled()
    campaigns: list[dict[str, Any]] = []
    agents: list[dict[str, Any]] = []
    error = ""
    if enabled:
        campaign_result, roster_result = await asyncio.gather(
            run_in_threadpool(module.list_campaigns, limit=20),
            run_in_threadpool(external_agents.roster),
            return_exceptions=True,
        )
        if isinstance(campaign_result, Exception):
            error = "Red-team campaign records are temporarily unavailable."
        else:
            campaigns = campaign_result["items"]
        if isinstance(roster_result, Exception):
            error = error or "The external-agent roster is temporarily unavailable."
        else:
            agents = [row for row in roster_result if row.get("active") is True]
    return {
        "enabled": enabled,
        "campaigns": campaigns,
        "agents": agents,
        "error": error,
    }


async def _ai_inventory_page_data(
    module: Any,
    model_risk_assets: list[dict[str, Any]],
) -> dict[str, Any]:
    enabled = module.enabled()
    assets: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    statuses: dict[str, Any] = {}
    connectors: list[str] = []
    error = ""
    if enabled:
        try:
            inventory_config = module.get_ai_inventory_config()
            connectors = list(inventory_config.get("connectors") or [])
            results = await asyncio.gather(
                run_in_threadpool(module.list_discovered_assets),
                run_in_threadpool(module.list_discovery_runs, limit=50),
                *(
                    run_in_threadpool(module.connector_status, connector)
                    for connector in connectors
                ),
                return_exceptions=True,
            )
            asset_result, run_result, *status_results = results
            if isinstance(asset_result, Exception) or isinstance(run_result, Exception):
                raise RuntimeError("inventory governed records unavailable")
            observation_index = {
                row.get("asset_id"): row for row in model_risk_assets
            }
            for state_row in asset_result:
                row = dict(state_row)
                observation = observation_index.get(row.get("asset_id")) or {}
                row["governed_display_name"] = observation.get("display_name")
                row["governed_version_digest"] = observation.get("version_digest")
                assets.append(row)
            runs = run_result
            for connector, result in zip(connectors, status_results, strict=True):
                statuses[connector] = (
                    None if isinstance(result, Exception) else result
                )
        except Exception as exc:
            if "active tenant" in str(exc).lower():
                error = (
                    "Choose a workspace first to see discovered AI systems. "
                    "Nothing was read."
                )
            else:
                error = "AI inventory records are temporarily unavailable."
    return {
        "enabled": enabled,
        "assets": assets,
        "runs": runs,
        "statuses": statuses,
        "connectors": connectors,
        "error": error,
    }


async def _policy_pack_page_data(module: Any) -> dict[str, Any]:
    enabled = module.enabled()
    bundled: dict[str, dict[str, Any]] = {}
    catalog: dict[str, Any] = {"items": [], "count": 0}
    channels: dict[str, Any] = {"items": [], "count": 0}
    subscriptions: dict[str, Any] = {"items": [], "count": 0}
    error = ""
    if enabled:
        results = await asyncio.gather(
            run_in_threadpool(module.bundled_summaries),
            run_in_threadpool(module.list_catalog),
            run_in_threadpool(module.list_channels),
            run_in_threadpool(module.list_subscriptions),
            return_exceptions=True,
        )
        bundled_result, catalog_result, channel_result, subscription_result = results
        if isinstance(bundled_result, Exception):
            error = "Bundled policy-pack manifests are unavailable."
        else:
            bundled = bundled_result
        if isinstance(catalog_result, Exception):
            error = error or "The policy-pack catalog is temporarily unavailable."
        else:
            catalog = catalog_result
        if isinstance(channel_result, Exception):
            error = error or "Active policy-pack channels are temporarily unavailable."
        else:
            channels = channel_result
        if isinstance(subscription_result, Exception):
            error = error or "Select a workspace to view policy-pack subscriptions."
        else:
            subscriptions = subscription_result
    return {
        "enabled": enabled,
        "bundled": bundled,
        "catalog": catalog,
        "channels": channels,
        "subscriptions": subscriptions,
        "error": error,
    }


async def _evidence_gateway_page_data(module: Any) -> dict[str, Any]:
    enabled = module.enabled()
    error = ""
    error_action = ""
    panel_errors: dict[str, str] = {}
    summary: dict[str, Any] = {}
    policies: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    impacts: list[dict[str, Any]] = []
    impact_page: dict[str, Any] = {
        "next_cursor": None,
        "snapshot_total": 0,
        "count": 0,
        "status": None,
        "pending_first": True,
    }
    if enabled:
        results = await asyncio.gather(
            run_in_threadpool(module.summary),
            run_in_threadpool(module.list_policies),
            run_in_threadpool(module.list_interaction_receipts, limit=100),
            run_in_threadpool(
                module.list_regulatory_impacts_page,
                limit=100,
                pending_first=True,
            ),
            return_exceptions=True,
        )
        summary_result, policy_result, receipt_result, impact_result = results
        if isinstance(summary_result, Exception):
            if (
                type(summary_result).__name__ == "EvidenceGatewayStateError"
                and str(summary_result)
                == "AI evidence gateway records require an explicit tenant scope"
            ):
                error = (
                    "Choose a workspace first to see evidence. "
                    "Nothing was read."
                )
                error_action = (
                    "Pick a workspace from the workspace menu, then reload this "
                    "page. If there is no workspace to pick, ask an administrator."
                )
            else:
                error = (
                    "Gateway records could not be loaded safely. "
                    "No readiness conclusion is available."
                )
                error_action = (
                    "Use the built-in health checks on the Get started page "
                    "to identify the blocker, then reload this cockpit."
                )
            panel_errors["summary"] = error
        else:
            summary = summary_result
        if isinstance(policy_result, Exception):
            panel_errors["policies"] = (
                "Policy and model bindings are temporarily unavailable."
            )
        else:
            policies = policy_result
        if isinstance(receipt_result, Exception):
            panel_errors["receipts"] = (
                "Interaction receipts are temporarily unavailable."
            )
        else:
            receipts = receipt_result
        if isinstance(impact_result, Exception):
            panel_errors["impacts"] = (
                "Regulatory impacts are temporarily unavailable."
            )
        else:
            impact_page = impact_result
            impacts = list(impact_page["items"])
    from .operator_cockpit import display_timestamp, gateway_view

    receipt_rows = []
    for receipt in receipts[:100]:
        row = dict(receipt)
        row["issued_display"] = display_timestamp(row.get("issued_at") or row.get("created_at"))
        receipt_rows.append(row)
    view = gateway_view(summary, policies, receipts, impacts)
    if "maverick" in str(view["next_action"].get("code", "")).lower():
        view["next_action"]["code"] = ""
    return {
        "enabled": enabled,
        "error": error,
        "error_action": error_action,
        "panel_errors": panel_errors,
        "summary": summary,
        "policies": policies,
        "receipts": receipt_rows,
        "impacts": impacts,
        "impact_page": impact_page,
        "view": view,
    }


@app.get("/security/assurance", response_class=HTMLResponse)
async def model_risk_assurance_page(request: Request) -> HTMLResponse:
    """Governed AI evidence gateway and model-risk operator cockpit."""
    require_permission(request, "operate")
    from maverick import (
        agent_topology,
        ai_evidence_gateway,
        ai_incident_reporting,
        ai_inventory,
        ai_vendor_risk,
        drift_monitoring,
        external_agents,
        model_risk_assurance,
        policy_packs,
        portfolio_risk,
        red_team_assurance,
    )

    from .auth import has_global_permission

    model_data = await _model_risk_page_data(model_risk_assurance)
    model_risk_enabled = model_data["enabled"]
    model_risk_errors = model_data["errors"]
    assets = model_data["assets"]
    evidence = model_data["evidence"]
    findings = model_data["findings"]

    extensions_data = await _governance_extensions_page_data(
        ai_vendor_risk,
        drift_monitoring,
        agent_topology,
        model_risk_assurance,
    )

    portfolio_data = await _portfolio_risk_page_data(portfolio_risk)
    portfolio_enabled = portfolio_data["enabled"]
    portfolio_report = portfolio_data["report"]
    portfolio_snapshots = portfolio_data["snapshots"]
    portfolio_error = portfolio_data["error"]

    ai_incident_data = await _ai_incident_page_data(ai_incident_reporting)

    red_team_data = await _red_team_page_data(
        red_team_assurance,
        external_agents,
    )
    red_team_enabled = red_team_data["enabled"]
    red_team_campaigns = red_team_data["campaigns"]
    red_team_agents = red_team_data["agents"]
    red_team_error = red_team_data["error"]

    inventory_data = await _ai_inventory_page_data(ai_inventory, assets)
    ai_inventory_enabled = inventory_data["enabled"]
    ai_inventory_assets = inventory_data["assets"]
    ai_inventory_runs = inventory_data["runs"]
    ai_inventory_statuses = inventory_data["statuses"]
    ai_inventory_connectors = inventory_data["connectors"]
    ai_inventory_error = inventory_data["error"]

    policy_data = await _policy_pack_page_data(policy_packs)
    policy_packs_enabled = policy_data["enabled"]
    policy_pack_bundled = policy_data["bundled"]
    policy_pack_catalog = policy_data["catalog"]
    policy_pack_channels = policy_data["channels"]
    policy_pack_subscriptions = policy_data["subscriptions"]
    policy_pack_error = policy_data["error"]

    gateway_data = await _evidence_gateway_page_data(ai_evidence_gateway)
    gateway_enabled = gateway_data["enabled"]
    gateway_error = gateway_data["error"]
    gateway_error_action = gateway_data["error_action"]
    gateway_panel_errors = gateway_data["panel_errors"]
    gateway_summary = gateway_data["summary"]
    policies = gateway_data["policies"]
    receipt_rows = gateway_data["receipts"]
    regulatory_impacts = gateway_data["impacts"]
    impact_page = gateway_data["impact_page"]
    view = gateway_data["view"]

    return templates.TemplateResponse(
        request,
        "model_risk_assurance.html",
        {
            "model_risk_enabled": model_risk_enabled,
            "work_details_available": page_visible(request, "/work-details"),
            "model_risk_totals": {
                "assets": len(assets),
                "evidence": len(evidence),
                "findings": len(findings),
            },
            "findings": findings[:20],
            "model_risk_assets": assets[:500],
            "model_risk_errors": model_risk_errors,
            "ai_vendor_items": extensions_data["vendor_items"],
            "ai_vendor_questions": [
                {"id": question.id, "section": question.section, "text": question.text}
                for question in ai_vendor_risk.AI_VENDOR_QUESTIONS
            ],
            "ai_vendor_error": extensions_data["vendor_error"],
            "drift_monitoring_enabled": extensions_data["drift_enabled"],
            "drift_monitoring_items": extensions_data["drift_items"],
            "drift_monitoring_error": extensions_data["drift_error"],
            "agent_topology_enabled": extensions_data["topology_enabled"],
            "agent_topology_error": extensions_data["topology_error"],
            "ai_incident_enabled": ai_incident_data["enabled"],
            "ai_incident_declarations": ai_incident_data["declarations"],
            "ai_incident_overdue": ai_incident_data["overdue"],
            "ai_incident_error": ai_incident_data["error"],
            "portfolio_enabled": portfolio_enabled,
            "portfolio_report": portfolio_report,
            "portfolio_snapshots": portfolio_snapshots[:20],
            "portfolio_error": portfolio_error,
            "red_team_enabled": red_team_enabled,
            "red_team_campaigns": red_team_campaigns[:20],
            "red_team_agents": red_team_agents[:500],
            "red_team_error": red_team_error,
            "ai_inventory_enabled": ai_inventory_enabled,
            "ai_inventory_assets": ai_inventory_assets[:500],
            "ai_inventory_runs": ai_inventory_runs[:50],
            "ai_inventory_statuses": ai_inventory_statuses,
            "ai_inventory_connectors": ai_inventory_connectors,
            "ai_inventory_error": ai_inventory_error,
            "policy_packs_enabled": policy_packs_enabled,
            "policy_pack_bundled": policy_pack_bundled,
            "policy_pack_catalog": policy_pack_catalog,
            "policy_pack_channels": policy_pack_channels,
            "policy_pack_subscriptions": policy_pack_subscriptions,
            "policy_pack_error": policy_pack_error,
            "gateway_enabled": gateway_enabled,
            "gateway_error": gateway_error,
            "gateway_error_action": gateway_error_action,
            "gateway_panel_errors": gateway_panel_errors,
            "gateway_summary": gateway_summary,
            "policies": policies[:100],
            "receipts": receipt_rows,
            "regulatory_impacts": regulatory_impacts[:100],
            "impact_page": impact_page,
            "gateway_view": view,
            "gateway_admin": has_global_permission(request, "admin"),
        },
    )


async def _governance_workspace_page_data(
    conformity: Any,
    literacy: Any,
    sync: Any,
) -> dict[str, Any]:
    """Bounded context for the legal/privacy governance workspace page.

    Tables carry identifiers, statuses, and progress counts only; assessment
    content and report drafts stay behind the authenticated governance API.
    """

    data: dict[str, Any] = {
        "eu_conformity_enabled": conformity.enabled(),
        "fria_records": [],
        "fria_error": "",
        "art43_routes": [],
        "pmm_plans": [],
        "registrations": [],
        "ai_literacy_enabled": literacy.enabled(),
        "literacy_gaps": {},
        "literacy_plane_status": {},
        "literacy_error": "",
        "literacy_training_keys": [],
        "literacy_roles": [],
        "grc_sync_enabled": sync.enabled(),
        "grc_status": {},
        "grc_outbound": [],
        "grc_error": "",
    }
    if data["eu_conformity_enabled"]:
        try:
            rows = await run_in_threadpool(conformity.list_frias)
        except Exception:
            data["fria_error"] = (
                "Fundamental-rights assessments are temporarily unavailable."
            )
        else:
            for row in rows[:100]:
                elements = row.get("elements") or {}
                data["fria_records"].append(
                    {
                        "id": row.get("id"),
                        "asset_id": row.get("asset_id"),
                        "context": row.get("context"),
                        "status": row.get("status"),
                        "revision": row.get("revision"),
                        "progress": sum(
                            1
                            for value in elements.values()
                            if isinstance(value, dict)
                        ),
                    }
                )
        try:
            routes = await run_in_threadpool(conformity.list_assessment_routes)
        except Exception:
            data["fria_error"] = data["fria_error"] or (
                "Conformity-route records are temporarily unavailable."
            )
        else:
            data["art43_routes"] = [
                {
                    "asset_id": row.get("asset_id"),
                    "route": row.get("route"),
                    "annex_iii_point": row.get("annex_iii_point"),
                    "status": row.get("status"),
                    "revision": row.get("revision"),
                    "modifications": len(row.get("modifications") or []),
                }
                for row in routes[:100]
            ]
        pmm_result, registration_result = await asyncio.gather(
            run_in_threadpool(conformity.list_pmm_plans),
            run_in_threadpool(conformity.list_registrations),
            return_exceptions=True,
        )
        if not isinstance(pmm_result, Exception):
            data["pmm_plans"] = [
                {
                    "asset_id": row.get("asset_id"),
                    "plan_reference": row.get("plan_reference"),
                    "reviews": len(row.get("reviews") or []),
                    "revision": row.get("revision"),
                }
                for row in pmm_result[:100]
            ]
        if not isinstance(registration_result, Exception):
            data["registrations"] = [
                {
                    "asset_id": row.get("asset_id"),
                    "basis": row.get("basis"),
                    "citation": row.get("citation"),
                    "registry": row.get("registry"),
                    "reference": row.get("reference"),
                }
                for row in registration_result[:100]
            ]
    if data["ai_literacy_enabled"]:
        try:
            data["literacy_gaps"] = await run_in_threadpool(literacy.literacy_gaps)
        except Exception:
            data["literacy_error"] = (
                "Training assignments and completions are temporarily unavailable."
            )
        try:
            data["literacy_plane_status"] = await run_in_threadpool(
                literacy.literacy_plane_status
            )
        except Exception:
            data["literacy_error"] = data["literacy_error"] or (
                "The canonical AI-literacy evidence authority is temporarily "
                "unavailable."
            )
        try:
            requirements = await run_in_threadpool(literacy.list_requirements)
        except Exception:
            requirements = []
        keys: dict[str, str] = {}
        for requirement in requirements:
            for training in requirement.get("trainings") or []:
                keys.setdefault(
                    str(training.get("key")), str(training.get("title") or "")
                )
        data["literacy_training_keys"] = [
            {"key": key, "title": title} for key, title in sorted(keys.items())
        ]
        data["literacy_roles"] = sorted(
            {str(row.get("role")) for row in requirements if row.get("role")}
        )
    if data["grc_sync_enabled"]:
        status_result, outbound_result = await asyncio.gather(
            run_in_threadpool(sync.sync_status),
            run_in_threadpool(sync.list_outbound, limit=50),
            return_exceptions=True,
        )
        if isinstance(status_result, Exception):
            data["grc_error"] = "The GRC sync ledger is temporarily unavailable."
        else:
            data["grc_status"] = status_result
        if isinstance(outbound_result, Exception):
            data["grc_error"] = (
                data["grc_error"]
                or "The GRC sync ledger is temporarily unavailable."
            )
        else:
            data["grc_outbound"] = outbound_result
    return data


@app.get("/security/governance", response_class=HTMLResponse)
async def governance_workspace_page(request: Request) -> HTMLResponse:
    """The governance workspace for legal, privacy, compliance, and HR:
    FRIA, Annex IV checklist, AI-literacy tracking, Art. 73 clocks, and
    GRC sync visibility, driven by /api/v1/security/governance."""
    require_permission(request, "operate")
    from maverick import (
        ai_incident_reporting,
        ai_literacy,
        eu_conformity,
        grc_sync,
        model_risk_assurance,
    )

    workspace = await _governance_workspace_page_data(
        eu_conformity,
        ai_literacy,
        grc_sync,
    )
    ai_incident_data = await _ai_incident_page_data(ai_incident_reporting)

    # The two per-model registers: GPAI provider obligations and Art. 26
    # deployer duties, as status rows the page can render and act on.
    def _register_states() -> tuple[list, list]:
        if not workspace["eu_conformity_enabled"]:
            return [], []
        try:
            gpai = [
                eu_conformity.gpai_status_from_record(row)
                for row in eu_conformity.list_gpai_registers()[:100]
            ]
            deployer = [
                eu_conformity.deployer_status_from_record(row)
                for row in eu_conformity.list_deployer_registers()[:100]
            ]
            return gpai, deployer
        except Exception:
            return [], []

    gpai_registers, deployer_registers = await run_in_threadpool(
        _register_states)

    from maverick import governance_alerts

    try:
        attention = await run_in_threadpool(governance_alerts.digest)
    except Exception:
        attention = {"attention_count": 0, "sections": {}}

    # Pickers so nobody has to paste raw MAA-/MRI- ids: the governed asset
    # inventory and recorded assurance incidents, both fail-soft and bounded.
    governed_assets: list[dict[str, Any]] = []
    assurance_incidents: list[dict[str, Any]] = []
    if model_risk_assurance.enabled():
        assets_result, incidents_result = await asyncio.gather(
            run_in_threadpool(model_risk_assurance.list_inventory),
            run_in_threadpool(model_risk_assurance.list_incidents),
            return_exceptions=True,
        )
        if not isinstance(assets_result, Exception):
            governed_assets = [
                {
                    "asset_id": row.get("asset_id"),
                    "display_name": row.get("display_name"),
                    "asset_type": row.get("asset_type"),
                }
                for row in assets_result[:500]
            ]
        if not isinstance(incidents_result, Exception):
            assurance_incidents = [
                {
                    "id": row.get("id"),
                    "severity": row.get("severity"),
                    "summary": str(row.get("summary") or "")[:120],
                }
                for row in incidents_result[:100]
            ]

    return templates.TemplateResponse(
        request,
        "governance.html",
        {
            "eu_conformity_enabled": workspace["eu_conformity_enabled"],
            "fria_records": workspace["fria_records"],
            "fria_error": workspace["fria_error"],
            "fria_elements": eu_conformity.FRIA_ELEMENTS,
            "annex_iv_items": eu_conformity.ANNEX_IV_ITEMS,
            "art43_routes": workspace["art43_routes"],
            "conformity_routes": eu_conformity.ROUTES,
            "pmm_plans": workspace["pmm_plans"],
            "registrations": workspace["registrations"],
            "registration_bases": eu_conformity.REGISTRATION_BASES,
            "ifu_items": eu_conformity.IFU_ITEMS,
            "gpai_registers": gpai_registers,
            "gpai_obligations": eu_conformity.GPAI_OBLIGATIONS,
            "gpai_systemic_obligations": eu_conformity.GPAI_SYSTEMIC_OBLIGATIONS,
            "deployer_registers": deployer_registers,
            "deployer_obligations": eu_conformity.DEPLOYER_OBLIGATIONS,
            "deployer_conditional_obligations":
                eu_conformity.DEPLOYER_CONDITIONAL_OBLIGATIONS,
            "attention": attention,
            "governed_assets": governed_assets,
            "assurance_incidents": assurance_incidents,
            "ai_literacy_enabled": workspace["ai_literacy_enabled"],
            "literacy_gaps": workspace["literacy_gaps"],
            "literacy_plane_status": workspace["literacy_plane_status"],
            "literacy_error": workspace["literacy_error"],
            "literacy_training_keys": workspace["literacy_training_keys"],
            "literacy_roles": workspace["literacy_roles"],
            "ai_incident_enabled": ai_incident_data["enabled"],
            "ai_incident_declarations": ai_incident_data["declarations"],
            "ai_incident_error": ai_incident_data["error"],
            "ai_incident_categories": (
                ai_incident_reporting.SERIOUS_INCIDENT_CATEGORIES
            ),
            "grc_sync_enabled": workspace["grc_sync_enabled"],
            "grc_status": workspace["grc_status"],
            "grc_outbound": workspace["grc_outbound"][:50],
            "grc_error": workspace["grc_error"],
        },
    )


@app.get("/security/threats", response_class=HTMLResponse)
async def platform_threats_page(request: Request) -> HTMLResponse:
    """Internal Lightwork platform threat-hunter console."""
    require_permission(request, "operate")
    from maverick import platform_hunt

    from .immune_actions_api import people_choices

    return templates.TemplateResponse(
        request, "security_threats.html", {
            "enabled": platform_hunt.enabled(),
            "can_global_admin": has_global_permission(request, "admin"),
            "people": people_choices(),
        },
    )


@app.get("/security/soc", response_class=HTMLResponse)
async def environment_threats_page(request: Request) -> HTMLResponse:
    """Customer-environment defensive SOC hunter console."""
    require_permission(request, "operate")
    from maverick import env_hunt

    from .immune_actions_api import people_choices
    from .security_page_helpers import (
        CURATED_TITLES,
        SOC_CONNECTOR_LABELS,
        soc_connector_choices,
    )

    enabled = env_hunt.enabled()
    pull, push = soc_connector_choices() if enabled else ([], [])
    rules = [{"title": CURATED_TITLES.get(r.id, r.title), "level": r.level,
              "techniques": list(r.mitre_techniques)}
             for r in env_hunt.curated_rules()] if enabled else []
    return templates.TemplateResponse(
        request,
        "security_soc.html",
        {
            "enabled": enabled,
            "response_execution": env_hunt.response_execution_enabled(),
            "can_global_admin": has_global_permission(request, "admin"),
            "people": people_choices(),
            "pull_connectors": [{"value": n, "label": SOC_CONNECTOR_LABELS.get(n, n)} for n in pull],
            "push_connectors": [{"value": n, "label": SOC_CONNECTOR_LABELS.get(n, n)} for n in push],
            "curated_rules": rules,
        },
    )


@app.get("/finance/board", response_class=HTMLResponse)
async def finance_board_page(request: Request) -> HTMLResponse:
    """The finance command center: the board chassis parameterized to the
    finance department — control tests, close readiness, SoD lint, the
    coverage posture (never an audit opinion), the license renewal runway,
    and the learning loop over finance decisions. Data from
    GET /api/v1/finance/board."""
    require_permission(request, "operate")
    require_suite(request, "finance")
    return templates.TemplateResponse(request, "finance_board.html", {})


@app.get("/finance", response_class=HTMLResponse)
async def finance_page(request: Request) -> HTMLResponse:
    """The Finance workspace: the same chassis over the finance team's
    assessment types — SOX controls, fraud risk, ITGC, credit risk, and
    close readiness — with the shared review pop-out."""
    require_permission(request, "operate")
    require_suite(request, "finance")
    operations = {
        "enabled": False,
        "degraded": False,
        "error_type": "",
        "regulatory_alerts": [],
        "licensing_packs": [],
        "anomaly_cases": [],
        "aml_cases": [],
        "aml_list_versions": 0,
        "control_cycles": [],
    }
    try:
        from dataclasses import asdict

        from maverick.finance import aml_screening, control_testing
        from maverick.finance.anomaly_engine import FinanceAnomalyCaseQueue
        from maverick.finance.licensing import load_licensing_pack
        from maverick.finance.regulatory_change import RegulatoryChangeEngine
        from maverick.paths import data_dir

        operations["enabled"] = aml_screening.enabled()
        if operations["enabled"]:
            engine = RegulatoryChangeEngine(
                data_dir("finance_operations", "regulatory_change.sqlite3")
            )
            operations["regulatory_alerts"] = [asdict(row) for row in engine.list_alerts(limit=20)]
            operations["licensing_packs"] = [
                {
                    "vertical": pack.vertical,
                    "title": pack.title,
                    "version": pack.version,
                    "as_of": pack.as_of,
                    "jurisdictions": len(pack.requirements),
                    "source_check_required": sum(
                        row.determination == "source_check_required" for row in pack.requirements
                    ),
                    "content_sha256": pack.content_sha256,
                }
                for pack in (
                    load_licensing_pack("money_transmitter"),
                    load_licensing_pack("insurance_producer"),
                )
            ]
            operations["anomaly_cases"] = [
                {
                    "id": row.get("id"),
                    "finding_id": row.get("finding_id"),
                    "rule_id": (row.get("finding") or {}).get("rule_id"),
                    "severity": row.get("severity"),
                    "status": row.get("status"),
                    "revision": row.get("revision"),
                }
                for row in FinanceAnomalyCaseQueue().list_cases(limit=20)
            ]
            aml_cases = aml_screening.list_cases(limit=20)
            operations["aml_cases"] = [
                {
                    "id": row.get("id"),
                    "status": row.get("status"),
                    "hit_count": len(row.get("hits") or []),
                    "revision": row.get("revision"),
                }
                for row in aml_cases
            ]
            operations["aml_list_versions"] = len(aml_screening.list_versions(limit=10_001))
            operations["control_cycles"] = [
                {
                    "id": row.get("id"),
                    "status": row.get("status"),
                    "engagement_id": row.get("engagement_id"),
                    "observed_at": row.get("observed_at"),
                }
                for row in control_testing.list_cycles(limit=20)
            ]
    except Exception as exc:  # failure-policy: visible_degradation
        operations["degraded"] = True
        operations["error_type"] = type(exc).__name__
        log.warning("finance workspace operations summary degraded: %s", type(exc).__name__)
    context = _workspace_ctx("finance", viewer=caller_principal(request) or "")
    context["operations"] = operations
    return templates.TemplateResponse(request, "finance.html", context)


@app.get("/work-value", response_class=HTMLResponse)
def work_value_page(request: Request) -> HTMLResponse:
    from .intent_value_api import authority
    authority(request)
    return templates.TemplateResponse(request, "intent_value.html", {})


@app.get("/savings", response_class=HTMLResponse)
def savings_page(request: Request, days: int = 90) -> HTMLResponse:
    """The value dashboard: money saved vs the typical human cost, computed
    from real completed work and the client's OWN cost/value inputs (their
    hourly rate + human hours per task, editable right on the page)."""
    from . import department_boards
    if department_boards.scoped(request):
        return department_boards.page(request, "savings")
    require_unscoped_board(request)
    from maverick import savings as savings_mod

    from .api import _value_assumptions_resolution
    from .value_views import assumptions_confirmed, value_scope

    days = max(1, min(days, 730))
    resolution = _value_assumptions_resolution()
    cfg = resolution["effective_assumptions"]
    value_view = value_scope(request)
    report = savings_mod.compute(_world(), window_days=days, cfg=cfg, owner=value_view["owner"])
    return templates.TemplateResponse(
        request,
        "savings.html",
        {
            "spend_recorded_at": _newest_cost_at(_world(), value_view["owner"]),
            "days": days,
            "cfg": cfg,
            "report": savings_mod.to_dict(report),
            "value_resolution": resolution,
            "can_manage_assumptions": has_global_permission(request, "operate"),
            "value_view": value_view,
            "assumptions_confirmed": assumptions_confirmed(),
            "practice_cost": _practice_cost_text(value_view["owner"], when=f"in the last {days} days, not part of these savings",
                                                 since=time.time() - days * 86400),
        },
    )


@app.get("/billing")
def billing_page(request: Request, format: str = "", period: str = "", receipt_offset: int = 0):
    """Tenant billing statement: accrued charges for the current period, a
    period-over-period trend, and an itemized CSV invoice.

    Charges are the priced runs (episodes) bucketed by month. The active
    tenant / client id labels the statement (the world is tenant-scoped).
    ``?format=csv&period=YYYY-MM`` downloads the itemized invoice for a month.
    """
    from datetime import datetime, timezone

    w = _world()
    # Keep both the statement and its itemized export within the same
    # principal boundary as the spend APIs. Tenant scoping alone is not enough:
    # a tenant can contain many mutually untrusted dashboard users.
    from maverick.episode_reporting import iter_episodes

    owner = goal_owner_filter(request)
    episodes = iter_episodes(w, owner=owner, finished_only=True)
    months: dict[str, dict] = {}
    newest_cost_at = None  # the "Spending updated" label: the newest finished attempt
    for e in episodes:
        if not e.ended_at:
            continue
        newest_cost_at = max(newest_cost_at or e.ended_at, e.ended_at)
        m = datetime.fromtimestamp(e.started_at, timezone.utc).strftime("%Y-%m")
        b = months.setdefault(
            m, {"period": m, "cost": 0.0, "unknown_cost_runs": 0, "input_tokens": 0, "output_tokens": 0, "runs": 0}
        )
        if e.cost_dollars is None:
            b["unknown_cost_runs"] += 1
        else:
            b["cost"] += e.cost_dollars
        b["input_tokens"] += e.input_tokens
        b["output_tokens"] += e.output_tokens
        b["runs"] += 1
    for b in months.values():
        b["cost"] = round(b["cost"], 6)

    try:
        from maverick.client import client_id
        from maverick.paths import current_tenant

        tenant = current_tenant() or client_id() or "default"
    except Exception:
        tenant = "default"

    # Keep native workspace identifiers out of the statement's display name.
    tenant_label = "Main workspace" if tenant == "default" else "Unnamed workspace"
    try:
        from maverick.tenant.registry import get_tenant

        _rec = get_tenant(tenant)
        if _rec and (_rec.display_name or "").strip():
            tenant_label = _rec.display_name.strip()
    except Exception:  # noqa: BLE001 - registry optional; label is cosmetic
        pass

    if format == "csv":
        sel = period or datetime.now(timezone.utc).strftime("%Y-%m")
        try:
            start = datetime.strptime(sel, "%Y-%m").replace(tzinfo=timezone.utc)
            if start.strftime("%Y-%m") != sel:
                raise ValueError("invalid month")
            end = start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1)
        except ValueError:
            raise HTTPException(422, "Choose a billing month in year-month order.") from None

        def rows():
            import csv
            import io

            from maverick.cost_provenance import EXPORT_HEADERS, export_fields

            from .audit_actions_api import csv_safe
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Run", "Task", "Started", "Finished", "Result", "Cost (USD)",
                             "Input tokens", "Output tokens", "Tool uses", *EXPORT_HEADERS])
            yield buf.getvalue()
            for episode in iter_episodes(w, owner=owner, since=start.timestamp(), until=end.timestamp(), finished_only=True):
                buf.seek(0)
                buf.truncate(0)
                writer.writerow([episode.id, episode.goal_id,
                                 datetime.fromtimestamp(episode.started_at, timezone.utc).isoformat(),
                                 datetime.fromtimestamp(episode.ended_at, timezone.utc).isoformat(),
                                 csv_safe(episode.outcome or ""),
                                 "unknown" if episode.cost_dollars is None else f"{episode.cost_dollars:.6f}",
                                 episode.input_tokens, episode.output_tokens, episode.tool_calls,
                                 *export_fields(episode)])
                yield buf.getvalue()
            # Practice runs cost real provider money: one labelled row, apart from the real runs.
            from maverick import practice_costs

            extra = practice_costs.export_row(practice_costs.summary(owner, since=start.timestamp(),
                                                                     until=end.timestamp()), 9 + len(EXPORT_HEADERS))
            if extra:
                buf.seek(0)
                buf.truncate(0)
                writer.writerow(extra)
                yield buf.getvalue()
        safe_tenant = "".join(c for c in tenant if c.isalnum() or c in "-_")[:64] or "workspace"
        return StreamingResponse(rows(), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="statement-{safe_tenant}-{sel}.csv"',
                     "Cache-Control": "private, no-store"})

    cur = datetime.now(timezone.utc).strftime("%Y-%m")
    current = months.get(
        cur, {"period": cur, "cost": 0.0, "unknown_cost_runs": 0, "input_tokens": 0, "output_tokens": 0, "runs": 0}
    )
    prev_keys = sorted([m for m in months if m < cur], reverse=True)
    previous = months.get(prev_keys[0]) if prev_keys else None
    delta_pct = None
    if previous and previous["cost"] > 0 and not previous["unknown_cost_runs"] and not current["unknown_cost_runs"]:
        delta_pct = round((current["cost"] - previous["cost"]) / previous["cost"] * 100, 1)
    series = [months[k] for k in sorted(months, reverse=True)][:12]
    from maverick import practice_costs
    from maverick.quotas import UsageLedger, UsageLedgerError

    _practice = practice_costs.summary(owner, since=practice_costs.month_bounds()[0])
    practice_cost = practice_costs.label(_practice, "this month") if _practice else ""
    receipt_error = None
    receipts = {"items": [], "total": 0, "offset": max(0, receipt_offset), "limit": 50, "has_more": False}
    try:
        receipts = UsageLedger().settlement_receipts(principal=goal_owner_filter(request),
                                                     offset=max(0, receipt_offset))
    except (UsageLedgerError, OSError):
        receipt_error = "Usage reconciliation records could not be loaded. Their absence has not been interpreted as zero usage."
    return templates.TemplateResponse(
        request,
        "billing.html",
        {
            "tenant": tenant,
            "tenant_label": tenant_label,
            "current": current,
            "previous": previous,
            "delta_pct": delta_pct,
            "series": series,
            "usage_receipts": receipts,
            "usage_receipt_error": receipt_error,
            "practice_cost": practice_cost,
            "spend_recorded_at": newest_cost_at,
            "invoice_admin": has_global_permission(request, "admin"),
            "invoice_workspaces": _invoice_workspaces(tenant, tenant_label),
        },
    )


def _invoice_workspaces(current: str, current_label: str) -> list[dict]:
    """Workspaces an administrator can make an invoice for (Billing page)."""
    from .workspace_display import duplicate_workspace_ids

    try:
        from maverick.tenant.registry import list_tenants
        rows = [{"id": t.id, "name": (t.display_name or "").strip()
                 or ("Main workspace" if t.id == "default" else "Unnamed workspace")} for t in list_tenants()]
    except Exception:  # noqa: BLE001 - registry optional
        rows = []
    duplicates = duplicate_workspace_ids((row["id"], row["name"]) for row in rows)
    for row in rows:
        if row["id"] in duplicates:
            row["name"] += f" (Reference: {row['id']})"
    return rows or [{"id": current, "name": current_label}]


def _provider_integration_inventory(workspace: dict) -> list[dict]:
    from maverick_dashboard import settings_store
    from maverick_dashboard.integration_readiness import (
        IntegrationConfigurationUnavailable,
        require_readable_config,
    )

    require_readable_config()
    rows = settings_store.state()["providers"]
    if any(row.get("source_errors") for row in rows):
        raise IntegrationConfigurationUnavailable(
            "provider configuration source changed while it was read"
        )
    # A fail-soft workspace verdict may have no provider rows. A partial row
    # lacks status/receipt fields the page and API promise, so fail closed.
    present = {row["name"] for row in workspace.get("providers") or []}
    if any(row["name"] not in present for row in rows):
        raise IntegrationConfigurationUnavailable("provider readiness is unavailable")
    # The one truth (configured, last test, status words) overrides the raw
    # store view so this page can never disagree with Settings, Chat or /start.
    from maverick_dashboard.provider_readiness import apply_to_rows

    return apply_to_rows(rows, workspace)


@app.get("/providers", response_class=HTMLResponse)
async def providers_page(request: Request) -> HTMLResponse:
    from maverick.provider_health import get as _health

    from .provider_readiness import workspace_readiness

    try:
        workspace = workspace_readiness()
        inventory = _provider_integration_inventory(workspace)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="provider inventory is unavailable",
        ) from exc
    from .auth import has_global_permission
    return templates.TemplateResponse(
        request,
        "providers.html",
        {"inventory": inventory, "rows": _health().snapshot(),
         "workspace": workspace,
         "is_admin": has_global_permission(request, "admin"),
         "tested": request.query_params.get("tested") == "1"},
    )


# ----- Control surface pages -----


def safe_audit_day(day: str | None) -> str | None:
    """Validate a ``?day=`` value as YYYY-MM-DD before it reaches the
    audit log's path builder.

    The audit log resolves ``day`` to ``audit_dir/{day}.ndjson``; an
    unvalidated value like ``../../../etc/foo`` would escape the audit
    directory. Anything that isn't a bare date is rejected to ``None``
    (today), neutralizing path traversal at the HTTP boundary.
    """
    # Delegate to the core's canonical validator so the HTTP boundary and the
    # CLI stay in lockstep: it enforces the anchored shape (path-safety) AND a
    # real calendar date, so a typo like 2026-13-99 falls back to today rather
    # than resolving to a nonexistent day-file.
    from maverick.audit.events import is_valid_day

    if is_valid_day(day):
        return day
    return None


# How many events one date-range view of the activity log reads at most.
_AUDIT_RANGE_SCAN_LIMIT = 2_000_000


def _global_audit_tail(request: Request, audit_log, n: int, day: str | None) -> list[dict]:
    """The deployment-wide chain's tail for a global administrator, tagged
    ``scope=deployment``; empty when the caller may not see it or when the
    workspace chain is already the global one."""
    try:
        if not has_global_permission(request, "admin"):
            return []
        from maverick.audit import global_audit_log

        global_log = global_audit_log()
        if global_log is audit_log or getattr(global_log, "audit_dir", None) == getattr(audit_log, "audit_dir", None):
            return []
        rows = global_log.tail(n, day=day)
    except Exception:  # pragma: no cover -- the workspace chain still renders
        return []
    return [{**e, "scope": "deployment"} for e in rows if isinstance(e, dict)]


def _audit_matcher(*, kind: str, person: str, agent: str, q: str):
    """The activity log's filter: kind of event, person, agent or specialist,
    and words. Words also find an AI action by a file, address or table it
    reached, which the row shows only as a fingerprint."""
    from . import audit_actions_api as _audit_plain
    from .content_access import resource_fingerprint

    needle = q.lower()
    resource_hit = resource_fingerprint(q) if q else ""

    def matches(e: dict) -> bool:
        if kind and e.get("kind") != kind:
            return False
        if person and _audit_plain.event_person(e) != person:
            return False
        if agent and e.get("agent") != agent:
            return False
        if q and resource_hit in (e.get("resource_fingerprints") or []):
            return True
        return not needle or (needle in json.dumps(e, default=str).lower()
                              or needle in _audit_plain.kind_label(e.get("kind")).lower())

    return matches


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request) -> HTMLResponse:
    """The activity log: recent events for a day or a date range, filtered by
    kind of event, person and text, shown as a readable table."""
    # Gate on ``audit`` to match the ``/api/v1/audit/tail`` twin -- otherwise a
    # view-only caller reads the full audit log via the HTML page despite the
    # API denying them.
    require_permission(request, "audit")
    from maverick.audit import default_audit_log

    from . import audit_actions_api as _audit_plain

    # 50 entries a page: the 200-row default made a 400 KB page that blocked a
    # phone for most of a second. "Show older activity" continues the search.
    try:
        n = max(1, min(int(request.query_params.get("n") or 50), 1000))
    except (TypeError, ValueError):
        n = 50
    raw_day = request.query_params.get("day")
    day = safe_audit_day(raw_day)
    if raw_day not in (None, "") and day is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid audit day. Enter a real date in YYYY-MM-DD format.",
        )
    raw_since, raw_until = request.query_params.get("since"), request.query_params.get("until")
    since, until = safe_audit_day(raw_since), safe_audit_day(raw_until)
    filter_error = ""
    if (raw_since and since is None) or (raw_until and until is None):
        filter_error = "Enter a real From and To date in year-month-day order. No search was performed."
    elif since and until and since > until:
        filter_error = "From must be on or before To. No search was performed."
    before_event = request.query_params.get("before_event", "")
    if before_event and (len(before_event) != 64 or any(c not in "0123456789abcdef" for c in before_event)):
        filter_error = "This continuation is invalid. Start a new activity search."
    audit_log = default_audit_log()
    from maverick.audit.segments import ReadReport

    read_report = ReadReport()
    kind = (request.query_params.get("kind") or "").strip()
    person = (request.query_params.get("person") or "").strip()
    agent = (request.query_params.get("agent") or "").strip()[:128]
    q = (request.query_params.get("q") or "").strip()[:200]
    _matches = _audit_matcher(kind=kind, person=person, agent=agent, q=q)

    from datetime import datetime, timezone
    from urllib.parse import urlencode

    from maverick.audit.export import iter_audit_events

    from .audit_search import search_events

    window_note, next_href = "", None
    events, kind_set, people_set, agent_set = [], set(), set(), set()
    deployment_filter_view = False
    displayed_audit_log = audit_log
    if not filter_error:
        scan_since, scan_until = since, until
        if not (since or until):
            scan_since = scan_until = day or datetime.now(timezone.utc).date().isoformat()
        source_events = iter_audit_events(since=scan_since, until=scan_until, report=read_report)
        if kind == "setting_changed" and has_global_permission(request, "admin"):
            # Setting writes are recorded in the deployment chain. The normal
            # workspace reader cannot see that chain on tenant installations.
            from maverick.audit import global_audit_log

            global_log = global_audit_log()
            if global_log.audit_dir != audit_log.audit_dir:
                from maverick.audit.reader import iter_events

                displayed_audit_log = global_log
                deployment_filter_view = True
                source_events = iter_events(
                    since=scan_since, until=scan_until,
                    audit_dir=global_log.audit_dir, report=read_report,
                )
        result = await run_in_threadpool(
            search_events, source_events,
            matches=_matches, person_for=_audit_plain.event_person, limit=n,
            before=before_event, scan_limit=_AUDIT_RANGE_SCAN_LIMIT,
        )
        events, kind_set, people_set = result["events"], result["kinds"], result["people"]
        agent_set = result.get("agents", set())
        if deployment_filter_view:
            events = [{**event, "scope": "deployment"} for event in events]
        if not result["cursor_found"]:
            filter_error = "The saved activity position is no longer available. Start a new search."
            events = []
        elif result["cut"]:
            window_note = "The activity scan reached its limit. This is a partial view; narrow the dates before relying on its totals."
        else:
            source_label = "deployment " if deployment_filter_view else ""
            window_note = f"Showing {len(events)} of {result['matched']} matching {source_label}events before this page boundary."
        if result["next_cursor"] and not filter_error:
            params = dict(request.query_params)
            if not (since or until):
                params["day"] = scan_since
            params["before_event"] = result["next_cursor"]
            next_href = "/audit?" + urlencode(params)
    # Deployment-wide records have a separate chain and are shown as a
    # clearly bounded recent view, never silently mixed into this cursor.
    deployment_events = []
    if not (filter_error or since or until or before_event or kind or person or agent or q):
        deployment_events = await run_in_threadpool(
            _global_audit_tail, request, audit_log, min(n, 200), day)
    order = "oldest" if request.query_params.get("order") == "oldest" else "newest"
    events = sorted(events, key=lambda event: float(event.get("ts") or 0),
                    reverse=(order == "newest"))
    # Distinct kinds and people in the window (for the filter dropdowns),
    # gathered before filtering so every choice stays selectable.
    kinds = sorted(kind_set, key=_audit_plain.kind_label)
    people = sorted(people_set - {""})
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "events": events,
            "n": n,
            "day": day,
            "since": since,
            "until": until,
            "kind": kind,
            "kinds": kinds,
            "person": person,
            "people": [{"value": p, "label": _idfmt.humanize_principal(p).name} for p in people],
            "agent": agent,
            "agents": [{"value": a, "label": _idfmt.humanize(a)} for a in sorted(agent_set)],
            "q": q,
            "order": order,
            "can_admin": has_permission(request, "admin"),
            "can_global_admin": has_global_permission(request, "admin"),
            "deployment_filter_view": deployment_filter_view,
            "audit_signing_enabled": bool(displayed_audit_log.signing_enabled),
            "audit_read_report": read_report.as_dict(),
            "audit_window_note": window_note,
            "audit_filter_error": filter_error,
            "audit_next_href": next_href,
            "deployment_events": deployment_events,
            **_audit_plain.page_helpers(),
        },
    )


@app.get("/partner", response_class=HTMLResponse)
async def partner_page(request: Request) -> HTMLResponse:
    """The partner fleet console: every client deployment this partner
    operates -- health, latency, agent version, white-label theme, and the
    summed value ledgers. Reading is operate-tier; adding/removing tenants
    (which carry probe URLs + optional tokens) is admin via the API."""
    require_permission(request, "operate")
    return templates.TemplateResponse(request, "partner.html", {})


@app.get("/audit/binder", response_class=HTMLResponse)
async def audit_binder_page(request: Request, days: int = 90) -> HTMLResponse:
    """The audit binder: a print-friendly, regulator-grade evidence pack --
    signed-chain verification, approvals with identity and quorum, the
    assessment register with revisions and decisions, the privacy registers,
    and the acceptance-learning KPIs. Audit-gated like /audit; the product
    generates its own workpapers."""
    require_permission(request, "audit")

    from starlette.concurrency import run_in_threadpool as _rit

    from .api import _binder_payload

    b = await _rit(_binder_payload, max(1, min(days, 730)))
    generated = _plain_labels.datetime_text(b["generated_at"])
    from .audit_actions_api import kind_label

    return templates.TemplateResponse(
        request, "audit_binder.html",
        {"b": b, "days": b["window_days"], "generated": generated, "kind_label": kind_label},
    )


def _replay_tabs(request: Request, goal_id: int | None) -> list[tuple[str, str, str]]:
    """Task replay's views this person may open: Replay, then Branches (the
    /run-tree page) and Video (the /walkthroughs page) under the same access
    those pages check. The selected task carries over to Branches."""
    from .navigation_api import may_open

    task = f"goal={goal_id}" if goal_id is not None else ""
    tabs = [("", "Replay", "/replay" + (f"?{task}" if task else ""))]
    if may_open(request, "/run-tree"):
        tabs.append(("branches", "Branches", "/replay?tab=branches" + (f"&{task}" if task else "")))
    if may_open(request, "/walkthroughs"):
        tabs.append(("video", "Video", "/replay?tab=video"))
    return tabs


@app.get("/replay", response_class=HTMLResponse)
def replay_page(request: Request, tab: str = "") -> HTMLResponse:
    """Flight recorder: reconstruct a run's action timeline from the signed
    audit log, verify the tamper-evident chain, and offer an evidence export.

    With no ``?goal=<id>`` it lists recent runs (owner-scoped) to pick from.
    ``?tab=branches`` and ``?tab=video`` show the Branches and Video views
    (the /run-tree and /walkthroughs pages) to people who may open those.
    """
    from maverick.world_model import close_world_if_owned, open_world

    from .control_plane import build_replay
    from .navigation_api import areas_on

    raw = (request.query_params.get("goal") or "").strip()
    goal_id = int(raw) if raw.isdigit() else None
    tabs = _replay_tabs(request, goal_id)
    if tab in ("branches", "video"):
        if tab not in {key for key, _label, _href in tabs}:
            raise HTTPException(status_code=403, detail="this page is not enabled for your role")
        if tab == "branches":
            context = {**_run_tree_context(request), "branches_href": "/replay?tab=branches&"}
        else:
            context = _walkthroughs_context(request)
        context["tab_host"] = {
            "title": "Task replay", "label": "Task replay views", "tabs": tabs, "selected": tab,
            "lede": "See everything a task did, step by step, check that the record hasn't been altered, "
                    "and download evidence for auditors."}
        return templates.TemplateResponse(
            request, "run_tree.html" if tab == "branches" else "walkthroughs.html", context)
    replay_tabs = tabs if len(tabs) > 1 and areas_on(request) else None
    w = open_world()
    try:
        if goal_id is None:
            goals = w.list_goals(limit=50, order="desc", owner=goal_owner_filter(request))
            return templates.TemplateResponse(
                request,
                "replay.html",
                {"goal": None, "goals": goals, "replay": None, "replay_tabs": replay_tabs},
            )
        goal = w.get_goal(goal_id)
        if goal is None:
            raise HTTPException(status_code=404, detail="no such goal")
        assert_goal_access(request, goal)
        replay = build_replay(goal_id, window=(goal.created_at, goal.updated_at))
        return templates.TemplateResponse(
            request,
            "replay.html",
            {"goal": goal, "goals": None, "replay": replay, "replay_tabs": replay_tabs},
        )
    finally:
        try:
            close_world_if_owned(w)
        except Exception:  # pragma: no cover -- best-effort response teardown
            pass


@app.get("/trust", response_class=HTMLResponse, response_model=None)
def trust_page(request: Request) -> HTMLResponse | RedirectResponse:
    """Agent Trust Plane: the cross-agent permission graph -- every external
    agent allowed to interact, with its tool/risk/budget ceilings + lifecycle.
    In areas navigation it is Outside agents' Access tab."""
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return templates.TemplateResponse(request, "trust.html", _trust_context(request))


def _trust_context(request: Request) -> dict:
    """Agent Trust: which outside agents may work with Lightwork, and what
    each may do, see and spend (/trust, and Outside agents' Access tab)."""
    from .control_plane import _discover_tools, trust_overview
    from .trust_page_api import managed_ids
    from .ui_choices_api import work_area_choices

    context = trust_overview()
    managed = managed_ids()
    for agent in context.get("agents", []):
        agent["managed"] = agent["id"] in managed
    tools = sorted({t["name"] for t in (_discover_tools().get("entries") or [])}
                   | {name for a in context.get("agents", []) for name in a["allow_tools"] + a["deny_tools"]
                      if name != "*"})
    context.update({
        "tool_choices": [[name, _idfmt.humanize(name)] for name in tools],
        "area_choices": work_area_choices(
            _world(), [s for a in context.get("agents", []) for s in a["data_scopes"]]),
        "can_admin": has_permission(request, "admin"),
    })
    return context


_OUTSIDE_AGENT_TABS = (("", "Agents", "/external-agents"), ("access", "Access", "/external-agents?tab=access"))


@app.get("/external-agents", response_class=HTMLResponse)
async def external_agents_page(request: Request, tab: str = "") -> HTMLResponse:
    """Bring-your-own-agent console: enroll agents built on other platforms
    (Agentforce, Bedrock, Copilot Studio, custom), mint their credentials,
    and watch their governed runs/spend land on the Operating Record.
    ``?tab=access`` shows Agent Trust (the /trust page) to people who may
    open it."""
    from maverick import external_agents as xa

    from .navigation_api import areas_on, may_open

    tabs = list(_OUTSIDE_AGENT_TABS) if may_open(request, "/trust") else None
    if tab == "access":
        if tabs is None:
            raise HTTPException(status_code=403, detail="this page is not enabled for your role")
        context = await run_in_threadpool(_trust_context, request)
        context["tab_host"] = {
            "title": "Outside agents", "label": "Outside agents views", "tabs": tabs, "selected": "access",
            "lede": "Choose which outside AI agents may work with Lightwork, and what each one may do, see and spend."}
        return templates.TemplateResponse(request, "trust.html", context)
    enabled = xa.enabled()

    return templates.TemplateResponse(
        request,
        "external_agents.html",
        {
            "enabled": enabled,
            "external_agents_can_manage": enabled and has_permission(request, "admin"),
            "external_agents_can_activate": has_global_permission(request, "admin"),
            "status": xa.status(),
            "agents": xa.roster(),
            "platforms": xa.PLATFORMS,
            "surfaces": xa.TOKEN_SURFACES,
            "outside_agent_tabs": tabs if areas_on(request) else None,
        },
    )


@app.get("/external-agents/{agent_id}", response_class=HTMLResponse)
async def external_agent_scorecard(request: Request, agent_id: str) -> HTMLResponse:
    """One external agent's scorecard: ceilings, spend vs budget, run
    history on the Operating Record, and governance state (containment,
    wall violations, credentials)."""
    from maverick import external_agents as xa

    from .external_agent_detail_service import detail_for

    detail = await run_in_threadpool(detail_for, request, agent_id)
    can_manage = xa.enabled() and has_permission(request, "admin")
    access = None
    try:
        from .effective_access import outside_agent

        access = outside_agent(agent_id)
    except Exception:  # noqa: BLE001 -- the access check is read-only help
        log.warning("outside agent access check unavailable", exc_info=True)
    return templates.TemplateResponse(
        request, "external_agent_detail.html",
        {"a": detail, "can_manage": can_manage, "access": access},
        headers={"Cache-Control": "private, no-store"}
    )


@app.get("/discovery", response_class=HTMLResponse, response_model=None)
async def discovery_page(request: Request) -> HTMLResponse | RedirectResponse:
    """Inventory every governable surface the deployment exposes (tools, MCP
    servers, providers, channels, external agents). In areas navigation it
    is the Permissions page's Inventory tab."""
    from .control_plane import discovery_overview
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return templates.TemplateResponse(
        request, "discovery.html", {"discovery": discovery_overview()}
    )


@app.get("/simulate", response_class=HTMLResponse)
async def simulate_page(request: Request) -> HTMLResponse:
    """Dry-run a proposed action: its risk + whether it would be gated, no run."""
    from . import simulate_choices
    from .control_plane import simulate_action

    surface = request.query_params.get("surface") or ""
    action = request.query_params.get("action") or ""
    target = request.query_params.get("target") or ""
    result = simulate_action(surface, action, target) if surface else None
    return templates.TemplateResponse(
        request,
        "simulate.html",
        {
            "surface": surface,
            "action": action,
            "target": target,
            "result": result,
            "plain": simulate_choices.explain(result),
            "surfaces": simulate_choices.SURFACES,
            "action_groups": simulate_choices.action_groups(),
            "research_component": "tabular",
            "research_result": None,
            "research_error": None,
        },
    )


@app.post("/simulate/research", response_class=HTMLResponse)
async def simulate_research_page(
    request: Request,
    component: str = Form("tabular", max_length=32),
) -> HTMLResponse:
    """Run and render the actual isolated synthetic research study."""
    from maverick.research_simulator import ResearchSimulationError

    from .control_plane import run_isolated_research_simulation
    from .simulation_authority import authenticated_human_identity

    status_code = 200
    research_result = None
    research_error = None
    try:
        identity = authenticated_human_identity(request)
        research_result = await run_in_threadpool(
            run_isolated_research_simulation,
            identity,
            component_name=component,
        )
    except HTTPException as exc:
        status_code = exc.status_code
        research_error = (
            "Sign in with your own named account to run a practice study."
            if exc.status_code in (401, 403)
            else "The practice study could not start. Try again."
        )
    except ValueError:
        status_code = 400
        research_error = "Choose a study type from the list and try again."
    except ResearchSimulationError:
        status_code = 503
        research_error = "Practice studies are not available right now."
    from . import simulate_choices

    return templates.TemplateResponse(
        request,
        "simulate.html",
        {
            "surface": "",
            "action": "",
            "target": "",
            "result": None,
            "plain": None,
            "surfaces": simulate_choices.SURFACES,
            "action_groups": simulate_choices.action_groups(),
            "research_component": component,
            "research_result": research_result,
            "research_error": research_error,
        },
        status_code=status_code,
    )


@app.get("/compartments", response_class=HTMLResponse)
async def compartments_page(
    request: Request,
    q: str = Query(default="", max_length=128),
    page: int = Query(default=1, ge=1, le=100_000),
    per_page: int = Query(default=50, ge=1, le=100),
) -> HTMLResponse:
    """The agent factory's roster: each domain pack and the bulkhead it runs in.

    Reads the discoverable domain packs (built-in + onboarded) so an operator
    can see which sealed agents exist and the capability envelope each runs
    under -- the compartments a Rung-2 seal acts on. Searched and paginated
    like /tools: unscoped, the full roster is 2,000+ packs and rendered
    every capability envelope into one multi-megabyte page."""
    query = q.strip()
    domain_page = {
        "query": query,
        "page": page,
        "per_page": per_page,
        "catalog_total": 0,
        "filtered_total": 0,
        "returned": 0,
        "page_count": 1,
        "first": 0,
        "last": 0,
    }
    domains: list = []
    try:
        from maverick.domain import available_domains, suites_for_domain

        from .auth import caller_suites

        # Job-function scoping: a scoped caller sees only their departments'
        # sealed agents and capability envelopes, matching /agents (this page
        # otherwise leaks every department's pack config).
        allowed = caller_suites(request)
        catalog = [
            profile for name, profile in sorted(available_domains().items(), key=lambda item: item[1].name)
            if allowed is None or suites_for_domain(name, profile) <= allowed
        ]
        folded = query.casefold()
        filtered = [
            d
            for d in catalog
            if not folded
            or folded in d.name.casefold()
            or folded in (getattr(d, "persona", "") or "").casefold()
            or folded in (getattr(d, "description", "") or "").casefold()
            or folded in (getattr(d, "compartment", "") or "").casefold()
        ]
        page_count = max(1, (len(filtered) + per_page - 1) // per_page)
        if page > page_count:
            raise HTTPException(
                status_code=400,
                detail="compartment page exceeds the available search results",
            )
        start = (page - 1) * per_page
        domains = filtered[start : start + per_page]
        domain_page = {
            "query": query,
            "page": page,
            "per_page": per_page,
            "catalog_total": len(catalog),
            "filtered_total": len(filtered),
            "returned": len(domains),
            "page_count": page_count,
            "first": start + 1 if domains else 0,
            "last": start + len(domains),
        }
    except HTTPException:
        raise
    except Exception:  # never 500 the page if the factory layer is unavailable
        domains = []
    return templates.TemplateResponse(
        request, "compartments.html", {"domains": domains, "domain_page": domain_page},
    )


@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request) -> HTMLResponse:
    """The per-client agent editor: browse every pack and customize one for this
    deployment. ``?name=`` opens that agent's editor (persona, tools, risk, and
    its workflow playbook); saving writes a tenant override that inherits the
    built-in base and patches only what changed. Read-only when [features]
    pack_editing is off. The roster + the selected agent's merged view are
    rendered server-side; the page JS only drives the save/validate/reset
    calls to /api/v1/agents."""
    agents: list = []
    rejected_agents: list = []
    selected = None
    editable = False
    # ``?new=1`` opens a blank builder for a brand-new, from-scratch custom agent
    # (no built-in base): the save posts to /api/v1/agents/<the id you type>, which
    # coerces a standalone pack. ``?name=`` still tailors an existing specialist.
    creating = request.query_params.get("new") in ("1", "true", "yes")
    try:
        from maverick.domain import rejected_workspace_domains
        from maverick.domain_edit import list_agents, rejected_override_view, resolved_view

        from .auth import caller_suites
        from .editor_policy import pack_editing_denial

        editable = pack_editing_denial(request) is None
        # Job-function scoping: mirror GET /api/v1/agents — a caller with a
        # department grant browses their departments' specialists plus generic
        # packs; a non-granted selection renders nothing rather than its config.
        allowed = caller_suites(request)
        agents = [
            agent for agent in list_agents()
            if allowed is None or set(agent["suites"]) <= allowed
        ]
        _assign_picker_labels(agents)
        if editable:
            rejected_agents = [
                view for name in sorted(rejected_workspace_domains())
                if (view := rejected_override_view(name)) is not None
            ]
        name = request.query_params.get("name")
        if name:
            view = resolved_view(name)
            if view and (allowed is None or set(view["suites"]) <= allowed):
                selected = view
                selected["plain_errors"] = _plain_findings(view.get("errors") or [])
                selected["plain_warnings"] = _plain_findings(view.get("warnings") or [])
                selected["picker_label"] = next(
                    (agent["picker_label"] for agent in agents if agent["name"] == name),
                    f"{view.get('description') or _idfmt.humanize(name)} · {_idfmt.humanize(name)}",
                )
            creating = False  # editing an existing agent wins over the new form
    except Exception:  # never 500 the page if the factory layer is unavailable
        agents = []
    agent_changes: list = []
    selected_kind = "agent"
    if selected:
        try:
            from . import agent_changelog

            agent_changes = agent_changelog.entries(selected["name"], limit=10)
            selected_kind = agent_changelog.agent_kind(selected["name"])
        except Exception:  # pragma: no cover -- the history is best effort
            agent_changes = []
    access = None
    if selected:
        try:
            from .effective_access import agent as agent_access

            access = agent_access(selected["name"], selected)
        except Exception:  # noqa: BLE001 -- the access check is read-only help
            log.warning("specialist or agent access check unavailable", exc_info=True)
    typical = None
    if selected and not creating:
        from maverick.typical_cost import typical_cost

        # The cost history is a database read: keep it off the event loop.
        typical = await run_in_threadpool(lambda: typical_cost(_world(), specialist=selected["name"]))
    from maverick.role_edit import ROLES

    model_options = [(spec, _plain_labels.model_label(spec)) for spec, _label in model_picker_options()] if (selected or creating) and editable else []
    model_roles = [{"role": role, "label": _plain_labels.agent_role_title(role)} for role in ROLES]
    published_work_available = False
    if selected and not creating and has_permission(request, "operate"):
        from .product_operations_task_launch import published_selection
        try:
            published_selection(request, selected["name"])
            published_work_available = True
        except HTTPException as exc:
            if exc.status_code not in {403, 409}:
                raise
    return templates.TemplateResponse(
        request,
        "agents.html",
        {"agents": agents, "rejected_agents": rejected_agents,
         "selected": selected, "editable": editable, "creating": creating,
         "model_options": model_options, "model_roles": model_roles,
         "published_work_available": published_work_available,
         "can_set_model_cost_tier": has_global_permission(request, "admin"),
         "agent_changes": agent_changes, "selected_kind": selected_kind,
         # Names of the people who changed an agent are shown to administrators.
         "show_change_authors": has_global_permission(request, "admin"),
         "access": access, "typical_cost": typical},
    )


def _plain_findings(findings: list) -> list[str]:
    """Setup-check findings in plain words, each said once; the raw lint text
    stays under Technical details."""
    from .workforce_ops_api import _finding

    return list(dict.fromkeys(_finding(str(item)) for item in findings))


def _assign_picker_labels(agents: list[dict]) -> None:
    """Give each specialist an unambiguous picker label, even when two packs
    share a description or their names look identical after humanizing."""
    picker_values: set[str] = set()
    for agent in agents:
        name = agent["name"]
        base = f"{agent.get('description') or _idfmt.humanize(name)} · {_idfmt.humanize(name)}"
        value = base
        if value in picker_values:
            value = f"{base} ({name})"
        suffix = 2
        while value in picker_values:
            value = f"{base} ({name}, {suffix})"
            suffix += 1
        agent["picker_label"] = value
        picker_values.add(value)


_PICKER_READINESS_ORDER = {"action_ready": 0, "needs_setup": 1}


def _picker_rank(query: str, label: str, name: str) -> int | None:
    """Where a specialist sorts for a picker search, or None when it does not
    match: the label or pack name starting with the words first, then a word
    in the label starting with them, then a match anywhere."""
    if not query:
        return 0
    text, key = label.casefold(), name.casefold()
    if text.startswith(query) or key.startswith(query):
        return 0
    if re.search(r"(?:^|\W)" + re.escape(query), text):
        return 1
    if query in text or query in key:
        return 2
    return None


@app.get("/api/v1/chat/specialists")
def chat_specialist_choices(
    request: Request,
    q: str = Query(default="", max_length=100),
    limit: int = Query(default=20, ge=1, le=50),
) -> JSONResponse:
    """Published specialists matching a Chat search, best name matches first.

    The same current, department-scoped choices Chat validates on start; the
    workspace context lets the page refuse a reply from a changed account.
    """
    require_permission(request, "operate")
    require_page_visible(request, "/chat")
    from maverick.governed_operations import dataclass_digest

    from .product_operations_task_launch import published_specialists

    current = published_specialists(request, revisions=False)
    query = " ".join(q.split()).casefold()
    matches = [
        choice for choice in current["choices"]
        if not query or query in choice["label"].casefold() or query in choice["value"].casefold()
    ]
    matches.sort(key=lambda choice: (not choice["label"].casefold().startswith(query), choice["label"].casefold()))
    # Each revision digests a whole specialist: only the page returned needs one.
    items = [{"value": choice["value"], "label": choice["label"], "revision": dataclass_digest(choice["profile"])}
             for choice in matches[:limit]]
    return JSONResponse(
        {"context": current["context"], "items": items, "total": len(matches)},
        headers={"Cache-Control": "no-store, private"},
    )


@app.get("/agents/picker")
def agents_picker(request: Request, q: str = "", setup: bool = False, limit: int = 20) -> dict:
    """Search-as-you-type for the Agent Factory picker.

    Rather than ship all 2,000+ specialists as one picker list, this
    answers with the best matches only: ready-to-run specialists unless
    ``setup`` asks for those that need setup too, at most ``limit`` (20 by
    default, 50 at most). It sits under /agents, so the page's role visibility
    applies, and it is department-scoped exactly like the page's roster.
    """
    from maverick.domain_edit import list_agents

    from .auth import caller_suites

    query = " ".join(q.split())[:100].casefold()
    limit = max(1, min(limit, 50))
    allowed = caller_suites(request)
    try:
        roster = list_agents()
    except Exception as exc:  # noqa: BLE001 - the page says the list is unavailable
        raise HTTPException(status_code=503, detail="The list of agents and specialists is unavailable. Try again.") from exc
    visible = [agent for agent in roster if allowed is None or set(agent["suites"]) <= allowed]
    _assign_picker_labels(visible)
    ranked = []
    for position, agent in enumerate(visible):
        readiness = agent.get("readiness") or {}
        state = readiness.get("state")
        ready = state == "action_ready"
        if not ready and not setup:
            continue
        label = agent["picker_label"] + (" (custom)" if agent.get("is_override") else "")
        rank = _picker_rank(query, label, agent["name"])
        if rank is not None:
            # Best text match first; within it, specialists that can start, then
            # those needing setup, then those whose setup check is unavailable.
            ranked.append((rank, _PICKER_READINESS_ORDER.get(state, 2), position,
                           {"name": agent["name"], "label": label, "ready": ready,
                            "readiness": readiness.get("label", "")}))
    ranked.sort(key=lambda row: row[:3])
    return {"items": [row[3] for row in ranked[:limit]], "total": len(ranked), "limit": limit}


@app.get("/assessments", response_class=HTMLResponse)
def assessments_page(request: Request) -> HTMLResponse:
    """Govern → Assessments: the privacy / security / AI-risk register. Every
    agent and flow can be auto-assessed from its declared capability surface,
    reviewed and signed off per lens, and re-assessed when it changes. The
    register + templates load client-side from /api/v1/assessments; the page
    provides the subject pickers (agents + flows) for drafting a new one."""
    agents: list = []
    flows: list = []
    try:
        from maverick.domain_edit import list_agents

        from .auth import caller_suites

        # Job-function scoping: the subject picker offers only the caller's
        # departments' specialists, matching the scoped /agents roster (else a
        # picked-but-403'd pack drives mixed failures mid-assessment).
        allowed = caller_suites(request)
        agents = [
            {"name": agent["name"], "suite": agent.get("suite")}
            for agent in list_agents()
            if allowed is None or set(agent["suites"]) <= allowed
        ]
        # People pick from readable names grouped by department; the pack
        # name stays the option value the API receives.
        from maverick.departments import department_title
        from maverick.domain import available_domains

        from .plain_labels import pack_display_name

        profiles = available_domains()
        for a in agents:
            prof = profiles.get(a["name"])
            a["label"] = pack_display_name(
                a["name"],
                getattr(prof, "persona", ""),
                getattr(prof, "description", ""),
            )
            a["group"] = department_title(a["suite"]) if a.get("suite") else "Other agents and specialists"
        agents.sort(key=lambda a: (a["group"].casefold(), a["label"].casefold(), a["name"]))
    except Exception:  # never 500 the page if the factory layer is unavailable
        agents = []
    try:
        from maverick import flow as _flow

        if _flow.enabled():
            from maverick.flow import store as _flow_store

            flows = [
                {"id": f.get("id"), "name": f.get("name") or f.get("id")}
                for f in _flow_store.list_flow_summaries()
            ]
    except Exception:  # pragma: no cover -- flow engine optional
        flows = []
    return templates.TemplateResponse(
        request,
        "assessments.html",
        {"agents": agents, "flows": flows, "assessment_can_review": has_permission(request, "admin")},
    )


def model_picker_options() -> list[tuple[str, str]]:
    """Every model a picker may offer, as ``(spec, provider_label)``: the built-in
    catalogue, plus any ``[models] catalog`` the admin added, capped to the admin
    allow-list when one is set. Shared by the Settings and Roles model pickers so
    the two never drift."""
    import re as _re

    from maverick.llm import catalog_specs
    from maverick.runtime_overrides import allowed_models

    options = list(catalog_specs())
    seen = {s for s, _ in options}
    try:  # admins extend the picker via [models] catalog in config.toml
        from maverick.config import load_config

        for spec in (load_config().get("models", {}) or {}).get("catalog") or []:
            s = str(spec).strip()
            if s and s not in seen and _re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", s):
                options.append((s, "Custom (config)"))
                seen.add(s)
    except Exception:  # pragma: no cover -- config read fails soft
        pass
    allow = allowed_models()
    if allow:
        label_by_spec = dict(options)
        return [(s, label_by_spec.get(s, "Allowed")) for s in sorted(allow)]
    return options


@app.get("/roles", response_class=HTMLResponse)
async def roles_page(request: Request) -> HTMLResponse:
    """The per-client roles editor: each core role (orchestrator, coder, ...)
    with an editable system-prompt addendum AND an editable per-role model
    (picked from the catalogue) + reasoning effort. ``?role=`` opens that role.
    The addendum is appended to the role's base template at spawn. Read-only
    when [features] role_editing is off."""
    roles: list = []
    selected = None
    editable = True
    model_options: list[tuple[str, str]] = []
    try:
        from maverick.config import get_features
        from maverick.role_edit import list_roles, resolved_role

        editable = bool(get_features().get("role_editing", True))
        roles = list_roles()
        role = request.query_params.get("role")
        if role:
            selected = resolved_role(role)
        model_options = model_picker_options()
    except RuntimeOverridesSecurityError:
        raise
    except Exception:  # never 500 the page if the role layer is unavailable
        roles = []
    return templates.TemplateResponse(
        request,
        "roles.html",
        {
            "roles": roles,
            "selected": selected,
            "editable": editable,
            "model_options": model_options,
        },
    )


_OVERSIGHT_KINDS = frozenset(
    {
        "governance_denied",
        "shield_block",
        "capability_denied",
        "egress_blocked",
        "consent_result",
        "halt",
    }
)


def _is_intervention(e: dict) -> bool:
    """True iff an audit event is a control-plane intervention.

    A ``consent_result`` only counts when it denied/timed out -- an approval is
    not an intervention.
    """
    kind = e.get("kind")
    if kind == "consent_result":
        return str(e.get("decision") or "").lower() in {"deny", "timeout"}
    return kind in _OVERSIGHT_KINDS


def _intervention_detail(e: dict) -> str:
    """A one-line, plain-language summary of an intervention, by kind."""
    from .identity_format import humanize

    kind = e.get("kind")
    if kind == "shield_block":
        stage = humanize(e.get("stage") or "")
        reason = str(e.get("reason") or "").strip()
        return f"Safety filter stopped it{(' at ' + stage.lower()) if stage else ''}: {reason}".strip(": ")
    if kind == "capability_denied":
        return f"Not allowed to use {humanize(e.get('tool') or 'this tool').lower()}"
    if kind == "egress_blocked":
        return f"Not allowed to send data to {humanize(e.get('provider') or 'that service')}"
    if kind == "consent_result":
        decision = str(e.get("decision") or "").lower()
        what = "Consent timed out" if decision == "timeout" else "Consent refused"
        return f"{what}: {e.get('action') or ''}".strip(": ")
    if kind == "halt":
        detail = str(e.get("detail") or "").strip()
        return f"Emergency stop{(': ' + detail) if detail else ''}"
    # governance_denied (and any future kind): the reason, plus which policy
    # rule fired so the operator can see why it was held.
    detail = str(e.get("reason") or e.get("detail") or e.get("tool") or "")
    rule = e.get("rule")
    if kind == "governance_denied" and rule:
        detail = f"{detail} (company rule: {humanize(rule).lower()})".strip()
    return detail


def _audit_event_visible_to_caller(
    e: dict,
    *,
    principal: str | None,
    owner_filter: str | None,
    world,
    goal_owner_cache: dict[int, str | None],
) -> bool:
    """Match exact task ownership before projecting intervention metadata.

    Local installation authority covers unowned local work only. Named task
    owners and explicit named actors never become local through a missing login.
    Unknown task references fail closed. Global audit review uses /audit.
    """
    scope = owner_filter or ""
    if principal and principal != scope:
        return False
    raw_goal_id = e.get("goal_id")
    if isinstance(raw_goal_id, bool):
        return False
    if raw_goal_id not in (None, "", 0):
        if not isinstance(raw_goal_id, (str, int)):
            return False
        try:
            goal_id = int(raw_goal_id)
        except (TypeError, ValueError):
            return False
        if goal_id not in goal_owner_cache:
            try:
                goal = world.get_goal(goal_id)
                goal_owner_cache[goal_id] = getattr(goal, "owner", None) if goal else None
            except Exception:
                goal_owner_cache[goal_id] = None
        return goal_owner_cache[goal_id] == scope
    actor = e.get("principal") or e.get("actor") or ""
    if scope:
        return actor == scope
    # Agent-only system events without a task carry no named employee content;
    # only their metadata will be shown. Malformed actor markers are withheld.
    return isinstance(actor, str) and (not actor or actor.startswith(("agent:", "local:")))



@app.get("/oversight", response_class=HTMLResponse)
def oversight_page(request: Request) -> HTMLResponse:
    """Operator mission-control: every control-plane intervention in one pane.

    Unifies what each guardrail did to the fleet -- org-policy DENY /
    REQUIRE_HUMAN (governance, EU AI Act Art 14), shield blocks, capability
    denials, the enterprise egress lock, consent denials, and killswitch halts
    -- next to the live halt state, the pending human-approval queue, and the
    count of active agents. The per-guardrail pages (/safety, /approvals,
    /audit, /fleets) remain the deep dives; this is the at-a-glance roll-up.
    Fail-soft: an unreadable audit log yields empty panels, never a 500.
    """
    from . import department_boards
    if department_boards.scoped(request):
        return department_boards.page(request, "oversight")
    require_unscoped_board(request)
    # This page contains the deployment-wide approval queue and mutating
    # decision controls. Authorize before reading either approval details or
    # the audit/world-model stores.
    require_permission(request, "operate")

    from collections import Counter, deque

    try:
        n = max(1, min(int(request.query_params.get("n") or 1000), 5000))
    except (TypeError, ValueError):
        n = 1000
    day = safe_audit_day(request.query_params.get("day"))
    since = safe_audit_day(request.query_params.get("since"))
    until = safe_audit_day(request.query_params.get("until"))
    ranged = bool(since or until)
    w = _world()
    owner_filter = goal_owner_filter(request)
    principal = caller_principal(request)
    goal_owner_cache: dict[int, str | None] = {}

    # Counts span the whole window; the trail keeps only the newest 150 (a
    # bounded deque), so a wide incident-review range stays cheap in memory.
    by_kind: Counter = Counter()
    recent: deque = deque(maxlen=150)
    total = 0
    source_errors = []
    from datetime import datetime, timezone

    from maverick.audit.export import iter_audit_events
    from maverick.audit.segments import ReadReport

    from .content_access import audit_metadata

    report = ReadReport()
    scan_since, scan_until = since, until
    if not ranged:
        scan_since = scan_until = day or datetime.now(timezone.utc).date().isoformat()
    try:
        for scanned, event in enumerate(iter_audit_events(since=scan_since, until=scan_until, report=report)):
            if scanned >= 200_000:
                source_errors.append("Activity is partial: narrow the date range to inspect the rest.")
                break
            if _is_intervention(event) and _audit_event_visible_to_caller(
                event, principal=principal, owner_filter=owner_filter, world=w,
                goal_owner_cache=goal_owner_cache,
            ):
                safe = audit_metadata(event)
                by_kind[str(safe.get("kind"))] += 1
                total += 1
                recent.append(safe)
        if report.as_dict().get("failures"):
            source_errors.append("Some activity segments could not be read. Counts are partial; review the activity log.")
    except Exception:
        total = None
        source_errors.append("Activity is unavailable. An empty list does not mean that no intervention occurred.")

    titles: dict[int, str] = {}

    def _goal_title(goal_id) -> str:
        if not isinstance(goal_id, int):
            return ""
        if goal_id not in titles:
            try:
                goal = w.get_goal(goal_id)
                assert_goal_access(request, goal)
            except Exception:  # pragma: no cover - a missing or private title shows a number
                goal = None
            titles[goal_id] = (goal.title if goal is not None else "") or ""
        return titles[goal_id]

    rows = [
        {
            "ts": e.get("ts"),
            "kind": e.get("kind"),
            "agent": e.get("agent") or "",
            "goal_id": e.get("goal_id"),
            "goal_title": _goal_title(e.get("goal_id")),
            "detail": _intervention_detail(e),
        }
        for e in reversed(recent)
    ]

    try:
        from maverick.killswitch import is_active
        halted = bool(is_active())
    except Exception:
        halted = None
        source_errors.append("Emergency-stop state is unavailable. Check its controls before relying on this view.")

    try:
        from .content_access import can_read_approval
        approvals = [a for a in w.pending_approvals() if can_read_approval(request, a, world=w)]
        pending = len(approvals)
    except Exception:
        approvals, pending = [], None
        source_errors.append("Your approval queue is unavailable. Its current size is unknown.")
    approval_context = _approval_queue_context(approvals, request)
    try:
        active = len(w.list_goals(status="active", owner=owner_filter))
    except Exception:
        active = None
        source_errors.append("Active task state is unavailable.")

    return templates.TemplateResponse(
        request,
        "oversight.html",
        {
            "events": rows,
            "by_kind": dict(by_kind),
            "total": total,
            "ranged": ranged,
            "since": since,
            "until": until,
            "halted": halted,
            "can_halt": has_global_permission(request, "operate"),
            "approvals": approvals,
            **approval_context,
            "pending": pending,
            "source_errors": source_errors,
            "active": active,
            "n": n,
            "day": day,
        },
    )


@app.get("/run-tree", response_class=HTMLResponse, response_model=None)
def run_tree_page(request: Request) -> HTMLResponse | RedirectResponse:
    """Counterfactual review: the runs that were forked, and their branches.

    Read-only. Forking happens on the run itself; this is where a reviewer
    reads what the agent chose against what the alternative did, under one
    root. Owner-scoped like the goal listings, and fail-soft: an unreadable
    lineage sidecar renders the empty state, never a 500. In areas navigation
    it is Task replay's Branches tab (/replay?tab=branches).
    """
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return templates.TemplateResponse(request, "run_tree.html", _run_tree_context(request))


def _run_tree_context(request: Request) -> dict:
    """The Branches view: tasks with branches, one task's branch tree and
    the branch controls (/run-tree, and Task replay's Branches tab)."""
    from maverick import session_tree

    owner_filter = goal_owner_filter(request)
    rows = session_tree.roots(limit=200)
    if owner_filter is not None:
        rows = [r for r in rows if r["owner"] == owner_filter]
    selected = request.query_params.get("goal")
    try:
        goal_id = int(selected) if selected else (rows[0]["goal_id"] if rows else 0)
    except (TypeError, ValueError):
        goal_id = 0
    tree = session_tree.tree(goal_id) if goal_id else {}
    if tree and owner_filter is not None and tree.get("owner") != owner_filter:
        tree = {}
    try:
        from maverick.config import get_session_tree

        cfg = get_session_tree()
    except Exception:  # pragma: no cover - unreadable config => documented defaults
        cfg = {"enable": False, "max_depth": 10}
    try:
        recent = [
            {"id": g.id, "title": g.title, "status": g.status}
            for g in _world().list_goals(owner=owner_filter, limit=50, order="desc")
        ]
    except Exception:  # pragma: no cover - the picker is best-effort
        recent = []
    return {
        "enabled": bool(cfg.get("enable")),
        "max_depth": cfg.get("max_depth"),
        "roots": rows,
        "tree": tree,
        "recent": recent,
        "can_operate": has_permission(request, "operate"),
        "can_admin": has_permission(request, "admin"),
        "branches_href": "/run-tree?",
    }


@app.get("/safety", response_class=HTMLResponse)
async def safety_page(request: Request) -> HTMLResponse:
    """Shield activity: what the safety layer blocked, by stage and reason."""
    from collections import Counter

    from maverick.audit import default_audit_log

    from .content_access import audit_metadata

    require_permission(request, "audit")

    try:
        n = max(1, min(int(request.query_params.get("n") or 1000), 5000))
    except (TypeError, ValueError):
        n = 1000
    day = safe_audit_day(request.query_params.get("day"))
    blocks = [audit_metadata(e) for e in default_audit_log().tail(n, day=day) if e.get("kind") == "shield_block"]
    by_stage = Counter((e.get("stage") or "unknown") for e in blocks)
    top_reasons = [("Details are private; audit metadata only", len(blocks))] if blocks else []
    recent = list(reversed(blocks))[:100]
    return templates.TemplateResponse(
        request,
        "safety.html",
        {
            "total": len(blocks),
            "by_stage": dict(by_stage),
            "top_reasons": top_reasons,
            "events": recent,
            "n": n,
            "day": day,
        },
    )


def _compliance_view(framework: str) -> dict:
    """Build the control-coverage view for the /compliance page + export.

    Reuses ``maverick.compliance.compliance_report()`` (the same source the
    ``maverick compliance`` CLI maps to GDPR + EU AI Act + US frameworks) and
    applies the ``?framework=eu|us|all`` filter the CLI uses. Fail-soft: if the
    core import or the report raises, return an empty view so the page renders an
    empty state instead of 500ing. ``framework`` is normalised to one of
    ``eu``/``us``/``all`` (default ``all``).
    """
    framework = framework if framework in {"eu", "us", "all"} else "all"
    try:
        from maverick.compliance import COMPLIANCE_DISCLAIMER, compliance_report

        checks = compliance_report()
    except Exception:  # pragma: no cover - never 500 the console if core is absent
        return {"framework": framework, "groups": {}, "summary": {}, "disclaimer": ""}
    history = {"checked_at": None, "controls": {}, "changes": []}
    try:
        from maverick.compliance_history import record

        # Each visit is a check too: keep when it ran and since when each status holds.
        history = record(checks)
    except Exception:  # noqa: BLE001 -- the page renders without its history
        log.warning("compliance history unavailable", exc_info=True)
    if framework != "all":
        checks = [c for c in checks if c.framework == framework]
    # Group by framework bucket ("eu"/"us") for labelled tables on the page.
    labels = {
        "eu": "European Union (AI Act and GDPR)",
        "us": "United States (federal and state rules)",
    }
    groups: dict[str, dict] = {}
    for c in checks:
        bucket = groups.setdefault(
            c.framework, {"label": labels.get(c.framework, c.framework), "rows": []}
        )
        bucket["rows"].append(c)
    summary = {
        "active": sum(1 for c in checks if c.status == "active"),
        "action_needed": sum(1 for c in checks if c.status == "action_needed"),
        "total": len(checks),
    }
    return {
        "framework": framework,
        "groups": groups,
        "summary": summary,
        "disclaimer": COMPLIANCE_DISCLAIMER,
        "control_history": history,
    }


_COMPLIANCE_TABS = (("", "Coverage", "/compliance"), ("overview", "Overview", "/compliance?tab=overview"))


@app.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request, tab: str = "") -> HTMLResponse:
    """Auditor-ready control-coverage report (GDPR + EU AI Act + US frameworks).

    Org/system-level posture (like /safety), grouped by framework. The
    ``?framework=eu|us|all`` query param mirrors ``maverick compliance``.
    Control coverage only -- not a legal attestation. Fail-soft to an empty
    state so a missing core install never 500s the console. ``?tab=overview``
    shows the Autonomous Compliance landing to people who may open it.
    """
    from .navigation_api import areas_on, may_open

    tabs = list(_COMPLIANCE_TABS) if may_open(request, "/autonomous-compliance") else None
    if tab == "overview":
        if tabs is None:
            raise HTTPException(status_code=403, detail="this page is not enabled for your role")
        require_permission(request, "view")  # the landing's own check
        from .autonomous_compliance_page import landing_context, with_landing_headers

        context = landing_context()
        context["tab_host"] = {
            "kicker": "Governance", "title": "Compliance", "subtitle": "What is covered and what still needs doing",
            "label": "Compliance views", "tabs": tabs, "selected": "overview",
            "lede": "Everything you need to run your compliance program, in six areas. Pick a card to open "
                    "that part of Lightwork. Each card says whether it is ready to use today."}
        return with_landing_headers(templates.TemplateResponse(request, "autonomous_compliance.html", context))
    view = _compliance_view(request.query_params.get("framework") or "all")
    view["compliance_tabs"] = tabs if areas_on(request) else None
    from .compliance_controls_api import RETENTION_FIELDS, STATUS_TEXT, guide_for

    view["guide_for"] = guide_for
    view["status_word"] = lambda status: STATUS_TEXT.get(status, "Unknown").lower()
    view["retention_fields"] = RETENTION_FIELDS
    view["report_download_context"] = _conversation_context(request)
    view["can_admin"] = has_permission(request, "admin")
    view["can_operate"] = has_permission(request, "operate")
    view["can_global_admin"] = has_global_permission(request, "admin")
    view.update(_compliance_owner_view(request, view["can_admin"]))
    from .ediscovery_api import page_context as ediscovery_page_context

    view.update(ediscovery_page_context(request))
    return templates.TemplateResponse(request, "compliance.html", view)


def _compliance_owner_view(request: Request, can_admin: bool) -> dict:
    """Owners, due dates and steps for protections that need action, plus
    when the report was checked (it is computed live for this page)."""
    import datetime as _dt

    from . import compliance_owners
    try:
        owners = compliance_owners.load()
    except Exception:  # noqa: BLE001 -- the report still shows without owners
        owners = {}
    people: list[tuple[str, str]] = []
    if can_admin:
        try:
            from .rbac import list_users
            people = [(p, _idfmt.humanize_principal(p).name) for p in sorted(list_users())]
        except Exception:  # noqa: BLE001 -- a free choice is still offered below
            people = []
    return {"owners": owners, "owner_people": people, "checked_at": time.time(),
            "owner_steps": compliance_owners.steps_for, "owner_overdue": compliance_owners.overdue,
            "today": _dt.date.today().isoformat(),
            "owner_saved": request.query_params.get("owner_saved") == "1",
            "owner_error": {"control": "Choose a protection from the list.", "owner": "Choose an owner.",
                            "due": "Choose a due date."}.get(request.query_params.get("owner_error", ""), "")}


@app.post("/compliance/owners")
async def compliance_set_owner(request: Request) -> RedirectResponse:
    """Set the owner and due date of a protection that needs action. Workspace
    administrators only; each change is written to the activity record."""
    require_permission(request, "admin")
    _require_same_origin(request)
    from urllib.parse import urlencode

    from . import compliance_owners
    from .audit_actions_api import _audit_event
    form = await request.form()
    control = str(form.get("control", ""))
    owner = str(form.get("owner", ""))
    due = str(form.get("due", ""))
    try:
        from maverick.compliance import compliance_report
        known = {c.control for c in compliance_report()}
        entry = compliance_owners.save(control, owner=owner, due=due,
                                       actor=caller_principal(request) or "local", known=known)
    except compliance_owners.OwnerError as exc:
        code = "due" if "date" in str(exc) else "owner" if "owner" in str(exc) else "control"
        return RedirectResponse("/compliance?" + urlencode({"owner_error": code}) + "#cmp-attention",
                                status_code=303)
    _audit_event(request, "compliance_control_owner_set", control=control.strip(),
                 owner=entry["owner"], due=entry["due"])
    return RedirectResponse("/compliance?owner_saved=1#cmp-attention", status_code=303)


@app.get("/compliance/policy-links", response_class=HTMLResponse)
async def policy_publication_links_page(request: Request) -> HTMLResponse:
    """Review-gated evergreen public and private policy-link workspace."""

    require_permission(request, "operate")
    from maverick import policy_publication_links

    return templates.TemplateResponse(
        request,
        "policy_publication_links.html",
        {
            "policy_publication_links_enabled": policy_publication_links.enabled(),
            "policy_links_can_admin": has_global_permission(request, "admin"),
            "policy_links_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/compliance/scoping", response_class=HTMLResponse)
async def compliance_scoping_page(request: Request) -> HTMLResponse:
    """Closed-questionnaire technology-risk compliance-scoping workbench."""

    require_permission(request, "operate")
    from .compliance_scoping_api import compliance_scoping_enabled_for_page

    return templates.TemplateResponse(
        request,
        "compliance_scoping.html",
        {
            "compliance_scoping_enabled": compliance_scoping_enabled_for_page(),
            "can_admin": has_global_permission(request, "admin"),
            "can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/compliance/scope-actions", response_class=HTMLResponse)
async def compliance_scope_actions_page(request: Request) -> HTMLResponse:
    """Scope-derived control and evidence-task planning workbench."""

    require_permission(request, "operate")
    from .compliance_scope_actions_api import (
        compliance_scope_actions_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "compliance_scope_actions.html",
        {
            "compliance_scope_actions_enabled": (compliance_scope_actions_enabled_for_page()),
            "can_admin": has_global_permission(request, "admin"),
            "can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/compliance/continuous-evidence", response_class=HTMLResponse)
async def trc_continuous_evidence_page(request: Request) -> HTMLResponse:
    """Continuous technical-evidence collector operations workbench."""

    require_permission(request, "operate")
    from maverick.compliance_catalog import module_status

    from .trc_continuous_evidence_api import (
        trc_continuous_evidence_enabled_for_page,
    )

    return templates.TemplateResponse(
        request,
        "trc_continuous_evidence.html",
        {
            "trc_continuous_evidence_enabled": (
                trc_continuous_evidence_enabled_for_page()
            ),
            "acm_module_status": module_status("/compliance/continuous-evidence"),
            "trc_can_admin": has_global_permission(request, "admin"),
            "trc_can_audit": has_global_permission(request, "audit"),
        },
    )


@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request) -> HTMLResponse:
    """Show discovery, configuration, trust-gate, and import status."""
    require_global_permission(request, "admin")
    try:
        from maverick.plugins import installable_plugins, plugin_status_snapshot

        from maverick_dashboard.integration_readiness import plugin_readiness

        snapshot = plugin_status_snapshot()
        for items in snapshot["plugins"].values():
            for item in items:
                item["readiness"] = plugin_readiness(item)
        installable = installable_plugins()
    except Exception:
        return templates.TemplateResponse(
            request,
            "plugins.html",
            {
                "groups": {},
                "allowlist_active": False,
                "error": "Plugin discovery failed.",
                "installable": [],
                "install_enabled": _plugin_install_enabled(),
                "install_env_forced_off": _plugin_install_env_state() is False,
                "plugins_can_admin": has_global_permission(request, "admin"),
            },
        )
    discovery_errors = snapshot.get("discovery_errors") or []
    error = "; ".join(
        f"{item.get('kind', 'plugin')}: {item.get('error', 'discovery failed')}"
        for item in discovery_errors
    ) or None
    return templates.TemplateResponse(
        request,
        "plugins.html",
        {
            "groups": snapshot["plugins"],
            "allowlist_active": snapshot["allowlist_active"],
            "error": error,
            "installable": installable,
            "install_enabled": _plugin_install_enabled(),
            "install_env_forced_off": _plugin_install_env_state() is False,
            "plugins_can_admin": has_global_permission(request, "admin"),
        },
    )


def _plugin_install_env_state() -> bool | None:
    """The MAVERICK_ALLOW_PLUGIN_INSTALL env override: True/False when the
    operator set it explicitly, None when unset (config decides)."""
    env = os.environ.get("MAVERICK_ALLOW_PLUGIN_INSTALL", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    return None


def _plugin_install_enabled() -> bool:
    """Whether the dashboard may run plugin installs.

    Historically env-only (MAVERICK_ALLOW_PLUGIN_INSTALL) -- a shell step the
    dashboard promises not to need. Now `[plugins] allow_install` (settings
    overlay or config.toml) is the in-app path, and the env var keeps final
    say in BOTH directions: an explicit falsy value force-disables installs
    on a hardened deployment no matter what the overlay says.
    """
    env = _plugin_install_env_state()
    if env is not None:
        return env
    try:
        from maverick.config import load_config

        return bool(((load_config() or {}).get("plugins") or {}).get("allow_install", False))
    except Exception:  # pragma: no cover -- uncertainty cannot enable installs
        return False


@app.post("/plugins/toggle")
async def plugins_toggle(
    request: Request, name: str = Form(...), action: str = Form(...)
) -> RedirectResponse:
    """Enable / disable / reset a plugin from the dashboard. Writes the runtime
    overlay, never config.toml. Enabling loads the plugin's code on the next goal."""
    _require_same_origin(request)
    # Enabling a plugin loads its code on the next goal -- a control-plane
    # change as privileged as /plugins/install (which requires admin). Gate it
    # the same way so a viewer/operator can't alter what code the agent loads.
    require_global_permission(request, "admin")
    from maverick.runtime_overrides import (
        disable_plugin,
        enable_plugin,
        reset_plugin,
    )

    fn = {"enable": enable_plugin, "disable": disable_plugin, "reset": reset_plugin}.get(action)
    if fn is None:
        raise HTTPException(status_code=400, detail="unknown action")
    try:
        fn(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid plugin name") from exc
    return RedirectResponse("/plugins", status_code=303)


@app.post("/plugins/install")
async def plugins_install(request: Request, name: str = Form(...)) -> RedirectResponse:
    """Install a plugin *package* the operator pre-approved in ``[plugins]
    installable``, then redirect back so its slots show up to enable.

    Sensitive (runs ``pip install``), so it's quad-gated: same-origin, an
    explicit install opt-in (the [plugins] allow_install switch on the
    Plugins page, or MAVERICK_ALLOW_PLUGIN_INSTALL -- whose falsy value
    force-disables regardless of config), the admin role, and the install
    allowlist (``install_plugin`` rejects anything not on it). Only the
    allowlisted package names are ever accepted -- never free-text input."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    if not _plugin_install_enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "Installing plugins from the dashboard is disabled on this "
                "server — an administrator can opt in from the Plugins page "
                "(or with MAVERICK_ALLOW_PLUGIN_INSTALL=1)."
            ),
        )
    from maverick.plugins import install_plugin

    try:
        install_plugin(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/plugins", status_code=303)


@app.post("/plugins/approvals")
async def plugins_approvals(
    request: Request, names: list[str] = Form([])  # ticked boxes plus one new name
) -> RedirectResponse:
    """Replace the pre-approved install allowlist from the Plugins page.

    The allowlist decides WHAT the one-click installer may ever pull, so it is
    admin + same-origin gated and every name must be a plain distribution name
    (the store re-applies install_plugin's _SAFE_PKG check at write time).
    ``names`` is a whitespace/comma/newline-separated list; an empty submission
    clears the allowlist (fail closed)."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick_dashboard import settings_store

    parsed = [p for value in names for chunk in value.replace(",", "\n").splitlines() for p in chunk.split()]
    from maverick.plugins import installable_plugins

    wanted = list(dict.fromkeys(parsed))
    hold, approved = await run_in_threadpool(
        _plugins_quorum, request, "installable", "Plugins that can be installed",
        list(installable_plugins()), wanted)
    if hold is not None:
        return hold
    try:
        from .settings_audit import bind_setting_write

        with bind_setting_write(
            request, section="plugins", key="installable",
            project=lambda d: (d.get("plugins") or {}).get("installable", []),
            confirmed=approved is not None,
        ):
            await run_in_threadpool(settings_store.set_installable_plugins, parsed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    from maverick.config import reset_config_cache

    reset_config_cache()
    await run_in_threadpool(_settle_plugins_quorum, approved)
    return RedirectResponse("/plugins", status_code=303)


@app.post("/plugins/install-switch")
async def plugins_install_switch(
    request: Request, enabled: str = Form(...)
) -> RedirectResponse:
    """Flip the in-app plugin-install opt-in ([plugins] allow_install) from
    the Plugins page. Admin + same-origin; an explicit falsy
    MAVERICK_ALLOW_PLUGIN_INSTALL still force-disables installs regardless."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    if enabled not in {"on", "off"}:
        raise HTTPException(status_code=400, detail="enabled must be 'on' or 'off'")
    from maverick_dashboard import settings_store

    hold, approved = await run_in_threadpool(
        _plugins_quorum, request, "allow_install", "Install plugins from this page",
        _plugin_install_enabled(), enabled == "on")
    if hold is not None:
        return hold
    from .settings_audit import bind_setting_write

    with bind_setting_write(
        request, section="plugins", key="allow_install",
        project=lambda d: (d.get("plugins") or {}).get("allow_install"),
        confirmed=approved is not None,
    ):
        await run_in_threadpool(settings_store.set_plugin_install_allowed, enabled == "on")
    from maverick.config import reset_config_cache

    reset_config_cache()
    await run_in_threadpool(_settle_plugins_quorum, approved)
    return RedirectResponse("/plugins", status_code=303)


def _plugins_quorum(request: Request, key: str, label: str, old: object,
                    new: object) -> tuple[JSONResponse | None, str | None]:
    """[plugins] is protected by the settings quorum ([safety] quorum_*), so a
    change here waits for other administrators exactly as on All settings.
    Returns ``(held response, None)`` or ``(None, approved change id)``."""
    if old == new:
        return None, None
    from types import SimpleNamespace

    from maverick_dashboard import auth as auth_module
    from maverick_dashboard import settings_quorum

    actor = auth_module.caller_principal(request) or "local administrator"
    change = [{"setting": SimpleNamespace(id=f"plugins.{key}", label=label),
               "old": old, "new": new}]
    hold, approved = settings_quorum.review(change, actor, lambda _s, value: value)
    if hold is not None:
        return JSONResponse({"changed": [], "quorum": hold, "message": hold["message"]},
                            status_code=202, headers={"Cache-Control": "no-store"}), None
    return None, approved


def _settle_plugins_quorum(approved: str | None) -> None:
    from maverick_dashboard import settings_quorum

    settings_quorum.settle(approved)


@app.get("/mcp", response_class=HTMLResponse)
async def mcp_page(request: Request, saved: str = "") -> HTMLResponse:
    """MCP servers: config.toml entries (read-only here) plus dashboard-added
    servers (overlay, removable). Admins add a new server from the form below —
    no config.toml editing needed."""
    require_global_permission(request, "admin")
    try:
        from maverick_dashboard.integration_readiness import mcp_inventory

        rows = mcp_inventory()
    except RuntimeOverridesSecurityError:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="MCP inventory is unavailable",
        ) from exc
    saved_msg = {
        "add": "Tool server added. Press Test to check that it works.",
        "remove": "Tool server removed.",
        "test": "Test finished. The result is shown next to the server.",
    }.get(saved, "")
    from .mcp_presets import PRESETS as _MCP_PRESETS
    return templates.TemplateResponse(
        request,
        "mcp.html",
        {"servers": rows, "saved": saved_msg, "presets": _MCP_PRESETS},
    )


def _parse_kv_lines(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines (env / headers from the MCP add form) into a
    dict, skipping blanks and lines without an ``=``."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


@app.post("/mcp/add")
async def mcp_add(request: Request) -> RedirectResponse:
    """Add a dashboard-managed MCP server from the form. Builds a stdio
    (command/args/env) or http (url/headers/auth) spec and stores it in the
    runtime overlay; the kernel validates + unions it on the next goal."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick.runtime_overrides import add_mcp_server

    form = await request.form()
    name = (form.get("name") or "").strip()
    transport = (form.get("transport") or "stdio").strip()
    spec: dict = {}
    if transport == "http":
        url = (form.get("url") or "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="a URL is required for an http server")
        spec["url"] = url
        token = (form.get("auth_token") or "").strip()
        if token:
            spec["auth_token"] = token
        headers = _parse_kv_lines(form.get("headers") or "")
        if headers:
            spec["headers"] = headers
    else:
        command = (form.get("command") or "").strip()
        if not command:
            raise HTTPException(status_code=400, detail="a command is required for a stdio server")
        spec["command"] = command
        args = [a.strip() for a in (form.get("args") or "").splitlines() if a.strip()]
        if args:
            spec["args"] = args
        env = _parse_kv_lines(form.get("env") or "")
        if env:
            spec["env"] = env
    try:
        add_mcp_server(name, spec)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid MCP server: {exc}") from exc
    return RedirectResponse("/mcp?saved=add", status_code=303)


@app.post("/mcp/remove")
async def mcp_remove(request: Request, name: str = Form(...)) -> RedirectResponse:
    """Remove a dashboard-added MCP server (config.toml servers are untouched)."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick.runtime_overrides import remove_mcp_server

    remove_mcp_server((name or "").strip())
    return RedirectResponse("/mcp?saved=remove", status_code=303)


@app.post("/mcp/test")
async def mcp_test(request: Request, name: str = Form(...)) -> RedirectResponse:
    """Run a bounded initialize/tools-list handshake for one configured server."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick_dashboard.integration_readiness import mcp_server_config, test_mcp

    server = (name or "").strip()
    spec = mcp_server_config(server)
    if spec is None:
        raise HTTPException(status_code=404, detail="no such MCP server")
    await test_mcp(server, spec)
    return RedirectResponse("/mcp?saved=test", status_code=303)


@app.get("/tools", response_class=HTMLResponse)
def tools_page(
    request: Request,
    q: str = Query(default="", max_length=128),
    page: int = Query(default=1, ge=1, le=100_000),
    per_page: int = Query(default=50, ge=1, le=100),
) -> HTMLResponse:
    """Bounded registered-tool inventory (post-ACL, post-rate-limit)."""
    tools: list[dict] = []
    error = None
    enterprise_blocked_total = 0
    query = q.strip()
    tool_page = {
        "query": query,
        "page": page,
        "per_page": per_page,
        "catalog_total": 0,
        "filtered_total": 0,
        "returned": 0,
        "page_count": 1,
        "first": 0,
        "last": 0,
    }
    try:
        from maverick.sandbox import build_sandbox
        from maverick.tools import base_registry, enterprise_unavailable_tool_names

        from .tool_summary import plain_tool_summary

        wm = _world()  # honor the configured backend (SQLite or Postgres)
        sb = build_sandbox()
        reg = base_registry(world=wm, sandbox=sb)
        enterprise_blocked = enterprise_unavailable_tool_names()
        # One snapshot of the permitted tools serves the list and its summaries.
        registered = {t.name: t for t in reg.all()}
        catalog = [
            {
                "name": t.name,
                "description": (t.description or "")[:240],
                "summary": plain_tool_summary(t.name, t.description) if query else "",
                "enterprise_blocked": t.name in enterprise_blocked,
            }
            for t in sorted(registered.values(), key=lambda x: x.name)
        ]
        enterprise_blocked_total = sum(1 for tool in catalog if tool["enterprise_blocked"])
        folded = query.casefold()
        filtered = [
            tool
            for tool in catalog
            if not folded
            or folded in tool["name"].casefold()
            or folded in tool["description"].casefold()
            or folded in tool["summary"].casefold()
        ]
        page_count = max(1, (len(filtered) + per_page - 1) // per_page)
        if page > page_count:
            raise HTTPException(
                status_code=400,
                detail="tool page exceeds the available search results",
            )
        start = (page - 1) * per_page
        tools = filtered[start : start + per_page]
        if not query:
            # Browsing needs only this page's copy. Searches still inspect
            # every current permitted summary, including its full description.
            for tool in tools:
                tool["summary"] = plain_tool_summary(tool["name"], registered[tool["name"]].description)
        tool_page = {
            "query": query,
            "page": page,
            "per_page": per_page,
            "catalog_total": len(catalog),
            "filtered_total": len(filtered),
            "returned": len(tools),
            "page_count": page_count,
            "first": start + 1 if tools else 0,
            "last": start + len(tools),
        }
    except RuntimeOverridesSecurityError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    return templates.TemplateResponse(
        request,
        "tools.html",
        {
            "tools": tools,
            "error": error,
            "tool_page": tool_page,
            "enterprise_blocked_total": enterprise_blocked_total,
        },
    )


_TOOL_PREREQUISITE_STATES = {"ready", "blocked", "unknown", "not_required"}


def _tool_prerequisite(status: str, detail: str) -> dict:
    """One closed readiness dimension for a registered tool."""
    normalized = str(status or "unknown").strip().lower()
    if normalized not in _TOOL_PREREQUISITE_STATES:
        normalized = "unknown"
        detail = "invalid readiness evidence was rejected"
    return {
        "status": normalized,
        "ready": (
            True
            if normalized in {"ready", "not_required"}
            else False
            if normalized == "blocked"
            else None
        ),
        "detail": str(detail)[:240],
    }


def _tool_permission_row(
    name: str,
    *,
    catalog_present: bool,
    base_acl_allowed: bool,
    effective_acl_allowed: bool | None = None,
    overlay_blocked: bool = False,
    provider_status: str = "unknown",
    connection_status: str = "unknown",
    feature_policy_status: str = "unknown",
    sandbox_status: str = "unknown",
    sandbox_constructed: bool = False,
    base_acl_detail: str = "",
) -> dict:
    """Build a fail-closed, dimensioned tool-usability statement.

    The current registry does not declare provider, connection, or feature
    dependencies per tool.  Those dimensions therefore stay ``unknown`` until
    a caller supplies explicit evidence; catalog presence and ACL admission can
    never silently stand in for them.
    """

    def dependency(status: str, label: str) -> dict:
        normalized = str(status or "unknown").strip().lower()
        detail = {
            "ready": f"required {label} is explicitly ready",
            "blocked": f"required {label} is blocked or unready",
            "not_required": f"{label} is explicitly not required",
            "unknown": (
                f"required-{label} dependency metadata is not declared for this tool"
            ),
        }.get(normalized, f"{label} readiness evidence is invalid")
        return _tool_prerequisite(normalized, detail)

    sandbox_normalized = str(sandbox_status or "unknown").strip().lower()
    sandbox_detail = {
        "ready": (
            "sandbox construction and tool-level readiness are explicitly verified"
        ),
        "blocked": "sandbox construction or readiness is blocked",
        "not_required": "this tool explicitly does not require a sandbox",
        "unknown": (
            "sandbox constructed, but tool-level execution readiness was not probed"
            if sandbox_constructed
            else "sandbox construction/readiness evidence is unavailable"
        ),
    }.get(sandbox_normalized, "sandbox evidence is invalid")
    if effective_acl_allowed is None:
        effective_acl_allowed = base_acl_allowed and not overlay_blocked
    prerequisites = {
        "provider": dependency(provider_status, "provider"),
        "connection": dependency(connection_status, "connection"),
        "feature_policy": dependency(
            feature_policy_status,
            "feature/module policy",
        ),
        "base_acl": _tool_prerequisite(
            "ready" if base_acl_allowed else "blocked",
            base_acl_detail
            or (
                "tool is admitted by the effective base ACL"
                if base_acl_allowed
                else "tool is blocked by the effective base ACL"
            ),
        ),
        "dashboard_override": _tool_prerequisite(
            "blocked" if overlay_blocked else "ready",
            (
                "tool is blocked by the dashboard runtime override"
                if overlay_blocked
                else "no dashboard runtime override blocks this tool"
            ),
        ),
        "effective_acl": _tool_prerequisite(
            "ready" if effective_acl_allowed else "blocked",
            (
                "the production ACL resolver admits this tool"
                if effective_acl_allowed
                else "the production ACL resolver blocks this tool"
            ),
        ),
        "sandbox": _tool_prerequisite(
            sandbox_normalized,
            sandbox_detail,
        ),
    }
    blocked = [
        key for key, value in prerequisites.items() if value["status"] == "blocked"
    ]
    unknown = [
        key for key, value in prerequisites.items() if value["status"] == "unknown"
    ]
    usable = bool(
        catalog_present
        and not blocked
        and not unknown
        and all(
            value["status"] in {"ready", "not_required"}
            for value in prerequisites.values()
        )
    )
    if not catalog_present:
        state = "not_in_catalog"
        reason = "tool is not present in the assembled catalog"
    elif any(
        dimension in blocked
        for dimension in ("base_acl", "dashboard_override", "effective_acl")
    ):
        state = "policy_blocked"
        reason = (
            prerequisites["base_acl"]["detail"]
            if "base_acl" in blocked
            else prerequisites["dashboard_override"]["detail"]
            if "dashboard_override" in blocked
            else prerequisites["effective_acl"]["detail"]
        )
    elif blocked:
        state = "prerequisite_blocked"
        reason = "blocked prerequisite(s): " + ", ".join(blocked)
    elif unknown:
        state = "readiness_unknown"
        reason = (
            "usability is unverified; unknown prerequisite(s): "
            + ", ".join(unknown)
        )
    else:
        state = "usable"
        reason = "every declared prerequisite is ready"
    return {
        "name": str(name),
        # Backward compatibility only: ``enabled`` now aliases strict usability,
        # not the narrower ACL-admission result.
        "enabled": usable,
        "usable": usable,
        "catalog_present": bool(catalog_present),
        "configured": None,
        "provider_ready": prerequisites["provider"]["ready"],
        "connection_ready": prerequisites["connection"]["ready"],
        "feature_policy_allowed": prerequisites["feature_policy"]["ready"],
        "base_acl_allowed": prerequisites["base_acl"]["ready"] is True,
        "policy_allowed": prerequisites["effective_acl"]["ready"] is True,
        "overlay_blocked": bool(overlay_blocked),
        "sandbox_constructed": bool(sandbox_constructed),
        "sandbox_ready": prerequisites["sandbox"]["ready"],
        "runtime_ready": None,
        "prerequisites": prerequisites,
        "unready_dimensions": blocked + unknown,
        "state": state,
        "reason": reason,
    }


def _permissions_snapshot() -> dict:
    """Aggregate everything the agent is currently allowed to do.

    Read-only view assembled from config + the live registry + the
    dashboard's runtime overrides. Powers the /permissions page and
    GET /api/v1/permissions.
    """
    snap: dict = {
        "tools": [],
        "capabilities": {},
        "channels": [],
        "sandbox": {},
        "budget": {},
        "network": "open",
        "plugins": [],
        "providers": [],
        "provider_states": [],
        "retention": {},
        "overlay_denied": [],
        "error": None,
        "sandbox_warning": None,
    }
    try:
        from maverick.config import load_config

        cfg = load_config() or {}
    except Exception as e:
        snap["error"] = f"config read failed: {type(e).__name__}: {e}"
        cfg = {}

    snap["capabilities"] = cfg.get("capabilities") or {}
    snap["budget"] = cfg.get("budget") or {}
    snap["retention"] = cfg.get("retention") or {}
    snap["sandbox"] = cfg.get("sandbox") or {}
    # Security surface: the default 'local' sandbox runs model-driven shell on
    # the host with no filesystem/network isolation (secret env vars are
    # scrubbed, but it is not a container). Make the posture explicit on the
    # /permissions page + API instead of leaving it silent.
    _sb_backend = str(snap["sandbox"].get("backend") or "local").strip().lower()
    if _sb_backend == "local":
        snap["sandbox_warning"] = (
            "Work runs directly on this computer, with no isolation from its "
            "files or network. For goals you do not fully trust, choose an "
            "isolated container under Where work runs."
        )
    try:
        from maverick.config import provider_configuration_state

        from maverick_dashboard.settings_store import PROVIDERS

        snap["provider_states"] = [
            provider_configuration_state(spec["name"]) for spec in PROVIDERS
        ]
        snap["providers"] = sorted(
            state["name"]
            for state in snap["provider_states"]
            if state["configured"]
        )
    except Exception as e:
        snap["provider_states"] = []
        snap["error"] = (snap["error"] or "") + (
            f" provider state: {type(e).__name__}: {e}"
        )
    snap["channels"] = [
        {"name": n, "enabled": bool(c.get("enabled", True))}
        for n, c in (cfg.get("channels") or {}).items()
    ]
    sec = cfg.get("security") or {}
    # The enforced network posture ([security] network_policy), normalized, so
    # the page never shows a label the kernel does not apply.
    from maverick.sandbox.network_policy import network_posture

    snap["network"] = network_posture(cfg)

    try:
        from maverick.runtime_overrides import denied_tools as _overlay

        snap["overlay_denied"] = sorted(_overlay())
    except RuntimeOverridesSecurityError:
        raise
    except Exception:
        snap["overlay_denied"] = []

    # Capture the catalog before ACL filtering, then apply the exact production
    # ACL resolver. Registry presence proves only that a tool implementation was
    # assembled and admitted by policy; it does NOT prove credentials,
    # dependency health, network reachability, or a successful live call.
    sandbox_constructed = False
    sandbox_status = "unknown"
    base_policy_allowed: set[str] = set()
    try:
        from maverick.safety.tool_acl import apply_to_registry, filter_tools, resolve_max_risk
        from maverick.safety.tool_risk import tools_exceeding
        from maverick.sandbox import build_sandbox
        from maverick.tools import base_registry

        wm = _world()  # honor the configured backend (SQLite or Postgres)
        sandbox = build_sandbox()
        sandbox_constructed = True
        reg = base_registry(
            world=wm,
            sandbox=sandbox,
            _skip_tool_acl=True,
        )
        catalog = {t.name for t in reg.all()}
        allowed = set(sec.get("allowed_tools") or [])
        denied = set(sec.get("denied_tools") or [])
        max_risk = resolve_max_risk()
        if max_risk:
            denied |= tools_exceeding(catalog, max_risk)
        base_policy_allowed = filter_tools(
            catalog,
            allowed=allowed,
            denied=denied,
        )
        apply_to_registry(reg)
        policy_allowed = {t.name for t in reg.all()}
    except RuntimeOverridesSecurityError:
        raise
    except Exception as e:
        snap["error"] = (snap["error"] or "") + f" registry: {type(e).__name__}: {e}"
        catalog = set()
        policy_allowed = set()
        sandbox_status = "blocked"
    # Show every assembled catalog tool, including policy-denied rows. Runtime
    # readiness remains explicitly unverified until a typed readiness receipt
    # exists for that connector/tool.
    names = sorted(catalog | set(snap["overlay_denied"]))
    snap["tools"] = []
    for name in names:
        admitted = name in policy_allowed
        base_admitted = name in base_policy_allowed
        overlay_blocked = name in snap["overlay_denied"]
        if overlay_blocked:
            acl_detail = (
                "tool is admitted by the configured base ACL"
                if base_admitted
                else "tool is blocked by the configured base ACL or risk policy"
            )
        elif not base_admitted:
            acl_detail = "blocked by the configured base ACL or risk policy"
        else:
            acl_detail = "tool is admitted by the configured base ACL"
        snap["tools"].append(
            _tool_permission_row(
                name,
                catalog_present=name in catalog,
                base_acl_allowed=base_admitted,
                effective_acl_allowed=admitted,
                overlay_blocked=overlay_blocked,
                sandbox_status=sandbox_status,
                sandbox_constructed=sandbox_constructed,
                base_acl_detail=acl_detail,
            )
        )

    try:
        from maverick.plugins import installed_plugins

        snap["plugins"] = installed_plugins()
    except RuntimeOverridesSecurityError:
        raise
    except Exception:
        snap["plugins"] = {}
    return snap


def _permissions_tool_page(
    snapshot: dict,
    *,
    q: str = "",
    state: str = "all",
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Return a bounded, filterable tool slice without mutating ``snapshot``."""

    query = q.strip().casefold()
    if len(query) > 128:
        raise HTTPException(status_code=400, detail="tool search is limited to 128 characters")
    selected_state = state.strip().lower() or "all"
    if selected_state not in {"all", "admitted", "blocked"}:
        raise HTTPException(status_code=400, detail="state must be all, admitted, or blocked")
    if page < 1 or per_page < 1 or per_page > 100:
        raise HTTPException(status_code=400, detail="invalid tool page bounds")

    catalog = list(snapshot.get("tools") or [])
    filtered = [
        tool
        for tool in catalog
        if (
            not query
            or query in str(tool.get("name") or "").casefold()
            or query in str(tool.get("reason") or "").casefold()
        )
        and (
            selected_state == "all"
            or bool(tool.get("policy_allowed")) == (selected_state == "admitted")
        )
    ]
    start = (page - 1) * per_page
    result = dict(snapshot)
    result["tools"] = filtered[start : start + per_page]
    result["tool_page"] = {
        "query": q.strip(),
        "state": selected_state,
        "page": page,
        "per_page": per_page,
        "catalog_total": len(catalog),
        "admitted_total": sum(bool(tool.get("policy_allowed")) for tool in catalog),
        "filtered_total": len(filtered),
        "returned": len(result["tools"]),
        "page_count": max(1, (len(filtered) + per_page - 1) // per_page),
        "complete": start == 0 and len(result["tools"]) == len(filtered),
    }
    return result


_PERMISSION_TABS = (("", "Permissions", "/permissions"), ("inventory", "Inventory", "/permissions?tab=inventory"))


@app.get("/permissions", response_class=HTMLResponse)
async def permissions_page(
    request: Request,
    q: str = Query(default="", max_length=128),
    state: str = Query(default="all"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=100),
    tab: str = Query(default="", max_length=32),
) -> HTMLResponse:
    """What Lightwork can do — tools, capabilities, channels, data flow.
    ``?tab=inventory`` shows everything Lightwork can use here (the
    /discovery page) to people who may open it."""
    from .navigation_api import areas_on, may_open

    tabs = list(_PERMISSION_TABS) if may_open(request, "/discovery") else None
    if tab == "inventory":
        if tabs is None:
            raise HTTPException(status_code=403, detail="this page is not enabled for your role")
        from .control_plane import discovery_overview

        return templates.TemplateResponse(request, "discovery.html", {
            "discovery": discovery_overview(),
            "tab_host": {"kicker": "Governance", "title": "Permissions", "subtitle": "What Lightwork can do",
                         "label": "Permissions views", "tabs": tabs, "selected": "inventory",
                         "lede": "Everything Lightwork can use here and keep under your rules: actions, connected "
                                 "tool servers, AI providers, channels and outside agents."}})
    perm = _permissions_tool_page(
        _permissions_snapshot(),
        q=q,
        state=state,
        page=page,
        per_page=per_page,
    )
    return templates.TemplateResponse(
        request,
        "permissions.html",
        {
            "perm": perm,
            "permissions_can_manage_sandbox": has_global_permission(request, "admin"),
            "permissions_can_manage_tools": has_global_permission(request, "operate"),
            "permission_tabs": tabs if areas_on(request) else None,
        },
    )


# The audit kind a governance verdict records when it blocks or parks an
# action (see maverick.governance + the kernel tool path). Referenced as a
# literal so the dashboard reads the log even on a kernel build that predates
# the EventKind constant; resolved from the constant when it exists.
def _governance_event_kind() -> str:
    try:
        from maverick.audit import EventKind

        return getattr(EventKind, "GOVERNANCE_DENIED", "governance_denied")
    except Exception:  # pragma: no cover - audit module always importable
        return "governance_denied"


def _approval_source(provenance: str | None) -> str | None:
    """Label trusted governance/Art-14 approvals, else ``None``.

    Approval ``detail`` is free-form operator context and may include
    model-, user-, or remote-server-controlled text. Only the explicit
    trusted ``provenance`` field may drive source labels in the decision UI.
    """
    if provenance == "governance":
        return "Required human oversight (EU AI Act)"
    if provenance == "external_agents":
        return "Outside agent"
    if provenance == "harness_refine":
        # The agent is asking to change its OWN operating instructions.
        # An approver must be able to see that at a glance, not read it as
        # an ordinary task approval.
        return "Agent wants to change its own instructions"
    if provenance == "assessment":
        return "Assessment review"
    if provenance == "plan":
        # [autonomy] confirm_plan: the task's first outside action waits for
        # a person to check the whole plan (maverick.plan_review).
        return "Plan to check before the task acts"
    if provenance == "goal_risk":
        # A task held before it starts because its wording looks risky.
        return "Task waiting to start"
    if provenance == "ifc":
        return "Sensitive data about to leave Lightwork"
    return None


def _approval_viewer_context(request: Request | None, approvals: list) -> dict:
    """Who is looking at the queue, so a card can say "your own request", and
    -- when the enforced rules keep that person from approving it (someone
    else must, or under two-person approval their vote doesn't count) -- why.
    Also which waiting requests have had their one reminder sent."""
    if request is None:
        return {"approval_viewer": "", "own_request_notes": {}, "approval_reminders": set()}
    from .api import _supervisor
    from .approval_decisions import own_request_note
    from .approval_reminders import reminder_sent

    viewer = _supervisor(request)
    world = _world()
    notes = {}
    reminders = set()
    for approval in approvals:
        note = own_request_note(world, approval, viewer)
        if note:
            notes[approval.id] = note
        if reminder_sent(world, approval):
            reminders.add(approval.id)
    return {"approval_viewer": viewer, "own_request_notes": notes, "approval_reminders": reminders}


def _approval_progress(approvals: list, request: Request) -> dict:
    """Each pending card's approval progress, in the words the card shows.

    The same facts ``GET /api/v1/approvals/{id}/state`` returns, rendered with
    the page instead of fetched once per card after load. Callers pass only
    the approvals the viewer may open (the page routes filter with
    ``can_read_approval``, the state API's content check); the state API's
    operate floor applies here too.
    """
    if not has_permission(request, "operate"):
        return {}
    from maverick.safety.dual_control import allow_self_approval

    from .api import _supervisor
    from .approval_decisions import own_request_note

    who = _supervisor(request)
    world = _world()
    progress = {}
    for approval in approvals:
        try:
            state = world.approval_state(approval.id)
        except Exception:  # noqa: BLE001 - the card keeps its server-side checks
            continue
        if not state or state.get("status") != "pending":
            continue
        required = int(state.get("approvals_required") or 1)
        words = ["One approval is needed." if required <= 1
                 else f"{state.get('approved_count', 0)} of {required} required approvals received."]
        recorded = who in (state.get("approvers") or [])
        if recorded:
            words.append("Your approval is recorded.")
        elif state.get("requested_by") and state.get("requested_by") == who:
            # The words follow what is enforced: one approver may be the person
            # who asked; under two-person approval their vote may not count.
            # When another approver must decide, the card already says why.
            if own_request_note(world, approval, who):
                pass
            elif required > 1 and not allow_self_approval():
                words.append("You asked for this, so other people must approve it.")
            elif required <= 1:
                words.append("You asked for this, so approving it approves your own request.")
            else:
                words.append("You asked for this; your approval counts as one of them.")
        progress[approval.id] = {"text": " ".join(words), "recorded": recorded}
    return progress


def _approval_queue_context(approvals: list, request: Request | None = None) -> dict:
    """Build the exact-operation review context shared by approval surfaces."""

    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    from maverick.safety.secret_detector import redact

    def safe(value: object, *, fallback: str = "") -> str:
        try:
            text, _matches = redact(" ".join(str(value or "").split()))
            return text[:2000]
        except Exception:
            return fallback

    sources = {approval.id: _approval_source(approval.provenance) for approval in approvals}
    cards = {}
    card_statuses = {}
    approval_details = {}
    approval_actions = {}
    approval_scopes = {}
    assessment_ids = {}
    for approval in approvals:
        approval_actions[approval.id] = safe(
            approval.action, fallback="reviewed operation",
        )
        approval_scopes[approval.id] = safe(
            approval.scope, fallback="reviewed target",
        )
        # Assessment UI enhancement is selected from explicit, app-owned
        # provenance. Free-form detail, target labels, and model output must not
        # be able to opt another approval into a DOM rewrite by containing an
        # ``assessment:...`` substring.
        if approval.provenance == "assessment":
            assessment_match = re.search(
                r"\[assessment:([A-Za-z0-9._-]{1,128})\]\s*$",
                str(approval.detail or ""),
            )
            if assessment_match:
                assessment_ids[approval.id] = assessment_match.group(1)
        try:
            card = decode_approval_detail(approval.detail)
        except ApprovalCardError:
            card = None
            card_statuses[approval.id] = "invalid"
            approval_details[approval.id] = (
                "Structured approval details failed their integrity check."
            )
        else:
            cards[approval.id] = card
            approval_details[approval.id] = (
                card["summary"] if card is not None else safe(approval.detail)
            )
            card_statuses[approval.id] = (
                "expired"
                if card is not None and time.time() >= card["expires_at"]
                else ("current" if card is not None else "legacy")
            )
    return {
        "sources": sources,
        "cards": cards,
        "card_statuses": card_statuses,
        "approval_details": approval_details,
        "approval_actions": approval_actions,
        "approval_scopes": approval_scopes,
        "assessment_ids": assessment_ids,
        "approval_progress": _approval_progress(approvals, request) if request is not None else {},
        **_approval_viewer_context(request, approvals),
    }


def _all_decisions_view(request: Request, view: str) -> dict:
    """Approvals' ``?view=all``: the Action Center's list (every kind of item
    waiting on you) in place of the approvals list, under the hero's same
    approval count. Only for people the Action Center itself admits -- its
    page policy, ``operate`` and its feature switch -- refused with the Action
    Center's own answer otherwise. In the job-named navigation the Approvals
    section's page tabs (Approvals, Action Center) switch between the two."""
    from .action_center_api import require_enabled
    from .draft_api import context_for

    if view != "all":
        return {"approvals_view": ""}
    require_page_visible(request, "/action-center")
    require_enabled(request)
    return {"approvals_view": "all", "action_context": context_for(request),
            "can_admin": has_permission(request, "admin")}


@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request, view: str = "") -> HTMLResponse:
    """Pending high-risk actions awaiting approve/deny.

    Populated when an agent runs with ``MAVERICK_CONSENT_MODE=dashboard``:
    ``safety.consent.require_consent`` parks each gated action here and
    polls for the decision this page writes back. Governance ``REQUIRE_HUMAN``
    holds (EU AI Act Art 14) arrive with trusted provenance metadata;
    ``_approval_source`` labels them so an operator can distinguish a policy
    hold from a plain consent one without trusting free-form detail text.

    Gated on ``operate`` to match the ``/api/v1/approvals`` twin: the queue has
    no per-user owner and may carry another user's goal content in ``detail``,
    so a view-only caller must not read it via the HTML page either.
    """
    require_permission(request, "operate")
    from . import content_access
    from .content_access import can_read_approval
    from .flow_approval_inbox import pending_for_request

    all_view = _all_decisions_view(request, view)
    world = _world()
    pending = list(world.pending_approvals())
    approvals = [row for row in pending if can_read_approval(request, row, world)]
    flow_approvals = pending_for_request(request)
    # Requests from colleagues' private tasks: a card with only who asked,
    # the action and its risk, the agent or specialist and the expiry.
    from .api import _supervisor
    from .approval_private_cards import private_cards

    readable = {row.id for row in approvals}
    private = private_cards(world, [row for row in pending if row.id not in readable],
                            _supervisor(request) or "")
    return templates.TemplateResponse(
        request,
        "approvals.html",
        {
            "approvals": approvals,
            "flow_approvals": flow_approvals["items"],
            "flow_approval_coverage": flow_approvals["coverage"],
            "private_count": len(pending) - len(approvals),
            "private_cards": private,
            "viewer_role": _approval_viewer_role(request),
            # Link to Content access only when asking for a card read is on.
            "content_access_on": content_access.enabled(),
            **_approval_queue_context(approvals, request),
            **all_view,
        },
        headers={"Cache-Control": "private, no-store"},
    )


def _approval_viewer_role(request: Request) -> str:
    """The viewer's role name in this workspace, for "why you see this"."""
    from . import auth as _auth
    from .api import _supervisor

    try:
        return _auth.role_for_principal(_supervisor(request) or "") or ""
    except Exception:  # an unreadable roster names no role
        return ""


def _recent_governance_holds(limit: int = 10) -> list[dict]:
    """The most recent governance oversight events for the operator console.

    Reuses the audit reader behind ``/audit`` (today's NDJSON tail), filtered to
    governance verdicts (``GOVERNANCE_DENIED``) and returned newest-first. These
    are the Art-14 / Art-12 record of every org-policy block + human-oversight
    hold. Fail-soft: a missing/unreadable log yields an empty panel, never a 500.
    """
    try:
        from maverick.audit import default_audit_log

        kind = _governance_event_kind()
        events = [e for e in default_audit_log().tail(500) if e.get("kind") == kind]
    except Exception:  # pragma: no cover - never 500 the console on a log error
        return []
    from .content_access import audit_metadata
    return [audit_metadata(event) for event in reversed(events)][:limit]


def _fleet_typical_costs(fleets: list) -> tuple[dict, dict | None]:
    """What each team agent's past tasks usually cost, beside the task form,
    and the workspace's remaining budget. A specialist's history is its pack's
    tasks in this workspace; any other agent's is its own tasks."""
    from maverick.typical_cost import min_runs, typical_cost

    world, minimum = _world(), min_runs()
    costs: dict[str, dict] = {}
    for fleet in fleets:
        for agent in fleet.agents:
            principal = "" if agent.domain else fleet.principal_for(agent.name)
            costs[f"{fleet.name}/{agent.name}"] = typical_cost(
                world, specialist=agent.domain or "", agent_principal=principal, minimum=minimum)
    try:
        from maverick import spending_limits

        workspace = spending_limits.workspace_standing()
    except Exception:  # noqa: BLE001 -- the task form still works; the line is left out
        workspace = None
    return costs, workspace


def _fleet_recent_runs(fleet_name: str, *, owner: str | None = None, limit: int = 12) -> list[dict]:
    """A fleet's recent agent runs for the operator console (newest-first).

    Mirrors ``maverick fleet status``: reads the per-fleet run index
    (``maverick.fleet.load_runs``) and resolves each run's goal via the
    dashboard world to recover its ``status`` + ``title``. When ``owner`` is
    set, only goals owned by that principal are rendered, so a stale run index
    from a deleted same-name fleet cannot be attached to a new owner's roster.
    Returns at most ``limit`` rows of ``{agent, goal_id, title, status, ts}``.
    Fail-soft: a missing/garbled index or a vanished goal yields an
    empty/partial list, never a 500.
    """
    try:
        from maverick.fleet import load_runs

        runs = load_runs(fleet_name)
    except Exception:  # pragma: no cover - never 500 the console on a read error
        return []
    w = _world()
    rows: list[dict] = []
    # Newest-first, capped after owner filtering: the index is oldest-first.
    for r in reversed(runs):
        if len(rows) >= limit:
            break
        gid = r.get("goal_id")
        goal = None
        try:
            if isinstance(gid, int):
                goal = w.get_goal(gid)
        except Exception:  # pragma: no cover - a bad row must not break the page
            goal = None
        if owner is not None and (goal is None or getattr(goal, "owner", "") != owner):
            continue
        rows.append(
            {
                "agent": r.get("agent") or "—",
                "goal_id": gid,
                "title": goal.title if goal else "",
                "status": goal.status if goal else "missing",
                "ts": r.get("ts"),
            }
        )
    return rows


@app.get("/fleets", response_class=HTMLResponse)
def fleets_page(request: Request) -> HTMLResponse:
    """Operator console: the per-employee agent fleets + their oversight.

    Layer C of the enterprise control plane (see
    ``docs/enterprise/architecture.md``): lists each fleet (owner + role-scoped
    roster) alongside the recent governance oversight trail and a link to the
    pending human-approval queue -- the EU AI Act Art 14 human-oversight surface.
    """
    try:
        from maverick.fleet import list_fleets

        fleets = list_fleets()
    except Exception:  # pragma: no cover - never 500 the console if the registry errors
        fleets = []
    # Owner-scope the roster to the caller (auth-off/admin -> all).
    owner = goal_owner_filter(request)
    if owner is not None:
        fleets = [f for f in fleets if f.owner == owner]
    # Saved teams can outlive a specialist's department setting or pack file.
    # Show the current check beside the task form, rather than discovering a
    # missing required action after the person has already assigned work.
    domains = {agent.domain for fleet in fleets for agent in fleet.agents if agent.domain}
    specialist_readiness: dict[str, dict] = {}
    if domains:
        try:
            from maverick.domain import _disabled_suites, available_domains
            from maverick.domain_edit import _configured_tool_names, workflow_readiness

            catalog = available_domains()
            known_tools = _configured_tool_names()
            disabled_suites = frozenset(_disabled_suites())
            for domain in domains:
                profile = catalog.get(domain)
                if profile is None:
                    specialist_readiness[domain] = {
                        "state": "needs_setup", "label": "No longer available",
                        "fix_url": "/agents", "missing_tools": [],
                    }
                else:
                    specialist_readiness[domain] = workflow_readiness(
                        profile, known_tools, disabled_suites=disabled_suites,
                    )
        except Exception:
            specialist_readiness = {
                domain: {"state": "unknown", "label": "Setup check unavailable",
                         "fix_url": "/settings"}
                for domain in domains
            }
    fleet_can_start = {
        fleet.name: any(
            not agent.domain
            or specialist_readiness.get(agent.domain, {}).get("state") == "action_ready"
            for agent in fleet.agents
        )
        for fleet in fleets
    }
    # Per-fleet recent runs (newest-first), scoped to the fleets already shown.
    runs_by_fleet = {f.name: _fleet_recent_runs(f.name, owner=owner) for f in fleets}
    typical_costs, workspace_limit = _fleet_typical_costs(fleets)
    try:  # role picker for new agents (same roles the access page offers)
        from . import rbac as _rbac

        role_options = list(_rbac.known_roles())
    except Exception:  # pragma: no cover - the picker falls back to typing
        role_options = []
    return templates.TemplateResponse(
        request,
        "fleets.html",
        {
            "fleets": fleets,
            "specialist_readiness": specialist_readiness,
            "fleet_can_start": fleet_can_start,
            "role_options": role_options,
            "runs_by_fleet": runs_by_fleet,
            "typical_costs": typical_costs,
            "workspace_limit": workspace_limit,
            "holds": _recent_governance_holds(),
            "pending_count": len(_world().pending_approvals()),
        },
    )


@app.get("/cache", response_class=HTMLResponse)
async def cache_page(request: Request) -> HTMLResponse:
    """In-process cache stats + purge buttons."""
    from maverick.cache import stats

    return templates.TemplateResponse(
        request,
        "cache.html",
        {"stats": stats()},
    )


@app.get("/store", response_class=HTMLResponse)
def store_page(request: Request, saved: str = "") -> HTMLResponse:
    """Skill Store: browse + install catalog skills without a terminal.

    A plain ``def`` (thread-pooled): the catalog index is fetched over the
    network, which must never run on the event loop.
    """
    from maverick.catalog import PAGE_FETCH_TIMEOUT, load_catalog

    from .store_catalogs import current_catalogs

    try:
        entries = [e.to_dict() for e in load_catalog("skills", timeout=PAGE_FETCH_TIMEOUT)]
    except Exception:
        entries = []
    installed = {s.name for s in _load_skills()}
    catalogs, catalogs_default = current_catalogs()
    return templates.TemplateResponse(
        request,
        "store.html",
        {"entries": entries, "installed": installed,
         "is_admin": has_permission(request, "admin"),
         "catalog_admin": has_global_permission(request, "admin"),
         "install_allowed": __import__("maverick.skills", fromlist=["x"]).url_install_allowed(),
         "catalogs": catalogs, "catalogs_default": catalogs_default, "saved": saved},
    )


def template_market_entries(principal: str | None = None) -> list[dict]:
    """The goal-template catalog (user-installed + bundled), annotated with the
    operator's own star ratings from the marketplace ratings ledger.

    Powers the /templates page and GET /api/v1/templates. Offline + fail-soft:
    a template that no longer parses is skipped; a missing ratings ledger
    means everything shows unrated.
    """
    from maverick.marketplace.ratings import RatingsLedger, stars_bar
    from maverick.templates import can_read_template, list_templates, load_template

    try:
        ratings = RatingsLedger().all_ratings("templates")
    except Exception:  # pragma: no cover -- ratings never block the catalog
        ratings = {}
    entries: list[dict] = []
    for name in list_templates():
        try:
            tpl = load_template(name)
            if not can_read_template(tpl, principal):
                continue
        except (OSError, ValueError, FileNotFoundError):
            continue
        mine = ratings.get(name) or {}
        stars = mine.get("stars")
        entries.append(
            {
                "name": name,
                "title": tpl.title,
                "params": list(tpl.params),
                "parameter_schema": tpl.parameter_schema,
                "body": tpl.body[:2000],
                "stars": stars,
                "rating_bar": stars_bar(float(stars), 0) if stars else "unrated",
            }
        )
    preferred = {
        "weekly-update": 0, "project-plan": 1, "vendor-evidence-review": 2,
        "compare-options": 3, "trip-plan": 4, "standup": 5,
    }
    return sorted(entries, key=lambda entry: (preferred.get(entry["name"], 99), entry["name"]))


@app.get("/templates", response_class=HTMLResponse)
async def templates_market_page(request: Request) -> HTMLResponse:
    """Visual goal-templates marketplace: browse the catalog with ratings and
    one-click "use template" (prefills the chat form via query params — the
    goal never auto-starts)."""
    from maverick.config import get_features

    feats = get_features()
    return templates.TemplateResponse(
        request,
        "templates_market.html",
        {
            "entries": template_market_entries(caller_principal(request)),
            "scheduling_enabled": feats.get("scheduling", True),
            "triggers_enabled": feats.get("triggers", True),
        },
    )


@app.get("/channels", response_class=HTMLResponse)
def channels_page(request: Request, saved: str = "") -> HTMLResponse:
    # A link code supplied in a GET URL is not evidence that this admin issued it.
    return _render_channels_page(request, saved=saved)


def _channel_form_context(request: Request) -> str:
    from maverick.paths import current_tenant_id_strict

    from .api_flow_operator_review import _workspace_authority
    from .draft_api import context_for

    require_global_permission(request, "admin")
    actor = caller_principal(request) or "local administrator"
    tenant = current_tenant_id_strict()
    workspace = _workspace_authority(request, actor, tenant) if tenant else "local"
    return hashlib.sha256(json.dumps([context_for(request), workspace]).encode()).hexdigest()


def _channel_form_review(request: Request) -> str:
    from maverick.crypto_at_rest import deployment_key_scope, is_sealed_str, seal_to_str

    from .settings_all_page import _revision

    with deployment_key_scope():
        token = seal_to_str(json.dumps({"purpose": "channel-settings-review-v1", "context": _channel_form_context(request),
                                       "revision": _revision(), "deadline": time.time() + 600}))
    if not is_sealed_str(token):
        raise HTTPException(503, "The current settings comparison could not be protected. Refresh Channels after protected storage is restored.")
    return token


def _require_channel_review(request: Request, token: str) -> None:
    """Recheck the protected full source comparison after native writer waits."""
    from maverick.crypto_at_rest import deployment_key_scope, is_sealed_str, unseal_from_str

    from . import settings_all_page as page
    from .integration_readiness import require_readable_config

    require_global_permission(request, "admin")
    require_readable_config()
    try:
        if len(token) > 4000 or not is_sealed_str(token):
            raise ValueError("protected review required")
        with deployment_key_scope():
            review = json.loads(unseal_from_str(token))
        if (set(review) != {"purpose", "context", "revision", "deadline"}
                or review["purpose"] != "channel-settings-review-v1"):
            raise ValueError("unsupported review")
    except Exception as exc:
        raise HTTPException(409, "Refresh the current comparison before saving. Your draft is kept.") from exc
    if not hmac.compare_digest(str(review["context"]), _channel_form_context(request)):
        raise HTTPException(409, {"message": "Your account or workspace changed. Reload Channels before editing.",
                                  "context_changed": True})
    if (type(review["deadline"]) not in (int, float) or not math.isfinite(review["deadline"])
            or not time.time() < review["deadline"] <= time.time() + 600
            or not hmac.compare_digest(str(review["revision"]), page._revision())):
        raise HTTPException(409, "Saved settings changed or this comparison expired. Refresh the current comparison; your draft is kept.")


def _channel_removal_people(name: str) -> dict:
    from copy import deepcopy

    from . import settings_all_page as page
    from .settings_catalog import BY_ID, CHANNEL_ALLOWLISTS

    access = CHANNEL_ALLOWLISTS.get(name)
    if not access:
        return {}
    setting = BY_ID[f"channels.{name}.{access[2]}"]
    layers = page._sources()
    before = page._resolve(setting, layers)
    inherited = deepcopy(layers)
    (inherited["here"].get("channels") or {}).pop(name, None)
    after = page._resolve(setting, inherited)
    if not before["known"] or not after["known"]:
        raise HTTPException(503, "The complete current and inherited people lists cannot be read. No saved settings were removed.")
    return {"before": before["value"], "after": after["value"],
            "before_source": before.get("source_text", page.SOURCE_TEXT[before["source"]]),
            "after_source": after.get("source_text", page.SOURCE_TEXT[after["source"]])}


def _render_channels_page(request: Request, *, saved: str = "",
                          issued_code: str = "", draft: dict | None = None,
                          error: str = "", status_code: int = 200) -> HTMLResponse:
    """Channels: manage the common ones (enable + credentials) from the form
    sections, plus a read-only, secret-redacted view of everything configured.
    Saved to the dashboard overlay; a running chat service must restart to
    pick up changed connection details."""
    from maverick import microsoft_mail
    require_global_permission(request, "admin")
    sensitive_markers = (
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "cookie",
        "session",
    )

    def _display_channels(channels: dict) -> dict:
        out: dict = {}
        for name, cfg in (channels or {}).items():
            # [channels] rich_render and the [channels.routing] rules apply
            # to every chat app; they are not channels of their own.
            if not isinstance(cfg, dict) or name == "routing":
                continue
            safe_cfg: dict = {}
            for key, value in cfg.items():
                key_l = str(key).lower()
                if any(marker in key_l for marker in sensitive_markers):
                    safe_cfg[key] = "[redacted]"
                else:
                    safe_cfg[key] = value
            out[name] = safe_cfg
        return out

    try:
        from maverick_dashboard import settings_store
        from maverick_dashboard.integration_readiness import (
            channel_readiness,
            require_readable_config,
        )

        effective_channels = require_readable_config().get("channels") or {}
        channels = _display_channels(effective_channels)
        managed = settings_store.channels_state()
        for channel in managed:
            raw = effective_channels.get(channel["name"])
            raw = raw if isinstance(raw, dict) else {}
            channel["configured"] = bool(raw.get("enabled", False))
            channel["readiness"] = channel_readiness(channel["name"], raw)
        channel_inventory = []
        for name, safe in channels.items():
            raw = effective_channels.get(name)
            raw = raw if isinstance(raw, dict) else {"enabled": bool(raw)}
            channel_inventory.append(
                {
                    "name": name,
                    "enabled": bool(raw.get("enabled", False)),
                    "configured": bool(raw.get("enabled", False)),
                    "detail": safe,
                    "readiness": channel_readiness(name, raw),
                }
            )
    except RuntimeOverridesSecurityError:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="channel inventory is unavailable",
        ) from exc
    saved_msg = {
        "save": "Chat app saved. Check the chat service below, then send a test message to confirm delivery.",
        "clear": "Saved settings removed.",
        "tested": "Connection test passed.",
        "test_failed": "The connection test failed. Check the details and try again.",
        "sent": "Test message sent. Check that it arrived.",
        "send_failed": "The test message could not be sent. Check the details and try again.",
        "linked": "Teams account linked.",
        "unlinked": "Teams link removed.",
        "link_code": "One-time link code created. Give it to the person; it works once and "
                     "expires in 15 minutes.",
        "email_sent": "Test email sent. Check that it arrived.",
        "email_failed": "The test email could not be sent. Check the mail settings "
                        "(Settings > All settings > Integrations > Email alerts).",
    }.get(saved, "")
    from . import plain_labels, public_chat_api, teams_links_api
    try:
        from .service_supervisor import status as service_status

        channel_runtime = service_status(["channels"])[0]
    except Exception:
        channel_runtime = None
    for channel in managed:
        if channel.get("dashboard_set"):
            channel["removal_people"] = _channel_removal_people(channel["name"])
        for field in channel["fields"]:
            label, help_text, advanced = plain_labels.CHANNEL_FIELDS.get(
                (channel["name"], field["key"]), (field["label"], field.get("help", ""), False))
            field.update(label=label, help=help_text, advanced=advanced)
        channel["help_link"] = plain_labels.CHANNEL_HELP_LINKS.get(channel["name"], "")
    managed_names = {channel["name"] for channel in managed}
    if draft:
        for channel in managed:
            if channel["name"] != draft.get("channel"):
                continue
            channel["enabled"] = bool(draft.get("enabled"))
            for field in channel["fields"]:
                if not field["secret"] and field["key"] in draft:
                    field["value"] = str(draft[field["key"]])[:60600]
    return templates.TemplateResponse(
        request,
        "channels.html",
        {
            "channels": channels,
            "channel_inventory": [row for row in channel_inventory if row["name"] not in managed_names],
            "managed": managed,
            "saved": saved_msg,
            "saved_failed": saved in {"test_failed", "send_failed", "email_failed"},
            "sendable": ["email", "sms", "slack"],
            "channel_runtime": channel_runtime,
            **teams_links_api.page_context(issued_code),
            **public_chat_api.admin_section_context(request),
            "mail_configured": _mail_configured(),
            "channel_context": _channel_form_context(request),
            "channel_review": _channel_form_review(request),
            "channel_error": error,
            "email_oauth_choices": microsoft_mail.choices(caller_principal(request)),
        },
        status_code=status_code, headers={"Cache-Control": "private, no-store"},
    )


def _mail_configured() -> bool:
    """Whether [notifications.email] can send (the Channels page "Test email")."""
    try:
        from maverick.notifications import email_configured

        return email_configured()
    except Exception:  # noqa: BLE001 -- the page must render either way
        return False


@app.post("/channels/save")
async def channels_save(request: Request) -> Response:
    """Enable/disable a channel and set its credentials from the form. Stored in
    the dashboard overlay (dashboard-config.toml), never config.toml; blank
    fields keep the current value so a toggle never wipes a hidden secret."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick_dashboard import settings_store

    form = await request.form()
    name = (form.get("channel") or "").strip()
    enabled = form.get("enabled") is not None  # checkbox present == on
    values = {k: v for k, v in form.items()
              if k not in ("channel", "enabled", "review_token", "confirm_people")}
    from .settings_audit import bind_setting_write

    def guard() -> None:
        from . import settings_all_page as page
        from .settings_catalog import BY_ID, CHANNEL_ALLOWLISTS, coerce

        _require_channel_review(request, str(form.get("review_token") or ""))
        access = CHANNEL_ALLOWLISTS.get(name)
        if access and access[2] in values:
            setting = BY_ID[f"channels.{name}.{access[2]}"]
            resolved = page._resolve(setting, page._sources())
            after = coerce(setting, re.split(r"[,\r\n]+", str(values[access[2]])))
            if not resolved["known"] or resolved["locked"]:
                raise HTTPException(409, "Your server's deployment settings own this people list. No channel settings were changed.")
            if sorted(after) != sorted(resolved["value"]) and form.get("confirm_people") != "yes":
                raise HTTPException(422, "Review who may message Lightwork before and after this change, then tick the confirmation. Your draft is kept.")

    def _audit_channel(data: dict) -> dict:
        channels = data.get("channels") or {}
        table = channels.get(name) if isinstance(channels, dict) else None
        table = table if isinstance(table, dict) else {}
        return {
            "enabled": table.get("enabled"),
            "fields_set": sorted(k for k, v in table.items() if k != "enabled" and v),
        }

    try:
        def save() -> None:
            with bind_setting_write(request, section="channels", key=name,
                                    project=_audit_channel, confirmed=form.get("confirm_people") == "yes"):
                settings_store.set_channel(name, enabled, values, before_write=guard, actor=caller_principal(request))

        await run_in_threadpool(save)
    except (ValueError, HTTPException, OSError, settings_store.SecuritySuiteConfigUnavailable) as exc:
        status = exc.status_code if isinstance(exc, HTTPException) else 400 if isinstance(exc, ValueError) else 503
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc) if status == 400 else "The save could not be confirmed. Review current settings before making another change."
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"detail": detail, "uncertain": status >= 500}, status_code=status,
                                headers={"Cache-Control": "private, no-store"})
        if status in {400, 422}:
            return _render_channels_page(request, draft={**values, "channel": name, "enabled": enabled},
                                         error=str(detail), status_code=status)
        raise HTTPException(status, detail) from exc
    from .audit_actions_api import _audit_event

    # Only which fields changed is recorded, never their values.
    _audit_event(request, "channel_saved", channel=name, enabled=enabled,
                 fields=sorted(k for k, v in values.items() if str(v).strip()))
    if "application/json" in request.headers.get("accept", ""):
        require_global_permission(request, "admin")
        current = next(item for item in settings_store.channels_state() if item["name"] == name)
        from .integration_readiness import channel_readiness, require_readable_config

        channel_config = (require_readable_config().get("channels") or {}).get(name) or {}
        readiness = channel_readiness(name, channel_config)
        readiness_html = str(templates.get_template("_integration_readiness.html").module.integration_readiness(readiness))
        return JSONResponse({"saved": True, "context": _channel_form_context(request),
                             "enabled": bool(channel_config.get("enabled")), "readiness_html": readiness_html,
                             "review_token": _channel_form_review(request),
                             "people": next((field["people"] for field in current["fields"] if field["type"] == "list"), []),
                             "people_source": next((field["people_source"] for field in current["fields"] if field["type"] == "list"), ""),
                             "message": "Chat app settings saved. Apply the change to the chat service before testing delivery."},
                            headers={"Cache-Control": "private, no-store"})
    return RedirectResponse("/channels?saved=save", status_code=303)


@app.post("/channels/clear")
def channels_clear(request: Request, channel: str = Form(...), review_token: str = Form(""),
                   confirm_people: str = Form("")) -> Response:
    """Remove only saved overrides after complete inherited-access review."""
    _require_same_origin(request)
    require_global_permission(request, "admin")
    from . import settings_store
    from .settings_audit import bind_setting_write

    name = (channel or "").strip()

    def guard() -> None:
        _channel_removal_people(name)
        _require_channel_review(request, review_token)
        if confirm_people != "yes":
            raise HTTPException(422, "Review the complete current and inherited people lists, then tick the confirmation. No saved settings were removed.")

    try:
        with bind_setting_write(request, section="channels", key=name, confirmed=confirm_people == "yes",
                                project=lambda d: {
                                    "enabled": ((d.get("channels") or {}).get(name) or {}).get("enabled"),
                                    "fields_set": sorted(k for k, v in
                                                         ((d.get("channels") or {}).get(name) or {}).items()
                                                         if k != "enabled" and v),
                                }):
            settings_store.clear_channel(name, before_write=guard)
    except (ValueError, HTTPException, OSError, settings_store.SecuritySuiteConfigUnavailable) as exc:
        status = exc.status_code if isinstance(exc, HTTPException) else 400 if isinstance(exc, ValueError) else 503
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc) if status == 400 else "The removal could not be confirmed. Review current settings before making another change."
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"detail": detail, "uncertain": status >= 500}, status_code=status,
                                headers={"Cache-Control": "private, no-store"})
        raise HTTPException(status, detail) from exc
    from .audit_actions_api import _audit_event

    _audit_event(request, "channel_settings_removed", channel=name)
    if "application/json" in request.headers.get("accept", ""):
        current = _channel_removal_people(name)
        return JSONResponse({"saved": True, "removed": True, "context": _channel_form_context(request),
                             "review_token": _channel_form_review(request),
                             "people": current.get("before", []),
                             "people_source": current.get("before_source", ""),
                             "message": "Settings saved here were removed. Installer or server settings apply again; this does not prove the app disconnected. Apply the change to the chat service before testing delivery."},
                            headers={"Cache-Control": "private, no-store"})
    return RedirectResponse("/channels?saved=clear", status_code=303)


@app.get("/api/v1/providers")
async def providers_api(request: Request) -> JSONResponse:
    # This is the raw deployment inventory, including effective base URLs and
    # config-source diagnostics. It is a global control-plane resource, not a
    # tenant-scoped readiness summary.
    require_global_permission(request, "admin")
    from maverick.provider_health import get as _health

    from .provider_readiness import public_verdict, workspace_readiness

    try:
        workspace = workspace_readiness()
        inventory = _provider_integration_inventory(workspace)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="provider inventory is unavailable",
        ) from exc
    return JSONResponse(
        {
            "providers": inventory,
            "health": _health().snapshot(),
            "workspace": public_verdict(workspace),
        }
    )


async def _websocket_ip_allowlist_gate(websocket: WebSocket) -> None:
    """The installation list for a WebSocket handshake. Starlette never runs
    ``@app.middleware("http")`` for one, so the route applies it itself:
    listed first among its dependencies, it refuses a blocked address before
    sign-in runs and before the connection is accepted."""
    from . import ip_allowlist

    if await run_in_threadpool(ip_allowlist.installation_allows, websocket):
        return
    _auth_metrics.record_auth_failure("ip_allowlist")
    raise WebSocketException(code=1008, reason=ip_allowlist.BLOCKED_MESSAGE)


@app.websocket("/ws/v1/runs/{goal_id}/events")
async def run_events_firehose(
    websocket: WebSocket,
    goal_id: int,
    _address: None = Depends(_websocket_ip_allowlist_gate),
    principal: VerifiedPrincipal | None = Depends(require_websocket_principal_in_context),
) -> None:
    """Run-events firehose: stream a goal's events over WebSocket as they land.

    Sends each event as one JSON message ``{id, agent, kind, content, ts}``;
    a final ``{kind: "status", content: <terminal>}`` message closes the
    stream when the goal finishes. Auth mirrors the HTTP policy (Authorization
    header in token mode; loopback-only otherwise), checked before accept.
    Resume with ``?since_id=``."""
    import asyncio as _asyncio

    from fastapi import WebSocketDisconnect

    from ._event_stream import TERMINAL_RUN_STATUSES, event_payload, replay_cursor
    from .auth import websocket_authorized

    if not websocket_authorized(websocket, principal):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    since = replay_cursor(websocket.query_params.get("since_id", 0))
    w = _world()
    g = await run_in_threadpool(w.get_goal, goal_id)
    if g is None:
        await websocket.send_json({"error": "no such goal"})
        await websocket.close(code=4404)
        return
    if not can_access_goal_principal(websocket_caller_principal(principal), g):
        await websocket.send_json({"error": "no such goal"})
        await websocket.close(code=4404)
        return
    # Cap concurrent firehoses (shared with the SSE cap) so many open tabs can't
    # exhaust FDs/tasks, and bound each stream's lifetime — the same two guards
    # as the SSE route.
    sem = _get_sse_semaphore()
    if sem.locked():
        await websocket.send_json({"error": "too many concurrent streams; retry shortly"})
        await websocket.close(code=1013)  # "try again later"
        return
    await sem.acquire()
    MAX_STREAM_SECONDS = 300
    started = _asyncio.get_running_loop().time()
    try:
        last = since
        while True:
            # Offload the blocking, lock-held SQLite reads off the event loop.
            events = await run_in_threadpool(w.goal_events, goal_id, since_id=last, limit=500)
            for e in events:
                last = e.id
                await websocket.send_json(event_payload(e))
            g = await run_in_threadpool(w.get_goal, goal_id)
            if g is None or (g.status in TERMINAL_RUN_STATUSES and len(events) < 500):
                await websocket.send_json(
                    {
                        "id": last,
                        "next_id": last,
                        "terminal": True,
                        "agent": "system",
                        "kind": "status",
                        "content": (g.status if g else "deleted"),
                        "ts": time.time(),
                    }
                )
                break
            if (_asyncio.get_running_loop().time() - started) >= MAX_STREAM_SECONDS:
                await websocket.send_json(
                    {
                        "id": last,
                        "next_id": last,
                        "terminal": False,
                        "agent": "system",
                        "kind": "status",
                        "content": "stream lifetime exceeded; reconnect to resume",
                        "ts": time.time(),
                    }
                )
                break
            if len(events) == 500:
                continue
            await _asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    finally:
        sem.release()
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/api/v1/goals/{goal_id}/cost-preview")
def goal_cost_preview(request: Request, goal_id: int, iterations: int = 1) -> JSONResponse:
    """Inline cost preview: project a pending goal's cost before running it.

    Treats the goal description as one step per non-empty line (or the whole
    text as one step), projects tokens/dollars via maverick.cost.projection,
    and reports the OK/TIGHT/OVER verdict against the configured default
    budget."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.cost.projection import compare_against_budget, project_plan
    from maverick.runner import configured_max_dollars

    text = (g.description or g.title or "").strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    steps = [{"text": ln} for ln in (lines or [text])]
    projection = project_plan(steps, iterations=max(1, min(int(iterations), 10)))
    budget_dollars = configured_max_dollars()
    verdict = compare_against_budget(projection, budget_dollars)
    return JSONResponse(
        {
            "goal_id": goal_id,
            "steps": len(steps),
            "total_tokens": projection.total_tokens,
            "total_dollars": round(projection.total_dollars, 4),
            "budget_dollars": budget_dollars,
            "verdict": verdict.verdict,
            "recommendation": verdict.recommendation,
        }
    )


@app.get("/api/v1/goals/{goal_id}/cost-breakdown")
def goal_cost_breakdown(request: Request, goal_id: int) -> JSONResponse:
    """'Why this cost' drill-down: a run's spend split by agent role/outcome.

    Buckets the goal's episodes (cost, tokens, count) so the dollar figure on
    the dashboard decomposes into who spent it and on what."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    buckets: dict[str, dict] = {}
    total = 0.0
    for ep in w.list_episodes(limit=10_000, goal_id=goal_id):
        key = str(getattr(ep, "outcome", "") or "episode")
        b = buckets.setdefault(
            key, {"episodes": 0, "dollars": 0.0, "in_tokens": 0, "out_tokens": 0}
        )
        cost = float(getattr(ep, "cost_dollars", 0) or 0)
        b["episodes"] += 1
        b["dollars"] += cost
        b["in_tokens"] += int(getattr(ep, "input_tokens", 0) or 0)
        b["out_tokens"] += int(getattr(ep, "output_tokens", 0) or 0)
        total += cost
    rows = [
        {"bucket": k, **{kk: (round(vv, 4) if kk == "dollars" else vv) for kk, vv in v.items()}}
        for k, v in sorted(buckets.items(), key=lambda kv: -kv[1]["dollars"])
    ]
    return JSONResponse({"goal_id": goal_id, "total_dollars": round(total, 4), "buckets": rows})


def _owned_goal_ids(world, owner: str) -> set[int]:
    """Ids of the owner's newest 10,000 goals. A world that reads the status
    columns alone is asked for the ids only, so no goal is decrypted here."""
    states = getattr(world, "goal_states", None)
    if callable(states):
        return {gid for gid, _status, _updated in states(owner=owner, limit=10_000, order="desc")}
    return {g.id for g in world.list_goals(owner=owner, limit=10_000, order="desc")}


@app.get("/api/v1/cost/anomalies")
def cost_anomalies(
    request: Request,
    threshold_sigma: float = 3.0,
    limit: int = 500,
) -> JSONResponse:
    """Cost anomaly alerts: goals whose spend is a statistical outlier.

    Computes per-goal spend over the recent episode window and flags goals
    above mean + threshold_sigma * stdev (min 3 goals before anything can
    flag). The data behind a dashboard alert badge.

    Owner-scoped: an authenticated non-admin sees anomalies only among their own
    goals (auth-off / admin see all), so other tenants' goal ids and exact spend
    don't leak -- the same scoping ``/api/v1/cost/by-tag`` applies."""
    import statistics

    w = _world()
    limit = max(1, min(int(limit), 10_000))
    owner = goal_owner_filter(request)
    owned: set[int] | None = None
    if owner is not None:
        owned = _owned_goal_ids(w, owner)
    by_goal: dict[int, float] = {}
    for ep in w.list_episodes(limit=limit):
        gid = getattr(ep, "goal_id", None)
        if gid is None:
            continue
        if owned is not None and gid not in owned:
            continue
        by_goal[gid] = by_goal.get(gid, 0.0) + float(getattr(ep, "cost_dollars", 0) or 0)
    spends = [s for s in by_goal.values() if s > 0]
    if len(spends) < 3:
        return JSONResponse(
            {
                "anomalies": [],
                "goals_considered": len(by_goal),
                "note": "need >=3 priced goals to baseline",
            }
        )
    mean = statistics.fmean(spends)
    stdev = statistics.pstdev(spends)
    cut = mean + max(0.5, float(threshold_sigma)) * stdev
    anomalies = [
        {"goal_id": gid, "dollars": round(s, 4), "x_mean": round(s / mean, 1) if mean else None}
        for gid, s in sorted(by_goal.items(), key=lambda kv: -kv[1])
        if s > cut and stdev > 0
    ]
    return JSONResponse(
        {
            "anomalies": anomalies,
            "goals_considered": len(by_goal),
            "mean_dollars": round(mean, 4),
            "cutoff_dollars": round(cut, 4),
        }
    )


@app.post("/api/v1/skills/validate")
async def skills_validate(request: Request) -> JSONResponse:
    """Skill validator service: lint a SKILL.md body without installing it.

    POST the raw SKILL.md text (text/plain or markdown); responds
    ``{ok, errors, warnings}`` from the same linter `maverick skill validate`
    runs locally — so a marketplace author can validate from CI or an editor
    against a self-hosted instance. Size-capped; nothing is persisted."""
    import tempfile as _tempfile
    from pathlib import Path as _Path

    from maverick.skills import validate_skill_file

    body = await _read_limited_skill_validator_body(request)
    if not body:
        raise HTTPException(status_code=400, detail="POST the SKILL.md body")
    with _tempfile.TemporaryDirectory(prefix="mvk-skill-validate-") as td:
        p = _Path(td) / "SKILL.md"
        p.write_bytes(body)
        result = validate_skill_file(p)
    return JSONResponse(
        {
            "ok": result.ok,
            "errors": result.errors,
            "warnings": result.warnings,
        }
    )


@app.get("/api/v1/pins")
async def pins_list(request: Request) -> JSONResponse:
    """Pinned watch list for the calling principal (most-recently-pinned first)."""
    from maverick.ux_store import shared as _ux

    return JSONResponse({"pins": _ux().pins(caller_principal(request))})


@app.post("/api/v1/pins/{goal_id}")
def pins_add(request: Request, goal_id: int) -> JSONResponse:
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.ux_store import shared as _ux

    return JSONResponse({"pins": _ux().pin(caller_principal(request), goal_id)})


@app.delete("/api/v1/pins/{goal_id}")
async def pins_remove(request: Request, goal_id: int) -> JSONResponse:
    from maverick.ux_store import shared as _ux

    return JSONResponse({"pins": _ux().unpin(caller_principal(request), goal_id)})


@app.get("/api/v1/views")
async def views_list(request: Request, task_filters: bool = False) -> JSONResponse:
    """Saved dashboard views (named filter/query-param sets) for the caller."""
    from maverick.ux_store import shared as _ux

    if task_filters:
        from .task_saved_views import current
        return JSONResponse(current(request), headers={"Cache-Control": "private, no-store"})
    return JSONResponse({"views": _ux().views(caller_principal(request))})


@app.post("/api/v1/views/{name}")
async def views_save(request: Request, name: str, task_filters: bool = False) -> JSONResponse:
    from maverick.ux_store import shared as _ux

    try:
        raw_body = await _read_limited_request_body(
            request,
            max_bytes=_MAX_SAVED_VIEW_BODY_BYTES,
            too_large_detail="saved view body too large",
        )
        body = json.loads(raw_body or b"{}")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="body must be a JSON object of params"
        ) from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object of params")
    if task_filters:
        from pydantic import ValidationError

        from .task_saved_views import Change, change
        try:
            reviewed = Change.model_validate(body)
        except ValidationError as exc:
            raise HTTPException(422, "Refresh saved views and review a valid task search and status.") from exc
        return JSONResponse(change(request, name, reviewed), status_code=201,
                            headers={"Cache-Control": "private, no-store"})
    try:
        _ux().save_view(caller_principal(request), name, body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return JSONResponse({"saved": name}, status_code=201)


@app.delete("/api/v1/views/{name}")
async def views_delete(request: Request, name: str, task_filters: bool = False) -> JSONResponse:
    from maverick.ux_store import shared as _ux

    if task_filters:
        from pydantic import ValidationError

        from .task_saved_views import Change, change
        try:
            raw = await _read_limited_request_body(request, max_bytes=_MAX_SAVED_VIEW_BODY_BYTES,
                                                 too_large_detail="saved view body too large")
            reviewed = Change.model_validate(json.loads(raw or b"{}"))
        except (ValueError, ValidationError) as exc:
            raise HTTPException(422, "Refresh saved views before reviewing removal.") from exc
        return JSONResponse(change(request, name, reviewed, delete=True),
                            headers={"Cache-Control": "private, no-store"})
    if not _ux().delete_view(caller_principal(request), name):
        raise HTTPException(status_code=404, detail="no such view")
    return JSONResponse({"deleted": name})


@app.get("/api/v1/gallery")
def gallery_list(request: Request) -> JSONResponse:
    """Run gallery: the deployment's featured runs, enriched with live goal
    state and links to the tutorial/explain exports."""
    from maverick.ux_store import shared as _ux

    w = _world()
    runs = []
    for entry in _ux().gallery():
        g = w.get_goal(entry["goal_id"])
        if g is None or not can_access_goal(request, g):
            continue
        runs.append(
            {
                **entry,
                "title": (g.title or "")[:120],
                "status": g.status,
                "tutorial": f"/api/v1/goals/{entry['goal_id']}/tutorial.md",
                "explain": f"/api/v1/goals/{entry['goal_id']}/explain",
            }
        )
    return JSONResponse({"gallery": runs})


@app.post("/api/v1/gallery/{goal_id}")
async def gallery_add(request: Request, goal_id: int) -> JSONResponse:
    # The gallery is a deployment-wide showcase, not per-user personalization,
    # so publishing to it takes "operate" (viewers can read it but not curate).
    require_permission(request, "operate")
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    try:
        body = await request.json()
    except ValueError:
        body = {}
    blurb = str((body or {}).get("blurb") or "")
    from maverick.ux_store import shared as _ux

    try:
        entry = _ux().gallery_add(goal_id, blurb=blurb, curator=caller_principal(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return JSONResponse(entry, status_code=201)


@app.delete("/api/v1/gallery/{goal_id}")
def gallery_remove(request: Request, goal_id: int) -> JSONResponse:
    require_permission(request, "operate")
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.ux_store import shared as _ux

    if not _ux().gallery_remove(goal_id):
        raise HTTPException(status_code=404, detail="not in the gallery")
    return JSONResponse({"removed": goal_id})


@app.get("/api/v1/goals/{goal_id}/annotations")
def annotations_list(request: Request, goal_id: int) -> JSONResponse:
    """Trace annotations: human notes pinned to replay-trace steps (seq)."""
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.ux_store import shared as _ux

    return JSONResponse({"annotations": _ux().annotations(goal_id)})


@app.post("/api/v1/goals/{goal_id}/annotations")
async def annotations_add(request: Request, goal_id: int) -> JSONResponse:
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="body must be JSON {seq, note}") from None
    if not isinstance(body, dict) or "seq" not in body or not body.get("note"):
        raise HTTPException(status_code=400, detail="body must be JSON {seq, note}")
    from maverick.ux_store import shared as _ux

    try:
        entry = _ux().annotate(
            goal_id, int(body["seq"]), str(body["note"]), author=caller_principal(request)
        )
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return JSONResponse(entry, status_code=201)


@app.get("/api/v1/goals/{goal_id}/anomalies")
def goal_anomalies(request: Request, goal_id: int, history: int = 50) -> JSONResponse:
    """Cross-run anomaly signals for one run vs the deployment baseline."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.cross_run_anomaly import MIN_BASELINE_RUNS, detect

    anomalies = detect(
        w, goal_id, history=max(5, min(int(history), 500)), owner=goal_owner_filter(request)
    )
    return JSONResponse(
        {
            "goal_id": goal_id,
            "anomalies": [
                {"kind": a.kind, "severity": a.severity, "detail": a.detail} for a in anomalies
            ],
            "note": (
                f"baseline needs >= {MIN_BASELINE_RUNS} terminal runs before anything can flag"
            ),
        }
    )


@app.get("/api/v1/goals/{goal_id}/tutorial.md")
def goal_tutorial(request: Request, goal_id: int) -> PlainTextResponse:
    """Run-as-tutorial export: the run rendered as step-by-step markdown."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.tutorial_export import tutorial_markdown

    events = w.goal_events(goal_id, limit=5000)
    md = tutorial_markdown(g, events)
    return PlainTextResponse(content=md, media_type="text/markdown; charset=utf-8")


@app.get("/api/v1/goals/{goal_id}/replay-storyboard")
def goal_replay_storyboard(request: Request, goal_id: int) -> JSONResponse:
    """Replay-to-MP4 storyboard: the ordered captioned frames + durations and
    the exact ffmpeg command an operator runs to encode the video.

    The deterministic, offline half of replay-to-MP4 (the encode needs ffmpeg
    and is done out-of-band or via the CLI). Secret/PII-scrubbed."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from pathlib import Path as _Path

    from maverick.replay.video import ffmpeg_command, storyboard

    # Feed the world's goal events (the live trail) rather than the audit-log
    # files replay_video reads by default, so the storyboard reflects this run.
    events = [
        {"kind": e.kind, "ts": e.ts, "agent": e.agent, "content": e.content}
        for e in w.goal_events(goal_id, limit=5000)
    ]
    frames = storyboard(goal_id, events=events)
    cmd = ffmpeg_command(_Path("frames.ffconcat"), _Path(f"replay-{goal_id}.mp4"))
    return JSONResponse(
        {
            "goal_id": goal_id,
            "frames": [
                {"index": f.index, "kind": f.kind, "caption": f.caption, "seconds": f.seconds}
                for f in frames
            ],
            "total_seconds": round(sum(f.seconds for f in frames), 2),
            "ffmpeg_command": cmd,
        }
    )


@app.get("/api/v1/goals/{goal_id}/explain")
def goal_explain(request: Request, goal_id: int) -> JSONResponse:
    """Plain-language narrative of a run (deterministic, no LLM)."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.plain_language import explain

    events = w.goal_events(goal_id, limit=2000)
    return JSONResponse({"goal_id": goal_id, "explanation": explain(g, events)})


@app.get("/api/v1/runs/compare")
def runs_compare(request: Request, ids: str) -> JSONResponse:
    """Multi-run dashboard: side-by-side summary of up to 8 runs."""
    try:
        goal_ids = [int(x) for x in ids.split(",") if x.strip()][:8]
    except ValueError:
        raise HTTPException(
            status_code=400, detail="ids must be comma-separated integers"
        ) from None
    if not goal_ids:
        raise HTTPException(status_code=400, detail="ids is required")
    w = _world()
    runs = []
    for gid in goal_ids:
        g = w.get_goal(gid)
        if g is None:
            # Opaque detail (no id) so "does not exist" is indistinguishable from
            # assert_goal_access's "exists but forbidden" -- otherwise the two
            # different messages re-introduce a cross-tenant existence oracle.
            raise HTTPException(status_code=404, detail="no such goal")
        assert_goal_access(request, g)
        events = w.goal_events(gid, limit=10_000)
        errors = sum(1 for e in events if e.kind == "error")
        runs.append(
            {
                "goal_id": gid,
                "title": (g.title or "")[:120],
                "status": g.status,
                "events": len(events),
                "errors": errors,
                "created_at": getattr(g, "created_at", None),
            }
        )
    return JSONResponse({"runs": runs})


@app.get("/api/v1/cost/by-tag")
def cost_by_tag_api(
    request: Request,
    tag_field: str = "tag",
    limit: int = 500,
) -> JSONResponse:
    """Cost-attribution API: spend split by tag (team / project / cost-center).

    Buckets the priced episodes by their tag (episode field, else the goal's
    metadata/tags) via ``maverick.cost.by_tag`` and returns
    ``{buckets: [{tag, cost, in_tok, out_tok, runs}, ...]}`` sorted by spend. The JSON face of ``maverick status --cost``'s tag split,
    for chargeback exports and BI pulls. Behind the dashboard's normal auth."""
    from maverick.cost.by_tag import gather, split_by_tag

    limit = max(1, min(int(limit), 10_000))
    w = _world()
    owner = goal_owner_filter(request)
    if owner is not None and hasattr(w, "episodes_for_owner_goals"):
        # One owner-scoped query: the newest goals' runs, no per-goal reads.
        rows = gather(w, tag_field=tag_field,
                      episodes=w.episodes_for_owner_goals(owner, limit=limit))
    else:
        goal_ids = None
        if owner is not None:
            goal_ids = [g.id for g in w.list_goals(owner=owner, limit=10_000, order="desc")]
        rows = gather(w, tag_field=tag_field, limit=limit, goal_ids=goal_ids)
    buckets = split_by_tag(rows)
    return JSONResponse({"tag_field": tag_field, "buckets": buckets})


@app.get("/api/v1/shield/calibration")
async def shield_calibration_api() -> JSONResponse:
    """Shield calibration data for the oversight console.

    Threshold sweep (recall / precision / fp-rate per block threshold) plus
    per-rule hit counts over the red-team corpus — the shipped one, or an
    operator's own via ``MAVERICK_REDTEAM_CORPUS``. Behind the dashboard's
    normal auth (not in the exempt list)."""
    import os as _os
    from pathlib import Path as _Path

    try:
        from maverick_shield.redteam import calibration_report, load_corpus
    except ImportError as exc:
        raise HTTPException(status_code=501, detail="maverick-shield is not installed") from exc
    corpus_env = _os.environ.get("MAVERICK_REDTEAM_CORPUS", "").strip()
    try:
        cases = load_corpus(_Path(corpus_env) if corpus_env else None)
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"corpus error: {e}") from e
    return JSONResponse(calibration_report(cases))


@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request, compose: str = "") -> HTMLResponse:
    """Chat. ``?compose=form`` shows the task builder's form (the Task builder
    page's job in the job-named navigation): the same fields, checks and
    submit, under that page's own check."""
    from maverick import flow
    from maverick.runner import configured_max_dollars, configured_max_wall_seconds

    from .onboarding_state import workspace_readiness

    compose_form = compose == "form"
    if compose_form:
        require_page_visible(request, "/goal-builder")

    workspace = workspace_readiness()
    w = _world()
    recent = [goal for goal in w.list_goals(owner=goal_owner_filter(request), limit=10, order="desc")
              if can_access_goal(request, goal)]
    # "Use template" on /templates links here with ?title=&description= to
    # prefill the form (never auto-start; the user reviews, edits, submits).
    prefill_title = (request.query_params.get("title") or "")[:200]
    prefill_description = (request.query_params.get("description") or "")[:8000]
    from .product_operations_task_launch import (
        SPECIALIST_NOTICE,
        published_selection,
        published_specialists,
    )
    requested_specialist = request.query_params.get("specialist")

    # The roster has 2,000+ specialists: the page ships only the requested and
    # saved choices, and Find a specialist searches the rest (/api/v1/chat/specialists).
    def shown(personal_default):
        return {requested_specialist, personal_default} - {None, ""}

    specialist_choices = (published_specialists(request, only=shown) if has_permission(request, "operate")
                          else {"context": "", "choices": []})
    if requested_specialist is not None:
        published_selection(request, requested_specialist)
    return templates.TemplateResponse(
        request,
        "chat.html",
        {
            "recent": recent,
            "threads": _chat_threads(request, w),
            "prefill_title": prefill_title,
            "prefill_description": prefill_description,
            "value_opportunity": request.query_params.get("value_opportunity", "")[:100],
            "published_specialists": specialist_choices,
            "specialist_work_notice": SPECIALIST_NOTICE,
            "requested_specialist": requested_specialist,
            "submission_key": secrets.token_urlsafe(24),
            # One truth: a missing, blocked or failed AI service disables the
            # composer; a saved-but-untested key still lets work start.
            "model_route_ready": workspace["verdict"] != "not_ready",
            "workspace": workspace,
            "director_profiles": _director_choices(),
            "goal_max_dollars": configured_max_dollars(),
            "goal_max_wall_seconds": configured_max_wall_seconds(),
            "flows_enabled": flow.enabled(),
            "can_enable_flows": has_global_permission(request, "admin") and "MAVERICK_FLOWS" not in os.environ,
            # What Lightwork can do (examples for the person's department) and
            # one limit that is true in code.
            "chat_examples": _chat_examples(request),
            "chat_limits": _CHAT_LIMITS,
            "chat_capability": _CHAT_CAPABILITY,
            "compose_form": compose_form,
            "compose_form_available": page_visible(request, "/goal-builder"),
            "typical_cost": _own_typical_cost(request, w),
            "channels": _goal_builder_channels() if compose_form else [],
        },
    )


def _own_typical_cost(request: Request, world) -> dict | None:
    """What the signed-in person's own past tasks cost (none without a named account)."""
    principal = caller_principal(request) or ""
    if not principal.startswith("user:"):
        return None
    from maverick.typical_cost import typical_cost

    return typical_cost(world, owner=principal)


def _goal_builder_channels() -> list:
    from .control_plane import _discover_channels

    return _discover_channels()


def _chat_examples(request: Request) -> dict:
    try:
        from .chat_examples import examples_for

        return examples_for(request)
    except Exception:  # pragma: no cover -- the empty chat renders without examples
        return {"department": None, "examples": [], "sample": None}


from .chat_examples import CAPABILITY as _CHAT_CAPABILITY  # noqa: E402
from .chat_examples import LIMITS as _CHAT_LIMITS  # noqa: E402


def _director_choices() -> list[dict]:
    """The start form's autonomy levels, from ``[director] profiles``."""
    try:
        from maverick.director_mode import profile_choices

        return profile_choices()
    except Exception:  # pragma: no cover -- the start form never fails on this
        return []


# ---- Chat threads -----------------------------------------------------------
# A chat is a thread of goals. The first message creates the root goal; every
# follow-up is a new goal with parent_id = root, run inside ONE world
# conversation keyed by that root, so the orchestrator threads the earlier
# turns into the brief exactly as it does for a channel session (see
# orchestrator.qa_block / history_block). The web conversation's user_id is
# "<owner>/<root goal id>", which keeps threads apart per person and per chat.
_THREAD_LIST_LIMIT = 25


def _thread_root_id(goal) -> int:
    return int(goal.parent_id) if goal.parent_id else int(goal.id)


def _turn_text(title: str, description: str) -> str:
    """The message as the person wrote it: the title alone when the details
    repeat it, otherwise both, with the details kept verbatim."""
    detail = (description or "").strip()
    return title if not detail or detail == title.strip() else f"{title}\n\n{description}"


def _chat_threads(request: Request, w, *, active_root: int | None = None) -> list[dict]:
    """The caller's recent chats (root goals) for the sidebar, newest first."""
    from maverick.chat_threads import ChatThreads
    from maverick.stop_reasons import stop_payload

    try:
        goals = w.conversation_summaries(owner=goal_owner_filter(request), limit=_THREAD_LIST_LIMIT)
    except Exception:  # pragma: no cover -- the sidebar must never 500 a page
        return []
    from .conversation_organization import organization, pinned_roots
    try:
        known = {goal.id for goal in goals}
        goals.extend(goal for goal in pinned_roots(request, w) if goal.id not in known)
    except Exception:
        pass  # Current authorized tasks remain readable if organization storage is unavailable.
    from .run_status import status_label

    try:  # one read for the listed conversations; each is still checked below
        from maverick.world_model import goals_by_id

        loaded = goals_by_id(w, [g.id for g in goals])
    except Exception:
        loaded = {}
    threads: list[dict] = []
    for g in goals:
        target_id = ChatThreads(w).latest(g.id)
        target = w.goal_stream_state(target_id)
        if target is None:
            continue
        if not can_access_goal(request, target):
            continue
        stop_kind = ""
        if target.status == "blocked":
            try:
                stopped = w.goal_stream_state(target_id, include_result=True)
                stop_kind = (stop_payload(stopped.status, stopped.result) or {}).get("kind", "") if stopped else ""
            except Exception:
                pass  # A sidebar label must not make a task page unavailable.
        try:
            metadata = organization(request, w, g.id, goal=loaded.get(g.id))
        except Exception:
            metadata = {"title": "", "pinned": False, "archived": False}
        if metadata["archived"] and g.id != active_root:
            continue
        threads.append({
            "id": g.id, "target_id": target_id, "title": metadata["title"] or g.title, "status": target.status,
            "stop_kind": stop_kind,
            "state_label": status_label(target.status, stop_kind),
            "pinned": metadata["pinned"], "archived": metadata["archived"],
            "active": g.id == active_root, "updated_at": g.updated_at,
        })
    return sorted(threads, key=lambda row: (not row["pinned"], -row["updated_at"]))


def _thread_turns(w, goal) -> list:
    """Earlier turns of the goal's thread (older goals' messages and answers),
    for the page to render above the live turn. Never blocks the page."""
    try:
        from maverick.chat_threads import ChatThreads

        turns, _ = ChatThreads(w).history(goal.id, limit=50)
        return turns
    except Exception:  # The history control exposes retry without losing this task.
        return []



def _director_run(profile: str, title: str, description: str, base_max_dollars: float | None = None):
    """Director mode for a dashboard start: ``None`` for an ordinary task.

    The autonomy level's spending share is applied to the configured cap and
    clamped to it; its consent mode and review checkpoints can only tighten
    the installation's when the run applies them (``maverick.runner``).
    """
    name = (profile or "").strip()
    if not name:
        return None
    from maverick.director_mode import UnknownProfileError, direct
    from maverick.runner import configured_max_dollars, requested_goal_dollars

    base = base_max_dollars if base_max_dollars is not None else configured_max_dollars()
    try:
        run = direct(title, profile=name, base_max_dollars=base)
    except (UnknownProfileError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Choose one of the listed autonomy levels.") from exc
    import dataclasses

    framed = run.goal_description + (f"\n\n{description}" if description.strip() else "")
    return dataclasses.replace(run, goal_title=title, goal_description=framed,
                               max_dollars=requested_goal_dollars(run.max_dollars))


def _dispatch_goal(request: Request, bg: BackgroundTasks, goal_id: int, *, conversation_id: int | None,
                   receipt: dict, max_dollars: float | None = None) -> None:
    """Hand a goal to the shared runner (same concurrency cap, budget defaults
    and error handling as the REST API and MCP server)."""
    from maverick.runner import run_goal_in_background_async

    from ._request_memo import fresh_configuration
    from .attachment_submission import dispatch
    from .task_model_selection_api import effect_guard as task_ai_guard

    kwargs: dict = {"allowed_suites": caller_suites(request)}
    selection = receipt.get("detail", {}).get("specialist_selection")
    context, check_specialist = _conversation_context(request), None
    if selection is not None:
        from .product_operations_task_launch import published_guard

        if (not isinstance(selection, dict) or set(selection) != {"name", "context", "revision"}
                or any(not isinstance(value, str) for value in selection.values())):
            raise HTTPException(409, "This specialist selection cannot be verified. Start a new task with the current specialist.")
        goal = _world().get_goal(goal_id)
        if goal is None or goal.domain != selection["name"]:
            raise HTTPException(409, "The original specialist selection no longer matches this task.")
        context, check_specialist = selection["context"], published_guard(request, **selection)
    # Every start re-reads the current session, SCIM and workspace authority
    # when the run is admitted, not only one that chose a specialist: a person
    # deactivated or signed out during an upload or writer wait must not start it.
    check_model = task_ai_guard(request, receipt["detail"].get("task_model_selection"), context)
    def current_start_guard():
        with fresh_configuration():
            check_model()
            if check_specialist is not None:
                check_specialist()
            if caller_suites(request) != kwargs["allowed_suites"]:
                raise HTTPException(409, "Your specialist access changed. Reopen Chat and review the current choices before starting.")
    current_start_guard()
    kwargs["effect_guard"] = current_start_guard
    if max_dollars is not None:
        kwargs["max_dollars"] = max_dollars
    if conversation_id is not None:
        kwargs["conversation_id"] = conversation_id
    user_id = execution_user_id_from_request(request)
    if user_id:
        kwargs.update(channel="dashboard", user_id=user_id)
    # Every caller redirects to the task's page: the run starts once that page
    # was served (at most half a second later), not while the browser waits.
    page_handoff.expect(goal_id)
    bg.add_task(dispatch, _world(), receipt, page_handoff.after_page(run_goal_in_background_async),
                goal_id, **kwargs)


def _submission_conversation(w, receipt) -> int | None:
    """Resolve persisted membership, including receipts from older versions."""
    from maverick.chat_threads import ChatThreads

    binding = ChatThreads(w).binding(receipt["goal_id"])
    return binding.conversation_id if binding else None


# The dashboard lands on the chat page (the primary working surface), so the
# bare root renders it too; the overview/stats view lives at /overview. This is
# a distinct handler rather than a second decorator on chat_page so the route
# name stays unique (duplicate names collide as OpenAPI operationIds).
def _owner_setup_first(request: Request) -> bool:
    """A fresh install opens on owner creation before anything else, unless the
    person chose Skip for now (a cookie the /start page sets)."""
    if request.query_params.get("owner") == "later" or request.cookies.get("mvk_owner_later"):
        return False
    try:
        from .local_owner import available as local_owner_available

        return bool(local_owner_available(request))
    except Exception:  # pragma: no cover -- never block the home page on this
        return False


@app.get("/", response_class=HTMLResponse, response_model=None)
async def home(request: Request) -> HTMLResponse | RedirectResponse:
    from .onboarding_state import selected_model_routes_ready

    if _owner_setup_first(request):
        return RedirectResponse("/auth/local-owner", status_code=303)
    if not await run_in_threadpool(selected_model_routes_ready):
        return RedirectResponse("/start", status_code=303)
    if caller_principal(request):
        from .preferences_api import _state

        try:
            start_state = await run_in_threadpool(_state, request)
            start = start_state["values"]["start_page"]
            if start_state["sources"].get("start_page") == "product default":
                # Areas navigation starts each role on its preset's page.
                from .navigation_api import preset_start

                start = await run_in_threadpool(preset_start, request) or start
            if start != "/chat" and start != "/":
                return RedirectResponse(start, status_code=303)
        except (HTTPException, ValueError, OSError):
            pass
    return await run_in_threadpool(chat_page, request)


@app.post("/chat/send")
async def chat_send(
    request: Request,
    bg: BackgroundTasks,
    title: str = Form(...),
    description: str = Form(""),
    files: list[UploadFile] = File(default=[]),
    submission_key: str = Form(""),
    director_profile: str = Form(""),
    connection_references: str = Form(""),
    composer_mode: str = Form(""),
    task_model: str = Form(""),
    task_effort: str = Form(""),
    task_model_context: str = Form(""),
    domain: str = Form(""),
    specialist_context: str = Form(""),
    specialist_revision: str = Form(""),
    value_opportunity: str = Form(""),
) -> RedirectResponse:
    _require_same_origin(request)
    require_permission(request, "operate")
    require_provider_or_400()
    check_goal_rate_limit(request)
    from .task_model_selection_api import effect_guard as task_ai_guard
    from .task_model_selection_api import selection as select_task_ai

    task_selection = select_task_ai(request, task_model, task_effort, task_model_context)
    from .intent_value_handoff import bind as bind_opportunity
    from .intent_value_handoff import validate as validate_opportunity
    from .product_operations_task_launch import published_guard
    validate_opportunity(request, value_opportunity)
    chosen_specialist = domain.strip()
    if len(chosen_specialist) > 120:
        raise HTTPException(422, "Choose a named published specialist from the list.")
    task_model_guard = task_ai_guard(request, task_selection, task_model_context)
    specialist_guard = published_guard(request, chosen_specialist, specialist_context, specialist_revision) if chosen_specialist else None
    def start_guard():
        validate_opportunity(request, value_opportunity)
        task_model_guard()
        if specialist_guard is not None:
            specialist_guard()
    start_guard()
    from maverick.template_connections import validate as validate_connections
    try:
        if len(connection_references) > 200000:
            raise ValueError("The account selection is too large.")
        refs = validate_connections(caller_principal(request) or "", json.loads(connection_references or "[]"))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    message = title or ""
    title = message.strip()
    if not title:
        raise HTTPException(status_code=400, detail="goal text is required")
    if composer_mode == "message":
        # Chat accepts the full message as the task brief. The first line is
        # only the short navigation title; it must not truncate the work.
        brief = message + ("\n\n" + description if description.strip() else "")
        if len(brief) > GOAL_DESCRIPTION_MAX_LENGTH:
            raise HTTPException(status_code=422, detail=(
                f"Shorten your message and details to {GOAL_DESCRIPTION_MAX_LENGTH:,} characters or fewer."
            ))
        title = next(line.strip() for line in message.splitlines() if line.strip())[:GOAL_TITLE_MAX_LENGTH]
        description = chat_text = brief
    else:
        if len(title) > GOAL_TITLE_MAX_LENGTH:
            raise HTTPException(
                status_code=422,
                detail=f"Shorten the task to {GOAL_TITLE_MAX_LENGTH:,} characters or fewer. Move additional instructions to Add details.",
            )
        if len(description) > GOAL_DESCRIPTION_MAX_LENGTH:
            raise HTTPException(
                status_code=422,
                detail=f"Shorten the details to {GOAL_DESCRIPTION_MAX_LENGTH:,} characters or fewer before starting the goal.",
            )
        # Existing API/form callers continue to send a separate short title
        # and description. Preserve their recorded conversation semantics.
        description = description if description.strip() else title
        chat_text = _turn_text(title, description)
    # Director mode: the chosen autonomy level frames the task plan-first and
    # sets its consent, review checkpoints and spending share (never above the
    # configured cap, never looser than the installation's consent mode).
    director = _director_run(director_profile, title, description)
    if director is not None:
        description = director.goal_description
        if len(description) > GOAL_DESCRIPTION_MAX_LENGTH:
            raise HTTPException(status_code=422, detail=(
                "Shorten the details a little: director mode adds a short plan-first note."))
    w = _world()
    owner = caller_principal(request) or ""
    from .attachment_submission import submit

    receipt = await submit(w, files, token=request.headers.get("Idempotency-Key") or submission_key or secrets.token_urlsafe(24),
                           owner=owner, title=title, description=description,
                           domain=chosen_specialist,
                           chat_text=chat_text, connection_references=refs,
                           task_selection=task_selection,
                           specialist_selection={"name": chosen_specialist, "context": specialist_context,
                                                 "revision": specialist_revision} if chosen_specialist else None,
                           effect_guard=start_guard)
    start_guard()
    goal_id = receipt["goal_id"]
    bind_opportunity(request, value_opportunity, w, goal_id)
    if director is not None and receipt.get("created"):
        from maverick.director_mode import record

        await run_in_threadpool(record, w, goal_id, director)
    # The first message opens a chat thread: this goal is its root.
    conversation_id = _submission_conversation(w, receipt)
    _dispatch_goal(request, bg, goal_id, conversation_id=conversation_id, receipt=receipt,
                   max_dollars=director.max_dollars if director is not None else None)
    return RedirectResponse(f"/chat/goal/{goal_id}", status_code=303)


@app.post("/chat/goal/{goal_id}/reply")
async def chat_reply(
    request: Request,
    bg: BackgroundTasks,
    goal_id: int,
    message: str = Form(...),
    files: list[UploadFile] = File(default=[]),
    submission_key: str = Form(""),
    task_model: str = Form(""),
    task_effort: str = Form(""),
    task_model_context: str = Form(""),
) -> RedirectResponse:
    """Continue a chat. The message becomes the next goal in the same thread
    (parent_id = the root goal) and runs inside the thread's conversation, so
    the agent sees the earlier messages and answers as prior turns."""
    _require_same_origin(request)
    require_permission(request, "operate")
    require_provider_or_400()
    check_goal_rate_limit(request)
    from .task_model_selection_api import effect_guard as task_ai_guard
    from .task_model_selection_api import selection as select_task_ai

    task_selection = select_task_ai(request, task_model, task_effort, task_model_context)
    w = _world()
    parent = w.get_goal(goal_id)
    if parent is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, parent)
    from ._event_stream import TERMINAL_RUN_STATUSES

    if parent.status not in TERMINAL_RUN_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=(
                "Lightwork is still working on the previous message. "
                "Wait for it to finish, or stop it, before sending the next one."
            ),
        )
    message = (message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")
    if len(message) > GOAL_DESCRIPTION_MAX_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=f"Shorten the message to {GOAL_DESCRIPTION_MAX_LENGTH:,} characters or fewer.",
        )
    root_id = _thread_root_id(parent)
    root = parent if root_id == parent.id else (w.get_goal(root_id) or parent)
    assert_goal_access(request, root)
    title = message.splitlines()[0].strip()[:GOAL_TITLE_MAX_LENGTH] or message[:GOAL_TITLE_MAX_LENGTH]
    from .attachment_submission import submit

    receipt = await submit(
        w, files, token=request.headers.get("Idempotency-Key") or submission_key or secrets.token_urlsafe(24),
        title=title, description=message, parent_id=root_id,
        owner=root.owner or "",
        domain=root.domain or "",
        project_id=root.project_id,
        chat_text=message, chat_root_id=root_id,
        task_selection=task_selection,
        effect_guard=task_ai_guard(request, task_selection, task_model_context),
    )
    new_id = receipt["goal_id"]
    conversation_id = _submission_conversation(w, receipt)
    _dispatch_goal(request, bg, new_id, conversation_id=conversation_id, receipt=receipt)
    return RedirectResponse(f"/chat/goal/{new_id}", status_code=303)


@app.post("/chat/goal/{goal_id}/recover-submission")
async def recover_chat_submission(request: Request, bg: BackgroundTasks, goal_id: int) -> RedirectResponse:
    _require_same_origin(request)
    require_permission(request, "operate")
    require_provider_or_400()
    from maverick.attachment_submissions import SubmissionStore

    w = _world()
    goal = w.get_goal(goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, goal)
    # Recovery re-runs the owner's own chat draft. It never runs someone else's
    # request under the recovering user's identity and suites.
    if (goal.owner or "") != (caller_principal(request) or ""):
        raise HTTPException(status_code=403, detail="Only the person who submitted this request can recover it")
    receipt = await run_in_threadpool(SubmissionStore(w).for_goal, goal_id)
    if receipt is None or goal.status != "draft":
        raise HTTPException(status_code=409, detail="This submission is not a recoverable draft")
    detail = receipt["detail"]
    if detail.get("kind") == "api" or (detail.get("dispatch_intent") or {}).get("channel") == "api":
        # An API request carries the client's limits; replaying it with the same
        # Idempotency-Key resumes it with exactly those. Chat recovery would not.
        raise HTTPException(status_code=409, detail=(
            "This request came through the API. Replay it with the same Idempotency-Key to run it."))
    records = {(r.filename, r.mime, r.size_bytes, r.sha256) for r in w.list_attachments(goal_id)}
    if any((r["filename"], r["mime"], r["size_bytes"], r["sha256"]) not in records
           for r in receipt["detail"]["manifest"]):
        raise HTTPException(status_code=409, detail="The attachment batch is incomplete. Resubmit the original form and files to recover it.")
    conversation_id = _submission_conversation(w, receipt)
    _dispatch_goal(request, bg, goal_id, conversation_id=conversation_id, receipt=receipt)
    return RedirectResponse(f"/chat/goal/{goal_id}", status_code=303)


@app.post("/webhook/start")
async def webhook_start(request: Request, bg: BackgroundTasks) -> JSONResponse:
    """Generic inbound webhook: create a goal from an HMAC-signed POST.

    Body is JSON ``{title, description?, budget?, id?}`` (an optional ``id``
    gives at-most-once delivery: a repeat within the freshness window 409s).
    The request must carry
    an ``X-Lightwork-Signature: sha256=<hex>`` header computed over the
    timestamp + raw body with the configured ``[webhooks] secret`` (see
    ``maverick.webhooks``), plus an ``X-Lightwork-Timestamp`` header. Matching
    ``X-Maverick-*`` aliases remain supported for existing clients. Returns
    ``{"goal_id": <int>}`` on success.

    Auth: this route is exempt from the dashboard bearer / same-origin
    middleware (see ``_AUTH_EXEMPT``); the HMAC signature is the only
    credential. We fail closed -- a missing/empty secret yields 401.

    Replay defence (Lightwork-CONTROLLED format): the signature binds the
    signed timestamp; a request whose timestamp is outside the
    configured freshness window (``[webhooks] max_age_seconds``) is rejected,
    so a captured signed request can't be replayed to re-spend budget.
    """
    payload = await _verify_maverick_webhook(request)

    title = str(payload.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title is required")
    description = str(payload.get("description") or "")

    # Opt-in exactly-once via a caller-stamped delivery id (see webhook_run).
    if _webhook_duplicate_delivery("start", payload):
        raise HTTPException(status_code=409, detail="duplicate delivery id (already processed)")

    check_goal_rate_limit(request, source="webhook")
    w = _world()
    # HMAC webhooks carry no OIDC principal, so this resolves to "" (unowned):
    # reachable only by no-auth/admin callers, never another tenant.
    goal_id = w.create_goal(
        title[:200],
        description[:8000],
        owner=caller_principal(request) or "",
    )

    from maverick.runner import (
        requested_goal_dollars,
        run_goal_in_background_async,
    )

    budget = payload.get("budget")
    max_dollars = None
    if budget is not None:
        try:
            max_dollars = float(budget)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="budget must be a number") from None
        # Clamp to the same ceiling the REST route enforces. The shared runner
        # treats max_dollars as the highest-precedence override with no cap of
        # its own, so an unclamped webhook value (negative, or arbitrarily
        # large) would defeat the budget ceiling -- budget caps are not
        # optional, even on an externally reachable signed endpoint.
        if not math.isfinite(max_dollars) or max_dollars < 0:
            raise HTTPException(status_code=400, detail="budget must be a finite non-negative number")
        max_dollars = requested_goal_dollars(max_dollars)
    bg.add_task(run_goal_in_background_async, goal_id, max_dollars)
    return JSONResponse({"goal_id": goal_id}, status_code=201)


@contextmanager
def _stored_trigger_tenant(trigger: dict):
    """Pin a trigger fire to its creation namespace and recheck admission."""
    tenant = str(trigger.get("tenant") or "").strip()
    if tenant:
        from maverick.tenant.registry import (
            TenantRegistryError,
            TenantSuspended,
            assert_tenant_active,
        )

        try:
            assert_tenant_active(tenant)
        except (TenantSuspended, KeyError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="trigger unavailable") from exc
        except TenantRegistryError as exc:
            raise HTTPException(
                status_code=503, detail="trigger authorization unavailable"
            ) from exc
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant(tenant or None)
    try:
        yield tenant
    finally:
        reset_tenant(token)


def _stored_trigger_identity(trigger: dict) -> tuple[str, str | None, frozenset[str] | None]:
    """Revalidate a request-less trigger owner's current execution authority."""
    try:
        return stored_automation_identity(str(trigger.get("owner") or ""))
    except AutomationAuthorizationError as exc:
        raise HTTPException(status_code=409, detail="trigger owner is unavailable") from exc


async def _run_trigger_goal_in_tenant(
    goal_id: int,
    max_dollars: float | None,
    max_wall: float | None,
    *,
    tenant: str,
    owner: str,
    allowed_suites: frozenset[str] | None,
) -> None:
    """Restore durable trigger identity for the post-response goal runner."""
    from maverick.paths import reset_tenant, set_tenant
    from maverick.runner import run_goal_in_background_async

    if tenant:
        from maverick.tenant.registry import assert_tenant_active

        assert_tenant_active(tenant)
    current_owner, current_user_id, current_suites = stored_automation_identity(owner)
    if allowed_suites is None:
        run_suites = current_suites
    elif current_suites is None:
        run_suites = allowed_suites
    else:
        run_suites = allowed_suites & current_suites
    token = set_tenant(tenant or None)
    try:
        await run_goal_in_background_async(
            goal_id,
            max_dollars,
            max_wall,
            channel="api" if current_user_id else None,
            user_id=current_user_id,
            concurrency_principal=current_owner or None,
            allowed_suites=run_suites,
        )
    finally:
        reset_tenant(token)


def _fire_stored_trigger(
    request: Request,
    bg: BackgroundTasks,
    payload: dict,
    name: str,
    trigger: dict,
) -> JSONResponse:
    """Fire a trigger under its durable tenant, owner, and current grants."""
    with _stored_trigger_tenant(trigger) as tenant:
        owner, user_id, allowed_suites = _stored_trigger_identity(trigger)
        if trigger.get("flow"):
            from maverick import flow as flow_mod

            if not flow_mod.enabled():
                raise HTTPException(status_code=409, detail="the flow engine is off")
            from maverick.flow import store as flow_store

            try:
                published = flow_store.load_published_bundle(trigger["flow"])
            except flow_store.FlowSnapshotError as exc:
                raise HTTPException(status_code=409, detail="trigger flow unavailable") from exc
            if published is None:
                raise HTTPException(status_code=409, detail="trigger flow unavailable")
            flow, release = published
            expected_owner = str(trigger.get("flow_owner") or "")
            expected_revision = str(trigger.get("flow_revision") or "")
            if not expected_revision and not auth_genuinely_off():
                raise HTTPException(status_code=409, detail="trigger flow binding is stale")
            if expected_revision and (
                flow.owner != expected_owner
                or str(release.get("release_id") or "") != expected_revision
            ):
                raise HTTPException(status_code=409, detail="trigger flow binding is stale")
            check_goal_rate_limit(request, source="webhook")
            inbound_data = payload.get("data")
            run_data = (
                {str(k): v for k, v in inbound_data.items()}
                if isinstance(inbound_data, dict)
                else {}
            )
            delivery = str(payload.get("id") or "").strip()
            idem = f"webhook:{name}:{delivery}" if delivery else ""
            from maverick_dashboard import automation_queue as aq

            try:
                run_id = aq.enqueue_published_flow_run(
                    trigger["flow"],
                    run_data,
                    owner=owner,
                    idem_key=idem,
                    channel="api" if user_id else None,
                    user_id=user_id,
                    allowed_suites=allowed_suites,
                    expected_revision=expected_revision,
                )
            except flow_store.FlowSnapshotError as exc:
                raise HTTPException(
                    status_code=409, detail="trigger flow binding is unavailable"
                ) from exc
            return JSONResponse(
                {"run_id": run_id, "trigger": name, "flow": trigger["flow"]},
                status_code=201,
            )

        try:
            from maverick_dashboard import triggers_store

            tpl = triggers_store.bound_template(trigger)
        except ValueError as exc:
            raise HTTPException(
                status_code=409, detail="trigger template binding is unavailable"
            ) from exc
        declared = set(tpl.params) - {key for key, spec in tpl.parameter_schema.get("fields", {}).items() if spec["type"] == "connection"}
        params = dict(trigger.get("params") or {})
        inbound = payload.get("data")
        if isinstance(inbound, dict):
            for key, value in inbound.items():
                if key in declared:
                    params[str(key)] = str(value)[:2000]
        try:
            from maverick.template_connections import parameters as connection_parameters
            _, refs = connection_parameters(tpl, owner, params)
            title, description = tpl.render_for(owner, **params)
        except ValueError as exc:
            from maverick.secrets import scrub

            detail = scrub(str(exc))[:500] or "template parameters are invalid"
            raise HTTPException(status_code=400, detail=detail) from exc

        check_goal_rate_limit(request, source="webhook")
        world = _world()
        goal_id = world.create_goal(title[:200], description[:8000], owner=owner,
            **({"connection_references": refs} if refs else {}))
        world.record_goal_origin(goal_id, "trigger", name)
        from maverick.runner import (
            requested_goal_dollars,
            requested_goal_wall_seconds,
        )

        max_dollars = requested_goal_dollars(tpl.budget_dollars)
        max_wall = requested_goal_wall_seconds(tpl.budget_wall_seconds)
        bg.add_task(
            _run_trigger_goal_in_tenant,
            goal_id,
            max_dollars,
            max_wall,
            tenant=tenant,
            owner=owner,
            allowed_suites=allowed_suites,
        )
        return JSONResponse({"goal_id": goal_id, "trigger": name}, status_code=201)


@app.post("/webhook/run")
async def webhook_run(request: Request, bg: BackgroundTasks) -> JSONResponse:  # noqa: C901
    """Fire a registered trigger: render its saved template and run it as a goal.

    Body is JSON ``{"trigger": "<name>", "data"?: {...}, "id"?: "<delivery-id>"}``.
    Authenticated by the same HMAC signature as ``/webhook/start``
    (``X-Lightwork-Signature`` over the ``X-Lightwork-Timestamp`` + raw body, with
    the ``[webhooks]`` secret; matching legacy aliases remain accepted) and
    the same replay-freshness window. We fail
    closed -- a missing secret yields 401. An optional ``id`` gives at-most-once
    delivery: a repeat of that id within the window is rejected (409).

    This is deliberately NARROWER than ``/webhook/start``: it runs only a
    template an operator registered via the dashboard (with operator-set default
    params), never arbitrary text. ``data`` may override only the template's
    *declared* params (undeclared keys are ignored, values are length-bounded),
    so an external caller can fill declared slots but cannot inject new ones.

    Gated by ``[features] triggers``; 404s when triggers are disabled.
    """
    # Verify the HMAC signature BEFORE consulting the feature flag: checking the
    # flag first lets an unauthenticated caller distinguish "triggers disabled"
    # (404) from "triggers on" (401/403) as a config probe. Auth first, then gate.
    payload = await _verify_maverick_webhook(request)

    from maverick.config import get_features

    if not get_features().get("triggers", True):
        raise HTTPException(status_code=404, detail="triggers are disabled")

    # Event resume: {"resume": "<run_id>", "data": {...}} continues a flow run
    # paused on a wait_event node -- the external callback the node was waiting
    # for. Same HMAC credential; the data merges into the run before it continues.
    resume_id = str(payload.get("resume") or "").strip()
    if resume_id:
        # Same guards as the trigger paths below: reject a replayed delivery id
        # and apply the webhook rate limit, so a holder of the secret can't flood
        # resume enqueues by varying the timestamp/body.
        if _webhook_duplicate_delivery("run", payload):
            raise HTTPException(status_code=409, detail="duplicate delivery id (already processed)")
        from maverick import flow as flow_mod

        if not flow_mod.enabled():
            raise HTTPException(status_code=409, detail="the flow engine is off")
        from maverick.flow import store as flow_store

        # The webhook HMAC covers the full payload, so an explicit tenant claim
        # is authenticated.  Scope lookup and the queued continuation to that
        # same tenant; without it a tenant run must never fall through to a
        # same-id object in the shared namespace.
        resume_tenant = str(payload.get("tenant") or "").strip()
        tenant_token = None
        if resume_tenant:
            from maverick.tenant.registry import TenantRegistryError, assert_tenant_active

            try:
                assert_tenant_active(resume_tenant)
            except (KeyError, PermissionError, ValueError) as exc:
                raise HTTPException(status_code=404, detail="Workspace unavailable. No workflow continuation was started.") from exc
            except TenantRegistryError as exc:
                raise HTTPException(status_code=503, detail="Workspace access could not be verified. No workflow continuation was started.") from exc
            from maverick.paths import set_tenant

            tenant_token = set_tenant(resume_tenant)
        try:
            run = flow_store.load_run(resume_id)
        finally:
            if tenant_token is not None:
                from maverick.paths import reset_tenant

                reset_tenant(tenant_token)
        if run is None:
            raise HTTPException(status_code=404, detail="no such run")
        if run.status != "paused_event":
            raise HTTPException(
                status_code=409, detail=f"run is not waiting for an event (status {run.status})"
            )
        check_goal_rate_limit(request, source="webhook")
        inbound_evt = payload.get("data")
        inputs = (
            {str(k): v for k, v in inbound_evt.items()} if isinstance(inbound_evt, dict) else {}
        )
        from maverick_dashboard import automation_queue as aq

        try:
            aq.enqueue_flow_resume(
                run.flow_id,
                run.run_id,
                owner=run.owner,
                inputs=inputs,
                tenant=resume_tenant,
            )
        except flow_store.FlowSnapshotError as exc:
            raise HTTPException(status_code=409, detail="run release is no longer active") from exc
        return JSONResponse({"run_id": run.run_id, "status": "resuming"}, status_code=202)

    name = str(payload.get("trigger") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="trigger is required")

    # Optional exactly-once: when the caller stamps a delivery ``id``, reject a
    # replay of that id within the freshness window (409). Unlike byte-level
    # signature dedup this does NOT penalise a legitimate rapid identical fire --
    # those carry distinct ids (or none, in which case no dedup applies).
    if _webhook_duplicate_delivery("run", payload):
        raise HTTPException(status_code=409, detail="duplicate delivery id (already processed)")

    from maverick_dashboard import triggers_store

    trig = triggers_store.get_trigger(name)
    if trig is None:
        raise HTTPException(status_code=404, detail="unknown trigger")

    return _fire_stored_trigger(request, bg, payload, name, trig)


def _flow_approve_page(
    title: str,
    message: str,
    *,
    status: int = 200,
    form_token: str = "",
    approval_card: dict | None = None,
) -> HTMLResponse:
    """A minimal self-contained confirmation/result page for the signed approval
    link. When ``form_token`` is set it renders a confirm button that POSTs back
    (so a link-prefetcher that merely GETs the URL never actuates the decision)."""
    from html import escape

    try:
        from maverick.safety.secret_detector import redact

        title, _title_matches = redact(str(title))
        message, _message_matches = redact(str(message))
    except Exception:
        title = "Approval"
        message = "Approval details are unavailable. Open the app and review again."

    review = ""
    if approval_card is not None:
        from maverick.approval_cards import (
            ApprovalCardError,
            require_current_approval_card,
        )

        try:
            card = require_current_approval_card(approval_card)
        except ApprovalCardError:
            form_token = ""
            review = (
                '<section aria-label="Approval details" class="review invalid">'
                "Approval details failed their integrity or expiry check. "
                "Open the app and request a fresh review.</section>"
            )
        else:
            consequences = card["consequences"]
            effects = "".join(
                f"<li>{escape(str(item))}</li>"
                for item in consequences["known_effects"]
            )
            assumptions = "".join(
                f"<li>{escape(str(item))}</li>"
                for item in consequences["unresolved_assumptions"]
            ) or "<li>None recorded.</li>"
            parameters = "".join(
                f"<li>{escape(str(item))}</li>"
                for item in card["parameters"]["summary"]
            )
            review = (
                '<section aria-label="Approval details" class="review">'
                '<strong>Recommendation only — prediction does not grant authority.</strong>'
                f"<h3>{escape(card['summary'])}</h3>"
                f"<p><b>Target:</b> {escape(card['target']['label'])}<br>"
                f"<b>Actor:</b> {escape(card['authority']['actor'])}<br>"
                f"<b>Workspace:</b> {escape(card['authority']['workspace'])}<br>"
                f"<b>Role:</b> {escape(card['authority']['role'])}<br>"
                f"<b>Expires:</b> {escape(str(card['expires_at']))}</p>"
                f"<h4>Exact inputs</h4><ul>{parameters}</ul>"
                f"<p><b>Before:</b> {escape(card['preview']['before'])}<br>"
                f"<b>After:</b> {escape(card['preview']['after'])}</p>"
                f"<h4>Known effects</h4><ul>{effects}</ul>"
                f"<h4>Unresolved assumptions</h4><ul>{assumptions}</ul>"
                f"<p><b>Irreversible or uncertain:</b> "
                f"{'yes' if consequences['irreversible'] else 'no'}</p>"
                "</section>"
            )
    form = ""
    if form_token:
        form = (
            f'<form method="post" action="/flow/approve">'
            f'<input type="hidden" name="token" value="{escape(form_token)}">'
            f'<button type="submit" style="font-size:16px;padding:10px 22px;'
            f'border-radius:8px;border:1px solid #888;cursor:pointer;">'
            f"Confirm exact operation</button>"
            f"</form>"
        )
    html = (
        f"<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer>"
        f"<meta name=viewport "
        f'content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title>"
        f'<div style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;'
        f'padding:0 20px;">'
        f"<h2>{escape(title)}</h2><p>{escape(message)}</p>{review}{form}</div>"
    )
    return HTMLResponse(html, status_code=status)


def _load_paused_approval_run(token: str):
    """Verify a signed approval ``token`` and return ``(run, decision)`` when it
    points at a run currently paused on an approval; else ``(None, reason)``."""
    from maverick.flow import store
    from maverick.flow.approvals import verify_token

    claim = verify_token(token)
    if not claim:
        return None, "This approval link is invalid or has expired.", "", ""
    tenant = str(claim.get("tenant") or "")
    tenant_token = None
    if tenant:
        try:
            from maverick.tenant.registry import assert_tenant_active

            assert_tenant_active(tenant)
        except Exception:
            return None, "That workspace is not active.", tenant, ""
        from maverick.paths import set_tenant

        tenant_token = set_tenant(tenant)
    try:
        run = store.load_run(claim["run_id"])
    finally:
        if tenant_token is not None:
            from maverick.paths import reset_tenant

            reset_tenant(tenant_token)
    if run is None:
        return None, "That flow run no longer exists.", tenant, ""
    if run.status != "paused_approval":
        return None, f"This run is no longer awaiting approval (status: {run.status}).", tenant, ""
    if (
        str(run.cursor or "") != claim.get("cursor")
        or str(run.prompt or "") != claim.get("prompt")
        or float(run.updated or 0.0) != float(claim.get("updated", -1.0))
    ):
        return None, "This approval link is for an older approval step.", tenant, ""
    if str((run.human or {}).get("assignee") or "") != claim.get("assignee", "") or str(
        run.owner or ""
    ) != claim.get("owner", ""):
        return None, "This approval link is for a different approver scope.", tenant, ""
    from maverick_dashboard import automation_queue as aq

    binding = str(claim.get("binding_sha256") or "")
    try:
        if tenant:
            from maverick.paths import tenant_scope

            with tenant_scope(tenant=tenant):
                current_binding = aq.flow_approval_binding(run)
        else:
            current_binding = aq.flow_approval_binding(run)
    except Exception:
        return None, "Current approval authority is unavailable.", tenant, ""
    if not binding or not hmac.compare_digest(binding, current_binding):
        return None, "This approval link is for an older operation or authority.", tenant, ""
    from maverick.approval_cards import ApprovalCardError, require_current_approval_card

    try:
        require_current_approval_card((run.human or {}).get("approval_card"))
    except ApprovalCardError:
        return None, "This approval has expired. Open the app for a fresh review.", tenant, ""
    return run, claim["decision"], tenant, binding


def _approval_link_actor(
    request: Request, run, *, tenant: str = "",
) -> tuple[str, object]:
    """Return a provable authorized actor for a signed link, or fail closed."""
    from .approval_authority import require_approval_authority

    authority = require_approval_authority(
        request,
        action="flow.approval-link.decide",
        resource=str(run.run_id),
        tenant=tenant or None,
    )
    principal = str(caller_principal(request) or "").strip()
    if not principal:
        raise HTTPException(
            status_code=403,
            detail="sign in with an attributable identity to decide this approval",
        )
    aliases = {principal.casefold()}
    if principal.casefold().startswith("user:") and principal[5:]:
        subject = principal[5:].casefold()
        aliases.update({subject, f"@{subject}"})
    assignee = str((run.human or {}).get("assignee") or "").strip().casefold()
    if assignee and assignee not in aliases:
        raise HTTPException(status_code=403, detail="this approval is assigned to someone else")
    if not assignee and run.owner and principal != run.owner:
        raise HTTPException(status_code=403, detail="this approval belongs to another user")
    return principal, authority


@app.get("/flow/approve", response_class=HTMLResponse)
async def flow_approve_confirm(request: Request, token: str = "") -> HTMLResponse:
    """Show a one-click confirmation for a signed approve/reject link. The state
    change happens on the POST (below), not this GET, so an email/link scanner
    that pre-fetches the URL cannot silently actuate a decision. The token binds
    the pause while dashboard authentication proves the approver identity."""
    from maverick import flow

    if not flow.enabled():
        raise HTTPException(status_code=404, detail="the flow engine is off")
    run, decision, _tenant, _binding = _load_paused_approval_run(token)
    if run is None:
        return _flow_approve_page("Approval unavailable", decision, status=410)
    try:
        _approval_link_actor(request, run, tenant=_tenant)
    except HTTPException as exc:
        return _flow_approve_page(
            "Approval unavailable",
            str(exc.detail),
            status=exc.status_code,
        )
    verb = "approve" if decision == "approved" else "reject"
    name = run.flow_id
    return _flow_approve_page(
        f"Confirm: {verb} this flow?",
        f"“{name}” is paused: {run.prompt or 'awaiting your decision'}. "
        f"Review the exact operation, then click Confirm to {verb} and resume it.",
        form_token=token,
        approval_card=(run.human or {}).get("approval_card"),
    )


@app.post("/flow/approve", response_class=HTMLResponse)
async def flow_approve_submit(request: Request, token: str = Form("")) -> HTMLResponse:
    """Actuate a signed approve/reject link: resume the paused run with the
    decision the token carries. Idempotent -- a second click finds the run no
    longer paused and reports that instead of re-resuming."""
    from maverick import flow

    if not flow.enabled():
        raise HTTPException(status_code=404, detail="the flow engine is off")
    run, decision, tenant, approval_binding = _load_paused_approval_run(token)
    if run is None:
        return _flow_approve_page("Approval unavailable", decision, status=410)
    try:
        decided_by, decision_authority = _approval_link_actor(
            request, run, tenant=tenant,
        )
    except HTTPException as exc:
        return _flow_approve_page(
            "Approval unavailable",
            str(exc.detail),
            status=exc.status_code,
        )
    from maverick.flow import store as flow_store

    from maverick_dashboard import automation_queue as aq

    try:
        aq.enqueue_flow_resume(
            run.flow_id,
            run.run_id,
            decision,
            run.owner,
            tenant=tenant,
            decided_by=decided_by,
            approval_binding_sha256=approval_binding,
            decision_authority=decision_authority,
        )
    except flow_store.FlowSnapshotError:
        return _flow_approve_page(
            "Approval unavailable",
            "This flow release is no longer active.",
            status=410,
        )
    verb = "approved" if decision == "approved" else "rejected"
    return _flow_approve_page(
        "Thanks — recorded",
        f"You {verb} “{run.flow_id}”. It is resuming now; you can close this page.",
    )


_FORM_LOOKUPS_PER_MINUTE = 30
_FORM_LOOKUP_LIMIT = None


def _limit_form_lookups(request: Request) -> None:
    """Throttle public form-token lookups per address, before any lookup runs.

    Each lookup scans the registered form triggers and the vendor
    questionnaires, so unknown-token guesses get their own per-address limit
    instead of spending the goal ceiling that real task starts share."""
    global _FORM_LOOKUP_LIMIT
    if _FORM_LOOKUP_LIMIT is None:
        from maverick.public_rights_form import SlidingWindowLimit

        _FORM_LOOKUP_LIMIT = SlidingWindowLimit(60.0)
    from .ip_allowlist import client_ip

    address = client_ip(request)
    if not _FORM_LOOKUP_LIMIT.hit(f"ip:{address if address is not None else 'unknown'}",
                                  _FORM_LOOKUPS_PER_MINUTE, time.time()):
        raise HTTPException(status_code=429, detail="too many attempts; try again shortly",
                            headers={"Retry-After": "60"})


def _vendor_questionnaire_for(token: str) -> dict | None:
    """Resolve one form; unavailable authority must not masquerade as a 404."""
    try:
        from maverick import vendor_management
        return vendor_management.questionnaire_for_token(token)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="questionnaire lookup is temporarily unavailable",
                            headers={"Retry-After": "2"}) from exc


@app.get("/form/{token}", response_class=HTMLResponse)
async def form_page(request: Request, token: str) -> HTMLResponse:
    """Public submission page for a live automation or vendor questionnaire.

    The token is the addressing secret. Match POST's automation-first order so
    one URL never displays a different form from the one receiving its answers.
    """
    from maverick import automation_events

    _limit_form_lookups(request)
    if automation_events.enabled():
        try:
            trigger = await run_in_threadpool(_registered_form_trigger, token)
            if trigger is not None:
                definition = await run_in_threadpool(_automation_form_definition, trigger, token)
                return templates.TemplateResponse(
                    request, "form_automation.html", {"form": definition},
                    headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                             "X-Robots-Tag": "noindex, nofollow"},
                )
        except _FormTargetUnavailable as exc:
            raise HTTPException(status_code=404, detail="no such form") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="This form is temporarily unavailable.",
            ) from exc
    questionnaire = await run_in_threadpool(_vendor_questionnaire_for, token)
    if questionnaire is None:
        raise HTTPException(status_code=404, detail="no such form")
    return templates.TemplateResponse(
        request, "form_questionnaire.html",
        {"questionnaire": questionnaire, "token": token},
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                 "X-Robots-Tag": "noindex, nofollow"},
    )


def _registered_form_trigger(token: str) -> dict | None:
    """Resolve one public form token to exactly one active tenant namespace."""
    from maverick import form_store
    from maverick.paths import implicit_tenant_id

    from . import event_triggers_store

    registered = [
        trigger for trigger in event_triggers_store.list_triggers()
        if trigger.get("source") == "form"
        and (trigger.get("flow") or trigger.get("template"))
    ]
    matches = [
        trigger for trigger in registered
        if str((trigger.get("config") or {}).get("token") or "") == token
    ]
    tenants = {str(trigger.get("tenant") or "") for trigger in matches}
    floor = implicit_tenant_id()
    if len(matches) != 1 or len(tenants) != 1 or (floor and tenants != {floor}):
        return None
    # Older releases allowed punctuation and mapped it to a filename. Keep
    # those links working, but never let two distinct registered tokens share
    # a queue when their legacy storage names collide.
    key = form_store.storage_key(token)
    if any(
        str(trigger.get("tenant") or "") in tenants
        and str((trigger.get("config") or {}).get("token") or "") != token
        and form_store.storage_key((trigger.get("config") or {}).get("token")) == key
        for trigger in registered
    ):
        return None
    return matches[0]


class _FormTargetUnavailable(RuntimeError):
    """The form's saved automation no longer names an executable release."""


@contextmanager
def _live_registered_form_target(trigger: dict, token: str):
    """Hold one verified target stable for a page read or submission append."""
    from maverick import flow
    from maverick.flow import store as flow_store

    from . import event_triggers_store
    from .event_poll import (
        _require_stored_event_source_authority,
        _trigger_key,
        event_source_authority,
    )
    from .triggers_store import bound_template

    with event_triggers_store.registry_lock():
        current = _registered_form_trigger(token)
        if current is None or _trigger_key(current) != _trigger_key(trigger):
            raise _FormTargetUnavailable("form binding changed during submission")
        flow_id = str(current.get("flow") or "")
        template_id = str(current.get("template") or "")
        if bool(flow_id) == bool(template_id):
            raise _FormTargetUnavailable("form trigger has no single target")
        with _stored_trigger_tenant(current):
            owner = str(current.get("owner") or "").strip()
            try:
                stored_automation_identity(owner)
                _require_stored_event_source_authority(
                    owner, event_source_authority("form", current.get("config") or {}),
                )
            except AutomationAuthorizationError as exc:
                raise HTTPException(
                    status_code=503, detail="This form is not accepting submissions."
                ) from exc
            if flow_id:
                if not flow.enabled():
                    raise _FormTargetUnavailable("form flow engine is off")
                release_id = str(current.get("flow_revision") or "")
                if not release_id:
                    raise _FormTargetUnavailable("form trigger has no bound release")
                try:
                    # This is the same release authority used for durable flow-run
                    # reservation. An unpublish/re-publish cannot race the append.
                    with flow_store.published_flow_guard(
                        flow_id, expected_release_id=release_id,
                    ) as (bound_flow, _release):
                        if bound_flow.owner != str(current.get("flow_owner") or ""):
                            raise _FormTargetUnavailable("form trigger owner changed")
                        yield current, bound_flow
                except flow_store.FlowSnapshotError as exc:
                    raise _FormTargetUnavailable("form release is unavailable") from exc
            else:
                try:
                    template = bound_template(current)
                except ValueError as exc:
                    raise _FormTargetUnavailable("form template is unavailable") from exc
                yield current, template


def _automation_form_definition(trigger: dict, token: str) -> dict:
    """Only display fields from the verified immutable target, never a draft."""
    from .form_inputs import FormInputError, public_form_fields

    with _live_registered_form_target(trigger, token) as (current, target):
        try:
            fields = public_form_fields(
                target, current.get("params") or {}, is_flow=bool(current.get("flow")),
            )
        except FormInputError as exc:
            raise _FormTargetUnavailable("form fields are unavailable") from exc
        title = target.name if current.get("flow") else target.title
        title = str(title or current.get("name") or "Submission form")
        if "{{" in title:
            title = str(current.get("name") or "Submission form").replace("-", " ").title()
        return {"title": title[:160], "fields": fields}


def _append_registered_form(trigger: dict, token: str, fields: dict) -> int:
    """Check and append under the same registry lock as edits and deletion."""
    from maverick import form_store

    from .form_inputs import (
        FormInputError,
        coerce_flow_form,
        public_form_fields,
        validate_public_form_fields,
        validate_template_form,
    )

    with _live_registered_form_target(trigger, token) as (current, target):
        try:
            allowed = public_form_fields(
                target, current.get("params") or {}, is_flow=bool(current.get("flow")),
            )
        except FormInputError as exc:
            raise _FormTargetUnavailable("form fields are unavailable") from exc
        validate_public_form_fields(fields, allowed)
        if current.get("flow"):
            coerce_flow_form(target, {**(current.get("params") or {}), **fields})
        else:
            validate_template_form(target, current.get("params") or {}, fields)
        return form_store.append(token, fields)


@app.post("/form/{token}")
async def form_submit(request: Request, token: str) -> JSONResponse:
    """Record a hosted-form submission under ``token`` so a ``form`` event trigger
    fires a flow with the submitted fields as data. Public by design (a form is
    meant to be filled by anyone with the link); the unguessable ``token`` in the
    path is the addressing secret, the body is size/field-bounded, and firing is
    rate-limited before parsing. Only a registered form trigger or a live vendor
    questionnaire can accept a submission."""
    from maverick import automation_events, form_store

    from .form_inputs import FormInputError

    # Unknown tokens must never allocate a per-token file, and an anonymous
    # guess must not spend the goal ceiling real task starts share: throttle
    # lookups per address, resolve the token, then check the shared admission
    # limit before parsing even a multipart request.
    _limit_form_lookups(request)
    trigger = None
    if automation_events.enabled():
        trigger = await run_in_threadpool(_registered_form_trigger, token)
    if trigger is None:
        questionnaire = await run_in_threadpool(_vendor_questionnaire_for, token)
        if questionnaire is None:
            raise HTTPException(status_code=404, detail="no such form")
    check_goal_rate_limit(request)
    fields: dict = {}
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        body = await _read_limited_webhook_body(request)  # bounded read (shared cap)
        import json as _json

        try:
            parsed = _json.loads(body or b"{}")
        except ValueError as e:
            raise HTTPException(status_code=400, detail="invalid JSON body") from e
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="form fields must be an object")
        fields = parsed
    else:
        # Limit the complete body before Starlette's multipart parser can spool
        # anything to disk. The Request body cache lets the parser reuse it.
        body = await _read_limited_webhook_body(request)
        request._body = body  # noqa: SLF001 - bounded body replay for form parser
        form = await request.form(max_files=0, max_fields=form_store._MAX_FIELDS)
        fields = {k: str(v) for k, v in form.items()}
    if len(fields) > form_store._MAX_FIELDS:
        raise HTTPException(status_code=400, detail="This form has too many fields.")
    if any(len(str(key)) > 200 for key in fields):
        raise HTTPException(status_code=400, detail="A form field name is too long.")
    if any(len("" if value is None else str(value)) > form_store._MAX_VALUE
           for value in fields.values()):
        raise HTTPException(status_code=400, detail="A form answer is too long.")
    # A trigger may have been deleted while its public caller uploaded a body.
    if trigger is not None:
        current = await run_in_threadpool(_registered_form_trigger, token)
        if current is None or current.get("tenant", "") != trigger.get("tenant", ""):
            raise HTTPException(status_code=404, detail="no such form")
    try:
        if trigger is not None:
            seq = await run_in_threadpool(_append_registered_form, trigger, token, fields)
        else:
            seq = await run_in_threadpool(form_store.append, token, fields)
    except _FormTargetUnavailable as exc:
        raise HTTPException(status_code=404, detail="no such form") from exc
    except FormInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except form_store.FormStoreFull as exc:
        raise HTTPException(
            status_code=507,
            detail="This form has reached its submission limit. Please contact the form owner.",
        ) from exc
    except form_store.FormStoreClosed as exc:
        raise HTTPException(status_code=404, detail="no such form") from exc
    if not seq:
        raise HTTPException(status_code=503, detail="This form could not accept a submission.")
    return JSONResponse({"ok": True, "seq": seq}, status_code=201)


@app.get("/dsar/response/{token}")
async def dsar_response_page(request: Request, token: str) -> JSONResponse:
    """The subject's DSAR response, addressed by its unguessable token.

    Public by design, exactly like /form/{token}: the token (stored
    server-side only as a SHA-256 digest, with expiry) is the addressing
    secret. The bundle is assembled at delivery time and scrubbed of
    third-party identifiers by the deterministic redactor before anything
    leaves. Unknown, expired, or disabled all read as the same 404."""
    from maverick import dsar_fulfillment
    if not dsar_fulfillment.enabled():
        raise HTTPException(status_code=404, detail="no such response")
    _check_dsar_response_rate(request)
    response = await run_in_threadpool(
        dsar_fulfillment.response_for_token, token)
    if response is None:
        raise HTTPException(status_code=404, detail="no such response")
    return JSONResponse(response)


@app.post("/consent/webhook")
async def consent_webhook(request: Request) -> JSONResponse:
    """Signed consent-event push from any consent front end (CMP).

    Authenticated by HMAC-SHA256 over ``{timestamp}.{body}``
    (X-Lightwork-Signature hex + X-Lightwork-Timestamp unix seconds,
    ±300s replay window) — external CMPs hold the webhook secret, never
    a dashboard credential. Bounded body; per-event failures skip rather
    than abort; a backdated or replayed event can never flip a newer
    withdrawal."""
    from maverick import consent_registry
    if not consent_registry.webhook_enabled():
        raise HTTPException(
            status_code=403,
            detail="the consent webhook is disabled ([consent_registry] "
                   "webhook_enable)")
    body = await _read_limited_webhook_body(request)
    signature = request.headers.get("x-lightwork-signature", "")
    timestamp = request.headers.get("x-lightwork-timestamp", "")
    try:
        result = await run_in_threadpool(
            consent_registry.ingest_consent_webhook, body, signature,
            timestamp,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except consent_registry.ConsentRegistryConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return JSONResponse(result, status_code=202)


@app.post("/webhook/linear")
async def webhook_linear(request: Request, bg: BackgroundTasks) -> JSONResponse:
    """Linear issue-assigned webhook -> goal. Signature in ``Linear-Signature``."""
    return await _handle_issue_webhook("linear", "Linear-Signature", request, bg)


@app.post("/webhook/jira")
async def webhook_jira(request: Request, bg: BackgroundTasks) -> JSONResponse:
    """Jira issue-assigned webhook -> goal. Signature in ``X-Hub-Signature``."""
    return await _handle_issue_webhook("jira", "X-Hub-Signature", request, bg)


@app.post("/webhook/github")
async def webhook_github(request: Request, bg: BackgroundTasks) -> JSONResponse:
    """Verify GitHub events and report that issue automation is unavailable."""
    import json as _json

    from maverick.github_app import (
        parse_webhook,
        verify_signature,
        webhook_secret,
    )
    signature = request.headers.get("X-Hub-Signature-256")
    body = await _read_limited_webhook_body(request)
    secret = await run_in_threadpool(webhook_secret)
    from maverick.webhooks import separate_webhook_credential
    if not await run_in_threadpool(separate_webhook_credential, secret, "github"):
        secret = None
    if not verify_signature(body, signature, secret):
        return JSONResponse({"detail": "invalid signature"}, status_code=401)
    try:
        payload = parse_webhook(request.headers.get("X-GitHub-Event", ""), _json.loads(body))
    except (ValueError, TypeError):
        return JSONResponse({"detail": "bad payload"}, status_code=400)
    if payload is None:
        return JSONResponse({"status": "ignored"})

    # Preserve delivery validation, but do not consume replay or goal quotas
    # for a workflow that cannot start.
    if not (request.headers.get("X-GitHub-Delivery") or "").strip():
        return JSONResponse({"detail": "missing delivery id"}, status_code=403)

    return JSONResponse(
        {"detail": "GitHub issue automation is unavailable until checkout isolation is implemented"},
        status_code=503,
    )


@app.post("/webhook/gitlab")
async def webhook_gitlab(request: Request, bg: BackgroundTasks) -> JSONResponse:
    """GitLab issue-assigned webhook -> goal.

    GitLab authenticates with a shared ``X-Gitlab-Token`` (no body HMAC), so
    this route verifies that token (constant-time, fail-closed) and keys
    replay-dedup on the required ``X-Gitlab-Event-UUID`` delivery id instead
    of a body signature.
    """
    from maverick.issue_webhooks import (
        build_brief,
        gitlab_webhook_token,
        parse_issue_event,
        replay_window_seconds,
        verify_gitlab_token,
    )

    secret = await run_in_threadpool(gitlab_webhook_token)
    from maverick.webhooks import separate_webhook_credential
    if not await run_in_threadpool(separate_webhook_credential, secret, "gitlab"):
        secret = None
    if not secret:
        raise HTTPException(
            status_code=401,
            detail=(
                "GitLab webhooks aren't set up yet — an administrator must "
                "set the shared webhook token in Settings > All settings (or "
                "the MAVERICK_GITLAB_WEBHOOK_TOKEN environment variable)."
            ),
        )
    if not verify_gitlab_token(request.headers.get("X-Gitlab-Token"), secret):
        raise HTTPException(status_code=403, detail="bad webhook token")
    body = await _read_limited_webhook_body(request)
    try:
        payload = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    event = parse_issue_event("gitlab", payload)
    if event is None:
        return JSONResponse({"ignored": True}, status_code=200)

    # GitLab sends no signed timestamp; the per-delivery UUID is the dedup key.
    delivery = (request.headers.get("X-Gitlab-Event-UUID") or "").strip()
    if not delivery:
        raise HTTPException(status_code=403, detail="missing delivery id")
    if _issue_webhook_replay_seen(f"gitlab:{delivery}", replay_window_seconds()):
        raise HTTPException(status_code=409, detail="duplicate webhook delivery")

    require_provider_or_400()
    check_goal_rate_limit(request, source="webhook:gitlab")
    w = _world()
    title = f"{event.issue_id}: {event.title}".strip()
    goal_id = w.create_goal(title[:200], build_brief(event)[:8000], owner="")
    from maverick.runner import run_goal_in_background_async

    bg.add_task(run_goal_in_background_async, goal_id, None)
    return JSONResponse({"goal_id": goal_id}, status_code=201)


@app.post("/webhook/stripe")
async def webhook_stripe(request: Request) -> JSONResponse:
    """Stripe payment notices (failed or recovered payments, subscription
    changes) -> the workspace's billing status.

    Authenticated by Stripe's own ``Stripe-Signature`` (HMAC-SHA256 over the
    signed timestamp and body, compared in constant time, stale timestamps
    refused) against the Stripe message signing secret
    (``MAVERICK_STRIPE_WEBHOOK_SECRET`` or the sealed All settings value).
    Refused while no secret is set; an unsigned or badly signed event is never
    read. A repeated event id is acknowledged without being applied again, and
    every accepted event is recorded in the activity record before it is
    applied (a refused record means Stripe retries later)."""
    from maverick import billing_stripe
    from maverick.audit import AuditRefused, audit_event

    secret = await run_in_threadpool(billing_stripe._webhook_secret)
    if not secret:
        raise HTTPException(
            status_code=503,
            detail=(
                "Stripe payment notices aren't set up yet. An administrator must save "
                "the Stripe message signing secret in Settings > All settings."
            ),
        )
    body = await _read_limited_webhook_body(request)
    try:
        event = billing_stripe.verify_webhook(
            body, request.headers.get("Stripe-Signature") or "", secret=secret)
    except billing_stripe.StripeWebhookError as exc:
        raise HTTPException(status_code=400, detail="bad Stripe signature") from exc
    event_id = str(event.get("id") or "").strip()[:200]
    event_type = str(event.get("type") or "")[:200]
    if not event_id:
        raise HTTPException(status_code=400, detail="Stripe event has no id")
    if _issue_webhook_replay_seen(f"stripe:{event_id}",
                                  billing_stripe._DEFAULT_WEBHOOK_TOLERANCE * 2):
        return JSONResponse({"received": True, "duplicate": True})
    try:
        await run_in_threadpool(
            lambda: audit_event("control_plane_action", agent="stripe", _global=True,
                                action="stripe_payment_notice", actor="stripe",
                                event_id=event_id, event_type=event_type))
    except AuditRefused as exc:
        with _issue_webhook_seen_lock:
            _issue_webhook_seen.pop(f"stripe:{event_id}", None)
        raise HTTPException(status_code=503, detail=(
            "This notice could not be added to the activity record. Stripe will send it "
            "again.")) from exc
    result = await run_in_threadpool(billing_stripe.handle_event, event)
    return JSONResponse({"received": True, "handled": bool(result.get("handled"))})


# Replay dedup for inbound issue webhooks, keyed on the request's HMAC signature
# (unique per signed body), so a captured delivery replayed within the freshness
# window is rejected. Backed by the SHARED world store when Postgres is
# configured (HA / multi-replica) so a replay can't slip through on a sibling
# replica; falls back to the per-process window for the default single-process /
# SQLite deployment. Same first-writer-wins primitive used for channel dedup and
# the OIDC replay guard.
_issue_webhook_seen: dict[str, float] = {}
_issue_webhook_seen_lock = threading.Lock()
_ISSUE_WEBHOOK_SEEN_MAX = 4096
_ISSUE_WEBHOOK_CHANNEL = "__issue_webhook__"


def _shared_issue_webhook_seen(signature: str) -> bool | None:
    """Record/check ``signature`` in the shared store when Postgres (HA) is
    configured. Returns True if already seen (replay), False on first delivery,
    or None when there is no shared backend / it is unavailable (caller falls
    back to the in-process window). Never raises -- a degraded store must not
    drop webhooks; the HMAC + freshness checks still hold."""
    try:
        from maverick.world_model_backends import is_postgres_configured

        if not is_postgres_configured():
            return None
        # True == first writer (not previously seen) -> NOT a replay.
        first = bool(_world().mark_message_processed(_ISSUE_WEBHOOK_CHANNEL, signature))
        return not first
    except Exception:  # pragma: no cover - shared dedup must never drop a webhook
        log.warning("issue webhook dedup: shared store unavailable, using in-process window")
        return None


def _issue_webhook_replay_seen(signature: str, ttl_seconds: int) -> bool:
    """True if ``signature`` was already delivered within ``ttl_seconds``.

    Prefers the shared store (cross-replica) when Postgres is configured;
    otherwise records the signature in the per-process window and evicts
    expired/overflow entries. The first delivery returns False (and is
    recorded); a replay returns True.
    """
    shared = _shared_issue_webhook_seen(signature)
    if shared is not None:
        return shared
    now = time.time()
    with _issue_webhook_seen_lock:
        for k, t in list(_issue_webhook_seen.items()):
            if t < now - ttl_seconds:
                _issue_webhook_seen.pop(k, None)
        if signature in _issue_webhook_seen:
            return True
        _issue_webhook_seen[signature] = now
        if len(_issue_webhook_seen) > _ISSUE_WEBHOOK_SEEN_MAX:
            # Hard cap: drop the oldest half so a flood can't grow unbounded.
            for k in sorted(_issue_webhook_seen, key=_issue_webhook_seen.get)[
                : len(_issue_webhook_seen) // 2
            ]:
                _issue_webhook_seen.pop(k, None)
        return False


async def _handle_issue_webhook(
    provider: str,
    sig_header: str,
    request: Request,
    bg: BackgroundTasks,
) -> JSONResponse:
    """Shared handler for inbound issue-assigned webhooks (Linear/Jira).

    HMAC-signed with a provider-specific secret (no secret -> 401, bad
    signature -> 403). When the payload isn't an issue assigned to the
    configured bot, acknowledge with ``{"ignored": true}`` instead of
    spawning a goal. On a real assignment, create a goal from the issue and
    enqueue the run, returning ``{"goal_id": <int>}``.
    """
    from maverick.issue_webhooks import (
        build_brief,
        canonical_signature,
        is_fresh,
        parse_issue_event,
        replay_window_seconds,
        verify_signature,
    )
    from maverick.webhooks import issue_webhook_secret

    secret = issue_webhook_secret(provider)
    if not secret:
        raise HTTPException(
            status_code=401,
            detail=(
                "Inbound webhooks aren't set up yet — an administrator must "
                f"configure a distinct MAVERICK_{provider.upper()}_WEBHOOK_SECRET."
            ),
        )
    signature = request.headers.get(sig_header) or ""
    if not signature:
        raise HTTPException(status_code=403, detail="bad webhook signature")
    body = await _read_limited_webhook_body(request)
    if not verify_signature(body, signature, secret):
        raise HTTPException(status_code=403, detail="bad webhook signature")

    try:
        payload = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    event = parse_issue_event(provider, payload)
    if event is None:
        # Wrong event type, unassigned, or assigned to someone other than the
        # bot -- acknowledge without driving the swarm.
        return JSONResponse({"ignored": True}, status_code=200)

    # Replay defence for actionable (goal-spawning) events -- parity with
    # /webhook/start. Linear/Jira sign only the body, but it carries an
    # authenticated webhookTimestamp/timestamp we age-check, and the signature
    # is a per-delivery dedup key. A captured signed event must not be able to
    # re-create and re-run a paid goal indefinitely.
    if not is_fresh(provider, payload):
        raise HTTPException(status_code=403, detail="stale or undated webhook")
    dedup_signature = canonical_signature(signature)
    if not dedup_signature:
        raise HTTPException(status_code=403, detail="bad webhook signature")
    if _issue_webhook_replay_seen(dedup_signature, replay_window_seconds()):
        raise HTTPException(status_code=409, detail="duplicate webhook delivery")

    require_provider_or_400()
    check_goal_rate_limit(request, source=f"webhook:{provider}")
    w = _world()
    title = f"{event.issue_id}: {event.title}".strip()
    # Webhook-driven goal: no authenticated principal -> unowned ("").
    goal_id = w.create_goal(title[:200], build_brief(event)[:8000], owner="")
    from maverick.runner import run_goal_in_background_async

    bg.add_task(run_goal_in_background_async, goal_id, None)
    return JSONResponse({"goal_id": goal_id}, status_code=201)


def _goal_deliverable(g, *, strict: bool = False):
    """A goal's result rendered as the deliverable its pack declares.

    Returns ``(contract, rendered)`` -- the pack's output contract (label /
    consumers / cadence / gate) and the result parsed per its ``shape`` -- or
    ``(None, None)`` for a generic/ungated prose goal or when the factory layer
    is unavailable. A terminal-gated prose pack still returns its contract so
    the reviewer gets a sign-off panel even when an AI-generated playbook did
    not also generate a structured output contract."""
    try:
        from maverick.deliverable import render_deliverable
        from maverick.domain import available_domains, enforced_gate

        prof = available_domains().get(g.domain) if g.domain else None
        if prof is None:
            if strict and g.domain:
                raise LookupError("The task's result policy is unavailable")
            return None, None
        rendered = render_deliverable(prof.output.shape, g.result)
        gate = enforced_gate(prof)
        if not rendered.structured and not gate:
            return None, None
        out = prof.output
        contract = {
            "shape": out.shape,
            "deliverable": out.deliverable,
            "consumers": list(out.consumers),
            "cadence": out.cadence,
            "gate": gate,
        }
        return contract, rendered
    except Exception:  # never 500 the full page if the factory layer is unavailable
        if strict:
            raise
        return None, None


def _require_chat_answer_download(w, goal) -> None:
    """Apply the persisted deliverable release policy to a saved-answer export."""
    from .deliverable_policy import goal_gate as _goal_gate

    if goal.status in ("blocked", "failed"):
        raise HTTPException(status_code=409, detail="this task stopped before producing an answer to download")
    if not goal.result:
        raise HTTPException(status_code=409, detail="this task has no answer to download yet")
    gate = _goal_gate(goal.domain)
    if gate is not None:
        signoff = w.signoff_for(goal.id)
        if signoff is None or signoff.get("decision") != "approved":
            raise HTTPException(
                status_code=403,
                detail="a reviewer must approve this answer before it can be downloaded",
            )


def _chat_answer_text(goal) -> str:
    """Export the same structured cells the person actually reviewed."""
    if goal.status in ("blocked", "failed"):
        from maverick.stop_reasons import stop_payload

        stop = stop_payload(goal.status, goal.result)
        return f"{stop['message']}\n\n{stop['action']}" if stop else ""
    _, rendered = _goal_deliverable(goal)
    if rendered is None or rendered.table is None:
        return goal.result or ""

    def cell(value) -> str:
        return (str(value).replace("\\", "\\\\").replace("|", "\\|")
                .replace("\r\n", "<br>").replace("\r", "<br>").replace("\n", "<br>"))

    table = rendered.table
    lines = ["| " + " | ".join(cell(value) for value in table.headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in table.headers) + " |")
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in table.rows)
    return "\n".join(lines)


def _historical_chat_answer_text(w, goal, turn) -> str:
    from .deliverable_policy import goal_gate as _goal_gate

    if goal.status in ("blocked", "failed"):
        raise HTTPException(status_code=409, detail="this task stopped before producing an answer to download")
    if not turn.content:
        raise HTTPException(status_code=409, detail="this message has no answer to download")
    if _goal_gate(goal.domain) is None:
        return turn.content
    if turn.content != goal.result:
        raise HTTPException(
            status_code=409, detail="open the answer to download its current reviewed version",
        )
    _require_chat_answer_download(w, goal)
    return _chat_answer_text(goal)


def _chat_answer_download_state(w, goal) -> tuple[bool, str]:
    """Explain export availability without relaxing a missing release policy."""
    try:
        _require_chat_answer_download(w, goal)
    except HTTPException as exc:
        if exc.status_code == 403:
            return False, "A reviewer must approve this answer before it can be downloaded."
        if goal.status in ("blocked", "failed"):
            return False, "This task stopped before producing an answer to download."
        if not goal.result:
            return False, "An answer will be available to download after Lightwork produces it."
        return False, "Download is unavailable until this answer's review requirements can be checked."
    except Exception:  # a failed approval read cannot expose an export affordance
        return False, "Download is unavailable until this answer's review requirements can be checked."
    return True, ""


def _chat_history_download_states(request: Request, w, turns) -> dict:
    """Only the current reviewed bytes qualify a gated historical snapshot."""
    out = {}
    goals = {}
    for turn in turns:
        if turn.role != "assistant":
            continue
        allowed, note = False, "Open answer to download its reviewed version."
        try:
            if turn.goal_id not in goals:
                goals[turn.goal_id] = w.get_goal(turn.goal_id)
            goal = goals[turn.goal_id]
            if goal is not None:
                assert_goal_access(request, goal)
                _historical_chat_answer_text(w, goal, turn)
                allowed, note = True, ""
        except Exception:  # history never implies unavailable release authority
            allowed = False
        out[turn.id] = {"allowed": allowed, "note": note}
    return out
@app.get("/chat/goal/{goal_id}/answer-panel", response_class=HTMLResponse)
def chat_answer_panel(request: Request, goal_id: int) -> HTMLResponse:
    """Current authorized saved result, actions, release gate and artifact versions."""
    from .answer_projection import projection, settled

    context = settled(lambda: projection(request, _world(), goal_id))
    return templates.TemplateResponse(request, "_chat_answer_panel.html", context,
                                      headers={"Cache-Control": "no-store, private",
                                               "X-Lightwork-Context": context["conversation_context"]})


def _stop_progress(world, goal):
    from .stop_progress import summarize
    try:
        return summarize(world, goal)
    except Exception:  # pragma: no cover -- never 500 the goal page
        return None


@app.get("/chat/goal/{goal_id}", response_class=HTMLResponse)
def chat_goal(request: Request, goal_id: int) -> HTMLResponse:
    """A task's page; built again when the task changed while it was read."""
    from .answer_projection import settled

    try:
        return settled(lambda: _chat_goal_page(request, goal_id))
    finally:
        page_handoff.served(goal_id)


def _chat_goal_page(request: Request, goal_id: int) -> HTMLResponse:
    require_permission(request, "view")
    original_context = _conversation_context(request)
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    can_download_answer, download_note = _chat_answer_download_state(w, g)
    contract, rendered = (None, None) if g.status in ("blocked", "failed") else _goal_deliverable(g)
    # The current sign-off, only for a gated deliverable (the panel that lets a
    # human certify it and hand it off). None elsewhere -> no panel.
    signoff = None
    if contract and contract.get("gate"):
        try:
            signoff = w.signoff_for(goal_id)
        except Exception:  # pragma: no cover -- never 500 the goal page
            signoff = None
    artifacts = _goal_artifacts(w, goal_id)
    try:
        projects = w.list_projects(owner=goal_owner_filter(request))
    except Exception:  # pragma: no cover -- never 500 the goal page
        projects = []
    try:
        share_links = [s for s in w.share_links_for_goal(goal_id) if s["active"]]
    except Exception:  # pragma: no cover -- never 500 the goal page
        share_links = []
    root_id = _thread_root_id(g)
    root = g if root_id == g.id else (w.get_goal(root_id) or g)
    assert_goal_access(request, root)
    from maverick.attachment_submissions import SubmissionStore
    from maverick.chat_threads import ChatThreads
    from maverick.governed_operations import digest
    from maverick.runner import configured_goal_ceiling_dollars

    from ._event_stream import TERMINAL_RUN_STATUSES
    from .answer_checks import answer_facts
    from .answer_projection import validate_current, version_for
    from .answer_run_details import read as read_run_details

    try:
        spend_ceiling = configured_goal_ceiling_dollars()
    except Exception:  # pragma: no cover -- never 500 the goal page
        spend_ceiling = None
    # Why the run stopped, in plain words. The raw kernel text is shown only
    # to administrators, under a disclosure, never in the card itself.
    from maverick.stop_reasons import stop_payload

    show_technical = has_global_permission(request, "admin")
    stop = stop_payload(g.status, g.result, include_technical=show_technical)

    thread_turns = _thread_turns(w, g) if can_access_goal_principal(caller_principal(request), g) else []
    from .chat_stop_visibility import stop_notes

    thread_stop_notes = stop_notes(w, thread_turns)
    thread_questions = {}
    for earlier_id in {turn.goal_id for turn in thread_turns}:
        earlier = w.get_goal(earlier_id)
        if earlier is not None and can_access_goal(request, earlier):
            thread_questions[earlier_id] = [
                q for q in w.all_questions(earlier_id) if q.answer is not None
            ]
    from types import SimpleNamespace

    from maverick.task_handoffs import apply_ceiling, closure
    handed_off = closure(w, goal_id)
    handoff_budget = SimpleNamespace(max_dollars=spend_ceiling)
    apply_ceiling(w, goal_id, handoff_budget)
    spend_ceiling = handoff_budget.max_dollars
    answer_run_details = read_run_details(request, w, goal_id, expected_goal=g)

    context = {
            "goal": g,
            "can_download_chat_answer": can_download_answer,
            "chat_answer_download_note": download_note,
            "chat_answer_text": _chat_answer_text(g),
            "answered_questions": [q for q in w.all_questions(goal_id) if q.answer is not None],
            "can_operate": not handed_off and has_permission(request, "operate") and (caller_principal(request) or "") == (g.owner or ""),
            "handoff_closed": handed_off,
            "stop": stop,
            "stop_progress": _stop_progress(w, g),
            "show_technical_details": show_technical,
            "submission_key": secrets.token_urlsafe(24),
            "submission": SubmissionStore(w).for_goal(goal_id),
            "spend_ceiling": spend_ceiling,
            "spend_ceiling_text": (
                f"{spend_ceiling:,.2f}" if spend_ceiling is not None else ""
            ),
            "thread_title": _conversation_title(request, w, root),
            "conversation_context": _conversation_context(request),
            "latest_chat_goal_id": ChatThreads(w).latest(g.id),
            "thread_turns": thread_turns,
            "thread_stop_notes": thread_stop_notes,
            "thread_downloads": _chat_history_download_states(request, w, thread_turns),
            "thread_questions": thread_questions,
            "threads": _chat_threads(request, w, active_root=root_id),
            "run_open": g.status not in TERMINAL_RUN_STATUSES and g.status != "draft",
            "can_recover_task_files": bool(g.owner and g.owner.startswith("user:") and caller_principal(request) == g.owner),
            "deliverable": contract,
            "rendered": rendered,
            "signoff": signoff,
            "artifacts": artifacts,
            "answer_version": version_for(g, contract, signoff, artifacts, handed_off),
            "answer_run_details": answer_run_details,
            "answer_run_details_version": digest(answer_run_details),
            **answer_facts(w, g, frozenset(_withheld_event_markers()), request=request),
            "projects": projects,
            "share_links": share_links,
            "withheld_markers": _withheld_event_markers(),
            "voice_only": _voice_only_mode(),
    }
    validate_current(request, w, context, original_context)
    current_root = w.get_goal(root_id)
    if current_root is None:
        raise HTTPException(404, "This conversation is no longer available.")
    assert_goal_access(request, current_root)
    return templates.TemplateResponse(request, "chat_goal.html", context,
                                      headers={"Cache-Control": "no-store, private"})


@app.get("/chat/goal/{goal_id}/download.md")
def download_chat_answer(request: Request, goal_id: int, turn_id: int | None = None) -> Response:
    """Download the saved answer, using the same goal access check as Chat."""
    w = _world()
    goal = w.get_goal(goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, goal)
    if turn_id is None:
        _require_chat_answer_download(w, goal)
        text = _chat_answer_text(goal)
    else:
        from maverick.chat_threads import ChatThreads

        binding = ChatThreads(w).binding(goal_id)
        if binding is None:
            raise HTTPException(status_code=404, detail="no such answer")
        turn = next((t for t in ChatThreads(w).selected_turns(goal_id, turn_id=turn_id)
                     if t.id == turn_id and t.goal_id == goal_id and t.role == "assistant"), None)
        if turn is None:
            raise HTTPException(status_code=404, detail="no such answer")
        text = _historical_chat_answer_text(w, goal, turn)
    # Approval and the rendered answer must describe the same saved version.
    # Recheck after materialization so an intervening edit/restart cannot pair
    # old bytes with a newer approval (or a revoked one).
    current = w.get_goal(goal_id)
    if current is None or (current.updated_at, current.result, current.status, current.domain) != (
        goal.updated_at, goal.result, goal.status, goal.domain,
    ):
        raise HTTPException(status_code=409, detail="this answer changed; reload before downloading")
    assert_goal_access(request, current)
    if turn_id is None:
        _require_chat_answer_download(w, current)
    else:
        _historical_chat_answer_text(w, current, turn)
    return Response(
        text,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="lightwork-answer-{goal_id}.md"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
@app.get("/api/v1/chat/goal/{goal_id}/permissions")
def chat_goal_permissions(request: Request, goal_id: int) -> dict:
    """Fresh task authority for a long-lived page; ownership is not a role."""
    require_permission(request, "view")
    goal = _world().get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "no such goal")
    assert_goal_access(request, goal)
    from maverick.task_handoffs import CLOSED, closure
    if closure(_world(), goal_id):
        return {"can_operate": False, "reason": CLOSED}
    allowed = has_permission(request, "operate") and can_access_goal_principal(caller_principal(request), goal)
    return {"can_operate": allowed, "reason": "" if allowed else (
        "Your current access allows viewing this task only. A reviewed content read does not grant changes. "
        "Ask a workspace administrator about your role. Your draft has not been submitted.")}


def _voice_only_mode() -> bool:
    """``[voice] only_mode``: the finished result is read aloud on arrival."""
    try:
        from maverick.voice_only import voice_only_enabled

        return voice_only_enabled()
    except Exception:  # pragma: no cover -- never 500 the goal page
        return False


def _withheld_event_markers() -> list[str]:
    """The placeholder texts the kernel writes in place of a model-derived
    run event (evidence gateway on, or secret redaction unavailable). The goal
    page folds a run of those into one progress line instead of repeating the
    same sentence once per step."""
    try:
        from maverick.blackboard import Blackboard

        return [Blackboard._WITHHELD_CONTENT, Blackboard._REDACTION_UNAVAILABLE_CONTENT]
    except Exception:  # pragma: no cover -- a page must render without the kernel constant
        return []


def _goal_artifacts(w, goal_id: int, *, strict: bool = False) -> list[dict]:
    """A goal's latest artifacts, each pre-rendered by kind: a ``table`` artifact
    parses to a grid (reusing the deliverable renderer), everything else falls
    back to text. ``[]`` if the goal has none (the panel then doesn't render)."""
    try:
        from maverick.deliverable import render_deliverable

        out: list[dict] = []
        for a in w.latest_artifacts(goal_id):
            shape = "table" if a.get("kind") == "table" else "prose"
            r = render_deliverable(shape, a.get("content"))
            out.append({**a, "table": r.table, "prose": r.prose})
        return out
    except Exception:  # the live projection reports unavailable rather than empty
        if strict:
            raise
        return []


@app.get("/share/{token}", response_class=HTMLResponse)
def shared_goal(request: Request, token: str) -> HTMLResponse:
    """Resolve opaque workspace routing, then authenticate in its world store."""
    from maverick.paths import reset_tenant, set_tenant

    from .share_link_routing import ShareRouteError, resolve

    try:
        route = resolve(token)
    except (ShareRouteError, OSError):
        raise HTTPException(status_code=404, detail="not found") from None
    # Existing tokens from the deployment's default scope stay valid.
    scope_token = set_tenant(route.tenant) if route is not None else None
    try:
        return _shared_goal_in_scope(request, token)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="not found") from None
    finally:
        if scope_token is not None:
            reset_tenant(scope_token)


def _require_shared_goal_release(world, goal, goal_id: int):
    """Fail closed when a removed policy or revoked sign-off blocks sharing."""
    try:
        from maverick.chat_message_actions import require_copy_sources
        from maverick.conversation_inbox import current_authority

        require_copy_sources(world, goal_id, authorize=current_authority)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    try:
        from maverick.domain import available_domains, deliverable_release_allowed

        profile = available_domains().get(goal.domain) if goal.domain else None
        if goal.domain and profile is None:
            raise HTTPException(status_code=404, detail="not found")
        if profile is not None and not deliverable_release_allowed(
            profile, world.signoff_for(goal_id)
        ):
            raise HTTPException(status_code=404, detail="not found")
        return profile
    except HTTPException:
        raise
    except Exception as exc:
        if goal.domain:
            raise HTTPException(status_code=404, detail="not found") from exc
        return None


def _shared_goal_in_scope(request: Request, token: str) -> HTMLResponse:
    """Public, read-only view of a goal's deliverable behind a share token.

    Auth-exempt (the token IS the credential): an unknown, revoked, or expired
    token 404s with no detail. Renders only the title + deliverable + artifacts
    -- never the worklog, spend, controls, or nav."""
    from maverick import world_model
    from maverick.paths import (
        _tenant_segment,
        canonical_tenant_id,
        current_tenant_id_strict,
        maverick_home,
    )
    from maverick.world_model_backends import is_postgres_configured

    if not is_postgres_configured():
        tenant = current_tenant_id_strict()
        if tenant:
            # Check existence before world_for_tenant can reserve/open storage.
            # Canonical validation is read-only; namespace admission remains in
            # _world once the persisted world is known to exist.
            segment = _tenant_segment(canonical_tenant_id(tenant))
            path = maverick_home() / "tenants" / segment / "world.db"
        elif world_model.DEFAULT_DB is not world_model._INITIAL_DEFAULT_DB:
            path = Path(world_model.DEFAULT_DB).expanduser()
        else:
            path = maverick_home() / "world.db"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="not found")
    w = _world()
    goal_id = w.resolve_share_link(token)
    if goal_id is None:
        raise HTTPException(
            status_code=404, detail="this share link is invalid, revoked, or expired"
        )
    g = w.get_goal(goal_id)
    if g is None:  # pragma: no cover -- link resolved but goal gone
        raise HTTPException(status_code=404, detail="not found")
    # Resolve-time authorization matters as much as mint-time authorization:
    # an edit/rerun/rejection invalidates approval but cannot recall a token
    # already copied. Fail closed without revealing whether a gate exists.
    if g.status != "done" or not g.result:
        raise HTTPException(status_code=404, detail="not found")
    _require_shared_goal_release(w, g, goal_id)
    from .deliverable_sharing import release_matches, release_snapshot, source_generation
    try:
        generation = source_generation(w) if token.startswith("r1_") else None
        released = release_snapshot(w, g, token) if token.startswith("r1_") else None
        if token.startswith("r1_") and released is None:
            raise HTTPException(404, "not found")
    except Exception as exc:
        raise HTTPException(404, "not found") from exc
    contract, rendered = _goal_deliverable(g)
    transcript = released.get("transcript") if released else None
    artifacts = [] if transcript is not None else _goal_artifacts(w, goal_id)
    # Re-check after materializing the composite payload. If an artifact or
    # result changed between the first authorization read and these reads, its
    # transaction revoked sign-off; never render that mixed-version snapshot.
    _require_shared_goal_release(w, g, goal_id)
    try:
        fresh_goal = w.get_goal(goal_id)
        if (fresh_goal is None or w.resolve_share_link(token) != goal_id
                or not release_matches(w, fresh_goal, token, source=released, generation=generation)):
            raise HTTPException(404, "not found")
    except Exception as exc:
        raise HTTPException(404, "not found") from exc
    return templates.TemplateResponse(
        request,
        "shared_goal.html",
        {"goal": g, "deliverable": contract, "rendered": rendered, "artifacts": artifacts,
         "transcript": transcript},
    )


@app.get("/api/goal/{goal_id}")
def api_goal_legacy(request: Request, goal_id: int) -> dict:
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    return {"id": g.id, "status": g.status, "title": g.title, "result": g.result or ""}


def _build_plan_tree(world, goal_id: int, depth_cap: int = 6) -> dict:
    """Assemble the plan tree rooted at ``goal_id`` in two queries.

    Avoids the N+1 shape (one query per node, each with a correlated cost
    subquery, thousands of SQL calls for a depth-6 tree): a single
    recursive CTE for the descendant set + one aggregate JOIN for
    costs, then assembles the tree in Python.
    """
    root = world.get_goal(goal_id)
    if root is None:
        return {}

    per_parent_cap = 50
    rows = world.query(
        """
        WITH RECURSIVE descendants(id, parent_id, title, status, depth, created_at) AS (
          SELECT id, parent_id, title, status, 0, created_at
            FROM goals WHERE id = ?
          UNION ALL
          SELECT child.id, child.parent_id, child.title, child.status, d.depth + 1, child.created_at
            FROM descendants d
            JOIN goals child
              ON child.id IN (
                SELECT g.id
                  FROM goals g
                 WHERE g.parent_id = d.id
                 ORDER BY g.created_at ASC, g.id ASC
                 LIMIT ?
              )
           WHERE d.depth < ?
        ),
        episode_totals AS (
          SELECT e.goal_id, SUM(e.cost_dollars) AS dollars
            FROM episodes e
            JOIN descendants d ON d.id = e.goal_id
           GROUP BY e.goal_id
        )
        SELECT d.id, d.parent_id, d.title, d.status, d.depth,
               COALESCE(e.dollars, 0) AS dollars
          FROM descendants d
          LEFT JOIN episode_totals e ON e.goal_id = d.id
         ORDER BY d.depth ASC, d.created_at ASC, d.id ASC
        """,
        (goal_id, per_parent_cap, depth_cap),
    )

    # This tree reads goals.title via raw SQL, so decrypt it the same way the
    # WorldModel accessors do when at-rest encryption seals the column.
    from maverick.world_model import _dec_field

    nodes: dict[int, dict] = {}
    for r in rows:
        nodes[r["id"]] = {
            "id": r["id"],
            "parent_id": r["parent_id"],
            "title": _dec_field(r["title"]),
            "status": r["status"],
            "dollars": float(r["dollars"] or 0.0),
            "children": [],
        }
    # Assemble children lists. Per-parent fan-out cap stays at 50 to
    # match the prior LIMIT (truncates noisy fan-outs in the UI).
    for n in nodes.values():
        parent = nodes.get(n["parent_id"])
        if parent is not None and parent["id"] != n["id"]:
            if len(parent["children"]) < per_parent_cap:
                parent["children"].append(n)
    root_node = nodes.get(goal_id)
    if root_node is None:
        return {
            "id": root.id,
            "parent_id": root.parent_id,
            "title": root.title,
            "status": root.status,
            "dollars": 0.0,
            "children": [],
        }
    return root_node


@app.get("/api/v1/goals/{goal_id}/tree")
def api_plan_tree(request: Request, goal_id: int) -> dict:
    """Plan-tree JSON: root + recursive children with status + cost."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    return _build_plan_tree(w, goal_id)


@app.get("/api/v1/goals/{goal_id}/minimap", response_class=PlainTextResponse)
def goal_minimap(request: Request, goal_id: int, depth: int = 3) -> PlainTextResponse:
    """Plan-tree minimap: the goal's subtree as compact one-line-per-node text.

    Pure render via ``maverick.plan_minimap`` (status glyphs, depth
    indentation, collapsed counts beyond the ``?depth=`` budget).
    """
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.plan_minimap import render_minimap

    try:
        depth = max(0, min(int(depth), 8))
    except (TypeError, ValueError):
        depth = 3
    text = render_minimap(w, goal_id, max_depth=depth)
    return PlainTextResponse(text + "\n", media_type="text/plain; charset=utf-8")


def _render_tree_html(node: dict) -> str:
    """Pre-render the plan-tree as nested <ul><li> HTML.

    Avoids Jinja's recursive-macro limitation (dict args aren't hashable
    for the autoescape cache). Escapes user-controlled fields with html
    escape to keep titles safe.
    """
    import html as _html

    def _esc(s) -> str:
        # quote=True so the value is safe in attribute context too — the
        # status string is interpolated into class="badge {status}".
        # Status is enum-bounded today, but a future writer shouldn't be
        # one missing quote away from attribute-injection.
        return _html.escape(str(s), quote=True) if s is not None else ""

    def _render(n: dict) -> str:
        dollars_html = f' <span class="cost">{_plain_labels.money(n["dollars"])}</span>' if n.get("dollars") else ""
        node_html = (
            f'<a class="node" href="/chat/goal/{_esc(n["id"])}">'
            f'<span class="badge {_esc(n["status"])}">{_esc(_idfmt.humanize(n["status"]))}</span> '
            f'<span class="title">{_esc(n.get("title") or "(untitled)")}</span>'
            f"{dollars_html}"
            f"</a>"
        )
        children = n.get("children") or []
        if not children:
            return f"<li>{node_html}</li>"
        children_html = "".join(_render(c) for c in children)
        return f"<li>{node_html}<ul>{children_html}</ul></li>"

    return f"<ul>{_render(node)}</ul>"


@app.get("/goals/{goal_id}", response_class=HTMLResponse, response_model=None)
def goal_page(request: Request, goal_id: int) -> RedirectResponse:
    """The task's own address: the Result tab (the readable chat view). The
    other tabs live at /goals/{id}/trajectory, /plan and /errors."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    return RedirectResponse(f"/chat/goal/{goal_id}", status_code=302)


@app.get("/goals/{goal_id}/plan", response_class=HTMLResponse)
def plan_tree_page(request: Request, goal_id: int) -> HTMLResponse:
    """HTML plan-tree visualization."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    root = _build_plan_tree(w, goal_id)
    tree_html = _render_tree_html(root)
    return templates.TemplateResponse(
        request,
        "plan_tree.html",
        {"goal": g, "root": root, "tree_html": tree_html},
    )


@app.get("/goals/{goal_id}/trajectory", response_class=HTMLResponse)
def trajectory_page(request: Request, goal_id: int) -> HTMLResponse:
    """Trajectory replay: timeline of every event with a scrubber."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    events = w.goal_events(goal_id, limit=10_000)
    try:
        from maverick import session_tree

        fork_enabled = session_tree.enabled()
    except Exception:  # pragma: no cover - branching is optional
        fork_enabled = False
    from .step_narration import narrate, who

    # Plain words for each step; the recorded text stays under Technical details.
    steps = {e.id: narrate(e.kind, e.agent, e.content) for e in events}
    agents = {e.agent: who(e.agent) for e in events}
    return templates.TemplateResponse(
        request,
        "trajectory.html",
        {"goal": g, "events": events, "fork_enabled": fork_enabled, "steps": steps, "agents": agents,
         "can_operate": has_permission(request, "operate") and can_access_goal_principal(caller_principal(request), g)},
    )


@app.get("/goals/{goal_id}/errors", response_class=HTMLResponse)
def errors_page(request: Request, goal_id: int) -> HTMLResponse:
    """Error inspector: every failed turn for a goal, with full content."""
    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    errors = [e for e in w.goal_events(goal_id, limit=10_000) if e.kind == "error"]
    return templates.TemplateResponse(
        request,
        "errors.html",
        {"goal": g, "errors": errors},
    )


@app.get("/api/v1/cost.csv")
def cost_csv(request: Request, month: str | None = None) -> StreamingResponse:
    """CSV rollup of episode spend, streamed.

    The prior version fetched up to 100k episodes
    into memory, then filtered by month in Python before writing the
    CSV to a StringIO. Now: stream rows directly from the DB, with the
    month filter pushed to SQL.

    ``month`` filter: YYYY-MM (e.g. 2026-04). Omit for lifetime.
    Columns: episode_id, goal_id, started_at, ended_at, outcome,
    dollars, in_tokens, out_tokens, tool_calls.
    """
    import csv
    import datetime as _dt
    import io as _io

    w = _world()
    # Owner-scope the export: an authenticated non-admin gets only their own
    # episodes (auth-off / admin get everything, the historical behaviour), so
    # this chargeback CSV can't leak every tenant's spend ledger. Mirrors the
    # owner scoping on /api/v1/cost/by-tag.
    owner = goal_owner_filter(request)
    start_ts: float | None = None
    end_ts: float | None = None
    if month:
        try:
            start = _dt.datetime.strptime(month, "%Y-%m").replace(tzinfo=_dt.timezone.utc)
            # episodes.started_at is a UTC epoch, so build the window in UTC --
            # a naive strptime().timestamp() interprets midnight in the server's
            # LOCAL zone, shifting the month boundary by the UTC offset (the CSV
            # then drops/keeps the wrong rows for anyone not running in UTC).
            # Roll over by calendar month, not +31 days, which over-counts the
            # short months (e.g. Feb would leak early-March rows).
            if start.month == 12:
                nxt = start.replace(year=start.year + 1, month=1)
            else:
                nxt = start.replace(month=start.month + 1)
        except ValueError:
            # Don't echo strptime's internals (e.g. "unconverted data remains").
            raise HTTPException(
                status_code=400, detail="month must be YYYY-MM (e.g. 2026-04)"
            ) from None
        start_ts = start.timestamp()
        end_ts = nxt.timestamp()

    def generate():
        buf = _io.StringIO()
        writer = csv.writer(buf)
        from maverick.cost_provenance import EXPORT_HEADERS, export_fields
        writer.writerow(
            [
                "episode_id",
                "goal_id",
                "started_at",
                "ended_at",
                "outcome",
                "dollars",
                "input_tokens",
                "output_tokens",
                "tool_calls",
                *EXPORT_HEADERS,
            ]
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        from maverick.episode_reporting import iter_episodes

        from .audit_actions_api import csv_safe

        for episode in iter_episodes(w, owner=owner, since=start_ts, until=end_ts, finished_only=True):
            writer.writerow([episode.id, episode.goal_id, episode.started_at, episode.ended_at,
                             csv_safe(episode.outcome or ""),
                             "unknown" if episode.cost_dollars is None else f"{episode.cost_dollars:.6f}",
                             episode.input_tokens, episode.output_tokens, episode.tool_calls, *export_fields(episode)])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
        # Practice runs cost real provider money: one labelled row, apart from the real runs.
        from maverick import practice_costs

        extra = practice_costs.export_row(practice_costs.summary(owner, since=start_ts, until=end_ts),
                                          9 + len(EXPORT_HEADERS))
        if extra:
            writer.writerow(extra)
            yield buf.getvalue()

    fname = f"maverick-cost-{month}.csv" if month else "maverick-cost-all.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"', "Cache-Control": "private, no-store"},
    )


@app.get("/api/goal/{goal_id}/events")
def api_goal_events_legacy(
    request: Request,
    goal_id: int,
    since: int = 0,
    limit: int = 200,
) -> dict:
    from ._event_stream import TERMINAL_RUN_STATUSES, _chat_event_dict, event_page, replay_cursor

    w = _world()
    g = w.get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, g)
    from maverick.stop_reasons import stop_payload

    since = replay_cursor(since)
    events, has_more = event_page(w, goal_id, since, limit)
    stop = stop_payload(g.status, g.result)
    return {
        "status": g.status,
        "result": stop["message"] if stop else g.result or "",
        "stop": stop,
        "next_id": events[-1].id if events else since,
        "has_more": has_more,
        "terminal": g.status in TERMINAL_RUN_STATUSES and not has_more,
        "events": [_chat_event_dict(e) for e in events],
    }


_SSE_MAX_BATCH = 200  # events per poll read (module-level so tests can shrink it)


@app.get("/api/goal/{goal_id}/events/stream")
async def api_goal_events_stream(
    request: Request, goal_id: int, since: int = 0
) -> StreamingResponse:
    """Server-Sent Events stream of new goal events.

    Polling every 2s (visible tab) / 5s (hidden tab) over the lifetime
    of every open goal page would burn 30 req/min/tab idle on a goal that
    finished an hour ago. SSE holds one TCP connection open, server polls SQLite at 0.5s
    cadence, yields ``data: {json}\\n\\n`` only when there's something
    new. EventSource on the client reconnects automatically and goes
    silent the moment status flips to done/cancelled/failed.

    Terminal statuses close the stream with a final event so the
    client knows it can stop listening (EventSource normally retries
    forever).
    """
    from ._event_stream import (
        LeasedStreamingResponse,
        StreamLease,
        goal_stream,
        replay_cursor,
        stream_state,
    )

    world = _world()
    goal = await run_in_threadpool(stream_state, world, goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="no such goal")
    assert_goal_access(request, goal)
    sem = _get_sse_semaphore()
    if sem.locked():
        raise HTTPException(status_code=503, detail="too many concurrent event streams; retry shortly",
                            headers={"Retry-After": "5"})
    await sem.acquire()
    lease = StreamLease(sem)
    content = goal_stream(
        request, world, goal_id,
        since=replay_cursor(since, request.headers.get("last-event-id")),
        lease=lease, visible=lambda state: can_access_goal(request, state),
        legacy=True, max_batch=_SSE_MAX_BATCH, max_poll=2.0,
    )
    return LeasedStreamingResponse(content, lease=lease, media_type="text/event-stream",
                                   headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----- feature cluster: graph editor / goal builder / embed / benchmarks /
#       walkthroughs / 3D plan tree -----

_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/static/intent-value.js")
def intent_value_script(request: Request):
    require_permission(request, "view")
    return FileResponse(_STATIC_DIR / "intent-value.js", media_type="application/javascript")


@app.get("/static/intent-value.css")
def intent_value_styles(request: Request):
    require_permission(request, "view")
    return FileResponse(_STATIC_DIR / "intent-value.css", media_type="text/css")


@app.get("/static/lightwork-archive-viewer.html")
def archive_viewer_download(request: Request):
    """The offline archive viewer the trajectory page offers. Sent only as a
    download: it runs its own inline script when opened from disk, so it is
    never rendered as a page under the dashboard's address."""
    require_permission(request, "view")
    return FileResponse(_STATIC_DIR / "lightwork-archive-viewer.html", media_type="text/html",
                        filename="lightwork-archive-viewer.html")


@app.get("/static/lightwork-analytics.js")
async def embed_analytics_js() -> FileResponse:
    """The embeddable ``<lightwork-analytics>`` web component (plain JS, no
    framework). See the file's header comment for the same-origin + token
    caveats; /embed-demo shows it running."""
    return FileResponse(
        _STATIC_DIR / "lightwork-analytics.js",
        media_type="application/javascript; charset=utf-8",
    )


@app.get("/static/maverick-analytics.js")
async def embed_analytics_js_legacy() -> FileResponse:
    """Pre-rebrand URL for the analytics component. Pages that embedded the
    script before the Lightwork rebrand keep working; the file itself also
    registers the old <maverick-analytics> tag as an alias."""
    return FileResponse(
        _STATIC_DIR / "lightwork-analytics.js",
        media_type="application/javascript; charset=utf-8",
    )


@app.get("/static/lightwork.css")
async def shell_stylesheet() -> FileResponse:
    """The dashboard shell's design system, served apart from base.html so the
    template stays markup. Short-lived cache: the browser revalidates cheaply
    but a dashboard upgrade restyles without a hard refresh."""
    return FileResponse(
        _STATIC_DIR / "lightwork.css",
        media_type="text/css; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/board.js")
async def board_engine_js() -> FileResponse:
    """The shared executive-board engine (KPI tiles, area/donut/bar charts,
    slicer + live refresh) behind Overview, Spend, and Workforce."""
    return FileResponse(
        _STATIC_DIR / "board.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-ui.js")
async def shell_behaviors_js() -> FileResponse:
    """The shell behaviors (mvToast/mvConfirm/mvForm primitives, halt pill,
    sidebar + preferences), served apart from base.html; loaded at the end of
    <body> on every page."""
    return FileResponse(
        _STATIC_DIR / "lightwork-ui.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-copilot.js")
async def shell_copilot_js() -> FileResponse:
    """The shared page-aware Copilot client used by every dashboard module."""

    return FileResponse(
        _STATIC_DIR / "lightwork-copilot.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-agent-picker.js")
@app.get("/static/lightwork-answer-panel.js")
@app.get("/static/lightwork-approval-history.js")
@app.get("/static/lightwork-chat-drafts.js")
@app.get("/static/lightwork-conversation-inbox.js")
@app.get("/static/lightwork-conversation-organization.js")
@app.get("/static/lightwork-deliverable-bundles.js")
@app.get("/static/lightwork-deliverable-sharing.js")
@app.get("/static/lightwork-employee-companion.js")
@app.get("/static/lightwork-external-agent-executions.js")
@app.get("/static/lightwork-file-selection.js")
@app.get("/static/lightwork-my-work.js")
@app.get("/static/lightwork-permission-requests.js")
@app.get("/static/lightwork-personal-data.js")
@app.get("/static/lightwork-preferences.js")
@app.get("/static/lightwork-project-workspaces.js")
@app.get("/static/lightwork-settings-review.js")
@app.get("/static/lightwork-settings-runtime.js")
@app.get("/static/lightwork-task-authority.js")
@app.get("/static/lightwork-task-handoffs.js")
@app.get("/static/lightwork-thread-history.js")
@app.get("/static/lightwork-employee-companion.css")
@app.get("/static/lightwork-product-operations.js")
@app.get("/static/lightwork-specialist-drafts.js")
@app.get("/static/lightwork-specialist-trials.js")
@app.get("/static/lightwork-company-signin-migration.js")
@app.get("/static/lightwork-company-saml-setup.js")
@app.get("/static/lightwork-connected-event-sources.js")
@app.get("/static/lightwork-knowledge-sources.js")
@app.get("/static/lightwork-personal-alert-tests.js")
@app.get("/static/lightwork-personal-push-devices.js")
@app.get("/static/lightwork-human-conversation-handoffs.js")
@app.get("/static/lightwork-vendor-profile.js")
@app.get("/static/lightwork-channel-message-tests.js")
@app.get("/static/lightwork-settings-search.js")
@app.get("/static/lightwork-shortcuts.js")
@app.get("/static/lightwork-pins.js")
@app.get("/static/lightwork-command.css")
@app.get("/static/lightwork-task-resume.js")
@app.get("/static/lightwork-facts.js")
@app.get("/static/lightwork-access-state.js")
@app.get("/static/lightwork-consent-policy-editor.js")
@app.get("/static/lightwork-setup.js")
@app.get("/static/lightwork-voice-setup.js")
@app.get("/static/lightwork-vendor-setup.js")
@app.get("/static/lightwork-portal-routing-key.js")
@app.get("/static/lightwork-task-file-recovery.js")
@app.get("/static/lightwork-connections.js")
@app.get("/static/lightwork-chat-message-actions.js")
@app.get("/static/lightwork-account-inventory.js")
@app.get("/static/lightwork-schedule-management.js")
@app.get("/static/lightwork-connection-setup.js")
@app.get("/static/lightwork-native-account-return.js")
@app.get("/static/lightwork-template-library.js")
@app.get("/static/lightwork-template-connections.js")
@app.get("/static/lightwork-guided-actions.js")
@app.get("/static/lightwork-ai-business-intake.js")
@app.get("/static/lightwork-guided-actions.css")
@app.get("/static/lightwork-product-tour.css")
@app.get("/static/lightwork-product-tour.js")
@app.get("/static/lightwork-audit-checkpoint-custody.js")
@app.get("/static/lightwork-draft-recovery.js")
@app.get("/static/lightwork-support.js")
@app.get("/static/lightwork-support.css")
@app.get("/static/lightwork-record-search.js")
@app.get("/static/lightwork-record-search.css")
@app.get("/static/lightwork-grc-recovery.js")
@app.get("/static/lightwork-workspace-recovery.js")
@app.get("/static/lightwork-recovery-copilot.js")
@app.get("/static/lightwork-learning-example.js")
@app.get("/static/lightwork-webhook-settings.js")
@app.get("/static/lightwork-workspace-recovery.css")
@app.get("/static/lightwork-action-center.js")
@app.get("/static/lightwork-outcome-accounting.js")
@app.get("/static/lightwork-outcome-value.js")
@app.get("/static/lightwork-outcome-pilots.js")
@app.get("/static/lightwork-commitment-viability.js")
@app.get("/static/lightwork-outcome-pilot-costs.js")
@app.get("/static/lightwork-project-reviews.js")
@app.get("/static/lightwork-workspace-members.js")
@app.get("/static/lightwork-consent-workbench.js")
@app.get("/static/lightwork-consent-workbench.css")
@app.get("/static/lightwork-consent-publishing.js")
@app.get("/static/lightwork-markdown.js")
@app.get("/static/lightwork-chat-code-actions.js")
@app.get("/static/lightwork-learning-question-checks.js")
@app.get("/static/lightwork-task-model-selection.js")
@app.get("/static/lightwork-privacy-discovery-data-use.js")
@app.get("/static/lightwork-runtime-enforcement.js")
@app.get("/static/lightwork-draft-recovery.css")
@app.get("/static/lightwork-governance-agents.js")
@app.get("/static/lightwork-knowledge-library.js")
@app.get("/static/lightwork-tabs.js")
async def in_app_ui_asset(request: Request) -> FileResponse:
    """Serve only the explicitly registered in-app form assets."""
    name = request.url.path.rsplit("/", 1)[-1]
    return FileResponse(
        _STATIC_DIR / name,
        media_type=("text/css" if name.endswith(".css") else "application/javascript") + "; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-plugins.js")
async def plugin_mutations_js() -> FileResponse:
    """Serve plugin confirmations, duplicate-submit guards, and error feedback."""
    return FileResponse(
        _STATIC_DIR / "lightwork-plugins.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-navfinder.js")
async def shell_navfinder_js() -> FileResponse:
    """Accessible registry-backed sidebar search and command palette."""

    return FileResponse(
        _STATIC_DIR / "lightwork-navfinder.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-ai-evidence-analysis.css")
async def ai_evidence_analysis_stylesheet() -> FileResponse:
    """Scoped layout additions for the shared-shell evidence workbench."""

    return FileResponse(
        _STATIC_DIR / "lightwork-ai-evidence-analysis.css",
        media_type="text/css; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-ai-evidence-analysis.js")
async def ai_evidence_analysis_client() -> FileResponse:
    """Bounded raw-body upload and review client for evidence analysis."""

    return FileResponse(
        _STATIC_DIR / "lightwork-ai-evidence-analysis.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-assessment-evidence-autopopulation.css")
async def assessment_evidence_autopopulation_stylesheet() -> FileResponse:
    """Liquid-glass styles for evidence-assisted assessment proposals."""

    return FileResponse(
        _STATIC_DIR / "lightwork-assessment-evidence-autopopulation.css",
        media_type="text/css; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-assessment-evidence-autopopulation.js")
async def assessment_evidence_autopopulation_client() -> FileResponse:
    """Bounded proposal, review, and separate-apply workbench client."""

    return FileResponse(
        _STATIC_DIR / "lightwork-assessment-evidence-autopopulation.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-ai-entity-tasks.js")
async def ai_entity_tasks_client() -> FileResponse:
    """Closed-input client for revision-pinned AI entity tasks."""

    return FileResponse(
        _STATIC_DIR / "lightwork-ai-entity-tasks.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-custom-index.js")
async def consent_custom_index_client() -> FileResponse:
    """Closed-input client for governed exact consent-profile indexes."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-custom-index.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-bulk-jobs.js")
async def consent_bulk_jobs_client() -> FileResponse:
    """Bounded operator client for governed consent export and action jobs."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-bulk-jobs.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-publish-settings.js")
async def consent_publish_settings_client() -> FileResponse:
    """Bounded operator client for versioned website publish settings."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-publish-settings.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-global-opt-out.js")
async def consent_global_opt_out_client() -> FileResponse:
    """Bounded operator client for governed Global Opt-Out configuration."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-global-opt-out.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-application-scanner.css")
async def consent_application_scanner_styles() -> FileResponse:
    """Liquid-glass styles for the governed application-scanner workbench."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-application-scanner.css",
        media_type="text/css; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-application-scanner.js")
async def consent_application_scanner_client() -> FileResponse:
    """Bounded client for governed mobile and connected-app manifest analysis."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-application-scanner.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-consent-native-admin.js")
async def consent_native_admin_client() -> FileResponse:
    """Bounded same-origin client for native-consent administration."""

    return FileResponse(
        _STATIC_DIR / "lightwork-consent-native-admin.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-public-chat-admin.js")
async def public_chat_admin_client() -> FileResponse:
    """Same-origin client for the public website chat section of the Channels page."""

    return FileResponse(
        _STATIC_DIR / "lightwork-public-chat-admin.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-third-party-contracts.js")
async def third_party_contracts_client() -> FileResponse:
    """Closed-input client for Contract and Engagement lifecycle operations."""

    return FileResponse(
        _STATIC_DIR / "lightwork-third-party-contracts.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-third-party-executive-reports.js")
async def third_party_executive_reports_client() -> FileResponse:
    """Bounded client for governed role-aware executive PDF reports."""

    return FileResponse(
        _STATIC_DIR / "lightwork-third-party-executive-reports.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-work-record-details.js")
async def work_record_details_client() -> FileResponse:
    """Reviewed business-field controls using the shared product design."""
    return FileResponse(
        _STATIC_DIR / "lightwork-work-record-details.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-agent-activity.js")
async def agent_activity_client() -> FileResponse:
    """Current authorized recent work for the selected specialist."""
    return FileResponse(
        _STATIC_DIR / "lightwork-agent-activity.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-executive-report-schedules.js")
async def executive_report_schedules_client() -> FileResponse:
    """Ordinary controls for current reviewed recurring executive reports."""
    return FileResponse(
        _STATIC_DIR / "lightwork-executive-report-schedules.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-governed-document-vault.js")
async def governed_document_vault_client() -> FileResponse:
    """Bounded client for encrypted document custody and one-time delivery."""

    return FileResponse(
        _STATIC_DIR / "lightwork-governed-document-vault.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-vendor-onboarding.js")
async def vendor_onboarding_client() -> FileResponse:
    return FileResponse(
        _STATIC_DIR / "lightwork-vendor-onboarding.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-no-code-grc-studio.js")
async def no_code_grc_studio_client() -> FileResponse:
    """Closed-input client for the tenant-private no-code GRC studio."""

    return FileResponse(
        _STATIC_DIR / "lightwork-no-code-grc-studio.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-shared-governance-inventory.js")
async def shared_governance_inventory_client() -> FileResponse:
    """Bounded client for the tenant-private six-suite inventory."""

    return FileResponse(
        _STATIC_DIR / "lightwork-shared-governance-inventory.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-agent-control-plane.js")
async def agent_control_plane_client() -> FileResponse:
    """Client for the Agent Control Plane console (roster + verbs)."""

    return FileResponse(
        _STATIC_DIR / "lightwork-agent-control-plane.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-regulatory-obligations.js")
async def regulatory_obligations_client() -> FileResponse:
    """Client for the Compliance -> Obligations console (regulatory compiler)."""

    return FileResponse(
        _STATIC_DIR / "lightwork-regulatory-obligations.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-trust-receipts.js")
async def trust_receipts_client() -> FileResponse:
    """Client for the Audit -> Trust Receipts console (mint / verify)."""

    return FileResponse(
        _STATIC_DIR / "lightwork-trust-receipts.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-cortex.js")
async def cortex_script() -> FileResponse:
    """The Cortex page's lattice figure and recall console, served same-origin
    like every other page script (an explicit route, never a directory mount)."""
    return FileResponse(
        _STATIC_DIR / "lightwork-cortex.js",
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-immune-console.js")
async def immune_console_client() -> FileResponse:
    """Client for the read-only Immune layer and Code consoles."""

    return FileResponse(
        _STATIC_DIR / "lightwork-immune-console.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-evolution-ledger.js")
async def evolution_ledger_client() -> FileResponse:
    """Client for the Audit -> Evolution Ledger read-only console."""

    return FileResponse(
        _STATIC_DIR / "lightwork-evolution-ledger.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-privacy-data-discovery.css")
async def privacy_data_discovery_styles() -> FileResponse:
    """Liquid-glass styling for the privacy discovery workbench."""

    return FileResponse(
        _STATIC_DIR / "lightwork-privacy-data-discovery.css",
        media_type="text/css; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-privacy-data-discovery.js")
async def privacy_data_discovery_client() -> FileResponse:
    """Bounded same-origin client for privacy discovery and remediation."""

    return FileResponse(
        _STATIC_DIR / "lightwork-privacy-data-discovery.js",
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/static/lightwork-record-workflows.js")
async def record_workflows_client() -> FileResponse:
    """Shared record-list helpers for the privacy and compliance pages."""

    return FileResponse(
        _STATIC_DIR / "lightwork-record-workflows.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-privacy-drop-management.js")
async def privacy_drop_management_client() -> FileResponse:
    """Closed-input client for the authenticated DROP operator workbench."""

    return FileResponse(
        _STATIC_DIR / "lightwork-privacy-drop-management.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/lightwork-voice.js")
async def natural_voice_js() -> FileResponse:
    """The natural-voice layer: ranked speech voices, humanized text, and
    sentence-chunked delivery for every browser read-aloud fallback — the
    bare default utterance is what makes an agent sound robotic."""
    return FileResponse(
        _STATIC_DIR / "lightwork-voice.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/static/daybreak-logo.jpg")
async def brand_logo() -> FileResponse:
    """The Daybreak AI Labs brand logo, served same-origin for the sidebar brand,
    the favicon, and the public share view. Auth-exempt by nature (a brand
    image), cached a day."""
    return FileResponse(
        _STATIC_DIR / "daybreak-logo.jpg",
        media_type="image/jpeg",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/static/daybreak-mark.png")
async def brand_mark() -> FileResponse:
    """The Daybreak AI Labs mark (the circuit-sunrise D) used by the topbar brand.
    Public by nature, cached a day."""
    return FileResponse(
        _STATIC_DIR / "daybreak-mark.png",
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


#: The self-hosted faces the design system declares. An allowlist, not a
#: directory mount: nothing else under static/fonts/ is ever served.
_FONT_FILES = frozenset({
    "manrope-var.woff2",
    "jbm-400.woff2", "jbm-500.woff2",
})


@app.get("/static/fonts/{name}")
async def shell_font(name: str) -> FileResponse:
    """Manrope and JetBrains Mono, served same-origin so the dashboard stays
    offline-first (no third-party font request). Immutable: the file name is
    the version."""
    if name not in _FONT_FILES:
        raise HTTPException(status_code=404)
    return FileResponse(
        _STATIC_DIR / "fonts" / name,
        media_type="font/woff2",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


_MAP_VIEWS = (("", "Flat map", "/graph-editor"), ("3d", "3D view", "/graph-editor?view=3d"))


@app.get("/graph-editor", response_class=HTMLResponse)
def graph_editor_page(request: Request, view: str = "") -> HTMLResponse:
    """Visual graph editor: the goal forest as an editable SVG node graph.

    Layout comes from the server (GET /api/v1/goal-tree); the page JS only
    draws and posts edits (retitle / re-parent / add child). ``?view=3d``
    shows the same forest in 3D (the 3D plan view's page, under the task
    map), for people who may open the 3D plan view."""
    from .goal_tree import forest_html, goal_nodes
    from .navigation_api import areas_on, may_open

    show_3d = may_open(request, "/plan-tree-3d")
    if view == "3d" and not show_3d:
        raise HTTPException(status_code=403, detail="this page is not enabled for your role")
    nodes = goal_nodes(_world(), owner=goal_owner_filter(request))
    # The views bar is areas navigation's; the classic page keeps its 3D link.
    context = {"node_count": len(nodes), "fallback_html": forest_html(nodes),
               "map_views": list(_MAP_VIEWS) if show_3d and areas_on(request) else None}
    if view == "3d":
        context["tab_host"] = {"title": "Task map", "label": "Task map views", "tabs": list(_MAP_VIEWS),
                               "selected": "3d",
                               "lede": "Your tasks and their smaller steps as a 3D map you can move around."}
        return templates.TemplateResponse(request, "plan_tree_3d.html", context)
    return templates.TemplateResponse(request, "graph_editor.html", context)


@app.get("/goal-builder", response_class=HTMLResponse)
async def goal_builder_page(request: Request) -> HTMLResponse:
    """Drag-and-drop goal builder: compose a brief from blocks, then run it."""
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Chat's form mode
    if moved is not None:
        return moved
    return templates.TemplateResponse(
        request, "goal_builder.html", {"channels": _goal_builder_channels()}
    )


# "Step by step", not "Steps": the editor's own view switch already says "Steps".
_BUILDER_MODES = (("", "Describe it", "/workflow-builder"), ("steps", "Step by step", "/workflow-builder?mode=steps"))
_FLOW_ID = re.compile(r"[A-Za-z0-9_-]{1,120}")


@app.get("/workflow-builder", response_class=HTMLResponse)
async def workflow_builder_page(
    request: Request,
    template: str | None = None,
    edit: str | None = None,
    edit_agent: str | None = None,
    mode: str = "",
    flow: str = "",
    from_template: str = "",
) -> HTMLResponse:
    """AI workflow builder: draft a reusable workflow from a brief or an
    uploaded document, edit it, then save it as a runnable template.

    ``?template=<name>`` deep-links from the Templates page: jump straight to
    automating an existing saved template (schedule / webhook trigger) without
    re-drafting it. ``?edit=<name>`` rehydrates the full template editor so Save
    overwrites it; ``?edit_agent=<name>`` rehydrates the playbook editor for an
    existing agent (round-tripping override fields the builder can't show, so
    editing can't silently clear them). An unknown name yields no prefill.

    ``?mode=steps`` is the step-by-step editor (the flow designer's, with its
    drafting, canvas, testing, publishing and assistant) for people who may
    open the flow designer; ``&flow=<id>`` opens a saved flow in it and
    ``&from_template=<name>`` starts from a saved template, as the designer
    does. Flows save through the same /api/v1/flows calls either way."""
    from maverick.config import get_features

    from .navigation_api import areas_on, may_open

    modes = list(_BUILDER_MODES) if may_open(request, "/flows/designer") else None
    if mode == "steps":
        if modes is None:
            raise HTTPException(status_code=403, detail="this page is not enabled for your role")
        flow_id = flow if _FLOW_ID.fullmatch(flow) else ""
        context = _flow_designer_context(request, flow_id, from_template)
        context["builder_modes"] = modes
        return templates.TemplateResponse(request, "flow_designer.html", context)
    feats = get_features()
    prefill = None
    edit_prefill = None
    edit_agent_prefill = None
    # Drafting an unsaved first pass needs only ``operate``; reading or saving
    # an existing pack remains the admin-only control-plane boundary. Compute
    # this before loading the requested agent so a non-admin deep-link cannot
    # receive pack internals embedded in page JavaScript.
    from .editor_policy import pack_editing_denial

    pack_editing_allowed = pack_editing_denial(request) is None
    edit_agent_denied = str(edit_agent or "") if edit_agent and not pack_editing_allowed else ""
    if edit_agent and pack_editing_allowed:
        from maverick.domain_edit import read_override, resolved_view

        try:
            view = resolved_view(edit_agent)
        except Exception:
            view = None
        if view:
            try:
                raw = read_override(edit_agent) or {}
            except Exception:
                raw = {}
            # Preserve the explicitly-overridden fields the builder doesn't
            # expose, so a save (which replaces the override) can't drop them.
            preserve = {
                k: raw[k]
                for k in ("knowledge_sources", "models", "compartment", "extends", "autonomy")
                if k in raw
            }
            edit_agent_prefill = {
                "name": view.get("name", edit_agent),
                "generation": view.get("generation"),
                "description": view.get("description", ""),
                "persona": view.get("persona", ""),
                "allow_tools": view.get("allow_tools", []),
                "deny_tools": view.get("deny_tools", []),
                "max_risk": view.get("max_risk", "medium"),
                "workflow": view.get("workflow", []),
                "preserve": preserve,
            }
    elif edit:
        from maverick.templates import load_template

        try:
            t = load_template(edit)
            assert_template_access(request, t)
            edit_prefill = {
                "name": t.name,
                "title": t.title,
                "body": t.body,
                "params": list(t.params),
                "parameter_schema": t.parameter_schema,
                "budget_dollars": t.budget_dollars,
                # Carry the wall-seconds cap so a save round-trip can't
                # silently reset it to the schema default (3600).
                "budget_wall_seconds": t.budget_wall_seconds,
                "generation": t.generation,
            }
        except (ValueError, FileNotFoundError):
            edit_prefill = None
    elif template:
        from maverick.templates import load_template

        try:
            tpl = load_template(template)
            assert_template_access(request, tpl)
            prefill = {"name": tpl.name, "params": list(tpl.params),
                "parameter_schema": tpl.parameter_schema, "title": tpl.title}
        except (ValueError, FileNotFoundError):
            prefill = None
    return templates.TemplateResponse(
        request,
        "workflow_builder.html",
        {
            "scheduling_enabled": feats.get("scheduling", True),
            "triggers_enabled": feats.get("triggers", True),
            "pack_editing_allowed": pack_editing_allowed,
            "webhook_setup_available": has_global_permission(request, "admin") and page_visible(request, "/settings"),
            "prefill": prefill,
            "edit_prefill": edit_prefill,
            "edit_agent_prefill": edit_agent_prefill,
            "edit_agent_denied": edit_agent_denied,
            "builder_modes": modes if areas_on(request) else None,
        },
    )


@app.get("/start", response_class=HTMLResponse, response_model=None)
def get_started_page(request: Request, use_case: str = "deliverable") -> HTMLResponse | RedirectResponse:
    """First-run guide: a live checklist from zero to a running AI workforce.
    Each step reflects real workspace state (provider configured? a workflow or
    agent built? anything run or automated?) so it self-completes as you go."""
    from maverick.config import get_features

    if _owner_setup_first(request):
        return RedirectResponse("/auth/local-owner", status_code=303)

    from .guided_outcome import for_request
    from .onboarding_state import build

    guided = for_request(request, _world(), use_case) if get_features().get("guided_onboarding") is True else None

    state = build(
        _world(),
        can_configure=has_global_permission(request, "admin"),
        can_operate=has_permission(request, "operate"),
        owner=goal_owner_filter(request),
        reviewed_outcome=guided["outcome"] if guided else None,
    )
    state["guided"] = guided
    state["employee_activation_enabled"] = get_features().get("employee_activation") is True
    from .guided_outcome import first_outcomes_for
    state["first_outcomes"] = first_outcomes_for(request)
    from .local_owner import available as local_owner_available
    state["local_owner_setup_available"] = local_owner_available(request)
    response = templates.TemplateResponse(
        request,
        "get_started.html",
        state,
    )
    if request.query_params.get("owner") == "later":
        response.set_cookie("mvk_owner_later", "1", max_age=7 * 24 * 3600, httponly=True, samesite="lax")
    return response


@app.get("/workflows", response_class=HTMLResponse)
def workflows_index_page(request: Request) -> HTMLResponse:
    """Your saved workflows: templates you authored + agent playbooks you built,
    with quick edit / automate actions. The builder is reached via 'New'. (This
    is the management index; /templates remains the browse-the-catalog page.)"""
    from maverick.config import get_features
    from maverick.templates import can_read_template, load_template, user_templates_dir

    feats = get_features()
    tpls: list[dict] = []
    try:
        names = sorted(p.stem for p in user_templates_dir().glob("*.md"))
    except OSError:
        names = []
    for name in names:
        try:
            t = load_template(name)
            if not can_read_template(t, caller_principal(request)):
                continue
            tpls.append({"name": t.name, "title": t.title, "params": list(t.params)})
        except (ValueError, FileNotFoundError):
            continue
    try:
        from maverick.domain_edit import list_agents

        playbooks = [a for a in list_agents() if a.get("is_override") and a.get("has_workflow")]
    except Exception:
        playbooks = []
    # Unify the surface: saved flow graphs live here too, not on a separate page.
    flows: list[dict] = []
    flows_enabled = False
    try:
        from maverick import flow as _flow

        flows_enabled = _flow.enabled()
        if flows_enabled:
            from maverick.flow import store as _flow_store

            flows = _flow_store.list_flow_summaries(owner=caller_principal(request) or "")
    except Exception:  # pragma: no cover -- never block the page on the flow engine
        flows = []
    return templates.TemplateResponse(
        request,
        "workflows_index.html",
        {
            "templates": tpls,
            "playbooks": playbooks,
            "flows": flows,
            "flows_enabled": flows_enabled,
            "can_manage_flows": has_global_permission(request, "admin"),
            "can_operate_workflows": has_permission(request, "operate"),
            "scheduling_enabled": feats.get("scheduling", True),
            "triggers_enabled": feats.get("triggers", True),
        },
    )


@app.get("/flows/analytics", response_class=HTMLResponse)
async def flow_analytics_page(request: Request) -> HTMLResponse:
    """Per-flow run analytics (volume, success rate, duration p50/p95, top
    errors). Data comes from /api/v1/flows/analytics client-side."""
    from maverick import flow

    return templates.TemplateResponse(request, "flow_analytics.html", {
        "flows_enabled": flow.enabled(),
        "can_manage_flows": has_global_permission(request, "admin"),
    })


@app.get("/connections", response_class=HTMLResponse)
async def connections_page(request: Request) -> HTMLResponse:
    """Manage named SaaS connections (base URL + sealed token) so connectors can
    be wired without env vars. CRUD + reachability test go through
    /api/v1/connections; the feature gate is enforced there."""
    try:
        from maverick import connections as _connections
        enabled = bool(_connections.enabled())
    except Exception:  # pragma: no cover -- the API still enforces the gate
        enabled = True
    people: list[dict] = []
    if has_global_permission(request, "admin") or has_permission(request, "admin"):
        # Choices for "Also allow these people"; the grant itself is still
        # validated by the connections API.
        try:
            from . import invites, rbac
            from .admin_pages import _invite_labels, _people, _signed_in_principals
            labels = _invite_labels(invites.list_invites())
            people = _people(rbac.list_users(), labels, _signed_in_principals())
        except Exception:
            people = []
    try:
        from maverick.tools import enterprise_unavailable_tool_names
        refused = enterprise_unavailable_tool_names()
    except Exception:  # pragma: no cover -- a missing notice never hides the page
        refused = frozenset()
    # Name only the well-known systems that really are refused, so the notice
    # stays true as individual connectors move onto saved connections.
    refused_examples = [label for key, label in (
        ("salesforce", "Salesforce"), ("servicenow", "ServiceNow"),
        ("workday", "Workday"), ("sap", "SAP"), ("jira", "Jira"),
    ) if key in refused]
    return templates.TemplateResponse(request, "connections.html", {
        "connections_enabled": enabled,
        "can_manage_keys": has_permission(request, "admin"),
        "people": people,
        "enterprise_connectors_limited": bool(refused),
        "enterprise_connector_examples": refused_examples,
    })


@app.get(
    "/flows/designer",
    response_class=HTMLResponse,
    name="flow_designer_create_page",
)
@app.get(
    "/flows/designer/{flow_id}",
    response_class=HTMLResponse,
    name="flow_designer_edit_page",
)
async def flow_designer_page(
    request: Request, flow_id: str = "", from_template: str = ""
) -> Response:
    """The visual flow designer -- a canvas node editor + the natural-language
    drafter + the copilot chat. Talks to the /api/v1/flows endpoints; the
    flow-engine gate is enforced there, so the page renders even when flows are
    off (empty canvas).

    ``?from_template=<name>`` opens a saved TEMPLATE as its equivalent
    single-agent flow (the IR's degenerate case) -- the bridge from the text
    workflow builder into the graph designer: start from what you had, then add
    branches/approvals/loops around it. In areas navigation a new flow starts
    in the workflow builder's Steps mode; a saved flow keeps its address."""
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return templates.TemplateResponse(
        request, "flow_designer.html", _flow_designer_context(request, flow_id, from_template))


def _flow_designer_context(request: Request, flow_id: str, from_template: str) -> dict:
    """The flow designer's editor: the flow to open (or a template seed) and
    the engine and management switches (/flows/designer, and the workflow
    builder's Steps mode)."""
    from maverick import flow as _flow

    seed_flow = None
    if from_template:
        try:
            from maverick.templates import load_template

            tpl = load_template(from_template)

            assert_template_access(request, tpl)
            from maverick.flow.ir import single_agent_flow

            body = getattr(tpl, "body", "") or getattr(tpl, "title", "") or from_template
            seed = single_agent_flow("", tpl.title or from_template, str(body)[:8000])
            seed_flow = seed.to_dict()
        except (ValueError, FileNotFoundError):
            seed_flow = None  # unknown template -> a blank canvas, not a 500
    return {
        "flow_id": flow_id,
        "seed_flow": seed_flow,
        "flows_enabled": _flow.enabled(),
        "can_manage_flows": has_global_permission(request, "admin") and "MAVERICK_FLOWS" not in os.environ,
    }


@app.get("/flows/{flow_id}/runs/{run_id}", response_class=HTMLResponse)
async def flow_run_page(request: Request, flow_id: str, run_id: str) -> HTMLResponse:
    """The run viewer: one flow run's node-by-node timeline, inputs/outputs
    (redacted), and the recovery actions (approve/reject, retry, retry from the
    failed step). Data comes from /api/v1/flows/runs/{run_id} client-side, so
    owner-scoping and the flow-engine gate are enforced by the API."""

    from maverick.config import get_flows

    signed_in = bool(caller_principal(request))
    try:
        capture_on = get_flows().get("action_episode_capture") is True
    except Exception:  # an unreadable setting leaves the panel's own checks to explain
        capture_on = True
    return templates.TemplateResponse(request, "flow_run.html", {
        "flow_id": flow_id, "run_id": run_id,
        "learning_example_panel": signed_in,
        "learning_capture_panel": signed_in,
        # With example collection off the keep-as-example panel says so
        # instead of probing APIs that refuse while it is off.
        "learning_capture_on": capture_on,
    })


@app.get("/automations", response_class=HTMLResponse)
def automations_page(request: Request) -> HTMLResponse:
    """One place to see and manage every automation: cron schedules and inbound
    webhook triggers. The page lists the existing /api/v1/schedules and
    /api/v1/triggers; each section is hidden when its [features] knob is off."""
    from maverick.config import get_features

    feats = get_features()
    try:
        from maverick.automation_import import enabled as _import_enabled

        import_enabled = _import_enabled()
    except Exception:  # pragma: no cover -- never block the page on the feature
        import_enabled = False
    try:
        from maverick.automation_events import enabled as _events_enabled

        event_triggers_enabled = _events_enabled()
    except Exception:  # pragma: no cover
        event_triggers_enabled = False
    # Real inventory counts for the page hero, owner-scoped exactly like the
    # /api/v1 lists the page renders from (fail-soft: an unreadable store just
    # counts as zero, never a 500).
    owner = goal_owner_filter(request)
    schedule_count = trigger_count = event_trigger_count = 0
    try:
        from maverick.job_queue import JobQueue

        schedule_count = sum(
            1
            for j in JobQueue().list(status="pending")
            if (j.payload or {}).get("__cron__")
            and (owner is None or (j.payload or {}).get("owner") == owner)
        )
    except Exception:  # pragma: no cover - the hero count is best-effort
        pass
    try:
        from . import triggers_store

        trigger_count = sum(
            1
            for t in triggers_store.list_triggers()
            if owner is None or t.get("owner", "") == owner
        )
    except Exception:  # pragma: no cover - the hero count is best-effort
        pass
    try:
        from maverick.paths import current_tenant_id

        from . import event_triggers_store

        tenant = current_tenant_id() or ""
        event_trigger_count = sum(
            1
            for t in event_triggers_store.list_triggers()
            if t.get("tenant", "") == tenant and (owner is None or t.get("owner", "") == owner)
        )
    except Exception:  # pragma: no cover - the hero count is best-effort
        pass
    return templates.TemplateResponse(
        request,
        "automations.html",
        {
            "scheduling_enabled": feats.get("scheduling", True),
            "triggers_enabled": feats.get("triggers", True),
            "import_enabled": import_enabled,
            "event_triggers_enabled": event_triggers_enabled,
            "schedule_count": schedule_count,
            "trigger_count": trigger_count,
            "event_trigger_count": event_trigger_count,
            "can_admin": has_permission(request, "admin"),
        },
    )


@app.get("/embed-demo", response_class=HTMLResponse)
async def embed_demo_page(request: Request) -> HTMLResponse:
    """Demo + honest usage notes for the <maverick-analytics> web component."""
    return templates.TemplateResponse(request, "embed_demo.html", {})


def _sparkline_points(values: list[float], width: int = 160, height: int = 36, pad: int = 3) -> str:
    """SVG polyline ``points`` for a score series (server-side sparkline)."""
    if not values:
        return ""
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1.0
    n = len(values)
    pts = []
    for i, v in enumerate(values):
        x = pad + (width - 2 * pad) * (i / (n - 1) if n > 1 else 0.5)
        y = pad + (height - 2 * pad) * (1 - (v - lo) / span)
        pts.append(f"{x:.1f},{y:.1f}")
    return " ".join(pts)


@app.get("/benchmarks", response_class=HTMLResponse)
async def benchmarks_page(request: Request) -> HTMLResponse:
    """Continuous-benchmark history: this deployment's recorded runs only.

    Per-suite trend sparklines + a comparison table over the real
    ``~/.maverick/benchmarks/history.json`` store. No competitor numbers are
    shown or invented here."""
    from .api import _benchmark_snapshot

    snap = _benchmark_snapshot()
    for s in snap["suites"]:
        s["spark"] = _sparkline_points([e["score"] for e in s["entries"]])
    snap["can_record"] = has_global_permission(request, "admin")
    return templates.TemplateResponse(request, "benchmarks.html", snap)


@app.get("/walkthroughs", response_class=HTMLResponse, response_model=None)
def walkthroughs_page(request: Request) -> HTMLResponse | RedirectResponse:
    """Locally exported run walkthrough videos (no external hosting).

    Lists the MP4s under the walkthroughs dir with native <video> embeds and
    a captions track when the export produced one. The export itself is
    POST /api/v1/goals/{id}/walkthrough (replay-to-MP4 machinery). In areas
    navigation it is Task replay's Video tab (/replay?tab=video)."""
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return templates.TemplateResponse(request, "walkthroughs.html", _walkthroughs_context(request))


def _walkthroughs_context(request: Request) -> dict:
    """The Video view: exported walkthrough videos the person may open and
    the finished tasks they may turn into one."""
    from .api import _walkthroughs_dir

    d = _walkthroughs_dir()
    items = []
    if d.is_dir():
        for p in sorted(d.glob("*.mp4"), key=lambda q: q.stat().st_mtime, reverse=True):
            try:
                goal_id = _walkthrough_goal_id(p.name)
            except HTTPException:
                continue
            g = _world().get_goal(goal_id)
            if g is None or not can_access_goal(request, g):
                continue
            captions = p.with_suffix(".vtt")
            items.append(
                {
                    "title": getattr(g, "title", "") or "",
                    "name": p.name,
                    "size_mb": round(p.stat().st_size / 1_048_576, 2),
                    "mtime": p.stat().st_mtime,
                    "captions": captions.name if captions.exists() else None,
                    "goal_id": goal_id,
                }
            )
    # NB: not named "dir" — the context processor injects the page's text
    # direction under that key (RTL support) and would shadow it.
    # Recent runs the caller can open, for the "make a video" picker (the
    # export API still checks access on the chosen run).
    runs = [
        {"id": g.id, "title": g.title or "Untitled task", "status": g.status,
         "has_video": any(it["goal_id"] == g.id for it in items)}
        for g in _world().list_goals(owner=goal_owner_filter(request), limit=100, order="desc")
        if g.status not in {"pending", "running"}
    ]
    return {"items": items, "runs": runs}


_WALKTHROUGH_NAME_RE = re.compile(r"^goal-(\d+)\.(mp4|vtt)$")


def _walkthrough_goal_id(name: str) -> int:
    """Return the goal id encoded in a supported walkthrough artifact name."""
    m = _WALKTHROUGH_NAME_RE.fullmatch(name)
    if not m:
        raise HTTPException(status_code=400, detail="invalid walkthrough name")
    return int(m.group(1))


def _assert_walkthrough_access(request: Request, name: str) -> int:
    """Ensure the caller can access the goal-derived walkthrough artifact."""
    goal_id = _walkthrough_goal_id(name)
    g = _world().get_goal(goal_id)
    if g is None:
        raise HTTPException(status_code=404, detail="no such walkthrough")
    assert_goal_access(request, g)
    return goal_id


@app.get("/walkthroughs/media/{name}")
async def walkthrough_media(request: Request, name: str) -> FileResponse:
    """Serve one exported walkthrough artifact after checking goal access."""
    from .api import _walkthroughs_dir

    _assert_walkthrough_access(request, name)
    path = _walkthroughs_dir() / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="no such walkthrough")
    media = "video/mp4" if name.endswith(".mp4") else "text/vtt"
    return FileResponse(path, media_type=media)


@app.get("/plan-tree-3d", response_class=HTMLResponse, response_model=None)
def plan_tree_3d_page(request: Request) -> HTMLResponse | RedirectResponse:
    """The goal forest in 3D (vanilla WebGL; no three.js, no CDN).

    Progressive enhancement: without WebGL (or JS) the server-rendered text
    tree IS the page — it is also always present in a <details> for screen
    readers. WebXR shows an "Enter VR" button only when the browser reports
    support. In areas navigation it lives at /graph-editor?view=3d."""
    from .goal_tree import forest_html, goal_nodes
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)
    if moved is not None:
        return moved
    nodes = goal_nodes(_world(), owner=goal_owner_filter(request))
    return templates.TemplateResponse(
        request,
        "plan_tree_3d.html",
        {"node_count": len(nodes), "fallback_html": forest_html(nodes)},
    )


@app.post("/gateway/v1/chat/completions")
async def llm_gateway_chat_completions(request: Request) -> JSONResponse:
    """OpenAI-compatible governed pass-through for never-enrolled agents.

    Auth is the gateway's own bearer, verified inside the core module; the
    body is screened, forwarded over the SSRF-pinned egress path, and the
    caller ledger updated. Bodies are never stored."""
    from maverick import llm_gateway

    if not llm_gateway.enabled():
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": (
                        "The LLM gateway is disabled; enable [llm_gateway] "
                        "in the Lightwork configuration."
                    ),
                    "type": "invalid_request_error",
                }
            },
        )
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    # Bounded read BEFORE parsing: this path is auth-exempt, so an
    # unauthenticated caller must never be able to make the dashboard
    # buffer an unbounded body (request.json() would). The core module
    # re-checks the same cap post-parse as a second line of defense.
    settings = llm_gateway.get_llm_gateway_config()
    try:
        raw = await _read_limited_request_body(
            request,
            max_bytes=settings["max_body_bytes"],
            too_large_detail=(
                "The request exceeds the gateway's configured size cap."
            ),
        )
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"message": str(exc.detail),
                               "type": "invalid_request_error"}},
        )
    import json as _json
    try:
        body = _json.loads(raw or b"{}")
    except ValueError:
        body = None
    status_code, payload = await run_in_threadpool(
        llm_gateway.handle_chat_completion, body, caller_token=token,
    )
    return JSONResponse(status_code=status_code, content=payload)


@app.post("/gateway/v1/messages")
async def llm_gateway_anthropic_messages(request: Request) -> JSONResponse:
    """Anthropic-compatible governed runtime firewall endpoint.

    Like the OpenAI route, this is self-authenticated by a scoped gateway
    bearer rather than a dashboard cookie.  The core module emits the native
    Anthropic error envelope and performs all policy/redaction/budget checks.
    """
    from maverick import llm_gateway

    if not llm_gateway.enabled():
        return JSONResponse(
            status_code=403,
            content={
                "type": "error",
                "error": {
                    "type": "permission_error",
                    "message": (
                        "The LLM gateway is disabled; enable [llm_gateway] "
                        "in the Lightwork configuration."
                    ),
                },
            },
        )
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    settings = llm_gateway.get_llm_gateway_config()
    try:
        raw = await _read_limited_request_body(
            request,
            max_bytes=settings["max_body_bytes"],
            too_large_detail="The request exceeds the gateway's configured size cap.",
        )
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": str(exc.detail),
                },
            },
        )
    import json as _json
    try:
        body = _json.loads(raw or b"{}")
    except ValueError:
        body = None
    status_code, payload = await run_in_threadpool(
        llm_gateway.handle_anthropic_message, body, caller_token=token,
    )
    return JSONResponse(status_code=status_code, content=payload)


@app.post("/gateway/v1/otel")
async def llm_gateway_otel(request: Request) -> JSONResponse:
    """OTLP/JSON GenAI span ingestion into the shadow-caller ledger.

    Point any OpenTelemetry collector's HTTP exporter here (same gateway
    bearer as the chat endpoint): spans carrying the GenAI semantic
    conventions become governed telemetry — model identity and token
    counts only, never prompts or completions."""
    from maverick import llm_gateway

    if not llm_gateway.enabled():
        return JSONResponse(
            status_code=403,
            content={"error": {"message": "The LLM gateway is disabled.",
                               "type": "invalid_request_error"}},
        )
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    if not llm_gateway.verify_gateway_bearer(token):
        return JSONResponse(
            status_code=401,
            content={"error": {"message": "The gateway bearer is missing or wrong.",
                               "type": "invalid_request_error"}},
        )
    body = await _read_limited_webhook_body(request)
    import json as _json
    try:
        payload = _json.loads(body or b"{}")
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "The OTLP payload must be JSON.",
                               "type": "invalid_request_error"}},
        )
    try:
        result = await run_in_threadpool(llm_gateway.ingest_otel_spans, payload)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": str(exc),
                               "type": "invalid_request_error"}},
        )
    return JSONResponse(status_code=200, content=result)


@app.get("/livez")
async def livez() -> dict:
    """Process is alive (TCP-accept liveness only)."""
    return {"status": "ok"}


def _readiness_deep_checks() -> tuple[bool, dict[str, str]]:
    """The deep readiness checks behind ``/readyz`` and ``/healthz``."""
    return _health_routes.readiness_deep_checks()


@app.get("/healthz")
async def healthz() -> JSONResponse:
    """Deep health: DB writable, LLM provider key present, runner alive."""
    from .provider_readiness import public_verdict, workspace_readiness

    response = await _health_response(
        world_provider=_world,
        provider_key_set=_any_provider_key_set,
        provider_verdict=lambda: public_verdict(workspace_readiness()),
    )
    # Fixed, non-secret identity for the native bounded loopback handshake.
    # A provider-missing 503 still identifies a genuine onboarding dashboard.
    response.headers["X-Lightwork-Service"] = "dashboard-v1"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/readyz")
async def readyz() -> JSONResponse:
    """Ready to serve traffic: the /healthz checks PLUS the deep readiness
    checks (client binding, shield-required, agent-trust registry) so a
    k8s/LB never routes to a pod that is up but configured to refuse all work.
    """
    return await _readiness_response(
        world_provider=_world,
        provider_key_set=_any_provider_key_set,
    )


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> PlainTextResponse:
    """Prometheus text format. Gated by the same bearer as /api/v1."""
    return await _metrics_response(
        request,
        world_provider=_world,
        owner_filter=goal_owner_filter,
    )


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Lightwork dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--recovery-mode", action="store_true")
    args = parser.parse_args()
    if args.recovery_mode:
        from .recovery_mode import configure
        configure(app, host=args.host)

    if not _is_loopback_host(args.host) and not _dashboard_token():
        raise SystemExit(
            "Refusing to bind dashboard to a non-loopback host without "
            "MAVERICK_DASHBOARD_TOKEN (or the access token on Settings > All settings) set."
        )

    # Apply Lightwork's shared logging config (JSON via MAVERICK_LOG_FORMAT=json,
    # correlation-id context filter, secret scrubbing) at the real process
    # entrypoint — not in the lifespan, so the in-process TestClient never
    # reconfigures global logging. The most network-exposed process otherwise
    # inherited raw uvicorn logging with none of the CLI's hygiene.
    try:
        from maverick.logging_config import configure_logging

        configure_logging()
    except Exception:  # pragma: no cover - logging setup never blocks startup
        pass

    # Validate config at startup: a typo'd section/key silently falls back to a
    # default (e.g. an uncapped budget), so surface it now instead of only via
    # `maverick config-lint`. Warn-only unless MAVERICK_CONFIG_STRICT=1.
    try:
        from maverick.config_lint import warn_config_at_startup

        warn_config_at_startup()
    except SystemExit:
        raise
    except Exception:  # pragma: no cover - linting never blocks a non-strict start
        pass

    # JSON logging consistency: uvicorn installs its OWN plaintext access/error
    # formatters by default, so even after configure_logging() switches the root
    # handler to JSON the access lines stayed plaintext -- a mixed JSON+text
    # stream that breaks strict ingestion (Loki/CloudWatch). In JSON mode pass
    # log_config=None so uvicorn doesn't reconfigure those loggers; they then
    # propagate to the JSON root handler. In text mode omit the kwarg entirely so
    # uvicorn keeps its colored default for the local-dev experience.
    from maverick.env_setting import env_or_config as _env_or_config

    from ._server import run_dashboard_server

    _json_logs = (_env_or_config("MAVERICK_LOG_FORMAT", "logging", "format", "text")
                  or "text").strip().lower() == "json"
    try:
        from maverick.proxy_auth import uvicorn_launch_kwargs
        _proxy_kwargs = uvicorn_launch_kwargs()
    except Exception:  # pragma: no cover - never block startup on a config read
        _proxy_kwargs = {}
    if _json_logs:
        run_dashboard_server(app, host=args.host, port=args.port, log_level="info",
                             log_config=None, **_proxy_kwargs)
    else:
        run_dashboard_server(app, host=args.host, port=args.port, log_level="info", **_proxy_kwargs)


# This must remain after every route declaration so lazy included-router
# contexts and request-scope route objects receive the same final identity.
_stabilize_effective_route_names(app)

# Every middleware and handler below the memo shares one per-request memo for
# configuration-derived authorization predicates. Outside it (added last), the
# activity count lets start-up work wait for a quiet moment.
from ._request_memo import RequestMemoMiddleware  # noqa: E402
from .request_activity import RequestActivityMiddleware  # noqa: E402

app.add_middleware(RequestMemoMiddleware)
app.add_middleware(RequestActivityMiddleware)
# Added last, so outermost: one OTLP span per request, when tracing is on. Decided
# here, once; with tracing off nothing is added and a request pays nothing for it.
request_spans.install(app)

# The 13 consecutive function middlewares above run as one layer (about 2 ms
# of task groups and streams per request); order and isolation are unchanged.
from .middleware_chain import merge_function_middleware  # noqa: E402

merge_function_middleware(app)

# A request for a path served before goes straight to its route instead of
# trying the 575 entries before it (6.5-7.4 ms for a late page).
from .route_dispatch import install as _remember_route_matches  # noqa: E402

_remember_route_matches(app.router)


if __name__ == "__main__":
    main()
