"""Settings > All settings: every catalogued product setting with a real control.

``GET /settings/all`` renders the page: the list of groups, and a group's
settings only when asked for (``?group=``, ``?q=``, ``?changed=1``, ``?id=``); the
page loads the rest from ``GET /settings/all/rows`` as the person opens a group or
searches. ``GET /api/v1/settings/catalog`` lists the current state (with the same
filters) and ``POST /api/v1/settings/catalog`` saves or resets one or
more settings in a single overlay write. Every route is global-admin only (the
overlay is deployment-wide), every write is same-origin checked, and each
changed setting lands one ``setting_changed`` audit row that never carries a
secret's value. Changes that lower a protection are refused unless the request
carries ``confirm: true`` -- the page asks the person first, and the server
enforces it independently of the page.
"""
from __future__ import annotations

import contextvars
import copy
import dataclasses
import hashlib
import itertools
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import auth, settings_access_guard, settings_tests, step_up
from . import settings_catalog as catalog

router = APIRouter()

PAGE_PATH = "/settings/all"
ROWS_PATH = PAGE_PATH + "/rows"
API_PATH = "/api/v1/settings/catalog"

SOURCE_TEXT = {
    "deployment": "Set by your server's deployment settings",
    "here": "Set here",
    "installer": "Set by your installer",
    "default": "Default",
}


def _app():
    from . import app as app_module

    return app_module


class _Refused(Exception):
    """A request the page explains in its own plain sentence."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# ---------------------------------------------------------------- state
def _sources() -> dict[str, Any]:
    """The configuration layers the page reports, lowest precedence first."""
    from maverick import config

    from . import settings_store

    config.reset_config_cache()
    config._load_wizard_env()
    try:
        base = config._load_config_file(config.config_path())
    except Exception:  # an unreadable base file shows as "not set by installer"
        base = {}
    operator: dict = {}
    overlay_env = os.environ.get(config.CONFIG_OVERLAY_ENV, "").strip()
    if overlay_env:
        try:
            operator = config._load_config_file(Path(overlay_env).expanduser())
        except Exception:
            operator = {}
    tenant: dict = {}
    tenant_path = config.tenant_config_path()
    if tenant_path:
        try:
            tenant = config._load_config_file(tenant_path, interpolate=False)
        except Exception:
            tenant = {}
    return {
        "base": base if isinstance(base, dict) else {},
        "here": settings_store.load_overlay(),
        "operator": operator if isinstance(operator, dict) else {},
        "tenant": tenant if isinstance(tenant, dict) else {},
    }


def _revision(layers: dict[str, Any] | None = None) -> str:
    """Opaque review binding, including deployment overrides and environment."""
    from maverick import config

    from . import settings_store

    sources = _sources() if layers is None else layers
    names = {name for setting in catalog.SETTINGS for name in setting.env}
    names.update(name for provider in settings_store.PROVIDERS for name in provider.get("env", ()))
    names.update(config.PROVIDER_KEY_ENV_VARS)
    names.update(config.PROVIDER_BASE_URL_ENV_VARS)
    names.update(f"{name.upper()}_{row[2].upper()}" for name, row in catalog.CHANNEL_ALLOWLISTS.items())
    names.update(name for name in os.environ if name.startswith("MAVERICK_"))
    # Variable references may be chosen by the installer rather than named in
    # the catalog. Bind their values without ever sending those values out.
    from maverick.config import _ENV_PATTERN
    names.update(_ENV_PATTERN.findall(json.dumps(sources, default=str)))
    environment = {name: os.environ.get(name, "") for name in names}
    return hashlib.sha256(json.dumps([sources, environment], sort_keys=True,
                                     default=str).encode()).hexdigest()


def _env_locked(setting: catalog.Setting) -> bool:
    return any(os.environ.get(name, "").strip() for name in setting.env)


def _default_of(setting: catalog.Setting) -> object:
    default = setting.default
    return list(default) if isinstance(default, list) else default


def _layer_value(setting: catalog.Setting, layer: object) -> tuple[bool, object]:
    """``(present, value)`` of ``setting`` in one configuration layer."""
    present, value = catalog.lookup(layer, setting.path)
    if setting.key_kind == "entries":
        if not present or not isinstance(value, dict):
            return False, None
        tables = setting.row_kind in {"grid", "named"}  # rows that are small tables
        rows = {k: v for k, v in value.items()
                if k not in setting.fixed_keys and (tables or not isinstance(v, dict))}
        return (bool(rows), rows or None)
    return present, value


def _resolve_table(setting: catalog.Setting, layers: dict[str, Any]) -> dict[str, Any]:
    """Tables merge like the kernel's config loader: later layers add rows."""
    from maverick.config_resets import apply_to_base, is_reset
    masked = is_reset(layers["here"], setting)
    layers = {**layers, "base": apply_to_base(layers["base"], layers["here"])}
    merged: dict[str, object] = {}
    source = "here" if masked else "default"
    for name, label in (("base", "installer"), ("here", "here")):
        present, value = _layer_value(setting, layers[name])
        if present and isinstance(value, dict):
            merged.update(value)
            source = label
    present, value = _layer_value(setting, layers["operator"])
    if present:
        merged.update(value if isinstance(value, dict) else {})
        return {"source": "deployment", "locked": True, "value": merged, "known": True}
    return {"source": "here" if masked else source, "locked": False, "value": merged, "known": True}


def _resolve(setting: catalog.Setting, layers: dict[str, Any]) -> dict[str, Any]:
    """Effective value, where it comes from, and whether this page may change it."""
    if setting.id == "capabilities.deferred_tools":
        return _resolve_deferred_tools(layers)
    provider = _resolve_provider_field(setting, layers)
    if provider is not None:
        return provider
    if setting.section == "features":
        return _resolve_feature(setting, layers)
    if setting.section.startswith("channels."):
        name = setting.section.removeprefix("channels.")
        access = catalog.CHANNEL_ALLOWLISTS.get(name)
        if access and setting.key == access[2]:
            # The adapters use a server list only when NO configured list is
            # present. An explicit [] must remain authoritative and deny all.
            from maverick.config_resets import apply_to_base
            from maverick_channels.base import normalize_allowlist

            layers = {**layers, "base": apply_to_base(layers["base"], layers["here"])}
            paths = [setting.path]
            if name == "teams":
                paths.append((*setting.path[:-1], "allowed_user_ids"))
            for path in paths:
                for layer, source in (("tenant", "deployment"), ("operator", "deployment"),
                                      ("here", "here"), ("base", "installer")):
                    present, value = catalog.lookup(layers[layer], path)
                    if present and value is not None:
                        if not isinstance(value, (list, tuple, set)):
                            return {"source": source, "locked": True, "value": None, "known": False}
                        return {"source": source, "locked": source == "deployment",
                                "value": sorted(normalize_allowlist(value, "")), "known": True}
            environment = f"{name.upper()}_{setting.key.upper()}"
            people = sorted(normalize_allowlist(None, environment))
            if people:
                return {"source": "deployment", "locked": False,
                        "source_text": "Set when this Lightwork process starts · save here to replace it",
                        "value": people, "known": True}
            return {"source": "default", "locked": False, "value": [], "known": True}
    if _env_locked(setting):
        return {"source": "deployment", "locked": True, "value": None, "known": False}
    if setting.control == "table":
        return _resolve_table(setting, layers)
    present, value = catalog.lookup(layers["operator"], setting.path)
    if present:
        return {"source": "deployment", "locked": True, "value": value, "known": True}
    present, value = catalog.lookup(layers["here"], setting.path)
    if present:
        return {"source": "here", "locked": False, "value": value, "known": True}
    from maverick.config_resets import is_reset
    if is_reset(layers["here"], setting):
        return {"source": "here", "locked": False, "value": _default_in(setting, layers), "known": True}
    present, value = catalog.lookup(layers["base"], setting.path)
    if present:
        return {"source": "installer", "locked": False, "value": value, "known": True}
    return {"source": "default", "locked": False, "value": _default_in(setting, layers),
            "known": True}


def _resolve_deferred_tools(layers: dict[str, Any]) -> dict[str, Any]:
    """Show the same explicit/current/legacy choice as the native registry."""
    from maverick.config import env_flag
    from maverick.config_resets import apply_to_base

    # The kernel ignores a value it cannot read, so only a readable one locks.
    environment = env_flag("MAVERICK_DEFERRED_TOOLS")
    if environment is not None:
        return {"source": "deployment", "locked": True, "value": environment, "known": True}
    layers = {**layers, "base": apply_to_base(layers["base"], layers["here"])}
    for path in (("capabilities", "deferred_tools"), ("tools", "deferred_loading")):
        for name in ("tenant", "operator", "here", "base"):
            present, value = catalog.lookup(layers[name], path)
            if not present:
                continue
            legacy = path[0] == "tools"
            source = {"tenant": "deployment", "operator": "deployment",
                      "here": "here", "base": "installer"}[name]
            state = {"source": source, "locked": not legacy and source == "deployment",
                     "value": value if type(value) is bool else True, "known": True}
            if type(value) is not bool:
                state["source_text"] = "The earlier choice is invalid; the short list stays on."
            elif legacy:
                state["source_text"] = "Earlier saved choice · save here to replace it"
            return state
    return {"source": "default", "locked": False, "value": True, "known": True}


def _resolve_feature(setting: catalog.Setting, layers: dict[str, Any]) -> dict[str, Any]:
    """Use the switch's real native layers; installation trust is global only."""
    if any(name in os.environ for name in setting.env):
        return {"source": "deployment", "locked": True, "value": None, "known": False}
    names = ("operator", "here", "base") if setting.key == "signing_identity_transition" else (
        "tenant", "operator", "here", "base")
    for name in names:
        present, value = _layer_value(setting, layers[name])
        if present:
            source = {"tenant": "deployment", "operator": "deployment",
                      "here": "here", "base": "installer"}[name]
            return {"source": source, "locked": name in {"tenant", "operator"},
                    "value": value, "known": type(value) is bool}
    return {"source": "default", "locked": False, "value": setting.default, "known": True}


def _resolve_provider_field(setting: catalog.Setting, layers: dict[str, Any]) -> dict[str, Any] | None:
    """Match provider runtime precedence; a server fallback can be replaced here."""
    if (not setting.section.startswith("providers.")
            or setting.key not in {"api_key", "base_url"}):
        return None
    from maverick import config
    from maverick.config_resets import apply_to_base

    from .settings_store import provider_address_display

    def public_value(value):
        return bool(value) if setting.secret else provider_address_display(value)[0]

    name = setting.section.removeprefix("providers.")
    env_map = (config.PROVIDER_KEY_ENV_MAP if setting.key == "api_key"
               else config.PROVIDER_BASE_URL_ENV_MAP)
    value: object = None
    source = "default"
    base = apply_to_base(layers["base"], layers["here"])
    for layer, label in (("base", "installer"), ("here", "here"),
                         ("operator", "deployment"), ("tenant", "deployment")):
        present, candidate = catalog.lookup(base if layer == "base" else layers.get(layer, {}),
                                            setting.path)
        if present:
            value, source = candidate, label
    if not isinstance(value, str) or not value.strip():
        value, source = None, "default"
        for env_name in env_map.get(name, ()):
            candidate = os.environ.get(env_name, "").strip()
            if candidate:
                value, source = candidate, "deployment"
                break
        if source == "deployment":
            # Unlike most deployment settings, provider environment variables
            # are a fallback: a dashboard value takes precedence at runtime.
            return {"source": source, "locked": False,
                    "source_text": "Set when Lightwork starts · save here to replace it",
                    "value": public_value(value), "known": True}
    if value is None:
        return {"source": "default", "locked": False, "value": _default_of(setting), "known": True}
    return {"source": source, "locked": source == "deployment",
            "value": public_value(value), "known": True}


def _has_partial_default(setting: catalog.Setting) -> bool:
    return setting.partial_default is not catalog._NO_PARTIAL


def _table_written(layers: dict[str, Any], path: tuple[str, ...]) -> bool:
    """True when any configuration layer holds keys in the table at ``path``."""
    for layer in layers.values():
        present, table = catalog.lookup(layer, path)
        if present and table:
            return True
    return False


def _default_in(setting: catalog.Setting, layers: dict[str, Any]) -> object:
    """The default the kernel applies now (some readers keep an older default
    once their table holds other keys)."""
    if _has_partial_default(setting) and _table_written(layers, setting.path[:-1]):
        return setting.partial_default
    return _default_of(setting)


def _pin_partial_defaults(writes: dict, layers: dict[str, Any]) -> None:
    """Writing the first key of a table whose reader changes its defaults once
    the table exists: also write those defaults, so nothing else changes."""
    for top in {path[0] for path, value in writes.items() if value is not None}:
        if _table_written(layers, (top,)):
            continue
        for setting in catalog.SETTINGS:
            if setting.top == top and _has_partial_default(setting):
                writes.setdefault(setting.path, _default_of(setting))


# ------------------------------------------------------------ live choices
_TOOL_CACHE: dict[str, Any] = {"at": 0.0, "names": None}
_TOOL_LOCK = threading.Lock()
_TOOL_TTL = 300.0
_CONNECTOR_LABELS = {"salesforce": "Salesforce", "servicenow": "ServiceNow"}
TOOL_FAMILIES: tuple[tuple[str, str], ...] = (
    ("mcp_*", "Every tool from outside tool servers"),
)


def _tool_names() -> list[str]:
    """Registered tool names (cached briefly: building the list is slow)."""
    with _TOOL_LOCK:
        cached = _TOOL_CACHE["names"]
        if cached is not None and time.monotonic() - _TOOL_CACHE["at"] < _TOOL_TTL:
            return list(cached)
    try:
        from maverick.tools import base_tool_names

        names = sorted(base_tool_names() or ())
    except Exception:  # a missing optional extra must not break the page
        names = []
    with _TOOL_LOCK:
        _TOOL_CACHE.update(at=time.monotonic(), names=tuple(names))
    return names


def _people_choices() -> list[tuple[str, str]]:
    from . import identity_format, rbac

    try:
        users = sorted(rbac.list_users())
    except Exception:
        users = []
    out = [("", "Nobody: changes wait until someone approves them outside Lightwork")]
    for principal in users:
        who = identity_format.humanize_principal(principal)
        out.append((principal, f"{who.name} ({who.detail})" if who.detail else who.name))
    return out


# One listing of the page reuses each live list (several settings share one,
# and some are slow to build: the specialist packs are read from disk).
_CHOICE_MEMO: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "settings_choice_memo", default=None)


def _source_choices(source: str) -> list[tuple[str, str]]:
    memo = _CHOICE_MEMO.get()
    if memo is None:
        return _build_source_choices(source)
    if source not in memo:
        memo[source] = tuple(_build_source_choices(source))
    return list(memo[source])


def _build_source_choices(source: str) -> list[tuple[str, str]]:  # noqa: C901 - one branch per source
    from . import identity_format

    if source == "people":
        return _people_choices()
    if source == "governed_connectors":
        try:
            from maverick.governed_rest import available_rest_connectors

            names = available_rest_connectors()
        except Exception:
            names = []
        return [(n, _CONNECTOR_LABELS.get(n, identity_format.humanize(n))) for n in names]
    if source == "gateway_models":
        from maverick.llm import MODEL_CATALOG, PROVIDER_LABELS

        out: list[tuple[str, str]] = []
        for provider, ids in MODEL_CATALOG.items():
            for model in ids:
                if all(model != v for v, _ in out):
                    out.append((model, f"{model} ({PROVIDER_LABELS.get(provider, provider)})"))
        return out
    if source == "local_models":
        from maverick.llm import PROVIDER_LABELS, catalog_specs
        from maverick.provider_local_first import is_local
        from maverick.providers import _canonical

        from .model_pickers import config_catalog

        out = [("", "None chosen")]
        specs = [spec for spec, _label in catalog_specs()] + config_catalog()
        for spec in dict.fromkeys(specs):
            if is_local(spec):
                provider, _, model = spec.partition(":")
                provider = _canonical(provider)
                label = PROVIDER_LABELS.get(provider) or {"tgi": "Hugging Face (local)", "vllm": "vLLM (local)"}[provider]
                out.append((spec, f"{model} ({label})"))
        return out
    if source == "tools":
        return [*TOOL_FAMILIES,
                *((n, identity_format.humanize(n)) for n in _tool_names())]
    if source == "tools_any":
        return [("*", "Any tool"), *_source_choices("tools")]
    return _more_choices(source)


def _merged_table(name: str) -> dict:
    from maverick import config

    try:
        table = (config.load_config() or {}).get(name) or {}
    except Exception:  # an unreadable configuration offers nothing new
        table = {}
    return table if isinstance(table, dict) else {}


def _more_choices(source: str) -> list[tuple[str, str]]:  # noqa: C901 - one branch per source
    """Live options for the admin-policy settings (people, apps, models...)."""
    from . import identity_format

    if source == "people_only":
        return _people_choices()[1:]
    if source == "chat_channels":
        return [(name, catalog.CHANNEL_ALLOWLISTS.get(name, (identity_format.humanize(name),))[0])
                for name, table in sorted(_merged_table("channels").items())
                if isinstance(table, dict) and name != "routing"]
    if source == "providers":
        from maverick import config

        from . import settings_store

        out: list[tuple[str, str]] = []
        for provider in settings_store.PROVIDERS:
            try:
                configured = config.provider_configuration_state(provider["name"])["configured"]
            except Exception:
                configured = False
            if configured:
                out.append((provider["name"], provider["label"]))
        known = {v for v, _ in out}
        for name, table in sorted(_merged_table("providers").items()):
            if isinstance(table, dict) and name not in known:
                out.append((name, identity_format.humanize(name)))
        return out
    if source == "models":
        from maverick.llm import PROVIDER_LABELS, catalog_specs

        from .model_pickers import config_catalog

        out = []
        for spec in dict.fromkeys([spec for spec, _label in catalog_specs()] + config_catalog()):
            provider, sep, model = spec.partition(":")
            if not sep:
                provider, model = "anthropic", spec
            out.append((spec, f"{model} ({PROVIDER_LABELS.get(provider, identity_format.humanize(provider))})"))
        return out
    if source == "suites":
        from maverick.departments import department_title
        from maverick.suite_grants import known_suites

        return sorted(((s, department_title(s)) for s in known_suites()), key=lambda c: c[1])
    if source == "local_linux_images":
        from maverick.sandbox.local_images import inventory
        images, _notice = inventory()
        return [("", "No practice environment selected"), *((image.id, image.label) for image in images)]
    if source == "roles":
        from . import rbac

        return [(role, identity_format.role_label(role)) for role in rbac.known_roles()]
    if source == "scim_groups":
        from . import scim

        try:
            groups = scim._load_groups()
        except Exception:  # an unreadable group store offers no groups
            groups = {}
        names = sorted({str(g.get("displayName") or "").strip() for g in groups.values()} - {""})
        return [(name, name) for name in names]
    if source == "specialists":
        from .settings_catalog_integrations import specialist_choices

        return specialist_choices()
    if source in {"voice_programs", "voice_model_files"}:
        from .settings_catalog_integrations import voice_choices

        return voice_choices(source)
    if source in _ACCESS_SOURCES:
        return _ACCESS_SOURCES[source]()
    if source == "ekko_apps":
        from maverick.config import _EKKO_DEFAULT_BLOCKED_APPS
        from maverick.work_discovery import KNOWN_APPS

        from .ekko_routes import _app_name

        apps = sorted(set(KNOWN_APPS) - set(_EKKO_DEFAULT_BLOCKED_APPS))
        return sorted(((a, _app_name(a)) for a in apps), key=lambda c: c[1])
    return []


def _theme_choices() -> list[tuple[str, str]]:
    from . import identity_format
    from .themes import BUILTIN_THEMES, custom_themes

    names = {"dark": "Dark", "light": "Light", "solarized": "Solarized",
             "hicontrast": "High contrast"}
    out = [(name, names.get(name, identity_format.humanize(name)))
           for name in sorted(BUILTIN_THEMES)]
    try:
        extra = sorted(custom_themes())
    except Exception:  # an unreadable theme table offers the built-in themes
        extra = []
    return out + [(name, identity_format.humanize(name)) for name in extra]


def _capability_role_choices() -> list[tuple[str, str]]:
    from maverick.capability import configured_roles

    from . import identity_format

    try:
        roles = sorted(configured_roles())
    except Exception:  # an unreadable roles table offers no roles
        roles = []
    # No empty choice: an empty default permission set would make every
    # permission lookup fail. Reset removes the setting instead.
    return [(role, identity_format.humanize(role)) for role in roles]


def _workspace_choices() -> list[tuple[str, str]]:
    from .workspace_display import duplicate_workspace_ids

    try:
        from maverick.tenant.registry import list_tenants

        tenants = list_tenants()
    except Exception:  # no workspace list: nothing to choose
        tenants = []
    out = []
    for tenant in tenants:
        tid = str(getattr(tenant, "id", "") or "")
        if tid:
            out.append((tid, str(getattr(tenant, "display_name", "") or "") or tid))
    duplicates = duplicate_workspace_ids(out)
    return sorted(
        [(tid, f"{label} (Reference: {tid})" if tid in duplicates else label)
         for tid, label in out],
        key=lambda choice: choice[1].lower(),
    )


def _model_role_choices() -> list[tuple[str, str]]:
    from maverick.llm import ROLE_MODELS

    from . import identity_format

    return [(role, identity_format.humanize(role)) for role in sorted(ROLE_MODELS)]


def _structured_sources() -> dict[str, Any]:
    from .settings_structured_sources import SOURCES

    return SOURCES


_ACCESS_SOURCES = {
    "themes": _theme_choices,
    "preference_themes": lambda: [("system", "Follow system"), *_theme_choices()],
    "capability_roles": _capability_role_choices,
    "workspaces": _workspace_choices,
    "model_roles": _model_role_choices,
    **{name: (lambda name=name: _structured_sources()[name]())
       for name in ("chat_users", "tts_voices", "voice_languages", "persona_languages",
                    "gateway_teams", "canary_metrics", "failure_classes",
                    "regulatory_regimes", "regulatory_domains", "jurisdictions")},
}
# Lists too long (or too slow: the voices ask the speech service) to put in
# the page: loaded when the person searches them.
_LAZY_SOURCES = frozenset({"tools", "tools_any", "chat_users", "tts_voices", "local_linux_images"})
_TOOL_SOURCES = frozenset({"tools", "tools_any"})


def _resolved(
    setting: catalog.Setting, current: object = None, *, full: bool = True,
) -> catalog.Setting:
    """``setting`` with live options filled in (keeping whatever is set now).

    ``full=False`` skips the tool list, which is slow to build and which the
    page loads separately; the rows already set still get their labels.
    """
    if setting.columns:
        setting = dataclasses.replace(
            setting, columns=_resolved_columns(setting, current, full=full))
    if not setting.choices_from:
        return setting
    from . import identity_format

    if setting.choices_from in _LAZY_SOURCES and not full:
        choices = list(TOOL_FAMILIES) if setting.choices_from == "tools" else []
        if setting.choices_from == "local_linux_images":
            choices = [("", "No practice environment selected")]
    else:
        if setting.choices_from == "local_linux_images":
            from maverick.sandbox.local_images import LocalImageUnavailable
            try:
                choices = list(_source_choices(setting.choices_from))
            except LocalImageUnavailable:
                # Preserve the exact draft; coerce performs the fresh selected
                # image check and returns a plain refusal before any write.
                choices = [("", "No practice environment selected")]
        else:
            choices = list(_source_choices(setting.choices_from))
    known = {v for v, _ in choices}
    extra = current if isinstance(current, (list, dict)) else [current]
    if setting.control == "rules":
        extra = []
    for value in extra:
        if value not in (None, "") and str(value) not in known:
            if setting.choices_from == "local_linux_images":
                from maverick.sandbox.local_images import (
                    LocalImageUnavailable,
                    cached_label,
                    selected,
                )
                label = cached_label(value)
                if full:
                    try:
                        label = selected(str(value)).label
                    except LocalImageUnavailable:
                        label = "Previously selected practice environment · unavailable"
                choices.append((str(value), label))
            else:
                choices.append((str(value), identity_format.humanize(value)))
            known.add(str(value))
    if setting.control == "table":
        choices = [c for c in choices if c[0] not in setting.fixed_keys]
    return dataclasses.replace(setting, choices=tuple(choices))


def _cell_values(setting: catalog.Setting, current: object, column: catalog.Column) -> list:
    """Every value a column holds now, so a saved value keeps a label."""
    if setting.control == "rules":
        specs = [r for r in current if isinstance(r, dict)] if isinstance(current, list) else []
        cells = [spec.get(column.key) for spec in specs]
    elif isinstance(current, dict):
        cells = [spec if setting.scalar else (spec or {}).get(column.key)
                 for spec in current.values() if setting.scalar or isinstance(spec, dict)]
    else:
        cells = []
    out: list = []
    for cell in cells:
        out.extend(cell if isinstance(cell, list) else [cell])
    return out


def _resolved_columns(
    setting: catalog.Setting, current: object, *, full: bool,
) -> tuple[catalog.Column, ...]:
    from . import identity_format

    columns = []
    for column in setting.columns:
        if not column.choices_from:
            columns.append(column)
            continue
        lazy = column.choices_from in _LAZY_SOURCES and not full
        if lazy:
            choices = [c for c in (("*", "Any tool"), *TOOL_FAMILIES)
                       if column.choices_from == "tools_any" or c[0] != "*"] \
                if column.choices_from in _TOOL_SOURCES else []
        else:
            choices = list(_source_choices(column.choices_from))
        known = {v for v, _ in choices}
        for value in _cell_values(setting, current, column):
            if isinstance(value, str) and value and value not in known:
                choices.append((value, identity_format.humanize(value)))
                known.add(value)
        columns.append(dataclasses.replace(column, choices=tuple(choices)))
    return tuple(columns)


def _note_unreadable_containment(row: dict[str, Any]) -> None:
    """Containment is on while a source that may hold it cannot be read; say
    so instead of showing the default "off" the readable layers give."""
    from maverick import containment

    current = containment.status()
    if current["reason"] == "unreadable_configuration":
        row.update(value=None, locked=True, value_text=current["message"])


def _row(setting: catalog.Setting, layers: dict[str, Any]) -> dict[str, Any]:
    state = _resolve(setting, layers)
    value = state["value"]
    setting = _resolved(setting, value if state["known"] else None, full=False)
    row: dict[str, Any] = {
        "id": setting.id,
        "label": setting.label,
        "help": setting.help,
        "control": setting.control,
        "group": setting.group,
        "choices": [{"value": v, "label": label} for v, label in setting.choices],
        "minimum": setting.minimum,
        "maximum": setting.maximum,
        "step": setting.step or (1 if setting.integer else "any"),
        "unit": setting.unit,
        "restart": setting.restart,
        "warning": setting.warning,
        "warning_lead": catalog.warning_lead(setting) if setting.warning else "",
        "source": state["source"],
        "source_text": state.get("source_text", SOURCE_TEXT[state["source"]]),
        "locked": state["locked"],
        "default_text": catalog.display_value(setting, _default_of(setting)),
        "max_length": setting.max_length,
        "aliases": setting.aliases,
        "optional": setting.default is None,
        "subgroup": setting.subgroup,
        "item_label": setting.item_label,
        "item_hint": setting.item_hint,
        "empty_text": setting.empty_text,
        "add_label": setting.add_label,
        "path_kind": setting.path_kind,
        "test_label": settings_tests.button_label(setting),
    }
    if setting.empty_hint:
        row["empty_hint"] = setting.empty_hint
    if setting.choices_from == "people" and len(setting.choices) <= 1:
        row["empty_hint"] = "Nobody has been added yet. Add people on the People page first."
    if setting.secret:
        row["is_set"] = bool(value) if state["known"] else True
        row["value"] = None
        row["value_text"] = "Set" if row["is_set"] else "Not set"
    elif not state["known"]:
        row["value"] = None
        row["value_text"] = "Controlled by the server"
    else:
        row["value"] = _form_value(setting, value)
        row["value_text"] = catalog.display_value(setting, value)
    if setting.id == "containment.enabled":
        _note_unreadable_containment(row)
    periods = [{"value": s, "label": f"Every {n}"} for s, n in catalog.RATE_PERIODS]
    if setting.control == "rate":
        parsed = catalog.parse_rate(value) if state["known"] else None
        row["rate_count"] = parsed[0] if parsed else ""
        row["rate_seconds"] = parsed[1] if parsed else 60
        row["periods"] = periods
    if setting.control == "keys":
        row["key_items"] = [
            {"value": key, "fingerprint": catalog.key_fingerprint(key)}
            for key in (value if isinstance(value, list) else [])
        ]
    if setting.control == "select" and setting.choices_from in _LAZY_SOURCES:
        row["choices_url"] = f"{API_PATH}/choices/{setting.id}"
    if setting.control == "picks":
        labels = dict(setting.choices)
        row["picks"] = [{"value": str(v), "label": labels.get(str(v), str(v))}
                        for v in (value if isinstance(value, list) and state["known"] else [])]
        lazy = setting.choices_from in _LAZY_SOURCES
        row["choices_url"] = f"{API_PATH}/choices/{setting.id}" if lazy else ""
        if lazy:
            row["choices"] = []  # long list: the page loads it when needed
    if setting.control == "document":
        from . import settings_documents

        row["document"] = settings_documents.summary(setting, value if state["known"] else None)
    if setting.control == "fingerprint":
        row["fingerprint_from_server"] = bool(setting.fingerprint_of)
    if setting.workspace_segment:
        row["segment_at"] = catalog.workspace_address_parts(value)[1] if state["known"] else -1
    if setting.preview:
        row["preview_url"] = f"{API_PATH}/preview/{setting.id}"
        # The approval-threshold preview also covers the default (empty) choice.
        row["preview_any"] = setting.preview == "approval_checks"
    if setting.control == "table":
        if setting.choices_from == "tools":
            row["choices"] = []  # long list: the page loads it when needed
        row["periods"] = periods
        row["risks"] = [{"value": v, "label": label} for v, label in catalog.RISK_LEVELS]
        row["row_kind"] = setting.row_kind
        row["rows"] = _table_rows(setting, value)
    if setting.columns:
        row["grid"] = _grid_state(setting, value if state["known"] else None)
        row["row_kind"] = row.get("row_kind") or "rules"
    return row


def _grid_state(setting: catalog.Setting, value: object) -> dict[str, Any]:
    """What the page needs to draw a grid or a list of rules."""
    columns = []
    for column in setting.columns:
        lazy = column.choices_from in _LAZY_SOURCES
        columns.append({
            "key": column.key, "label": column.label, "kind": column.kind,
            "required": column.required, "default": column.default,
            "minimum": column.minimum, "maximum": column.maximum, "unit": column.unit,
            "step": 1 if column.integer else "any", "max_length": column.max_length,
            "choices": [] if lazy else [{"value": v, "label": label}
                                        for v, label in column.choices],
            "choices_url": (f"{API_PATH}/choices/{setting.id}?column={column.key}"
                            if lazy else ""),
        })
    return {
        "kind": "rules" if setting.control == "rules" else (
            "named" if setting.row_kind == "named" else "grid"),
        "columns": columns,
        "key_choices": [{"value": v, "label": label} for v, label in setting.choices],
        "row_label": setting.row_label,
        "item_label": setting.item_label,
        "rows": _grid_rows(setting, value),
        # Rows named from a long list: the page searches it when needed.
        "key_choices_url": (f"{API_PATH}/choices/{setting.id}"
                            if setting.choices_from in _LAZY_SOURCES else ""),
    }


def _grid_rows(setting: catalog.Setting, value: object) -> list[dict[str, Any]]:
    labels = dict(setting.choices)
    column_labels = {c.key: dict(c.choices) for c in setting.columns}
    if setting.control == "rules":
        entries = [(None, spec) for spec in value if isinstance(spec, dict)] \
            if isinstance(value, list) else []
    else:
        entries = sorted(value.items()) if isinstance(value, dict) else []
    rows = []
    for name, spec in entries:
        cells: dict[str, Any] = {}
        for column in setting.columns:
            if setting.scalar:
                cell = spec
            else:
                cell = spec.get(column.key) if isinstance(spec, dict) else None
            if column.kind == "secret":
                cells[column.key] = {"is_set": bool(cell)}  # never the password
                continue
            if cell is None:
                cell = [] if column.kind == "picks" else column.default
            if column.kind == "picks":
                items = cell if isinstance(cell, list) else [cell]
                cell = [{"value": str(v), "label": column_labels[column.key].get(str(v), str(v))}
                        for v in items if v not in (None, "")]
            elif column.kind == "words":
                cell = ", ".join(str(v) for v in cell) if isinstance(cell, list) else str(cell or "")
            elif column.kind in {"select", "pick"}:
                cell = {"value": str(cell or ""),
                        "label": column_labels[column.key].get(str(cell or ""), str(cell or ""))}
            cells[column.key] = cell
        entry: dict[str, Any] = {"cells": cells}
        if name is not None:
            entry.update(name=name, label=labels.get(name, name))
        rows.append(entry)
    return rows


def _table_rows(setting: catalog.Setting, value: object) -> list[dict[str, Any]]:
    labels = dict(setting.choices)
    rows = []
    for name, spec in sorted((value or {}).items()) if isinstance(value, dict) else []:
        row: dict[str, Any] = {"name": name, "label": labels.get(name, name)}
        if setting.row_kind == "rate":
            parsed = catalog.parse_rate(spec)
            row["count"], row["seconds"] = parsed or ("", 60)
        else:
            row["risk"] = spec.get("risk", "high") if isinstance(spec, dict) else "high"
        rows.append(row)
    return rows


def _form_value(setting: catalog.Setting, value: object) -> object:
    """The value as the page's control shows it."""
    if setting.control == "select":
        return "" if value is None else str(value)
    if setting.control in {"multiselect", "list"}:
        return [str(v) for v in value] if isinstance(value, list) else []
    if setting.control == "number" and setting.scale != 1.0 and catalog._is_number(value):
        shown = round(float(value) / setting.scale, 4)
        return int(shown) if shown == int(shown) else shown
    if setting.control in {"keys", "table", "rules", "picks", "document"}:
        return None  # carried by ``keys`` / ``rows`` / ``grid`` / ``picks`` / ``document``
    if setting.workspace_segment:
        return catalog.workspace_address_parts(value)[0] if value else ""
    return value


def _effective(setting: catalog.Setting, layers: dict[str, Any]) -> object:
    state = _resolve(setting, layers)
    return state["value"] if state["known"] else None


def _working_values(layers: dict[str, Any]) -> dict[str, object]:
    """Every setting's value as the kernel uses it, for checks run on the
    server (a value set in the environment is used as the environment has it).
    Secrets are included; nothing built from this is ever sent to the page."""
    values: dict[str, object] = {}
    for setting in catalog.SETTINGS:
        env = next((os.environ[n].strip() for n in setting.env if os.environ.get(n, "").strip()), None)
        values[setting.id] = env if env is not None else _effective(setting, layers)
    return values


def _search_text(setting: catalog.Setting) -> str:
    """What a search matches (the page filters its loaded rows on the same words)."""
    return " ".join((setting.id, setting.id.replace(".", " "), setting.label, setting.help, setting.aliases, setting.group,
                     setting.subgroup)).lower()


def _words(query: str) -> tuple[str, ...]:
    return tuple(query.strip().lower().split())


def _group_named(slug: str) -> str | None:
    return next((name for name in catalog.GROUPS if _slug(name) == slug), None)


def catalog_state(
    group: str = "", words: tuple[str, ...] = (), *, changed: bool = False,
) -> dict[str, Any]:
    """Every setting's state, by group; or only one group (``group``, its slug),
    the settings matching every search word, or only those changed here."""
    layers = _sources()
    groups = []
    revision = _revision(layers)
    filtered = bool(group or words or changed)
    order = itertools.count()
    token = _CHOICE_MEMO.set({})
    try:
        for name in catalog.GROUPS:
            settings = [(next(order), s) for s in _in_page_order(name)]
            parts = _parts([s for _i, s in settings])
            if group and _slug(name) != group:
                continue
            if words:
                settings = [(i, s) for i, s in settings
                            if all(w in _search_text(s) for w in words)]
            if changed:
                settings = [(i, s) for i, s in settings
                            if _resolve(s, layers)["source"] == "here"]
            if filtered and not settings:
                continue
            rows = []
            for index, setting in settings:
                rows.append(_row(setting, layers))
                rows[-1]["order"] = index
                rows[-1]["revision"] = revision
            groups.append(_group_state(name, rows, parts))
    finally:
        _CHOICE_MEMO.reset(token)
    return {"groups": groups, "revision": revision}


def _parts(settings: list[catalog.Setting]) -> dict[str, int]:
    """A group's parts (subgroups), numbered in page order from 1."""
    names = dict.fromkeys(s.subgroup for s in settings if s.subgroup)
    return {name: index for index, name in enumerate(names, 1)}


def _group_state(
    name: str, rows: list[dict[str, Any]], parts: dict[str, int],
) -> dict[str, Any]:
    subgroups = list(dict.fromkeys(r["subgroup"] for r in rows if r["subgroup"]))
    for r in rows:
        r["subgroup_slug"] = _slug(name + " " + r["subgroup"]) if r["subgroup"] else ""
    return {
        "name": name,
        "slug": _slug(name),
        "intro": catalog.GROUP_INTROS.get(name, ""),
        "settings": rows,
        "subgroups": [{"name": sub, "slug": _slug(name + " " + sub), "order": parts[sub]}
                      for sub in subgroups],
    }


def _outline() -> list[dict[str, Any]]:
    """Every group with its parts and counts, without building its rows."""
    layers = _sources()
    groups = []
    for name in catalog.GROUPS:
        settings = _in_page_order(name)
        groups.append({
            "name": name,
            "slug": _slug(name),
            "intro": catalog.GROUP_INTROS.get(name, ""),
            "subgroups": [{"name": sub, "slug": _slug(name + " " + sub), "order": index}
                          for sub, index in _parts(settings).items()],
            "count": len(settings),
            "changed": sum(1 for s in settings if _resolve(s, layers)["source"] == "here"),
            "settings": [],
            "loaded": False,
        })
    return groups


def _in_page_order(group: str) -> list[catalog.Setting]:
    """A group's settings with each part (subgroup) kept together.

    Rows come from several group modules, so one part's rows can be split by
    another module's; the page shows rows without a part first, then each part
    in the order it first appears, never one heading twice."""
    settings = [s for s in catalog.SETTINGS if s.group == group]
    first: dict[str, int] = {}
    for setting in settings:
        first.setdefault(setting.subgroup, len(first))
    return sorted(settings, key=lambda s: (s.subgroup != "", first[s.subgroup]))


def _slug(name: str) -> str:
    text = "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")
    while "--" in text:
        text = text.replace("--", "-")
    return text


def _module_rows() -> list[dict[str, Any]]:
    """In-app module switches, with their effective on/off state."""
    from . import module_activation

    try:
        loaded = module_activation._load_module_config()
    except Exception:
        loaded = None
    rows = []
    for section, meta in sorted(module_activation._MODULE_SWITCHES.items(), key=lambda kv: kv[1]["label"].lower()):
        enabled = (
            module_activation._module_activation_state(loaded, section)["enabled"] is True
            if isinstance(loaded, dict) else None
        )
        rows.append({
            "section": section,
            "label": meta["label"],
            "enabled": enabled,
            "needs": [module_activation._MODULE_SWITCHES[p]["label"] for p in meta["requires"]],
        })
    return rows


# ---------------------------------------------------------------- assets
# The dashboard serves only registered static files; without these routes
# the page rendered with no script or styles (every Save button was dead).
_STATIC = Path(__file__).parent / "static"


@router.get("/static/lightwork-settings-all.js", include_in_schema=False)
async def settings_all_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-settings-all.js",
                        media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


@router.get("/static/lightwork-settings-all.css", include_in_schema=False)
async def settings_all_styles() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-settings-all.css",
                        media_type="text/css; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


# ---------------------------------------------------------------- page
def _filters(group: str, q: str) -> tuple[str, tuple[str, ...]]:
    return (group if _group_named(group) else ""), _words(q)


@router.get(PAGE_PATH, response_class=HTMLResponse)
def all_settings_page(
    request: Request,
    group: str = Query("", max_length=80),
    q: str = Query("", max_length=100),
    changed: bool = False,
    setting_id: str = Query("", alias="id", max_length=120),
) -> HTMLResponse:
    """The list of groups; a group's settings are loaded when it is opened.

    ``?group=`` (or ``?id=``, a setting's group) and ``?q=`` / ``?changed=1``
    put those settings in the page itself, so every setting can be reached and
    read without the page's script."""
    auth.require_global_permission(request, "admin")
    focus = catalog.BY_ID.get(setting_id)
    if focus is not None:
        group = _slug(focus.group)
    group, words = _filters(group, q)
    groups = _outline()
    if group or words or changed:
        loaded = {g["slug"]: g["settings"]
                  for g in catalog_state(group, words, changed=changed)["groups"]}
        for g in groups:
            g["settings"] = loaded.get(g["slug"], [])
            g["loaded"] = g["slug"] == group and not words and not changed
    from maverick.oidc import login_enabled

    from .saml import _session_secret, saml_enabled
    from .settings_catalog_requests import authority
    from .voice_receiver_api import setup as voice_setup

    return _app().templates.TemplateResponse(request, "settings_all.html", {
        "groups": groups,
        "modules": _module_rows(),
        "setting_count": sum(g["count"] for g in groups),
        "changed_count": sum(g["changed"] for g in groups),
        "group": group,
        "query": " ".join(words),
        "only_changed": changed,
        "focus_id": focus.id if focus is not None else "",
        "served": bool(words or changed),
        "oidc_login_active": login_enabled(),
        "saml_login_active": saml_enabled() and bool(_session_secret()),
        "settings_request_context": authority(request),
        "voice_setup": voice_setup(request),
    })


@router.get(ROWS_PATH, response_class=HTMLResponse)
def all_settings_rows(
    request: Request,
    group: str = Query("", max_length=80),
    q: str = Query("", max_length=100),
    changed: bool = False,
) -> HTMLResponse:
    """The rows of one group, or of the settings matching a search, as the page
    shows them (the page puts them in place)."""
    auth.require_global_permission(request, "admin")
    group, words = _filters(group, q)
    if not (group or words or changed):
        return HTMLResponse("", status_code=400, headers={"Cache-Control": "no-store"})
    state = catalog_state(group, words, changed=changed)
    response = _app().templates.TemplateResponse(request, "settings_all_rows.html", {
        "groups": state["groups"],
        "complete": group if not (words or changed) else "",
    })
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------- API
class SettingChange(BaseModel):
    id: str = Field(min_length=3, max_length=120)
    value: Any = None
    reset: bool = False
    inherit: bool = False


class CatalogUpdate(BaseModel):
    expected_revision: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    changes: list[SettingChange] = Field(min_length=1, max_length=len(catalog.SETTINGS))
    confirm: bool = False
    reviewed_token: str | None = Field(default=None, max_length=1048576)


@router.get(API_PATH + "/choices/{setting_id}")
async def catalog_choices(
    request: Request, setting_id: str, column: str = "", refresh: bool = False,
) -> JSONResponse:
    """The options of one setting (or one column of its rows) whose list is
    too long to put in the page."""
    auth.require_global_permission(request, "admin")
    setting = catalog.BY_ID.get(setting_id)
    wanted = next((c for c in setting.columns if c.key == column), None) \
        if setting is not None and column else None
    if setting is None or (column and (wanted is None or not wanted.choices_from)) \
            or (not column and not setting.choices_from):
        return JSONResponse({"detail": "That setting has no list of options.",
                             "message": "That setting has no list of options."},
                            status_code=404)
    notice = ""
    if setting.choices_from == "local_linux_images":
        from maverick.sandbox.local_images import LocalImageUnavailable, inventory
        try:
            images, notice = await run_in_threadpool(inventory, refresh=refresh)
        except LocalImageUnavailable as exc:
            raise HTTPException(503, str(exc)) from exc
        choices = (("", "No practice environment selected"), *((image.id, image.label) for image in images))
        return JSONResponse({"choices": [{"value": v, "label": label} for v, label in choices], "notice": notice}, headers={"Cache-Control": "no-store"})
    resolved = await run_in_threadpool(_resolved, setting)
    choices = (next(c for c in resolved.columns if c.key == column).choices
               if column else resolved.choices)
    return JSONResponse(
        {"choices": [{"value": v, "label": label} for v, label in choices]},
        headers={"Cache-Control": "no-store"},
    )


@router.get(API_PATH)
async def catalog_list(
    request: Request,
    group: str = Query("", max_length=80),
    q: str = Query("", max_length=100),
    changed: bool = False,
) -> JSONResponse:
    """The settings' state: all of it, one group (``?group=``, the group's
    slug), those matching every word of ``?q=``, or those changed here."""
    auth.require_global_permission(request, "admin")
    if group and not _group_named(group):
        message = "There is no group of settings with that name."
        return JSONResponse({"detail": message, "message": message}, status_code=404,
                            headers={"Cache-Control": "no-store"})
    state = await run_in_threadpool(catalog_state, group, _words(q), changed=changed)
    from .draft_api import context_for

    auth.require_global_permission(request, "admin")
    state["context"] = context_for(request)
    return _conditional_json(request, state)


def _conditional_json(request: Request, state: dict[str, Any]) -> Response:
    """The state as JSON with a content ETag; ``304 Not Modified`` when the
    client's ``If-None-Match`` still matches.

    The whole catalog is ~1.5 MB. ``private, no-cache`` lets the browser
    keep its copy but revalidate every time, so a repeat load of the page
    moves no bytes when nothing changed. The server still computes the state
    (its inputs include per-setting choice providers, so a cheaper
    fingerprint would risk serving stale rows).
    """
    body = json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'
    headers = {"Cache-Control": "private, no-cache", "ETag": etag, "Vary": "Cookie, Authorization"}
    if _etag_matches(request.headers.get("if-none-match", ""), etag):
        return Response(status_code=304, headers=headers)
    return Response(body, media_type="application/json", headers=headers)


def _etag_matches(header: str, etag: str) -> bool:
    if not header:
        return False
    if header.strip() == "*":
        return True
    tags = {t.strip().removeprefix("W/") for t in header.split(",")}
    return etag in tags


def _audit_value(setting: catalog.Setting, value: object) -> object:
    if setting.secret:
        return "set" if value else "not set"
    if setting.control == "number" and not catalog.valid_number(setting, value):
        encoded = json.dumps([type(value).__name__, value], sort_keys=True, default=repr).encode("utf-8")
        return {"state": "invalid previous number", "fingerprint": hashlib.sha256(encoded).hexdigest()}
    if setting.control == "keys" and isinstance(value, list):
        return [catalog.key_fingerprint(k) for k in value]
    if setting.control == "document":
        from . import settings_documents

        return settings_documents.summary(setting, value)
    secret = _secret_columns(setting)
    if secret and isinstance(value, list):
        return [{k: ("set" if v else "not set") if k in secret else v for k, v in row.items()}
                if isinstance(row, dict) else row for row in value]
    if secret and isinstance(value, dict):
        # Named rows with a password: only whether each row has one.
        return {name: ("set" if spec else "not set") if setting.scalar else
                {k: ("set" if v else "not set") if k in secret else v
                 for k, v in (spec.items() if isinstance(spec, dict) else ())}
                for name, spec in value.items()}
    return value


def _secret_columns(setting: catalog.Setting) -> list[str]:
    return [c.key for c in setting.columns if c.kind == "secret"]


def _keep_row_secrets(setting: catalog.Setting, old: object, new: object) -> object:
    """A password left empty in a row keeps that row's saved password (rows
    are matched by their unique column); a new row must have one."""
    keys = _secret_columns(setting)
    if not keys or not isinstance(new, list):
        return new
    unique = next((c.key for c in setting.columns if c.unique), None)
    saved = {row.get(unique): row for row in (old if isinstance(old, list) else [])
             if isinstance(row, dict) and unique}
    out = []
    for row in new:
        row = dict(row)
        for key in keys:
            if row.get(key):
                continue
            previous = saved.get(row.get(unique)) if unique else None
            kept = previous.get(key) if isinstance(previous, dict) else None
            column = next(c for c in setting.columns if c.key == key)
            if not kept and column.required:
                raise _Refused(400, f"{setting.label}: enter the {column.label.lower()} for "
                                    f"each new {setting.item_label.lower()}.")
            row[key] = kept or ""
        out.append(row)
    return out


def _sealed_rows(setting: catalog.Setting, rows: object) -> object:
    """Rows as they are written: every password sealed with the deployment key."""
    keys = _secret_columns(setting)
    if not keys or not isinstance(rows, list):
        return rows
    from . import settings_store

    return [{k: settings_store._seal_global_secret(v) if k in keys and v else v
             for k, v in row.items()} for row in rows]


def _require_valid_number(setting: catalog.Setting, value: object) -> None:
    if setting.control == "number" and not catalog.valid_number(setting, value):
        raise _Refused(400, f"{setting.label}: choose a valid number or its product default before continuing.")


def _plan(body: CatalogUpdate) -> tuple[dict, list[dict], list[dict], dict]:  # noqa: C901
    """Validate a request against the catalog; nothing is written here."""
    layers = _sources()
    writes: dict[tuple[str, ...], object] = {}
    changes: list[dict] = []
    weakening: list[dict] = []
    seen: set[str] = set()
    prospective = {s.id: _effective(s, layers) for s in catalog.SETTINGS}
    for item in body.changes:
        setting = catalog.BY_ID.get(item.id)
        if setting is None:
            raise _Refused(400, "That setting is not available here.")
        if item.id in seen:
            raise _Refused(400, "Each setting can be changed once per save.")
        seen.add(item.id)
        state = _resolve(setting, layers)
        if state["locked"]:
            raise _Refused(
                409,
                f"{setting.label} is set by your server's deployment settings, "
                "so it can't be changed here.",
            )
        old = state["value"]
        from maverick.config_resets import METADATA, is_reset, reset_spec
        marker = (METADATA, setting.id)
        was_reset = is_reset(layers["here"], setting)
        if item.reset and item.inherit:
            raise _Refused(400, "Choose either product default or inherited value.")
        if item.inherit and setting.control != "table":
            if not catalog.lookup(layers["here"], setting.path)[0] and not was_reset:
                continue
            if was_reset:
                writes[marker] = None
            inherited = {**layers, "here": {}}
            new = _resolve(setting, inherited)["value"]
            if setting.id == "plugins.workbench_image":
                try:
                    new = catalog.coerce(_resolved(setting, new), new)
                except catalog.SettingError as exc:
                    raise _Refused(400, str(exc)) from exc
            _require_valid_number(setting, new)
            writes[setting.path] = None
            prospective[setting.id] = new
            changes.append({"setting": setting, "old": old, "new": new})
            if catalog.weakens(setting, old, new):
                weakening.append({"id": setting.id, "label": setting.label,
                                  "warning": setting.warning})
            continue
        if setting.control == "table":
            new, table_writes = _plan_table(setting, item, old, layers)
            if old == new and not ((item.reset or item.inherit) and table_writes):
                continue
            writes.update(table_writes)
            prospective[setting.id] = new
            changes.append({"setting": setting, "old": old, "new": new})
            if catalog.weakens(setting, old, new):
                weakening.append({"id": setting.id, "label": setting.label,
                                  "warning": setting.warning})
            continue
        if item.reset:
            default = _default_of(setting)
            base_present, base_value = catalog.lookup(layers["base"], setting.path)
            if (setting.section.startswith("providers.") and setting.key in {"api_key", "base_url"}
                    and base_present and base_value != default):
                # Empty provider fields are omitted by the overlay writer. A
                # reset marker is required to mask a nonempty installer value.
                writes[marker] = reset_spec(setting)
                writes[setting.path] = None
                new = default
            elif (setting.section.startswith("channels.")
                    and (access := catalog.CHANNEL_ALLOWLISTS.get(setting.section.removeprefix("channels.")))
                    and setting.key == access[2]):
                # Product-default access is nobody, including where a server
                # environment would otherwise supply a fallback list.
                writes[setting.path] = []
                new = []
            elif default is None and base_present:
                writes[marker] = reset_spec(setting)
                writes[setting.path] = None
                new = None
            elif _has_partial_default(setting):
                # Removing the value could let an older default apply: write
                # the default itself.
                writes[setting.path] = default
                new = default
            elif (base_present and default is not None and base_value != default):
                # The installer chose something else: write the default so the
                # setting really returns to it.
                writes[setting.path] = default
                new = default
            else:
                writes[setting.path] = None  # drop the value set here
                new = base_value if base_present else default
        else:
            if was_reset:
                writes[marker] = None
            try:
                new = catalog.coerce(_resolved(setting, old), item.value)
                if setting.control == "document":
                    from . import settings_documents

                    settings_documents.check_replacement(setting, old, new)
            except catalog.SettingError as exc:
                raise _Refused(400, str(exc)) from exc
            new = _keep_row_secrets(setting, old, new)
            if new is None:
                base_present, base_value = catalog.lookup(layers["base"], setting.path)
                writes[setting.path] = None
                new = base_value if base_present else _default_of(setting)
            else:
                writes[setting.path] = _sealed_rows(setting, new)
        if (item.reset and setting.section.startswith("providers.")
                and setting.key in {"api_key", "base_url"}):
            # A cleared provider value can reveal a server fallback. Compare
            # and review the value that will actually take effect after save.
            planned_here = copy.deepcopy(layers["here"])
            if marker in writes:
                metadata = planned_here.setdefault(METADATA, {})
                if writes[marker] is None:
                    metadata.pop(setting.id, None)
                else:
                    metadata[setting.id] = writes[marker]
            node = planned_here
            for part in setting.path[:-1]:
                node = node.setdefault(part, {})
            if writes.get(setting.path) is None:
                node.pop(setting.path[-1], None)
            else:
                node[setting.path[-1]] = writes[setting.path]
            new = _resolve(setting, {**layers, "here": planned_here})["value"]
        if item.reset and setting.id == "plugins.workbench_image":
            try:
                new = catalog.coerce(_resolved(setting, new), new)
            except catalog.SettingError as exc:
                raise _Refused(400, str(exc)) from exc
        _require_valid_number(setting, new)
        unchanged = old == new and (not item.reset or state["source"] != "here")
        if unchanged and marker not in writes and (item.reset or not setting.secret):
            writes.pop(setting.path, None)
            continue
        prospective[setting.id] = new
        changes.append({"setting": setting, "old": old, "new": new})
        if catalog.weakens(setting, old, new):
            weakening.append({"id": setting.id, "label": setting.label,
                              "warning": setting.warning})
    try:
        catalog.cross_checks(prospective)
    except catalog.SettingError as exc:
        raise _Refused(400, str(exc)) from exc
    if writes:
        _pin_partial_defaults(writes, layers)
    return writes, changes, weakening, layers


# A tool newly offered through the tool gateway: the gateway needs a
# description and an input shape; the conservative "any object" shape is the
# same one the installer writes, to be narrowed by the tool's reviewer.
_NEW_GATEWAY_TOOL = {
    "description": "Reviewed tool offered through the gateway",
    "input_schema": {"type": "object", "properties": {}},
}


def _plan_table(
    setting: catalog.Setting, item: SettingChange, old: object, layers: dict[str, Any],
) -> tuple[dict, dict[tuple[str, ...], object]]:
    """Rows to write for a table setting, and the table the kernel will see."""
    before = old if isinstance(old, dict) else {}
    _present, base_rows = _layer_value(setting, layers["base"])
    base_rows = dict(base_rows) if isinstance(base_rows, dict) else {}
    _present, here_rows = _layer_value(setting, layers["here"])
    here_rows = dict(here_rows) if isinstance(here_rows, dict) else {}
    from maverick.config_resets import METADATA, is_reset, reset_spec
    marker = (METADATA, setting.id)
    was_reset = is_reset(layers["here"], setting)
    metadata_writes = {}
    if item.inherit:
        if was_reset:
            metadata_writes[marker] = None
        wanted = dict(base_rows)
    elif item.reset:
        wanted = dict(_default_of(setting))
        metadata_writes[marker] = reset_spec(setting)
        base_rows = {}
    else:
        if was_reset:
            base_rows = {}
        try:
            wanted = catalog.coerce(_resolved(setting, before), item.value)
        except catalog.SettingError as exc:
            raise _Refused(400, str(exc)) from exc
        kept = [name for name in base_rows if name not in wanted]
        if kept:
            label = dict(_resolved(setting, before).choices).get(kept[0], kept[0])
            raise _Refused(
                400,
                f"{setting.label}: “{label}” was set by your installer, so it can be "
                "changed here but not removed.",
            )
        if setting.row_kind == "risk":
            wanted = {
                name: {**(before.get(name) if isinstance(before.get(name), dict)
                          else _NEW_GATEWAY_TOOL), **spec}
                for name, spec in wanted.items()
            }
        wanted = _keep_named_secrets(setting, before, wanted)
        if setting.id == "dashboard.themes":
            from .themes import contrast_issues

            for name, palette in wanted.items():
                issues = contrast_issues(palette)
                if issues:
                    raise _Refused(400, f"Theme {name}: " + " ".join(issues))
    writes: dict[tuple[str, ...], object] = dict(metadata_writes)
    if setting.key_kind == "entries":
        for name in here_rows:
            if name not in wanted or wanted[name] == base_rows.get(name):
                writes[(*setting.path, name)] = None
        for name, spec in wanted.items():
            if base_rows.get(name) != spec and here_rows.get(name) != spec:
                writes[(*setting.path, name)] = spec
    else:
        overlay = {name: spec for name, spec in wanted.items() if base_rows.get(name) != spec}
        if overlay != here_rows:
            writes[setting.path] = _sealed_named(setting, overlay) or None
    return {**base_rows, **wanted}, writes


def _keep_named_secrets(setting: catalog.Setting, before: dict, wanted: dict) -> dict:
    """A password left empty in a named row keeps that row's saved one; a new
    row must have one."""
    keys = _secret_columns(setting)
    if not keys:
        return wanted
    out = {}
    for name, spec in wanted.items():
        saved = before.get(name)
        if setting.scalar:
            if not spec and not saved:
                raise _Refused(400, f"{setting.label}: enter the {setting.columns[0].label.lower()} "
                                    f"for each new {setting.item_label.lower()}.")
            out[name] = spec or saved
            continue
        spec = dict(spec)
        for key in keys:
            kept = saved.get(key) if isinstance(saved, dict) else None
            if not spec.get(key):
                if not kept:
                    column = next(c for c in setting.columns if c.key == key)
                    raise _Refused(400, f"{setting.label}: enter the {column.label.lower()} "
                                        f"for each new {setting.item_label.lower()}.")
                spec[key] = kept
        out[name] = spec
    return out


def _sealed_named(setting: catalog.Setting, rows: dict) -> dict:
    """Named rows as they are written: every password sealed."""
    keys = _secret_columns(setting)
    if not keys:
        return rows
    from . import settings_store

    seal = settings_store._seal_global_secret
    if setting.scalar:
        return {name: seal(spec) for name, spec in rows.items()}
    return {name: {k: seal(v) if k in keys and v else v for k, v in spec.items()}
            for name, spec in rows.items()}


def _record(changes: list[dict], actor: str, confirmed: bool,
            asked: frozenset[str] = frozenset(), before_revision: str = "", after_revision: str = "") -> None:
    from maverick.audit import EventKind, audit_event

    for change in changes:
        setting: catalog.Setting = change["setting"]
        audit_event(
            EventKind.SETTING_CHANGED,
            agent="dashboard",
            _global=True,
            actor=actor,
            section=setting.section,
            key=setting.key,
            before_revision=before_revision, after_revision=after_revision,
            old=_audit_value(setting, change["old"]),
            new=_audit_value(setting, change["new"]),
            confirmed=bool(confirmed and (setting.id in asked or catalog.weakens(
                setting, change["old"], change["new"]))),
        )


def _guard(request: Request, writes: dict, changes: list[dict],
           layers: dict[str, Any]) -> list[dict]:
    """Sign-in, administrator and key changes that could lock people or data
    out: refused (settings_access_guard.Refused) or returned for confirmation."""
    prospective = _working_values(layers)
    for change in changes:
        prospective[change["setting"].id] = change["new"]
    return settings_access_guard.review(request, changes, layers, writes, prospective)


def _saved_state(before: dict[str, Any] | None, asked: set[str]) -> dict[str, Any]:
    """The state after a save: only the rows the request named or whose state
    the save changed (a governance level also sets other settings, a new
    service adds choices elsewhere); ``before`` None gives every row."""
    after = catalog_state()
    if before is None:
        return after
    old = {r["id"]: r for g in before["groups"] for r in g["settings"]}
    groups = []
    for group in after["groups"]:
        rows = [r for r in group["settings"] if r["id"] in asked or
                {k: v for k, v in old.get(r["id"], {}).items() if k != "revision"} !=
                {k: v for k, v in r.items() if k != "revision"}]
        if rows:
            parts = {r["subgroup"] for r in rows}
            groups.append({**group, "settings": rows,
                           "subgroups": [s for s in group["subgroups"] if s["name"] in parts]})
    return {"groups": groups, "revision": after["revision"]}


@router.post(API_PATH)
async def catalog_update(request: Request, body: CatalogUpdate, full: bool = False) -> JSONResponse:
    """Validate, commit and record one reviewed revision under the writer lock."""
    def save() -> JSONResponse:
        from . import settings_store

        if body.reviewed_token:
            if not body.confirm:
                raise HTTPException(422, "Confirm the complete reviewed changes before saving.")
            from .settings_catalog_requests import apply
            value, status = apply(request, body.reviewed_token, full=full)
            _resume_contact_centre(value)  # apply has released the writer lock
            return JSONResponse(value, status_code=status, headers={"Cache-Control": "private, no-store"})
        with settings_store._locked(strict=True):
            response = _catalog_update_locked(request, body, full)
        _resume_contact_centre(json.loads(response.body))  # the writer lock is released
        return response

    return await run_in_threadpool(save)


def _resume_contact_centre(saved) -> None:
    """Handoffs waiting for contact-centre settings are sent now, not at the next restart.

    This runs after the settings writer lock is released, so the outbox files of every
    workspace are not read while other settings writers wait. The settings are
    deployment-wide, so every active workspace's waiting handoffs are checked.
    The save is already recorded, so a failure here is logged and the handoffs keep
    their state for the next save or restart.
    """
    if not any(str(item).startswith("contact_centre.") for item in (saved or {}).get("changed") or []):
        return
    try:
        from maverick.contact_centre import resume_all_workspaces

        resume_all_workspaces(restarted=False)
    except Exception as exc:  # noqa: BLE001 -- the saved settings stand; only the resume is lost
        logging.getLogger(__name__).warning("contact centre handoffs not resumed after a settings save (%s)", type(exc).__name__)


def _catalog_update_locked(request: Request, body: CatalogUpdate, full: bool=False, *, effect_guard=None) -> JSONResponse:
    """Save or reset settings. The reply carries the rows the save touched
    (``?full=1``: every row, as ``GET`` lists them)."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, 'admin')
    if effect_guard is not None:
        effect_guard()
    from maverick.audit import AuditRefused

    from . import settings_governance_level, settings_store
    current = _revision()
    if body.expected_revision != current:
        state = catalog_state()
        asked = {item.id for item in body.changes}
        conflicts = [{"id": row["id"], "label": row["label"],
                      "current": row["value_text"], "source": row["source_text"]}
                     for group in state["groups"] for row in group["settings"]
                     if row["id"] in asked]
        return JSONResponse({"message": "Settings changed since you reviewed them. Your draft is kept.",
                             "conflicts": conflicts, "revision": current}, status_code=409,
                            headers={"Cache-Control": "no-store"})
    try:
        body, learning = settings_governance_level.expand(body, SettingChange)
        writes, changes, weakening, _layers = _plan(body)
    except settings_governance_level.Unavailable as exc:
        return JSONResponse({'detail': str(exc), 'message': str(exc)}, status_code=409, headers={'Cache-Control': 'no-store'})
    except _Refused as exc:
        return JSONResponse({'detail': exc.message, 'message': exc.message}, status_code=exc.status, headers={'Cache-Control': 'no-store'})
    if any(c["setting"].section == "features"
           or c["setting"].id in settings_access_guard.SIGN_IN_IDS
           or c["setting"].id.startswith(settings_access_guard.SIGN_IN_PREFIXES)
           or c["setting"].id.startswith(settings_access_guard.KEY_PREFIXES)
           for c in changes):
        step_up.require_recent_mfa(request, "change_auth_settings")
    try:
        access = _guard(request, writes, changes, _layers) if changes else []
    except settings_access_guard.Refused as exc:
        return JSONResponse({'detail': exc.message, 'message': exc.message, 'lockout': True}, status_code=409, headers={'Cache-Control': 'no-store'})
    weakening = weakening + access + settings_governance_level.confirm_items(learning)
    if weakening and (not body.confirm):
        return JSONResponse({'detail': 'confirmation required', 'confirm': weakening}, status_code=409, headers={'Cache-Control': 'no-store'})
    asked = {item.id for item in body.changes}
    before = None if full else catalog_state()
    if not writes:
        if effect_guard is not None:
            effect_guard()
        if learning:
            settings_governance_level.turn_on(learning, auth.caller_principal(request) or 'local administrator')
        state = _saved_state(before, asked)
        return JSONResponse({'changed': [], 'restart': False, **state}, headers={'Cache-Control': 'no-store'})
    actor = auth.caller_principal(request) or 'local administrator'
    from . import settings_quorum
    if effect_guard is not None:
        effect_guard()
    hold, approved = settings_quorum.review(changes, actor, _audit_value)
    if hold is not None:
        state = _saved_state(before, asked)
        return JSONResponse({'changed': [], 'restart': False, 'quorum': hold, 'message': hold['message'], **state}, status_code=202, headers={'Cache-Control': 'no-store'})
    payload = {path: settings_store.REMOVE if value is None else value for path, value in writes.items()}
    try:
        previous = settings_store.set_catalog_values(payload, before_effect=effect_guard)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='That setting is not available here.') from exc
    except (OSError, TypeError, settings_store.SecuritySuiteConfigUnavailable) as exc:
        raise HTTPException(status_code=503, detail='Settings could not be saved right now. Nothing was changed.') from exc
    try:
        _record(changes, actor, body.confirm, frozenset(item['id'] for item in access), current, _revision())
    except AuditRefused as exc:
        try:
            settings_store.set_catalog_values(previous)
        except Exception as rollback_exc:
            raise HTTPException(status_code=500, detail='The change could not be recorded and could not be undone.') from rollback_exc
        raise HTTPException(status_code=503, detail='The change could not be recorded, so it was undone.') from exc
    settings_quorum.settle(approved)
    if learning:
        try:
            settings_governance_level.turn_on(learning, actor)
        except (RuntimeError, OSError) as exc:
            raise HTTPException(status_code=503, detail='The settings were saved, but the learning systems for this level could not be turned on. Turn them on from the Learning page.') from exc
    if any(path[0] in {"dreaming", "data_engine", "self_harness", "flows", "automation_events"}
           for path in writes):
        from .automation_queue import refresh_runtime

        refresh_runtime(request)
    state = _saved_state(before, asked)
    return JSONResponse({'changed': [c['setting'].id for c in changes], 'restart': any(c['setting'].restart for c in changes), **state}, headers={'Cache-Control': 'no-store'})

# ---------------------------------------------------------------- checks
class SettingCheck(BaseModel):
    id: str = Field(min_length=3, max_length=120)
    value: Any = None


# A few checks a minute: each can reach out over the network, so the button
# must not become a way to probe the server's surroundings.
_CHECK_LIMIT = 20
_CHECK_WINDOW = 60.0
_CHECK_TIMES: list[float] = []
_CHECK_LOCK = threading.Lock()


def _check_allowed() -> bool:
    now = time.monotonic()
    with _CHECK_LOCK:
        _CHECK_TIMES[:] = [t for t in _CHECK_TIMES if now - t < _CHECK_WINDOW]
        if len(_CHECK_TIMES) >= _CHECK_LIMIT:
            return False
        _CHECK_TIMES.append(now)
        return True


def _run_check(setting: catalog.Setting, value: object) -> settings_tests.Outcome:
    layers = _sources()
    values = _working_values(layers)
    if value is None or value == "":
        value = values.get(setting.id)
    elif setting.control != "path":
        try:
            value = catalog.coerce(_resolved(setting, values.get(setting.id)), value)
        except catalog.SettingError as exc:
            return settings_tests.Outcome(False, str(exc))
        values[setting.id] = value
    else:
        values[setting.id] = value
    return settings_tests.run(setting, value, values)


@router.post(API_PATH + "/test")
async def catalog_test(request: Request, body: SettingCheck) -> JSONResponse:
    """Try an entered (or the saved) value: one plain pass or fail sentence.

    Never echoes the value or any secret, reaches the network only through the
    SSRF guard with a short time limit, and is limited to a few checks a
    minute."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    setting = catalog.BY_ID.get(body.id)
    headers = {"Cache-Control": "no-store"}
    if setting is None or not settings_tests.button_label(setting):
        message = "This setting has nothing to test."
        return JSONResponse({"detail": message, "message": message}, status_code=404,
                            headers=headers)
    if not _check_allowed():
        message = "Too many checks in a short time. Wait a minute and try again."
        return JSONResponse({"detail": message, "message": message}, status_code=429,
                            headers=headers)
    outcome = await run_in_threadpool(_run_check, setting, body.value)
    return JSONResponse({"ok": outcome.ok, "message": outcome.message}, headers=headers)


# ------------------------------------------------------------ fingerprints
@router.post(API_PATH + "/fingerprint")
async def catalog_fingerprint(
    request: Request, setting_id: str, server: bool = False,
) -> JSONResponse:
    """Work out a fingerprint for a ``fingerprint`` row, from the uploaded file
    (the request body, read as it arrives and never kept) or, where the row
    allows it, from the files installed on this server. Nothing is saved: the
    page puts the fingerprint in the row and the person saves it."""
    _app()._require_same_origin(request)
    auth.require_global_permission(request, "admin")
    from . import settings_fingerprints

    headers = {"Cache-Control": "no-store"}
    setting = catalog.BY_ID.get(setting_id)
    if setting is None or setting.control != "fingerprint":
        message = "This setting has no fingerprint to work out."
        return JSONResponse({"detail": message, "message": message}, status_code=404,
                            headers=headers)
    if not _check_allowed():
        message = "Too many checks in a short time. Wait a minute and try again."
        return JSONResponse({"detail": message, "message": message}, status_code=429,
                            headers=headers)
    try:
        if server:
            value = await run_in_threadpool(settings_fingerprints.of_server,
                                            setting.fingerprint_of)
        else:
            value = await settings_fingerprints.of_upload(request.stream())
    except settings_fingerprints.Refused as exc:
        return JSONResponse({"detail": str(exc), "message": str(exc)}, status_code=400,
                            headers=headers)
    return JSONResponse({"fingerprint": value, "shown": settings_fingerprints.shown(value)},
                        headers=headers)


# ---------------------------------------------------------------- previews
@router.get(API_PATH + "/preview/{setting_id}")
async def catalog_preview(request: Request, setting_id: str, value: str = "") -> JSONResponse:
    """What saving ``value`` would also change (nothing is saved)."""
    auth.require_global_permission(request, "admin")
    from . import settings_governance_level

    headers = {"Cache-Control": "no-store"}
    setting = catalog.BY_ID.get(setting_id)
    if setting is not None and setting.preview == "retention":
        # A shorter keep period: what the next clean-up would delete (a dry run).
        from maverick import policy_preview
        try:
            shown = await run_in_threadpool(policy_preview.retention, setting.key, value)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc), "message": str(exc)}, status_code=422,
                                headers=headers)
        return JSONResponse(shown, headers=headers)
    if setting is not None and setting.preview == "approval_checks":
        # The approval threshold: what the recorded checks would have needed (report only).
        from . import approval_threshold_preview
        try:
            shown = await run_in_threadpool(approval_threshold_preview.preview, value)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc), "message": str(exc)}, status_code=422,
                                headers=headers)
        return JSONResponse(shown, headers=headers)
    if setting is None or setting.preview != "governance_level":
        message = "This setting has nothing to preview."
        return JSONResponse({"detail": message, "message": message}, status_code=404,
                            headers=headers)
    try:
        shown = await run_in_threadpool(settings_governance_level.preview, value)
    except settings_governance_level.Unavailable as exc:
        return JSONResponse({"detail": str(exc), "message": str(exc)}, status_code=409,
                            headers=headers)
    return JSONResponse(shown, headers=headers)


__all__ = ["router", "catalog_state", "PAGE_PATH", "ROWS_PATH", "API_PATH"]
