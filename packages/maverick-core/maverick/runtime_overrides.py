"""Dashboard-owned runtime overrides.

The dashboard's permissions page lets a user disable a tool with one
click. Writing that into ``config.toml`` would clobber the user's
hand-tuned, comment-annotated, wizard-generated file. Instead the
dashboard owns a separate ``~/.maverick/runtime-overrides.toml`` that
the kernel unions into the deny-list at registry-build time.

Only a small, well-defined surface lives here today:

    [security]
    denied_tools = ["computer", "browser"]

``tool_acl.resolve_lists`` reads ``denied_tools`` and unions it with
the config + channel + user deny-lists, so a disable takes effect on
the next goal with no restart. config.toml is never touched.
"""
from __future__ import annotations

import copy
import functools
import logging
import math
import re
import threading
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date, datetime, timezone
from pathlib import Path

from .paths import data_dir, diagnostic_data_dir, reset_tenant, set_tenant

log = logging.getLogger(__name__)

# ``OVERRIDES_PATH`` stays a Path for callers and tests that inspect or
# monkeypatch it, but the built-in location is resolved at *call time* by
# :func:`overrides_path`: a home, tenant floor or client binding established
# after this module was imported must not be ignored. Identity (not equality)
# tells an intentional override from this untouched compatibility value, which
# is computed without any storage admission so importing can never fail.
_INITIAL_OVERRIDES_PATH = diagnostic_data_dir("runtime-overrides.toml")
OVERRIDES_PATH = _INITIAL_OVERRIDES_PATH
_VALID_TOOL_NAME = re.compile(r"^[a-z0-9_-]+$")

# One overlay file holds every surface (denied_tools, models, budget, plugins,
# allowed_models, mcp, style); each mutator re-reads the whole overlay and
# rewrites it. Two dashboard requests racing would otherwise lose one change --
# e.g. a set_budget that read a stale denied_tools drops a just-applied
# disable_tool, silently re-enabling a tool the operator just denied. Serialize
# every mutator's read-modify-write in-process (RLock) and cross-process (flock).
_OVERRIDE_LOCK = threading.RLock()
_mutation_context = threading.local()
_setting_audit: ContextVar[object | None] = ContextVar(
    "runtime_override_setting_audit", default=None,
)


@contextmanager
def setting_audit_callback(callback):
    """Bind a dashboard audit hook to a serialized runtime-overlay write."""
    token = _setting_audit.set(callback)
    try:
        yield
    finally:
        _setting_audit.reset(token)


_LKG_LIMIT = 8
_LOAD_FAILURE_LIMIT = 32
_MAX_OVERRIDE_BYTES = 1024 * 1024
_KNOWN_TOP_LEVEL = frozenset(
    {"security", "models", "model_rates", "budget", "plugins", "access", "styles", "mcp_servers"}
)
_MCP_SPEC_KEYS = frozenset(
    {
        "command",
        "args",
        "env",
        "inherit_env",
        "pin_sha256",
        "url",
        "headers",
        "auth_token",
        "oauth",
        "enabled",
    }
)
_last_known_good: OrderedDict[str, dict] = OrderedDict()
_announced_load_failures: OrderedDict[tuple[str, str], None] = OrderedDict()


class RuntimeOverridesSecurityError(RuntimeError):
    """The operator policy exists but cannot be read or validated safely."""


def overrides_path() -> Path:
    """The overlay file to read and write right now.

    This is the DEPLOYMENT-wide policy: denied tools, the model allow-list and
    pins, the spend cap and dashboard-added MCP servers are shared control-plane
    state that every workspace runs under, and only a global administrator may
    change them. A workspace selected for the current request or run therefore
    does not move the file -- resolving it per workspace would stop a global
    administrator's tool denies from applying inside workspaces. Only the
    operator's floor (``MAVERICK_HOME``, ``MAVERICK_TENANT``, a bound client)
    is honoured, and it is read on every call.

    A location that cannot be resolved fails closed like an unreadable policy:
    consumers re-raise :class:`RuntimeOverridesSecurityError` but swallow other
    exceptions, which would silently drop the deny-list.
    """
    if OVERRIDES_PATH is not _INITIAL_OVERRIDES_PATH:
        return Path(OVERRIDES_PATH)
    token = set_tenant(None)  # ignore a request- or run-scoped workspace
    try:
        return data_dir("runtime-overrides.toml")
    except Exception as exc:
        raise RuntimeOverridesSecurityError(
            "refusing to continue: the operator policy location cannot be "
            "resolved; repair the tenant or client binding"
        ) from exc
    finally:
        reset_tenant(token)


def _serialized(fn):
    """Serialize a mutator's whole read-modify-write of the overlay file. The
    public mutators never call one another, so the non-reentrant flock can't
    self-deadlock."""
    @functools.wraps(fn)
    def _wrap(*args, **kwargs):
        from .authority_effects import authority_effect_fence
        from .file_lock import cross_process_lock
        with authority_effect_fence(), _OVERRIDE_LOCK, cross_process_lock(overrides_path()):
            previous = getattr(_mutation_context, "strict_reads", False)
            _mutation_context.strict_reads = True
            try:
                return fn(*args, **kwargs)
            finally:
                _mutation_context.strict_reads = previous
    return _wrap


def _tomllib():
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib


def _cache_key(path: Path) -> str:
    """Stable lexical identity for the policy path.

    Resolving symlinks makes the key depend on whether the link currently
    exists: after a valid symlink-backed policy is loaded, deleting the link
    would otherwise change the key and bypass its last-known-good policy.
    """
    try:
        return str(path.absolute())
    except OSError:
        return str(path)


def _remember_valid(key: str, state: dict) -> dict:
    """Cache a bounded, detached last-known-good policy for transient damage."""
    detached = copy.deepcopy(state)
    _last_known_good[key] = detached
    _last_known_good.move_to_end(key)
    while len(_last_known_good) > _LKG_LIMIT:
        _last_known_good.popitem(last=False)
    return copy.deepcopy(detached)


def _read_overlay(path: Path) -> dict:
    with open(path, "rb") as f:
        content = f.read(_MAX_OVERRIDE_BYTES + 1)
    if len(content) > _MAX_OVERRIDE_BYTES:
        raise ValueError(
            f"runtime override exceeds {_MAX_OVERRIDE_BYTES} bytes"
        )
    return _tomllib().loads(content.decode("utf-8"))


def _require_table(state: dict, name: str) -> dict:
    value = state.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"[{name}] must be a TOML table")
    return value


def _reject_unknown_keys(table: dict, allowed: set[str] | frozenset[str], label: str) -> None:
    unknown = sorted(str(key) for key in set(table) - set(allowed))
    if unknown:
        raise ValueError(f"{label} contains unknown key(s): {', '.join(unknown)}")


def _require_optional_type(
    table: dict,
    key: str,
    expected_type: type,
    *,
    label: str,
) -> None:
    if key in table and not isinstance(table[key], expected_type):
        raise ValueError(f"{label} must be a {expected_type.__name__}")


def _require_string_map(table: dict, key: str, *, label: str) -> None:
    if key not in table:
        return
    value = table[key]
    if not isinstance(value, dict) or any(
        not isinstance(map_key, str) or not isinstance(map_value, str)
        for map_key, map_value in value.items()
    ):
        raise ValueError(f"{label} must be a string-to-string table")


def _require_string_list(
    table: dict,
    key: str,
    pattern: re.Pattern[str],
    *,
    label: str,
) -> None:
    if key not in table:
        return
    values = table[key]
    if not isinstance(values, list):
        raise ValueError(f"{label} must be a list")
    for value in values:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise ValueError(f"{label} contains an invalid entry")


def _validate_loaded_state(state: object) -> dict:
    """Validate every dashboard-owned surface before it can affect policy.

    A syntactically valid but structurally damaged security table must not be
    treated as an empty deny/allow list.  Validating all known sections also
    prevents a dashboard mutation from silently discarding malformed state.
    Unknown top-level sections are rejected so misspelled security controls
    cannot silently become inert.
    """
    if not isinstance(state, dict):
        raise ValueError("runtime override root must be a TOML table")
    _reject_unknown_keys(state, _KNOWN_TOP_LEVEL, "runtime override")

    security = _require_table(state, "security")
    _reject_unknown_keys(security, {"denied_tools"}, "security")
    _require_string_list(
        security,
        "denied_tools",
        _VALID_TOOL_NAME,
        label="security.denied_tools",
    )

    models = _require_table(state, "models")
    for role, model in models.items():
        if (
            not isinstance(role, str)
            or not _VALID_ROLE.fullmatch(role)
            or not isinstance(model, str)
            or not _VALID_MODEL.fullmatch(model.strip())
        ):
            raise ValueError("models contains an invalid role or model id")

    rates = _require_table(state, "model_rates")
    if len(rates) > 100:
        raise ValueError("too many administrator-approved model rates")
    for model, rate in rates.items():
        if not isinstance(model, str) or not _VALID_MODEL.fullmatch(model):
            raise ValueError("model_rates contains an invalid model id")
        _validate_model_rate(rate)

    budget = _require_table(state, "budget")
    _reject_unknown_keys(budget, {"max_dollars", "task_limits_enabled"}, "budget")
    if "task_limits_enabled" in budget and type(budget["task_limits_enabled"]) is not bool:
        raise ValueError("budget.task_limits_enabled must be true or false")
    if "max_dollars" in budget:
        value = budget["max_dollars"]
        if isinstance(value, bool):
            raise ValueError("budget.max_dollars must be a positive number")
        try:
            amount = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("budget.max_dollars must be a positive number") from exc
        if not math.isfinite(amount) or amount <= 0:
            raise ValueError("budget.max_dollars must be a positive number")

    plugins = _require_table(state, "plugins")
    _reject_unknown_keys(plugins, {"enabled", "disabled"}, "plugins")
    _require_string_list(
        plugins,
        "enabled",
        _VALID_PLUGIN,
        label="plugins.enabled",
    )
    _require_string_list(
        plugins,
        "disabled",
        _VALID_PLUGIN,
        label="plugins.disabled",
    )

    access = _require_table(state, "access")
    _reject_unknown_keys(access, {"allowed_models"}, "access")
    _require_string_list(
        access,
        "allowed_models",
        _VALID_MODEL,
        label="access.allowed_models",
    )

    styles = _require_table(state, "styles")
    _reject_unknown_keys(styles, {"active"}, "styles")
    if "active" in styles and (
        not isinstance(styles["active"], str) or not styles["active"].strip()
    ):
        raise ValueError("styles.active must be a non-empty string")

    servers = _require_table(state, "mcp_servers")
    for name, spec in servers.items():
        if (
            not isinstance(name, str)
            or not _VALID_SERVER_NAME.fullmatch(name)
            or not isinstance(spec, dict)
        ):
            raise ValueError("mcp_servers contains an invalid server definition")
        _reject_unknown_keys(spec, _MCP_SPEC_KEYS, f"mcp_servers.{name}")

        label = f"mcp_servers.{name}"
        _require_optional_type(spec, "command", str, label=f"{label}.command")
        _require_optional_type(spec, "url", str, label=f"{label}.url")
        has_command = "command" in spec
        has_url = "url" in spec
        if has_command == has_url:
            raise ValueError(
                f"{label} must define exactly one non-empty command or url"
            )
        selected = spec["command"] if has_command else spec["url"]
        if not selected.strip():
            raise ValueError(
                f"{label} must define exactly one non-empty command or url"
            )

        _require_string_list(
            spec,
            "args",
            re.compile(r"^[^\0\r\n]*$"),
            label=f"{label}.args",
        )
        _require_string_map(spec, "env", label=f"{label}.env")
        _require_string_map(spec, "headers", label=f"{label}.headers")
        _require_optional_type(
            spec,
            "inherit_env",
            bool,
            label=f"{label}.inherit_env",
        )
        _require_optional_type(
            spec,
            "auth_token",
            str,
            label=f"{label}.auth_token",
        )
        _require_optional_type(
            spec,
            "pin_sha256",
            str,
            label=f"{label}.pin_sha256",
        )
        _require_optional_type(spec, "oauth", dict, label=f"{label}.oauth")
        if "enabled" in spec and not isinstance(spec["enabled"], bool):
            raise ValueError(f"{label}.enabled must be a boolean")
        from .mcp_client import MCPServerSpec

        try:
            MCPServerSpec.from_config(
                name,
                {key: value for key, value in spec.items() if key != "enabled"},
            )
        except Exception as exc:
            # MCPServerSpec is a second validation layer. Normalize all of its
            # failures so callers never mistake a schema/delegation bug for an
            # absent runtime policy and fall back to unrestricted defaults.
            raise ValueError(f"{label} is invalid") from exc

    return state


def _load() -> dict:
    path = overrides_path()
    key = _cache_key(path)
    try:
        # lstat distinguishes a genuinely absent policy from a dangling or
        # unreadable symlink, which must fail closed rather than look empty.
        path.lstat()
    except FileNotFoundError:
        with _OVERRIDE_LOCK:
            retained = key in _last_known_good
            for failure in tuple(_announced_load_failures):
                if failure[0] == key:
                    _announced_load_failures.pop(failure, None)
        if retained:
            return _recover_or_raise(
                key,
                FileNotFoundError(
                    "operator policy disappeared after a valid policy was loaded"
                ),
            )
        return {}
    except OSError as exc:
        return _recover_or_raise(key, exc)
    try:
        state = _validate_loaded_state(_read_overlay(path))
    except Exception as exc:
        # Every read, schema, and delegated MCP validation failure has the same
        # fail-closed contract. Critical consumers special-case
        # RuntimeOverridesSecurityError; leaking a KeyError/TypeError here lets
        # their generic resilience catches silently discard the entire policy.
        return _recover_or_raise(key, exc)
    with _OVERRIDE_LOCK:
        for failure in tuple(_announced_load_failures):
            if failure[0] == key:
                _announced_load_failures.pop(failure, None)
        return _remember_valid(key, state)


def _recover_or_raise(key: str, exc: Exception) -> dict:
    with _OVERRIDE_LOCK:
        if (
            key in _last_known_good
            and not getattr(_mutation_context, "strict_reads", False)
        ):
            state = copy.deepcopy(_last_known_good[key])
            _last_known_good.move_to_end(key)
            fingerprint = (key, f"{type(exc).__name__}: {exc}")
            if fingerprint not in _announced_load_failures:
                _announced_load_failures[fingerprint] = None
                _announced_load_failures.move_to_end(fingerprint)
                while len(_announced_load_failures) > _LOAD_FAILURE_LIMIT:
                    _announced_load_failures.popitem(last=False)
                log.error(
                    "runtime_overrides: cannot read or validate %s; retaining "
                    "the in-process last-known-good policy: %s",
                    key,
                    exc,
                )
            return state
    raise RuntimeOverridesSecurityError(
        f"refusing to continue with unreadable or invalid operator policy "
        f"{key}; repair or restore the file"
    ) from exc


_ANNOUNCED_LIMIT = 64
_announced: OrderedDict[str, None] = OrderedDict()


def denied_tools() -> set[str]:
    """Tools the dashboard has disabled. Unioned into the ACL deny-list.

    Re-validates each name against the same charset the writer enforces, so a
    hand-edited / corrupt override file can't push junk or oversized entries
    into ACL resolution. Logs once (per distinct denial set) that the override
    file is actively restricting tools -- this file influences the security
    ACL but lives outside config.toml, so its effect should not be silent.
    """
    sec = (_load().get("security") or {})
    raw = sec.get("denied_tools") or []
    valid = {str(n) for n in raw if isinstance(n, str) and _VALID_TOOL_NAME.match(n)}
    dropped = [n for n in raw if not (isinstance(n, str) and _VALID_TOOL_NAME.match(n))]
    if dropped:
        log.warning(
            "runtime_overrides: ignoring %d invalid denied_tools entr(y/ies) in %s: %r",
            len(dropped), overrides_path(), dropped[:10],
        )
    if valid:
        key = ",".join(sorted(valid))
        if key not in _announced:
            _announced[key] = None
            while len(_announced) > _ANNOUNCED_LIMIT:
                _announced.popitem(last=False)
            log.info(
                "runtime_overrides: %s is denying %d tool(s) via the dashboard "
                "overlay: %s", overrides_path(), len(valid), ", ".join(sorted(valid)),
            )
    return valid


# A model spec is a bare id ("claude-sonnet-4-6") or "provider:model-id"
# ("anthropic:claude-opus-4-8"). Keep the charset tight so a hand-edited /
# corrupt override can't push junk into model resolution.
# "@" admits Vertex AI name@version ids; it is not a path or query character here.
_VALID_MODEL = re.compile(r"^[A-Za-z0-9_.:/@-]{1,128}$")
# Override keys under [models]: a role name (orchestrator, coder, ...) or the
# special "default" that applies to every role. Tight charset so a hand-edited
# file can't inject junk keys.
_VALID_ROLE = re.compile(r"^[a-z_]{1,40}$")
_MODEL_RATE_KEYS = frozenset({
    "input_per_mtok", "output_per_mtok", "source", "as_of", "valid_until",
    "approved_at", "approved_by",
})


def _validate_model_rate(rate: object) -> dict:
    """An operator-attested *ceiling*, never a vendor-verified invoice rate."""
    if not isinstance(rate, dict) or set(rate) != _MODEL_RATE_KEYS:
        raise ValueError("model rate requires both prices, source, dates and approver")
    for key in ("input_per_mtok", "output_per_mtok"):
        value = rate[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1_000_000:
            raise ValueError("model rate must be a finite non-negative USD amount")
    if not (rate["input_per_mtok"] or rate["output_per_mtok"]):
        raise ValueError("a zero-cost model needs provider evidence, not an entered rate")
    for key, limit in (("source", 300), ("approved_by", 200)):
        value = rate[key]
        if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
            raise ValueError(f"invalid model rate {key}")
    try:
        as_of = date.fromisoformat(rate["as_of"])
        expires = date.fromisoformat(rate["valid_until"])
        approved = datetime.fromisoformat(rate["approved_at"].replace("Z", "+00:00"))
    except (TypeError, AttributeError, ValueError) as exc:
        raise ValueError("model rate dates are invalid") from exc
    today = datetime.now(timezone.utc).date()
    if (approved.tzinfo is None or as_of > today or expires < as_of
            or (expires - as_of).days > 366
            or approved.astimezone(timezone.utc).date() > today):
        raise ValueError("model rate dates require a current, dated source")
    return rate


def model_rate_overrides() -> dict[str, dict]:
    """Read the shared, validated rate ceilings without changing routing."""
    return copy.deepcopy(_load().get("model_rates") or {})


def _models_overlay() -> dict[str, str]:
    """The dashboard's ``[models]`` table: ``{"default": spec, "<role>": spec}``.
    Re-validated on read; junk keys/values are dropped."""
    raw = _load().get("models") or {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if (isinstance(k, str) and _VALID_ROLE.fullmatch(k)
                and isinstance(v, str) and _VALID_MODEL.fullmatch(v.strip())):
            out[k] = v.strip()
    return out


def default_model_override() -> str | None:
    """The dashboard's global default model pin, or None. Consulted by
    ``llm.model_for_role`` below the user's ``config.toml`` ``[models]`` and
    above the built-in ``ROLE_MODELS`` defaults."""
    return _models_overlay().get("default")


def role_model_override(role: str) -> str | None:
    """The dashboard's per-role model pin for ``role``, or None. Wins over the
    global default; consulted by ``llm.model_for_role`` at the same precedence."""
    return _models_overlay().get(role) if role != "default" else None


def budget_override() -> float | None:
    """The per-goal spend cap (USD) the dashboard's settings page has set, or
    None. Consulted by ``budget.budget_from_config`` above the ``[budget]``
    config section. Re-validated on read; only a finite, positive number wins."""
    raw = (_load().get("budget") or {}).get("max_dollars")
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and v > 0 else None


# Plugin / entry-point name: alnum plus _.@- (covers "weather", "weather@dist").
_VALID_PLUGIN = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


def plugin_overlay() -> tuple[set[str], set[str]]:
    """The dashboard's ``[plugins]`` overlay as ``(force_enabled, force_disabled)``
    name sets. Consulted by ``plugins._allowed_plugin_names`` -- ``enabled`` adds
    to the config allowlist, ``disabled`` removes from it (disable wins).
    Re-validated on read; junk entries dropped."""
    p = _load().get("plugins") or {}

    def _clean(key: str) -> set[str]:
        return {n.strip() for n in (p.get(key) or [])
                if isinstance(n, str) and _VALID_PLUGIN.fullmatch(n.strip())}
    on, off = _clean("enabled"), _clean("disabled")
    return on - off, off  # disable wins if a name appears in both


def allowed_models() -> set[str]:
    """The admin allow-list of model specs (dashboard ``[access] allowed_models``).
    When non-empty, ``llm.model_for_role`` caps every role to this set and the
    settings pickers offer only these. Empty = no restriction. Re-validated on
    read so a tampered file can't inject junk."""
    raw = (_load().get("access") or {}).get("allowed_models") or []
    return {s.strip() for s in raw
            if isinstance(s, str) and _VALID_MODEL.fullmatch(s.strip())}


# MCP server name: bare TOML key charset (no dots, so the ``[mcp_servers.<name>]``
# header is unambiguous). The kernel revalidates the whole spec at load time.
_VALID_SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def mcp_overlay() -> dict[str, dict]:
    """Dashboard-added MCP servers as ``{name: spec_dict}`` (overlay
    ``[mcp_servers.<name>]``). Unioned into ``mcp_client.load_mcp_specs_from_config``
    so a server added from the dashboard runs on the next goal with no config.toml
    edit -- config wins on a name clash. Re-validated on read: a name must be a
    bare key and the spec a dict carrying ``command`` (stdio) or ``url`` (http)."""
    raw = _load().get("mcp_servers") or {}
    out: dict[str, dict] = {}
    for name, spec in raw.items():
        if (isinstance(name, str) and _VALID_SERVER_NAME.fullmatch(name)
                and isinstance(spec, dict)
                and ("command" in spec or "url" in spec)):
            out[name] = _unseal_mcp_spec(spec)
    return out


def _toml_inline(value) -> str:
    """Render a scalar / list / string-map as a TOML inline value. Used for the
    ``[mcp_servers.<name>]`` blocks (args list, env/headers/oauth inline tables)
    -- the rest of the overlay is plain string lists handled inline above."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _toml_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_inline(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(
            f"{_toml_string(str(k))} = {_toml_inline(v)}" for k, v in value.items()) + "}"
    raise ValueError(f"cannot serialise {type(value).__name__} to TOML")


def _transform_secret_tree(value: object, transform) -> object:
    """Apply ``transform`` to every string leaf of one credential container."""
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, dict):
        return {key: _transform_secret_tree(item, transform) for key, item in value.items()}
    if isinstance(value, list):
        return [_transform_secret_tree(item, transform) for item in value]
    if isinstance(value, tuple):
        return tuple(_transform_secret_tree(item, transform) for item in value)
    return value


def _map_mcp_secrets(spec: dict, transform) -> dict:
    """Transform only MCP credential-bearing fields in a detached spec."""
    out = copy.deepcopy(spec)
    if isinstance(out.get("auth_token"), str):
        out["auth_token"] = transform(out["auth_token"])
    # Values in these user-supplied containers are credential material or may
    # carry it (Authorization headers and stdio environment values in
    # particular).  Keys remain visible so runtime schema validation and
    # operator diagnostics still work without opening the values.
    for field in ("env", "headers", "oauth"):
        if isinstance(out.get(field), dict):
            out[field] = _transform_secret_tree(out[field], transform)
    return out


def _seal_mcp_spec(spec: dict) -> dict:
    from .crypto_at_rest import deployment_key_scope, is_sealed_str, seal_to_str

    def seal_value(value: str) -> str:
        return value if is_sealed_str(value) else seal_to_str(value)

    with deployment_key_scope():
        return _map_mcp_secrets(spec, seal_value)


def _unseal_mcp_spec(spec: dict) -> dict:
    from .crypto_at_rest import deployment_key_scope, is_sealed_str, unseal_from_str

    def unseal_value(value: str) -> str:
        return unseal_from_str(value) if is_sealed_str(value) else value

    with deployment_key_scope():
        return _map_mcp_secrets(spec, unseal_value)


def _render_mcp(servers: dict[str, dict]) -> str:
    """Render ``[mcp_servers.<name>]`` tables. Names are bare keys (validated by
    add_mcp_server) so the header is unambiguous; these tables come LAST in the
    file so no top-level key is captured by a subtable."""
    body = ""
    for name in sorted(servers):
        body += f"\n[mcp_servers.{name}]\n"
        sealed = _seal_mcp_spec(servers[name])
        for key, val in sealed.items():
            if key == "name":  # the table key already carries the name
                continue
            body += f"{_toml_string(str(key))} = {_toml_inline(val)}\n"
    return body


def _write_state(denied: set[str], models: dict[str, str] | None,
                 budget: float | None,
                 plugins: tuple[set[str], set[str]] | None = None,
                 allowed: set[str] | None = None,
                 mcp: dict[str, dict] | None = None,
                 style: str | None = None,
                 task_limits: bool | None = None,
                 model_rates: dict[str, dict] | None = None) -> None:
    """Serialise the whole overlay: [security] denied_tools + optional [models]
    (default + per-role) + [budget] max_dollars + [plugins] enabled/disabled +
    [access] allowed_models + [mcp_servers.<name>] tables. One file holds every
    surface, so each write renders the full state -- changing one must not drop
    the others. Optional params default to the on-disk overlay so the existing
    callers preserve what they don't touch. Atomic write at 0o600; no tomli-w
    dependency.
    """
    path = overrides_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered =", ".join(_toml_string(n) for n in sorted(denied))
    body = (
        "# Dashboard-managed overrides. Edit via the dashboard's\n"
        "# permissions page, not by hand (the dashboard rewrites this\n"
        "# file). Your config.toml is never touched by the dashboard.\n\n"
        "[security]\n"
        f"denied_tools = [{rendered}]\n"
    )
    if models:
        body += "\n[models]\n"
        # "default" first (if present), then roles sorted -- deterministic.
        ordered = (["default"] if "default" in models else []) \
            + sorted(k for k in models if k != "default")
        for k in ordered:
            body += f"{k} = {_toml_string(models[k])}\n"
    if task_limits is None:
        task_limits = (_load().get("budget") or {}).get("task_limits_enabled")
    if budget is not None or task_limits is not None:
        body += "\n[budget]\n"
        if budget is not None:
            body += f"max_dollars = {float(budget)}\n"
        if task_limits is not None:
            body += f"task_limits_enabled = {str(task_limits).lower()}\n"
    on, off = plugin_overlay() if plugins is None else plugins
    if on or off:
        body += "\n[plugins]\n"
        if on:
            body += f"enabled = [{', '.join(_toml_string(n) for n in sorted(on))}]\n"
        if off:
            body += f"disabled = [{', '.join(_toml_string(n) for n in sorted(off))}]\n"
    allow = allowed_models() if allowed is None else allowed
    if allow:
        body += ("\n[access]\nallowed_models = ["
                 f"{', '.join(_toml_string(s) for s in sorted(allow))}]\n")
    active_style = style_override() if style is None else style
    if active_style:
        body += f"\n[styles]\nactive = {_toml_string(active_style)}\n"
    rates = model_rate_overrides() if model_rates is None else model_rates
    if rates:
        body += "\n[model_rates]\n"
        for spec, rate in sorted(rates.items()):
            body += f"{_toml_string(spec)} = {_toml_inline(rate)}\n"
    # MCP server tables come last: once a subtable header is emitted every
    # following key belongs to it, so no top-level section may follow.
    servers = mcp_overlay() if mcp is None else mcp
    if servers:
        body += _render_mcp(servers)
    # Unique temp + os.replace (0600): a fixed ".toml.tmp" collides under two
    # concurrent writers -- one os.replace moves it out from under the other.
    from .file_lock import atomic_write_text
    # Parse and validate before replacement. A renderer/schema bug must never
    # atomically replace the last valid operator policy with corrupt TOML.
    state = _validate_loaded_state(_tomllib().loads(body))
    from .runtime_policy_recovery import retain_current, retain_written
    retain_current()
    audit = _setting_audit.get()
    if audit is not None:
        audit("prepared", _load(), state)
    atomic_write_text(path, body)
    retain_written(body)
    if audit is not None:
        audit("completed", {}, state)
    # Keep the fallback synchronized with writes from this process.
    with _OVERRIDE_LOCK:
        _remember_valid(_cache_key(path), state)


def _toml_string(value: str) -> str:
    import json
    return json.dumps(value)


def _validate_tool_name(name: str) -> str:
    n = (name or "").strip()
    if not _VALID_TOOL_NAME.fullmatch(n):
        raise ValueError("invalid tool name")
    return n


def _validate_model(model: str) -> str:
    m = (model or "").strip()
    if not _VALID_MODEL.fullmatch(m):
        raise ValueError("invalid model id")
    return m


def _validate_role(role: str) -> str:
    r = (role or "").strip().lower()
    if r == "default" or not _VALID_ROLE.fullmatch(r):
        # the global pin goes through set_default_model, not the per-role path
        raise ValueError("invalid role")
    return r


@_serialized
def disable_tool(name: str) -> set[str]:
    """Add ``name`` to the overlay deny-list. Returns the new set."""
    current = denied_tools()
    current.add(_validate_tool_name(name))
    _write_state(current, _models_overlay() or None, budget_override())
    return current


@_serialized
def enable_tool(name: str) -> set[str]:
    """Remove ``name`` from the overlay deny-list. Returns the new set.

    Note: this only clears a dashboard-set override. If a tool is
    denied in config.toml itself, re-enabling requires editing config.
    """
    current = denied_tools()
    current.discard(_validate_tool_name(name))
    _write_state(current, _models_overlay() or None, budget_override())
    return current


@_serialized
def set_default_model(model: str) -> str:
    """Pin the dashboard's global default model. Returns the stored spec."""
    spec = _validate_model(model)
    models = _models_overlay()
    models["default"] = spec
    _write_state(denied_tools(), models, budget_override())
    return spec


@_serialized
def clear_default_model() -> None:
    """Drop the global default model pin (per-role pins are untouched)."""
    models = _models_overlay()
    models.pop("default", None)
    _write_state(denied_tools(), models or None, budget_override())


@_serialized
def set_model_rate(spec: str, *, input_per_mtok: float, output_per_mtok: float,
                   source: str, as_of: str, valid_until: str, approved_by: str) -> dict:
    """Approve a sourced USD ceiling for a route without claiming vendor verification."""
    model = _validate_model(spec)
    rate = _validate_model_rate({
        "input_per_mtok": float(input_per_mtok),
        "output_per_mtok": float(output_per_mtok),
        "source": source.strip(), "as_of": as_of, "valid_until": valid_until,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "approved_by": approved_by,
    })
    if date.fromisoformat(valid_until) < datetime.now(timezone.utc).date():
        raise ValueError("model rate has expired")
    rates = model_rate_overrides()
    rates[model] = rate
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 model_rates=rates)
    return copy.deepcopy(rate)


@_serialized
def clear_model_rate(spec: str) -> None:
    model = _validate_model(spec)
    rates = model_rate_overrides()
    rates.pop(model, None)
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 model_rates=rates)


@_serialized
def set_role_models(updates: dict[str, str | None]) -> None:
    """Batch set/clear per-role model pins in one write. A falsy value clears
    that role. Invalid role/model ids raise ValueError before anything writes."""
    models = _models_overlay()
    cleaned = {_validate_role(role): (_validate_model(spec) if spec else None)
               for role, spec in updates.items()}
    for r, spec in cleaned.items():
        if spec:
            models[r] = spec
        else:
            models.pop(r, None)
    _write_state(denied_tools(), models or None, budget_override())


@_serialized
def set_budget(max_dollars: float) -> float:
    """Set the dashboard's per-goal spend cap (USD). Returns the stored value."""
    try:
        v = float(max_dollars)
    except (TypeError, ValueError) as exc:
        raise ValueError("budget must be a number") from exc
    if not math.isfinite(v) or v <= 0:
        raise ValueError("budget must be a positive number")
    _write_state(denied_tools(), _models_overlay() or None, v, task_limits=True)
    return v


@_serialized
def clear_budget() -> None:
    """Drop the dashboard spend cap, reverting to config.toml / defaults."""
    _write_state(denied_tools(), _models_overlay() or None, None)


def task_limits_override() -> bool | None:
    return (_load().get("budget") or {}).get("task_limits_enabled")


@_serialized
def set_task_limits(enabled: bool) -> None:
    """Intentionally disable/reinstate configured task caps; never organization caps."""
    if type(enabled) is not bool:
        raise ValueError("task limits choice must be a boolean")
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 task_limits=enabled)


def style_override() -> str | None:
    """The dashboard-selected output style name, or ``None`` if unset."""
    v = _load().get("styles", {})
    name = v.get("active") if isinstance(v, dict) else None
    return name if isinstance(name, str) and name.strip() else None


@_serialized
def set_style(name: str) -> str:
    """Select the active output style (a name from ``styles.all_styles()``).
    Validated against the registry so a typo can't silently take effect."""
    n = (name or "").strip()
    from .styles import all_styles
    if n not in all_styles():
        raise ValueError(f"unknown output style: {name!r}")
    _write_state(denied_tools(), _models_overlay() or None, budget_override(), style=n)
    return n


@_serialized
def clear_style() -> None:
    """Drop the output style, reverting to the default voice."""
    _write_state(denied_tools(), _models_overlay() or None, budget_override(), style="")


def _validate_plugin(name: str) -> str:
    n = (name or "").strip()
    if not _VALID_PLUGIN.fullmatch(n):
        raise ValueError("invalid plugin name")
    return n


def _set_plugins(on: set[str], off: set[str]) -> None:
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 (on, off))


@_serialized
def enable_plugin(name: str) -> None:
    """Force-enable a plugin from the dashboard (adds it to the allowlist)."""
    n = _validate_plugin(name)
    on, off = plugin_overlay()
    on.add(n)
    off.discard(n)
    _set_plugins(on, off)


@_serialized
def disable_plugin(name: str) -> None:
    """Force-disable a plugin from the dashboard (removes it from the allowlist,
    even when config.toml enables it)."""
    n = _validate_plugin(name)
    on, off = plugin_overlay()
    off.add(n)
    on.discard(n)
    _set_plugins(on, off)


@_serialized
def reset_plugin(name: str) -> None:
    """Clear any dashboard plugin override, reverting to config.toml."""
    n = _validate_plugin(name)
    on, off = plugin_overlay()
    on.discard(n)
    off.discard(n)
    _set_plugins(on, off)


@_serialized
def set_allowed_models(specs) -> set[str]:
    """Set the admin model allow-list (an empty list clears it). Validates each
    spec before writing; returns the stored set."""
    allow: set[str] = set()
    for s in (specs or []):
        m = (str(s) or "").strip()
        if not m:
            continue
        if not _VALID_MODEL.fullmatch(m):
            raise ValueError("invalid model id")
        allow.add(m)
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 allowed=allow)
    return allow


@_serialized
def add_mcp_server(name: str, spec: dict) -> dict:
    """Add (or replace) a dashboard-managed MCP server. Validates the spec the
    same way the kernel will at load time (``MCPServerSpec.from_config`` -- the
    subprocess-injection / url guards), stores the normalised dict, and returns
    it. Raises ValueError on a bad name or spec; config.toml is never touched."""
    n = (name or "").strip()
    if not _VALID_SERVER_NAME.fullmatch(n) or n.endswith("_") or "__" in n:
        # The kernel refuses such a server's tools (``mcp_<server>__<tool>``
        # must split one way), so refuse it here instead of saving it silently.
        raise ValueError("invalid MCP server name")
    if not isinstance(spec, dict) or ("command" not in spec and "url" not in spec):
        raise ValueError("MCP server needs a command (stdio) or url (http)")
    from .mcp_client import MCPServerSpec  # lazy: avoid an import cycle
    stored = MCPServerSpec.from_config(n, spec).to_dict()
    servers = mcp_overlay()
    servers[n] = stored
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 mcp=servers)
    return stored


@_serialized
def remove_mcp_server(name: str) -> bool:
    """Remove a dashboard-managed MCP server. Returns True if one was removed.
    Only clears a dashboard-added server; a config.toml server is not touched."""
    n = (name or "").strip()
    servers = mcp_overlay()
    if n not in servers:
        return False
    del servers[n]
    _write_state(denied_tools(), _models_overlay() or None, budget_override(),
                 mcp=servers)
    return True


__all__ = [
    "RuntimeOverridesSecurityError",
    "denied_tools", "disable_tool", "enable_tool",
    "default_model_override", "set_default_model", "clear_default_model",
    "model_rate_overrides", "set_model_rate", "clear_model_rate",
    "role_model_override", "set_role_models",
    "budget_override", "set_budget", "clear_budget",
    "plugin_overlay", "enable_plugin", "disable_plugin", "reset_plugin",
    "allowed_models", "set_allowed_models",
    "mcp_overlay", "add_mcp_server", "remove_mcp_server",
    "OVERRIDES_PATH", "overrides_path",
]
