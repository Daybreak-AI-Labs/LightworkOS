"""Helpers shared by the dashboard's ``app`` and ``api`` modules.

These four symbols lived as verbatim copies in both ``app`` and ``api``.
The duplication was deliberate -- ``app`` imports ``api`` at module load,
so the reverse import would cycle, and the old ``_world`` docstrings said
as much. A third module that imports neither removes the copies without
reintroducing the cycle; both modules ``from ._shared import`` these.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

from maverick.runtime_overrides import RuntimeOverridesSecurityError

# One process-wide WorldModel cache keyed by absolute DB path (was a
# separate dict per module). Tests clear it via ``<module>._world_cache``.
_world_cache: dict[str, Any] = {}


# SSE concurrency cap. Each open event-stream holds a slot; new streams 503
# past the cap. This lived as a verbatim copy in both ``app`` and ``api``,
# which created TWO independent semaphores -- so the real ceiling was the cap
# per module, not process-wide. One shared semaphore makes the limit actually
# bind across all streaming routes. Built lazily on the running loop.
def dashboard_setting(env: str, key: str, default: object) -> object:
    """``env`` when set, else ``[dashboard] <key>`` (settable on Settings > All
    settings), else ``default``."""
    raw = os.environ.get(env)
    if raw is not None and raw.strip() != "":
        return raw
    try:
        from maverick.config import load_config

        table = (load_config() or {}).get("dashboard") or {}
    except Exception:  # an unreadable config keeps the default
        return default
    value = table.get(key) if isinstance(table, dict) else None
    return default if value is None else value


def dashboard_token() -> str:
    """The server's access token: ``MAVERICK_DASHBOARD_TOKEN``, else the sealed
    ``[dashboard] token`` a global administrator set on Settings > All
    settings (installation-wide config only: a workspace's own settings can
    never supply it). Empty when neither is set."""
    env = os.environ.get("MAVERICK_DASHBOARD_TOKEN", "")
    if env:
        return env
    try:
        from maverick.config import load_global_config

        table = (load_global_config() or {}).get("dashboard") or {}
    except Exception:  # unreadable settings: no configured token (auth fails closed)
        return ""
    value = table.get("token") if isinstance(table, dict) else None
    return value.strip() if isinstance(value, str) else ""


def _max_sse_streams() -> int:
    try:
        return max(1, int(dashboard_setting("MAVERICK_DASHBOARD_MAX_SSE", "max_sse", 64)))
    except (TypeError, ValueError):
        return 64


_sse_semaphore: asyncio.Semaphore | None = None


def _get_sse_semaphore() -> asyncio.Semaphore:
    global _sse_semaphore
    if _sse_semaphore is None:
        _sse_semaphore = asyncio.Semaphore(_max_sse_streams())
    return _sse_semaphore

def _any_provider_key_set() -> bool:
    """True iff some LLM provider is configured (env key, base-url env, or
    a ``[providers.<name>]`` config table with api_key/base_url).

    OpenAI, Gemini and keyless self-hosted setups (Ollama/vLLM/TGI via config
    or *_BASE_URL) count, exactly as they do for the CLI: this delegates to
    the one shared predicate in maverick.config, so every component agrees.
    The name is kept for call sites.
    """
    try:
        from maverick.config import any_provider_configured
        return any_provider_configured()
    except Exception:  # pragma: no cover -- never block the dashboard on config
        return False


def task_step_readiness() -> dict[str, Any]:
    """Plain current task-step readiness, without echoing invalid source values."""
    from maverick import config

    from . import settings_all_page as page
    from . import settings_catalog as catalog

    layers = page._sources()
    setting = catalog.BY_ID["agent.max_steps"]
    source = page._resolve(setting, layers)
    tenant_present, _value = catalog.lookup(layers["tenant"], setting.path)
    deployment = bool(source["locked"] or tenant_present)
    try:
        value = config.get_agent_max_steps()
    except config.AgentStepConfigError:
        remedy = (
            "This limit is controlled by the installation’s deployment settings. "
            "Ask the person responsible for this installation to correct it; saving here cannot override it."
            if deployment else
            "An administrator can open All settings → AI models → ‘Most steps an agent may take’ "
            "and choose a positive whole number, or use Reset to product default for no step limit."
        )
        return {"ready": False, "max_steps": None, "deployment_managed": deployment,
                "reason": "New tasks cannot start because the task-step limit is invalid. " + remedy,
                "settings": {"label": "Review task-step limit", "href": "/settings/all?id=agent.max_steps"}}
    return {"ready": True, "max_steps": value, "deployment_managed": deployment,
            "reason": "No step limit is set; spending and time limits still apply." if value is None else
                      f"Each agent can take up to {value} steps on a task.",
            "settings": {"label": "Review task-step limit", "href": "/settings/all?id=agent.max_steps"}}


def require_task_settings_or_400() -> None:
    from fastapi import HTTPException

    state = task_step_readiness()
    if not state["ready"]:
        raise HTTPException(400, state["reason"], headers={"X-Lightwork-Task-Settings": "agent.max_steps"})


def require_provider_or_400(*, role: str | None = None) -> None:
    """Raise HTTP 400 unless the route(s) this operation uses are complete.

    ``role=None`` validates every deterministic swarm route before goal state
    is created. A drafting endpoint can name its one role so an unrelated or
    incomplete worker route does not block a single bounded completion.
    """
    if role is None:
        require_task_settings_or_400()
    try:
        from maverick.config import load_config
        from maverick.operator_preflight import (
            _format_route_missing,
            _role_configuration_missing,
            _routed_configuration_missing,
        )

        cfg = load_config()
        if role is None:
            missing = {
                provider: fields
                for provider, fields in _routed_configuration_missing(cfg).items()
                if fields
            }
        else:
            provider, fields = _role_configuration_missing(role, cfg)
            missing = {provider: fields} if fields else {}
    except RuntimeOverridesSecurityError:
        # This is an operator-policy integrity failure, not an incomplete model
        # route. Let the app's explicit handler return the actionable 503.
        raise
    except Exception:
        missing = {"selected": ("configuration",)}
    if not missing:
        return
    from fastapi import HTTPException

    missing_detail = _format_route_missing(missing)
    raise HTTPException(
        status_code=400,
        detail=(
            "The selected AI model route is incomplete "
            f"({missing_detail}). An administrator can add the missing key in "
            "Lightwork > Settings (or run 'maverick init' on a computer with no "
            "Lightwork setup yet), then run 'maverick preflight'."
        ),
    )


def authenticated_subject(request, *, error_detail: str) -> str:
    """Resolve the caller's identity subject for a suite API's per-caller
    principal-ref digest.

    29 suite-API modules each copied a `_principal`/
    `_principal_ref` helper that reads `request.state.principal` and 401s
    when it's empty. But `require_principal` (auth.py) deliberately leaves
    `request.state.principal` UNSET for two legitimate authenticated shapes,
    not just a genuinely missing identity: a valid static
    `MAVERICK_DASHBOARD_TOKEN` bearer (`_dashboard_token_authenticated`
    returns True; there's no per-user OIDC/session subject to attach) and
    genuine local single-user auth-off mode (`anonymous_local_access_allowed`).
    `require_permission`'s own authorization check (`_authorization_principal`)
    already treats both as authenticated -- these suite modules didn't, so the
    documented static-token API path and single-user local mode 401'd on
    every one of them while core routes and 7 other suite modules (which
    happened to implement this same three-way check themselves) worked fine.

    Returns a named principal's subject when one exists (unchanged from
    before -- callers keep their own digest namespace/prefix, so an
    already-authenticated caller's principal ref does not change), else a
    stable synthetic operator subject for the other two accepted shapes
    (matching the "authorized-local-operator" / "static-dashboard-operator"
    strings a few of these modules had already independently landed on), else
    raises 401 with the caller's own message -- only when NONE of the three
    shapes require_permission() itself accepts actually authenticated this
    request.

    Reads ``request.state.principal`` directly (checking both its
    ``.principal`` and ``.sub`` attributes) rather than going through
    ``auth.caller_principal`` (which only reads ``.principal``): the two are
    always in sync on the real ``VerifiedPrincipal`` production attaches
    (``.principal`` is a derived ``f"user:{sub}"`` property), but most of the
    22 call sites this replaces made both names acceptable, and this keeps
    that unchanged instead of narrowing it.
    """
    from fastapi import HTTPException

    from .auth import _dashboard_token_authenticated, anonymous_local_access_allowed

    verified = getattr(getattr(request, "state", None), "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if isinstance(subject, str) and subject.strip() and len(subject) <= 512:
        return subject.strip()
    if anonymous_local_access_allowed():
        return "authorized-local-operator"
    if _dashboard_token_authenticated(request):
        return "static-dashboard-operator"
    raise HTTPException(status_code=401, detail=error_detail)


def _world():
    """Return a per-DB-path cached WorldModel.

    Opening a new WorldModel on every request re-runs the PRAGMAs and the
    schema-migration check, leaks the connection (no close()), and
    serialises the asyncio loop because sqlite3 is sync. Cache by absolute
    DB path so test fixtures that monkeypatch ``DEFAULT_DB`` to a fresh
    ``tmp_path`` still get an isolated WorldModel per test.
    """
    # Client binding: when the deployment is bound to a client, the dashboard
    # reads/writes that client's isolated world DB (under tenants/<client>/),
    # never the shared root. Unbound (legacy / tests that monkeypatch
    # DEFAULT_DB) keeps the prior DEFAULT_DB path exactly.
    #
    # Backend selection (split-brain fix): when the deployment opts into Postgres
    # ([world_model] backend = "postgres" / MAVERICK_WORLD_BACKEND=postgres), the
    # dashboard must read/write the SAME Postgres the runner, channel server and
    # gRPC API use; always opening SQLite would leave a Postgres deployment's
    # dashboard reading a stale local world.db. Checked before
    # the tenant floor because Postgres isolates by tenant_id at query time, not
    # by a per-tenant file. open_postgres_world() builds a fresh connection per
    # call, so cache the one backend for the process under a fixed key.
    from maverick.world_model_backends import is_postgres_configured
    if is_postgres_configured():
        cached = _world_cache.get("__postgres__")
        if cached is None:
            from maverick.world_model import open_world
            cached = open_world()  # also enforces the at-rest fail-closed guard
            _world_cache["__postgres__"] = cached
        return cached
    from maverick.paths import current_tenant_id
    tid = current_tenant_id()
    if tid:
        from maverick.world_model import world_for_tenant
        return world_for_tenant(tid)
    from maverick.world_model import default_db_path, open_world
    path = default_db_path()
    key = str(path)
    cached = _world_cache.get(key)
    if cached is None:
        # Preserve DEFAULT_DB override ownership semantics: open_world() knows
        # whether this is Lightwork's managed default or a caller-owned path.
        cached = open_world()
        _world_cache[key] = cached
    return cached
