"""What the in-product service banner says when an AI service is paused,
a connection can't be used, or the database is read-only.

The circuit breaker (:mod:`maverick.circuit_breaker`) pauses an AI provider
after repeated errors (``llm:<provider>`` keys, or ``llm:<provider>:route:<hash>``
for a native client) and lets one test request through once its cooldown ends.
This module turns that state into the three
things a person needs: what is affected, what happens to running tasks, and
when Lightwork checks again. It looks at every provider this workspace uses
(the role models and their backup models), so one healthy backup reads as
"reduced", not "down".

The breaker is held in memory by the process that runs the AI calls. Tasks
run inside the dashboard process by default, so the dashboard sees it;
separate worker processes keep their own and are not reflected here.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

_PAUSED_STATES = {"open", "half_open"}
_NAMES = {"openai": "OpenAI", "xai": "xAI", "deepseek": "DeepSeek", "openrouter": "OpenRouter",
          "azure_openai": "Azure OpenAI", "codex_cli": "Codex", "tgi": "TGI", "vllm": "vLLM"}

#: What happens to a task whose next step needs a paused service (read from
#: llm._enforce_circuit and the runners' failure path): the call is refused at
#: once, a configured backup model is tried, and otherwise the task stops as
#: "Failed" with what it already finished kept.
TASKS_DOWN = ("Tasks that need an AI answer now stop and show “Failed”. "
              "What they already finished is kept; run them again once the service is back.")
TASKS_REDUCED = ("Steps that need {paused} move to a backup model where one is set up; "
                 "otherwise that task stops and shows “Failed”. Tasks that use {healthy} keep working.")
#: Another way to get the work done meanwhile: the fourth thing a failure
#: message says, after what broke, what is safe and when it returns.
ALTERNATIVE_DOWN = ("Meanwhile, an administrator can set up another AI service under Settings > AI models "
                    "so tasks can carry on, and urgent steps can be done by hand.")
ALTERNATIVE_REDUCED = "Meanwhile, start new work as usual: it uses {healthy}."


def provider_name(provider: str) -> str:
    key = str(provider or "").strip().lower()
    return _NAMES.get(key) or key.replace("_", " ").title() or "An AI service"


def _provider_of(spec: object) -> str:
    text = str(spec or "")
    return text.split(":", 1)[0].strip().lower() if ":" in text else ""


def providers_in_use() -> set[str]:
    """Providers named by this workspace's role models and backup chains."""
    from .config import get_role_model, load_config
    from .llm import ROLE_MODELS

    used = set()
    for role, default in ROLE_MODELS.items():
        try:
            used.add(_provider_of(get_role_model(role) or default))
        except Exception:  # noqa: BLE001 -- an unreadable role keeps its default
            used.add(_provider_of(default))
    try:
        chains = ((load_config() or {}).get("provider_failover") or {}).get("chains") or {}
    except Exception:  # noqa: BLE001 -- unreadable config: no backups known
        chains = {}
    if isinstance(chains, dict):
        for primary, backups in chains.items():
            used.add(_provider_of(primary))
            for backup in backups if isinstance(backups, list) else ():
                used.add(_provider_of(backup))
    return {name for name in used if name}


def current(*, breakers: list[dict] | None = None, in_use: set[str] | None = None) -> dict[str, Any] | None:
    """The banner's content, or ``None`` when no AI service is paused."""
    if breakers is None:
        from .circuit_breaker import snapshot
        breakers = snapshot()
    paused: dict[str, dict] = {}
    for row in breakers:
        key = str(row.get("key") or "")
        if key.startswith("llm:") and row.get("state") in _PAUSED_STATES:
            # llm._dispatch_client keys a native client's breaker
            # ``llm:<provider>:route:<sha256>``: name the provider, and keep one
            # row (the most recently opened) when several routes are paused.
            provider = key[4:].split(":route:", 1)[0].lower()
            held = paused.get(provider)
            if held is None or float(row.get("opened_at") or 0) >= float(held.get("opened_at") or 0):
                paused[provider] = row
    if not paused:
        return None
    if in_use is None:
        try:
            in_use = providers_in_use()
        except Exception:  # noqa: BLE001 -- unknown setup reads as "nothing else can serve"
            log.debug("service status: provider list unavailable", exc_info=True)
            in_use = set()
    healthy = sorted(in_use - set(paused))
    names = [provider_name(name) for name in sorted(paused)]
    affected = " and ".join(names)
    verb = "are" if len(names) > 1 else "is"
    checks = []
    for name, row in sorted(paused.items()):
        if row.get("state") == "half_open":
            checks.append({"provider": provider_name(name), "at": None})
        else:
            opened = float(row.get("opened_at") or 0)
            cooldown = float(row.get("cooldown_seconds") or 30)
            checks.append({"provider": provider_name(name), "at": opened + cooldown if opened else None})
    if healthy:
        healthy_names = " and ".join(provider_name(name) for name in healthy)
        return {"level": "reduced", "affected": affected,
                "title": f"{affected} {verb} paused after repeated errors. Lightwork is still working with {healthy_names}.",
                "tasks": TASKS_REDUCED.format(paused=affected, healthy=healthy_names),
                "alternative": ALTERNATIVE_REDUCED.format(healthy=healthy_names),
                "checks": checks, "healthy": [provider_name(name) for name in healthy]}
    return {"level": "down", "affected": affected,
            "title": f"{affected} {verb} paused after repeated errors, and no other AI service is set up to take over.",
            "tasks": TASKS_DOWN, "alternative": ALTERNATIVE_DOWN, "checks": checks, "healthy": []}


#: The same four parts for the other two shared dependencies: a connection people's tasks
#: use (expired sign-in, failing check) and the world database itself.
CONNECTOR_TASKS = "Steps that need it stop and say why; everything else keeps working."
CONNECTOR_WHEN = "It works again as soon as it is reconnected in Connections."
CONNECTOR_ALTERNATIVE = "Meanwhile, do that step by hand or use another connection for it."
READ_ONLY_TITLE = "Lightwork can't save changes right now because its database is read-only."
READ_ONLY_TASKS = ("Everything already saved is safe. New changes and running tasks can't be saved, so check "
                   "a task's result before running it again.")
READ_ONLY_WHEN = ("It works again as soon as an administrator makes the database writable; Help and "
                  "diagnostics shows where it is.")
READ_ONLY_ALTERNATIVE = "Meanwhile, you can still read and export what you need."
READ_ONLY_REFUSAL = (READ_ONLY_TITLE + " Nothing was changed. Everything already saved is safe and can still be "
                     "read; try again once an administrator makes the database writable.")


def connector_notice(items: list[dict]) -> dict[str, Any] | None:
    """The banner for connections that can't be used (from the Connections
    attention list: expired sign-in, failed check), or ``None``."""
    names = [str(item.get("title") or item.get("name") or "") for item in items or ()]
    names = [name for name in names if name]
    if not names:
        return None
    affected = " and ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
    return {"level": "connector", "kind": "connector", "affected": affected,
            "title": f"{affected} can't be used right now.", "tasks": CONNECTOR_TASKS,
            "when": CONNECTOR_WHEN, "alternative": CONNECTOR_ALTERNATIVE,
            "link": {"href": "/connections", "label": "Review in Connections"}}


def _world_writable() -> bool:
    """Whether the built-in world database (and its folder) can be written."""
    import os

    from .world_model import default_db_path
    from .world_model_backends import is_postgres_configured

    if is_postgres_configured():
        return True  # the database server reports its own state
    path = default_db_path()
    folder = path.parent
    if path.exists():
        return os.access(path, os.W_OK) and os.access(folder, os.W_OK)
    return not folder.exists() or os.access(folder, os.W_OK)


def database_notice() -> dict[str, Any] | None:
    """The banner while the world database is read-only, or ``None``."""
    try:
        if _world_writable():
            return None
    except Exception:  # noqa: BLE001 -- an unknown state shows no banner
        log.debug("database status unavailable", exc_info=True)
        return None
    return {"level": "down", "kind": "database", "title": READ_ONLY_TITLE, "tasks": READ_ONLY_TASKS,
            "when": READ_ONLY_WHEN, "alternative": READ_ONLY_ALTERNATIVE,
            "link": {"href": "/help", "label": "Open Help and diagnostics"}}


def is_read_only_error(exc: BaseException) -> bool:
    """A write refused because the database or its disk is read-only."""
    text = str(exc).lower()
    return type(exc).__name__ == "OperationalError" and (
        "readonly database" in text or "read-only file system" in text or "read-only database" in text)


def safe_current() -> dict[str, Any] | None:
    """:func:`current` for page rendering: a fault never breaks a page."""
    try:
        return current()
    except Exception:  # noqa: BLE001 -- the banner is advisory
        log.debug("service status unavailable", exc_info=True)
        return None


__all__ = ["ALTERNATIVE_DOWN", "ALTERNATIVE_REDUCED", "CONNECTOR_ALTERNATIVE", "CONNECTOR_TASKS", "CONNECTOR_WHEN",
           "READ_ONLY_ALTERNATIVE", "READ_ONLY_REFUSAL", "READ_ONLY_TASKS", "READ_ONLY_TITLE", "READ_ONLY_WHEN",
           "TASKS_DOWN", "TASKS_REDUCED", "connector_notice", "current", "database_notice", "is_read_only_error",
           "provider_name", "providers_in_use", "safe_current"]
