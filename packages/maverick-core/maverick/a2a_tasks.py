"""A2A task lifecycle: the execution half of A2A (discovery lives in
``a2a.py``).

Implements the A2A 0.3 JSON-RPC task surface over a single ``POST
/a2a/v1`` endpoint, mounted on the dashboard FastAPI app by
``a2a.mount()`` when A2A is enabled:

  - ``message/send``     run a goal to completion, return the final Task.
  - ``message/stream``   same, but stream Task / status-update /
                         artifact-update events over SSE.
  - ``tasks/get``        fetch a task (status + message + state history).
  - ``tasks/cancel``     best-effort cancel (marks terminal; an already
                         in-flight goal isn't force-killed).
  - ``tasks/pushNotificationConfig/set|get``  register a webhook that
                         receives the Task when it reaches a terminal state.

Spec shapes follow https://a2a-protocol.org/v0.3.0/specification/: Task ``kind="task"``,
``status.state`` in {submitted, working, completed, failed, canceled,
rejected}, and ``status-update`` / ``artifact-update`` stream events.

Security — this surface is outward-facing and spends real provider
budget, so by default it requires bearer auth: set ``MAVERICK_A2A_TOKEN``
and callers must send ``Authorization: Bearer <token>``. For a trusted
localhost you can run it open with
``MAVERICK_A2A_ALLOW_UNAUTHENTICATED=1``. Client-supplied budget is always
clamped to operator ceilings (``MAVERICK_A2A_MAX_DOLLARS`` /
``_MAX_WALL_SECONDS`` / ``_MAX_DEPTH``), and the prompt is screened by the
safety shield when installed (fail-open).
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, RLock
from typing import Any

log = logging.getLogger(__name__)

# The resolved trust-registry id of the current A2A caller (set per task from
# its principal; read by _a2a_capability to apply that caller's ceiling). A
# contextvar so it propagates into the worker thread (asyncio.to_thread copies
# the context) without threading it through the fixed Runner signature.
_caller_agent: ContextVar[str | None] = ContextVar("a2a_caller_agent", default=None)
# The exact trust-policy snapshot used for the execution-time admission check.
# It is propagated into ``asyncio.to_thread`` with the caller id so the
# capability ceiling cannot observe a different registry/config generation
# after a queued task has already crossed the gate.
_caller_trust_state: ContextVar[tuple[bool, dict[str, Any]] | None] = ContextVar(
    "a2a_caller_trust_state", default=None,
)


def _agent_id_of(principal: str | None) -> str | None:
    """The registry agent id behind a principal, or ``None`` for shared/anon."""
    if principal and principal.startswith("agent:"):
        return principal[len("agent:"):]
    return None

TERMINAL_STATES = {"completed", "failed", "canceled", "rejected"}


def _a2a_value(env: str, key: str, default: object = None) -> object:
    """``env`` when set, else ``[a2a] <key>`` (settable on the dashboard's All
    settings page), else ``default``."""
    raw = os.environ.get(env)
    if raw is not None and raw.strip() != "":
        return raw
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("a2a") or {}
    except Exception:
        return default
    value = cfg.get(key) if isinstance(cfg, dict) else None
    return default if value is None else value


def _a2a_flag(env: str, key: str) -> bool:
    value = _a2a_value(env, key, False)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value is True


def _max_tasks() -> int:
    try:
        return max(16, int(_a2a_value("MAVERICK_A2A_MAX_TASKS", "max_tasks", 1000)))
    except (TypeError, ValueError):
        return 1000


_MAX_TASKS = _max_tasks()


def _max_concurrency() -> int:
    """Max A2A goals that may execute concurrently. Default small (4) so one
    caller can't saturate the process-wide default ThreadPoolExecutor (which
    asyncio.to_thread uses) with long-running goals and stall every other
    to_thread consumer in the dashboard process. 0 disables the cap."""
    try:
        return max(0, int(_a2a_value("MAVERICK_A2A_MAX_CONCURRENCY", "max_concurrency", 4)))
    except (TypeError, ValueError):
        return 4


# One semaphore per running event loop. The engine is constructed once at
# mount, but a Semaphore must be awaited on the loop it was created on; keying
# by the running loop keeps this correct across the test harness's per-call
# loops and under a single long-lived server loop in production. The map is
# bounded so a churn of short-lived loops can't leak entries -- a missing entry
# just recreates the (cheap) semaphore for the current loop.
_RUN_SEM_LOCK = Lock()
_RUN_SEMAPHORES: dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}
_RUN_SEM_MAX_LOOPS = 64


def _run_semaphore() -> asyncio.Semaphore | None:
    """The concurrency limiter for the current event loop, or None when the
    cap is disabled (MAVERICK_A2A_MAX_CONCURRENCY=0)."""
    limit = _max_concurrency()
    if limit <= 0:
        return None
    loop = asyncio.get_running_loop()
    with _RUN_SEM_LOCK:
        sem = _RUN_SEMAPHORES.get(loop)
        if sem is None:
            if len(_RUN_SEMAPHORES) >= _RUN_SEM_MAX_LOOPS:
                # Sweep semaphores bound to loops that have closed; drop the
                # oldest if none are reclaimable so the map stays bounded.
                for stale in [lp for lp in _RUN_SEMAPHORES if lp.is_closed()]:
                    _RUN_SEMAPHORES.pop(stale, None)
                while len(_RUN_SEMAPHORES) >= _RUN_SEM_MAX_LOOPS:
                    _RUN_SEMAPHORES.pop(next(iter(_RUN_SEMAPHORES)))
            sem = asyncio.Semaphore(limit)
            _RUN_SEMAPHORES[loop] = sem
    return sem


@contextlib.asynccontextmanager
async def _run_slot() -> AsyncIterator[None]:
    """Hold a concurrency slot for the duration of a goal run, or admit freely
    when the cap is disabled. Sized by MAVERICK_A2A_MAX_CONCURRENCY (default 4)."""
    sem = _run_semaphore()
    if sem is None:
        yield
        return
    async with sem:
        yield

# JSON-RPC error codes used by the engine (-32000..-32099 is the
# server-defined range; the standard codes like parse/invalid-request are
# emitted as literals at the HTTP boundary in a2a.py).
_INVALID_PARAMS = -32602
_AUTH_REQUIRED = -32001
_TASK_NOT_FOUND = -32002
_SERVER_BUSY = -32003
_MAX_MESSAGE_ID_LENGTH = 256
_MAX_REQUEST_RETAINED_BYTES = 64 * 1024
_MAX_ARTIFACT_TEXT_BYTES = 128 * 1024
_MAX_TASK_RETAINED_BYTES = 192 * 1024
_MAX_TOTAL_RETAINED_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_NAME_BYTES = 256
_MAX_PUSH_URL_BYTES = 4096
_MAX_PUSH_TOKEN_BYTES = 4096
_PUSH_CONFIG_FIELDS = frozenset({"url", "token"})
_MAX_DURABLE_CLAIMS = 100_000
_MAX_DURABLE_SNAPSHOT_BYTES = 256 * 1024
_MAX_DURABLE_STORED_SNAPSHOT_BYTES = 384 * 1024
_MAX_DURABLE_RETAINED_BYTES = 64 * 1024 * 1024


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


@contextlib.contextmanager
def _task_tenant_scope(tenant: str):
    """Pin a captured task tenant while its async execution is active."""
    from .paths import reset_tenant, set_tenant

    token = set_tenant(tenant or None)
    try:
        yield
    finally:
        reset_tenant(token)


def _text_parts(text: str) -> list[dict]:
    return [{"kind": "text", "text": text}]


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _truncate_utf8(value: Any, limit: int, *, marker: str = "\n[truncated]") -> str:
    """Return a valid UTF-8 prefix whose encoded size is at most ``limit``."""
    text = str(value or "")
    raw = text.encode("utf-8", errors="replace")
    text = raw.decode("utf-8")
    if len(raw) <= limit:
        return text
    if limit <= 0:
        return ""
    suffix = marker.encode("utf-8")
    if len(suffix) > limit:
        suffix = b""
    prefix = raw[: limit - len(suffix)].decode("utf-8", errors="ignore")
    return prefix + suffix.decode("utf-8")


def _artifact_for_budget(
    text: Any, name: Any, max_bytes: int,
) -> tuple[dict, int] | None:
    """Build the largest artifact that fits an exact serialized-byte budget."""
    if max_bytes <= 0:
        return None
    bounded_name = _truncate_utf8(name, _MAX_ARTIFACT_NAME_BYTES, marker="")
    bounded_text = _truncate_utf8(text, _MAX_ARTIFACT_TEXT_BYTES)

    def build(candidate: str) -> tuple[dict, int]:
        artifact = {
            "artifactId": _new_id(),
            "name": bounded_name,
            "parts": _text_parts(candidate),
        }
        return artifact, len(_json_bytes(artifact))

    artifact, size = build(bounded_text)
    if size <= max_bytes:
        return artifact, size

    # JSON escaping can make serialized size larger than raw UTF-8 size. Binary
    # search the prefix budget and measure the actual retained representation.
    source = bounded_text
    high = len(source.encode("utf-8"))
    low = 0
    best: tuple[dict, int] | None = None
    while low <= high:
        middle = (low + high) // 2
        candidate = _truncate_utf8(source, middle, marker="")
        current, current_size = build(candidate)
        if current_size <= max_bytes:
            best = current, current_size
            low = middle + 1
        else:
            high = middle - 1
    return best


def _message_text(message: dict) -> str:
    """Concatenate the text parts of an A2A Message.

    Defensive about a hostile client's shape: ``parts`` may be any JSON value
    (a string/number, not a list) and its items may be non-objects, so this
    must not assume a list of dicts — otherwise iterating a string or calling
    ``.get`` on a non-dict raises out of the task runner (a 500 / DoS)."""
    parts = message.get("parts")
    if not isinstance(parts, list):
        return ""
    chunks = [
        p.get("text", "") for p in parts
        if isinstance(p, dict) and p.get("kind") == "text"
    ]
    return "\n".join(c for c in chunks if c).strip()


def _bounded_float(value: Any, *, default: float, ceiling: Any) -> float:
    """Clamp a client-supplied number to [0, ceiling]; fall back on junk."""
    try:
        v = float(value)
        cap = float(ceiling)
    except (TypeError, ValueError):
        return default
    if v != v or v < 0:  # NaN or negative
        return default
    return min(v, cap)


def _bounded_int(value: Any, *, default: int, ceiling: Any) -> int:
    return int(_bounded_float(value, default=float(default), ceiling=ceiling))


def _redacted_push_config(cfg: dict | None) -> dict | None:
    """Mask the push-notification ``token`` for read-back.

    The token is a write-only secret an A2A caller registers so it can
    authenticate the callbacks we POST to its webhook. Echoing it back from
    ``get_push_config`` would let a peer that shares the (single) A2A bearer
    token read another caller's webhook secret. Mask it to a fixed marker so
    the owner can still tell that a token is configured; the real value stays
    in storage for ``_fire_push``.
    """
    if not cfg or "token" not in cfg:
        return cfg
    redacted = dict(cfg)
    redacted["token"] = "***"
    return redacted


# Runner signature: (text, *, max_dollars, max_wall, max_depth) -> result str.
Runner = Callable[..., str]


def _a2a_capability() -> Any:
    """Tool ceiling for A2A-initiated goals.

    A2A is a remote, machine-to-machine surface, so its goals run under a
    capability instead of inheriting full local tool access. Defaults to
    ``max_risk="medium"`` -- high-risk tools (shell / code_exec / write / send /
    infra, plus the unclassified MCP tools that now default to high) are off
    unless an operator opts in. Configurable via the ``[a2a]`` config section
    (``max_risk``, ``tools`` allowlist, ``deny_tools``) with a
    ``MAVERICK_A2A_MAX_RISK`` env override; set the risk to ``none``/``off`` to
    lift the ceiling entirely (the prior behaviour).
    """
    from .capability import Capability
    from .safety.tool_risk import RISK_LEVELS

    try:
        from .config import config_source_errors, load_config

        loaded = load_config() or {}
        if config_source_errors():
            raise RuntimeError("A2A capability config source is unreadable")
        cfg = loaded.get("a2a") or {}
        if not isinstance(cfg, dict):
            raise RuntimeError("A2A capability policy must be a table")
    except Exception as e:
        # Losing an allowlist/denylist while executing a remote task can widen
        # access even though the generic risk ceiling remains "medium".
        raise RuntimeError("A2A capability policy unavailable") from e

    # Blank counts as unset, as for every other A2A setting: a compose or unit
    # file that passes the variable through empty must not lift the ceiling.
    raw = os.environ.get("MAVERICK_A2A_MAX_RISK", "").strip()
    if not raw:
        raw = cfg.get("max_risk", "medium")
    raw = str(raw).strip().lower()
    if not raw:
        raw = "medium"
    if raw in ("none", "off", "any", "unlimited"):
        max_risk: str | None = None
    elif raw in RISK_LEVELS:
        max_risk = raw
    else:
        max_risk = "medium"  # unrecognized value -> safe default

    def _names(cfg_key: str, env_key: str) -> frozenset[str]:
        vals = cfg.get(cfg_key)
        if vals is None:
            vals = os.environ.get(env_key, "").split(",")
        if isinstance(vals, str):
            vals = [vals]
        if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals):
            raise RuntimeError(f"A2A {cfg_key} policy must be a list of names")
        return frozenset(v.strip() for v in vals if v.strip())

    cap = Capability(
        principal="a2a",
        allow_tools=_names("tools", "MAVERICK_A2A_TOOLS"),
        deny_tools=_names("deny_tools", "MAVERICK_A2A_DENY_TOOLS"),
        max_risk=max_risk,
    )
    # When the Agent Trust Plane is engaged, the caller's [agent_trust] entry
    # tightens this ceiling (intersection, never a broadening). A per-caller
    # bearer resolves to that caller's own entry (via the _caller_agent
    # contextvar); a shared-bearer/anon caller falls back to the surface-wide
    # "a2a" entry. Admission itself is gated separately by _a2a_trust_block.
    try:
        from . import agent_trust

        trust_state = _caller_trust_state.get()
        if trust_state is None:
            trust_state = agent_trust.load_trust_state()
        enforced, registry = trust_state
        if enforced:
            caller = _caller_agent.get()
            entry = agent_trust.lookup(caller, registry=registry) if caller else None
            if entry is None:
                entry = agent_trust.lookup("a2a", registry=registry)
            if entry is not None:
                cap = cap.intersect(entry.capability(principal="a2a"),
                                    principal="a2a")
    except Exception as e:
        # This is a remote execution boundary. If an enabled trust ceiling
        # cannot be read, abort before the runner starts rather than widening to
        # the generic A2A capability.
        raise RuntimeError("A2A agent trust policy unavailable") from e
    return cap


def _a2a_trust_block(
    principal: str = "anon",
    *,
    trust_state: tuple[bool, dict[str, Any]] | None = None,
) -> str | None:
    """Default-deny admission for the A2A surface when the plane is engaged.

    Gates on the CALLER's registry entry: a per-caller bearer (principal
    ``agent:<id>``) is governed by that agent's entry; a shared-bearer/anon
    caller falls back to the surface-wide ``"a2a"`` entry. So engaging the plane
    does not leave A2A open at its medium ceiling to anyone with the bearer (the
    prior tighten-only, fail-open gap). Returns ``None`` (admit) when disengaged.
    """
    try:
        from . import agent_trust
        if trust_state is None:
            trust_state = agent_trust.load_trust_state()
        enforced, registry = trust_state
    except Exception:
        return "agent trust policy unavailable"
    if not enforced:
        return None
    agent_id = _agent_id_of(principal) or "a2a"
    decision = agent_trust.decide_inbound(agent_id, registry=registry, enforced=True)
    if decision.denied:
        agent_trust.record_denied(agent_id, decision, direction="inbound")
        return decision.reason
    return None


def _default_runner(
    text: str, *, max_dollars: float, max_wall: float, max_depth: int,
) -> str:
    """Run a goal through the real orchestrator and return its result."""
    from .budget import Budget
    from .llm import LLM
    from .orchestrator import run_goal_sync
    from .sandbox import build_sandbox
    from .world_model import close_world_if_owned, open_world

    budget = Budget(max_dollars=max_dollars, max_wall_seconds=max_wall)
    world = open_world()
    try:
        goal_id = world.create_goal(text[:120] or "a2a task", text)
        llm = LLM()
        sandbox = build_sandbox()
        # A2A goals run under a tool ceiling (default max_risk="medium") so a remote
        # caller can't reach full local tool access; see _a2a_capability.
        return run_goal_sync(
            llm, world, budget, goal_id, sandbox=sandbox, max_depth=max_depth,
            capability=_a2a_capability(),
        )
    finally:
        close_world_if_owned(world)


class _Task:
    """Task record with status + state-transition history.

    The live object remains in memory for the low-latency single-process path.
    A mounted A2A service additionally serializes a bounded copy through
    :class:`_DurableTaskStore` before execution and after each transition.
    """

    def __init__(self, context_id: str, user_message: dict, *, tenant: str = ""):
        self.id = _new_id()
        self.context_id = context_id or _new_id()
        self.created_at = _now_iso()
        self.state = "submitted"
        self.status_history: list[dict] = [
            {"state": "submitted", "timestamp": self.created_at}
        ]
        self.messages: list[dict] = [user_message]
        self.artifacts: list[dict] = []
        self.push_config: dict | None = None
        self.cancel_requested = False
        # Principal that created the task; get/cancel/push-config are scoped to
        # it so one A2A caller can't read/cancel/redirect another's task.
        self.principal: str = ""
        # Raw tenant id captured at admission. Never re-resolve this while a
        # task is running: an async context may later be reset or reused.
        self.tenant: str = tenant
        # Client-requested budget captured at creation, clamped to the operator
        # ceiling at run time (see TaskEngine._limits).
        self.budget_request: dict = {}
        # Present only for caller-supplied messageId values. Used to remove the
        # dedupe index entry when this task is eventually evicted.
        self.idempotency_key: tuple[str, str, str] | None = None
        self.request_digest: str = ""
        # Exact retained request/artifact bytes charged to the engine-wide
        # ceiling. Push configuration has its own strict field bounds.
        self.retained_bytes = 0

    def set_state(self, state: str) -> dict:
        self.state = state
        entry = {"state": state, "timestamp": _now_iso()}
        self.status_history.append(entry)
        return entry

    def add_artifact(self, text: str, name: str = "result") -> dict:
        fitted = _artifact_for_budget(
            text, name, _MAX_TASK_RETAINED_BYTES - self.retained_bytes,
        )
        if fitted is None:
            return {}
        art, size = fitted
        self.artifacts.append(art)
        self.retained_bytes += size
        return art

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "contextId": self.context_id,
            "status": {
                "state": self.state,
                "timestamp": self.status_history[-1]["timestamp"],
            },
            "artifacts": list(self.artifacts),
            "history": list(self.messages),
            "kind": "task",
            # stateTransitionHistory capability: expose the recorded
            # status timeline so clients can audit how the task progressed.
            "metadata": {"statusHistory": list(self.status_history)},
        }

    def durable_snapshot(self) -> str:
        """Return the bounded, secret-minimal durable representation.

        Push-notification bearer tokens intentionally remain process-local.
        Persisting them in a general task database would turn a task-history
        feature into a credential vault without the vault's sealing contract.
        """
        payload = {
            "version": 1,
            "id": self.id,
            "context_id": self.context_id,
            "created_at": self.created_at,
            "state": self.state,
            "status_history": self.status_history,
            "messages": self.messages,
            "artifacts": self.artifacts,
            "budget_request": self.budget_request,
            "cancel_requested": self.cancel_requested,
            "retained_bytes": self.retained_bytes,
        }
        encoded = _json_bytes(payload)
        if len(encoded) > _MAX_DURABLE_SNAPSHOT_BYTES:
            raise ValueError("A2A durable task snapshot exceeds its byte limit")
        return encoded.decode("utf-8")

    @classmethod
    def from_durable_snapshot(
        cls,
        snapshot: str,
        *,
        task_id: str,
        tenant: str,
        principal: str,
        message_key: str,
        request_digest: str,
    ) -> _Task:
        """Hydrate a terminal task, rejecting corrupt/tampered state."""
        if not isinstance(snapshot, str):
            raise ValueError("invalid A2A durable task snapshot")
        encoded = snapshot.encode("utf-8")
        if len(encoded) > _MAX_DURABLE_SNAPSHOT_BYTES:
            raise ValueError("A2A durable task snapshot exceeds its byte limit")
        payload = json.loads(snapshot)
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("invalid A2A durable task snapshot version")
        state = payload.get("state")
        history = payload.get("status_history")
        messages = payload.get("messages")
        artifacts = payload.get("artifacts")
        budget_request = payload.get("budget_request")
        if state not in TERMINAL_STATES:
            raise ValueError("durable A2A result is not terminal")
        if (
            payload.get("id") != task_id
            or not isinstance(payload.get("context_id"), str)
            or not isinstance(payload.get("created_at"), str)
            or not isinstance(history, list)
            or not history
            or not isinstance(history[-1], dict)
            or history[-1].get("state") != state
            or not isinstance(messages, list)
            or not messages
            or not isinstance(messages[0], dict)
            or not isinstance(messages[0].get("messageId"), str)
            or not hmac.compare_digest(
                hashlib.sha256(
                    messages[0]["messageId"].encode("utf-8")
                ).hexdigest(),
                message_key,
            )
            or not isinstance(artifacts, list)
            or not isinstance(budget_request, dict)
            or not isinstance(payload.get("cancel_requested"), bool)
            or not isinstance(payload.get("retained_bytes"), int)
        ):
            raise ValueError("invalid A2A durable task snapshot shape")
        # Re-encode the parsed value to reject NaN/non-JSON mutations and
        # independently verify the exact accounting convention used at
        # admission + artifact retention.
        retained_bytes = len(_json_bytes({
            "history": messages,
            "budgetRequest": budget_request,
        }))
        retained_bytes += sum(len(_json_bytes(artifact)) for artifact in artifacts)
        if (
            payload["retained_bytes"] != retained_bytes
            or retained_bytes < 0
            or retained_bytes > _MAX_TASK_RETAINED_BYTES
        ):
            raise ValueError("invalid A2A durable retained-byte accounting")

        task = cls.__new__(cls)
        task.id = task_id
        task.context_id = payload["context_id"]
        task.created_at = payload["created_at"]
        task.state = state
        task.status_history = history
        task.messages = messages
        task.artifacts = artifacts
        task.push_config = None
        task.cancel_requested = payload["cancel_requested"]
        task.principal = principal
        task.tenant = tenant
        task.budget_request = budget_request
        task.idempotency_key = (tenant, principal, messages[0]["messageId"])
        task.request_digest = request_digest
        task.retained_bytes = retained_bytes
        return task


class _DurableTaskStore:
    """Tenant-bound, cross-process authority for A2A task idempotency.

    A claim is inserted under ``BEGIN IMMEDIATE`` before any runner is invoked.
    Terminal snapshots can be replayed by a restarted worker. A row left
    ``in_progress`` by a crash is never reclaimed automatically: its external
    side effects are unknowable, so another worker must refuse re-execution.
    When the bounded snapshot budget is full, old terminal bodies become
    ``tombstone`` rows; their message ids remain permanently consumed.
    """

    def __init__(self, path: Path | None = None):
        self._path_override = Path(path).expanduser() if path is not None else None

    @staticmethod
    def _message_key(message_id: str) -> str:
        # messageId is caller-controlled and may accidentally carry PII. The
        # ledger needs equality only, so retain a fixed digest outside the
        # optionally encrypted snapshot rather than the raw identifier.
        return hashlib.sha256(message_id.encode("utf-8")).hexdigest()

    def _path(self, tenant: str) -> Path:
        if self._path_override is not None:
            return self._path_override
        from .paths import data_dir

        return data_dir("a2a", "tasks.sqlite3", tenant=tenant or None)

    @staticmethod
    def _encode_snapshot(tenant: str, snapshot: str) -> str:
        """Honor the deployment's at-rest policy for sensitive task bodies."""
        with _task_tenant_scope(tenant):
            from .crypto_at_rest import at_rest_enabled, seal_to_str

            stored = seal_to_str(snapshot) if at_rest_enabled() else snapshot
        if len(stored.encode("utf-8")) > _MAX_DURABLE_STORED_SNAPSHOT_BYTES:
            raise ValueError("stored A2A durable task snapshot exceeds its byte limit")
        return stored

    @staticmethod
    def _decode_snapshot(tenant: str, stored: str) -> str:
        """Open a sealed snapshot; never expose plaintext under encryption."""
        if not isinstance(stored, str):
            raise ValueError("invalid stored A2A durable task snapshot")
        if len(stored.encode("utf-8")) > _MAX_DURABLE_STORED_SNAPSHOT_BYTES:
            raise ValueError("stored A2A durable task snapshot exceeds its byte limit")
        with _task_tenant_scope(tenant):
            from .crypto_at_rest import (
                at_rest_enabled,
                is_sealed_str,
                unseal_from_str,
            )

            sealed = is_sealed_str(stored)
            if at_rest_enabled() and not sealed:
                raise ValueError(
                    "unsealed A2A snapshot found while at-rest encryption is enabled"
                )
            return unseal_from_str(stored) if sealed else stored

    @contextlib.contextmanager
    def _connect(self, tenant: str):
        from .file_lock import ensure_private_directory, ensure_private_file

        path = self._path(tenant)
        ensure_private_directory(path.parent)
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            ensure_private_file(path, 0o600)
        else:
            os.close(fd)
            ensure_private_file(path, 0o600)

        conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA secure_delete=ON")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS a2a_task_claims (
                    tenant TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    message_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('in_progress', 'terminal', 'tombstone')
                    ),
                    snapshot_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant, principal, message_key),
                    UNIQUE (tenant, task_id)
                );
                CREATE INDEX IF NOT EXISTS a2a_task_claims_lookup
                    ON a2a_task_claims(tenant, principal, task_id);
                CREATE INDEX IF NOT EXISTS a2a_task_claims_prune
                    ON a2a_task_claims(tenant, status, updated_at);
                CREATE TABLE IF NOT EXISTS a2a_task_meta (
                    tenant TEXT PRIMARY KEY,
                    claim_count INTEGER NOT NULL,
                    snapshot_bytes INTEGER NOT NULL
                );
            """)
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _ensure_meta(conn: sqlite3.Connection, tenant: str) -> tuple[int, int]:
        conn.execute(
            "INSERT OR IGNORE INTO a2a_task_meta(tenant, claim_count, snapshot_bytes) "
            "SELECT ?, COUNT(*), COALESCE(SUM("
            "CASE WHEN snapshot_json IS NULL THEN 0 "
            "ELSE length(CAST(snapshot_json AS BLOB)) END), 0) "
            "FROM a2a_task_claims WHERE tenant = ?",
            (tenant, tenant),
        )
        row = conn.execute(
            "SELECT claim_count, snapshot_bytes FROM a2a_task_meta WHERE tenant = ?",
            (tenant,),
        ).fetchone()
        if row is None:
            raise ValueError("A2A durable task accounting unavailable")
        count, retained = int(row[0]), int(row[1])
        if count < 0 or retained < 0 or retained > _MAX_DURABLE_RETAINED_BYTES:
            raise ValueError("invalid A2A durable task accounting")
        return count, retained

    @staticmethod
    def _make_snapshot_room(
        conn: sqlite3.Connection,
        tenant: str,
        *,
        retained: int,
        old_size: int,
        new_size: int,
        exclude_task_id: str = "",
    ) -> int | None:
        target = retained - old_size + new_size
        while target > _MAX_DURABLE_RETAINED_BYTES:
            row = conn.execute(
                "SELECT task_id, length(CAST(snapshot_json AS BLOB)) AS size "
                "FROM a2a_task_claims "
                "WHERE tenant = ? AND status = 'terminal' "
                "AND snapshot_json IS NOT NULL AND task_id != ? "
                "ORDER BY updated_at ASC LIMIT 1",
                (tenant, exclude_task_id),
            ).fetchone()
            if row is None:
                return None
            size = int(row["size"] or 0)
            conn.execute(
                "UPDATE a2a_task_claims SET status = 'tombstone', "
                "snapshot_json = NULL WHERE tenant = ? AND task_id = ? "
                "AND status = 'terminal'",
                (tenant, str(row["task_id"])),
            )
            retained = max(0, retained - size)
            target = retained - old_size + new_size
        return target

    def claim(
        self,
        task: _Task,
        *,
        message_id: str,
        request_digest: str,
    ) -> tuple[str, _Task | None]:
        snapshot = self._encode_snapshot(task.tenant, task.durable_snapshot())
        snapshot_size = len(snapshot.encode("utf-8"))
        message_key = self._message_key(message_id)
        now = time.time()
        with self._connect(task.tenant) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT request_digest, task_id, status, snapshot_json "
                "FROM a2a_task_claims WHERE tenant = ? AND principal = ? "
                "AND message_key = ?",
                (task.tenant, task.principal, message_key),
            ).fetchone()
            if row is not None:
                original_digest = str(row["request_digest"])
                if not hmac.compare_digest(original_digest, request_digest):
                    return "conflict", None
                status = str(row["status"])
                if status == "in_progress":
                    return "indeterminate", None
                if status == "tombstone":
                    return "tombstone", None
                if status != "terminal" or row["snapshot_json"] is None:
                    raise ValueError("invalid A2A durable task status")
                snapshot = self._decode_snapshot(
                    task.tenant, str(row["snapshot_json"]),
                )
                cached = _Task.from_durable_snapshot(
                    snapshot,
                    task_id=str(row["task_id"]),
                    tenant=task.tenant,
                    principal=task.principal,
                    message_key=message_key,
                    request_digest=request_digest,
                )
                return "cached", cached

            count, retained = self._ensure_meta(conn, task.tenant)
            if count >= _MAX_DURABLE_CLAIMS:
                return "capacity", None
            next_retained = self._make_snapshot_room(
                conn,
                task.tenant,
                retained=retained,
                old_size=0,
                new_size=snapshot_size,
            )
            if next_retained is None:
                # _make_snapshot_room may have selected terminal snapshots
                # before discovering that active rows alone fill the budget.
                # Roll the transaction back so their bodies and the metadata
                # counter remain one atomic accounting unit.
                conn.execute("ROLLBACK")
                return "capacity", None
            conn.execute(
                "INSERT INTO a2a_task_claims("
                "tenant, principal, message_key, request_digest, task_id, "
                "status, snapshot_json, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?, ?)",
                (
                    task.tenant,
                    task.principal,
                    message_key,
                    request_digest,
                    task.id,
                    snapshot,
                    now,
                    now,
                ),
            )
            conn.execute(
                "UPDATE a2a_task_meta SET claim_count = ?, snapshot_bytes = ? "
                "WHERE tenant = ?",
                (count + 1, next_retained, task.tenant),
            )
            return "owner", None

    def save(self, task: _Task) -> str:
        if task.idempotency_key is None or not task.request_digest:
            raise ValueError("durable A2A task is missing its claim identity")
        _tenant, _principal, message_id = task.idempotency_key
        message_key = self._message_key(message_id)
        snapshot = self._encode_snapshot(task.tenant, task.durable_snapshot())
        snapshot_size = len(snapshot.encode("utf-8"))
        new_status = "terminal" if task.state in TERMINAL_STATES else "in_progress"
        with self._connect(task.tenant) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT request_digest, status, snapshot_json "
                "FROM a2a_task_claims WHERE tenant = ? AND principal = ? "
                "AND message_key = ? AND task_id = ?",
                (task.tenant, task.principal, message_key, task.id),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                str(row["request_digest"]), task.request_digest,
            ):
                raise ValueError("durable A2A claim identity mismatch")
            old_status = str(row["status"])
            if old_status == "tombstone":
                return "tombstone"
            if old_status == "terminal" and new_status != "terminal":
                raise ValueError("durable A2A terminal state cannot be reopened")
            old_snapshot = row["snapshot_json"]
            old_size = (
                len(str(old_snapshot).encode("utf-8"))
                if old_snapshot is not None else 0
            )
            _count, retained = self._ensure_meta(conn, task.tenant)
            next_retained = self._make_snapshot_room(
                conn,
                task.tenant,
                retained=retained,
                old_size=old_size,
                new_size=snapshot_size,
                exclude_task_id=task.id,
            )
            if next_retained is None:
                if new_status != "terminal":
                    raise ValueError("A2A durable active-state capacity reached")
                # Preserve the no-replay claim even when the result body cannot
                # fit. The current caller still receives its in-memory result;
                # later retries get an explicit consumed-id refusal.
                conn.execute(
                    "UPDATE a2a_task_claims SET status = 'tombstone', "
                    "snapshot_json = NULL, updated_at = ? "
                    "WHERE tenant = ? AND principal = ? AND message_key = ? "
                    "AND task_id = ?",
                    (time.time(), task.tenant, task.principal, message_key, task.id),
                )
                actual_retained = int(conn.execute(
                    "SELECT COALESCE(SUM(CASE WHEN snapshot_json IS NULL THEN 0 "
                    "ELSE length(CAST(snapshot_json AS BLOB)) END), 0) "
                    "FROM a2a_task_claims WHERE tenant = ?",
                    (task.tenant,),
                ).fetchone()[0])
                conn.execute(
                    "UPDATE a2a_task_meta SET snapshot_bytes = ? WHERE tenant = ?",
                    (actual_retained, task.tenant),
                )
                return "tombstone"
            conn.execute(
                "UPDATE a2a_task_claims SET status = ?, snapshot_json = ?, "
                "updated_at = ? WHERE tenant = ? AND principal = ? "
                "AND message_key = ? AND task_id = ?",
                (
                    new_status,
                    snapshot,
                    time.time(),
                    task.tenant,
                    task.principal,
                    message_key,
                    task.id,
                ),
            )
            conn.execute(
                "UPDATE a2a_task_meta SET snapshot_bytes = ? WHERE tenant = ?",
                (next_retained, task.tenant),
            )
            return new_status

    def load(
        self, *, tenant: str, principal: str, task_id: str,
    ) -> tuple[str, _Task | None]:
        with self._connect(tenant) as conn:
            row = conn.execute(
                "SELECT message_key, request_digest, status, snapshot_json "
                "FROM a2a_task_claims WHERE tenant = ? AND principal = ? "
                "AND task_id = ?",
                (tenant, principal, task_id),
            ).fetchone()
        if row is None:
            return "missing", None
        status = str(row["status"])
        if status != "terminal":
            if status not in {"in_progress", "tombstone"}:
                raise ValueError("invalid A2A durable task status")
            return status, None
        if row["snapshot_json"] is None:
            raise ValueError("terminal A2A durable task has no snapshot")
        snapshot = self._decode_snapshot(tenant, str(row["snapshot_json"]))
        task = _Task.from_durable_snapshot(
            snapshot,
            task_id=task_id,
            tenant=tenant,
            principal=principal,
            message_key=str(row["message_key"]),
            request_digest=str(row["request_digest"]),
        )
        return "terminal", task


class TaskEngine:
    """Runs A2A tasks and tracks their lifecycle. FastAPI-agnostic so it
    can be unit-tested directly; ``a2a.mount`` adapts it to HTTP/SSE."""

    def __init__(
        self,
        runner: Runner | None = None,
        *,
        durable: bool = False,
        state_path: Path | None = None,
    ):
        self._runner: Runner = runner or _default_runner
        self._tasks: dict[str, _Task] = {}
        # A2A messageId is the protocol's idempotency key. Scope it to the
        # active tenant AND authenticated principal so unrelated callers may
        # use the same ID without sharing an idempotency namespace.
        # Values carry a canonical request digest to reject key reuse with
        # different content instead of returning the wrong task.
        self._message_index: dict[tuple[str, str, str], tuple[str, str]] = {}
        self._retained_bytes = 0
        self._lock = RLock()
        # Directly-constructed engines keep the historical in-memory behavior
        # unless durability is requested. The outward-facing mounted service
        # opts in unconditionally (see a2a._mount_task_endpoint).
        from .a2a_store import DurableTaskStore

        self._store = (
            DurableTaskStore(state_path)
            if durable or state_path is not None else None
        )

    # ---- auth + limits -------------------------------------------------

    def auth_error(self, authorization: str | None) -> dict | None:
        """Return a JSON-RPC error object if the request isn't authorised,
        else None.

        Two accepted credentials: the shared operator bearer
        (``MAVERICK_A2A_TOKEN``) and a per-caller ``[agent_trust] a2a_token``
        (which also establishes per-caller identity, see ``principal_for``).
        Bearer required unless ``MAVERICK_A2A_ALLOW_UNAUTHENTICATED`` and no
        token of either kind is configured."""
        env_token = str(_a2a_value("MAVERICK_A2A_TOKEN", "token", "") or "").strip()
        given = ""
        if authorization and authorization.startswith("Bearer "):
            given = authorization[len("Bearer "):].strip()
        per_caller = None
        if given:
            try:
                from . import agent_trust
                per_caller = agent_trust.agent_for_a2a_token(given)
            except Exception:  # pragma: no cover - never break auth on read error
                per_caller = None
        if not env_token and per_caller is None and not given:
            if _a2a_flag("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", "allow_unauthenticated"):
                block = _a2a_trust_block("anon")
                return (
                    _err(_AUTH_REQUIRED, f"refused by agent trust plane: {block}")
                    if block else None
                )
            return _err(
                _AUTH_REQUIRED,
                "A2A task endpoint requires auth: set MAVERICK_A2A_TOKEN, a "
                "per-caller [agent_trust] a2a_token (or "
                "MAVERICK_A2A_ALLOW_UNAUTHENTICATED=1 for trusted localhost).",
            )
        if not given:
            return _err(_AUTH_REQUIRED, "missing bearer token")
        if env_token and hmac.compare_digest(env_token.encode(), given.encode()):
            principal = "bearer:" + hashlib.sha256(given.encode()).hexdigest()
            block = _a2a_trust_block(principal)
            return (
                _err(_AUTH_REQUIRED, f"refused by agent trust plane: {block}")
                if block else None
            )
        if per_caller is not None:
            block = _a2a_trust_block(f"agent:{per_caller.id}")
            return (
                _err(_AUTH_REQUIRED, f"refused by agent trust plane: {block}")
                if block else None
            )
        return _err(_AUTH_REQUIRED, "invalid bearer token")

    @staticmethod
    def principal_for(authorization: str | None) -> str:
        """Derive a stable principal id for a request, used to scope tasks.

        A task is bound to its creator's principal at creation, and
        get/cancel/push-config reject a mismatch -- so one A2A caller cannot
        read, cancel, or redirect another caller's task.

        A per-caller ``[agent_trust] a2a_token`` resolves to the stable
        principal ``agent:<id>`` — real per-caller identity the trust plane
        governs individually. Otherwise the shared operator bearer maps all its
        callers to one ``bearer:<hash>`` principal (we never store the raw
        bearer), and an unauthenticated request is ``anon``."""
        if authorization and authorization.startswith("Bearer "):
            given = authorization[len("Bearer "):].strip()
            if given:
                try:
                    from . import agent_trust
                    agent = agent_trust.agent_for_a2a_token(given)
                    if agent is not None:
                        return f"agent:{agent.id}"
                except Exception:  # pragma: no cover - fall back to bearer hash
                    pass
                return "bearer:" + hashlib.sha256(given.encode()).hexdigest()
        return "anon"

    @staticmethod
    def _tenant_key() -> str:
        """Resolve the request tenant, failing closed if policy is unreadable."""
        try:
            from .paths import current_tenant_id

            return current_tenant_id() or ""
        except Exception as e:
            raise _RpcError(
                _SERVER_BUSY, "A2A tenant scope is unavailable",
            ) from e

    @staticmethod
    def _durable_error(message: str, error: Exception) -> _RpcError:
        log.exception("A2A durable task state failure", exc_info=error)
        return _RpcError(_SERVER_BUSY, message)

    def _cache_loaded_locked(self, task: _Task) -> None:
        """Best-effort cache of a durable terminal result under memory caps."""
        existing = self._tasks.get(task.id)
        if existing is not None:
            return
        if not self._make_room_locked(task.retained_bytes, new_task=True):
            return
        self._tasks[task.id] = task
        self._retained_bytes += task.retained_bytes
        if task.idempotency_key is not None:
            self._message_index[task.idempotency_key] = (
                task.id, task.request_digest,
            )

    def _revalidate_cached(self, task: _Task) -> _Task:
        """A cached object cannot hide lost authority or a pruned result."""
        if self._store is None:
            return task
        try:
            status, persisted = self._store.load(
                tenant=task.tenant, principal=task.principal, task_id=task.id,
            )
        except Exception as error:
            raise self._durable_error(
                "durable A2A task state is unavailable; refusing cached state", error,
            ) from error
        if status == "terminal" and persisted is not None:
            return persisted
        if status == "in_progress" and task.state not in TERMINAL_STATES:
            # This engine still owns its live object. Other engines have no
            # such object and continue to refuse indeterminate remote work.
            return task
        if status == "tombstone":
            raise _RpcError(_SERVER_BUSY, "task result is no longer retained, but its messageId remains consumed")
        raise _RpcError(_SERVER_BUSY, "cached A2A task authority is unavailable or indeterminate")

    def _owned(self, task_id: object, principal: str) -> _Task:
        """Look up a task and enforce principal ownership.

        Raises a 'task not found' error (not a distinct 'forbidden') for both a
        missing task and a cross-principal one, so a caller can't probe which
        ids exist that belong to someone else.

        Task ids are opaque strings; a hostile client can send a non-string
        ``id``/``taskId`` (a list/dict), which must resolve to 'not found'
        rather than blow up the dict lookup with an unhashable-key TypeError."""
        key = task_id if isinstance(task_id, str) else ""
        tenant = self._tenant_key()
        with self._lock:
            task = self._tasks.get(key)
            if (
                task is not None
                and task.principal == principal
                and task.tenant == tenant
            ):
                return self._revalidate_cached(task)
        if self._store is None or not key:
            raise _RpcError(_TASK_NOT_FOUND, "task not found")
        try:
            status, task = self._store.load(
                tenant=tenant, principal=principal, task_id=key,
            )
        except Exception as e:
            raise self._durable_error(
                "durable A2A task state is unavailable; refusing an ambiguous lookup",
                e,
            ) from e
        if status == "missing":
            raise _RpcError(_TASK_NOT_FOUND, "task not found")
        if status == "in_progress":
            raise _RpcError(
                _SERVER_BUSY,
                "task outcome is in progress or indeterminate on another worker; "
                "refusing an ambiguous operation",
            )
        if status == "tombstone":
            raise _RpcError(
                _SERVER_BUSY,
                "task result is no longer retained, but its messageId remains "
                "consumed and will not be re-executed",
            )
        if status != "terminal" or task is None:
            raise _RpcError(_SERVER_BUSY, "invalid durable A2A task state")
        with self._lock:
            self._cache_loaded_locked(task)
        return task

    def _limits(self, task: _Task | None = None) -> dict:
        """Resolve per-run limits, clamping the CLIENT request to the operator
        ceiling.

        The operator env vars are the hard ceiling; the A2A caller may request
        *less* via its message (captured in ``task.budget_request``). We pass
        the client value as ``value`` and the operator setting as ``ceiling`` so
        ``min(client, operator)`` clamps the request DOWN -- never up. Passing
        the same env var as both value and ceiling would make the ``min`` a
        tautology and ignore the client request. With no client value the run defaults to the operator ceiling."""
        req = task.budget_request if task else {}
        ceil_dollars = _a2a_value("MAVERICK_A2A_MAX_DOLLARS", "max_dollars", 5.0)
        ceil_wall = _a2a_value("MAVERICK_A2A_MAX_WALL_SECONDS", "max_wall_seconds", 3600.0)
        ceil_depth = _a2a_value("MAVERICK_A2A_MAX_DEPTH", "max_depth", 3)
        return {
            "max_dollars": _bounded_float(
                req.get("max_dollars", ceil_dollars),
                default=_bounded_float(ceil_dollars, default=5.0, ceiling=ceil_dollars),
                ceiling=ceil_dollars,
            ),
            "max_wall": _bounded_float(
                req.get("max_wall", ceil_wall),
                default=_bounded_float(ceil_wall, default=3600.0, ceiling=ceil_wall),
                ceiling=ceil_wall,
            ),
            "max_depth": _bounded_int(
                req.get("max_depth", ceil_depth),
                default=_bounded_int(ceil_depth, default=3, ceiling=ceil_depth),
                ceiling=ceil_depth,
            ),
        }

    @staticmethod
    def _client_budget(params: dict | None) -> dict:
        """Extract a client-requested budget from the request params.

        A2A callers carry per-call budget hints in ``params.configuration`` and
        /or the message ``metadata``; we read a small explicit set of keys.
        Absent / junk values simply don't appear here and fall back to the
        operator ceiling in ``_limits`` -- and whatever the client asks for is
        still clamped DOWN to the ceiling there, never up."""
        params = params or {}
        sources: list[dict] = []
        cfg = params.get("configuration")
        if isinstance(cfg, dict):
            sources.append(cfg)
        msg = params.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("metadata"), dict):
            sources.append(msg["metadata"])
        out: dict = {}
        for src in sources:
            for key in ("max_dollars", "max_wall", "max_depth"):
                if key in src and key not in out:
                    out[key] = src[key]
        return out

    def _shield_block(self, text: str) -> str | None:
        """Return a reason string if the shield blocks the input, else None.

        Delegates to :func:`maverick.shield_policy.scan_block`: a scan error
        blocks (fail-toward-gate), and a *missing* shield blocks only when the
        shield is required (enterprise / [safety] require_shield) — so an
        outward-facing A2A surface can't silently admit unscreened input on a
        regulated deployment, while personal installs keep the fail-open default.
        """
        from .shield_policy import scan_block
        return scan_block(text)

    # ---- task helpers --------------------------------------------------

    def _evict_terminal_locked(self, *, exclude: _Task | None = None) -> bool:
        evict_id = next(
            (
                task_id
                for task_id, old in self._tasks.items()
                if old is not exclude and old.state in TERMINAL_STATES
            ),
            None,
        )
        if evict_id is None:
            return False
        evicted = self._tasks.pop(evict_id)
        self._retained_bytes = max(
            0, self._retained_bytes - evicted.retained_bytes,
        )
        if evicted.idempotency_key is not None:
            self._message_index.pop(evicted.idempotency_key, None)
        return True

    def _make_room_locked(
        self, incoming_bytes: int, *, new_task: bool, exclude: _Task | None = None,
    ) -> bool:
        """Evict terminal records until count and retained-byte caps fit."""
        while (
            (new_task and len(self._tasks) >= _MAX_TASKS)
            or self._retained_bytes + incoming_bytes > _MAX_TOTAL_RETAINED_BYTES
        ):
            if not self._evict_terminal_locked(exclude=exclude):
                return False
        return True

    def _add_artifact(
        self, task: _Task, text: Any, name: str = "result",
    ) -> dict | None:
        """Retain a bounded artifact while enforcing the engine-wide ceiling."""
        with self._lock:
            remaining = _MAX_TASK_RETAINED_BYTES - task.retained_bytes
            fitted = _artifact_for_budget(text, name, remaining)
            if fitted is None:
                return None
            artifact, size = fitted
            if not self._make_room_locked(size, new_task=False, exclude=task):
                # All retained bytes belong to active tasks. Do not exceed the
                # global cap merely to preserve a result body.
                available = min(
                    remaining,
                    max(0, _MAX_TOTAL_RETAINED_BYTES - self._retained_bytes),
                )
                fitted = _artifact_for_budget(text, name, available)
                if fitted is None:
                    return None
                artifact, size = fitted
            task.artifacts.append(artifact)
            task.retained_bytes += size
            self._retained_bytes += size
            return artifact

    @staticmethod
    def _mark_canceled(task: _Task) -> None:
        task.cancel_requested = True
        if task.state not in TERMINAL_STATES:
            task.set_state("canceled")

    def _persist_task(self, task: _Task) -> None:
        if self._store is None:
            return
        try:
            self._store.save(task)
        except Exception as e:
            raise self._durable_error(
                "durable A2A settlement failed; the outcome is indeterminate "
                "and this messageId will not be re-executed",
                e,
            ) from e

    def _cancel_task(self, task: _Task) -> None:
        with self._lock:
            self._mark_canceled(task)
            self._persist_task(task)

    def _set_working(self, task: _Task) -> bool:
        with self._lock:
            if task.cancel_requested or task.state == "canceled":
                self._mark_canceled(task)
                self._persist_task(task)
                return False
            task.set_state("working")
            self._persist_task(task)
            return True

    def _reject_task(
        self, task: _Task, detail: str | None = None,
    ) -> bool:
        with self._lock:
            if task.cancel_requested or task.state == "canceled":
                self._mark_canceled(task)
                self._persist_task(task)
                return False
            task.set_state("rejected")
            if detail:
                self._add_artifact(task, detail, "error")
            self._persist_task(task)
            return True

    def _fail_task(self, task: _Task, detail: str) -> bool:
        with self._lock:
            if task.cancel_requested or task.state == "canceled":
                self._mark_canceled(task)
                self._persist_task(task)
                return False
            task.set_state("failed")
            self._add_artifact(task, detail, "error")
            self._persist_task(task)
            return True

    def _complete_task(self, task: _Task, result: Any) -> dict | None:
        with self._lock:
            if task.cancel_requested or task.state == "canceled":
                self._mark_canceled(task)
                self._persist_task(task)
                return None
            artifact = self._add_artifact(task, result or "")
            task.set_state("completed")
            self._persist_task(task)
            return artifact

    @staticmethod
    def _encoded_request(params: dict) -> bytes:
        try:
            encoded = _json_bytes(params)
        except (TypeError, ValueError) as e:
            raise _RpcError(_INVALID_PARAMS, "params must contain valid JSON values") from e
        if len(encoded) > _MAX_REQUEST_RETAINED_BYTES:
            raise _RpcError(
                _INVALID_PARAMS,
                "A2A request exceeds the per-task retained-byte limit",
            )
        return encoded

    @staticmethod
    def _request_digest(params: dict) -> str:
        return hashlib.sha256(TaskEngine._encoded_request(params)).hexdigest()

    @classmethod
    def _validated_request(
        cls, params: dict,
    ) -> tuple[dict, dict, str, str]:
        """Validate and deep-copy one message/send request.

        Returns ``(canonical_params, message, message_id, digest)``. The copy
        and digest come from the same bytes, closing mutation races between
        claim admission and runner execution.
        """
        if not isinstance(params, dict):
            raise _RpcError(_INVALID_PARAMS, "params must be an object")
        message = params.get("message")
        if not isinstance(message, dict):
            raise _RpcError(_INVALID_PARAMS, "message must be an object")
        if message.get("role") != "user":
            raise _RpcError(_INVALID_PARAMS, "message.role must be 'user'")
        if "kind" in message and message.get("kind") != "message":
            raise _RpcError(_INVALID_PARAMS, "message.kind must be 'message'")
        parts = message.get("parts")
        if not isinstance(parts, list) or not parts:
            raise _RpcError(_INVALID_PARAMS, "message.parts must be a non-empty array")
        if any(not isinstance(part, dict) for part in parts):
            raise _RpcError(_INVALID_PARAMS, "every message part must be an object")
        if any(
            part.get("kind") == "text" and not isinstance(part.get("text"), str)
            for part in parts
        ):
            raise _RpcError(_INVALID_PARAMS, "text parts must carry string text")
        for field_name in ("contextId", "taskId"):
            value = message.get(field_name)
            if value is not None and not isinstance(value, str):
                raise _RpcError(
                    _INVALID_PARAMS, f"message.{field_name} must be a string"
                )
        if "metadata" in message and not isinstance(message.get("metadata"), dict):
            raise _RpcError(_INVALID_PARAMS, "message.metadata must be an object")
        message_id = message.get("messageId")
        if (
            not isinstance(message_id, str)
            or not message_id.strip()
            or len(message_id) > _MAX_MESSAGE_ID_LENGTH
        ):
            raise _RpcError(
                _INVALID_PARAMS,
                "messageId is required and must be a non-empty string up to "
                f"{_MAX_MESSAGE_ID_LENGTH} chars",
            )
        encoded_request = cls._encoded_request(params)
        canonical_params = json.loads(encoded_request)
        return (
            canonical_params,
            canonical_params["message"],
            message_id,
            hashlib.sha256(encoded_request).hexdigest(),
        )

    def _claim_durable_locked(
        self, task: _Task, *, message_id: str, request_digest: str,
    ) -> _Task | None:
        """Claim a durable idempotency key; return a cached terminal task."""
        if self._store is None:
            return None
        try:
            claim_status, cached = self._store.claim(
                task,
                message_id=message_id,
                request_digest=request_digest,
            )
        except Exception as e:
            raise self._durable_error(
                "durable A2A claim state is unavailable; refusing to execute",
                e,
            ) from e
        if claim_status == "conflict":
            raise _RpcError(
                _INVALID_PARAMS, "messageId was already used with different content",
            )
        if claim_status == "indeterminate":
            raise _RpcError(
                _SERVER_BUSY,
                "messageId is already in progress or was interrupted on another "
                "worker; its outcome is indeterminate and it will not be re-executed",
            )
        if claim_status == "tombstone":
            raise _RpcError(
                _SERVER_BUSY,
                "messageId was already consumed; its result is no longer retained "
                "and it will not be re-executed",
            )
        if claim_status == "capacity":
            raise _RpcError(_SERVER_BUSY, "durable A2A claim capacity is full")
        if claim_status == "cached":
            if cached is None:
                raise _RpcError(_SERVER_BUSY, "invalid durable A2A result")
            return cached
        if claim_status != "owner":
            raise _RpcError(_SERVER_BUSY, "invalid durable A2A claim state")
        return None

    def _new_or_existing_task(
        self, params: dict, principal: str = "anon",
    ) -> tuple[_Task, bool]:
        canonical_params, message, supplied_message_id, request_digest = (
            self._validated_request(params)
        )
        context_id = message.get("contextId") or ""
        tenant = self._tenant_key()
        idempotency_key = (tenant, principal, supplied_message_id)
        # Normalise the inbound message so history echoes a complete record.
        user_message = {
            "role": message.get("role", "user"),
            "parts": message.get("parts") or [],
            "messageId": supplied_message_id,
            "kind": "message",
        }
        with self._lock:
            if idempotency_key is not None:
                existing = self._message_index.get(idempotency_key)
                if existing is not None:
                    task_id, original_digest = existing
                    task = self._tasks.get(task_id)
                    if task is not None:
                        if not hmac.compare_digest(original_digest, request_digest):
                            raise _RpcError(
                                _INVALID_PARAMS,
                                "messageId was already used with different content",
                            )
                        return self._revalidate_cached(task), False
                    self._message_index.pop(idempotency_key, None)

            task = _Task(context_id, user_message, tenant=tenant)
            task.principal = principal
            task.budget_request = self._client_budget(canonical_params)
            task.idempotency_key = idempotency_key
            task.request_digest = request_digest
            user_message["taskId"] = task.id
            user_message["contextId"] = task.context_id
            retained_request_size = len(_json_bytes({
                "history": task.messages,
                "budgetRequest": task.budget_request,
            }))
            if retained_request_size > _MAX_REQUEST_RETAINED_BYTES:
                raise _RpcError(
                    _INVALID_PARAMS,
                    "A2A request exceeds the per-task retained-byte limit",
                )
            # Never evict a submitted/working task: doing so makes a live goal
            # unqueryable and uncancellable. Reclaim terminal records for both
            # the count cap and the exact retained-byte cap; otherwise apply
            # backpressure.
            if not self._make_room_locked(retained_request_size, new_task=True):
                raise _RpcError(_SERVER_BUSY, "A2A task capacity is full")
            task.retained_bytes = retained_request_size
            cached = self._claim_durable_locked(
                task,
                message_id=supplied_message_id,
                request_digest=request_digest,
            )
            if cached is not None:
                self._cache_loaded_locked(cached)
                return cached, False
            self._tasks[task.id] = task
            self._retained_bytes += retained_request_size
            self._message_index[idempotency_key] = (task.id, request_digest)
        return task, True

    def _new_task(self, params: dict, principal: str = "anon") -> _Task:
        """Compatibility helper for tests/internal callers that need a record."""
        task, _created = self._new_or_existing_task(params, principal)
        return task

    async def _run(self, task: _Task) -> None:
        """Execute under the tenant captured when the task was admitted."""
        with _task_tenant_scope(task.tenant):
            await self._run_in_tenant(task)

    async def _run_in_tenant(self, task: _Task) -> None:
        """Execute the goal, transitioning task state. Updates the record
        in place; callers read task.to_dict() afterwards."""
        if task.cancel_requested or task.state == "canceled":
            self._cancel_task(task)
            return
        text = _message_text(task.messages[0])
        if not text:
            self._reject_task(task, "empty message: no text parts to act on")
            return
        try:
            from . import agent_trust

            trust_state = agent_trust.load_trust_state()
        except Exception:
            self._reject_task(task, "refused: agent trust policy unavailable")
            return
        tblock = _a2a_trust_block(task.principal, trust_state=trust_state)
        if tblock:
            self._reject_task(task, f"refused by agent trust plane: {tblock}")
            return
        block = self._shield_block(text)
        if block:
            self._reject_task(task, f"blocked by safety shield: {block}")
            return
        if not self._set_working(task):
            return
        limits = self._limits(task)
        # Bind the caller id so _a2a_capability applies THIS caller's ceiling
        # (the contextvar copies into the worker thread).
        cv = _caller_agent.set(_agent_id_of(task.principal))
        trust_cv = _caller_trust_state.set(trust_state)
        try:
            # Cap concurrently executing goals so one caller can't saturate the
            # process-wide default ThreadPoolExecutor (asyncio.to_thread) for up
            # to the max_wall ceiling and stall every other to_thread consumer.
            async with _run_slot():
                # Cancellation can land while this task is queued on the
                # semaphore. Re-check after acquisition so a canceled waiter
                # never reaches the synchronous runner.
                if task.cancel_requested:
                    result = None
                else:
                    result = await asyncio.to_thread(
                        self._runner,
                        text,
                        max_dollars=limits["max_dollars"],
                        max_wall=limits["max_wall"],
                        max_depth=limits["max_depth"],
                    )
        except asyncio.CancelledError:
            # Client disconnect/task cancellation must leave a durable terminal
            # record, even though an already-running worker thread cannot be
            # forcefully stopped by asyncio.
            self._cancel_task(task)
            raise
        except Exception as e:
            log.exception("a2a task %s failed", task.id)
            # Scrub the exception before it enters the artifact: it is returned
            # to the caller AND pushed to the notification webhook, and an
            # exception message can carry a secret/PII (a DB DSN, a token in a
            # URL, a row value). Fail safe to the type name if scrub is missing.
            try:
                from .secrets import scrub
                detail = scrub(f"{type(e).__name__}: {e}")
            except Exception:  # pragma: no cover -- never let reporting raise
                detail = type(e).__name__
            self._fail_task(task, f"task failed: {detail}")
            return
        finally:
            _caller_trust_state.reset(trust_cv)
            _caller_agent.reset(cv)
        # Completion and cancellation arbitration are atomic under the engine
        # lock, so a concurrent tasks/cancel cannot be resurrected to completed.
        self._complete_task(task, result)

    # ---- JSON-RPC methods ----------------------------------------------

    async def send(self, params: dict, principal: str = "anon") -> dict:
        task, created = self._new_or_existing_task(params, principal)
        if not created:
            return task.to_dict()
        await self._run(task)
        await self._fire_push(task)
        return task.to_dict()

    async def stream(
        self,
        params: dict,
        principal: str = "anon",
        *,
        tenant: str | None = None,
    ) -> AsyncIterator[dict]:
        """Yield events under a request-time tenant pin.

        ``StreamingResponse`` may consume an async iterator after request
        middleware has reset its ContextVar. The HTTP adapter therefore passes
        the tenant it captured before returning the response.
        """
        bound_tenant = self._tenant_key() if tenant is None else tenant
        with _task_tenant_scope(bound_tenant):
            async for event in self._stream_in_tenant(params, principal):
                yield event

    async def _stream_in_tenant(
        self, params: dict, principal: str = "anon",
    ) -> AsyncIterator[dict]:
        """Yield A2A stream events (already in result-object form)."""
        task, created = self._new_or_existing_task(params, principal)
        try:
            # 1. initial Task snapshot.
            yield task.to_dict()
            if not created:
                return
            if task.cancel_requested:
                self._cancel_task(task)
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            text = _message_text(task.messages[0])
            block = None if text else "empty message"
            trust_state = None
            if not block:
                try:
                    from . import agent_trust

                    trust_state = agent_trust.load_trust_state()
                except Exception:
                    block = "refused: agent trust policy unavailable"
            if not block:
                block = (
                    _a2a_trust_block(task.principal, trust_state=trust_state)
                    or self._shield_block(text)
                )
            if block:
                self._reject_task(task)
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            if task.cancel_requested:
                self._cancel_task(task)
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            # 2. working status.
            if not self._set_working(task):
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            yield _status_event(task, final=False)
            # 3. run.
            limits = self._limits(task)
            cv = _caller_agent.set(_agent_id_of(task.principal))
            trust_cv = _caller_trust_state.set(trust_state)
            try:
                async with _run_slot():
                    # A tasks/cancel request may have landed while this stream
                    # waited for a concurrency slot. Never invoke its runner.
                    if task.cancel_requested:
                        result = None
                    else:
                        result = await asyncio.to_thread(
                            self._runner, text,
                            max_dollars=limits["max_dollars"],
                            max_wall=limits["max_wall"],
                            max_depth=limits["max_depth"],
                        )
            except asyncio.CancelledError:
                self._cancel_task(task)
                raise
            except Exception as e:
                log.exception("a2a stream task %s failed", task.id)
                if task.cancel_requested:
                    self._cancel_task(task)
                    yield _status_event(task, final=True)
                    await self._fire_push(task)
                    return
                # Scrub before the exception enters the artifact + push webhook
                # (same reasoning as the non-streaming path above).
                try:
                    from .secrets import scrub
                    detail = scrub(f"{type(e).__name__}: {e}")
                except Exception:  # pragma: no cover -- never let reporting raise
                    detail = type(e).__name__
                self._fail_task(task, f"task failed: {detail}")
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            finally:
                _caller_trust_state.reset(trust_cv)
                _caller_agent.reset(cv)
            if task.cancel_requested:
                self._cancel_task(task)
                yield _status_event(task, final=True)
                await self._fire_push(task)
                return
            # 4. artifact then terminal status.
            art = self._complete_task(task, result)
            if art is not None:
                yield _artifact_event(task, art)
            yield _status_event(task, final=True)
            await self._fire_push(task)
        except (asyncio.CancelledError, GeneratorExit):
            # Closing an SSE generator at any yield point is cancellation too;
            # otherwise disconnects can strand submitted/working records.
            if created:
                self._cancel_task(task)
            raise

    def get(self, params: dict, principal: str = "anon") -> dict:
        task = self._owned((params or {}).get("id", ""), principal)
        return task.to_dict()

    def cancel(self, params: dict, principal: str = "anon") -> dict:
        task = self._owned((params or {}).get("id", ""), principal)
        self._cancel_task(task)
        return task.to_dict()

    def set_push_config(self, params: dict, principal: str = "anon") -> dict:
        if not isinstance(params, dict):
            raise _RpcError(_INVALID_PARAMS, "params must be an object")
        task = self._owned(params.get("taskId", ""), principal)
        cfg = params.get("pushNotificationConfig")
        if not isinstance(cfg, dict):
            raise _RpcError(
                _INVALID_PARAMS, "pushNotificationConfig must be an object",
            )
        unknown = set(cfg) - _PUSH_CONFIG_FIELDS
        if unknown:
            raise _RpcError(
                _INVALID_PARAMS,
                "pushNotificationConfig contains unsupported fields: "
                + ", ".join(sorted(str(field) for field in unknown)),
            )
        url = cfg.get("url")
        if not isinstance(url, str) or not url.strip():
            raise _RpcError(
                _INVALID_PARAMS, "pushNotificationConfig.url must be a string",
            )
        try:
            url_size = len(url.encode("utf-8"))
        except UnicodeError as e:
            raise _RpcError(
                _INVALID_PARAMS,
                "pushNotificationConfig.url is invalid or too long",
            ) from e
        if url_size > _MAX_PUSH_URL_BYTES or any(
            ord(char) < 0x20 or ord(char) == 0x7F for char in url
        ):
            raise _RpcError(
                _INVALID_PARAMS,
                "pushNotificationConfig.url is invalid or too long",
            )
        token = cfg.get("token")
        if token is not None:
            if not isinstance(token, str):
                raise _RpcError(
                    _INVALID_PARAMS,
                    "pushNotificationConfig.token must be a string",
                )
            try:
                token_size = len(token.encode("utf-8"))
            except UnicodeError as e:
                raise _RpcError(
                    _INVALID_PARAMS,
                    "pushNotificationConfig.token is invalid or too long",
                ) from e
            if token_size > _MAX_PUSH_TOKEN_BYTES or any(
                ord(char) < 0x20 or ord(char) == 0x7F for char in token
            ):
                raise _RpcError(
                    _INVALID_PARAMS,
                    "pushNotificationConfig.token is invalid or too long",
                )
        # Validate the push URL at REGISTRATION (not just at fire time): a
        # loopback/metadata/internal target must be refused here so it can never
        # be stored, mirroring the SSRF guard _fire_push applies. Reuse the same
        # resolve-and-check primitive.
        try:
            from urllib.parse import urlparse

            from .tools._ssrf import BlockedHost, resolve_pinned_ip
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise BlockedHost(f"scheme {parsed.scheme!r} not allowed")
            if parsed.username is not None or parsed.password is not None:
                raise BlockedHost("URL credentials are not allowed")
            # Accessing .port validates malformed/out-of-range ports.
            _validated_port = parsed.port
            # Public addresses only, whatever the fetch tool's private-network
            # override says: the caller chooses this URL and its bearer.
            resolve_pinned_ip(parsed.hostname or "", require_public=True)
        except ImportError as e:  # pragma: no cover - packaged with core
            raise _RpcError(
                _INVALID_PARAMS,
                "pushNotificationConfig.url validation unavailable",
            ) from e
        except (BlockedHost, ValueError, UnicodeError) as e:
            # The detail (what a name resolves to) stays in the server log so
            # the endpoint cannot be used to read the server's internal DNS.
            log.info("a2a push URL rejected for %s: %s", task.id, e)
            raise _RpcError(
                _INVALID_PARAMS,
                "pushNotificationConfig.url rejected: it must be an http(s) "
                "URL on a public host",
            ) from e
        # Retain only fields this implementation actually supports, after type
        # and byte validation, so caller mutation cannot alter stored state.
        safe_cfg = {"url": url}
        if token is not None:
            safe_cfg["token"] = token
        task.push_config = safe_cfg
        return {
            "taskId": task.id,
            "pushNotificationConfig": _redacted_push_config(safe_cfg),
        }

    def get_push_config(self, params: dict, principal: str = "anon") -> dict:
        task = self._owned((params or {}).get("id", "")
                           or (params or {}).get("taskId", ""), principal)
        return {
            "taskId": task.id,
            "pushNotificationConfig": _redacted_push_config(task.push_config),
        }

    async def _fire_push(self, task: _Task) -> None:
        """POST the terminal Task to a registered webhook (best-effort).

        The webhook URL is supplied by the (outward-facing) A2A caller, so it
        is routed through the SSRF guard: a peer must not be able to make the
        server POST the task to ``169.254.169.254`` / ``127.0.0.1`` / other
        internal hosts. ``_public_push_client`` resolves once, rejects any
        non-public address, and pins the connection (no rebind window).
        """
        cfg = task.push_config
        if not cfg or task.state not in TERMINAL_STATES:
            return
        try:
            from .tools._ssrf import BlockedHost
        except Exception:  # pragma: no cover
            return
        url = cfg.get("url") or ""
        headers = {}
        tok = cfg.get("token")
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        # ``_public_push_client`` resolves the host once, rejects any non-public
        # address, and pins the connection to that IP (Host/SNI preserved) --
        # so there is no second lookup to rebind. A bad scheme or non-public
        # host raises BlockedHost and we fail closed (no request sent).
        try:
            client = _public_push_client(url)
        except BlockedHost as e:
            log.warning("a2a push notify blocked for %s (SSRF guard): %s", task.id, e)
            return
        try:
            async with client:
                await client.post(url, headers=headers, json=task.to_dict())
        except Exception as e:  # pragma: no cover
            log.warning("a2a push notify failed for %s: %s", task.id, e)


def _public_push_client(url: str):
    """An ``httpx.AsyncClient`` pinned to ``url``'s host, which must resolve to
    public addresses only (``require_public``: the private-network override for
    the fetch tool does not apply to a caller-chosen webhook). Raises
    ``BlockedHost``."""
    from urllib.parse import urlparse

    import httpx

    from .egress_guard import _check
    from .tools._ssrf import BlockedHost, _AsyncPinnedTransport, resolve_pinned_ip

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedHost(f"scheme {parsed.scheme!r} not allowed")
    _check(url)
    host = parsed.hostname or ""
    ip = resolve_pinned_ip(host, require_public=True)
    host_header = host if not parsed.port else f"{host}:{parsed.port}"
    transport = _AsyncPinnedTransport(host, host_header, ip, httpx.AsyncHTTPTransport())
    return httpx.AsyncClient(transport=transport, timeout=15.0, follow_redirects=False)


# Methods that return an SSE stream rather than a single JSON response.
STREAM_METHODS = {"message/stream"}


def _err(code: int, message: str) -> dict:
    return {"code": code, "message": message}


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _status_event(task: _Task, *, final: bool) -> dict:
    return {
        "taskId": task.id,
        "contextId": task.context_id,
        "kind": "status-update",
        "status": {
            "state": task.state,
            "timestamp": task.status_history[-1]["timestamp"],
        },
        "final": final,
    }


def _artifact_event(task: _Task, artifact: dict) -> dict:
    return {
        "taskId": task.id,
        "contextId": task.context_id,
        "kind": "artifact-update",
        "artifact": artifact,
        "append": False,
        "lastChunk": True,
    }
