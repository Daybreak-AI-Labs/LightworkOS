"""MCP server for Lightwork."""
from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import sys
import threading
from typing import Any

from .application import ApplicationDependencies, MCPApplication

# Preserve the historical server-level catalog API for integrations.
from .authorization import (
    _CREDENTIAL_FINGERPRINT_KEY as _CREDENTIAL_FINGERPRINT_KEY,
)
from .authorization import (
    _TaskExecutionContext as _TaskExecutionContext,
)
from .authorization import (
    capability_permits,
    capability_principal,
    connector_principal,
    principal_permits,
    refresh_task_capability,
    task_authorizer,
    task_execution_context,
)
from .authorization import (
    credential_fingerprint as _credential_fingerprint,
)
from .catalog import (
    _TOOL_BY_NAME as _TOOL_BY_NAME,
)
from .catalog import (
    _TOOL_NAMES as _TOOL_NAMES,
)
from .catalog import (
    TOOLS as TOOLS,
)
from .catalog import (
    ToolSpec as ToolSpec,
)
from .catalog import (
    _validate_tool_specs as _validate_tool_specs,
)
from .prompts import get_prompt, list_prompts
from .protocol import (
    PROTOCOL_VERSION as PROTOCOL_VERSION,
)
from .protocol import (
    PROTOCOL_VERSION_FALLBACK as PROTOCOL_VERSION_FALLBACK,
)
from .protocol import (
    SERVER_NAME as SERVER_NAME,
)
from .protocol import (
    SERVER_VERSION as SERVER_VERSION,
)
from .protocol import (
    SUPPORTED_PROTOCOL_VERSIONS as SUPPORTED_PROTOCOL_VERSIONS,
)
from .protocol import ProtocolError as _ProtocolError
from .protocol import (
    error_envelope,
    initialize_response,
    result_envelope,
)
from .resources import ResourceDependencies, ResourceService
from .session import (
    _NO_OVERRIDE as _NO_OVERRIDE,
)
from .session import (
    _RESOURCE_PENDING_UPDATES_CTX as _RESOURCE_PENDING_UPDATES_CTX,
)
from .session import (
    _RESOURCE_SUBSCRIPTIONS_CTX as _RESOURCE_SUBSCRIPTIONS_CTX,
)
from .session import (
    _STRUCTURED_OVERRIDE_CTX as _STRUCTURED_OVERRIDE_CTX,
)
from .session import (
    current_pending_updates,
    current_structured_override,
    current_subscriptions,
    set_scoped_structured_override,
)
from .session import (
    resource_update_scope as request_resource_update_scope,
)
from .settings import mcp_setting
from .tasks import TaskError

log = logging.getLogger(__name__)

_MAX_TOOL_ERROR_CHARS = 500

@contextlib.contextmanager
def _canonical_world():
    """Yield the configured, tenant-aware world and release only owned handles.

    ``open_world`` is the single backend-selection boundary for SQLite and
    Postgres.  A no-path SQLite world may be owned by the process-wide tenant
    cache, while a Postgres world is normally a per-call handle; delegating the
    teardown decision to ``close_world_if_owned`` preserves both contracts.
    """
    from maverick.world_model import close_world_if_owned, open_world

    world = open_world()
    try:
        yield world
    finally:
        close_world_if_owned(world)

def _configure_mcp_logging() -> None:
    """Apply Lightwork's shared logging config (honors MAVERICK_LOG_FORMAT=json,
    the correlation-id context filter, and secret scrubbing). Logs to STDERR —
    never stdout, which is the MCP stdio protocol channel. Called from main(),
    NOT at import, so importing the server (e.g. in tests) never reconfigures
    global logging. Falls back to a stderr basicConfig if core import fails."""
    try:
        from maverick.logging_config import configure_logging
        configure_logging()
    except Exception:  # pragma: no cover - fall back to a stderr basicConfig
        logging.basicConfig(
            level=logging.INFO,
            stream=sys.stderr,
            format="%(asctime)s [%(levelname)s] mcp: %(message)s",
        )

# Sentinel distinguishing a MISSING JSON-RPC "id" (a notification, owed no
# response) from an explicit `"id": null` (a request that still wants a reply).
_NO_ID = object()

def _bounded_float(value: Any, *, default: float, ceiling: float) -> float:
    """Return a finite, non-negative value clamped to an operator ceiling."""
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = float(default)
    if not math.isfinite(parsed) or parsed < 0:
        parsed = float(default)

    try:
        parsed_ceiling = float(ceiling)
    except (TypeError, ValueError):
        parsed_ceiling = float(default)
    if not math.isfinite(parsed_ceiling) or parsed_ceiling < 0:
        parsed_ceiling = float(default)

    return min(parsed, parsed_ceiling)


def _bounded_int(value: Any, *, default: int, ceiling: float) -> int:
    return int(_bounded_float(value, default=float(default), ceiling=ceiling))


def _task_budget(args: dict):
    """Optional caller limits, constrained by current operator authority."""
    from maverick.budget import budget_from_config, resolve_budget_caps
    from maverick.runner import (
        DEFAULT_MAX_DOLLARS,
        DEFAULT_MAX_WALL_SECONDS,
        clamp_task_limit,
        configured_goal_ceiling_dollars,
        configured_goal_ceiling_wall_seconds,
    )

    configured = resolve_budget_caps()
    overrides = {}
    # MAVERICK_MCP_MAX_DOLLARS / MAVERICK_MCP_MAX_WALL_SECONDS, else [mcp].
    for key in ("max_dollars", "max_wall_seconds"):
        limits = []
        runner_limit = (configured_goal_ceiling_dollars() if key == "max_dollars"
                        else configured_goal_ceiling_wall_seconds())
        for raw in (args.get(key), mcp_setting(key), configured.get(key), runner_limit):
            if raw is None:
                limits.append(None)
                continue
            try:
                value = float(raw)
                if isinstance(raw, bool) or not math.isfinite(value) or value < 0:
                    raise ValueError
            except (TypeError, ValueError, OverflowError):
                raise ValueError(f"{key} must be a finite non-negative limit") from None
            limits.append(value)
        ceiling = clamp_task_limit(clamp_task_limit(limits[1], limits[2]), limits[3])
        if ceiling is None:
            ceiling = DEFAULT_MAX_DOLLARS if key == "max_dollars" else DEFAULT_MAX_WALL_SECONDS
        overrides[key] = clamp_task_limit(limits[0], ceiling)
    from maverick.agent_trust import clamp_budget, load_trust_state
    from maverick.connections import current_principal

    principal = current_principal() or ""
    if principal.startswith("agent:"):
        _, registry = load_trust_state()
        agent = registry.get(principal.removeprefix("agent:"))
        overrides["max_dollars"], overrides["max_wall_seconds"] = clamp_budget(agent, **overrides)
    return budget_from_config(**overrides)


# Form a parked free-text ask_user question is surfaced as, when the client
# supports elicitation. A single required string keeps the round trip simple.
_ELICIT_ANSWER_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string", "title": "Your answer"}},
    "required": ["answer"],
}


def _elicit_timeout() -> float:
    """Seconds to wait for an elicitation response before giving up (and
    leaving the question parked for the async maverick_answer flow)."""
    return _bounded_float(
        mcp_setting("elicitation_timeout", "300"),
        default=300.0, ceiling=86400.0,
    )


def _elicit_allowed_hosts() -> frozenset[str]:
    """Operator allowlist of hosts a URL-mode elicitation may point the user at.

    From ``MAVERICK_MCP_ELICIT_ALLOWED_HOSTS`` (comma-separated, wins) or
    ``[mcp] elicit_allowed_hosts`` in config. Empty -> no restriction (any
    https, the documented residual risk that a prompt-injected model could aim
    the user at an arbitrary site). Set it to pin elicitation to the providers
    you actually use (e.g. accounts.google.com, github.com)."""
    raw = os.environ.get("MAVERICK_MCP_ELICIT_ALLOWED_HOSTS")
    hosts: list[str] = []
    if raw and raw.strip():
        hosts = [h.strip() for h in raw.split(",") if h.strip()]
    else:
        try:
            from maverick.config import load_config
            cfg = ((load_config() or {}).get("mcp") or {}).get("elicit_allowed_hosts") or []
            hosts = [str(h).strip() for h in cfg if str(h).strip()]
        except Exception:
            hosts = []
    return frozenset(h.lower().rstrip(".") for h in hosts)


def _elicit_host_allowed(url: str, allowed: frozenset[str]) -> bool:
    """True if ``url``'s host is in ``allowed`` (exact or a subdomain). An empty
    allowlist means no restriction."""
    if "\\" in url:
        return False
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.username is not None or parsed.password is not None:
            return False
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False
    return not allowed or (bool(host) and any(host == a or host.endswith("." + a) for a in allowed))


def _tool_supports_tasks(tool_spec: ToolSpec) -> bool:
    """Whether a tool opted into task augmentation via execution.taskSupport."""
    return tool_spec.get("execution", {}).get("taskSupport") in ("optional", "required")


def _normalize_tool_result(result: Any) -> tuple[Any, bool]:
    """Preserve explicit in-process state while keeping legacy text behavior."""
    from maverick.tool_results import ToolOutcome, ToolResultText, tool_result_failed

    if isinstance(result, ToolOutcome):
        result = result.as_text()
    return result, isinstance(result, ToolResultText) and tool_result_failed(result)


def _reset_tool_call_state(server) -> None:
    """Clear the current request's structured result and pending notifications."""
    server._structured_override = None
    pending = server._resource_pending_updates()
    if pending is None:
        server._pending_updates = []
    else:
        pending.clear()


class MCPServer:
    # Resources a client may subscribe to, and which mutating tool dirties
    # each -- after such a tool call we push notifications/resources/updated.
    RESOURCE_URIS = ("maverick://goals", "maverick://skills")
    _RESOURCE_READ_TOOL = {
        "maverick://goals": "maverick_status",
        "maverick://skills": "maverick_skills_list",
    }
    _TOOL_RESOURCE = {
        "maverick_start": "maverick://goals",
        "maverick_resume": "maverick://goals",
        "maverick_answer": "maverick://goals",
        "maverick_skill_install": "maverick://skills",
    }

    def __init__(self):
        self._initialized = False
        self._shield = self._build_shield()
        # resources/subscribe state: URIs the client wants updates for, plus
        # the updates queued by the current tools/call to flush after its
        # result (so the client sees result-then-notification).
        self._subscriptions: set[str] = set()
        self._pending_updates: list[str] = []
        # Elicitation (server-initiated forms). Capabilities the CLIENT
        # advertised at initialize -- elicitation is a *client* capability, so
        # we only emit elicitation/create when the client declared it. _stdio
        # gates it to the stdio transport (a server->client request mid-call has
        # no place in the HTTP request/response model). _elicit_seq namespaces
        # our outbound request ids so they never collide with the client's.
        self._client_capabilities: dict = {}
        self._stdio = False
        self._stdio_session = None
        self._elicit_seq = 0
        # MCP Tasks: lazily built on first task-augmented call so a transport
        # that never uses tasks doesn't spin up an executor.
        self._tasks = None
        self._tasks_lock = threading.Lock()
        from .execution import RequestExecutions

        self._requests = RequestExecutions()
        # Whether async tasks are offered on this transport. stdio sets it in
        # run(); the HTTP transport sets it from MAVERICK_MCP_HTTP_TASKS in
        # build_app (opt-in, since multi-client task isolation is bearer-scoped).
        # Kept distinct from _stdio because elicitation is stdio-only (it needs
        # the bidirectional pipe) while tasks are not.
        self._tasks_enabled = False
        # Serializes transport writes. A task's background worker emits
        # notifications/tasks/status while the main loop may be writing a
        # response, so the two must not interleave a half-line on stdout.
        self._send_lock = threading.Lock()
        # Side-effectful tools stash their structured result here during
        # dispatch. stdio maps one server to one client so the instance attr is
        # safe; HTTP reuses ONE server across concurrent clients, so the
        # property routes to a per-request ContextVar (set by
        # resource_update_scope) to keep one client's structured result from
        # leaking into another's response.
        self._structured_override_attr: dict | None = None

    @property
    def _structured_override(self) -> dict | None:
        return current_structured_override(self._structured_override_attr)

    @_structured_override.setter
    def _structured_override(self, value: dict | None) -> None:
        if not set_scoped_structured_override(value):
            self._structured_override_attr = value

    @staticmethod
    def _build_shield():
        try:
            from maverick_shield import Shield
            return Shield.from_config()
        except Exception:
            return None

    def handle_initialize(self, params: dict) -> dict:
        self._initialized = True
        # Record the client's advertised capabilities. Elicitation is a client
        # capability: its presence here is our gate for emitting elicitation/
        # create later (see _maybe_elicit_open_questions). Coerce a non-object
        # to {} so a hostile initialize can't break the .get() gate.
        caps = params.get("capabilities")
        self._client_capabilities = caps if isinstance(caps, dict) else {}
        # Elicitation remains a client capability. Tasks are advertised only
        # when the active transport enables them.
        return initialize_response(params.get("protocolVersion", ""), tasks_enabled=self._tasks_enabled)

    def handle_tools_list(
        self,
        params: dict,
        *,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        """List only tools the authenticated caller can actually invoke."""
        if not self._principal_permits(caller_trust_principal):
            return {"tools": []}
        principal = (self._connector_principal(None, caller_trust_principal, capability)
                     or self._current_object_principal() or "")
        return {
            "tools": [
                tool for tool in TOOLS
                if self._capability_permits(capability, tool["name"])
                and not (principal.startswith("agent:")
                         and tool["name"] in {"maverick_fact_set", "maverick_facts_get"})
            ]
        }

    # ---- 2025-11-25 Resources -----------------------------------------

    def _resource_service(self) -> ResourceService:
        return ResourceService(ResourceDependencies(
            world_factory=_canonical_world,
            read_tools=self._RESOURCE_READ_TOOL,
            access_permits=self._resource_access_permits,
            record_denial=self._record_capability_denial,
            connector_principal=self._connector_principal,
            shield_required=self._shield_required,
            shield_scan_reason=self._shield_scan_reason,
        ))

    def handle_resources_list(
        self, params: dict, *, caller_trust_principal: str | None = None, capability=None,
    ) -> dict:
        return self._resource_service().list(
            params, caller_trust_principal=caller_trust_principal, capability=capability,
        )

    def handle_resources_read(
        self, params: dict, *, caller_identity: str | None = None,
        caller_trust_principal: str | None = None, capability=None,
    ) -> dict:
        return self._resource_service().read(
            params, caller_identity=caller_identity,
            caller_trust_principal=caller_trust_principal, capability=capability,
        )

    # ---- 2025-11-25 Prompts -------------------------------------------

    @contextlib.contextmanager
    def resource_update_scope(self, subscriptions: set[str]):
        """Temporarily scope resource subscriptions/updates to one HTTP client.

        stdio uses the instance fields below because one MCPServer maps to one
        client process. HTTP reuses a single MCPServer for all clients, so the
        transport supplies per-session subscription state with this context.
        The pending list is per request and is shared with ``asyncio.to_thread``
        through ContextVar propagation, preserving result-then-notification
        ordering without leaking updates across clients.
        """
        with request_resource_update_scope(subscriptions):
            yield

    def _resource_subscriptions(self) -> set[str]:
        return current_subscriptions(self._subscriptions)

    def _resource_pending_updates(self) -> list[str] | None:
        return current_pending_updates()

    def handle_resources_subscribe(
        self,
        params: dict,
        *,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        """Track a client's interest in a resource (2025-11-25 subscribe)."""
        uri = params.get("uri", "")
        if uri not in self.RESOURCE_URIS:
            raise _ProtocolError(
                -32602, f"cannot subscribe to unknown resource: {uri!r}"
            )
        read_tool = self._RESOURCE_READ_TOOL[uri]
        if not self._resource_access_permits(
            capability,
            caller_trust_principal,
            read_tool,
        ):
            self._record_capability_denial(
                capability,
                caller_identity,
                read_tool,
            )
            raise _ProtocolError(
                -32602, f"cannot subscribe to unknown resource: {uri!r}"
            )
        self._resource_subscriptions().add(uri)
        return {}

    def handle_resources_unsubscribe(self, params: dict) -> dict:
        """Stop notifying a client about a resource. Idempotent."""
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise _ProtocolError(-32602, "uri must be a string")
        self._resource_subscriptions().discard(uri)
        return {}

    def _queue_resource_update(self, tool_name: str) -> None:
        """Record that ``tool_name`` dirtied a resource, to flush once the
        tool result has been sent (result-then-notification ordering)."""
        uri = self._TOOL_RESOURCE.get(tool_name)
        if uri is not None:
            pending = self._resource_pending_updates()
            if pending is None:
                pending = self._pending_updates
            pending.append(uri)

    def drain_resource_updates(self) -> list[str]:
        """Pop the queued updates, returning those a client subscribed to.

        Shared by both transports so neither double-emits: stdio sends each as
        a notification (_flush_resource_updates); the HTTP transport yields
        them on the SSE stream after the tool result.
        """
        pending = self._resource_pending_updates()
        if pending is None:
            pending, self._pending_updates = self._pending_updates, []
        else:
            queued = pending[:]
            pending.clear()
            pending = queued
        subscriptions = self._resource_subscriptions()
        return [uri for uri in pending if uri in subscriptions]

    def _flush_resource_updates(self) -> None:
        """stdio: emit notifications/resources/updated for subscribed URIs."""
        for uri in self.drain_resource_updates():
            self._send({
                "jsonrpc": "2.0",
                "method": "notifications/resources/updated",
                "params": {"uri": uri},
            })

    def handle_prompts_list(self, params: dict) -> dict:
        return list_prompts(params)

    def handle_prompts_get(self, params: dict) -> dict:
        return get_prompt(params)

    @staticmethod
    def _capability_permits(capability, tool_name: str) -> bool:
        return capability_permits(capability, tool_name)

    @staticmethod
    def _principal_permits(principal: str | None) -> bool:
        return principal_permits(principal)

    @classmethod
    def _resource_access_permits(
        cls,
        capability,
        caller_trust_principal: str | None,
        read_tool: str,
    ) -> bool:
        return cls._principal_permits(
            caller_trust_principal
        ) and cls._capability_permits(capability, read_tool)

    @staticmethod
    def _capability_principal(capability, caller_identity: str | None) -> str:
        return capability_principal(capability, caller_identity)

    @staticmethod
    def _connector_principal(caller_identity: str | None, caller_trust_principal: str | None, capability) -> str | None:
        return connector_principal(caller_identity, caller_trust_principal, capability)

    @classmethod
    @contextlib.contextmanager
    def _bind_connector_principal(
        cls,
        caller_identity: str | None,
        caller_trust_principal: str | None,
        capability,
    ):
        """Bind authenticated connector authority without clearing local scope."""
        principal = cls._connector_principal(
            caller_identity,
            caller_trust_principal,
            capability,
        )
        if not principal:
            # Stdio/local embedding retains an already-bound outer principal;
            # do not replace it with the unscoped local identity.
            yield
            return
        from maverick.connections import bind_principal

        with bind_principal(principal):
            yield

    def _record_capability_denial(
        self,
        capability,
        caller_identity: str | None,
        tool_name: str,
    ) -> None:
        try:
            from maverick.agent_trust import record_denied

            principal = self._capability_principal(capability, caller_identity)
            record_denied(
                principal,
                direction="inbound",
                rule="capability",
                reason=f"MCP tool {tool_name!r} is outside the caller capability",
            )
        except Exception:  # pragma: no cover - audit is fail-safe
            pass

    @staticmethod
    def _task_execution_context(*, caller_identity: str | None, trust_principal: str | None,
                                credential_kind: str | None, credential_fingerprint: str | None,
                                capability) -> _TaskExecutionContext | None:
        return task_execution_context(
            caller_identity=caller_identity, trust_principal=trust_principal,
            credential_kind=credential_kind, credential_fingerprint=credential_fingerprint,
            capability=capability,
        )

    @staticmethod
    def _shield_required() -> bool:
        # Enterprise is a floor, not an overrideable default. The shared core
        # policy preserves a local env override for compatibility, but a
        # network-reachable MCP deployment must not let
        # MAVERICK_REQUIRE_SHIELD=0 disable the enterprise boundary.
        try:
            from maverick.enterprise import enterprise_enabled

            if enterprise_enabled():
                return True
        except Exception as e:
            log.error("MCP enterprise policy unavailable; requiring Shield: %s", e)
            return True
        try:
            from maverick.shield_policy import shield_required

            return bool(shield_required())
        except Exception as e:  # policy resolution failed at a security boundary
            log.error("MCP Shield policy unavailable; requiring scan: %s", e)
            return True

    def _shield_scan_reason(
        self,
        payload: str,
        *,
        output: bool,
        required: bool | None = None,
    ) -> str | None:
        """Return a block reason while preserving explicit local/dev posture.

        Missing or failing Shield remains fail-open in ordinary local mode.
        Enterprise mode and ``require_shield`` fail closed, including scanner
        exceptions.
        """
        # Callers that make a multi-step decision can pass one policy snapshot
        # so a transient config read cannot make preflight observe both
        # "required" and "optional" for the same request.
        if required is None:
            required = self._shield_required()
        if self._shield is None:
            if required:
                return "safety shield is required but unavailable"
            return None
        try:
            scan = self._shield.scan_output if output else self._shield.scan_input
            verdict = scan(payload)
        except Exception as e:
            if required:
                log.warning("MCP Shield scan failed (blocking): %s", e)
                return "safety shield scan error"
            log.warning("MCP Shield scan failed (local/dev fail-open): %s", e)
            return None
        if getattr(verdict, "allowed", True):
            return None
        return "; ".join(getattr(verdict, "reasons", []) or []) or "blocked by Shield"

    def _shield_block_or_none(self, payload: str) -> dict | None:
        """Scan tool output and return a protocol tool-error when blocked."""
        reasons = self._shield_scan_reason(payload, output=True)
        if reasons is None:
            return None
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"⚠ Output blocked: {reasons}"}],
        }

    def _tool_exception_result(self, exc: Exception) -> dict:
        """Return one bounded, scrubbed, Shield-gated tool failure."""
        try:
            from maverick.secrets import scrub

            detail = scrub(f"{type(exc).__name__}: {exc}")
        except Exception:  # scrubbing failure must not expose the raw error
            detail = type(exc).__name__
        detail = detail[:_MAX_TOOL_ERROR_CHARS]
        if self._shield_scan_reason(detail, output=True) is not None:
            # Scanner reasons can contain the matched span. Keep the exception
            # path generic so a denial cannot echo non-regex secret material.
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": "Output blocked by safety policy",
                }],
            }
        return {
            "isError": True,
            "content": [{"type": "text", "text": detail}],
        }

    def _required_shield_input_block_or_none(
        self,
        tool_name: str,
        arguments: dict,
    ) -> dict | None:
        """Preflight required Shield before any network-triggered side effect.

        In ordinary local/dev mode the existing targeted scans retain their
        fail-open behavior.  When Shield is required, every MCP call is scanned
        before task creation or tool dispatch so a missing/broken scanner cannot
        execute a mutation and merely hide its output afterward.
        """
        required = self._shield_required()
        if not required:
            return None
        # ensure_ascii=False: \uXXXX escapes would hide full-width or other
        # non-ASCII text from the scanner's normalization.
        payload = json.dumps(
            {"tool": tool_name, "arguments": arguments},
            default=str,
            sort_keys=True,
            ensure_ascii=False,
        )
        reasons = self._shield_scan_reason(
            payload,
            output=False,
            required=required,
        )
        if reasons is None:
            return None
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"⚠ Input blocked: {reasons}"}],
        }

    def handle_tools_call(
        self,
        params: dict,
        *,
        task_owner: str | None = None,
        task_quota_owner: str | None = None,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        caller_credential_kind: str | None = None,
        caller_credential_fingerprint: str | None = None,
        capability=None,
    ) -> dict:
        from .execution import ExecutionCancelled, check_execution

        check_execution()
        name = params.get("name")
        # A non-hashable `name` (list/dict) raises TypeError on the set-membership
        # test below, escaping as a scrubbed -32603; coerce to -32602 like the
        # `arguments` guard just below.
        if not isinstance(name, str) or name not in _TOOL_NAMES:
            raise _ProtocolError(-32602, f"unknown tool: {name!r}")
        if not (
            self._principal_permits(caller_trust_principal)
            and self._capability_permits(capability, name)
        ):
            self._record_capability_denial(capability, caller_identity, name)
            # Match the unknown-tool response so a scoped caller cannot use
            # direct calls to enumerate tools hidden from tools/list.
            raise _ProtocolError(-32602, f"unknown tool: {name!r}")
        arguments = params.get("arguments", {}) or {}
        # A client can send `arguments` as a non-object (number/bool/string/
        # list). A truthy non-dict (e.g. 5, True) survives the `or {}` and then
        # raises TypeError on the `r not in arguments` membership test below,
        # escaping this dispatch helper as a scrubbed -32603. Reject it as the
        # correct -32602 invalid-params instead -- mirrors the non-dict `params`
        # coercion in _handle_stdio_line.
        if not isinstance(arguments, dict):
            raise _ProtocolError(-32602, f"arguments for {name} must be an object")
        tool_spec = _TOOL_BY_NAME[name]
        required = tool_spec.get("inputSchema", {}).get("required", []) or []
        missing = [r for r in required if r not in arguments]
        if missing:
            raise _ProtocolError(-32602, f"missing required argument(s) for {name}: {missing}")
        blocked_input = self._required_shield_input_block_or_none(name, arguments)
        if blocked_input is not None:
            return blocked_input
        # MCP task augmentation: a tools/call carrying a `task` field runs async
        # when the tool opts in (execution.taskSupport) and this transport has
        # tasks enabled. Returns a CreateTaskResult immediately; the worker runs
        # the tool on an isolated MCPServer instance and the client polls
        # tasks/get|result. When tasks are disabled the field is ignored and the
        # call runs normally, per the spec.
        task_param = params.get("task")
        if isinstance(task_param, dict) and self._tasks_enabled:
            if not _tool_supports_tasks(tool_spec):
                raise _ProtocolError(
                    -32601, f"tool {name!r} does not support task augmentation")
            task_context = self._task_execution_context(
                caller_identity=caller_identity,
                trust_principal=caller_trust_principal,
                credential_kind=caller_credential_kind,
                credential_fingerprint=caller_credential_fingerprint,
                capability=capability,
            )
            task = self._task_store().create(
                name,
                arguments,
                task_param,
                owner=task_owner,
                quota_owner=task_quota_owner,
                context=task_context,
            )
            # The frozen creation snapshot: a CreateTaskResult always reports the
            # initial `working` status, even if a fast tool already finished.
            return {"task": task.create_result}
        # Action tools cannot safely be re-derived after dispatch, so they
        # stash their structured result here; reset per call so a prior call's
        # value cannot leak.
        _reset_tool_call_state(self)
        with self._bind_connector_principal(
            caller_identity,
            caller_trust_principal,
            capability,
        ):
            try:
                check_execution()
                if capability is not None and name in (
                    "maverick_start", "maverick_resume",
                ):
                    result = self._dispatch_tool(
                        name, arguments, capability=capability)
                else:
                    result = self._dispatch_tool(name, arguments)
                check_execution()
            except (_ProtocolError, TaskError, ExecutionCancelled):
                # Control-flow errors carry an explicit JSON-RPC (code, message) and
                # MUST surface as a structured protocol error -- both transports
                # convert them (stdio _dispatch_stdio_message, http _exception_to_
                # error_response). Collapsing them into an isError envelope here (the
                # blanket catch did) broke the documented -32602 contract for typed
                # clients AND leaked the internal class name ("_ProtocolError: ...")
                # into the tool-result text. Re-raise; only genuine tool crashes
                # below become isError.
                raise
            except Exception as e:
                # Genuine tool failures are still model-visible output. Scrub known
                # credential shapes, cap amplification, and run the same required
                # Shield output gate as a successful tool result before returning.
                return self._tool_exception_result(e)
            # Form elicitation: if the run parked questions and the (stdio)
            # client advertised elicitation, surface them as protocol forms now,
            # record the answers, and resume -- so the caller gets the finished
            # answer in one round trip instead of the start -> answer -> resume
            # dance. A no-op for HTTP clients or those without the capability,
            # leaving the async ask_user / maverick_answer flow unchanged.
            if name in ("maverick_start", "maverick_resume"):
                elicited = self._maybe_elicit_open_questions(
                    arguments, capability=capability)
                if elicited is not None:
                    result = elicited
        # Explicit tool states survive in-process transport; ordinary legacy
        # strings retain the existing MCP result semantics.
        result, explicit_error = _normalize_tool_result(result)
        blocked = self._shield_block_or_none(result)
        if blocked is not None:
            return blocked
        response: dict[str, Any] = {
            "isError": explicit_error,
            "content": [{"type": "text", "text": str(result)}],
        }
        if explicit_error:
            # An explicit failure must not be advertised as a successful
            # structured action or enqueue a resource-change notification.
            return response
        # Every tool declares an outputSchema and returns structuredContent, so
        # typed cross-language clients get parsed JSON instead of re-parsing
        # the text block. Additive + best-effort:
        # the text block stays for back-compat, and a structured-form failure
        # never fails the call. Structured data is scanned before it is
        # attached, because it may carry fields absent from the text block
        # (e.g. extra skill triggers) that would otherwise bypass output
        # filtering for typed cross-language clients.
        if "outputSchema" in tool_spec:
            try:
                # Action tools stash their structured result during dispatch
                # (can't be re-derived); query tools re-derive from the world
                # model.
                structured = self._structured_override
                if structured is None:
                    # Query results are re-derived after synchronous dispatch,
                    # outside its connector ContextVar scope. Rebind here so
                    # the typed status payload cannot enumerate objects that
                    # the text status correctly hid.
                    with self._bind_connector_principal(
                        caller_identity,
                        caller_trust_principal,
                        capability,
                    ):
                        structured = self._structured_result(name)
            except Exception:  # pragma: no cover -- structured form is best-effort
                structured = None
            if structured is not None:
                blocked = self._shield_block_or_none(
                    json.dumps(structured, default=str, sort_keys=True, ensure_ascii=False)
                )
                if blocked is not None:
                    return blocked
                response["structuredContent"] = structured
        # A successful mutating tool dirties a resource; queue the update to
        # flush after the result is sent (run() calls _flush_resource_updates).
        self._queue_resource_update(name)
        return response

    def _dispatch_tool(self, name: str, args: dict, *, capability=None) -> str:
        # Single dispatch table (the no-arg query tools ignore `args`). Keeping
        # one mapping prevents drift between this and _structured_result.
        start = (
            (lambda a: self._tool_start(a, capability=capability))
            if capability is not None else self._tool_start
        )
        resume = (
            (lambda a: self._tool_resume(a, capability=capability))
            if capability is not None else self._tool_resume
        )
        handlers = {
            "maverick_start": start,
            "maverick_status": lambda a: self._tool_status(),
            "maverick_resume": resume,
            "maverick_answer": lambda a: self._tool_answer(a),
            "maverick_skill_install": lambda a: self._tool_skill_install(a),
            "maverick_skills_list": lambda a: self._tool_skills_list(),
            "maverick_fact_set": lambda a: self._tool_fact_set(a),
            "maverick_facts_get": lambda a: self._tool_facts_get(),
            "maverick_fleet_ingest": lambda a: self._tool_fleet_ingest(a),
            "maverick_fleet_recall": lambda a: self._tool_fleet_recall(a),
        }
        handler = handlers.get(name)
        if handler is None:
            raise _ProtocolError(-32602, f"unknown tool {name!r}")
        return handler(args)

    def _application(self) -> MCPApplication:
        return MCPApplication(ApplicationDependencies(
            world_factory=_canonical_world, shield=self._shield,
            shield_scan_reason=self._shield_scan_reason,
            current_principal=self._current_object_principal,
            goal_for_principal=self._goal_for_principal, task_budget=_task_budget,
            bounded_int=_bounded_int, setting=mcp_setting,
            set_structured=lambda value: setattr(self, "_structured_override", value),
        ))

    def _tool_fleet_ingest(self, args: dict) -> str:
        return self._application()._tool_fleet_ingest(args)

    def _tool_fleet_recall(self, args: dict) -> str:
        return self._application()._tool_fleet_recall(args)

    def _structured_result(self, name: str) -> dict | None:
        return self._application()._structured_result(name)

    @staticmethod
    def _current_object_principal() -> str | None:
        """Principal whose persisted MCP objects are visible in this call."""
        from maverick.connections import current_principal

        return current_principal()

    @staticmethod
    def _goal_for_principal(world, goal_id: int, principal: str | None):
        """Return an authorized goal, hiding foreign ids as nonexistent."""
        goal = world.get_goal(goal_id)
        if goal is None:
            raise _ProtocolError(-32602, "goal not found")
        if principal is not None and (getattr(goal, "owner", "") or "") != principal:
            raise _ProtocolError(-32602, "goal not found")
        return goal

    def _tool_start(self, args: dict, *, capability=None) -> str:
        return self._application()._tool_start(args, capability=capability)

    def _tool_status(self) -> str:
        return self._application()._tool_status()

    def _tool_resume(self, args: dict, *, capability=None) -> str:
        return self._application()._tool_resume(args, capability=capability)

    def _tool_answer(self, args: dict) -> str:
        return self._application()._tool_answer(args)

    def _tool_skill_install(self, args: dict) -> str:
        return self._application()._tool_skill_install(args)

    def _tool_skills_list(self) -> str:
        return self._application()._tool_skills_list()

    def _tool_fact_set(self, args: dict) -> str:
        return self._application()._tool_fact_set(args)

    def _tool_facts_get(self) -> str:
        return self._application()._tool_facts_get()

    def _send(self, message: dict) -> None:
        from .stdio_transport import send_stdio_message

        send_stdio_message(message, stream=sys.stdout, lock=self._send_lock)

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        self._send(error_envelope(request_id, code, message))

    def _send_result(self, request_id: Any, result: dict) -> None:
        self._send(result_envelope(request_id, result))

    # ---- server-initiated elicitation (stdio, capability-gated) ----------

    def _client_supports_elicitation(self) -> bool:
        return (
            self._stdio
            and isinstance(self._client_capabilities, dict)
            and "elicitation" in self._client_capabilities
        )

    def _next_elicit_id(self) -> str:
        # String ids namespace our server->client requests so they can never be
        # confused with the client's own (integer) request ids on the wire.
        with self._send_lock:
            self._elicit_seq += 1
            return f"elicit-{self._elicit_seq}"

    def _exchange_elicitation(self, message: dict) -> dict | None:
        if self._stdio_session is not None:
            return self._stdio_session.elicit(message, _elicit_timeout())
        self._send(message)
        return self._await_elicit_response(message["id"], _elicit_timeout())

    def _elicit(self, message: str, requested_schema: dict) -> dict | None:
        """Send one elicitation/create and block for the client's response.

        Returns the MCP elicitation result ({"action": ..., "content"?: ...}),
        or None if the client can't elicit, the round trip times out, or the
        client errors -- callers fall back to the async question flow."""
        if not self._client_supports_elicitation():
            return None
        req_id = self._next_elicit_id()
        return self._exchange_elicitation({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "elicitation/create",
            "params": {"message": message, "requestedSchema": requested_schema},
        })

    def _elicit_url(self, message: str, url: str) -> dict | None:
        """URL-mode elicitation: point the user at ``url`` to provide a
        sensitive value (OAuth / API key / payment) **directly to the service**,
        so the secret never transits the model context. The response carries only
        an action (accept / decline / cancel) — never the credential.

        The prompt is shield-screened before it leaves (it's model-influenced
        text going to the user). ``url`` must be https. Returns the elicitation
        result, or ``None`` when the client can't elicit / times out."""
        if not self._client_supports_elicitation():
            return None
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError("URL-mode elicitation requires an https:// url")
        # Host allowlist: the destination is model-influenced, so a prompt
        # injection could otherwise aim the user at an attacker site to harvest
        # the very credential this flow protects. When [mcp] elicit_allowed_hosts
        # is configured, refuse a URL whose host isn't on it. No-op when unset.
        if not _elicit_host_allowed(url, _elicit_allowed_hosts()):
            raise ValueError(
                "URL-mode elicitation host is not in [mcp] elicit_allowed_hosts"
            )
        safe_message = self._screen_elicit_prompt(message)
        req_id = self._next_elicit_id()
        return self._exchange_elicitation({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "elicitation/create",
            "params": {"message": safe_message, "mode": "url", "url": url},
        })

    def elicit_url_action(self, message: str, url: str) -> str:
        """Run a URL-mode elicitation and return the outcome action:
        ``accept`` / ``decline`` / ``cancel``, or ``unavailable`` if the client
        can't elicit. No content is returned by design — the secret went
        user↔service directly, never through the LLM."""
        result = self._elicit_url(message, url)
        if result is None:
            return "unavailable"
        action = result.get("action")
        return action if action in ("accept", "decline", "cancel") else "cancel"

    def _screen_elicit_prompt(self, message: str) -> str:
        """Shield-screen an outbound elicitation prompt; fail-open to the raw
        text if no shield is configured or it errors (the shield is a chokepoint,
        not a hard dependency)."""
        shield = getattr(self, "_shield", None)
        if shield is None:
            return message
        try:
            verdict = shield.scan_output(message)
            if not getattr(verdict, "allowed", True):
                return "[elicitation prompt withheld by shield]"
        except Exception:  # pragma: no cover -- shield never blocks the flow
            pass
        return message

    def _await_elicit_response(self, req_id: str, timeout: float) -> dict | None:
        """Legacy direct-embedding wait; run() uses StdioSession's sole reader.

        The client is awaiting our tools/call result, so the only traffic we
        expect meanwhile is that response (plus the odd keep-alive ping). We
        answer pings, treat a cancelled notification as a cancel, and ignore
        anything else rather than re-entering tool dispatch from here."""
        import time as _time
        deadline = _time.monotonic() + max(0.0, timeout)
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                log.warning("elicitation %s timed out", req_id)
                return None
            line = self._readline_with_timeout(remaining)
            if not line:  # timeout (None) or EOF ('')
                return None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("id") == req_id and "method" not in msg:
                if "error" in msg:
                    return None
                result = msg.get("result")
                return result if isinstance(result, dict) else {}
            method = msg.get("method")
            if method == "ping" and msg.get("id") is not None:
                self._send_result(msg["id"], {})  # keep-alive
            elif method == "notifications/cancelled":
                return None
            # else: a stray message while we wait -- drop it (don't re-enter
            # tool dispatch from inside an in-flight tool call).

    def _readline_with_timeout(self, timeout: float | None) -> str | None:
        """Read a line from stdin, returning None if `timeout` elapses first.

        The timeout only applies when stdin is backed by a real fd (the stdio
        transport); test/StringIO streams fall through to a plain readline."""
        src = sys.stdin
        if timeout is not None and os.name == "posix":
            try:
                fd = src.fileno()
            except (AttributeError, OSError, ValueError):
                fd = None
            if fd is not None:
                import select
                ready, _, _ = select.select([src], [], [], timeout)
                if not ready:
                    return None
        return src.readline()

    def _maybe_elicit_open_questions(
        self,
        original_args: dict | None = None,
        *,
        capability=None,
    ) -> str | None:
        """Resolve questions the just-finished run parked, via elicitation.

        For an elicitation-capable stdio client: elicit each open question for
        the goal, record the answer (shield-screened) through the same path as
        maverick_answer, and resume so the swarm consumes it -- looping until no
        questions remain, the client declines, or a round cap is hit. Returns
        the final (resumed) answer, or None if nothing was elicited (caller
        keeps the original result; the async flow is unchanged)."""
        if not self._client_supports_elicitation():
            return None
        goal_id = (self._structured_override or {}).get("goal_id")
        if goal_id is None:
            return None
        with _canonical_world() as world:
            owner = self._current_object_principal()
            if owner is not None:
                try:
                    self._goal_for_principal(world, goal_id, owner)
                except _ProtocolError:
                    return None
            max_rounds = _bounded_int(
                mcp_setting("max_elicit_rounds", "8"),
                default=8, ceiling=64,
            )
            resume_args = {"goal_id": goal_id}
            for limit_name in ("max_dollars", "max_wall_seconds", "max_depth"):
                if original_args and limit_name in original_args:
                    resume_args[limit_name] = original_args[limit_name]
            final_answer: str | None = None
            for _ in range(max_rounds):
                questions = [q for q in world.open_questions() if q.goal_id == goal_id]
                if not questions:
                    break
                answered = False
                for q in questions:
                    from .execution import check_execution

                    check_execution()
                    reply = self._elicit_question(q.question)
                    if reply is None:
                        return final_answer  # declined / blocked / timed out
                    check_execution()
                    if owner is not None:
                        if not world.answer(q.id, reply, expected_owner=owner):
                            return final_answer
                    else:
                        # Preserve the local/stdio duck-typed WorldModel contract:
                        # older embeddings recorded the answer but returned None.
                        world.answer(q.id, reply)
                    answered = True
                if not answered:
                    break
                if capability is None:
                    final_answer = self._tool_resume(dict(resume_args))
                else:
                    final_answer = self._tool_resume(
                        dict(resume_args), capability=capability)
            return final_answer

    def _elicit_question(self, question: str) -> str | None:
        """Elicit one free-text answer, shield-screening both legs.

        Returns the answer string on accept, or None on decline/cancel, a
        shield block, or an unusable response (caller leaves it parked)."""
        # Outbound: the question is model-influenced text going to the user.
        if self._shield is not None:
            try:
                v = self._shield.scan_output(question)
                if not getattr(v, "allowed", True):
                    log.warning("elicitation prompt blocked by shield")
                    return None
            except Exception:  # pragma: no cover -- fail open (kernel rule 1)
                pass
        result = self._elicit(question, _ELICIT_ANSWER_SCHEMA)
        if not result or result.get("action") != "accept":
            return None
        content = result.get("content")
        if not isinstance(content, dict):
            return None
        answer = content.get("answer")
        if not isinstance(answer, str) or not answer:
            return None
        # Inbound: the answer is fed back into the agent loop -- scan it like
        # _tool_answer does before it becomes the user's reply.
        if self._shield is not None:
            try:
                v = self._shield.scan_input(answer)
                if not getattr(v, "allowed", True):
                    log.warning("elicited answer rejected by shield")
                    return None
            except Exception:  # pragma: no cover -- fail open (kernel rule 1)
                pass
        return answer

    # ---- MCP tasks (stdio: async, pollable tool execution) ----------------

    def _task_store(self):
        with self._tasks_lock:
            if self._tasks is None:
                from .tasks import TaskStore
                self._tasks = TaskStore(
                    lambda name, arguments: self._task_runner(name, arguments),
                    context_runner=self._task_runner,
                    on_status_change=self._emit_task_status)
        return self._tasks

    # ---- task JSON-RPC methods (shared by stdio + HTTP transports) --------

    def _require_tasks_enabled(self) -> None:
        """Reject tasks/* when this transport hasn't enabled tasks.

        Mirrors "capability absent -> method not supported": a client that
        didn't see the tasks capability shouldn't be calling these, and an
        HTTP deployment with tasks off must not silently spin up a store."""
        if not self._tasks_enabled:
            raise _ProtocolError(-32601, "tasks capability not enabled on this transport")

    def _task_authorizer(
        self, capability, caller_identity: str | None, caller_trust_principal: str | None, *,
        audit_denial: bool, refresh_context: _TaskExecutionContext | None = None,
    ):
        return task_authorizer(
            capability, caller_identity, caller_trust_principal,
            audit_denial=audit_denial, refresh_context=refresh_context,
            refresh_capability=lambda context: self._refresh_task_capability(context),
            record_denial=lambda grant, identity, tool: self._record_capability_denial(grant, identity, tool),
            principal_check=lambda principal: self._principal_permits(principal),
            capability_check=lambda grant, tool: self._capability_permits(grant, tool),
        )

    def handle_tasks_get(
        self,
        params: dict,
        *,
        task_owner: str | None = None,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        self._require_tasks_enabled()
        return self._task_store().get(
            params.get("taskId"),
            owner=task_owner,
            authorize=self._task_authorizer(
                capability,
                caller_identity,
                caller_trust_principal,
                audit_denial=True,
            ),
        )

    def _task_result_arguments(
        self,
        params: dict,
        *,
        task_owner: str | None = None,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        caller_credential_kind: str | None = None,
        caller_credential_fingerprint: str | None = None,
        capability=None,
    ) -> dict:
        self._require_tasks_enabled()
        refresh_context = None
        if caller_credential_kind is not None or caller_credential_fingerprint is not None:
            refresh_context = self._task_execution_context(
                caller_identity=caller_identity,
                trust_principal=caller_trust_principal,
                credential_kind=caller_credential_kind,
                credential_fingerprint=caller_credential_fingerprint,
                capability=capability,
            )
        return {
            "task_id": params.get("taskId"),
            "owner": task_owner,
            "authorize": self._task_authorizer(
                capability,
                caller_identity,
                caller_trust_principal,
                audit_denial=True,
            ),
            "reauthorize": self._task_authorizer(
                capability,
                caller_identity,
                caller_trust_principal,
                audit_denial=True,
                refresh_context=refresh_context,
            ),
        }

    def handle_tasks_result(self, params: dict, **kwargs) -> dict:
        arguments = self._task_result_arguments(params, **kwargs)
        return self._task_store().result(**arguments)

    async def handle_tasks_result_async(self, params: dict, **kwargs) -> dict:
        arguments = self._task_result_arguments(params, **kwargs)
        return await self._task_store().result_async(**arguments)

    def shutdown(self) -> None:
        self._requests.shutdown()
        with self._tasks_lock:
            if self._tasks is not None:
                self._tasks.shutdown()

    def handle_tasks_cancel(
        self,
        params: dict,
        *,
        task_owner: str | None = None,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        self._require_tasks_enabled()
        return self._task_store().cancel(
            params.get("taskId"),
            owner=task_owner,
            authorize=self._task_authorizer(
                capability,
                caller_identity,
                caller_trust_principal,
                audit_denial=True,
            ),
        )

    def handle_tasks_list(
        self,
        params: dict,
        *,
        task_owner: str | None = None,
        caller_identity: str | None = None,
        caller_trust_principal: str | None = None,
        capability=None,
    ) -> dict:
        self._require_tasks_enabled()
        return self._task_store().list(
            params.get("cursor"),
            owner=task_owner,
            authorize=self._task_authorizer(
                capability,
                caller_identity,
                caller_trust_principal,
                audit_denial=False,
            ),
        )

    def _emit_task_status(self, task) -> None:
        """Push a notifications/tasks/status when a task changes status.

        stdio-only: it writes to the bidirectional pipe via _send. The HTTP
        transport has no server->client push channel here, so this is a no-op
        there and HTTP clients learn of completion by polling tasks/get (which
        the spec requires them to support regardless).

        Optional per spec. Runs on the worker thread for completed/failed and
        the main thread for cancelled; _send is locked, so either is safe. No
        related-task _meta: the taskId is already in params."""
        if not self._stdio:
            return
        self._send({
            "jsonrpc": "2.0",
            "method": "notifications/tasks/status",
            "params": task.to_dict(),
        })

    @staticmethod
    def _refresh_task_capability(context: _TaskExecutionContext):
        return refresh_task_capability(
            context, setting=mcp_setting, fingerprint=_credential_fingerprint,
        )

    def _task_runner(
        self,
        name: str,
        arguments: dict,
        context: _TaskExecutionContext | None = None,
    ) -> dict:
        """Execute a task's tool on a FRESH server instance.

        Isolation matters: a background worker must not touch the main server's
        per-call state (``_structured_override`` / ``_pending_updates``) or its
        stdio. The fresh instance has ``_stdio=False``, so it takes the normal
        synchronous path (no elicitation, no resource-update flush) and returns
        the CallToolResult the client later fetches via ``tasks/result``."""
        worker = MCPServer()
        worker._shield = self._shield  # reuse the (stateless) shield scanner
        caller_identity = context.caller_identity if context is not None else None
        capability = (
            self._refresh_task_capability(context)
            if context is not None else None
        )
        from maverick.fleet_memory import bind_caller

        with bind_caller(caller_identity):
            return worker.handle_tools_call(
                {"name": name, "arguments": arguments},
                caller_identity=caller_identity,
                caller_trust_principal=(
                    context.trust_principal if context is not None else None
                ),
                capability=capability,
            )

    def _dispatch_stdio_message(self, method, request_id, params, is_notification) -> None:
        from .stdio_transport import dispatch_stdio_message

        dispatch_stdio_message(self, method, request_id, params, is_notification)

    def _handle_stdio_line(self, line: str) -> None:
        from .stdio_transport import handle_stdio_line

        handle_stdio_line(self, line, no_id=_NO_ID, logger=log)

    def run(self) -> None:
        from .stdio_transport import serve_stdio

        serve_stdio(self, stdin=sys.stdin, protocol_version=PROTOCOL_VERSION, logger=log)


def main() -> None:
    """Entry point. Defaults to stdio transport (Claude Desktop /
    Cursor compatible). Pass `--http` for the Streamable HTTP
    transport (hosted Lightwork, MCP gateways)."""
    import argparse
    ap = argparse.ArgumentParser(prog="maverick-mcp")
    ap.add_argument("--http", action="store_true",
                    help="Serve over Streamable HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8771)
    args = ap.parse_args()
    _configure_mcp_logging()
    from maverick.deployment import require_enterprise_or_die
    require_enterprise_or_die()
    if args.http:
        from .http_transport import serve
        serve(host=args.host, port=args.port)
    else:
        server = MCPServer()
        try:
            server.run()
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
