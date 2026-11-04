"""Govern enterprise-connector WRITES in the live tool path.

The enterprise REST connectors expose a service as a ``confirm=true``-gated tool
-- but the AGENT can set ``confirm`` itself, so a consequential write to a system
of record has no human in the loop. The live registry therefore enforces the
boundary for every compatible connector. Writes are simulated, human-gated, and surrounded
by durable PREPARE/COMMIT receipts. The agent cannot self-approve. Reads pass
through unchanged.

The governed ``apply`` reuses the ORIGINAL tool's write path (the same env auth +
SSRF-safe request), so wrapping never changes *where* a write goes -- only that
it must clear the approval gate and any required remote revision precondition
first.

Connectors whose tool exposes an ``op`` plus ``confirm`` schema are wrapped,
including the ``make_rest_tool`` family and bespoke Salesforce/ServiceNow
connectors. The wrapper derives a stable resource label from ``path`` when
available, or from connector-specific record identifiers for bespoke tools.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import uuid
from contextvars import ContextVar
from urllib.parse import urlsplit, urlunsplit

from .approval_cards import ApprovalCardError, digest
from .connector_attempts import CONTROL_ERRORS, ConnectorResult
from .safety.consent import ConsentDenied
from .tools import Tool

log = logging.getLogger(__name__)

_WRITE_OPS = (
    "post", "put", "patch", "delete",
    "record_create", "record_update", "record_delete",
    "create", "update",
)

_REVISION_EXEMPT_OPS = frozenset({
    "call_create", "capture", "comment", "create", "create_event",
    "dispatch", "dns_create", "event", "insert", "invoke",
    "lpush", "meeting_create", "mr_comment", "page_append", "page_create",
    "post", "publish", "record_create", "refund_create", "reply",
    "run", "send", "send_event", "send_mail", "sms", "sms_send",
    "submit_event", "submit_metric", "subscribe", "task_create", "track",
    "trigger",
})

# These provider operations create a new object or append a new comment. Their
# exact names differ from the generic create/comment verbs above; no existing
# remote record is overwritten by the requested operation.
_REVIEWED_CREATE_APPEND_OPS: dict[str, frozenset[str]] = {
    "hubspot": frozenset({"contact_create"}),
    "gitlab": frozenset({"issue_create", "issue_comment"}),
    "trello": frozenset({"card_create"}),
}


class _RevisionPreconditionError(ValueError):
    """A remote mutation has no enforceable compare-and-set boundary."""

# Bespoke external-system tools do not all use the REST factory's
# ``op`` + ``confirm`` schema. Their mutating operations still cross the same
# production trust boundary and therefore need the same durable transaction
# protocol in enterprise mode. Keep this explicit: inferring writes from words
# like ``call`` or from tool risk would either miss mutations or gate reads.
_BESPOKE_WRITE_OPS: dict[str, frozenset[str]] = {
    "asana": frozenset({"task_complete", "task_create"}),
    "calendar": frozenset({"create_event"}),
    "calendly": frozenset({"cancel"}),
    "clickup": frozenset({"task_create"}),
    "cloudflare": frozenset({"dns_create", "dns_delete", "dns_update", "purge"}),
    "confluence": frozenset({"page_create", "page_update"}),
    "databricks": frozenset({"job_run"}),
    "datadog": frozenset({"submit_event", "submit_metric"}),
    "discord_bot": frozenset({"post", "react", "reply"}),
    "dropbox": frozenset({"delete", "share", "upload"}),
    "email": frozenset({"send"}),
    "elasticsearch": frozenset({"delete", "index"}),
    "ga4": frozenset({"send_event"}),
    "github_actions": frozenset({"cancel", "dispatch"}),
    "github_issues": frozenset({"create"}),
    "gmail": frozenset({"send"}),
    "gitlab": frozenset({"issue_comment", "issue_create", "mr_comment"}),
    "gitlab_issues": frozenset({"create"}),
    "home_assistant": frozenset({"call_service"}),
    "hubspot": frozenset({"contact_create", "contact_update"}),
    "jira": frozenset({"comment", "create", "transition"}),
    "lambda": frozenset({"invoke"}),
    "linear": frozenset({"comment", "create", "update_status"}),
    "mixpanel": frozenset({"people_set", "track"}),
    "mongodb": frozenset({"delete", "insert", "update"}),
    "msgraph": frozenset({"send_mail"}),
    "notion": frozenset({"page_append", "page_create"}),
    # A described OpenAPI operation may be mutating even when its HTTP method
    # is hidden behind the operation id. Treat execution (not discovery) as the
    # consequential boundary.
    "openapi_runner": frozenset({"call"}),
    "plausible": frozenset({"event"}),
    "posthog": frozenset({"capture", "identify"}),
    "pagerduty": frozenset({"acknowledge", "resolve", "trigger"}),
    "redis": frozenset({"delete", "lpush", "publish", "set"}),
    # Replicate's paid ``run`` has no legacy confirm field. Explicit metadata
    # makes the tool governable and prevents a paid remote effect from falling
    # outside the transaction boundary.
    "replicate": frozenset({"cancel", "run"}),
    "sentry": frozenset({"resolve"}),
    "ses": frozenset({"send"}),
    "shopify": frozenset({"refund_create"}),
    "sns": frozenset({"publish", "sms", "subscribe", "unsubscribe"}),
    "spotify": frozenset({"pause", "play"}),
    "stripe": frozenset({"refund_create"}),
    "slack_bot": frozenset({"join", "post", "upload"}),
    "teams": frozenset({"send"}),
    "trello": frozenset({"card_create", "card_move", "comment"}),
    "twilio": frozenset({"call_create", "sms_send"}),
    "vercel": frozenset({"cancel"}),
    "zoom": frozenset({"meeting_create", "meeting_delete"}),
}

# Reviewed, tool-specific read metadata for confirm-bearing bespoke connectors.
# A global verb allowlist is insufficient: a future vendor could legitimately
# name a mutating operation ``get`` or reuse another connector's read verb.
# Unknown tool/operation pairs are governed until explicitly reviewed.
_BESPOKE_READ_OPS: dict[str, frozenset[str]] = {
    "airtable": frozenset({"get", "list"}),
    "asana": frozenset({"projects", "task_get", "tasks", "workspaces"}),
    "calendly": frozenset({"event_invitees", "event_types", "events", "me"}),
    "clickup": frozenset({"lists", "spaces", "task_get", "tasks", "teams"}),
    "cloudflare": frozenset({"dns_list"}),
    "confluence": frozenset({"page_get", "search"}),
    "databricks": frozenset({"jobs_list", "run_get"}),
    "datadog": frozenset({"monitor_get", "monitors"}),
    "dropbox": frozenset({"download", "list"}),
    "dynamodb": frozenset({"get", "query", "scan", "tables"}),
    "dynamics": frozenset({"query"}),
    "elasticsearch": frozenset({"count", "get", "indices", "search"}),
    "gdrive": frozenset({"export", "get", "list"}),
    "github_actions": frozenset({"jobs", "run_get", "runs", "workflows"}),
    "gmail": frozenset({"get", "labels", "list"}),
    "home_assistant": frozenset({"history", "state_get", "states"}),
    "hubspot": frozenset({"companies", "contact_get", "contacts", "deals"}),
    "lambda": frozenset({"get_function", "list_functions", "recent_logs"}),
    "mongodb": frozenset({"collections", "count", "find", "find_one"}),
    "msgraph": frozenset({"drive_list", "events", "me", "messages"}),
    "pagerduty": frozenset({"incident_get", "incidents", "on_call"}),
    "redis": frozenset({"get", "info", "keys", "lrange"}),
    "replicate": frozenset({"models", "predict_get"}),
    "s3": frozenset({"get", "list_buckets", "list_objects", "presign"}),
    "salesforce": frozenset({"record_get", "soql"}),
    "sentry": frozenset({"events", "issue_get", "issues", "releases"}),
    "servicenow": frozenset({"get", "query"}),
    "ses": frozenset({"quota", "verified_identities"}),
    "shopify": frozenset({
        "customer_get", "inventory", "order_get", "orders", "product_get",
        "products",
    }),
    "sns": frozenset({"topics"}),
    "spotify": frozenset({
        "playback_state", "playlist_get", "playlists", "search", "track_get",
    }),
    "stripe": frozenset({
        "balance", "charges", "customer_get", "customer_search", "subscriptions",
    }),
    "trello": frozenset({"boards", "card_get", "cards", "lists"}),
    "twilio": frozenset({"lookup", "sms_list"}),
    "vercel": frozenset({
        "deployment_get", "deployment_logs", "deployments", "domains", "projects",
    }),
    "zoom": frozenset({"meeting_get", "meetings", "recordings"}),
}

_SQL_CONNECTORS = frozenset({
    "bigquery", "database", "databricks", "oracle", "snowflake",
})

# A constant projection is the only SQL read whose lack of a remote data access
# or mutation can be established without parsing each provider's SQL dialect.
# Do not admit comments, expressions, FROM clauses, or stacked statements here.
_PURE_SQL_PROBE = re.compile(r"[ \t\r\n]*SELECT[ \t\r\n]+1[ \t\r\n]*;?[ \t\r\n]*", re.ASCII | re.IGNORECASE)

# Only the exact request that cleared a fresh human decision may omit a remote
# revision in a connector that otherwise requires one. A model cannot set this
# ContextVar through tool arguments.
_APPROVED_NO_REVISION: ContextVar[tuple[str, str] | None] = ContextVar(
    "lightwork_approved_connector_without_revision", default=None,
)


def approved_without_revision(name: str, args: dict) -> bool:
    current = _APPROVED_NO_REVISION.get()
    if current is None or current[0] != name:
        return False
    request = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(request.encode("utf-8")).hexdigest() == current[1]


def _no_revision_review_note(contract: dict[str, object]) -> str:
    if contract.get("state") != "human_approved_no_revision":
        return ""
    return (
        "; NO REMOTE REVISION CHECK: Lightwork has not verified whether this "
        "service offers an ETag; the request could overwrite newer work"
    )


def _unresolved_connector_assumptions(contract: dict[str, object]) -> list[str]:
    assumptions = [
        "The remote service may apply additional automation after accepting the request."
    ]
    if contract.get("state") == "human_approved_no_revision":
        assumptions.append(
            "No current ETag was supplied. Lightwork has not verified whether "
            "the service offers one, so newer remote work could be overwritten."
        )
    return assumptions


def _is_pure_sql_probe(tool_name: str, args: dict) -> bool:
    field = "sql" if tool_name in {"bigquery", "database"} else "statement"
    statement = args.get(field)
    return isinstance(statement, str) and _PURE_SQL_PROBE.fullmatch(statement) is not None


def _governed_description(tool: Tool) -> str:
    from .tools._lazy import GOVERNED_DESCRIPTION_NOTE

    if tool.name in _SQL_CONNECTORS:
        # Raw connector descriptions advertise ordinary SQL reads. The live
        # governed registry sends anything beyond a constant probe through a
        # fresh human decision because SQL dialects admit effectful functions.
        return (
            f"{tool.name} SQL. A constant SELECT 1 connection check runs "
            "directly. Other queries and changes require a fresh human review; "
            "the review explains when the service has no concurrency protection."
            + GOVERNED_DESCRIPTION_NOTE
        )[:1024]
    return (tool.description + GOVERNED_DESCRIPTION_NOTE)[:1024]


def _enterprise_mode() -> bool:
    """Central enterprise predicate, strict on policy-source uncertainty.

    The connector wrapper is a mandatory enterprise floor.  If the config
    source that may contain ``[enterprise] mode = true`` is unreadable, the
    safe interpretation at this effect boundary is enterprise-on; treating a
    loader error as ``False`` would silently remove approval and receipts.
    """
    try:
        from .config import config_source_errors
        from .enterprise import enterprise_enabled

        if config_source_errors():
            log.error(
                "governed_connectors: config source unreadable; enforcing "
                "enterprise connector governance",
            )
            return True
        return bool(enterprise_enabled())
    except Exception:
        log.exception(
            "governed_connectors: enterprise policy unavailable; enforcing "
            "connector governance",
        )
        return True


def _approver() -> str:
    """The standing approver of record for governed connector writes."""
    a = os.environ.get("MAVERICK_GOVERNED_APPROVER", "").strip()
    if a:
        return a
    try:
        from .config import get_governed_connectors
        return str(get_governed_connectors().get("approver", "")).strip()
    except Exception:  # pragma: no cover -- config must never break tool assembly
        return ""


def _is_governable_op_tool(tool: Tool) -> bool:
    """Whether ``tool`` speaks an op/confirm schema we can govern.

    ``make_rest_tool`` connectors include ``path``; Salesforce and ServiceNow
    use bespoke record identifiers. GraphQL connectors also expose ``op`` plus
    ``confirm``, but mutations are declared in the ``query`` document instead of
    the ``op`` value, so the wrapper detects those writes separately. In all
    cases, governance can safely force ``confirm=True`` only after approval
    because the original tool keeps full responsibility for validating and
    applying the requested write.
    """
    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict) or "op" not in props:
        return False
    return "confirm" in props or tool.name in _BESPOKE_WRITE_OPS


def _is_graphql_op_tool(tool: Tool) -> bool:
    """Whether ``tool`` uses the GraphQL op/query/confirm connector schema."""
    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict) or "query" not in props or "confirm" not in props:
        return False
    op = props.get("op")
    if not isinstance(op, dict):
        return False
    enum = op.get("enum")
    return isinstance(enum, list) and {str(item).lower() for item in enum} == {"query"}


def _is_declared_rest_op_tool(tool: Tool) -> bool:
    """Whether a schema declares the reviewed HTTP verb/path contract."""
    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict) or "path" not in props:
        return False
    raw_op = props.get("op")
    enum = raw_op.get("enum") if isinstance(raw_op, dict) else None
    operations = {str(item).lower() for item in enum or []}
    return bool(operations) and operations <= {"get", "post", "put", "patch", "delete"}


def _is_governed_write(tool: Tool, args: dict) -> bool:
    """Return whether this connector call needs the governed write boundary.

    Confirm-bearing connector operations fail closed: only an explicitly safe
    read may bypass governance. That makes new/custom operation names safe by
    default instead of depending on an ever-growing write denylist.
    """
    op = str(args.get("op") or ("send" if tool.name == "teams" else "")).strip().lower()
    if _is_graphql_op_tool(tool):
        from .tools._rest_connector import _graphql_has_mutation

        return _graphql_has_mutation(str(args.get("query") or ""))
    if tool.name in _SQL_CONNECTORS and op in {"query", "sql"}:
        # SQL cannot be proven side-effect-free from a leading keyword across
        # dialects: SELECT INTO/OUTFILE, locks, sequences, and stored/volatile
        # functions all mutate. Only an exact constant SELECT 1 probe bypasses
        # the write boundary; all data reads and writes remain governed.
        return not _is_pure_sql_probe(tool.name, args)
    if tool.name == "lambda" and op == "invoke":
        return str(args.get("invocation_type") or "RequestResponse").lower() != "dryrun"
    if op in _BESPOKE_WRITE_OPS.get(tool.name, frozenset()):
        return True
    if op in _WRITE_OPS:
        return True
    if _is_declared_rest_op_tool(tool):
        return op != "get"
    props = (tool.input_schema or {}).get("properties", {})
    if not isinstance(props, dict) or "confirm" not in props:
        return False
    return op not in _BESPOKE_READ_OPS.get(tool.name, frozenset())


def _resource_label(tool_name: str, args: dict) -> str:
    """Return a stable, non-secret label for the governed write preview."""
    if tool_name in _SQL_CONNECTORS:
        return f"{tool_name} SQL statement"
    if tool_name == "teams":
        try:
            webhook = urlsplit(str(args.get("webhook") or os.environ.get("TEAMS_WEBHOOK_URL") or ""))
            return urlunsplit((webhook.scheme, webhook.netloc, "", "", "")) or "Teams webhook"
        except ValueError:
            return "Teams webhook"
    path = str(args.get("path") or "").strip()
    if path:
        return path
    if tool_name == "salesforce":
        sobject = str(args.get("sobject") or "").strip()
        rid = str(args.get("id") or "").strip()
        return "/".join(part for part in ("sobjects", sobject, rid) if part)
    if tool_name == "servicenow":
        table = str(args.get("table") or "").strip()
        sys_id = str(args.get("sys_id") or "").strip()
        return "/".join(part for part in ("table", table, sys_id) if part)
    return str(args.get("op") or "write")


def _connector_effect(tool_name: str, operation: str, path: str) -> str:
    if tool_name in _SQL_CONNECTORS and operation in {"query", "sql"}:
        return f"Run a SQL statement in {tool_name}"
    return f"would {operation.upper()} {tool_name} {path}".rstrip()


def _safe_resource_label(value: str) -> str:
    """Return readable target context without query/userinfo capabilities."""

    text = str(value or "").strip()
    try:
        parts = urlsplit(text)
        if parts.scheme or parts.netloc:
            host = parts.hostname or ""
            if parts.port is not None:
                host = f"{host}:{parts.port}"
            text = urlunsplit((parts.scheme, host, parts.path, "", ""))
        else:
            text = text.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        text = "[invalid connector target]"
    try:
        from .safety.secret_detector import redact

        text, _matches = redact(" ".join(text.split()))
    except Exception:
        return "[connector target unavailable]"
    return (text or "[connector target]")[:500]


def _safe_connector_result(value: object) -> str:
    """Redact a connector result before receipts or model-visible return."""

    raw = str(value)
    try:
        from .safety.secret_detector import redact

        raw, _matches = redact(raw)
    except Exception:
        return f"[connector result withheld; sha256={digest(raw)}]"
    return raw


def _governed_public_result(result, safe_result: str, state):
    """Preserve explicit state after redaction and a durable COMMIT receipt."""
    from .tool_results import ToolOutcome, ToolResultText, classify_tool_result

    if isinstance(result, (ToolOutcome, ToolResultText)):
        return ToolResultText(safe_result, state)
    if isinstance(result, ConnectorResult) and classify_tool_result(safe_result) is not state:
        return ToolResultText(safe_result, state)
    return safe_result


def _connector_revision_contract(tool: Tool, args: dict) -> dict[str, object]:
    """Resolve an enforceable remote compare-and-set contract for a write."""

    op = str(args.get("op") or "").strip().lower()
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
    declared = schema.get("x-lightwork-conditional-revision")
    if isinstance(declared, dict):
        field = str(declared.get("field") or "").strip()
        header = str(declared.get("header") or "").strip()
        operations = {
            str(item).strip().lower()
            for item in declared.get("operations", [])
        }
        if op in operations:
            if not field or not header:
                raise _RevisionPreconditionError("the connector's revision contract is incomplete")
            value = args.get(field)
            if value is None or value == "":
                return {
                    "schema": "lightwork.connector-conditional-revision.v1",
                    "state": "human_approved_no_revision",
                    "reason": "No current ETag was supplied; newer remote work could be overwritten",
                }
            if (
                not isinstance(value, str)
                or not value.strip()
                or value.strip() == "*"
                or len(value) > 512
                or "\r" in value
                or "\n" in value
            ):
                raise _RevisionPreconditionError(
                    "the current remote ETag/revision is required"
                )
            return {
                "schema": "lightwork.connector-conditional-revision.v1",
                "field": field,
                "header": header,
                "value_sha256": digest(value.strip()),
            }

    existing_state_mutation = (
        _is_graphql_op_tool(tool)
        or tool.name in _SQL_CONNECTORS
        or (op not in _REVISION_EXEMPT_OPS
            and op not in _REVIEWED_CREATE_APPEND_OPS.get(tool.name, frozenset()))
    )
    if existing_state_mutation:
        return {
            "schema": "lightwork.connector-conditional-revision.v1",
            "state": "human_approved_no_revision",
            "reason": "No current ETag was supplied; newer remote work could be overwritten",
        }
    return {
        "schema": "lightwork.connector-conditional-revision.v1",
        "state": "not_applicable",
        "reason": "reviewed create, append, or one-shot effect",
    }


def _approval_detail(
    effect: str,
    *,
    transaction_id: str,
    request_digest: str,
) -> str:
    """Brief approval headline; the complete redacted request is shown below."""
    return (
        f"{effect}; transaction_id={transaction_id}; "
        f"request_sha256={request_digest}; review every redacted request part below"
    )


_REDACTED_REQUEST_VALUE = "[REDACTED:sensitive field]"
_SENSITIVE_REQUEST_WORDS = frozenset({
    "auth", "authorization", "bearer", "cert", "certificate", "credential",
    "credentials", "password", "passwd", "passphrase", "secret", "secrets",
    "token", "cookie", "cookies", "dsn", "key", "apikey", "accesskey", "webhook",
    "privatekey", "clientsecret", "connectionstring",
})
_SENSITIVE_REQUEST_PAIRS = frozenset({
    ("api", "key"), ("access", "key"), ("private", "key"),
    ("connection", "string"),
})


def _sensitive_request_key(key: object) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    words = re.findall(r"[a-z0-9]+", separated.lower())
    return any(word in _SENSITIVE_REQUEST_WORDS for word in words) or any(
        pair in _SENSITIVE_REQUEST_PAIRS for pair in zip(words, words[1:], strict=False)
    )


def _redact_request_fields(value: object, *, sensitive: bool = False) -> object:
    """Retain the request shape while hiding all leaves below sensitive keys."""
    if isinstance(value, dict):
        return {
            key: _redact_request_fields(
                item, sensitive=sensitive or _sensitive_request_key(key),
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_request_fields(item, sensitive=sensitive) for item in value]
    return _REDACTED_REQUEST_VALUE if sensitive else value


def _approval_request_parts(args: dict) -> list[str]:
    """Show the frozen request shape with sensitive values redacted."""
    size = 380
    try:
        raw_request = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
        if not raw_request or len(raw_request) > size * 20:
            raise ApprovalCardError("the full connector request is too long to review")
        request = json.dumps(
            _redact_request_fields(args), sort_keys=True,
            separators=(",", ":"), default=str,
        )
        from .safety.secret_detector import redact

        request, _ = redact(request)
        if len(request) > size * 20:
            raise ApprovalCardError("the full connector request is too long to review")
    except ApprovalCardError:
        raise
    except Exception as exc:
        raise ApprovalCardError("the full connector request could not be shown") from exc
    parts = [request[i:i + size] for i in range(0, len(request), size)]
    return [f"Request part {i + 1}/{len(parts)}: {part}" for i, part in enumerate(parts)]


def _approval_card_error_reason(exc: ApprovalCardError) -> str:
    lowered = str(exc).lower()
    if "expired" in lowered:
        return "approval expired"
    if "full connector request" in lowered:
        return str(exc)
    if "actor is unavailable" in lowered:
        return "the current signed-in actor is unavailable"
    return "the operation or its authority changed"


def _connector_credential_versions(tool: Tool) -> dict[str, str]:
    """Commit to live connector credential authority without retaining secrets.

    Connectors resolve credentials at their request boundary.  The generic
    wrapper cannot safely read a token, but it can bind every process
    credential generation and every sealed connection revision.  Any rotation
    therefore invalidates a waiting permit before the connector is called.
    """

    from .approval_cards import digest

    environment = [
        [name, hashlib.sha256(value.encode("utf-8")).hexdigest()]
        for name, value in sorted(os.environ.items())
    ]
    from .connections import list_connections

    connections = [
        {
            "name": row.get("name"),
            "connector": row.get("connector"),
            "revision": row.get("revision"),
            "owner": row.get("owner"),
            "access": row.get("access"),
            "allowed_principals": row.get("allowed_principals"),
        }
        for row in list_connections()
    ]
    implementation = {
        "module": getattr(tool.fn, "__module__", ""),
        "qualname": getattr(tool.fn, "__qualname__", type(tool.fn).__qualname__),
        "bytecode_sha256": hashlib.sha256(
            getattr(getattr(tool.fn, "__code__", None), "co_code", b"")
        ).hexdigest(),
    }
    return {
        "schema": "lightwork.connector-credential-authority.v1",
        "process_environment_sha256": digest(environment),
        "saved_connections_sha256": digest(connections),
        "implementation_sha256": digest(implementation),
    }


def _connector_target(
    tool: Tool,
    path: str,
    revision_contract: dict[str, object],
) -> dict[str, object]:
    """Live connector/operation target re-read at permit consumption."""

    return {
        "tool": tool.name,
        "resource": path,
        "conditional_revision": copy.deepcopy(revision_contract),
        "input_schema": tool.input_schema,
        "implementation": {
            "module": getattr(tool.fn, "__module__", ""),
            "qualname": getattr(tool.fn, "__qualname__", type(tool.fn).__qualname__),
        },
    }


def _wrap_lazy_connector_tool(tool, *, goal_id, actor, enterprise):
    # Discovery needs exactly the governed schema/description, but not the
    # thousands of executor/receipt closures. Bind this registry's actor,
    # goal and enterprise snapshot; the existing wrapper is constructed
    # around the real connector before its first invocation.
    strict = _enterprise_mode() if enterprise is None else bool(enterprise)
    return tool.with_wrapper(
        lambda resolved: wrap_connector_tool(
            resolved, goal_id=goal_id, actor=actor, enterprise=strict,
        ),
        description=_governed_description(tool),
    )


def wrap_connector_tool(
    tool: Tool,
    *,
    goal_id: int | None = None,
    actor: str = "",
    enterprise: bool | None = None,
) -> Tool:
    """Return a connector with simulate, approval, and durable receipts.

    The external effect is never attempted until a PREPARE receipt is fsynced.
    A missing COMMIT receipt after the effect produces an explicit
    ``INDETERMINATE`` outcome so callers do not blindly retry a write.
    """
    from .tools._lazy import LazyTool

    if isinstance(tool, LazyTool):
        return _wrap_lazy_connector_tool(
            tool, goal_id=goal_id, actor=actor, enterprise=enterprise,
        )
    return _wrap_connector_executor(tool, goal_id=goal_id, actor=actor, enterprise=enterprise)


def _preserve_connector_failure(exc, receipt):
    """Record an uncertain effect without consuming the originating stop."""
    detail = type(exc).__name__[:120]
    stopping = isinstance(exc, (*CONTROL_ERRORS, asyncio.CancelledError))
    try:
        receipt(detail)
    except (Exception, asyncio.CancelledError) as reporting_error:
        # Preserve the original stop even when its receipt separately fails.
        # A newly raised stop still propagates when the original was ordinary.
        if not stopping and isinstance(reporting_error, (*CONTROL_ERRORS, asyncio.CancelledError)):
            raise
    if stopping:
        raise exc
    return detail


def _prepare_connector_args(tool: Tool, args: dict) -> tuple[dict, str | None]:
    if tool.name != "teams":
        return args, None
    args = copy.deepcopy(args)
    if args.get("webhook"):
        return args, "ERROR: Teams accepts only the operator-configured webhook destination"
    if not args.get("op"):
        args["op"] = "send"
    return args, None


def _connector_approval_denial(decision, decision_actor: str, expected_approver: str, path: str) -> str | None:
    if decision.source == "dashboard" and not decision_actor:
        return (
            "REFUSED (governed): the dashboard decision did not carry "
            f"an authenticated approver identity for target {path!r}; no write was attempted."
        )
    if expected_approver and decision_actor != expected_approver:
        return (
            "REFUSED (governed): the configured approver did not approve "
            f"the change to {path!r}; no write was attempted."
        )
    return None


def _wrap_connector_executor(
    tool: Tool,
    *,
    goal_id: int | None,
    actor: str,
    enterprise: bool | None,
) -> Tool:
    """Bind the existing governed boundary around a materialized executor."""
    from .governed_actions import (
        ActionError,
        ActionSpec,
        GovernedActions,
        record_tool_lineage,
    )

    strict = _enterprise_mode() if enterprise is None else bool(enterprise)

    def _receipt(
        *,
        action: str,
        args: dict,
        effect: str,
        approver: str,
        transaction_id: str,
        phase: str,
        result: str = "",
        strict_write: bool,
    ) -> bool:
        return record_tool_lineage(
            goal_id,
            action,
            args,
            actor=actor,
            effect=effect,
            result=result,
            approver=approver,
            transaction_id=transaction_id,
            phase=phase,
            sources=(f"tool:{tool.name}",),
            force=True,
            strict=strict_write,
        )

    def _fn(args: dict) -> str:
        args, error = _prepare_connector_args(tool, args)
        if error:
            return error
        op = str(args.get("op", "")).strip().lower()
        if not _is_governed_write(tool, args):
            return tool.fn(args)
        resource = _resource_label(tool.name, args)
        path = _safe_resource_label(resource)
        ga = GovernedActions()
        action = f"{tool.name}.write"
        ga.register(ActionSpec(
            name=action,
            params={"op": str, "path": str},
            risk="high",
            simulate=lambda p: _connector_effect(tool.name, p["op"], p["path"]),
        ))
        params = {"op": op, "path": path}
        try:
            try:
                revision_contract = _connector_revision_contract(tool, args)
            except _RevisionPreconditionError as exc:
                return (
                    "REFUSED (governed): a fresh read and atomic remote "
                    f"revision precondition are required for target {path!r} "
                    f"({exc}); no external write was attempted."
                )
            preview = ga.simulate(action, params)

            # Freeze the exact request before approval so a caller retaining a
            # reference to the input dict cannot race a different payload into
            # the external call after the human decision.  ``confirm`` is part
            # of the binding because it is forced at the effect boundary.
            receipt_args = copy.deepcopy(args)
            receipt_args["confirm"] = True
            request_bytes = json.dumps(
                receipt_args, sort_keys=True, separators=(",", ":"), default=str,
            ).encode("utf-8")
            request_digest = hashlib.sha256(request_bytes).hexdigest()
            transaction_id = uuid.uuid4().hex

            # Every connector mutation requires a fresh explicit human decision:
            # neither silent auto approval nor a persistent ledger grant can
            # authorize this external effect.
            from .safety.consent import (
                consume_operation_consent,
                require_operation_consent,
            )

            approval_scope = f"{path}#sha256={request_digest}"
            approval_detail = _approval_detail(
                    preview.effect,
                    transaction_id=transaction_id,
                    request_digest=request_digest,
                )
            request_parts = _approval_request_parts(receipt_args)
            no_revision = revision_contract.get("state") == "human_approved_no_revision"
            approval_detail += _no_revision_review_note(revision_contract)
            expected_approver = _approver()

            def approval_target():
                return {**_connector_target(tool, resource, revision_contract),
                        "standing_approver": _approver()}

            permit = require_operation_consent(
                action,
                risk="high",
                scope=approval_scope,
                detail=approval_detail,
                provenance="governed-connector",
                target=approval_target(),
                parameters={
                    "request": receipt_args,
                    "transaction_id": transaction_id,
                },
                parameter_summary=[
                    "Review every redacted request part below. The SHA-256 binds the exact inputs sent once.",
                    *request_parts,
                    (
                        "Remote revision precondition: "
                        f"{revision_contract.get('header', revision_contract.get('reason'))}."
                    ),
                ],
                known_effects=[preview.effect],
                unresolved_assumptions=_unresolved_connector_assumptions(revision_contract),
                before="No PREPARE receipt or remote write exists for this transaction.",
                after="The remote system may contain the reviewed change and Lightwork records its outcome.",
                irreversible=True,
                target_provider=approval_target,
                parameters_provider=lambda: {
                    "request": copy.deepcopy(receipt_args),
                    "transaction_id": transaction_id,
                },
                input_versions_provider=lambda: {
                    "request_sha256": request_digest,
                },
                credential_versions_provider=lambda: (
                    _connector_credential_versions(tool)
                ),
                budget_provider=lambda: {
                    "transaction_id": transaction_id,
                    "external_effect_cost": "unmeasured",
                },
                allow_auto_approve=False,
                consult_ledger=False,
            )
            decision = permit.decision

            decision_actor = str(getattr(decision, "actor", "") or "").strip()
            denial = _connector_approval_denial(decision, decision_actor, expected_approver, path)
            if denial:
                return denial
            approval_identity = decision_actor or decision.source
            try:
                prepared = _receipt(
                    action=f"{action}.prepare",
                    args=receipt_args,
                    effect=preview.effect,
                    approver=approval_identity,
                    transaction_id=transaction_id,
                    phase="PREPARE",
                    strict_write=strict,
                )
            except Exception:  # strict ledger failure: effect has not started
                prepared = False
            if not prepared:
                return (
                    "REFUSED (governed): the durable PREPARE receipt could not "
                    f"be persisted for target {path!r}; no external write was "
                    "attempted."
                )

            # Spend and revalidate after PREPARE, immediately before the
            # connector crosses its remote effect boundary.
            with consume_operation_consent(permit):
                token = _APPROVED_NO_REVISION.set(
                    (tool.name, request_digest) if no_revision else None
                )
                try:
                    result = tool.fn(receipt_args)
                except (Exception, asyncio.CancelledError) as exc:
                    # Exception messages from HTTP/database libraries routinely
                    # embed credentialed URLs, headers, and DSNs. Receipts and the
                    # model-visible result get only a bounded type marker; the
                    # transaction id is sufficient for privileged reconciliation.
                    detail = _preserve_connector_failure(
                        exc, lambda detail: _receipt(
                            action=f"{action}.indeterminate",
                            args=receipt_args,
                            effect=preview.effect,
                            result=detail,
                            approver=approval_identity,
                            transaction_id=transaction_id,
                            phase="INDETERMINATE",
                            strict_write=False,
                        ),
                    )
                    return (
                        "INDETERMINATE (governed): the connector raised after its "
                        "external-effect boundary; reconcile before retrying. "
                        f"transaction_id={transaction_id}; failure_type={detail}"
                    )
                finally:
                    _APPROVED_NO_REVISION.reset(token)

            # A string error from a connector is also ambiguous: several
            # connector implementations catch network exceptions internally,
            # after the remote system may have accepted the request. Never
            # convert that uncertainty into an ordinary retryable failure.
            from .tool_results import ToolOutcome, ToolResultState

            outcome = ToolOutcome.from_legacy(result)
            result_state = outcome.state
            if result_state is not ToolResultState.SUCCEEDED:
                result_marker = result_state.value
                try:
                    _receipt(
                        action=f"{action}.indeterminate",
                        args=receipt_args,
                        effect=preview.effect,
                        result=result_marker,
                        approver=approval_identity,
                        transaction_id=transaction_id,
                        phase="INDETERMINATE",
                        strict_write=False,
                    )
                except Exception:
                    pass
                return (
                    "INDETERMINATE (governed): the connector did not prove a "
                    "committed or definitively aborted write; reconcile before "
                    f"retrying. transaction_id={transaction_id}; "
                    f"result_state={result_marker}"
                )

            safe_result = _safe_connector_result(outcome.content)
            try:
                committed = _receipt(
                    action=f"{action}.commit",
                    args=receipt_args,
                    effect=preview.effect,
                    result=safe_result,
                    approver=approval_identity,
                    transaction_id=transaction_id,
                    phase="COMMIT",
                    strict_write=strict,
                )
            except Exception:  # effect completed but durable ACK did not
                committed = False
            if not committed:
                return (
                    "INDETERMINATE (governed): the connector write may have "
                    "succeeded, but its COMMIT receipt could not be persisted. "
                    f"transaction_id={transaction_id}; do not retry automatically."
                )
            return _governed_public_result(result, safe_result, result_state)
        except CONTROL_ERRORS:
            raise
        except ConsentDenied:
            return (
                f"REFUSED (governed): approval was denied for target {path!r}; "
                "no external write was attempted."
            )
        except ApprovalCardError as exc:
            reason = _approval_card_error_reason(exc)
            return (
                f"REFUSED (governed): {reason} for target {path!r}; review the "
                "current target and request again. No external write was "
                "attempted."
            )
        except ActionError:
            return "ERROR (governed): action policy rejected the request"
        except Exception as exc:  # noqa: BLE001 -- policy errors refuse writes
            return (
                "ERROR (governed): internal policy failure; no retry without "
                f"operator review (failure_type={type(exc).__name__[:120]})"
            )

    # Preserve connector provenance used by registry inventory and credential
    # scoping checks while the closure still supplies the governed boundary.
    _fn.__module__ = getattr(tool.fn, "__module__", _fn.__module__)
    _fn.__qualname__ = "wrap_connector_tool.<locals>._fn"
    return Tool(
        name=tool.name,
        description=_governed_description(tool),
        input_schema=tool.input_schema,
        fn=_fn,
        parallel_safe=False,
    )


def governance_enabled() -> bool:
    """The live connector mutation boundary is always active."""

    return True


def apply_governed_connectors(reg, *, goal_id: int | None = None) -> list[str]:
    """Replace external write tools with governed wrappers.

    Every compatible connector is wrapped. Configuration may name connectors
    for inventory checks, but cannot remove the mutation boundary.
    """
    if not governance_enabled():
        return []
    enterprise = _enterprise_mode()
    try:
        from .config import get_governed_connectors
        names = get_governed_connectors().get("connectors", [])
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("cannot load governed connector policy") from exc

    configured = [str(name).strip() for name in names if str(name).strip()]
    available = {tool.name: tool for tool in reg.all()}
    if enterprise and configured:
        invalid = [
            name for name in configured
            if name not in available or not _is_governable_op_tool(available[name])
        ]
        if invalid:
            raise RuntimeError(
                "enterprise governed connector policy names missing or "
                f"incompatible tools: {', '.join(sorted(invalid))}"
            )

    candidates = [
        name for name, tool in available.items()
        if _is_governable_op_tool(tool)
    ]

    wrapped: list[str] = []
    for name in candidates:
        try:
            tool = reg.get(name)
        except Exception:  # noqa: BLE001 -- unknown/ACL'd name: skip
            continue
        if not _is_governable_op_tool(tool):
            log.info("governed_connectors: %s is not an op/confirm tool; left ungoverned", name)
            continue
        reg.register(wrap_connector_tool(
            tool,
            goal_id=goal_id,
            actor=str(getattr(reg, "_principal", "") or ""),
            enterprise=enterprise,
        ))
        wrapped.append(name)
    return wrapped


__all__ = ["wrap_connector_tool", "apply_governed_connectors", "governance_enabled"]
