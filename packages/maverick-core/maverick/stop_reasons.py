"""Plain-language explanations for a run that stopped.

The kernel records WHY a run stopped as a string on the goal (``goal.result``
for a blocked goal): a quota refusal, a paused workspace, a provider outage,
an internal error. Those strings are written for logs -- they name tenant
ids, principals and exception classes. This module is the one place that
turns them into what a person reading the chat needs: what happened, the
next step, and where to take it. Raw text is kept only as ``technical``
detail for administrators.

Classification is by the wording the kernel writes (see the ``_RULES`` table);
the order matters -- the tenant refusal starts with ``over quota:`` and must
not be read as a spending problem.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: Most raw text an explanation carries for administrators.
RAW_TEXT_LIMIT = 1000
_MESSAGE_LIMIT = 600

#: Where AI provider keys live: Settings > Connections > Provider keys, with
#: the row of the provider that needs attention focused. The Connections page
#: is for connected accounts (and may be turned off), not AI keys.
AI_PROVIDER_KEYS_HREF = "/settings?focus=ai-provider#settings-integrations"

_GENERIC_MESSAGE = "The run stopped before finishing."
_GENERIC_ACTION = "Try again. If it keeps stopping, ask an administrator to check the logs."


def exception_stop_text(exc: BaseException) -> str:
    """Store a stable, non-sensitive cause for a failed AI call.

    SDK exception text can contain URLs, account names, and provider response
    bodies. Those belong in the server log, never in the customer-facing goal.
    Classification uses SDK type/status rather than matching those bodies.
    """
    from .circuit_breaker import CircuitOpen

    if isinstance(exc, CircuitOpen):
        # The AI service was paused after repeated errors (the service banner
        # says when Lightwork checks again); not a fault inside Lightwork.
        return "provider_error:paused"
    name = type(exc).__name__
    module = type(exc).__module__.split(".", 1)[0]
    provider = module in {"openai", "anthropic"} or name in {
        "APIConnectionError", "APITimeoutError", "AuthenticationError",
        "RateLimitError", "InternalServerError", "NotFoundError",
    }
    if not provider:
        return "internal error"
    status = getattr(exc, "status_code", None)
    if status in {401, 403} or name == "AuthenticationError":
        return "provider_error:authentication"
    if status == 429 or name == "RateLimitError":
        return "provider_error:rate_limit"
    if status == 404 or name == "NotFoundError":
        return "provider_error:model_not_found"
    if (isinstance(status, int) and status >= 500) or name == "InternalServerError":
        return "provider_error:unavailable"
    if name in {"APIConnectionError", "APITimeoutError"}:
        return "provider_error:connection"
    return "provider_error:configuration"


@dataclass(frozen=True)
class StopReason:
    """What a person reads when a run stops."""

    kind: str
    message: str
    action: str
    link: str | None = None
    link_label: str | None = None
    technical: str = ""

    def as_dict(self, *, include_technical: bool = False) -> dict:
        out = {"kind": self.kind, "message": self.message, "action": self.action,
               "link": self.link, "link_label": self.link_label}
        if include_technical:
            out["technical"] = self.technical
        return out


def _rx(*parts: str) -> re.Pattern[str]:
    return re.compile("|".join(parts), re.IGNORECASE)


# (kind, pattern, message, action, link, link_label) -- first match wins.
_RULES: tuple[tuple[str, re.Pattern[str], str, str, str | None, str | None], ...] = (
    (
        "pilot_prepared",
        _rx(r"^Prepared for a workflow pilot\. Start this task after the pilot plan is frozen\.$"),
        "This task is ready for its workflow pilot.",
        "Review and freeze the pilot plan and spending limit before starting.",
        "/outcome-pilots", "Open Workflow pilot plan",
    ),
    (
        "process_restart",
        _rx(r"\[process restarted mid-run\]\s*$"),
        "Lightwork restarted while this task was running.",
        "Review the saved work and any changes already made before trying again. This task will not restart on its own.",
        None, None,
    ),
    (
        "provider_authentication",
        _rx(r"^provider_error:authentication$", r"\bAuthenticationError\b"),
        "The AI connection needs attention.",
        "Ask an administrator to check the AI account and key, then try again.",
        AI_PROVIDER_KEYS_HREF, "Open AI provider keys",
    ),
    (
        "provider_rate_limit",
        _rx(r"^provider_error:rate_limit$", r"\bRateLimitError\b",
            r"Error code: 429\b"),
        "The AI service is busy right now.",
        "Try again in a few minutes. If it keeps happening, ask an administrator to check the service account.",
        AI_PROVIDER_KEYS_HREF, "Check AI connection",
    ),
    (
        "provider_model_not_found",
        _rx(r"^provider_error:model_not_found$", r"\bNotFoundError\b"),
        "The selected AI model is unavailable.",
        "Ask an administrator to choose an available model, then try again.",
        AI_PROVIDER_KEYS_HREF, "Open AI provider keys",
    ),
    (
        "provider_paused",
        _rx(r"^provider_error:paused$"),
        "The AI service was paused after repeated errors, so this task stopped. What it already finished is kept.",
        "Run it again once the service is back. The notice at the top of the page says when Lightwork checks again.",
        None, None,
    ),
    (
        "provider_unavailable",
        _rx(r"^provider_error:unavailable$", r"\bInternalServerError\b",
            r"Error code: 5\d\d\b"),
        "The AI service is not responding.",
        "Try again when the service is back. Ask an administrator to check the AI connection if it continues.",
        AI_PROVIDER_KEYS_HREF, "Check AI connection",
    ),
    (
        "provider_connection",
        _rx(r"^provider_error:connection$", r"\bAPIConnectionError\b",
            r"\bAPITimeoutError\b"),
        "Lightwork couldn't reach the AI service.",
        "Check the AI connection and try again.",
        AI_PROVIDER_KEYS_HREF, "Open AI provider keys",
    ),
    (
        "provider_configuration",
        _rx(r"^provider_error:configuration$"),
        "The AI connection could not complete this request.",
        "Ask an administrator to check the AI connection, then try again.",
        AI_PROVIDER_KEYS_HREF, "Open AI provider keys",
    ),
    (
        "workspace_paused",
        _rx(r"tenant is suspended or unknown", r"tenant policy unavailable",
            r"tenant registry", r"TenantSuspended", r"TenantRegistryError",
            r"queued tenant policy", r"workspace is paused"),
        "This workspace is paused or hasn't been set up. Open Workspaces to resume it.",
        "Open Workspaces, resume this workspace, then try again.",
        "/workspaces", "Open Workspaces",
    ),
    (
        "halted",
        _rx(r"^halted$", r"HALT file", r"is halted"),
        "Lightwork is stopped by an emergency stop.",
        "An administrator can clear the emergency stop; then try again.",
        None, None,
    ),
    (
        "awaiting_input",
        _rx(r"^Paused: waiting for you to answer",
            r"^Paused: the assistant said it needs more information"),
        "Lightwork needs more information to continue.",
        "Open the task and answer its question, or send a follow-up message.",
        None, None,
    ),
    (
        "unpriced_model",
        _rx(r"^unpriced model:", r"\bUnpricedModelError\b"),
        "This AI model needs a price before Lightwork can continue.",
        "Ask an administrator to choose a priced model or enter this model's "
        "current spending ceiling in Settings.",
        "/settings#settings-model-prices", "Review model prices",
    ),
    (
        "spending_limit",
        _rx(r"over its daily (spend|token) quota", r"spend cap", r"spending limit",
            r"spending allowance", r"budget exhausted", r"of \$[\d.,]+ cap",
            r"BudgetExceeded", r"over quota"),
        "This task reached a spending limit.",
        "Set a spending limit for this attempt, or ask an administrator to raise "
        "the workspace's limit.",
        "/spending-limits", "Open Spending limits",
    ),
    (
        # The kernel refuses to build a specialist whose workflow needs a tool
        # this workspace does not have; no model work has started. Web search
        # alone is a switch an administrator can turn on.
        "specialist_needs_web_search",
        _rx(r"cannot deploy: required workflow tools unavailable:\s*web_search\."),
        "This specialist couldn't start because Web search is unavailable in this workspace. "
        "No work was started.",
        "Ask an administrator to enable Web search, then check setup again before restarting.",
        "/settings/all?id=capabilities.web_search", "Review Web search setup",
    ),
    (
        "specialist_needs_connection",
        _rx(r"cannot deploy: required workflow tools unavailable"),
        "This specialist needs an action that isn't available in this workspace. "
        "No work was started.",
        "Ask an administrator to review its required actions and tool connections.",
        "/mcp", "Open Tool servers",
    ),
    (
        "specialist_setup",
        _rx(r"cannot start because its setup needs review"),
        "This specialist couldn't start because its setup needs review. No work was started.",
        "Ask an administrator to review this specialist's setup.",
        "/agents", "Browse specialists",
    ),
    (
        "internal_error",
        _rx(r"^Stopped: the assistant ran into an error"),
        "Something went wrong inside Lightwork.",
        _GENERIC_ACTION,
        None, None,
    ),
    (
        "provider_not_ready",
        _rx(r"api[_ ]?key", r"provider", r"ConnectError", r"connection (refused|reset|error)",
            r"could not (reach|connect)", r"model route", r"AuthenticationError",
            r"timed out", r"ReadTimeout"),
        "Lightwork couldn't reach the AI service.",
        "Connect an AI service, then try again.",
        AI_PROVIDER_KEYS_HREF, "Connect an AI service",
    ),
    (
        "permission_denied",
        _rx(r"permission", r"insufficient role", r"not allowed", r"forbidden",
            r"execution principal", r"may not use"),
        "You don't have permission to run this.",
        "A workspace administrator can grant you access on the People page.",
        "/users", "Open People",
    ),
    (
        "policy_blocked",
        _rx(r"rejected by Shield", r"input blocked", r"brief blocked", r"blocked by hook"),
        "A safety or company rule stopped this request.",
        "Reword the request, or ask an administrator which rule applied.",
        None, None,
    ),
    (
        "internal_error",
        _rx(r"^internal error", r"Traceback", r"\b\w+(Error|Exception)\b",
            r"dispatch (failed|unavailable)"),
        "Something went wrong inside Lightwork.",
        _GENERIC_ACTION,
        None, None,
    ),
)

# Text a person should never have to read: identifiers, paths, code.
_TECHNICAL = _rx(r"\b\w+(Error|Exception)\b", r"Traceback", r"'[^' ]+'", r"\"[^\" ]+\"",
                 r"(^|[\s(])/[\w.-]+/", r"[A-Za-z]:\\", r"\btenant\b", r"\bprincipal\b",
                 r"\buser:[\w.@-]+", r"<[^>]+>", r"\b0x[0-9a-f]+\b",
                 r"\bmaverick\s+(resume|unhalt|answer)\b")


def _bounded(text: str, limit: int) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def explain_stop(raw: str | None, *, status: str | None = None) -> StopReason:
    """Map the kernel's stop text to a :class:`StopReason`.

    ``status`` is accepted for callers that know the goal's state; a raw text
    that reads as plain prose (no identifiers, paths or exception names) is
    passed through as the message so the kernel's own sentences still show.
    """
    del status  # every stopped status is explained the same way today
    text = (raw or "").strip()
    technical = _bounded(text, RAW_TEXT_LIMIT)
    if not text:
        return StopReason("other", _GENERIC_MESSAGE, _GENERIC_ACTION)
    for kind, pattern, message, action, link, label in _RULES:
        if pattern.search(text):
            return StopReason(kind, message, action, link, label, technical)
    if _TECHNICAL.search(text):
        return StopReason("internal_error", "Something went wrong inside Lightwork.",
                          _GENERIC_ACTION, None, None, technical)
    return StopReason("other", _bounded(text, _MESSAGE_LIMIT), "Try again when you are ready.",
                      None, None, technical)


def stop_payload(status: str | None, raw: str | None, *,
                 include_technical: bool = False) -> dict | None:
    """The ``stop`` field for goal payloads: set for a stopped goal, else None."""
    if status not in ("blocked", "failed"):
        return None
    return explain_stop(raw, status=status).as_dict(include_technical=include_technical)
