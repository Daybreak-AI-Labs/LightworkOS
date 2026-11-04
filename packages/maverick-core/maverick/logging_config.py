"""Structured logging for production deployments.

Set ``MAVERICK_LOG_FORMAT=json`` to emit one JSON object per line --
parseable by Loki/CloudWatch/Datadog/etc. Default stays human-readable.

Set ``MAVERICK_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR`` (default INFO).

Per-goal trace context is propagated through ``contextvars`` so every
log line emitted inside ``run_goal`` is automatically tagged with the
goal id, conversation id, and channel without callers passing it
through every function.

Crash-safe copy (opt-in, ``[logging] crash_log`` or ``MAVERICK_CRASH_LOG=1``):
warnings and errors are also written, one fsync'd line each, to
``logs/crash-only.jsonl`` under Lightwork's data folder through
:class:`maverick.crash_only_log.CrashOnlyLog`, so the records describing a
crash survive the crash. ``[logging] crash_only_fsync = "never"`` keeps the
format but trades per-line durability for speed. Off by default.
"""
from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time
from typing import Any

# Log-extra keys whose VALUE is almost certainly a secret -> redact wholesale.
# Tighter than sandbox.local._SECRET_ENV_RE (no URI/URL/CONN, which match
# benign log keys like "url"); this is matched against caller-chosen field
# names, not shell env vars.
_SECRET_KEY_RE = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|AUTH|BEARER|SESSION)",
    re.IGNORECASE,
)


def _is_secret_key(name: str) -> bool:
    return bool(_SECRET_KEY_RE.search(name or ""))


def _scrub_value(value: Any) -> Any:
    """Run string values through secrets.scrub so an inline key/token/Bearer
    header/.env line in a log extra is redacted before it leaves the process.
    Non-strings pass through unchanged. Never raises (logging must not crash)."""
    if not isinstance(value, str):
        return value
    try:
        from .secrets import scrub
        return scrub(value)
    except Exception:  # pragma: no cover -- scrubbing must never break logging
        return value


def _scrub_deep(value: Any) -> Any:
    """Recursively scrub a structured log value, preserving its shape.

    The flat :func:`_scrub_value` only touches top-level strings, so a secret
    nested in a dict/list ``extra=`` value (e.g. ``extra={"meta": {"token":
    "sk-..."}}``) reached the aggregator verbatim -- the value isn't a string,
    so scrub passed it through, and the top-level secret-key filter never saw
    the nested key. Walk dicts/lists: redact secret-NAMED keys at every depth
    and run every nested string through scrub. Never raises."""
    try:
        if isinstance(value, str):
            return _scrub_value(value)
        if isinstance(value, dict):
            return {k: ("[REDACTED]" if _is_secret_key(str(k)) else _scrub_deep(x))
                    for k, x in value.items()}
        if isinstance(value, (list, tuple)):
            return [_scrub_deep(x) for x in value]
    except Exception:  # pragma: no cover -- scrubbing must never break logging
        return value
    return value


def _anon_enabled() -> bool:
    try:
        from .privacy import anon_enabled
        return anon_enabled()
    except Exception:  # pragma: no cover -- logging must never break
        return False


def _anonymize_log_record(value: dict[str, Any]) -> dict[str, Any]:
    if not _anon_enabled():
        return value
    try:
        from .privacy import anonymize_dict
        return anonymize_dict(value)
    except Exception:  # pragma: no cover -- logging must never break
        return value


_goal_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "maverick_goal_id", default=None,
)
_conversation_id_var: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "maverick_conversation_id", default=None,
)
_channel_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "maverick_channel", default=None,
)


def set_goal_context(
    goal_id: int | None = None,
    conversation_id: int | None = None,
    channel: str | None = None,
) -> dict[str, Any]:
    """Bind context for log lines emitted in this async/sync task.

    Returns reset tokens (one per var actually set) so the caller can restore
    the *prior* values via ``reset_goal_context`` instead of nulling globally.
    The old set/clear pair leaked across concurrent goals on one loop: a
    second goal's set overwrote the first's, and either goal's clear then
    nulled the var for BOTH — so log lines got mislabeled with the wrong
    goal_id. Per-call token reset scopes the binding to this run.
    """
    tokens: dict[str, Any] = {}
    if goal_id is not None:
        tokens["goal_id"] = _goal_id_var.set(goal_id)
    if conversation_id is not None:
        tokens["conversation_id"] = _conversation_id_var.set(conversation_id)
    if channel is not None:
        tokens["channel"] = _channel_var.set(channel)
    return tokens


def reset_goal_context(tokens: dict[str, Any] | None) -> None:
    """Restore the context vars to the values held before ``set_goal_context``.

    Pass the dict ``set_goal_context`` returned. Restoring the prior value
    (rather than None) means a nested/concurrent goal doesn't wipe an outer
    goal's context. Tolerant of a partial/None mapping and stale tokens."""
    if not tokens:
        return
    for var, key in (
        (_goal_id_var, "goal_id"),
        (_conversation_id_var, "conversation_id"),
        (_channel_var, "channel"),
    ):
        tok = tokens.get(key)
        if tok is not None:
            try:
                var.reset(tok)
            except (ValueError, LookupError):  # pragma: no cover -- stale/cross-context token
                var.set(None)


def clear_goal_context() -> None:
    """Null all context vars. Back-compat for callers that don't hold tokens;
    prefer set_goal_context()/reset_goal_context() to avoid cross-goal leaks."""
    _goal_id_var.set(None)
    _conversation_id_var.set(None)
    _channel_var.set(None)


def current_goal_id() -> int | None:
    """The goal id bound to the current async/sync task, or None outside a goal.

    Lets non-logging callers (e.g. the consent gate, which attributes a queued
    approval to the requesting principal) identify the executing goal without
    re-plumbing the id through every call site. Propagates across
    ``asyncio.to_thread`` because that copies the context."""
    return _goal_id_var.get()


class _ContextFilter(logging.Filter):
    """Attach goal/conversation/channel context to every record, and scrub
    secrets from the message + traceback.

    Scrubbing lives in the filter (not only the JsonFormatter) because a filter
    runs for EVERY handler/formatter regardless of ``MAVERICK_LOG_FORMAT``. The
    default is text mode, so without this an interpolated provider key / DSN
    password / Bearer token in a log message would reach the sink verbatim."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.goal_id = _goal_id_var.get()
        record.conversation_id = _conversation_id_var.get()
        record.channel = _channel_var.get()
        # Resolve args into the message and scrub, then drop args so no handler
        # re-interpolates the unscrubbed values. Never raise from logging.
        try:
            record.msg = _scrub_value(record.getMessage())
            record.args = ()
        except Exception:  # pragma: no cover -- scrubbing must never break logging
            pass
        # Pre-format + scrub the traceback into cached exc_text so the text
        # formatter emits the scrubbed version. exc_info is left intact so the
        # JsonFormatter (which re-derives and independently scrubs it) still
        # renders a traceback in JSON mode.
        if record.exc_text:
            record.exc_text = _scrub_value(record.exc_text)
        elif record.exc_info:
            try:
                import traceback as _tb
                record.exc_text = _scrub_value(
                    "".join(_tb.format_exception(*record.exc_info))
                )
            except Exception:  # pragma: no cover
                pass
        if record.stack_info:
            record.stack_info = _scrub_value(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line."""

    # Skip these stdlib LogRecord attrs; everything else (custom extras
    # + context) is included automatically.
    _STDLIB = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message",
    }

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            # Scrub the message and the traceback too: an interpolated arg
            # (`logger.info("resp %s", body)`) or a provider exception message
            # routinely carries an API key / Bearer header, and only the extras
            # were being redacted -- so the two fields most likely to hold a
            # secret reached the aggregator verbatim.
            "msg": _scrub_value(record.getMessage()),
        }
        if record.exc_info:
            out["exc"] = _scrub_value(self.formatException(record.exc_info))
        # Add filter-attached context + any caller-passed extras. Caller extras
        # are NOT trusted: a stray logger.info(..., extra={"api_key": k})
        # anywhere would otherwise ship a secret to the aggregator verbatim.
        # Drop secret-named keys outright and run string values through
        # secrets.scrub (catches inline keys/tokens/Bearer headers/.env lines).
        for k, v in record.__dict__.items():
            if k in self._STDLIB or k.startswith("_"):
                continue
            if k in ("goal_id", "conversation_id", "channel") and v is None:
                continue
            if _is_secret_key(k):
                out[k] = "[REDACTED]"
                continue
            try:
                json.dumps(v)
                # Scrub RECURSIVELY (and preserve shape): _scrub_value leaves
                # non-strings untouched, so scrubbing only the top-level object
                # would let a secret inside a dict/list extra slip past.
                out[k] = _scrub_deep(v)
            except (TypeError, ValueError):
                out[k] = _scrub_value(str(v))
        out = _anonymize_log_record(out)
        return json.dumps(out, separators=(",", ":"))


class _CrashOnlyHandler(logging.Handler):
    """Write each record as one durable line of a crash-only log."""

    def __init__(self, sink) -> None:
        super().__init__(level=logging.WARNING)
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._sink.append(
                "log", level=record.levelname, logger=record.name,
                msg=record.getMessage(), goal_id=getattr(record, "goal_id", None),
                exc=_scrub_value(record.exc_text) if record.exc_text else None,
            )
        except Exception:  # pragma: no cover -- a log sink never breaks the caller
            self.handleError(record)


def crash_log_path():
    """Where the crash-only copy of warnings and errors is kept."""
    from .paths import data_dir

    return data_dir("logs") / "crash-only.jsonl"


def _crash_only_handler() -> logging.Handler | None:
    """The crash-only sink when ``[logging] crash_log`` is on, else None."""
    from .env_setting import env_or_config

    raw = env_or_config("MAVERICK_CRASH_LOG", "logging", "crash_log", "") or ""
    if raw.strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    try:
        from .crash_only_log import CrashOnlyLog

        handler = _CrashOnlyHandler(CrashOnlyLog(crash_log_path()))
    except Exception as exc:  # never block logging on the optional sink
        logging.getLogger(__name__).warning(
            "crash-only log unavailable: %s", type(exc).__name__)
        return None
    handler.addFilter(_ContextFilter())
    return handler


_configured = False


def configure_logging(
    level: str | None = None,
    fmt: str | None = None,
) -> None:
    """Configure root logging. Idempotent.

    Reads from env:
      MAVERICK_LOG_LEVEL  default INFO
      MAVERICK_LOG_FORMAT json|text  default text
    """
    global _configured
    if _configured:
        return

    from .env_setting import env_or_config

    level_name = (level or env_or_config("MAVERICK_LOG_LEVEL", "logging", "level", "INFO")
                  or "INFO").upper()
    fmt_name = (fmt or env_or_config("MAVERICK_LOG_FORMAT", "logging", "format", "text")
                or "text").lower()

    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt_name == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
        ))
    handler.addFilter(_ContextFilter())

    root = logging.getLogger()
    # Don't double-handle if user already configured logging.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level_name, logging.INFO))
    crash = _crash_only_handler()
    if crash is not None:
        root.addHandler(crash)

    _configured = True
