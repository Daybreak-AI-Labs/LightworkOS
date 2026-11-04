"""Linear + Jira inbound triggers — assign an issue to the bot, get a goal.

Mirrors ``github_app.py`` (label an issue, get a PR) for the two other
trackers Lightwork already has read/write tools for (``tools/linear.py``,
``tools/jira.py``). When a Linear or Jira issue is *assigned to the bot*,
the receiver creates a Lightwork goal from the issue title + body.

Two pure pieces, kept transport-free so they unit-test without a server
(the FastAPI routes live in ``maverick_dashboard.app`` next to
``/webhook/start`` and just call into here):

  - ``verify_signature(body, header, secret)`` — HMAC-SHA256 over the raw
    body. Linear sends a bare hex digest in ``Linear-Signature``; Jira
    automation/Connect senders commonly use a ``sha256=`` prefix. Accept
    both. Empty secret fails CLOSED (unlike github_app's dev fail-open):
    these receivers are mounted on the public dashboard app.
  - ``parse_issue_event(provider, payload)`` — normalize a Linear/Jira
    webhook into an ``IssueEvent`` IFF it is an assignment whose assignee
    is the configured bot. Returns ``None`` for anything else (non-assign
    events, assigned-to-someone-else) so the caller no-ops.

Who is "the bot": set ``MAVERICK_BOT_LINEAR_ID`` (Linear user id) and/or
``MAVERICK_BOT_JIRA_ACCOUNT_ID`` (Jira accountId, or the bot's email).
Matching is case-insensitive and also accepts the assignee's email so an
operator can configure either. With no bot id configured the receiver
fails closed: a signed tracker event alone must not be enough to trigger
Lightwork unless the assignee matches an explicitly configured bot.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class IssueEvent:
    """Normalized issue-assigned event from Linear / Jira / GitLab."""
    provider: str        # "linear" | "jira" | "gitlab"
    issue_id: str        # "ENG-123" (Linear) / "PROJ-7" (Jira) / "group/repo#42" (GitLab)
    title: str
    body: str
    assignee: str        # id/email the issue was assigned to (for logging)


def canonical_signature(signature_header: str | None) -> str | None:
    """Return the canonical HMAC digest accepted by ``verify_signature``.

    Linear sends a bare hex digest and Jira senders commonly prefix the same
    digest with ``sha256=``. Normalize those equivalent wire forms to the
    digest that is actually compared so replay-dedup keys match verification.
    """
    if not signature_header:
        return None
    sig = signature_header.strip()
    sig = sig.removeprefix("sha256=")
    return sig


def verify_signature(
    body: bytes,
    signature_header: str | None,
    secret: str | None,
) -> bool:
    """HMAC-SHA256 verification of a Linear/Jira webhook signature.

    Linear's ``Linear-Signature`` is a bare hex digest; Jira automation /
    Connect senders typically prefix ``sha256=``. Accept either. Fails
    CLOSED when no secret is configured — these routes hang off the public
    dashboard app, so an unsigned request must be rejected, not accepted.
    """
    if not secret:
        return False
    sig = canonical_signature(signature_header)
    if not sig:
        return False
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256,
    ).hexdigest()
    # Compare as bytes: sig is attacker-controlled and hmac.compare_digest
    # raises TypeError on a str with any non-ASCII char, which would 500 the
    # webhook instead of cleanly failing closed.
    return hmac.compare_digest(expected.encode("utf-8"), sig.encode("utf-8"))


def gitlab_webhook_token() -> str:
    """The shared GitLab webhook token: ``MAVERICK_GITLAB_WEBHOOK_TOKEN`` wins;
    otherwise ``[webhooks] gitlab_token``, saved sealed on the All settings
    page and opened by ``load_config``. Empty means GitLab webhooks are
    refused."""
    env = os.environ.get("MAVERICK_GITLAB_WEBHOOK_TOKEN", "").strip()
    if env:
        return env
    try:
        from .config import load_config
        value = ((load_config() or {}).get("webhooks") or {}).get("gitlab_token")
    except Exception:  # pragma: no cover - unreadable config means "not set"
        return ""
    return value.strip() if isinstance(value, str) else ""


def verify_gitlab_token(token_header: str | None, secret: str | None) -> bool:
    """Constant-time check of GitLab's ``X-Gitlab-Token`` shared secret.

    GitLab webhooks don't HMAC the body; they replay the configured secret
    verbatim in a header. Fails CLOSED when no secret is configured, like
    ``verify_signature`` — these routes hang off the public dashboard app.
    """
    if not secret or not token_header:
        return False
    # Compare as bytes: token_header is attacker-controlled and
    # hmac.compare_digest raises TypeError on a str with any non-ASCII char.
    return hmac.compare_digest(
        secret.strip().encode("utf-8"), token_header.strip().encode("utf-8")
    )


def replay_window_seconds() -> int:
    """Anti-replay freshness window (seconds).

    Shares the ``[webhooks] max_age_seconds`` knob (env
    ``MAVERICK_WEBHOOK_MAX_AGE_SECONDS``) with the Lightwork-signed
    ``/webhook/start`` path so operators tune one window. Defaults to 300s.
    """
    try:
        from .webhooks import _default_max_age
        return _default_max_age()
    except Exception:  # pragma: no cover - webhooks helper unavailable
        return 300


def event_timestamp_ms(provider: str, payload: dict) -> float | None:
    """The sender's authenticated event time in ms-epoch, or ``None``.

    Linear carries ``webhookTimestamp`` and Jira ``timestamp`` at the top level
    of the body. The body is HMAC-signed, so neither field can be altered or
    stripped from a captured event without breaking the signature -- which makes
    them a trustworthy basis for a freshness (anti-replay) check.
    """
    raw = payload.get("webhookTimestamp" if provider == "linear" else "timestamp")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def is_fresh(
    provider: str,
    payload: dict,
    *,
    now: float | None = None,
    max_age_seconds: int | None = None,
) -> bool:
    """True if the event's signed timestamp is within the replay window.

    Fails CLOSED: a payload with no (or unparseable) timestamp is treated as
    NOT fresh. Real Linear/Jira events always carry one, and a replayer can't
    add or alter it without breaking the body HMAC, so the only events this
    rejects are stale captures (replays) and far-future / clock-skew stamps.
    """
    ts_ms = event_timestamp_ms(provider, payload)
    if ts_ms is None:
        return False
    # Linear/Jira send milliseconds; tolerate a seconds-valued stamp too.
    ts_sec = ts_ms / 1000.0 if ts_ms > 1e11 else ts_ms
    window = replay_window_seconds() if max_age_seconds is None else max_age_seconds
    now = time.time() if now is None else now
    return abs(now - ts_sec) <= window


_BOT_ENVS = {
    "linear": "MAVERICK_BOT_LINEAR_ID",
    "jira": "MAVERICK_BOT_JIRA_ACCOUNT_ID",
    "gitlab": "MAVERICK_BOT_GITLAB_USERNAME",
}
# The same identities saved on the All settings page ([webhooks] table); the
# environment variable above wins when it is set.
_BOT_KEYS = {
    "linear": "linear_bot_id",
    "jira": "jira_bot_id",
    "gitlab": "gitlab_bot_username",
}


def _bot_id(provider: str) -> str:
    env = os.environ.get(_BOT_ENVS.get(provider, ""), "").strip()
    if env or provider not in _BOT_KEYS:
        return env.lower()
    try:
        from .config import load_config
        value = ((load_config() or {}).get("webhooks") or {}).get(_BOT_KEYS[provider])
    except Exception:  # pragma: no cover - config never blocks a webhook
        return ""
    return value.strip().lower() if isinstance(value, str) else ""


def _is_bot(assignee_candidates: list[str], provider: str) -> bool:
    """True if the issue is assigned to the explicitly configured bot."""
    candidates = {c.strip().lower() for c in assignee_candidates if c and c.strip()}
    if not candidates:
        return False
    bot = _bot_id(provider)
    if not bot:
        log.warning(
            "no bot id configured for %s inbound webhook (set %s); "
            "ignoring assignment",
            provider,
            _BOT_ENVS.get(provider, "<unknown provider>"),
        )
        return False
    return bot in candidates


def _parse_linear(payload: dict) -> IssueEvent | None:
    # Linear fires {type, action, data}. Issue assignment is a
    # type=="Issue" update carrying an assignee object/id on data.
    if payload.get("type") != "Issue":
        return None
    action = payload.get("action")
    if action not in ("create", "update"):
        return None
    # Gate on the assignment TRANSITION, not merely the bot being the current
    # assignee: an ``update`` that didn't change the assignee (priority/state/
    # description edit) must not re-fire a paid goal. Linear reports the prior
    # values in ``updatedFrom``; require the assignee field there. ``create``
    # is always the initial assignment, so it needs no such gate.
    if action == "update":
        updated_from = payload.get("updatedFrom") or {}
        if not any(k in updated_from for k in ("assigneeId", "assignee")):
            return None
    data = payload.get("data") or {}
    assignee = data.get("assignee") or {}
    candidates = [
        str(data.get("assigneeId") or ""),
        str(assignee.get("id") or ""),
        str(assignee.get("email") or ""),
    ]
    if not _is_bot(candidates, "linear"):
        return None
    return IssueEvent(
        provider="linear",
        issue_id=str(data.get("identifier") or data.get("id") or ""),
        title=str(data.get("title") or ""),
        body=str(data.get("description") or ""),
        assignee=next((c for c in candidates if c), ""),
    )


def _flatten_adf(desc) -> str:
    """Flatten a Jira ADF description to text (mirror tools/jira._get)."""
    if isinstance(desc, str):
        return desc
    if not isinstance(desc, dict):
        return ""
    out = ""
    for block in desc.get("content") or []:
        for run in block.get("content") or []:
            if run.get("type") == "text":
                out += run.get("text", "")
        out += "\n"
    return out


def _parse_jira(payload: dict) -> IssueEvent | None:
    # Jira fires {webhookEvent, issue:{key, fields}}. An assignment is an
    # issue_updated whose fields.assignee is the bot.
    event = payload.get("webhookEvent")
    if event not in ("jira:issue_updated", "jira:issue_created"):
        return None
    # Gate on the assignment TRANSITION, not merely the bot being the current
    # assignee: an ``issue_updated`` that didn't touch the assignee must not
    # re-fire a paid goal. Jira reports changed fields in ``changelog.items``;
    # require an "assignee" item. ``issue_created`` is the initial assignment.
    if event == "jira:issue_updated":
        items = (payload.get("changelog") or {}).get("items") or []
        if not any(
            isinstance(it, dict) and it.get("field") == "assignee" for it in items
        ):
            return None
    issue = payload.get("issue") or {}
    fields = issue.get("fields") or {}
    assignee = fields.get("assignee") or {}
    candidates = [
        str(assignee.get("accountId") or ""),
        str(assignee.get("emailAddress") or ""),
    ]
    if not _is_bot(candidates, "jira"):
        return None
    return IssueEvent(
        provider="jira",
        issue_id=str(issue.get("key") or ""),
        title=str(fields.get("summary") or ""),
        body=_flatten_adf(fields.get("description")),
        assignee=next((c for c in candidates if c), ""),
    )


def _parse_gitlab(payload: dict) -> IssueEvent | None:
    # GitLab fires {object_kind: "issue", object_attributes: {...},
    # assignees: [{username, ...}]}. An open is the initial assignment;
    # updates/reopens need evidence that the bot was newly assigned. Edits to
    # title, labels or description while it remains assigned must not start
    # another paid goal.
    if payload.get("object_kind") != "issue":
        return None
    attrs = payload.get("object_attributes") or {}
    action = attrs.get("action")
    if action not in ("open", "update", "reopen"):
        return None
    assignees = payload.get("assignees") or []
    candidates = [str(a.get("username") or "") for a in assignees if isinstance(a, dict)]
    if not _is_bot(candidates, "gitlab"):
        return None
    if action != "open":
        changes = payload.get("changes") or {}
        if not isinstance(changes, dict):
            return None
        changed = next((changes[key] for key in ("assignees", "assignee_ids", "assignee_id") if key in changes), None)
        if not isinstance(changed, dict) or "previous" not in changed or "current" not in changed:
            return None
        if changed["previous"] == changed["current"]:
            return None
        previous = changed["previous"]
        old_assignees = previous if isinstance(previous, list) else [previous]
        old_names = [str(row["username"]) for row in old_assignees
                     if isinstance(row, dict) and row.get("username")]
        if _is_bot(old_names, "gitlab"):
            return None
        bot_ids = {str(row.get("id")) for row in assignees if isinstance(row, dict)
                   and _is_bot([str(row.get("username") or "")], "gitlab") and row.get("id") is not None}
        if old_assignees and not old_names and not bot_ids:
            # With only prior numeric IDs and no current bot ID, the hook
            # cannot prove this bot was newly assigned. Do not spend again.
            return None
        old_ids = {str(row.get("id")) if isinstance(row, dict) else str(row)
                   for row in old_assignees if row is not None}
        if bot_ids & old_ids:
            return None
    project = payload.get("project") or {}
    path = str(project.get("path_with_namespace") or "")
    iid = attrs.get("iid")
    issue_id = f"{path}#{iid}" if path and iid is not None else str(iid or attrs.get("id") or "")
    return IssueEvent(
        provider="gitlab",
        issue_id=issue_id,
        title=str(attrs.get("title") or ""),
        body=str(attrs.get("description") or ""),
        assignee=next((c for c in candidates if c), ""),
    )


def parse_issue_event(provider: str, payload: dict) -> IssueEvent | None:
    """Normalize a Linear/Jira/GitLab webhook to an ``IssueEvent``.

    Returns ``None`` for events we don't act on: non-assignment events,
    or an assignment to someone other than the configured bot.
    """
    if provider == "linear":
        return _parse_linear(payload)
    if provider == "jira":
        return _parse_jira(payload)
    if provider == "gitlab":
        return _parse_gitlab(payload)
    return None


def build_brief(event: IssueEvent) -> str:
    """Render the assigned issue into a Lightwork goal brief."""
    return (
        f"{event.provider.title()} issue: {event.issue_id}\n"
        f"Title: {event.title}\n\n"
        f"Issue body:\n{event.body}\n\n"
        "This issue was assigned to Lightwork. Implement a minimal fix or "
        "feature satisfying it."
    )


__all__ = [
    "IssueEvent",
    "verify_signature",
    "verify_gitlab_token",
    "parse_issue_event",
    "build_brief",
    "is_fresh",
    "event_timestamp_ms",
    "replay_window_seconds",
]
