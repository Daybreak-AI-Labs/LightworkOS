"""Adaptive Cards the Teams channel sends. Pure functions, no I/O.

Card JSON follows the Adaptive Card 1.4 schema with Universal Actions
(``Action.Execute``), which Teams delivers back to the bot as an ``invoke``
activity named ``adaptiveCard/action``
(https://learn.microsoft.com/adaptive-cards/authoring-cards/universal-action-model).
The approval card shows the same content as the dashboard's approval queue
(``_approvals_queue.html``): what it changes, who asked, decide-by time,
spending, what it will do, before/after, what happens next (and whether it
can be undone) and open questions.
"""
from __future__ import annotations

import datetime as _dt
import html as _html
import json
import re

SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
VERSION = "1.4"
CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
MAX_TEXT = 4000
# Teams refuses a bot message over 100 KB counted as UTF-16 (413
# MessageSizeTooBig) and advises staying within 80 KB
# (https://learn.microsoft.com/microsoftteams/platform/bots/how-to/format-your-bot-messages).
MAX_MESSAGE_BYTES = 80 * 1024
_MENTION = re.compile(r"<at>(.*?)</at>", re.DOTALL)


def _text(value: object, *, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(value or "").split())
    return _escape_markdown(text[:limit])


def _escape_markdown(text: str) -> str:
    # Adaptive Cards TextBlocks render Markdown. Escape formatting and link
    # delimiters in values originating in requests or tool output.
    return re.sub(r"([\\`*_\[\]()<>#!])", r"\\\1", text)


def _block(text: str, *, weight: str = "default", size: str = "default",
           wrap: bool = True, color: str = "default", spacing: str = "default") -> dict:
    block = {"type": "TextBlock", "text": text, "wrap": wrap}
    if weight != "default":
        block["weight"] = weight
    if size != "default":
        block["size"] = size
    if color != "default":
        block["color"] = color
    if spacing != "default":
        block["spacing"] = spacing
    return block


def _facts(rows: list[tuple[str, str]]) -> dict:
    return {"type": "FactSet", "facts": [{"title": t, "value": _text(v, limit=500) or "—"}
                                         for t, v in rows]}


def _card(body: list[dict], actions: list[dict] | None = None) -> dict:
    card = {"$schema": SCHEMA, "type": "AdaptiveCard", "version": VERSION, "body": body}
    if actions:
        card["actions"] = actions
    return card


def attachment(card: dict) -> dict:
    return {"contentType": CARD_CONTENT_TYPE, "content": card}


def fits_message(payload: dict) -> bool:
    """Whether ``payload`` stays within Teams' advised message size. It is
    measured as spaced JSON with non-ASCII escaped, which is no smaller than the
    body sent; sending adds only the activity type."""
    return len(json.dumps(payload).encode("utf-16-le")) <= MAX_MESSAGE_BYTES


def humanize(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace(".", " ").replace("_", " ") if " " not in text else text
    return text[:1].upper() + text[1:]


def budget_text(budget: object) -> str:
    """The dashboard's spending line, in the same words (one shared sentence;
    fingerprints and raw field names never appear on a card)."""
    from maverick.channel_approvals import spending_text

    return spending_text(budget if isinstance(budget, dict) else None)


def decide_by(expires_at: object) -> str:
    try:
        when = _dt.datetime.fromtimestamp(float(expires_at), tz=_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return "Not stated"
    return when.strftime("%Y-%m-%d %H:%M UTC")


def _lines(value: object, *, limit: int = MAX_TEXT) -> list[tuple[str, bool]]:
    """``(line, after_blank_line)`` pairs, whitespace trimmed per line, within
    ``limit`` characters in all. A TextBlock does not keep a bare newline, so
    each line becomes its own block."""
    out: list[tuple[str, bool]] = []
    used, gap = 0, False
    for raw in str(value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            gap = bool(out)
            continue
        line = line[: limit - used]
        if not line:
            break
        out.append((line, gap))
        used += len(line)
        gap = False
    return out


def text_card(text: str, *, title: str = "") -> dict:
    """A plain reply as a card (used for long results and welcome text). Line
    breaks and paragraphs are kept."""
    body = []
    if title:
        body.append(_block(_text(title, limit=200), weight="bolder", size="medium"))
    lines = _lines(text)
    for line, after_blank in lines:
        body.append(_block(_escape_markdown(line), spacing="medium" if after_blank else "default"))
    if not lines:
        body.append(_block(""))
    return _card(body)


def result_card(text: str) -> dict:
    return text_card(text, title="Lightwork")


def strip_mentions_text(text: str) -> str:
    """Turn remaining ``<at>Name</at>`` markup (other people's mentions) into
    the plain name, so the agent still sees who was named."""
    return _MENTION.sub(lambda m: m.group(1), text or "").strip()


def _bullets(items: object) -> str:
    if not isinstance(items, (list, tuple)) or not items:
        return "None."
    return "\n".join(f"- {_text(item, limit=500)}" for item in items[:24])


def approval_card(approval: dict, card: dict | None, *, source_label: str | None = None,
                  decided: dict | None = None, note: str = "", dashboard_url: str = "") -> dict:
    """The approval request as a card. ``approval`` is the queue row projected
    to a dict (``id``, ``action``, ``risk``, ``scope``, ``detail``); ``card`` is
    the decoded structured card (``maverick.approval_cards``) or ``None`` for a
    legacy or invalid request, which the card refuses to approve like the
    dashboard does. ``decided`` replaces the buttons with the outcome. With a
    ``dashboard_url`` the card also opens that exact approval in Lightwork."""
    risk = str(approval.get("risk") or "medium")
    action = humanize(approval.get("action")) or "Reviewed action"
    body: list[dict] = [
        _block("Approval needed" if not decided else "Approval decided",
               weight="bolder", size="large"),
        _block(_text(action, limit=300), weight="bolder", size="medium"),
        _block(f"Risk: {_text(humanize(risk))}", weight="bolder",
               color="attention" if risk in ("high", "critical") else "default"),
        _block("You get this because you are linked to Lightwork as an approver."),
    ]
    if source_label:
        body.append(_block(_text(source_label, limit=200), color="attention"))
    else:
        body.append(_block("An agent asked for permission."))
    body.append(_facts([("Applies to", approval.get("scope") or "The item described")]))
    if card:
        body.append(_block("This is Lightwork's suggestion — the decision is yours. "
                           "Your decision applies only to exactly what is described here.",
                           spacing="medium"))
        body.append(_block(_text(card.get("summary")), spacing="medium"))
        authority = card.get("authority") or {}
        body.append(_facts([
            ("What it changes", (card.get("target") or {}).get("label")),
            ("Requested by", f"{authority.get('actor', '')} · {authority.get('role', '')}"),
            ("Decide by", decide_by(card.get("expires_at"))),
            ("Spending", budget_text(card.get("budget"))),
        ]))
        body.append(_block("What it will do", weight="bolder", spacing="medium"))
        body.append(_block(_bullets((card.get("parameters") or {}).get("summary"))))
        if card.get("display"):
            # The exact command stays on the access-checked Approvals page.
            body.append(_block("The exact command is shown on the Approvals page."))
        preview = card.get("preview") or {}
        body.append(_facts([("Before", preview.get("before")), ("After", preview.get("after"))]))
        consequences = card.get("consequences") or {}
        heading = "What happens next"
        if consequences.get("irreversible"):
            heading += " — Can't be undone"
        body.append(_block(heading, weight="bolder", spacing="medium",
                           color="attention" if consequences.get("irreversible") else "default"))
        body.append(_block(_bullets(consequences.get("known_effects"))))
        body.append(_block("Open questions", weight="bolder", spacing="medium"))
        body.append(_block(_bullets(consequences.get("unresolved_assumptions"))))
    else:
        body.append(_block(_text(approval.get("detail"))))
        body.append(_block("This request is missing the details needed to approve it safely. "
                           "Reject it and ask for a new request.", color="attention",
                           spacing="medium"))
    if note:
        body.append(_block(_text(note, limit=500), color="attention", spacing="medium"))
    if decided:
        outcome = str(decided.get("status") or "")
        label = {"approved": "Approved", "denied": "Rejected",
                 "superseded": "Sent back for changes"}.get(outcome, humanize(outcome))
        if outcome == "pending":
            label = (f"Approval recorded ({decided.get('approved_count', 0)} of "
                     f"{decided.get('approvals_required', 1)}); more approvers are needed")
        body.append(_block(f"{_text(label)} by {_text(decided.get('decided_by', ''))}", weight="bolder",
                           spacing="medium",
                           color="good" if outcome == "approved" else "attention"))
        if decided.get("audit") == "pending":
            body.append(_block("Saved but not in effect yet while Lightwork finishes the "
                               "signed record.", color="warning"))
        undo_seconds = int(decided.get("undo_seconds") or 0)
        if decided.get("effective") and undo_seconds > 0 and outcome in ("approved", "denied"):
            body.append(_block(f"Changed your mind? You can undo this for {undo_seconds} seconds; "
                               "the agent waits that long before acting.", spacing="medium"))
            return _card(body, [{"type": "Action.Execute", "title": "Undo", "verb": "undo",
                                 "data": {"approval_id": int(approval["id"]), "risk": risk,
                                          "decided_at": float(decided.get("decided_at") or 0)}}])
        return _card(body)
    data = {"approval_id": int(approval["id"]),
            "binding": str((card or {}).get("binding_sha256") or ""), "risk": risk}
    actions = []
    if dashboard_url:
        actions.append({"type": "Action.OpenUrl", "title": "Open in Lightwork",
                        "url": f"{dashboard_url.rstrip('/')}/approvals#approval-{int(approval['id'])}"})
    if card:
        actions.append({"type": "Action.Execute", "title": "Approve", "verb": "approve",
                        "style": "positive", "data": data})
    actions.append({"type": "Action.Execute", "title": "Reject", "verb": "reject",
                    "style": "destructive", "data": data})
    actions.append({"type": "Action.ShowCard", "title": "Ask a question (send back)", "card": _card(
        [_block("Your question goes to the requester and sends this request back for a "
                "new one. The action does not run."),
         {"type": "Input.Text", "id": "question", "isMultiline": True,
          "placeholder": "What should change, or what do you need to know?"}],
        [{"type": "Action.Execute", "title": "Send back with this question", "verb": "ask",
          "data": data}])})
    return _card(body, actions)


def confirm_card(approval: dict, *, binding: str) -> dict:
    """The second step for a high or critical risk approval."""
    risk = str(approval.get("risk") or "high")
    data = {"approval_id": int(approval["id"]), "binding": binding, "risk": risk}
    body = [
        _block("Please confirm", weight="bolder", size="large"),
        _block(f"This is a {_text(risk)} risk action: "
               f"{_text(humanize(approval.get('action')), limit=300)}.", color="attention"),
        _block("Approving it lets the agent carry out exactly what the card describes. "
               "Nothing happens until you confirm."),
        {"type": "Input.Toggle", "id": "acknowledged", "value": "false", "valueOn": "true",
         "valueOff": "false", "title": "I have read what this action will do."},
    ]
    if risk == "critical":
        body.append(_block("Type APPROVE to confirm this critical action.", weight="bolder"))
        body.append({"type": "Input.Text", "id": "confirmation", "placeholder": "APPROVE"})
    return _card(body, [
        {"type": "Action.Execute", "title": f"Yes, approve this {_text(risk)} risk action",
         "verb": "approve_confirm", "style": "destructive", "data": data},
        {"type": "Action.Execute", "title": "No, go back", "verb": "cancel", "data": data},
    ])


def message_response(text: str) -> dict:
    """Invoke response that shows a message to the person who pressed the button."""
    return {"statusCode": 200, "type": "application/vnd.microsoft.activity.message",
            "value": _text(text, limit=1000)}


def card_response(card: dict) -> dict:
    """Invoke response that replaces the card in place for the person."""
    return {"statusCode": 200, "type": CARD_CONTENT_TYPE, "value": card}


def welcome_text(bot_name: str = "Lightwork") -> str:
    return (f"Hi, I'm {bot_name}. Send me a task in this chat and I'll work on it and "
            "reply here. In a channel or group chat, @mention me. If an administrator "
            "gave you a link code, send `link <code>` to connect this account.")


def unescape(text: str) -> str:
    return _html.unescape(text or "")


__all__ = ["CARD_CONTENT_TYPE", "approval_card", "attachment", "budget_text", "card_response",
           "confirm_card", "decide_by", "fits_message", "message_response", "result_card",
           "strip_mentions_text", "text_card", "welcome_text"]
