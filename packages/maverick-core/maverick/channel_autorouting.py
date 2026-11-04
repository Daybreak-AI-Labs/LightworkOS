"""Channel auto-routing.

An inbound message can arrive on one channel but be best *answered* on another:
a three-paragraph question with a stack-trace attachment wants an email/ticket
reply, not a one-line SMS; an "URGENT, prod is down" ping wants a pager profile.
This is the routing brain for that: given a message's signals (length, detected
language, urgency keywords, attachment types, plus an optional injected
classifier label) it scores a **configurable** routing table (``[channels.routing]``)
and returns the best-fit reply channel / handler profile, with an :func:`explain`
that shows exactly which rule won and why.

Pure and deterministic — signals in, a :class:`RouteDecision` out — so it is
unit-tested with no I/O. **Opt-in and fail-open**: with no table configured the
decision is a ``passthrough`` (reply on the channel the message arrived on), so
wiring this in never changes behaviour until an operator writes rules.

The channel server calls :func:`specialist_for` for every inbound chat message:
a matching rule whose destination is a ``specialist`` (an enabled department
pack) makes that specialist handle the message's task. The rules are written
with the guided editor on Settings > All settings > Chat channels.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# A "rule" matches when EVERY condition it declares holds. Conditions are all
# optional; an empty rule matches anything (a catch-all default). Recognised
# condition keys (others are ignored, so a future key never crashes an old
# kernel):
#   min_length / max_length : int, message char length bounds (inclusive)
#   languages               : list[str], detected language must be one of these
#   urgency                 : "low" | "normal" | "high" | "critical" (>= this)
#   any_keyword             : list[str], any appears (case-insensitive substring)
#   attachments             : list[str], message must carry one of these types
#   label                   : str, the injected classifier label must equal this
_URGENCY_ORDER = ("low", "normal", "high", "critical")

# Default urgency keyword lexicon, used only when the caller does not pass an
# explicit urgency and lets us infer one from the text. Deliberately small and
# unsurprising; operators tune routing via the table, not this list.
_URGENCY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "critical": ("outage", "down", "sev1", "sev 1", "p0", "data loss", "breach"),
    "high": ("urgent", "asap", "immediately", "critical", "emergency", "blocker"),
}


def _urgency_rank(level: str) -> int:
    try:
        return _URGENCY_ORDER.index((level or "").strip().lower())
    except ValueError:
        return 0


@dataclass(frozen=True)
class MessageSignals:
    """What we know about an inbound message, independent of any channel."""

    text: str = ""
    language: str = ""                 # ISO-ish code, e.g. "en"; "" = unknown
    urgency: str = ""                  # explicit override; "" = infer from text
    attachments: tuple[str, ...] = ()  # type hints, e.g. ("image", "log", "pdf")
    label: str = ""                    # optional injected-classifier verdict

    @property
    def length(self) -> int:
        return len(self.text or "")

    def effective_urgency(self) -> str:
        """The explicit urgency, else the highest urgency inferred from text."""
        if self.urgency:
            return self.urgency.strip().lower()
        low = (self.text or "").lower()
        for level in ("critical", "high"):
            if any(kw in low for kw in _URGENCY_KEYWORDS[level]):
                return level
        return "normal"


@dataclass(frozen=True)
class RouteRule:
    """One row of the routing table: conditions + where to route it (a reply
    ``channel`` and/or the ``specialist`` pack that should handle it)."""

    channel: str
    min_length: int | None = None
    max_length: int | None = None
    languages: tuple[str, ...] = ()
    urgency: str = ""                  # minimum urgency (>=) to match
    any_keyword: tuple[str, ...] = ()
    attachments: tuple[str, ...] = ()
    label: str = ""
    name: str = ""                     # human label for explain()
    specialist: str = ""               # department pack that handles the task

    def reasons(self, sig: MessageSignals) -> list[str] | None:
        """Return the satisfied-condition strings if this rule matches ``sig``,
        else ``None``. A rule with no conditions matches anything (catch-all)."""
        why: list[str] = []
        if self.min_length is not None:
            if sig.length < self.min_length:
                return None
            why.append(f"length>={self.min_length}")
        if self.max_length is not None:
            if sig.length > self.max_length:
                return None
            why.append(f"length<={self.max_length}")
        if self.languages:
            if (sig.language or "").strip().lower() not in self.languages:
                return None
            why.append(f"language in {list(self.languages)}")
        if self.urgency:
            if _urgency_rank(sig.effective_urgency()) < _urgency_rank(self.urgency):
                return None
            why.append(f"urgency>={self.urgency}")
        if self.any_keyword:
            low = (sig.text or "").lower()
            hit = next((k for k in self.any_keyword if k in low), None)
            if hit is None:
                return None
            why.append(f"keyword:{hit!r}")
        if self.attachments:
            have = {a.strip().lower() for a in sig.attachments}
            hit = next((a for a in self.attachments if a in have), None)
            if hit is None:
                return None
            why.append(f"attachment:{hit}")
        if self.label:
            if (sig.label or "").strip().lower() != self.label:
                return None
            why.append(f"label=={self.label}")
        if not why:
            why.append("catch-all (no conditions)")
        return why


@dataclass(frozen=True)
class RouteDecision:
    channel: str
    rule: str            # the winning rule's name, or "passthrough"
    reasons: list[str] = field(default_factory=list)
    passthrough: bool = False
    specialist: str = ""


def _norm_list(v) -> tuple[str, ...]:
    if isinstance(v, str):
        items = [v]
    elif isinstance(v, (list, tuple)):
        items = list(v)
    else:
        return ()
    return tuple(str(x).strip().lower() for x in items if str(x).strip())


def parse_rules(raw: list[dict]) -> list[RouteRule]:
    """Build rules from ``[[channels.routing.rules]]`` dicts.

    Rules are tried in order; the first match wins. A row without a ``channel``
    is skipped (rather than raising) so one typo can't break routing.
    """
    out: list[RouteRule] = []
    for i, r in enumerate(raw or []):
        if not isinstance(r, dict):
            continue
        channel = str(r.get("channel") or "").strip()
        specialist = str(r.get("specialist") or "").strip()
        if not channel and not specialist:
            continue

        def _int(key, *, r=r):
            v = r.get(key)
            if isinstance(v, bool):
                return None
            try:
                number = int(v) if v is not None else None
            except (TypeError, ValueError):
                return None
            # The guided editor writes 0 for "no limit".
            return number if number is None or number > 0 else None

        urg = str(r.get("urgency") or "").strip().lower()
        if urg and urg not in _URGENCY_ORDER:
            urg = ""
        out.append(RouteRule(
            channel=channel,
            min_length=_int("min_length"),
            max_length=_int("max_length"),
            languages=_norm_list(r.get("languages")),
            urgency=urg,
            any_keyword=_norm_list(r.get("any_keyword")),
            attachments=_norm_list(r.get("attachments")),
            label=str(r.get("label") or "").strip().lower(),
            name=str(r.get("name") or f"rule[{i}]"),
            specialist=specialist,
        ))
    return out


def load_rules() -> list[RouteRule]:
    """Rules from ``[channels.routing] rules`` in config (empty when unset)."""
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("channels") or {}
        routing = cfg.get("routing") or {}
        return parse_rules(routing.get("rules") or [])
    except Exception:  # pragma: no cover -- config never blocks routing
        return []


def route(
    sig: MessageSignals,
    *,
    rules: list[RouteRule] | None = None,
    inbound_channel: str = "",
    classifier=None,
) -> RouteDecision:
    """Pick the best-fit reply channel for ``sig``.

    ``classifier`` (optional, injected) is called as ``classifier(sig)`` and may
    return a label string; it overrides ``sig.label`` for this decision only,
    letting a learned model feed the same rule table a heuristic would. With no
    rules (or no match), the result is a ``passthrough`` onto ``inbound_channel``
    — the safe default that changes nothing until rules exist.
    """
    rules = rules if rules is not None else load_rules()
    if classifier is not None:
        try:
            label = classifier(sig)
            if isinstance(label, str) and label.strip():
                sig = MessageSignals(
                    text=sig.text, language=sig.language, urgency=sig.urgency,
                    attachments=sig.attachments, label=label.strip(),
                )
        except Exception:  # pragma: no cover -- a bad classifier never blocks
            pass
    for rule in rules:
        why = rule.reasons(sig)
        if why is not None:
            return RouteDecision(channel=rule.channel or inbound_channel or "passthrough",
                                 rule=rule.name, reasons=why, specialist=rule.specialist)
    return RouteDecision(
        channel=inbound_channel or "passthrough",
        rule="passthrough",
        reasons=["no routing rule matched"],
        passthrough=True,
    )


def explain(
    sig: MessageSignals,
    *,
    rules: list[RouteRule] | None = None,
    inbound_channel: str = "",
    classifier=None,
) -> str:
    """A one-line, human-readable account of the routing decision."""
    d = route(sig, rules=rules, inbound_channel=inbound_channel, classifier=classifier)
    why = "; ".join(d.reasons) if d.reasons else "—"
    if d.passthrough:
        return (f"route -> {d.channel} (passthrough: {why}); "
                f"urgency={sig.effective_urgency()}, length={sig.length}")
    return (f"route -> {d.channel} via {d.rule} ({why}); "
            f"urgency={sig.effective_urgency()}, length={sig.length}")


_KINDS = (("image/", "image"), ("audio/", "audio"), ("video/", "video"),
          ("application/pdf", "pdf"), ("text/", "text"))


def signals_for_message(msg) -> MessageSignals:
    """What the rules can see about an inbound chat message: its text and
    the kinds of files it carries (picture, sound, video, PDF, text, file)."""
    kinds = []
    for item in getattr(msg, "attachments", None) or []:
        mime = str((item or {}).get("mime") or "").lower() if isinstance(item, dict) else ""
        kind = next((name for prefix, name in _KINDS if mime.startswith(prefix)), "file")
        if kind not in kinds:
            kinds.append(kind)
    return MessageSignals(text=str(getattr(msg, "text", "") or ""), attachments=tuple(kinds))


def specialist_for(msg, *, rules: list[RouteRule] | None = None) -> str:
    """The specialist pack the first matching rule sends ``msg`` to, or "".

    "" (the general assistant, exactly as with no rules) when nothing is
    configured, nothing matches, or the chosen specialist is not an enabled
    pack any more. Never raises: routing must not block intake."""
    import logging

    try:
        rules = [r for r in (load_rules() if rules is None else rules) if r.specialist]
        if not rules:
            return ""
        decision = route(signals_for_message(msg), rules=rules,
                         inbound_channel=str(getattr(msg, "channel", "") or ""))
        if decision.passthrough or not decision.specialist:
            return ""
        from .domain import enabled_domains
        if decision.specialist not in enabled_domains():
            logging.getLogger(__name__).warning(
                "routing rule %s names specialist %r, which is not enabled; "
                "using the general assistant", decision.rule, decision.specialist)
            return ""
        return decision.specialist
    except Exception:  # noqa: BLE001 -- intake continues unrouted
        logging.getLogger(__name__).warning("channel routing failed; message not routed",
                                            exc_info=True)
        return ""


__all__ = [
    "MessageSignals",
    "RouteRule",
    "RouteDecision",
    "parse_rules",
    "load_rules",
    "route",
    "explain",
    "signals_for_message",
    "specialist_for",
]
