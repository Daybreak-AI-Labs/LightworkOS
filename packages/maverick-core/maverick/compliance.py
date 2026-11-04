"""EU AI Act Article 50 transparency disclosure for channel users.

Article 50 of the EU AI Act (applicable from 2 August 2026) mandates
that users interacting with a chatbot must be informed they are talking
to AI unless that fact is obvious from context.

This module gives the channel server a single function:

    disclosure = first_turn_disclosure(channel, user_id)

It returns the disclosure string to PREPEND to the agent's first reply
on each new conversation, or None if the user has already seen it (we
track via the world model's conversations.last_seen vs created_at).
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass

# Default text. Can be overridden via:
#   MAVERICK_AI_DISCLOSURE="<your custom text>"
# or [compliance] disclosure_text in ~/.maverick/config.toml.
DEFAULT_DISCLOSURE = (
    "Hi -- I'm Lightwork, an AI assistant. Conversations may be reviewed "
    "for safety. Reply STOP to end."
)


_UNSET = object()

# The mark under every agent-written answer Lightwork sends to a chat app or by
# email. Unlike the first-turn disclosure it is on every answer and
# cannot be turned off; it says where to see how the answer was made.
AI_ANSWER_LABEL = "Written by an agent in Lightwork. AI can make mistakes, so check important facts."


def ai_answer_label(goal_id: int, base_url: str = "") -> str:
    """One line naming the answer as AI-written, with the way into "why":
    the task's Steps page (every step the agent took)."""
    goal = int(goal_id)
    where = (f"See how it was made: {base_url.rstrip('/')}/goals/{goal}/trajectory" if base_url
             else f"See how it was made: open task #{goal} in Lightwork and choose Steps.")
    return f"-- {AI_ANSWER_LABEL} {where}"


# Channels that speak the reply: a read-out link is noise, so the mark is one
# plain sentence. Channels with a short message limit get a one-line mark.
SPOKEN_CHANNELS = frozenset({"voice"})
SHORT_CHANNELS = frozenset({"sms", "rcs", "bluesky", "mastodon", "threads", "irc"})


def label_ai_answer(text: str, goal_id: int, base_url: str | None = None, channel: str = "") -> str:
    """``text`` with the AI mark under it, in the form ``channel`` can carry."""
    if channel in SPOKEN_CHANNELS:
        return f"{text}\n\nWritten by an agent in Lightwork."
    if channel in SHORT_CHANNELS:
        return f"{text}\n\n-- Written by an agent in Lightwork. Task #{int(goal_id)}."
    if base_url is None:
        try:
            from .daily_digest import dashboard_url
            base_url = dashboard_url()
        except Exception:  # no link is better than a wrong one
            base_url = ""
    return f"{text}\n\n{ai_answer_label(goal_id, base_url)}"


def _custom_disclosure():
    """Return a 3-state result:
      - explicit non-empty string  -> use it
      - explicit empty string      -> opt-out (return "")
      - not configured at all      -> _UNSET (caller uses default)
    """
    env = os.environ.get("MAVERICK_AI_DISCLOSURE")
    if env is not None:
        return env
    try:
        from .config import load_config
        text = load_config().get("compliance", {}).get("disclosure_text")
        if text is not None:
            return text
    except Exception:
        pass
    return _UNSET


def first_turn_disclosure(
    world,
    channel: str,
    user_id: str,
) -> str | None:
    """Return the AI disclosure string for the user's first turn, or None.

    "First turn" = no prior conversation row OR the conversation has
    zero assistant turns yet. Subsequent turns on the same conversation
    return None so we don't spam the user. Per Article 50 the user
    must be informed at the start of the interaction.

    The conversation row is created/updated as a side effect to keep
    this idempotent across retries.
    """
    conv = world.get_or_create_conversation(channel=channel, user_id=user_id)
    # If ANY prior assistant turn exists, the user has already seen the
    # disclosure (or the operator opted out via empty text). Skip. We must scan
    # a window, not just the single newest row: a failed/blocked goal leaves the
    # conversation's last row as a 'user' turn (no assistant reply is written),
    # and a limit=1 check would then re-show the disclosure on the next message.
    prior = world.recent_turns(conv.id, limit=50)
    for t in prior:
        if t.role == "assistant":
            return None
    text = _custom_disclosure()
    if text is _UNSET:
        text = DEFAULT_DISCLOSURE
    if not text or not text.strip():
        # Operator explicitly opted out (empty string). Don't disclose.
        return None
    return text


# ---------------------------------------------------------------------------
# Compliance posture report
#
# Honest framing (the liability line): this reports *control coverage*, not a
# legal compliance attestation. Full GDPR / EU AI Act compliance also requires
# organizational + legal measures the code cannot perform (DPA, ROPA/Art. 30
# records, DPIA, risk classification, and review by qualified counsel).
# ---------------------------------------------------------------------------

COMPLIANCE_DISCLAIMER = (
    "Control-coverage report, not legal advice or a compliance attestation. "
    "Full GDPR / EU AI Act compliance also requires organizational and legal "
    "measures (DPA, ROPA/Art. 30 records, DPIA, AI-Act risk classification, and "
    "review by qualified counsel)."
)


@dataclass(frozen=True)
class ControlCheck:
    """One control mapped to the regulation article(s) it supports.

    ``status`` is one of:
      - ``active``        — enforced right now for this deployment.
      - ``available``     — a feature/command exists, invoked on demand.
      - ``action_needed`` — an opt-in control that is currently off.
    """

    control: str
    regulation: str
    status: str
    detail: str
    framework: str = "eu"  # "eu" (EU AI Act / GDPR) or "us" (NIST RMF + US state)


def _report_cfg() -> dict:
    try:
        from .config import load_config
        return load_config() or {}
    except Exception:
        return {}


def compliance_report() -> list[ControlCheck]:
    """Introspect this deployment and map active controls to GDPR + EU AI Act
    articles. The result powers ``maverick compliance``."""
    cfg = _report_cfg()
    checks: list[ControlCheck] = []

    # EU AI Act Art. 50 — transparency disclosure (wired into the channel server).
    disclosure = _custom_disclosure()
    art50_on = disclosure is _UNSET or bool(disclosure and str(disclosure).strip())
    checks.append(ControlCheck(
        "AI transparency disclosure", "EU AI Act Art. 50",
        "active" if art50_on else "action_needed",
        "first-turn AI disclosure shown to channel users" if art50_on
        else "re-enable by unsetting [compliance] disclosure_text (empty = disabled)",
    ))

    # EU AI Act Art. 12 / GDPR Art. 30 — record-keeping.
    checks.append(ControlCheck(
        "Audit logging (record-keeping)", "EU AI Act Art. 12 / GDPR Art. 30",
        "active", "append-only event log at ~/.maverick/audit/YYYY-MM-DD.ndjson",
    ))
    # Reuse the ACTIVE signing probe (it writes + verifies a signed row to a
    # throwaway probe file, then deletes it -- no real-log side effect, and no I/O
    # at all when signing isn't requested) instead of inferring from "signing
    # requested AND cryptography importable". The inference could read "active"
    # while live writes silently fall back to unsigned; the probe reflects a real
    # signed write, so this agrees with 'maverick enterprise verify'.
    signing_on = False
    signing_detail = "enable [audit] sign = true (or MAVERICK_AUDIT_SIGN=1)"
    try:
        from .deployment import _verify_audit_signing

        probe = _verify_audit_signing()
        signing_on = probe.passed
        signing_detail = probe.detail
    except Exception:
        pass
    checks.append(ControlCheck(
        "Tamper-evident audit", "EU AI Act Art. 12",
        "active" if signing_on else "action_needed",
        signing_detail,
    ))

    # EU AI Act Art. 14 — human oversight.
    mode = "auto-approve"
    try:
        from .safety.consent import _resolve_mode
        mode = _resolve_mode()
    except Exception:
        pass
    oversight_on = mode in {"ask", "dashboard", "auto-deny"}
    checks.append(ControlCheck(
        "Human oversight (consent gating)", "EU AI Act Art. 14",
        "active" if oversight_on else "action_needed",
        f"consent mode = {mode}" if oversight_on
        else "set MAVERICK_CONSENT_MODE=ask/dashboard, or enable enterprise mode",
    ))
    checks.append(ControlCheck(
        "Kill switch", "EU AI Act Art. 14", "available",
        "create ~/.maverick/HALT to abort all running goals",
    ))

    # GDPR Art. 15 & 20 — access + portability.
    checks.append(ControlCheck(
        "Data-subject access & portability", "GDPR Art. 15 & 20", "available",
        "maverick export-user --channel <c> --user <u>",
    ))
    # GDPR Art. 17 — erasure.
    checks.append(ControlCheck(
        "Right to erasure", "GDPR Art. 17", "available",
        "maverick erase --channel <c> --user <u> (re-anchors the signed audit)",
    ))

    # GDPR Art. 5(1)(e) — storage limitation / retention.
    retention_on = bool(cfg.get("retention"))
    checks.append(ControlCheck(
        "Storage limitation (retention)", "GDPR Art. 5(1)(e)",
        "active" if retention_on else "action_needed",
        "retention configured; run 'maverick retention enforce'" if retention_on
        else "set [retention] audit_days / episodes_days / events_days / messages_days",
    ))

    # GDPR Art. 32 / EU AI Act Art. 15 — security: data egress.
    ent_on = False
    try:
        from .enterprise import enterprise_enabled
        ent_on = enterprise_enabled()
    except Exception:
        pass
    checks.append(ControlCheck(
        "Data-egress control", "GDPR Art. 32 / EU AI Act Art. 15",
        "active" if ent_on else "action_needed",
        "enterprise mode: LLM calls pinned to local/self-hosted providers" if ent_on
        else "enable [enterprise] mode = true to keep data on-box",
    ))

    # GDPR Art. 25 & 32 — data protection by design. Secret redaction is
    # UNCONDITIONAL, but PII redaction (email/SSN/phone) only runs under anon
    # mode (default off). One combined "active" control would overstate the
    # default posture -- an auditor would read it as "email/SSN redacted from
    # logs", which is false by default. Split them so each control reflects
    # what is actually applied.
    from .crypto_at_rest import at_rest_enabled
    from .privacy import anon_enabled
    checks.append(ControlCheck(
        "Secret redaction in logs", "GDPR Art. 25 & 32", "active",
        "audit events pass through the secret detector before write",
    ))
    # PII redaction in logs is active only when anon mode redacts it before the
    # audit event is serialized. At-rest encryption is reported separately below:
    # audit sealing intentionally skips the current day-file, so encryption alone
    # must not satisfy a live log-redaction control.
    if anon_enabled():
        _pii_status, _pii_detail = "active", (
            "anonymization mode redacts PII (email/SSN/phone) from audit events")
    else:
        _enc_note = (
            "; at-rest encryption may protect closed sealed audit segments, but "
            "the current audit day-file remains plaintext until sealed"
            if at_rest_enabled() else ""
        )
        _pii_status, _pii_detail = "action_needed", (
            "PII is NOT redacted from logs by default; enable [privacy] anonymous = true"
            f"{_enc_note} -- secrets are always redacted regardless")
    checks.append(ControlCheck(
        "PII redaction in logs", "GDPR Art. 25 & 32", _pii_status, _pii_detail,
    ))

    # GDPR Art. 32 — encryption of personal data at rest (memory store).
    enc_on = False
    try:
        from .crypto_at_rest import at_rest_enabled
        enc_on = at_rest_enabled()
    except Exception:
        pass
    checks.append(ControlCheck(
        "Encryption at rest", "GDPR Art. 32",
        "active" if enc_on else "action_needed",
        "AES-256-GCM seals the memory store + world-DB content (goals, episodes, "
        "approvals, turns, facts, messages, questions, events); the audit log is "
        "signed, not sealed"
        if enc_on
        else "enable [encryption] at_rest = true (or enterprise mode) to seal it",
    ))

    anon_on = False
    try:
        from .privacy import anon_enabled
        anon_on = anon_enabled()
    except Exception:
        pass
    checks.append(ControlCheck(
        "Log data minimization (anonymous mode)", "GDPR Art. 5(1)(c)",
        "active" if anon_on else "available",
        "anonymous mode on" if anon_on
        else "enable [privacy] anonymous = true to hash identifiers in logs",
    ))

    # ---- US frameworks (NIST AI RMF + enforceable state/sector law) --------
    # There is no single US AI statute, so map the same live controls onto the
    # US de-facto anchor (NIST AI RMF) and the enforceable state/sector laws.
    # Several obligations are part legal/operator process -- flagged "available"
    # (Lightwork supplies the evidence trail) rather than "active".
    checks.append(ControlCheck(
        "Governance, accountability & records", "NIST AI RMF (GOVERN / MANAGE)",
        "active" if (signing_on or oversight_on) else "available",
        "signed audit + attenuating capabilities + consent gating + kill switch",
        framework="us",
    ))
    checks.append(ControlCheck(
        "Measurement & monitoring", "NIST AI RMF (MEASURE)", "available",
        "eval harness (pass@1 / cost) + budget & quota metering + observability",
        framework="us",
    ))
    checks.append(ControlCheck(
        "Consumer notice of AI", "Colorado AI Act (SB 26-189) / CA SB 1001",
        "active" if art50_on else "action_needed",
        "first-turn AI disclosure shown to users" if art50_on
        else "re-enable by unsetting [compliance] disclosure_text (empty = disabled)",
        framework="us",
    ))
    checks.append(ControlCheck(
        "Human review of consequential decisions",
        "Colorado AI Act / EEOC (Title VII, ADA)",
        "active" if oversight_on else "action_needed",
        f"consent/oversight gate (mode = {mode})" if oversight_on
        else "set MAVERICK_CONSENT_MODE=ask/dashboard to put a human in the loop",
        framework="us",
    ))
    checks.append(ControlCheck(
        "Automated employment-decision audit trail", "NYC Local Law 144",
        "available",
        "signed decision log is the evidence trail; the annual independent bias "
        "audit itself is an operator/legal step",
        framework="us",
    ))
    checks.append(ControlCheck(
        "Consumer access & deletion", "CCPA / CPRA", "available",
        "maverick export-user / maverick erase (data access + right to delete)",
        framework="us",
    ))

    return checks


_STATUS_LABEL = {
    "active": "active",
    "available": "on-demand",
    "action_needed": "ACTION NEEDED",
}


def render_report_text(checks: list[ControlCheck]) -> str:
    width = max((len(c.control) for c in checks), default=10)
    rows: list[str] = []
    for c in checks:
        rows.append(f"  [{_STATUS_LABEL.get(c.status, c.status):>13}]  {c.control:<{width}}  {c.regulation}")
        rows.append(f"  {'':>13}    {'':<{width}}  -> {c.detail}")
    active = sum(1 for c in checks if c.status == "active")
    needed = sum(1 for c in checks if c.status == "action_needed")
    head = "GDPR + EU AI Act + US frameworks — control coverage"
    return "\n".join([
        head, "=" * len(head), "", *rows, "",
        f"{active} active, {needed} need action, {len(checks)} total", "",
        COMPLIANCE_DISCLAIMER,
    ])


def render_report_json(checks: list[ControlCheck]) -> str:
    import json
    return json.dumps(
        {
            "controls": [asdict(c) for c in checks],
            "summary": {
                "active": sum(1 for c in checks if c.status == "active"),
                "action_needed": sum(1 for c in checks if c.status == "action_needed"),
                "total": len(checks),
            },
            "disclaimer": COMPLIANCE_DISCLAIMER,
        },
        indent=2,
    )
