"""Platform outbound mail — system emails the *product* sends (invite links).

Distinct from the agent-facing email tool (:mod:`maverick.tools.email_tool`,
which an agent drives as a capability) and the email *channel* (inbound IMAP +
conversational replies): this is the small, boring sender for platform
notices — an invite link, and later password-reset-style flows. It deliberately
**reuses the same ``[email]`` config / env the email tool documents**
(``EMAIL_USER`` / ``EMAIL_APP_PASSWORD`` / ``EMAIL_SMTP_HOST`` /
``EMAIL_SMTP_PORT``), so a deployment configures ONE sending account and both
surfaces work — no second credential section to drift (kernel rule 5: the knob
already exists, as does its wizard step).

stdlib only (``smtplib`` + ``email.message``), no new deps. Same safety rails
as the tool: CR/LF header-injection rejection, the ``MAVERICK_EMAIL_DISABLE``
kill switch, SSL on port 465 / STARTTLS otherwise, bounded timeout. Failures
raise :class:`MailerError` with a compact reason — callers own the fail-soft
decision (an invite that can't be emailed still shows its copyable link).
"""
from __future__ import annotations

import logging
from contextlib import nullcontext

log = logging.getLogger(__name__)

SMTP_TIMEOUT = 30.0


class MailerError(RuntimeError):
    """A send failed (bad config, refused headers, SMTP error)."""


class MailerNotSent(MailerError):
    """The effect was not started, or the single recipient was explicitly refused."""


def sending_scope() -> dict[str, str]:
    """Private current account pin; never return this mapping in a product response."""
    return {key: _cfg(key, env, default) for key, env, default in (
        ("provider", "EMAIL_PROVIDER", "smtp"), ("user", "EMAIL_USER", ""),
        ("app_password", "EMAIL_APP_PASSWORD", ""), ("from", "EMAIL_FROM", ""),
        ("smtp_host", "EMAIL_SMTP_HOST", "smtp.gmail.com"), ("smtp_port", "EMAIL_SMTP_PORT", "465"))}


def _cfg(key: str, env: str, default: str = "") -> str:
    """Env-first lookup, then the ``[email]`` config table (same precedence as
    the email tool, so one account configuration serves both)."""
    import os
    val = os.environ.get(env, "").strip()
    if val:
        return val
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("email") or {}
        return str(cfg.get(key, default) or default).strip()
    except Exception:  # noqa: BLE001 - config trouble => act unconfigured
        return default


def sending_disabled() -> bool:
    """The email kill switch shared by the email tool and platform email.

    ``MAVERICK_EMAIL_DISABLE`` decides when it is set (a false value such as
    ``0`` allows sending; ``1``, ``true`` or any unrecognised value blocks it);
    otherwise ``[email] disable = true`` (the All settings page) blocks
    sending. Off by default, but on while a config source is unreadable, since
    that source may hold the switch."""
    import os

    from ._envparse import coerce_bool
    env = os.environ.get("MAVERICK_EMAIL_DISABLE")
    if env is not None and env.strip():
        return coerce_bool(env, default=True)
    try:
        from .config import config_source_errors, load_config
        cfg = (load_config() or {}).get("email") or {}
        if config_source_errors(include_tenant=True):
            return True
        return isinstance(cfg, dict) and cfg.get("disable") is True
    except Exception:  # noqa: BLE001 - config trouble => keep sending blocked
        return True


def configured() -> bool:
    """True when a sending path is set up and the kill switch is off. The invite
    flow checks this to decide between "emailed" and "copy this link" UX — never
    an error path.

    Two providers: ``smtp`` (default) needs ``EMAIL_USER`` + ``EMAIL_APP_PASSWORD``;
    ``ses`` (``EMAIL_PROVIDER=ses``) sends via the Amazon SES API using the
    ambient AWS role (no stored credential) and only needs a verified
    ``EMAIL_FROM``."""
    if sending_disabled():
        return False
    if _cfg("provider", "EMAIL_PROVIDER", "smtp").lower() == "ses":
        return bool(_cfg("from", "EMAIL_FROM"))
    return bool(_cfg("user", "EMAIL_USER") and _cfg("app_password", "EMAIL_APP_PASSWORD"))


def unavailable_reason() -> str:
    """Why platform email cannot be sent right now, or "" when it can.

    "configuration unreadable" when a config source cannot be read (sending is
    held off because the source may hold the kill switch), "sending disabled"
    for the kill switch, "no sending account configured" otherwise.
    """
    if sending_disabled():
        import os
        if (os.environ.get("MAVERICK_EMAIL_DISABLE") or "").strip():
            return "sending disabled"  # the environment decides; config is not consulted
        try:
            from .config import config_source_errors
            unreadable = bool(config_source_errors(include_tenant=True))
        except Exception:  # noqa: BLE001 - the seam itself failing is the same answer
            unreadable = True
        return "configuration unreadable" if unreadable else "sending disabled"
    return "" if configured() else "no sending account configured"


_DISABLED_MESSAGES = {
    "configuration unreadable": (
        "Email sending is paused: the configuration could not be read "
        "(configuration unreadable). Fix the settings file to resume."),
}


def _require_single_recipient(to: str) -> None:
    """Platform email has exactly one recipient; "a@x, b@y" would reach both."""
    from email.utils import getaddresses
    recipients = [addr for _name, addr in getaddresses([to]) if addr]
    if len(recipients) != 1 or "@" not in recipients[0]:
        raise MailerNotSent("Send requires a single recipient address.")


def send(to: str, subject: str, body: str, *, transport=None, before_effect=None) -> None:
    """Send a plain-text platform email. Raises :class:`MailerError` on any
    problem; never returns partial success. ``transport`` is injectable for
    tests: a callable ``(host, port, user, password, msg) -> None``."""
    if sending_disabled():
        raise MailerNotSent(_DISABLED_MESSAGES.get(
            unavailable_reason(), "Email sending is disabled."))

    to = (to or "").strip()
    subject = (subject or "").strip()
    if not to or not subject:
        raise MailerNotSent("Send requires a recipient and a subject.")
    # Reject CR/LF in header fields: a newline smuggles extra headers (e.g. a
    # hidden Bcc:) into the message. Same guard as the email tool.
    for field, val in (("to", to), ("subject", subject)):
        if "\r" in val or "\n" in val:
            raise MailerNotSent(f"Invalid email {field}.")
    _require_single_recipient(to)

    original_scope = sending_scope()
    provider = original_scope["provider"].lower()

    def check_effect():
        if sending_disabled() or sending_scope() != original_scope:
            raise MailerNotSent("The sending account changed or sending was disabled. Review the current setup.")
        if before_effect:
            before_effect()

    # Amazon SES API path: sends with the ambient AWS role (the ECS task role) —
    # no stored SMTP credential. The From must be a verified SES identity.
    if provider == "ses":
        from_addr = original_scope["from"]
        if not from_addr:
            raise MailerNotSent("Choose a verified sending address in Email settings.")
        if "\r" in from_addr or "\n" in from_addr:
            raise MailerNotSent("Invalid sending address.")
        try:
            if transport:
                from .authority_effects import authority_effect_fence
                with authority_effect_fence() if before_effect else nullcontext():
                    check_effect()
                    transport(from_addr, to, subject, body)
            else:
                _ses_send(from_addr, to, subject, body, before_effect=check_effect if before_effect else None)
        except MailerError:
            raise
        except Exception as e:  # noqa: BLE001 - surface a compact, typed failure
            raise MailerError(f"Email sending failed ({type(e).__name__}).") from e
        log.info("Platform email accepted by the sending service.")
        return

    # SMTP path (Gmail-style accounts, or any SMTP relay).
    user = original_scope["user"]
    pw = original_scope["app_password"]
    if not user or not pw:
        raise MailerNotSent("no sending account configured "
                          "(EMAIL_USER + EMAIL_APP_PASSWORD / [email])")
    host = original_scope["smtp_host"]
    port_raw = original_scope["smtp_port"]
    try:
        port = int(port_raw)
    except ValueError as e:
        raise MailerNotSent("Choose a valid email server port in Settings.") from e

    # From: an explicit EMAIL_FROM when set, else the SMTP user (which is the
    # address itself for Gmail-style accounts, so existing setups are unchanged).
    from_addr = original_scope["from"] or user
    if "\r" in from_addr or "\n" in from_addr:
        raise MailerNotSent("Invalid sending address.")

    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if transport:
            from .authority_effects import authority_effect_fence
            with authority_effect_fence() if before_effect else nullcontext():
                check_effect()
                transport(host, port, user, pw, msg)
        else:
            _smtp_transport(host, port, user, pw, msg, before_effect=check_effect if before_effect else None)
    except MailerError:
        raise
    except Exception as e:  # noqa: BLE001 - surface a compact, typed failure
        raise MailerError(f"Email sending failed ({type(e).__name__}).") from e
    log.info("Platform email accepted by the sending service.")


def _ses_send(from_addr: str, to: str, subject: str, body: str, *, before_effect=None) -> None:
    """Send one plain-text email via the Amazon SES API using the ambient AWS
    credential chain (on ECS, the task role). Region from ``AWS_REGION``. Needs
    the optional ``boto3`` dependency (the ``[s3]`` extra), imported lazily so the
    default SMTP path never requires it."""
    import os
    try:
        import boto3
    except ModuleNotFoundError as e:  # pragma: no cover - depends on install extra
        raise MailerNotSent(
            "EMAIL_PROVIDER=ses needs boto3 (install the maverick-core [s3] extra)"
        ) from e
    from botocore.config import Config

    from .authority_effects import authority_effect_fence
    client = boto3.client(
        "ses",
        region_name=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or None,
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        config=Config(connect_timeout=SMTP_TIMEOUT, read_timeout=SMTP_TIMEOUT, retries={"max_attempts": 0}),
    )
    with authority_effect_fence() if before_effect else nullcontext():
        if before_effect:
            try:
                before_effect()
            except Exception as exc:
                raise MailerNotSent("The reviewed email permission changed before sending.") from exc
        client.send_email(Source=from_addr, Destination={"ToAddresses": [to]},
                          Message={"Subject": {"Data": subject}, "Body": {"Text": {"Data": body}}})


def _smtp_transport(host: str, port: int, user: str, pw: str, msg, *, before_effect=None) -> None:
    import smtplib
    import ssl

    from .authority_effects import authority_effect_fence
    started = False
    try:
        # smtplib's own default context checks neither the certificate nor the
        # host name; verify both before the password is sent.
        tls = ssl.create_default_context()
        if port == 465:
            connection = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=tls)
        else:
            connection = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
        with connection as s:
            if port != 465:
                s.starttls(context=tls)
            s.login(user, pw)
            with authority_effect_fence() if before_effect else nullcontext():
                if before_effect:
                    before_effect()
                started = True
                refused = s.send_message(msg)
                if refused:
                    raise smtplib.SMTPRecipientsRefused(refused)
    except Exception as exc:
        if not started or isinstance(exc, (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError)):
            raise MailerNotSent("Email was not sent. Check the account, recipient and current permission.") from exc
        raise
