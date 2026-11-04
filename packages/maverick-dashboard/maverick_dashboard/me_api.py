"""The personal "My work" page (``/me``), its small API, the Slack HTTP
receivers and the admin controls for linking chat accounts.

``/me`` works for every signed-in person (view floor): their pending
approvals, questions an agent is waiting on, recent results, spending this
month against the limit, linked chat accounts and the daily summary
choices. It is the same data the daily summary sends
(``maverick.daily_digest``).

``/webhook/slack/interactions`` and ``/webhook/slack/commands`` are the
non-Socket-Mode receivers: each request must carry Slack's signature over
the raw body (``[channels.slack] signing_secret``), a fresh timestamp and a
signature not seen before (replay), and is then handled by
``maverick.slack_interactive`` exactly as the Socket Mode adapter does.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import auth

log = logging.getLogger(__name__)

router = APIRouter(tags=["me"])
api = APIRouter(prefix="/api/v1", tags=["me"])
_SLACK_REPLAY_WINDOW = 600
_LOCAL_PRINCIPAL = "local:dashboard"


def _app():
    from maverick_dashboard import app as app_module

    return app_module


def _principal(request: Request) -> str:
    """The signed-in person; the shared local identity when sign-in is off."""
    name = auth.caller_principal(request)
    if name:
        return name
    if auth.auth_genuinely_off() or auth.anonymous_local_access_allowed():
        return _LOCAL_PRINCIPAL
    raise HTTPException(status_code=401, detail="sign in to see your work")


def _world():
    from ._shared import _world as shared_world

    return shared_world()


def _bridge_identity(request: Request) -> tuple[str, str, str] | None:
    """Exact IdP identity from this request's live OIDC browser session only."""
    from maverick.oidc import load_oidc_config, login_enabled
    from maverick.web_session import verify_session

    from .oidc_login import SESSION_COOKIE, _principal_from_request_session

    if not login_enabled():
        return None
    # The channel server belongs to this deployment. A browser-selected or
    # per-user virtual workspace has no matching first-party bot installation.
    if getattr(request.state, "workspace_tenant_source", "") in {
        "principal_selection", "principal_isolation",
    }:
        return None
    principal = _principal_from_request_session(request)
    if principal is None or auth.caller_principal(request) != principal.principal:
        return None
    cfg = load_oidc_config()
    payload = verify_session(request.cookies.get(SESSION_COOKIE, ""), cfg.session_secret)
    if (not isinstance(payload, dict) or payload.get("sub") != principal.sub
            or payload.get("oidc_issuer") != cfg.issuer
            or payload.get("oidc_audience") != cfg.audience):
        return None
    return principal.sub, cfg.issuer, cfg.audience


def _require_bridge_identity(request: Request) -> tuple[str, str, str]:
    identity = _bridge_identity(request)
    if identity is None:
        if getattr(request.state, "workspace_tenant_source", "") in {
            "principal_selection", "principal_isolation",
        }:
            raise HTTPException(
                status_code=409,
                detail="This chat bot is not connected to the selected workspace.",
            )
        raise HTTPException(
            status_code=403,
            detail="Sign in again with single sign-on to connect this chat account."
        )
    return identity


def _waiting_on(request: Request, world, principal: str, row: dict, *, can_decide: bool) -> str:
    """Who the request is really waiting on, by the rules that are enforced.

    "you" / "you_own": this person can open and decide it (the person who
    asked may approve their own request); "others": they asked, but someone
    else must decide (the separate-approver rule, or two-person approval);
    "requester": it belongs to a colleague's private task this person can't open;
    "you_chat": private here, but this person may decide it in Slack or Teams.
    """
    from .approval_decisions import own_request_note
    from .content_access import can_read_approval

    approval = world.get_approval(int(row["id"]))
    if approval is None:
        return "others"
    own = bool(principal) and approval.requested_by == principal
    if not can_decide or not can_read_approval(request, approval, world):
        if own:
            return "others"
        from .approval_private_cards import decides_in_chat

        # Private here, but the rules let this person decide it in chat.
        return "you_chat" if can_decide and decides_in_chat(approval, principal) else "requester"
    if not own:
        return "you"
    return "others" if own_request_note(world, approval, principal) else "you_own"


def _my_work(request: Request, principal: str) -> dict:
    from maverick import channel_identities, daily_digest, user_preferences

    prefs = user_preferences.get_preferences(principal)
    can_decide = auth.has_permission(request, "operate")
    everything = auth.goal_owner_filter(request) is None
    world = _world()
    digest = daily_digest.compose_digest(
        world, principal, can_decide=can_decide, sees_everything=everything,
        suites=auth.caller_suites(request), time_zone=prefs["time_zone"],
    )
    for row in digest["approvals"]:
        row["waiting_on"] = _waiting_on(request, world, principal, row, can_decide=can_decide)
    # "Things that need you" counts only the requests this person can decide.
    digest["counts"]["approvals"] = sum(
        1 for row in digest["approvals"] if row["waiting_on"] in ("you", "you_own", "you_chat"))
    try:
        links = channel_identities.links_for(principal)
    except channel_identities.ChannelIdentityError:
        links = []
    bridge_identity = _bridge_identity(request)
    bridge_links, bridge_pending, bridge_notice = [], [], ""
    if bridge_identity:
        from maverick import channel_oidc_bridge

        try:
            bridge_links = channel_oidc_bridge.links_for(*bridge_identity)
            bridge_pending = channel_oidc_bridge.pending(*bridge_identity)
        except channel_oidc_bridge.BridgeError:
            bridge_notice = "Connected chat account records are unavailable. Ask an administrator to check them."
    return {"digest": digest, "preferences": prefs, "links": links,
            "can_decide": can_decide, "bridge_available": bridge_identity is not None,
            "bridge_can_connect": bridge_identity is not None and auth.has_permission(request, "operate"),
            "bridge_links": bridge_links, "bridge_pending": bridge_pending,
            "bridge_notice": bridge_notice}


# ----------------------------------------------------------------------------
# The page and its JSON twin
# ----------------------------------------------------------------------------

@router.get("/me", response_class=HTMLResponse)
def me_page(request: Request, saved: str = "") -> HTMLResponse:
    # Connection codes must only reach this page from the authenticated POST
    # that issued them. A GET URL can be supplied by someone else.
    from .navigation_api import areas_redirect

    moved = areas_redirect(request)  # areas mode: Home's My work section
    if moved is not None:
        return moved
    return _render_me_page(request, saved=saved)


def _render_me_page(request: Request, *, saved: str = "", link_code: str = "",
                    link_channel: str = "", bridge_code: str = "",
                    bridge_channel: str = "") -> HTMLResponse:
    """My work: what is waiting for me, my spending, my chat accounts, my summary."""
    auth.require_permission(request, "view")
    from maverick import user_preferences
    from maverick.config import get_my_work
    from maverick.notifications import email_configured

    principal = _principal(request)
    model = _my_work(request, principal)
    try:
        digest_on = bool(get_my_work().get("digest_enable"))
    except Exception:  # noqa: BLE001 -- an unreadable config shows "off"
        digest_on = False
    saved_msg = {
        "preferences": "Your choices are saved.",
        "unlinked": "That chat account is no longer linked.",
        "chat_connected": "This chat account can now start Lightwork tasks.",
        "chat_disconnected": "This chat account can no longer start Lightwork tasks.",
        "sent": "Your summary was sent. Check your linked chat app or inbox.",
        "not_sent": "Your summary could not be sent. Link a chat account or add an email first.",
        "unconfirmed": ("Your summary may have been sent, but the service did not confirm it. "
                        "Check your chat app or inbox before sending it again."),
        "bad_preferences": "Those choices could not be saved. Check the values and try again.",
    }.get(saved, "")
    model.update({
        "principal": principal,
        "saved": saved_msg,
        "saved_failed": saved in {"not_sent", "unconfirmed", "bad_preferences"},
        "link_code": link_code,
        "link_channel": link_channel,
        "bridge_code": bridge_code,
        "bridge_channel": bridge_channel,
        "time_zones": user_preferences.time_zone_choices(),
        "digest_scheduler_on": digest_on,
        "email_on": email_configured(),
        "hours": list(range(24)),
    })
    return _app().templates.TemplateResponse(request, "me.html", model)


@router.post("/me/channels/oidc/start")
def me_oidc_bridge_start(request: Request, channel: str = Form(...)) -> HTMLResponse:
    auth.require_permission(request, "operate")
    _app()._require_same_origin(request)
    from maverick import channel_oidc_bridge

    identity = _require_bridge_identity(request)
    try:
        issued = channel_oidc_bridge.begin(*identity, channel)
    except channel_oidc_bridge.BridgeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response = _render_me_page(request, bridge_code=issued["code"], bridge_channel=channel)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.post("/me/channels/oidc/confirm")
def me_oidc_bridge_confirm(request: Request, challenge_id: str = Form(...)) -> RedirectResponse:
    auth.require_permission(request, "operate")
    _app()._require_same_origin(request)
    from maverick import channel_oidc_bridge

    try:
        channel_oidc_bridge.confirm(*_require_bridge_identity(request), challenge_id)
    except channel_oidc_bridge.BridgeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse("/me?saved=chat_connected#chat-accounts", status_code=303)


@router.post("/me/channels/oidc/unlink")
def me_oidc_bridge_unlink(request: Request, link_id: str = Form(...)) -> RedirectResponse:
    auth.require_permission(request, "view")
    _app()._require_same_origin(request)
    from maverick import channel_oidc_bridge

    try:
        removed = channel_oidc_bridge.unlink(*_require_bridge_identity(request), link_id)
    except channel_oidc_bridge.BridgeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="That connection was not found.")
    return RedirectResponse("/me?saved=chat_disconnected#chat-accounts", status_code=303)


@router.post("/channels/oidc/revoke")
def admin_oidc_bridge_revoke(request: Request, link_id: str = Form(...)) -> RedirectResponse:
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import channel_oidc_bridge

    try:
        removed = channel_oidc_bridge.revoke(
            link_id, actor=auth.caller_principal(request) or "operator",
        )
    except channel_oidc_bridge.BridgeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="That connection was not found.")
    return RedirectResponse("/channels?saved=oidc_revoked#channel-slack", status_code=303)


@api.get("/me/work")
def me_work(request: Request) -> dict:
    """The My work page as data (the mobile companion reads this)."""
    auth.require_permission(request, "view")
    principal = _principal(request)
    model = _my_work(request, principal)
    return {"principal": principal, **model}


# ----------------------------------------------------------------------------
# Choices, chat accounts and "send it now"
# ----------------------------------------------------------------------------

@router.post("/me/preferences")
def me_preferences(
    request: Request,
    time_zone: str = Form("UTC"),
    digest_hour: int = Form(8),
    email: str = Form(""),
    digest_enabled: str = Form(""),
    send_when_empty: str = Form(""),
) -> RedirectResponse:
    auth.require_personal_write(request)
    _app()._require_same_origin(request)
    from maverick import user_preferences

    principal = _principal(request)
    try:
        user_preferences.set_preferences(
            principal, time_zone=time_zone.strip(), digest_hour=int(digest_hour),
            email=email.strip(), digest_enabled=digest_enabled == "on",
            send_when_empty=send_when_empty == "on",
        )
    except (user_preferences.UserPreferenceError, ValueError) as exc:
        from .product_errors import background_save
        if background_save(request):
            raise _preference_refusal(str(exc)) from exc
        return RedirectResponse("/me?saved=bad_preferences", status_code=303)
    return RedirectResponse("/me?saved=preferences", status_code=303)


def _preference_refusal(reason: str) -> HTTPException:
    """A refused daily-summary choice, tied to its field for a background save."""
    from .product_errors import product_error
    for words, field, message in (
        ("time zone", "time_zone", "Choose your time zone from the list."),
        ("hour", "digest_hour", "Choose the hour to send it from the list."),
        ("email", "email", "Enter a full email address. For example: name@company.com."),
    ):
        if words in reason:
            return product_error(422, "preferences_" + field, message, field_errors={field: message})
    return product_error(422, "preferences_invalid", "Those choices could not be saved. Check the values and try again.")


@router.post("/me/channels/link-code")
def me_link_code(request: Request, channel: str = Form(...)) -> HTMLResponse:
    """A one-time code the person sends from the chat app (``/lightwork link``)."""
    auth.require_personal_write(request)
    # The linked chat account starts tasks and decides approvals as this
    # person, so a key must hold both of those scopes to mint its code.
    auth.require_api_key_scope(request, "tasks:write")
    auth.require_api_key_scope(request, "approvals:decide")
    _app()._require_same_origin(request)
    from maverick import channel_identities

    principal = _principal(request)
    try:
        issued = channel_identities.issue_link_code(principal, channel)
    except channel_identities.ChannelIdentityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    response = _render_me_page(
        request, link_code=issued["code"], link_channel=issued["channel"],
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.post("/me/channels/unlink")
def me_unlink(request: Request, channel: str = Form(...),
              external_id: str = Form(...)) -> RedirectResponse:
    auth.require_personal_write(request)
    _app()._require_same_origin(request)
    from maverick import channel_identities

    principal = _principal(request)
    try:
        channel_identities.unlink(channel, external_id, actor=principal,
                                  expected_principal=principal)
    except channel_identities.ChannelIdentityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/me?saved=unlinked#chat-accounts", status_code=303)


@router.post("/me/digest/send-now")
async def me_send_now(request: Request) -> RedirectResponse:
    """Send today's summary to me right away (a test of the linked channels)."""
    auth.require_personal_write(request)
    _app()._require_same_origin(request)
    from maverick import channel_identities, daily_digest, user_preferences

    principal = _principal(request)
    prefs = user_preferences.get_preferences(principal)
    links = channel_identities.links_for(principal)
    if not links and not prefs.get("email"):
        return RedirectResponse("/me?saved=not_sent", status_code=303)
    digest = _prepared_digest(request, principal, prefs)
    outcomes = await run_in_threadpool(
        daily_digest.send_digest, principal, digest, links=links, prefs=prefs)
    deliveries = {o["delivery"] for o in outcomes}
    status = ("sent" if "accepted" in deliveries
              else "unconfirmed" if "unconfirmed" in deliveries else "not_sent")
    return RedirectResponse(f"/me?saved={status}", status_code=303)


def _prepared_digest(request: Request, principal: str, prefs: dict) -> dict:
    """Today's summary for this person, built exactly as it is sent."""
    from maverick import daily_digest

    return daily_digest.prepare_digest(
        _world(), principal, can_decide=auth.has_permission(request, "operate"), prefs=prefs,
        sees_everything=auth.goal_owner_filter(request) is None, suites=auth.caller_suites(request))


def _delivery_notes(principal: str, prefs: dict, digest: dict) -> tuple[bool, list[str]]:
    """Whether today's summary would really go out, and why not, in plain words."""
    from maverick import channel_identities
    from maverick.config import get_my_work

    try:
        workspace_on = bool(get_my_work().get("digest_enable"))
    except Exception:  # noqa: BLE001 -- an unreadable config reads as "off"
        workspace_on = False
    try:
        linked = bool(channel_identities.links_for(principal))
    except channel_identities.ChannelIdentityError:
        linked = False
    blocking = []
    if not workspace_on:
        blocking.append("The daily summary is turned off for this workspace, so nothing is sent. "
                        "An administrator can turn it on in Settings (My work › Send a daily summary).")
    if not prefs.get("digest_enabled", True):
        blocking.append("You turned your daily summary off in My work.")
    if not linked and not prefs.get("email"):
        blocking.append("No chat account or email address is linked, so there is nowhere to send it.")
    if digest["empty"] and not prefs.get("send_when_empty"):
        blocking.append("Nothing is waiting, and you chose not to get an empty summary.")
    notes = list(blocking)
    if digest.get("left_out_seen"):
        count = int(digest["left_out_seen"])
        notes.append(f"{count} result{'s' if count != 1 else ''} you already saw in the app "
                     f"{'are' if count != 1 else 'is'} left out.")
    if not blocking:
        notes.insert(0, f"It goes out at {int(prefs.get('digest_hour', 8)):02d}:00 "
                        f"({prefs.get('time_zone') or 'UTC'}) to your linked chat app or email.")
    return not blocking, notes


@api.get("/me/digest/preview")
def me_digest_preview(request: Request, response: Response) -> dict:
    """Exactly what today's summary would send, without sending anything."""
    auth.require_permission(request, "view")
    from maverick import daily_digest, user_preferences

    response.headers["Cache-Control"] = "private, no-store"
    principal = _principal(request)
    prefs = user_preferences.get_preferences(principal)
    digest = _prepared_digest(request, principal, prefs)
    would_send, notes = _delivery_notes(principal, prefs, digest)
    return {"subject": daily_digest.subject(digest),
            "text": daily_digest.render_text(digest, dashboard_url=daily_digest.dashboard_url()),
            "would_send": would_send, "notes": notes, "counts": digest["counts"]}


# ----------------------------------------------------------------------------
# Administrators: map chat accounts on the Users page; test the mail backend
# ----------------------------------------------------------------------------

@router.post("/users/channels/link")
def users_channel_link(request: Request, principal: str = Form(...),
                       channel: str = Form(...), external_id: str = Form(...)) -> RedirectResponse:
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import channel_identities

    try:
        channel_identities.link(channel, external_id, principal.strip(),
                                actor=auth.caller_principal(request) or "local", method="admin")
    except channel_identities.ChannelIdentityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/users?saved=channel_linked#chat-accounts", status_code=303)


@router.post("/users/channels/unlink")
def users_channel_unlink(request: Request, channel: str = Form(...),
                         external_id: str = Form(...)) -> RedirectResponse:
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick import channel_identities

    try:
        channel_identities.unlink(channel, external_id,
                                  actor=auth.caller_principal(request) or "local")
    except channel_identities.ChannelIdentityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse("/users?saved=channel_unlinked#chat-accounts", status_code=303)


@router.post("/channels/test-email")
async def channels_test_email(request: Request, to: str = Form(...)) -> RedirectResponse:
    """The "Test email" button: one message through ``[notifications.email]``."""
    auth.require_global_permission(request, "admin")
    _app()._require_same_origin(request)
    from maverick.notifications import send_email

    ok = await run_in_threadpool(
        send_email, to.strip(), "Lightwork test email",
        "This is a test message from Lightwork. If you can read it, email alerts and "
        "the daily summary can reach this address.",
    )
    return RedirectResponse(f"/channels?saved={'email_sent' if ok else 'email_failed'}",
                            status_code=303)


# ----------------------------------------------------------------------------
# Slack over HTTP (the non-Socket deployment)
# ----------------------------------------------------------------------------

def _slack_signing_secret() -> str:
    from maverick.config import load_config
    from maverick.notifications import _resolve_env_ref
    from maverick.secret_provider import get_secret_or_saved

    try:
        section = (load_config().get("channels") or {}).get("slack") or {}
    except Exception:  # noqa: BLE001 -- an unreadable config means "not set up"
        section = {}
    saved = section.get("signing_secret") if isinstance(section, dict) else None
    saved = _resolve_env_ref(saved) if isinstance(saved, str) else None
    return get_secret_or_saved("SLACK_SIGNING_SECRET", saved) or ""


async def _verified_slack_body(request: Request) -> bytes:
    """Refuse unless the request is signed by Slack, fresh, and not a replay."""
    from maverick.slack_interactive import verify_slack_signature

    secret = await run_in_threadpool(_slack_signing_secret)
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Slack buttons over HTTP aren't set up yet. An administrator must save the "
                   "Slack signing secret on the Channels page.")
    body = await _app()._read_limited_webhook_body(request)
    timestamp = request.headers.get("X-Slack-Request-Timestamp") or ""
    signature = request.headers.get("X-Slack-Signature") or ""
    if not verify_slack_signature(secret, timestamp=timestamp, signature=signature, body=body):
        raise HTTPException(status_code=401, detail="bad Slack signature")
    if _app()._issue_webhook_replay_seen(f"slack:{signature}", _SLACK_REPLAY_WINDOW):
        raise HTTPException(status_code=409, detail="that Slack request was already handled")
    return body


def _slack_principal_for(user_id: str):
    from maverick.oidc import oidc_enabled

    if oidc_enabled():
        # The HTTP interaction's signature proves the configured Slack app,
        # but this route has no verified current bot installation receipt.
        # Socket Mode can resolve the exact workspace/account tuple; HTTP
        # decisions stay unavailable until it can establish that same proof.
        return None
    from maverick.channel_identities import principal_for

    return principal_for("slack", user_id)


@router.post("/webhook/slack/interactions")
async def webhook_slack_interactions(request: Request) -> JSONResponse:
    """Button presses from Slack (signed; ``payload`` form field)."""
    from maverick.slack_interactive import (
        handle_block_action,
        handle_view_submission,
        open_view,
        parse_interaction_body,
        respond,
        slack_bot_token,
    )

    from .approval_decisions import _authority_for

    body = await _verified_slack_body(request)
    payload = parse_interaction_body(body)
    # The linked person needs the operate role, like a dashboard or Teams voter.
    authorize = _authority_for("slack")
    if payload.get("type") == "view_submission":
        # The typed confirmation for a Critical request: Slack reads the answer
        # from this response (response_action), the card update goes through
        # the response_url kept in the modal.
        outcome = await run_in_threadpool(
            handle_view_submission, payload, world=_world(), principal_for=_slack_principal_for,
            authorize=authorize)
        if outcome and outcome.get("message"):
            await run_in_threadpool(respond, outcome["respond_to"], outcome["message"])
        return JSONResponse((outcome or {}).get("ack") or {})
    if payload.get("type") != "block_actions":
        return JSONResponse({})
    token = slack_bot_token()
    result = await run_in_threadpool(
        handle_block_action, payload, world=_world(), principal_for=_slack_principal_for,
        open_view=(lambda trigger, view: open_view(token, trigger, view)) if token else None,
        authorize=authorize)
    if result is None:
        return JSONResponse({})
    # Update the card in place through the payload's response_url; answering the
    # POST itself is only the acknowledgement Slack wants within 3 seconds.
    await run_in_threadpool(respond, str(payload.get("response_url") or ""), result)
    return JSONResponse({})


@router.post("/webhook/slack/commands")
async def webhook_slack_commands(request: Request) -> JSONResponse:
    """``/lightwork ...`` slash commands from Slack (signed form POST).

    ``/lightwork ask`` needs the running chat bot (``maverick serve`` with the
    Slack channel); over HTTP it answers with that pointer.
    """
    from maverick.slack_interactive import handle_slash_command, parse_form

    from .approval_decisions import _authority_for
    from .daily_digest_scheduler import status_scope

    body = await _verified_slack_body(request)
    form = parse_form(body)
    result = await run_in_threadpool(
        handle_slash_command, form, world=_world(), principal_for=_slack_principal_for, ask=None,
        authorize=_authority_for("slack"), status_scope=status_scope)
    return JSONResponse(result)



__all__ = ["api", "router"]
