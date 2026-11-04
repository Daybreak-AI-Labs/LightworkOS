"""Slack channel via Socket Mode (no public webhook needed).

Set up:
  1. Create a Slack app at https://api.slack.com/apps
  2. Enable Socket Mode; copy the App-Level Token to ${SLACK_APP_TOKEN}
  3. Install to your workspace; copy the Bot Token to ${SLACK_BOT_TOKEN}
  4. Bot token scopes: `chat:write`, `commands`, `im:history`,
     `channels:history`, `groups:history`, `app_mentions:read`, `users:read`,
     `im:write` (daily summary DMs); `files:read` if people share files
     (shared files become goal attachments); `files:write` to deliver saved
     task outputs and rendered replies
  5. Subscribe to bot events `message.im`, `message.channels`,
     `message.groups`, `app_mention`; turn on Interactivity; add the slash
     command `/lightwork`
  6. For the HTTP (non-Socket) deployment, point Interactivity and the slash
     command at ``https://<dashboard>/webhook/slack/interactions`` and
     ``/webhook/slack/commands`` and save the signing secret as
     ``[channels.slack] signing_secret`` (see docs/channels/slack.md)

Direct messages behave as before (a message is a task). In channels and
groups the bot answers when it is mentioned. Approval cards carry Approve /
Reject / Ask a question buttons (High/Critical confirm twice) and slash
commands ``/lightwork approve|reject|status|help|ask|link`` work everywhere;
the decision logic is ``maverick.channel_approvals`` (shared with the
dashboard), the card and payload handling ``maverick.slack_interactive``.

Requires::

    python -m pip install -e './packages/maverick-channels[slack]'
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import re

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import (
    DeliveryNotSent,
    DeliveryUnknown,
    delivery_active,
    read_reply_file,
    saved_reply_files,
    send_chunk,
)

log = logging.getLogger(__name__)

try:
    from slack_sdk.socket_mode.aiohttp import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse
    from slack_sdk.web.async_client import AsyncWebClient
    _HAVE_SLACK = True
except ImportError:
    _HAVE_SLACK = False
    SocketModeClient = AsyncWebClient = SocketModeResponse = None  # type: ignore


class SlackChannel(Channel):
    name = "slack"

    def __init__(
        self,
        handler,
        app_token: str | None = None,
        bot_token: str | None = None,
        allowed_user_ids=None,
        thread_replies: bool | None = None,
        world=None,
        approvals_channel: str | None = None,
        authorize=None,
    ):
        super().__init__(handler)
        if not _HAVE_SLACK:
            raise ImportError(
                "slack_sdk not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[slack]'"
            )
        self.app_token = app_token or os.environ.get("SLACK_APP_TOKEN")
        self.bot_token = bot_token or os.environ.get("SLACK_BOT_TOKEN")
        if not self.app_token or not self.bot_token:
            raise ValueError("SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set")
        # Without an allowlist, ANY workspace user who can message the bot
        # drives the agent (and burns the operator's budget). Require one,
        # matching discord/telegram. Default-deny via base.is_allowed.
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "SLACK_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError("Set SLACK_ALLOWED_USER_IDS to restrict access")
        # Opt-in reply threading: answers post under the asking message's
        # thread (thread_ts) instead of interleaving into the channel.
        # [channels.slack] thread_replies / SLACK_THREAD_REPLIES.
        if thread_replies is None:
            thread_replies = os.environ.get(
                "SLACK_THREAD_REPLIES", "").strip().lower() in {"1", "true", "yes", "on"}
        self.thread_replies = bool(thread_replies)
        self._web = AsyncWebClient(token=self.bot_token)
        self._sm = SocketModeClient(app_token=self.app_token, web_client=self._web)
        self._sm.socket_mode_request_listeners.append(self._on_request)
        self._stop_event = asyncio.Event()
        self._account_id = ""
        self._team_id = ""
        self._bot_user_id = ""
        # The world holding the approval queue (the server passes its own);
        # opened lazily otherwise so a channels-only process still starts.
        self._world = world
        # [channels.slack] approvals_channel: where new approval cards are posted.
        self.approvals_channel = (approvals_channel
                                  or os.environ.get("SLACK_APPROVALS_CHANNEL", "")).strip()
        # ``authorize(principal, approval_id)``: the permission check a vote needs
        # (see ``_vote_authority``); None means the dashboard's own rule.
        self._authorize = authorize

    def _vote_authority(self):
        """The permission check for an approval vote, as the HTTP receivers apply it.

        The injected one, else the dashboard's ``operate`` role rule (the linked
        person must hold it, like a dashboard voter). With neither the kernel has
        no roster to ask, so every decision is refused rather than let through.
        """
        if self._authorize is not None:
            return self._authorize
        try:
            from maverick_dashboard.approval_decisions import _authority_for
        except Exception:  # noqa: BLE001 -- the kernel runs without the dashboard
            from maverick.channel_approvals import ChannelApprovalRefused

            def refuse(principal, approval_id):
                raise ChannelApprovalRefused(
                    "not_permitted",
                    "Approvals can't be decided from Slack here. Use the Lightwork dashboard.")
            return refuse
        return _authority_for("slack")

    @staticmethod
    def _status_scope():
        """The dashboard's role and department rule for ``/lightwork status``;
        without the dashboard, status shows only the person's own requests."""
        try:
            from maverick_dashboard.daily_digest_scheduler import status_scope
        except Exception:  # noqa: BLE001 -- the kernel runs without the dashboard
            return None
        return status_scope

    def _authorized(self, msg, account):
        from maverick.oidc import oidc_enabled

        if not (account and account == self._account_id
                and is_allowed(msg.principal_id, self.allowed_user_ids)):
            return False
        if (not oidc_enabled() and msg.provider_tenant_id is None
                and msg.provider_sender_id is None):
            # Pre-upgrade durable receipts had no provider tuple. They retain
            # the original account and current allowlist checks, but cannot
            # acquire OIDC identity authority after an upgrade.
            return True
        return bool(msg.provider_tenant_id == self._team_id
                    and msg.provider_sender_id == msg.principal_id)

    async def _prepare(self, msg, route):
        msg.attachments = await self._download_files({"files": route.get("files", [])})
        return msg

    async def _send_saved(self, msg, reply, route):
        files = await saved_reply_files(reply)
        thread = reply.thread_ref or route.get("reply_to")
        if reply.text:
            await self.send_threaded(msg.user_id, reply.text, reply_to=thread)
        receipt = None
        for index, item in enumerate(files):
            async def upload(item=item):
                data = await read_reply_file(item)
                # This SDK call has multiple remote phases. A failure can follow
                # upload acceptance, so it must remain unknown, never retryable.
                with io.BytesIO(data) as document:
                    result = await self._web.files_upload_v2(channel=msg.user_id,
                        thread_ts=thread, filename=item["filename"], file=document)
                returned = result.get("files") or []
                identity = returned[0].get("id") if len(returned) == 1 else None
                if result.get("ok") is False or not isinstance(identity, str) or not identity:
                    raise DeliveryUnknown("Slack file attachment has no confirmed receipt")
                return identity
            receipt = await send_chunk("file-" + str(index), {"recipient": msg.user_id,
                "thread": thread, **{key: item[key] for key in ("filename", "mime", "size_bytes", "sha256")}}, upload)
        return receipt

    async def _download_files(self, event: dict) -> list[dict]:
        """Download a message's shared files into IncomingMessage.attachments.

        Slack file objects carry ``url_private_download`` which requires the
        bot token as a bearer header (and the ``files:read`` scope). Each
        file becomes ``{"filename", "mime", "data"}``; the server stores them
        under the same size/mime/magic-byte rules as a dashboard upload.
        Best-effort: a missing scope or a failed download just means no
        attachment, never a dropped message.
        """
        files = event.get("files") or []
        if not files:
            return []
        try:
            import aiohttp  # slack_sdk's async client already requires it
        except ImportError:  # pragma: no cover
            return []
        out: list[dict] = []
        headers = {"Authorization": f"Bearer {self.bot_token}"}
        async with aiohttp.ClientSession(headers=headers) as session:
            for f in files[:10]:
                url = f.get("url_private_download") or f.get("url_private")
                if not url:
                    continue
                size = f.get("size")
                if size and int(size) > 100 * 1024 * 1024:
                    continue  # attachments.store would reject it anyway
                try:
                    async with session.get(url) as resp:
                        resp.raise_for_status()
                        data = await resp.content.read(100 * 1024 * 1024 + 1)
                except Exception:  # noqa: BLE001 -- never drop the message
                    log.warning("slack: file download failed", exc_info=True)
                    continue
                if not data or len(data) > 100 * 1024 * 1024:
                    continue
                out.append({
                    "filename": f.get("name") or "file.bin",
                    "mime": f.get("mimetype") or "application/octet-stream",
                    "data": data,
                })
        return out

    # ---- approvals, buttons and slash commands ------------------------------

    def _approval_world(self):
        if self._world is None:
            from maverick.world_model import open_world

            self._world = open_world()
        return self._world

    def _principal_for(self, user_id: str):
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            if not self._account_id or not self._team_id:
                return None
            from maverick.channel_oidc_bridge import BridgeError, resolve

            from .delivery import _digest

            try:
                return resolve("slack", _digest(self._account_id), self._team_id, user_id)
            except BridgeError:
                return None
        from maverick.channel_identities import principal_for

        return principal_for("slack", user_id)

    async def _ack(self, client, req, payload=None):
        kwargs = {"envelope_id": req.envelope_id}
        if payload is not None:
            kwargs["payload"] = payload
        await client.send_socket_mode_response(SocketModeResponse(**kwargs))

    async def _open_view(self, trigger_id: str, view: dict) -> bool:
        """``views.open`` through the Socket Mode web client (the modal for Critical)."""
        try:
            result = await self._web.views_open(trigger_id=trigger_id, view=view)
        except Exception:  # noqa: BLE001 -- the caller falls back to the slash-command path
            log.warning("slack views.open failed", exc_info=True)
            return False
        return bool(result.get("ok", True))

    async def _on_view_submission(self, client, req, payload: dict):
        from maverick.slack_interactive import handle_view_submission, respond

        outcome = await asyncio.to_thread(
            handle_view_submission, payload, world=self._approval_world(),
            principal_for=self._principal_for, authorize=self._vote_authority(),
        )
        await self._ack(client, req, (outcome or {}).get("ack"))
        if outcome and outcome.get("message"):
            await asyncio.to_thread(respond, outcome["respond_to"], outcome["message"])
        return outcome

    async def _on_interactive(self, client, req):
        """A button press: ack within Slack's 3 seconds, decide, update in place.
        A submitted confirmation modal is answered in the ack itself."""
        from maverick.slack_interactive import handle_block_action, respond

        payload = req.payload if isinstance(req.payload, dict) else {}
        user_id = str((payload.get("user") or {}).get("id") or "")
        team = payload.get("team") if isinstance(payload.get("team"), dict) else {}
        from maverick.oidc import oidc_enabled

        allowed = (is_allowed(user_id, self.allowed_user_ids)
                   and (not oidc_enabled() or team.get("id") == self._team_id))
        if payload.get("type") == "view_submission" and allowed:
            return await self._on_view_submission(client, req, payload)
        await self._ack(client, req)
        if payload.get("type") != "block_actions" or not allowed:
            return None
        loop = asyncio.get_running_loop()

        def open_view(trigger_id: str, view: dict) -> bool:
            future = asyncio.run_coroutine_threadsafe(self._open_view(trigger_id, view), loop)
            return bool(future.result(timeout=5))

        result = await asyncio.to_thread(
            handle_block_action, payload, world=self._approval_world(),
            principal_for=self._principal_for, open_view=open_view,
            authorize=self._vote_authority(),
        )
        if result is not None:
            await asyncio.to_thread(respond, str(payload.get("response_url") or ""), result)
        return result

    async def _ask_from_slash(self, form: dict) -> str:
        """``/lightwork ask <goal>`` runs the same handler as a chat message."""
        from maverick.oidc import oidc_enabled
        from maverick.slack_interactive import parse_slash_text

        if oidc_enabled():
            # Slash commands have no durable execution receipt. A provider
            # tuple alone cannot stand in for the delivery journal's verified
            # app-account receipt, so direct messages carry OIDC chat tasks.
            return "Send your task in a direct message to the Lightwork bot."

        _verb, goal = parse_slash_text(form.get("text"))
        msg = IncomingMessage(user_id=str(form.get("channel_id") or ""), text=goal,
                              channel=self.name, sender_id=str(form.get("user_id") or ""))
        return await self.dispatch_text(msg)

    async def _on_slash_command(self, client, req):
        from maverick.slack_interactive import handle_slash_command, parse_slash_text, respond

        form = req.payload if isinstance(req.payload, dict) else {}
        await self._ack(client, req)
        user_id = str(form.get("user_id") or "")
        from maverick.oidc import oidc_enabled

        if oidc_enabled() and form.get("team_id") != self._team_id:
            return None
        if not is_allowed(user_id, self.allowed_user_ids):
            return None
        verb, rest = parse_slash_text(form.get("text"))
        if verb == "ask" and oidc_enabled():
            result = {"response_type": "ephemeral", "replace_original": False,
                      "text": "Send your task in a direct message to the Lightwork bot. "
                              "Connect your account from My work first if needed."}
        elif verb == "ask" and rest and self._principal_for(user_id):
            answer = await self._ask_from_slash(form)
            result = {"response_type": "ephemeral", "replace_original": False,
                      "text": str(answer)[:3000]}
        else:
            result = await asyncio.to_thread(
                handle_slash_command, form, world=self._approval_world(),
                principal_for=self._principal_for, ask=None,
                authorize=self._vote_authority(), status_scope=self._status_scope(),
            )
        await asyncio.to_thread(respond, str(form.get("response_url") or ""), result)
        return result

    def _strip_mention(self, text: str) -> str:
        if not self._bot_user_id:
            return text
        return re.sub(rf"<@{re.escape(self._bot_user_id)}(\|[^>]*)?>", " ", text).strip()

    async def _thread_admitted(self, event: dict) -> bool:
        """Whether this thread's first message was admitted (the bot was asked
        there). Without the identity to look it up, the checks that follow
        refuse the event as before."""
        from .delivery import DeliveryJournal, _record_id

        if not self._account_id or not event.get("channel") or not event.get("thread_ts"):
            return True
        root = _record_id(self.name, self._account_id, f"{event['channel']}:{event['thread_ts']}")
        return await asyncio.to_thread(DeliveryJournal().get, root) is not None

    def _addressed_to_bot(self, event: dict) -> bool:
        """DMs always; channels and groups only when the bot is mentioned."""
        if event.get("type") == "app_mention":
            return True
        if event.get("channel_type") not in ("channel", "group", "mpim"):
            return True  # a direct message (or an older payload without the type)
        return bool(self._bot_user_id and f"<@{self._bot_user_id}" in str(event.get("text") or ""))

    async def post_approval_card(self, channel: str, approval, *, dashboard_url: str = ""):
        """Post one approval as a Block Kit card with decision buttons."""
        from maverick.channel_approvals import card_content
        from maverick.slack_interactive import _slack_literal, approval_blocks

        content = card_content(approval)
        blocks = approval_blocks(content, dashboard_url=dashboard_url)
        result = await self._web.chat_postMessage(
            channel=channel, text=_slack_literal(f"Approval needed: {content['action']} (#{content['id']})"),
            blocks=blocks, mrkdwn=False, parse="none", link_names=False,
        )
        return result.get("ts") if isinstance(result, dict) or hasattr(result, "get") else None

    async def _on_request(self, client, req):
        if req.type == "interactive":
            return await self._on_interactive(client, req)
        if req.type == "slash_commands":
            return await self._on_slash_command(client, req)
        event = req.payload.get("event", {}) if req.type == "events_api" else {}
        sender = event.get("user", "")
        addressed = self._addressed_to_bot(event)
        threaded_reply = bool(event.get("thread_ts") and event.get("channel_type")
                              in ("channel", "group", "mpim"))
        accepted = (event.get("type") in ("message", "app_mention") and "bot_id" not in event
                    and event.get("subtype") in (None, "file_share")
                    and is_allowed(sender, self.allowed_user_ids)
                    and (addressed or threaded_reply))
        reply_only = threaded_reply and not addressed
        if accepted and reply_only:
            # A reply that does not mention the bot can only answer a question
            # asked in that thread, and questions are asked in the thread of a
            # message the bot admitted. Other threads are people talking to each
            # other: admitting them (and their files) filled the intake.
            accepted = await self._thread_admitted(event)
        if accepted:
            # auth_test binds this transport to its immutable workspace/bot.
            # Persist only the envelope before ACK; file downloads and agent
            # work happen afterward. A failed/slow save permits redelivery.
            if (not self._account_id or req.payload.get("team_id") != self._team_id
                    or not event.get("channel") or not event.get("ts")):
                raise PermissionError("Slack event has no verified account/message identity")
            # An answer is the reply's text: files sent with it are not fetched.
            files = [] if reply_only else [{key: value for key, value in item.items() if key in {
                "id", "name", "mimetype", "size", "url_private", "url_private_download",
            }} for item in (event.get("files") or [])[:10]]
            text = self._strip_mention(event.get("text") or "")
            in_room = (event.get("type") == "app_mention"
                       or event.get("channel_type") in ("channel", "group", "mpim"))
            thread = event.get("thread_ts") or event["ts"]
            msg = IncomingMessage(
                user_id=event["channel"], text=text or
                ("Process the attached file(s)." if files else ""), channel=self.name,
                sender_id=sender, message_id=event["ts"],
                provider_tenant_id=self._team_id, provider_sender_id=sender,
                conversation_ref=thread if in_room else None,
                question_reply_only=reply_only,
            )
            account = self._account_id
            # A mention in a channel or group answers in its thread so the
            # room is not flooded; DMs keep the configured threading.
            route = {"reply_to": thread if (self.thread_replies or in_room) else None,
                     "files": files}
            external_id = event["channel"] + ":" + event["ts"]
            receipt = await self.admit_message(msg, external_id=external_id, account=account,
                authorize=lambda: self._authorized(msg, account), route=route)
        await client.send_socket_mode_response(
            SocketModeResponse(envelope_id=req.envelope_id)
        )
        if accepted:
            return await self.process_message(msg, external_id=external_id, account=account,
                authorize=lambda: self._authorized(msg, account), route=route, receipt=receipt,
                prepare=lambda incoming: self._prepare(incoming, route),
                send=lambda reply: self._send_saved(msg, reply, route))

    async def start(self) -> None:
        identity = await self._web.auth_test()
        if not identity.get("team_id") or not identity.get("user_id"):
            raise PermissionError("Slack account identity unavailable")
        self._team_id = identity["team_id"]
        self._bot_user_id = str(identity["user_id"])
        self._account_id = self._team_id + ":" + identity["user_id"]
        account = self._account_id
        await self._sm.connect()
        log.info("Slack channel connected")
        async with self.recovery_worker(account=account,
                authorize=lambda msg: self._authorized(msg, account),
                send=self._send_saved, prepare=self._prepare):
            await self._stop_event.wait()

    async def send(self, user_id: str, text: str) -> None:
        return await self.send_threaded(user_id, text)

    async def send_threaded(
        self, user_id: str, text: str, *, reply_to: str | None = None,
    ) -> None:
        from maverick.slack_interactive import _slack_literal_chunks
        rejected = {"not_authed", "invalid_auth", "account_inactive", "token_revoked",
                    "missing_scope", "channel_not_found", "not_in_channel", "is_archived",
                    "msg_too_long", "no_text", "restricted_action", "ratelimited"}
        receipt = None
        if not text:
            raise DeliveryNotSent("Slack cannot deliver an empty reply")
        # Format before splitting so escaping cannot expand a chunk past its
        # bound. Slack otherwise silently truncates a long successful post.
        for index, chunk in enumerate(_slack_literal_chunks(text, limit=4000)):
            kwargs = {"channel": user_id, "text": chunk, "mrkdwn": False,
                      "parse": "none", "link_names": False}
            if reply_to:
                kwargs["thread_ts"] = reply_to
            async def post(kwargs=kwargs):
                try:
                    result = await self._web.chat_postMessage(**kwargs)
                except Exception as exc:
                    response = getattr(exc, "response", None)
                    if response is not None and response.get("error") in rejected:
                        raise DeliveryNotSent("Slack rejected the reply") from exc
                    raise
                if result.get("ok") is False:
                    if result.get("error") in rejected:
                        raise DeliveryNotSent("Slack rejected the reply")
                    raise DeliveryUnknown("Slack reply acceptance is uncertain")
                provider_id = result.get("ts")
                if delivery_active() and not isinstance(provider_id, str):
                    raise DeliveryUnknown("Slack reply acknowledgement has no message id")
                return provider_id
            receipt = await send_chunk("text-" + str(index), kwargs, post)
        return receipt

    async def stop(self) -> None:
        self._stop_event.set()
        await self._sm.disconnect()
